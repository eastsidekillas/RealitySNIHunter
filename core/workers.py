"""Worker threads for RealitySNIHunter."""

import asyncio
import aiohttp
from PySide6.QtCore import QThread, Signal
from .networking import (
    tls_sni_discover_async, check_sni_with_target_async,
    read_geoip_urls_async, read_geosite_urls_async,
    download_geoip_db_async, load_geoip_db, get_country_code
)


class GeoIPDownloadWorker(QThread):
    """Worker для загрузки GeoIP базы Country.mmdb."""

    log_signal = Signal(str)
    done_signal = Signal(bool)

    def __init__(self, url: str):
        super().__init__()
        self.url = url

    def run(self):
        asyncio.run(self.async_run())

    async def async_run(self):
        try:
            self.log_signal.emit("⏳ Загрузка GeoIP базы Country.mmdb...")

            success = await download_geoip_db_async(self.url, "data/Country.mmdb")

            if success:
                self.log_signal.emit("✅ GeoIP база успешно загружена!")

                if load_geoip_db("data/Country.mmdb"):
                    self.log_signal.emit("✅ GeoIP база успешно открыта и готова к использованию!")
                    self.done_signal.emit(True)
                else:
                    self.log_signal.emit("❌ Не удалось открыть загруженную базу")
                    self.done_signal.emit(False)
            else:
                self.log_signal.emit("❌ Ошибка загрузки GeoIP базы")
                self.done_signal.emit(False)

        except Exception as e:
            self.log_signal.emit(f"❌ Ошибка: {e}")
            self.done_signal.emit(False)


class GeoDataWorker(QThread):
    """Worker для загрузки Geo данных (IP и домены)."""

    done_signal = Signal(list, list)

    def __init__(self, geoip_urls: list, geosite_urls: list):
        super().__init__()
        self.geoip_urls = geoip_urls
        self.geosite_urls = geosite_urls

    def run(self):
        asyncio.run(self.async_run())

    async def async_run(self):
        async with aiohttp.ClientSession() as session:
            ip_list = []
            domain_list = []

            if self.geoip_urls:
                ip_list = await read_geoip_urls_async(session, self.geoip_urls)

            if self.geosite_urls:
                domain_list = await read_geosite_urls_async(session, self.geosite_urls)

            self.done_signal.emit(ip_list, domain_list)


class ScanWorker(QThread):
    """Worker для сканирования IP адресов и доменов."""

    log_signal = Signal(str)
    progress_signal = Signal(int, int)
    done_signal = Signal(list, list, int)

    def __init__(self, ip_list: list, domain_list: list, port: int, concurrency: int):
        super().__init__()
        self.ip_list = ip_list
        self.domain_list = domain_list
        self.port = port
        self.concurrency = concurrency
        self.rows = []
        self.discovered_snis = set()

    def run(self):
        asyncio.run(self.async_run())

    async def async_run(self):
        """Асинхронное сканирование."""
        targets = []

        # IP адреса
        for ip in self.ip_list:
            targets.append(('ip', ip))

        # Домены
        for domain in self.domain_list:
            targets.append(('domain', domain))

        total = len(targets)

        if total == 0:
            self.log_signal.emit("⚠️ Нет целей для сканирования")
            self.done_signal.emit([], [], 0)
            return

        self.log_signal.emit(f"🔍 Начало сканирования {total} целей...")
        self.progress_signal.emit(0, total)

        semaphore = asyncio.Semaphore(self.concurrency)
        completed = 0

        async def scan_target(target_type: str, target: str):
            nonlocal completed
            async with semaphore:
                try:
                    # Сканируем цель
                    success, sni, details = await tls_sni_discover_async(target, self.port, timeout=5.0)

                    completed += 1
                    self.progress_signal.emit(completed, total)

                    if success and sni:
                        self.discovered_snis.add(sni)

                        # Получаем код страны
                        country = get_country_code(target) if target_type == 'ip' else 'N/A'

                        # Извлекаем детали
                        protocol = details.get('protocol', 'Unknown')
                        cipher = details.get('cipher', 'Unknown')
                        cert = details.get('cert', {})

                        # Issuer
                        issuer = 'Unknown'
                        if cert and 'issuer' in cert:
                            issuer_tuple = cert['issuer']
                            for item in issuer_tuple:
                                for key, value in item:
                                    if key == 'organizationName':
                                        issuer = value
                                        break

                        row = {
                            'ip': target if target_type == 'ip' else 'N/A',
                            'sni': sni,
                            'tls_version': protocol,
                            'cipher': cipher,
                            'alpn': 'N/A',  # ALPN требует специального извлечения
                            'issuer': issuer,
                            'country': country
                        }

                        self.rows.append(row)
                        self.log_signal.emit(f"✅ [{completed}/{total}] {target} → {sni}")
                    else:
                        self.log_signal.emit(f"❌ [{completed}/{total}] {target}: Нет TLS или SNI")

                except Exception as e:
                    completed += 1
                    self.progress_signal.emit(completed, total)
                    self.log_signal.emit(f"❌ [{completed}/{total}] {target}: {str(e)[:50]}")

        # Запускаем сканирование
        tasks = [scan_target(t_type, t_value) for t_type, t_value in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.log_signal.emit(f"\n✅ Сканирование завершено: найдено {len(self.discovered_snis)} уникальных SNI")
        self.done_signal.emit(self.rows, list(self.discovered_snis), total)


class SniCheckerWorker(QThread):
    """Worker для проверки SNI с целевым IP."""

    log_signal = Signal(str)
    progress_signal = Signal(int, int)
    result_signal = Signal(list)

    def __init__(self, target_ip: str, sni_list: list, port: int, concurrency: int):
        super().__init__()
        self.target_ip = target_ip
        self.sni_list = sni_list
        self.port = port
        self.concurrency = concurrency
        self.working_snis = []

    def run(self):
        asyncio.run(self.async_run())

    async def async_run(self):
        """Асинхронная проверка SNI."""
        total = len(self.sni_list)

        if total == 0:
            self.log_signal.emit("⚠️ Нет SNI для проверки")
            self.result_signal.emit([])
            return

        self.log_signal.emit(f"🔍 Начало проверки {total} SNI с IP {self.target_ip}...")
        self.progress_signal.emit(0, total)

        semaphore = asyncio.Semaphore(self.concurrency)
        completed = 0

        async def check_sni(sni: str):
            nonlocal completed
            async with semaphore:
                try:
                    success = await check_sni_with_target_async(self.target_ip, sni, self.port, timeout=5.0)

                    completed += 1
                    self.progress_signal.emit(completed, total)

                    if success:
                        self.working_snis.append(sni)
                        self.log_signal.emit(f"✅ [{completed}/{total}] {sni}: Работает")
                    else:
                        self.log_signal.emit(f"❌ [{completed}/{total}] {sni}: Не работает")

                except Exception as e:
                    completed += 1
                    self.progress_signal.emit(completed, total)
                    self.log_signal.emit(f"❌ [{completed}/{total}] {sni}: {str(e)[:50]}")

        # Запускаем проверку
        tasks = [check_sni(sni) for sni in self.sni_list]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.log_signal.emit(f"\n✅ Проверка завершена: {len(self.working_snis)}/{total} SNI работают")
        self.result_signal.emit(self.working_snis)