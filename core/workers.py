from PySide6.QtCore import QThread, Signal
import asyncio
import socket
import aiohttp
from .networking import (
    tls_sni_discover_async, read_geoip_urls_async,
    read_geosite_urls_async, auto_ip_range, download_geoip_db_async,
    load_geoip_db, close_geoip_db
)
from .xray_checker import test_snis_batch


class GeoIPDownloadWorker(QThread):
    log_signal = Signal(str)
    done_signal = Signal(bool)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        asyncio.run(self.async_run())

    async def async_run(self):
        self.log_signal.emit(f"Загрузка GeoIP базы Country.mmdb...")
        async with aiohttp.ClientSession() as session:
            success = await download_geoip_db_async(session, self.url, "Country.mmdb")
            if success:
                if load_geoip_db("Country.mmdb"):
                    self.log_signal.emit("✅ GeoIP база успешно загружена и активирована!")
                    self.done_signal.emit(True)
                else:
                    self.log_signal.emit("❌ Ошибка загрузки GeoIP базы")
                    self.done_signal.emit(False)
            else:
                self.log_signal.emit("❌ Не удалось скачать GeoIP базу")
                self.done_signal.emit(False)


class XrayCheckerWorker(QThread):
    log_signal = Signal(str)
    progress_signal = Signal(int, int)
    result_signal = Signal(list)

    def __init__(self, server_ip, server_port, snis, xray_path="xray.exe"):
        super().__init__()
        self.server_ip = server_ip
        self.server_port = server_port
        self.snis = snis
        self.xray_path = xray_path

    def run(self):
        asyncio.run(self.async_run())

    async def async_run(self):
        total = len(self.snis)
        self.log_signal.emit(f"\n🔍 Начало проверки {total} SNI через Xray-core Reality...\n")
        
        results = await test_snis_batch(
            self.server_ip,
            self.server_port,
            self.snis,
            self.xray_path,
            max_concurrent=1  # По одному, чтобы не конфликтовать
        )
        
        successful_snis = []
        for i, result in enumerate(results, 1):
            self.progress_signal.emit(i, total)
            
            if result["success"]:
                self.log_signal.emit(f"[{result['sni']}] ✅ Xray Reality: Успешное подключение!")
                successful_snis.append(result['sni'])
            else:
                self.log_signal.emit(f"[{result['sni']}] ❌ Xray Reality: {result['error']}")
        
        self.result_signal.emit(successful_snis)


class ScanWorker(QThread):
    log_signal = Signal(str)
    progress_signal = Signal(int, int)
    done_signal = Signal(list, list, list)

    def __init__(self, ip_list, domain_list, port, threads):
        super().__init__()
        self.ip_list = ip_list
        self.domain_list = domain_list
        self.port = port
        self.threads = threads

    def run(self):
        asyncio.run(self.async_run())

    async def async_run(self):
        rows = []
        discovered = set()
        total = len(self.ip_list) + len(self.domain_list)
        counter = 0

        def log(msg):
            self.log_signal.emit(msg)

        def update_progress():
            nonlocal counter
            counter += 1
            self.progress_signal.emit(counter, total)

        # 1. Сначала резолвим домены асинхронно
        ip_and_domains = []
        for domain in self.domain_list:
            try:
                ip_d = await asyncio.to_thread(socket.gethostbyname, domain)
                ip_and_domains.append((ip_d, domain))
            except:
                pass

        all_tasks = []
        for ip in self.ip_list:
            all_tasks.append(tls_sni_discover_async(ip, self.port, 4, None))

        for ip, domain in ip_and_domains:
            all_tasks.append(tls_sni_discover_async(ip, self.port, 4, domain))

        sem = asyncio.Semaphore(self.threads)

        async def worker(task):
            nonlocal rows, discovered
            async with sem:
                res = await task
                update_progress()
                if res.get("success"):
                    country_info = f"[IP: {res['ip_country'] or '?'}]"
                    if res.get('domain_country'):
                        country_info += f" [Domain: {res['domain_country']}]"
                    
                    log(f"{res['ip']} {country_info} ✅ {res['domain'] or ''} | TLS {res['tls'] or '-'} | ALPN {res['alpn'] or '-'} | ISSUER: {res['issuer'] or '-'}")
                    if res['domain']:
                        for dom in res['domain'].split(';'):
                            if dom not in discovered and dom != "" and "." in dom:
                                discovered.add(dom)
                else:
                    country_info = f"[{res['ip_country'] or '?'}]"
                    log(f"{res['ip']} {country_info} ❌ {res['error']}")
                rows.append(res)

        await asyncio.gather(*(worker(task) for task in all_tasks))
        self.done_signal.emit(rows, list(discovered), [])


class GeoDataWorker(QThread):
    log_signal = Signal(str)
    done_signal = Signal(list, list)

    def __init__(self, geoip_urls, geosite_urls):
        super().__init__()
        self.geoip_urls = geoip_urls
        self.geosite_urls = geosite_urls

    def run(self):
        asyncio.run(self.async_run())

    async def async_run(self):
        async with aiohttp.ClientSession() as session:
            geoip_task = read_geoip_urls_async(session, self.geoip_urls)
            geosite_task = read_geosite_urls_async(session, self.geosite_urls)
            ip_geo, dom_geo = await asyncio.gather(geoip_task, geosite_task)
            self.done_signal.emit(ip_geo, dom_geo)


class SniCheckerWorker(QThread):
    log_signal = Signal(str)
    progress_signal = Signal(int, int)
    result_signal = Signal(list)

    def __init__(self, ip, snis, port, concurrency):
        super().__init__()
        self.ip = ip
        self.snis = snis
        self.port = port
        self.concurrency = concurrency

    def run(self):
        asyncio.run(self.async_run())

    async def async_run(self):
        ok_snis = []
        total = len(self.snis)
        counter = 0

        def log(msg):
            self.log_signal.emit(msg)

        def update_progress():
            nonlocal counter
            counter += 1
            self.progress_signal.emit(counter, total)

        sem = asyncio.Semaphore(self.concurrency)

        async def check_sni(sni):
            nonlocal ok_snis
            async with sem:
                res = await tls_sni_discover_async(self.ip, self.port, 4, sni)
                update_progress()
                if res.get('success'):
                    country_info = f"[IP: {res['ip_country'] or '?'}]"
                    if res.get('domain_country'):
                        country_info += f" [Domain: {res['domain_country']}]"
                    log(f"[{sni}] {country_info} ==> ✅ TLS {res['tls']} | ISSUER: {res['issuer']}")
                    ok_snis.append(sni)
                else:
                    log(f"[{sni}] ==> ❌ {res['error']}")

        await asyncio.gather(*(check_sni(sni) for sni in self.snis))
        self.result_signal.emit(ok_snis)