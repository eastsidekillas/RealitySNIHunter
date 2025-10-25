"""Networking utilities for RealitySNIHunter."""

import asyncio
import ssl
import socket
import csv
import ipaddress
import os
import sys
from pathlib import Path
from typing import Dict, Optional, List, Tuple
import maxminddb
import aiohttp

# Подавление ошибок ConnectionResetError на Windows
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Глобальная переменная для GeoIP базы
_geoip_reader = None


def load_geoip_db(path: str) -> bool:
    """Загрузка GeoIP базы Country.mmdb."""
    global _geoip_reader
    try:
        _geoip_reader = maxminddb.open_database(path)
        return True
    except Exception as e:
        print(f"Ошибка загрузки GeoIP базы: {e}")
        return False


def close_geoip_db():
    """Закрытие GeoIP базы."""
    global _geoip_reader
    if _geoip_reader:
        _geoip_reader.close()
        _geoip_reader = None


def get_country_code(ip: str) -> Optional[str]:
    """Получение кода страны по IP из GeoIP базы."""
    global _geoip_reader
    if not _geoip_reader:
        return None
    try:
        result = _geoip_reader.get(ip)
        if result and 'country' in result:
            return result['country'].get('iso_code')
        return None
    except Exception:
        return None


async def get_my_ip_async(session) -> str:
    """Получение публичного IP адреса."""
    try:
        async with session.get("https://api.ipify.org?format=text", timeout=10) as resp:
            if resp.status == 200:
                return (await resp.text()).strip()
    except:
        pass
    return "0.0.0.0"


def auto_ip_range(base_ip: str, extended: bool = False) -> list:
    """Генерация списка IP адресов в диапазоне."""
    try:
        ip_obj = ipaddress.IPv4Address(base_ip)
        network = ipaddress.IPv4Network(f"{base_ip}/24", strict=False)

        if extended:
            # Расширенный диапазон: все IP в /24 сети
            return [str(ip) for ip in network.hosts()]
        else:
            # Стандартный диапазон: ±5 IP от базового
            base_int = int(ip_obj)
            ips = []
            for offset in range(-5, 6):
                try:
                    new_ip = ipaddress.IPv4Address(base_int + offset)
                    if new_ip in network:
                        ips.append(str(new_ip))
                except:
                    continue
            return ips
    except:
        return [base_ip]


async def close_connection_safely(writer):
    """Безопасное закрытие SSL соединения без ошибок на Windows."""
    try:
        if writer and not writer.is_closing():
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except (asyncio.TimeoutError, ConnectionResetError, OSError):
                pass  # Игнорируем ошибки при закрытии
    except Exception:
        pass


async def tls_sni_discover_async(ip: str, port: int = 443, timeout: float = 3.0) -> Tuple[bool, Optional[str], Dict]:
    """
    Асинхронное TLS подключение для обнаружения SNI.

    Returns:
        Tuple[bool, Optional[str], Dict]: (успех, SNI/домен, детали соединения)
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context),
            timeout=timeout
        )

        ssl_object = writer.get_extra_info('ssl_object')
        if ssl_object:
            peercert = ssl_object.getpeercert()
            cipher = ssl_object.cipher()
            protocol = ssl_object.version()

            # Извлечение SNI/домена из сертификата
            sni = None
            if peercert:
                # Проверяем subjectAltName
                for ext in peercert.get('subjectAltName', []):
                    if ext[0] == 'DNS':
                        sni = ext[1]
                        break

                # Если нет в subjectAltName, берем из subject
                if not sni:
                    for item in peercert.get('subject', []):
                        for key, value in item:
                            if key == 'commonName':
                                sni = value
                                break

            details = {
                'protocol': protocol,
                'cipher': cipher[0] if cipher else 'Unknown',
                'cert': peercert
            }

            await close_connection_safely(writer)
            return True, sni, details

        await close_connection_safely(writer)
        return False, None, {}

    except (asyncio.TimeoutError, ConnectionRefusedError, ssl.SSLError, OSError):
        if writer:
            await close_connection_safely(writer)
        return False, None, {}


async def check_sni_with_target_async(target_ip: str, sni_domain: str, port: int = 443, timeout: float = 5.0) -> bool:
    """
    Проверка работоспособности SNI с целевым IP.

    Args:
        target_ip: IP адрес для проверки.
        sni_domain: SNI домен для проверки.
        port: Порт для подключения.
        timeout: Таймаут подключения.

    Returns:
        True если SNI работает с целевым IP, иначе False.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                target_ip,
                port,
                ssl=context,
                server_hostname=sni_domain
            ),
            timeout=timeout
        )

        await close_connection_safely(writer)
        return True

    except:
        if writer:
            await close_connection_safely(writer)
        return False


async def check_xray_functionality_async(
        ip: str,
        sni_domain: str,
        port: int = 443,
        timeout: float = 5.0
) -> Dict[str, str]:
    """
    Проверяет функциональность SNI для Xray, тестируя TLS-рукопожатие.

    Args:
        ip: IP-адрес вашего хостинга с Xray.
        sni_domain: Домен, который нужно использовать как SNI (проверяемый SNI).
        port: Порт Xray (обычно 443).
        timeout: Таймаут подключения в секундах.

    Returns:
        Словарь с результатами проверки.
    """

    # Создаем контекст TLS для подключения к целевому IP с указанным SNI
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Устанавливаем современные шифры
    try:
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    except:
        context.set_ciphers('DEFAULT')

    start_time = asyncio.get_event_loop().time()
    writer = None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip,
                port,
                ssl=context,
                server_hostname=sni_domain,
            ),
            timeout=timeout
        )

        connection_time = (asyncio.get_event_loop().time() - start_time) * 1000

        ssl_object = writer.get_extra_info('ssl_object')
        if ssl_object:
            cipher = ssl_object.cipher()
            protocol = ssl_object.version()

            await asyncio.sleep(0.5)

            try:
                peercert = ssl_object.getpeercert()
                cert_valid = peercert is not None
            except:
                cert_valid = False

            await close_connection_safely(writer)

            return {
                "sni": sni_domain,
                "ip": ip,
                "status": "OK",
                "latency": round(connection_time, 2),
                "protocol": protocol,
                "cipher": cipher[0] if cipher else "Unknown",
                "cert_valid": cert_valid,
                "details": f"Успешное TLS-рукопожатие ({protocol}, {connection_time:.0f}ms)"
            }
        else:
            await close_connection_safely(writer)

            return {
                "sni": sni_domain,
                "ip": ip,
                "status": "WARNING",
                "latency": round(connection_time, 2),
                "details": "TLS-рукопожатие выполнено, но SSL-объект недоступен"
            }

    except ConnectionResetError:
        if writer:
            await close_connection_safely(writer)
        connection_time = (asyncio.get_event_loop().time() - start_time) * 1000
        return {
            "sni": sni_domain,
            "ip": ip,
            "status": "BLOCKED",
            "latency": round(connection_time, 2),
            "details": "Соединение сброшено сразу после рукопожатия (возможна блокировка DPI)"
        }

    except asyncio.TimeoutError:
        if writer:
            await close_connection_safely(writer)
        return {
            "sni": sni_domain,
            "ip": ip,
            "status": "TIMEOUT",
            "latency": timeout * 1000,
            "details": f"Таймаут подключения ({timeout}s)"
        }

    except ssl.SSLError as e:
        if writer:
            await close_connection_safely(writer)
        connection_time = (asyncio.get_event_loop().time() - start_time) * 1000
        error_msg = str(e)

        if "certificate verify failed" in error_msg.lower():
            status = "CERT_ERROR"
        elif "handshake" in error_msg.lower():
            status = "HANDSHAKE_FAILED"
        elif "sslv3 alert" in error_msg.lower():
            status = "SSL_ALERT"
        else:
            status = "SSL_ERROR"

        return {
            "sni": sni_domain,
            "ip": ip,
            "status": status,
            "latency": round(connection_time, 2),
            "details": f"SSL ошибка: {error_msg[:100]}"
        }

    except Exception as e:
        if writer:
            await close_connection_safely(writer)
        connection_time = (asyncio.get_event_loop().time() - start_time) * 1000
        return {
            "sni": sni_domain,
            "ip": ip,
            "status": "FAILED",
            "latency": round(connection_time, 2),
            "details": f"Ошибка: {str(e)[:100]}"
        }


async def batch_check_xray_functionality(
        ip: str,
        sni_list: List[str],
        port: int = 443,
        max_workers: int = 10,
        timeout: float = 5.0
) -> List[Dict[str, str]]:
    """
    Пакетная проверка списка SNI на функциональность с Xray.
    """
    semaphore = asyncio.Semaphore(max_workers)

    async def check_with_semaphore(sni: str) -> Dict[str, str]:
        async with semaphore:
            return await check_xray_functionality_async(ip, sni, port, timeout)

    tasks = [check_with_semaphore(sni) for sni in sni_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    valid_results = []
    for result in results:
        if isinstance(result, dict):
            valid_results.append(result)
        else:
            valid_results.append({
                "sni": "unknown",
                "ip": ip,
                "status": "ERROR",
                "details": str(result)
            })

    return valid_results


async def download_geoip_db_async(url: str, save_path: str = "data/Country.mmdb") -> bool:
    """
    Асинхронная загрузка GeoIP базы Country.mmdb.
    """
    try:
        save_dir = Path(save_path).parent
        save_dir.mkdir(parents=True, exist_ok=True)

        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=60) as resp:
                if resp.status == 200:
                    content = await resp.read()

                    with open(save_path, 'wb') as f:
                        f.write(content)

                    print(f"GeoIP база успешно загружена: {save_path}")
                    return True
                else:
                    print(f"Ошибка загрузки: HTTP {resp.status}")
                    return False

    except Exception as e:
        print(f"Ошибка загрузки GeoIP базы: {e}")
        return False


async def read_geoip_urls_async(session: aiohttp.ClientSession, urls: List[str]) -> List[str]:
    """Загрузка и парсинг GeoIP данных."""
    all_ips = []

    for url in urls:
        try:
            async with session.get(url, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    ips = parse_geoip_dat(data)
                    all_ips.extend(ips)
        except Exception as e:
            print(f"Ошибка загрузки GeoIP из {url}: {e}")

    return all_ips


async def read_geosite_urls_async(session: aiohttp.ClientSession, urls: List[str]) -> List[str]:
    """Загрузка и парсинг Geosite данных."""
    all_domains = []

    for url in urls:
        try:
            async with session.get(url, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    domains = parse_geosite_dat(data)
                    all_domains.extend(domains)
        except Exception as e:
            print(f"Ошибка загрузки Geosite из {url}: {e}")

    return all_domains


def parse_geoip_dat(data: bytes) -> List[str]:
    """Парсинг бинарного формата geoip.dat."""
    ips = []

    try:
        i = 0
        while i < len(data) - 4:
            if data[i] <= 255 and data[i + 1] <= 255 and data[i + 2] <= 255 and data[i + 3] <= 255:
                if data[i] > 0 and data[i] < 240:
                    ip = f"{data[i]}.{data[i + 1]}.{data[i + 2]}.{data[i + 3]}"
                    try:
                        ipaddress.IPv4Address(ip)
                        ips.append(ip)
                    except:
                        pass
            i += 1

        ips = list(set(ips))[:1000]

    except Exception as e:
        print(f"Ошибка парсинга geoip.dat: {e}")

    return ips


def parse_geosite_dat(data: bytes) -> List[str]:
    """Парсинг бинарного формата geosite.dat."""
    domains = []

    try:
        text = data.decode('utf-8', errors='ignore')

        import re
        domain_pattern = r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}'
        found_domains = re.findall(domain_pattern, text.lower())

        for match in found_domains:
            if isinstance(match, tuple):
                domain = ''.join(match)
            else:
                domain = match

            if domain and '.' in domain and len(domain) > 4:
                domains.append(domain)

        domains = list(set(domains))[:500]

    except Exception as e:
        print(f"Ошибка парсинга geosite.dat: {e}")

    return domains


def save_rows_to_csv(rows: list, path: str):
    """Сохранение результатов в CSV файл."""
    if not rows:
        return

    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def pick_best_sni(rows: list, topn: int = 20, filter_country: Optional[List[str]] = None) -> list:
    """Выбор лучших SNI по критериям."""
    candidates = []

    for r in rows:
        sni = r.get('sni', '')
        if not sni:
            continue

        if filter_country:
            ip = r.get('ip', '')
            country = get_country_code(ip)
            if country not in filter_country:
                continue

        tls_version = r.get('tls_version', '')
        alpn = r.get('alpn', '')
        issuer = r.get('issuer', '')

        score = 0

        if 'TLSv1.3' in tls_version:
            score += 10
        elif 'TLSv1.2' in tls_version:
            score += 5

        if 'h2' in alpn:
            score += 8

        if 'Let\'s Encrypt' in issuer or 'letsencrypt' in issuer.lower():
            score += 5
        elif 'GlobalSign' in issuer:
            score += 5
        elif 'DigiCert' in issuer:
            score += 4
        elif 'Cloudflare' in issuer:
            score += 4

        candidates.append({
            'sni': sni,
            'score': score,
            'tls': tls_version,
            'alpn': alpn,
            'issuer': issuer,
            'ip': r.get('ip', ''),
            'country': get_country_code(r.get('ip', '')) if filter_country else None
        })

    candidates.sort(key=lambda x: x['score'], reverse=True)

    result = []
    for c in candidates[:topn]:
        country_info = f" [{c['country']}]" if c.get('country') else ""
        result.append(
            f"{c['sni']:40s} | TLS: {c['tls']:10s} | ALPN: {c['alpn']:15s} | CA: {c['issuer'][:30]:30s}{country_info}"
        )

    return result