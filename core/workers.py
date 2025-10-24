from PySide6.QtCore import QThread, Signal
import asyncio
import socket
import aiohttp
from .networking import (
    tls_sni_discover_async, read_geoip_urls_async,
    read_geosite_urls_async, auto_ip_range
)


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
                    log(f"{res['ip']} ✅ {res['domain'] or ''} | TLS {res['tls'] or '-'} | ALPN {res['alpn'] or '-'} | ISSUER: {res['issuer'] or '-'}")
                    if res['domain']:
                        for dom in res['domain'].split(';'):
                            if dom not in discovered and dom != "" and "." in dom:
                                discovered.add(dom)
                else:
                    log(f"{res['ip']} ❌ {res['error']}")
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
                    log(f"[{sni}] ==> ✅ TLS {res['tls']} | ISSUER: {res['issuer']}")
                    ok_snis.append(sni)
                else:
                    log(f"[{sni}] ==> ❌ {res['error']}")

        await asyncio.gather(*(check_sni(sni) for sni in self.snis))
        self.result_signal.emit(ok_snis)