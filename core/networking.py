import socket
import ssl
import hashlib
import ipaddress
import csv
import asyncio
import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def auto_ip_range(ip, extended=False):
    try:
        ipaddress.IPv4Address(ip)
        net = ipaddress.IPv4Network(f"{ip}/24" if extended else f"{ip}/28", strict=False)
        return [str(a) for a in net.hosts()]
    except:
        return []


async def get_my_ip_async(session):
    try:
        async with session.get("https://api-ipv4.ip.sb/ip", timeout=5) as resp:
            return (await resp.text()).strip()
    except Exception:
        return ""


def save_rows_to_csv(rows, path):
    with open(path, "w", newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f,
                                fieldnames=["ip", "tls", "alpn", "domain", "issuer", "fingerprint", "success", "error"])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def pick_best_sni(rows, topn=20):
    filtered = []
    for r in rows:
        if r.get('success') and r.get('tls') and 'TLSv1.3' in r['tls'] \
                and r.get('alpn') == 'h2' \
                and r.get('issuer') and ('Encrypt' in r['issuer'] or 'GlobalSign' in r['issuer']):
            for dom in r['domain'].split(';'):
                if dom not in filtered and '.' in dom:
                    filtered.append(dom)
    return filtered[:topn]


async def read_geoip_urls_async(session, urls):
    ips = []

    async def fetch(url):
        try:
            async with session.get(url, timeout=20) as resp:
                async for line in resp.content:
                    try:
                        parts = line.decode('utf-8').strip().split(',')
                        if len(parts) > 1 and '/' in parts[1]:
                            net = ipaddress.IPv4Network(parts[1], strict=False)
                            ips.extend([str(ip) for ip in net.hosts()])
                    except:
                        continue
        except Exception as e:
            print(f"geoip загрузка: {url} {e}")

    await asyncio.gather(*(fetch(url) for url in urls))
    return ips


async def read_geosite_urls_async(session, urls):
    domains = []

    async def fetch(url):
        try:
            async with session.get(url, timeout=20) as resp:
                async for line in resp.content:
                    try:
                        d = line.decode('utf-8').strip()
                        if '.' in d and not d.startswith('#') and not '//' in d:
                            domains.append(d)
                    except:
                        continue
        except Exception as e:
            print(f"geosite загрузка: {url} {e}")

    await asyncio.gather(*(fetch(url) for url in urls))
    return domains


async def tls_sni_discover_async(ip, port=443, timeout=4, domain_mode=None):
    context = ssl.create_default_context()
    context.set_ciphers('ECDHE+AESGCM')
    context.check_hostname = False
    context.set_alpn_protocols(['h2', 'http/1.1'])
    try:
        fut = asyncio.open_connection(ip, port, ssl=context, server_hostname=domain_mode, happy_eyeballs_delay=0.1)
        try:
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            raise socket.timeout('timeout')

        ssock = writer.get_extra_info('ssl_object')
        cert_bin = ssock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_bin, default_backend())

        names = []
        try:
            names += [a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
        except:
            pass
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names += ext.value.get_values_for_type(x509.DNSName)
        except:
            pass

        issuer = cert.issuer.rfc4514_string()
        alpn = ssock.selected_alpn_protocol()
        tlv = ssock.version()
        fp = hashlib.sha256(cert_bin).hexdigest()[:32]

        writer.close()
        await writer.wait_closed()

        names = [n for n in set(names) if '.' in n and not n.endswith('.local')]
        return {
            "ip": ip,
            "tls": tlv,
            "alpn": alpn,
            "domain": ";".join(names),
            "issuer": issuer[:30],
            "fingerprint": fp,
            "success": True
        }
    except Exception as e:
        return {
            "ip": ip,
            "success": False,
            "tls": None,
            "alpn": None,
            "domain": None,
            "issuer": None,
            "fingerprint": None,
            "error": str(e)[:60]
        }
