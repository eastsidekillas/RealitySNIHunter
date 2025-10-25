"""Xray Core verification module for testing SNI connectivity."""

import asyncio
import json
import os
import platform
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp
from PySide6.QtCore import QObject, Signal


class XrayVerifier(QObject):
    """Verifies SNI using Xray Core."""

    progress_signal = Signal(str)
    result_signal = Signal(dict)

    XRAY_VERSION = "1.8.24"
    XRAY_DOWNLOAD_URLS = {
        "Windows": f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-windows-64.zip",
        "Linux": f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-linux-64.zip",
        "Darwin": f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-macos-64.zip"
    }

    def __init__(self):
        super().__init__()
        self.xray_path = None
        self.temp_dir = tempfile.mkdtemp(prefix="xray_")

    async def ensure_xray_installed(self) -> bool:
        """Download and install Xray Core if not present."""
        system = platform.system()
        xray_executable = "xray.exe" if system == "Windows" else "xray"

        # Check if xray already exists in temp directory
        xray_path = Path(self.temp_dir) / xray_executable
        if xray_path.exists():
            self.xray_path = str(xray_path)
            return True

        # Check if xray is in PATH
        xray_in_path = self._find_xray_in_path()
        if xray_in_path:
            self.xray_path = xray_in_path
            self.progress_signal.emit("✓ Xray Core найден в системе")
            return True

        # Download Xray Core
        download_url = self.XRAY_DOWNLOAD_URLS.get(system)
        if not download_url:
            self.progress_signal.emit(f"❌ Неподдерживаемая ОС: {system}")
            return False

        try:
            self.progress_signal.emit("⬇️ Загрузка Xray Core...")
            async with aiohttp.ClientSession() as session:
                async with session.get(download_url) as response:
                    if response.status != 200:
                        self.progress_signal.emit(f"❌ Ошибка загрузки: HTTP {response.status}")
                        return False

                    zip_path = Path(self.temp_dir) / "xray.zip"
                    with open(zip_path, 'wb') as f:
                        f.write(await response.read())

                    self.progress_signal.emit("📦 Распаковка Xray Core...")
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(self.temp_dir)

                    # Make executable on Unix systems
                    if system != "Windows":
                        os.chmod(xray_path, 0o755)

                    self.xray_path = str(xray_path)
                    self.progress_signal.emit("✓ Xray Core установлен")
                    return True

        except Exception as e:
            self.progress_signal.emit(f"❌ Ошибка установки Xray Core: {e}")
            return False

    def _find_xray_in_path(self) -> Optional[str]:
        """Find xray executable in system PATH."""
        try:
            result = subprocess.run(
                ["xray", "version"] if platform.system() != "Windows" else ["xray.exe", "version"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                return "xray.exe" if platform.system() == "Windows" else "xray"
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return None

    def _parse_vless_config(self, vless_link: str) -> Optional[Dict]:
        """Parse VLESS link to extract connection parameters."""
        try:
            if not vless_link.startswith("vless://"):
                return None

            # Remove vless:// prefix
            link = vless_link[8:]

            # Split user info and address
            if '@' not in link:
                return None

            user_info, rest = link.split('@', 1)

            # Split address and parameters
            if '?' not in rest:
                return None

            address_port, params = rest.split('?', 1)

            # Parse address and port
            if ':' not in address_port:
                return None

            address, port = address_port.rsplit(':', 1)

            # Parse URL parameters
            params_dict = {}
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params_dict[key] = value

            # Extract fragment (name) if present
            if '#' in params_dict.get('type', ''):
                params_dict['type'], name = params_dict['type'].split('#', 1)

            return {
                'uuid': user_info,
                'address': address,
                'port': int(port.split('#')[0]),
                'security': params_dict.get('security', 'reality'),
                'sni': params_dict.get('sni', 'www.google.com'),
                'fp': params_dict.get('fp', 'chrome'),
                'pbk': params_dict.get('pbk', ''),
                'sid': params_dict.get('sid', ''),
                'flow': params_dict.get('flow', 'xtls-rprx-vision'),
                'type': params_dict.get('type', 'tcp'),
                'encryption': params_dict.get('encryption', 'none')
            }

        except Exception as e:
            self.progress_signal.emit(f"⚠️ Ошибка парсинга VLESS: {e}")
            return None

    def _create_xray_config(self, server_config: Dict, test_sni: str) -> Dict:
        """Create Xray Core configuration for testing."""
        config = server_config.copy()
        config['sni'] = test_sni

        xray_config = {
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [{
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "udp": True
                }
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": config['address'],
                        "port": config['port'],
                        "users": [{
                            "id": config['uuid'],
                            "encryption": config['encryption'],
                            "flow": config['flow']
                        }]
                    }]
                },
                "streamSettings": {
                    "network": config['type'],
                    "security": config['security'],
                    "realitySettings": {
                        "serverName": config['sni'],
                        "fingerprint": config['fp'],
                        "show": False,
                        "publicKey": config['pbk'],
                        "shortId": config['sid'],
                        "spiderX": ""
                    }
                }
            }]
        }

        return xray_config

    async def _test_connection(self, config_path: str, timeout: int = 10) -> Tuple[bool, float, str]:
        """Test connection using Xray Core."""
        process = None
        try:
            # Start Xray Core
            process = await asyncio.create_subprocess_exec(
                self.xray_path,
                "run",
                "-c",
                config_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Wait for Xray to start
            await asyncio.sleep(2)

            # Test connection with HTTP request through SOCKS5 proxy
            import time
            start_time = time.time()

            connector = aiohttp.TCPConnector()
            async with aiohttp.ClientSession(connector=connector) as session:
                proxy = "socks5://127.0.0.1:10808"
                try:
                    async with session.get(
                        "http://www.gstatic.com/generate_204",
                        proxy=proxy,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=False
                    ) as response:
                        latency = (time.time() - start_time) * 1000  # Convert to ms

                        # Check if response is successful
                        if response.status == 204:
                            return True, latency, "OK"
                        else:
                            return False, latency, f"HTTP {response.status}"

                except asyncio.TimeoutError:
                    return False, 0, "Timeout"
                except aiohttp.ClientError as e:
                    return False, 0, f"Connection error: {str(e)[:50]}"

        except Exception as e:
            return False, 0, f"Error: {str(e)[:50]}"
        finally:
            if process:
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=2)
                except:
                    try:
                        process.kill()
                    except:
                        pass

    async def verify_sni_list(
        self,
        vless_config: str,
        sni_list: List[str],
        max_workers: int = 3
    ) -> List[Dict]:
        """Verify list of SNIs using Xray Core."""

        # Ensure Xray Core is installed
        if not await self.ensure_xray_installed():
            return []

        # Parse VLESS configuration
        server_config = self._parse_vless_config(vless_config)
        if not server_config:
            self.progress_signal.emit("❌ Не удалось распарсить VLESS конфигурацию")
            return []

        total_snis = len(sni_list)
        self.progress_signal.emit(f"🔍 Начало проверки ВСЕХ {total_snis} SNI через Xray Core...")
        self.progress_signal.emit(f"⚙️ Параллельных проверок: {max_workers}")
        self.progress_signal.emit(f"⏱️ Примерное время: ~{(total_snis * 12) // max_workers // 60} мин\n")

        results = []
        successful_count = 0
        failed_count = 0
        semaphore = asyncio.Semaphore(max_workers)

        async def test_single_sni(sni: str, index: int) -> Optional[Dict]:
            nonlocal successful_count, failed_count

            async with semaphore:
                try:
                    # Create temporary config file
                    xray_config = self._create_xray_config(server_config, sni)
                    config_path = Path(self.temp_dir) / f"config_{index}.json"

                    with open(config_path, 'w', encoding='utf-8') as f:
                        json.dump(xray_config, f, indent=2)

                    progress_percent = (index / total_snis) * 100
                    self.progress_signal.emit(
                        f"🧪 [{index}/{total_snis}] ({progress_percent:.1f}%) Тестирование: {sni}"
                    )

                    # Test connection
                    success, latency, status = await self._test_connection(str(config_path))

                    # Clean up config file
                    try:
                        config_path.unlink()
                    except:
                        pass

                    result = {
                        'sni': sni,
                        'success': success,
                        'latency': latency,
                        'status': status
                    }

                    if success:
                        successful_count += 1
                        self.progress_signal.emit(
                            f"✅ [{successful_count} успешных] {sni}: {latency:.0f}ms"
                        )
                    else:
                        failed_count += 1
                        if failed_count % 10 == 0:  # Логируем каждую 10-ю неудачу
                            self.progress_signal.emit(
                                f"❌ [{failed_count} неудач] Последний: {sni}: {status}"
                            )

                    return result

                except Exception as e:
                    failed_count += 1
                    self.progress_signal.emit(f"⚠️ Ошибка при тестировании {sni}: {e}")
                    return {
                        'sni': sni,
                        'success': False,
                        'latency': 0,
                        'status': f"Error: {str(e)[:50]}"
                    }

        # Test all SNIs
        tasks = [test_single_sni(sni, i + 1) for i, sni in enumerate(sni_list)]
        results = await asyncio.gather(*tasks)

        # Filter and sort results
        valid_results = [r for r in results if r and r['success']]
        valid_results.sort(key=lambda x: x['latency'])

        self.progress_signal.emit(f"\n{'='*60}")
        self.progress_signal.emit(f"✅ ПРОВЕРКА ЗАВЕРШЕНА")
        self.progress_signal.emit(f"{'='*60}")
        self.progress_signal.emit(f"📊 Проверено: {total_snis} SNI")
        self.progress_signal.emit(f"✅ Успешных: {len(valid_results)}")
        self.progress_signal.emit(f"❌ Неудачных: {total_snis - len(valid_results)}")
        self.progress_signal.emit(f"📈 Процент успеха: {(len(valid_results)/total_snis*100):.1f}%\n")

        return valid_results

    def cleanup(self):
        """Clean up temporary files."""
        try:
            import shutil
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            self.progress_signal.emit(f"⚠️ Ошибка очистки: {e}")
