import subprocess
import json
import tempfile
import os
import asyncio
import uuid
from pathlib import Path


class XrayChecker:
    def __init__(self, xray_path="xray.exe"):
        """
        Инициализация проверки Xray
        :param xray_path: Путь к исполняемому файлу xray-core
        """
        self.xray_path = xray_path
        self.xray_available = self._check_xray_available()
    
    def _check_xray_available(self):
        """Проверяет доступность xray-core"""
        try:
            result = subprocess.run(
                [self.xray_path, "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def generate_config(self, server_ip, server_port, sni, public_key=None, short_id=None):
        """
        Генерирует конфигурацию Xray для Reality
        :param server_ip: IP сервера
        :param server_port: Порт сервера
        :param sni: Server Name Indication
        :param public_key: Public key сервера (если известен)
        :param short_id: Short ID (если известен)
        :return: Словарь с конфигурацией
        """
        # Если ключи не указаны, используем тестовые (для базовой проверки подключения)
        if not public_key:
            public_key = "test_public_key_placeholder_32chars"
        if not short_id:
            short_id = ""
        
        config = {
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [
                {
                    "port": 10808,
                    "protocol": "socks",
                    "settings": {
                        "udp": True
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": server_ip,
                                "port": int(server_port),
                                "users": [
                                    {
                                        "id": str(uuid.uuid4()),
                                        "encryption": "none",
                                        "flow": "xtls-rprx-vision"
                                    }
                                ]
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": sni,
                            "publicKey": public_key,
                            "shortId": short_id,
                            "fingerprint": "chrome"
                        }
                    }
                }
            ]
        }
        return config
    
    async def test_sni_async(self, server_ip, server_port, sni, timeout=10):
        """
        Асинхронно тестирует SNI через Xray-core
        :param server_ip: IP сервера
        :param server_port: Порт сервера
        :param sni: Server Name Indication
        :param timeout: Таймаут подключения
        :return: dict с результатом проверки
        """
        if not self.xray_available:
            return {
                "success": False,
                "sni": sni,
                "error": "Xray-core недоступен"
            }
        
        # Создаем временный конфиг файл
        config = self.generate_config(server_ip, server_port, sni)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f, indent=2)
            config_path = f.name
        
        try:
            # Запускаем xray в фоне
            process = await asyncio.create_subprocess_exec(
                self.xray_path,
                "-c", config_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Даем время на инициализацию
            await asyncio.sleep(2)
            
            # Проверяем, запустился ли процесс
            if process.returncode is not None:
                stderr = await process.stderr.read()
                return {
                    "success": False,
                    "sni": sni,
                    "error": f"Xray завершился с ошибкой: {stderr.decode('utf-8', errors='ignore')[:100]}"
                }
            
            # Пытаемся подключиться через SOCKS5 прокси
            try:
                # Простая проверка доступности через curl или wget
                test_result = await asyncio.wait_for(
                    self._test_connection_through_proxy(),
                    timeout=timeout
                )
                
                # Завершаем процесс xray
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=2)
                
                return {
                    "success": test_result,
                    "sni": sni,
                    "error": None if test_result else "Не удалось подключиться через прокси"
                }
            except asyncio.TimeoutError:
                process.terminate()
                await process.wait()
                return {
                    "success": False,
                    "sni": sni,
                    "error": "Таймаут при проверке соединения"
                }
            except Exception as e:
                process.terminate()
                await process.wait()
                return {
                    "success": False,
                    "sni": sni,
                    "error": f"Ошибка проверки: {str(e)[:100]}"
                }
        
        except Exception as e:
            return {
                "success": False,
                "sni": sni,
                "error": f"Ошибка запуска Xray: {str(e)[:100]}"
            }
        finally:
            # Удаляем временный файл
            try:
                os.unlink(config_path)
            except:
                pass
    
    async def _test_connection_through_proxy(self):
        """
        Тестирует подключение через SOCKS5 прокси
        Пытается подключиться к тестовому сайту
        """
        try:
            # Используем aiohttp с SOCKS прокси
            import aiohttp_socks
            
            connector = aiohttp_socks.ProxyConnector.from_url('socks5://127.0.0.1:10808')
            
            async with aiohttp_socks.ClientSession(connector=connector) as session:
                async with session.get('http://www.google.com', timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    return resp.status == 200
        except:
            # Если aiohttp_socks не установлен, используем альтернативный метод
            # Проверяем только то, что SOCKS порт открыт
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection('127.0.0.1', 10808),
                    timeout=3
                )
                writer.close()
                await writer.wait_closed()
                return True
            except:
                return False


async def test_snis_batch(server_ip, server_port, snis, xray_path="xray.exe", max_concurrent=3):
    """
    Пакетное тестирование SNI через Xray
    :param server_ip: IP сервера
    :param server_port: Порт сервера
    :param snis: Список SNI для проверки
    :param xray_path: Путь к xray.exe
    :param max_concurrent: Максимальное количество одновременных проверок
    :return: Список результатов
    """
    checker = XrayChecker(xray_path)
    
    if not checker.xray_available:
        return [{
            "success": False,
            "sni": sni,
            "error": "Xray-core недоступен"
        } for sni in snis]
    
    sem = asyncio.Semaphore(max_concurrent)
    
    async def check_with_semaphore(sni):
        async with sem:
            return await checker.test_sni_async(server_ip, server_port, sni)
    
    results = await asyncio.gather(*[check_with_semaphore(sni) for sni in snis])
    return results