import sys
import os
import aiohttp
import asyncio
from PySide6.QtWidgets import (
    QWidget, QLabel, QPushButton, QVBoxLayout,
    QLineEdit, QHBoxLayout, QMessageBox, QTextEdit, QFileDialog,
    QCheckBox, QProgressBar, QGroupBox, QTabWidget, QGridLayout, QFrame
)
from PySide6.QtCore import QThread, Signal, Qt

from core.workers import ScanWorker, SniCheckerWorker, GeoDataWorker
from core.networking import get_my_ip_async, auto_ip_range, save_rows_to_csv, pick_best_sni


class RealitySNIHunterApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RealitySNIHunter")


        self.rows = []
        self.valid_snis = []
        self.current_ip_list = []
        self.current_domain_list = []
        self.geo_worker = None
        self._ip_worker = None
        self._create_widgets()
        self._setup_ui()

        self.resize(1200, 800)

    # --- UI Setup Methods ---

    def _create_widgets(self):
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("IP (например, 1.1.1.1) для авто-диапазона и проверки SNI")

        self.port_edit = QLineEdit("443")
        self.port_edit.setPlaceholderText("Порт (443)")

        self.concurrent_edit = QLineEdit("300")
        self.concurrent_edit.setPlaceholderText("Параллельных задач (100-1000)")

        self.myip_btn = QPushButton("🌍 Мой IP")
        self.myip_btn.clicked.connect(self.fill_my_ip)

        self.ext_range_cb = QCheckBox("Расширенный диапазон (/24, до 250 IP)")
        self.ext_range_cb.setChecked(False)

        self.geoip_url_edit = QTextEdit()
        self.geoip_url_edit.setPlaceholderText("Ссылки на geoip.dat (каждая с новой строки)")

        self.geosite_url_edit = QTextEdit()
        self.geosite_url_edit.setPlaceholderText("Ссылки на geosite.dat (каждая с новой строки)")

        self.start_btn = QPushButton("🚀 Старт сканирования")
        self.start_btn.clicked.connect(self.start_scan)

        self.save_btn = QPushButton("💾 Сохранить CSV")
        self.save_btn.clicked.connect(self.save_results)
        self.save_btn.setEnabled(False)

        self.progress = QProgressBar()
        self.progress.setMinimum(0)
        self.progress.setMaximum(1)
        self.progress.setValue(0)

        self.status_label = QLabel("Ожидание запуска...")

        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)

        self.final_sni_output = QTextEdit()
        self.final_sni_output.setReadOnly(True)

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(self.result_output, "Лог сканирования и Детали")
        self.tab_widget.addTab(self.final_sni_output, "Лучшие SNI (Авто-фильтр)")

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)

        settings_group = QGroupBox("Параметры Сканирования")
        settings_layout = QGridLayout()

        settings_layout.addWidget(QLabel("IP / Диапазон:"), 0, 0)
        settings_layout.addWidget(self.ip_edit, 0, 1)
        settings_layout.addWidget(self.myip_btn, 0, 2)

        settings_layout.addWidget(QLabel("Порт:"), 1, 0)
        settings_layout.addWidget(self.port_edit, 1, 1)

        settings_layout.addWidget(QLabel("Потоки:"), 2, 0)
        settings_layout.addWidget(self.concurrent_edit, 2, 1)

        settings_layout.addWidget(self.ext_range_cb, 3, 1, 1, 2)

        settings_group.setLayout(settings_layout)
        main_layout.addWidget(settings_group)

        geo_group = QGroupBox("Дополнительные Источники")
        geo_layout = QHBoxLayout()

        geoip_frame = QFrame()
        geoip_vbox = QVBoxLayout(geoip_frame)
        geoip_vbox.addWidget(QLabel("🌐 **GeoIP** ссылки (диапазоны IP):"))
        geoip_vbox.addWidget(self.geoip_url_edit)

        geosite_frame = QFrame()
        geosite_vbox = QVBoxLayout(geosite_frame)
        geosite_vbox.addWidget(QLabel("🔗 **Geosite** ссылки (домены):"))
        geosite_vbox.addWidget(self.geosite_url_edit)

        geo_layout.addWidget(geoip_frame)
        geo_layout.addWidget(geosite_frame)
        geo_group.setLayout(geo_layout)
        main_layout.addWidget(geo_group)

        control_status_layout = QVBoxLayout()

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.save_btn)
        control_status_layout.addLayout(button_layout)

        control_status_layout.addWidget(self.status_label)
        control_status_layout.addWidget(self.progress)

        main_layout.addLayout(control_status_layout)

        main_layout.addWidget(self.tab_widget)

    def fill_my_ip(self):
        self.status_label.setText("Запрос вашего IP...")
        class MyIPWorker(QThread):
            ip_signal = Signal(str)

            def run(self):
                async def fetch_ip():
                    async with aiohttp.ClientSession() as session:
                        return await get_my_ip_async(session)

                ip = asyncio.run(fetch_ip())
                self.ip_signal.emit(ip)

        self._ip_worker = MyIPWorker()
        self._ip_worker.ip_signal.connect(self._handle_my_ip_result)
        self._ip_worker.start()

    def _handle_my_ip_result(self, ip):
        self.ip_edit.setText(ip)
        self.status_label.setText("IP установлен.")

    def log_write(self, text):
        if "✅" in text:
            html_text = f'<span style="color: green; font-weight: bold;">{text}</span>'
        elif "❌" in text:
            html_text = f'<span style="color: red; font-weight: bold;">{text}</span>'
        elif "🔥" in text or "🏆" in text:
            html_text = f'<span style="color: blue; font-weight: bold;">{text}</span>'
        else:
            html_text = text

        if self.tab_widget.currentIndex() != 0:
            self.tab_widget.setCurrentIndex(0)

        self.result_output.append(html_text)

    def update_progress(self, val, total):
        self.progress.setMaximum(total)
        self.progress.setValue(val)
        self.status_label.setText(f"Сканирование: {val} из {total} целей...")

    def set_running_state(self, is_running):
        self.start_btn.setEnabled(not is_running)
        self.save_btn.setEnabled(not is_running and bool(self.rows))
        self.ip_edit.setEnabled(not is_running)
        self.port_edit.setEnabled(not is_running)
        self.concurrent_edit.setEnabled(not is_running)
        self.myip_btn.setEnabled(not is_running)
        self.ext_range_cb.setEnabled(not is_running)
        self.geoip_url_edit.setEnabled(not is_running)
        self.geosite_url_edit.setEnabled(not is_running)
        self.start_btn.setText("🚀 Сканирование...") if is_running else self.start_btn.setText("🚀 Старт сканирования")

    def start_scan(self):
        ip = self.ip_edit.text().strip()
        if not ip:
            QMessageBox.warning(self, "Ошибка", "Укажи IP!")
            return

        self.set_running_state(True)
        self.rows = []
        self.final_sni_output.clear()
        self.result_output.clear()

        self.ip = ip
        self.port = int(self.port_edit.text() or 443)
        self.concurrency = max(50, min(int(self.concurrent_edit.text() or 300), 1000))

        self.current_ip_list = auto_ip_range(ip, self.ext_range_cb.isChecked())

        geoip_urls = [u.strip() for u in self.geoip_url_edit.toPlainText().split('\n') if u.strip()]
        geosite_urls = [u.strip() for u in self.geosite_url_edit.toPlainText().split('\n') if u.strip()]

        self.log_write(
            f"Подготовка: {len(self.current_ip_list)} IP-адресов в диапазоне. Асинхронных задач: {self.concurrency}\n")

        if geoip_urls or geosite_urls:
            self.status_label.setText("Загрузка Geo-данных...")
            self.progress.setRange(0, 0)
            self.log_write(
                f"Загружаем geoip ({len(geoip_urls)} ссылок) и geosite ({len(geosite_urls)} ссылок) параллельно...")
            self.geo_worker = GeoDataWorker(geoip_urls, geosite_urls)
            self.geo_worker.done_signal.connect(self._start_scan_with_geo)
            self.geo_worker.start()
        else:
            self._start_scan_with_geo([], [])

    def _start_scan_with_geo(self, ip_geo, dom_geo):
        self.progress.setRange(0, 1)
        if ip_geo:
            self.current_ip_list.extend(ip_geo)
            self.log_write(f"Добавлено {len(ip_geo)} IP из geoip!")
        if dom_geo:
            self.current_domain_list.extend(dom_geo)
            self.log_write(f"Добавлено {len(dom_geo)} доменов из geosite!")

        total = len(self.current_ip_list) + len(self.current_domain_list)
        self.log_write(f"Начало сканирования: {total} целей.\n")
        self.progress.setMaximum(total)
        self.progress.setValue(0)

        self.worker = ScanWorker(
            self.current_ip_list,
            self.current_domain_list,
            self.port,
            self.concurrency
        )
        self.worker.log_signal.connect(self.log_write)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.done_signal.connect(self._finish_scan)
        self.worker.start()

    def _finish_scan(self, rows, discovered, _):
        self.rows = rows
        fresh_SNI = [dom for dom in discovered if dom]
        self.valid_snis = fresh_SNI

        if fresh_SNI:
            self.log_write("\n--- ВСЕ НАЙДЕННЫЕ SNI ---")

        self.status_label.setText(f"Сканирование завершено. Найдено {len(fresh_SNI)} уникальных SNI. Проверка SNI...")


        self.progress.setMaximum(len(fresh_SNI))
        self.progress.setValue(0)
        self.log_write("\n--- ПРОЦЕСС ВЫБОРА ЛУЧШЕГО SNI ---")

        sni_concurrency = min(self.concurrency, 100)
        self.sni_worker = SniCheckerWorker(self.ip, fresh_SNI, self.port, sni_concurrency)
        self.sni_worker.log_signal.connect(self.log_write)
        self.sni_worker.progress_signal.connect(self.update_progress)
        self.sni_worker.result_signal.connect(self._finish_sni_check)
        self.sni_worker.start()

    def _finish_sni_check(self, ok_snis):
        self.set_running_state(False)
        self.status_label.setText("✅ Все задачи завершены!")
        self.final_sni_output.clear()
        self.final_sni_output.append("🔥 **Лучшие SNI, успешно работающие с целевым IP:**")
        self.final_sni_output.append("<p style='color: blue; font-weight: bold;'>\n" + "\n".join(ok_snis) + "</p>")
        self.final_sni_output.append("\n" + "-" * 40 + "\n")
        self.final_sni_output.append("🏆 **20 самых оптимальных SNI (TLSv1.3, ALPN h2, Let's Encrypt/GlobalSign):**")
        best_sni = pick_best_sni(self.rows, topn=20)
        self.final_sni_output.append("<p style='color: green; font-weight: bold;'>\n" + "\n".join(best_sni) + "</p>")

        self.log_write("\n--- АНАЛИЗ ЗАВЕРШЕН ---")
        self.tab_widget.setCurrentIndex(1)

    def save_results(self):
        if not self.rows:
            QMessageBox.warning(self, "Ошибка", "Нет результатов для экспорта")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Сохр. как CSV", "result.csv", "CSV (*.csv)")
        if path:
            save_rows_to_csv(self.rows, path)
            QMessageBox.information(self, "Готово", f"Сохранено в {path}")