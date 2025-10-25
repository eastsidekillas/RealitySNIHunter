import sys
import os
import aiohttp
import asyncio
from PySide6.QtWidgets import (
    QWidget, QLabel, QPushButton, QVBoxLayout,
    QLineEdit, QHBoxLayout, QMessageBox, QTextEdit, QFileDialog,
    QCheckBox, QProgressBar, QGroupBox, QTabWidget, QGridLayout, QFrame, QComboBox
)
from PySide6.QtCore import QThread, Signal, Qt
from core.workers import ScanWorker, SniCheckerWorker, GeoDataWorker, GeoIPDownloadWorker
from core.networking import (
    get_my_ip_async, auto_ip_range, save_rows_to_csv,
    pick_best_sni, load_geoip_db, close_geoip_db
)


class RealitySNIHunterApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RealitySNIHunter v0.2")
        self.rows = []
        self.valid_snis = []
        self.current_ip_list = []
        self.current_domain_list = []
        self.geo_worker = None
        self._ip_worker = None
        self.geoip_db_loaded = False
        self._create_widgets()
        self._setup_ui()
        self.resize(1200, 800)

        # Попытка загрузить существующую базу при запуске
        if load_geoip_db("data/Country.mmdb"):
            self.geoip_db_loaded = True
            self.geoip_status_label.setText("✅ GeoIP база загружена")


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

        # GeoIP Country.mmdb
        self.geoip_mmdb_url_edit = QLineEdit(
            "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb")
        self.geoip_mmdb_url_edit.setPlaceholderText("Ссылка на Country.mmdb")

        self.download_geoip_btn = QPushButton("📥 Загрузить GeoIP базу")
        self.download_geoip_btn.clicked.connect(self.download_geoip_db)

        self.geoip_status_label = QLabel("❌ GeoIP база не загружена")

        # Фильтр по стране
        self.country_filter_label = QLabel("Фильтр по странам (для топ-20):")
        self.country_filter_edit = QLineEdit()
        self.country_filter_edit.setPlaceholderText("Коды стран через запятую (RU,US,DE) или оставьте пустым")

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

    def _create_separator(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        return line

    def _create_settings_tab(self):
        settings_widget = QWidget()
        main_layout = QVBoxLayout(settings_widget)

        geoip_mmdb_group = QGroupBox("🌍 GeoIP Country Database (Country.mmdb)")
        geoip_mmdb_layout = QVBoxLayout()

        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Ссылка для загрузки:"))
        url_layout.addWidget(self.geoip_mmdb_url_edit)
        url_layout.addWidget(self.download_geoip_btn)

        geoip_mmdb_layout.addLayout(url_layout)
        geoip_mmdb_layout.addWidget(self.geoip_status_label)

        # Фильтр по стране
        country_filter_layout = QHBoxLayout()
        country_filter_layout.addWidget(self.country_filter_label)
        country_filter_layout.addWidget(self.country_filter_edit)
        geoip_mmdb_layout.addLayout(country_filter_layout)

        geoip_mmdb_group.setLayout(geoip_mmdb_layout)
        main_layout.addWidget(geoip_mmdb_group)

        main_layout.addWidget(self._create_separator())

        geo_group = QGroupBox("Дополнительные Geo Источники (GeoIP / Geosite)")
        geo_layout = QHBoxLayout()

        geoip_frame = QFrame()
        geoip_vbox = QVBoxLayout(geoip_frame)
        geoip_vbox.addWidget(QLabel("🌐 GeoIP ссылки (диапазоны IP):"))
        geoip_vbox.addWidget(self.geoip_url_edit)

        geosite_frame = QFrame()
        geosite_vbox = QVBoxLayout(geosite_frame)
        geosite_vbox.addWidget(QLabel("🔗 Geosite ссылки (домены):"))
        geosite_vbox.addWidget(self.geosite_url_edit)

        geo_layout.addWidget(geoip_frame)
        geo_layout.addWidget(geosite_frame)
        geo_group.setLayout(geo_layout)
        main_layout.addWidget(geo_group)

        main_layout.addStretch(1)
        return settings_widget

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)

        main_tab_widget = QWidget()
        main_tab_layout = QVBoxLayout(main_tab_widget)

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
        main_tab_layout.addWidget(settings_group)

        control_status_layout = QVBoxLayout()
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.save_btn)
        control_status_layout.addLayout(button_layout)
        control_status_layout.addWidget(self.status_label)
        control_status_layout.addWidget(self.progress)
        main_tab_layout.addLayout(control_status_layout)

        main_tab_layout.addStretch(1)

        settings_tab_widget = self._create_settings_tab()

        self.primary_tab_widget = QTabWidget()
        self.primary_tab_widget.addTab(main_tab_widget, "Главная")
        self.primary_tab_widget.addTab(settings_tab_widget, "Настройки")

        main_layout.addWidget(self.primary_tab_widget)

        self.result_tab_widget = QTabWidget()
        self.result_tab_widget.addTab(self.result_output, "Лог сканирования и Детали")
        self.result_tab_widget.addTab(self.final_sni_output, "Лучшие SNI (Авто-фильтр)")

        main_layout.addWidget(self.result_tab_widget)

    def download_geoip_db(self):
        url = self.geoip_mmdb_url_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Укажите ссылку на Country.mmdb!")
            return

        if self.geoip_db_loaded:
            close_geoip_db()
            self.geoip_db_loaded = False

        self.download_geoip_btn.setEnabled(False)
        self.geoip_status_label.setText("⏳ Загрузка GeoIP базы...")

        self.geoip_download_worker = GeoIPDownloadWorker(url)
        self.geoip_download_worker.log_signal.connect(self.log_write)
        self.geoip_download_worker.done_signal.connect(self._handle_geoip_download)
        self.geoip_download_worker.start()

    def _handle_geoip_download(self, success):
        self.download_geoip_btn.setEnabled(True)
        if success:
            self.geoip_db_loaded = True
            self.geoip_status_label.setText("✅ GeoIP база загружена")
        else:
            self.geoip_db_loaded = False
            self.geoip_status_label.setText("❌ Ошибка загрузки GeoIP базы")

    def log_write(self, text):
        if "✅" in text:
            html_text = f'<span style="color: #4CAF50;">{text}</span>'
        elif "❌" in text:
            html_text = f'<span style="color: #f44336;">{text}</span>'
        elif "🔥" in text or "🏆" in text:
            html_text = f'<span style="color: #FFC107; font-weight: bold;">{text}</span>'
        else:
            html_text = text

        # используем переключение на лог
        if self.result_tab_widget.currentIndex() != 0:
            self.result_tab_widget.setCurrentIndex(0)

        self.result_output.append(html_text)

    def _finish_sni_check(self, ok_snis):
        self.set_running_state(False)
        self.status_label.setText("✅ Все задачи завершены!")

        self.final_sni_output.clear()
        self.final_sni_output.append("🔥 **Лучшие SNI, успешно работающие с целевым IP:**")
        self.final_sni_output.append("\n" + "\n".join(ok_snis) + "\n\n")

        self.final_sni_output.append("\n" + "-" * 40 + "\n")

        country_filter_text = self.country_filter_edit.text().strip().upper()
        country_filter = [c.strip() for c in country_filter_text.split(',')] if country_filter_text else None

        if country_filter:
            self.final_sni_output.append(
                f"🏆 **20 самых оптимальных SNI (TLSv1.3, ALPN h2, Let's Encrypt/GlobalSign) для стран: {', '.join(country_filter)}:**")
        else:
            self.final_sni_output.append("🏆 **20 самых оптимальных SNI (TLSv1.3, ALPN h2, Let's Encrypt/GlobalSign):**")

        best_sni = pick_best_sni(self.rows, topn=20, filter_country=country_filter)

        if not best_sni and country_filter:
            self.final_sni_output.append("\n⚠️ Не найдено SNI для указанных стран. Попробуйте без фильтра.\n")
        else:
            self.final_sni_output.append("\n" + "\n".join(best_sni) + "\n\n")

        self.log_write("\n--- АНАЛИЗ ЗАВЕРШЕН ---")

        # переключаем на итоговые результы, тк поменяли виджеты
        self.result_tab_widget.setCurrentIndex(1)

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
        self.download_geoip_btn.setEnabled(not is_running)
        self.start_btn.setText("🚀 Сканирование...") if is_running else self.start_btn.setText("🚀 Старт сканирования")

    def start_scan(self):
        ip = self.ip_edit.text().strip()
        if not ip:
            QMessageBox.warning(self, "Ошибка", "Укажи IP!")
            return

        if not self.geoip_db_loaded:
            reply = QMessageBox.question(
                self,
                "GeoIP база не загружена",
                "GeoIP база Country.mmdb не загружена. Фильтрация по странам будет недоступна.\n\nПродолжить сканирование?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
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
            self.status_label.setText(
                f"Сканирование завершено. Найдено {len(fresh_SNI)} уникальных SNI. Проверка SNI...")
            self.progress.setMaximum(len(fresh_SNI))
            self.progress.setValue(0)

            self.log_write("\n--- ПРОЦЕСС ВЫБОРА ЛУЧШЕГО SNI ---")

            sni_concurrency = min(self.concurrency, 100)
            self.sni_worker = SniCheckerWorker(self.ip, fresh_SNI, self.port, sni_concurrency)
            self.sni_worker.log_signal.connect(self.log_write)
            self.sni_worker.progress_signal.connect(self.update_progress)
            self.sni_worker.result_signal.connect(self._finish_sni_check)
            self.sni_worker.start()
        else:
            self.status_label.setText("Сканирование завершено. Подходящих SNI не найдено.")
            self.progress.setMaximum(1)
            self.progress.setValue(1)
            self.log_write("\n❌ **Сканирование завершено.** Подходящих SNI для проверки не найдено.")

            self.set_running_state(False)

    def save_results(self):
        if not self.rows:
            QMessageBox.warning(self, "Ошибка", "Нет результатов для экспорта")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Сохр. как CSV", "result.csv", "CSV (*.csv)")
        if path:
            save_rows_to_csv(self.rows, path)
            QMessageBox.information(self, "Готово", f"Сохранено в {path}")

    def closeEvent(self, event):
        """Закрываем базу GeoIP при выходе"""
        close_geoip_db()
        event.accept()