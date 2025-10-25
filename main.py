"""Main entry point for RealitySNIHunter."""

import sys
from PySide6.QtWidgets import QApplication
from ui.main_window import RealitySNIHunterApp


def main():
    app = QApplication(sys.argv)

    # Загрузка стилей
    try:
        with open('style.qss', 'r', encoding='utf-8') as f:
            app.setStyleSheet(f.read())
    except FileNotFoundError:
        print("⚠️ Файл style.qss не найден, используется стандартная тема")

    window = RealitySNIHunterApp()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
