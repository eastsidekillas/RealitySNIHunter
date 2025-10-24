import sys
import os
from PySide6.QtWidgets import QApplication
from ui.main_window import RealitySNIHunterApp


def load_qss_file(app, path="style.qss"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
    except FileNotFoundError:
        print(f"Ошибка: Файл стилей {path} не найден.")


if __name__ == "__main__":
    if os.getcwd() not in sys.path:
        sys.path.append(os.getcwd())

    app = QApplication(sys.argv)

    load_qss_file(app, "style.qss")

    win = RealitySNIHunterApp()
    win.show()

    sys.exit(app.exec())