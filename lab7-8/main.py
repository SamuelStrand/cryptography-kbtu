import sys
from PyQt6.QtWidgets import QApplication
from gui import DigitalSignatureApp

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DigitalSignatureApp()
    window.show()
    sys.exit(app.exec())
