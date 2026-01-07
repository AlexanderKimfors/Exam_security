from PyQt6.QtWidgets import QApplication
from gui import Window
import sys

SERIAL_PORT, SERIAL_SPEED = sys.argv[1].split(":")
SECRET = sys.argv[2]

app = QApplication([])

window = Window(f"{SERIAL_PORT}:{SERIAL_SPEED}", SECRET)

window.show()

app.exec()