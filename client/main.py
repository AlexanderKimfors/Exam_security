from PyQt6.QtWidgets import QApplication
from gui import Window

app = QApplication([])

window = Window()

window.show()

app.exec()