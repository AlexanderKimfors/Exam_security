from PyQt6.QtWidgets import QWidget, QPushButton

BTN_Y = 7
BTN_LENGTH = 150
BTN_WIDTH = 25

BTN_1_X = 7
BTN_2_X = BTN_1_X + BTN_LENGTH + 7
BTN_3_X = BTN_2_X + BTN_LENGTH + 7



class Window(QWidget):
    def __init__(self):
        super().__init__()

        self.setStyleSheet("""
        QWidget {
            background-color: black;
            color: white;
            font-size: 12px;
        }
        QPushButton {
            background-color: #222;
            border: 1px solid #555;
            padding: 5px;
        }
        QPushButton:hover {
            background-color: #333;
        }
        QPushButton:disabled {
            background-color: #111;
            color: #666;
        }
        """)


        self.setWindowTitle("Client")
        self.setGeometry(600, 200, 600, 500)

        self.btn_session = QPushButton("Establish session", self)
        self.btn_session.setGeometry(BTN_1_X, BTN_Y, BTN_LENGTH, BTN_WIDTH)
        self.btn_session.clicked.connect(self.handle_session)


        self.btn_temp = QPushButton("Get temperature", self)
        self.btn_temp.setGeometry(BTN_2_X, BTN_Y, BTN_LENGTH, BTN_WIDTH)
        self.btn_temp.clicked.connect(self.get_temperature)

        self.btn_led = QPushButton("Toggle LED", self)
        self.btn_led.setGeometry(BTN_3_X, BTN_Y, BTN_LENGTH, BTN_WIDTH)
        self.btn_led.clicked.connect(self.toggle_led)

        self.btn_temp.setEnabled(False)
        self.btn_led.setEnabled(False)

        self.session_active = False


    def handle_session(self):
        if not self.session_active:
            print("Establishing session...")
            self.session_active = True
            self.btn_session.setText("Close session")
            self.btn_temp.setEnabled(True)
            self.btn_led.setEnabled(True)
        else:
            print("Closing session...")
            self.session_active = False
            self.btn_session.setText("Establish session")
            self.btn_temp.setEnabled(False)
            self.btn_led.setEnabled(False)


    def get_temperature(self):
        print("Get temperature pressed")

    def toggle_led(self):
        print("Toggle LED pressed")