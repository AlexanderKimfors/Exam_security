from PyQt6.QtWidgets import QWidget, QPushButton, QTextEdit
from PyQt6.QtGui import QCloseEvent
from session import Session, SessionStatus

BTN_OFFSET = 7

BTN_Y = BTN_OFFSET
BTN_LENGTH = 150
BTN_WIDTH = 25

BTN_1_X = BTN_OFFSET
BTN_2_X = BTN_1_X + BTN_LENGTH + BTN_OFFSET
BTN_3_X = BTN_2_X + BTN_LENGTH + BTN_OFFSET

class Window(QWidget):
    def __init__(self, comparam: str, sessionparam: str):
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

        self.log = QTextEdit(self)
        self.log.setReadOnly(True)
        self.log.setGeometry(
        BTN_OFFSET,
        BTN_Y + BTN_WIDTH + BTN_OFFSET,
        self.width() - 2 * BTN_OFFSET,
        self.height() - BTN_WIDTH - 3 * BTN_OFFSET
        )

        self.session_active = False

        self.__session = Session(comparam, sessionparam)


    def handle_session(self):
        if not self.session_active:
            (status, timestamp) = self.__session.establish_session()
            if(status):
                self.__open_session()
                self.log_message(f"[{timestamp}]    Session established")
            else:
                self.log_message(f"[{timestamp}]    Session establishment failed")
        else:
            self.__close_session()


    def get_temperature(self):
        (status, timestamp, temperature) = self.__session.get_temperature()

        match status:
            case SessionStatus.OK:
                self.log_message(f"[{timestamp}]    Temperature: {temperature:.2f} °C")
            case SessionStatus.EXPIRED:
                self.log_message(f"[{timestamp}]    The session has expired.")
                self.session_active = False
                self.btn_session.setText("Establish session")
                self.btn_temp.setEnabled(False)
                self.btn_led.setEnabled(False)
    
            case SessionStatus.ERROR:
                self.log_message(f"[{timestamp}]    Could not read the temperature.")
    


    def toggle_led(self):
        (status, timestamp, led_state) = self.__session.toggle_led()

        match status:
            case SessionStatus.OK:
                self.log_message(f"[{timestamp}]    Led state is {led_state}")
            case SessionStatus.EXPIRED:
                self.log_message(f"[{timestamp}]    The session has expired.")
                self.session_active = False
                self.btn_session.setText("Establish session")
                self.btn_temp.setEnabled(False)
                self.btn_led.setEnabled(False)
    
            case SessionStatus.ERROR:
                self.log_message(f"[{timestamp}]    Could not toggle the LED.")

    def log_message(self, message: str):
        self.log.append(message)

    def closeEvent(self, event: QCloseEvent): # Think this should be gone, we dont want to close the session if escaping the window?
        if self.session_active:
            self.__session.close_session()
        event.accept()

    def __close_session(self):
        (status, timestamp) = self.__session.close_session()

        match status:
            case SessionStatus.OK:
                self.log_message(f"[{timestamp}]    Closed the session")
            case SessionStatus.EXPIRED:
                self.log_message(f"[{timestamp}]    The session has expired, closed sesssion")
            case SessionStatus.ERROR:
                self.log_message(f"[{timestamp}]    Something went wrong trying to close the session")

        self.session_active = False
        self.btn_session.setText("Establish session")
        self.btn_temp.setEnabled(False)
        self.btn_led.setEnabled(False)
    
    def __open_session(self):
        self.session_active = True
        self.btn_session.setText("Close session")
        self.btn_temp.setEnabled(True)
        self.btn_led.setEnabled(True)
        