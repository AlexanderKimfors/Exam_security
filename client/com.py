import serial

class SerialClient:
    def __init__(self, port, baudrate):
        self.port = port
        self.baudrate = baudrate
        self.ser = None

    def open(self):
        self.ser = serial.Serial(
            port=self.port,
            baudrate=self.baudrate,
            timeout=1
        )

    def send(self, data: bytes):
        self.ser.write(data)

    def receive(self) -> bytes:
        return self.ser.readline()
        
    
    def has_data(self) -> bool:
        return self.ser.in_waiting > 0

    def close(self):
        if self.ser.is_open:
            self.ser.close()
