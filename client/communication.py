import serial, sys

SERIAL_PORT, SERIAL_SPEED = sys.argv[1].split(":")

class Communication:
    def __init__(self):
        self.__serial = serial.Serial()
        self.__serial.port=SERIAL_PORT
        self.__serial.baudrate=SERIAL_SPEED
        self.__serial.bytesize=serial.EIGHTBITS
        self.__serial.parity=serial.PARITY_NONE
        self.__serial.stopbits=serial.STOPBITS_ONE
        self.__serial.timeout=3
                


    def send(self, buffer: bytes) -> bool:
        status = False

        try:
            if self.__serial.is_open:
                status = (len(buffer) == self.__serial.write(buffer))
        except serial.SerialException as e:
            print(f"Error sending data in serial communication: {e}")
            raise

        return status

    def receive(self, size: int) -> bytes:
        if not self.__serial.is_open:
            raise serial.SerialException("Serial is not open")

        try:
            data = self.__serial.read(size)
            if len(data) != size:
                raise serial.SerialException(f"Excpected {size} bytes, but read {len(data)} bytes")
        except Exception as e:
            print(f"Error receiving data: {e}")
            raise

        return data


    def open(self):
        try:
            if not self.__serial.is_open:
                self.__serial.open()
        except serial.SerialException as e:
            print(f"Error opening serial communication: {e}")
            raise

    def close(self):
        if self.__serial.is_open:
            self.__serial.close()
