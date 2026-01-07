import serial

class Communication:
    def __init__(self, param: str):
        port, speed = param.split(":")
        speed = int(speed)

        self.__serial = serial.Serial()
        self.__serial.port=port
        self.__serial.baudrate=speed

        try:
            if not self.__serial.is_open:
                self.__serial.open()
        except serial.SerialException as e:
            print(f"Error opening serial communication: {e}")
            raise
    
    def __del__(self):
        if self.__serial.is_open:
            self.__serial.close()

                

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


