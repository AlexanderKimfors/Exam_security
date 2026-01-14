import serial

class Communication:
    def __init__(self, param: str):
        port, speed = param.split(":")
        speed = int(speed)
        self.__serial = serial.Serial(port, speed)

    
    def __del__(self):
        try:
            if self.__serial.is_open:
                self.__serial.close()
        except:
            pass


    def send(self, buffer: bytes) -> bool:
        status = False

        try:
            if self.__serial.is_open:
                self.__serial.reset_output_buffer()
                status = (len(buffer) == self.__serial.write(buffer))
        except:
            pass

        return status

    def receive(self, size: int) -> bytes:
        data = bytes()
        try:
            if self.__serial.is_open:
                self.__serial.reset_input_buffer()
                data = self.__serial.read(size)
            if len(data) != size:
                data = bytes()
        except:
            pass

        return data
