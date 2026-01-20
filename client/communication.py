import serial
import time

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
        """
        reads exactly the length specified
        """
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

    def receive_2(self, size: int) -> bytes:
        data = bytes()
        try:
            if self.__serial.is_open:
                self.__serial.reset_input_buffer()
                while self.__serial.in_waiting == 0:
                    pass
                time.sleep(0.2)
                data = self.__serial.read(min(size, self.__serial.in_waiting))
        except:
            pass

        return data
