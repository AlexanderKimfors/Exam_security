from communication import Communication
from mbedtls import cipher
from enum import IntEnum
import struct, random
import time


class SessionRequest(IntEnum):
    CLOSE = 0
    GET_TEMP = 1
    TOGGLE_LED = 2

class Session:
    def __init__(self, comparam: str, secret: str):
        self.__com = Communication(comparam)

        self.__session_state = False
        self.__session_id = bytes([0,0,0,0,0,0,0,0])
        self.__secret = secret.encode()
        self.__TAG_SIZE = 16
        self.__RAND_SIZE = 8
        self.__AES_IV_SIZE = 12
        self.__AES_KEY_SIZE = 32
        self.__SESSION_ID_SIZE = 8
        self.__TIME_STAMP_SIZE = 8



    def establish_session(self) -> tuple[bool, str]:
        status = True # Ändra efter jag har gjort error handling under funktionen
        # ======================================= First msg to send =======================================
        random.seed()
        AES_KEY = random.randbytes(self.__AES_KEY_SIZE)
        AES_IV = random.randbytes(self.__AES_IV_SIZE)
        RAND = random.randbytes(self.__RAND_SIZE)

        #                                                         AAD
        aes = cipher.AES.new(self.__secret, cipher.MODE_GCM, AES_IV, self.__session_id)

        cphr, tag = aes.encrypt(AES_KEY + RAND)

        message = AES_IV + cphr + tag
        self.__com.send(message)

        # ===================================== First msg to receive =======================================
        response = self.__com.receive(self.__AES_IV_SIZE + self.__SESSION_ID_SIZE + self.__TAG_SIZE)

        offset = 0
        AES_IV = response[offset : offset + self.__AES_IV_SIZE]
        offset += self.__AES_IV_SIZE
        cphr = response[offset: offset + self.__SESSION_ID_SIZE]
        offset +=  self.__SESSION_ID_SIZE
        tag = response[offset : offset + self.__TAG_SIZE]

        #                                                      AAD
        aes = cipher.AES.new(AES_KEY, cipher.MODE_GCM, AES_IV, RAND)
        session_id = aes.decrypt(cphr, tag)

        # ======================================= Second msg to send =======================================
        timestamp_us = time.time_ns() // 1_000
        timestamp_us_b = struct.pack(">Q", timestamp_us)

        AES_IV = random.randbytes(self.__AES_IV_SIZE)

        #                                                      AAD
        aes = cipher.AES.new(AES_KEY, cipher.MODE_GCM, AES_IV, session_id)
        cphr, tag = aes.encrypt(timestamp_us_b)

        message = AES_IV + cphr + tag
        self.__com.send(message)


        # ===================================== Second msg to receive ======================================
        response = self.__com.receive(self.__AES_IV_SIZE + self.__TIME_STAMP_SIZE + self.__TAG_SIZE)

        offset = 0 
        AES_IV = response[offset : offset + self.__AES_IV_SIZE]
        offset += self.__AES_IV_SIZE
        cphr = response[offset : offset + self.__TIME_STAMP_SIZE]
        offset += self.__TIME_STAMP_SIZE
        tag = response[offset : offset + self.__TAG_SIZE]

        aes = cipher.AES.new(AES_KEY, cipher.MODE_GCM, AES_IV, session_id)
        timestamp_us_b_received = aes.decrypt(cphr, tag)

        if(timestamp_us_b == timestamp_us_b_received):
            self.__session_state = True
            self.__session_id = session_id
            self.__key = AES_KEY
        else:
            # ???
            pass
        
        #DEBUG
        print(self.__session_state)

        readable_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_us / 1_000_000))
        return (status, readable_time)


    def close_session(self):
        self.__send_request(SessionRequest.CLOSE)
        self.__session_id = bytes([0,0,0,0,0,0,0,0])
    


    def toggle_led(self) -> str:
        timestamp_us = self.__send_request(SessionRequest.TOGGLE_LED)
        timestamp_sec = timestamp_us / 1_000_000
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))
        return timestamp_str
        

    def get_temperature(self) -> tuple[float, str]:

        self.__send_request(SessionRequest.GET_TEMP)

        # =========== Ta emot ett paket via UART med IV + temp + TAG ==============
        response = self.__com.receive(self.__AES_IV_SIZE + 4 + self.__TAG_SIZE)

        # ============== Packa upp meddelandet i IV, cipher, TAG ==================
        offset = 0
        AES_IV = response[offset : offset + self.__AES_IV_SIZE]
        offset += self.__AES_IV_SIZE
        cphr = response[offset: offset + 4]
        offset +=  4
        tag = response[offset : offset + self.__TAG_SIZE]

        # ====================== Dekryptera cipher till temp ======================
        #                                                      AAD
        aes = cipher.AES.new(self.__key, cipher.MODE_GCM, AES_IV, self.__session_id)
        temp = aes.decrypt(cphr, tag)

        temp = struct.unpack("<f", temp)[0]
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        return (temp, timestamp)
    

    def __send_request(self, req: SessionRequest) -> int:
        timestamp_us = time.time_ns() // 1_000
        timestamp_us_b = struct.pack(">Q", timestamp_us)

        AES_IV = random.randbytes(self.__AES_IV_SIZE)

        #                                                         AAD
        aes = cipher.AES.new(self.__key, cipher.MODE_GCM, AES_IV, self.__session_id)
        req_b = struct.pack(">B", req)
        msg = req_b + timestamp_us_b
        cphr, tag = aes.encrypt(msg)
        package = AES_IV + cphr + tag
        self.__com.send(package)

        return timestamp_us