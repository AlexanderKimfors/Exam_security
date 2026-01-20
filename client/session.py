from communication import Communication
from mbedtls import cipher
from enum import IntEnum
import struct, random
import time
import hashlib


class SessionRequest(IntEnum):
    CLOSE = 0
    GET_TEMP = 1
    TOGGLE_LED = 2
    TIMEOUT = 3

class SessionStatus(IntEnum):
    EXPIRED = -1
    ERROR = 0
    OK = 1


class Session:
    def __init__(self, comparam: str, secret: str):
        self.__com = Communication(comparam)

        self.__session_id = bytes([0,0,0,0,0,0,0,0])
        self.__secret = hashlib.sha256(secret.encode()).digest()

        self.__TAG_SIZE = 16
        self.__RAND_SIZE = 8
        self.__AES_IV_SIZE = 12
        self.__AES_KEY_SIZE = 32
        self.__SESSION_ID_SIZE = 8
        self.__TIME_STAMP_SIZE = 8
        self.__REQ_SIZE = 1
        self.__STATUS_SIZE = 1
        self.__LED_STATE_SIZE = 1
        self.__TEMPERATURE_SIZE = 4

    def establish_session(self) -> tuple[bool, str]:
        status = True 
        readable_time = ""
        # ======================================= First msg to send =======================================
        random.seed()
        key = random.randbytes(self.__AES_KEY_SIZE)
        iv = random.randbytes(self.__AES_IV_SIZE)
        RAND = random.randbytes(self.__RAND_SIZE)
        try:
            aes = cipher.AES.new(
                self.__secret,
                cipher.MODE_GCM,
                iv,
                self.__session_id) # AAD
            
            cphr, tag = aes.encrypt(key + RAND)

            message = iv + cphr + tag
            status = self.__com.send(message)

            # ===================================== First msg to receive =======================================
            if status:
                len_to_read = self.__AES_IV_SIZE + self.__SESSION_ID_SIZE + self.__TAG_SIZE
                response = self.__com.receive(len_to_read)

                if len(response) == len_to_read:
                    offset = 0
                    iv = response[offset : offset + self.__AES_IV_SIZE]
                    offset += self.__AES_IV_SIZE
                    cphr = response[offset: offset + self.__SESSION_ID_SIZE]
                    offset +=  self.__SESSION_ID_SIZE
                    tag = response[offset : offset + self.__TAG_SIZE]
                
                    aes = cipher.AES.new(
                        key,
                        cipher.MODE_GCM,
                        iv,
                        RAND) # AAD
                    
                    session_id = aes.decrypt(cphr, tag)

                    # ======================================= Second msg to send =======================================
                    timestamp_us = time.time_ns() // 1_000
                    timestamp_us_b = struct.pack(">Q", timestamp_us)

                    iv = random.randbytes(self.__AES_IV_SIZE)

                    aes = cipher.AES.new(
                        key,
                        cipher.MODE_GCM,
                        iv,
                        session_id) # AAD
                    
                    cphr, tag = aes.encrypt(timestamp_us_b)

                    message = iv + cphr + tag
                    status = self.__com.send(message)

                    # ===================================== Second msg to receive ======================================
                    if status:
                        len_to_read = self.__AES_IV_SIZE + self.__TIME_STAMP_SIZE + self.__TAG_SIZE
                        response = self.__com.receive(self.__AES_IV_SIZE + self.__TIME_STAMP_SIZE + self.__TAG_SIZE)

                        if len(response) == len_to_read:
                            offset = 0 
                            iv = response[offset : offset + self.__AES_IV_SIZE]
                            offset += self.__AES_IV_SIZE
                            cphr = response[offset : offset + self.__TIME_STAMP_SIZE]
                            offset += self.__TIME_STAMP_SIZE
                            tag = response[offset : offset + self.__TAG_SIZE]

                            aes = cipher.AES.new(
                                key,
                                cipher.MODE_GCM,
                                iv,
                                session_id) # AAD
                            
                            timestamp_us_b_received = aes.decrypt(cphr, tag)

                            if(timestamp_us_b == timestamp_us_b_received):
                                self.__session_id = session_id
                                self.__key = key
                            else:
                                status = False

                            timestamp_us_received = struct.unpack(">Q", timestamp_us_b_received)[0]
                            readable_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_us_received / 1_000_000))
                else:
                    status = False
        except:
            status = False

        

        return (status, readable_time)

    def close_session(self) -> tuple[SessionStatus, str]:
        self.__send_request(SessionRequest.CLOSE)

        receive_size = self.__AES_IV_SIZE + self.__STATUS_SIZE + self.__TIME_STAMP_SIZE + self.__TAG_SIZE
        response = self.__com.receive(receive_size)

        if len(response) == receive_size:
            offset = 0
            iv = response[offset : offset + self.__AES_IV_SIZE]
            offset += self.__AES_IV_SIZE
            cphr = response[offset: offset + self.__STATUS_SIZE + self.__TIME_STAMP_SIZE]
            offset += (self.__STATUS_SIZE + self.__TIME_STAMP_SIZE)
            tag = response[offset : offset + self.__TAG_SIZE]

            aes = cipher.AES.new(
                self.__key, 
                cipher.MODE_GCM,
                iv,
                self.__session_id  # AAD
            )
            plaintext = aes.decrypt(cphr, tag)

            offset = 0
            status = SessionStatus(struct.unpack(">b", plaintext[0:self.__STATUS_SIZE])[0])
            offset += self.__STATUS_SIZE
            time_us_received = struct.unpack(">Q", plaintext[offset: offset + self.__TIME_STAMP_SIZE])[0]

            timestamp_sec = time_us_received / 1_000_000
            timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))

            self.__session_id = bytes(self.__SESSION_ID_SIZE)
            self.__key = None
        
        return (status, timestamp_str)


    def toggle_led(self) -> tuple[SessionStatus, str, bool]:
        """
        Returns (status, timestamp, led_state)
        """
        if self.__send_request(SessionRequest.TOGGLE_LED):
            response = self.__com.receive(self.__AES_IV_SIZE + self.__STATUS_SIZE + self.__TIME_STAMP_SIZE + self.__LED_STATE_SIZE + self.__TAG_SIZE)

            if (len(response) == (self.__AES_IV_SIZE + self.__STATUS_SIZE + self.__TIME_STAMP_SIZE + self.__LED_STATE_SIZE + self.__TAG_SIZE)):
                offset = 0
                iv = response[offset : offset + self.__AES_IV_SIZE]
                offset += self.__AES_IV_SIZE
                cphr = response[offset: offset + self.__STATUS_SIZE + self.__TIME_STAMP_SIZE + self.__LED_STATE_SIZE]
                offset += (self.__STATUS_SIZE + self.__TIME_STAMP_SIZE + self.__LED_STATE_SIZE)
                tag = response[offset : offset + self.__TAG_SIZE]

                aes = cipher.AES.new(
                    self.__key,
                    cipher.MODE_GCM,
                    iv,
                    self.__session_id # AAD
                )

                plaintext = aes.decrypt(cphr, tag)

                offset = 0
                status = SessionStatus(struct.unpack(">b", plaintext[offset:self.__STATUS_SIZE])[0])
                offset += self.__STATUS_SIZE
                time_us_received = struct.unpack(">Q", plaintext[self.__STATUS_SIZE:offset + self.__TIME_STAMP_SIZE])[0]
                offset += self.__TIME_STAMP_SIZE
                led_state = plaintext[offset]

                if status == SessionStatus.OK:
                    timestamp_sec = time_us_received / 1_000_000
                    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))

            elif (len(response) == (self.__AES_IV_SIZE + self.__STATUS_SIZE + self.__TIME_STAMP_SIZE + self.__TAG_SIZE)):
                offset = 0
                iv = response[offset : offset + self.__AES_IV_SIZE]
                offset += self.__AES_IV_SIZE
                cphr = response[offset: offset + self.__STATUS_SIZE + self.__TIME_STAMP_SIZE]
                offset += (self.__STATUS_SIZE + self.__TIME_STAMP_SIZE)
                tag = response[offset : offset + self.__TAG_SIZE]

                aes = cipher.AES.new(
                    self.__key,
                    cipher.MODE_GCM,
                    iv,
                    self.__session_id # AAD
                )
                plaintext = aes.decrypt(cphr, tag)

                offset = 0
                status = SessionStatus(struct.unpack(">b", plaintext[offset:offset + self.__STATUS_SIZE])[0])
                offset += self.__STATUS_SIZE
                time_us_received = struct.unpack(">Q", plaintext[offset:offset + self.__TIME_STAMP_SIZE])[0]

                if status:
                    timestamp_sec = time_us_received / 1_000_000
                    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))

                led_state = 0
                self.__session_id = bytes([0,0,0,0,0,0,0,0])

            else:
                status = SessionStatus.ERROR
                timestamp_str = ""
                led_state = 0
        
        return (status, timestamp_str, led_state)
        

    def get_temperature(self) -> tuple[SessionStatus, str, float]:
        """
        Returns (status, timestamp, temperature)
        """
        status = self.__send_request(SessionRequest.GET_TEMP)
        if status:

            response = self.__com.receive(self.__AES_IV_SIZE + self.__STATUS_SIZE + self.__TIME_STAMP_SIZE + self.__TEMPERATURE_SIZE + self.__TAG_SIZE) # receive_2

            if(len(response) == self.__AES_IV_SIZE + self.__STATUS_SIZE + self.__TIME_STAMP_SIZE + self.__TEMPERATURE_SIZE + self.__TAG_SIZE):
                offset = 0
                iv = response[offset : offset + self.__AES_IV_SIZE]
                offset += self.__AES_IV_SIZE
                cphr = response[offset: offset + 1 + self.__TIME_STAMP_SIZE + self.__TEMPERATURE_SIZE]
                offset += (1 + self.__TIME_STAMP_SIZE + self.__TEMPERATURE_SIZE)
                tag = response[offset : offset + self.__TAG_SIZE]

                aes = cipher.AES.new(
                    self.__key, 
                    cipher.MODE_GCM,
                    iv, self.__session_id  # AAD
                )
                plaintext = aes.decrypt(cphr, tag)

                offset = 0
                status = SessionStatus(struct.unpack(">b", plaintext[offset:self.__STATUS_SIZE])[0])
                offset += self.__STATUS_SIZE
                time_us_received = struct.unpack(">Q", plaintext[offset: offset + self.__TIME_STAMP_SIZE])[0]
                offset += self.__TIME_STAMP_SIZE
                temp_b = plaintext[offset: offset + self.__TEMPERATURE_SIZE]

                temperature = struct.unpack(">f", temp_b)[0]
                timestamp_sec = time_us_received / 1_000_000
                timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))

            elif(len(response) == self.__AES_IV_SIZE + self.__STATUS_SIZE + self.__TIME_STAMP_SIZE + self.__TAG_SIZE):
                offset = 0
                iv = response[offset : offset + self.__AES_IV_SIZE]
                offset += self.__AES_IV_SIZE
                cphr = response[offset: offset + self.__STATUS_SIZE + self.__TIME_STAMP_SIZE]
                offset += (self.__STATUS_SIZE + self.__TIME_STAMP_SIZE)
                tag = response[offset : offset + self.__TAG_SIZE]

                aes = cipher.AES.new(
                    self.__key, 
                    cipher.MODE_GCM,
                    iv, self.__session_id  # AAD
                )
                plaintext = aes.decrypt(cphr, tag)

                offset = 0
                status = SessionStatus(struct.unpack(">b", plaintext[offset:self.__STATUS_SIZE])[0])
                offset += self.__STATUS_SIZE
                time_us_received = struct.unpack(">Q", plaintext[offset: offset + self.__TIME_STAMP_SIZE])[0]
                timestamp_sec = time_us_received / 1_000_000
                timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))

                temperature = 0
                self.__session_id = bytes([0,0,0,0,0,0,0,0])

            else:
                status = SessionStatus.ERROR
                timestamp_str = ""
                temperature = 0
                

        return (status, timestamp_str, temperature)
    

    
    def __send_request(self, req: SessionRequest) -> bool:
        status = True

        timestamp_us = time.time_ns() // 1_000
        timestamp_b = struct.pack(">Q", timestamp_us)

        iv = random.randbytes(self.__AES_IV_SIZE)

        try:
            aes = cipher.AES.new(
                self.__key,
                cipher.MODE_GCM,
                iv,
                self.__session_id  # AAD
            )

            payload = struct.pack(">B", req) + timestamp_b
            cphr, tag = aes.encrypt(payload)

            packet = iv + cphr + tag

            if not self.__com.send(packet):
                status = False
        except:
            status = False
        
        return status