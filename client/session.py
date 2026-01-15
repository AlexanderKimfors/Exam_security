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

        self.__session_state = False
        self.__session_id = bytes([0,0,0,0,0,0,0,0])
        self.__secret = hashlib.sha256(secret.encode()).digest()
        self.__TAG_SIZE = 16
        self.__RAND_SIZE = 8
        self.__AES_IV_SIZE = 12
        self.__AES_KEY_SIZE = 32
        self.__SESSION_ID_SIZE = 8
        self.__TIME_STAMP_SIZE = 8

    def establish_session(self) -> tuple[bool, str]:
        status = True 
        readable_time = ""
        # ======================================= First msg to send =======================================
        random.seed()
        AES_KEY = random.randbytes(self.__AES_KEY_SIZE)
        AES_IV = random.randbytes(self.__AES_IV_SIZE)
        RAND = random.randbytes(self.__RAND_SIZE)
        try:
            #                                                            AAD
            aes = cipher.AES.new(self.__secret, cipher.MODE_GCM, AES_IV, self.__session_id)
            cphr, tag = aes.encrypt(AES_KEY + RAND)

            message = AES_IV + cphr + tag
            status = self.__com.send(message)

            # ===================================== First msg to receive =======================================
            if status:
                len_to_read = self.__AES_IV_SIZE + self.__SESSION_ID_SIZE + self.__TAG_SIZE
                response = self.__com.receive(len_to_read)

                if len(response) == len_to_read:
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
                    status = self.__com.send(message)

                    # ===================================== Second msg to receive ======================================
                    if status:
                        len_to_read = self.__AES_IV_SIZE + self.__TIME_STAMP_SIZE + self.__TAG_SIZE
                        response = self.__com.receive(self.__AES_IV_SIZE + self.__TIME_STAMP_SIZE + self.__TAG_SIZE)

                        if len(response) == len_to_read:
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
                                status = False

                            timestamp_us_received = struct.unpack(">Q", timestamp_us_b_received)[0]

                            readable_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_us_received / 1_000_000))
                else:
                    status = False
                    print(status)
        except:
            status = False

        

        return (status, readable_time)

    def close_session(self) -> tuple[SessionStatus, str]:
        self.__send_request(SessionRequest.CLOSE)

        receive_size = self.__AES_IV_SIZE + 1 + self.__TIME_STAMP_SIZE + self.__TAG_SIZE
        response = self.__com.receive(receive_size)

        if len(response) == receive_size:
            offset = 0
            AES_IV = response[offset : offset + self.__AES_IV_SIZE]
            offset += self.__AES_IV_SIZE
            cphr = response[offset: offset + 1 + self.__TIME_STAMP_SIZE]
            offset += (1 + self.__TIME_STAMP_SIZE)
            tag = response[offset : offset + self.__TAG_SIZE]

            aes = cipher.AES.new(
                self.__key, 
                cipher.MODE_GCM,
                AES_IV, self.__session_id  # AAD
            )
            plaintext = aes.decrypt(cphr, tag)

            offset = 0
            status = SessionStatus(struct.unpack(">b", plaintext[0:1])[0])
            offset += 1
            time_us_received = struct.unpack(">Q", plaintext[offset: offset + self.__TIME_STAMP_SIZE])[0]

            timestamp_sec = time_us_received / 1_000_000
            timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))

            self.__session_id = bytes([0,0,0,0,0,0,0,0])
            self.__session_state = False
        
        return (status, timestamp_str)


    def toggle_led(self) -> tuple[SessionStatus, str, bool]:
        """
        Returns: (status, time, led_state)
        """
        status = self.__send_request(SessionRequest.TOGGLE_LED) # Ta bort timestamp och sätt in logiken här iställt från svaret

        if status:
            response = self.__com.receive_2(self.__AES_IV_SIZE + 1 + self.__TIME_STAMP_SIZE + 1 + self.__TAG_SIZE) # [IV, status 1 + time 8 + led_state 1, + TAG]

            # Unpack response
            if (len(response) == (self.__AES_IV_SIZE + 1 + self.__TIME_STAMP_SIZE + 1 + self.__TAG_SIZE)):
                offset = 0
                AES_IV = response[offset : offset + self.__AES_IV_SIZE]
                offset += self.__AES_IV_SIZE
                cphr = response[offset: offset + 1 + self.__TIME_STAMP_SIZE + 1]
                offset += (1 + self.__TIME_STAMP_SIZE + 1)
                tag = response[offset : offset + self.__TAG_SIZE]

                # Decrypte cipher
                aes = cipher.AES.new(
                    self.__key,
                    cipher.MODE_GCM,
                    AES_IV,
                    self.__session_id # AAD
                )

                plaintext = aes.decrypt(cphr, tag)

                # Unpack plaintext
                status = SessionStatus(struct.unpack(">b", plaintext[0:1])[0])
                time_us_received = struct.unpack(">Q", plaintext[1:9])[0]
                led_state = plaintext[9]

                if status:
                    timestamp_sec = time_us_received / 1_000_000
                    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))

            elif (len(response) == (self.__AES_IV_SIZE + 1 + self.__TIME_STAMP_SIZE + self.__TAG_SIZE)):
                offset = 0
                AES_IV = response[offset : offset + self.__AES_IV_SIZE]
                offset += self.__AES_IV_SIZE
                cphr = response[offset: offset + 1 + self.__TIME_STAMP_SIZE]
                offset += (1 + self.__TIME_STAMP_SIZE)
                tag = response[offset : offset + self.__TAG_SIZE]

                # Decrypte cipher
                aes = cipher.AES.new(
                    self.__key,
                    cipher.MODE_GCM,
                    AES_IV,
                    self.__session_id # AAD
                )

                plaintext = aes.decrypt(cphr, tag)

                # Unpack plaintext
                status = SessionStatus(struct.unpack(">b", plaintext[0:1])[0])
                time_us_received = struct.unpack(">Q", plaintext[1:9])[0]

                if status:
                    timestamp_sec = time_us_received / 1_000_000
                    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))

                led_state = 0

                self.__session_id = bytes([0,0,0,0,0,0,0,0])
                self.__session_state = False

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

            response = self.__com.receive_2(self.__AES_IV_SIZE + 1 + self.__TIME_STAMP_SIZE + 4 + self.__TAG_SIZE) # [IV, status + time + temp, TAG]

            if(len(response) == self.__AES_IV_SIZE + 1 + self.__TIME_STAMP_SIZE + 4 + self.__TAG_SIZE):
                # ============== Unpack the msg: IV, cipher, TAG ==================
                offset = 0
                AES_IV = response[offset : offset + self.__AES_IV_SIZE]
                offset += self.__AES_IV_SIZE
                cphr = response[offset: offset + 1 + self.__TIME_STAMP_SIZE + 4]
                offset += (1 + self.__TIME_STAMP_SIZE + 4)
                tag = response[offset : offset + self.__TAG_SIZE]

                aes = cipher.AES.new(
                    self.__key, 
                    cipher.MODE_GCM,
                    AES_IV, self.__session_id  # AAD
                )
                plaintext = aes.decrypt(cphr, tag)

                offset = 0
                status = SessionStatus(struct.unpack(">b", plaintext[0:1])[0])
                offset += 1
                time_us_received = struct.unpack(">Q", plaintext[offset: offset + self.__TIME_STAMP_SIZE])[0]
                offset += self.__TIME_STAMP_SIZE
                temp_b = plaintext[offset: offset + 4]

                temperature = struct.unpack(">f", temp_b)[0]
                timestamp_sec = time_us_received / 1_000_000
                timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))
            elif(len(response) == self.__AES_IV_SIZE + 1 + self.__TIME_STAMP_SIZE + self.__TAG_SIZE):
                 # ============== Unpack the msg: IV, cipher, TAG ==================
                offset = 0
                AES_IV = response[offset : offset + self.__AES_IV_SIZE]
                offset += self.__AES_IV_SIZE
                cphr = response[offset: offset + 1 + self.__TIME_STAMP_SIZE]
                offset += (1 + self.__TIME_STAMP_SIZE)
                tag = response[offset : offset + self.__TAG_SIZE]

                aes = cipher.AES.new(
                    self.__key, 
                    cipher.MODE_GCM,
                    AES_IV, self.__session_id  # AAD
                )
                plaintext = aes.decrypt(cphr, tag)

                offset = 0
                status = SessionStatus(struct.unpack(">b", plaintext[0:1])[0])
                offset += 1
                time_us_received = struct.unpack(">Q", plaintext[offset: offset + self.__TIME_STAMP_SIZE])[0]
                timestamp_sec = time_us_received / 1_000_000
                timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_sec))
                temperature = 0
                self.__session_id = bytes([0,0,0,0,0,0,0,0])
                self.__session_state = False
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
            ciphertext, tag = aes.encrypt(payload)

            packet = iv + ciphertext + tag

            if not self.__com.send(packet):
                status = False
        except:
            status = False
        
        return status