from communication import Communication
from mbedtls import hashlib, cipher
import struct, random, sys
import time

AES_KEY_SIZE = 32
AES_IV_SIZE = 12
RAND_SIZE = 8

SECRET = sys.argv[2].encode()
class Session:
    def __init__(self):
        self.__com = Communication()
        self._session_id = bytes([0,0,0,0,0,0,0,0])
        self._session_state = False

    def establish_session(self) -> bool:
        # ============== without security ================
        self.__com.open()
        # ================================================



        # ======================================= STEG 1 =======================================
        # Generate random SESSION_KEY[32], CIV[12], RAND[8]
        random.seed()
        AES_KEY = random.randbytes(AES_KEY_SIZE)
        AES_IV = random.randbytes(AES_IV_SIZE)
        RAND = random.randbytes(RAND_SIZE)

        #                    KEY                      IV      AAD
        aes = cipher.AES.new(SECRET, cipher.MODE_GCM, AES_IV, self._session_id)

        # Cipher, tag = encrypt(session_key + RAND) with AES_GCM and use HSECRET as key, CIV as IV and SESSION_ID as AAD
        cphr, tag = aes.encrypt(AES_KEY + RAND)


        # Send(CIV + cipher + tag)
        #[IV 12 bytes, cphr 40 bytes, tag 16 bytes] --> total 12+40+16 = 68 bytes
        message = AES_IV + cphr + tag
        self.__com.send(message)

        # ======================================= STEG 2 =======================================
        # Läs (decrypt) SESSION_ID med RAND som AAD och AES_KEY som nyckel
        response = self.__com.receive(36)

        AES_IV = response[0:12]
        cphr = response[12:20]
        tag = response[20:36]

        aes = cipher.AES.new(AES_KEY, cipher.MODE_GCM, AES_IV, RAND)
        session_id = aes.decrypt(cphr, tag) # lokalt sparat session_id

        # Time_stamp = tiden i mikrosekunder
        timestamp_us = time.time_ns() // 1_000
        time_bytes = struct.pack(">Q", timestamp_us)

        # Generera ett nytt IV
        AES_IV = random.randbytes(AES_IV_SIZE)

        # Encryptera time_stamp med AES_GCM med SESSION_ID som AAD
        aes = cipher.AES.new(AES_KEY, cipher.MODE_GCM, AES_IV, session_id)
        cphr, tag = aes.encrypt(time_bytes)

        #         12     + 8    + 16  = 36 bytes
        message = AES_IV + cphr + tag
        self.__com.send(message)


        # ======================================= STEG 3 =======================================
        # Read (decrypt) time_stamp med AES_GCM och session_id som AAD
        response = self.__com.receive(36)

        AES_IV = response[0:12]
        cphr = response[12:20]
        tag = response[20:36]

        aes = cipher.AES.new(AES_KEY, cipher.MODE_GCM, AES_IV, session_id)
        timestamp_us_received_bytes = aes.decrypt(cphr, tag) # lokalt sparat session_id

        # Kontrollera om time_stamp mottagit är samma som vi skickade
        # Om det är samma så sätt SESSION_ID till global SESSION_ID
        timestamp_us_received = struct.unpack(">Q", timestamp_us_received_bytes)[0]
        if(timestamp_us == timestamp_us_received):
            self._session_state = True
            self._session_id = session_id
        
        print(self._session_state)

        # Vi har nu skapat en session

    def close_session(self):
        # ============== without security ================
        self.__com.close()
        # ================================================
    


    def toggle_led(self):
        # ============== without security ================
        self.__com.send(b"toggle LED\n")
        # ================================================
        

    def get_temperature(self) -> float:

        # ============== without security ================
        self.__com.send(b"temperature\n")
        temp = self.__com.receive(4)
        return struct.unpack('f',temp)[0]
        # ================================================