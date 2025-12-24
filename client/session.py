from communication import Communication
import struct

class Session:
    def __init__(self):
        self.__com = Communication()

    def establish_session(self) -> bool:
        # ============== without security ================
        self.__com.open()
        # ================================================



        # ======================================= STEG 1 =======================================
        # Generate random SESSION_KEY[32], CIV[12], RAND[8]
        # SESSION_ID[8] = 0
        # Cipher, tag = encrypt(session_key + RAND) with AES_GCM and use HSECRET as key, CIV as IV and SESSION_ID as AAD
        # Send(CIV + cipher + tag)


        # ======================================= STEG 2 =======================================
        # Read (decrypt) SESSION_ID and RAND från server med AES_GCM med SESSION_KEY som nyckel
        # Kontrollera att RAND är samma som vi skickade
        # Spara SESSION_ID temporärt

        # Time_stamp = tiden i mikrosekunder
        # Generera ett nytt IV
        # Encryptera time_stamp med AES_GCM med SESSION_ID som AAD


        # ======================================= STEG 3 =======================================
        # Read (decrypt) time_stamp och SESSION_ID med AES_GCM
        # Kontrollera om time_stamp mottagit är samma som vi skickade
        # Om det är samma så sätt SESSION_ID till global SESSION_ID
        # Vi har nu skapat en session
        pass

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