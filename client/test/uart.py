import serial
import time

PORT = "/dev/ttyUSB0"  
BAUD = 2097152

ser = serial.Serial(PORT, BAUD)

print("UART test started")


while True:
    tx = (b'1234567891' * 300)
    print("Sending:", tx)

    ser.write(tx)

    rx = ser.read(3000)

    if rx:
        print("Received:", rx)
    else:
        print("Timeout / no data")

    print(tx == rx)

    time.sleep(10)