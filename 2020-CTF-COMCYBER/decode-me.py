"""
srandom(0x3d8)
0x80dcda0 <ascii>:	0xa0	0x31	0x6f	0x1b	0xca	0x2e	0x56	0x29
0x80dcda8 <ascii+8>:	0xc5	0x53	0x73	0x91	0xd6	0xd3	0xa3	0x5c
0x80dcdb0 <ascii+16>:	0x8a	0x83	0xe8	0xaf	0x50	0xbf	0xa4	0x43
0x80dcdb8 <ascii+24>:	0x95	0x28	0x14	0x51	0x19	0x34	0xdb	0xb9
0x80dcdc0 <ascii+32>:	0x65	0x4a	0xd5	0x2f	0x78	0x2b	0x58	0x3d
0x80dcdc8 <ascii+40>:	0x7e	0xcb	0xcf	0x54


srandom(0x3ad)
x/44x 0x80dcda0
0x80dcda0 <ascii>:	0x02	0xdd	0x57	0x80	0x19	0xc5	0xae	0xb7
0x80dcda8 <ascii+8>:	0xa2	0xd0	0xb8	0xa7	0x63	0x19	0x5f	0x77
0x80dcdb0 <ascii+16>:	0xfc	0x9f	0xff	0x28	0xda	0x69	0xb0	0x92
0x80dcdb8 <ascii+24>:	0x8c	0x80	0x0b	0xc1	0xab	0x95	0xab	0xae
0x80dcdc0 <ascii+32>:	0x72	0x03	0x2e	0x8b	0xc8	0xdd	0x43	0x6b
0x80dcdc8 <ascii+40>:	0xad	0xfb	0x12	0x10

srandom(0x20a)
x/44x 0x80dcda0
0x80dcda0 <ascii>:	0x28	0x25	0xd1	0x19	0x32	0x1f	0xb0	0xb1
0x80dcda8 <ascii+8>:	0xa9	0xea	0xf0	0xe1	0xf3	0x14	0xe1	0x20
0x80dcdb0 <ascii+16>:	0x7f	0xde	0xd1	0x23	0x2c	0xa1	0x63	0x7d
0x80dcdb8 <ascii+24>:	0x72	0xfe	0x6d	0x39	0x76	0x3a	0x58	0x9f
0x80dcdc0 <ascii+32>:	0x5f	0x2a	0xb8	0x91	0x49	0x68	0x42	0xf2
0x80dcdc8 <ascii+40>:	0x52	0x32	0xd4	0x45
"""

"""
gdb decode-me

b *0x08049005
b *0x08048f55
b *0x08048ccc

b *0x080488a5
b *0x080488fc
b *0x08048953
b *0x080489f2

j *0x08048eef
j *0x08048f8e

Num     Type           Disp Enb Address    What
1       breakpoint     keep y   0x08049005 <main+46>
	breakpoint already hit 1 time
2       breakpoint     keep y   0x08048f55 <authentification+102>
	breakpoint already hit 1 time
6       breakpoint     keep y   0x080488fc <f2>
	breakpoint already hit 1 time
7       breakpoint     keep y   0x08048953 <f3>
	breakpoint already hit 1 time
8       breakpoint     keep y   0x080489f2 <f4>
	breakpoint already hit 2 times
11      breakpoint     keep y   0x08048ce9 <check_password+318>
	breakpoint already hit 2 times

"""

def ROR(x, n, bits = 8):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))

def ROL(x, n, bits = 8):
    return ROR(x, bits - n, bits)

def SAR(a, width):
    sign = a & 0x80
    a &= 0x7F
    a >>= width
    a |= sign
    return a

def SHR(dest, count=1):
    return dest >> count

# char not(char c) {
#  return ~c;
# }

def inverse_bit(x):
    return x ^ 0xff

def decode0(a, v):
    return ROL(a, 3) ^ v

def decode1(a, v):
    return a ^ ROL(v, 1)

def decode2(a, v):
    p = 0
    v3 = ROR(a, 3)
    v4 = SHR(SAR(v3, 0x1F), 0x1D)
    while not ( p == 256 or ROL(inverse_bit(p), (((v3 + v4) & 7) - v4) & 0xFF) == v):
      p += 1
    if p == 256 :
      print("Failure decode3")
    return p

def decode3(i, v):
    return inverse_bit(v) ^ i

def next(R):
    K = SHR(SAR(0xE2, 0x1F), 0x1E)
    return ((R+K) & 3 - K)


print("Test SAR")
print(SAR(0x3a, 0x1f) == 0)
print(SAR(0x0e, 0x1f) == 0)
print("Test SHR")
print(SHR(0x00, 0x1d) == 0)


print("Test ROR")
print(ROR(0xed, 1) == 0xf6)
print(ROR(0x88, 3) == 0x11)
print(ROR(0xcf, 3) == 0xf9)
print(ROR(0xd1, 3) == 0x3a)


print("Test ROL")
print(ROL(0x9b, 1) == 0x37)
print(ROL(0x99, 2) == 0x66)
print(ROL(0xb8, 6) == 0x2e)
print(ROL(0x97, 0) == 0x97)

print("Test inverse_bit")
print(inverse_bit(0x62) == 0x9d)
print(inverse_bit(0x41) == 0xbe)
print(inverse_bit(0x66) == 0x99)
print(inverse_bit(0x47) == 0xb8)
print(inverse_bit(0x68) == 0x97)
print(inverse_bit(0x41) == 0xbe)



print("Main test!!!")

print("Test decode0")
print(decode0(0x87, 0x48) == ord('t'))

print("Test decode1")
print(decode1(0xf7, 0xd1) == ord('T'))
print(decode1(0xc3, 0x5b) == ord('u'))
print(decode1(0x41, 0x12) == ord('e'))
print(decode1(0xb0, 0xc8) == ord('!'))

print("Test decode2")
print(decode2(0x05, 0x73) == ord('2'))
print(decode2(0x8d, 0x97) == ord('4'))
print(decode2(0x7c, 0x46) == ord('s'))
print(decode2(0xac, 0x71) == ord('t'))
print(decode2(0x46, 0x97) == ord('h'))


print("Test decode3")
print(decode3(6, 0xca) == ord('3'))
print(decode3(1, 0x90) == ord('n'))
print(decode3(4, 0x8f) == ord('t'))
print(decode3(5, 0x88) == ord('r'))
print(decode3(8, 0xbe) == ord('I'))

print("Test Offset")
print(next(0xc6) == 2)
print(next(0xb0) == 0)
print(next(0xcf) == 3)
print(next(0x8f) == 3)
print(next(0x9f) == 3)
print(next(0x98) == 0)
print(next(0xd7) == 3)
print(next(0xd0) == 0)




val = bytearray.fromhex('b8b894f3afd7ab9da89932592fd8201fb0f6b6cecc7427c9e0f055598d9026cc5eabb5e669ef9c52d5d5e804')
val = list(val)
print(len(val))

def ddd(ASCII, off, val, k = -1):
  offset = off
  decode = []
  i = 0
  while i < len(val):
    # print(offset)
    if offset == 0:
      R = decode0(ASCII[i], val[i])
    elif offset == 1:
      R = decode1(ASCII[i], val[i])
    elif offset == 2:
      R = decode2(ASCII[i], val[i])
    elif offset == 3:
      R = decode3(i, val[i]) 
    else:
      print(f"Failure offset {offset}")
      break
    decode.append(R)
    # print(R)
    offset = next(val[i])
    i += 1
  d = "".join([chr(x) for x in decode])
  # print(f"{k} - offset: {off} - {d}")
  print(d)
 
with open('decode-me.ascii') as f:
  lines = f.readlines()

  print("TEST GLOBAL")
  A = bytearray.fromhex(lines[0x3a4].strip())
  o = 1
  v = bytearray.fromhex("95d0b8d79f9f9817c6cd9c662bc40ee3dfd7d523d8485877a2da9b08b88b0408bbceffff01000000c2000000")
  ddd(A, o, v) # should print azasdeae1234567809853DRFERF
  print([ord(x) for x in "azasdeae1234567809853DRFERF"])

  k = 0
  for line in lines:
    ASCII = bytearray.fromhex(line.strip())
    for off in range(0, 4):
      offset = off
      ddd(ASCII, off, val, k)
    k += 1
