from pwn import *

HOST = '127.0.0.1'
PORT = 8000

s = remote(HOST, PORT)
# Works also with local process
# s = process('./exploitme')

s.sendline("ABCD")
data = s.recvuntil(b"\n\n")
