#!/usr/bin/python3

import sys, os, stat
from pwn import *

context(os="linux", arch="amd64", log_level="error")

file = ELF(sys.argv[1])
shellcode = file.section(".text")
#run_shellcode(shellcode).interactive()

#ELF.from_bytes(shellcode).save(sys.argv[2])
#os.chmod(sys.argv[2], stat.S_IEXEC)

print(disasm(shellcode))
print(shellcode.hex())

print("%d bytes - Found NULL byte" % len(shellcode)) if [i for i in shellcode if i == 0] else print("%d bytes - No NULL bytes" % len(shellcode))

