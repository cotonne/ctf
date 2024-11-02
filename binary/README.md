# Assembly

## Tools

 - nasm: asm compiler
 - ld: linker
 - objdump: disassemble sections
 - gdb + gef
 - strings (-eL to view wide characters strings)
 
 curl -o  ~/.gdbinit-gef.py -q https://gef.blah.cat/py
 echo source ~/.gdbinit-gef.py >> ~/.gdbinit
 - Dump a specific section : objcopy crackme1 --dump-section .data=out
 - Dump a specific section (pwntools): 

## Hello World in asm

> $ cat hello.asm 
>          global  _start
> 
>          section .data
> message: db      "Hello HTB Academy!"
> 
>          section .text
> _start:
>          mov     rax, 1
>          mov     rdi, 1
>          mov     rsi, message
>          mov     rdx, 18
>          syscall
> 
>          mov     rax, 60
>          mov     rdi, 0
>          syscall

## Compile it

$ nasm -f elf64 -o hello.o hello.asm
$ objdump -M intel -D -s hello.o

hello.o:     file format elf64-x86-64

Contents of section .data:
 0000 48656c6c 6f204854 42204163 6164656d  Hello HTB Academ
 0010 7921                                 y!              
Contents of section .text:
 0000 b8010000 00bf0100 000048be 00000000  ..........H.....
 0010 00000000 ba120000 000f05b8 3c000000  ............<...
 0020 bf000000 000f05                      .......         

Disassembly of section .data:

0000000000000000 <message>:
   0:   48                      rex.W
   1:   65 6c                   gs ins BYTE PTR es:[rdi],dx
   3:   6c                      ins    BYTE PTR es:[rdi],dx
   4:   6f                      outs   dx,DWORD PTR ds:[rsi]
   5:   20 48 54                and    BYTE PTR [rax+0x54],cl
   8:   42 20 41 63             rex.X and BYTE PTR [rcx+0x63],al
   c:   61                      (bad)
   d:   64 65 6d                fs gs ins DWORD PTR es:[rdi],dx
  10:   79 21                   jns    33 <message+0x33>

Disassembly of section .text:

0000000000000000 <_start>:
   0:   b8 01 00 00 00          mov    eax,0x1
   5:   bf 01 00 00 00          mov    edi,0x1
   a:   48 be 00 00 00 00 00    movabs rsi,0x0
  11:   00 00 00 
  14:   ba 12 00 00 00          mov    edx,0x12
  19:   0f 05                   syscall
  1b:   b8 3c 00 00 00          mov    eax,0x3c
  20:   bf 00 00 00 00          mov    edi,0x0
  25:   0f 05                   syscall


## Make a valid executable

$ ld -o a.out hello.o

### View strings from section .data 

> $ objdump -M intel -sj .data  a.out
> a.out:     file format elf64-x86-64
> 
> Contents of section .data:
>  402000 48656c6c 6f204854 42204163 6164656d  Hello HTB Academ
>  402010 7921                                 y! 

### Sections 

 - .text: executable program
 - .data: constant / static values
 - .bss: uninitialized buffer space


## Gdb

 - info vaariables
 - info functions
 - info registers
 - disas _start/0xAAAA (disassemble at an address)
 - break / b "function"/0xAAAA/*0xAAAA (break at the address stored at 0xAAAA)
 - run / r
 - step / stepi / next / nexti (count)
 - x/FMT 0xAAAA : examine/print a value at a given address. FMT: CountFormatSize
   * Count: Number of Format to print
   * Format: x(hex), s(string), c(char), i(instruction), ....
   * Size: b(byte),hwg
 - GEF specific: patch string 0x402000 "Patched!\\x0a"


## Instructions

| Instruction | Description | Example |
|--|--|--|
| mov | Move data or load immediate data | mov rax, 1 -> rax = 1, mov rax, [rbx] -> rax = \*rbx |
| lea | Load an address pointing to the value | lea rax, [rsp+5] -> rax = rsp+5 |
| xchg | Swap data between two registers or addresses | xchg rax, rbx -> rax = rbx, rbx = rax |
| inc | Increment by 1 | inc rax -> rax++ or rax += 1 -> rax = 2 |
| dec | Decrement by 1 | dec rax -> rax-- or rax -= 1 -> rax = 0 |
| add | Add both operands | add rax, rbx -> rax = 1 + 1 -> 2 |
| sub | Subtract Source from Destination (i.e rax = rax - rbx) | sub rax, rbx -> rax = 1 - 1 -> 0 |
| imul | Multiply both operands | imul rax, rbx -> rax = 1 * 1 -> 1 |
| not | Bitwise NOT (invert all bits, 0->1 and 1->0) | not rax -> NOT 00000001 -> 11111110 |
| and | Bitwise AND (if both bits are 1 -> 1, if bits are different -> 0) | and rax, rbx -> 00000001 AND 00000010 -> 00000000 |
| or | Bitwise OR (if either bit is 1 -> 1, if both are 0 -> 0) | or rax, rbx -> 00000001 OR 00000010 -> 00000011 |
| xor | Bitwise XOR (if bits are the same -> 0, if bits are different -> 1) | xor rax, rbx -> 00000001 XOR 00000010 -> 00000011|
| mov rcx, x | Sets loop (rcx) counter to x | mov rcx, 3|
| loop | Jumps back to the start of loop until counter/rcx reaches 0 | loop label|
| jmp | Jumps to specified label, address, or location | jmp loop|
| jz,jnz,js,jns,jge, jl ,jle | jump zero, negative, less/greater, ...| RFLAGS/EFLAGS |
| cmp | Sets RFLAGS by subtracting second operand from first operand (i.e. first - second) | cmp rax, rbx -> rax - rbx |
| push | Copies the specified register/address to the top of the stack | push rax |
| pop | Moves the item at the top of the stack to the specified register/address | pop rax |
| syscall | call a system function like write (refer to unistd\_64.h & man -s 2 write) | syscall 1 (write(XXX)) |
| call | push the next instruction pointer rip to the stack, then jumps to the specified procedure | call printMessage |
| ret | pop the address at rsp into rip, then jump to it | ret |

 To call a syscall, we have to:

Save registers to stack
Set its syscall number in rax
Set its arguments in the registers
Use the syscall assembly instruction to call it

Arguments
Syscall Number/Return value | rax | al
Callee Saved | rbx | bl
1st arg | rdi | dil
2nd arg | rsi | sil
3rd arg | rdx | dl
4th arg | rcx | cl
5th arg | r8 | r8b
6th arg | r9 | r9b




rdi -> 1 (for stdout)
rsi -> 'Fibonacci Sequence:\n' (pointer to our string)
rdx -> 20 (length of our string)

## Registry

 - $rbp: base stack pointer
 - $rsp: top of stack 


js => <= 0

Every time the loop reaches the loop instruction, it will decrease rcx by 1 (i.e., dec rcx) and jump back to the specified label, exampleLoop in this case. So, before we enter any loop, we should mov the number of loop iterations we want to the rcx register.

## Functions

### Calling

Save Registers on the stack (Caller Saved)
Pass Function Arguments (like syscalls)
Fix Stack Alignment (we should have 16-bytes (or a multiple of 16) on top of the stack before making a call, mainly there for processor performance efficiency)
Get Function's Return Value (in rax)

### Writing

Saving Callee Saved registers (rbx and rbp)
Get arguments from registers
Align the Stack
Return value in rax

## Dump memory

Case when an exe uses mprotect to make page executable

 - Search for executable heap page: grep heap /proc/<pid>/maps  | grep rwx
 - Connect to the process with GDB: gdb -p <pid>
 - Dump memory into file: dump memory output 0x55555555a000 0x55555555a3a0

## DLL HiJack

```C++
#include <stdio.h>
#include <stdlib.h>

void xxx() {
    setreuid(getreuid(), getreuid());
    system("/bin/sh -p");
}
```
gcc -shared -o libs/libx.so -fPIC libs/libx.c

## Find gadget

    $ ropper --file libc.so --search "add jsp, 0x??"


pwn disasm '0xhex' -c 'amd64'

# References

 - [Leaking information](https://github.com/Naetw/CTF-pwn-tips)
 - [Shellcode](https://shell-storm.org/shellcode/index.html)
