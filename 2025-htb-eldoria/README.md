# Hack The Box - Cyber Apocalypse CTF 2025: Tales from Eldoria

## Pwn

### Quack Quack (Very Easy)


### Blessing (Very Easy)

```
$ file blessing 
blessing: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=55d3b2dc0fc79ac741ea2e837be349c4c9e1cd78, for GNU/Linux 3.2.0, not stripped
$ checksec --file=blessing  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified   Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   RW-RUNPATH   60 Symbols        No    0  2blessing
```

The process prints an address and the delete it with return character.

If we look at the code with a reverse tool, it is the address of an array from malloc
```
000015f4      int64_t* rax_2 = malloc(bytes: 0x30000)
00001601      *rax_2 = 1
0000162d      printf(format: &data_263a, rax_2)
```

To get the flag, we need to set a zero value at the start of this array

```
00001758      if (*rax_2 != 0)
00001793          printf(format: "\n%s[%sBard%s]: Your song was no…", "\x1b[1;31m", "\x1b[1;32m", "\x1b[1;31m")
00001758      else
0000175f          read_flag()
```

We can provide a number that will be the size of a second allocated array.
This array will be set to one except the last byte.
```
000016d3      int64_t buf = malloc(bytes: buffer_length)
0000171e      read(fd: 0, buf, nbytes: buffer_length)
00001732      *(buf + buffer_length - 1) = 0
00001749      write(fd: 1, buf, nbytes: buffer_length)
```

What happen if you provide a huge value to malloc? It returns NULL.
According to the man page:

> RETURN VALUE
>       The  malloc(),  calloc(),  realloc(), and reallocarray() functions return a pointer to the allocated memory,
>       which is suitably aligned for any type that fits into the requested size or less.  On error, these functions
>       return NULL and set errno.

And what if the function `read` has a NULL value for the buffer?
It is not precised. Here, nothing is read. And for `write`? The same.
Here, if buf is NULL, `write` will set the value at the `buffer_length` position.

By sending the address received plus one, `rax_2` is set to zero:

Code is available here : [script_blessing.py][script_blessing.py]

### Crossbow (Easy)

```
$ file crossbow 
crossbow: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped
                                                                                                                   
$ checksec --file=crossbow
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified  Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   241 Symbols       No    0 0crossbow
```

Open the binary with your favorite decompiler. The code is simplified and variables are renamed:

```
00401220        if (__isoc99_scanf("%d%*c", 0) != 1) {
00401259            exit(0x520);
00401220        }
00401220        
0040126f        int32_t index;
0040126f        void** buffer = ((int64_t)index << 3) + leak_stack_address;
00401282        *(uint64_t*)buffer = calloc(1, 0x80);
00401282        
0040128b        if (!*(uint64_t*)buffer) {
004012c4            exit(0x1b39);
0040128b        }
0040128b        
004012f6        printf("%s\n[%sSir Alaric%s]: Give me yo…", 0);
00401321        void* result = fgets(*(uint64_t*)((char*)leak_stack_address + ((int64_t)index << 3)), 0x80, U"\t");
00401321        
00401329        if (result)
0040136d            return result;
```

The argument of the function is an address of the stack. 
We can provide a value and we will on the stack with `fgets`.

There is no control on the value, so we can write wherever we want on the stack.
We can write directly on the return address and do a classical ROP.

We find averything we need in the stack to call execve:
 - syscall
 - pop rax
 - pop rdi
 - mov [rdi], rax

rsi and rdi are NULL. We can write "/bin/sh" in the bss and call execve with it.

Code is available here : [script_crossbow.py][script_crossbow.py]

### Laconic (Easy)

Interesting challenge. There is only one call to `read`. When we look at the context, 
it will write to the stack. So we can overwrite the return pointer and we have a syscall gadget.

We can write up to 262 bytes, enough for a sigreturn exploitation.
Sigreturn is a syscall that can be used to set register.
So, we can call it with values to call execve, redo a syscall for and get a shell.

Code is available here : [script_laconic.py][script_laconic.py]

### Contractor (Medium)

```
$ file contractor 
contractor: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=e4444977f8666016be051a50d4709a42809bda4f, for GNU/Linux 3.2.0, not stripped
                                                                                                                    
$ checksec --file=contractor
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified   Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   RW-RUNPATH   85 Symbols        No    0  3contractor

```

In the binary, there is a function `contract` that spawns a shell.
Our objective will be to change the return address to this function
without modifying the canary.

In this challenge, we are requested to provide 4 values:
 - Name (16 bytes)
 - Reason (16 bytes)
 - Age (8 bytes)
 - Specialty (256 bytes)

The buffer is set to zero before usage, so no value to read.
After setting the values, there are displayed.

If we write 16 bytes to the reason, it will make with the following value a longer string that will be printed.

```
+------------------------------------------------------------------------+

        [Name]: 
        [Reason to join]: 
        [Age]: 0
        [Specialty]: aaaaaaaaaaaaaaaaP�*<�U

+------------------------------------------------------------------------+
```

A value from the stack is read. This value is the current address of `_init` that is set at the begging of main
With that, we are able to defeat PIE and to recompute the current address of `contract`.

We now have the opportunity to update some values.
But, there is a "bug". Speciality is not written at the same position.

```
; original position
000015de          *(uint8_t*)((buffer + ((int64_t)i)) + 0x10) = safe_buffer
...
; new position
00001971                  *(uint8_t*)((buffer + ((int64_t)i)) + 0x118) = safe_buffer;
```

With that, we might be able to overwrite the return address... But, by doing so, we will change the canary.
But, there is a trick. On the road to writing the return address, we will meet the address of buffer that we 
will modified, arriving to some unexpected place. 

The listing is the state of the memory when we start to overwrite

```
0x00007fffcb0d8938│+0x0118   0x0000000000000000   <== begin of reason ==> Edition of Speciality starts here
0x00007fffcb0d8940│+0x0120   0x0000000000000000   ==> end
0x00007fffcb0d8948│+0x0128   0x000055a2eed76b50   ==> Leak from print **__libc_csu_init**
0x00007fffcb0d8950│+0x0130   0x0000000000000000   
0x00007fffcb0d8958│+0x0138   0x00007fffcb0d8820   <== buffer address
0x00007fffcb0d8960│+0x0140   0x00007fffcb0d8a60   
0x00007fffcb0d8968│+0x0148   0x76fd5d70bdf47c00   <== Canary
0x00007fffcb0d8970│+0x0150   0x0000000000000000   <== $rbp
0x00007fffcb0d8978│+0x0158   0x00007fb1cc4ea083   <== Return address
```

If we are lucky and we can change the lowest byte to a correct shift, changing the address of 
**0x00007fffcb0d8820** to **0x00007fffcb0d88XY**, making it possible to directly change the return address.
We will need around 8 tests in average, due to the fact that Y must be equal to 0 to have an align stack.

Code is available here : [script_contractor.py][script_contractor.py]

## Reverse

### Encrypted Scroll (Very Easy)

Open the binary with your favorite tool. The code is not stripped, so we quickly identify 
the function `decrypt_message`:

```
000012be      __builtin_strcpy(&var_38, "IUC|t2nqm4`gm5h`5s2uin4u2d~");
000012e2      int32_t var_3c = 0;
000012e2      
00001313      while (*(uint8_t*)(&var_38 + ((int64_t)var_3c)) != 0)
00001313      {
000012ff          *(uint8_t*)(&var_38 + ((int64_t)var_3c)) -= 1;
00001303          var_3c += 1;
00001313      }
00001313      
0000132a      if (strcmp(arg1, &var_38) != 0)
00001347          puts("The scroll remains unreadable...…");
0000132a      else
00001336          puts("The Dragon's Heart is hidden ben…");
```

Here, you can just set a breakpoint before strcmp and check the stack.
Another solution is to understand the encryption algorithm, a shift by 1 of each character. 

### Sealed Rune (Very Easy)


Open the binary with your favorite tool. The code is not stripped, so we quickly identify 
the function `decode_flag`:

```
0000145a  char* decode_flag()

0000146c      char* result = base64_decode("LmB9ZDNsNDN2M3JfYzFnNG1fM251cntC…")
0000147c      reverse_str(result)
00001486      return result
```

With a one-liner:
```
$ python -c 'from base64 import b64decode as d;print(d("LmB9ZDNsNDN2M3JfYzFnNG1fM251cntCVEhgIHNpIGxsZXBzIHRlcmNlcyBlaFQ=")[::-1])'
b'The secret spell is `HTB{run3_m4g1c_r3v34l3d}`.'
```

### Impossimaze (Easy)

I found this one funny. When you run the challenge, you get a maze with NCurses.

If you look at the code, you can see an interesting portion of code that is only triggered 
when the maze is 13x37 ...

```
000014e2          if ((height == 13 && width == 37))
000014e2          {
000015bb              void* rbp_1 = &encoded_flag;
000015bb              
000015d0              for (int32_t j_1 = 6; j_1 != 0x1e; )
000015d0              {
000015d2                  uint64_t j_2 = ((uint64_t)j_1);
000015d4                  j_1 += 1;
000015d4                  
000015eb                  if (wmove(stdscr, 6, j_2) != 0xffffffff)
00001603                      waddch(stdscr, ((uint64_t)*(uint8_t*)(&maze + ((int64_t)*(uint32_t*)rbp_1))));
00001603                  
000015c9                  rbp_1 += 4;
000015d0              }
000015d0              
000014e2          }

```

If you resize the console to this size, you get the flag:

```
13:37───────────────────────────────┐
│VAV   VVV    AA  V   V A VVV A VV  │
│   A AV V A      VVVVV     VA    VV│
│     V VVAA     V  AVV  V  A       │
│V  A        VVV V VA V A V   V  V  │
│    A VVVVVAVVVV  VV A   V VVV  V  │
│ AV VHTB{th3_curs3_is_brok3n}VV  V │
│V A VV    A AV V A      VVVVV     V│
│A V A V   V  V    VV  VVV V    VVAV│
│ A VVVVVAVVVV  VV A   V VVV  V  VAV│
│  V  VAV   VVV    AA  V   V A VVV A│
│  VV A   V VVV  V  VAV   VVV    AA │
└───────────────────────────────────┘
```

### EndlessCycle (Easy)

The code is encrypted and decrypted with a call to random. 
```
00001191      int64_t rax = mmap(addr: nullptr, len: 0x9e, prot: 7, flags: 0x21, fd: 0xffffffff, offset: 0)
000011a2      srand(x: data_42b8)
000011a2      
00001206      for (void* i = nullptr; i u<= 0x9d; i += 1)
000011e1          for (int64_t j = 0; j u< sx.q(*((i << 2) + &data_4040)); j += 1)
000011bb              rand()
000011bb          
000011f7          *(i + rax) = rand()

00001219      if (dynamic_code() != 1)
00001236          puts(str: "The mysteries of the universe re…")
00001219      else
00001225          puts(str: "You catch a brief glimpse of the…")

```

You can try to revert it... or you can attach a debugger and visualize the code:

```asm
; rcx = our input
00007ffa0f2d1059  8131fecaefbe       xor     dword [rcx], 0xbeefcafe
00007ffa0f2d105f  4883c104           add     rcx, 0x4
00007ffa0f2d1063  4839c1             cmp     rcx, rax
00007ffa0f2d1066  72f1               jb      0x7ffa0f2d1059

00007ffa0f2d1068  4c89e7             mov     rdi, r12
00007ffa0f2d106b  488d3512000000     lea     rsi, [rel data_7ffa0f2d1084]
```

Our value is xor with the key (**0xbeefcafe**) then compares to the key.

[Click here to view the solution with CyberChef](https://cyberchef.io/#recipe=From_Hex%28'Auto'%29XOR%28%7B'option':'Hex','string':'fecaefbe'%7D,'Standard',false%29&input=YjY5ZWFkYzU5MmZhZGZkNWExYThkY2M3Y2VhNDhiZTE4YWEyZGNlMTg5ZmE5ZGQyOWFiNw)


