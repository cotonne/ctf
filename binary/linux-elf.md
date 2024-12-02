 - ret2libc
 - Good descriptoin: https://gist.github.com/DtxdF/e6d940271e0efca7e0e2977723aec360

## FSOP

 - File Structure is a struct created by fopen. link list of FILE
 - stdin, stdout, ... are located in the section data of libc

```
0x00007ffff7f9a000 0x00007ffff7f9c000 0x00000000001e6000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6

p _IO_2_1_stdin_ 
$1 = {
  file = {
    _flags = 0xfbad2288,
    _IO_read_ptr = 0x5555556036b0 "",
    _IO_read_end = 0x5555556036b0 "",
    _IO_read_base = 0x5555556036b0 "",
    _IO_write_base = 0x5555556036b0 "",
    _IO_write_ptr = 0x5555556036b0 "",
    _IO_write_end = 0x5555556036b0 "",
    _IO_buf_base = 0x5555556036b0 "",
    _IO_buf_end = 0x555555603ab0 "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 0x0,
    _flags2 = 0x0,
    _old_offset = 0xffffffffffffffff,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = "",
    _lock = 0x7ffff7f9c720 <_IO_stdfile_0_lock>,
    _offset = 0xffffffffffffffff,
    _codecvt = 0x0,
    _wide_data = 0x7ffff7f9a9c0 <_IO_wide_data_0>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    _prevchain = 0x7ffff7f9b628 <_IO_2_1_stdout_+104>,
    _mode = 0xffffffff,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7ffff7f98ff0 <_IO_file_jumps>
}
```

 - Craft a fake chain of FILE (House of Pig)
 - Modify entry of vtable
 - Modify _IO_buf_end to overwrite part of memory

 - Ref: 
   - https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/EN%20-%20Play%20with%20FILE%20Structure%20-%20Yet%20Another%20Binary%20Exploit%20Technique%20-%20An-Jie%20Yang.pdf
   - https://niftic.ca/posts/fsop/



#