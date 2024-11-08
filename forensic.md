# Tools

## Useful Linux cmd

 - file
 - identify -verbose
 - hexdump -C
 - strings
 - gimp (can read RAW image data from .data file)


## Lost Partition/File

 - Recover partitions: testdisk drive.image
 - Recover photos from partition: photorec drive.image

## Recover partitions

 - ntfsfix

## Recover images

 - [Acropalypse / CVE-2023-21036](https://github.com/frankthetank-music/Acropalypse-Multi-Tool)
 - pngcheck
 - [PCRT (PNG Check & Repair Tool)](https://github.com/sherlly/PCRT)

# Mount Partitions

## OVA

Untar the ova file which contains a VMDK filesystem: `tar -xf vm.ova`

Access the VMDK:
 - The loopback way:
   * https://gist.github.com/PedroCavaleiro/43e4a19a6bec21bc7c587b3bbb966265
   * https://forums.opensuse.org/t/mounting-virtual-box-machine-images-on-a-host/75409
 - [guestmount](https://stackoverflow.com/a/30201153)

> For newer Linux systems, you can use guestmount to mount the third partition within a VMDK image:
> guestmount -a xyz.vmdk -m /dev/sda3 --ro /mnt/vmdk
> Alternatively, to autodetect and mount an image (less reliable), you can try:
> guestmount -a xyz.vmdk -i --ro /mnt/vmdk

 - 7z l xyz.vmdk

# Volatility

## Installation

```bash
python -m pip install volatility3
export PATH=$HOME/.local/bin:$PATH
```

## Plugins 

 - Get Windows env: `vol -f mem.dmp windows.envars.Envars`
 - Get Password Hashes : `vol -f mem.dmp windows.hashdump.Hashdump`
 - List of cmdllines: `vol -f ch2.dmp windows.cmdline.CmdLine`
 - Extract file from dump
```
> vol -f memory.dmp windows.filescan.FileScan | grep filename 
> vol -f memory.dmp windows.dumpfiles.DumpFiles --physaddr 0xXXX
```
 - Find which process owns a given string
```
echo "Interesting strings" > strings.txt
strings -t x memory.dmp | grep A_string > strings.txt
vol -f memory.dmp windows.strings.Strings --strings-file strings.txt
```
 - Dump memory from process: ` vol -f image.dmp windows.pslist.PsList --pid 2608 --dump`
 - Dump memory from process: ` vol -f memory.dmp windows.memmap.Memmap --pid 3476 --dump`
 - Registry key: `vol -f dump windows.registry.printkey.PrintKey --key 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\TrueCrypt' --recurse`
 
## 

`impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL`

# Notes

 - ODT, XLSX, ... can be opened as zip

## Windows

 - Groups.xml: contains cpassword ([Fix AES key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN), base64 encoded, iv = 00 * 16).  Ref: [Privilege Escalation via Group Policy Preferences (GPP)](https://www.mindpointgroup.com/blog/privilege-escalation-via-group-policy-preferences-gpp)

## Linux

 - Dump memory: `dd if=/dev/mem of=/tmp/memory.raw bs=1MB`

## Reference 

 - [Internal All The things](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-ntds-dumping/#forensic-tools)
 - [MITRE ATT&CK T1003 Credential Dumping](https://www.picussecurity.com/resource/blog/picus-10-critical-mitre-attck-techniques-t1003-credential-dumping)
