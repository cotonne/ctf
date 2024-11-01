# Tools

## Useful Linux cmd

 - file
 - identify -verbose
 - hexdump -C
 - strings


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
 - Get Hashes : `vol -f mem.dmp windows.hashdump.Hashdump`

## 

`impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL`

# Notes

 - ODT, XLSX, ... can be opened as zip

## Windows

 - Kerberoasting: servicePrincipalName

## Reference 

 - [Internal All The things](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-ntds-dumping/#forensic-tools)
 - [MITRE ATT&CK T1003 Credential Dumping](https://www.picussecurity.com/resource/blog/picus-10-critical-mitre-attck-techniques-t1003-credential-dumping)
