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

# Memory Analysis with Volatility

## Installation

```bash
python -m pip install volatility3
export PATH=$HOME/.local/bin:$PATH
```
## Volatility common modules

 - `pslist`: Lists the running processes.
 - `cmdline`: Displays process command-line arguments
 - `netscan`: Scans for network connections and open ports.
 - `malfind`: Scans for potentially malicious code injected into processes.
 - `handles``: Scans for open handles
 - `svcscan`: Lists Windows services.
 - `dlllist`: Lists loaded DLLs (Dynamic-link Libraries) in a process.
 - `hivelist`: Lists the registry hives in memory.

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

## Plugins (vol 2)

 - Get image profil : `vol.py -f /path/to/image imageinfo`
 - Code injection into process: `vol.py -f /path/to/image --profile=Win7SP1x64 malfind --pid=xxx`
 - File open by a process : `vol.py -f /path/to/image --profile=Win7SP1x64 handles -p 1792 --object-type=File`
 - Keys used by a process: `vol.py -f /path/to/image --profile=Win7SP1x64 handles -p 1792 --object-type=Key`
 - In memory DLLs: `vol.py -f /path/to/image --profile=Win7SP1x64 dlllist`

# Windows Disk Analysis 

## Files

 - MFT$: list of stored files on disk, essential informations about disks
 - Prefetch: preloading of commonly used programs. Under `c:/Windows/Prefetch`, can be open with `sccainfo -v PREFETCH.pf`
 - SuperFetch
 - hiberfile.sys: data copied from RAM for hibernation
 - Swap: C:\pagefile.sys & swapfile.sys
 - Deleted files
 - Shim: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
 - AmCache: `C:\Windows\AppCompat\Programs\Amcache.hve`
 - UserAssist: Registry: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
 - RunMRU Lists: Registry: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU	
 - Jump Lists: %AppData%\Microsoft\Windows\Recent
 - Windows User Access Logs: `c:\windows\system32\LogFiles\SUM`
 - Hiding informations: Alternate Data Streams / File Slack (remaining space not used by a file in a block). [ADS are also available for downloaded files](https://www.digital-detective.net/forensic-analysis-of-zone-identifier-stream/)
 - Groups.xml: contains cpassword ([Fix AES key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN), base64 encoded, iv = 00 * 16).  Ref: [Privilege Escalation via Group Policy Preferences (GPP)](https://www.mindpointgroup.com/blog/privilege-escalation-via-group-policy-preferences-gpp)
 - Browser files, ...
 - Events logs (`c:\windows\System32\winevt\logs\*.evtx`
 - Registries: HKLM, ... stored in hives SYSTEM/SAM/SECURITY under `C:\Windows\System32\config`. User registries are stored under `%HOMEPATH%\ntuser.dat` `%LOCALAPPDATA%\Local\Microsoft\UsrClass.DAT`
    * Samba mounts: HKCU\Network
    * Samba mounts: HKLM\SYSTEM\MountedDevices
    * Shell bags (params of explorer): `NTUSER.DAT\Software\Microsoft\Windows\Shell*` or  `UsrClass.DAT\Local Settings\Microsoft\Windows\Shell*`

## Persistence artifacts

 - Autorun
 - Keys used by WinLogon Process:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
 - Startup Keys
 - schtasks: C:\Windows\System32\Tasks
 - services: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services

## Mounting a disk 

[Autopsy](https://www.autopsy.com/) can also be used

### Identify partitions

```
$ fdisk -l image
Disk SCENAR: 19.54 GiB, 20971520000 bytes, 40960000 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x51f4e7e5

Device     Boot   Start      End  Sectors  Size Id Type
DEVICE1    *       2048  1126399  1124352  549M  7 HPFS/NTFS/exFAT
DEVICE2         1126400 40962047 39835648   19G  7 HPFS/NTFS/exFAT
```

### Mouting partitions

```
sudo mount -o ro,noload -o loop,offset=$((2048*512)) -t ntfs-3g SCENAR $PWD/DEVICE1
sudo mount -o ro -o loop,offset=$((1126400*512)) -t ntfs3 SCENAR $PWD/SCENAR2
```

Multiple drivers for ntfs : ntfs3, ntfs-3g

## Tools

### chainsaw

Can use [sigma rules](https://github.com/SigmaHQ/sigma) to detect attacks

```
chainsaw hunt --mapping sigma-mapping.yml --rules sigma/ $HOME/mount/Windows/System32/winevt/Logs/
chainsaw search -e event  $HOME/mount/Windows/System32/winevt/Logs/
```

### Plaso / log2timeline

Built a timeline by merging multiple sources (event logs, registries, ...)

```
log2timeline.py --artifact-filters WindowsEventLogSystem,WindowsMountedDevices,WindowsXMLEventLogApplication,WindowsXMLEventLogPowerShell,WindowsXMLEventLogSecurity,WindowsXMLEventLogSysmon,WindowsCommandProcessorAutoRun /path/to/mounted/drive
psort.py --output-time-zone "UTC" -o l2tcsv -w 20250131T091253-XXX.csv 20250131T091253-XXX.plaso
```

## Extracting hashes

```
> cd c:\Windows\System32\config
> impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL # AD
> impacket-secretsdump -system SYSTEM -sam SAM -system SYSTEM
```

# Notes

 - ODT, XLSX, ... can be opened as zip

## Linux

 - Dump memory: `dd if=/dev/mem of=/tmp/memory.raw bs=1MB`

## Tools

 - [Autopsy](https://www.autopsy.com/): open source digital forensics platform built by Sleuth library
 - [Eric Zimmerman tools](https://ericzimmerman.github.io/#!index.md)

## Reference 

 - [Internal All The things](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-ntds-dumping/#forensic-tools)
 - [MITRE ATT&CK T1003 Credential Dumping](https://www.picussecurity.com/resource/blog/picus-10-critical-mitre-attck-techniques-t1003-credential-dumping)
