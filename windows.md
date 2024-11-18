# Windows

## Basic information

 - Get OS version

```
PS> Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber

Version    BuildNumber
-------    -----------
10.0.19041 19041
```

 - Get list of process: `Get-WmiObject -Class Win32_Process | select name`
 - Get BIOS version: `Win32_Bios`
 - Get OS Version (WMI): `wmic os list brief`
 - Get Computer Name: `wmic computersystem get name`
 - Get current user : `whoami /user`
 - Get any user info: `wmic useraccount get sid`
 - Get any group info: `wmic group`
 - Get security protection settings: `Get-MpComputerStatus`

## File System

 - FAT32
 - NTFS
   * Integrity Control Access Control List (icacls)

```
icacls c:\dir
c:\dir NT SERVICE\TrustedInstaller:(F)
       NT SERVICE\TrustedInstaller:(CI)(IO)(F)

(CI): container inherit
(OI): object inherit
(IO): inherit only
(NP): do not propagate inherit
(I): permission inherited from parent container
```

### Shares

#### From Linux
 
 - List avaliable Shares: `smbclient -L SERVER_IP -U user`
 - Connecting to a share: `smbclient '\\SERVER_IP\a_share' -U user`
 - Mount share: `mount -t cifs -o username=USERNAME,password=PASSWORD //SERVER_IP/"a_share" /home/user/Desktop/`

#### From Windows

 - Display shares: `net share`

### Logs
 
 - Computer Management / Event Viewer

### Useful commands

 - Scheduled tasks: `schtasks`
 - Alias (powershell): `Get-Alias`
 - Remote Desktop Access with RDP: `xfreerdp /v:<targetIp> /u:Usernmae /p:Password`
 - Group Policy Editor: `gpedit` 

### Services

 - services.msc
 - View running services (powershell): `Get-Service | ? {$_.Status -eq "Running"} | select -First 2 |fl`
 - Create/Delete/... services: `sc.exe`
 - Query service information: `sc.exe qc wuauserv`
 - View Discretionary Access Control List (DACL)  - ref for decrypt: Security Descriptor Definition Language (SDDL).

```
sc sdshow wuauserv

D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)S:(AU;FA;CCDCLCSWRPWPDTLOSDRCWDWO;;;WD)
```
 - View DACL (powershell): `Get-ACL -Path HKLM:\System\CurrentControlSet\Services\wuauserv | Format-List`

 - lsass.exe	The Local Security Authentication Server verifies the validity of user logons to a PC or server. It generates the process responsible for authenticating users for the Winlogon service.
 - svchost.exe with RPCSS	Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Remote Procedure Call (RPC) Service (RPCSS).
 - svchost.exe with Dcom/PnP	Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Distributed Component Object Model (DCOM) and Plug and Play (PnP) services.


### Registry

 - regedit
 - The system regedit is stored under:  C:\Windows\System32\Config\
 - The user-specific registry hive (HKCU) is stored in the user folder (i.e., C:\Users\<USERNAME>\Ntuser.dat).
 - Run on startup : HKCU or HKLM\Software\Microsoft\Windows\CurrentVersion\Run

### Access Rights

 - UAC
 - Create new user: `net user USERNAME /ADD`

### Tools

#### SysInternals

 - Process Explorer
 - ProcDump
 - [JuicyPotato](https://github.com/ohpe/juicy-potato): If the user has SeImpersonate or SeAssignPrimaryToken privileges then you are SYSTEM.
 - [Mimikatz](https://github.com/ParrotSec/mimikatz):  extract plaintexts passwords, hash, PIN code and kerberos tickets from memory, pass-the-hash, pass-the-ticket or build Golden tickets
