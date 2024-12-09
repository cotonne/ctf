# Windows

## Enumeration

 - `systeminfo`
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
 - Get security protection settings: `Get-MpComputerStatus`
 - Get env variables: `set`
 - Get installed Windows patched:  `Get-Hotfix` or `wmic qfe`
 - Get installed programs: `Get-WmiObject -Class Win32_Product |  select Name, Version` or `wmic product get name`
 - User enumerations with rpcclient : [rpcclient](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration). Other tools: [nulllinux](https://github.com/m8sec/nullinux), [NetExec](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration)

## File

### File System

 - FAT32
 - NTFS
   * Integrity Control Access Control List (icacls): view permissions, can help identify extra permission allowed to EVERYONE

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
 - `.\SharpUp.exe audit`

### NamedPipe

 - `pipelist.exe /accepteula`, ` accesschk.exe /accepteula \\.\Pipe\lsass -v` or `gci \\.\pipe\` (Pipes are used for communication between two applications or processes using shared memory)


## Protections

 - Windows Defender: cmdlet `Get-MpComputerStatus`
 - AppLocker: rules to allow or deny apps from running based on information about the apps' files. You can also use AppLocker to control which users or groups can run those apps. Cmdlet `Get-AppLockerPolicy -Local` to enumerate policy. ` Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`
 - User Account Control / UAC. [List of by-passing techniques](https://github.com/hfiref0x/UACME)
   = Checking if UAC is enabled: `REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA`
   * Checking UAC level: `REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin`

## Network

### Commands
 
 - `ipconfig /all`
 - `arp -a`
 - `route print`
 - `netstat -ano | findstr LISTENING`: get running processes with open ports

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

 - Use services.msc or `tasklist /svc` to find misconfigured or vulnerable services. (`tasklist` lists all running processes)
 - Find a service by name `get-service | ? {$_.DisplayName -like 'Druva*'}`
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

 - `accesschk.exe /accepteula -quvcw AService`, check for who has `SERVICE_ALL_ACCESS`
 - **Unquoted Service Path**: for a service with the path: C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe, Windows will look at: C:\Program, C:\Program Files, C:\Program Files (x86)\System, ... If you can create a file at C:\Program.exe or C:\Program Files (x86)\System.exe, the program will be run
 - `accesschk.exe /accepteula "<USERNAME>" -kvuqsw hklm\System\CurrentControlSet\services` : find Weak Service ACLs. If you can modify `KEY_ALL_ACCESS`, you can overwrite the execution path in service


### Registry

 - regedit
 - The system regedit is stored under:  C:\Windows\System32\Config\
 - The user-specific registry hive (HKCU) is stored in the user folder (i.e., C:\Users\<USERNAME>\Ntuser.dat).
 - Run on startup : HKCU or HKLM\Software\Microsoft\Windows\CurrentVersion\Run

## Users and Groups

### Users

 - `whoami /all`
 - `query user`: get information on logged-in users
 - Display username: `echo %USERNMAE%`
 - Get current user : `whoami /user`
 - Get privilege of current user: `whoami /priv`
 - Get groups of current user: `whoami /groups`
 - Get any user info: `wmic useraccount get sid`, `Get-WmiObject -Class win32_UserAccount | Format-Table Name,SID
`, `Get-CimInstance -Class win32_UserAccount | Format-Table Name,SID`, `Get-LocalUser | Select-Object Name, SID
`
 - Get any group info: `wmic group`
 - Get all users: `net user`
 - Create new user: `net user USERNAME /ADD`
 - Pasword policy: `net accounts`

### Groups

 - Get local groups: `net localgroup`, `net localgroup administrators`
 - Power groups:  Local Administrators, 
 - Power Accounts: NT AUTHORITY\SYSTEM, builtin\administrator
 - Hyper-V Administrators: If Domain Controllers have been virtualized, then the virtualization admins should be considered Domain Admins

### Tokens

 - Access tokens are used to describe the security context: user id, privileges, groups, ... 
 - When a user logged-in, the Local Security Authority (LSA) verifies it and creates an access token
 - Windows validation of token for an action
   * Check the autorization in the token
   * Check the desired requested access
   * Check that the security descriptor (with a discretionary access control list (DACL)) allows that the user/group can have access to the object and has the correct granted type of access. Windows skips the DACL part if the token has the privilege  SeDebugPrivilege

 - [Script to make disabled privs get enabled](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) [Ref1](https://medium.com/@markmotig/enable-all-token-privileges-a7d21b1a4a77), [Ref2](https://medium.com/@markmotig/enable-all-token-privileges-a7d21b1a4a77)
 - Visualize it : [ToeknViewer](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools)
 - [Primary Tokens & Impersonation Token](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/access-tokens#types-of-tokens): 4 levels
 - [Another good ref](https://www.elastic.co/blog/introduction-to-windows-tokens-for-security-practitioners)
 - [Abusing Token Privileges For LPE](https://raw.githubusercontent.com/hatRiot/token-priv/refs/heads/master/abusing_token_eop_1.0.txt)
## Tools

#### SysInternals

 - Process Explorer
 - ProcDump
 - [AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk): list accesses specific users or groups have to resources including files, directories, Registry keys, global objects and Windows services.
 - PsService: View security info of a service `PsService.exe security <service name>`

#### Others

 - [JuicyPotato](https://github.com/ohpe/juicy-potato): If the user has SeImpersonate or SeAssignPrimaryToken privileges then you are SYSTEM. Doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards.
 - [PrintSpoof](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) Windows 10 and Server 2019
 - [RoguePotato](https://github.com/antonioCoco/RoguePotato): Windows Local Privilege Escalation
 - [Mimikatz](https://github.com/ParrotSec/mimikatz):  extract plaintexts passwords, hash, PIN code and kerberos tickets from memory, pass-the-hash, pass-the-ticket or build Golden tickets
   * Use offline to retrieve the NTLM password hash from a LSASS dump
 - [impacket secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
   * Retrieve the hashes of SYSTEM, SAM, and SECURITY from registry hives and do a pass-the-hash attack
 - [Snaffler](https://github.com/SnaffCon/Snaffler) find file shares for sensitive information
 - [WinPeas]() find weaknesses on host
 - Seatbelt:	C# project for performing a wide variety of local privilege escalation checks
 - PowerUp: PowerShell script for finding common Windows privilege escalation vectors that rely on misconfigurations. It can also be used to exploit some of the issues found
 - [SharpUp](https://github.com/GhostPack/SharpUp/): C# version of PowerUp
   = `.\SharpUp.exe audit` to get weak permissions
 - JAWS: PowerShell script for enumerating privilege escalation vectors written in PowerShell 2.0
 - SessionGopher: SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information
 - Watson: Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities.
 - LaZagne:	Tool used for retrieving passwords stored on a local machine from web browsers, chat tools, databases, Git, email, memory dumps, PHP, sysadmin tools, wireless network configurations, internal Windows password storage mechanisms, and more
 - Windows Exploit Suggester - Next Generation: WES-NG is a tool based on the output of Windows' systeminfo utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported
