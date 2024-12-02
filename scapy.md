Read a pcap file and extract ICMP data from ICMP request type:

```python
from scapy.all import *

f = rdpcap('file.pcapng')
flag = b''.join([p[ICMP].load for p in f if ICMP in p and p[ICMP].type == 8])
```

