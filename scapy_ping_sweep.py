from scapy.all import *

# sr(IP(dst="192.168.56.99-110")/ICMP())
def pingsweep(ip_cidr: str):
    """
        Get all responding hosts given an IP with CIDR
    """
    all_ips = []
     
    for ip in list(Net(ip_cidr))[1:]:
        print("Current : ", ip)

        packet = IP(dst=ip) / ICMP()
        response = sr1(packet, timeout = 1, retry=0, verbose=0)
        if response is not None and ICMP in response and response[ICMP].type == 0:
            print(response)
            all_ips.append(response.src)

    return all_ips

if __name__ == '__main__':
    print(pingsweep("10.0.2.0/27"))
