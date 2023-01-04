import time
import socket
from scapy.all import * 
pkt = Ether()
print(pkt.src)
from netaddr import IPAddress
from netaddr.eui import EUI
mac = EUI(\"$MAC\")
ip = mac.ipv6(IPAddress('fe80::'))
print('{ip}%{iface}'.format(ip=ip, iface=\"$IFACE\"))"

for pings in range(10):
    client_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    client_socket.settimeout(1.0)
    message = b'test'
    addr = (pkt.src, 12000)

    start = time.time()
    client_socket.sendto(message, addr)
    try:
        data, server = client_socket.recvfrom(1024)
        end = time.time()
        elapsed = end - start
        print('%s %s %s' % (data,pings,elapsed))
    except socket.timeout:
        print('REQUEST TIMED OUT')
