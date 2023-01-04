from scapy.all import *

def prnt(pkt):
    print(pkt.src,pkt.dst)

print("[+] Sniffing .... ")
while True:
	sniff(filter='ip',prn=prnt)
