from  scapy.all import *
import time 

def print_packet(pkt):
    pkt.show()

while True:
    sniff(filter='ip',iface='h1-eth0',count = 1, prn=print_packet)
    time.sleep(1)
