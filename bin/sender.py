from scapy.all import * 
import time 

pkt=Ether()/IP(src='10.1.0.252',dst='10.0.0.251')/TCP()/ICMP()/Raw()
i = 0 
while i < 100:
     sendp(pkt,iface='h2-eth0')
     i = i + 1
     print("sent packet no %s" % str(i))
     time.sleep(1)

