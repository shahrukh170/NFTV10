#!/bin/bash
brctl delif br0 eth0 eth1
ifconfig br0 down
brctl delbr br0
ifconfig eth0 192.168.1.1 up
ifconfig eth1 192.168.1.2 up

iptables -D INPUT -m physdev --physdev-in eth0 -j NFQUEUE --queue-num 1
iptables -D INPUT -m physdev --physdev-in eth1 -j NFQUEUE --queue-num 1
iptables -D FORWARD -m physdev --physdev-in eth0 -j NFQUEUE --queue-num 1
iptables -D FORWARD -m physdev --physdev-in eth1 -j NFQUEUE --queue-num 1
