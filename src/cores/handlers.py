from multiprocessing import Process
from scapy.all import *
from scapy.layers import *
from cores.stores import NetflowsStore,RulesStore
from cores.types import PacketInfo
from cores.util import processPktWithPbfRules,processFlowWithfbfRules
import time 
actions = []
ip_packets = []

"""Packet Processing handlers. 

Modes:

        Code                    | Name
        ------------------------+------------------------------------------
        0                       | Gateway
        1                       | Static / Normal
"""

def packetBasedActionDecisionMaker(ip_packet):
        """
                a. Takes an IP packet
                b. applies all avaliable Packet-Based Rules
                c. then returns a new (modified if normalization has been done) packet
                d. the action performed on the packet.

        :param ip_packet a IP packet
        """
        active_rules = RulesStore.pbfRules()
        return processPktWithPbfRules(ip_packet, active_rules)

def flowBasedActionDecisionMaker(net_flow_id):
        """This function: [ Version 5 ]
                1. Takes a net flow ID
                2. Searches for the net flow using that ID
                3. If found, all available net flow rules are applied.
                4. Decision is made to either:
                        4.1 Forward all packets belonging to this flow,
                        4.2 Drop all packets belonging to this flow or
                        4.3 Normalize all packets belonging to this flow.

        :param net_flow_id a Real Netflow ID
        """
        global actions
        actions = []
        action = 'normalised'
        global ip_packets
        ip_packet = net_flow_id
        
        if net_flow_id.haslayer(NetflowDataflowsetV9) and len(net_flow_id.getlayer(NetflowDataflowsetV9).records) > 0 :
                 for i in range(0,len(net_flow_id.getlayer(NetflowDataflowsetV9).records),1):
                        nf_record = net_flow_id.getlayer(NetflowDataflowsetV9).records[i]
                        nf_records = netflow.NetflowRecordV9(nf_record)
                        nf_records.show()
                        templateIDs = net_flow_id.getlayer(netflow.NetflowDataflowsetV9).templateID
                        #active_rules = RulesStore.fbfRules()
                        active_rules = RulesStore.pbfRules()
                        ip_packet,action = processFlowWithfbfRules(ip_packet, active_rules,nf_record)
                        ip_packets.append(ip_packet)
                        actions.append(action)
                        print(action)
                        
                        
        
        print(action,actions)
        #nf_record = net_flow_id.getlayer(NetflowHeaderV9)
        #ip_packet = NetflowRecordV9(nf_record)
        #active_rules = RulesStore.fbfRules()
        return  ip_packet,action ##processFlowWithfbfRules(ip_packet, active_rules)

def gatewayFilterPacketsHandler(packet,dashboard_object,nf_object,dashboard2_object,dashboard3_object):
        """A callback method for packets captured in Gateway mode.
        """
        ip_pkt = IP(packet.get_payload())
        NetflowsStore.update(PacketInfo.fromIpPacket(ip_pkt))
        time_lapsed = (time.time() - nf_object.start_time)+1 ## seconds  
        nf_object.data_in_flow = round(len(packet.get_payload()),3)
        nf_object.data_in_flow_sec = round((len(packet.get_payload())/(time_lapsed)),3)
        action = 'forwarded'
        
        #ip_packet=  ip_packets =IP(packet.get_payload())
        #p_info =PacketInfo.fromIpPacket(ip_packet)
        #NetflowsStore.update(p_info)
        #if ip_packet.haslayer(IP) or ip_packet.haslayer(ICMP) or ip_packet.haslayer(TCP) or ip_packet.haslayer(UDP):
        #        ip_packet.show()
        #        ip_packet, action = packetBasedActionDecisionMaker(ip_packet)
        #        
        #if ip_packet.haslayer(netflow.NetflowHeader):
        #        try:
        #                ip_packets = netflowv9_defragment(ip_packet)[0]
        #                #ip_packets.show()
        #                
        #        except Exception as e:
        #                print("Exception :" + str(e))
        #                pass
        #        if ip_packet.haslayer(netflow.NetflowHeaderV9):
        #                ip_packets, action = flowBasedActionDecisionMaker(ip_packet)
        
        print("Action : %s " % (action))
        
        #if action == 'forwarded' or action == 'normalised':
        if action == 'forwarded':
                 nf_object.forwarded_packets += 1

        #                packet.accept()
        #        if action == 'normalised':
        #                nf_object.normalized_packets += 1
        #                packet.set_payload(ip_packet.__bytes__())
        #                packet.accept()
        #
        #else:
        #        packet.drop()
        #        nf_object.dropped_packets += 1
        
         
        nf_object.total_out_packets = nf_object.forwarded_packets + nf_object.normalized_packets
        time_lapsed = (time.time() - nf_object.start_time)+1 ## seconds 
        nf_object.forwarded_packets_array.append(nf_object.forwarded_packets)
        nf_object.normalized_packets_array.append(nf_object.normalized_packets)
        nf_object.dropped_packets_array.append(nf_object.dropped_packets)
        nf_object.total_in_packets_array.append(nf_object.total_in_packets)
        nf_object.total_out_packets_array.append(nf_object.total_out_packets)
        nf_object.total_in_packets_secs_array.append(round(float(nf_object.total_in_packets/time_lapsed),3))
        nf_object.total_out_packets_secs_array.append(round(float(nf_object.total_out_packets/time_lapsed),3))
        
        nf_object.data_out_flow = round(len(packet.get_payload()),3)
        if action == "dropped":
                nf_object.data_out_flow = 0.0
        nf_object.data_out_flow_sec = round((len(packet.get_payload())/(time_lapsed)),3)
        if action == "dropped":
                nf_object.data_out_flow_sec = 0.0
        print("Ping 1")      
        ######################### set display values on dashboard #######################
        dashboard_object.packets_in.delete(0,"end")
        dashboard_object.packets_in.insert(0,nf_object.total_in_packets)
        dashboard_object.packets_out.delete(0,'end')
        dashboard_object.packets_out.insert(0,nf_object.total_out_packets)
        dashboard_object.packets_in_sec.delete(0,'end')
        dashboard_object.packets_in_sec.insert(0,round(float(nf_object.total_in_packets/time_lapsed),3))
        dashboard_object.packets_out_sec.delete(0,'end')
        dashboard_object.packets_out_sec.insert(0,round(float(nf_object.total_out_packets/time_lapsed),3))
         
        
        try: 
                dashboard_object.data_recvd.delete(0,'end')
                dashboard_object.data_recvd.insert(0,nf_object.data_in_flow)
                dashboard_object.data_sent.delete(0,'end')
                dashboard_object.data_sent.insert(0,nf_object.data_out_flow)
                dashboard_object.data_recvd_sec.delete(0,'end')
                dashboard_object.data_recvd_sec.insert(0,round(float(nf_object.data_in_flow_sec/time_lapsed),3))
                dashboard_object.data_sent_sec.delete(0,'end')
                dashboard_object.data_sent_sec.insert(0,round(float(nf_object.data_out_flow_sec/time_lapsed),3))
                 
        
                dashboard_object.ax1.plot(range(len(nf_object.total_in_packets_array)),nf_object.total_in_packets_array,'--g')
                dashboard_object.ax1.plot(range(len(nf_object.total_out_packets_array)),nf_object.total_out_packets_array,'--r')
                dashboard_object.ax1.plot(range(len(nf_object.total_in_packets_secs_array)),nf_object.total_in_packets_secs_array,'--b')
                dashboard_object.ax1.plot(range(len(nf_object.total_out_packets_secs_array)),nf_object.total_out_packets_secs_array,'--o')
        except Exception as e:
                print("Exception:" + str(e))
                pass
        
        print("Ping 2")	
        nf_object.data_in_flow_array.append(nf_object.data_out_flow)
        nf_object.data_out_flow_array.append(nf_object.data_out_flow)
        nf_object.data_in_flow_sec_array.append(nf_object.data_in_flow_sec)
        nf_object.data_out_flow_sec_array.append(nf_object.data_out_flow_sec)
        
        try:                                    
                dashboard_object.ax2.plot(range(len(nf_object.data_in_flow_array)),nf_object.data_in_flow_array,'--g')
                dashboard_object.ax2.plot(range(len(nf_object.data_out_flow_array)),nf_object.data_out_flow_array,'--r')
                dashboard_object.ax2.plot(range(len(nf_object.data_in_flow_sec_array)),nf_object.data_in_flow_sec_array,'--b')
                dashboard_object.ax2.plot(range(len(nf_object.data_in_flow_sec_array)),nf_object.data_in_flow_sec_array,'--o')
                                
        except :
                return False 
        try:
                nf_object.checkMemoryUsage()
                nf_object.printResourcesUsageStats(dashboard2_object,dashboard_object)
                dashboard_object.canvas.draw()
                dashboard_object.toolbar.update()
                
                
        except:
                return False
        
        try:                 
                ######################### set display values on dashboard2 #######################
                dashboard2_object.forwarded_packets.delete(0,'end')
                dashboard2_object.forwarded_packets.insert(0,nf_object.forwarded_packets)
                dashboard2_object.dropped_packets.delete(0,'end')
                dashboard2_object.dropped_packets.insert(0,nf_object.dropped_packets)
                dashboard2_object.normalized_packets.delete(0,'end')
                dashboard2_object.normalized_packets.insert(0,nf_object.normalized_packets)
                dashboard2_object.packets_out.delete(0,'end')
                dashboard2_object.packets_out.insert(0,nf_object.total_out_packets)
                dashboard2_object.ax4.plot(range(len(nf_object.forwarded_packets_array)),nf_object.forwarded_packets_array,'--g')
                dashboard2_object.ax4.plot(range(len(nf_object.dropped_packets_array)),nf_object.dropped_packets_array,'--r')
                dashboard2_object.ax4.plot(range(len(nf_object.normalized_packets_array)),nf_object.normalized_packets_array,'--b')
                dashboard2_object.ax4.plot(range(len(nf_object.total_out_packets_array)),nf_object.total_out_packets_array,'--o')
                dashboard2_object.canvas.draw()
                dashboard2_object.toolbar.update()
                
        except:
                return False 
        print("Ping 3")  
        packet.accept()
        return True


def staticFilterPacketsHandler(packet,dashboard_object,nf_object,dashboard2_object,dashboard3_object):
        """A callback method for packets captured in Static / Noraml Filter mode.

        :param packet a newly captured packet.
        """
        
        time_lapsed = (time.time() - nf_object.start_time)+1 ## seconds  
        nf_object.data_in_flow = round(len(packet.get_payload()),3)
        nf_object.data_in_flow_sec = round((len(packet.get_payload())/(time_lapsed)),3)
        action = 'forwarded'
        
        ip_packet=  ip_packets =IP(packet.get_payload())
        p_info =PacketInfo.fromIpPacket(ip_packet)
        NetflowsStore.update(p_info)
        if ip_packet.haslayer(IP) or ip_packet.haslayer(ICMP) or ip_packet.haslayer(TCP) or ip_packet.haslayer(UDP):
                ip_packet.show()
                ip_packet, action = packetBasedActionDecisionMaker(ip_packet)
                
        if ip_packet.haslayer(netflow.NetflowHeader):
                try:
                        ip_packets = netflowv9_defragment(ip_packet)[0]
                        #ip_packets.show()
                        
                except Exception as e:
                        print("Exception :" + str(e))
                        pass
                if ip_packet.haslayer(netflow.NetflowHeaderV9):
                        ip_packets, action = flowBasedActionDecisionMaker(ip_packet)
        
        print("Action : %s " % (action))
        
        if action == 'forwarded' or action == 'normalised':
                if action == 'forwarded':
                        nf_object.forwarded_packets += 1
                        packet.accept()
                if action == 'normalised':
                        nf_object.normalized_packets += 1
                        packet.set_payload(ip_packet.__bytes__())
                        packet.accept()

        else:
                packet.drop()
                nf_object.dropped_packets += 1
        
         
        nf_object.total_out_packets = nf_object.forwarded_packets + nf_object.normalized_packets
        time_lapsed = (time.time() - nf_object.start_time)+1 ## seconds 
        nf_object.forwarded_packets_array.append(nf_object.forwarded_packets)
        nf_object.normalized_packets_array.append(nf_object.normalized_packets)
        nf_object.dropped_packets_array.append(nf_object.dropped_packets)
        nf_object.total_in_packets_array.append(nf_object.total_in_packets)
        nf_object.total_out_packets_array.append(nf_object.total_out_packets)
        nf_object.total_in_packets_secs_array.append(round(float(nf_object.total_in_packets/time_lapsed),3))
        nf_object.total_out_packets_secs_array.append(round(float(nf_object.total_out_packets/time_lapsed),3))
        
        nf_object.data_out_flow = round(len(packet.get_payload()),3)
        if action == "dropped":
                nf_object.data_out_flow = 0.0
        nf_object.data_out_flow_sec = round((len(packet.get_payload())/(time_lapsed)),3)
        if action == "dropped":
                nf_object.data_out_flow_sec = 0.0
        print("Ping 1")      
        ######################### set display values on dashboard #######################
        dashboard_object.packets_in.delete(0,"end")
        dashboard_object.packets_in.insert(0,nf_object.total_in_packets)
        dashboard_object.packets_out.delete(0,'end')
        dashboard_object.packets_out.insert(0,nf_object.total_out_packets)
        dashboard_object.packets_in_sec.delete(0,'end')
        dashboard_object.packets_in_sec.insert(0,round(float(nf_object.total_in_packets/time_lapsed),3))
        dashboard_object.packets_out_sec.delete(0,'end')
        dashboard_object.packets_out_sec.insert(0,round(float(nf_object.total_out_packets/time_lapsed),3))
         
        
        try: 
                dashboard_object.data_recvd.delete(0,'end')
                dashboard_object.data_recvd.insert(0,nf_object.data_in_flow)
                dashboard_object.data_sent.delete(0,'end')
                dashboard_object.data_sent.insert(0,nf_object.data_out_flow)
                dashboard_object.data_recvd_sec.delete(0,'end')
                dashboard_object.data_recvd_sec.insert(0,round(float(nf_object.data_in_flow_sec/time_lapsed),3))
                dashboard_object.data_sent_sec.delete(0,'end')
                dashboard_object.data_sent_sec.insert(0,round(float(nf_object.data_out_flow_sec/time_lapsed),3))
                 
        
                dashboard_object.ax1.plot(range(len(nf_object.total_in_packets_array)),nf_object.total_in_packets_array,'--g')
                dashboard_object.ax1.plot(range(len(nf_object.total_out_packets_array)),nf_object.total_out_packets_array,'--r')
                dashboard_object.ax1.plot(range(len(nf_object.total_in_packets_secs_array)),nf_object.total_in_packets_secs_array,'--b')
                dashboard_object.ax1.plot(range(len(nf_object.total_out_packets_secs_array)),nf_object.total_out_packets_secs_array,'--o')
        except Exception as e:
                print("Exception:" + str(e))
                pass
        
        print("Ping 2")	
        nf_object.data_in_flow_array.append(nf_object.data_out_flow)
        nf_object.data_out_flow_array.append(nf_object.data_out_flow)
        nf_object.data_in_flow_sec_array.append(nf_object.data_in_flow_sec)
        nf_object.data_out_flow_sec_array.append(nf_object.data_out_flow_sec)
        
        try:                                    
                dashboard_object.ax2.plot(range(len(nf_object.data_in_flow_array)),nf_object.data_in_flow_array,'--g')
                dashboard_object.ax2.plot(range(len(nf_object.data_out_flow_array)),nf_object.data_out_flow_array,'--r')
                dashboard_object.ax2.plot(range(len(nf_object.data_in_flow_sec_array)),nf_object.data_in_flow_sec_array,'--b')
                dashboard_object.ax2.plot(range(len(nf_object.data_in_flow_sec_array)),nf_object.data_in_flow_sec_array,'--o')
                                
        except :
                return False 
        try:
                #process1 = Process(target=nf_object.checkMemoryUsage())
                #process1.start()
                #process2 = Process(args=(dashboard2_object,dashboard_object),target=nf_object.printResourcesUsageStats())
                #process2.start()
                nf_object.checkMemoryUsage()
                nf_object.printResourcesUsageStats(dashboard2_object,dashboard_object)
                dashboard_object.canvas.draw()
                dashboard_object.toolbar.update()
                #process1.join()
                #process2.join()

        except:
                return False
        
        try:                 
                ######################### set display values on dashboard2 #######################
                dashboard2_object.forwarded_packets.delete(0,'end')
                dashboard2_object.forwarded_packets.insert(0,nf_object.forwarded_packets)
                dashboard2_object.dropped_packets.delete(0,'end')
                dashboard2_object.dropped_packets.insert(0,nf_object.dropped_packets)
                dashboard2_object.normalized_packets.delete(0,'end')
                dashboard2_object.normalized_packets.insert(0,nf_object.normalized_packets)
                dashboard2_object.packets_out.delete(0,'end')
                dashboard2_object.packets_out.insert(0,nf_object.total_out_packets)
                dashboard2_object.ax4.plot(range(len(nf_object.forwarded_packets_array)),nf_object.forwarded_packets_array,'--g')
                dashboard2_object.ax4.plot(range(len(nf_object.dropped_packets_array)),nf_object.dropped_packets_array,'--r')
                dashboard2_object.ax4.plot(range(len(nf_object.normalized_packets_array)),nf_object.normalized_packets_array,'--b')
                dashboard2_object.ax4.plot(range(len(nf_object.total_out_packets_array)),nf_object.total_out_packets_array,'--o')
                dashboard2_object.canvas.draw()
                dashboard2_object.toolbar.update()
                
        except:
                return False 
        print("Ping 3")  
        return True
          
 
        
               
