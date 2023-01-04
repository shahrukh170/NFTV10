from scapy.all import IP
from core.stores import NetflowsStore,RulesStore,PacketflowsStore
from core.rules import Rule
from core.types import packetInfo,NetflowPacketInfo
from core.types import packetInfo as PacketInfo , NetflowPacketInfo, Netflow,Packetflow, PacketBasedFilterRule
from core.util import processPktWithPbfRules,processFlowWithfbfRules
from scapy.all import *
from scapy.contrib import *
from scapy.contrib.bgp import *
from scapy.contrib.ldp import *
from scapy.layers.netflow import *
from scapy.layers.all import *
import netfilterqueue
from DynTimeOuts import LruPacketflow
from functools import lru_cache
from timeit import repeat
import sys,psutil ,os
# Initialise the Node
class Node:
    def __init__(self, data):
        self.item = data
        self.data = data
        self.next = None
        self.prev = None
        
# Class for doubly Linked List
class doublyLinkedList:
    def __init__(self):
        self.start_node = None
        self.values = dict()
    # Insert Element to Empty list
    def InsertToEmptyList(self, data):
        if self.start_node is None:
            new_node = Node(data)
            self.start_node = new_node
        else:
            print("The list is empty")
    # Insert element at the end
    def InsertToEnd(self, data):
        # Check if the list is empty
        if self.start_node is None:
            new_node = Node(data)
            self.start_node = new_node
            return
        n = self.start_node
        # Iterate till the next reaches NULL
        while n.next is not None:
            n = n.next
        new_node = Node(data)
        n.next = new_node
        new_node.prev = n
        
    # Insert element at the start
    def InsertToStart(self, data):
        # Check if the list is empty
        if self.start_node is None:
            new_node = Node(data)
            self.start_node = new_node
            return
        n = self.start_node
        # Iterate till the next reaches NULL
        while n.prev is not None:
            n = n.prev
        new_node = Node(data)
        self.start_node = new_node
        new_node.next = n

    # Insert element at the start
    def MoveToStart(self,key):
        data = None
        #search for the key
        found,index = self.search(key)
        if found:
            data = self.get_node_data(key)
            self.delete(index-2)
        else:
            new_node = Node(data)
            self.start_node = new_node
            return False
        
        n = self.start_node
        # Iterate till the next reaches NULL
        while n.prev is not None:
            n = n.prev
        new_node = Node(data)
        self.start_node = new_node
        new_node.next = n
        if self.search(key):
            return True
        else:
            return False
        
        
    # Delete the elements from the start
    def DeleteAtStart(self):
        if self.start_node is None:
            print("The Linked list is empty, no element to delete")
            return 
        if self.start_node.next is None:
            self.start_node = None
            return
        self.start_node = self.start_node.next
        self.start_prev = None;
    # Delete the elements from the end
    def delete_at_end(self):
        # Check if the List is empty
        if self.start_node is None:
            print("The Linked list is empty, no element to delete")
            return 
        if self.start_node.next is None:
            self.start_node = None
            return
        n = self.start_node
        while n.next is not None:
            n = n.next
        n.prev.next = None
    # Traversing and Displaying each element of the list
    def Display(self):
        if self.start_node is None:
            print("The list is empty")
            return
        else:
            n = self.start_node
            while n is not None:
                print("Element is: ", n.item)
                n = n.next
        print("\n")
    # Traversing and Displaying each element of the list
    def generate_dict(self):
        if self.start_node is None:
            print("The list is empty")
            return
        else:
            n = self.start_node
            results = dict()
            while n is not None:
                results.update(n.data)
                #print("Element is: ", n.item)
                n = n.next
        #print("\n")
        return results
      
    def get_stored_policy_records(self):
        i = 0
        if self.start_node is None:
            print("The list is empty")
            return "kukar"
        else:
            n = self.start_node
            while n is not None:
                #print("Element is: ", n.item)
                self.values[i+1] = n.item
                n = n.next
                i = i + 1
        #print("\n")
        return self.values 
        
    def get_node_data(self, key):
        curr = self.start_node
        while curr:
            if list(curr.data.keys())[0] == key:
                return curr.data
            curr = curr.next
    
    def delete(self, key):
        curr = self.start_node
        while curr:
            if list(curr.data.keys())[0] == key:
                node_to_delete = curr.next
                curr.data = node_to_delete.data
                curr.next = node_to_delete.next
                return True
            curr = curr.next
        return False    
    def search(self, key):
        curr = self.start_node
        i = 1 
        while curr:
            if list(curr.data.keys())[0] == key:
                return True , i
            curr = curr.next
            i = i + 1
        curr = self.start_node
        i = 0 
        while curr:
            if list(curr.data.keys())[0] == key:
                return True , i
            curr = curr.prev
            i = i + 1
        
        False,0
####### LINKED LIST LRU OPERATION ###############
branches = [ { i+1 : str(i+1) } for i in range(12)]
branches = branches[0]
LRU_Cursor = doublyLinkedList()
def populate_db_linked_list_LRU():
        for key,value in branches.items():
            LRU_Cursor.InsertToEnd({key:value})

DynTimeOuts = LruPacketflow(branches)
actions = []
ip_packets = []
ruleno = ''
active_rules = RulesStore.fbfRules()
                
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

def flowBasedActionDecisionMaker(net_flow_id,nf_object):
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
        global ruleno 
        actions = []
        ruleno = ''
        action = 'forwarded'
        global ip_packets
        ip_packet = net_flow_id
        branches = {i+1 : str(i+1) for i in range(12)}
        #branches = branches[0]
        if net_flow_id.haslayer(NetflowDataflowsetV9)and len(net_flow_id.getlayer(NetflowDataflowsetV9).records) > 0 :
                         for i in range(0,len(net_flow_id.getlayer(NetflowDataflowsetV9).records)):
                                nf_record = net_flow_id.getlayer(NetflowDataflowsetV9).records[i]
                                nf_records = NetflowRecordV9(nf_record)
                                ##nf_records.show()
                                templateIDs = net_flow_id.getlayer(NetflowDataflowsetV9).templateID
                                active_rules = RulesStore.fbfRules()
                                branch = {len(branches) + 1 : str(ruleno)}
                                ip_packet,action,rulenos = processFlowWithfbfRules(ip_packet, active_rules,nf_records)
                                p_info = NetflowPacketInfo.fromIpPacket(nf_records,rulenos)
                                NetflowsStore.update(p_info) 
                                ruleno = str(int(rulenos)+1) ###+ "," ## .append(rulenos)
                                ##print(p_info)
                                LRU_Cursor.InsertToEnd(branch)
                                nf_object.net_flow_records += 1
                                #ip_packets.append(ip_packet)
                                #actions.append(action)
                                                        
                        
        return  ip_packet,action,ruleno     ##processFlowWithfbfRules(ip_packet, active_rules)
        ##print(action,actions,ruleno)
        #nf_record = net_flow_id.getlayer(NetflowHeaderV9)
        #ip_packet = NetflowRecordV9(nf_record)
        #active_rules = RulesStore.fbfRules()
        ############  RE ORDERING FLOWS WITH LINKED LIST #######################
        #keys = len(self.branches)
        #           self.LRU_Cursor.InsertToEnd({keys:rule_fields})
        #           branchesX.pop(key)
            
        # Resolve conflicts after matching packet with 4 or more rules in policy
        # EXPERT POLICY HAS 4 of redundant(conflicting) anomalies
        threshold = 2
        X = 0
        i = 0
        active_rules = RulesStore.fbfRules()
        #branches = LRU_Cursor.generate_dict()
        #LRU_Cursor.InsertToEnd({len(branches)+1:ruleno})
        if branches and len(active_rules) >= 0:
                branches = LRU_Cursor.generate_dict()
                #print(branches.keys())
                branch = {len(branches) + 1 : str(ruleno)}
                DynTimeOuts = LruPacketflow(branches)
                branches = DynTimeOuts.update(branch,len(branches) + 1)
                #print(branches.keys())
                               
        

        return  ip_packet,action,ruleno     ##processFlowWithfbfRules(ip_packet, active_rules)

def gatewayFilterPacketsHandler(packet,nf_object):
        """A callback method for packets captured in Gateway mode."""
        global ruleno
        action = 'forwarded'
        p_info = None
        ### NET FLOW VERSION 
        NFV = 0 
        ruleno = ''
        ip_pkt = p_info  = ip_packet = IP(packet.get_payload())
        if ip_packet.haslayer(NetflowHeader) or ip_packet.haslayer(NetflowHeaderV9) or ip_packet.haslayer(NetflowFlowsetV9) or ip_packet.haslayer(NetflowDataflowsetV9):
                ruleno = str('0,')
                NetflowsStore.update(NetflowPacketInfo.fromIpPacket(ip_pkt,ruleno))
                NFV = 9   
        else:
                ruleno = str('0,') 
                PacketflowsStore.update(packetInfo.fromIpPacket(ip_pkt,ruleno))
                NFV = 1
        
        proto = None
        try:
                proto =  netfilterqueue.PROTOCOLS[p_info.proto]

        except:
                proto = "NA"
                pass 
         
        action = 'forwarded'
        pid = os.getpid()
        python_process = psutil.Process(pid)
        nf_object.avg_ram = memoryUse = python_process.memory_info()[0]/2.**30  # memory use in GB...I think
        #print('memory use:', memoryUse)

        print("    %-20s%-20s%-10s%-10d%-15s%-15.4f%-.3f" % (p_info.src, p_info.dst, proto,\
			NFV, action.upper(), round(memoryUse * 1000,4), nf_object.get_cpu_usage()))
        action = 'forwarded'
        ##print("Action : %s " % (action))
        if action == 'forwarded':
                nf_object.forwarded_packets += 1
                packet.accept()

        if action == 'normalised':
                nf_object.normalized_packets += 1
                packet.set_payload(ip_packet.__bytes__())
                packet.accept()

        if action == 'dropped':
                packet.drop()
                nf_object.dropped_packets += 1
        nf_object.total_packets_g.append(nf_object.forwarded_packets + nf_object.normalized_packets + nf_object.dropped_packets)
        nf_object.drop_packets_g.append(nf_object.dropped_packets)
        nf_object.forward_packets_g.append(nf_object.forwarded_packets)
        nf_object.normalized_packets_g.append(nf_object.normalized_packets)
        nf_object.cpu_g.append(nf_object.get_cpu_usage())
        nf_object.ram_g.append(round(memoryUse*1000,4))
        nf_object.uptime_g.append(nf_object.uptime)




def staticFilterPacketsHandler(packet,nf_object):
        """A callback method for packets captured in Static / Noraml Filter mode.

        :param packet a newly captured packet.
        """
        global ruleno
        action = 'forwarded'
        p_info = None

        ### NET FLOW VERSION 
        NFV = 0 
        ruleno = ''
        ip_packet=  ip_packets =IP(packet.get_payload())
        #if ip_packet.haslayer(IP) or ip_packet.haslayer(ICMP) or ip_packet.haslayer(TCP) or ip_packet.haslayer(UDP):
        #        print("Dynamic .... warden .... ") ##ip_packet.show()
        #        ip_packet, action = packetBasedActionDecisionMaker(ip_packet)
                
        if ip_packet.haslayer(NetflowHeader) or ip_packet.haslayer(NetflowHeaderV9) or ip_packet.haslayer(NetflowFlowsetV9) or ip_packet.haslayer(NetflowDataflowsetV9):
                ##print("Netflow .... warden .... ")
                #ip_packet.show()
                try:
                        ip_packets = netflowv9_defragment(ip_packet)
                        #ip_packets[0].show()
                        ip_packet = ip_packets[0]
                        
                except Exception as e:
                        print("Exception:" + str(e))
                        pass
                #if ip_packet.haslayer(NetflowHeaderV9):
                #ip_packet.show()
                ## MET FLOW VERSION 
                NFV = 9
                p_info, action,ruleno = flowBasedActionDecisionMaker(ip_packet,nf_object)
                #NetflowsStore.reportInExcel()
                NFV = "9(" + ruleno + ")"  
                nf_object.net_flow_packets += 1                  
                        
        else:
                ##print("Dynamic .... warden .... ") 
                ## NETFLOW VERSION 
                NFV = 1  
                ##ip_packet.show()
                p_info, action,rulenos = packetBasedActionDecisionMaker(ip_packet)
                p_info = packetInfo.fromIpPacket(ip_packet,rulenos)
                PacketflowsStore.update(p_info) 
                #PacketflowsStore.reportInExcel()
                nf_object.normal_packets = abs(nf_object.total_in_packets - nf_object.net_flow_packets) 
                ruleno = str(int(rulenos)+1)  ##+ ","
                NFV = "1(" + ruleno + ")" 
                #wrpcap('sniff3.pcap', packets[0], append=True)  #appends packet$
                #print("Packet count :" + str(count))
                #count = count + 1
        proto = None
        try:
                proto =  netfilterqueue.PROTOCOLS[p_info.proto]

        except:
                pass 
        #if proto == 'UDP' or 'I-NLSP':
        #        return
        pid = os.getpid()
        python_process = psutil.Process(pid)
        nf_object.avg_ram = memoryUse = python_process.memory_info()[0]/2.**30  # memory use in GB...I think
        #print('memory use:', memoryUse)
        #print("packet size " , sys.getsizeof(packet),NFV,str(psutil.virtual_memory().percent))        
        print("    %-20s%-20s%-10s%-15s%-15s%-15.4f%-.3f" % (p_info.src, p_info.dst, proto,\
			NFV, action.upper(), round(memoryUse*1000,4), nf_object.get_cpu_usage()))
        
        ##print("Action : %s " % (action))
        if action == 'forwarded':
                nf_object.forwarded_packets += 1
                packet.accept()

        if action == 'normalised':
                nf_object.normalized_packets += 1
                packet.set_payload(ip_packet.__bytes__())
                packet.accept()

        if action == 'dropped':
                packet.drop()
                nf_object.dropped_packets += 1

        nf_object.total_packets_g.append(nf_object.forwarded_packets + nf_object.normalized_packets + nf_object.dropped_packets)
        nf_object.drop_packets_g.append(nf_object.dropped_packets)
        nf_object.forward_packets_g.append(nf_object.forwarded_packets)
        nf_object.normalized_packets_g.append(nf_object.normalized_packets)
        nf_object.cpu_g.append(nf_object.get_cpu_usage())
        nf_object.ram_g.append(round(memoryUse*1000,4))
        nf_object.uptime_g.append(nf_object.uptime)


