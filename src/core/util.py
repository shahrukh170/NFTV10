from scapy.all import *
from scapy.layers import *
import netifaces
from core.stores import RulesStore
import netfilterqueue
from netfilterqueue import PROTOCOLS
import json
from functools import lru_cache
from timeit import repeat

def getIfaceNameByAddr(ip):

        all_ifaces = netifaces.interfaces()

        #resolve ip for each, compare with 'ip'
        for iface in all_ifaces:
                all_addrs = netifaces.ifaddresses(iface)
                if iface is not 'lo' and all_addrs.__contains__(netifaces.AF_INET):
                        af_inet = all_addrs[netifaces.AF_INET][0]
                        if af_inet.__contains__('addr') and af_inet['addr'] == ip:
                                return iface
        return None


def getConditionalOperator(cond):
        """
        get the comparison operator used in the condition
        """
        all_ops = ['<=','<','==','!=','>=','>']

        for op in all_ops:
                if len(cond.split(op)) > 1:
                        return op


def extractNetworkAddr(sub_ip_info, pkt_ip):
        """
        get the network part of an ip (src/dst) and the network part of a subnet ip
        """
        sub_addr = sub_ip_info[0].split('.')[:3] if(sub_ip_info[1] >= '24') else \
                sub_ip_info[0].split('.')[:2] if(sub_ip_info[1] >= '16') else sub_ip_info[0].split('.')[:1]
        
        ip_addr  = pkt_ip.split('.')[:3] if(len(sub_addr) == 3) else \
                pkt_ip.split('.')[:2] if(len(sub_addr) == 2) else pkt_ip.split('.')[:1]

        sub_addr_str = ''
        ip_addr_str  = ''

        for i in sub_addr:
                sub_addr_str = sub_addr_str + str(i) + '.'

        for i in ip_addr:
                ip_addr_str = ip_addr_str + str(i) + '.'

        return (ip_addr_str, sub_addr_str)


def bytes_to_str(byts):

        strng = ''
        for i in range(len(byts)):
                j = int(byts[i])
                if j < 127 and j >= 32:
                        strng += chr(j)
                else:
                        strng += '.'

        return strng


def alterPacketAttr(pkt, prtcl, norm_op):
        """
        apply a normalization rule
        """
        #the attribute to be altered must be separated by '=' from the value
        attr_name = norm_op.split('=')[0]
        attr_val  = norm_op.split('=')[1]
        # search for attributes top-down i.e if we want to alter flags in IP()/TCP(), its really hard to tell whether its tcp or ip
        # flags. The script will have a standard way of handling this TCP layer first then back to IP layer 
        if attr_name == 'payload' and pkt.haslayer(prtcl) and pkt.haslayer('Raw'):
                pkt.getlayer('Raw').setfieldval('load',attr_val)
                return IP(pkt.__bytes__())

        if pkt.haslayer(prtcl):
                try:
                        pkt.getlayer(prtcl).getfieldval(attr_name)
                        pkt.getlayer(prtcl).setfieldval(attr_name, attr_val if(attr_name == 'dst' or attr_name == 'src') \
                                else None if(attr_val == 'NULL') else int(attr_val))

                except AttributeError:
                        #this means the attr in question is in the lower layer (IP)
                        try:
                                pkt.getfieldval(attr_name)
                                pkt.setfieldval(attr_name, attr_val if(attr_name == 'dst' or attr_name == 'src') \
                                        else None if(attr_val == 'NULL') else int(attr_val))
                        except:
                                pass
        else:
                #protocol ==> ANY
                try:
                        pkt.getfieldval(attr_name)
                        pkt.setfieldval(attr_name, (attr_val if(attr_name == 'dst' or attr_name == 'src') \
                                else None if(attr_val == 'NULL') else int(attr_val)))
                except:
                        #this means the attr isnt in the IP layer either
                        #make no changes
                        pass

        return IP(pkt.__bytes__())

def eval_t(args,cond_op):
                if not args:
                    return 0                     
                if  len(args) > 1:
                    args = "".join(args)
                parts = args.split(cond_op)
                
                if type(parts[0]) == int and type(parts[1]) == int:
                    if cond_op == '==':
                        return eval(parts[0] == parts[1])
                    elif cond_op == '=':
                        return eval(parts[0] == parts[1])
                    elif cond_op == '<>':
                        return eval(parts[0] != parts[1])
                    elif cond_op == '!=':
                        return eval(parts[0] != parts[1])
                    
                    elif cond_op == '<=':
                        return eval(parts[0] <= parts[1])
                    
                    elif cond_op == '>=':
                        return eval(parts[0] >= parts[1])

                    elif cond_op == '>':
                        return eval(parts[0] > parts[1])

                    elif cond_op == '<':
                        return eval(parts[0] < parts[1])
                    
                if type(parts[0]) == str and type(parts[1]) == str:
                    set1 = set(parts[0].split('.'))
                    set2 = set(parts[1].split('.'))
                           
                    if cond_op == '==':
                        
                        return set1 == set2
                    elif cond_op == '=':
                        return set1 == set2
                    elif cond_op == '<>':
                        return set1 != set2
                    elif cond_op == '!=':
                        return set1 != set2
                                        
                return False
        



def evalPbfRuleCondition(pkt, cond_list, rule_proto):
        """
        evaluate the condition
        """
        rule_applicable = True

        for cond in cond_list:
                new_cond = None
                cond_op = getConditionalOperator(cond)
                attr_name = cond.split(cond_op)[0]
                attr_val  = cond.split(cond_op)[1]

                if attr_name == 'dst' or attr_name == 'src':
                        rule_ip_info = cond.split(cond_op)[1].split('/')
                        if len(rule_ip_info) == 1:
                                #not net mask
                                new_cond = cond.replace(attr_name, repr(pkt.getfieldval(attr_name)))
                                new_cond = new_cond.replace(attr_val, repr(attr_val))

                        elif len(rule_ip_info) == 2:
                                #subnet
                                ip_net, net = extractNetworkAddr(rule_ip_info, pkt.getfieldval(attr_name))
                                new_cond = cond.replace(attr_name, repr(ip_net))
                                new_cond = new_cond.replace(attr_val, repr(net))
                        else:
                                pass
                        

                elif attr_name == 'payload' and pkt.haslayer('Raw') and pkt.getlayer('Raw').load:
                        #get actual payload value (in string format) 
                        ##new_cond = cond.replace(attr_name, pkt.getlayer('Raw').load.decode('UTF-8'))
                        try:
                                new_cond = cond.replace(attr_name, bytes_to_str(pkt.getlayer('Raw').load))
                                new_cond = new_cond.replace(attr_val, str(attr_val))
                        except:
                                pass

                else:
                        
                        if pkt.haslayer(rule_proto):
                                try:
                                        new_cond = cond.replace(attr_name, str(pkt.getlayer(rule_proto).getfieldval(attr_name)))
                                        new_cond = new_cond.replace(attr_val, str(attr_val))
                                
                                except AttributeError:
                                        #not in that layer, check for it the lower layer (IP)
                                        try:
                                                new_cond = cond.replace(attr_name, str(pkt.getfieldval(attr_name)))
                                                new_cond = new_cond.replace(attr_val, str(attr_val))
                                        except:
                                                rule_applicable = rule_applicable and False
                                                continue
                        else:
                                #any protocol
                                try:
                                        new_cond = cond.replace(attr_name, str(pkt.getfieldval(attr_name)))
                                        new_cond = new_cond.replace(attr_val, str(attr_val))
                                except:
                                        rule_applicable = rule_applicable and False
                                        continue
                #try:
                #        rule_applicable = rule_applicable and eval(new_cond) ###eval_t(new_cond,cond_op)
                #except:
                #        rule_applicable = rule_applicable and True
                rule_applicable = rule_applicable and eval_t(new_cond,cond_op)
                
        return rule_applicable

def applyPbfRuleAction(ip_pkt, rule):

        if rule.get_action() == 'drop':
                return (ip_pkt,'D')
        elif rule.get_action() == 'normalise':
                return (alterPacketAttr(ip_pkt, rule.get_protocol(), rule.get_norm_op()),'N') #N for normalised
        else:
                return (ip_pkt,'F') #F for accepted/forwarded without normalization

def applyPbfRule(ip_pkt, rule):

        applied = False
        if rule.has_conditions():
                #evaluate condition
                if evalPbfRuleCondition(ip_pkt, rule.get_conditions(), rule.get_protocol()):
                        #evaluate protocol
                        if (rule.get_protocol()).upper() == netfilterqueue.PROTOCOLS[ip_pkt.proto]:
                                #apply a rule's action, return a new IP packet and a char defining the action taken on the packet
                                ip_pkt, applied_action = applyPbfRuleAction(ip_pkt, rule)
                                if applied_action == 'D':
                                        return(ip_pkt, 'dropped', False)
                                #continue applying rules
                                elif applied_action == 'N':
                                        return(ip_pkt, 'normalised', True)
                                else:
                                        return(ip_pkt, 'forwarded', False)
                        else:
                                ip_pkt, applied_action = applyPbfRuleAction(ip_pkt, rule)
                                if applied_action == 'D':
                                        #dropped = True
                                        return(ip_pkt, 'dropped', False)
                                #continue applying rules
                                elif applied_action == 'N':
                                        return(ip_pkt, 'normalised', True)
                                else:
                                        return(ip_pkt, 'forwarded', False)
                else:
                        # NO MATCH
                        return (ip_pkt, "none", False)
        else:
                if (rule.get_protocol()).upper() == netfilterqueue.PROTOCOLS[ip_pkt.proto]:
                        #apply a rule's action, return a new IP packet and a char defining the action taken on the packet
                        ip_pkt, applied_action = applyPbfRuleAction(ip_pkt, rule)
                        if applied_action == 'D':
                                return (ip_pkt, 'dropped', False)
                        #continue applying rules
                        elif applied_action == 'N':
                                return(ip_pkt, 'normalised', True)
                        else:
                                return(ip_pkt, 'forwarded', False)
                else:
                        # NO MATCH
                        return (ip_pkt, "none", False)

def processPktWithPbfRules(ip_packet, rules):
        num = [i for i in RulesStore.fbfRule_nos()]
        i = 0
        is_norm = False
        __slots__ = ( rule for rule in rules)
        
        for rule in __slots__:
        #for rule in rules:
                ip_packet, action, is_norm = applyPbfRule(ip_packet, rule)
                if action == "forwarded":
                        return (ip_packet, action,str(num[i-1]))
 
                if action == "dropped":
                        return (ip_packet, action,str(num[i-1]))

                if is_norm is True:
                        return (ip_packet, 'normalised',str(num[i-1]))
                i = i + 1  
        return (ip_packet, 'forwarded',str(num[i-1]))

def alterFlowAttr(pkt, prtcl, norm_op):
        """
        apply a normalization rule
        """
        #the attribute to be altered must be separated by '=' from the value
        attr_name = norm_op.split('=')[0]
        attr_val  = norm_op.split('=')[1]
        # search for attributes top-down i.e if we want to alter flags in IP()/TCP(), its really hard to tell whether its tcp or ip
        # flags. The script will have a standard way of handling this TCP layer first then back to IP layer 
        if attr_name == 'payload' and pkt.haslayer(prtcl) and pkt.haslayer('Raw'):
                pkt.getlayer('Raw').setfieldval('load',attr_val)
                return IP(pkt.__bytes__())

        if pkt.haslayer(prtcl):
                try:
                        pkt.getlayer(prtcl).getfieldval(attr_name)
                        pkt.getlayer(prtcl).setfieldval(attr_name, attr_val if(attr_name == 'dst' or attr_name == 'src') \
                                else None if(attr_val == 'NULL') else int(attr_val))

                except AttributeError:
                        #this means the attr in question is in the lower layer (IP)
                        try:
                                pkt.getfieldval(attr_name)
                                pkt.setfieldval(attr_name, attr_val if(attr_name == 'dst' or attr_name == 'src') \
                                        else None if(attr_val == 'NULL') else int(attr_val))
                        except:
                                pass
        else:
                #protocol ==> ANY
                try:
                        pkt.getfieldval(attr_name)
                        pkt.setfieldval(attr_name, (attr_val if(attr_name == 'dst' or attr_name == 'src') \
                                else None if(attr_val == 'NULL') else int(attr_val)))
                except:
                        #this means the attr isnt in the IP layer either
                        #make no changes
                        pass

        return IP(pkt.__bytes__())


def evalFbfRuleConditionss(pkt, cond_list, rule_proto):
        """
        evaluate the condition
        """
        rule_applicable = True
               
        for cond in cond_list:
                new_cond = None
                cond_op = getConditionalOperator(cond)
                attr_name = cond.split(cond_op)[0]
                attr_val  = cond.split(cond_op)[1]
                print("go 4") 

                if attr_name == 'dst' or attr_name == 'src':
                        rule_ip_info = cond.split(cond_op)[1].split('/')
                        if len(rule_ip_info) == 1:
                                #not net mask
                                new_cond = cond.replace(attr_name, repr(pkt.getfieldval(attr_name)))
                                new_cond = new_cond.replace(attr_val, repr(attr_val))

                        elif len(rule_ip_info) == 2:
                                #subnet
                                ip_net, net = extractNetworkAddr(rule_ip_info, pkt.getfieldval(attr_name))
                                new_cond = cond.replace(attr_name, repr(ip_net))
                                new_cond = new_cond.replace(attr_val, repr(net))
                        else:
                                pass
                        

                elif attr_name == 'payload' and pkt.haslayer('Raw'):
                        #get actual payload value (in string format) 
                        new_cond = cond.replace(attr_name, bytes_to_str(pkt.getlayer('Raw').load))
                        new_cond = new_cond.replace(attr_val, str(attr_val))

                else:
                        
                        if pkt.haslayer(rule_proto):
                                try:
                                        new_cond = cond.replace(attr_name, str(pkt.getlayer(rule_proto).getfieldval(attr_name)))
                                        new_cond = new_cond.replace(attr_val, str(attr_val))
                                
                                except AttributeError:
                                        #not in that layer, check for it the lower layer (IP)
                                        try:
                                                new_cond = cond.replace(attr_name, str(pkt.getfieldval(attr_name)))
                                                new_cond = new_cond.replace(attr_val, str(attr_val))
                                        except:
                                                rule_applicable = rule_applicable and False
                                                continue
                        else:
                                #any protocol
                                try:
                                        new_cond = cond.replace(attr_name, str(pkt.getfieldval(attr_name)))
                                        new_cond = new_cond.replace(attr_val, str(attr_val))
                                except:
                                        rule_applicable = rule_applicable and False
                                        continue
                #try:
                #        rule_applicable = rule_applicable and eval(new_cond) ###eval_t(new_cond,cond_op)
                #except:
                #        rule_applicable = rule_applicable and True
                rule_applicable = rule_applicable and eval_t(new_cond,cond_op)
                
        return rule_applicable

def bytes_to_str(self,byts):

                strng = ''
                for i in range(len(byts)):
                        j = int(byts[i])
                        if j < 127 and j >= 32:
                                strng += chr(j)
                        else:
                                strng += '.'

                return strng

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

##@lru_cache(maxsize=1)
def evalFbfRuleCondition(packet,nf_record_x, cond_list, rule_proto):
        """
        evaluate the condition
        """
        cond = new_cond = None
        rule_applicable_a = True
        rule_applicable = False
        
        nf_record =nf_record_x  
        ###nf_record.show()
        proto_no = 0
        proto = None
        nf_protocol = None 
        #if rule_proto == '' or rule_proto == None:
        #        rule_proto = 'UDP'
        try:
                nf_protocol =  PROTOCOLS[nf_record.fieldValue.PROTOCOL]
                
        except Exception as e:
                nf_protocol  = "UDP" 
                ##print("Exception :" + str(e))    
                #return False
                pass
               
                   
        
        new_cond = None
        for cond in cond_list:
                try: 
                     
                    

                    cond_op = getConditionalOperator(cond)
                    attr_name = cond.split(cond_op)[0]
                    attr_val  = cond.split(cond_op)[1]
                    #attr_name = attr_name.upper()
                    
                    #nf_record.show()
                    

                    if rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "version","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.IP_PROTOCOL_VERSION
                                rule_ip_info = cond.split(cond_op)
                                versionX = int(nf_record.fieldValue.IP_PROTOCOL_VERSION)
                                new_cond = cond.replace(attr_name, repr(versionX))
                                
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                #if not rule_applicable_a and versionX !=  Protocol_f[m]:
                                #    return False, "FORWARD",m
                            except Exception as e:
                                #print("Exception :" + str(e))    
                                pass
                                               

                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "seq","=="):
                            flagsX = None
                            try:
                                
                                flagsX = int(nf_record.fieldValue.ICMP_IPv4_TYPE.decode('utf-8','ignore'))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                                  
                            except Exception as e:
                                #print("Exception :" + str(e))    
                                pass        

                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "type","=="):
                            try:
                                    
                                    rule_ip_info = cond.split(cond_op)
                                    tosX = int(nf_record.fieldValue.ICMP_TYPE.decode('utf-8','ignore').replace('\x00',''))
                                    
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)
                                       
                                    
                            except Exception as e:
                                #print("Exception 1:" + str(e))    
                                pass
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "id","=="):
                            try:
                                                                   
                                    #tosX = int(packet[IP].id)
                                    tosX = int(nf_record.fieldValue.FLOW_SAMPLER_ID.decode('utf-8','ignore').replace('\x00',''))
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    

                            except Exception as e:
                                #print("Exception 2:" + str(e))    
                                pass
                    if rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "id","=="):
                            try:
                                                                   
                                    #tosX = int(packet[IP].id)
                                    tosX = int(nf_record.fieldValue.FLOW_SAMPLER_ID) ####.decode('utf-8','ignore').replace('\x00',''))
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                     

                            except Exception as e:
                                #print("Exception 3:" + str(e))    
                                pass    
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "id","=="):
                            try:
                                                                   
                                    #tosX = int(packet[IP].id)
                                    tosX = int(nf_record.fieldValue.FLOW_SAMPLER_ID.decode('utf-8','ignore').replace('\x00',''))
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    

                            except Exception as e:
                                #print("Exception 4:" + str(e))    
                                pass

                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "unused","=="):
                            try:
                                    
                                    rule_ip_info = cond.split(cond_op)                                
                                    tosX = int(nf_record.fieldValue.ICMP_IPv4_CODE.decode('utf-8','ignore'))
                                    
                                    new_cond = cond.replace("unused", repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    
                                    
                            except Exception as e:
                                #print("Exception 5:" + str(e))    
                                pass
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "reserved","=="):
                            try:
                                    
                                    rule_ip_info = cond.split(cond_op)                                
                                    tosX = int(nf_record.fieldValue.ICMP_IPv4_CODE.decode('utf-8','ignore'))
                                    
                                    new_cond = cond.replace("reserved", repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                                                        
                            except Exception as e:
                                #print("Exception 6:" + str(e))    
                                pass
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "src","=="):
                        flagsX = None
                        try:
                            flagsX = nf_record.fieldValue.IPV4_SRC_ADDR
                        except Exception as e:
                                #print("Exception 7:" + str(e))    
                                pass
                            
                        rule_ip_info = cond.split(cond_op)[1].split('/')
                        if len(rule_ip_info) == 1:
                                #not net mask
                                new_cond = cond.replace(attr_val,repr(attr_val))
                                new_cond = new_cond.replace(attr_name, repr(nf_record.fieldValue.IPV4_SRC_ADDR))
                                

                        elif len(rule_ip_info) == 2:
                                #subnet
                                ip_net, net =  extractNetworkAddr(rule_ip_info, nf_record.fieldValue.IPV4_SRC_ADDR)
                                new_cond = cond.replace(attr_val, repr(net))
                                new_cond = new_cond.replace(attr_name, repr(ip_net))

                        #rule_applicable =  rule_applicable and   eval_t(new_cond,cond_op)
                        
                        
                        
                    elif  eval_t(attr_name + "==" + "dst","=="):
                        flagsX = None
                        try:
                            flagsX = nf_record.fieldValue.IPV4_DST_ADDR
                        except Exception as e:
                                #print("Exception :" + str(e))    
                                pass
                            
                        rule_ip_info = cond.split(cond_op)[1].split('/')
                        if len(rule_ip_info) == 1:
                                #not net mask
                                new_cond = cond.replace(attr_val, repr(attr_val))
                                new_cond = new_cond.replace(attr_name, repr(nf_record.fieldValue.IPV4_SRC_ADDR))
                                

                        elif len(rule_ip_info) == 2:
                                #subnet
                                ip_net, net =  extractNetworkAddr(rule_ip_info, nf_record.fieldValue.IPV4_SRC_ADDR)
                                new_cond = cond.replace(attr_val, repr(net))
                                new_cond = new_cond.replace(attr_name, repr(ip_net))
                                
                        
                        
                        #rule_applicable =  rule_applicable and   eval_t(new_cond,cond_op)
                                                
                            
                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "frag","=="):
                            flagsX = None
                            try:
                                flagsX = str(nf_record.fieldValue.FRAGMENT_OFFSET.decode('utf-8','ignore'))
                                rule_ip_info = cond.split(cond_op)
                                flagsX = int(flagsX)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 8:" + str(e))    
                                pass
                            
                    
                                    
                            
                             
                    if rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "id","=="):
                            
                            flagsX = None
                            try:
                                flagsX = packet[IP].id
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            
                            except Exception as e:
                                #print("Exception 9:" + str(e))    
                                pass

                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "chksum","=="):
                            
                            flagsX = None
                            try:
                                
                                flagsX = int(nf_record.fieldValue.FORWARDING_STATUS.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                 

                            except Exception as e:
                                #print("Exception 10:" + str(e))    
                                pass

                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "chksum","=="):
                            
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.FORWARDING_STATUS.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception 11:" + str(e))    
                                pass
                                    
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "id","=="):
                            
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.ICMP_IPv4_CODE.decode('utf-8','ignore').replace('\x00','')
                                rule_ip_info = cond.split(cond_op)
                                flagsX = int(nf_record.fieldValue.ICMP_IPv4_CODE)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                new_cond = new_cond.replace(attr_val, repr(attr_val))
                                 

                            except Exception as e:
                                #print("Exception 12 :" + str(e))    
                                pass
                    
                            
                            
                         
                            
                            
                            
                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "tos","=="):
                            
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.TOS) ###.decode('utf-8','ignore').replace('\x00','')
                                rule_ip_info = cond.split(cond_op)
                                tosX = int(nf_record.fieldValue.TOS)
                                new_cond = cond.replace(attr_name, repr(tosX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 13 :" + str(e))    
                                pass

                    elif  rule_proto.upper() == nf_protocol.upper()=="SCTP" and eval_t(attr_name + "==" + "tos","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.TOS) ##.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                tosX = int(nf_record.fieldValue.TOS)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                 
                                 
                            except Exception as e:
                                #print("Exception 14 :" + str(e))    
                                pass
        
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "ttl","=="):
                            flagsX = None
                            try:
                                ##nf_record.show()
                                flagsX = int(packet[IP].ttl)
                                ##flagsX = int(nf_record.fieldValue.IP_TTL) ##.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            
                            except Exception as e:
                                #print("Exception 15 :" + str(e))    
                                pass
                            

                    elif rule_proto.upper() != nf_protocol.upper() and  eval_t(attr_name + "==" + "ttl","=="):
                            flagsX = None
                            try:
                                ##nf_record.show()
                                flagsX = int(packet[IP].ttl)
                                ###flagsX = int(nf_record.fieldValue.IP_TTL) ####.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            
                            except Exception as e:
                                #print("Exception 16:" + str(e))    
                                pass        
                            
                    #elif  eval_t(attr_name + "==" + "protocol","=="):
                    #        flagsX = None
                    #        try:
                    #            flagsX = nf_record.fieldValue.PROTOCOL
                    #        except Exception as e:
                    #            #print("Exception :" + str(e))    
                    #            pass
                    #        rule_ip_info = cond.split(cond_op)
                    #        tosX = int(nf_record.fieldValue.PROTOCOL)
                    #        
                    #        new_cond = cond.replace(attr_name, repr(tosX))
                    #        #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                            
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "urgptr","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TCP_URGENT_PTR.decode('utf-8','ignore')
                                flagsX = flagsX.replace('\x00','')
                                rule_ip_info = cond.split(cond_op)
                                ttlX = int(nf_record.fieldValue.TCP_URGENT_PTR.decode('utf-8','ignore').replace('\x00',''))
                                new_cond = cond.replace(attr_name, repr(ttlX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            except Exception as e:
                                #print("Exception 17:" + str(e))    
                                pass
                            
                            
                            #
                    
                    
                    
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "flags","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TCP_FLAGS
                                rule_ip_info = cond.split(cond_op)
                                DNSX = int(nf_record.fieldValue.TCP_FLAGS)
                                new_cond = cond.replace(attr_name, repr(DNSX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 18:" + str(e))    
                                pass
                            
                    
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "payload","==") and packet.haslayer(Raw): ## and packet.haslayer(Raw).load:
                            #get actual payload value (in string format)
                            
                                     
                            new_cond = cond.replace(attr_name, str(packet.getlayer(Raw).load.decode('utf-8','ignore')))
                            #new_cond = new_cond.replace(attr_val,str(packet.getlayer('Raw').load.decode('utf-8','ignore'))) #str(attr_val))
                                   
                            
                    
                    elif rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "window","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.TCP_WINDOW_SIZE.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                ttlX = int(nf_record.fieldValue.TCP_WINDOW_SIZE.decode('utf-8','ignore').replace('\x00',''))
                                new_cond = cond.replace(attr_name, repr(ttlX))
                                #new_cond = new_cond.replace(attr_val, pr(attr_val))
                            except Exception as e:
                                #print("Exception 19:" + str(e))    
                                pass
     

                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "ack","=="):
                            flagsX = None
                            try:
                                
                                flagsX = int(nf_record.fieldValue.TCP_ACK_NUM.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                timeoutX = int(nf_record.fieldValue.TCP_ACK_NUM.decode('utf-8','ignore').replace('\x00',''))
                                new_cond = cond.replace(attr_name, repr(timeoutX))
                                #new_cond = new_cond.replace(attr_val, pr(attr_val))
                                
                            
                            except Exception as e:
                                #print("Exception 20:" + str(e))    
                                pass
                            
                            
                            

                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "sport","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.L4_SRC_PORT)
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception 21:" + str(e))    
                                pass
                            
                            
                            
                            
                    
                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "dport","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.L4_DST_PORT
                                rule_ip_info = cond.split(cond_op)
                                dportX = int(nf_record.fieldValue.L4_DST_PORT)
                                new_cond = cond.replace(attr_name, repr(dportX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 22:" + str(e))    
                                pass
                            
                            
                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "sport","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.L4_SRC_PORT)
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception 23:" + str(e))    
                                pass
                            
                            
                            
                            
                    
                    elif  rule_proto.upper() == nf_protocol.upper()  and eval_t(attr_name + "==" + "dport","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.L4_DST_PORT
                                rule_ip_info = cond.split(cond_op)
                                dportX = int(nf_record.fieldValue.L4_DST_PORT)
                                new_cond = cond.replace(attr_name, repr(dportX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 24:" + str(e))    
                                pass        
                            
                            
                                    

                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "seq","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.TCP_SEQ_NUM.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                chksumX = int(nf_record.fieldValue.TCP_SEQ_NUM.decode('utf-8','ignore').replace('\x00',''))
                                new_cond = cond.replace(attr_name, repr(chksumX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 25:" + str(e))    
                                pass
                            
                            
                    #print(rule_applicable,eval_t(new_cond,cond_op),cond,new_cond)      
                    rule_applicable = eval_t(new_cond,cond_op)
                    rule_applicable_a = rule_applicable_a and rule_applicable

                
                except Exception as e:
                    print ("Exception TXT :" + str(e))
                    pass
        #print(rule_applicable,rule_applicable_a, rule_applicable_a and rule_applicable)
        return rule_applicable_a    
                      
        
def evalFbfRuleCondition_X(packet,nf_record_x, cond_list, rule_proto):
        """
        evaluate the condition
        """
        cond = new_cond = None
        rule_applicable_a = True
        rule_applicable = False
        
        nf_record =nf_record_x  
        ###nf_record.show()
        proto_no = 0
        proto = None
        nf_protocol = None 
                
        #if rule_proto == '' or rule_proto == None:
        #        rule_proto = 'UDP'
        try:
                nf_protocol =  PROTOCOLS[nf_record.fieldValue.PROTOCOL]
                
        except Exception as e:
                nf_protocol  = "UDP" 
                ##print("Exception :" + str(e))    
                #return False
                pass
               
                   
        
        new_cond = None
        for cond in cond_list:
                try: 
                     
                    

                    cond_op = getConditionalOperator(cond)
                    attr_name = cond.split(cond_op)[0]
                    attr_val  = cond.split(cond_op)[1]
                    #attr_name = attr_name.upper()
                    
                    #nf_record.show()
                    

                    if rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "version","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.IP_PROTOCOL_VERSION
                                rule_ip_info = cond.split(cond_op)
                                versionX = int(nf_record.fieldValue.IP_PROTOCOL_VERSION)
                                new_cond = cond.replace(attr_name, repr(versionX))
                                
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                #if not rule_applicable_a and versionX !=  Protocol_f[m]:
                                #    return False, "FORWARD",m
                            except Exception as e:
                                #print("Exception :" + str(e))    
                                pass
                                               

                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "seq","=="):
                            flagsX = None
                            try:
                                
                                flagsX = int(nf_record.fieldValue.ICMP_IPv4_TYPE.decode('utf-8','ignore'))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                                  
                            except Exception as e:
                                #print("Exception :" + str(e))    
                                pass        

                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "type","=="):
                            try:
                                    
                                    rule_ip_info = cond.split(cond_op)
                                    tosX = int(nf_record.fieldValue.ICMP_TYPE.decode('utf-8','ignore').replace('\x00',''))
                                    
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)
                                       
                                    
                            except Exception as e:
                                #print("Exception 1:" + str(e))    
                                pass
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "id","=="):
                            try:
                                                                   
                                    #tosX = int(packet[IP].id)
                                    tosX = int(nf_record.fieldValue.FLOW_SAMPLER_ID.decode('utf-8','ignore').replace('\x00',''))
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    

                            except Exception as e:
                                #print("Exception 2:" + str(e))    
                                pass
                    if rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "id","=="):
                            try:
                                                                   
                                    #tosX = int(packet[IP].id)
                                    tosX = int(nf_record.fieldValue.FLOW_SAMPLER_ID) ####.decode('utf-8','ignore').replace('\x00',''))
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                     

                            except Exception as e:
                                #print("Exception 3:" + str(e))    
                                pass    
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "id","=="):
                            try:
                                                                   
                                    #tosX = int(packet[IP].id)
                                    tosX = int(nf_record.fieldValue.FLOW_SAMPLER_ID.decode('utf-8','ignore').replace('\x00',''))
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    

                            except Exception as e:
                                #print("Exception 4:" + str(e))    
                                pass

                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "unused","=="):
                            try:
                                    
                                    rule_ip_info = cond.split(cond_op)                                
                                    tosX = int(nf_record.fieldValue.ICMP_IPv4_CODE.decode('utf-8','ignore'))
                                    
                                    new_cond = cond.replace("unused", repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    
                                    
                            except Exception as e:
                                #print("Exception 5:" + str(e))    
                                pass
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "reserved","=="):
                            try:
                                    
                                    rule_ip_info = cond.split(cond_op)                                
                                    tosX = int(nf_record.fieldValue.ICMP_IPv4_CODE.decode('utf-8','ignore'))
                                    
                                    new_cond = cond.replace("reserved", repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                                                        
                            except Exception as e:
                                #print("Exception 6:" + str(e))    
                                pass
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "src","=="):
                        flagsX = None
                        try:
                            flagsX = nf_record.fieldValue.IPV4_SRC_ADDR
                        except Exception as e:
                                #print("Exception 7:" + str(e))    
                                pass
                            
                        rule_ip_info = cond.split(cond_op)[1].split('/')
                        if len(rule_ip_info) == 1:
                                #not net mask
                                new_cond = cond.replace(attr_val,repr(attr_val))
                                new_cond = new_cond.replace(attr_name, repr(nf_record.fieldValue.IPV4_SRC_ADDR))
                                

                        elif len(rule_ip_info) == 2:
                                #subnet
                                ip_net, net =  extractNetworkAddr(rule_ip_info, nf_record.fieldValue.IPV4_SRC_ADDR)
                                new_cond = cond.replace(attr_val, repr(net))
                                new_cond = new_cond.replace(attr_name, repr(ip_net))

                        #rule_applicable =  rule_applicable and   eval_t(new_cond,cond_op)
                        
                        
                        
                    elif  eval_t(attr_name + "==" + "dst","=="):
                        flagsX = None
                        try:
                            flagsX = nf_record.fieldValue.IPV4_DST_ADDR
                        except Exception as e:
                                #print("Exception :" + str(e))    
                                pass
                            
                        rule_ip_info = cond.split(cond_op)[1].split('/')
                        if len(rule_ip_info) == 1:
                                #not net mask
                                new_cond = cond.replace(attr_val, repr(attr_val))
                                new_cond = new_cond.replace(attr_name, repr(nf_record.fieldValue.IPV4_SRC_ADDR))
                                

                        elif len(rule_ip_info) == 2:
                                #subnet
                                ip_net, net =  extractNetworkAddr(rule_ip_info, nf_record.fieldValue.IPV4_SRC_ADDR)
                                new_cond = cond.replace(attr_val, repr(net))
                                new_cond = new_cond.replace(attr_name, repr(ip_net))
                                
                        
                        
                        #rule_applicable =  rule_applicable and   eval_t(new_cond,cond_op)
                                                
                            
                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "frag","=="):
                            flagsX = None
                            try:
                                flagsX = str(nf_record.fieldValue.FRAGMENT_OFFSET.decode('utf-8','ignore'))
                                rule_ip_info = cond.split(cond_op)
                                flagsX = int(flagsX)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 8:" + str(e))    
                                pass
                            
                    
                                    
                            
                             
                    if rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "id","=="):
                            
                            flagsX = None
                            try:
                                flagsX = packet[IP].id
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            
                            except Exception as e:
                                #print("Exception 9:" + str(e))    
                                pass

                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "chksum","=="):
                            
                            flagsX = None
                            try:
                                
                                flagsX = int(nf_record.fieldValue.FORWARDING_STATUS.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                 

                            except Exception as e:
                                #print("Exception 10:" + str(e))    
                                pass

                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "chksum","=="):
                            
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.FORWARDING_STATUS.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception 11:" + str(e))    
                                pass
                                    
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "id","=="):
                            
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.ICMP_IPv4_CODE.decode('utf-8','ignore').replace('\x00','')
                                rule_ip_info = cond.split(cond_op)
                                flagsX = int(nf_record.fieldValue.ICMP_IPv4_CODE)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                new_cond = new_cond.replace(attr_val, repr(attr_val))
                                 

                            except Exception as e:
                                #print("Exception 12 :" + str(e))    
                                pass
                    
                            
                            
                         
                            
                            
                            
                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "tos","=="):
                            
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.TOS) ###.decode('utf-8','ignore').replace('\x00','')
                                rule_ip_info = cond.split(cond_op)
                                tosX = int(nf_record.fieldValue.TOS)
                                new_cond = cond.replace(attr_name, repr(tosX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 13 :" + str(e))    
                                pass

                    elif  rule_proto.upper() == nf_protocol.upper()=="SCTP" and eval_t(attr_name + "==" + "tos","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.TOS) ##.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                tosX = int(nf_record.fieldValue.TOS)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                 
                                 
                            except Exception as e:
                                #print("Exception 14 :" + str(e))    
                                pass
        
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "ttl","=="):
                            flagsX = None
                            try:
                                ##nf_record.show()
                                flagsX = int(packet[IP].ttl)
                                ##flagsX = int(nf_record.fieldValue.IP_TTL) ##.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            
                            except Exception as e:
                                #print("Exception 15 :" + str(e))    
                                pass
                            

                    elif rule_proto.upper() != nf_protocol.upper() and  eval_t(attr_name + "==" + "ttl","=="):
                            flagsX = None
                            try:
                                ##nf_record.show()
                                flagsX = int(packet[IP].ttl)
                                ###flagsX = int(nf_record.fieldValue.IP_TTL) ####.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            
                            except Exception as e:
                                #print("Exception 16:" + str(e))    
                                pass        
                            
                    #elif  eval_t(attr_name + "==" + "protocol","=="):
                    #        flagsX = None
                    #        try:
                    #            flagsX = nf_record.fieldValue.PROTOCOL
                    #        except Exception as e:
                    #            #print("Exception :" + str(e))    
                    #            pass
                    #        rule_ip_info = cond.split(cond_op)
                    #        tosX = int(nf_record.fieldValue.PROTOCOL)
                    #        
                    #        new_cond = cond.replace(attr_name, repr(tosX))
                    #        #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                            
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "urgptr","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TCP_URGENT_PTR.decode('utf-8','ignore')
                                flagsX = flagsX.replace('\x00','')
                                rule_ip_info = cond.split(cond_op)
                                ttlX = int(nf_record.fieldValue.TCP_URGENT_PTR.decode('utf-8','ignore').replace('\x00',''))
                                new_cond = cond.replace(attr_name, repr(ttlX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            except Exception as e:
                                #print("Exception 17:" + str(e))    
                                pass
                            
                            
                            #
                    
                    
                    
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "flags","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TCP_FLAGS
                                rule_ip_info = cond.split(cond_op)
                                DNSX = int(nf_record.fieldValue.TCP_FLAGS)
                                new_cond = cond.replace(attr_name, repr(DNSX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 18:" + str(e))    
                                pass
                            
                    
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "payload","==") and packet.haslayer(Raw): ## and packet.haslayer(Raw).load:
                            #get actual payload value (in string format)
                            
                                     
                            new_cond = cond.replace(attr_name, str(packet.getlayer(Raw).load.decode('utf-8','ignore')))
                            #new_cond = new_cond.replace(attr_val,str(packet.getlayer('Raw').load.decode('utf-8','ignore'))) #str(attr_val))
                                   
                            
                    
                    elif rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "window","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.TCP_WINDOW_SIZE.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                ttlX = int(nf_record.fieldValue.TCP_WINDOW_SIZE.decode('utf-8','ignore').replace('\x00',''))
                                new_cond = cond.replace(attr_name, repr(ttlX))
                                #new_cond = new_cond.replace(attr_val, pr(attr_val))
                            except Exception as e:
                                #print("Exception 19:" + str(e))    
                                pass
     

                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "ack","=="):
                            flagsX = None
                            try:
                                
                                flagsX = int(nf_record.fieldValue.TCP_ACK_NUM.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                timeoutX = int(nf_record.fieldValue.TCP_ACK_NUM.decode('utf-8','ignore').replace('\x00',''))
                                new_cond = cond.replace(attr_name, repr(timeoutX))
                                #new_cond = new_cond.replace(attr_val, pr(attr_val))
                                
                            
                            except Exception as e:
                                #print("Exception 20:" + str(e))    
                                pass
                            
                            
                            

                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "sport","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.L4_SRC_PORT)
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception 21:" + str(e))    
                                pass
                            
                            
                            
                            
                    
                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "dport","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.L4_DST_PORT
                                rule_ip_info = cond.split(cond_op)
                                dportX = int(nf_record.fieldValue.L4_DST_PORT)
                                new_cond = cond.replace(attr_name, repr(dportX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 22:" + str(e))    
                                pass
                            
                            
                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "sport","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.L4_SRC_PORT)
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception 23:" + str(e))    
                                pass
                            
                            
                            
                            
                    
                    elif  rule_proto.upper() == nf_protocol.upper()  and eval_t(attr_name + "==" + "dport","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.L4_DST_PORT
                                rule_ip_info = cond.split(cond_op)
                                dportX = int(nf_record.fieldValue.L4_DST_PORT)
                                new_cond = cond.replace(attr_name, repr(dportX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 24:" + str(e))    
                                pass        
                            
                            
                                    

                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "seq","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.TCP_SEQ_NUM.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                chksumX = int(nf_record.fieldValue.TCP_SEQ_NUM.decode('utf-8','ignore').replace('\x00',''))
                                new_cond = cond.replace(attr_name, repr(chksumX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                

                            except Exception as e:
                                #print("Exception 25:" + str(e))    
                                pass
                            
                            
                    #print(rule_applicable,eval_t(new_cond,cond_op),cond,new_cond)      
                    rule_applicable = eval_t(new_cond,cond_op)
                    rule_applicable_a = rule_applicable_a and rule_applicable

                
                except Exception as e:
                    print ("Exception TXT :" + str(e))
                    pass
        #print(rule_applicable,rule_applicable_a, rule_applicable_a and rule_applicable)
        return rule_applicable_a    
                      
        

#@lru_cache(maxsize=1)
def applyFbfRuleAction(ip_pkt, rule):
        
        if rule.get_action() == 'drop':
                return (ip_pkt,'D')
        elif rule.get_action() == 'normalise':
                return (alterFlowAttr(ip_pkt, rule.get_protocol(), rule.get_norm_op()),'N') #N for normalised
        else:
                return (ip_pkt,'F') #F for accepted/forwarded without normalization

#@lru_cache(maxsize=16)
def applyFbfRule(ip_pkt, rule,nf_record):

        applied = False
        state,proto_no = False , 0
       
        if (ip_pkt,nf_record, rule.get_conditions(), rule.get_protocol()) and len(rule.get_conditions()) > 0 :
                
                #evaluate condition
                state = evalFbfRuleCondition(ip_pkt,nf_record, rule.get_conditions(), rule.get_protocol())
       
                #nf_record = netflow.NetflowRecordV9(nf_record)
       
                proto_no = 0
                proto = None
                
                try:
                    proto_no = nf_record.fieldValue.PROTOCOL
                    proto = PROTOCOLS[proto_no].lower()
                
                except Exception as e:
                    #print("Exception :" + str(e))
                    pass
       
                if state:
                        #evaluate protocol
       
                        if (rule.get_protocol()).upper() == netfilterqueue.PROTOCOLS[proto_no]:
       
                                #apply a rule's action, return a new IP packet and a char defining the action taken on the packet
                                ip_pkt, applied_action = applyFbfRuleAction(ip_pkt, rule)
                                if applied_action == 'D':
                                        return(ip_pkt, 'dropped', False)
                                #continue applying rules
                                elif applied_action == 'N':
                                        return(ip_pkt, 'normalised', True)
                                else:
                                        return(ip_pkt, 'forwarded', False)
                        else:
                                ip_pkt, applied_action = applyFbfRuleAction(ip_pkt, rule)
       
                                if applied_action == 'D':
                                        #dropped = True
                                        return(ip_pkt, 'dropped', False)
                                #continue applying rules
                                elif applied_action == 'N':
                                        return(ip_pkt, 'normalised', True)
                                else:
                                        return(ip_pkt, 'forwarded', False)
                else:
                        # NO MATCH
                        return (ip_pkt, "forwarded", False)
        else:
                #nf_record = netflow.NetflowRecordV9(nf_record)
                proto_no = 0
                proto = None
       
                try:
                    proto_no = nf_record.fieldValue.PROTOCOL
                    proto = PROTOCOLS[proto_no].lower()
                
                except Exception as e:
                    ##print("Exception :" + str(e))
                    pass
                if (rule.get_protocol()).upper() == netfilterqueue.PROTOCOLS[proto_no]:
                        #apply a rule's action, return a new IP packet and a char defining the action taken on the packet
                        ip_pkt, applied_action = applyFbfRuleAction(nf_record, rule)
                        if applied_action == 'D':
                                return (ip_pkt, 'dropped', False)
                        #continue applying rules
                        elif applied_action == 'N':
                                return(ip_pkt, 'normalised', True)
                        else:
                                return(ip_pkt, 'forwarded', False)
       
                else:
                        # NO MATCH
                        return (ip_pkt, "forwarded", False)

rules_names = {}
##@lru_cache(maxsize=1)
def processFlowWithfbfRules(ip_packet, rules,nf_record):
        # packet analyzer
        num = [i for i in RulesStore.fbfRule_nos()]
        i = 0
        is_norm = False
        __slots__ = ( rule for rule in rules)
        
        for rule in __slots__:
                ip_packet, action, is_norm = applyFbfRule(ip_packet, rule,nf_record)
                if action in rules_names.keys():
                      rules_names[action] += 1
                else:
                      rules_names[action] = 1
                i = i + 1
        if "dropped" in rules_names.keys() and rules_names["dropped"] > rules_names["forwarded"]: 
             return (ip_packet, "dropped",str(num[i-1]))
       	if "normalised" in rules_names.keys()  and rules_names["dropped"] < rules_names["normalised"]:
             return (ip_packet, "normalised",str(num[i-1]))

        return (ip_packet, action , str(num[i-1]))

        """
        is_norm = False
        i = 1 
        nums = RulesStore.fbfRule_nos()
        for rule in rules:
                ip_packet, action, is_norm = applyFbfRule(ip_packet, rule,nf_record)
                                
                if action == "dropped":
                        ##print("Rule Selected :",i) 
                        return (ip_packet, action,str(nums(i)))
                        
                if is_norm is True:
                        ##print("Rule Selected :",i)    
                        return (ip_packet, 'normalised',str(nums(i)))
                if action == "forwarded":
                        ##print("Rule Selected :",i)                        
                        return (ip_packet, action,str(nums[i]))
                 
                is_norm = False
                i = i + 1         
                #print("Rule Missed :",i)
        """
        return (ip_packet, 'forwarded','0')
        
        
