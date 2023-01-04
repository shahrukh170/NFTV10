from scapy.all import *
from scapy.layers import *
import netifaces
import netfilterqueue
from netfilterqueue import PROTOCOLS
import json
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
        

def eval_t_23(args,cond_op):
                if len(args) > 1:
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
        """
        packet analyzer
        """
        is_norm = False
        for rule in rules:
                ip_packet, action, is_norm = applyPbfRule(ip_packet, rule)
                if action == "forwarded":
                        return (ip_packet, action)
 
                if action == "dropped":
                        return (ip_packet, action)

                if is_norm is True:
                        return (ip_packet, 'normalised')
                
        return (ip_packet, 'forwarded')

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

def evalFbfRuleCondition(packet,nf_record_x, cond_list, rule_proto):
        """
        evaluate the condition
        """
        cond = new_cond = None
        rule_applicable_a = True
        rule_applicable = True
        
        nf_record =nf_record_x  
        ##nf_record.show()
        proto_no = 0
        proto = None
        nf_protocol = None 
        #if rule_proto == '' or rule_proto == None:
        #        rule_proto = 'UDP'
        try:
                nf_protocol =  PROTOCOLS[nf_record.fieldValue.PROTOCOL].lower()
                
        except Exception as e:
                #print("Exception :" + str(e))    
                #return False
                pass
       
                   
        
        

        for cond in cond_list:
                try: 
                     
                    new_cond = None

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
                                    tosX = int(nf_record.fieldValue.ICMP_TYPE)
                                    
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)
                                    
                            except Exception as e:
                                #print("Exception 333:" + str(e))    
                                pass
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "id","=="):
                            try:
                                                                   
                                    #tosX = int(packet[IP].id)
                                    tosX = int(nf_record.fieldValue.FLOW_SAMPLER_ID)
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    
                            except Exception as e:
                                #print("Exception 444:" + str(e))    
                                pass    
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "id","=="):
                            try:
                                                                   
                                    #tosX = int(packet[IP].id)
                                    tosX = int(nf_record.fieldValue.FLOW_SAMPLER_ID)
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    
                            except Exception as e:
                                #print("Exception 444:" + str(e))    
                                pass    
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "id","=="):
                            try:
                                                                   
                                    #tosX = int(packet[IP].id)
                                    tosX = int(nf_record.fieldValue.FLOW_SAMPLER_ID)
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    
                            except Exception as e:
                                #print("Exception 444:" + str(e))    
                                pass    

                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "unused","=="):
                            try:
                                    
                                    rule_ip_info = cond.split(cond_op)                                
                                    tosX = int(nf_record.fieldValue.ICMP_IPv4_CODE.decode('utf-8','ignore'))
                                    
                                    new_cond = cond.replace("unused", repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    
                                    
                            except Exception as e:
                                #print("Exception 444:" + str(e))    
                                pass
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "reserved","=="):
                            try:
                                    
                                    rule_ip_info = cond.split(cond_op)                                
                                    tosX = int(nf_record.fieldValue.ICMP_IPv4_CODE.decode('utf-8','ignore'))
                                    
                                    new_cond = cond.replace("reserved", repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    
                                    
                            except Exception as e:
                                #print("Exception 444:" + str(e))    
                                pass
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "src","=="):
                        flagsX = None
                        try:
                            flagsX = nf_record.fieldValue.IPV4_SRC_ADDR
                        except Exception as e:
                                #print("Exception :" + str(e))    
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
                                #print("Exception :" + str(e))    
                                pass
                            
                    
                                    
                            
                             
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "id","=="):
                            
                            flagsX = None
                            try:
                                flagsX = packet[IP].id
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                            except Exception as e:
                                #print("Exception :" + str(e))    
                                pass
                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "chksum","=="):
                            
                            flagsX = None
                            try:
                                
                                flagsX = int(nf_record.fieldValue.FORWARDING_STATUS.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception :" + str(e))    
                                pass

                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "chksum","=="):
                            
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.FORWARDING_STATUS.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception :" + str(e))    
                                pass
                                    
                    elif rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "id","=="):
                            
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.ICMP_IPv4_CODE
                                rule_ip_info = cond.split(cond_op)
                                flagsX = int(nf_record.fieldValue.ICMP_IPv4_CODE)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                            except Exception as e:
                                #print("Exception :" + str(e))    
                                pass
                    
                            
                            
                         
                            
                            
                            
                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "tos","=="):
                            
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TOS
                                rule_ip_info = cond.split(cond_op)
                                tosX = int(nf_record.fieldValue.TOS)
                                new_cond = cond.replace(attr_name, repr(tosX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception :" + str(e))    
                                pass

                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "tos","=="):
                            
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.TOS)
                                rule_ip_info = cond.split(cond_op)
                                tosX = int(nf_record.fieldValue.TOS)
                                new_cond = cond.replace(attr_name, repr(tosX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception :" + str(e))    
                                pass        
                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "ttl","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.IP_TTL.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            
                            except Exception as e:
                                #print("Exception :" + str(e))    
                                pass
                            

                    elif rule_proto.upper() == nf_protocol.upper() and  eval_t(attr_name + "==" + "ttl","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.IP_TTL.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            
                            except Exception as e:
                                #p3rint("Exception :" + str(e))    
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
                                #print("Exception :" + str(e))    
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
                                #print("Exception :" + str(e))    
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
                                #print("Exception :" + str(e))    
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
                                #print("Exception :" + str(e))    
                                pass
                            
                            
                            

                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "sport","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.L4_SRC_PORT)
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception :" + str(e))    
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
                                #print("Exception :" + str(e))    
                                pass
                            
                            
                    elif  rule_proto.upper() == nf_protocol.upper() and eval_t(attr_name + "==" + "sport","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.L4_SRC_PORT)
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                #print("Exception :" + str(e))    
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
                                #print("Exception :" + str(e))    
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
                                #print("Exception :" + str(e))    
                                pass
                            
                            
                    #print(rule_applicable,eval_t(new_cond,cond_op),cond,new_cond)      
                    rule_applicable = eval_t(new_cond,cond_op)
                    rule_applicable_a = rule_applicable_a and rule_applicable

                
                except Exception as e:
                    #print ("Exception :" + str(e))
                    pass
        #print(rule_applicable,rule_applicable_a, rule_applicable_a and rule_applicable)
        return rule_applicable_a    
                      
        
def evalFbfRuleCondition_23(packet,nf_record_x, cond_list, rule_proto):
        """
        evaluate the condition
        """
        cond = new_cond = None
        rule_applicable_a = True
        rule_applicable = True
        
        nf_record = netflow.NetflowRecordV9(nf_record_x)
        proto_no = 0
        proto = None
                    
        
        try:
                for cond in cond_list:
                    new_cond = None
                    cond_op = getConditionalOperator(cond)
                    attr_name = cond.split(cond_op)[0]
                    attr_val  = cond.split(cond_op)[1]
                    
                    nf_record.show()
                    
                    if rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "version","=="):
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
                                print("Exception :" + str(e))    
                                pass
                    elif rule_proto.upper() == 'ICMP' and eval_t(attr_name + "==" + "seq","=="):
                            flagsX = None
                            try:
                                
                                flagsX = int(nf_record.fieldValue.ICMP_IPv4_TYPE.decode('utf-8','ignore'))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                  
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass        

                    elif rule_proto.upper() == 'ICMP' and  eval_t(attr_name + "==" + "type","=="):
                            try:
                                    
                                    rule_ip_info = cond.split(cond_op)
                                    tosX = int(nf_record.fieldValue.ICMP_TYPE)
                                    
                                    new_cond = cond.replace(attr_name, repr(tosX))
                                    
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)
                                    
                            except Exception as e:
                                print("Exception 333:" + str(e))    
                                pass
                    elif rule_proto.upper() == 'ICMP' and  eval_t(attr_name + "==" + "id","=="):
                            try:
                                                                   
                                    tosX = int(packet[IP].id)
                                    
                                    new_cond = cond.replace("id", repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    
                            except Exception as e:
                                print("Exception 444:" + str(e))    
                                pass    
                    elif rule_proto.upper() == 'ICMP' and  eval_t(attr_name + "==" + "unused","=="):
                            try:
                                    
                                    rule_ip_info = cond.split(cond_op)                                
                                    tosX = int(nf_record.fieldValue.ICMP_IPv4_CODE.decode('utf-8','ignore'))
                                    
                                    new_cond = cond.replace("unused", repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    
                                    
                            except Exception as e:
                                print("Exception 444:" + str(e))    
                                pass
                    elif rule_proto.upper() == 'ICMP' and  eval_t(attr_name + "==" + "reserved","=="):
                            try:
                                    
                                    rule_ip_info = cond.split(cond_op)                                
                                    tosX = int(nf_record.fieldValue.ICMP_IPv4_CODE.decode('utf-8','ignore'))
                                    
                                    new_cond = cond.replace("reserved", repr(tosX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)                 
                                    
                                    
                            except Exception as e:
                                print("Exception 444:" + str(e))    
                                pass
                    elif rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "src","=="):
                        flagsX = None
                        try:
                            flagsX = nf_record.fieldValue.IPV4_SRC_ADDR
                        except Exception as e:
                                print("Exception :" + str(e))    
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
                                print("Exception :" + str(e))    
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
                        
                        
                            
                    elif  rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "frag","=="):
                            flagsX = None
                            try:
                                flagsX = str(nf_record.fieldValue.FRAGMENT_OFFSET.decode('utf-8','ignore'))
                                rule_ip_info = cond.split(cond_op)
                                flagsX = int(flagsX)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                            
                    
                                    
                            
                             
                    elif rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "id","=="):
                            
                            flagsX = None
                            try:
                                flagsX = packet[IP].id
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                    elif  rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "chksum","=="):
                            
                            flagsX = None
                            try:
                                
                                flagsX = int(nf_record.fieldValue.FORWARDING_STATUS.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass

                    elif  rule_proto.upper() == 'UDP' and eval_t(attr_name + "==" + "chksum","=="):
                            
                            flagsX = None
                            try:
                                print("cholayyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy aallllllllllloooooooooooooooooooooooooooooooooooooooooo")
                                flagsX = int(nf_record.fieldValue.FORWARDING_STATUS.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                                    
                    elif rule_proto.upper() == 'ICMP' and eval_t(attr_name + "==" + "id","=="):
                            
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.ICMP_IPv4_CODE
                                rule_ip_info = cond.split(cond_op)
                                flagsX = int(nf_record.fieldValue.ICMP_IPv4_CODE)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                    
                            
                            
                         
                            
                            
                            
                    elif  rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "tos","=="):
                            
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TOS
                                rule_ip_info = cond.split(cond_op)
                                tosX = int(nf_record.fieldValue.TOS)
                                new_cond = cond.replace(attr_name, repr(tosX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass

                    elif  rule_proto.upper() == 'SCTP' and eval_t(attr_name + "==" + "tos","=="):
                            
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.TOS)
                                rule_ip_info = cond.split(cond_op)
                                tosX = int(nf_record.fieldValue.TOS)
                                new_cond = cond.replace(attr_name, repr(tosX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass        
                    elif rule_proto.upper() == 'TCP' and  eval_t(attr_name + "==" + "ttl","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.IP_TTL.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                            

                    elif rule_proto.upper() == 'ICMP' and  eval_t(attr_name + "==" + "ttl","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.IP_TTL.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass        
                            
                    elif  eval_t(attr_name + "==" + "protocol","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.PROTOCOL
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                            rule_ip_info = cond.split(cond_op)
                            tosX = int(nf_record.fieldValue.PROTOCOL)
                            
                            new_cond = cond.replace(attr_name, repr(tosX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                            
                    elif rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "urgptr","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TCP_URGENT_PTR.decode('utf-8','ignore')
                                flagsX = flagsX.replace('\x00','')
                                rule_ip_info = cond.split(cond_op)
                                ttlX = int(nf_record.fieldValue.TCP_URGENT_PTR.decode('utf-8','ignore').replace('\x00',''))
                                new_cond = cond.replace(attr_name, repr(ttlX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                            
                            
                            
                    
                    
                    
                    elif rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "flags","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TCP_FLAGS
                                rule_ip_info = cond.split(cond_op)
                                DNSX = int(nf_record.fieldValue.TCP_FLAGS)
                                new_cond = cond.replace(attr_name, repr(DNSX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                           
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                            
                    
                    elif rule_proto.upper() == 'ICMP' and eval_t(attr_name + "==" + "payload","==") and packet.haslayer(Raw): ## and packet.haslayer(Raw).load:
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
                                print("Exception :" + str(e))    
                                pass
                            
                            

                            
                            

                            

                    
                            

                    elif  rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "ack","=="):
                            flagsX = None
                            try:
                                
                                flagsX = int(nf_record.fieldValue.TCP_ACK_NUM.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                timeoutX = int(nf_record.fieldValue.TCP_ACK_NUM.decode('utf-8','ignore').replace('\x00',''))
                                new_cond = cond.replace(attr_name, repr(timeoutX))
                                #new_cond = new_cond.replace(attr_val, pr(attr_val))
                                
                            
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                            
                            
                            

                    elif  rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "sport","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.L4_SRC_PORT)
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                            
                            
                            
                            
                    
                    elif  rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "dport","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.L4_DST_PORT
                                rule_ip_info = cond.split(cond_op)
                                dportX = int(nf_record.fieldValue.L4_DST_PORT)
                                new_cond = cond.replace(attr_name, repr(dportX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                            
                            
                    elif  rule_proto.upper() == 'UDP' and eval_t(attr_name + "==" + "sport","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.L4_SRC_PORT)
                                rule_ip_info = cond.split(cond_op)
                                new_cond = cond.replace(attr_name, repr(flagsX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                            
                            
                            
                            
                    
                    elif  rule_proto.upper() == 'UDP' and eval_t(attr_name + "==" + "dport","=="):
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.L4_DST_PORT
                                rule_ip_info = cond.split(cond_op)
                                dportX = int(nf_record.fieldValue.L4_DST_PORT)
                                new_cond = cond.replace(attr_name, repr(dportX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass        
                            
                            
                                    

                    elif rule_proto.upper() == 'TCP' and eval_t(attr_name + "==" + "seq","=="):
                            flagsX = None
                            try:
                                flagsX = int(nf_record.fieldValue.TCP_SEQ_NUM.decode('utf-8','ignore').replace('\x00',''))
                                rule_ip_info = cond.split(cond_op)
                                chksumX = int(nf_record.fieldValue.TCP_SEQ_NUM.decode('utf-8','ignore').replace('\x00',''))
                                new_cond = cond.replace(attr_name, repr(chksumX))
                                #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                            except Exception as e:
                                print("Exception :" + str(e))    
                                pass
                            
                            
                    print(rule_applicable,eval_t(new_cond,cond_op),cond,new_cond)      
                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)

                return rule_applicable            
        except Exception as e:
              print ("Exception :" + str(e))
              return False
        

def evalFbfRuleConditionsss(nf_record, cond_list, rule_proto):
        """
        evaluate the condition
        """
        cond = new_cond = None
        rule_applicable_a = True
        rule_applicable = True
        
        nf_record = netflow.NetflowRecordV9(nf_record)
        proto_no = 0
        proto = None
        
        try:
            proto_no = nf_record.fieldValue.PROTOCOL
            proto = PROTOCOLS[proto_no].lower()
        
        except Exception as e:
            print("Exception :" + str(e))
            pass
        
        set1 = set(proto.lower().split())
        set2 = set(rule_proto.lower().split())

        if set1 != set2 :
            return False
        
        for cond in cond_list:
                    new_cond = None
                    cond_op = getConditionalOperator(cond)
                    attr_name = cond.split(cond_op)[0]
                    attr_val  = cond.split(cond_op)[1]
                                         
                    if  attr_name == 'version':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.IP_PROTOCOL_VERSION
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                            rule_ip_info = cond.split(cond_op)
                            versionX = int(nf_record.fieldValue.IP_PROTOCOL_VERSION)
                            new_cond = cond.replace(attr_name, repr(versionX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            #if not rule_applicable_a and versionX !=  Protocol_f[m]:
                            #    return False, "FORWARD",m
                            

                    elif  attr_name == 'type':
                            cond = str(attr_name) + str(cond_op) + str(attr_val)
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.ICMP_TYPE
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                                                             
                            rule_ip_info = cond.split(cond_op)
                            tosX = int(nf_record.fieldValue.ICMP_TYPE)
                            ##print(cond,rule_ip_info ,packet[TCP].flags,str(packet[TCP].flags),int(packet[TCP].flags),packet['TCP'].flags,"paramparaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                            new_cond = cond.replace(attr_name, repr(tosX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  rule_applicable_a and  eval_t(new_cond,cond_op)
                    
                    
                    elif attr_name == 'src':
                        flagsX = None
                        try:
                            flagsX = nf_record.fieldValue.IPV4_SRC_ADDR
                        except:
                            print("Exception :" + str(e))    
                            pass
                            
                        rule_ip_info = cond.split(cond_op)[1].split('/')
                        if len(rule_ip_info) == 1:
                                #not net mask
                                new_cond = cond.replace(attr_val,repr(attr_val))
                                new_cond = new_cond.replace(attr_name, repr(nf_record.fieldValue.IPV4_DST_ADDR))
                                

                        elif len(rule_ip_info) == 2:
                                #subnet
                                ip_net, net =  extractNetworkAddr(rule_ip_info, nf_record.fieldValue.IPV4_DST_ADDR)
                                new_cond = cond.replace(attr_val, repr(net))
                                new_cond = new_cond.replace(attr_name, repr(ip_net))

                        #rule_applicable =  rule_applicable and   eval_t(new_cond,cond_op)
                        rule_applicable_a =  rule_applicable_a and  eval_t(new_cond,cond_op)
                        
                        
                    elif  attr_name == 'dst':
                        flagsX = None
                        try:
                            flagsX = nf_record.fieldValue.IPV4_DST_ADDR
                        except:
                            print("Exception :" + str(e))    
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
                        rule_applicable_a =  rule_applicable_a and  eval_t(new_cond,cond_op)
                        
                    elif proto.upper() == 'TCP' and  attr_name == 'tos':
                            flags,TOS = None,None
                            try:
                                flagsX = nf_record.fieldValue.PROTOCOL
                            except:
                                print("Exception :" + str(e))    
                                pass
                            try:
                                TOS = nf_record.fieldValue.TOS
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                            
                            rule_ip_info = cond.split(cond_op)
                            flagsX = int(nf_record.fieldValue.PROTOCOL)
                            new_cond = cond.replace(attr_name, repr(flagsX))
                            new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =   eval_t(new_cond,cond_op)
                            
                            rule_ip_info = cond.split(cond_op)
                            tosX = int(nf_record.fieldValue.TOS)
                            new_cond = cond.replace(attr_name, repr(tosX))
                            new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            
                    elif  attr_name == 'frag':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.FRAGMENT_OFFSET
                            except:
                                print("Exception :" + str(e))    
                                pass
                            try:
                                flagsX = nf_record.fieldValue.TCP_FLAGS
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                            rule_ip_info = cond.split(cond_op)
                            flagsX = int(nf_record.fieldValue.FRAGMENT_OFFSET)
                            new_cond = cond.replace(attr_name, repr(flagsX))
                            new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = eval_t(new_cond,cond_op)
                             
                            rule_ip_info = cond.split(cond_op)
                            flagsX = int(nf_record.fieldValue.FRAGMENT_OFFSET)
                            new_cond = cond.replace(attr_name, repr(flagsX))
                            new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and  eval_t(new_cond,cond_op)
                            
                    elif   attr_name == 'flags':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TCP_FLAGS
                            except:
                                print("Exception :" + str(e))    
                                pass
                            flagsX2 = None
                            rule_ip_info = cond.split(cond_op)
                            flagsX = int(nf_record.fieldValue.TCP_FLAGS)
                            new_cond = cond.replace(attr_name, repr(flagsX))
                            new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                            
                            
                    elif proto.upper() == 'TCP' and  attr_name == 'version':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.IP_PROTOCOL_VERSION
                            except:
                                print("Exception :" + str(e))    
                                pass
                                                                       
                            rule_ip_info = cond.split(cond_op)
                            flagsX = int(nf_record.fieldValue.IP_PROTOCOL_VERSION)
                            new_cond = cond.replace(attr_name, repr(flagsX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            print( eval_t(new_cond,cond_op),new_cond)
                            rule_applicable_a =  rule_applicable_a and  eval_t(new_cond,cond_op)
                            
                            
                    elif proto.upper() =='SCTP'  and attr_name == 'tos':
                            
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TOS
                            except:
                                print("Exception :" + str(e))    
                                pass
                            rule_ip_info = cond.split(cond_op)
                            tosX = int(nf_record.fieldValue.TOS)
                            ##print(cond,rule_ip_info ,packet[TCP].flags,str(packet[TCP].flags),int(packet[TCP].flags),packet['TCP'].flags,"paramparaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                            new_cond = cond.replace(attr_name, repr(tosX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            
                    elif  attr_name == 'tos':
                            
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TOS
                            except:
                                print("Exception :" + str(e))    
                                pass
                            rule_ip_info = cond.split(cond_op)
                            tosX = int(nf_record.fieldValue.TOS)
                            ##print(cond,rule_ip_info ,packet[TCP].flags,str(packet[TCP].flags),int(packet[TCP].flags),packet['TCP'].flags,"paramparaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                            new_cond = cond.replace(attr_name, repr(tosX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            
                    elif proto.upper() =='IP'  and attr_name == 'tos':
                            
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TOS
                            except:
                                print("Exception :" + str(e))    
                                pass
                            rule_ip_info = cond.split(cond_op)
                            tosX = int(nf_record.fieldValue.TOS)
                            ##print(cond,rule_ip_info ,packet[TCP].flags,str(packet[TCP].flags),int(packet[TCP].flags),packet['TCP'].flags,"paramparaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                            new_cond = cond.replace(attr_name, repr(tosX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            
                    

                    elif   attr_name == 'ttl':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.IP_TTL
                            except:
                                continue
                            flagsX2 = None
                            try:
                                flagsX2 = nf_record.fieldValue.L4_SRC_PORT
                            except:
                                print("Exception :" + str(e))    
                                pass
                            rule_ip_info = cond.split(cond_op)
                            tosX = int(nf_record.fieldValue.IP_TTL)
                            ##print(cond,rule_ip_info ,packet[TCP].flags,str(packet[TCP].flags),int(packet[TCP].flags),packet['TCP'].flags,"paramparaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                            new_cond = cond.replace(attr_name, repr(tosX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)

                            rule_ip_info = cond.split(cond_op)
                            tosX = int(nf_record.fieldValue.L4_SRC_PORT)
                            ##print(cond,rule_ip_info ,packet[TCP].flags,str(packet[TCP].flags),int(packet[TCP].flags),packet['TCP'].flags,"paramparaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                            new_cond = cond.replace(attr_name, repr(tosX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            
                    elif   attr_name == 'protocol':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.PROTOCOL
                            except:
                                print("Exception :" + str(e))    
                                pass
                            rule_ip_info = cond.split(cond_op)
                            tosX = int(nf_record.fieldValue.PROTOCOL)
                            ##print(cond,rule_ip_info ,packet[TCP].flags,str(packet[TCP].flags),int(packet[TCP].flags),packet['TCP'].flags,"paramparaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                            new_cond = cond.replace(attr_name, repr(tosX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            
                    elif  attr_name == 'urgptr':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TCP_URGENT_PTR
                            except:
                                print("Exception :" + str(e))    
                                pass
                            try:
                                flagsX = nf_record.fieldValue.TCP_FLAGS
                            except:
                                print("Exception :" + str(e))    
                                pass
                            rule_ip_info = cond.split(cond_op)
                            ttlX = int(nf_record.fieldValue.TCP_URGENT_PTR)
                            new_cond = cond.replace(attr_name, repr(ttlX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)

                            rule_ip_info = cond.split(cond_op)
                            ttlX = int(nf_record.fieldValue.TCP_FLAGS)
                            new_cond = cond.replace(attr_name, repr(ttlX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            
                    elif  attr_name == 'seq':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TCP_SEQ_NUM
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                            rule_ip_info = cond.split(cond_op)
                            ttlX = int(nf_record.fieldValue.TCP_SEQ_NUM)
                            new_cond = cond.replace(attr_name, repr(ttlX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                    
                    
                    elif    attr_name == 'sport':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.L4_SRC_PORT
                            except:
                                print("Exception :" + str(e))    
                                pass
                            try:
                                flagsX = nf_record.fieldValue.TCP_FLAGS
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                            rule_ip_info = cond.split(cond_op)
                            DNSX = int(nf_record.fieldValue.L4_SRC_PORT)
                            new_cond = cond.replace(attr_name, repr(DNSX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)

                            rule_ip_info = cond.split(cond_op)
                            DNSX = int(nf_record.fieldValue.TCP_FLAGS)
                            new_cond = cond.replace(attr_name, repr(DNSX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            
                    
                    elif   attr_name == 'payload' and packet.haslayer(Raw): ## and packet.haslayer(Raw).load:
                            #get actual payload value (in string format)
                            
                                     
                            try:
                                    hexval = int(packet.getlayer('Raw').load, 16)
                                    message = bytes_to_str(hexval)
                                    message =   bytes.fromhex(message).decode('utf-8')
                                    new_cond = cond.replace(attr_name, str(message))
                                    new_cond = new_cond.replace(str(attr_val),str(message)) #str(attr_val))
                                    #rule_applicable = rule_applicable and bool(new_cond)
                            except :
                                    new_cond = cond.replace(attr_name, str(packet.getlayer('Raw').load.decode('utf-8','ignore')))
                                    new_cond = new_cond.replace(attr_val,str(packet.getlayer('Raw').load.decode('utf-8','ignore'))) #str(attr_val))
                            
                            new_cond = cond.replace(attr_name,str(packet.getlayer('Raw').load.decode('utf-8','ignore')))
                            try:
                                rule_applicable = rule_applicable and bool(new_cond)
                            except:
                                parts = new_cond.split(cond_op)
                                rule_applicable =  len(parts[0]) == len(parts[1])
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                                    
                            
                    
                    elif  attr_name == 'dport':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.L4_DST_PORT
                            except:
                                print("Exception :" + str(e))    
                                pass
                            try:
                                flagsX = nf_record.fieldValue.TCP_WINDOW_SIZE
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                            rule_ip_info = cond.split(cond_op)
                            ttlX = int(nf_record.fieldValue.L4_DST_PORT)
                            new_cond = cond.replace(attr_name, repr(ttlX))
                            #new_cond = new_cond.replace(attr_val, pr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)

                            rule_ip_info = cond.split(cond_op)
                            ttlX = int(nf_record.fieldValue.TCP_WINDOW_SIZE)
                            new_cond = cond.replace(attr_name, repr(ttlX))
                            #new_cond = new_cond.replace(attr_val, pr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)

                            

                    
                            

                    elif  attr_name == 'ack':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TCP_ACK_NUM
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                            rule_ip_info = cond.split(cond_op)
                            timeoutX = int(nf_record.fieldValue.TCP_ACK_NUM.decode())
                            new_cond = cond.replace(attr_name, repr(timeoutX))
                            #new_cond = new_cond.replace(attr_val, pr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            

                    elif  attr_name == 'L4_SRC_PORT':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.UDP_SRC_PORT
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                            rule_ip_info = cond.split(cond_op)
                            sportX = int(nf_record.fieldValue.L4_SRC_PORT)
                            new_cond = cond.replace(attr_name, repr(sportX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            
                    
                    elif  attr_name == 'sport':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.L4_SRC_PORT
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                            rule_ip_info = cond.split(cond_op)
                            dportX = int(nf_record.fieldValue.L4_SRC_PORT)
                            new_cond = cond.replace(attr_name, repr(dportX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            
                    elif  attr_name == 'dport':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.L4_SRC_PORT
                            except:
                                print("Exception :" + str(e))    
                                pass
                            try:
                                flagsX = nf_record.fieldValue.L4_DST_PORT
                            except:
                                print("Exception :" + str(e))    
                                pass
                            rule_ip_info = cond.split(cond_op)
                            dportX = int(nf_record.fieldValue.L4_SRC_PORT)
                            new_cond = cond.replace(attr_name, repr(dportX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            #rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)

                            rule_ip_info = cond.split(cond_op)
                            dportX = int(nf_record.fieldValue.L4_DST_PORT)
                            new_cond = cond.replace(attr_name, repr(dportX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            #rule_applicable_a = rule_applicable_a and   eval_t(new_cond,cond_op)
                            
                    elif  attr_name == 'ttl':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.IP_TTL
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                            rule_ip_info = cond.split(cond_op)
                            if packet[TCP].chksum:
                                    chksumX = int(nf_record.IP_TTLdecode())
                                    new_cond = cond.replace(attr_name, repr(chksumX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                                    

                    elif  attr_name == 'tos':
                            flagsX = None
                            try:
                                flagsX = nf_record.fieldValue.TCP_SEQ_NUM
                            except:
                                print("Exception :" + str(e))    
                                pass
                            
                            rule_ip_info = cond.split(cond_op)
                            if packet[UDP].chksum:
                                    chksumX = int(nf_record.fieldValue.TCP_SEQ_NUM)
                                    new_cond = cond.replace(attr_name, repr(chksumX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            
                          
                    rule_applicable = rule_applicable and eval_t(new_cond,cond_op)
                
        return rule_applicable,proto_no

def applyFbfRuleAction(ip_pkt, rule):
        
        if rule.get_action() == 'drop':
                return (ip_pkt,'D')
        elif rule.get_action() == 'normalise':
                return (alterFlowAttr(ip_pkt, rule.get_protocol(), rule.get_norm_op()),'N') #N for normalised
        else:
                return (ip_pkt,'F') #F for accepted/forwarded without normalization

def applyFbfRule(ip_pkt, rule,nf_record):

        applied = False
        state,proto_no = False , 0
        
        if len(rule.get_conditions()) > 0 :
                
                #evaluate condition
                state = evalFbfRuleCondition(ip_pkt,nf_record, rule.get_conditions(), rule.get_protocol())
       
                #nf_record = netflow.NetflowRecordV9(nf_record)
       
                proto_no = 0
                proto = None
                
                try:
                    proto_no = nf_record.fieldValue.PROTOCOL
                    proto = PROTOCOLS[proto_no].lower()
                
                except Exception as e:
                    print("Exception :" + str(e))
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
                        return (ip_pkt, "none", False)
        else:
                #nf_record = netflow.NetflowRecordV9(nf_record)
                proto_no = 0
                proto = None
       
                try:
                    proto_no = nf_record.fieldValue.PROTOCOL
                    proto = PROTOCOLS[proto_no].lower()
                
                except Exception as e:
                    print("Exception :" + str(e))
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
                        return (ip_pkt, "none", False)
       

def processFlowWithfbfRules(ip_packet, rules,nf_record):
        """
        packet analyzer
        """
        is_norm = False
        
        i = 1 
        for rule in rules:
                
                ip_packet, action, is_norm = applyFbfRule(ip_packet, rule,nf_record)
                print(action,"rule no",i)
                if action == "dropped":
                        return (ip_packet, action)
                if is_norm is True:
                        return (ip_packet, 'normalised')
                if action == "forwarded":
                        return (ip_packet, action)
                
                is_norm = False
                i = i + 1         
        return (ip_packet, 'forwarded')

