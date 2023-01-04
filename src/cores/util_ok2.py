from scapy.all import IP, Ether, ICMP, TCP, UDP, DNS, ARP, Packet, conf
import netifaces
import netfilterqueue

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
        
def evalPbfRuleConditionss(pkt, cond_list, rule_proto):
        """
        evaluate the condition
        """
        cond = new_cond = None
        rule_applicable = False
        rule_applicable_a = False
        for cond in cond_list:
                print("GO gi gi ")
                new_cond = None
                cond_op = getConditionalOperator(cond)
                attr_name = cond.split(cond_op)[0]
                attr_val  = cond.split(cond_op)[1]
                if attr_name == 'src':
                        rule_ip_info = cond.split(cond_op)[1].split('/')
                        if len(rule_ip_info) == 1:
                                #not net mask
                                new_cond = cond.replace(attr_val,repr(attr_val))
                                new_cond = new_cond.replace(attr_name, repr(packet.dst))
                                

                        elif len(rule_ip_info) == 2:
                                #subnet
                                ip_net, net = extractNetworkAddr(rule_ip_info, packet.dst)
                                new_cond = cond.replace(attr_val, repr(net))
                                new_cond = new_cond.replace(attr_name, repr(ip_net))

                        #rule_applicable =  rule_applicable and  eval_t(new_cond,cond_op)
                        rule_applicable_a =  eval_t(new_cond,cond_op)
                        
                        
                elif attr_name == 'dst':
                        rule_ip_info = cond.split(cond_op)[1].split('/')
                        if len(rule_ip_info) == 1:
                                #not net mask
                                new_cond = cond.replace(attr_val, repr(attr_val))
                                new_cond = new_cond.replace(attr_name, repr(packet.src))
                                

                        elif len(rule_ip_info) == 2:
                                #subnet
                                ip_net, net = extractNetworkAddr(rule_ip_info, packet.src)
                                new_cond = cond.replace(attr_val, repr(net))
                                new_cond = new_cond.replace(attr_name, repr(ip_net))
                                
                        
                        
                        #rule_applicable =  rule_applicable and  eval_t(new_cond,cond_op)
                        rule_applicable_a =  eval_t(new_cond,cond_op)
                        
                elif pkt.haslayer(rule_proto) and attr_name == 'flags':
                            print("condition 1 matched") 
                            rule_ip_info = cond.split(cond_op)
                            flagsX = int(packet[TCP].flags)
                            new_cond = cond.replace(attr_name, repr(flagsX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            
                elif pkt.haslayer(rule_proto) and attr_name == 'flags':
                            
                            rule_ip_info = cond.split(cond_op)
                            flagsX = int(packet[TCP].flags)
                            new_cond = cond.replace(attr_name, repr(flagsX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                                
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            
                            
                elif pkt.haslayer(rule_proto) and attr_name == 'tos':
                            rule_ip_info = cond.split(cond_op)
                            tosX = int(packet[IP].tos)
                            ##print(cond,rule_ip_info ,packet[TCP].flags,str(packet[TCP].flags),int(packet[TCP].flags),packet['TCP'].flags,"paramparaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                            new_cond = cond.replace(attr_name, repr(tosX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =   eval_t(new_cond,cond_op)
                            
                elif pkt.haslayer(rule_proto) and attr_name == 'tos':
                            rule_ip_info = cond.split(cond_op)
                            tosX = int(packet[IP].tos)
                            ##print(cond,rule_ip_info ,packet[TCP].flags,str(packet[TCP].flags),int(packet[TCP].flags),packet['TCP'].flags,"paramparaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                            new_cond = cond.replace(attr_name, repr(tosX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            
                elif pkt.haslayer(rule_proto) and attr_name == 'ttl':
                            rule_ip_info = cond.split(cond_op)
                            ttlX = int(packet[IP].ttl)
                            new_cond = cond.replace(attr_name, repr(ttlX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            
                elif pkt.haslayer(rule_proto) and attr_name == 'ttl':
                            rule_ip_info = cond.split(cond_op)
                            ttlX = int(packet[IP].ttl)
                            new_cond = cond.replace(attr_name, repr(ttlX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                    
                    
                elif pkt.haslayer(rule_proto) and attr_name == 'id':
                            rule_ip_info = cond.split(cond_op)
                            DNSX = int(packet[DNS].id)
                            new_cond = cond.replace(attr_name, repr(DNSX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            
                    
                elif  attr_name == 'payload' and packet.haslayer('Raw'):
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
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                                    
                elif pkt.haslayer(rule_proto) and attr_name == 'type':
                            rule_ip_info = cond.split(cond_op)
                            typeX = int(packet[ICMP].type)
                            new_cond = cond.replace(attr_name, repr(typeX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            
                    
                elif pkt.haslayer(rule_proto) and attr_name == 'ttl':
                            rule_ip_info = cond.split(cond_op)
                            ttlX = int(packet[ICMP].ttl)
                            new_cond = cond.replace(attr_name, repr(ttlX))
                            #new_cond = new_cond.replace(attr_val, pr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            

                elif pkt.haslayer(rule_proto) and attr_name == 'tos':
                            rule_ip_info = cond.split(cond_op)
                            tosX = int(packet[ICMP].tos)
                            new_cond = cond.replace(attr_name, repr(tosX))
                            #new_cond = new_cond.replace(attr_val, pr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            

                elif pkt.haslayer(rule_proto) and attr_name == 'timeout':
                            rule_ip_info = cond.split(cond_op)
                            timeoutX = int(packet[ICMP].timeout)
                            new_cond = cond.replace(attr_name, repr(timeoutX))
                            #new_cond = new_cond.replace(attr_val, pr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            

                elif pkt.haslayer(rule_proto) and attr_name == 'sport':
                            rule_ip_info = cond.split(cond_op)
                            sportX = int(packet[UDP].sport)
                            new_cond = cond.replace(attr_name, repr(sportX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            
                    
                elif pkt.haslayer(rule_proto) and attr_name == 'dport':
                            rule_ip_info = cond.split(cond_op)
                            dportX = int(packet[UDP].dport)
                            new_cond = cond.replace(attr_name, repr(dportX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            

                elif pkt.haslayer(rule_proto) and attr_name == 'chksum':
                            rule_ip_info = cond.split(cond_op)
                            if packet[TCP].chksum:
                                    chksumX = int(packet[TCP].chksum)
                                    new_cond = cond.replace(attr_name, repr(chksumX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                                    

                elif pkt.haslayer(rule_proto) and attr_name == 'chksum':
                            rule_ip_info = cond.split(cond_op)
                            if packet[UDP].chksum:
                                    chksumX = int(packet[UDP].chksum)
                                    new_cond = cond.replace(attr_name, repr(chksumX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                                    

                elif pkt.haslayer(rule_proto) and attr_name == 'chksum':
                            rule_ip_info = cond.split(cond_op)
                            if packet[ICMP].chksum:
                                    chksumX = int(packet[ICMP].chksum)
                                    new_cond = cond.replace(attr_name, repr(chksumX))
                                    #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            
                    
                elif pkt.haslayer(rule_proto) and attr_name == 'sport':
                            rule_ip_info = cond.split(cond_op)
                            sportX = int(packet[TCP].sport)
                            new_cond = cond.replace(attr_name, repr(sportX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            
                    
                elif pkt.haslayer(rule_proto) and attr_name == 'dport':
                            rule_ip_info = cond.split(cond_op)
                            dportX = int(packet[TCP].dport)
                            new_cond = cond.replace(attr_name, repr(dportX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)
                            
                                            
                elif pkt.haslayer(rule_proto) and attr_name == 'version':
                            print("condition 2 matched")
                            rule_ip_info = cond.split(cond_op)
                            versionX = int(packet[IP].version)
                            new_cond = cond.replace(attr_name, repr(versionX))
                            #new_cond = new_cond.replace(attr_val, repr(attr_val))
                            rule_applicable_a =  eval_t(new_cond,cond_op)

                rule_applicable = rule_applicable and  rule_applicable_a
                    
        print(new_cond, rule_applicable)       
        return rule_applicable


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
                        

                elif attr_name == 'payload' and pkt.haslayer('Raw'):
                        #get actual payload value (in string format) 
                        new_cond = cond.replace(attr_name, bytes_to_str(pkt.getlayer('Raw').load))
                        new_cond = new_cond.replace(attr_val, str(attr_val))

                else:
                        print(cond,"yeh cheez")
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
                print(new_cond, rule_applicable,"condy 1")
        print(new_cond, rule_applicable,"condy 2")
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
