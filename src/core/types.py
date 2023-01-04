from scapy.all import TCP, UDP
from netfilterqueue import PROTOCOLS
import time
import argparse
from datetime import datetime
from core.rules import PACKET_BASED_FILTER_RULES


class PacketBasedFilterRule:
        """A class that defines the attributes for a packet-based filter rule.
        """
        def __init__(self):
                pass

        def __init__(self, num, ptype='', conds=[], action='', protocol='', norm_op='', desc=''):

                #initialise variables
                self.num        = num 
                self._ptype     = ptype #IP, ARP ...
                self._conds_lst = conds #e.g [ ttl>30, src!=192.14.33.2 ]
                self._action    = action #e.g drop, accept and normalise
                self._protocol  = protocol #TCP 
                self._norm_op   = norm_op #normalization operation e.g ttl=126
                self._desc      = desc

        def get_ptype(self):
                return self._ptype


        def has_conditions(self):
                return True if(len(self._conds_lst) > 0) else False


        def get_conditions(self):
                return self._conds_lst


        def get_action(self):
                return self._action


        def get_protocol(self):
                return self._protocol


        def get_norm_op(self):
                return self._norm_op

        def __str__(self):
                return self._desc
        
        @staticmethod
        def getPacketBasedFilterRuleByNumber(rule_no):
                """Retrieves a rule string from PACKET_BASED_FILTER_RULES, parse and return a 
                PacketBasedFilterRule object or None on error
                """
                rule = PACKET_BASED_FILTER_RULES[rule_no]
                r_string = rule[0]
                r_parser = argparse.ArgumentParser(description="PacketBasedFilterRule parser")
                r_parser.add_argument(
                        '--type',
                        action='store',
                        dest='ptype',
                        required=True,
                        type=str)
                r_parser.add_argument(
                        '--condition',
                        action='store',
                        dest='conds',
                        required=False,
                        type=str, 
                        default='', 
                        nargs='+')
                r_parser.add_argument(
                        '--protocol',
                        action='store',
                        dest='protocol',
                        required=False,
                        type=str,
                        default='any')
                r_parser.add_argument(
                        '--action',
                        action='store',
                        dest='action',
                        required=True, 
                        type=str)
                r_parser.add_argument(
                        '--norm-op',
                        action='store',
                        dest='norm_op',
                        required=False,
                        type=str, 
                        default='', 
                        nargs='+')

                try:
                        result = r_parser.parse_args(r_string.split())
                except:
                        return None
                norm_op_str = ' '.join(result.norm_op)
                if result.conds == '':
                        return PacketBasedFilterRule(num=rule_no, ptype=result.ptype, action=result.action, \
                                protocol=result.protocol.upper(),norm_op=norm_op_str, desc=rule[1])

                conds_str = ' '.join(result.conds)

                return PacketBasedFilterRule(num=rule_no, ptype=result.ptype, conds=conds_str.split(','), action=result.action, \
                        protocol=result.protocol.upper(),norm_op=norm_op_str, desc=rule[1])

        @staticmethod
        def get_rules_randomly(no_of_rules):
                """get a given no. of rules randomly
                """
                print("    # generating", no_of_rules, "rule number(s) randomly.")
                #get all rule no.s
                new_list = random.sample(PACKET_BASED_FILTER_RULES.keys(), no_of_rules)
                new_list.sort()
                return new_list

        """
        get a given no of random rules, and the rules should not be in the initial list given as a parameter to the method
        """
        @staticmethod
        def get_new_rules_randomly(no_of_rules, init_rules):
                print("    # generating", no_of_rules,"rule number(s) randomly.")
                #print(available)
                new_list = random.sample(list(set(PacketBasedFilterRule.get_all_rules().keys()) - set(init_rules)), no_of_rules)
                new_list.sort()
                return new_list

        @staticmethod
        def getPacketBasedFilterRulesFromNumbers(rule_numbers):
                """Create PacketBasedFilterRule objects from rule numbers
                """
                init    = 0
                no_init = 0
                rules   = []
                for rule_num in rule_numbers:
                        rl = PacketBasedFilterRule.getPacketBasedFilterRuleByNumber(rule_num)
                        if rl != None:
                                rules.append(rl)
                                init += 1
                        else:
                                no_init += 1

                print(' | successful: %d, fail: %d' %(init, no_init))
                return rules



class Netflow:

        """
        NetFlow is a feature that was introduced on network routers by Cisco ease the collection of IP network 
        traffic as it enters and exits network interfaces.

        According to Cisco standard NetFlow version 5, a NetFlow is a unidirectional sequence of packets that share the same 
        values for:
                - SNMP (Simple Network Management Protocol) ifIndex.
                - Source IP address.
                - Destination IP address.
                - IP protocol.
                - Source port for UDP or TCP, 0 for other protocols
                - Destination port for UDP or TCP, type and code for ICMP, or 0 for other protocols.
                - IP Type of Service.

        This Python class provides a data store for holding information about a single NetFlow. This class provides many more 
        attributes (Time-based and Volume-based) that can be used describe a NetFlow.
        """

        def __init__(self, flow_id, group_id, first_packet):

                # basic
                self.id               = flow_id
                self.group_id         = group_id
                self.src_ip_addr      = first_packet.src
                self.dst_ip_addr      = first_packet.dst
                self.sport            = first_packet.sport
                self.dport            = first_packet.dport
                self.proto            = first_packet.proto
                # self.is_bidirectional = is_bidirectional

                self.packets          = [first_packet]

                self.payload_len      = first_packet.pload_len
                self.hdr_len          = first_packet.hdr_len
                self.start_time       = first_packet.timestamp
                self.last_seen        = first_packet.timestamp
                # ruleno in netflow records
                self.ruleno           = first_packet.ruleno 
                self.if_desc          = first_packet.if_desc 
                self.version          = first_packet.version  
                self.first_switched   = first_packet.first_switched
                self.last_switched    = first_packet.last_switched

                self.status    = 'Active'

        def update(self, newPacketInfo):

                self.packets.append(newPacketInfo)
                self.payload_len += newPacketInfo.pload_len
                self.hdr_len     += newPacketInfo.hdr_len
                self.last_seen    = newPacketInfo.timestamp

class Packetflow:

	"""
	NetFlow is a feature that was introduced on network routers by Cisco ease the collection of IP network 
	traffic as it enters and exits network interfaces.

	According to Cisco standard NetFlow version 5, a NetFlow is a unidirectional sequence of packets that share the same 
	values for:
		- SNMP (Simple Network Management Protocol) ifIndex.
		- Source IP address.
		- Destination IP address.
		- IP protocol.
		- Source port for UDP or TCP, 0 for other protocols
		- Destination port for UDP or TCP, type and code for ICMP, or 0 for other protocols.
		- IP Type of Service.

	This Python class provides a data store for holding information about a single NetFlow. This class provides many more 
	attributes (Time-based and Volume-based) that can be used describe a NetFlow.
	"""

	def __init__(self, flow_id, group_id, first_packet):
                # basic
                self.id               = flow_id
                self.group_id         = group_id
                self.src_ip_addr      = first_packet.src
                self.dst_ip_addr      = first_packet.dst
                self.sport            = first_packet.sport
                self.dport            = first_packet.dport
                self.proto            = first_packet.proto
                # self.is_bidirectional = is_bidirectional
                self.packets          = [first_packet]
                self.ruleno           = first_packet.ruleno
                self.payload_len      = first_packet.pload_len
                self.hdr_len          = first_packet.hdr_len
                self.start_time       = first_packet.timestamp
                self.last_seen        = first_packet.timestamp
                # TCP flags stats
                self.psh_count = 1 if(first_packet.psh) else 0
                self.fin_count = 1 if(first_packet.fin) else 0
                self.urg_count = 1 if(first_packet.urg) else 0
                self.rst_count = 1 if(first_packet.rst) else 0
                self.ack_count = 1 if(first_packet.ack) else 0
                self.ece_count = 1 if(first_packet.ece) else 0
                self.cwr_count = 1 if(first_packet.cwr) else 0
                self.syn_count = 1 if(first_packet.syn) else 0
                self.status    = 'Active'

	def update(self, newPacketInfo):

		self.packets.append(newPacketInfo)

		if newPacketInfo.fin:
			self.fin_count += 1
		if newPacketInfo.syn:
			self.syn_count += 1
		if newPacketInfo.rst:
			self.rst_count += 1
		if newPacketInfo.psh:
			self.psh_count += 1
		if newPacketInfo.ack:
			self.ack_count += 1
		if newPacketInfo.urg:
			self.urg_count += 1
		if newPacketInfo.cwr:
			self.cwr_count += 1
		if newPacketInfo.ece:
			self.ece_count += 1

		self.payload_len += newPacketInfo.pload_len
		self.hdr_len     += newPacketInfo.hdr_len
		self.last_seen    = newPacketInfo.timestamp



class packetInfo:
        """
        This is a utility class for temporarily holding relevant data about a network packet.
        """

        def __init__(self, src, dst, sport, dport, proto, timestamp, pload_len, hdr_len, window,ruleno):
                self.src       = src
                self.dst       = dst
                self.sport     = sport
                self.dport     = dport
                self.proto     = proto
                self.timestamp = timestamp
                self.pload_len = pload_len
                self.hdr_len   = hdr_len
                self.window    = window
                self.fin       = False
                self.psh       = False
                self.urg       = False
                self.ece       = False
                self.syn       = False
                self.ack       = False
                self.cwr       = False
                self.rst       = False
                self.ruleno    = ruleno 
                # self.is_of_bidirectional_flow = False

        def __str__(self):
                #return f'id: {PacketInfo.netflowIdOf(self)}, src: {self.src}, dst: {self.dst}, sport: {self.sport}, dport: {self.dport},' \
                #                + f' tstamp: {self.timestamp}, pllen: {self.pload_len}, hdrlen: {self.hdr_len}' 
                one ='id: %s , src : %s ,dst : %s , sport : %s , dport:%s ,' % (packetInfo.netflowGroupIdOf(self), self.src, self.dst,self.sport, self.dport)
                two ='tstamp: %s ,pllen: %s ,hdrlen : %s ,ruleno : %s ' % (self.timestamp,self.pload_len,self.hdr_len,self.ruleno) 
                return one+two

        @staticmethod
        def fromIpPacket(ip_packet,ruleno):
                (ns, cwr, ece, urg, ack, psh, rst, syn, fin) = (0, 0, 0, 0, 0, 0, 0, 0, 0) 
                dport     = 0
                sport     = 0
                window    = 0
                pload_len = len(bytes(ip_packet.payload))
                hdr_len   = len(bytes(ip_packet)) - pload_len

                transport_layer = TCP if(ip_packet.haslayer(TCP)) else UDP if(ip_packet.haslayer(UDP)) else None
                if transport_layer:
                        dport = ip_packet[transport_layer].dport
                        sport = ip_packet[transport_layer].sport

                        if transport_layer == TCP:
                                window = ip_packet[TCP].window
                                tcp_flags_bits = 0
                                try:
                                        tcp_flags_bits = bin(ip_packet[transport_layer].flags)
                                        (ns, cwr, ece, urg, ack, psh, rst, syn, fin) = \
                                        '0'*(9 - len(tcp_flags_bits[tcp_flags_bits.find('b') + 1:])) + tcp_flags_bits[tcp_flags_bits.find('b') + 1:]

                                except:
                                        pass

                packet_info = packetInfo(
                        ip_packet.src,
                        ip_packet.dst,
                        sport,
                        dport,
                        ip_packet.proto,
                        time.time(),
                        pload_len,
                        hdr_len,
                        window,ruleno)

                packet_info.cwr = bool(int(cwr))
                packet_info.ece = bool(int(ece))
                packet_info.urg = bool(int(urg))
                packet_info.psh = bool(int(psh))
                packet_info.rst = bool(int(rst))
                packet_info.syn = bool(int(syn))
                packet_info.ack = bool(int(ack))
                packet_info.fin = bool(int(fin))
                # packet_info.is_of_bidirectional_flow = ip_packet.haslayer(TCP)

                return packet_info

        @staticmethod
        def netflowGroupIdOf(packetInfo):

                is_forward = True
                index = 0
                src_ip_octets = packetInfo.src.split('.')
                dst_ip_octets = packetInfo.dst.split('.')
                proto = 0

                while index < len(src_ip_octets):
                        if int(src_ip_octets[index]) != int(dst_ip_octets[index]):
                                if int(src_ip_octets[index]) > int(dst_ip_octets[index]):
                                        is_forward = False
                                index = len(src_ip_octets)
                        index = index + 1
                try: 
                        proto = PROTOCOLS[packetInfo.proto].lower()
                except:
                        proto = 'UDP'

                if is_forward:
                        #return f'{packetInfo.src}:{packetInfo.sport}->{packetInfo.dst}:{packetInfo.dport}-{proto}'
                        return '%s:%s->%s:%s-%s' % (packetInfo.src,packetInfo.sport,packetInfo.dst,packetInfo.dport,proto)
                else:
                        #return f'{packetInfo.dst}:{packetInfo.dport}->{packetInfo.src}:{packetInfo.sport}-{proto}'
                        return '%s:%s->%s:%s-%s' % (packetInfo.dst,packetInfo.dport,packetInfo.src,packetInfo.sport,proto)

        @staticmethod
        def netflowRealIdOf(packetInfo):

                is_forward = True
                index = 0
                src_ip_octets = packetInfo.src.split('.')
                dst_ip_octets = packetInfo.dst.split('.')
                proto = 0

                while index < len(src_ip_octets):
                        if int(src_ip_octets[index]) != int(dst_ip_octets[index]):
                                if int(src_ip_octets[index]) > int(dst_ip_octets[index]):
                                        is_forward = False
                                index = len(src_ip_octets)
                        index = index + 1
                try: 
                        proto = PROTOCOLS[packetInfo.proto].lower()
                except:
                        proto = 'UDP'

                #proto = PROTOCOLS[packetInfo.proto].lower()
                dt_str = datetime.fromtimestamp(packetInfo.timestamp).strftime('%Y%m%H%M%S%f')

                if is_forward:
                        #return f'{packetInfo.src}:{packetInfo.sport}->{packetInfo.dst}:{packetInfo.dport}-{proto}-{dt_str}'
                        return '%s:%s->%s:%s-%s-%s' % (packetInfo.src,packetInfo.sport,packetInfo.dst,packetInfo.dport,proto,dt_str)
                else:
                        #return f'{packetInfo.dst}:{packetInfo.dport}->{packetInfo.src}:{packetInfo.sport}-{proto}-{dt_str}'
                        return '%s:%s->%s:%s-%s-%s' % (packetInfo.dst,packetInfo.dport,packetInfo.src,packetInfo.sport,proto,dt_str)

class NetflowPacketInfo:
        """
        This is a utility class for temporarily holding relevant data about a network packet.
        """

        def __init__(self, src, dst, sport, dport, proto, timestamp, pload_len, hdr_len, window,ruleno,if_desc,version,last_switched,first_switched):
                self.src       = src
                self.dst       = dst
                self.sport     = sport
                self.dport     = dport
                self.proto     = proto
                self.timestamp = timestamp
                self.pload_len = pload_len
                self.hdr_len   = hdr_len
                self.window    = window
                self.if_desc   = if_desc
                self.version   = version
                self.last_switched = last_switched
                self.first_switched = first_switched
                self.ruleno    = ruleno 
                # self.is_of_bidirectional_flow = False

        def __str__(self):
                #return f'id: {PacketInfo.netflowIdOf(self)}, src: {self.src}, dst: {self.dst}, sport: {self.sport}, dport: {self.dport},' \
                #                + f' tstamp: {self.timestamp}, pllen: {self.pload_len}, hdrlen: {self.hdr_len}' 
                one ='id: %s , src : %s ,dst : %s , sport : %s , dport:%s ,' % (NetflowPacketInfo.netflowGroupIdOf(self), self.src, self.dst,self.sport, self.dport)
                two ='tstamp: %s ,pllen: %s ,hdrlen : %s ,ruleno : %s ' % (self.timestamp,self.pload_len,self.hdr_len,self.ruleno) 
                return one+two

        @staticmethod
        def fromIpPacket(nf_record,ruleno):
                src       = None
                dst       = None 
                proto     = None
                dport     = 0
                sport     = 0
                window    = 0
                pload_len = len(bytes(nf_record.payload))
                hdr_len   = len(bytes(nf_record.payload)) - pload_len
                if_desc   = None
                version   = 0 
                last_switched = 0.0
                first_switched = 0.0
                ruleno    =  ruleno 
                if nf_record:
                        try:
                                
                               dport = nf_record.fieldValue.L4_DST_PORT
                               sport = nf_record.fieldValue.L4_SRC_PORT
                               proto = nf_record.fieldValue.PROTOCOL 
                               src = nf_record.fieldValue.IPV4_SRC_ADDR
                               dst = nf_record.fieldValue.IPV4_DST_ADDR 
                               if_desc = nf_record.fieldValue.IF_DESC
                               version = nf_record.fieldValue.IP_PROTOCOL_VERSION
                               last_switched = nf_record.fieldValue.LAST_SWITCHED
                               first_switched = nf_record.fieldValue.FIRST_SWITCHED                               
                               
                               
                      
                        except Exception as e:
                               #print("Exception :" + str(e)) 
                               pass      

                packet_info = NetflowPacketInfo(
                        src,
                        dst,
                        sport,
                        dport,
                        proto,
                        time.time(),
                        pload_len,
                        hdr_len,
                        window,
			ruleno,if_desc,version,last_switched,first_switched)

                return packet_info

        @staticmethod
        def netflowGroupIdOf(NetflowPacketInfo):

                is_forward = True
                index = 0
                src_ip_octets = None
                dst_ip_octets = None
                try:
                	src_ip_octets = NetflowPacketInfo.src.split('.')
                	dst_ip_octets = NetflowPacketInfo.dst.split('.')
	         
                except:
                        return 
                
                proto = 0

                while index < len(src_ip_octets):
                        if int(src_ip_octets[index]) != int(dst_ip_octets[index]):
                                if int(src_ip_octets[index]) > int(dst_ip_octets[index]):
                                        is_forward = False
                                index = len(src_ip_octets)
                        index = index + 1
                try: 
                        proto = PROTOCOLS[NetflowPacketInfo.proto].lower()
                except:
                        proto = 17
                        pass

                if is_forward:
                        #return f'{packetInfo.src}:{packetInfo.sport}->{packetInfo.dst}:{packetInfo.dport}-{proto}'
                        return '%s:%s->%s:%s-%s' % (NetflowPacketInfo.src,NetflowPacketInfo.sport,NetflowPacketInfo.dst,NetflowPacketInfo.dport,proto)
                else:
                        #return f'{packetInfo.dst}:{packetInfo.dport}->{packetInfo.src}:{packetInfo.sport}-{proto}'
                        return '%s:%s->%s:%s-%s' % (NetflowPacketInfo.dst,NetflowPacketInfo.dport,NetflowPacketInfo.src,NetflowPacketInfo.sport,proto)

        @staticmethod
        def netflowRealIdOf(NetflowPacketInfo):

                is_forward = True
                index = 0
                src_ip_octets = None
                dst_ip_octets = None
                try:
                	src_ip_octets = NetflowPacketInfo.src.split('.')
                	dst_ip_octets = NetflowPacketInfo.dst.split('.')
	         
                except:
                        return 
  
                proto = 0

                while index < len(src_ip_octets):
                        if int(src_ip_octets[index]) != int(dst_ip_octets[index]):
                                if int(src_ip_octets[index]) > int(dst_ip_octets[index]):
                                        is_forward = False
                                index = len(src_ip_octets)
                        index = index + 1
                try: 
                        proto = PROTOCOLS[NetflowPacketInfo.proto].lower()
                except:
                        proto = 17
                        pass

                #proto = PROTOCOLS[packetInfo.proto].lower()
                dt_str = datetime.fromtimestamp(NetflowPacketInfo.timestamp).strftime('%Y%m%H%M%S%f')

                if is_forward:
                        #return f'{packetInfo.src}:{packetInfo.sport}->{packetInfo.dst}:{packetInfo.dport}-{proto}-{dt_str}'
                        return '%s:%s->%s:%s-%s-%s' % (NetflowPacketInfo.src,NetflowPacketInfo.sport,NetflowPacketInfo.dst,NetflowPacketInfo.dport,proto,dt_str)
                else:
                        #return f'{packetInfo.dst}:{packetInfo.dport}->{packetInfo.src}:{packetInfo.sport}-{proto}-{dt_str}'
                        return '%s:%s->%s:%s-%s-%s' % (NetflowPacketInfo.dst,NetflowPacketInfo.dport,NetflowPacketInfo.src,NetflowPacketInfo.sport,proto,dt_str)

