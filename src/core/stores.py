import time
import copy
from netfilterqueue import PROTOCOLS
import pandas as pd
from core.types import packetInfo as PacketInfo , NetflowPacketInfo, Netflow,Packetflow, PacketBasedFilterRule

class NetflowsStore:
        """A class encapsulating a disctionaries of all active netflows and all exported net flows.
        """

        __ACTIVE_NET_FLOWS = dict()
        __EXPORTED_FLOWS   = dict()

        # 2 mins - 120 secs
        __FLOW_TIMEOUT     = 120.0
        # 5 secs
        __ACTIVITY_TIMEOUT = 5.0

        def __init__(self):
                self.net_flow = None

        @staticmethod
        def update(packet_info):
                """Updates the Store with new PacketInfo. If a net flow (for that PacketInfo) is found,
                the net flow is updated, else, a new Netflow is created and initialized.

                :param PacketInfo packet_info the data for a newly sniffed packet.
                :return: None
                """

                group_id = NetflowPacketInfo.netflowGroupIdOf(packet_info)
                real_id  = NetflowPacketInfo.netflowRealIdOf(packet_info)

                if  group_id in NetflowsStore.__ACTIVE_NET_FLOWS.keys():
                        net_flow_info = NetflowsStore.__ACTIVE_NET_FLOWS[group_id]
                        now = time.time()

                        if ((now - net_flow_info.start_time) > NetflowsStore.__FLOW_TIMEOUT) \
                                or ((now - net_flow_info.last_seen) > NetflowsStore.__ACTIVITY_TIMEOUT) : ##or packet_info.fin:

                                if ((now - net_flow_info.start_time) > NetflowsStore.__FLOW_TIMEOUT):
                                        NetflowsStore.export(group_id, 'Timed Out')
                                        NetflowsStore.__ACTIVE_NET_FLOWS.update({group_id: Netflow(real_id, group_id, packet_info)})
                                elif ((now - net_flow_info.last_seen) > NetflowsStore.__ACTIVITY_TIMEOUT):
                                        NetflowsStore.export(group_id, 'Stalled')
                                        NetflowsStore.__ACTIVE_NET_FLOWS.update({group_id: Netflow(real_id, group_id, packet_info)})
                                else :  ##if packet_info.fin:
                                        NetflowsStore.__ACTIVE_NET_FLOWS[group_id].update(packet_info)
                                        NetflowsStore.export(group_id, 'FINished')
                                #else:
                                #        pass
                        else:
                                NetflowsStore.__ACTIVE_NET_FLOWS[group_id].update(packet_info)
                else:
                        NetflowsStore.__ACTIVE_NET_FLOWS.update({group_id: Netflow(real_id, group_id, packet_info)})

        @staticmethod
        def export(group_id, status):
                """Moves a Net Flow from ACTIVE state to EXPORTED state.
                """

                if group_id in NetflowsStore.__ACTIVE_NET_FLOWS.keys():
                        NetflowsStore.__ACTIVE_NET_FLOWS[group_id].status = status
                        real_id = NetflowsStore.__ACTIVE_NET_FLOWS[group_id].id
                        NetflowsStore.__EXPORTED_FLOWS.update({real_id: NetflowsStore.__ACTIVE_NET_FLOWS.pop(group_id)})

        @staticmethod
        def netflowExistsById(net_flow_id):
                """Check if a Net flow exists, by ID.

                :param str net_flow_id Net flow ID.
                :return: None
                """
                return net_flow_id in NetflowsStore.__ACTIVE_NET_FLOWS.keys()

        @staticmethod
        def reportInExcel():
                """Print the current state of the Netflows dictionary
                """
                headers = [
                        "Group ID",
                        "ID",
                        "Src",
                        "Dst",
                        "Sport",
                        "Dport",
                        "Protocol",
                        "No of Pkts",
                        "Rule Nos",
                        "Total Payload len",
                        "Total Hdr len",
                        "Started At",
                        "Last seen",
                        "IF_DESC",
                        "IP VERSION",
                        "First Switched",
                        "Last Switched",
                        "Status"]

                xlsx_data = []
 
                if len(NetflowsStore.__ACTIVE_NET_FLOWS.items()) <= 0 :
                        return 

                for key, net_flow in NetflowsStore.__EXPORTED_FLOWS.items():
                        if net_flow or net_flow.proto is None:
                                net_flow.proto = 17
                                net_flow.if_desc = b"Covert.Channel"
                                net_flow.version = 4
                                net_flow.first_switched = 0.0
                                net_flow.last_switched = 0.0 
  
                        xlsx_data.append([
                                net_flow.group_id,
                                net_flow.id,
                                net_flow.src_ip_addr,
                                net_flow.dst_ip_addr,
                                net_flow.sport,
                                net_flow.dport,
                                PROTOCOLS[net_flow.proto].lower(),
				len(net_flow.packets),
                                net_flow.ruleno,
                                net_flow.payload_len,
                                net_flow.hdr_len,
                                net_flow.start_time,
                                net_flow.last_seen,
                                net_flow.if_desc.decode('UTF-8','ignore'),
                                net_flow.version,
                                net_flow.first_switched,
                                net_flow.last_switched,
                                net_flow.status])

                for key, net_flow in NetflowsStore.__ACTIVE_NET_FLOWS.items():
                        if net_flow or net_flow.proto is None:
                                net_flow.proto = 17
                                net_flow.if_desc = b"Covert.Channel"
                                net_flow.version = 4
                                net_flow.first_switched = 0.0
                                net_flow.last_switched = 0.0 
                        
                        xlsx_data.append([
                                net_flow.group_id,
                                net_flow.id,
                                net_flow.src_ip_addr,
                                net_flow.dst_ip_addr,
                                net_flow.sport,
                                net_flow.dport,
                                PROTOCOLS[net_flow.proto].lower(),
				len(net_flow.packets),
                                net_flow.ruleno,
                                net_flow.payload_len,
                                net_flow.hdr_len,
                                net_flow.start_time,
                                net_flow.last_seen,
                                net_flow.if_desc.decode('UTF-8','ignore'),
                                net_flow.version,
                                net_flow.first_switched,
                                net_flow.last_switched,
                                net_flow.status])

                #print(len(headers),len(xlsx_data),xlsx_data)
                #if len(xlsx_data) <= 0:
                #        return 
                pd.DataFrame(data=xlsx_data, columns=headers).to_excel(excel_writer='../output/Netflow_report.xlsx', index=False)

                total_nb_of_packets = 0
                for key, net_flow in NetflowsStore.__ACTIVE_NET_FLOWS.items():
                        total_nb_of_packets = total_nb_of_packets + len(net_flow.packets)

                for key, net_flow in NetflowsStore.__EXPORTED_FLOWS.items():
                        total_nb_of_packets = total_nb_of_packets + len(net_flow.packets)

                nb_of_active_net_flows = len(NetflowsStore.__ACTIVE_NET_FLOWS)
                nb_of_exported_net_flows = len(NetflowsStore.__EXPORTED_FLOWS)

                print('\n')
                print('Total No. of Packets     :  %s ' % (total_nb_of_packets))
                print('No. of Active Flows      :  %s ' % (nb_of_active_net_flows))
                print('No. of Exported Flows    :  %s ' % (nb_of_exported_net_flows))
                   

class PacketflowsStore:
        """A class encapsulating a disctionaries of all active netflows and all exported net flows.
        """

        __ACTIVE_NET_FLOWS = dict()
        __EXPORTED_FLOWS   = dict()

        # 2 mins - 120 secs
        __FLOW_TIMEOUT     = 120.0
        # 5 secs
        __ACTIVITY_TIMEOUT = 5.0

        def __init__(self):
                pass

        @staticmethod
        def update(packet_info):
                """Updates the Store with new PacketInfo. If a net flow (for that PacketInfo) is found,
                the net flow is updated, else, a new Netflow is created and initialized.

                :param PacketInfo packet_info the data for a newly sniffed packet.
                :return: None
                """

                group_id = PacketInfo.netflowGroupIdOf(packet_info)
                real_id  = PacketInfo.netflowRealIdOf(packet_info)

                if  group_id in PacketflowsStore.__ACTIVE_NET_FLOWS.keys():
                        net_flow_info = PacketflowsStore.__ACTIVE_NET_FLOWS[group_id]
                        now = time.time()

                        if ((now - net_flow_info.start_time) > PacketflowsStore.__FLOW_TIMEOUT) \
                                or ((now - net_flow_info.last_seen) > PacketflowsStore.__ACTIVITY_TIMEOUT) \
                                or packet_info.fin:

                                if ((now - net_flow_info.start_time) > PacketflowsStore.__FLOW_TIMEOUT):
                                        PacketflowsStore.export(group_id, 'Timed Out')
                                        PacketflowsStore.__ACTIVE_NET_FLOWS.update({group_id: Packetflow(real_id, group_id, packet_info)})
                                elif ((now - net_flow_info.last_seen) > PacketflowsStore.__ACTIVITY_TIMEOUT):
                                        PacketflowsStore.export(group_id, 'Stalled')
                                        PacketflowsStore.__ACTIVE_NET_FLOWS.update({group_id: Packetflow(real_id, group_id, packet_info)})
                                elif packet_info.fin:
                                        PacketflowsStore.__ACTIVE_NET_FLOWS[group_id].update(packet_info)
                                        PacketflowsStore.export(group_id, 'FINished')
                                else:
                                        pass
                        else:
                                PacketflowsStore.__ACTIVE_NET_FLOWS[group_id].update(packet_info)
                else:
                        PacketflowsStore.__ACTIVE_NET_FLOWS.update({group_id: Packetflow(real_id, group_id, packet_info)})

        @staticmethod
        def export(group_id, status):
                """Moves a Net Flow from ACTIVE state to EXPORTED state.
                """

                if group_id in PacketflowsStore.__ACTIVE_NET_FLOWS.keys():
                        PacketflowsStore.__ACTIVE_NET_FLOWS[group_id].status = status
                        real_id = PacketflowsStore.__ACTIVE_NET_FLOWS[group_id].id
                        PacketflowsStore.__EXPORTED_FLOWS.update({real_id: PacketflowsStore.__ACTIVE_NET_FLOWS.pop(group_id)})

        @staticmethod
        def netflowExistsById(net_flow_id):
                """Check if a Net flow exists, by ID.

                :param str net_flow_id Net flow ID.
                :return: None
                """
                return net_flow_id in PacketflowsStore.__ACTIVE_NET_FLOWS.keys()

        @staticmethod
        def reportInExcel():
                """Print the current state of the Netflows dictionary
                """
                headers = [
                        "Group ID",
                        "ID",
                        "Src",
                        "Dst",
                        "Sport",
                        "Dport",
                        "Protocol",
                        "No of Pkts",
                        "Rule Nos",
                        "Total Payload len",
                        "Total Hdr len",
                        "Started At",
                        "Last seen",
                        "TCP FINs",
                        "TCP SYNs",
                        "TCP RSTs",
                        "TCP ACKs",
                        "TCP ECEs",
                        "TCP CWRs",
                        "TCP URGs",
                        "TCP PSHs",
                        "Status"]

                xlsx_data = []
                if len(PacketflowsStore.__ACTIVE_NET_FLOWS.items()) <= 0 :
                        return  

                for key, net_flow in PacketflowsStore.__EXPORTED_FLOWS.items():
                        xlsx_data.append([
                                net_flow.group_id,
                                net_flow.id,
                                net_flow.src_ip_addr,
                                net_flow.dst_ip_addr,
                                net_flow.sport,
                                net_flow.dport,
                                net_flow.proto,
                                len(net_flow.packets),
                                net_flow.ruleno,
                                net_flow.payload_len,
                                net_flow.hdr_len,
                                net_flow.start_time,
                                net_flow.last_seen,
                                net_flow.fin_count,
                                net_flow.syn_count,
                                net_flow.rst_count,
                                net_flow.ack_count,
                                net_flow.ece_count,
                                net_flow.cwr_count,
                                net_flow.urg_count,
                                net_flow.psh_count,
                                net_flow.status])

                for key, net_flow in PacketflowsStore.__ACTIVE_NET_FLOWS.items():
                        xlsx_data.append([
                                net_flow.group_id,
                                net_flow.id,
                                net_flow.src_ip_addr,
                                net_flow.dst_ip_addr,
                                net_flow.sport,
                                net_flow.dport,
                                net_flow.proto,
                                len(net_flow.packets),
                                net_flow.ruleno,
                                net_flow.payload_len,
                                net_flow.hdr_len,
                                net_flow.start_time,
                                net_flow.last_seen,
                                net_flow.fin_count,
                                net_flow.syn_count,
                                net_flow.rst_count,
                                net_flow.ack_count,
                                net_flow.ece_count,
                                net_flow.cwr_count,
                                net_flow.urg_count,
                                net_flow.psh_count,
                                net_flow.status])

                pd.DataFrame(data=xlsx_data, columns=headers).to_excel(excel_writer='../output/Packetflow_report.xlsx', index=False)

                total_nb_of_packets = 0
                for key, net_flow in PacketflowsStore.__ACTIVE_NET_FLOWS.items():
                        total_nb_of_packets = total_nb_of_packets + len(net_flow.packets)

                for key, net_flow in PacketflowsStore.__EXPORTED_FLOWS.items():
                        total_nb_of_packets = total_nb_of_packets + len(net_flow.packets)

                nb_of_active_net_flows = len(PacketflowsStore.__ACTIVE_NET_FLOWS)
                nb_of_exported_net_flows = len(PacketflowsStore.__EXPORTED_FLOWS)

                print('\n')
                print('Total No. of Packets     :  %s ' % (total_nb_of_packets))
                print('No. of Active Flows      :  %s ' % (nb_of_active_net_flows))
                print('No. of Exported Flows    :  %s ' % (nb_of_exported_net_flows))


class RulesStore:
        """A container for storing and managing filter rules (both packet and floe based).
        """
        __PBF_RULE_NUMBERS = []
        __FBF_RULE_NUMBERS = []
        __PBF_RULES = []
        __FBF_RULES = []

        @staticmethod
        def initialize(pbf_rule_numbers, fbf_rule_numbers):
                """Set the initial set of:

                        1. Packet-based filter rule numbers.
                        2. Flow-based filter rule numbers.

                :param pbf_rule_numbers a list of Packet-based filter rule numbers.
                :param fbf_rule_numbers a list of Flow-based filter rule numbers.
                """
                RulesStore.__PBF_RULE_NUMBERS = copy.deepcopy(pbf_rule_numbers)
                RulesStore.__FBF_RULE_NUMBERS = copy.deepcopy(fbf_rule_numbers)
                RulesStore.__PBF_RULES = PacketBasedFilterRule.getPacketBasedFilterRulesFromNumbers(pbf_rule_numbers)
                RulesStore.__FBF_RULES = PacketBasedFilterRule.getPacketBasedFilterRulesFromNumbers(fbf_rule_numbers)
        @staticmethod
        def pbfRule_nos():
                """Creates and returns a deep copy of __PBF_RULES
                """
                return copy.deepcopy(RulesStore.__PBF_RULE_NUMBERS)

        @staticmethod
        def pbfRules():
                """Creates and returns a deep copy of __PBF_RULES
                """
                return copy.deepcopy(RulesStore.__PBF_RULES)

        @staticmethod
        def fbfRules():
                """Creates and returns a deep copy of __PBF_RULES
                """
                return copy.deepcopy(RulesStore.__PBF_RULES)

        @staticmethod
        def fbfRule_nos():
                """Creates and returns a deep copy of __PBF_RULES
                """
                return copy.deepcopy(RulesStore.__PBF_RULE_NUMBERS)

        @staticmethod
        def contents():
                """Returns a tuple of __PBF_RULE_NUMBERS, __FBF_RULE_NUMBERS, __PBF_RULES and __FBF_RULES.
                """
                return (
                        RulesStore.__PBF_RULE_NUMBERS, 
                        RulesStore.__FBF_RULE_NUMBERS, 
                        RulesStore.__PBF_RULES, 
                        RulesStore.__FBF_RULES)

