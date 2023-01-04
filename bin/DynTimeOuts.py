import time
import copy
#from netfilterqueue import PROTOCOLS
import pandas as pd


class LruPacketflow:
        
        def __init__(self,branches):
                self.branches = branches
                self.__ACTIVE_NET_FLOWS = branches
                self.__EXPORTED_FLOWS   = dict()

                # 2 mins - 120 secs
                self.__FLOW_TIMEOUT     = 120.0
                # 5 secs
                self.__ACTIVITY_TIMEOUT = 5.0
                
        
        def update(self,rule_fields,key):
        
                group_id = int(key)
                real_id  = int(key)
                rule_fields['fin'] = 0
                if  group_id in self.__ACTIVE_NET_FLOWS.keys():
                        net_flow = self.__ACTIVE_NET_FLOWS[group_id]
                        now = time.time()
                
                        if ((now - net_flow['frame.time']) > self.__FLOW_TIMEOUT) \
                                or ((now - net_flow['frame.time']) > self.__ACTIVITY_TIMEOUT) \
                                or  rule_fields.fin:

                                if ((now - net_flow['frame.time']) > self.__FLOW_TIMEOUT):
                                        self.export(group_id, 'Timed Out')
                                        self.__ACTIVE_NET_FLOWS.update({group_id : rule_fields})
                                elif ((now - net_flow_info['frame.time']) > self.__ACTIVITY_TIMEOUT):
                                        self.export(group_id, 'Stalled')
                                        self.__ACTIVE_NET_FLOWS.update({group_id : rule_fields})
                                elif rule_fields['fin']:
                                        self.__ACTIVE_NET_FLOWS.update({group_id : rule_fields})
                                        self.export(group_id, 'FINished')
                                else:
                                        pass
                        else:
                                self.__ACTIVE_NET_FLOWS[group_id].update(rule_fields)
                else:
                        self.__ACTIVE_NET_FLOWS[group_id] = rule_fields

                return self.branches      
        def export(self,group_id, status):
                """Moves a Flow state from ACTIVE state to EXPORTED state.
                """

                if group_id in self.__ACTIVE_NET_FLOWS.keys():
                        self.__ACTIVE_NET_FLOWS[group_id]= {'status': status }
                        self.__ACTIVE_NET_FLOWS[group_id]= {'id': group_id}
                        real_id = group_id
                        self.__EXPORTED_FLOWS[real_id] = self.__ACTIVE_NET_FLOWS[group_id]
                        if group_id in self.__ACTIVE_NET_FLOWS.keys():
                                self.__ACTIVE_NET_FLOWS.pop(group_id)
                        if group_id in self.branches.keys():
                                self.branches.pop(group_id)
                        
                
                
        def netflowExistsById(self,net_flow_id):
                """Check if a flow exists, by ID.

                :param str net_flow_id Net flow ID.
                :return: None
                """
                return net_flow_id in self.__ACTIVE_NET_FLOWS.keys()

        
        
