import logging
logging.getLogger("kamene.runtime").setLevel(logging.ERROR)
from kamene.all import conf

conf.verb = 0
from functools import lru_cache
from timeit import repeat
import sys
import queue
import os
import time
from threading import Thread, Event
from subprocess import PIPE, Popen
from netfilterqueue import NetfilterQueue
import psutil
import pandas as pd
from core.cli import cliArgumentsToConfiguration
from core.stores import NetflowsStore,PacketflowsStore,RulesStore
from core.handlers import gatewayFilterPacketsHandler, staticFilterPacketsHandler

import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.pyplot import figure
from pylab import *
from matplotlib import style
style.use('ggplot')
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.pyplot import figure
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.figure import Figure
try:
   from tkinter import *
   import tkinter as tk
   import tkinter as ttk
except ImportError:
    import Tkinter as ttk
    import Tkinter as tk

if sys.version_info[0] < 3:
    import Tkinter as Tk
    import Tkinter as tk
else:
    import tkinter as Tk
    from tkinter import messagebox
    import tkinter as tk

class ShareItGraph(tk.Frame):
    def __init__(self):
        self.packet_in = 0
        self.data = []
        self.fig = plt.figure(figsize=(8, 6))

        # getting screen's height in pixels
        height = 500 ##controller.winfo_screenheight()

        # getting screen's width in pixels
        width = 900 ###controller.winfo_screenwidth()

        self.fig,self.ax = plt.subplots(nrows=2,ncols=3,figsize = (13,5.8), dpi=100)
        #self.fig = plt.figure(2,figsize=(10,10))

        #self.ax1 = plt.subplot(711)
        #self.ax[0,0].grid()
        self.ax[0,0].set_title("Total Packets Vs Time (sec)")
        self.ax[0,0].set_ylabel('Total Packets')
        self.ax[0,0].set_xlabel('Time (secs)')

        #self.ax2 = plt.subplot(712)
        #self.ax[0,1].grid()
        self.ax[0,1].set_title("Forward Pkts vs Time (secs)")
        self.ax[0,1].set_title("Forward Packets")
        self.ax[0,1].set_ylabel('Time (secs)')
        #self.ax3 = plt.subplot(713)
        #self.ax[0,2].grid()
        self.ax[0,2].set_title("Drop Packets vs Time ")
        self.ax[0,2].set_ylabel("Drop Packets")
        self.ax[0,2].set_xlabel('Time (secs)')

        #self.ax4 = plt.subplot(714)
        #self.ax[1,0].grid()
        self.ax[1,0].set_title("Normalise Packets vs Time")
        self.ax[1,0].set_ylabel("Normalise packets")
        self.ax[1,0].set_xlabel('Time (secs)')

        #self.ax5 = plt.subplot(725)
        #self.ax[1,1].grid()
        self.ax[1,1].set_title("RAM (MBytes) vs Time (secs)")
        self.ax[1,1].set_ylabel("RAM Usage (MBytes)")
        self.ax[1,1].set_xlabel('Time (secs)')

        #self.ax6 = plt.subplot(726)
        #self.ax[1,2].grid()
        self.ax[1,2].set_title("CPU (secs) vs Time (secs)")
        self.ax[1,2].set_ylabel("CPU Usage (secs)")
        self.ax[1,2].set_xlabel('Time (secs)')


        self.fig.subplots_adjust(hspace=0.5)
        self.fig.tight_layout()


class NetflowMeter(Thread):
        """This module contains code for:

                1. Packet capturing - Captures the flow from a network interface and extracts header from each packet passing 
                        through the monitoring interface. 
                2. Time stamping - Each packet header is marked with the timestamp when the header was captured.
                3. Sampling - The header is then processed by a sampling-filtering module, where it can be sampled.
                4. Filtering - The packets are then filtered according to specific requirements (e.g., a specific protocol or IP range).

        A thread is created. Inside the scope of the thread:
                1. A bridge is created.
                2. Everytime a packat goes through the bridge:
                        i. Its header is extracted.
                        ii. The is marked with the timestamp when the header was captured.
                        iii. The header is then processed by a sampling-filtering module, where it can be sampled
                        iv. The packets are then filtered according to specific requirements.
        """

        def __init__(self, input_q, handler):
                super(NetflowMeter, self).__init__(name="Flow-Meter", daemon=True)
                self.__input_q = input_q
                self.__handler = handler
                self.forwarded_packets =0
                self.normalized_packets = 0
                self.dropped_packets = 0
                self.total_in_packets = 0
                self.net_flow_packets = 0
                self.net_flow_records = 0
                self.normal_packets = 0
                self.this_process    = psutil.Process(os.getpid())
                self.cpu             = 1.0 ##  sum(self.this_process.cpu_times())
                self.avg_ram         = 120.0 ### (sum(self.this_process.memory_info()) / 1000000)
                self.startx          = 0.0
                self.uptime          = 0.0 
                ############ GRAPH FUNCTIONS #####################
                self.total_packets_g = []
                self.drop_packets_g = []
                self.forward_packets_g = []
                self.normalized_packets_g = []
                self.cpu_g = []
                self.ram_g = []
                self.uptime_g = []  
		

        def get_mem_usage(self):
                mem = (sum(self.this_process.memory_info()) / 1000000)
                self.avg_ram = (mem + self.avg_ram) / 2.0
                return mem

        def get_cpu_usage(self):
                return self.cpu if(self.cpu == 0.0) else (sum(self.this_process.cpu_times()) - self.cpu)

        def init_resource_usage(self):
                self.startx = int(time.time())
                self.cpu   = (sum(self.this_process.cpu_times()) - self.cpu)
                self.avg_ram   = (sum(self.this_process.memory_info()) / 1000000)
	
        #@lru_cache(5,128)
        def run(self):
                """Reads packets from the INPUT_Q and processes them one by one.
                """
                while True:
                        next_packet = self.__input_q.get()
                        self.__handler(next_packet,self)
                        self.total_in_packets += 1
                        #NetflowsStore.reportInExcel()
                        #PacketflowsStore.reportInExcel()
                        time.sleep(0.40)
                ShareIt = ShareItGraph()
                ShareIt.ax[0,0].plot(range(len(self.total_packets_g)),self.total_packets_g,'--g')
                ShareIt.ax[0,0].plot(range(len(self.total_packets_g)),self.total_packets_g,'--b')

                ShareIt.ax[0,1].plot(range(len(self.forward_packets_g)),self.forward_packets_g,'--s')
                ShareIt.ax[0,1].plot(range(len(self.forward_packets_g)),self.forward_packets_g,'--b')

                ShareIt.ax[0,2].plot(range(len(self.drop_packets_g)),self.drop_packets_g,'--p')
                ShareIt.ax[0,2].plot(range(len(self.drop_packets_g)),self.drop_packets_g,'--b')

                ShareIt.ax[1,0].plot(range(len(self.normalized_packets_g)),self.normalized_packets_g,'--k')
                ShareIt.ax[1,0].plot(range(len(self.normalized_packets_g)),self.normalized_packets_g,'--b')

                ShareIt.ax[1,1].plot(range(len(self.cpu_g)),self.cpu_g,'--o')
                ShareIt.ax[1,1].plot(range(len(self.cpu_g)),self.cpu_g,'--b')

                ShareIt.ax[1,2].plot(range(len(self.ram_g)),self.ram_g,'--o')
                ShareIt.ax[1,2].plot(range(len(self.ram_g)),self.ram_g,'--b')

                ShareIt.fig.savefig('./Statistics_WARDEN.png')
                        


class FlowbasedFilter:
        
        __INPUT_Q = queue.Queue()
        __CONF = {}
        __RESOURCES_MONITORING_WORKER = None
        __MEM_SERIES = []
        __START_TIME = None
        __INIT_CPU_TIME = None
        __THIS_PROCESS = None
        __IS_STARTED_EVENT = Event()


        @staticmethod
        def captureAll():
                nfqueue = NetfilterQueue()
                print("    ", end = "")
                print("src".ljust(20) + "dst".ljust(20) + "protocol".ljust(10) + "NetFlow(RuleNo)".ljust(10) + "action".ljust(15) + \
                              "memory(MBs)".ljust(15) + "cummulative cpu time(secs)")
                print("    ", end = "")
                print(('-'*116))

                try:
                        nfqueue.bind(1, FlowbasedFilter.onCapture)
                        nfqueue.run()
                except:
                        pass
                finally:
                        nfqueue.unbind()

        @staticmethod
        def onCapture(packet):
                """A callback method. Executed every time a packet is captured

                :param Packet packet a captured network packet 
                :return: None
                """
                #if not FlowbasedFilter.__IS_STARTED_EVENT.isSet():
                #        FlowbasedFilter.__THIS_PROCESS  = psutil.Process(os.getpid())
                #        FlowbasedFilter.__START_TIME    = time.time()
                #        FlowbasedFilter.__INIT_CPU_TIME = sum(FlowbasedFilter.__THIS_PROCESS.cpu_times())
                #        FlowbasedFilter.__IS_STARTED_EVENT.set()

                FlowbasedFilter.__INPUT_Q.put(packet)

        @staticmethod
        def scheduledResourcesUsageCheck():
                #FlowbasedFilter.__IS_STARTED_EVENT.wait()
                while True:
                        time.sleep(2)
                        FlowbasedFilter.checkMemoryUsage()

        @staticmethod
        def checkMemoryUsage():
                """Logs resource usage every second.
                """
                if FlowbasedFilter.__THIS_PROCESS:
                        FlowbasedFilter.__MEM_SERIES.append(sum(FlowbasedFilter.__THIS_PROCESS.memory_info()) / 1000000)

        @staticmethod
        def printResourcesUsageStats(netflow):

                mem_avg  = pd.np.average(FlowbasedFilter.__MEM_SERIES) if (len(FlowbasedFilter.__MEM_SERIES)) else 0.0
                cpu_time = (sum(FlowbasedFilter.__THIS_PROCESS.cpu_times()) - FlowbasedFilter.__INIT_CPU_TIME) if (
                        FlowbasedFilter.__THIS_PROCESS) else 0.0
                uptime   = (time.time() - FlowbasedFilter.__START_TIME) if (FlowbasedFilter.__START_TIME) else 0.0

                print('Average Memory Usage     : %s MBs' % (round(netflow.avg_ram*1000,4)))
                print('CPU Time                 : %s secs' % (round(cpu_time,2)))
                print('Uptime                   : %s secs' % (round(uptime,2)))
                print('Forward Flow Records     : %s ' % (netflow.forwarded_packets))
                print('Normalized Flow  Records : %s ' % (netflow.normalized_packets))
                print('Dropped Flow Records     : %s ' % (netflow.dropped_packets))
                print('Total Flow Records       : %s ' % (netflow.total_in_packets ))
                print('Total Flow Records       : %s ' % (netflow.total_in_packets ))
                print('Total Net Flow Packets   : %s ' % (netflow.net_flow_packets ))
                print('Total -Normal- Packets   : %s ' % (netflow.normal_packets ))
                print('Total Net Flow Records   : %s ' % (netflow.net_flow_records ))                
                
        @staticmethod
        def printResourcesUsageStatsxx(flowmeter):

                mem_avg  = pd.np.average(FlowbasedFilter.__MEM_SERIES) if (len(FlowbasedFilter.__MEM_SERIES)) else 0.0
                cpu_time = (sum(FlowbasedFilter.__THIS_PROCESS.cpu_times()) - FlowbasedFilter.__INIT_CPU_TIME) if (
                        FlowbasedFilter.__THIS_PROCESS) else 0.0
                self.utptime = uptime   = (time.time() - FlowbasedFilter.__START_TIME) if (FlowbasedFilter.__START_TIME) else 0.0

                print('\n')
                print('Flow Stream Statistics : \n')
                print('=======================================================\n')
                print('Forwarded Flow Records   : %s ' % (flowmeter.total_nb_of_forward_flow_records))
                print('Normalized Flow Records  : %s ' % (flowmeter.nb_of_covert_channel_net_flows))
                print('Dropped Flow Records     : %s ' % (flowmeter.total_nb_of_normalized_flow_records))
                print('\n')
                print('=======================================================\n')
                print('\n')
                print('Packet Stats : \n')
                print('=======================================================\n')
                print('Dropped Packets          : %s ' % (flowmeter.dropped_pkts))
                print('Normalized Packets       : %s ' % (flowmeter.normalised_pkts))
                print('Forwarded Packets        : %s ' % (flowmeter.forwarded_pkts))
                #print('Invalid Packets          : %s ' % (flowmeter.invalid_pkts))
                print('Total Packets            : %s ' % (flowmeter.all_pkts))
                #print('Total No. of Packets     : %s ' % (NetflowsStore.total_nb_of_packets))
                print('\n')
                print('=======================================================\n')
                print('Active Rules For CC     : %s ' % (flowmeter.active_rules_CC))
                print('=======================================================\n')
                print('\n')
                print('\n')
                print('System Statistics : \n')
                print('=======================================================\n')
                print('Average Memory Usage     : %s MBs' % (round(NetflowsStore.avg_ram*1000,4)))
                print('CPU Time                 : %s secs' % (round(cpu_time,2)))
                print('Uptime                   : %s secs' % (round(uptime,2)))
                
                print('No. of Active Flows      : %s ' % (NetflowsStore.nb_of_active_net_flows))
                print('No. of Exported Flows    : %s ' % (NetflowsStore.nb_of_exported_net_flows))
                print('No. of Covert Ch Flows   : %s ' % (NetflowsStore.nb_of_covert_channel_net_flows))
                print('Total No. of Flow Records: %s ' % (NetflowsStore.total_nb_of_packets))
                print('\n')
                print('\n')

        @staticmethod
        def initialize(args):
                """Parses CLI arguments and configures bridge. 
                """
                FlowbasedFilter.__START_TIME = time.time()
                conf = cliArgumentsToConfiguration(args)
                print(conf)
                FlowbasedFilter.__CONF.update(conf)
                FlowbasedFilter.configure()
                if FlowbasedFilter.__CONF['handler'] == staticFilterPacketsHandler : 
            	        RulesStore.initialize(FlowbasedFilter.__CONF['pbf_rule_numbers'], FlowbasedFilter.__CONF['fbf_rule_numbers'])
                else:
                        RulesStore.initialize([],[])


                FlowbasedFilter.__RESOURCES_MONITORING_WORKER = Thread(
                        target=FlowbasedFilter.scheduledResourcesUsageCheck,
                        name="Resources Monitoring Worker",
                        daemon=True)
                FlowbasedFilter.__RESOURCES_MONITORING_WORKER.start()
                print("\n[+]*** warden started ***[+]\n")

        @staticmethod
        def configure():
                """Sets up a bridge.
                """
                ingress_ip, egress_ip       = FlowbasedFilter.__CONF['ingress_ip'], FlowbasedFilter.__CONF['egress_ip']
                ingress_iface, egress_iface = FlowbasedFilter.__CONF['ingress_iface'], FlowbasedFilter.__CONF['egress_iface']
                bridge_ip           = ingress_ip  if(ingress_ip < egress_ip) else egress_ip

                start_cmds = [
                        [
                                'sudo brctl addbr br0',
                                'sudo brctl addif br0 %s %s' %(ingress_iface,egress_iface),
                                'sudo brctl stp br0 yes',
                                'sudo ifconfig %s 0.0.0.0' % (ingress_iface),
                                'sudo ifconfig %s 0.0.0.0' % (egress_iface),
                                'sudo ifconfig br0 %s up' % (bridge_ip),
                        ],[
                                'iptables -A INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' %(ingress_iface),
                                'iptables -A INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface),
                                'iptables -A FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (ingress_iface),
                                'iptables -A FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface)
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

                print('\n[*] configuring iptables.')
                for cmd in start_cmds[1]:
                        cmd = 'sudo %s' % (cmd)
                        p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
                        if len(p.stderr.read()) > 0:
                                print('    # %s [ fail ]' % (cmd.ljust(85)))
                        else:
                                print('    # %s [ success ]' % (cmd.ljust(85)))

                if FlowbasedFilter.__CONF['handler']  == 'gateway':
                        print('\n[*] Enter gatway mode 0.')
                elif FlowbasedFilter.__CONF['handler']  == 'static':
                        print('\n[*] Enter static mode 1.')
                
                
        @staticmethod
        def reconfigure():
                """Reconfigures the filter.
                """
                ingress_ip, egress_ip       =  FlowbasedFilter.__CONF['ingress_ip'], FlowbasedFilter.__CONF['egress_ip']
                ingress_iface, egress_iface =  FlowbasedFilter.__CONF['ingress_iface'], FlowbasedFilter.__CONF['egress_iface']
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
                                'iptables -D INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (ingress_iface),
                                'iptables -D INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface),
                                'iptables -D FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (ingress_iface),
                                'iptables -D FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface)
                        ]
                ]

                for cmd in exit_cmds[0]:
                        cmd = 'sudo %s' % (cmd)
                        p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
                        if len(p.stderr.read()) > 0:
                                print('    # %s [ fail ]' % (cmd.ljust(85)))
                        else:
                                print('    # %s [ success ]' % (cmd.ljust(85)))

                print('\n[*] restoring iptables.')
                for cmd in exit_cmds[1]:
                        cmd = 'sudo ' + cmd
                        p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
                        if len(p.stderr.read()) > 0:
                                print('    #  %s [ fail ]' % (cmd.ljust(85)))
                        else:
                                print('    # %s [ success ]' % (cmd.ljust(85)))



        @staticmethod
        def run(args):
                """
                This is the Filter's 'Main' function. Intialization, configuration and processing starts here.
                """

                FlowbasedFilter.initialize(args)

                try:
                        flow_meter = NetflowMeter(
                                FlowbasedFilter.__INPUT_Q, 
                                FlowbasedFilter.__CONF['handler'])
                        if not flow_meter.total_in_packets:
                                flow_meter.init_resource_usage()
                        flow_meter.start()
                        FlowbasedFilter.captureAll()
                        FlowbasedFilter.printResourcesUsageStats(flow_meter)
                        FlowbasedFilter.reconfigure()
                        NetflowsStore.reportInExcel()
                        PacketflowsStore.reportInExcel()

			
                except KeyboardInterrupt:
                        pass

