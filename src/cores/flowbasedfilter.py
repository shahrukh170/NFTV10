import logging
logging.getLogger("kamene.runtime").setLevel(logging.ERROR)
#from kamene.all import conf
from scapy.all import *

conf.verb = 0

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
from core.stores import NetflowsStore, RulesStore

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

	def run(self):
		"""Reads packets from the INPUT_Q and processes them one by one.
		"""
		while True:
			next_packet = self.__input_q.get()
			self.__handler(next_packet)

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
		if not FlowbasedFilter.__IS_STARTED_EVENT.isSet():
			FlowbasedFilter.__THIS_PROCESS  = psutil.Process(os.getpid())
			FlowbasedFilter.__START_TIME    = time.time()
			FlowbasedFilter.__INIT_CPU_TIME = sum(FlowbasedFilter.__THIS_PROCESS.cpu_times())
			FlowbasedFilter.__IS_STARTED_EVENT.set()

		FlowbasedFilter.__INPUT_Q.put(packet)

	@staticmethod
	def scheduledResourcesUsageCheck():
		FlowbasedFilter.__IS_STARTED_EVENT.wait()
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
	def printResourcesUsageStats():

		mem_avg  = pd.np.average(FlowbasedFilter.__MEM_SERIES) if (len(FlowbasedFilter.__MEM_SERIES)) else 0.0
		cpu_time = (sum(FlowbasedFilter.__THIS_PROCESS.cpu_times()) - FlowbasedFilter.__INIT_CPU_TIME) if (
			FlowbasedFilter.__THIS_PROCESS) else 0.0
		uptime   = (time.time() - FlowbasedFilter.__START_TIME) if (FlowbasedFilter.__START_TIME) else 0.0

		print('Average Memory Usage     :   %s MBs' % str(mem_avg))
		print(f'CPU Time                 :  %s secs' % str(cpu_time))
		print(f'Uptime                   :  %s  secs' % str(uptime))

	@staticmethod
	def initialize(args):
		"""Parses CLI arguments and configures bridge. 
		"""
		FlowbasedFilter.__START_TIME = time.time()
		conf = cliArgumentsToConfiguration(args)
		FlowbasedFilter.__CONF.update(conf)
		FlowbasedFilter.configure()
		RulesStore.initialize(FlowbasedFilter.__CONF['pbf_rule_numbers'], [])

		FlowbasedFilter.__RESOURCES_MONITORING_WORKER = Thread(
			target=FlowbasedFilter.scheduledResourcesUsageCheck,
			name="Resources Monitoring Worker",
			daemon=True)
		FlowbasedFilter.__RESOURCES_MONITORING_WORKER.start()

	@staticmethod
	def configure():
		"""Sets up a bridge.
		"""
		ingress_ip, egress_ip       = FlowbasedFilter.__CONF['ingress_ip'], FlowbasedFilter.__CONF['egress_ip']
		ingress_iface, egress_iface = FlowbasedFilter.__CONF['ingress_iface'], FlowbasedFilter.__CONF['egress_iface']
		bridge_ip           = ingress_ip if(ingress_ip < egress_ip) else egress_ip

		start_cmds = [
			[
				'brctl addbr br0',
				f'brctl addif br0 {ingress_iface} {egress_iface}',
				'brctl stp br0 yes',
				f'ifconfig {ingress_iface} 0.0.0.0',
				f'ifconfig {egress_iface} 0.0.0.0',
				f'ifconfig br0 {bridge_ip} up',
			],[
				f'iptables -A INPUT -m physdev --physdev-in {ingress_iface} -j NFQUEUE --queue-num 1',
				f'iptables -A INPUT -m physdev --physdev-in {egress_iface} -j NFQUEUE --queue-num 1',
				f'iptables -A FORWARD -m physdev --physdev-in {ingress_iface} -j NFQUEUE --queue-num 1',
				f'iptables -A FORWARD -m physdev --physdev-in {egress_iface} -j NFQUEUE --queue-num 1'
			]
		]

		print('[*] creating a bridge.')

		for cmd in start_cmds[0]:
			cmd = f'sudo {cmd}'
			p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
			if len(p.stderr.read()) > 0:
				print(f'    # {cmd.ljust(85)} [ fail ]')
			else:
				print(f'    # {cmd.ljust(85)} [ success ]')

		print('\n[*] configuring iptables.')
		for cmd in start_cmds[1]:
			cmd = f'sudo {cmd}'
			p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
			if len(p.stderr.read()) > 0:
				print(f'    # {cmd.ljust(85)} [ fail ]')
			else:
				print(f'    # {cmd.ljust(85)} [ success ]')

	@staticmethod
	def reconfigure():
		"""Reconfigures the filter.
		"""
		ingress_ip, egress_ip       = FlowbasedFilter.__CONF['ingress_ip'], FlowbasedFilter.__CONF['egress_ip']
		ingress_iface, egress_iface = FlowbasedFilter.__CONF['ingress_iface'], FlowbasedFilter.__CONF['egress_iface']
		bridge_ip           = ingress_ip if(ingress_ip < egress_ip) else egress_ip

		print("\n[*] restoring interface states.")
		exit_cmds = [
			[
				f'brctl delif br0 {ingress_iface} {egress_iface}',
				'ifconfig br0 down',
				'brctl delbr br0',
				f'ifconfig {ingress_iface} {ingress_ip} up',
				f'ifconfig {egress_iface} {egress_ip} up'
			],[
				f'iptables -D INPUT -m physdev --physdev-in {ingress_iface} -j NFQUEUE --queue-num 1',
				f'iptables -D INPUT -m physdev --physdev-in {egress_iface} -j NFQUEUE --queue-num 1',
				f'iptables -D FORWARD -m physdev --physdev-in {ingress_iface} -j NFQUEUE --queue-num 1',
				f'iptables -D FORWARD -m physdev --physdev-in {egress_iface} -j NFQUEUE --queue-num 1'
			]
		]

		for cmd in exit_cmds[0]:
			cmd = f'sudo {cmd}'
			p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
			if len(p.stderr.read()) > 0:
				print(f'    # {cmd.ljust(85)} [ fail ]')
			else:
				print(f'    # {cmd.ljust(85)} [ success ]')

		print('\n[*] restoring iptables.')
		for cmd in exit_cmds[1]:
			cmd = 'sudo ' + cmd
			p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
			if len(p.stderr.read()) > 0:
				print(f'    # {cmd.ljust(85)} [ fail ]')
			else:
				print(f'    # {cmd.ljust(85)} [ success ]')

	@staticmethod
	def run():
		"""
		This is the Filter's 'Main' function. Intialization, configuration and processing starts here.
		"""

		FlowbasedFilter.initialize()

		try:
			flow_meter = NetflowMeter(
				FlowbasedFilter.__INPUT_Q, 
				FlowbasedFilter.__CONF['handler'])

			flow_meter.start()

			FlowbasedFilter.captureAll()
			FlowbasedFilter.reconfigure()
			NetflowsStore.reportInExcel()
			FlowbasedFilter.printResourcesUsageStats()

		except KeyboardInterrupt:
			pass
