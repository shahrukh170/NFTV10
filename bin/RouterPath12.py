#!/usr/bin/python
import re
import sys
import os

from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.net import Mininet
from mininet.link import Intf,TCIntf,TCLink
from mininet.topolib import TreeTopo
from mininet.util import quietRun
from mininet.term import makeTerms,makeTerm
from mininet.link import TCLink, Intf
from mininet.log import setLogLevel, info
from mininet.node import CPULimitedHost, Host, Node,OVSKernelSwitch
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch
import time
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from json import dumps
try:
  from urllib.request import build_opener, HTTPHandler, Request
except ImportError:
  from urllib2 import build_opener, HTTPHandler, Request
#import tracemalloc
from re import match
from fcntl import ioctl
from struct import pack, unpack
from sys import maxsize
import socket
from array import array
import sys
from os import listdir, environ
import pexpect

def getIfInfo(dst):
    is_64bits = maxsize > 2**32
    struct_size = 40 if is_64bits else 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_possible = 8 # initial value
    while True:
      bytes = max_possible * struct_size
      names = array('B')
      for i in range(0, bytes):
        names.append(0)
      outbytes = unpack('iL', ioctl(
        s.fileno(),
        0x8912,  # SIOCGIFCONF
        pack('iL', bytes, names.buffer_info()[0])
      ))[0]
      if outbytes == bytes:
        max_possible *= 2
      else:
        break
    s.connect((dst, 0))
    ip = s.getsockname()[0]
    for i in range(0, outbytes, struct_size):
      addr = socket.inet_ntoa(names[i+20:i+24])
      if addr == ip:
        name = names[i:i+16]
        try:
          name = name.tobytes().decode('utf-8')
        except AttributeError:
          name = name.tostring()
        name = name.split('\0', 1)[0]
        return (name,addr)

def configSFlow(net,collector,ifname,sampling,polling):
    info("*** Enabling sFlow:\n")
    sflow = 'ovs-vsctl -- --id=@sflow create sflow agent=%s target=%s sampling=%s polling=%s --' % (ifname,collector,sampling,polling)
    for s in net.switches:
      sflow += ' -- set bridge %s sflow=@sflow' % s
    info(' '.join([s.name for s in net.switches]) + "\n")
    quietRun(sflow)

def sendTopology(net,agent,collector):
    info("*** Sending topology\n")
    topo = {'nodes':{}, 'links':{}}
    for s in net.switches:
      topo['nodes'][s.name] = {'agent':agent, 'ports':{}}
    path = '/sys/devices/virtual/net/'
    for child in listdir(path):
      parts = match('(^.+)-(.+)', child)
      if parts == None: continue
      if parts.group(1) in topo['nodes']:
        ifindex = open(path+child+'/ifindex').read().split('\n',1)[0]
        topo['nodes'][parts.group(1)]['ports'][child] = {'ifindex': ifindex}
    i = 0
    for s1 in net.switches:
      j = 0
      for s2 in net.switches:
        if j > i:
          intfs = s1.connectionsTo(s2)
          for intf in intfs:
            s1ifIdx = topo['nodes'][s1.name]['ports'][intf[0].name]['ifindex']
            s2ifIdx = topo['nodes'][s2.name]['ports'][intf[1].name]['ifindex']
            linkName = '%s-%s' % (s1.name, s2.name)
            topo['links'][linkName] = {'node1': s1.name, 'port1': intf[0].name, 'node2': s2.name, 'port2': intf[1].name}
        j += 1
      i += 1

    opener = build_opener(HTTPHandler)
    request = Request('http://%s:8008/topology/json' % collector, data=dumps(topo).encode('utf-8'))
    request.add_header('Content-Type','application/json')
    request.get_method = lambda: 'PUT'
    url = opener.open(request)

def result(args):
    #res = fn(*args,**kwargs)
    net = args
    collector = environ.get('COLLECTOR','127.0.0.1')
    sampling = environ.get('SAMPLING','10')
    polling = environ.get('POLLING','10')
    (ifname, agent) = getIfInfo(collector)
    configSFlow(net,collector,ifname,sampling,polling)
    sendTopology(net,agent,collector)
    return net

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

def checkIntf( intf ):
    "Make sure intf exists and is not configured."

    config = quietRun( 'ifconfig %s 2>/dev/null' % intf, shell=True )

    if not config:
        error( 'Error:', intf, 'does not exist!\n' )
        #exit( 1 )
        return False

    ips = re.findall( r'\d+\.\d+\.\d+\.\d+', config )
    if ips:

        #error( 'Error:', intf, 'has an IP address,'
        #       'and is probably in use!\n' )
        os.popen( 'sudo ifconfig %s %s down' % (intf,ips))
        if not config:
                time.sleep(3)
                checkIntf(intf)
        else:
                 return True

    return True

class MininetSchoolTopology(Topo):
    def build(self, **_opts):
        defaultIP1 = '192.168.1.2/8'  # IP address for eth1
        defaultIP2 = '192.168.1.3/8'  # IP address for eth1  
               
        router1 = self.addNode( 'rtr1', cls=LinuxRouter, ip=defaultIP1 )
                        
        
        # Adding three Switches 
        sw1 = self.addSwitch('sw1', cls=OVSKernelSwitch)
        sw2 = self.addSwitch('sw2', cls=OVSKernelSwitch)
        #sw3 = self.addSwitch('sw3')
        #sw4 = self.addSwitch('sw4')
        self.addLink( sw1, router1, intfName2='enp0s8')
                      ##params2={ 'ip' : defaultIP1 } )  # for clarity
        self.addLink( sw2 , router1, intfName2='enp0s9')
                      ##params2={ 'ip' : defaultIP2 } )


                
        # we add hosts to the network by specifying the default route 
        hh1 = self.addHost(name='hh1',ip='192.168.1.100/8',defaultRoute='via 192.168.1.2')
        hh2 = self.addHost(name='hh2',ip='192.168.1.200/8',defaultRoute='via 192.168.1.3')
        # hh3 = self.addHost(name='hh3')
        #hh4 = self.addHost(name='hh4',
        #                  ip='10.3.0.254/24',
        #                  defaultRoute='via 10.3.0.1')
    

        # Add host-switch links
        self.addLink(sw1, sw2,cls=TCLink,loss=0.0,delay='10ms',bw=5) 
        self.addLink(sw1, hh1,cls=TCLink,loss=0.0,delay='0ms',bw=1)
        self.addLink(sw2, hh2,cls=TCLink,loss=0.0,delay='0ms',bw=1)
        

def run():
    # try to get hw intf from the command line; by default, use eth1
    intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'eth1'
    info( '*** Connecting to hw intf: %s' % intfName )
    info( '*** Connecting to hw intf: %s' % intfName )
    intfName1 = 'br0'
    intfName2 = 'enp0s8'
    intfName3 = 'enp0s9'
    intfName4 = 'enp0s3'
    info( '*** Checking', intfName1, '\n' )
    if checkIntf( intfName1 ):
          os.popen('sudo ifconfig br0 down')
          os.popen('sudo brctl delbr br0')

    if  checkIntf( intfName2 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth1 192.168.1.2 down')
          os.popen('sudo ifconfig enp0s8 192.168.1.2/8 up')


    if  checkIntf( intfName3 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth2 192.168.2.3 down')
          os.popen('sudo ifconfig enp0s9 192.168.1.3/8 up')

    #if  checkIntf( intfName4 ):
    #      print("Found .... ")
    #      #os.popen('sudo ifconfig eth0 10.0.2.15 down')
    #      os.popen('sudo ifconfig eth0 10.0.0.3 up')


    topo = MininetSchoolTopology()
    net = Mininet(topo=topo,controller=lambda name: RemoteController( name, ip='127.0.0.1',port=6633 ),
        switch=OVSSwitch,
        autoSetMacs=True )


    
    info( '*** Routing Table on Router:\n' )
    info( net[ 'sw1' ].cmd( 'route' ) )
    info( net[ 'sw2' ].cmd( 'route' ) )
    #info( net[ 'sw3' ].cmd( 'route' ) )

    info(net['rtr1'].cmd("ip route add 192.168.0.0/8 via 192.168.1.3 dev enp0s8"))
    info(net['rtr1'].cmd("ip route add 172.16.0.0/8 via  192.168.1.3 dev enp0s8"))

    info(net['rtr1'].cmd("ip route add 192.168.0.0/8 via 192.168.1.2 dev enp0s9"))
    info(net['rtr1'].cmd("ip route add 172.16.0.0/8 via  192.168.1.2 dev enp0s9"))


    #info(net['sw1'].cmd("ip route add 192.168.2.0/16 via 192.168.1.2 dev eth2"))
    #info(net['sw2'].cmd("ip route add 192.168.1.0/16 via 192.168.2.3 dev eth2"))
     
    #info(net['sw1'].cmd("route add -net 192.168.1.0/24 gw 192.168.1.2 dev eth1"))
    #info(net['sw2'].cmd("route add -net 192.168.2.0/24 gw 192.168.2.3 dev eth2"))    
    
    #info(net['rtr3'].cmd("route add -net 10.2.0.0/24 gw 10.100.0.5"))    
    #info(net['rtr2'].cmd("route add -net 10.2.0.0/24 gw 10.100.0.6"))    

    
    switch1 = net.get('sw1')
    switch2 = net.get('sw2')
    #switch3 = net.get('sw3')

    
    net.start()
    net.pingAll()
    config_rtr1_intf1= 'sudo ifconfig enp0s8 192.168.1.2/8 up'
    config_rtr1_intf2= 'sudo ifconfig enp0s9 192.168.1.3/8 up'
    net.get('rtr1').cmd(config_rtr1_intf1)
    net.get('rtr1').cmd(config_rtr1_intf2)
    ### 95% rules active 
    ### command3 = 'sudo python3 run.py -i 192.168.1.2 -o 192.168.1.3 static -pl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34.35,36,37,38,39,40,41,42,43 -fl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34.35,36,37,38,39,40,41,42,43'
    ### 20% rules active 
    ### command3 = 'sudo python3 run.py -i 192.168.1.2 -o 192.168.1.3 static -pl 1,2,3,4,5,6,7,8 -fl 1,2,3,4,5,6,7,8'
    ### 30% rules active 
    ### command3 = 'sudo python3 run.py -i 192.168.1.2 -o 192.168.1.3 static -pl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 -fl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15'
    ### 40% rules active 
    command3 = 'sudo python3 run.py -i 192.168.1.2 -o 192.168.1.3 static -pl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 -fl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15'
    ### static gateway mode 0 
    ### command3 = 'sudo python3 run.py -i 192.168.1.2 -o 192.168.1.3 gateway'
    net.terms += makeTerm( net.get('rtr1'), cmd="bash -c ' %s' ;bash " % command3 )

    #net.terms += makeTerm( net.get('sw2'), cmd="bash -c ' %s' ;bash " % command3 )
    
    net.pingAll()
    
    info( '*** Adding hardware interface', intfName2, 'to switch',switch1.name, '\n' )
    _intf1 = Intf( intfName2, node=switch1 )
    info( '*** Adding hardware interface', intfName3, 'to switch',switch2.name, '\n' )
    _intf2 = Intf( intfName3, node=switch2 )
    #info( '*** Adding hardware interface', intfName4, 'to switch',switch3.name, '\n' )
    #_intf3 = Intf( intfName1, node=switch3 )

    info( '*** Routing Table on Router:\n' )
    info( net[ 'rtr1' ].cmd( 'route' ) )
    info( net[ 'sw1' ].cmd( 'route' ) )
    #info( net[ 'sw3' ].cmd( 'route' ) )
    net.pingAll()
    
    #command4 = 'sudo python3 sender.py'
    #command5 = 'sudo python3 sniffer.py'
    command4 = 'sudo ./NELphase-master/nel sender  192.168.1.100 172.16.1.1' ##127.0.0.1'  ## % (net.get('hh2').IP())
    command5 = 'sudo ./NELphase-master/nel receiver  172.16.1.4 hh1-eth0' ###192.168.1.200 lo' ## % (net.get('hh2').IP())
    time.sleep(3)
    net.terms += makeTerm( net.get('hh1'), cmd="bash -c ' %s' ;bash " % command5 )
    time.sleep(3)
    net.terms += makeTerm( net.get('hh2'), cmd="bash -c ' %s' ;bash " % command4 )
    #net.terms += makeTerm( net.get('hh3'), cmd="bash -c ' %s' ;bash " % command3 )
    net = result(net)
    net.pingAll()
    time.sleep(2)
    CLI(net)
    net.stop()
    os.popen('sudo ifconfig br0 down')
    os.popen('sudo brctl delbr br0')
    #os.popen('sudo ifconfig eth1 10.0.0.1 down')
    #os.popen('sudo ifconfig eth2 10.0.0.4 down')
    os.popen('sudo ifconfig enp0s8 192.168.1.2 up')
    os.popen('sudo ifconfig enp0s9 192.168.2.3 up')
    os.popen('sudo ifconfig enp0s3 10.0.2.15 up')
if __name__ == '__main__':
    setLogLevel('info')
    run()
