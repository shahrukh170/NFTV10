#!/usr/bin/python

"""
This example shows how to add an interface (for example a real
hardware interface) to a network after the network is created.
"""

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
import time 
#import netifaces 

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

if __name__ == '__main__':
    setLogLevel( 'info' )

    # try to get hw intf from the command line; by default, use eth1
    intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'eth1'
    info( '*** Connecting to hw intf: %s' % intfName )
    intfName1 = 'br0'
    intfName2 = 'eth1' 
    intfName3 = 'eth2'
    info( '*** Checking', intfName1, '\n' )
    if checkIntf( intfName1 ):
          os.popen('sudo ifconfig br0 down')
          os.popen('sudo brctl delbr br0')

    if  checkIntf( intfName2 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth1 192.168.1.2 down')
          os.popen('sudo ifconfig eth1 192.168.1.2 up')

          
    if  checkIntf( intfName3 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth2 192.168.2.3 down')
          os.popen('sudo ifconfig eth2 192.168.2.3 up')
    

    info( '*** Creating network\n' )
    net = Mininet( topo= TreeTopo( depth=1, fanout=2 ) )
    #h1 = net.addHost('h1',cls=Host,ip='192.168.1.100',defaultRoute='192.168.1.2')
    #h2 = net.addHost('h2',cls=Host,ip='192.168.2.200',defaultRoute='192.168.2.3')
    #switch = net.addSwitch('s1', cls=OVSKernelSwitch)
    #switch.cmd('sysctl -w net.ipv4.ip_forward=1')
    h1 = net.get('h1').setIP('192.168.1.100')
    h1 = net.get('h2').setIP('192.168.2.100')
    switch = net.switches[ 0 ]
    #info( '*** Adding hardware interface', intfName2, 'to switch',switch.name, '\n' )
    #_intf1 = Intf( intfName2, node=switch )
    
    
    

    info( '*** Note: you may need to reconfigure the interfaces for '
          'the Mininet hosts:\n', net.hosts, '\n' )

    
    #_intf2 = Intf( intfName3, node=switch )
    #net.addLink(h1, switch,cls=TCLink ,intf=TCIntf , params1={'delay':'50ms', 'bw' : 10})
    #net.addLink(h2, switch,cls=TCLink,  params1={'delay':'50ms', 'bw' : 10 })
    #self.addLink(h1,s1, intf=TCIntf,  params1={'delay':'50ms', 'bw' : 10, 'ip' : '192.168.1.2/24' })
    net.build()
    time.sleep(3)
    command3 = 'sudo python3 run.py -i 192.168.1.2 -o 192.168.2.3 static -pl 1,2,3,4,5,6,7,8,9 -fl 1,2,3,4,5,6,7,8,9'
    net.terms += makeTerm( switch, cmd="bash -c ' %s' ;bash " % command3 )
   
    net.pingAll()
    CLI( net )
    net.stop()
    os.popen('sudo ifconfig br0 down')
    os.popen('sudo brctl delbr br0')
    os.popen('sudo ifconfig eth1 192.168.1.2 up')
    os.popen('sudo ifconfig eth2 192.168.2.3 up') 
