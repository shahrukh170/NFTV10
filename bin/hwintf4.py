#!/usr/bin/env python

"""
linuxrouter.py: Example network with Linux IP router
This example converts a Node into a router using IP forwarding
already built into Linux.
The example topology creates a router and three IP subnets:
    - 192.168.1.0/24 (br0, IP: 192.168.1.2)
    - 172.16.1.0/24 (eth3, IP: 192.168.8.103)
    - 172.168.1.0/8 (r0-eth3, IP: 172.16.1.2)
    - 172.168.2.0/8 (r0-eth4, IP: 172.16.2.3)
Each subnet consists of a single host connected to
a single switch:
    br0     - s1-eth1 - h1-eth0 (IP: 192.168.1.1)
    br0     - s2-eth1 - h2-eth0 (IP: 192.168.1.4)
    r0-eth3 - s3-eth1 - h3-eth0 (IP: 172.168.1.100)
    r0-eth4 - s4-eth1 - h4-eth0 (IP: 172.168.2.100)
The example relies on default routing entries that are
automatically created for each router interface, as well
as 'defaultRoute' parameters for the host interfaces.
Additional routes may be added to the router or hosts by
executing 'ip route' or 'route' commands on the router or hosts.
"""
##
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
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."

    # pylint: disable=arguments-differ
    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()


class NetworkTopo( Topo ):
    "A LinuxRouter connecting three IP subnets"

    # pylint: disable=arguments-differ
    def build( self, **_opts ):

        defaultIP = '192.168.1.2/16'  # IP address for r0-eth1
        router = self.addNode( 'r0', cls=LinuxRouter, ip=defaultIP )

        s1, s2, s3 , s4 = [ self.addSwitch( s ) for s in ( 's1', 's2', 's3' , 's4' ) ]

        self.addLink( s1, router, intfName2='eth1',
                      params2={ 'ip' : defaultIP } )  # for clarity
        self.addLink( s2, router, intfName2='eth2',
                      params2={ 'ip' : '192.168.2.3/16' } )
        self.addLink( s3, router, intfName2='eth3',
                      params2={ 'ip' : '192.168.8.103/16' } )
        self.addLink( s4, router, intfName2='br0',
                      params2={ 'ip' : '172.16.1.2/16' } )

        h1 = self.addHost( 'h1', ip='192.168.1.1/16',
                           defaultRoute='via 192.168.1.2' )
        h2 = self.addHost( 'h2', ip='192.168.1.4/16',
                           defaultRoute='via 192.168.2.3' )
        h3 = self.addHost( 'h3', ip='172.16.1.1/8',
                           defaultRoute='via 192.168.8.103' )
        h4 = self.addHost( 'h4', ip='172.16.1.4/16',
                           defaultRoute='via 172.16.2.3' )
        
        for h, s in [ (h1, s1), (h1, s2), (h1, s3),(h1 , s4),(h2 , s1),(h2 , s2),( h2 ,s3), ( h2 , s4 ), ( h3 , s3 ), ( h4 , s4 ) ]:
            self.addLink( h, s )

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

def run():
    # try to get hw intf from the command line; by default, use eth1
    intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'eth1'
    info( '*** Connecting to hw intf: %s' % intfName )
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

    "Test linux router"
    topo = NetworkTopo()
    net = Mininet( topo=topo,waitConnected=True )  # controller is used by s1-s3
    net.start()
    info(net['r0'].cmd("ip route add 192.168.0.0/16 via 192.168.1.2 dev br0"))
    info(net['r0'].cmd("ip route add 192.168.0.0/16 via 192.168.1.2 dev eth1"))
    info(net['r0'].cmd("ip route add 192.168.0.0/16 via 192.168.2.3 dev eth2"))
    info(net['r0'].cmd("ip route add 172.16.0.0/16 via 192.168.8.103 dev eth3"))

    info( '*** Routing Table on Router:\n' )
    info( net[ 'r0' ].cmd( 'route' ) )
    net.pingAll()
    time.sleep(3)
    command3 = 'sudo python3 run.py -i 192.168.1.2 -o 192.168.2.3 static -pl 1,2,3,4,5,6,7,8,9 -fl 1,2,3,4,5,6,7,8,9'
    net.terms += makeTerm( net.get('r0'), cmd="bash -c ' %s' ;bash " % command3 )
    #command4 = 'sudo python3 sender.py'
    #command5 = 'sudo python3 sniffer.py'
    command4 = 'sudo ./NELphase-master/nel sender 172.16.1.1 192.168.1.1'
    command5 = 'sudo ./NELphase-master/nel receiver 192.168.1.4 h2-eth0'
    time.sleep(10)
    net.terms += makeTerm( net.get('h2'), cmd="bash -c ' %s' ;bash " % command5 )
    time.sleep(10)
    net.terms += makeTerm( net.get('h1'), cmd="bash -c ' %s' ;bash " % command4 )
    
   
    CLI( net )
    net.stop()
    os.popen('sudo ifconfig br0 down')
    os.popen('sudo brctl delbr br0')
    os.popen('sudo ifconfig eth1 192.168.1.2 up')
    os.popen('sudo ifconfig eth2 192.168.2.3 up')



if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
