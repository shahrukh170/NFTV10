#!/usr/bin/python2.7
import re
from mn_wifi.link import wmediumd, mesh
import sys
import os
##
from mn_wifi.wmediumdConnector import interference
from mn_wifi.cli import CLI
from mininet.log import setLogLevel, info, error
from mn_wifi.net import Mininet_wifi
from mininet.link import Intf,TCIntf,TCLink
from mininet.topolib import TreeTopo
from mininet.util import quietRun
from mininet.term import makeTerms,makeTerm
from mininet.link import TCLink, Intf
from mininet.log import setLogLevel, info
from mn_wifi.link import wmediumd, mesh
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference
from mininet.node import RemoteController, OVSSwitch
import time
from mininet.node import Node
from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from scapy.all import *
from scapy.layers import *


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

def run():
    # try to get hw intf from the command line; by default, use eth1
    intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'ap1-eth1'
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
          os.popen('sudo ifconfig ap1-eth1 192.168.1.2 up')


    if  checkIntf( intfName3 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth2 192.168.2.3 down')
          os.popen('sudo ifconfig ap2-eth1 192.168.1.3 up')
 
    #if  checkIntf( intfName4 ):
    #      print("Found .... ")
    #      #os.popen('sudo ifconfig eth0 10.0.2.15 down')
    #      os.popen('sudo ifconfig eth0 10.0.0.3 up')


    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference) 
     
                
    # we add hosts to the network by specifying the default route
    sta1 = net.addStation('sta1',ip='192.168.1.100',mac='00:00:00:00:00:14', position='10,10,0',defaultRoute='via 192.168.1.2')
    sta2 = net.addStation('sta2',ip='192.168.1.200',mac='00:00:00:00:00:15', position='20,20,0',defaultRoute='via 192.168.1.2')
    
    # Adding three Switches 
    ap1= net.addAccessPoint('ap1',wlans=2, ssid='ssid1', position='10,10,0')
    ap2 = net.addAccessPoint('ap2',wlans=2, ssid='ssid1', position='15,15,0')
    ap3 = net.addAccessPoint('ap3',wlans=2, ssid='ssid1', position='25,15,0',defaultIP='192.168.1.2')


    info( '*** Adding controller\n' )
    c0 = net.addController('c0',  controller=RemoteController, port=6633,ip='127.0.0.1')
    
    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    # Add host-switch links
    #net.addLink(ap1, ap3)
    #net.addLink(ap3, ap2)
    #net.addLink(ap3, ap1)
    net.addLink(sta1, ap1,cls=TCLink,loss=0.50,delay='100ms',bw=0.001)
    net.addLink(sta2, ap2,cls=TCLink,loss=0.50,delay='100ms',bw=0.001)

    info("*** Associating Stations\n")
    net.addLink(ap1,intf='ap1-wlan2', cls=mesh, ssid='mesh-ssid', channel=5)
    net.addLink(ap2,intf='ap2-wlan2', cls=mesh, ssid='mesh-ssid', channel=5)
    net.addLink(ap3,intf='ap3-wlan2', cls=mesh, ssid='mesh-ssid', channel=5)

    #net.addLink(ap3,ap1, cls=mesh, ssid='mesh-ssid', channel=5)
    #net.addLink(sta1, ap1,cls=TCLink,loss=0.50,delay='100ms',bw=0.001)
    #net.addLink(sta2, ap2,cls=TCLink,loss=0.50,delay='100ms',bw=0.001)






    ##switch=OVSSwitch,autoSetMacs=True )

    net.build() 
    c0.start()
    ap1.start([c0])
    ap2.start([c0])

    info( '*** Sending sflow Topology\n')
 
    info( '*** Starting controllers\n')
    for controller in net.controllers:
          controller.start()
    info( '*** Starting switcstaes/APs\n')
    net.get('ap1').start([c0])
    net.get('ap2').start([c0])


    info( '*** Routing Table on Router:\n' )
    info( net[ 'ap1' ].cmd( 'route' ) )
    info( net[ 'ap2' ].cmd( 'route' ) )
    #info( net[ 'sw3' ].cmd( 'route' ) )

    info(net['ap3'].cmd("ip route add 192.168.0.0/16 via 192.168.1.3 dev enp0s8"))
    info(net['ap3'].cmd("ip route add 172.16.0.0/16 via  192.168.1.3 dev enp0s8"))

    info(net['ap3'].cmd("ip route add 192.168.0.0/16 via 192.168.1.2 dev enp0s9"))
    info(net['ap3'].cmd("ip route add 172.16.0.0/16 via  192.168.1.2 dev enp0s9"))


    #info(net['sw1'].cmd("ip route add 192.168.2.0/16 via 192.168.1.2 dev eth2"))
    #info(net['sw2'].cmd("ip route add 192.168.1.0/16 via 192.168.2.3 dev eth2"))
     
    #info(net['sw1'].cmd("route add -net 192.168.1.0/24 gw 192.168.1.2 dev eth1"))
    #info(net['sw2'].cmd("route add -net 192.168.2.0/24 gw 192.168.2.3 dev eth2"))    
    
    #info(net['rtr3'].cmd("route add -net 10.2.0.0/24 gw 10.100.0.5"))    
    #info(net['rtr2'].cmd("route add -net 10.2.0.0/24 gw 10.100.0.6"))    

    
    switch1 = net.get('ap1')
    switch2 = net.get('ap2')
    #switch3 = net.get('sw3')

    
    #net.start()
    net.pingAll()
    config_rtr1_intf1= 'sudo ifconfig enp0s8 192.168.1.2 up'
    config_rtr1_intf2= 'sudo ifconfig enp0s9 192.168.1.3 up'
    net.get('ap3').cmd(config_rtr1_intf1)
    net.get('ap3').cmd(config_rtr1_intf2)
    command3 = 'sudo python3 run.py -i 192.168.1.2 -o 192.168.1.3 static -pl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30 -fl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30'
    net.terms += makeTerm( net.get('ap3'), cmd="bash -c ' %s' ;bash " % command3 )

    #net.terms += makeTerm( net.get('sw2'), cmd="bash -c ' %s' ;bash " % command3 )
    
    net.pingAll()
    
    info( '*** Adding hardware interface', intfName2, 'to switch',switch1.name, '\n' )
    _intf1 = Intf( intfName2, node=switch1 )
    info( '*** Adding hardware interface', intfName3, 'to switch',switch2.name, '\n' )
    _intf2 = Intf( intfName3, node=switch2 )
    #info( '*** Adding hardware interface', intfName4, 'to switch',switch3.name, '\n' )
    #_intf3 = Intf( intfName1, node=switch3 )

    info( '*** Routing Table on Router:\n' )
    info( net[ 'ap1' ].cmd( 'route' ) )
    info( net[ 'ap2' ].cmd( 'route' ) )
    #info( net[ 'sw3' ].cmd( 'route' ) )
    net.pingAll()
    
    #command4 = 'sudo python3 sender.py'
    #command5 = 'sudo python3 sniffer.py'
    command4 = 'sudo ./NELphase-master/nel sender  192.168.1.100 172.16.1.1' ##127.0.0.1'  ## % (net.get('hh2').IP())
    command5 = 'sudo ./NELphase-master/nel receiver  172.16.1.4 sta1-wlan0' ###192.168.1.200 lo' ## % (net.get('hh2').IP())
    time.sleep(3)
    net.terms += makeTerm( net.get('sta1'), cmd="bash -c ' %s' ;bash " % command5 )
    time.sleep(3)
    net.terms += makeTerm( net.get('sta2'), cmd="bash -c ' %s' ;bash " % command4 )
    #net.terms += makeTerm( net.get('hh3'), cmd="bash -c ' %s' ;bash " % command3 )
    net.pingAll()
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
