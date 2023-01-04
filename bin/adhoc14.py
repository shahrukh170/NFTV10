#!/usr/bin/python
##
"""
Setting the position of Nodes (only for Stations and Access Points) and providing mobility.

"""
import pexpect
from mininet.term import makeTerms,makeTerm
from mininet.link import Intf,TCIntf,TCLink
import sys,re,os,time
from mininet.util import quietRun
import time
from mn_wifi.net import Mininet_wifi
from mininet.net import Mininet
from mininet.node import Controller, RemoteController,OVSSwitch,Node,OVSKernelSwitch
from mn_wifi.node import OVSKernelAP
from mininet.link import TCLink
from mn_wifi.cli import CLI
from mininet.log import setLogLevel
from mininet.log import setLogLevel, info
##
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

def topology(mobility):

    "Create a network."
    net = Mininet_wifi(build=False, controller=RemoteController, link=TCLink, accessPoint=OVSKernelAP,switch=OVSSwitch)

    print("*** Creating nodes")
    defaultIP = '172.16.1.2/24'  # IP address for r0-eth1
    router = net.addHost( 'r0',cls=LinuxRouter, mac='00:00:00:00:00:01', ip=defaultIP )

    # sta3 = net.addHost( 'sta3', mac='00:00:00:00:00:01', ip='10.0.0.1/8' )
    # h2 = net.addHost( 'h2', mac='00:00:00:00:00:11', ip='10.0.1.1/8' )

    sta1 = net.addStation( 'sta1', mac='00:00:00:00:00:02', ip='172.16.1.1/24', position='25,50,0',range='25')
    sta2 = net.addStation( 'sta2', mac='00:00:00:00:00:03', ip='172.16.1.4/24', position='80,50,0',range='25')
    #sta3 = net.addStation( 'sta3', mac='00:00:00:00:00:04', ip='10.0.0.4/8', position='20,50,0')

    ap1 = net.addAccessPoint( 'ap1', ssid= 'new-ssid', mode= 'g', channel= '5', position='40,50,0', range='50',cls=OVSKernelAP, failmode='standalone', stp=True)
    ap2 = net.addAccessPoint( 'ap2', ssid= 'new-ssid', mode= 'g', channel= '5', position='60,50,0', range='50',cls=OVSKernelAP, failmode='standalone', stp=True)

    c1 = net.addController( 'c1',ip='127.0.0.1',port=6633,protocol='tcp' )
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, failMode='standalone',stp=True)

    net.setPropagationModel(model="logDistance", exp=4.5)
    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()
    print("*** Associating and Creating links")
    ## Note : if you use cls=TCLink then its a wired connection
    net.addLink(ap1, router) ###,intfName1='r0-eth0',params1={ 'ip' : '172.16.1.2/24' })
    net.addLink(ap2, router)  ###,intfName1='r0-eth1',params1={ 'ip' : '172.16.1.3/24' })
    net.addLink(ap1, s3) ### ,cls=TCLink,loss=0,delay='0ms',bw=1)
    net.addLink(ap2, s3) ### ,cls=TCLink,loss=0,delay='0ms',bw=1)
    #net.addLink(s3,  router )

    #net.addLink(ap1, ap2)
    #net.addLink(ap2, sta2)
    info("*** Associating Routing Stations\n")
    ## Note : if you use cls=TCLink then its a wired connection
    net.addLink(ap1, sta1,cls=TCLink,loss=10.0,delay='10ms',bw=0.1)
    net.addLink(ap2, sta2,cls=TCLink,loss=10.0,delay='10ms',bw=0.1)

    """uncomment to plot graph"""
    info("*** Plotting Graph\n")
    net.plotGraph(max_x=120, max_y=120)
     
    if mobility:
        net.startMobility(time=1)
        net.mobility(sta1, 'start', time=11, position='25,50,0')
        net.mobility(sta1, 'stop', time=66, position='0,50,0')
        net.stopMobility(time=66)



    print("*** Starting network")
    net.build()
    c1.start()
    ap1.start( [c1] )
    ap2.start( [c1] )
    s3.start(  [c1] )
    
    info( '*** Routing Table on Router:\n' )
    info( net[ 'r0' ].cmd( 'route' ) )
    
    #info(net['r0'].cmd("ip route add 172.16.1.0/24 via 192.168.1.2 dev r0-eth0"))
    info(net['r0'].cmd("ip route add 192.168.1.0/24 via  172.16.1.2 dev r0-eth0"))

    #info(net['r0'].cmd("ip route add 172.16.1.0/24 via 172.16.1.3 dev r0-eth1"))
    info(net['r0'].cmd("ip route add 192.168.1.0/24 via  172.16.1.3 dev r0-eth1"))
    
    config_sw1= 'sudo ifconfig r0-eth0 172.16.1.2 up'
    config_sw2= 'sudo ifconfig r0-eth1 172.16.1.3 up'
    net.get('r0').cmd(config_sw1)
    net.get('r0').cmd(config_sw2)
    
    ##command3 = 'sudo python3 run.py -i 172.16.1.2 -o 172.16.1.3 static -pl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30 -fl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30'
    ##### 50 % Active rules #####
    ##command3 = 'sudo python3 run.py -i 172.16.1.2 -o 172.16.1.3 static -pl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47 -fl 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47'
    command3 = 'sudo python3 run.py -i 172.16.1.2 -o 172.16.1.3 gateway'
    ##command3 = 'sudo python3 run.py -i 172.16.1.2 -o 172.16.1.3 static -pl 1,2,3,4,5,6 -fl 1,2,3,4,5,6'
    net.terms += makeTerm( net.get('r0'), cmd="bash -c '%s' ;bash " % command3 )
    time.sleep(4)

    config_sta1_intf1= 'sudo ifconfig sta1-eth1 192.168.1.1 up'
    config_sta2_intf2= 'sudo ifconfig sta2-eth1 192.168.1.4 up'
    net.get('sta1').cmd(config_sta1_intf1)
    net.get('sta2').cmd(config_sta2_intf2)
    
    ##command4 = 'sudo ./Packet-Filter/NELphase-masterX/nel sender 172.16.1.1 192.168.1.1' ##127.0.0.1'  ## % (net.get('hh2').IP())
    ##command5 = 'sudo ./Packet-Filter/NELphase-masterX/nel receiver 172.16.1.4 sta1-eth1' ###192.168.1.200 lo' ## % (net.get('hh2').IP())
    command4 = 'sudo ./NELphase-master/nel sender 172.16.1.1 192.168.1.1' ##127.0.0.1'  ## % (net.get('hh2').IP())
    command5 = 'sudo ./NELphase-master/nel receiver 172.16.1.4 sta1-eth1' ###192.168.1.200 lo' ## % (net.get('hh2').IP())
    time.sleep(3)
    net.terms += makeTerm( net.get('sta1'), cmd="bash -c '%s';bash" % command5 )
    time.sleep(3)
    net.terms += makeTerm( net.get('sta2'), cmd="bash -c '%s';bash" % command4 )
    ##net.terms += makeTerm( net.get('sta2'), cmd="bash -c ' %s' ;bash " % command3 )
    net.pingAll()

    

    #net.startMobility(startTime=0)
    #net.mobility(sta1, 'start', time=1, position='0,50,0')
    #net.mobility(sta1, 'stop', time=30, position='100,50,0')
    #net.stopMobility(stopTime=31)

    print("*** Running CLI")
    CLI( net )

    print("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    mobility = False
    topology(mobility)
