#!/usr/bin/python

"""Before running this script please stop network-manager:
service network-manager stop

This example shows how to create multiple SSID at the same AP and ideas
around SSID-based packet forwarding

            --------
             ssid-4
            --------
               |
               |
  ------      (5)     -------
  ssid-1---(2)ap1(4)---ssid-3
  ------      (3)     -------
               |
               |
            --------
             ssid-2
            --------"""
import time
import re
from mininet.term import makeTerms,makeTerm
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink 
from mininet.util import quietRun
from mininet.node import CPULimitedHost, Host, Node,OVSKernelSwitch,OVSSwitch
import sys,os
from time import sleep
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mn_wifi.node import UserAP
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
"""This example creates a simple network topology with 3 nodes

       sensor1
      /       \
    /          \
sensor2      sensor3
"""

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')
        self.cmd('sysctl net.ipv6.ip_forward=1')  
    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        self.cmd('sysctl net.ipv6.ip_forward=0')
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


def topology(args):
    # try to get hw intf from the command line; by default, use eth1
    intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'ap1-wlan1'
    info( '*** Connecting to hw intf: %s' % intfName )
    info( '*** Connecting to hw intf: %s' % intfName )
    intfName1 = 'br0'
    intfName2 = 'ap1-wlan1'
    intfName3 = 'ap1-wlan2'
    intfName4 = 'enp0s3'
    info( '*** Checking', intfName1, '\n' )
    if checkIntf( intfName1 ):
          os.popen('sudo ifconfig br0 down')
          os.popen('sudo brctl delbr br0')

    if  checkIntf( intfName2 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth1 192.168.1.2 down')
          os.popen('sudo ifconfig ap1-wlan1 2001::2/64  up')

    if  checkIntf( intfName3 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth2 192.168.2.3 down')
          os.popen('sudo ifconfig  ap1-wlan1 2001::3/64 up')


    ########## "Create a network." ####################
    net = Mininet_wifi(iot_module='fakelb') ###accessPoint=UserAP, autoAssociation=False,ifb=True)

    info("*** Creating nodes\n")
    #sta1 = net.addStation('sta1', position='10,60,0')
    #sta2 = net.addStation('sta2', position='20,15,0')
    #sta3 = net.addStation('sta3', position='10,25,0')
    #sta4 = net.addStation('sta4', position='50,30,0')
    #sta5 = net.addStation('sta5', position='45,65,0')
    
    info("*** Creating nodes\n")
    # There is no need to set the node position.
    # Signal range and position won't work as we expect
    # because there is no wmediumd-like code for mac802154_hwim yet.
    # However, you may want to add mobility and node position
    # and use wpan-hwsim for some purposes.
    sta1 = net.addSensor('sta1',ip4='192.168.1.100', ip6='2001::1/64', voltage=3.7, panid='0xbeef')
    sta2 = net.addSensor('sta2',ip4='192.168.1.200', ip6='2001::4/64', voltage=3.7, panid='0xbeef')
    ##sta3 = net.addSensor('sta3', ip6='2001::105/64', voltage=3.7, panid='0xbeef')
    #sta4 = net.addSensor('sta4', ip6='2001::106/64', voltage=3.7, panid='0xbeef')
    #sta5 = net.addSensor('sta5', ip6='2001::107/64', voltage=3.7, panid='0xbeef')
    
    ap1 = net.addAccessPoint('ap1', vssids=['ssid1,ssid2,ssid3,ssid4'],
                             ssid='ssid', mode="g", channel="1", position='30,40,0')
    # Adding AP's/Switches 
    ##ap1= net.addAccessPoint('ap1',wlans=2, ssid='ssid', position='10,10,0')
    # Adding three Switches 
    ##ap1 = net.addSwitch('ap1',cls=OVSSwitch)
    #sw2 = net.addSwitch('sw2',cls=OVSSwitch)
    info( '*** Adding controller\n' )
    c0 = net.addController('c0',  controller=RemoteController, port=5005,ip='127.0.0.1')

 
    ##c0 = net.addController('c0')

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    net.addLink(ap1,sta1,cls=TCLink,intf='sta1-wpan0',ssid='adhocNet')
    net.addLink(ap1,sta2,cls=TCLink,intf='sta2-wpan0',ssid='adhocNet')
    #net.addLink(ap1,sta3,cls=TCLink,intf='sta3-wpan0',ssid='adhocNet')
    #if '-p' not in args:
    net.plotGraph(max_x=100, max_y=100)

    info("*** Adding edges")
    # This is useful for routing
    # You may want to refer to https://github.com/linux-wpan/rpld
    # if you want to implement some custom routing
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 0 1')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 1 0')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 0 2')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 2 0')  
    #os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 0 3')  
    #os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 3 0')  
    #os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 0 4')  
    #os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 4 0')  
    #os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 0 5')  
    #os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 5 0')  

    print(os.system('ifconfig -a'))

    info("*** Starting network\n")
    net.build()
    c0.start()
    ap1.start([c0])

    sleep(2)
    '''
    cmd = 'iw dev {} connect {} {}'
    intf = ap1.wintfs[0].vssid
    print(sta1.params['wpan'][0], intf[0], ap1.wintfs[1].mac)
    print(intf)
    sta1.cmd(cmd.format(sta1.params['wpan'][0], intf[0], ap1.wintfs[1].mac))
    sta2.cmd(cmd.format(sta2.params['wpan'][0], intf[1], ap1.wintfs[2].mac))
    sta3.cmd(cmd.format(sta3.params['wpan'][0], intf[1], ap1.wintfs[2].mac))
    sta4.cmd(cmd.format(sta4.params['wpan'][0], intf[2], ap1.wintfs[3].mac))
    sta5.cmd(cmd.format(sta5.params['wpan'][0], intf[3], ap1.wintfs[4].mac))

    ap1.cmd('dpctl unix:/tmp/ap1 meter-mod cmd=add,flags=1,meter=1 '
            'drop:rate=100')
    ap1.cmd('dpctl unix:/tmp/ap1 meter-mod cmd=add,flags=1,meter=2 '
            'drop:rate=200')
    ap1.cmd('dpctl unix:/tmp/ap1 meter-mod cmd=add,flags=1,meter=3 '
            'drop:rate=300')
    ap1.cmd('dpctl unix:/tmp/ap1 meter-mod cmd=add,flags=1,meter=4 '
            'drop:rate=400')
    ap1.cmd('dpctl unix:/tmp/ap1 flow-mod table=0,cmd=add in_port=2 '
            'meter:1 apply:output=flood')
    ap1.cmd('dpctl unix:/tmp/ap1 flow-mod table=0,cmd=add in_port=3 '
            'meter:2 apply:output=flood')
    ap1.cmd('dpctl unix:/tmp/ap1 flow-mod table=0,cmd=add in_port=4 '
            'meter:3 apply:output=flood')
    ap1.cmd('dpctl unix:/tmp/ap1 flow-mod table=0,cmd=add in_port=5 '
            'meter:4 apply:output=flood')
    '''
    info( '*** Sending sflow Topology\n')
    
    info( '*** Starting controllers\n')
    for controller in net.controllers:
          controller.start()
    info( '*** Starting switcstaes/APs\n')
    net.get('ap1').start([c0])
    
    info( '*** Routing Table on Router:\n' )
    info( net[ 'ap1' ].cmd( 'route' ) )
    #info( net[ 'ap2' ].cmd( 'route' ) )
    #info( net[ 'sw3' ].cmd( 'route' ) )

    info(net['ap1'].cmd("ip route add 2001::0/64  via 2001::2/64  dev  ap1-wlan1"))
    info(net['ap1'].cmd("ip route add 172.16.0.0/16 via  2001::2/64  dev  ap1-wlan1"))

    info(net['ap1'].cmd("ip route add 2001::0/64 via 2001::3/64 dev  ap1-wlan2"))
    info(net['ap1'].cmd("ip route add 172.16.0.0/16 via 2001::3/64 dev  ap1-wlan2"))

    ap1 = net.get('ap1')

    net.pingAll()
    config_rtr1_intf1= 'sudo ifconfig  ap1-wlan1 2001::2/64 up'
    config_rtr1_intf2= 'sudo ifconfig  ap1-wlan2 2001::3/64 up'
    net.get('ap1').cmd(config_rtr1_intf1)
    net.get('ap1').cmd(config_rtr1_intf2)
    command3 = 'sudo python3 run.py -i 2001::2/64 -o 2001::3/64 static -pl 1,2,3,4,5,6,7,8,9 -fl 1,2,3,4,5,6,7,8,9'
    net.terms += makeTerm( net.get('ap1'), cmd="bash -c ' %s' ;bash " % command3)
    net.pingAll()
    info( '*** Routing Table on Router:\n' )
    info( net[ 'ap1' ].cmd( 'route' ) )
    #info( net[ 'sw3' ].cmd( 'route' ) )
    #net.pingAll()
    #net.get('sta1').cmd('ifconfig enp0s8 add 2100::104/64')
    #net.get('sta1').cmd('ip -6 route add default via 2100::1')
    #net.get('sta1').cmd('ifconfig enp0s8')
 
    #command4 = 'sudo python3 sender.py'
    #command5 = 'sudo python3 sniffer.py'
    command4 = 'sudo ./NELphase-master/nel sender 2001::1 172.16.1.1' ##127.0.0>
    command5 = 'sudo ./NELphase-master/nel receiver 172.16.1.4 sta1-eth1' #>
    time.sleep(3)
    net.terms += makeTerm( net.get('sta1'), cmd="bash -c ' %s' ;bash " % command5)
    time.sleep(3)
    net.terms += makeTerm( net.get('sta2'), cmd="bash -c ' %s' ;bash " % command4) 
    #net.terms += makeTerm( net.get('hh3'), cmd="bash -c ' %s' ;bash " % com>
    net.pingAll()

    print(ap1.cmd('wpa_cli -iap1-wlan1 p2p_find'))
    print(ap1.cmd('wpa_cli -iap1-wlan2 p2p_find'))    
    print(ap1.cmd('wpa_cli -iap1-wlan2 p2p_peers'))



    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)
