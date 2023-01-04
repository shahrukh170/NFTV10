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
from mininet.link import TCLink
from mininet.term import makeTerms,makeTerm
from mininet.log import setLogLevel, info, error
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


def topology(args):
    "Create a network."
    net = Mininet_wifi(iot_module='fakelb') ##,accessPoint=UserAP, autoAssociation=False,ifb=True)
    os.system('sudo ifconfig br0 192.168.1.2 down')
    os.system('sudo ifconfig enp0s8 192.168.1.2 down')
    os.system('sudo ifconfig enp0s9 192.168.1.3 down') 
    os.system('sudo ifconfig enp0s8 192.168.0.2 up')
    os.system('sudo ifconfig enp0s9 192.168.0.3 up') 
    # try to get hw intf from the command line; by default, use eth1
    intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'enp0s8'
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
          os.popen('sudo ifconfig enp0s8 192.168.1.2  up')

    if  checkIntf( intfName3 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth2 192.168.2.3 down')
          os.popen('sudo ifconfig enp0s9 192.168.1.3 up')


     
    info("*** Creating nodes Gorup 1 sensors \n")
    ########## GROUP ONE SENSORS ########################
    # There is no need to set the node position.
    # Signal range and position won't work as we expect
    # because there is no wmediumd-like code for mac802154_hwim yet.
    # However, you may want to add mobility and node position
    # and use wpan-hwsim for some purposes.
    sta1 = net.addSensor('sta1', ip6='2001::1/64', voltage=3.7, panid='0xbeef', position='0,0,0')
    sta2 = net.addSensor('sta2', ip6='2001::2/64', voltage=3.7, panid='0xbeef', position='80,80,0')
    sta3 = net.addSensor('sta3', ip6='2001::3/64', voltage=3.7, panid='0xbeef', position='40,40,0')
    sta4 = net.addSensor('sta4', ip6='2001::4/64', voltage=3.7, panid='0xbeef', position='0,80,0')
    sta5 = net.addSensor('sta5', ip6='2001::5/64', voltage=3.7, panid='0xbeef', position='0,40,0')
    
    info("*** Creating nodes Gorup 2 sensors \n")
    ########## GROUP ONE SENSORS ########################
    # There is no need to set the node position.
    # Signal range and position won't work as we expect
    # because there is no wmediumd-like code for mac802154_hwim yet.
    # However, you may want to add mobility and node position
    # and use wpan-hwsim for some purposes.
    sta6 = net.addSensor('sta6', ip6='2001::6/64', voltage=3.7, panid='0xbeef', position='180,80,0')
    sta7 = net.addSensor('sta7', ip6='2001::7/64', voltage=3.7, panid='0xbeef', position='140,40,0')
    sta8 = net.addSensor('sta8', ip6='2001::8/64', voltage=3.7, panid='0xbeef', position='120,0,0')
    sta9 = net.addSensor('sta9', ip6='2001::9/64', voltage=3.7, panid='0xbeef', position='120,80,0')
    sta10 = net.addSensor('sta10', ip6='2001::10/64', voltage=3.7, panid='0xbeef', position='120,40,0')


    ###### CREATING SINK NODE TO CONNECT TWO GROUPS WITH SWTICH ##########
    sta11 = net.addSensor('sta11', ip6='2001::11/64', voltage=3.7, panid='0xbeef', position='100,40,0')

    
    ap1 = net.addAccessPoint('ap1',wlans=2,ssid='ssid-a', mode="g", channel="1", position='30,40,0')
    #ap2 = net.addAccessPoint('ap2',wlans=2,ssid='ssid-b', mode="g", channel="1", position='30,40,0')

    # Adding AP's/Switches 
    #ap1= net.addAccessPoint('ap1',wlans=2, ssid='ssid', position='10,10,0')
    # Adding three Switches 
    #ap1 = net.addSwitch('ap1',OVSSwitch)
    #host = net.addSwitch('h1',cls=LinuxRouter)
    info( '*** Adding controller\n' )
    c0 = net.addController('c0',  controller=RemoteController, port=5005,ip='127.0.0.1')

 
    ##c0 = net.addController('c0')

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()
    net.addLink(ap1,sta1,cls=TCLink,intf='enp0s8',ssid='adhocNet')
    net.addLink(ap1,sta2,cls=TCLink,intf='enp0s9',ssid='adhocNet')
    
    #if '-p' not in args:
    #net.plotGraph(max_x=100, max_y=100)

    info("*** Adding edges g1")
    # This is useful for routing
    # You may want to refer to https://github.com/linux-wpan/rpld
    # if you want to implement some custom routing
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 0 1')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 1 0')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 0 2')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 2 0')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 0 3')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 3 0')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 0 4')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 4 0')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 0 5')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 5 0')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 0 6')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 6 0')  

    info("*** Adding edges g2")
    # This is useful for routing
    # You may want to refer to https://github.com/linux-wpan/rpld
    # if you want to implement some custom routing
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 7 8')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 8 7')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 7 9')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 9 7')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 7 10')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 10 7')  
    os.system('./../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 7 11')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 11 7')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 7 12')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 12 7')

    info("*** Adding edges to SINK Node 13 g1 g2")
    # This is useful for routing
    # You may want to refer to https://github.com/linux-wpan/rpld
    # if you want to implement some custom routing
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 7 1')  
    os.system('../../../../wpan-tools/wpan-hwsim/wpan-hwsim edge add 6 7')  

    ##print(os.system('ifconfig -a'))

    info("*** Starting network\n")
    net.build()
    c0.start()
    ap1.start([c0])
    ##ap2.start([c0])
               
    # set_socket_ip: localhost must be replaced by ip address
    # of the network interface of your system
    # The same must be done with socket_client.py
    info("*** Starting Socket Server\n")
    #net.socketServer(ip='127.0.0.1', port=12345)

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
    
    #info( '*** Starting controllers\n')
    #for controller in net.controllers:
    #      controller.start()
    #info( '*** Starting switcstaes/APs\n')
    #net.get('ap1').start([c0])
    
    info( '*** Routing Table on Router:\n' )
    info( net[ 'ap1' ].cmd( 'route' ) )
    #info( net[ 'ap2' ].cmd( 'route' ) )
    #info( net[ 'sw3' ].cmd( 'route' ) )

    info(net['ap1'].cmd("ip route add 192.168.0.0/16  via 192.168.1.2  dev enp0s8"))
    info(net['ap1'].cmd("ip route add 172.16.0.0/16 via  192.168.1.2  dev enp0s8"))

    info(net['ap1'].cmd("ip route add 192.168.0.0/16 via 192.168.1.3 dev enp0s9"))
    info(net['ap1'].cmd("ip route add 172.16.0.0/16 via 192.168.1.4  dev enp0s9"))

    net.pingAll()
    config_rtr1_intf1= 'sudo ifconfig enp0s8 192.168.1.2 up'
    config_rtr1_intf2= 'sudo ifconfig enp0s9 192.168.1.3 up'
    net.get('ap1').cmd(config_rtr1_intf1)
    net.get('ap1').cmd(config_rtr1_intf2)
    command3 = 'sudo python3 run.py -i 192.168.1.2 -o 192.168.1.3 static -pl 1,2,3,4,5,6,7,8,9 -fl 1,2,3,4,5,6,7,8,9'
    #command3 = 'sudo python3 Packet-Filter/main.py -i 192.168.1.2 -o 192.168.1.3 -m 1  -l 1,2,3,4,5,6,7,8,9 -n 9'
    net.terms += makeTerm( net.get('ap1'), cmd="bash -c ' %s' ;bash " % command3)
    #net.socket_client()
    #net.pingAll()
    info( '*** Routing Table on Router:\n' )
    info( net[ 'ap1' ].cmd( 'route' ) )
    #info( net[ 'sw3' ].cmd( 'route' ) )
    #config_sta1_intf1= 'sudo ifconfig sta1-eth1 192.168.1.100 up'
    #config_sta2_intf2= 'sudo ifconfig sta2-eth1 192.168.1.200 up'
    #net.get('sta1').cmd(config_sta1_intf1)
    #net.get('sta2').cmd(config_sta2_intf2)
    
    #sta1.setIP('192.168.1.100/24', intf='sta1-pan0')
    #sta1.setIP('192.168.1.100/24', intf='sta1-mp1')
    #sta2.setIP('192.168.1.200/24', intf='sta2-pan0')
    #sta2.setIP('192.168.1.200/24', intf='sta2-mp1')
    
    #command4 = 'sudo python3 sender.py'
    #command5 = 'sudo python3 sniffer.py'
    #command4 = 'sudo ./Packet-Filter/NELphase-master/nel sender 192.168.1.100 172.16.1.1' ##127.0.0>
    #command5 = 'sudo ./Packet-Filter/NELphase-master/nel receiver 172.16.1.4 sta1-eth1' #>
    command4 = 'sudo ./NELphase-master/nel sender 192.168.1.100 172.16.1.1' ##127.0.0>
    command5 = 'sudo ./NELphase-master/nel receiver 172.16.1.4 sta1-eth1' #>
    time.sleep(6)
    net.terms += makeTerm( net.get('sta1'), cmd="bash -c ' %s' ;bash " % command5)
    time.sleep(6)
    net.terms += makeTerm( net.get('sta2'), cmd="bash -c ' %s' ;bash " % command4) 
    #net.terms += makeTerm( net.get('hh3'), cmd="bash -c ' %s' ;bash " % com>
    time.sleep(3) 
    #net.pingAll()



    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()
    os.system('sudo ifconfig br0 192.168.1.2 down')
    os.system('sudo ifconfig ap1-wlan1 192.168.1.2 down')
    os.system('sudo ifconfig ap1-wlan2 192.168.1.3 down') 
    os.system('sudo ifconfig enp0s8 192.168.1.2 down')
    os.system('sudo ifconfig enp0s9 192.168.1.3 down') 
    os.system('sudo ifconfig enp0s8 192.168.0.2 up')
    os.system('sudo ifconfig enp0s9 192.168.0.3 up') 

if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)
