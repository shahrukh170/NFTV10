
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
import time
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI


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
        # Adding 3 routers having diffrent subnets 
        rtr1 = self.addHost('rtr1', cls=LinuxRouter, ip='10.0.0.1/24')
        rtr2 = self.addHost('rtr2', cls=LinuxRouter, ip='10.1.0.3/24')
        rtr3 = self.addHost('rtr3', cls=LinuxRouter, ip='10.2.0.1/24')
        #r4 = self.addHost('r4', cls=LinuxRouter, ip='10.3.0.1/24')

        # Adding three Switches 
        sw1 = self.addSwitch('sw1', cls=OVSKernelSwitch)
        sw2 = self.addSwitch('sw2', cls=OVSKernelSwitch)
        sw3 = self.addSwitch('sw3', cls=OVSKernelSwitch)
        #sw4 = self.addSwitch('sw4')

        # Linking three host to swtich in the same subnet 
        self.addLink(sw1,
                     rtr1,
                     intfName2='eth1',
                     params2={'ip': '10.0.0.2/24'})

        self.addLink(sw2,
                     rtr2,
                     intfName2='eth2',
                     params2={'ip': '10.1.0.3/24'})
        self.addLink(sw3,
                     rtr3,
                     intfName2='eth0',
                     params2={'ip': '10.2.0.1/24'})
        #self.addLink(sw4,
        #              rtr4,
        #             intfName2='r4-eth1',
        #             params2={'ip': '10.3.0.1/24'})


        # Now we connect router-to-router connection for subnets
        self.addLink(rtr1,
                     rtr2,
                     intfName1='r1-eth2',
                     intfName2='r2-eth2',
                     params1={'ip': '10.10.0.1/24'},
                     params2={'ip': '10.10.0.2/24'})

        # Now we connect router-to-router connection for subnets
        self.addLink(rtr2,
                     rtr3,
                     intfName1='r2-eth3',
                     intfName2='r3-eth2',

                     params1={'ip': '10.100.0.3/24'},
                     params2={'ip': '10.100.0.4/24'})

        # Add router-router link in a new subnet for the router-router connection
        self.addLink(rtr3,
                     rtr1,
                     intfName1='r1-eth3',
                     intfName2='r3-eth3',
                     params1={'ip': '10.10.10.5/24'},
                     params2={'ip': '10.10.10.6/24'})


        # we add hosts to the network by specifying the default route 
        hh1 = self.addHost(name='hh1',
                          ip='10.0.0.251/24',
                          defaultRoute='via 10.0.0.2')
        hh2 = self.addHost(name='hh2',
                          ip='10.1.0.252/24',
                          defaultRoute='via 10.1.0.3')
        hh3 = self.addHost(name='hh3',
                          ip='10.2.0.100/24',
                          defaultRoute='via 10.2.0.1')
        #hh4 = self.addHost(name='hh4',
        #                  ip='10.3.0.254/24',
        #                  defaultRoute='via 10.3.0.1')
    

        # Add host-switch links
        self.addLink(sw1, hh1)
        self.addLink(sw2, hh2)
        self.addLink(sw3, hh3)
        #self.addLink(hh4, sw4)



def run():
    # try to get hw intf from the command line; by default, use eth1
    intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'eth1'
    info( '*** Connecting to hw intf: %s' % intfName )
    info( '*** Connecting to hw intf: %s' % intfName )
    intfName1 = 'br0'
    intfName2 = 'eth1'
    intfName3 = 'eth2'
    intfName4 = 'eth0'
    info( '*** Checking', intfName1, '\n' )
    if checkIntf( intfName1 ):
          os.popen('sudo ifconfig br0 down')
          os.popen('sudo brctl delbr br0')

    if  checkIntf( intfName2 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth1 192.168.1.2 down')
          os.popen('sudo ifconfig eth1 10.0.0.2 up')


    if  checkIntf( intfName3 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth2 192.168.2.3 down')
          os.popen('sudo ifconfig eth2 10.1.0.3 up')

    if  checkIntf( intfName4 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth0 10.0.2.15 down')
          os.popen('sudo ifconfig eth0 10.2.0.1 up')


    topo = MininetSchoolTopology()
    net = Mininet(topo=topo)

    # Here in this part of the code we Add routing for reaching networks  that are not 
    # in one to one or direct connection with one another 
    info(net['rtr1'].cmd("ip route add 10.1.0.0/24 via 10.10.0.2 dev r1-eth2"))
    info(net['rtr2'].cmd("ip route add 10.0.0.0/24 via 10.10.0.1 dev r2-eth2"))
       
    info(net['rtr2'].cmd("ip route add 10.2.0.0/24 via 10.100.0.4 dev r2-eth3"))
    info(net['rtr3'].cmd("ip route add 10.1.0.0/24 via 10.100.0.3 dev r3-eth2"))    
   
    info(net['rtr1'].cmd("ip route add 10.2.0.0/24 via 10.10.10.5 dev r3-eth3"))
    info(net['rtr3'].cmd("ip route add 10.0.0.0/24 via 10.10.10.6 dev r1-eth3"))    
    

    info( '*** Routing Table on Router:\n' )
    info( net[ 'rtr1' ].cmd( 'route' ) )
    info( net[ 'rtr2' ].cmd( 'route' ) )
    info( net[ 'rtr3' ].cmd( 'route' ) )
         
    #info(net['rtr1'].cmd("route add -net 10.2.0.0/24 gw 10.100.0.6"))
    ##info(net['rtr3'].cmd("route add -net 10.0.0.0/24 gw 10.100.0.5"))    
    
    #info(net['rtr3'].cmd("route add -net 10.2.0.0/24 gw 10.100.0.5"))    
    #info(net['rtr2'].cmd("route add -net 10.2.0.0/24 gw 10.100.0.6"))    

    net.start()
    #net.pingAll()
    switch1 = net.get('sw1')
    switch2 = net.get('sw2')
    switch3 = net.get('sw3')


    info( '*** Routing Table on Router:\n' )
    info( net[ 'rtr1' ].cmd( 'route' ) )
    info( net[ 'rtr2' ].cmd( 'route' ) )
    info( net[ 'rtr3' ].cmd( 'route' ) )
    #net.pingAll()
    command3 = 'sudo python3 run.py -i 10.0.0.2 -o 10.1.0.3 static -pl 1,2,3,4,5,6,7,8,9 -fl 1,2,3,4,5,6,7,8,9'
    net.terms += makeTerm( net.get('sw1'), cmd="bash -c ' %s' ;bash " % command3 )
    info( '*** Adding hardware interface', intfName2, 'to switch',switch1.name, '\n' )
    _intf1 = Intf('eth1' , node=net.get('sw1') )
    info( '*** Adding hardware interface', intfName3, 'to switch',switch2.name, '\n' )
    _intf2 = Intf( 'eth2', node=net.get('sw2') )
    info( '*** Adding hardware interface', intfName4, 'to switch',switch3.name, '\n' )
    _intf3 = Intf( 'br0', node=net.get('sw3') )

    net.pingAll()
    #command4 = 'sudo python3 sender.py'
    #command5 = 'sudo python3 sniffer.py'
    command4 = 'sudo ./NELphase-master/nel sender 10.0.0.251 127.0.0.1'  ## % (net.get('hh2').IP())
    command5 = 'sudo ./NELphase-master/nel receiver 10.1.0.252 lo' ## % (net.get('hh2').IP())
    time.sleep(5)
    net.terms += makeTerm( net.get('hh1'), cmd="bash -c ' %s' ;bash " % command5 )
    time.sleep(5)
    net.terms += makeTerm( net.get('hh2'), cmd="bash -c ' %s' ;bash " % command4 )
    #net.terms += makeTerm( net.get('hh3'), cmd="bash -c ' %s' ;bash " % command3 )
    net.pingAll()
    CLI(net)
    net.stop()
    os.popen('sudo ifconfig br0 down')
    os.popen('sudo brctl delbr br0')
    os.popen('sudo ifconfig eth1 10.0.0.1 down')
    os.popen('sudo ifconfig eth2 10.1.0.1 down')
    os.popen('sudo ifconfig eth0 10.2.0.1 down')
    os.popen('sudo ifconfig eth1 192.168.1.2 up')
    os.popen('sudo ifconfig eth2 192.168.2.3 up')
    os.popen('sudo ifconfig eth0 10.0.2.15 up')
if __name__ == '__main__':
    setLogLevel('info')
    run()
