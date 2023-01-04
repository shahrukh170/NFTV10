
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
        defaultIP1 = '192.168.1.2/16'  # IP address for eth1
        defaultIP2 = '192.168.1.3/16'  # IP address for eth1  
               
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
        hh1 = self.addHost(name='hh1',ip='192.168.1.100/16',defaultRoute='via 192.168.1.2')
        hh2 = self.addHost(name='hh2',ip='192.168.1.200/16',defaultRoute='via 192.168.1.3')
        # hh3 = self.addHost(name='hh3')
        #hh4 = self.addHost(name='hh4',
        #                  ip='10.3.0.254/24',
        #                  defaultRoute='via 10.3.0.1')
    

        # Add host-switch links
        self.addLink(sw1, hh1,cls=TCLink,loss=0.0,delay='0ms',bw=5)
        self.addLink(sw2, hh2,cls=TCLink,loss=0.0,delay='0ms',bw=5)
        

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
          os.popen('sudo ifconfig enp0s8 192.168.1.2 up')


    if  checkIntf( intfName3 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth2 192.168.2.3 down')
          os.popen('sudo ifconfig enp0s9 192.168.1.3 up')

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

    info(net['rtr1'].cmd("ip route add 192.168.0.0/16 via 192.168.1.3 dev enp0s8"))
    info(net['rtr1'].cmd("ip route add 172.16.0.0/16 via  192.168.1.3 dev enp0s8"))

    info(net['rtr1'].cmd("ip route add 192.168.0.0/16 via 192.168.1.2 dev enp0s9"))
    info(net['rtr1'].cmd("ip route add 172.16.0.0/16 via  192.168.1.2 dev enp0s9"))


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
    config_rtr1_intf1= 'sudo ifconfig enp0s8 192.168.1.2 up'
    config_rtr1_intf2= 'sudo ifconfig enp0s9 192.168.1.3 up'
    net.get('rtr1').cmd(config_rtr1_intf1)
    net.get('rtr1').cmd(config_rtr1_intf2)
    ##command3 = 'sudo python3 run.py -i 192.168.1.2 -o 192.168.1.3 static -pl 1,2,3,4,5,6,7,8,9 -fl 1,2,3,4,5,6,7,8,9'
    command3 = 'sudo python3 run.py -i 192.168.1.2 -o 192.168.1.3 gateway'
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
