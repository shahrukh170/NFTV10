
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
        rtr2 = self.addHost('rtr2', cls=LinuxRouter, ip='10.1.0.1/24')
        rtr3 = self.addHost('rtr3', cls=LinuxRouter, ip='10.2.0.1/24')
        #r4 = self.addHost('r4', cls=LinuxRouter, ip='10.3.0.1/24')

        # Adding three Switches 
        sw1 = self.addSwitch('sw1')
        sw2 = self.addSwitch('sw2')
        sw3 = self.addSwitch('sw3')
        #sw4 = self.addSwitch('sw4')

        # Linking three host to swtich in the same subnet 
        self.addLink(sw1,
                     rtr1,
                     intfName2='eth1',
                     params2={'ip': '10.0.0.1/24'})

        self.addLink(sw2,
                     rtr2,
                     intfName2='eth2',
                     params2={'ip': '10.1.0.1/24'})
        self.addLink(sw3,
                     rtr3,
                     intfName2='r3-eth0',
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
                          defaultRoute='via 10.0.0.1')
        hh2 = self.addHost(name='hh2',
                          ip='10.1.0.252/24',
                          defaultRoute='via 10.1.0.1')
        hh3 = self.addHost(name='hh3',
                          ip='10.2.0.102/24',
                          defaultRoute='via 10.2.0.1')
        #hh4 = self.addHost(name='hh4',
        #                  ip='10.3.0.254/24',
        #                  defaultRoute='via 10.3.0.1')
    

        # Add host-switch links
        self.addLink(sw1, hh1)
        self.addLink(sw2, hh2)
        self.addLink(sw3, hh3)
        #self.addLink(hh4, sw4)

def create_bridge(ingress_ip,egress_ip,ingress_iface,egress_iface,node,net):
    bridge_ip = ingress_ip if(ingress_ip < egress_ip) else egress_ip

    start_cmds = [
                        [
                                'brctl addbr br0',
                                'brctl addif br0 %s %s' % (ingress_iface,egress_iface),
                                'brctl stp br0 yes',
                                'ifconfig %s 0.0.0.0' % (ingress_iface),
                                'ifconfig %s 0.0.0.0' % (egress_iface),
                                'ifconfig br0 %s up' % (bridge_ip),
                        ],[
                                'iptables -A INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (ingress_iface),
                                'iptables -A INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface),
                                'iptables -A FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (ingress_iface),
                                'iptables -A FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface)
                        ]
                ]

    print('[*] creating a bridge.')

    for cmd in start_cmds[0]:
            cmd = 'sudo %s' % (cmd)
            node.cmd("%s" % cmd )
            
    print('\n[*] configuring iptables.')
    for cmd in start_cmds[1]:
            cmd = '%s' % (cmd)
            node.cmd("%s" % cmd )
    return bridge_ip

def destory_bridge(ingress_ip,egress_ip,ingress_iface,egress_iface,node,net):
    bridge_ip = ingress_ip if(ingress_ip < egress_ip) else egress_ip

    print("\n[*] restoring interface states.")
    exit_cmds = [
                        [
                                'brctl delif br0 %s %s ' %( ingress_iface,egress_iface),
                                'ifconfig br0 down',
                                'brctl delbr br0',
                                'ifconfig %s %s up' % (ingress_iface,ingress_ip),
                                'ifconfig %s %s up' % (egress_iface,egress_ip)
                        ],[
                                'iptables -D INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (ingress_iface),
                                'iptables -D INPUT -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface),
                                'iptables -D FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (ingress_iface),
                                'iptables -D FORWARD -m physdev --physdev-in %s -j NFQUEUE --queue-num 1' % (egress_iface)
                        ]
                ]

    for cmd in exit_cmds[0]:
            cmd = 'sudo %s' % (cmd)
            node.cmd("%s" % cmd )
            
    print('\n[*] restoring iptables.')
    for cmd in exit_cmds[1]:
            cmd = 'sudo ' + cmd
            node.cmd("%s" % cmd )
            
            

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
          os.popen('sudo ifconfig eth1 10.0.0.1 up')


    if  checkIntf( intfName3 ):
          print("Found .... ")
          #os.popen('sudo ifconfig eth2 192.168.2.3 down')
          os.popen('sudo ifconfig eth2 10.1.0.1 up')

    

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
    net.pingAll()
    info( '*** Routing Table on Router:\n' )
    info( net[ 'rtr1' ].cmd( 'route' ) )
    info( net[ 'rtr2' ].cmd( 'route' ) )
    info( net[ 'rtr3' ].cmd( 'route' ) )

    command3 = 'sudo python3 run.py -i 10.0.0.1 -o 10.1.0.1 static -pl 1,2,3,4,5,6,7,8,9 -fl 1,2,3,4,5,6,7,8,9'
    #net.terms += makeTerm( net.get('sw1'), cmd="bash -c ' %s' ;bash " % command3 )
    net.terms += makeTerm( net.get('rtr1'), cmd="bash -c ' %s' ;bash " % command3 )
    #net.terms += makeTerm( net.get('sw3'), cmd="bash -c ' %s' ;bash " % command3 )
    net.pingAll()
    # now we have two addresses and one interface , there fore inorder to send receive
    # communication between hh1 hh2 we will have to use bridge interface
    #
    # creating bridge on node hh1 and hh2 
    node1 = net.get('hh1')
    node2 = net.get('hh2')
    node3 = net.get('hh3')
    ingress_ip1 = node1.IP()
    ingress_ip2 = node2.IP()
    egress_ip = node3.IP()
    ingress_iface1 = "eth0"
    egress_iface1  = "hh1-eth0" 
    ingress_iface2 = "eth0"
    egress_iface2  = "hh2-eth0" 
    '''
    bridge_ip1 = create_bridge(ingress_ip1,egress_ip,ingress_iface1,egress_iface1,node1,net)
    print(" @@@@@@@@ CREATING BRIDGE IP HH1 : %s @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ " % str(bridge_ip1) )
    bridge_ip2 = create_bridge(ingress_ip2,egress_ip,ingress_iface2,egress_iface2,node2,net)
    print(" @@@@@@@@ CREATING BRIDGE IP HH2 : %s @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ " % str(bridge_ip2) )
    net.pingAll()
    node1.cmd('sudo ifconfig hh1-eth0 down')    
    node2.cmd('sudo ifconfig hh2-eth0 down')    
    node1.cmd('sudo ifconfig hh1-eth0 10.2.1.100 up')    
    node2.cmd('sudo ifconfig hh2-eth0 10.2.2.100 up')    
    net.pingAll()
    '''
    #command4 = 'sudo python3 sender.py'
    #command5 = 'sudo python3 sniffer.py'
    command4 = 'sudo ./NELphase-master/nel receiver %s hh2-eth0' % '127.0.0.1' ##(ingress_ip2)
    command5 = 'sudo ./NELphase-master/nel sender %s %s' % (ingress_ip1,'127.0.0.1')

    time.sleep(10)
    net.terms += makeTerm( net.get('hh1'), cmd="bash -c ' %s' ;bash " % command4 )
    time.sleep(10)
    net.terms += makeTerm( net.get('hh2'), cmd="bash -c ' %s' ;bash " % command5 )
    CLI(net)
    net.stop()
    '''
    bridge_ip1 = destory_bridge(ingress_ip1,egress_ip,ingress_iface1,egress_iface1,node1,net)
    print(" @@@@@@@@ DESTROYING BRIDGE IP HH1 : %s @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ " % str(bridge_ip1) )
    bridge_ip2 = destory_bridge(ingress_ip2,egress_ip,ingress_iface2,egress_iface2,node2,net)
    print(" @@@@@@@@ DESTROYING BRIDGE IP HH2 : %s @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ " % str(bridge_ip2) )
    node1.cmd('sudo ifconfig hh1-eth0 10.2.1.100 down')    
    node2.cmd('sudo ifconfig hh2-eth0 10.2.2.100 down')    
    '''
    
    os.popen('sudo ifconfig br0 down')
    os.popen('sudo brctl delbr br0')
    #os.popen('sudo ifconfig eth1 10.0.0.1 down')
    #os.popen('sudo ifconfig eth2 10.1.0.1 down')
    #os.popen('sudo ifconfig eth0 10.2.0.1 down')
    os.popen('sudo ifconfig eth1 192.168.1.2 up')
    os.popen('sudo ifconfig eth2 192.168.2.3 up')
    os.popen('sudo ifconfig eth0 10.0.2.15 up')
if __name__ == '__main__':
    setLogLevel('info')
    run()
