#!/usr/bin/python

"""This example creates a simple network topology in which
   stations are equipped with batteries"""
from mn_wifi.link import wmediumd, adhoc
from mn_wifi.wmediumdConnector import interference
from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mininet.node import RemoteController, OVSSwitch
import os 
def topology():
    ##"Create a network."
    net = Mininet_wifi(iot_module='mac802154_hwsim') 
    #net = Mininet_wifi(iot_module='fakelb')
    # iot_module: fakelb or mac802154_hwsim
    # mac802154_hwsim is only supported from kernel 4.18

    info("*** Creating nodes\n")
    net.addSensor('sensor1', ip6='2001::1/64', voltage=3.7, panid='0xbeef')
    net.addSensor('sensor2', ip6='2001::2/64', voltage=3.7, panid='0xbeef')
    net.addSensor('sensor3', ip6='2001::3/64', voltage=3.7, panid='0xbeef')


    # Adding three Switches 
    #ap1= net.addAccessPoint('ap1',wlans=2, ssid='ssid1', position='10,10,0')
    #ap2 = net.addAccessPoint('ap2',wlans=2, ssid='ssid1', position='15,15,0')
  
    #net.addLink(sensor1, cls=adhoc, ssid='adhocNet') ##, **kwargs)
    
    #info( '*** Adding controller\n' )
    #c0 = net.addController('c0',  controller=RemoteController, port=5005,ip='127.0.0.1')
    #net.setModule('NELphase-master/mac80211_hwsim.ko')    
    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info("*** Starting network\n")
    net.build()
    
    info("*** Adding edges")
    # This is useful for routing
    # You may want to refer to https://github.com/linux-wpan/rpld
    # if you want to implement some custom routing
    os.system('wpan-hwsim edge add 0 1')  # sensor1 - sensor2
    os.system('wpan-hwsim edge add 1 0')  # sensor2 - sensor1
    os.system('wpan-hwsim edge add 0 2')  # sensor1 - sensor3
    os.system('wpan-hwsim edge add 2 0')  # sensor3 - sensor1

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
