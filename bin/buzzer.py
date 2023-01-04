from pexpect import *
import pexpect
import time 
import sys
child = None
try:
	#child = pexpect.spawn('sudo mn --wifi --topo single,3 --controller remote,port=6633') ###sudo python adhoc15.py')
        child = pexpect.spawn('sudo python adhoc15.py')
        ##(command_output, exitstatus) = run ('sudo python adhoc15.py', withexitstatus=1)
        ##print(command_output, exitstatus)
except pexpect.TIMEOUT:
        pass 
##print(child.expect('mininet-wifi>'))
##print(child.expect('mininet-wifi>'))
while True:
        try:
	        p = child.expect('mininet-wifi>.*')
        except pexpect.TIMEOUT:
                print("Exception")
	        continue
print child.before
time.sleep(5)
command3 = "cat recv_log.txt| grep seconds|" + 'tr - " "' + "|head -13|awk '{print $1,$4}' > results.txt"
print(command3)
p = pexpect.spawn(command3)
print(p.expect(".*"))
#child.sendline("pingall")
#child.sendline("sta1 ping -c 5 sta2")
#time.sleep(4)
#print child.after
