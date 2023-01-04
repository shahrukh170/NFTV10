#!/usr/bin/python
from adhoc14 import *
import time 

if __name__ == '__main__':
    setLogLevel( 'info' )
    mobility = False
    for k in range(10):
        print("selecting iteration number : " + str(k))
        topology(mobility)
        time.sleep(2)
