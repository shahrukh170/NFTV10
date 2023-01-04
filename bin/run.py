#!/usr/bin/env python3
import sys
sys.path.append('../src/')
from flowbasedfilter import FlowbasedFilter

if __name__ == '__main__':
	# ... run your application ...
	print(sys.getsizeof(FlowbasedFilter().run(sys.argv[1:])))
