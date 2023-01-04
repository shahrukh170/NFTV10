#!/usr/bin/env python3

"""
Netflow V5 collector and parser implementation in Python 3.
Created purely for fun. Not battled tested nor will it be.
This script is specifically implemented in combination with softflowd.
See https://github.com/djmdjm/softflowd
"""

import socket
import struct
import sys
import ipaddress


class DataFlow:
    """Holds one v5 DataRecord
    """
    def __init__(self, data):
        self.data = {}
        self.data['IPV4_SRC_ADDR'] = struct.unpack('!I', data[:4])[0]
        self.data['IPV4_DST_ADDR'] = struct.unpack('!I', data[4:8])[0]
        self.data['NEXT_HOP'] = struct.unpack('!I', data[8:12])[0]
        self.data['INPUT'] = struct.unpack('!H', data[12:14])[0]
        self.data['OUTPUT'] = struct.unpack('!H', data[14:16])[0]
        self.data['IN_PACKETS'] = struct.unpack('!I', data[16:20])[0]
        self.data['IN_OCTETS'] = struct.unpack('!I', data[20:24])[0]
        self.data['FIRST_SWITCHED'] = struct.unpack('!I', data[24:28])[0]
        self.data['LAST_SWITCHED'] = struct.unpack('!I', data[28:32])[0]
        self.data['SRC_PORT'] = struct.unpack('!H', data[32:34])[0]
        self.data['DST_PORT'] = struct.unpack('!H', data[34:36])[0]
        # Byte 36 is used for padding
        self.data['TCP_FLAGS'] = struct.unpack('!B', data[37:38])[0]
        self.data['PROTO'] = struct.unpack('!B', data[38:39])[0]
        self.data['TOS'] = struct.unpack('!B', data[39:40])[0]
        self.data['SRC_AS'] = struct.unpack('!H', data[40:42])[0]
        self.data['DST_AS'] = struct.unpack('!H', data[42:44])[0]
        self.data['SRC_MASK'] = struct.unpack('!B', data[44:45])[0]
        self.data['DST_MASK'] = struct.unpack('!B', data[45:46])[0]
        # Word 46 is used for padding

    def __repr__(self):
        return "<DataRecord with data {}>"\
            .format(self.data)


class Header:
    """The header of the ExportV5Packet.
    """
    def __init__(self, data):
        header = struct.unpack('!HHIIIIBBH', data[:24])
        self.version = header[0]
        self.count = header[1]
        self.uptime = header[2]
        self.timestamp = header[3]
        self.timestamp_nano = header[4]
        self.sequence = header[5]
        self.engine_type = header[6]
        self.engine_id = header[7]
        self.sampling_interval = header[8]


class ExportV5Packet:
    """The flow record holds the header and data flowsets.
    """
    def __init__(self, data):
        self.flows = []
        self.header = Header(data)

        offset = 24
        record_length = 48
        for flow_count in range(0, self.header.count):
            flow = DataFlow(data[offset:])
            self.flows.append(flow)
            offset += record_length

    def __repr__(self):
        return "<ExportV5Packet counting {} records>"\
            .format(self.header.count)
