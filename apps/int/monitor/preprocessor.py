#!/usr/bin/python3
# Copyright 2015-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
import sys

from struct import *
from scapy.all import *

#===========================================
# Constants 
#===========================================

MONITOR_IP = '192.168.1.100'
MONITOR_PORT = 54321

VXLAN_HDR_SIZE_B = 8
INT_SHIM_HDR_SIZE_B = 4
INT_MD_HDR_SIZE_B = 8
INT_HDRS_TOT_SIZE_B = VXLAN_HDR_SIZE_B + INT_SHIM_HDR_SIZE_B + INT_MD_HDR_SIZE_B

ETH_HDR_SIZE_B = 14
IP_HDR_SIZE_B = 20

#===========================================
# Global variables 
#===========================================

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
monitor_addr = (MONITOR_IP, MONITOR_PORT)
sock.connect(monitor_addr)

#===========================================
# Helper functions 
#===========================================

def handle_packet(pkt, self_ip):
    try:
        r = pkt['Raw'].load
        vxh_1 = socket.ntohl(unpack("I", r[0:4])[0])
        if vxh_1 == 0x0C000005: # INT data is present
            (ins_cnt, max_cnt, tot_cnt) = unpack("B B B", r[13:16])
            num_md_bytes = tot_cnt * ins_cnt * 4 # Number of bytes of INT metadata values
            eth_hdr_offset = INT_HDRS_TOT_SIZE_B + num_md_bytes
            ip_hdr_offset = eth_hdr_offset + ETH_HDR_SIZE_B
            udp_hdr_offset = ip_hdr_offset + IP_HDR_SIZE_B

            if (pkt['IP'].dst == self_ip):
                d = bytearray()
                d.extend(r[ip_hdr_offset + 12 : ip_hdr_offset + 20])
                d.extend(r[udp_hdr_offset : udp_hdr_offset + 4])
                d.extend(r[4:7])
                d.extend(r[ip_hdr_offset + 9 : ip_hdr_offset + 10])
                d.extend(r[12:16])
                d.extend(r[20:20 + num_md_bytes])

                sock.sendall(d)
    except Exception as ex:
        print("[WARNGIN] Exception caught")
        print(ex)

# For debug purposes
def print_bytearray(arr, nbytes):
    i = 0
    while(i < nbytes):
        (a,b,c,d) = unpack("B B B B", arr[i:i+4])
        print("%02X %02X %02X %02X" % (a,b,c,d))
        i = i + 4

if __name__ == '__main__':
    print(len(sys.argv))
    if len(sys.argv) != 2:
        print("Incorrect number of arguments passed to the script")
        print("  Syntax: <script> <ip of eth0 interface in dotted quad notation>")
        exit(1)

    self_ip = sys.argv[1]

    print("Starting preprocessor")
    print("Filtering packets with destination ip '%s'" % self_ip)

    cmd = "dst " + self_ip + " and udp and port 4790 "
    sniff(
        filter = cmd,
        prn = lambda x: handle_packet(x, self_ip),
        store = 0	
    )
