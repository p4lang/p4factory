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

import asyncio
import json
import socket
import threading
import websockets

from queue import Queue
from struct import *
from time import sleep

#===========================================
# Constants
#===========================================

MONITOR_IP = "192.168.1.100"
MONITOR_PORT = 54321

MAX_HOP_COUNT = 8 
MAX_INS_COUNT = 8 
MAX_MSG_SIZE = 12 + (MAX_HOP_COUNT * MAX_INS_COUNT * 4)

WEBSOCKET_HOST = "localhost"
WEBSOCKET_PORT = 8766

#===========================================
# Global variables
#===========================================

lock = threading.Lock()
viz_data_pkts = Queue()
switch_to_hop_lat = dict()

#===========================================
# Classes
#===========================================

class SnifferThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.monitor_sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        self.monitor_sock.bind(( MONITOR_IP, MONITOR_PORT ))
        self.buf = bytearray(MAX_MSG_SIZE)

    def run(self):
        while 1:
            nbytes, sender = self.monitor_sock.recvfrom_into(self.buf)
            handle_packet(self.buf)

#===========================================
# Helper functions 
#===========================================

def print_bytearray(arr, n):
    i = 0
    while(i < n):
        (a,b,c,d) = unpack("B B B B", arr[i:i+4])
        print("%02X %02X %02X %02X" % (a,b,c,d))
        i = i + 4

msg_id = 0

def handle_packet(pkt):
  global msg_id
  try:
    msg_id = msg_id + 1

    src_ip = socket.ntohl(unpack("I", pkt[0:4])[0])
    dst_ip = socket.ntohl(unpack("I", pkt[4:8])[0])
    src_port = socket.ntohs(unpack("H", pkt[8:10])[0])
    dst_port = socket.ntohs(unpack("H", pkt[10:12])[0])
    vni_and_proto = socket.ntohl(unpack("I", pkt[12:16])[0])
    (ins_cnt, max_cnt, tot_cnt) = unpack("B B B", pkt[17:20])

    viz_data = dict()
    ip_proto = vni_and_proto & 0x000000ff
    if (ip_proto == 6 or ip_proto == 17):
        viz_data["c"] = "%d:%d:%d:%d:%d" % (vni_and_proto, src_ip, dst_ip, src_port, dst_port) 
    else:
        viz_data["c"] = "%d:%d:%d" % (vni_and_proto, src_ip, dst_ip) 

    print_bytearray(pkt, 44)

    '''
    print("======================= Packet # %d" % msg_id)
    print("src_ip: %08X" % src_ip)
    print("dst_ip: %08X" % dst_ip)
    print("src_port: %04X" % src_port)
    print("dst_port: %04X" % dst_port)
    print("vni_and_proto: %08X" % vni_and_proto)
    #'''

    sw_hop_latencies = []
    idx = 20

    for i in range(tot_cnt):
        switch_id = socket.ntohl(unpack("I", pkt[idx:idx+4])[0])
        hop_lat = socket.ntohl(unpack("I", pkt[idx+4:idx+8])[0])
        q_occ = socket.ntohl(unpack("I", pkt[idx+8:idx+12])[0])

        #print("switch_id: %08X,  hop_lat: %08X,  q_occ: %08X" % (switch_id, hop_lat, q_occ))

        if i == tot_cnt - 1: q_occ = q_occ & 0x7FFF

        sw_hop_latencies.append([switch_id, hop_lat])
        idx = idx + 12

    viz_data["s"] = sw_hop_latencies
    viz_data_pkts.put(viz_data)
    
  except Exception as ex:
    print("[WARNING] Exception encountered:")
    print(ex)
    #raise ex

@asyncio.coroutine
def send_viz_data(websocket, path):
    while True:
        if not websocket.open: break

        p = viz_data_pkts.get()
        yield from websocket.send(json.dumps(p))

#===========================================
# Entry point
#===========================================

print("Starting websocket server at ws://%s:%d" % (WEBSOCKET_HOST, WEBSOCKET_PORT))

t = SnifferThread()
t.daemon = True
t.start()

start_server_pkt = websockets.serve(send_viz_data, WEBSOCKET_HOST, WEBSOCKET_PORT)
asyncio.get_event_loop().run_until_complete(start_server_pkt)

asyncio.get_event_loop().run_forever()
