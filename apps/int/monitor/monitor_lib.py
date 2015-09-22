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

import json
import pdb
import socket
import sys
import threading
import time

from queue import Queue
from struct import *

#===========================================
# Constants
#===========================================

MONITOR_IP = "192.168.1.100"
MONITOR_PORT = 54321

CLIENT_MSG_IP = "localhost"
CLIENT_MSG_PORT = 54322

MAX_HOP_COUNT = 8 
MAX_INS_COUNT = 8 
MAX_MSG_SIZE = 12 + (MAX_HOP_COUNT * MAX_INS_COUNT * 4)

#===========================================
# Class PpDataReceiverThread
#===========================================

class PpDataReceiverThread(threading.Thread):
    def __init__(self, app_state):
        threading.Thread.__init__(self)
        self.app_state = app_state
        self.monitor_sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        self.monitor_sock.bind(( MONITOR_IP, MONITOR_PORT ))
        self.buf = bytearray(MAX_MSG_SIZE)
        print("PpDataReceiverThread created")

    def run(self):
        while 1:
            nbytes, sender = self.monitor_sock.recvfrom_into(self.buf)
            self.handle_packet(self.buf)

    def handle_packet(self, pkt):
      try:
        self.app_state.client_connected_lock.acquire()

        if self.app_state.client_connected:
          ppd = PpData( pkt )
          self.app_state.pp_data_pkts.put(ppd)

        self.app_state.client_connected_lock.release()
        
      except Exception as ex:
        print("[WARNING][PpDataReceiverThread]: Exception caught:")
        print(ex)

#===========================================
# Class ClientMsgHandlerThread
#===========================================

class ClientMsgHandlerThread(threading.Thread):
    def __init__(self, app_state):
        threading.Thread.__init__(self)
        self.app_state = app_state
        self.client_sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        self.client_sock.bind(( CLIENT_MSG_IP, CLIENT_MSG_PORT ))
        self.buf = bytearray(8)
        print("Created ClientMsgHandlerThread")

    def run(self):
        while 1:
            nbytes, sender = self.client_sock.recvfrom_into(self.buf)
            self.handle_packet(self.buf)

    def handle_packet(self, pkt):
      try:
        i = unpack("I", pkt[0:4])[0]
        self.app_state.set_curr_flow_filter(i)
        flow = self.app_state.flows[ self.app_state.curr_flow_filter ]
        self.queue_filter_change_pkt(flow)
      except Exception as ex:
        print("[WARNING]ClientMsgHandlerThread]: Exception caught:")
        print(ex)

    def queue_filter_change_pkt(self, flow):
        self.app_state.viz_data_pkts.put({
            "t" : "ft",
            "f" : flow.flow_id,
            "l" : flow.path
        })

#===========================================
# Class PpData
#===========================================

class PpData():
    def __init__(self, pp_pkt):
        self.src_ip = socket.ntohl(unpack("I", pp_pkt[0:4])[0])
        self.dst_ip = socket.ntohl(unpack("I", pp_pkt[4:8])[0])
        self.src_port = socket.ntohs(unpack("H", pp_pkt[8:10])[0])
        self.dst_port = socket.ntohs(unpack("H", pp_pkt[10:12])[0])
        self.vni_and_proto = socket.ntohl(unpack("I", pp_pkt[12:16])[0])
        self.sw_hop_latencies = []

        ip_proto = self.vni_and_proto & 0x000000ff
        if (ip_proto == 6 or ip_proto == 17):
            self.flow_id = "%d:%d:%d:%d:%d" % (
                self.vni_and_proto, 
                self.src_ip, self.dst_ip,
                self.src_port, self.dst_port) 
        else:
            self.flow_id = "%d:%d:%d" % (
                self.vni_and_proto,
                self.src_ip, self.dst_ip) 

        idx = 20
        (ins_cnt, max_cnt, tot_cnt) = unpack("B B B", pp_pkt[17:20])
        for i in range(tot_cnt):
            switch_id = socket.ntohl(unpack("I", pp_pkt[idx:idx+4])[0])
            hop_lat = socket.ntohl(unpack("I", pp_pkt[idx+4:idx+8])[0])
            q_occ = socket.ntohl(unpack("I", pp_pkt[idx+8:idx+12])[0])

            if i == tot_cnt - 1: q_occ = q_occ & 0x7FFF

            self.sw_hop_latencies.append([switch_id, hop_lat])
            idx = idx + 12

#===========================================
# Class NetworkTopology
#===========================================

class NetworkTopology():
    def __init__(self, topo_file):
        self.nodes = []
        self.hosts = []
        self.switches = []
        self.links  = []
        self.src_to_dst_to_link = dict()
        self.num_switch_levels = 0
        self.level_to_num_nodes = []

        links = []
        with open(topo_file) as f:
          t = json.load(f)
          for h in t['hosts']:
            n = ip_str_to_num(h)
            self.nodes.append(n)
            self.hosts.append(n) 

          self.level_to_num_nodes.append(len(self.hosts))

          for arr in t['switches']:
            self.num_switch_levels = self.num_switch_levels + 1
            #arr = t['switches'][l]
            self.level_to_num_nodes.append(len(arr))
            for n in arr:
              s = int(n, 16)
              self.nodes.append(s)
              self.switches.append(s)
          
          for h in t['host_leaf_conns']:
            n = t['host_leaf_conns'][h]
            s = int(n, 16)
            links.append(( ip_str_to_num(h),s ))

          for l1 in range(0, self.num_switch_levels - 1):
            sw_arr1 = t['switches'][l1]
            sw_arr2 = t['switches'][l1 + 1]
            for s1 in sw_arr1:
              for s2 in sw_arr2:
                links.append(( int(s1, 16), int(s2, 16) ))

        self.links = to_bidirectional_links(links)
        self.src_to_dst_to_link = dict()
        
        for n in self.nodes: self.src_to_dst_to_link[n] = dict()

        for i, link in enumerate( self.links ):
            self.src_to_dst_to_link[ link[0] ][ link[1] ] = i 

    def get_link(self, src, dst):
        d = self.src_to_dst_to_link
        if (src in d) and (dst in d[src]):
            return d[ src ][ dst ]

        return None

#===========================================
# Class AppState
#===========================================

class AppState():
    def __init__(self):
        self.flows = dict()
        self.flows_arr = []
        self.sw_agg_lat = dict()
        self.pp_data_pkts = Queue()
        self.viz_data_pkts = Queue()
        self.agg_lat_lock = threading.Lock()
        self.flow_filter_lock = threading.Lock()
        self.client_connected = False
        self.client_connected_lock = threading.Lock()
        self.curr_flow_filter = "all"
        self.net_topo = NetworkTopology('../apps/int/monitor/topology.json')

        for s in self.net_topo.switches:
          self.sw_agg_lat[s] = 0

    def flow_matches_filter(self, flow_id):
      self.flow_filter_lock.acquire()
      if (self.curr_flow_filter == "all"):
        self.flow_filter_lock.release()
        return True

      b = (flow_id == self.curr_flow_filter)
      self.flow_filter_lock.release()
      return b

    def print_path(self, path):
      for i in reversed(range(len(path))):
        l = path[i]
        print("  %08X" % self.net_topo.links[l][0])
      dst = self.net_topo.links[path[0]][1]
      print("  %08X" % dst)

    def set_curr_flow_filter(self, i):
        if i < len(self.flows_arr):
            flow = self.flows_arr[i]
            self.flow_filter_lock.acquire()
            self.curr_flow_filter = flow.flow_id
            self.flow_filter_lock.release()

            # Clear the current aggregates
            self.agg_lat_lock.acquire()
            for sw in self.sw_agg_lat:
                self.sw_agg_lat[sw] = 0
            self.agg_lat_lock.release()
        else:
            print("[WARNING]: flow filter id >= number of flows ")

    def record_pp_data_pkt(self, ppd):
        is_new_flow = False
        is_path_change = False
        is_loop_detected = False
        flow_id = ppd.flow_id

        if len(ppd.sw_hop_latencies) > 0:
            curr_path = None
            if flow_id not in self.flows:
                is_new_flow = True
                curr_path = self.sw_hop_latencies_to_path( ppd.src_ip, ppd.dst_ip, ppd.sw_hop_latencies )
                flow = Flow( flow_id, curr_path )
                self.flows[flow_id] = flow
                flow.id = len(self.flows_arr)
                self.flows_arr.append(flow)

            if self.flow_matches_filter( flow_id ):
                if curr_path == None:
                    curr_path = self.sw_hop_latencies_to_path( ppd.src_ip, ppd.dst_ip, ppd.sw_hop_latencies )

                sw_lat = ppd.sw_hop_latencies

                self.agg_lat_lock.acquire()
                for (sw, lat) in sw_lat:
                    if lat > self.sw_agg_lat[sw]:
                        self.sw_agg_lat[sw] = lat

                self.agg_lat_lock.release()

                flow = self.flows[flow_id]
                if self.paths_differ( curr_path, flow.path ):
                    flow.prev_path = flow.path
                    flow.path = curr_path
                    is_path_change = True

                #if self.is_loop_present( ppd.sw_hop_latencies ):
                #    is_loop_detected = True

        return {
            "is_new_flow"      : is_new_flow,
            "is_path_change"   : is_path_change,
            "is_loop_detected" : is_loop_detected
        }

    def is_loop_present(self, hop_latencies):
        switchesSeen = set()
        for (sw, lat) in hop_latencies:
            if sw in switchesSeen: return True
            switchesSeen.add(sw)

        return False

    def paths_differ(self, p1, p2):
        return not (p1 == p2)

    def sw_hop_latencies_to_path(self, src_ip, dst_ip, hl):
        links = []
        try:
            if len(hl) > 0:
                prev_node = dst_ip
                for (sw, lat) in hl:
                    link = self.net_topo.get_link( sw, prev_node )
                    if link == None: return []

                    links.append(link)
                    prev_node = sw

                link = self.net_topo.get_link( src_ip, hl[-1][0] )
                if link == None: return []

                links.append(link)
            else:
                print("[WARNING]: Packet with no hop latencies received")
        except Exception as ex:
            print("[WARNING][1]: Exception caught")
            print(ex)

        return links

#===========================================
# Class Flow
#===========================================

class Flow():
    def __init__(self, flow_id, path):
        self.flow_id = flow_id
        self.path = path
        self.prev_path = []

#===========================================
# Class PpDataProcessorThread
#===========================================

class PpDataProcessorThread(threading.Thread):
    def __init__(self, app_state):
        threading.Thread.__init__(self)
        self.app_state = app_state

    def run(self):
        while 1:
            ppd = self.app_state.pp_data_pkts.get()
            res = self.app_state.record_pp_data_pkt( ppd )
            if res["is_new_flow"]:
                flow = self.app_state.flows[ ppd.flow_id ]
                self.queue_newflow_pkt( flow )

            if res["is_path_change"]:
                flow = self.app_state.flows[ ppd.flow_id ]
                self.queue_pathchange_pkt( ppd.flow_id, flow.path, flow.prev_path )

            #if res["is_loop_detected"]:
            #    flow = self.app_state.flows[ ppd.flow_id ]
            #    self.queue_loop_detected_pkt( ppd.flow_id, flow.path )

    def queue_newflow_pkt(self, flow):
        self.app_state.viz_data_pkts.put({
            "t" : "nf",
            "i" : flow.id,
            "f" : flow.flow_id,
            "l" : flow.path
        })

    def queue_pathchange_pkt(self, flow_id, new_path, old_path):
        self.app_state.viz_data_pkts.put({
            "t" : "pc",
            "f" : flow_id,
            "l" : new_path,
            "o" : old_path
        })

    def queue_loop_detected_pkt(self, flow_id, path):
        self.app_state.viz_data_pkts.put({
            "t" : "lp",
            "f" : flow_id,
            "p" : path
        })

#===========================================
# Class SwStatsAggregatorThread
#===========================================

class SwStatsAggregatorThread(threading.Thread):
    def __init__(self, app_state, agg_interval):
        threading.Thread.__init__(self)
        self.app_state = app_state
        self.agg_interval = agg_interval
        print("SwStatsAggregatorThread created")

    def run(self):
        while 1:
            self.app_state.agg_lat_lock.acquire()

            lat = dict()
            for sw in self.app_state.sw_agg_lat:
                lat[sw] = self.app_state.sw_agg_lat[sw]
                self.app_state.sw_agg_lat[sw] = 0

            self.app_state.viz_data_pkts.put({
                "t"  : "sl",
                "lt" : lat,
            })

            self.app_state.agg_lat_lock.release()
            time.sleep(self.agg_interval)

#===========================================
# Helper functions
#===========================================

def print_bytearray(arr, n): 
    i = 0 
    while(i < n): 
        (a,b,c,d) = unpack("B B B B", arr[i:i+4])
        print("%02X %02X %02X %02X" % (a,b,c,d))
        i = i + 4 

def ip_str_to_num(s):
  arr = s.split('.')
  return (int(arr[0]) << 24) | (int(arr[1]) << 16) | (int(arr[2]) << 8) | int(arr[3])

def to_bidirectional_links(links):
  res = []
  for l in links:
    res.append(l)
    res.append(( l[1], l[0] ))
  return res

