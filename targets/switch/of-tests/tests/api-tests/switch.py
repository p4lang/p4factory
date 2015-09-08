# Copyright 2013-present Barefoot Networks, Inc.
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

"""
Thrift API interface basic tests
"""

import switch_api_thrift

import time
import sys
import logging

import unittest
import random

import oftest.dataplane as dataplane
import api_base_tests

from oftest.testutils import *

import os

from utils import *

from switch_api_thrift.ttypes import  *

this_dir = os.path.dirname(os.path.abspath(__file__))

device=0

def verify_packet_list_any(test, pkt_list,  ofport_list):
    logging.debug("Checking for packet on given ports")
    (rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(timeout=1)
    test.assertTrue(rcv_pkt != None, "No packet received")

    i = 0
    match_found = 0
    for ofport in ofport_list:
        pkt = pkt_list[i]
        if ((str(rcv_pkt) == str(pkt)) and (ofport == rcv_port)):
            match_index = i
            match_found = 1
        i = i + 1
    test.assertTrue(match_found == 1, "Packet not received on expected port")
    return match_index

def verify_packet_list(test, pkt_list,  ofport_list):
    logging.debug("Checking for packet on given ports")

    match_found = 0
    for ofport in ofport_list:
        (rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(timeout=2)
        test.assertTrue(rcv_pkt != None, "No packet received")
        index = ofport_list.index(rcv_port)
        pkt = pkt_list[index]
        if (str(rcv_pkt) == str(pkt)):
            match_found += 1
    test.assertTrue(match_found == len(pkt_list), "Packet not received on expected port")

def verify_packet_on_set_of_ports(test, pkt, ofport_list):
    logging.debug("Checking for packet on set of ports")
    match_found = 0
    for port_list in ofport_list:
        for port in port_list:
            (rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(timeout=1)
            if (str(rcv_pkt) == str(pkt)):
                match_found += 1
    test.assertTrue(match_found == len(ofport_list), "Packet not received on expected port")

class L2AccessToAccessVlanTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet port 1 -> port 2 [access vlan=10])"
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:11:11:11:11', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:22:22:22:22', 2, if1)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=101,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=101,
                                ip_ttl=64)

        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:22:22:22:22:22')

            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_vlan_delete(device, vlan)

class L2TrunkToTrunkVlanTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet - port 1 -> port 2 [trunk vlan=10])"
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=3, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=3, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:11:11:11:11', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:22:22:22:22', 2, if1)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_id=102,
                                ip_ttl=64)

        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:22:22:22:22:22')

            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_vlan_delete(device, vlan)

class L2StaticMacMoveTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (00:22:22:22:22:22 -> 00:11:11:11:11:11)"
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=2, u=iu3, mac='00:77:66:55:44:33', label=0)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        vlan_port3 = switcht_vlan_port_t(handle=if3, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port3)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:11:11:11:11', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:22:22:22:22', 2, if1)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=103,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=103,
                                ip_ttl=64)
        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])

            print "Moving mac (00:11:11:11:11:11) from port 2 to port 3"
            print "Sending packet port 1 -> port 3 (00:22:22:22:22:22 -> 00:11:11:11:11:11)"

            self.client.switcht_api_mac_table_entry_update(device, vlan, '00:11:11:11:11:11', 2, if3)
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [3])
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:22:22:22:22:22')

            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)

            self.client.switcht_api_vlan_delete(device, vlan)

class L2MacLearnTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=2, u=iu3, mac='00:77:66:55:44:33', label=0)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        vlan_port3 = switcht_vlan_port_t(handle=if3, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port3)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:33:33:33:33:33', 2, if3)
        pkt1 = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='10.0.0.1',
                                ip_id=104,
                                ip_ttl=64)
        pkt2 = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=104,
                                ip_ttl=64)
        pkt3 = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                eth_dst='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=104,
                                ip_ttl=64)

        try:
            print "Sending packet port 1 -> port 3 (00:11:11:11:11:11 -> 00:33:33:33:33:33)"
            self.dataplane.send(1, str(pkt1))
            verify_packets(self, pkt1, [3])
            time.sleep(3)
            print "Sending packet port 2 -> port 3 (00:22:22:22:22:22 -> 00:33:33:33:33:33)"
            self.dataplane.send(2, str(pkt2))
            verify_packets(self, pkt2, [3])
            time.sleep(3)

            print "Sending packet port 1 -> port 2 (00:11:11:11:11:11 -> 00:22:22:22:22:22)"
            self.dataplane.send(1, str(pkt3))
            verify_packets(self, pkt3, [2])
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:22:22:22:22:22')
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:33:33:33:33:33')

            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)

            self.client.switcht_api_vlan_delete(device, vlan)

class L2DynamicMacMoveTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=2, u=iu3, mac='00:77:66:55:44:33', label=0)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        vlan_port3 = switcht_vlan_port_t(handle=if3, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port3)

        pkt1 = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=104,
                                ip_ttl=64)

        pkt2 = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                eth_dst='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=104,
                                ip_ttl=64)

        try:
            print "Sending packet port 1 -> port 2 (00:22:22:22:22:22 -> 00:11:11:11:11:11)"
            self.dataplane.send(1, str(pkt1))
            verify_packets(self, pkt1, [2, 3])
            time.sleep(3)

            print "Sending packet port 2 -> port 1 (00:11:11:11:11:11 -> 00:22:22:22:22:22)"
            self.dataplane.send(2, str(pkt2))
            verify_packets(self, pkt2, [1])
            time.sleep(3)

            print "Moving mac (00:22:22:22:22:22) from port 1 to port 3"
            print "Sending packet port 3 -> port 2 (00:22:22:22:22:22 -> 00:11:11:11:11:11)"
            self.dataplane.send(3, str(pkt1))
            verify_packets(self, pkt1, [2])
            time.sleep(3)

            print "Sending packet port 2 -> port 3 (00:11:11:11:11:11 -> 00:22:22:22:22:22)"
            self.dataplane.send(2, str(pkt2))
            verify_packets(self, pkt2, [3])
            time.sleep(12)
        finally:
            #self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:11:11:11:11:11')
            #self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:22:22:22:22:22')

            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)

            self.client.switcht_api_vlan_delete(device, vlan)

class L2DynamicLearnAgeTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=2, u=iu3, mac='00:77:66:55:44:33', label=0)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        vlan_port3 = switcht_vlan_port_t(handle=if3, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port3)

        pkt1 = simple_tcp_packet(eth_dst='00:66:66:66:66:66',
                                eth_src='00:77:77:77:77:77',
                                ip_dst='10.0.0.1',
                                ip_id=115,
                                ip_ttl=64)

        pkt2 = simple_tcp_packet(eth_src='00:66:66:66:66:66',
                                eth_dst='00:77:77:77:77:77',
                                ip_dst='10.0.0.1',
                                ip_id=115,
                                ip_ttl=64)

        try:
            print "Sending packet port 1 -> port 2, port 3 (00:77:77:77:77:77 -> 00:66:66:66:66:66)"
            self.dataplane.send(1, str(pkt1))
            verify_packets(self, pkt1, [2, 3])

            #allow it to learn. Next set of packets should be unicast
            time.sleep(5)

            print "Sending packet port 2 -> port 1 (00:66:66:66:66:66 -> 00:77:77:77:77:77)"
            self.dataplane.send(2, str(pkt2))
            verify_packets(self, pkt2, [1])

            #allow it to age. Next set of packets should be flooded
            time.sleep(20)

            print "Sending packet port 2 -> port 1,3 (00:66:66:66:66:66 -> 00:77:77:77:77:77)"
            self.dataplane.send(2, str(pkt2))
            verify_packets(self, pkt2, [1,3])

        finally:
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)

            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:11:11:11:11:11')

            self.client.switcht_api_vlan_delete(device, vlan)

class L3IPv4HostTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='10.10.10.1', prefix_length=32)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(device, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop, interface_handle=if2, mac_addr='00:11:22:33:44:55', ip_addr=i_ip3, rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop)

        # send the test packet(s)
        pkt = simple_tcp_packet( eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                #ip_tos=3,
                                ip_ttl=63)
        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, nhop)
            self.client.switcht_api_nhop_delete(device, nhop)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L3IPv4HostModifyTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101] route add)"
        print "Sending packet port 1 -> port 3 (192.168.0.1 -> 10.10.10.1 [id = 101] route update)"
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=4, u=iu3, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if3 = self.client.switcht_api_interface_create(device, i_info3)
        i_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='11.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if3, vrf, i_ip3)

        i_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='10.10.10.1', prefix_length=32)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1, interface_handle=if2, mac_addr='00:22:22:22:22:22', ip_addr=i_ip4, rw_type=1)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip4, nhop1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        self.dataplane.send(1, str(pkt))

        exp_pkt = simple_tcp_packet(
                                eth_dst='00:22:22:22:22:22',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        verify_packets(self, exp_pkt, [2])

        nhop_key2 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop2 = self.client.switcht_api_nhop_create(device, nhop_key2)
        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=nhop2, interface_handle=if3, mac_addr='00:33:33:33:33:33', ip_addr=i_ip4, rw_type=1)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip4, nhop2)

        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        self.dataplane.send(1, str(pkt))

        exp_pkt = simple_tcp_packet(
                                eth_dst='00:33:33:33:33:33',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        verify_packets(self, exp_pkt, [3])

        self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
        self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

        self.client.switcht_api_l3_route_delete(device, vrf, i_ip4, nhop2)

        self.client.switcht_api_nhop_delete(device, nhop1)
        self.client.switcht_api_nhop_delete(device, nhop2)

        self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
        self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)
        self.client.switcht_api_l3_interface_address_delete(device, if3, vrf, i_ip3)

        self.client.switcht_api_interface_delete(device, if1)
        self.client.switcht_api_interface_delete(device, if2)
        self.client.switcht_api_interface_delete(device, if3)

        self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
        self.client.switcht_api_router_mac_group_delete(device, rmac)
        self.client.switcht_api_vrf_delete(device, vrf)

class L3IPv4LpmTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.0.0.1 [id = 101])"
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='10.10.10.0', prefix_length=24)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(device, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop, interface_handle=if2, mac_addr='00:11:22:33:44:55', ip_addr=i_ip3, rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop)

        # send the test packet(s)
        pkt = simple_tcp_packet( eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                #ip_tos=3,
                                ip_ttl=63)
        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, nhop)
            self.client.switcht_api_nhop_delete(device, nhop)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L3IPv6HostTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (2000::1 -> 3000::1)"
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=1, ipaddr='2000::2', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=1, ipaddr='3000::2', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(addr_type=1, ipaddr='1234:5678:9abc:def0:4422:1133:5577:99aa', prefix_length=128)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(device, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop, interface_handle=if2, mac_addr='00:11:22:33:44:55', ip_addr=i_ip3, rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop)

        # send the test packet(s)
        pkt = simple_tcpv6_packet( eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ipv6_dst='1234:5678:9abc:def0:4422:1133:5577:99aa',
                                ipv6_src='2000::1',
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ipv6_dst='1234:5678:9abc:def0:4422:1133:5577:99aa',
                                ipv6_src='2000::1',
                                ipv6_hlim=63)
        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, nhop)
            self.client.switcht_api_nhop_delete(device, nhop)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L3IPv6LpmTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "IPv6 Lpm Test"
        print "Sending packet port 1 -> port 2 (2000::1 -> 3000::1, routing with 3000::0/120 route"
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=1, ipaddr='2000::2', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=1, ipaddr='3000::2', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(addr_type=1, ipaddr='3000::0', prefix_length=120)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(device, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop, interface_handle=if2, mac_addr='00:99:99:99:99:99', ip_addr=i_ip3, rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop)

        # send the test packet(s)
        pkt = simple_tcpv6_packet( eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ipv6_dst='3000::1',
                                ipv6_src='2000::1',
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
                                eth_dst='00:99:99:99:99:99',
                                eth_src='00:77:66:55:44:33',
                                ipv6_dst='3000::1',
                                ipv6_src='2000::1',
                                ipv6_hlim=63)
        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, nhop)
            self.client.switcht_api_nhop_delete(device, nhop)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L3IPv4EcmpTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.0.0.1 [id = 101])"
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=4, u=iu3, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if3 = self.client.switcht_api_interface_create(device, i_info3)
        i_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='11.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if3, vrf, i_ip3)

        i_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='10.10.10.1', prefix_length=32)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1, interface_handle=if2, mac_addr='00:11:22:33:44:55', ip_addr=i_ip4, rw_type=1)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        nhop_key2 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop2 = self.client.switcht_api_nhop_create(device, nhop_key2)
        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=nhop2, interface_handle=if3, mac_addr='00:11:22:33:44:56', ip_addr=i_ip4, rw_type=1)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        ecmp = self.client.switcht_api_l3_ecmp_create(device)
        self.client.switcht_api_l3_ecmp_member_add(device, ecmp, 2, [nhop1, nhop2])

        self.client.switcht_api_l3_route_add(device, vrf, i_ip4, ecmp)

        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=106,
                                ip_ttl=64)

        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:56',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=106,
                                #ip_tos=3,
                                ip_ttl=63)

        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [3])

            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.100.3',
                                    ip_id=106,
                                    ip_ttl=64)

            exp_pkt = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.100.3',
                                    ip_id=106,
                                    #ip_tos=3,
                                    ip_ttl=63)

            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip4, ecmp)

            self.client.switcht_api_l3_ecmp_member_delete(device, ecmp, 2, [nhop1, nhop2])
            self.client.switcht_api_l3_ecmp_delete(device, ecmp)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)
            self.client.switcht_api_nhop_delete(device, nhop2)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)
            self.client.switcht_api_l3_interface_address_delete(device, if3, vrf, i_ip3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L3IPv6EcmpTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (2000:1:1:0:0:0:0:1 -> 5000:1:1::0:0:0:0:1) [id = 101])"
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=1, ipaddr='2000:1:1:0:0:0:0:1', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=1, ipaddr='3000:1:1:0:0:0:0:1', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=4, u=iu3, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if3 = self.client.switcht_api_interface_create(device, i_info3)
        i_ip3 = switcht_ip_addr_t(addr_type=1, ipaddr='4000:1:1:0:0:0:0:1', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if3, vrf, i_ip3)

        i_ip4 = switcht_ip_addr_t(addr_type=1, ipaddr='5000:1:1:0:0:0:0:1', prefix_length=128)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1, interface_handle=if2, mac_addr='00:11:22:33:44:55', ip_addr=i_ip4, rw_type=1)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        nhop_key2 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop2 = self.client.switcht_api_nhop_create(device, nhop_key2)
        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=nhop2, interface_handle=if3, mac_addr='00:11:22:33:44:56', ip_addr=i_ip4, rw_type=1)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        ecmp = self.client.switcht_api_l3_ecmp_create(device)
        self.client.switcht_api_l3_ecmp_member_add(device, ecmp, 2, [nhop1, nhop2])

        self.client.switcht_api_l3_route_add(device, vrf, i_ip4, ecmp)

        try:
            recv_ports = set()
            for sport in xrange(16):
                pkt = simple_tcpv6_packet(
                    eth_dst='00:77:66:55:44:33',
                    eth_src='00:22:22:22:22:22',
                    ipv6_dst='5000:1:1:0:0:0:0:1',
                    ipv6_src='2000:1:1:0:0:0:0:1',
                    tcp_sport=0x1234 + sport,
                    ipv6_hlim=64
                )

                exp_pkt_2 = simple_tcpv6_packet(
                    eth_dst='00:11:22:33:44:55',
                    eth_src='00:77:66:55:44:33',
                    ipv6_dst='5000:1:1:0:0:0:0:1',
                    ipv6_src='2000:1:1:0:0:0:0:1',
                    tcp_sport=0x1234 + sport,
                    ipv6_hlim=63
                )

                exp_pkt_3 = simple_tcpv6_packet(
                    eth_dst='00:11:22:33:44:56',
                    eth_src='00:77:66:55:44:33',
                    ipv6_dst='5000:1:1:0:0:0:0:1',
                    ipv6_src='2000:1:1:0:0:0:0:1',
                    tcp_sport=0x1234 + sport,
                    ipv6_hlim=63
                )

                self.dataplane.send(1, str(pkt))
                recv_port = verify_packet_list_any(self, [exp_pkt_2, exp_pkt_3], [2, 3])
                recv_ports.add(recv_port)
            self.assertTrue(len(recv_ports) == 2, "")

        finally:
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip4, ecmp)

            self.client.switcht_api_l3_ecmp_member_delete(device, ecmp, 2, [nhop1, nhop2])
            self.client.switcht_api_l3_ecmp_delete(device, ecmp)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)
            self.client.switcht_api_nhop_delete(device, nhop2)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)
            self.client.switcht_api_l3_interface_address_delete(device, if3, vrf, i_ip3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L3IPv4LpmEcmpTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=4, u=iu3, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if3 = self.client.switcht_api_interface_create(device, i_info3)
        i_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='11.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if3, vrf, i_ip3)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        n_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.100', prefix_length=32)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1, interface_handle=if2, mac_addr='00:11:22:33:44:55', ip_addr=n_ip1, rw_type=1)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        nhop_key2 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop2 = self.client.switcht_api_nhop_create(device, nhop_key2)
        n_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='11.0.0.100', prefix_length=32)
        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=nhop2, interface_handle=if3, mac_addr='00:11:22:33:44:56', ip_addr=n_ip2, rw_type=1)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        nhop_key3 = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop3 = self.client.switcht_api_nhop_create(device, nhop_key3)
        n_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.101', prefix_length=32)
        neighbor_entry3 = switcht_neighbor_info_t(nhop_handle=nhop3, interface_handle=if2, mac_addr='00:11:22:33:44:57', ip_addr=n_ip3, rw_type=1)
        neighbor3 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry3)

        nhop_key4 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop4 = self.client.switcht_api_nhop_create(device, nhop_key4)
        n_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='11.0.0.101', prefix_length=32)
        neighbor_entry4 = switcht_neighbor_info_t(nhop_handle=nhop4, interface_handle=if3, mac_addr='00:11:22:33:44:58', ip_addr=n_ip4, rw_type=1)
        neighbor4 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry4)

        ecmp = self.client.switcht_api_l3_ecmp_create(device)
        self.client.switcht_api_l3_ecmp_member_add(device, ecmp, 4, [nhop1, nhop2, nhop3, nhop4])

        r_ip = switcht_ip_addr_t(addr_type=0, ipaddr='10.10.0.0', prefix_length=16)
        self.client.switcht_api_l3_route_add(device, vrf, r_ip, ecmp)

        try:
            count = [0, 0, 0, 0]
            dst_ip = int(socket.inet_aton('10.10.10.1').encode('hex'),16)
            max_itrs = 200
            random.seed(314159)
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntoa(hex(dst_ip)[2:].zfill(8).decode('hex'))
                src_port = random.randint(0, 65535)
                dst_port = random.randint(0, 65535)
                pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                        eth_src='00:22:22:22:22:22',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=64,
                        tcp_sport=src_port,
                        tcp_dport=dst_port)

                exp_pkt1 = simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63,
                        tcp_sport=src_port,
                        tcp_dport=dst_port)
                exp_pkt2 = simple_tcp_packet(eth_dst='00:11:22:33:44:56',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63,
                        tcp_sport=src_port,
                        tcp_dport=dst_port)
                exp_pkt3 = simple_tcp_packet(eth_dst='00:11:22:33:44:57',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63,
                        tcp_sport=src_port,
                        tcp_dport=dst_port)
                exp_pkt4 = simple_tcp_packet(eth_dst='00:11:22:33:44:58',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63,
                        tcp_sport=src_port,
                        tcp_dport=dst_port)

                self.dataplane.send(1, str(pkt))
                rcv_idx = verify_packet_list_any(self,
                              [exp_pkt1, exp_pkt2, exp_pkt3, exp_pkt4],
                              [2, 3, 2, 3])
                count[rcv_idx] += 1
                dst_ip += 1

            print "ECMP load balancing result ", count
            for i in range(0, 4):
                self.assertTrue((count[i] >= ((max_itrs / 4) * 0.7)),
                        "Not all paths are equally balanced")
        finally:
            self.client.switcht_api_l3_route_delete(device, vrf, r_ip, ecmp)

            self.client.switcht_api_l3_ecmp_member_delete(device, ecmp, 4, [nhop1, nhop2, nhop3, nhop4])
            self.client.switcht_api_l3_ecmp_delete(device, ecmp)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)
            self.client.switcht_api_nhop_delete(device, nhop2)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor3)
            self.client.switcht_api_nhop_delete(device, nhop3)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor4)
            self.client.switcht_api_nhop_delete(device, nhop4)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)
            self.client.switcht_api_l3_interface_address_delete(device, if3, vrf, i_ip3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L3IPv6LpmEcmpTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=1, ipaddr='1000:1:1:0:0:0:0:1', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=1, ipaddr='2000:1:1:0:0:0:0:1', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=4, u=iu3, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if3 = self.client.switcht_api_interface_create(device, i_info3)
        i_ip3 = switcht_ip_addr_t(addr_type=1, ipaddr='3000:1:1:0:0:0:0:1', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if3, vrf, i_ip3)

        iu4 = interface_union(port_lag_handle = 4)
        i_info4 = switcht_interface_info_t(device=0, type=4, u=iu4, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if4 = self.client.switcht_api_interface_create(device, i_info4)
        i_ip4 = switcht_ip_addr_t(addr_type=1, ipaddr='4000:1:1:0:0:0:0:1', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if4, vrf, i_ip4)

        iu5 = interface_union(port_lag_handle = 5)
        i_info5 = switcht_interface_info_t(device=0, type=4, u=iu5, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if5 = self.client.switcht_api_interface_create(device, i_info5)
        i_ip5 = switcht_ip_addr_t(addr_type=1, ipaddr='5000:1:1:0:0:0:0:1', prefix_length=120)
        self.client.switcht_api_l3_interface_address_add(device, if5, vrf, i_ip5)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1, interface_handle=if2, mac_addr='00:11:22:33:44:55', ip_addr=i_ip2, rw_type=1)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        nhop_key2 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop2 = self.client.switcht_api_nhop_create(device, nhop_key2)
        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=nhop2, interface_handle=if3, mac_addr='00:11:22:33:44:56', ip_addr=i_ip3, rw_type=1)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        nhop_key3 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop3 = self.client.switcht_api_nhop_create(device, nhop_key3)
        neighbor_entry3 = switcht_neighbor_info_t(nhop_handle=nhop3, interface_handle=if4, mac_addr='00:11:22:33:44:57', ip_addr=i_ip4, rw_type=1)
        neighbor3 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry3)

        nhop_key4 = switcht_nhop_key_t(intf_handle=if5, ip_addr_valid=0)
        nhop4 = self.client.switcht_api_nhop_create(device, nhop_key4)
        neighbor_entry4 = switcht_neighbor_info_t(nhop_handle=nhop4, interface_handle=if5, mac_addr='00:11:22:33:44:58', ip_addr=i_ip5, rw_type=1)
        neighbor4 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry4)

        ecmp = self.client.switcht_api_l3_ecmp_create(device)
        self.client.switcht_api_l3_ecmp_member_add(device, ecmp, 4, [nhop1, nhop2, nhop3, nhop4])

        r_ip = switcht_ip_addr_t(addr_type=1, ipaddr='6000:1:1:0:0:0:0:0', prefix_length=64)
        self.client.switcht_api_l3_route_add(device, vrf, r_ip, ecmp)

        try:
            count = [0, 0, 0, 0]
            dst_ip = socket.inet_pton(socket.AF_INET6, '6000:1:1:0:0:0:0:1')
            dst_ip_arr = list(dst_ip)
            max_itrs = 100
            sport = 0x1234
            dport = 0x50
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntop(socket.AF_INET6, dst_ip)
                #HACK: sport is a hack for hashing since the ecmp hash does not
                #include ipv6 sa and da.
                pkt = simple_tcpv6_packet(
                        eth_dst='00:77:66:55:44:33',
                        eth_src='00:22:22:22:22:22',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=64)
                exp_pkt1 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:55',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)
                exp_pkt2 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:56',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)
                exp_pkt3 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:57',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)
                exp_pkt4 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:58',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)

                self.dataplane.send(1, str(pkt))
                rcv_idx = verify_packet_list_any(self,
                              [exp_pkt1, exp_pkt2, exp_pkt3, exp_pkt4],
                              [2, 3, 4, 5])
                count[rcv_idx] += 1
                dst_ip_arr[15] = chr(ord(dst_ip_arr[15]) + 1)
                dst_ip = ''.join(dst_ip_arr)
                sport += 15
                dport += 20

            for i in range(0, 4):
                self.assertTrue((count[i] >= ((max_itrs / 4) * 0.9)),
                        "Not all paths are equally balanced")
        finally:
            self.client.switcht_api_l3_route_delete(device, vrf, r_ip, ecmp)

            self.client.switcht_api_l3_ecmp_member_delete(device, ecmp, 4, [nhop1, nhop2, nhop3, nhop4])
            self.client.switcht_api_l3_ecmp_delete(device, ecmp)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)
            self.client.switcht_api_nhop_delete(device, nhop2)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor3)
            self.client.switcht_api_nhop_delete(device, nhop3)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor4)
            self.client.switcht_api_nhop_delete(device, nhop4)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)
            self.client.switcht_api_l3_interface_address_delete(device, if3, vrf, i_ip3)
            self.client.switcht_api_l3_interface_address_delete(device, if4, vrf, i_ip4)
            self.client.switcht_api_l3_interface_address_delete(device, if5, vrf, i_ip5)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)
            self.client.switcht_api_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if5)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2FloodTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.0.0.1 [id = 101])"
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)
        self.client.switcht_api_vlan_learning_enabled_set(vlan, 0)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=2, u=iu3, mac='00:77:66:55:44:33', label=0)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        vlan_port3 = switcht_vlan_port_t(handle=if3, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port3)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=107,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=107,
                                ip_ttl=64)
        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2, 3])
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1, 3])
            self.dataplane.send(3, str(pkt))
            verify_packets(self, exp_pkt, [1, 2])
        finally:
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)

            self.client.switcht_api_vlan_delete(device, vlan)

class L2LagTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        lag = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag, side=0, port=5)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag, side=0, port=6)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag, side=0, port=7)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag, side=0, port=8)
        iu2 = interface_union(port_lag_handle = lag)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:11:11:11:11', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:22:22:22:22', 2, if1)

        try:
            count = [0, 0, 0, 0]
            dst_ip = int(socket.inet_aton('10.10.10.1').encode('hex'),16)
            max_itrs = 100
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntoa(hex(dst_ip)[2:].zfill(8).decode('hex'))
                pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                        eth_src='00:22:22:22:22:22',
                                        ip_dst=dst_ip_addr,
                                        ip_src='192.168.8.1',
                                        ip_id=109,
                                        ip_ttl=64)

                exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                            eth_src='00:22:22:22:22:22',
                                            ip_dst=dst_ip_addr,
                                            ip_src='192.168.8.1',
                                            ip_id=109,
                                            ip_ttl=64)

                self.dataplane.send(1, str(pkt))
                rcv_idx = verify_packet_list_any(self,
                              [exp_pkt, exp_pkt, exp_pkt, exp_pkt],
                              [5, 6, 7, 8])
                count[rcv_idx] += 1
                dst_ip += 1

            print 'L2LagTest:', count
            for i in range(0, 4):
                self.assertTrue((count[i] >= ((max_itrs / 4) * 0.9)),
                        "Not all paths are equally balanced")

            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=109,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=109,
                                    ip_ttl=64)
            print "Sending packet port 5 (lag member) -> port 1"
            self.dataplane.send(5, str(pkt))
            verify_packets(self, exp_pkt, [1])
            print "Sending packet port 6 (lag member) -> port 1"
            self.dataplane.send(6, str(pkt))
            verify_packets(self, exp_pkt, [1])
            print "Sending packet port 7 (lag member) -> port 1"
            self.dataplane.send(7, str(pkt))
            verify_packets(self, exp_pkt, [1])
            print "Sending packet port 8 (lag member) -> port 1"
            self.dataplane.send(8, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:22:22:22:22:22')
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:11:11:11:11:11')

            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag, side=0, port=5)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag, side=0, port=6)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag, side=0, port=7)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag, side=0, port=8)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_lag_delete(device, lag)
            self.client.switcht_api_vlan_delete(device, vlan)


class L3IPv4LagTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.0.0.1 [id = 101])"
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 2)
        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        lag = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag, side=0, port=2)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag, side=0, port=3)
        iu2 = interface_union(port_lag_handle = lag)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0,vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        i_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='10.10.10.1', prefix_length=32)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(device, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop, interface_handle=if2, mac_addr='00:11:22:33:44:55', ip_addr=i_ip3, rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop)

        try:
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.0.1',
                                    ip_id=110,
                                    ip_ttl=64)

            exp_pkt = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.0.1',
                                    ip_id=110,
                                    ip_ttl=63)
            self.dataplane.send(1, str(pkt))
            verify_packets_any(self, exp_pkt, [2, 3])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, nhop)
            self.client.switcht_api_nhop_delete(device, nhop)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag, side=0, port=2)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag, side=0, port=3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_lag_delete(device, lag)
            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L3IPv6LagTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (4001::1 -> 5001::1[id = 101])"
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 2)
        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=1, ipaddr='5001::10', prefix_length=128)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        lag = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag, side=0, port=2)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag, side=0, port=3)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag, side=0, port=4)
        iu2 = interface_union(port_lag_handle = lag)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0,vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=1, ipaddr='4001::10', prefix_length=128)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        i_ip3 = switcht_ip_addr_t(addr_type=1, ipaddr='4001::1', prefix_length=128)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(device, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop, interface_handle=if2, mac_addr='00:88:88:88:88:88', ip_addr=i_ip3, rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop)

        try:
            pkt = simple_tcpv6_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst='4001::1',
                                    ipv6_src='5001::1',
                                    ipv6_hlim=64)

            exp_pkt = simple_tcpv6_packet(
                                    eth_dst='00:88:88:88:88:88',
                                    eth_src='00:77:66:55:44:33',
                                    ipv6_dst='4001::1',
                                    ipv6_src='5001::1',
                                    ipv6_hlim=63)
            self.dataplane.send(1, str(pkt))
            verify_packets_any(self, exp_pkt, [2, 3, 4])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, nhop)
            self.client.switcht_api_nhop_delete(device, nhop)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag, side=0, port=2)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag, side=0, port=3)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag, side=0, port=4)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_lag_delete(device, lag)
            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L3EcmpLagTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> ecmp -> lag"
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1,
                mac='00:77:66:55:44:33', label=0, vrf_handle=vrf,
                rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='192.168.0.2',
                prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        lag1 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=2)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=3)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=4)
        iu2 = interface_union(port_lag_handle = lag1)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2,
                mac='00:77:66:55:44:33', label=0, vrf_handle=vrf,
                rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.2.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        lag2 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=5)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=6)
        iu3 = interface_union(port_lag_handle = lag2)
        i_info3 = switcht_interface_info_t(device=0, type=4, u=iu3,
                mac='00:77:66:55:44:33', label=0, vrf_handle=vrf,
                rmac_handle=rmac)
        if3 = self.client.switcht_api_interface_create(device, i_info3)
        i_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.3.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if3, vrf, i_ip3)

        iu4 = interface_union(port_lag_handle = 7)
        i_info4 = switcht_interface_info_t(device=0, type=4, u=iu4,
                mac='00:77:66:55:44:33', label=0, vrf_handle=vrf,
                rmac_handle=rmac)
        if4 = self.client.switcht_api_interface_create(device, i_info4)
        i_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.4.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if4, vrf, i_ip4)

        i_ip5 = switcht_ip_addr_t(addr_type=0, ipaddr='10.100.0.0',
                prefix_length=16)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                interface_handle=if2, mac_addr='00:11:22:33:44:55',
                ip_addr=i_ip5, rw_type=1)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        nhop_key2 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop2 = self.client.switcht_api_nhop_create(device, nhop_key2)
        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=nhop2,
                interface_handle=if3, mac_addr='00:11:22:33:44:56',
                ip_addr=i_ip5, rw_type=1)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        nhop_key3 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop3 = self.client.switcht_api_nhop_create(device, nhop_key3)
        neighbor_entry3 = switcht_neighbor_info_t(nhop_handle=nhop3,
                interface_handle=if4, mac_addr='00:11:22:33:44:57',
                ip_addr=i_ip5, rw_type=1)
        neighbor3 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry3)

        ecmp = self.client.switcht_api_l3_ecmp_create(device)
        self.client.switcht_api_l3_ecmp_member_add(device, ecmp, 3, [nhop1, nhop2, nhop3])

        self.client.switcht_api_l3_route_add(device, vrf, i_ip5, ecmp)

        try:
            count = [0, 0, 0, 0, 0, 0]
            dst_ip = int(socket.inet_aton('10.100.10.1').encode('hex'), 16)
            src_mac_start = '00:22:22:22:22:'
            max_itrs = 500
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntoa(hex(dst_ip)[2:].zfill(8).decode('hex'))
                src_mac = src_mac_start + str(i%99).zfill(2)
                pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                        eth_src=src_mac,
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=64)

                exp_pkt1 = simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt2 = simple_tcp_packet(eth_dst='00:11:22:33:44:56',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt3 = simple_tcp_packet(eth_dst='00:11:22:33:44:57',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)

                self.dataplane.send(1, str(pkt))
                rcv_idx = verify_packet_list_any(self,
                              [exp_pkt1, exp_pkt1, exp_pkt1,
                                  exp_pkt2, exp_pkt2, exp_pkt3],
                              [2, 3, 4, 5, 6, 7])
                count[rcv_idx] += 1
                dst_ip += 1

            print 'ecmp-count:', count
            ecmp_count = [count[0]+count[1]+count[2], count[3]+count[4],
                    count[5]]
            for i in range(0, 3):
                self.assertTrue((ecmp_count[i] >= ((max_itrs / 3) * 0.5)),
                        "Ecmp paths are not equally balanced")
            for i in range(0, 3):
                self.assertTrue((count[i] >= ((max_itrs / 9) * 0.5)),
                        "Lag path1 is not equally balanced")
            for i in range(3, 5):
                self.assertTrue((count[i] >= ((max_itrs / 6) * 0.5)),
                        "Lag path2 is not equally balanced")
        finally:
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip5, ecmp)

            self.client.switcht_api_l3_ecmp_member_delete(device, ecmp, 3, [nhop1, nhop2, nhop3])
            self.client.switcht_api_l3_ecmp_delete(device, ecmp)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)
            self.client.switcht_api_nhop_delete(device, nhop2)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor3)
            self.client.switcht_api_nhop_delete(device, nhop3)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0,
                    port=2)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0,
                    port=3)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0,
                    port=4)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0,
                    port=5)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0,
                    port=6)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)
            self.client.switcht_api_l3_interface_address_delete(device, if3, vrf, i_ip3)
            self.client.switcht_api_l3_interface_address_delete(device, if4, vrf, i_ip4)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)
            self.client.switcht_api_interface_delete(device, if4)

            self.client.switcht_api_lag_delete(device, lag1)
            self.client.switcht_api_lag_delete(device, lag2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2StpTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 (forwarding)-> port 2 (192.168.0.1 -> 10.0.0.1 [id = 101])"
        self.client.switcht_api_init(device)

        vlan = self.client.switcht_api_vlan_create(device, 10)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)

        stp = self.client.switcht_api_stp_group_create(device=0, stp_mode=1)
        self.client.switcht_api_stp_group_vlans_add(device, stp, 1, [vlan])
        self.client.switcht_api_stp_port_state_set(device=0, stp_handle=stp, intf_handle=if1, stp_state=3)
        self.client.switcht_api_stp_port_state_set(device=0, stp_handle=stp, intf_handle=if2, stp_state=3)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:11:11:11:11', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:22:22:22:22', 2, if1)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=113,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=113,
                                ip_ttl=64)
        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])

            print "Sending packet port 1 (blocked) -> port 2 (192.168.0.1 -> 10.0.0.1 [id = 101])"
            self.client.switcht_api_stp_port_state_set(device=0, stp_handle=stp, intf_handle=if1, stp_state=4)
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=113,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=113,
                                    ip_ttl=64)
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [])
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:22:22:22:22:22')

            self.client.switcht_api_stp_port_state_set(device=0, stp_handle=stp, intf_handle=if1, stp_state=0)
            self.client.switcht_api_stp_port_state_set(device=0, stp_handle=stp, intf_handle=if2, stp_state=0)

            self.client.switcht_api_stp_group_vlans_remove(device, stp, 1, [vlan])
            self.client.switcht_api_stp_group_delete(device, stp)

            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_vlan_delete(device, vlan)


class L3RpfTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)
        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac, v4_urpf_mode=1)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac, v4_urpf_mode=2)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        # add neighbor 192.168.0.1
        i_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='192.168.0.1', prefix_length=32)
        nhop_key1 = switcht_nhop_key_t(intf_handle=if1, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1, interface_handle=if1, mac_addr='00:11:22:33:44:55', ip_addr=i_ip1, rw_type=1)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        # add neighbor 10.0.0.2
        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.2', prefix_length=32)
        nhop_key2 = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop2 = self.client.switcht_api_nhop_create(device, nhop_key2)
        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=nhop2, interface_handle=if2, mac_addr='00:11:22:33:44:56', ip_addr=i_ip2, rw_type=1)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        # Add a static route 10.10/16 --> if1
        i_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='10.10.0.0', prefix_length=16)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop1)

        # Add a static route 10.11/16 --> if2
        i_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='10.11.0.0', prefix_length=16)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip4, nhop2)

        # Add a static route 10.13/16 --> if1
        i_ip5 = switcht_ip_addr_t(addr_type=0, ipaddr='10.13.0.0', prefix_length=16)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip5, nhop1)

        # send the test packet(s)
        try:
            print "Sending packet port 1 -> port 2. Loose urpf (permit)"
            pkt = simple_tcp_packet( eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.11.10.1',
                                    ip_src='10.10.10.1',
                                    ip_id=114,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:56',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.11.10.1',
                                    ip_src='10.10.10.1',
                                    ip_id=114,
                                    ip_ttl=63)
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])

            print "Sending packet port 1 -> port 2. Loose urpf (drop)"
            pkt = simple_tcp_packet( eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.11.10.1',
                                    ip_src='10.12.10.1',
                                    ip_id=114,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:56',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.11.10.1',
                                    ip_src='10.12.10.1',
                                    ip_id=114,
                                    ip_ttl=63)
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [])

            print "Sending packet port 2 -> port 1. Strict urpf (permit)"
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='10.10.10.1',
                                    ip_src='10.11.10.1',
                                    ip_id=114,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='10.11.10.1',
                                    ip_id=114,
                                    ip_ttl=63)
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])

            print "Sending packet port 2 -> port 1. Strict urpf (miss drop)"
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='10.10.10.1',
                                    ip_src='10.12.10.1',
                                    ip_id=114,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='10.12.10.1',
                                    ip_id=114,
                                    ip_ttl=63)
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [])

            print "Sending packet port 2 -> port 1. Strict urpf (hit drop)"
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='10.10.10.1',
                                    ip_src='10.13.10.1',
                                    ip_id=114,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='10.13.10.1',
                                    ip_id=114,
                                    ip_ttl=63)
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [])
        finally:
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, nhop1)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip4, nhop2)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip5, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_nhop_delete(device, nhop1)
            self.client.switcht_api_nhop_delete(device, nhop2)

            self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2StaticMacBulkDeleteTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 mac bulk delete"
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=2, u=iu3, mac='00:77:66:55:44:33', label=0)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        vlan_port3 = switcht_vlan_port_t(handle=if3, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port3)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:01', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:02', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:03', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:04', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:05', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:06', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:07', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:08', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:09', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:0a', 2, if1)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:01', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:02', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:03', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:04', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:05', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:06', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:07', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:08', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:09', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:0a', 2, if2)

        print "L2 mac delete by interface if1"
        self.client.switcht_api_mac_table_entries_delete_by_interface(device,
                                                                      if1)
        print "L2 mac delete by interface if2"
        self.client.switcht_api_mac_table_entries_delete_by_interface(device,
                                                                      if2)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:01', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:02', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:03', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:04', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:05', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:06', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:07', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:08', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:09', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:0a', 2, if1)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:01', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:02', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:03', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:04', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:05', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:06', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:07', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:08', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:09', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:0a', 2, if2)

        print "L2 mac delete by vlan"
        self.client.switcht_api_mac_table_entries_delete_by_vlan(device, vlan)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:01', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:02', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:03', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:04', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:00:00:00:05', 2, if1)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:01', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:02', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:03', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:04', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:00:00:00:05', 2, if2)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:33:00:00:00:01', 2, if3)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:33:00:00:00:02', 2, if3)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:33:00:00:00:03', 2, if3)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:33:00:00:00:04', 2, if3)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:33:00:00:00:05', 2, if3)

        print "L2 mac delete all"
        self.client.switcht_api_mac_table_entries_delete_all(device)

        self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)
        self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port3)

        self.client.switcht_api_interface_delete(device, if1)
        self.client.switcht_api_interface_delete(device, if2)
        self.client.switcht_api_interface_delete(device, if3)

        self.client.switcht_api_vlan_delete(device, vlan)


class L2VxlanUnicastBasicTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Vxlan Basic Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        udp = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp = switcht_udp_tcp_t(udp = udp)
        #encap_type 3 is vxlan
        encap_info = switcht_encap_info_t(encap_type=3)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=17, u=udp_tcp)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        iu4 = switcht_tunnel_info_t(encap_mode = 0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop1)

        try:
            print "Sending packet from Access port1 to Vxlan port2"
            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            vxlan_pkt1 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            vxlan_pkt2 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(pkt))
            verify_packet_list_any(self, [vxlan_pkt1, vxlan_pkt2], [2, 2])

            print "Sending packet from Vxlan port2 to Access port1"
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            vxlan_pkt = simple_vxlan_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(2, str(vxlan_pkt))
            verify_packets(self, pkt, [1])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2NvgreUnicastBasicTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Nvgre Basic Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        #encap_type 3 is vxlan
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        encap_info = switcht_encap_info_t(encap_type=5)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=47)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        iu4 = switcht_tunnel_info_t(encap_mode = 0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop1)

        try:
            print "Sending packet from Access port1 to Nvgre port2"
            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            nvgre_pkt1 = simple_nvgre_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x1234,
                                    inner_frame=pkt)
            nvgre_pkt2 = simple_nvgre_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(pkt))
            verify_packet_list_any(self, [nvgre_pkt1, nvgre_pkt2], [2, 2])

            print "Sending packet from Nvgre port2 to Access port1"
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            nvgre_pkt = simple_nvgre_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(2, str(nvgre_pkt))
            verify_packets(self, pkt, [1])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2NvgreUnicastEnhancedTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Vxlan Enhanced Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        nvgre = switcht_nvgre_id_t(tnid=0x1234)
        bt = switcht_bridge_type(nvgre_info=nvgre)
        encap_info = switcht_encap_info_t(encap_type=5, u=bt)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=47)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop1)

        try:
            print "Sending packet from Nvgre port2 to Access port1"
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            nvgre_pkt = simple_nvgre_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x1234,
                                    inner_frame=pkt)

            self.dataplane.send(2, str(nvgre_pkt))
            verify_packets(self, pkt, [1])

            print "Sending packet from Access port1 to Nvgre port2"
            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            nvgre_pkt1 = simple_nvgre_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x1234,
                                    inner_frame=pkt)
            nvgre_pkt2 = simple_nvgre_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(pkt))
            verify_packet_list_any(self, [nvgre_pkt1, nvgre_pkt2], [2, 2])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2VxlanUnicastLagBasicTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Vxlan Lag Basic Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        lag1 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=1)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=2)
        iu1 = interface_union(port_lag_handle = lag1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        lag2 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=3)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=4)
        iu2 = interface_union(port_lag_handle = lag2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        #encap_type 3 is vxlan
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        udp = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp = switcht_udp_tcp_t(udp = udp)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=17, u=udp_tcp)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        encap_info = switcht_encap_info_t(encap_type=3)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop1)

        try:
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            vxlan_pkt = simple_vxlan_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Lag Vxlan port3 to Access Lag"
            self.dataplane.send(3, str(vxlan_pkt))
            verify_packets_any(self, pkt, [1, 2])

            print "Sending packet from Lag Vxlan port4 to Access Lag"
            self.dataplane.send(4, str(vxlan_pkt))
            verify_packets_any(self, pkt, [1, 2])

            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Lag Access port1 to Vxlan Lag"
            self.dataplane.send(1, str(pkt))
            verify_packets_any(self, vxlan_pkt, [3, 4])

            print "Sending packet from Lag Access port2 to Vxlan Lag"
            self.dataplane.send(2, str(pkt))
            verify_packets_any(self, vxlan_pkt, [3, 4])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=1)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=2)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=3)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=4)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_lag_delete(device, lag1)
            self.client.switcht_api_lag_delete(device, lag2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2AccessToTrunkVlanTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet - port 1 -> port 2 [trunk vlan=10])"
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=3, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:11:11:11:11', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:22:22:22:22', 2, if1)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64,
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                pktlen=104)
        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:22:22:22:22:22')

            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_vlan_delete(device, vlan)

class L2TrunkToAccessVlanTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet - port 1 -> port 2 [trunk vlan=10])"
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=3, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:11:11:11:11', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:22:22:22:22', 2, if1)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64,
                                pktlen=96)
        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:22:22:22:22:22')

            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_vlan_delete(device, vlan)

class L2GeneveUnicastBasicTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Geneve Basic Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        #encap_type 3 is vxlan
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        udp = switcht_udp_t(src_port=1234, dst_port=6081)
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp = switcht_udp_tcp_t(udp = udp)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=17, u=udp_tcp)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        encap_info =  switcht_encap_info_t(encap_type=6)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop1)

        try:
            print "Sending packet from Access port1 to Geneve port2"
            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt1 = simple_geneve_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    geneve_vni=0x1234,
                                    inner_frame=pkt)
            geneve_pkt2 = simple_geneve_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    geneve_vni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(pkt))
            verify_packet_list_any(self, [geneve_pkt1, geneve_pkt2], [2, 2])

            print "Sending packet from Geneve port2 to Access port1"
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x1234,
                                    inner_frame=pkt)

            self.dataplane.send(2, str(geneve_pkt))
            verify_packets(self, pkt, [1])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2GeneveUnicastLagBasicTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Geneve Lag Basic Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        lag1 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=1)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=2)
        iu1 = interface_union(port_lag_handle = lag1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        lag2 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=3)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=4)
        iu2 = interface_union(port_lag_handle = lag2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        #encap_type 3 is vxlan
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        udp = switcht_udp_t(src_port=1234, dst_port=6081)
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp = switcht_udp_tcp_t(udp = udp)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=17, u=udp_tcp)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        encap_info = switcht_encap_info_t(encap_type=6)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop1)

        try:
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Lag Geneve port3 to Access Lag"
            self.dataplane.send(3, str(geneve_pkt))
            verify_packets_any(self, pkt, [1, 2])

            print "Sending packet from Lag Geneve port4 to Access Lag"
            self.dataplane.send(4, str(geneve_pkt))
            verify_packets_any(self, pkt, [1, 2])

            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    geneve_vni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Lag Access port1 to Geneve Lag"
            self.dataplane.send(1, str(pkt))
            verify_packets_any(self, geneve_pkt, [3, 4])

            print "Sending packet from Lag Access port2 to Geneve Lag"
            self.dataplane.send(2, str(pkt))
            verify_packets_any(self, geneve_pkt, [3, 4])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=1)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=2)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=3)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=4)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_lag_delete(device, lag1)
            self.client.switcht_api_lag_delete(device, lag2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2NvgreUnicastLagBasicTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Nvgre Lag Basic Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        lag1 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=1)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=2)
        iu1 = interface_union(port_lag_handle = lag1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        lag2 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=3)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=4)
        iu2 = interface_union(port_lag_handle = lag2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        #encap_type 3 is vxlan
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=47)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        encap_info = switcht_encap_info_t(encap_type=5)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop1)

        try:
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            nvgre_pkt = simple_nvgre_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Lag Nvgre port3 to Access Lag"
            self.dataplane.send(3, str(nvgre_pkt))
            verify_packets_any(self, pkt, [1, 2])

            print "Sending packet from Lag Nvgre port4 to Access Lag"
            self.dataplane.send(4, str(nvgre_pkt))
            verify_packets_any(self, pkt, [1, 2])

            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            nvgre_pkt = simple_nvgre_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Lag Access port1 to Nvgre Lag"
            self.dataplane.send(1, str(pkt))
            verify_packets_any(self, nvgre_pkt, [3, 4])

            print "Sending packet from Lag Access port2 to Nvgre Lag"
            self.dataplane.send(2, str(pkt))
            verify_packets_any(self, nvgre_pkt, [3, 4])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=1)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=2)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=3)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=4)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_lag_delete(device, lag1)
            self.client.switcht_api_lag_delete(device, lag2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2LNSubIntfEncapTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)
        pv1 = switcht_port_vlan_t(port_lag_handle=1, vlan_id=10)
        iu1 = interface_union(port_vlan = pv1)
        i_info1 = switcht_interface_info_t(device=0, type=9, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        pv2 = switcht_port_vlan_t(port_lag_handle=2, vlan_id=20)
        iu2 = interface_union(port_vlan = pv2)
        i_info2 = switcht_interface_info_t(device=0, type=9, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        lognet_info = switcht_logical_network_t(type=4, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, if1)

        try:
            print "Sending L2 packet - port 1(vlan 10) -> port 2(vlan 20)"
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    dl_vlan_enable=True,
                                    vlan_vid=10,
                                    ip_dst='10.0.0.1',
                                    ip_id=102,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    dl_vlan_enable=True,
                                    vlan_vid=20,
                                    ip_id=102,
                                    ip_ttl=64)
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])

            print "Sending L2 packet - port 2(vlan 20) -> port 1(vlan 10)"
            pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                    eth_src='00:11:11:11:11:11',
                                    dl_vlan_enable=True,
                                    vlan_vid=20,
                                    ip_dst='10.0.0.1',
                                    ip_id=102,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                    dl_vlan_enable=True,
                                    vlan_vid=10,
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='10.0.0.1',
                                    ip_id=102,
                                    ip_ttl=64)
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])

        finally:
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if2)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2VxlanToGeneveUnicastBasicTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Geneve-Vxlan Basic Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        #encap_type 3 is vxlan
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a geneve tunnel interface
        udp3 = switcht_udp_t(src_port=1234, dst_port=6081)
        src_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp3 = switcht_udp_tcp_t(udp = udp3)
        ip_encap3 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip3, dst_ip=dst_ip3, ttl=60, proto=17, u=udp_tcp3)
        tunnel_encap3 = switcht_tunnel_encap_t(ip_encap=ip_encap3)
        encap_info3 =  switcht_encap_info_t(encap_type=6)
        iu3 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap3, encap_info=encap_info3, out_if=if1)
        if3 = self.client.switcht_api_tunnel_interface_create(device, 0, iu3)

        # Create a vxlan tunnel interface
        udp4 = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.1', prefix_length=32)
        dst_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.3', prefix_length=32)
        udp_tcp4 = switcht_udp_tcp_t(udp = udp4)
        ip_encap4 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip4, dst_ip=dst_ip4, ttl=60, proto=17, u=udp_tcp4)
        tunnel_encap4 = switcht_tunnel_encap_t(ip_encap=ip_encap4)
        encap_info4 =  switcht_encap_info_t(encap_type=3)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap4, encap_info=encap_info4, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if3)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key3 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop3 = self.client.switcht_api_nhop_create(device, nhop_key3)
        neighbor_entry3 = switcht_neighbor_info_t(nhop_handle=nhop3,
                                                  interface_handle=if3,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip3,
                                                  rw_type=0, neigh_type=7)
        neighbor3 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry3)

        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if3, mac_addr='00:33:33:33:33:33', ip_addr=src_ip3)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        nhop_key4 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop4 = self.client.switcht_api_nhop_create(device, nhop_key4)
        neighbor_entry4 = switcht_neighbor_info_t(nhop_handle=nhop4,
                                                  interface_handle=if4,
                                                  mac_addr='00:44:44:44:44:44',
                                                  ip_addr=src_ip4,
                                                  rw_type=0, neigh_type=7)
        neighbor4 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry4)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:44:44:44:44:44', ip_addr=src_ip4)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, nhop3)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop4)

        print "L2 Tunnel Splicing - Geneve <-> Vxlan (Basic Mode)"
        print "Sending packet from Geneve port1 to Vxlan port2"

        try:
            pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x1234,
                                    inner_frame=pkt)

            vxlan_pkt1 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            vxlan_pkt2 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=108,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            self.dataplane.send(1, str(geneve_pkt))
            verify_packet_list_any(self, [vxlan_pkt1, vxlan_pkt2], [2, 2])

            print "Sending packet from Vxlan port2 to Geneve port1"
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            geneve_pkt1 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=9604,
                                    with_udp_chksum=False,
                                    geneve_vni=0x1234,
                                    inner_frame=pkt)
            geneve_pkt2 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    geneve_vni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(2, str(vxlan_pkt))
            verify_packet_list_any(self, [geneve_pkt1, geneve_pkt2], [1, 1])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor3)
            self.client.switcht_api_nhop_delete(device, nhop3)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor4)
            self.client.switcht_api_nhop_delete(device, nhop4)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if3)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if3)
            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2VxlanToGeneveUnicastLagBasicTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Vxlan-Geneve Lag Basic Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        lag1 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=1)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=2)
        iu1 = interface_union(port_lag_handle = lag1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        lag2 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=3)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=4)
        iu2 = interface_union(port_lag_handle = lag2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        #encap_type 3 is vxlan
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a geneve tunnel interface
        udp3 = switcht_udp_t(src_port=1234, dst_port=6081)
        src_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp3 = switcht_udp_tcp_t(udp = udp3)
        ip_encap3 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip3, dst_ip=dst_ip3, ttl=60, proto=17, u=udp_tcp3)
        tunnel_encap3 = switcht_tunnel_encap_t(ip_encap=ip_encap3)
        encap_info3 =  switcht_encap_info_t(encap_type=6)
        iu3 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap3, encap_info=encap_info3, out_if=if1)
        if3 = self.client.switcht_api_tunnel_interface_create(device, 0, iu3)

        # Create a vxlan tunnel interface
        udp4 = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.1', prefix_length=32)
        dst_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.3', prefix_length=32)
        udp_tcp4 = switcht_udp_tcp_t(udp = udp4)
        ip_encap4 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip4, dst_ip=dst_ip4, ttl=60, proto=17, u=udp_tcp4)
        tunnel_encap4 = switcht_tunnel_encap_t(ip_encap=ip_encap4)
        encap_info4 =  switcht_encap_info_t(encap_type=3)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap4, encap_info=encap_info4, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if3)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key3 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop3 = self.client.switcht_api_nhop_create(device, nhop_key3)
        neighbor_entry3 = switcht_neighbor_info_t(nhop_handle=nhop3,
                                                  interface_handle=if3,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip3,
                                                  rw_type=0, neigh_type=7)
        neighbor3 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry3)

        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if3, mac_addr='00:33:33:33:33:33', ip_addr=src_ip3)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        nhop_key4 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop4 = self.client.switcht_api_nhop_create(device, nhop_key4)
        neighbor_entry4 = switcht_neighbor_info_t(nhop_handle=nhop4,
                                                  interface_handle=if4,
                                                  mac_addr='00:44:44:44:44:44',
                                                  ip_addr=src_ip4,
                                                  rw_type=0, neigh_type=7)
        neighbor4 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry4)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:44:44:44:44:44', ip_addr=src_ip4)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, nhop3)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop4)

        print "L2 Tunnel Splicing - Geneve <-> Vxlan (Basic Mode)"
        try:
            pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            geneve_pkt = simple_geneve_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x1234,
                                    inner_frame=pkt)
            vxlan_pkt = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Geneve member port1 to Vxlan lag"
            self.dataplane.send(1, str(geneve_pkt))
            verify_packets_any(self, vxlan_pkt, [3, 4])

            print "Sending packet from Geneve member port2 to Vxlan lag"
            self.dataplane.send(2, str(geneve_pkt))
            verify_packets_any(self, vxlan_pkt, [3, 4])

            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            vxlan_pkt = simple_vxlan_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            geneve_pkt = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=9604,
                                    with_udp_chksum=False,
                                    geneve_vni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Vxlan member port1 to Geneve lag"
            self.dataplane.send(3, str(vxlan_pkt))
            verify_packets_any(self, geneve_pkt, [1, 2])

            print "Sending packet from Vxlan member port2 to Geneve lag"
            self.dataplane.send(4, str(vxlan_pkt))
            verify_packets_any(self, geneve_pkt, [1, 2])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor3)
            self.client.switcht_api_nhop_delete(device, nhop3)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor4)
            self.client.switcht_api_nhop_delete(device, nhop4)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if3)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if3)
            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=1)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=2)
            self.client.switcht_api_lag_delete(device, lag1)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=3)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=4)
            self.client.switcht_api_lag_delete(device, lag2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2VxlanUnicastEnhancedTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Vxlan Enhanced Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        udp = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp = switcht_udp_tcp_t(udp = udp)
        vxlan = switcht_vxlan_id_t(vnid=0x1234)
        bt = switcht_bridge_type(vxlan_info=vxlan)
        encap_info = switcht_encap_info_t(encap_type=3, u=bt)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=17, u=udp_tcp)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop1)

        try:
            print "Sending packet from Vxlan port2 to Access port1"
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            self.dataplane.send(2, str(vxlan_pkt))
            verify_packets(self, pkt, [1])

            print "Sending packet from Access port1 to Vxlan port2"
            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt1 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            vxlan_pkt2 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(pkt))
            verify_packet_list_any(self, [vxlan_pkt1, vxlan_pkt2], [2, 2])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2VxlanUnicastLagEnhancedTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Vxlan Lag Enahanced Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        lag1 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=1)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=2)
        iu1 = interface_union(port_lag_handle = lag1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        lag2 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=3)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=4)
        iu2 = interface_union(port_lag_handle = lag2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        #encap_type 3 is vxlan
        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        udp = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp = switcht_udp_tcp_t(udp = udp)
        vxlan = switcht_vxlan_id_t(vnid=0x1234)
        bt = switcht_bridge_type(vxlan_info=vxlan)
        encap_info = switcht_encap_info_t(encap_type=3, u=bt)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=17, u=udp_tcp)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop1)

        try:
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Lag Vxlan port3 to Access Lag"
            self.dataplane.send(3, str(vxlan_pkt))
            verify_packets_any(self, pkt, [1, 2])

            print "Sending packet from Lag Vxlan port4 to Access Lag"
            self.dataplane.send(4, str(vxlan_pkt))
            verify_packets_any(self, pkt, [1, 2])

            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Lag Access port1 to Vxlan Lag"
            self.dataplane.send(1, str(pkt))
            verify_packets_any(self, vxlan_pkt, [3, 4])

            print "Sending packet from Lag Access port2 to Vxlan Lag"
            self.dataplane.send(2, str(pkt))
            verify_packets_any(self, vxlan_pkt, [3, 4])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=1)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=2)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=3)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=4)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_lag_delete(device, lag1)
            self.client.switcht_api_lag_delete(device, lag2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2VxlanToGeneveUnicastEnhancedTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Geneve-Vxlan Enhanced Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a geneve tunnel interface
        udp3 = switcht_udp_t(src_port=1234, dst_port=6081)
        src_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp3 = switcht_udp_tcp_t(udp = udp3)
        geneve3 = switcht_geneve_id_t(vni=0x4321)
        bt3 = switcht_bridge_type(geneve_info=geneve3)
        encap_info3 = switcht_encap_info_t(encap_type=6, u=bt3)
        ip_encap3 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip3, dst_ip=dst_ip3, ttl=60, proto=17, u=udp_tcp3)
        tunnel_encap3 = switcht_tunnel_encap_t(ip_encap=ip_encap3)
        iu3 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap3, encap_info=encap_info3, out_if=if1)
        if3 = self.client.switcht_api_tunnel_interface_create(device, 0, iu3)

        # Create a vxlan tunnel interface
        udp4 = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.1', prefix_length=32)
        dst_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.3', prefix_length=32)
        udp_tcp4 = switcht_udp_tcp_t(udp = udp4)
        vxlan4 = switcht_vxlan_id_t(vnid=0x1234)
        bt4 = switcht_bridge_type(vxlan_info=vxlan4)
        encap_info4 = switcht_encap_info_t(encap_type=3, u=bt4)
        ip_encap4 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip4, dst_ip=dst_ip4, ttl=60, proto=17, u=udp_tcp4)
        tunnel_encap4 = switcht_tunnel_encap_t(ip_encap=ip_encap4)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap4, encap_info=encap_info4, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if3)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key3 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop3 = self.client.switcht_api_nhop_create(device, nhop_key3)
        neighbor_entry3 = switcht_neighbor_info_t(nhop_handle=nhop3,
                                                  interface_handle=if3,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip3,
                                                  rw_type=0, neigh_type=7)
        neighbor3 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry3)

        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if3, mac_addr='00:33:33:33:33:33', ip_addr=src_ip3)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        nhop_key4 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop4 = self.client.switcht_api_nhop_create(device, nhop_key4)
        neighbor_entry4 = switcht_neighbor_info_t(nhop_handle=nhop4,
                                                  interface_handle=if4,
                                                  mac_addr='00:44:44:44:44:44',
                                                  ip_addr=src_ip4,
                                                  rw_type=0, neigh_type=7)
        neighbor4 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry4)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:44:44:44:44:44', ip_addr=src_ip4)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, nhop3)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop4)

        print "L2 Tunnel Splicing - Geneve <-> Vxlan (Enhanced Mode)"
        print "Sending packet from Geneve port1 to Vxlan port2"

        try:
            pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)

            vxlan_pkt1 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            vxlan_pkt2 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=108,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(geneve_pkt))
            verify_packet_list_any(self, [vxlan_pkt1, vxlan_pkt2], [2, 2])

            print "Sending packet from Vxlan port2 to Geneve port1"
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            geneve_pkt1 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=9604,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            geneve_pkt2 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            self.dataplane.send(2, str(vxlan_pkt))
            verify_packet_list_any(self, [geneve_pkt1, geneve_pkt2], [1, 1])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor3)
            self.client.switcht_api_nhop_delete(device, nhop3)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor4)
            self.client.switcht_api_nhop_delete(device, nhop4)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if3)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if3)
            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2VxlanToGeneveUnicastLagEnhancedTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Geneve-Vxlan Lag Enhanced Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        lag1 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=1)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=2)
        iu1 = interface_union(port_lag_handle = lag1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        lag2 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=3)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=4)
        iu2 = interface_union(port_lag_handle = lag2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a geneve tunnel interface
        udp3 = switcht_udp_t(src_port=1234, dst_port=6081)
        src_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp3 = switcht_udp_tcp_t(udp = udp3)
        geneve3 = switcht_geneve_id_t(vni=0x4321)
        bt3 = switcht_bridge_type(geneve_info=geneve3)
        encap_info3 = switcht_encap_info_t(encap_type=6, u=bt3)
        ip_encap3 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip3, dst_ip=dst_ip3, ttl=60, proto=17, u=udp_tcp3)
        tunnel_encap3 = switcht_tunnel_encap_t(ip_encap=ip_encap3)
        iu3 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap3, encap_info=encap_info3, out_if=if1)
        if3 = self.client.switcht_api_tunnel_interface_create(device, 0, iu3)

        # Create a vxlan tunnel interface
        udp4 = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.1', prefix_length=32)
        dst_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.3', prefix_length=32)
        udp_tcp4 = switcht_udp_tcp_t(udp = udp4)
        vxlan4 = switcht_vxlan_id_t(vnid=0x1234)
        bt4 = switcht_bridge_type(vxlan_info=vxlan4)
        encap_info4 = switcht_encap_info_t(encap_type=3, u=bt4)
        ip_encap4 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip4, dst_ip=dst_ip4, ttl=60, proto=17, u=udp_tcp4)
        tunnel_encap4 = switcht_tunnel_encap_t(ip_encap=ip_encap4)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap4, encap_info=encap_info4, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if3)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        nhop_key3 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop3 = self.client.switcht_api_nhop_create(device, nhop_key3)
        neighbor_entry3 = switcht_neighbor_info_t(nhop_handle=nhop3,
                                                  interface_handle=if3,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip3,
                                                  rw_type=0, neigh_type=7)
        neighbor3 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry3)

        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if3, mac_addr='00:33:33:33:33:33', ip_addr=src_ip3)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        nhop_key4 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop4 = self.client.switcht_api_nhop_create(device, nhop_key4)
        neighbor_entry4 = switcht_neighbor_info_t(nhop_handle=nhop4,
                                                  interface_handle=if4,
                                                  mac_addr='00:44:44:44:44:44',
                                                  ip_addr=src_ip4,
                                                  rw_type=0, neigh_type=7)
        neighbor4 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry4)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:44:44:44:44:44', ip_addr=src_ip4)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, nhop3)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop4)

        print "L2 Tunnel Splicing - Geneve <-> Vxlan (Enahanced Mode)"

        try:
            pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Geneve member port1 to Vxlan lag"
            self.dataplane.send(1, str(geneve_pkt))
            verify_packets_any(self, vxlan_pkt, [3, 4])

            print "Sending packet from Geneve member port2 to Vxlan lag"
            self.dataplane.send(2, str(geneve_pkt))
            verify_packets_any(self, vxlan_pkt, [3, 4])

            print "Sending packet from Vxlan port2 to Geneve port1"
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            geneve_pkt = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=9604,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)

            print "Sending packet from Vxlan member port1 to Geneve lag"
            self.dataplane.send(3, str(vxlan_pkt))
            verify_packets_any(self, geneve_pkt, [1, 2])

            print "Sending packet from Vxlan member port2 to Geneve lag"
            self.dataplane.send(4, str(vxlan_pkt))
            verify_packets_any(self, geneve_pkt, [1, 2])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor3)
            self.client.switcht_api_nhop_delete(device, nhop3)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor4)
            self.client.switcht_api_nhop_delete(device, nhop4)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if3)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if3)
            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=1)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=2)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=3)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=4)

            self.client.switcht_api_lag_delete(device, lag1)
            self.client.switcht_api_lag_delete(device, lag2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2VxlanFloodBasicTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Vxlan Basic Mode Flood Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=4, u=iu3, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        # Create a logical network (LN)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        #encap_type 3 is vxlan
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        flags = switcht_interface_flags(flood_enabled=1)
        udp = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp = switcht_udp_tcp_t(udp = udp)
        encap_info = switcht_encap_info_t(encap_type=3)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=17, u=udp_tcp)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if3, flags=flags)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if2)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        try:
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Vxlan port3 to Access port1 and Access port2"
            self.dataplane.send(3, str(vxlan_pkt))
            verify_packets(self, pkt, [1, 2])

            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=9604,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            print "Sending packet from Access port1 to Access port2 and Vxlan port3"
            self.dataplane.send(1, str(pkt))
            verify_packet_list(self, [pkt, vxlan_pkt], [2, 3])

            print "Sending packet from Access port2 to Access port1 and Vxlan port3"
            self.dataplane.send(2, str(pkt))
            verify_packet_list(self, [pkt, vxlan_pkt], [1, 3])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if2)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)

class L3VxlanUnicastBasicTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L3 Vxlan Basic Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        # Create a logical network (LN)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        #encap_type 3 is vxlan
        ln_flags = switcht_ln_flags(ipv4_unicast_enabled=1)
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=1800, vrf=vrf, rmac_handle=rmac, flags=ln_flags)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        udp = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp = switcht_udp_tcp_t(udp = udp)
        encap_info = switcht_encap_info_t(encap_type=3)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=17, u=udp_tcp)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if2)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        i_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='10.10.10.1', prefix_length=32)
        nhop_key1 = switcht_nhop_key_t(intf_handle=if1, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if1,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=i_ip1,
                                                  rw_type=1)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='20.20.20.1', prefix_length=32)
        nhop_key2 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop2 = self.client.switcht_api_nhop_create(device, nhop_key2)
        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=nhop2,
                                                  interface_handle=if4,
                                                  mac_addr='00:44:44:44:44:44',
                                                  ip_addr=i_ip2,
                                                  rw_type=1, neigh_type=7)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        neighbor_entry3 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:55:55:55:55:55', ip_addr=src_ip)
        neighbor3 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry3)

        self.client.switcht_api_l3_route_add(device, vrf, i_ip1, nhop1)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip2, nhop2)

        try:
            print "Sending packet from Access port1 to Vxlan port2"
            pkt1 = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_dst='20.20.20.1',
                                    ip_src='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            pkt2 = simple_tcp_packet(eth_src='00:77:66:55:44:33',
                                     eth_dst='00:44:44:44:44:44',
                                    ip_dst='20.20.20.1',
                                    ip_src='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=63)
            vxlan_pkt1 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:55:55:55:55:55',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11587,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt2)
            vxlan_pkt2 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:55:55:55:55:55',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt2)
            self.dataplane.send(1, str(pkt1))
            verify_packet_list_any(self, [vxlan_pkt1, vxlan_pkt2], [2, 2])

            print "Sending packet from Vxlan port2 to Access port1"
            pkt1 = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_src='20.20.20.1',
                                    ip_id=108,
                                    ip_ttl=64)
            vxlan_pkt = simple_vxlan_packet(
                                    eth_src='00:44:44:44:44:44',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt1)
            pkt2 = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='20.20.20.1',
                                    ip_id=108,
                                    ip_ttl=63)
            self.dataplane.send(2, str(vxlan_pkt))
            verify_packets(self, pkt2, [1])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip1, nhop1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip2, nhop2)
            self.client.switcht_api_nhop_delete(device, nhop2)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor3)

            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2DynamicMacLearnTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)
        self.client.switcht_api_vlan_aging_interval_set(vlan, 60)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=2, u=iu3, mac='00:77:66:55:44:33', label=0)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        iu4 = interface_union(port_lag_handle = 4)
        i_info4 = switcht_interface_info_t(device=0, type=2, u=iu4, mac='00:77:66:55:44:33', label=0)
        if4 = self.client.switcht_api_interface_create(device, i_info4)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        vlan_port3 = switcht_vlan_port_t(handle=if3, tagging_mode=0)
        vlan_port4 = switcht_vlan_port_t(handle=if4, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port3)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port4)

        for port in range (1, 5):
            for mac_offset in range (1, 9):
                dst_mac = '00:33:33:33:' + str(port) + ':' + str(mac_offset)
                src_mac = '00:22:22:22:' + str(port) + ':' + str(mac_offset)
                pkt = simple_tcp_packet(eth_dst=dst_mac,
                                        eth_src=src_mac,
                                        ip_dst='10.10.10.1',
                                        ip_src='20.20.20.1',
                                        ip_id=108,
                                        ip_ttl=64)
                self.dataplane.send(port, str(pkt))

        time.sleep(3)

        try:
            for src_port in range (1, 5):
                for dst_port in range (1, 5):
                    for mac_offset in range (1, 9):
                        if src_port == dst_port:
                            continue
                        dst_mac = '00:22:22:22:' + str(dst_port) + ':' + str(mac_offset)
                        src_mac = '00:22:22:22:' + str(src_port) + ':' + str(mac_offset)
                        pkt = simple_tcp_packet(eth_dst=dst_mac,
                                                eth_src=src_mac,
                                                ip_dst='10.10.10.1',
                                                ip_src='20.20.20.1',
                                                ip_id=108,
                                                ip_ttl=64)
                        self.dataplane.send(src_port, str(pkt))
                        verify_packets(self, pkt, [dst_port])

        finally:
            time.sleep(60)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port3)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port4)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)
            self.client.switcht_api_interface_delete(device, if4)

            self.client.switcht_api_vlan_delete(device, vlan)

class L2MplsPopTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf, rmac_handle=rmac)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        mpls_tag1 = switcht_mpls_t(label=0xabcde, exp=0x5, ttl=0x30, bos=0)
        mpls_tag2 = switcht_mpls_t(label=0x54321, exp=0x2, ttl=0x40, bos=1)
        pop_info=switcht_mpls_pop_t(tag=[mpls_tag1, mpls_tag2], count=2)
        mpls_info = switcht_mpls_info_t(pop_info=pop_info)
        mpls_encap = switcht_mpls_encap_t(mpls_type=0, mpls_action=0, mpls_mode=2, u=mpls_info, bd_handle=ln1)
        tunnel_encap = switcht_tunnel_encap_t(mpls_encap=mpls_encap)
        flags=switcht_interface_flags(flood_enabled=0, core_intf=0)
        iu3 = switcht_tunnel_info_t(encap_mode=1, tunnel_encap=tunnel_encap, out_if=if1, flags=flags)
        if3 = self.client.switcht_api_tunnel_interface_create(device, 0, iu3)

        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if2)
        self.client.switcht_api_logical_network_member_add(device, ln1, if3)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if3)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, if2)

        try:
            tag1 = {'label' : 0xabcde, 'tc' : 0x5, 'ttl' : 0xAA, 's' : 0x0}
            tag2 = {'label' : 0x54321, 'tc' : 0x2, 'ttl' : 0xBB, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='20.20.20.1',
                                    ip_src='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=63)
            mpls_pkt = simple_mpls_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:11:11:11:11:11',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(mpls_pkt))
            verify_packets(self, pkt, [2])
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if2)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if3)

            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2MplsPushTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf, rmac_handle=rmac)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        mpls_tag1 = switcht_mpls_t(label=0xabcde, exp=0x5, ttl=0x30, bos=0)
        mpls_tag2 = switcht_mpls_t(label=0x54321, exp=0x2, ttl=0x40, bos=1)
        push_info=switcht_mpls_push_t(tag=[mpls_tag1, mpls_tag2], count=2)
        mpls_info = switcht_mpls_info_t(push_info=push_info)
        mpls_encap = switcht_mpls_encap_t(mpls_type=0, mpls_action=1, mpls_mode=0, u=mpls_info, bd_handle=ln1)
        tunnel_encap = switcht_tunnel_encap_t(mpls_encap=mpls_encap)
        flags=switcht_interface_flags(flood_enabled=0, core_intf=0)
        iu3 = switcht_tunnel_info_t(encap_mode=1, tunnel_encap=tunnel_encap, out_if=if1, flags=flags)
        if3 = self.client.switcht_api_tunnel_interface_create(device, 0, iu3)

        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if2)
        self.client.switcht_api_logical_network_member_add(device, ln1, if3)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)

        #neighbor type 5 is push l2vpn
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  neigh_type=5,
                                                  interface_handle= if3,
                                                  mpls_label=0,
                                                  header_count=2)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if3, mac_addr='00:44:44:44:44:44')
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:11:11:11:11:11', 2, if2)
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:22:22:22:22:22', 2, nhop1)

        try:
            tag1 = {'label' : 0xabcde, 'tc' : 0x5, 'ttl' : 0x30, 's' : 0x0}
            tag2 = {'label' : 0x54321, 'tc' : 0x2, 'ttl' : 0x40, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='20.20.20.1',
                                    ip_src='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=63)
            mpls_pkt = simple_mpls_packet(eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt)
            self.dataplane.send(2, str(pkt))
            verify_packets(self, mpls_pkt, [1])
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if2)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if3)

            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2MplsSwapTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf, rmac_handle=rmac)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if2)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        old_mpls_tag = switcht_mpls_t(label=0xabcde, exp=0x5, ttl=0x30, bos=0)
        new_mpls_tag = switcht_mpls_t(label=0x98765, exp=0x9, ttl=0x30, bos=0)
        inner_tag = switcht_mpls_t(label=0x54321, exp=0x2, ttl=0x40, bos=1)
        swap_info=switcht_mpls_swap_t(old_tag=old_mpls_tag, new_tag=new_mpls_tag)
        mpls_info = switcht_mpls_info_t(swap_info=swap_info)
        mpls_encap = switcht_mpls_encap_t(mpls_type=0, mpls_action=2, mpls_mode=1, u=mpls_info, nhop_handle=nhop1)
        self.client.switcht_api_mpls_tunnel_transit_create(device, mpls_encap)

        #neighbor type 2 is swap l2vpn
        neighbor_entry1 = switcht_neighbor_info_t(neigh_type=2, nhop_handle=nhop1, interface_handle=if2, mac_addr='00:44:44:44:44:44', mpls_label=0x98765, rw_type=0)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        try:
            old_tag = {'label' : 0xabcde, 'tc' : 0x5, 'ttl' : 0x30, 's' : 0x0}
            new_tag = {'label' : 0x98765, 'tc' : 0x5, 'ttl' : 0x2f, 's' : 0x0}
            inner_tag = {'label' : 0x54321, 'tc' : 0x2, 'ttl' : 0x40, 's' : 0x1}
            mpls_tags1 = [old_tag, inner_tag]
            mpls_tags2 = [new_tag, inner_tag]
            pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='20.20.20.1',
                                    ip_src='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=63)
            mpls_pkt1 = simple_mpls_packet(eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    mpls_tags=mpls_tags1,
                                    inner_frame=pkt)
            mpls_pkt2 = simple_mpls_packet(eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    mpls_tags=mpls_tags2,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(mpls_pkt1))
            verify_packets(self, mpls_pkt2, [2])
        finally:
            self.client.switcht_api_mpls_tunnel_transit_delete(device, mpls_encap)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if2)

            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L3MplsPopTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        ln_flags = switcht_ln_flags(ipv4_unicast_enabled=1)
        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf, rmac_handle=rmac, flags=ln_flags)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        mpls_tag1 = switcht_mpls_t(label=0xabcde, exp=0x5, ttl=0x30, bos=0)
        mpls_tag2 = switcht_mpls_t(label=0x54321, exp=0x2, ttl=0x40, bos=1)
        pop_info=switcht_mpls_pop_t(tag=[mpls_tag1, mpls_tag2], count=2)
        mpls_info = switcht_mpls_info_t(pop_info=pop_info)
        mpls_encap = switcht_mpls_encap_t(mpls_type=1, mpls_action=0, mpls_mode=2, u=mpls_info, bd_handle=ln1, vrf_handle=vrf)
        tunnel_encap = switcht_tunnel_encap_t(mpls_encap=mpls_encap)
        flags=switcht_interface_flags(flood_enabled=0, core_intf=0)
        iu3 = switcht_tunnel_info_t(encap_mode=1, tunnel_encap=tunnel_encap, out_if=if1, flags=flags)
        if3 = self.client.switcht_api_tunnel_interface_create(device, 0, iu3)

        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if3)

        i_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='20.20.20.1', prefix_length=32)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(device, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop, interface_handle=if2, mac_addr='00:33:33:33:33:33', ip_addr=i_ip3, rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop)

        try:
            tag1 = {'label' : 0xabcde, 'tc' : 0x5, 'ttl' : 0xAA, 's' : 0x0}
            tag2 = {'label' : 0x54321, 'tc' : 0x2, 'ttl' : 0xBB, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            pkt1 = simple_ip_only_packet(ip_dst='20.20.20.1',
                                    ip_src='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64,
                                    pktlen=86)
            mpls_pkt = simple_mpls_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:11:11:11:11:11',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt1)
            pkt2 = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='20.20.20.1',
                                    ip_src='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=63)
            self.dataplane.send(1, str(mpls_pkt))
            verify_packets(self, pkt2, [2])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, nhop)
            self.client.switcht_api_nhop_delete(device, nhop)

            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if3)

            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if3)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L3MplsPushTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf, rmac_handle=rmac)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        mpls_tag1 = switcht_mpls_t(label=0xabcde, exp=0x5, ttl=0x30, bos=0)
        mpls_tag2 = switcht_mpls_t(label=0x54321, exp=0x2, ttl=0x40, bos=1)
        push_info=switcht_mpls_push_t(tag=[mpls_tag1, mpls_tag2], count=2)
        mpls_info = switcht_mpls_info_t(push_info=push_info)
        mpls_encap = switcht_mpls_encap_t(mpls_type=1, mpls_action=1, mpls_mode=0, u=mpls_info, bd_handle=ln1)
        tunnel_encap = switcht_tunnel_encap_t(mpls_encap=mpls_encap)
        flags=switcht_interface_flags(flood_enabled=0, core_intf=0)
        iu3 = switcht_tunnel_info_t(encap_mode=1, tunnel_encap=tunnel_encap, out_if=if1, flags=flags)
        if3 = self.client.switcht_api_tunnel_interface_create(device, 0, iu3)

        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if3)

        i_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='20.20.20.1', prefix_length=32)
        nhop_key1 = switcht_nhop_key_t(intf_handle=if3, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)
        #neighbor type 6 is push l3vpn
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  neigh_type=6,
                                                  interface_handle=if3,
                                                  mpls_label=0,
                                                  header_count=2,
                                                  rw_type=1)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)
        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if3, mac_addr='00:44:44:44:44:44')
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop1)

        try:
            tag1 = {'label' : 0xabcde, 'tc' : 0x5, 'ttl' : 0x30, 's' : 0x0}
            tag2 = {'label' : 0x54321, 'tc' : 0x2, 'ttl' : 0x40, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            pkt1 = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='20.20.20.1',
                                    ip_src='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            pkt2 = simple_ip_only_packet(ip_dst='20.20.20.1',
                                    ip_src='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=63,
                                    pktlen=86)
            mpls_pkt = simple_mpls_packet(eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt2)
            self.dataplane.send(2, str(pkt1))
            verify_packets(self, mpls_pkt, [1])
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:22:22:22:22:22')

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)
            self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, nhop1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if3)

            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if3)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2TunnelSplicingExtreme1Test(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Geneve-Vxlan-Mpls Enhanced Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=4, u=iu3, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        # Create a logical network (LN)
        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a geneve tunnel interface
        udp4 = switcht_udp_t(src_port=1234, dst_port=6081)
        src_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp4 = switcht_udp_tcp_t(udp = udp4)
        geneve4 = switcht_geneve_id_t(vni=0x4321)
        bt4 = switcht_bridge_type(geneve_info=geneve4)
        encap_info4 = switcht_encap_info_t(encap_type=6, u=bt4)
        ip_encap4 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip4, dst_ip=dst_ip4, ttl=60, proto=17, u=udp_tcp4)
        tunnel_encap4 = switcht_tunnel_encap_t(ip_encap=ip_encap4)
        iu4 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap4, encap_info=encap_info4, out_if=if1)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        # Create a vxlan tunnel interface
        udp5 = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip5 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.1', prefix_length=32)
        dst_ip5 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.3', prefix_length=32)
        udp_tcp5 = switcht_udp_tcp_t(udp = udp5)
        vxlan5 = switcht_vxlan_id_t(vnid=0x1234)
        bt5 = switcht_bridge_type(vxlan_info=vxlan5)
        encap_info5 = switcht_encap_info_t(encap_type=3, u=bt5)
        ip_encap5 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip5, dst_ip=dst_ip5, ttl=60, proto=17, u=udp_tcp5)
        tunnel_encap5 = switcht_tunnel_encap_t(ip_encap=ip_encap5)
        iu5 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap5, encap_info=encap_info5, out_if=if2)
        if5 = self.client.switcht_api_tunnel_interface_create(device, 0, iu5)

        #Create a mpls push interface
        mpls_tag1 = switcht_mpls_t(label=0xaaaaa, exp=0x1, ttl=0x30, bos=0)
        mpls_tag2 = switcht_mpls_t(label=0xbbbbb, exp=0x2, ttl=0x40, bos=1)
        push_info=switcht_mpls_push_t(tag=[mpls_tag1, mpls_tag2], count=2)
        mpls_info = switcht_mpls_info_t(push_info=push_info)
        mpls_encap = switcht_mpls_encap_t(mpls_type=0, mpls_action=1, mpls_mode=0, u=mpls_info, bd_handle=ln1)
        tunnel_encap = switcht_tunnel_encap_t(mpls_encap=mpls_encap)
        flags=switcht_interface_flags(flood_enabled=0, core_intf=0)
        iu6 = switcht_tunnel_info_t(encap_mode=1, tunnel_encap=tunnel_encap, out_if=if3, flags=flags)
        if6 = self.client.switcht_api_tunnel_interface_create(device, 0, iu6)

        #Create a mpls pop interface
        mpls_tag1 = switcht_mpls_t(label=0xccccc, exp=0x1, ttl=0x30, bos=0)
        mpls_tag2 = switcht_mpls_t(label=0xddddd, exp=0x2, ttl=0x40, bos=1)
        pop_info=switcht_mpls_pop_t(tag=[mpls_tag1, mpls_tag2], count=2)
        mpls_info = switcht_mpls_info_t(pop_info=pop_info)
        mpls_encap = switcht_mpls_encap_t(mpls_type=0, mpls_action=0, mpls_mode=2, u=mpls_info, bd_handle=ln1)
        tunnel_encap = switcht_tunnel_encap_t(mpls_encap=mpls_encap)
        flags=switcht_interface_flags(flood_enabled=0, core_intf=0)
        iu7 = switcht_tunnel_info_t(encap_mode=1, tunnel_encap=tunnel_encap, out_if=if3, flags=flags)
        if7 = self.client.switcht_api_tunnel_interface_create(device, 0, iu7)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)
        self.client.switcht_api_logical_network_member_add(device, ln1, if5)
        self.client.switcht_api_logical_network_member_add(device, ln1, if6)
        self.client.switcht_api_logical_network_member_add(device, ln1, if7)

        nhop_key4 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop4 = self.client.switcht_api_nhop_create(device, nhop_key4)
        neighbor_entry4 = switcht_neighbor_info_t(nhop_handle=nhop4,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip4,
                                                  rw_type=0, neigh_type=7)
        neighbor4 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry4)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip4)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        nhop_key5 = switcht_nhop_key_t(intf_handle=if5, ip_addr_valid=0)
        nhop5 = self.client.switcht_api_nhop_create(device, nhop_key5)
        neighbor_entry5 = switcht_neighbor_info_t(nhop_handle=nhop5,
                                                  interface_handle=if5,
                                                  mac_addr='00:44:44:44:44:44',
                                                  ip_addr=src_ip5,
                                                  rw_type=0, neigh_type=7)
        neighbor5 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry5)
        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if5, mac_addr='00:44:44:44:44:44', ip_addr=src_ip5)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        #neighbor type 5 is push l2vpn
        nhop_key6 = switcht_nhop_key_t(intf_handle=if6, ip_addr_valid=0)
        nhop6 = self.client.switcht_api_nhop_create(device, nhop_key6)
        neighbor_entry6 = switcht_neighbor_info_t(nhop_handle=nhop6, neigh_type=5, interface_handle= if6, mpls_label=0, header_count=2, rw_type=0)
        neighbor6 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry6)
        neighbor_entry3 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if6, mac_addr='00:55:55:55:55:55')
        neighbor3 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry3)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:aa:aa:aa:aa:aa', 2, nhop4) #geneve mac
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:bb:bb:bb:bb:bb', 2, nhop5) #vxlan mac
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:cc:cc:cc:cc:cc', 2, nhop6) #mpls mac

        print "L2 Tunnel Splicing - Geneve <-> Vxlan (Enhanced Mode)"
        print "Sending packet from Geneve port1 to Vxlan port2"

        try:
            pkt = simple_tcp_packet(eth_dst='00:bb:bb:bb:bb:bb',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)

            vxlan_pkt1 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=11250,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            vxlan_pkt2 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=108,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(geneve_pkt))
            verify_packet_list_any(self, [vxlan_pkt1, vxlan_pkt2], [2, 2])

            print "Sending packet from Vxlan port2 to Geneve port1"
            pkt = simple_tcp_packet(eth_dst='00:aa:aa:aa:aa:aa',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            geneve_pkt1 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=5264,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            geneve_pkt2 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            self.dataplane.send(2, str(vxlan_pkt))
            verify_packet_list_any(self, [geneve_pkt1, geneve_pkt2], [1, 1])

            print "Sending packet from Vxlan port2 to Mpls port 3"
            pkt = simple_tcp_packet(eth_dst='00:cc:cc:cc:cc:cc',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            tag1 = {'label' : 0xaaaaa, 'tc' : 0x1, 'ttl' : 0x30, 's' : 0x0}
            tag2 = {'label' : 0xbbbbb, 'tc' : 0x2, 'ttl' : 0x40, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            mpls_pkt = simple_mpls_packet(eth_src='00:77:66:55:44:33',
                                    eth_dst='00:55:55:55:55:55',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt)
            self.dataplane.send(2, str(vxlan_pkt))
            verify_packets(self, mpls_pkt, [3])

            print "Sending packet from Geneve port1 to Mpls port 3"
            pkt = simple_tcp_packet(eth_dst='00:cc:cc:cc:cc:cc',
                                    eth_src='00:11:11:11:11:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)

            tag1 = {'label' : 0xaaaaa, 'tc' : 0x1, 'ttl' : 0x30, 's' : 0x0}
            tag2 = {'label' : 0xbbbbb, 'tc' : 0x2, 'ttl' : 0x40, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            mpls_pkt = simple_mpls_packet(eth_src='00:77:66:55:44:33',
                                    eth_dst='00:55:55:55:55:55',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(geneve_pkt))
            verify_packets(self, mpls_pkt, [3])

            print "Sending packet from Mpls port 3 to Geneve port 1"
            pkt = simple_tcp_packet(eth_dst='00:aa:aa:aa:aa:aa',
                                    eth_src='00:cc:cc:cc:cc:cc',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            tag1 = {'label' : 0xccccc, 'tc' : 0x1, 'ttl' : 0x30, 's' : 0x0}
            tag2 = {'label' : 0xddddd, 'tc' : 0x2, 'ttl' : 0x40, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            mpls_pkt = simple_mpls_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:55:55:55:55:55',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt)
            geneve_pkt1 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=15201,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            geneve_pkt2 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            self.dataplane.send(3, str(mpls_pkt))
            verify_packet_list_any(self, [geneve_pkt1, geneve_pkt2], [1, 1])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor4)
            self.client.switcht_api_nhop_delete(device, nhop4)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor5)
            self.client.switcht_api_nhop_delete(device, nhop5)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor6)
            self.client.switcht_api_nhop_delete(device, nhop6)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor3)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:aa:aa:aa:aa:aa')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:bb:bb:bb:bb:bb')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:cc:cc:cc:cc:cc')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if5)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if6)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if7)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_tunnel_interface_delete(device, if5)
            self.client.switcht_api_tunnel_interface_delete(device, if6)
            self.client.switcht_api_tunnel_interface_delete(device, if7)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)

class L2LagFloodTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Lag and native port flooding - lag1[1, 2], lag2[3, 4], lag3[5, 6], port7, port8"
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)
        self.client.switcht_api_vlan_learning_enabled_set(vlan, 0)

        lag1 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=1)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=2)
        iu1 = interface_union(port_lag_handle = lag1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        lag2 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=3)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag2, side=0, port=4)
        iu2 = interface_union(port_lag_handle = lag2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        lag3 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag3, side=0, port=5)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag3, side=0, port=6)
        iu3 = interface_union(port_lag_handle = lag3)
        i_info3 = switcht_interface_info_t(device=0, type=2, u=iu3, mac='00:77:66:55:44:33', label=0)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        iu4 = interface_union(port_lag_handle = 7)
        i_info4 = switcht_interface_info_t(device=0, type=2, u=iu4, mac='00:77:66:55:44:33', label=0)
        if4 = self.client.switcht_api_interface_create(device, i_info4)

        iu5 = interface_union(port_lag_handle = 8)
        i_info5 = switcht_interface_info_t(device=0, type=2, u=iu5, mac='00:77:66:55:44:33', label=0)
        if5 = self.client.switcht_api_interface_create(device, i_info5)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        vlan_port3 = switcht_vlan_port_t(handle=if3, tagging_mode=0)
        vlan_port4 = switcht_vlan_port_t(handle=if4, tagging_mode=0)
        vlan_port5 = switcht_vlan_port_t(handle=if5, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port3)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port4)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port5)

        try:
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=107,
                                ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=107,
                                ip_ttl=64)

            print "Sending packet from lag1 on port1 -> lag2, lag3, port7, port8"
            self.dataplane.send(1, str(pkt))
            verify_packet_on_set_of_ports(self, exp_pkt, [[3, 4], [5, 6], [7], [8]])
            print "Sending packet from lag1 on port2 -> lag2, lag3, port7, port8"
            self.dataplane.send(2, str(pkt))
            verify_packet_on_set_of_ports(self, exp_pkt, [[3, 4], [5, 6], [7], [8]])
            print "Sending packet from lag2 on port3 -> lag1, lag3, port7, port8"
            self.dataplane.send(3, str(pkt))
            verify_packet_on_set_of_ports(self, exp_pkt, [[1, 2], [5, 6], [7], [8]])
            print "Sending packet from lag2 on port4 -> lag1, lag3, port7, port8"
            self.dataplane.send(4, str(pkt))
            verify_packet_on_set_of_ports(self, exp_pkt, [[1, 2], [5, 6], [7], [8]])
            print "Sending packet from lag3 on port5 -> lag1, lag2, port7, port8"
            self.dataplane.send(5, str(pkt))
            verify_packet_on_set_of_ports(self, exp_pkt, [[1, 2], [3, 4], [7], [8]])
            print "Sending packet from lag3 on port6 -> lag1, lag2, port7, port8"
            self.dataplane.send(6, str(pkt))
            verify_packet_on_set_of_ports(self, exp_pkt, [[1, 2], [3, 4], [7], [8]])
            print "Sending packet from port7 -> lag1, lag2, lag3, port8"
            self.dataplane.send(7, str(pkt))
            verify_packet_on_set_of_ports(self, exp_pkt, [[1, 2], [3, 4], [5, 6], [8]])
            print "Sending packet from port7 -> lag1, lag2, lag3, port8"
            self.dataplane.send(8, str(pkt))
            verify_packet_on_set_of_ports(self, exp_pkt, [[1, 2], [3, 4], [5, 6], [7]])

        finally:
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port3)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port4)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port5)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)
            self.client.switcht_api_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if5)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=1)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=2)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=3)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag2, side=0, port=4)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag3, side=0, port=5)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag3, side=0, port=6)

            self.client.switcht_api_lag_delete(device, lag1)
            self.client.switcht_api_lag_delete(device, lag2)
            self.client.switcht_api_lag_delete(device, lag3)

            self.client.switcht_api_vlan_delete(device, vlan)

class L2TunnelSplicingExtreme2Test(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Tunnel Splicing - Extreme2 (Enhanced Mode)"
        print "L2 Geneve-Vxlan--Nvgre-Mpls-L2Lag-L2Native Enhanced Mode Unicast Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=4, u=iu3, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        iu4 = interface_union(port_lag_handle = 4)
        i_info4 = switcht_interface_info_t(device=0, type=4, u=iu4, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if4 = self.client.switcht_api_interface_create(device, i_info4)

        lag1 = self.client.switcht_api_lag_create(device)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=5)
        self.client.switcht_api_lag_member_add(device, lag_handle=lag1, side=0, port=6)
        iu5 = interface_union(port_lag_handle = lag1)
        i_info5 = switcht_interface_info_t(device=0, type=2, u=iu5, mac='00:77:66:55:44:33', label=0)
        if5 = self.client.switcht_api_interface_create(device, i_info3)

        iu7 = interface_union(port_lag_handle = 7)
        i_info7 = switcht_interface_info_t(device=0, type=2, u=iu7, mac='00:77:66:55:44:33', label=0)
        if7 = self.client.switcht_api_interface_create(device, i_info7)

        # Create a logical network (LN)
        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a geneve tunnel interface
        udp11 = switcht_udp_t(src_port=1234, dst_port=6081)
        src_ip11 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip11 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp11 = switcht_udp_tcp_t(udp = udp11)
        geneve11 = switcht_geneve_id_t(vni=0x4321)
        bt11 = switcht_bridge_type(geneve_info=geneve11)
        encap_info11 = switcht_encap_info_t(encap_type=6, u=bt11)
        ip_encap11 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip11, dst_ip=dst_ip11, ttl=60, proto=17, u=udp_tcp11)
        tunnel_encap11 = switcht_tunnel_encap_t(ip_encap=ip_encap11)
        iu11 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap11, encap_info=encap_info11, out_if=if1)
        if11 = self.client.switcht_api_tunnel_interface_create(device, 0, iu11)

        # Create a vxlan tunnel interface
        udp21 = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip21 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.1', prefix_length=32)
        dst_ip21 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.3', prefix_length=32)
        udp_tcp21 = switcht_udp_tcp_t(udp = udp21)
        vxlan21 = switcht_vxlan_id_t(vnid=0x1234)
        bt21 = switcht_bridge_type(vxlan_info=vxlan21)
        encap_info21 = switcht_encap_info_t(encap_type=3, u=bt21)
        ip_encap21 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip21, dst_ip=dst_ip21, ttl=60, proto=17, u=udp_tcp21)
        tunnel_encap21 = switcht_tunnel_encap_t(ip_encap=ip_encap21)
        iu21 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap21, encap_info=encap_info21, out_if=if2)
        if21 = self.client.switcht_api_tunnel_interface_create(device, 0, iu21)

        #Create a mpls push interface
        mpls_tag1 = switcht_mpls_t(label=0xaaaaa, exp=0x1, ttl=0x30, bos=0)
        mpls_tag2 = switcht_mpls_t(label=0xbbbbb, exp=0x2, ttl=0x40, bos=1)
        push_info=switcht_mpls_push_t(tag=[mpls_tag1, mpls_tag2], count=2)
        mpls_info = switcht_mpls_info_t(push_info=push_info)
        mpls_encap = switcht_mpls_encap_t(mpls_type=0, mpls_action=1, mpls_mode=0, u=mpls_info, bd_handle=ln1)
        tunnel_encap = switcht_tunnel_encap_t(mpls_encap=mpls_encap)
        flags=switcht_interface_flags(flood_enabled=0, core_intf=0)
        iu31 = switcht_tunnel_info_t(encap_mode=1, tunnel_encap=tunnel_encap, out_if=if3, flags=flags)
        if31 = self.client.switcht_api_tunnel_interface_create(device, 0, iu31)

        #Create a mpls pop interface
        mpls_tag1 = switcht_mpls_t(label=0xccccc, exp=0x1, ttl=0x30, bos=0)
        mpls_tag2 = switcht_mpls_t(label=0xddddd, exp=0x2, ttl=0x40, bos=1)
        pop_info=switcht_mpls_pop_t(tag=[mpls_tag1, mpls_tag2], count=2)
        mpls_info = switcht_mpls_info_t(pop_info=pop_info)
        mpls_encap = switcht_mpls_encap_t(mpls_type=0, mpls_action=0, mpls_mode=2, u=mpls_info, bd_handle=ln1)
        tunnel_encap = switcht_tunnel_encap_t(mpls_encap=mpls_encap)
        flags=switcht_interface_flags(flood_enabled=0, core_intf=0)
        iu32 = switcht_tunnel_info_t(encap_mode=1, tunnel_encap=tunnel_encap, out_if=if3, flags=flags)
        if32 = self.client.switcht_api_tunnel_interface_create(device, 0, iu32)

        # Create a nvgre tunnel interface
        src_ip41 = switcht_ip_addr_t(addr_type=0, ipaddr='3.3.3.1', prefix_length=32)
        dst_ip41 = switcht_ip_addr_t(addr_type=0, ipaddr='3.3.3.3', prefix_length=32)
        nvgre41 = switcht_nvgre_id_t(tnid=0x4545)
        bt41 = switcht_bridge_type(nvgre_info=nvgre41)
        encap_info41 = switcht_encap_info_t(encap_type=5, u=bt41)
        ip_encap41 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip41, dst_ip=dst_ip41, ttl=60, proto=47)
        tunnel_encap41 = switcht_tunnel_encap_t(ip_encap=ip_encap41)
        iu41 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap41, encap_info=encap_info41, out_if=if4)
        if41 = self.client.switcht_api_tunnel_interface_create(device, 0, iu41)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if5)
        self.client.switcht_api_logical_network_member_add(device, ln1, if7)
        self.client.switcht_api_logical_network_member_add(device, ln1, if11)
        self.client.switcht_api_logical_network_member_add(device, ln1, if21)
        self.client.switcht_api_logical_network_member_add(device, ln1, if31)
        self.client.switcht_api_logical_network_member_add(device, ln1, if32)
        self.client.switcht_api_logical_network_member_add(device, ln1, if41)

        nhop_key11 = switcht_nhop_key_t(intf_handle=if11, ip_addr_valid=0)
        nhop11 = self.client.switcht_api_nhop_create(device, nhop_key11)
        neighbor_entry11 = switcht_neighbor_info_t(nhop_handle=nhop11,
                                                   interface_handle=if11,
                                                   mac_addr='00:33:33:33:33:33',
                                                   ip_addr=src_ip11,
                                                   rw_type=0, neigh_type=7)
        neighbor11 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry11)
        neighbor_entry12 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if11, mac_addr='00:33:33:33:33:33', ip_addr=src_ip11)
        neighbor12 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry12)

        nhop_key21 = switcht_nhop_key_t(intf_handle=if21, ip_addr_valid=0)
        nhop21 = self.client.switcht_api_nhop_create(device, nhop_key21)
        neighbor_entry21 = switcht_neighbor_info_t(nhop_handle=nhop21,
                                                   interface_handle=if21,
                                                   mac_addr='00:44:44:44:44:44',
                                                   ip_addr=src_ip21,
                                                   rw_type=0, neigh_type=7)
        neighbor21 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry21)
        neighbor_entry22 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if21, mac_addr='00:44:44:44:44:44', ip_addr=src_ip21)
        neighbor22 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry22)

        #neighbor type 5 is push l2vpn
        nhop_key31 = switcht_nhop_key_t(intf_handle=if31, ip_addr_valid=0)
        nhop31 = self.client.switcht_api_nhop_create(device, nhop_key31)
        neighbor_entry31 = switcht_neighbor_info_t(nhop_handle=nhop31, neigh_type=5, interface_handle= if31, mpls_label=0, header_count=2, rw_type=0)
        neighbor31 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry31)
        neighbor_entry32 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if31, mac_addr='00:55:55:55:55:55')
        neighbor32 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry32)

        nhop_key41 = switcht_nhop_key_t(intf_handle=if41, ip_addr_valid=0)
        nhop41 = self.client.switcht_api_nhop_create(device, nhop_key41)
        neighbor_entry41 = switcht_neighbor_info_t(nhop_handle=nhop41,
                                                   interface_handle=if41,
                                                   mac_addr='00:66:66:66:66:66',
                                                   ip_addr=src_ip41,
                                                   rw_type=0, neigh_type=7)
        neighbor41 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry41)
        neighbor_entry42 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if41, mac_addr='00:66:66:66:66:66', ip_addr=src_ip41)
        neighbor42 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry42)

        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:01:00:00:00:11', 2, nhop11)  #geneve mac
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:02:00:00:00:21', 2, nhop21)  #vxlan mac
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:03:00:00:00:31', 2, nhop31)  #mpls mac
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:04:00:00:00:41', 2, nhop41)  #mpls mac
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:05:00:00:00:05', 2, if5)     #l2 lag port mac
        self.client.switcht_api_mac_table_entry_create(device, ln1, '00:07:00:00:00:07', 2, if7)     #l2 native port mac

        print "Sending packet from Geneve port1 to Vxlan port2"
        try:
            pkt = simple_tcp_packet(eth_dst='00:02:00:00:00:21',
                                    eth_src='00:01:00:00:00:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)

            vxlan_pkt1 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=13003,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            vxlan_pkt2 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=108,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(geneve_pkt))
            verify_packet_list_any(self, [vxlan_pkt1, vxlan_pkt2], [2, 2])

            print "Sending packet from Vxlan port2 to Geneve port1"
            pkt = simple_tcp_packet(eth_dst='00:01:00:00:00:11',
                                    eth_src='00:02:00:00:00:21',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            geneve_pkt1 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=3680,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            geneve_pkt2 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            self.dataplane.send(2, str(vxlan_pkt))
            verify_packet_list_any(self, [geneve_pkt1, geneve_pkt2], [1, 1])

            print "Sending packet from Vxlan port2 to Mpls port 3"
            pkt = simple_tcp_packet(eth_dst='00:03:00:00:00:31',
                                    eth_src='00:02:00:00:00:21',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            tag1 = {'label' : 0xaaaaa, 'tc' : 0x1, 'ttl' : 0x30, 's' : 0x0}
            tag2 = {'label' : 0xbbbbb, 'tc' : 0x2, 'ttl' : 0x40, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            mpls_pkt = simple_mpls_packet(eth_src='00:77:66:55:44:33',
                                    eth_dst='00:55:55:55:55:55',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt)
            self.dataplane.send(2, str(vxlan_pkt))
            verify_packets(self, mpls_pkt, [3])

            print "Sending packet from Geneve port1 to Mpls port 3"
            pkt = simple_tcp_packet(eth_dst='00:03:00:00:00:31',
                                    eth_src='00:01:00:00:00:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)

            tag1 = {'label' : 0xaaaaa, 'tc' : 0x1, 'ttl' : 0x30, 's' : 0x0}
            tag2 = {'label' : 0xbbbbb, 'tc' : 0x2, 'ttl' : 0x40, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            mpls_pkt = simple_mpls_packet(eth_src='00:77:66:55:44:33',
                                    eth_dst='00:55:55:55:55:55',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(geneve_pkt))
            verify_packets(self, mpls_pkt, [3])

            print "Sending packet from Mpls port 3 to Geneve port 1"
            pkt = simple_tcp_packet(eth_dst='00:01:00:00:00:11',
                                    eth_src='00:03:00:00:00:31',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            tag1 = {'label' : 0xccccc, 'tc' : 0x1, 'ttl' : 0x30, 's' : 0x0}
            tag2 = {'label' : 0xddddd, 'tc' : 0x2, 'ttl' : 0x40, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            mpls_pkt = simple_mpls_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:55:55:55:55:55',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt)
            geneve_pkt1 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=6761,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            geneve_pkt2 = simple_geneve_packet(
                                    eth_dst='00:33:33:33:33:33',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=108,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            self.dataplane.send(3, str(mpls_pkt))
            verify_packet_list_any(self, [geneve_pkt1, geneve_pkt2], [1, 1])

            print "Sending packet from Geneve port1 to Nvgre port4"
            pkt = simple_tcp_packet(eth_dst='00:04:00:00:00:41',
                                    eth_src='00:01:00:00:00:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)

            nvgre_pkt = simple_nvgre_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:66:66:66:66:66',
                                    ip_id=0,
                                    ip_dst='3.3.3.3',
                                    ip_src='3.3.3.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x4545,
                                    inner_frame=pkt)
            self.dataplane.send(1, str(geneve_pkt))
            verify_packets(self, nvgre_pkt, [4])

            print "Sending packet from Vxlan port2 to Nvgre port4"
            pkt = simple_tcp_packet(eth_dst='00:04:00:00:00:41',
                                    eth_src='00:02:00:00:00:21',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=574,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            nvgre_pkt = simple_nvgre_packet(
                                    eth_dst='00:66:66:66:66:66',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='3.3.3.3',
                                    ip_src='3.3.3.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x4545,
                                    inner_frame=pkt)
            self.dataplane.send(2, str(vxlan_pkt))
            verify_packets(self, nvgre_pkt, [4])

            print "Sending packet from Nvgre port4 to Geneve port1"
            pkt = simple_tcp_packet(eth_dst='00:01:00:00:00:11',
                                    eth_src='00:04:00:00:00:41',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            nvgre_pkt = simple_nvgre_packet(
                                    eth_src='00:66:66:66:66:66',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='3.3.3.3',
                                    ip_src='3.3.3.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x4545,
                                    inner_frame=pkt)

            geneve_pkt1 = simple_geneve_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=13908,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)

            geneve_pkt2 = simple_geneve_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            self.dataplane.send(4, str(nvgre_pkt))
            verify_packet_list_any(self, [geneve_pkt1, geneve_pkt2], [1, 1])

            print "Sending packet from Nvgre port4 to Vxlan port2"
            pkt = simple_tcp_packet(eth_dst='00:02:00:00:00:21',
                                    eth_src='00:04:00:00:00:41',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            nvgre_pkt = simple_nvgre_packet(
                                    eth_src='00:66:66:66:66:66',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='3.3.3.3',
                                    ip_src='3.3.3.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x4545,
                                    inner_frame=pkt)

            vxlan_pkt1 = simple_vxlan_packet(
                                    eth_dst='00:44:44:44:44:44',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=14053,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            vxlan_pkt2 = simple_vxlan_packet(
                                    eth_dst='00:44:44:44:44:44',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            self.dataplane.send(4, str(nvgre_pkt))
            verify_packet_list_any(self, [vxlan_pkt1, vxlan_pkt2], [2, 2])

            print "Sending packet from Nvgre port4 to Mpls port 3"
            pkt = simple_tcp_packet(eth_dst='00:03:00:00:00:31',
                                    eth_src='00:04:00:00:00:41',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            nvgre_pkt = simple_nvgre_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:66:66:66:66:66',
                                    ip_id=0,
                                    ip_dst='3.3.3.3',
                                    ip_src='3.3.3.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x4545,
                                    inner_frame=pkt)

            tag1 = {'label' : 0xaaaaa, 'tc' : 0x1, 'ttl' : 0x30, 's' : 0x0}
            tag2 = {'label' : 0xbbbbb, 'tc' : 0x2, 'ttl' : 0x40, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            mpls_pkt = simple_mpls_packet(eth_src='00:77:66:55:44:33',
                                    eth_dst='00:55:55:55:55:55',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt)
            self.dataplane.send(4, str(nvgre_pkt))
            verify_packets(self, mpls_pkt, [3])

            print "Sending packet from Mpls port 3 to Nvgre port 4"
            pkt = simple_tcp_packet(eth_dst='00:04:00:00:00:41',
                                    eth_src='00:03:00:00:00:31',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            tag1 = {'label' : 0xccccc, 'tc' : 0x1, 'ttl' : 0x30, 's' : 0x0}
            tag2 = {'label' : 0xddddd, 'tc' : 0x2, 'ttl' : 0x40, 's' : 0x1}
            mpls_tags = [tag1, tag2]
            mpls_pkt = simple_mpls_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:55:55:55:55:55',
                                    mpls_tags=mpls_tags,
                                    inner_frame=pkt)
            nvgre_pkt = simple_nvgre_packet(
                                    eth_dst='00:66:66:66:66:66',
                                    eth_src='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='3.3.3.3',
                                    ip_src='3.3.3.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x4545,
                                    inner_frame=pkt)
            self.dataplane.send(3, str(mpls_pkt))
            verify_packets(self, nvgre_pkt, [4])

            print "Sending packet from native port7 to Geneve port 1"
            pkt = simple_tcp_packet(eth_dst='00:01:00:00:00:11',
                                    eth_src='00:07:00:00:00:71',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            geneve_pkt1 = simple_geneve_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=2638,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)

            geneve_pkt2 = simple_geneve_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)
            self.dataplane.send(7, str(pkt))
            verify_packet_list_any(self, [geneve_pkt1, geneve_pkt2], [1, 1])

            print "Sending packet from native port7 to Vxlan port 2"
            pkt = simple_tcp_packet(eth_dst='00:02:00:00:00:21',
                                    eth_src='00:07:00:00:00:71',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            vxlan_pkt1 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=2815,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            vxlan_pkt2 = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:44:44:44:44:44',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=0,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)
            self.dataplane.send(7, str(pkt))
            verify_packet_list_any(self, [vxlan_pkt1, vxlan_pkt2], [2, 2])

            print "Sending packet from native port7 to Nvgre port 4"
            pkt = simple_tcp_packet(eth_dst='00:04:00:00:00:41',
                                    eth_src='00:07:00:00:00:71',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            nvgre_pkt = simple_nvgre_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:66:66:66:66:66',
                                    ip_id=0,
                                    ip_dst='3.3.3.3',
                                    ip_src='3.3.3.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x4545,
                                    inner_frame=pkt)

            self.dataplane.send(7, str(pkt))
            verify_packets(self, nvgre_pkt, [4])
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor11)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor12)
            self.client.switcht_api_nhop_delete(device, nhop11)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor21)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor22)
            self.client.switcht_api_nhop_delete(device, nhop21)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor31)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor32)
            self.client.switcht_api_nhop_delete(device, nhop31)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor41)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor42)
            self.client.switcht_api_nhop_delete(device, nhop41)

            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:01:00:00:00:11')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:02:00:00:00:21')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:03:00:00:00:31')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:04:00:00:00:41')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:05:00:00:00:05')
            self.client.switcht_api_mac_table_entry_delete(device, ln1, '00:07:00:00:00:07')

            self.client.switcht_api_logical_network_member_remove(device, ln1, if11)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if21)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if31)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if32)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if41)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if5)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if7)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if11)
            self.client.switcht_api_tunnel_interface_delete(device, if21)
            self.client.switcht_api_tunnel_interface_delete(device, if31)
            self.client.switcht_api_tunnel_interface_delete(device, if32)
            self.client.switcht_api_tunnel_interface_delete(device, if41)

            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=5)
            self.client.switcht_api_lag_member_delete(device, lag_handle=lag1, side=0, port=6)
            self.client.switcht_api_lag_delete(device, lag1)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)
            self.client.switcht_api_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if5)
            self.client.switcht_api_interface_delete(device, if7)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')

class L2VxlanLearnBasicTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Vxlan Basic Mode Learn Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=2, u=iu3, mac='00:77:66:55:44:33', label=0)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        # Create a logical network (LN)
        ln_flags = switcht_ln_flags(learn_enabled=1)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        #encap_type 3 is vxlan
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=10, vrf=vrf, flags=ln_flags)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a tunnel interface
        flags = switcht_interface_flags(flood_enabled=1)
        udp = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp = switcht_udp_tcp_t(udp = udp)
        encap_info = switcht_encap_info_t(encap_type=3)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=17, u=udp_tcp)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        iu4 = switcht_tunnel_info_t(encap_mode = 0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if2, flags=flags)
        if4 = self.client.switcht_api_tunnel_interface_create(device, 0, iu4)

        nhop_key1 = switcht_nhop_key_t(intf_handle=if4, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(device, nhop_key1)

        #add L2 port to LN
        self.client.switcht_api_logical_network_member_add(device, ln1, if1)
        self.client.switcht_api_logical_network_member_add(device, ln1, if3)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)

        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=if4,
                                                  mac_addr='00:33:33:33:33:33',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if4, mac_addr='00:33:33:33:33:33', ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry2)

        try:
            pkt1 = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            vxlan_pkt1 = simple_vxlan_packet(
                                eth_src='00:77:66:55:44:33',
                                eth_dst='00:33:33:33:33:33',
                                ip_id=0,
                                ip_dst='1.1.1.3',
                                ip_src='1.1.1.1',
                                ip_ttl=64,
                                udp_sport=574,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                inner_frame=pkt1)

            pkt2 = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)
            vxlan_pkt2 = simple_vxlan_packet(
                                    eth_src='00:33:33:33:33:33',
                                    eth_dst='00:77:66:55:44:33',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=11638,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt2)

            print "Sending packet from Access port1 to Vxlan port2 and native port 3 - Learn mac on port1"
            self.dataplane.send(1, str(pkt1))
            verify_packet_list(self, [vxlan_pkt1, pkt1], [2, 3])
            print "Sending packet from Vxlan port2 to Access port1 and native port 3 - Learn mac on vxlan tunnel port2"
            self.dataplane.send(2, str(vxlan_pkt2))
            verify_packets(self, pkt2, [1, 3])
            time.sleep(5)
            print "Sending packet from Access port1 to Vxlan port2 - unicast to vxlan port2"
            self.dataplane.send(1, str(pkt1))
            verify_packets(self, vxlan_pkt1, [2])
            print "Sending packet from Vxlan port2 to Access port1 - unicast to native port1"
            self.dataplane.send(2, str(vxlan_pkt2))
            verify_packets(self, pkt2, [1])
            time.sleep(10)
        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor1)
            self.client.switcht_api_nhop_delete(device, nhop1)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor2)

            self.client.switcht_api_logical_network_member_remove(device, ln1, if1)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if3)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
            self.client.switcht_api_router_mac_group_delete(device, rmac)
            self.client.switcht_api_vrf_delete(device, vrf)

class L2VlanStatsTestBasic(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet port 1 -> port 2 [access vlan=10])"
        self.client.switcht_api_init(device)
        vlan = self.client.switcht_api_vlan_create(device, 10)
        self.client.switcht_api_vlan_stats_enable(device, vlan)

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1, mac='00:77:66:55:44:33', label=0)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=2, u=iu2, mac='00:77:66:55:44:33', label=0)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        vlan_port1 = switcht_vlan_port_t(handle=if1, tagging_mode=0)
        vlan_port2 = switcht_vlan_port_t(handle=if2, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)
        self.client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)

        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:11:11:11:11:11', 2, if1)
        self.client.switcht_api_mac_table_entry_create(device, vlan, '00:22:22:22:22:22', 2, if2)

        try:
            num_bytes = 0
            num_packets = 200
            random.seed(314159)
            for i in range(0, num_packets):
                pktlen = random.randint(100, 250)
                pkt = simple_tcp_packet(
                        eth_dst='00:22:22:22:22:22',
                        eth_src='00:11:11:11:11:11',
                        ip_dst='10.10.10.1',
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=64,
                        pktlen=pktlen)

                exp_pkt = simple_tcp_packet(
                        eth_dst='00:22:22:22:22:22',
                        eth_src='00:11:11:11:11:11',
                        ip_dst='10.10.10.1',
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=64,
                        pktlen=pktlen)
                self.dataplane.send(1, str(pkt))
                verify_packet_list(self, [exp_pkt], [2])
                num_bytes += pktlen

            counter = self.client.switcht_api_vlan_stats_get(vlan, [0, 1, 2])
            self.assertGreaterEqual(counter[0].num_packets, num_packets)
            self.assertGreaterEqual(counter[0].num_bytes, num_bytes)
            self.assertGreaterEqual(counter[1].num_packets, 0)
            self.assertGreaterEqual(counter[1].num_bytes, 0)
            self.assertGreaterEqual(counter[2].num_packets, 0)
            self.assertGreaterEqual(counter[2].num_bytes, 0)
        finally:
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:11:11:11:11:11')
            self.client.switcht_api_mac_table_entry_delete(device, vlan, '00:22:22:22:22:22')

            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port1)
            self.client.switcht_api_vlan_ports_remove(device, vlan, vlan_port2)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)

            self.client.switcht_api_vlan_delete(device, vlan)

class L2TunnelFloodEnhancedTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "L2 Tunnel Flooding (Enhanced Mode)"
        print "L2 Geneve-Vxlan--Nvgre-Portvlan Enhanced Mode Flood Test"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 2)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)

        iu3 = interface_union(port_lag_handle = 3)
        i_info3 = switcht_interface_info_t(device=0, type=4, u=iu3, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if3 = self.client.switcht_api_interface_create(device, i_info3)

        # Create a logical network (LN)
        lognet_info = switcht_logical_network_t(type=5, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(device, lognet_info)

        # Create a geneve tunnel interface
        flags = switcht_interface_flags(flood_enabled=1)

        udp11 = switcht_udp_t(src_port=1234, dst_port=6081)
        src_ip11 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.1', prefix_length=32)
        dst_ip11 = switcht_ip_addr_t(addr_type=0, ipaddr='1.1.1.3', prefix_length=32)
        udp_tcp11 = switcht_udp_tcp_t(udp = udp11)
        geneve11 = switcht_geneve_id_t(vni=0x4321)
        bt11 = switcht_bridge_type(geneve_info=geneve11)
        encap_info11 = switcht_encap_info_t(encap_type=6, u=bt11)
        ip_encap11 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip11, dst_ip=dst_ip11, ttl=60, proto=17, u=udp_tcp11)
        tunnel_encap11 = switcht_tunnel_encap_t(ip_encap=ip_encap11)
        iu11 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap11, encap_info=encap_info11, out_if=if1, flags=flags)
        if11 = self.client.switcht_api_tunnel_interface_create(device, 0, iu11)

        # Create a vxlan tunnel interface
        udp21 = switcht_udp_t(src_port=1234, dst_port=4789)
        src_ip21 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.1', prefix_length=32)
        dst_ip21 = switcht_ip_addr_t(addr_type=0, ipaddr='2.2.2.3', prefix_length=32)
        udp_tcp21 = switcht_udp_tcp_t(udp = udp21)
        vxlan21 = switcht_vxlan_id_t(vnid=0x1234)
        bt21 = switcht_bridge_type(vxlan_info=vxlan21)
        encap_info21 = switcht_encap_info_t(encap_type=3, u=bt21)
        ip_encap21 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip21, dst_ip=dst_ip21, ttl=60, proto=17, u=udp_tcp21)
        tunnel_encap21 = switcht_tunnel_encap_t(ip_encap=ip_encap21)
        iu21 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap21, encap_info=encap_info21, out_if=if2, flags=flags)
        if21 = self.client.switcht_api_tunnel_interface_create(device, 0, iu21)

        # Create a nvgre tunnel interface
        src_ip31 = switcht_ip_addr_t(addr_type=0, ipaddr='3.3.3.1', prefix_length=32)
        dst_ip31 = switcht_ip_addr_t(addr_type=0, ipaddr='3.3.3.3', prefix_length=32)
        nvgre31 = switcht_nvgre_id_t(tnid=0x4545)
        bt31 = switcht_bridge_type(nvgre_info=nvgre31)
        encap_info31 = switcht_encap_info_t(encap_type=5, u=bt31)
        ip_encap31 =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip31, dst_ip=dst_ip31, ttl=60, proto=47)
        tunnel_encap31 = switcht_tunnel_encap_t(ip_encap=ip_encap31)
        iu31 = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap31, encap_info=encap_info31, out_if=if3, flags=flags)
        if31 = self.client.switcht_api_tunnel_interface_create(device, 0, iu31)

        pv4 = switcht_port_vlan_t(port_lag_handle=4, vlan_id=10)
        iu4 = interface_union(port_vlan = pv4)
        i_info4 = switcht_interface_info_t(device=0, type=9, u=iu4, mac='00:77:66:55:44:33', label=0)
        if4 = self.client.switcht_api_interface_create(device, i_info4)

        pv5 = switcht_port_vlan_t(port_lag_handle=5, vlan_id=20)
        iu5 = interface_union(port_vlan = pv5)
        i_info5 = switcht_interface_info_t(device=0, type=9, u=iu5, mac='00:77:66:55:44:33', label=0)
        if5 = self.client.switcht_api_interface_create(device, i_info5)

        iu6 = interface_union(port_lag_handle = 6)
        i_info6 = switcht_interface_info_t(device=0, type=2, u=iu6, mac='00:77:66:55:44:33', label=0)
        if6 = self.client.switcht_api_interface_create(device, i_info6)

        nhop_key11 = switcht_nhop_key_t(intf_handle=if11, ip_addr_valid=0)
        nhop_key21 = switcht_nhop_key_t(intf_handle=if21, ip_addr_valid=0)
        nhop_key31 = switcht_nhop_key_t(intf_handle=if31, ip_addr_valid=0)
        nhop11 = self.client.switcht_api_nhop_create(device, nhop_key11)
        nhop21 = self.client.switcht_api_nhop_create(device, nhop_key21)
        nhop31 = self.client.switcht_api_nhop_create(device, nhop_key31)

        self.client.switcht_api_logical_network_member_add(device, ln1, if11)
        self.client.switcht_api_logical_network_member_add(device, ln1, if21)
        self.client.switcht_api_logical_network_member_add(device, ln1, if31)
        self.client.switcht_api_logical_network_member_add(device, ln1, if4)
        self.client.switcht_api_logical_network_member_add(device, ln1, if5)
        self.client.switcht_api_logical_network_member_add(device, ln1, if6)

        neighbor_entry11 = switcht_neighbor_info_t(nhop_handle=nhop11,
                                                   interface_handle=if11,
                                                   mac_addr='00:11:11:11:11:11',
                                                   ip_addr=src_ip11,
                                                   rw_type=0, neigh_type=7)
        neighbor11 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry11)
        neighbor_entry12 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if11, mac_addr='00:11:11:11:11:11', ip_addr=src_ip11)
        neighbor12 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry12)

        neighbor_entry21 = switcht_neighbor_info_t(nhop_handle=nhop21,
                                                   interface_handle=if21,
                                                   mac_addr='00:22:22:22:22:22',
                                                   ip_addr=src_ip21,
                                                   rw_type=0, neigh_type=7)
        neighbor21 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry21)
        neighbor_entry22 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if21, mac_addr='00:22:22:22:22:22', ip_addr=src_ip21)
        neighbor22 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry22)

        neighbor_entry31 = switcht_neighbor_info_t(nhop_handle=nhop31,
                                                   interface_handle=if31,
                                                   mac_addr='00:33:33:33:33:33',
                                                   ip_addr=src_ip31,
                                                   rw_type=0, neigh_type=7)
        neighbor31 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry31)
        neighbor_entry32 = switcht_neighbor_info_t(nhop_handle=0, interface_handle=if31, mac_addr='00:33:33:33:33:33:33', ip_addr=src_ip31)
        neighbor32 = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry32)

        try:
            pkt = simple_tcp_packet(eth_dst='00:02:00:00:00:21',
                                    eth_src='00:01:00:00:00:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64)

            geneve_pkt = simple_geneve_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:11:11:11:11:11',
                                    ip_id=0,
                                    ip_dst='1.1.1.3',
                                    ip_src='1.1.1.1',
                                    ip_ttl=64,
                                    udp_sport=13003,
                                    with_udp_chksum=False,
                                    geneve_vni=0x4321,
                                    inner_frame=pkt)

            vxlan_pkt = simple_vxlan_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_id=0,
                                    ip_dst='2.2.2.3',
                                    ip_src='2.2.2.1',
                                    ip_ttl=64,
                                    udp_sport=13003,
                                    with_udp_chksum=False,
                                    vxlan_vni=0x1234,
                                    inner_frame=pkt)

            nvgre_pkt = simple_nvgre_packet(
                                    eth_src='00:77:66:55:44:33',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_id=0,
                                    ip_dst='3.3.3.3',
                                    ip_src='3.3.3.1',
                                    ip_ttl=64,
                                    nvgre_tni=0x4545,
                                    inner_frame=pkt)

            encap_pkt1 = simple_tcp_packet(eth_dst='00:02:00:00:00:21',
                                    eth_src='00:01:00:00:00:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64,
                                    dl_vlan_enable=True,
                                    vlan_vid=10,
                                    pktlen=104)

            encap_pkt2 = simple_tcp_packet(eth_dst='00:02:00:00:00:21',
                                    eth_src='00:01:00:00:00:11',
                                    ip_dst='10.10.10.1',
                                    ip_id=108,
                                    ip_ttl=64,
                                    dl_vlan_enable=True,
                                    vlan_vid=20,
                                    pktlen=104)

            print "Sending packet on native access port 6"
            self.dataplane.send(6, str(pkt))
            print "Packets expected on [geneve port1]. [vxlan port2], [nvgre port3], [encap vlan 10 port 4], [encap vlan 20 port 5]"
            verify_packet_list(self, [geneve_pkt, vxlan_pkt, nvgre_pkt, encap_pkt1, encap_pkt2], [1, 2, 3, 4, 5])
            time.sleep(5)

        finally:
            self.client.switcht_api_neighbor_entry_remove(device, neighbor11)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor12)
            self.client.switcht_api_nhop_delete(device, nhop11)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor21)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor22)
            self.client.switcht_api_nhop_delete(device, nhop21)

            self.client.switcht_api_neighbor_entry_remove(device, neighbor31)
            self.client.switcht_api_neighbor_entry_remove(device, neighbor32)
            self.client.switcht_api_nhop_delete(device, nhop31)

            self.client.switcht_api_logical_network_member_remove(device, ln1, if11)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if21)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if31)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if4)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if5)
            self.client.switcht_api_logical_network_member_remove(device, ln1, if6)
            self.client.switcht_api_logical_network_delete(device, ln1)

            self.client.switcht_api_tunnel_interface_delete(device, if11)
            self.client.switcht_api_tunnel_interface_delete(device, if21)
            self.client.switcht_api_tunnel_interface_delete(device, if31)

            self.client.switcht_api_interface_delete(device, if1)
            self.client.switcht_api_interface_delete(device, if2)
            self.client.switcht_api_interface_delete(device, if3)
            self.client.switcht_api_interface_delete(device, if4)
            self.client.switcht_api_interface_delete(device, if5)
            self.client.switcht_api_interface_delete(device, if6)

            self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
