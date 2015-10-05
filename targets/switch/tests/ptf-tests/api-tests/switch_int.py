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

"""
Thrift API interface - INT Tests
"""

import switch_api_thrift

import time
import sys
import logging

import unittest
import random

import ptf.dataplane as dataplane
import api_base_tests

from ptf.testutils import *
from ptf.thriftutils import *

import os

from switch_api_thrift.ttypes import  *

from xnt import *

this_dir = os.path.dirname(os.path.abspath(__file__))

is_bmv2 = ('BMV2_TEST' in os.environ) and (int(os.environ['BMV2_TEST']) == 1)

device=0

class int_transitTest_switchid(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print "Test INT transit device - add switch_id"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

#       Add a static route
        i_ip3 = switcht_ip_addr_t(ipaddr='10.10.10.1', prefix_length=32)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(device, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop,
                                                 interface_handle=if2,
                                                 mac_addr='00:11:22:33:44:55',
                                                 ip_addr=i_ip3,
                                                 rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop)

        # Enable INT transit processing and set switch_id
        self.client.switcht_int_transit_enable(device, 0x11111111, 1)

# send the test packet(s)
        pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_dst='1.1.1.1',
                                    ip_src='2.2.2.2',
                                    ip_id=108,
                                    ip_ttl=64)
        # create a packet coming from INT src - i.e.
        #   - It has INT meta header, but no INT data
        #   Each transit device will fill the data
        vxlan_int_pkt = vxlan_gpe_int_src_packet(
                                eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_id=0,
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_ttl=64,
                                udp_sport=101,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                int_inst_mask=0x8000, #only swid, 1 byte
                                int_inst_cnt=1,
                                inner_frame=pkt)
        exp_pkt = vxlan_gpe_int_src_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_id=0,
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_ttl=63,
                                udp_sport=101,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                int_inst_mask=0x8000, #only swid, 1 byte
                                int_inst_cnt=1,
                                inner_frame=pkt)
        send_packet(self, 1, str(vxlan_int_pkt))

        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x11111111, bos=True, incr_cnt=1)
        verify_packets(self, exp_pkt, [2])
        verify_no_other_packets(self)

        ### Cleanup
        self.client.switcht_int_transit_enable(device, 0x11111111, 0)
        self.client.switcht_api_neighbor_entry_remove(device, neighbor)
        self.client.switcht_api_nhop_delete(device, nhop)
        self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, if2)

        self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
        self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

        self.client.switcht_api_interface_delete(device, if1)
        self.client.switcht_api_interface_delete(device, if2)

        self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
        self.client.switcht_api_router_mac_group_delete(device, rmac)
        self.client.switcht_api_vrf_delete(device, vrf)

class int_transitTest_hop2(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print "Test INT transit device - add switch_id on hop2"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

#       Add a static route
        i_ip3 = switcht_ip_addr_t(ipaddr='10.10.10.1', prefix_length=32)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(device, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop,
                                                 interface_handle=if2,
                                                 mac_addr='00:11:22:33:44:55',
                                                 ip_addr=i_ip3,
                                                 rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop)

        # Enable INT transit processing and set switch_id
        self.client.switcht_int_transit_enable(device, 0x11111111, 1)

# send the test packet(s)
        pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_dst='1.1.1.1',
                                    ip_src='2.2.2.2',
                                    ip_id=108,
                                    ip_ttl=64)
        # create a packet coming from INT src - i.e.
        #   - It has INT meta header, but no INT data
        #   Each transit device will fill the data
        vxlan_int_pkt = vxlan_gpe_int_src_packet(
                                eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_id=0,
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_ttl=64,
                                udp_sport=101,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                int_inst_mask=0x8100, # swid, tx_util 1 byte
                                int_inst_cnt=2,
                                inner_frame=pkt)
        # add 1 hop info to the packet
        vxlan_int_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=vxlan_int_pkt,
                                     val=0x66666666, bos=True)
        vxlan_int_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=vxlan_int_pkt,
                                     val=0x22222222, bos=False, incr_cnt=1)
        exp_pkt = vxlan_gpe_int_src_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_id=0,
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_ttl=63,
                                udp_sport=101,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                int_inst_mask=0x8100,
                                int_inst_cnt=2,
                                inner_frame=pkt)

        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x66666666, bos=True)
        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x22222222, bos=False, incr_cnt=1)
        ## At this time p4 code does not support this info
        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x7FFFFFFF, bos=False)
        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x11111111, bos=False, incr_cnt=1)

        send_packet(self, 1, str(vxlan_int_pkt))
        verify_packets(self, exp_pkt, [2])
        verify_no_other_packets(self)

        ### Cleanup
        self.client.switcht_int_transit_enable(device, 0x11111111, 0)
        self.client.switcht_api_neighbor_entry_remove(device, neighbor)
        self.client.switcht_api_nhop_delete(device, nhop)
        self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, if2)

        self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
        self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

        self.client.switcht_api_interface_delete(device, if1)
        self.client.switcht_api_interface_delete(device, if2)

        self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
        self.client.switcht_api_router_mac_group_delete(device, rmac)
        self.client.switcht_api_vrf_delete(device, vrf)

class int_transitTest_Ebit(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print "Test INT transit device - E bit"
        self.client.switcht_api_init(device)

        vrf = self.client.switcht_api_vrf_create(device, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = 1)
        i_info1 = switcht_interface_info_t(device, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(device, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = 2)
        i_info2 = switcht_interface_info_t(device, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(device, if2, vrf, i_ip2)

#       Add a static route
        i_ip3 = switcht_ip_addr_t(ipaddr='10.10.10.1', prefix_length=32)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(device, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop,
                                                 interface_handle=if2,
                                                 mac_addr='00:11:22:33:44:55',
                                                 ip_addr=i_ip3,
                                                 rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(device, neighbor_entry)
        self.client.switcht_api_l3_route_add(device, vrf, i_ip3, nhop)

        # Enable INT transit processing and set switch_id
        self.client.switcht_int_transit_enable(device, 0x11111111, 1)

# send the test packet(s)
        pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:33:33:33:33:33',
                                    ip_dst='1.1.1.1',
                                    ip_src='2.2.2.2',
                                    ip_id=108,
                                    ip_ttl=64)
        # create a packet coming from INT src - i.e.
        #   - It has INT meta header, but no INT data
        #   Each transit device will fill the data
        vxlan_int_pkt = vxlan_gpe_int_src_packet(
                                eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_id=0,
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_ttl=64,
                                udp_sport=101,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                int_inst_mask=0xF700,
                                int_inst_cnt=7,
                                inner_frame=pkt)
        # add 1 hop info to the packet
        vxlan_int_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=vxlan_int_pkt,
                                     val=0x10, bos=True, incr_cnt=0)
        vxlan_int_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=vxlan_int_pkt,
                                     val=0x11, bos=False, incr_cnt=0)
        vxlan_int_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=vxlan_int_pkt,
                                     val=0x12, bos=False, incr_cnt=0)
        vxlan_int_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=vxlan_int_pkt,
                                     val=0x13, bos=False, incr_cnt=0)
        vxlan_int_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=vxlan_int_pkt,
                                     val=0x14, bos=False, incr_cnt=0)
        vxlan_int_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=vxlan_int_pkt,
                                     val=0x15, bos=False, incr_cnt=0)
        vxlan_int_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=vxlan_int_pkt,
                                     val=0x22222222, bos=False, incr_cnt=1)
        # Force Total cnt and max count to be the same
        vxlan_int_pkt[INT_META_HDR].max_hop_cnt = vxlan_int_pkt[INT_META_HDR].total_hop_cnt
        exp_pkt = vxlan_gpe_int_src_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_id=0,
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_ttl=63,
                                udp_sport=101,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                int_inst_mask=0xF700,
                                int_inst_cnt=7,
                                inner_frame=pkt)

        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x10, bos=True, incr_cnt=0)
        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x11, bos=False, incr_cnt=0)
        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x12, bos=False, incr_cnt=0)
        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x13, bos=False, incr_cnt=0)
        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x14, bos=False, incr_cnt=0)
        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x15, bos=False, incr_cnt=0)
        exp_pkt = vxlan_gpe_int_packet_add_hop_info(Packet=exp_pkt,
                                     val=0x22222222, bos=False, incr_cnt=1)
        exp_pkt[INT_META_HDR].max_hop_cnt = exp_pkt[INT_META_HDR].total_hop_cnt
        exp_pkt[INT_META_HDR].e = 1;

        send_packet(self, 1, str(vxlan_int_pkt))
        verify_packets(self, exp_pkt, [2])
        verify_no_other_packets(self)

        ### Cleanup
        self.client.switcht_int_transit_enable(device, 0x11111111, 0)
        self.client.switcht_api_neighbor_entry_remove(device, neighbor)
        self.client.switcht_api_nhop_delete(device, nhop)
        self.client.switcht_api_l3_route_delete(device, vrf, i_ip3, if2)

        self.client.switcht_api_l3_interface_address_delete(device, if1, vrf, i_ip1)
        self.client.switcht_api_l3_interface_address_delete(device, if2, vrf, i_ip2)

        self.client.switcht_api_interface_delete(device, if1)
        self.client.switcht_api_interface_delete(device, if2)

        self.client.switcht_api_router_mac_delete(device, rmac, '00:77:66:55:44:33')
        self.client.switcht_api_router_mac_group_delete(device, rmac)
        self.client.switcht_api_vrf_delete(device, vrf)
