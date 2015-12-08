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
Thrift API interface ACL tests
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

from erspan3 import *

this_dir = os.path.dirname(os.path.abspath(__file__))

is_bmv2 = ('BMV2_TEST' in os.environ) and (int(os.environ['BMV2_TEST']) == 1)
swports = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

###############################################################################
@group('acl')
class IPAclTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port %d" % swports[1], "  -> port %d" % swports[2], "  (192.168.0.1 -> 10.0.0.1 [id = 101])"
        self.client.switcht_api_init(0)
        vrf = self.client.switcht_api_vrf_create(0, 1)

        rmac = self.client.switcht_api_router_mac_group_create(0)
        self.client.switcht_api_router_mac_add(0, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = swports[1])
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(0, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = swports[2])
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(0, i_info2)
        i_ip2 = switcht_ip_addr_t(ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(ipaddr='10.10.10.1', prefix_length=32)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(0, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop,
                                                 interface_handle=if2,
                                                 mac_addr='00:11:22:33:44:55',
                                                 ip_addr=i_ip3,
                                                 rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(0, neighbor_entry)
        self.client.switcht_api_l3_route_add(0, vrf, i_ip3, nhop)

        # send the test packet(s)
        pkt = simple_tcp_packet( eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        send_packet(self, 1, str(pkt))

        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                #ip_tos=3,
                                ip_ttl=63)
        verify_packets(self, exp_pkt, [swports[2]])


        # setup a deny ACL to verify that the same packet does not make it
        # ip acl
        acl = self.client.switcht_api_acl_list_create(0, 0)
        # create kvp to match destination IP
        kvp = []
        kvp.append(switcht_acl_ip_key_value_pair_t(1, int("0a0a0a01", 16), int("ffffffff", 16)))
        action = 1
        action_param = switcht_acl_action_params_t(redirect = switcht_acl_action_redirect(handle = 0))
        ace = self.client.switcht_api_acl_ip_rule_create(0, acl, 10, 1, kvp, action, action_param)
        self.client.switcht_api_acl_reference(0, acl, if1)
        send_packet(self, 1, str(pkt))

        # check for absence of packet here!
        try:
            verify_packets(self, exp_pkt, [swports[2]])
            print 'FAILED - did not expect packet'
        except:
            print 'Success'

        # ip_acl
        self.client.switcht_api_acl_remove(0, acl, if1)
        self.client.switcht_api_acl_rule_delete(0, acl, ace)
        self.client.switcht_api_acl_list_delete(0, acl)

        #cleanup
        self.client.switcht_api_neighbor_entry_remove(0, neighbor)
        self.client.switcht_api_nhop_delete(0, nhop)
        self.client.switcht_api_l3_route_delete(0, vrf, i_ip3, if2)

        self.client.switcht_api_l3_interface_address_delete(0, if1, vrf, i_ip1)
        self.client.switcht_api_l3_interface_address_delete(0, if2, vrf, i_ip2)

        self.client.switcht_api_interface_delete(0, if1)
        self.client.switcht_api_interface_delete(0, if2)

        self.client.switcht_api_router_mac_delete(0, rmac, '00:77:66:55:44:33')
        self.client.switcht_api_router_mac_group_delete(0, rmac)
        self.client.switcht_api_vrf_delete(0, vrf)


###############################################################################
@group('acl')
@group('mirror')
class MirrorAclTest_i2e(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port %d" % swports[1], "  -> port %d" % swports[2], "  (192.168.0.1 -> 10.0.0.1 [id = 101])"
        self.client.switcht_api_init(0)
        vrf = self.client.switcht_api_vrf_create(0, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device=0)
        self.client.switcht_api_router_mac_add(0, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = swports[1])
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(0, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = swports[2])
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(0, i_info2)
        i_ip2 = switcht_ip_addr_t(ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(ipaddr='10.10.10.1', prefix_length=32)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(0, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop,
                                                 interface_handle=if2,
                                                 mac_addr='00:11:22:33:44:55',
                                                 ip_addr=i_ip3,
                                                 rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(0, neighbor_entry)
        self.client.switcht_api_l3_route_add(0, vrf, i_ip3, nhop)

        # send the test packet(s)
        pkt = simple_tcp_packet( eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        send_packet(self, 1, str(pkt))

        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                #ip_tos=3,
                                ip_ttl=63)
        verify_packets(self, exp_pkt, [swports[2]])

        # create a mirror session
        minfo1 = switcht_mirror_info_t(session_id=1, direction=1,
                                      egress_port=4, mirror_type=0,
                                      session_type=0,
                                      cos=0, max_pkt_len=0,
                                      ttl=0, enable=1, nhop_handle=0)
        mirror1 = self.client.switcht_api_mirror_session_create(0, minfo1)

        # setup a Mirror acl
        # ip acl
        print "Create Mirror ACL to mirror i2e from 1->4"
        acl = self.client.switcht_api_acl_list_create(0, 0)
        # create kvp to match destination IP
        kvp = []
        kvp.append(switcht_acl_ip_key_value_pair_t(1, int("0a0a0a01", 16), int("ffffffff", 16)))
        action = 9
        action_param = switcht_acl_action_params_t(mirror = switcht_acl_action_mirror(mirror_handle=mirror1))
        ace = self.client.switcht_api_acl_ip_rule_create(0, acl, 10, 1, kvp, action, action_param)
        self.client.switcht_api_acl_reference(0, acl, if1)

        # send the test packet(s)
        send_packet(self, 1, str(pkt))
        verify_packet(self, exp_pkt, swports[2])
        # verify mirrored packet
        verify_packet(self, pkt, swports[4])
        verify_no_other_packets(self)

        # delete the mirror sesion
        print "Delete Mirror ACL"
        self.client.switcht_api_mirror_session_delete(0, mirror1)
        # clean-up test, make sure pkt is not mirrored after session is deleted
        send_packet(self, 1, str(pkt))
        verify_packet(self, exp_pkt, swports[2])
        verify_no_other_packets(self)
        # ip_acl cleanup
        self.client.switcht_api_acl_remove(0, acl, if1)
        self.client.switcht_api_acl_rule_delete(0, acl, ace)
        self.client.switcht_api_acl_list_delete(0, acl)
        #cleanup
        self.client.switcht_api_neighbor_entry_remove(0, neighbor)
        self.client.switcht_api_nhop_delete(0, nhop)
        self.client.switcht_api_l3_route_delete(0, vrf, i_ip3, if2)

        self.client.switcht_api_l3_interface_address_delete(0, if1, vrf, i_ip1)
        self.client.switcht_api_l3_interface_address_delete(0, if2, vrf, i_ip2)

        self.client.switcht_api_interface_delete(0, if1)
        self.client.switcht_api_interface_delete(0, if2)

        self.client.switcht_api_router_mac_delete(0, rmac, '00:77:66:55:44:33')
        self.client.switcht_api_router_mac_group_delete(0, rmac)
        self.client.switcht_api_vrf_delete(0, vrf)


###############################################################################
@group('acl')
@group('mirror')
class MirrorSessionTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        self.client.switcht_api_init(0)
        print "create mirror sessions"
        minfo1 = switcht_mirror_info_t(session_id=1, direction=1,
                                      egress_port=3, mirror_type=0,
                                      session_type=0,
                                      cos=0, max_pkt_len=0,
                                      ttl=0, enable=1, nhop_handle=0)
        mirror1 = self.client.switcht_api_mirror_session_create(0, minfo1)
        minfo2 = switcht_mirror_info_t(session_id=101, direction=2,
                                      egress_port=3, mirror_type=0,
                                      session_type=0,
                                      cos=0, max_pkt_len=0,
                                      ttl=0, enable=1, nhop_handle=0)
        mirror2 = self.client.switcht_api_mirror_session_create(0, minfo2)
        minfo3 = switcht_mirror_info_t(session_id=201, direction=3,
                                      egress_port=3, mirror_type=0,
                                      session_type=0,
                                      cos=0, max_pkt_len=0,
                                      ttl=0, enable=1, nhop_handle=0)
        mirror3 = self.client.switcht_api_mirror_session_create(0, minfo3)
        print "delete mirror sessions"
        self.client.switcht_api_mirror_session_delete(0, mirror1)
        self.client.switcht_api_mirror_session_delete(0, mirror2)
        self.client.switcht_api_mirror_session_delete(0, mirror3)
        # delete again -ve test
        self.client.switcht_api_mirror_session_delete(0, mirror3)


###############################################################################
@group('acl')
@group('mirror')
class MirrorAclTest_e2e(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print "Test e2e Mirror packet port %d" % swports[1], "  -> port %d" % swports[2], "  (192.168.0.1 -> 10.0.0.1 [id = 101])"
        self.client.switcht_api_init(0)
        vrf = self.client.switcht_api_vrf_create(0, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device=0)
        self.client.switcht_api_router_mac_add(0, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = swports[1])
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(0, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = swports[2])
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(0, i_info2)
        i_ip2 = switcht_ip_addr_t(ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(ipaddr='10.10.10.1', prefix_length=32)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(0, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop,
                                                 interface_handle=if2,
                                                 mac_addr='00:11:22:33:44:55',
                                                 ip_addr=i_ip3,
                                                 rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(0, neighbor_entry)
        self.client.switcht_api_l3_route_add(0, vrf, i_ip3, nhop)

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
        # create a mirror session
        minfo1 = switcht_mirror_info_t(session_id=1, direction=2,
                                      egress_port=4, mirror_type=0,
                                      session_type=0,
                                      cos=0, max_pkt_len=0,
                                      ttl=0, enable=1, nhop_handle=0)
        mirror1 = self.client.switcht_api_mirror_session_create(0, minfo1)

        # setup a egress Mirror acl
        print "Create Egress Mirror ACL to mirror e2e from 2->4"
        acl = self.client.switcht_api_acl_list_create(0, 6)
        # create kvp to match egress port and defect bit
        kvp = []
        kvp.append(switcht_acl_egr_key_value_pair_t(field=0, value=2, mask=-1))
        kvp.append(switcht_acl_egr_key_value_pair_t(field=1, value=0, mask=-1))
        action = 1
        action_param = switcht_acl_action_params_t(mirror = switcht_acl_action_mirror(mirror_handle=mirror1))
        ace = self.client.switcht_api_acl_egr_rule_create(0, acl, 11, 2, kvp, action, action_param)
        self.client.switcht_api_acl_reference(0, acl, if2)
        send_packet(self, 1, str(pkt))
        verify_packet(self, exp_pkt, swports[2])
        # verify mirrored packet
        verify_packet(self, exp_pkt, swports[4])
        verify_no_other_packets(self)

        # update the mirror sesion to different port
        print "Update Egress Mirror Session's egr_port to 3 and test packet again"
        minfo1 = switcht_mirror_info_t(session_id=1, direction=2,
                                      egress_port=3, mirror_type=0,
                                      session_type=0,
                                      cos=0, max_pkt_len=0,
                                      ttl=0, enable=1, nhop_handle=0)
        self.client.switcht_api_mirror_session_update(0, mirror1, minfo1)
        send_packet(self, 1, str(pkt))
        verify_packet(self, exp_pkt, swports[2])
        verify_packet(self, exp_pkt, swports[3])
        verify_no_other_packets(self)
        print "Delete Mirror Session"
        self.client.switcht_api_mirror_session_delete(0, mirror1)
        # clean-up test, make sure pkt is not mirrored after session is deleted
        send_packet(self, 1, str(pkt))
        verify_packet(self, exp_pkt, swports[2])
        verify_no_other_packets(self)
        # ip_acl cleanup
        self.client.switcht_api_acl_remove(0, acl, if2)
        self.client.switcht_api_acl_rule_delete(0, acl, ace)
        self.client.switcht_api_acl_list_delete(0, acl)
        #cleanup
        self.client.switcht_api_neighbor_entry_remove(0, neighbor)
        self.client.switcht_api_nhop_delete(0, nhop)
        self.client.switcht_api_l3_route_delete(0, vrf, i_ip3, if2)

        self.client.switcht_api_l3_interface_address_delete(0, if1, vrf, i_ip1)
        self.client.switcht_api_l3_interface_address_delete(0, if2, vrf, i_ip2)

        self.client.switcht_api_interface_delete(0, if1)
        self.client.switcht_api_interface_delete(0, if2)

        self.client.switcht_api_router_mac_delete(0, rmac, '00:77:66:55:44:33')
        self.client.switcht_api_router_mac_group_delete(0, rmac)
        self.client.switcht_api_vrf_delete(0, vrf)


###############################################################################
@group('acl')
@group('mirror')
class MirrorAclTest_i2e_erspan(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print "Test i2e Erspan Mirror packet port %d" % swports[1], "  -> port %d" % swports[2], "  (192.168.0.1 -> 10.0.0.1 [id = 101])"
        self.client.switcht_api_init(0)
        vrf = self.client.switcht_api_vrf_create(0, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device=0)
        self.client.switcht_api_router_mac_add(0, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = swports[1])
        i_info1 = switcht_interface_info_t(device=0, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(0, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = swports[2])
        i_info2 = switcht_interface_info_t(device=0, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(0, i_info2)
        i_ip2 = switcht_ip_addr_t(ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(ipaddr='10.10.10.1', prefix_length=32)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(0, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop,
                                                 interface_handle=if2,
                                                 mac_addr='00:11:22:33:44:55',
                                                 ip_addr=i_ip3,
                                                 rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(0, neighbor_entry)
        self.client.switcht_api_l3_route_add(0, vrf, i_ip3, nhop)

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

        iu4 = interface_union(port_lag_handle = 4)
        i_info4 = switcht_interface_info_t(device=0, type=4, u=iu4, mac='00:44:44:44:44:44', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if4 = self.client.switcht_api_interface_create(0, i_info4)
        i_ip4 = switcht_ip_addr_t(ipaddr='10.0.0.4', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if4, vrf, i_ip4)

        # Create an ERSPAN tunnel interface
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='4.4.4.1', prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='4.4.4.3', prefix_length=32)
        encap_info = switcht_encap_info_t(encap_type=7)
        ip_encap =  switcht_ip_encap_t(vrf=vrf, src_ip=src_ip, dst_ip=dst_ip, ttl=60, proto=47)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        iut = switcht_tunnel_info_t(encap_mode = 0, tunnel_encap=tunnel_encap, encap_info=encap_info, out_if=if4)
        ift = self.client.switcht_api_tunnel_interface_create(0, 0, iut)

        # Create a logical network (LN)
        bt = switcht_bridge_type(tunnel_vni=0x1234)
        encap = switcht_encap_info_t(u=bt)
        #encap_type 3 is vxlan
        lognet_info = switcht_logical_network_t(type=4, encap_info=encap, age_interval=1800, vrf=vrf)
        ln1 = self.client.switcht_api_logical_network_create(0, lognet_info)
        self.client.switcht_api_logical_network_member_add(0, ln1, ift)

        # create erspan tunnel nexthop
        nhop_key1 = switcht_nhop_key_t(intf_handle=ift, ip_addr_valid=0)
        nhop1 = self.client.switcht_api_nhop_create(0, nhop_key1)
        neighbor_entry1 = switcht_neighbor_info_t(nhop_handle=nhop1,
                                                  interface_handle=ift,
                                                  mac_addr='00:44:44:44:44:44',
                                                  ip_addr=src_ip,
                                                  rw_type=0, neigh_type=7)
        neighbor1 = self.client.switcht_api_neighbor_entry_add(0, neighbor_entry1)

        neighbor_entry2 = switcht_neighbor_info_t(nhop_handle=0,
                                                  interface_handle=ift,
                                                  mac_addr='00:44:44:44:44:44',
                                                  ip_addr=src_ip)
        neighbor2 = self.client.switcht_api_neighbor_entry_add(0, neighbor_entry2)

        # create a mirror session
        minfo1 = switcht_mirror_info_t(session_id=85, direction=1,
                                      egress_port=4, mirror_type=3,
                                      session_type=0,
                                      cos=0, max_pkt_len=0,
                                      ttl=0, enable=1, nhop_handle=nhop1)
        mirror1 = self.client.switcht_api_mirror_session_create(0, minfo1)

        print "Create Mirror ACL to mirror i2e from 1->4"
        acl = self.client.switcht_api_acl_list_create(0, 0)
        # create kvp to match destination IP
        kvp = []
        kvp.append(switcht_acl_ip_key_value_pair_t(1, int("0a0a0a01", 16), int("ffffffff", 16)))
        action = 9
        action_param = switcht_acl_action_params_t(mirror = switcht_acl_action_mirror(mirror_handle=mirror1))
        ace = self.client.switcht_api_acl_ip_rule_create(0, acl, 10, 1, kvp, action, action_param)
        self.client.switcht_api_acl_reference(0, acl, if1)

        # egress interface if4
        send_packet(self, 1, str(pkt))
        # verify mirrored packet
        exp_mirrored_pkt = ipv4_erspan_pkt(eth_dst='00:44:44:44:44:44',
                                           eth_src='00:77:66:55:44:33',
                                           ip_src='4.4.4.1',
                                           ip_dst='4.4.4.3',
                                           ip_id=0,
                                           ip_ttl=64,
                                           version=2,
                                           mirror_id=(mirror1 & 0x3FFFFFFF),
                                           inner_frame=pkt);
        # verify mirrored and original pkts
        time.sleep(1)
        verify_erspan3_packet(self, exp_mirrored_pkt, swports[4])
        verify_packet(self, exp_pkt, swports[2])
        verify_no_other_packets(self)

        # delete the mirror sesion
        print "Delete Egress Mirror Session and test packet again"
        self.client.switcht_api_mirror_session_delete(0, mirror1)
        # clean-up test, make sure pkt is not mirrored after session is deleted
        send_packet(self, 1, str(pkt))
        verify_packet(self, exp_pkt, swports[2])
        verify_no_other_packets(self)
        # ip_acl cleanup
        self.client.switcht_api_acl_remove(0, acl, if1)
        self.client.switcht_api_acl_rule_delete(0, acl, ace)
        self.client.switcht_api_acl_list_delete(0, acl)
        #cleanup
        self.client.switcht_api_neighbor_entry_remove(0, neighbor)
        self.client.switcht_api_nhop_delete(0, nhop)
        self.client.switcht_api_neighbor_entry_remove(0, neighbor1)
        self.client.switcht_api_nhop_delete(0, nhop1)
        self.client.switcht_api_neighbor_entry_remove(0, neighbor2)

        self.client.switcht_api_l3_route_delete(0, vrf, i_ip3, if2)

        self.client.switcht_api_logical_network_member_remove(0, ln1, ift)
        self.client.switcht_api_logical_network_delete(0, ln1)

        self.client.switcht_api_l3_interface_address_delete(0, if1, vrf, i_ip1)
        self.client.switcht_api_l3_interface_address_delete(0, if2, vrf, i_ip2)
        self.client.switcht_api_l3_interface_address_delete(0, if4, vrf, i_ip4)

        self.client.switcht_api_interface_delete(0, if1)
        self.client.switcht_api_interface_delete(0, if2)
        self.client.switcht_api_interface_delete(0, if4)
        self.client.switcht_api_interface_delete(0, ift)

        self.client.switcht_api_router_mac_delete(0, rmac, '00:77:66:55:44:33')
        self.client.switcht_api_router_mac_group_delete(0, rmac)
        self.client.switcht_api_vrf_delete(0, vrf)
