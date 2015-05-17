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
Thrift PD interface basic tests
"""

import time
import sys
import logging

import unittest
import random

import oftest.dataplane as dataplane
import oftest.pd_base_tests as pd_base_tests

from oftest.testutils import *

import os

from utils import *

from p4_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *
from mc_pd_rpc.ttypes import *

this_dir = os.path.dirname(os.path.abspath(__file__))

#global defaults
inner_rmac_group = 1
outer_rmac_group = 2
rewrite_index = 1
vrf = 1
rmac = '00:33:33:33:33:33'

#Enable features based on p4src/p4feature.h
tunnel_enabled =1
ipv6_enabled = 1
acl_enabled = 1
learn_timeout = 6

def populate_default_entries(client, sess_hdl, dev_tgt):
    client.validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet(
                                     sess_hdl, dev_tgt)
    client.validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_packet(
                                     sess_hdl, dev_tgt)
    client.validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_packet(
                                     sess_hdl, dev_tgt)
    client.smac_set_default_action_smac_miss(
                                     sess_hdl, dev_tgt)
    client.dmac_set_default_action_dmac_miss(
                                     sess_hdl, dev_tgt)
    client.learn_notify_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.rmac_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
    client.ipv4_fib_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
    client.fwd_result_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.nexthop_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.egress_block_set_default_action_set_egress_drop(
                                     sess_hdl, dev_tgt)
    client.rid_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.rewrite_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.egress_vlan_xlate_set_default_action_nop(
                                     sess_hdl, dev_tgt)

    if acl_enabled:
        client.ip_acl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.ipv4_racl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.validate_packet_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    if tunnel_enabled:
        client.outer_rmac_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.ipv4_src_vtep_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.ipv4_dest_vtep_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.egress_bd_map_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    if ipv6_enabled and tunnel_enabled:
        client.ipv6_src_vtep_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.ipv6_dest_vtep_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    if ipv6_enabled and acl_enabled:
        client.ipv6_acl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.ipv6_racl_set_default_action_nop(
                                     sess_hdl, dev_tgt)

def populate_init_entries(client, sess_hdl, dev_tgt):
    match_spec = dc_example_mac_rewrite_match_spec_t(
                            l2_metadata_egress_smac_idx=rewrite_index,
                            ipv4_dstAddr=0,
                            ipv4_dstAddr_mask=0)
    action_spec = dc_example_rewrite_unicast_mac_action_spec_t(
                            action_smac=macAddr_to_string(rmac))
    client.mac_rewrite_table_add_with_rewrite_unicast_mac(
                            sess_hdl, dev_tgt,
                            match_spec, 1000, action_spec)

    match_spec = dc_example_fwd_result_match_spec_t(
                            l2_metadata_l2_redirect=0,
                            l2_metadata_l2_redirect_mask=0,
                            acl_metadata_acl_redirect=0,
                            acl_metadata_acl_redirect_mask=0,
                            acl_metadata_racl_redirect=0,
                            acl_metadata_racl_redirect_mask=0,
                            l3_metadata_fib_hit=1,
                            l3_metadata_fib_hit_mask=1)
    client.fwd_result_table_add_with_set_fib_redirect_action(
                            sess_hdl, dev_tgt,
                            match_spec, 1000)

    match_spec = dc_example_fwd_result_match_spec_t(
                            l2_metadata_l2_redirect=1,
                            l2_metadata_l2_redirect_mask=1,
                            acl_metadata_acl_redirect=0,
                            acl_metadata_acl_redirect_mask=0,
                            acl_metadata_racl_redirect=0,
                            acl_metadata_racl_redirect_mask=0,
                            l3_metadata_fib_hit=0,
                            l3_metadata_fib_hit_mask=0)
    client.fwd_result_table_add_with_set_l2_redirect_action(
                            sess_hdl, dev_tgt,
                            match_spec, 1000)

    #Add default inner rmac entry
    match_spec = dc_example_rmac_match_spec_t(
                           l3_metadata_rmac_group=inner_rmac_group,
                           l2_metadata_lkp_mac_da=macAddr_to_string(rmac))
    client.rmac_table_add_with_set_rmac_hit_flag(
                           sess_hdl, dev_tgt,
                           match_spec)

    match_spec = dc_example_egress_system_acl_match_spec_t(
                           l3_metadata_mtu_check_fail=0,
                           l3_metadata_mtu_check_fail_mask=0,
                           l2_metadata_prune=0,
                           l2_metadata_prune_mask=0x3FF)
    client.egress_system_acl_table_add_with_egress_drop(
                            sess_hdl, dev_tgt,
                            match_spec, 1000)

    if tunnel_enabled:
        #Add default outer rmac entry
        match_spec = dc_example_outer_rmac_match_spec_t(
                            tunnel_metadata_outer_rmac_group=outer_rmac_group,
                            l2_metadata_lkp_mac_da=macAddr_to_string(rmac))
        client.outer_rmac_table_add_with_set_outer_rmac_hit_flag(
                            sess_hdl, dev_tgt,
                            match_spec)


def add_ports(client, sess_hdl, dev_tgt, port_count):
    count = 1
    while (count <= port_count):
        match_spec = dc_example_port_mapping_match_spec_t(standard_metadata_ingress_port=count)
        action_spec = dc_example_set_ifindex_action_spec_t(
                            action_ifindex=count,
                            action_if_label=0)
        client.port_mapping_table_add_with_set_ifindex(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)

        action_spec = dc_example_set_lag_port_action_spec_t(
                              action_port=count)
        mbr_hdl = client.lag_action_profile_add_member_with_set_lag_port(
                             sess_hdl, dev_tgt,
                             action_spec)
        match_spec = dc_example_lag_group_match_spec_t(
                             l2_metadata_egress_ifindex=count)
        client.lag_group_add_entry(
                              sess_hdl, dev_tgt,
                              match_spec, mbr_hdl)
        count = count + 1

def program_outer_vlan(client, sess_hdl, dev_tgt, vlan, port, v4_enabled, v6_enabled, outer_rmac):

    action_spec = dc_example_set_bd_action_spec_t(
                            action_outer_vlan_bd=vlan,
                            action_vrf=vrf,
                            action_rmac_group=outer_rmac,
                            action_ipv4_unicast_enabled=v4_enabled,
                            action_ipv6_unicast_enabled=v6_enabled,
                            action_stp_group=0)
    mbr_hdl = client.outer_bd_action_profile_add_member_with_set_bd(
                            sess_hdl, dev_tgt,
                            action_spec)

    match_spec = dc_example_port_vlan_mapping_match_spec_t(
                            l2_metadata_ifindex=port,
                            vlan_tag__0__valid=0,
                            vlan_tag__0__vid=0,
                            vlan_tag__1__valid=0,
                            vlan_tag__1__vid=0)
    client.port_vlan_mapping_add_entry(
                            sess_hdl, dev_tgt,
                            match_spec, mbr_hdl)

def program_inner_vlan(client, sess_hdl, dev_tgt, vlan, v4_enabled, v6_enabled, inner_rmac, uuc_mc_index):
    match_spec = dc_example_bd_match_spec_t(
                              l2_metadata_bd=vlan)
    action_spec = dc_example_set_bd_info_action_spec_t(
                            action_vrf=vrf,
                            action_rmac_group=inner_rmac,
                            action_bd_label=0,
                            action_uuc_mc_index=uuc_mc_index,
                            action_umc_mc_index=0,
                            action_bcast_mc_index=0,
                            action_ipv4_unicast_enabled=v4_enabled,
                            action_ipv6_unicast_enabled=v6_enabled,
                            action_igmp_snooping_enabled=0,
                            action_mld_snooping_enabled=0,
                            action_stp_group=0)
    client.bd_table_add_with_set_bd_info(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)

def program_tunnel_vlan(client, sess_hdl, dev_tgt, vlan, port, vni, ttype, v4_enabled, inner_rmac):
    match_spec = dc_example_tunnel_match_spec_t(
                             tunnel_metadata_tunnel_vni=vni,
                             tunnel_metadata_ingress_tunnel_type=ttype,
                             inner_ipv4_valid=1)
    action_spec = dc_example_terminate_tunnel_inner_ipv4_action_spec_t(
                            action_bd=vlan,
                            action_vrf=vrf,
                            action_rmac_group=inner_rmac,
                            action_bd_label=0,
                            action_uuc_mc_index=0,
                            action_umc_mc_index=0,
                            action_bcast_mc_index=0,
                            action_ipv4_unicast_enabled=v4_enabled,
                            action_igmp_snooping_enabled=0)
    client.tunnel_table_add_with_terminate_tunnel_inner_ipv4(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)

def add_mac(client, sess_hdl, dev_tgt, vlan, mac, port):
    match_spec = dc_example_dmac_match_spec_t(
                            l2_metadata_lkp_mac_da=macAddr_to_string(mac),
                            l2_metadata_bd=vlan)
    action_spec = dc_example_dmac_hit_action_spec_t(
                            action_ifindex=port)
    client.dmac_table_add_with_dmac_hit(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec, 0)

    match_spec = dc_example_smac_match_spec_t(
                            l2_metadata_lkp_mac_sa=macAddr_to_string(mac),
                            l2_metadata_bd=vlan)
    action_spec = dc_example_smac_hit_action_spec_t(
                            action_ifindex=port)
    client.smac_table_add_with_smac_hit(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)

def add_mac_with_nexthop(client, sess_hdl, dev_tgt, vlan, mac, port, nhop):
    match_spec = dc_example_dmac_match_spec_t(
                            l2_metadata_lkp_mac_da=macAddr_to_string(mac),
                            l2_metadata_bd=vlan)
    action_spec = dc_example_dmac_redirect_nexthop_action_spec_t(
                            action_nexthop_index=nhop)
    client.dmac_table_add_with_dmac_redirect_nexthop(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec, 0)

    match_spec = dc_example_smac_match_spec_t(
                            l2_metadata_lkp_mac_sa=macAddr_to_string(mac),
                            l2_metadata_bd=vlan)
    action_spec = dc_example_smac_hit_action_spec_t(
                            action_ifindex=port)
    client.smac_table_add_with_smac_hit(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)

def add_v4_route(client, sess_hdl, dev_tgt, vrf, ip, prefix, nhop):
    if prefix == 32:
        match_spec = dc_example_ipv4_fib_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv4_metadata_lkp_ipv4_da=ip)
        action_spec = dc_example_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        client.ipv4_fib_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    else:
        match_spec = dc_example_ipv4_fib_lpm_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv4_metadata_lkp_ipv4_da=ip,
                             ipv4_metadata_lkp_ipv4_da_prefix_length=prefix)
        action_spec = dc_example_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        client.ipv4_fib_lpm_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)

def add_v6_route(client, sess_hdl, dev_tgt, vrf, ip, prefix, nhop):
    if ipv6_enabled == 0:
        return
    if prefix == 128:
        match_spec = dc_example_ipv6_fib_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv6_metadata_lkp_ipv6_da=ipv6Addr_to_string(ip))
        action_spec = dc_example_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        client.ipv6_fib_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    else:
        match_spec = dc_example_ipv6_fib_lpm_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv6_metadata_lkp_ipv6_da=ip,
                             ipv6_metadata_lkp_ipv6_da_prefix_length=prefix)
        action_spec = dc_example_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        client.ipv6_fib_lpm_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)

def add_nexthop(client, sess_hdl, dev_tgt, nhop, vlan, ifindex):
    match_spec = dc_example_nexthop_match_spec_t(
                             l3_metadata_nexthop_index=nhop)
    action_spec = dc_example_set_nexthop_details_action_spec_t(
                             action_ifindex=ifindex,
                             action_bd=vlan)
    client.nexthop_table_add_with_set_nexthop_details(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)

def add_v4_unicast_rewrite(client, sess_hdl, dev_tgt, nhop, dmac):
    match_spec = dc_example_rewrite_match_spec_t(
                             l3_metadata_nexthop_index=nhop)
    action_spec = dc_example_set_ipv4_unicast_rewrite_action_spec_t(
                             action_smac_idx=rewrite_index,
                             action_dmac=macAddr_to_string(dmac))
    client.rewrite_table_add_with_set_ipv4_unicast_rewrite(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)

def add_v6_unicast_rewrite(client, sess_hdl, dev_tgt, nhop, dmac):
    if ipv6_enabled == 0:
        return
    match_spec = dc_example_rewrite_match_spec_t(
                             l3_metadata_nexthop_index=nhop)
    action_spec = dc_example_set_ipv6_unicast_rewrite_action_spec_t(
                             action_smac_idx=rewrite_index,
                             action_dmac=macAddr_to_string(dmac))
    client.rewrite_table_add_with_set_ipv6_unicast_rewrite(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)

def enable_learning(client, sess_hdl, dev_tgt):
    match_spec = dc_example_learn_notify_match_spec_t(
                             l2_metadata_l2_src_miss=1,
                             l2_metadata_l2_src_miss_mask=1,
                             l2_metadata_l2_src_move=0,
                             l2_metadata_l2_src_move_mask=0,
                             l2_metadata_stp_state=0,
                             l2_metadata_stp_state_mask=0)

    client.learn_notify_table_add_with_generate_learn_notify(
                             sess_hdl, dev_tgt,
                             match_spec, 1000)

#Basic L2 Test case
class L2Test(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc_example")

    def runTest(self):
        print
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        print "Cleaning state"
        self.client.clean_all(sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        add_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan=10
        port1=1
        port2=2
        v4_enabled=0
        v6_enabled=0

        #Add ports to vlan
        #Outer vlan table programs (port, vlan) mapping and derives the bd
        #Inner vlan table derives the bd state
        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan, port1, v4_enabled, v6_enabled, 0)
        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan, port2, v4_enabled, v6_enabled, 0)

        program_inner_vlan(self.client, sess_hdl, dev_tgt, vlan, v4_enabled, v6_enabled, 0, 0)

        #Add static macs to ports. (vlan, mac -> port)
        add_mac(self.client, sess_hdl, dev_tgt, vlan, '00:11:11:11:11:11', 1)
        add_mac(self.client, sess_hdl, dev_tgt, vlan, '00:22:22:22:22:22', 2)

        print "Sending packet port 1 -> port 2 on vlan 10 (192.168.0.1 -> 10.0.0.1 [id = 101])"
        pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                ip_id=101,
                                ip_ttl=64,
                                ip_ihl=5)
        self.dataplane.send(1, str(pkt))
        verify_packets(self, pkt, [2])

#Basic L3 Test case
class L3Ipv4Test(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc_example")

    def runTest(self):
        print
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        print "Cleaning state"
        self.client.clean_all(sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        add_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan1=10
        vlan2=11
        port1=1
        port2=2
        v4_enabled=1
        v6_enabled=0

        #For every L3 port, an implicit vlan will be allocated
        #Add ports to vlan
        #Outer vlan table programs (port, vlan) mapping and derives the bd
        #Inner vlan table derives the bd state
        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan1, port1, v4_enabled, v6_enabled, 0)
        program_inner_vlan(self.client, sess_hdl, dev_tgt, vlan1, v4_enabled, v6_enabled, inner_rmac_group, 0)

        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan2, port2, v4_enabled, v6_enabled, 0)
        program_inner_vlan(self.client, sess_hdl, dev_tgt, vlan2, v4_enabled, v6_enabled, inner_rmac_group, 0)

        #Create nexthop
        nhop1=1
        add_nexthop(self.client, sess_hdl, dev_tgt, nhop1, vlan1, port1)
        #Add rewrite information (ARP info)
        add_v4_unicast_rewrite(self.client, sess_hdl, dev_tgt, nhop1, '00:11:11:11:11:11')
        #Add route
        add_v4_route(self.client, sess_hdl, dev_tgt, vrf, 0x0a0a0a01, 32, nhop1)
        #Create nexthop
        nhop2=2
        add_nexthop(self.client, sess_hdl, dev_tgt, nhop2, vlan2, port2)
        #Add rewrite information (ARP info)
        add_v4_unicast_rewrite(self.client, sess_hdl, dev_tgt, nhop2, '00:22:22:22:22:22')
        #Add route
        add_v4_route(self.client, sess_hdl, dev_tgt, vrf, 0x14141401, 32, nhop2)

        print "Sending packet port 1 -> port 2 (10.10.10.1 -> 20.20.20.1 [id = 101])"
        pkt = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='20.20.20.1',
                                ip_src='10.10.10.1',
                                ip_id=101,
                                ip_ttl=64,
                                ip_ihl=5)
        exp_pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                eth_src='00:33:33:33:33:33',
                                ip_dst='20.20.20.1',
                                ip_src='10.10.10.1',
                                ip_id=101,
                                ip_ttl=63,
                                ip_ihl=5)
        self.dataplane.send(1, str(pkt))
        verify_packets(self, exp_pkt, [2])

class L3Ipv6Test(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc_example")

    def runTest(self):
        print
        if ipv6_enabled == 0:
            print "ipv6 not enabled"
            return

        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        print "Cleaning state"
        self.client.clean_all(sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        add_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan1=10
        vlan2=11
        port1=1
        port2=2
        v4_enabled=0
        v6_enabled=1

        #For every L3 port, an implicit vlan will be allocated
        #Add ports to vlan
        #Outer vlan table programs (port, vlan) mapping and derives the bd
        #Inner vlan table derives the bd state
        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan1, port1, v4_enabled, v6_enabled, 0)
        program_inner_vlan(self.client, sess_hdl, dev_tgt, vlan1, v4_enabled, v6_enabled, inner_rmac_group, 0)

        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan2, port2, v4_enabled, v6_enabled, 0)
        program_inner_vlan(self.client, sess_hdl, dev_tgt, vlan2, v4_enabled, v6_enabled, inner_rmac_group, 0)

        #Create nexthop
        nhop1=1
        add_nexthop(self.client, sess_hdl, dev_tgt, nhop1, vlan1, port1)
        #Add rewrite information (ARP info)
        add_v6_unicast_rewrite(self.client, sess_hdl, dev_tgt, nhop1, '00:11:11:11:11:11')
        #Add route
        add_v6_route(self.client, sess_hdl, dev_tgt, vrf, '2000::1', 128, nhop1)
        #Create nexthop
        nhop2=2
        add_nexthop(self.client, sess_hdl, dev_tgt, nhop2, vlan2, port2)
        #Add rewrite information (ARP info)
        add_v6_unicast_rewrite(self.client, sess_hdl, dev_tgt, nhop2, '00:22:22:22:22:22')
        #Add route
        add_v6_route(self.client, sess_hdl, dev_tgt, vrf, '3000::1', 128, nhop2)

        print "Sending packet port 1 -> port 2 (10.10.10.1 -> 20.20.20.1 [id = 101])"
        pkt = simple_tcpv6_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:11:11:11:11:11',
                                ipv6_dst='3000::1',
                                ipv6_src='2000::1',
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(eth_dst='00:22:22:22:22:22',
                                eth_src='00:33:33:33:33:33',
                                ipv6_dst='3000::1',
                                ipv6_src='2000::1',
                                ipv6_hlim=63)
        self.dataplane.send(1, str(pkt))
        verify_packets(self, exp_pkt, [2])

#Basic Vxlan Tunneling Test case
class L2VxlanTunnelTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc_example")

    def runTest(self):
        print
        if tunnel_enabled == 0:
            print "tunnel not enabled"
            return

        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        print "Cleaning state"
        self.client.clean_all(sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        add_ports(self.client, sess_hdl, dev_tgt, 2)

        port1=1
        port2=2
        outer_v4_enabled=1
        inner_v4_enabled=0
        outer_v6_enabled=0
        inner_v6_enabled=0
        core_vlan=10
        tenant_vlan=1000
        vnid=0x1234

        #Indicates vxlan tunnel in Parser
        tunnel_type=1
        #Port2 belong to core vlan
        #Outer vlan table will derive core bd and the src vtep, dest vtep and vnid will derive the tenant bd
        program_outer_vlan(self.client, sess_hdl, dev_tgt, core_vlan, port2, outer_v4_enabled, outer_v6_enabled, outer_rmac_group)
        program_tunnel_vlan(self.client, sess_hdl, dev_tgt, tenant_vlan, port2, vnid, tunnel_type, inner_v4_enabled, 0)

        #Port1 belong to tenant vlan
        #Outer vlan table will derive tenant bd and inner bd table will derive bd state
        program_outer_vlan(self.client, sess_hdl, dev_tgt, tenant_vlan, port1, inner_v4_enabled, inner_v6_enabled, 0)
        program_inner_vlan(self.client, sess_hdl, dev_tgt, tenant_vlan, inner_v4_enabled, inner_v6_enabled, 0, 0)

        #Ingress Tunnel Decap - src vtep entry
        match_spec = dc_example_ipv4_src_vtep_match_spec_t(
                                  l3_metadata_vrf=vrf,
                                  ipv4_metadata_lkp_ipv4_sa=0x0a0a0a02)
        action_spec = dc_example_set_tunnel_lif_action_spec_t(
                                  action_lif=0)
        self.client.ipv4_src_vtep_table_add_with_set_tunnel_lif(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)

        #Ingress Tunnel Decap - dest vtep entry
        match_spec = dc_example_ipv4_dest_vtep_match_spec_t(
                                  l3_metadata_vrf=vrf,
                                  ipv4_metadata_lkp_ipv4_da=0x0a0a0a01,
                                  l3_metadata_lkp_ip_proto=17,
                                  l3_metadata_lkp_l4_dport=4789)
        self.client.ipv4_dest_vtep_table_add_with_set_tunnel_termination_flag(
                                  sess_hdl, dev_tgt,
                                  match_spec)

        #Add static macs to ports. (vlan, mac -> port)
        #Nextop should be created during mac lookup when the destinaion interface is a tunnel.
        #Nexthop allocated will derive egress bd in the ingress and derive rewrite info
        # at egress
        nhop=1
        add_mac(self.client, sess_hdl, dev_tgt, tenant_vlan, '00:11:11:11:11:11', port1)
        add_mac_with_nexthop(self.client, sess_hdl, dev_tgt, tenant_vlan, '00:22:22:22:22:22', port2, nhop)

        #add nexthop table
        add_nexthop(self.client, sess_hdl, dev_tgt, nhop, tenant_vlan, port2)

        #Egress Tunnel Encap - Rewrite information
        match_spec = dc_example_rewrite_match_spec_t(
                                  l3_metadata_nexthop_index=nhop)
        action_spec = dc_example_set_ipv4_vxlan_rewrite_action_spec_t(
                                  action_outer_bd=core_vlan,
                                  action_tunnel_src_index=0,
                                  action_tunnel_dst_index=0,
                                  action_smac_idx=rewrite_index,
                                  action_dmac=macAddr_to_string('00:55:55:55:55:55'))
        self.client.rewrite_table_add_with_set_ipv4_vxlan_rewrite(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)

        #Egress Tunnel Encap - Add tunnel header based on tunnel type
        match_spec = dc_example_tunnel_rewrite_match_spec_t(
                                  tunnel_metadata_egress_tunnel_type=tunnel_type,
                                  ipv4_valid=1,
                                  tcp_valid=1,
                                  udp_valid=0)
        self.client.tunnel_rewrite_table_add_with_ipv4_vxlan_inner_ipv4_tcp_rewrite(
                                  sess_hdl, dev_tgt,
                                  match_spec)

        #Egress Tunnel Encap - Source IP rewrite
        match_spec = dc_example_tunnel_src_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_src_index=0)
        action_spec = dc_example_rewrite_tunnel_ipv4_src_action_spec_t(
                                  action_ip=0x0a0a0a01)
        self.client.tunnel_src_rewrite_table_add_with_rewrite_tunnel_ipv4_src(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)

        #Egress Tunnel Encap - Destination IP rewrite
        match_spec = dc_example_tunnel_dst_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_dst_index=0)
        action_spec = dc_example_rewrite_tunnel_ipv4_dst_action_spec_t(
                                  action_ip=0x0a0a0a02)
        self.client.tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv4_dst(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)

        #Egress Tunnel Encap - Derive vnid from egress bd mapping
        match_spec = dc_example_egress_bd_map_match_spec_t(
                                  l2_metadata_egress_bd=tenant_vlan)
        action_spec = dc_example_set_egress_bd_properties_action_spec_t(
                                  action_vnid=0x1234)
        self.client.egress_bd_map_table_add_with_set_egress_bd_properties(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)

        #Egress Tunnel Decap - Decapsulate the vxlan header
        match_spec = dc_example_tunnel_decap_match_spec_t(
                                  tunnel_metadata_ingress_tunnel_type=tunnel_type,
                                  inner_ipv4_valid=1,
                                  inner_tcp_valid=1,
                                  inner_udp_valid=0)
        self.client.tunnel_decap_table_add_with_decapsulate_vxlan_packet_inner_ipv4_tcp(
                                  sess_hdl, dev_tgt,
                                  match_spec)


        print "Sending packet port 1 -> port 2 - Vxlan tunnel encap"
        print "Inner packet (192.168.10.1 -> 192.168.20.2 [id = 101])"
        print "Outer packet (10.10.10.1 -> 10.10.10.2 [vnid = 0x1234, id = 101])"
        pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='192.168.10.2',
                                ip_src='192.168.10.1',
                                ip_id=101,
                                ip_ttl=64)
        vxlan_pkt = simple_vxlan_packet(
                                eth_dst='00:55:55:55:55:55',
                                eth_src='00:33:33:33:33:33',
                                ip_id=0,
                                ip_dst='10.10.10.2',
                                ip_src='10.10.10.1',
                                ip_ttl=64,
                                udp_sport=4966,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                inner_frame=pkt)
        self.dataplane.send(1, str(pkt))
        verify_packets(self, vxlan_pkt, [2])

        print "Sending packet port 2 -> port 1 - Vxlan tunnel decap"
        print "Inner packet (192.168.10.2 -> 192.168.20.1 [id = 101])"
        print "Outer packet (10.10.10.2 -> 10.10.10.1 [vnid = 0x1234, id = 101])"
        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='192.168.10.1',
                                ip_src='192.168.10.2',
                                ip_id=101,
                                ip_ttl=64)
        vxlan_pkt = simple_vxlan_packet(
                                eth_dst='00:33:33:33:33:33',
                                eth_src='00:55:55:55:55:55',
                                ip_id=0,
                                ip_dst='10.10.10.1',
                                ip_src='10.10.10.2',
                                ip_ttl=63,
                                udp_sport=4966,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                inner_frame=pkt)
        self.dataplane.send(2, str(vxlan_pkt))
        verify_packets(self, pkt, [1])

class L3VxlanTunnelTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc_example")

    def runTest(self):
        print
        if tunnel_enabled == 0:
            print "tunnel not enabled"
            return
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        print "Cleaning state"
        self.client.clean_all(sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        add_ports(self.client, sess_hdl, dev_tgt, 2)

        port1=1
        port2=2
        outer_v4_enabled=1
        inner_v4_enabled=1
        outer_v6_enabled=0
        inner_v6_enabled=0
        core_vlan=10
        tenant_vlan1=1000
        tenant_vlan2=2000
        vnid=0x1234

        #Indicates vxlan tunnel in Parser
        tunnel_type=1
        #Port2 belong to core vlan
        #Outer vlan table will derive core bd and the src vtep, dest vtep and vnid will derive the tenant bd
        program_outer_vlan(self.client, sess_hdl, dev_tgt, core_vlan, port2, outer_v4_enabled, outer_v6_enabled, outer_rmac_group)
        program_tunnel_vlan(self.client, sess_hdl, dev_tgt, tenant_vlan2, port2, vnid, tunnel_type, inner_v4_enabled, inner_rmac_group)

        #Port1 belong to tenant vlan
        #Outer vlan table will derive tenant bd and inner bd table will derive bd state
        program_outer_vlan(self.client, sess_hdl, dev_tgt, tenant_vlan1, port1, inner_v4_enabled, inner_v6_enabled, 0)
        program_inner_vlan(self.client, sess_hdl, dev_tgt, tenant_vlan1, inner_v4_enabled, inner_v6_enabled, inner_rmac_group, 0)

        #Ingress Tunnel Decap - src vtep entry
        match_spec = dc_example_ipv4_src_vtep_match_spec_t(
                                  l3_metadata_vrf=vrf,
                                  ipv4_metadata_lkp_ipv4_sa=0x0a0a0a02)
        action_spec = dc_example_set_tunnel_lif_action_spec_t(
                                  action_lif=0)
        self.client.ipv4_src_vtep_table_add_with_set_tunnel_lif(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)

        #Ingress Tunnel Decap - dest vtep entry
        match_spec = dc_example_ipv4_dest_vtep_match_spec_t(
                                  l3_metadata_vrf=vrf,
                                  ipv4_metadata_lkp_ipv4_da=0x0a0a0a01,
                                  l3_metadata_lkp_ip_proto=17,
                                  l3_metadata_lkp_l4_dport=4789)
        self.client.ipv4_dest_vtep_table_add_with_set_tunnel_termination_flag(
                                  sess_hdl, dev_tgt,
                                  match_spec)


        #Add L3 routes
        nhop1=1
        nhop2=2
        add_v4_route(self.client, sess_hdl, dev_tgt, vrf, 0x0aa80a01, 32, nhop1)
        add_v4_route(self.client, sess_hdl, dev_tgt, vrf, 0x0aa80b01, 32, nhop2)

        #Add nexthop table
        add_nexthop(self.client, sess_hdl, dev_tgt, nhop1, tenant_vlan1, port1)
        add_nexthop(self.client, sess_hdl, dev_tgt, nhop2, tenant_vlan2, port2)

        #Egress Tunnel Encap - Rewrite information
        match_spec = dc_example_rewrite_match_spec_t(
                                  l3_metadata_nexthop_index=nhop2)
        action_spec = dc_example_set_ipv4_vxlan_rewrite_action_spec_t(
                                  action_outer_bd=core_vlan,
                                  action_tunnel_src_index=0,
                                  action_tunnel_dst_index=0,
                                  action_smac_idx=rewrite_index,
                                  action_dmac=macAddr_to_string('00:55:55:55:55:55'))
        self.client.rewrite_table_add_with_set_ipv4_vxlan_rewrite(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)

        #Egress Tunnel Encap - Add tunnel header based on tunnel type
        match_spec = dc_example_tunnel_rewrite_match_spec_t(
                                  tunnel_metadata_egress_tunnel_type=tunnel_type,
                                  ipv4_valid=1,
                                  tcp_valid=1,
                                  udp_valid=0)
        self.client.tunnel_rewrite_table_add_with_ipv4_vxlan_inner_ipv4_tcp_rewrite(
                                  sess_hdl, dev_tgt,
                                  match_spec)

        #Egress Tunnel Encap - Source IP rewrite
        match_spec = dc_example_tunnel_src_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_src_index=0)
        action_spec = dc_example_rewrite_tunnel_ipv4_src_action_spec_t(
                                  action_ip=0x0a0a0a01)
        self.client.tunnel_src_rewrite_table_add_with_rewrite_tunnel_ipv4_src(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)

        #Egress Tunnel Encap - Destination IP rewrite
        match_spec = dc_example_tunnel_dst_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_dst_index=0)
        action_spec = dc_example_rewrite_tunnel_ipv4_dst_action_spec_t(
                                  action_ip=0x0a0a0a02)
        self.client.tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv4_dst(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)

        #Egress Tunnel Encap - Derive vnid from egress bd mapping
        match_spec = dc_example_egress_bd_map_match_spec_t(
                                  l2_metadata_egress_bd=tenant_vlan2)
        action_spec = dc_example_set_egress_bd_properties_action_spec_t(
                                  action_vnid=0x1234)
        self.client.egress_bd_map_table_add_with_set_egress_bd_properties(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)

        #Egress Tunnel Decap - Decapsulate the vxlan header
        match_spec = dc_example_tunnel_decap_match_spec_t(
                                  tunnel_metadata_ingress_tunnel_type=tunnel_type,
                                  inner_ipv4_valid=1,
                                  inner_tcp_valid=1,
                                  inner_udp_valid=0)
        self.client.tunnel_decap_table_add_with_decapsulate_vxlan_packet_inner_ipv4_tcp(
                                  sess_hdl, dev_tgt,
                                  match_spec)

        print "Sending packet port 1 -> port 2 - Vxlan tunnel encap"
        print "Inner packet (10.168.10.1 -> 10.168.11.1 [id = 101])"
        print "Outer packet (10.10.10.1 -> 10.10.10.2 [vnid = 0x1234, id = 101])"
        pkt1 = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='10.168.11.1',
                                ip_src='10.168.10.1',
                                ip_id=101,
                                ip_ttl=64)

        pkt2 = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='10.168.11.1',
                                ip_src='10.168.10.1',
                                ip_id=101,
                                ip_ttl=63)

        vxlan_pkt = simple_vxlan_packet(
                                eth_dst='00:55:55:55:55:55',
                                eth_src='00:33:33:33:33:33',
                                ip_id=0,
                                ip_dst='10.10.10.2',
                                ip_src='10.10.10.1',
                                ip_ttl=63,
                                udp_sport=14479,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                inner_frame=pkt2)

        self.dataplane.send(1, str(pkt1))
        verify_packets(self, vxlan_pkt, [2])

        print "Sending packet port 2 -> port 1 - Vxlan tunnel decap"
        print "Inner packet (10.168.11.1 -> 10.168.10.1 [id = 101])"
        print "Outer packet (10.10.10.2 -> 10.10.10.1 [vnid = 0x1234, id = 101])"
        pkt = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.168.10.1',
                                ip_src='10.168.11.1',
                                ip_id=101,
                                ip_ttl=64)
        vxlan_pkt = simple_vxlan_packet(
                                eth_dst='00:33:33:33:33:33',
                                eth_src='00:55:55:55:55:55',
                                ip_id=0,
                                ip_dst='10.10.10.1',
                                ip_src='10.10.10.2',
                                ip_ttl=64,
                                udp_sport=14479,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                inner_frame=pkt)
        self.dataplane.send(2, str(vxlan_pkt))
        verify_packets(self, pkt, [1])

class L2LearningTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc_example")

    def runTest(self):
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        print "Cleaning state"
        self.client.clean_all(sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        add_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan=10
        port1=1
        port2=2
        v4_enabled=0
        v6_enabled=0

        #Add ports to vlan
        #Outer vlan table programs (port, vlan) mapping and derives the bd
        #Inner vlan table derives the bd state
        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan, port1, v4_enabled, v6_enabled, 0)
        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan, port2, v4_enabled, v6_enabled, 0)

        program_inner_vlan(self.client, sess_hdl, dev_tgt, vlan, v4_enabled, v6_enabled, 0, 0)

        enable_learning(self.client, sess_hdl, dev_tgt)

        self.client.set_learning_timeout(sess_hdl, 0, learn_timeout * 1000)
        self.client.mac_learn_digest_register(sess_hdl, 0)
        pkt = simple_tcp_packet(eth_dst='00:44:44:44:44:44',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.168.10.1',
                                ip_src='10.168.11.1',
                                ip_id=101,
                                ip_ttl=64)
        self.dataplane.send(1, str(pkt))
        time.sleep(learn_timeout + 1)
        digests = self.client.mac_learn_digest_get_digest(sess_hdl)
        assert len(digests.msg) == 1
        print "new mac learnt ",
        for b in string_to_bytes(digests.msg[0].l2_metadata_lkp_mac_sa):
            print("%02x:" % (b)),
        print "on port ", digests.msg[0].l2_metadata_ifindex
        self.client.mac_learn_digest_digest_notify_ack(sess_hdl, digests.msg_ptr)
        self.client.mac_learn_digest_deregister(sess_hdl, 0)

class L2FloodTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc_example")

    def runTest(self):
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        print "Cleaning state"
        self.client.clean_all(sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        add_ports(self.client, sess_hdl, dev_tgt, 4)

        vlan=10
        port1=1
        port2=2
        port3=3
        port4=4
        v4_enabled=0
        v6_enabled=0
        mgid = 0x100
        rid = 0x200

        #Add ports to vlan
        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan, port1, v4_enabled, v6_enabled, 0)
        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan, port2, v4_enabled, v6_enabled, 0)
        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan, port3, v4_enabled, v6_enabled, 0)
        program_outer_vlan(self.client, sess_hdl, dev_tgt, vlan, port4, v4_enabled, v6_enabled, 0)

        program_inner_vlan(self.client, sess_hdl, dev_tgt, vlan, v4_enabled, v6_enabled, 0, mgid)

        port_map = [0] * 32
        lag_map = [0] * 32
        port_map[0] = (1 << port1) + (1 << port2) + (1 << port3) + (1 << port4)
        mgrp_hdl = self.mc.mc_mgrp_create(sess_hdl, dev_tgt, mgid)
        l1_hdl = self.mc.mc_l1_node_create(sess_hdl, dev_tgt, rid)
        self.mc.mc_l1_associate_node(sess_hdl, dev_tgt, mgrp_hdl, l1_hdl)
        l2_hdl = self.mc.mc_l2_node_create(sess_hdl, dev_tgt, l1_hdl, port_map, lag_map)

        pkt = simple_tcp_packet(eth_dst='00:44:44:44:44:44',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.168.10.1',
                                ip_src='10.168.11.1',
                                ip_id=101,
                                ip_ttl=64)

        self.dataplane.send(1, str(pkt))
        verify_packets(self, pkt, [port2, port3, port4])
        time.sleep(1)
        self.mc.mc_l2_node_destroy(sess_hdl, dev_tgt, l2_hdl)
        self.mc.mc_l1_node_destroy(sess_hdl, dev_tgt, l1_hdl)
        self.mc.mc_mgrp_destroy(sess_hdl, dev_tgt, mgrp_hdl)
