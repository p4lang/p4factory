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

import pd_base_tests

from ptf.testutils import *
from ptf.thriftutils import *

import os

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
multicast_enabled = 1
stats_enabled = 1
learn_timeout = 6

def set_port_or_lag_bitmap(bit_map_size, indicies):
    bit_map = [0] * ((bit_map_size+7)/8)
    for index in indicies:
        bit_map[index/8] = (bit_map[index/8] | (1 << (index%8))) & 0xFF
    return bytes_to_string(bit_map)

def populate_default_entries(client, sess_hdl, dev_tgt):
    client.validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_untagged(
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
    client.rmac_set_default_action_rmac_miss(
                                     sess_hdl, dev_tgt)
    client.ipv4_fib_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
    client.fwd_result_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.nexthop_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.rid_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.rewrite_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.egress_vlan_xlate_set_default_action_set_egress_packet_vlan_untagged(
                                     sess_hdl, dev_tgt)
    client.egress_filter_set_default_action_set_egress_filter_drop(
                                     sess_hdl, dev_tgt)
    client.validate_packet_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.storm_control_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.vlan_decap_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.replica_type_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.rewrite_set_default_action_set_l2_rewrite(
                                     sess_hdl, dev_tgt)
    client.egress_port_mapping_set_default_action_egress_port_type_normal(
                                     sess_hdl, dev_tgt)
    client.compute_ipv4_hashes_set_default_action_compute_lkp_ipv4_hash(
                                     sess_hdl, dev_tgt)
    client.compute_ipv6_hashes_set_default_action_compute_lkp_ipv6_hash(
                                     sess_hdl, dev_tgt)
    client.compute_non_ip_hashes_set_default_action_compute_lkp_non_ip_hash(
                                     sess_hdl, dev_tgt)
    client.compute_other_hashes_set_default_action_computed_two_hashes(
                                     sess_hdl, dev_tgt)

    if acl_enabled:
        client.ip_acl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.ipv4_racl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.egress_acl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.qos_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.acl_stats_set_default_action_acl_stats_update(
                                     sess_hdl, dev_tgt)
    if tunnel_enabled:
        client.outer_rmac_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
        client.ipv4_src_vtep_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
        client.ipv4_dest_vtep_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.egress_bd_map_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    if ipv6_enabled and tunnel_enabled:
        client.ipv6_src_vtep_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
        client.ipv6_dest_vtep_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    if ipv6_enabled and acl_enabled:
        client.ipv6_acl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.ipv6_racl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    if stats_enabled:
        client.ingress_bd_stats_set_default_action_update_ingress_bd_stats(
                                     sess_hdl, dev_tgt)

    mbr_hdl = client.fabric_lag_action_profile_add_member_with_nop(
        sess_hdl, dev_tgt
    )
    client.fabric_lag_set_default_entry(
        sess_hdl, dev_tgt,
        mbr_hdl
    )
    client.int_insert_set_default_action_int_reset(sess_hdl, dev_tgt)

def populate_init_entries(client, sess_hdl, dev_tgt):
    ret = []
    match_spec = dc_mac_rewrite_match_spec_t(
                            egress_metadata_smac_idx=rewrite_index,
                            ipv4_valid=1,
                            ipv6_valid=0,
                            mpls_0__valid=0)
    action_spec = dc_rewrite_ipv4_unicast_mac_action_spec_t(
                            action_smac=macAddr_to_string(rmac))
    ret.append(client.mac_rewrite_table_add_with_rewrite_ipv4_unicast_mac(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec))

    match_spec = dc_mac_rewrite_match_spec_t(
                            egress_metadata_smac_idx=rewrite_index,
                            ipv4_valid=0,
                            ipv6_valid=1,
                            mpls_0__valid=0)
    action_spec = dc_rewrite_ipv6_unicast_mac_action_spec_t(
                            action_smac=macAddr_to_string(rmac))
    ret.append(client.mac_rewrite_table_add_with_rewrite_ipv6_unicast_mac(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec))

    match_spec = dc_fwd_result_match_spec_t(
                            l2_metadata_l2_redirect=0,
                            l2_metadata_l2_redirect_mask=0,
                            acl_metadata_acl_redirect=0,
                            acl_metadata_acl_redirect_mask=0,
                            acl_metadata_racl_redirect=0,
                            acl_metadata_racl_redirect_mask=0,
                            l3_metadata_fib_hit=1,
                            l3_metadata_fib_hit_mask=1,
                            l3_metadata_rmac_hit=0,
                            l3_metadata_rmac_hit_mask=0)
    ret.append(client.fwd_result_table_add_with_set_fib_redirect_action(
                            sess_hdl, dev_tgt,
                            match_spec, 1000))

    match_spec = dc_fwd_result_match_spec_t(
                            l2_metadata_l2_redirect=1,
                            l2_metadata_l2_redirect_mask=1,
                            acl_metadata_acl_redirect=0,
                            acl_metadata_acl_redirect_mask=0,
                            acl_metadata_racl_redirect=0,
                            acl_metadata_racl_redirect_mask=0,
                            l3_metadata_fib_hit=0,
                            l3_metadata_fib_hit_mask=0,
                            l3_metadata_rmac_hit=0,
                            l3_metadata_rmac_hit_mask=0)
    ret.append(client.fwd_result_table_add_with_set_l2_redirect_action(
                            sess_hdl, dev_tgt,
                            match_spec, 1000))

    #Add default inner rmac entry
    match_spec = dc_rmac_match_spec_t(
                           l3_metadata_rmac_group=inner_rmac_group,
                           l2_metadata_lkp_mac_da=macAddr_to_string(rmac))
    ret.append(client.rmac_table_add_with_rmac_hit(
                           sess_hdl, dev_tgt,
                           match_spec))

    if tunnel_enabled:
        #Add default outer rmac entry
        match_spec = dc_outer_rmac_match_spec_t(
                            l3_metadata_rmac_group=outer_rmac_group,
                            l2_metadata_lkp_mac_da=macAddr_to_string(rmac))
        ret.append(client.outer_rmac_table_add_with_outer_rmac_hit(
                            sess_hdl, dev_tgt,
                            match_spec))

    return ret

def delete_init_entries(client, sess_hdl, dev, ret_list):
    client.mac_rewrite_table_delete(
                            sess_hdl, dev,
                            ret_list[0])

    client.mac_rewrite_table_delete(
                            sess_hdl, dev,
                            ret_list[1])

    client.fwd_result_table_delete(
                            sess_hdl, dev,
                            ret_list[2])

    client.fwd_result_table_delete(
                            sess_hdl, dev,
                            ret_list[3])

    client.rmac_table_delete(
                           sess_hdl, dev,
                           ret_list[4])

    if tunnel_enabled:
        client.outer_rmac_table_delete(
                            sess_hdl, dev,
                            ret_list[5])


def program_ports(client, sess_hdl, dev_tgt, port_count):
    count = 1
    ret = []
    while (count <= port_count):
        match_spec = dc_ingress_port_mapping_match_spec_t(standard_metadata_ingress_port=count)
        action_spec = dc_set_ifindex_action_spec_t(
                            action_ifindex=count,
                            action_if_label=0,
                            action_port_type=0)
        port_hdl = client.ingress_port_mapping_table_add_with_set_ifindex(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)

        action_spec = dc_set_lag_port_action_spec_t(
                              action_port=count)
        mbr_hdl = client.lag_action_profile_add_member_with_set_lag_port(
                             sess_hdl, dev_tgt,
                             action_spec)

        match_spec = dc_lag_group_match_spec_t(
                             ingress_metadata_egress_ifindex=count)
        lag_hdl = client.lag_group_add_entry(
                              sess_hdl, dev_tgt,
                              match_spec, mbr_hdl)
        ret.append({ 'port': port_hdl, 'mbr' : mbr_hdl, 'lag' : lag_hdl})


        match_spec = dc_egress_lag_match_spec_t(
                              standard_metadata_egress_port=count)
        action_spec = dc_set_egress_ifindex_action_spec_t(
                              action_egress_ifindex=count)
        client.egress_lag_table_add_with_set_egress_ifindex(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
        count = count + 1
    return ret

def delete_ports(client, sess_hdl, dev, port_count, ret_list):
    count = 0
    while (count < port_count):
        client.lag_group_table_delete(
                              sess_hdl, dev,
                             ret_list[count]['lag'])
        client.lag_action_profile_del_member(
                             sess_hdl, dev,
                             ret_list[count]['mbr'])
        client.ingress_port_mapping_table_delete(
                             sess_hdl, dev, ret_list[count]['port'])
        count = count + 1

def program_bd(client, sess_hdl, dev_tgt, vlan, mc_index):
    match_spec = dc_bd_flood_match_spec_t(
                            ingress_metadata_bd=vlan,
                            l2_metadata_lkp_pkt_type=0x1)
    action_spec = dc_set_bd_flood_mc_index_action_spec_t(
                            action_mc_index=mc_index)
    hdl = client.bd_flood_table_add_with_set_bd_flood_mc_index(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)
    return hdl

def delete_bd(client, sess_hdl, dev, hdl):
    client.bd_flood_table_delete(sess_hdl, dev, hdl)
    return 0


def program_vlan_mapping(client, sess_hdl, dev_tgt, vlan, port, v4_enabled,
                         v6_enabled, rmac, learning_enabled):
#    print 'port ' + str(port) + ' vlan ' + str(vlan)
    action_spec = dc_set_bd_action_spec_t(
                            action_bd=vlan,
                            action_vrf=vrf,
                            action_rmac_group=rmac,
                            action_ipv4_unicast_enabled=v4_enabled,
                            action_ipv6_unicast_enabled=v6_enabled,
                            action_bd_label=0,
                            action_igmp_snooping_enabled=0,
                            action_mld_snooping_enabled=0,
                            action_ipv4_urpf_mode=0,
                            action_ipv6_urpf_mode=0,
                            action_stp_group=0,
                            action_stats_idx=0,
                            action_learning_enabled=learning_enabled)
    mbr_hdl = client.bd_action_profile_add_member_with_set_bd(
                            sess_hdl, dev_tgt,
                            action_spec)

    match_spec = dc_port_vlan_mapping_match_spec_t(
                            ingress_metadata_ifindex=port,
                            vlan_tag__0__valid=0,
                            vlan_tag__0__vid=0,
                            vlan_tag__1__valid=0,
                            vlan_tag__1__vid=0)
    hdl = client.port_vlan_mapping_add_entry(
                            sess_hdl, dev_tgt,
                            match_spec, mbr_hdl)
    return hdl, mbr_hdl

def delete_vlan_mapping(client, sess_hdl, dev, hdl, mbr_hdl):
    client.port_vlan_mapping_table_delete(
                            sess_hdl, dev,
                            hdl)
    client.bd_action_profile_del_member(
                            sess_hdl, dev,
                            mbr_hdl)


def program_tunnel_ethernet_vlan(client, sess_hdl, dev_tgt, vlan, port, vni, ttype, v4_enabled, inner_rmac):
    match_spec = dc_tunnel_match_spec_t(
                             tunnel_metadata_tunnel_vni=vni,
                             tunnel_metadata_ingress_tunnel_type=ttype,
                             inner_ipv4_valid=1,
                             inner_ipv6_valid=0)
    action_spec = dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t(
                            action_bd=vlan,
                            action_vrf=vrf,
                            action_rmac_group=inner_rmac,
                            action_bd_label=0,
                            action_ipv4_unicast_enabled=v4_enabled,
                            action_igmp_snooping_enabled=0,
                            action_ipv4_urpf_mode=0,
                            action_stats_idx=0)
    hdl = client.tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv4(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)
    return hdl

def delete_tunnel_ethernet_vlan(client, sess_hdl, dev, hdl):
    client.tunnel_table_delete(
                            sess_hdl, dev,
                            hdl)
    return hdl

def program_tunnel_ipv4_vlan(client, sess_hdl, dev_tgt, vlan, port, vni, ttype, v4_enabled, inner_rmac):
    match_spec = dc_tunnel_match_spec_t(
                             tunnel_metadata_tunnel_vni=vni,
                             tunnel_metadata_ingress_tunnel_type=ttype,
                             inner_ipv4_valid=1,
                             inner_ipv6_valid=0)
    action_spec = dc_terminate_tunnel_inner_ipv4_action_spec_t(
                            action_vrf=vrf,
                            action_rmac_group=inner_rmac,
                            action_ipv4_unicast_enabled=v4_enabled,
                            action_ipv4_urpf_mode=0)
    hdl = client.tunnel_table_add_with_terminate_tunnel_inner_ipv4(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)
    return hdl

def delete_tunnel_ipv4_vlan(client, sess_hdl, dev, hdl):
    client.tunnel_table_delete(
                            sess_hdl, dev,
                            hdl)

def program_mac(client, sess_hdl, dev_tgt, vlan, mac, port):
    match_spec = dc_dmac_match_spec_t(
                            l2_metadata_lkp_mac_da=macAddr_to_string(mac),
                            ingress_metadata_bd=vlan)
    action_spec = dc_dmac_hit_action_spec_t(
                            action_ifindex=port)
    dmac_hdl = client.dmac_table_add_with_dmac_hit(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec, 0)

    match_spec = dc_smac_match_spec_t(
                            l2_metadata_lkp_mac_sa=macAddr_to_string(mac),
                            ingress_metadata_bd=vlan)
    action_spec = dc_smac_hit_action_spec_t(
                            action_ifindex=port)
    smac_hdl = client.smac_table_add_with_smac_hit(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)
    return dmac_hdl, smac_hdl

def program_mac_with_nexthop(client, sess_hdl, dev_tgt, vlan, mac, port, nhop):
    match_spec = dc_dmac_match_spec_t(
                            l2_metadata_lkp_mac_da=macAddr_to_string(mac),
                            ingress_metadata_bd=vlan)
    action_spec = dc_dmac_redirect_nexthop_action_spec_t(
                            action_nexthop_index=nhop)
    dmac_hdl = client.dmac_table_add_with_dmac_redirect_nexthop(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec, 0)

    match_spec = dc_smac_match_spec_t(
                            l2_metadata_lkp_mac_sa=macAddr_to_string(mac),
                            ingress_metadata_bd=vlan)
    action_spec = dc_smac_hit_action_spec_t(
                            action_ifindex=port)
    smac_hdl = client.smac_table_add_with_smac_hit(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)
    return dmac_hdl, smac_hdl

def delete_mac(client, sess_hdl, dev, dmac_hdl, smac_hdl):
    client.dmac_table_delete(
                            sess_hdl, dev,
                            dmac_hdl)

    client.smac_table_delete(
                            sess_hdl, dev,
                            smac_hdl)

def program_ipv4_route(client, sess_hdl, dev_tgt, vrf, ip, prefix, nhop):
    if prefix == 32:
        match_spec = dc_ipv4_fib_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv4_metadata_lkp_ipv4_da=ip)
        action_spec = dc_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        hdl = client.ipv4_fib_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    else:
        match_spec = dc_ipv4_fib_lpm_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv4_metadata_lkp_ipv4_da=ip,
                             ipv4_metadata_lkp_ipv4_da_prefix_length=prefix)
        action_spec = dc_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        hdl = client.ipv4_fib_lpm_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    return hdl

def delete_ipv4_route(client, sess_hdl, dev, prefix, hdl):
    if prefix == 32:
        client.ipv4_fib_table_delete(
                             sess_hdl, dev,
                             hdl)
    else:
        client.ipv4_fib_lpm_table_delete(
                             sess_hdl, dev,
                             hdl)

def program_ipv6_route(client, sess_hdl, dev_tgt, vrf, ip, prefix, nhop):
    if ipv6_enabled == 0:
        return
    if prefix == 128:
        match_spec = dc_ipv6_fib_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv6_metadata_lkp_ipv6_da=ipv6Addr_to_string(ip))
        action_spec = dc_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        hdl = client.ipv6_fib_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    else:
        match_spec = dc_ipv6_fib_lpm_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv6_metadata_lkp_ipv6_da=ip,
                             ipv6_metadata_lkp_ipv6_da_prefix_length=prefix)
        action_spec = dc_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        hdl = client.ipv6_fib_lpm_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    return hdl

def delete_ipv6_route(client, sess_hdl, dev, prefix, hdl):
    if ipv6_enabled == 0:
        return
    if prefix == 128:
        client.ipv6_fib_table_delete(
                             sess_hdl, dev,
                             hdl)
    else:
        client.ipv6_fib_lpm_table_delete(
                             sess_hdl, dev,
                             hdl)

def program_nexthop(client, sess_hdl, dev_tgt, nhop, vlan, ifindex, tunnel):
    match_spec = dc_nexthop_match_spec_t(
                             l3_metadata_nexthop_index=nhop)
    action_spec = dc_set_nexthop_details_action_spec_t(
                             action_ifindex=ifindex,
                             action_bd=vlan,
                             action_tunnel=tunnel)
    hdl = client.nexthop_table_add_with_set_nexthop_details(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    return hdl

def delete_nexthop(client, sess_hdl, dev, hdl):
    client.nexthop_table_delete(
                             sess_hdl, dev,
                             hdl)

def program_ipv4_unicast_rewrite(client, sess_hdl, dev_tgt, bd, nhop, dmac):
    match_spec = dc_rewrite_match_spec_t(
                             l3_metadata_nexthop_index=nhop)
    action_spec = dc_set_l3_rewrite_action_spec_t(
                             action_smac_idx=rewrite_index,
                             action_dmac=macAddr_to_string(dmac),
                             action_bd=bd,
                             action_mtu_index=0)
    hdl = client.rewrite_table_add_with_set_l3_rewrite(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    return hdl

def delete_ipv4_unicast_rewrite(client, sess_hdl, dev, hdl):
    client.rewrite_table_delete(
                             sess_hdl, dev,
                             hdl)

def program_ipv6_unicast_rewrite(client, sess_hdl, dev_tgt, bd, nhop, dmac):
    if ipv6_enabled == 0:
        return
    match_spec = dc_rewrite_match_spec_t(
                             l3_metadata_nexthop_index=nhop)
    action_spec = dc_set_l3_rewrite_action_spec_t(
                             action_smac_idx=rewrite_index,
                             action_dmac=macAddr_to_string(dmac),
                             action_bd=bd,
                             action_mtu_index=0)
    hdl = client.rewrite_table_add_with_set_l3_rewrite(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    return hdl

def delete_ipv6_unicast_rewrite(client, sess_hdl, dev, hdl):
    if ipv6_enabled == 0:
        return
    client.rewrite_table_delete(
                             sess_hdl, dev,
                             hdl)

def program_tunnel_l2_unicast_rewrite(client, sess_hdl, dev_tgt, tunnel_index, tunnel_type, nhop, core_vlan):
    #Egress Tunnel Encap - Rewrite information
    match_spec = dc_rewrite_match_spec_t(
                                  l3_metadata_nexthop_index=nhop)
    action_spec = dc_set_l2_rewrite_with_tunnel_action_spec_t(
                                  action_tunnel_index=tunnel_index,
                                  action_tunnel_type=tunnel_type)
    hdl = client.rewrite_table_add_with_set_l2_rewrite_with_tunnel(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_l2_unicast_rewrite(client, sess_hdl, dev, hdl):
    client.rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_l3_unicast_rewrite(client, sess_hdl, dev_tgt, tunnel_index, tunnel_type, rewrite_index, nhop, core_vlan, dmac):
    #Egress Tunnel Encap - Rewrite information
    match_spec = dc_rewrite_match_spec_t(
                                  l3_metadata_nexthop_index=nhop)
    action_spec = dc_set_l3_rewrite_with_tunnel_action_spec_t(
                                  action_bd=core_vlan,
                                  action_tunnel_index=tunnel_index,
                                  action_smac_idx=rewrite_index,
                                  action_dmac=macAddr_to_string(dmac),
                                  action_tunnel_type=tunnel_type)
    hdl = client.rewrite_table_add_with_set_l3_rewrite_with_tunnel(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_l3_unicast_rewrite(client, sess_hdl, dev, hdl):
    client.rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def enable_learning(client, sess_hdl, dev_tgt):
    match_spec = dc_learn_notify_match_spec_t(
                             l2_metadata_l2_src_miss=1,
                             l2_metadata_l2_src_miss_mask=1,
                             l2_metadata_l2_src_move=0,
                             l2_metadata_l2_src_move_mask=0,
                             l2_metadata_stp_state=0,
                             l2_metadata_stp_state_mask=0)

    client.learn_notify_table_add_with_generate_learn_notify(
                             sess_hdl, dev_tgt,
                             match_spec, 1000)

def program_tunnel_ipv4_src_vtep(client, sess_hdl, dev_tgt, vrf, src_ip, ifindex):
    #Ingress Tunnel Decap - src vtep entry
    match_spec = dc_ipv4_src_vtep_match_spec_t(
                                  l3_metadata_vrf=vrf,
                                  ipv4_metadata_lkp_ipv4_sa=src_ip)
    action_spec = dc_src_vtep_hit_action_spec_t(
                                  action_ifindex=ifindex)
    hdl = client.ipv4_src_vtep_table_add_with_src_vtep_hit(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_ipv4_src_vtep(client, sess_hdl, dev, hdl):
    client.ipv4_src_vtep_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_ipv4_dst_vtep(client, sess_hdl, dev_tgt, vrf, dst_ip, tunnel_type):
    #Ingress Tunnel Decap - dest vtep entry
    match_spec = dc_ipv4_dest_vtep_match_spec_t(
                                  l3_metadata_vrf=vrf,
                                  ipv4_metadata_lkp_ipv4_da=dst_ip,
                                  tunnel_metadata_ingress_tunnel_type=tunnel_type)
    hdl = client.ipv4_dest_vtep_table_add_with_set_tunnel_termination_flag(
                                  sess_hdl, dev_tgt,
                                  match_spec)
    return hdl

def delete_tunnel_ipv4_dst_vtep(client, sess_hdl, dev, hdl):
    client.ipv4_dest_vtep_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_encap(client, sess_hdl, dev_tgt):
    match_spec = dc_tunnel_encap_process_outer_match_spec_t(
                                  tunnel_metadata_egress_tunnel_type=1,
                                  tunnel_metadata_egress_header_count=0,
                                  multicast_metadata_replica=0)
    hdl1 = client.tunnel_encap_process_outer_table_add_with_ipv4_vxlan_rewrite(
                                  sess_hdl, dev_tgt,
                                  match_spec)

    match_spec = dc_tunnel_encap_process_inner_match_spec_t(
                                  ipv4_valid=1, ipv6_valid=0,
                                  tcp_valid=1, udp_valid=0,
                                  icmp_valid=0)
    hdl2 = client.tunnel_encap_process_inner_table_add_with_inner_ipv4_tcp_rewrite(
                                  sess_hdl, dev_tgt,
                                  match_spec)
    return hdl1, hdl2

def delete_tunnel_encap(client, sess_hdl, dev, hdl1, hdl2):
    client.tunnel_encap_process_outer_table_delete(
                                  sess_hdl, dev,
                                  hdl1)

    client.tunnel_encap_process_inner_table_delete(
                                  sess_hdl, dev,
                                  hdl2)

def program_tunnel_decap(client, sess_hdl, dev_tgt):
    match_spec = dc_tunnel_decap_process_outer_match_spec_t(
                                  tunnel_metadata_ingress_tunnel_type=1,
                                  inner_ipv4_valid=1,
                                  inner_ipv6_valid=0)
    hdl1 = client.tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_ipv4(
                                  sess_hdl, dev_tgt,
                                  match_spec)

    match_spec = dc_tunnel_decap_process_inner_match_spec_t(
                                  inner_tcp_valid=1, inner_udp_valid=0, inner_icmp_valid=0)
    hdl2 = client.tunnel_decap_process_inner_table_add_with_decap_inner_tcp(
                                  sess_hdl, dev_tgt,
                                  match_spec)
    return (hdl1, hdl2)

def delete_tunnel_decap(client, sess_hdl, dev, hdl1, hdl2):
    client.tunnel_decap_process_outer_table_delete(
                                  sess_hdl, dev,
                                  hdl1)

    client.tunnel_decap_process_inner_table_delete(
                                  sess_hdl, dev,
                                  hdl2)

def program_tunnel_src_ipv4_rewrite(client, sess_hdl, dev_tgt, src_index, src_ip):
    #Egress Tunnel Encap - Source IP rewrite
    match_spec = dc_tunnel_src_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_src_index=src_index)
    action_spec = dc_rewrite_tunnel_ipv4_src_action_spec_t(
                                  action_ip=src_ip)
    hdl = client.tunnel_src_rewrite_table_add_with_rewrite_tunnel_ipv4_src(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_src_ipv4_rewrite(client, sess_hdl, dev, hdl):
    client.tunnel_src_rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_dst_ipv4_rewrite(client, sess_hdl, dev_tgt, dst_index, dst_ip):
    #Egress Tunnel Encap - Destination IP rewrite
    match_spec = dc_tunnel_dst_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_dst_index=dst_index)
    action_spec = dc_rewrite_tunnel_ipv4_dst_action_spec_t(
                                  action_ip=dst_ip)
    hdl = client.tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv4_dst(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_dst_ipv4_rewrite(client, sess_hdl, dev, hdl):
    client.tunnel_dst_rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_src_mac_rewrite(client, sess_hdl, dev_tgt, src_index, smac):
    match_spec = dc_tunnel_smac_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_smac_index=src_index)
    action_spec = dc_rewrite_tunnel_smac_action_spec_t(
                                  action_smac=macAddr_to_string(smac))
    hdl = client.tunnel_smac_rewrite_table_add_with_rewrite_tunnel_smac(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_src_mac_rewrite(client, sess_hdl, dev, hdl):
    client.tunnel_smac_rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_dst_mac_rewrite(client, sess_hdl, dev_tgt, dst_index, dmac):
    match_spec = dc_tunnel_dmac_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_dmac_index=dst_index)
    action_spec = dc_rewrite_tunnel_dmac_action_spec_t(
                                  action_dmac=macAddr_to_string(dmac))
    hdl = client.tunnel_dmac_rewrite_table_add_with_rewrite_tunnel_dmac(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_dst_mac_rewrite(client, sess_hdl, dev, hdl):
    client.tunnel_dmac_rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_rewrite(client, sess_hdl, dev_tgt, tunnel_index, sip_index, dip_index, smac_index, dmac_index, core_vlan):
    match_spec = dc_tunnel_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_index=tunnel_index)
    action_spec = dc_set_tunnel_rewrite_details_action_spec_t(
                                  action_smac_idx=smac_index,
                                  action_dmac_idx=dmac_index,
                                  action_sip_index=sip_index,
                                  action_dip_index=dip_index,
                                  action_outer_bd=core_vlan,
                                  action_mtu_index=0)
    hdl = client.tunnel_rewrite_table_add_with_set_tunnel_rewrite_details(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl


def delete_tunnel_rewrite(client, sess_hdl, dev, hdl):
    client.tunnel_rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_egress_vni(client, sess_hdl, dev_tgt, egress_tunnel_type, tenant_vlan, vnid):
    #Egress Tunnel Encap - Derive vnid from egress bd mapping
    match_spec = dc_egress_vni_match_spec_t(
                                  egress_metadata_bd=tenant_vlan,
                                  tunnel_metadata_egress_tunnel_type=egress_tunnel_type)
    action_spec = dc_set_egress_tunnel_vni_action_spec_t(
                                  action_vnid=vnid)
    hdl = client.egress_vni_table_add_with_set_egress_tunnel_vni(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)

def delete_egress_vni(client, sess_hdl, dev, hdl):
    client.egress_vni_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_rid(client, sess_hdl, dev_tgt, rid, inner_replica, bd, nhop_index, tunnel_type, tunnel_index):
    match_spec = dc_rid_match_spec_t(intrinsic_metadata_egress_rid=rid)
    if inner_replica:
        if nhop_index != None:
            action_spec = dc_inner_replica_from_rid_with_nexthop_action_spec_t(
                                           action_bd=bd,
                                           action_nexthop_index=nhop_index,
                                           action_tunnel_index=tunnel_index,
                                           action_tunnel_type=tunnel_type)
            hdl = client.rid_table_add_with_inner_replica_from_rid(sess_hdl,
                                                                   dev_tgt,
                                                                   match_spec,
                                                                   action_spec)
        else:
            action_spec = dc_inner_replica_from_rid_action_spec_t(
                                           action_bd=bd,
                                           action_tunnel_index=tunnel_index,
                                           action_tunnel_type=tunnel_type)
            hdl = client.rid_table_add_with_inner_replica_from_rid(sess_hdl,
                                                                   dev_tgt,
                                                                   match_spec,
                                                                   action_spec)
    else:
        if nhop_index != None:
            action_spec = dc_outer_replica_from_rid_with_nexthop_action_spec_t(
                                           action_bd=bd,
                                           action_nexthop_index=nhop_index,
                                           action_tunnel_index=tunnel_index,
                                           action_tunnel_type=tunnel_type)
            hdl = client.rid_table_add_with_outer_replica_from_rid(sess_hdl,
                                                                   dev_tgt,
                                                                   match_spec,
                                                                   action_spec)
        else:
            action_spec = dc_outer_replica_from_rid_action_spec_t(
                                           action_bd=bd,
                                           action_tunnel_index=tunnel_index,
                                           action_tunnel_type=tunnel_type)
            hdl = client.rid_table_add_with_outer_replica_from_rid(sess_hdl,
                                                                   dev_tgt,
                                                                   match_spec,
                                                                   action_spec)
    return hdl

def delete_rid(client, sess_hdl, dev, hdl):
    client.rid_table_delete(sess_hdl, dev, hdl)

def client_init(client, sess_hdl, dev_tgt):
    print "Cleaning state"
    client.clean_all(sess_hdl, dev_tgt)
    return 0

#Basic L2 Test case
class L2Test(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        print
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan=10
        port1=1
        port2=2
        v4_enabled=0
        v6_enabled=0

        # Add bd entry
        vlan_hdl = program_bd(self.client, sess_hdl, dev_tgt, vlan, 0)

        #Add ports to vlan
        #port vlan able programs (port, vlan) mapping and derives the bd
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, vlan, port1, v4_enabled, v6_enabled, 0, 0)

#        print 'port vlan map ' + str(hdl1) + ' ' + str(mbr_hdl1)

        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, vlan, port2, v4_enabled, v6_enabled, 0, 0)

#        print 'port vlan map ' + str(hdl2) + ' ' + str(mbr_hdl2)

        #Add static macs to ports. (vlan, mac -> port)
        dmac_hdl1, smac_hdl1 = program_mac(self.client, sess_hdl, dev_tgt, vlan, '00:11:11:11:11:11', 1)
        dmac_hdl2, smac_hdl2 = program_mac(self.client, sess_hdl, dev_tgt, vlan, '00:22:22:22:22:22', 2)

        self.conn_mgr.complete_operations(sess_hdl)

        print "Sending packet port 1 -> port 2 on vlan 10 (192.168.0.1 -> 10.0.0.1 [id = 101])"
        pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                ip_id=101,
                                ip_ttl=64,
                                ip_ihl=5)
        send_packet(self, 1, str(pkt))
        try:
            verify_packets(self, pkt, [2])
        except:
            print 'FAILED'

        delete_mac(self.client, sess_hdl, device, dmac_hdl2, smac_hdl2)
        delete_mac(self.client, sess_hdl, device, dmac_hdl1, smac_hdl1)

        delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
        delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

        # delete BD
        delete_bd(self.client, sess_hdl, device, vlan_hdl)

        # delete ports
        delete_ports(self.client, sess_hdl, device, 2, ret_list)

        # delete  init and default entries
        delete_init_entries(self.client, sess_hdl, device, ret_init)

        self.conn_mgr.complete_operations(sess_hdl)
        self.conn_mgr.client_cleanup(sess_hdl)


#Basic L3 Test case
class L3Ipv4Test(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        print
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan1=10
        vlan2=11
        port1=1
        port2=2
        v4_enabled=1
        v6_enabled=0

        # Add bd entry
        vlan_hdl1 = program_bd(self.client, sess_hdl, dev_tgt, vlan1, 0)
        vlan_hdl2 = program_bd(self.client, sess_hdl, dev_tgt, vlan2, 0)

        #For every L3 port, an implicit vlan will be allocated
        #Add ports to vlan
        #Outer vlan table programs (port, vlan) mapping and derives the bd
        #Inner vlan table derives the bd state
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, vlan1, port1, v4_enabled, v6_enabled, inner_rmac_group, 0)
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, vlan2, port2, v4_enabled, v6_enabled, inner_rmac_group, 0)

        #Create nexthop
        nhop1=1
        nhop_hdl1 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop1, vlan1, port1, 0)
        #Add rewrite information (ARP info)
        arp_hdl1 = program_ipv4_unicast_rewrite(self.client, sess_hdl, dev_tgt, vlan1, nhop1, '00:11:11:11:11:11')
        #Add route
        route_hdl1 = program_ipv4_route(self.client, sess_hdl, dev_tgt, vrf, 0x0a0a0a01, 32, nhop1)
        #Create nexthop
        nhop2=2
        nhop_hdl2 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop2, vlan2, port2, 0)
        #Add rewrite information (ARP info)
        arp_hdl2 = program_ipv4_unicast_rewrite(self.client, sess_hdl, dev_tgt, vlan2, nhop2, '00:22:22:22:22:22')
        #Add route
        route_hdl2 = program_ipv4_route(self.client, sess_hdl, dev_tgt, vrf, 0x14141401, 32, nhop2)

        print "Sending packet port 1 -> port 2 (10.10.10.1 -> 20.20.20.1 [id = 101])"
        self.conn_mgr.complete_operations(sess_hdl)

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
        send_packet(self, 1, str(pkt))
        time.sleep(1)
        verify_packets(self, exp_pkt, [2])

        delete_ipv4_route(self.client, sess_hdl, device, 32, route_hdl2)
        delete_ipv4_unicast_rewrite(self.client, sess_hdl, device, arp_hdl2)
        delete_nexthop(self.client, sess_hdl, device, nhop_hdl2)

        delete_ipv4_route(self.client, sess_hdl, device, 32, route_hdl1)
        delete_ipv4_unicast_rewrite(self.client, sess_hdl, device, arp_hdl1)
        delete_nexthop(self.client, sess_hdl, device, nhop_hdl1)

        delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
        delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

        delete_bd(self.client, sess_hdl, device, vlan_hdl1)
        delete_bd(self.client, sess_hdl, device, vlan_hdl2)

        # delete ports
        delete_ports(self.client, sess_hdl, device, 2, ret_list)

        # delete  init and default entries
        delete_init_entries(self.client, sess_hdl, device, ret_init)

        self.conn_mgr.complete_operations(sess_hdl)

        self.conn_mgr.client_cleanup(sess_hdl)


class L3Ipv6Test(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        print
        if ipv6_enabled == 0:
            print "ipv6 not enabled"
            return

        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan1=10
        vlan2=11
        port1=1
        port2=2
        v4_enabled=0
        v6_enabled=1

        # Add bd entry
        vlan_hdl1 = program_bd(self.client, sess_hdl, dev_tgt, vlan1, 0)
        vlan_hdl2 = program_bd(self.client, sess_hdl, dev_tgt, vlan2, 0)

        #For every L3 port, an implicit vlan will be allocated
        #Add ports to vlan
        #Outer vlan table programs (port, vlan) mapping and derives the bd
        #Inner vlan table derives the bd state
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, vlan1, port1, v4_enabled, v6_enabled, inner_rmac_group, 0)
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, vlan2, port2, v4_enabled, v6_enabled, inner_rmac_group, 0)

        #Create nexthop
        nhop1=1
        nhop_hdl1 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop1, vlan1, port1, 0)
        #Add rewrite information (ARP info)
        arp_hdl1 = program_ipv6_unicast_rewrite(self.client, sess_hdl, dev_tgt, vlan1, nhop1, '00:11:11:11:11:11')
        #Add route
        route_hdl1 = program_ipv6_route(self.client, sess_hdl, dev_tgt, vrf, '2000::1', 128, nhop1)
        #Create nexthop
        nhop2=2
        nhop_hdl2 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop2, vlan2, port2, 0)
        #Add rewrite information (ARP info)
        arp_hdl2 = program_ipv6_unicast_rewrite(self.client, sess_hdl, dev_tgt, vlan2, nhop2, '00:22:22:22:22:22')
        #Add route
        route_hdl2 = program_ipv6_route(self.client, sess_hdl, dev_tgt, vrf, '3000::1', 128, nhop2)

        print "Sending packet port 1 -> port 2 (10.10.10.1 -> 20.20.20.1 [id = 101])"
        self.conn_mgr.complete_operations(sess_hdl)

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
        send_packet(self, 1, str(pkt))
        verify_packets(self, exp_pkt, [2])

        delete_ipv6_route(self.client, sess_hdl, device, 128, route_hdl2)
        delete_ipv6_unicast_rewrite(self.client, sess_hdl, device, arp_hdl2)
        delete_nexthop(self.client, sess_hdl, device, nhop_hdl2)

        delete_ipv6_route(self.client, sess_hdl, device, 128, route_hdl1)
        delete_ipv6_unicast_rewrite(self.client, sess_hdl, device, arp_hdl1)
        delete_nexthop(self.client, sess_hdl, device, nhop_hdl1)

        delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
        delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

        delete_bd(self.client, sess_hdl, device, vlan_hdl1)
        delete_bd(self.client, sess_hdl, device, vlan_hdl2)

        # delete ports
        delete_ports(self.client, sess_hdl, device, 2, ret_list)

        # delete  init and default entries
        delete_init_entries(self.client, sess_hdl, device, ret_init)

        self.conn_mgr.complete_operations(sess_hdl)

        self.conn_mgr.client_cleanup(sess_hdl)


#Basic Vxlan Tunneling Test case
class L2VxlanTunnelTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        print
        if tunnel_enabled == 0:
            print "tunnel not enabled"
            return

        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        port1=1
        port2=2
        outer_v4_enabled=1
        inner_v4_enabled=0
        outer_v6_enabled=0
        inner_v6_enabled=0
        core_vlan=10
        tenant_vlan=1000
        vnid=0x1234
        tunnel_index = 0
        sip_index = 0
        dip_index = 0
        smac_index = 0
        dmac_index = 0
        tunnel_type=1 #vxlan

        #Indicates vxlan tunnel in Parser
        ingress_tunnel_type=1
        egress_tunnel_type=1

        # Add bd entry
        vlan_hdl1 = program_bd(self.client, sess_hdl, dev_tgt, core_vlan, 0)
        vlan_hdl2 = program_bd(self.client, sess_hdl, dev_tgt, tenant_vlan, 0)

        #Port2 belong to core vlan
        #Outer vlan table will derive core bd and the src vtep, dest vtep and vnid will derive the tenant bd
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, core_vlan, port2,
                             outer_v4_enabled, outer_v6_enabled,
                             outer_rmac_group, 0)
        tun_hdl = program_tunnel_ethernet_vlan(self.client, sess_hdl, dev_tgt, tenant_vlan, port2, vnid, ingress_tunnel_type, inner_v4_enabled, 0)

        #Port1 belong to tenant vlan
        #Outer vlan table will derive tenant bd and inner bd table will derive bd state
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, tenant_vlan,
                             port1, inner_v4_enabled, inner_v6_enabled, 0, 0)

        #Add static macs to ports. (vlan, mac -> port)
        #Nextop should be created during mac lookup when the destinaion interface is a tunnel.
        #Nexthop allocated will derive egress bd in the ingress and derive rewrite info
        # at egress
        nhop=1
        dmac_hdl1, smac_hdl1 = program_mac(self.client, sess_hdl, dev_tgt, tenant_vlan, '00:11:11:11:11:11', port1)
        dmac_hdl2, smac_hdl2 = program_mac_with_nexthop(self.client, sess_hdl, dev_tgt, tenant_vlan, '00:22:22:22:22:22', port2, nhop)

        #add nexthop table
        nhop_hdl1 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop, tenant_vlan, port2, 1)

        encap1, encap2 = program_tunnel_encap(self.client, sess_hdl, dev_tgt)
        decap1, decap2 = program_tunnel_decap(self.client, sess_hdl, dev_tgt)

        tun_src = program_tunnel_src_ipv4_rewrite(self.client, sess_hdl, dev_tgt, sip_index, 0x0a0a0a01)
        tun_dst = program_tunnel_dst_ipv4_rewrite(self.client, sess_hdl, dev_tgt, dip_index, 0x0a0a0a02)
        tun_smac = program_tunnel_src_mac_rewrite(self.client, sess_hdl, dev_tgt, smac_index, '00:33:33:33:33:33')
        tun_dmac = program_tunnel_dst_mac_rewrite(self.client, sess_hdl, dev_tgt, dmac_index, '00:55:55:55:55:55')
        tun_l2 = program_tunnel_l2_unicast_rewrite(self.client, sess_hdl, dev_tgt, tunnel_index, tunnel_type, nhop, core_vlan)
        tun_rewrite = program_tunnel_rewrite(self.client, sess_hdl, dev_tgt, tunnel_index, sip_index, dip_index, smac_index, dmac_index, core_vlan)
        tun_svtep = program_tunnel_ipv4_src_vtep(self.client, sess_hdl, dev_tgt, vrf, 0x0a0a0a02, 0)
        tun_dvtep = program_tunnel_ipv4_dst_vtep(self.client, sess_hdl, dev_tgt, vrf, 0x0a0a0a01, 1)
        tun_vni = program_egress_vni(self.client, sess_hdl, dev_tgt, egress_tunnel_type, tenant_vlan, vnid)

        self.conn_mgr.complete_operations(sess_hdl)

        #Egress Tunnel Decap - Decapsulate the vxlan header

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
                                udp_sport=27655,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                inner_frame=pkt)
        send_packet(self, 1, str(pkt))
        time.sleep(1)
        try:
            verify_packets(self, vxlan_pkt, [2])
        except:
            print 'FAILED'

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
        send_packet(self, 2, str(vxlan_pkt))
        verify_packets(self, pkt, [1])


        delete_egress_vni(self.client, sess_hdl, device, tun_vni)
        delete_tunnel_ipv4_dst_vtep(self.client, sess_hdl, device, tun_dvtep)
        delete_tunnel_ipv4_src_vtep(self.client, sess_hdl, device, tun_svtep)
        delete_tunnel_rewrite(self.client, sess_hdl, device, tun_rewrite)
        delete_tunnel_l2_unicast_rewrite(self.client, sess_hdl, device, tun_l2)
        delete_tunnel_dst_mac_rewrite(self.client, sess_hdl, device, tun_dmac)
        delete_tunnel_src_mac_rewrite(self.client, sess_hdl, device, tun_smac)
        delete_tunnel_dst_ipv4_rewrite(self.client, sess_hdl, device, tun_dst)
        delete_tunnel_src_ipv4_rewrite(self.client, sess_hdl, device, tun_src)

        delete_tunnel_decap(self.client, sess_hdl, device, decap1, decap2)
        delete_tunnel_encap(self.client, sess_hdl, device, encap1, encap2)

        delete_nexthop(self.client, sess_hdl, device, nhop_hdl1)

        delete_mac(self.client, sess_hdl, device, dmac_hdl2, smac_hdl2)
        delete_mac(self.client, sess_hdl, device, dmac_hdl1, smac_hdl1)

        delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
        delete_tunnel_ethernet_vlan(self.client, sess_hdl, device, tun_hdl)
        delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

        delete_bd(self.client, sess_hdl, device, vlan_hdl1)
        delete_bd(self.client, sess_hdl, device, vlan_hdl2)

        # delete ports
        delete_ports(self.client, sess_hdl, device, 2, ret_list)

        # delete  init and default entries
        delete_init_entries(self.client, sess_hdl, device, ret_init)

        self.conn_mgr.complete_operations(sess_hdl)

        self.conn_mgr.client_cleanup(sess_hdl)


class L3VxlanTunnelTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        print
        if tunnel_enabled == 0:
            print "tunnel not enabled"
            return
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

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
        tunnel_index = 0
        sip_index = 0
        dip_index = 0
        smac_index = 0
        dmac_index = 0

        #Indicates vxlan tunnel in Parser
        ingress_tunnel_type=1
        egress_tunnel_type=1

        # Add bd entry
        vlan_hdl1 = program_bd(self.client, sess_hdl, dev_tgt, core_vlan, 0)
        vlan_hdl2 = program_bd(self.client, sess_hdl, dev_tgt, tenant_vlan1, 0)
        vlan_hdl3 = program_bd(self.client, sess_hdl, dev_tgt, tenant_vlan2, 0)

        #Port2 belong to core vlan
        #Outer vlan table will derive core bd and the src vtep, dest vtep and vnid will derive the tenant bd
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, core_vlan, port2, outer_v4_enabled, outer_v6_enabled, outer_rmac_group, 0)
        tun_hdl = program_tunnel_ipv4_vlan(self.client, sess_hdl, dev_tgt, tenant_vlan2, port2, vnid, ingress_tunnel_type, inner_v4_enabled, inner_rmac_group)

        #Port1 belong to tenant vlan
        #Outer vlan table will derive tenant bd and inner bd table will derive bd state
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, tenant_vlan1, port1, inner_v4_enabled, inner_v6_enabled, inner_rmac_group, 0)

        #Add L3 routes
        nhop1=1
        nhop2=2
        route_hdl1 = program_ipv4_route(self.client, sess_hdl, dev_tgt, vrf, 0x0aa80a01, 32, nhop1)
        route_hdl2 = program_ipv4_route(self.client, sess_hdl, dev_tgt, vrf, 0x0aa80b01, 32, nhop2)

        #Add nexthop table
        nhop_hdl1 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop1, tenant_vlan1, port1, 0)
        arp_hdl1 = program_ipv4_unicast_rewrite(self.client, sess_hdl, dev_tgt, tenant_vlan1, nhop1, '00:11:11:11:11:11')

        nhop_hdl2 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop2, tenant_vlan2, port2, 1)

        encap1, encap2 = program_tunnel_encap(self.client, sess_hdl, dev_tgt)
        decap1, decap2 = program_tunnel_decap(self.client, sess_hdl, dev_tgt)
        tun_src = program_tunnel_src_ipv4_rewrite(self.client, sess_hdl, dev_tgt, sip_index, 0x0a0a0a01)
        tun_dst = program_tunnel_dst_ipv4_rewrite(self.client, sess_hdl, dev_tgt, dip_index, 0x0a0a0a02)
        tun_smac = program_tunnel_src_mac_rewrite(self.client, sess_hdl, dev_tgt, smac_index, '00:33:33:33:33:33')
        tun_dmac = program_tunnel_dst_mac_rewrite(self.client, sess_hdl, dev_tgt, dmac_index, '00:55:55:55:55:55')
        tun_l3 = program_tunnel_l3_unicast_rewrite(self.client, sess_hdl, dev_tgt, tunnel_index, egress_tunnel_type, rewrite_index, nhop2, tenant_vlan2, '00:22:22:22:22:22')
        tun_rewrite = program_tunnel_rewrite(self.client, sess_hdl, dev_tgt, tunnel_index, sip_index, dip_index, smac_index, dmac_index, core_vlan)
        tun_svtep = program_tunnel_ipv4_src_vtep(self.client, sess_hdl, dev_tgt, vrf, 0x0a0a0a02, 0)
        tun_dvtep = program_tunnel_ipv4_dst_vtep(self.client, sess_hdl, dev_tgt, vrf, 0x0a0a0a01, 1)
        tun_vni = program_egress_vni(self.client, sess_hdl, dev_tgt, egress_tunnel_type, tenant_vlan2, vnid)

        self.conn_mgr.complete_operations(sess_hdl)


        print "Sending packet port 1 -> port 2 - Vxlan tunnel encap"
        print "Inner packet (10.168.10.1 -> 10.168.11.1 [id = 101])"
        print "Outer packet (10.10.10.1 -> 10.10.10.2 [vnid = 0x1234, id = 101])"
        pkt1 = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='10.168.11.1',
                                ip_src='10.168.10.1',
                                ip_id=101,
                                ip_ttl=64)

        pkt2 = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                eth_src='00:33:33:33:33:33',
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
                                ip_ttl=64,
                                udp_sport=20087,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                inner_frame=pkt2)

        send_packet(self, 1, str(pkt1))
        try:
            verify_packets(self, vxlan_pkt, [2])
        except:
            print 'FAILED'

        print "Sending packet port 2 -> port 1 - Vxlan tunnel decap"
        print "Inner packet (10.168.11.1 -> 10.168.10.1 [id = 101])"
        print "Outer packet (10.10.10.2 -> 10.10.10.1 [vnid = 0x1234, id = 101])"
        pkt1 = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
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
                                inner_frame=pkt1)

        pkt2 = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:33:33:33:33:33',
                                ip_dst='10.168.10.1',
                                ip_src='10.168.11.1',
                                ip_id=101,
                                ip_ttl=63)
        send_packet(self, 2, str(vxlan_pkt))
        try:
            verify_packets(self, pkt2, [1])
        except:
            print 'FAILED'

        delete_egress_vni(self.client, sess_hdl, device, tun_vni)
        delete_tunnel_ipv4_dst_vtep(self.client, sess_hdl, device, tun_dvtep)
        delete_tunnel_ipv4_src_vtep(self.client, sess_hdl, device, tun_svtep)
        delete_tunnel_rewrite(self.client, sess_hdl, device, tun_rewrite)
        delete_tunnel_l3_unicast_rewrite(self.client, sess_hdl, device, tun_l3)
        delete_tunnel_dst_mac_rewrite(self.client, sess_hdl, device, tun_dmac)
        delete_tunnel_src_mac_rewrite(self.client, sess_hdl, device, tun_smac)
        delete_tunnel_dst_ipv4_rewrite(self.client, sess_hdl, device, tun_dst)
        delete_tunnel_src_ipv4_rewrite(self.client, sess_hdl, device, tun_src)

        delete_tunnel_decap(self.client, sess_hdl, device, decap1, decap2)
        delete_tunnel_encap(self.client, sess_hdl, device, encap1, encap2)

        delete_ipv4_route(self.client, sess_hdl, device, 32, route_hdl2)
        delete_nexthop(self.client, sess_hdl, device, nhop_hdl2)

        delete_ipv4_route(self.client, sess_hdl, device, 32, route_hdl1)
        delete_ipv4_unicast_rewrite(self.client, sess_hdl, device, arp_hdl1)
        delete_nexthop(self.client, sess_hdl, device, nhop_hdl1)

        delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
        delete_tunnel_ipv4_vlan(self.client, sess_hdl, device, tun_hdl)
        delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

        # delete BD
        delete_bd(self.client, sess_hdl, device, vlan_hdl3)
        delete_bd(self.client, sess_hdl, device, vlan_hdl2)
        delete_bd(self.client, sess_hdl, device, vlan_hdl1)

        # delete ports
        delete_ports(self.client, sess_hdl, device, 2, ret_list)

        # delete  init and default entries
        delete_init_entries(self.client, sess_hdl, device, ret_init)

        self.conn_mgr.complete_operations(sess_hdl)

        self.conn_mgr.client_cleanup(sess_hdl)


class L2LearningTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan=10
        port1=1
        port2=2
        v4_enabled=0
        v6_enabled=0

        # Add bd entry
        vlan_hdl = program_bd(self.client, sess_hdl, dev_tgt, vlan, 0)

        #Add ports to vlan
        #Outer vlan table programs (port, vlan) mapping and derives the bd
        #Inner vlan table derives the bd state
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                    vlan, port1, v4_enabled, v6_enabled, 0, 1)
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                    vlan, port2, v4_enabled, v6_enabled, 0, 1)

        dmac_hdl1, smac_hdl1 = program_mac(self.client, sess_hdl, dev_tgt, vlan, '00:44:44:44:44:44', 2)

        enable_learning(self.client, sess_hdl, dev_tgt)

        self.client.set_learning_timeout(sess_hdl, 0, learn_timeout * 1000)
        self.client.mac_learn_digest_register(sess_hdl, 0)

        self.conn_mgr.complete_operations(sess_hdl)

        pkt = simple_tcp_packet(eth_dst='00:44:44:44:44:44',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.168.10.1',
                                ip_src='10.168.11.1',
                                ip_id=101,
                                ip_ttl=64)
        send_packet(self, 1, str(pkt))
        time.sleep(learn_timeout + 1)
        digests = self.client.mac_learn_digest_get_digest(sess_hdl)
        assert len(digests.msg) == 1
        mac_str = digests.msg[0].l2_metadata_lkp_mac_sa
        print "new mac learnt ", mac_str,
        print "on port ", digests.msg[0].ingress_metadata_ifindex
        self.client.mac_learn_digest_digest_notify_ack(sess_hdl, digests.msg_ptr)
        self.client.mac_learn_digest_deregister(sess_hdl, 0)

        delete_mac(self.client, sess_hdl, device, dmac_hdl1, smac_hdl1)

        delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
        delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

        delete_bd(self.client, sess_hdl, device, vlan_hdl)

        # delete ports
        delete_ports(self.client, sess_hdl, device, 2, ret_list)

        # delete  init and default entries
        delete_init_entries(self.client, sess_hdl, device, ret_init)

        self.conn_mgr.complete_operations(sess_hdl)

        self.conn_mgr.client_cleanup(sess_hdl)


class L2FloodTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __str__(self):
        return self.id()

    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        sess_hdl = self.conn_mgr.client_init(16)
        mc_sess_hdl = self.mc.mc_create_session()
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt)

        #Create ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 4)

        vlan=10
        port1=1
        port2=2
        port3=3
        port4=4
        v4_enabled=0
        v6_enabled=0
        mgid = 0x100
        rid = 0x200
        inner_replica=True
        nhop_index=None
        tunnel_type=0
        tunnel_index=0

        # Add bd entry
        vlan_hdl = program_bd(self.client, sess_hdl, dev_tgt, vlan, mgid)

        #Add ports to vlan
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, vlan, port1, v4_enabled, v6_enabled, 0, 0)
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, vlan, port2, v4_enabled, v6_enabled, 0, 0)
        hdl3, mbr_hdl3 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, vlan, port3, v4_enabled, v6_enabled, 0, 0)
        hdl4, mbr_hdl4 = program_vlan_mapping(self.client, sess_hdl, dev_tgt, vlan, port4, v4_enabled, v6_enabled, 0, 0)

        rid_hdl = program_rid(self.client, sess_hdl, dev_tgt, rid, inner_replica, vlan, nhop_index, tunnel_type, tunnel_index)

        port_map = set_port_or_lag_bitmap(256, [port1, port2, port3, port4])
        lag_map = set_port_or_lag_bitmap(256, [])
        mgrp_hdl = self.mc.mc_mgrp_create(mc_sess_hdl, 0, mgid)
        node_hdl = self.mc.mc_node_create(mc_sess_hdl, 0, rid, port_map, lag_map)
        self.mc.mc_associate_node(mc_sess_hdl, dev_tgt.dev_id, mgrp_hdl, node_hdl)

        self.conn_mgr.complete_operations(sess_hdl)

        pkt = simple_tcp_packet(eth_dst='00:44:44:44:44:44',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.168.10.1',
                                ip_src='10.168.11.1',
                                ip_id=101,
                                ip_ttl=64)

        send_packet(self, 1, str(pkt))
        verify_packets(self, pkt, [port2, port3, port4])
        time.sleep(1)
        self.mc.mc_dissociate_node(mc_sess_hdl, dev_tgt.dev_id, mgrp_hdl, node_hdl)
        self.mc.mc_node_destroy(mc_sess_hdl, dev_tgt.dev_id, node_hdl)
        self.mc.mc_mgrp_destroy(mc_sess_hdl, dev_tgt.dev_id, mgrp_hdl)

#        self.mc.mc_complete_operations(mc_sess_hdl)
        delete_rid(self.client, sess_hdl, device, rid_hdl)

        # delete port_vlan entries
        delete_vlan_mapping(self.client, sess_hdl, device, hdl4, mbr_hdl4)
        delete_vlan_mapping(self.client, sess_hdl, device, hdl3, mbr_hdl3)
        delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
        delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

        # delete BD
        delete_bd(self.client, sess_hdl, device, vlan_hdl)

        # delete ports
        delete_ports(self.client, sess_hdl, device, 4, ret_list)

        # delete  init and default entries
        delete_init_entries(self.client, sess_hdl, device, ret_init)

        self.mc.mc_destroy_session(mc_sess_hdl)

        self.conn_mgr.complete_operations(sess_hdl)

        self.conn_mgr.client_cleanup(sess_hdl)


