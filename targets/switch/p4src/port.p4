/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


action set_valid_outer_unicast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
}

action set_valid_outer_unicast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
}

action set_valid_outer_unicast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
}

action set_valid_outer_unicast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
}

action set_valid_outer_multicast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
}

action set_valid_outer_multicast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
}

action set_valid_outer_multicast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
}

action set_valid_outer_multicast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
}

action set_valid_outer_broadcast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
}

action set_valid_outer_broadcast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
}

action set_valid_outer_broadcast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
}

action set_valid_outer_broadcast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(standard_metadata.egress_port, INVALID_PORT_ID);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
}

table validate_outer_ethernet {
    reads {
        ethernet.dstAddr : ternary;
        vlan_tag_[0] : valid;
        vlan_tag_[1] : valid;
    }
    actions {
        set_valid_outer_unicast_packet_untagged;
        set_valid_outer_unicast_packet_single_tagged;
        set_valid_outer_unicast_packet_double_tagged;
        set_valid_outer_unicast_packet_qinq_tagged;
        set_valid_outer_multicast_packet_untagged;
        set_valid_outer_multicast_packet_single_tagged;
        set_valid_outer_multicast_packet_double_tagged;
        set_valid_outer_multicast_packet_qinq_tagged;
        set_valid_outer_broadcast_packet_untagged;
        set_valid_outer_broadcast_packet_single_tagged;
        set_valid_outer_broadcast_packet_double_tagged;
        set_valid_outer_broadcast_packet_qinq_tagged;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}

control validate_outer_ethernet_header {
    apply(validate_outer_ethernet);
}
action set_ifindex(ifindex, if_label) {
    modify_field(ingress_metadata.ifindex, ifindex);
    modify_field(ingress_metadata.if_label, if_label);
}

table port_mapping {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        set_ifindex;
    }
    size : PORTMAP_TABLE_SIZE;
}

control process_port_mapping {
    apply(port_mapping);
}

action set_bd(bd, vrf, rmac_group, 
        bd_label, uuc_mc_index, bcast_mc_index, umc_mc_index,
        ipv4_unicast_enabled, ipv6_unicast_enabled,
        igmp_snooping_enabled, mld_snooping_enabled,
        ipv4_urpf_mode, ipv6_urpf_mode, stp_group) {
    modify_field(ingress_metadata.vrf, vrf);
    modify_field(ipv4_metadata.ipv4_unicast_enabled, ipv4_unicast_enabled);
    modify_field(ipv6_metadata.ipv6_unicast_enabled, ipv6_unicast_enabled);
    modify_field(multicast_metadata.igmp_snooping_enabled, igmp_snooping_enabled);
    modify_field(multicast_metadata.mld_snooping_enabled, mld_snooping_enabled);
    modify_field(ipv4_metadata.ipv4_urpf_mode, ipv4_urpf_mode);
    modify_field(ipv6_metadata.ipv6_urpf_mode, ipv6_urpf_mode);
    modify_field(l3_metadata.rmac_group, rmac_group);
    modify_field(ingress_metadata.uuc_mc_index, uuc_mc_index);
    modify_field(ingress_metadata.umc_mc_index, umc_mc_index);
    modify_field(ingress_metadata.bcast_mc_index, bcast_mc_index);
    modify_field(ingress_metadata.bd_label, bd_label);
    modify_field(ingress_metadata.bd, bd);
    modify_field(ingress_metadata.outer_bd, bd);
    modify_field(l2_metadata.stp_group, stp_group);
}

action_profile bd_action_profile {
    actions {
        set_bd;
    }
    size : BD_TABLE_SIZE;
}

table port_vlan_mapping {
    reads {
        ingress_metadata.ifindex : exact;
        vlan_tag_[0] : valid;
        vlan_tag_[0].vid : exact;
        vlan_tag_[1] : valid;
        vlan_tag_[1].vid : exact;
    }

    action_profile: bd_action_profile;
    size : PORT_VLAN_TABLE_SIZE;
}

control process_port_vlan_mapping {
    apply(port_vlan_mapping);
}

field_list lag_hash_fields {
    l2_metadata.lkp_mac_sa;
    l2_metadata.lkp_mac_da;
    l2_metadata.lkp_mac_type;
    ipv4_metadata.lkp_ipv4_sa;
    ipv4_metadata.lkp_ipv4_da;
    l3_metadata.lkp_ip_proto;
    ingress_metadata.lkp_l4_sport;
    ingress_metadata.lkp_l4_dport;
}

field_list_calculation lag_hash {
    input {
        lag_hash_fields;
    }
    algorithm : crc16;
    output_width : LAG_BIT_WIDTH;
}

action_selector lag_selector {
    selection_key : lag_hash;
}

action set_lag_port(port) {
    modify_field(standard_metadata.egress_spec, port);
}

action set_lag_miss() {
    modify_field_with_hash_based_offset(intrinsic_metadata.lag_hash, 0, lag_hash, 8192);
}

action_profile lag_action_profile {
    actions {
        set_lag_miss;
        set_lag_port;
    }
    size : LAG_GROUP_TABLE_SIZE;
    dynamic_action_selection : lag_selector;
}

table lag_group {
    reads {
        ingress_metadata.egress_ifindex : exact;
    }
    action_profile: lag_action_profile;
    size : LAG_SELECT_TABLE_SIZE;
}

control process_lag {
    apply(lag_group);
}

action set_egress_packet_vlan_tagged(vlan_id) {
    add_header(vlan_tag_[0]);
    modify_field(vlan_tag_[0].etherType, ethernet.etherType);
    modify_field(vlan_tag_[0].vid, vlan_id);
    modify_field(ethernet.etherType, 0x8100);
}

action set_egress_packet_vlan_untagged() {
}

table egress_vlan_xlate {
    reads {
        standard_metadata.egress_port : exact;
        egress_metadata.bd : exact;
    }
    actions {
        set_egress_packet_vlan_tagged;
        set_egress_packet_vlan_untagged;
    }
    size : EGRESS_VLAN_XLATE_TABLE_SIZE;
}

control process_vlan_xlate {
    apply(egress_vlan_xlate);
}
