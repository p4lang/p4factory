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

header_type l2_metadata_t {
    fields {
        lkp_pkt_type : 3;
        lkp_mac_sa : 48;
        lkp_mac_da : 48;
        lkp_mac_type: 16;

        l2_nexthop : 16;                       /* next hop from l2 */
        l2_nexthop_type : 1;                   /* ecmp or nexthop */
        l2_redirect : 1;                       /* l2 redirect action */
        l2_src_miss : 1;                       /* l2 source miss */
        l2_src_move : IFINDEX_BIT_WIDTH;       /* l2 source interface mis-match */
        stp_group: 10;                         /* spanning tree group id */
        stp_state : 3;                         /* spanning tree port state */
    }
}

metadata l2_metadata_t l2_metadata;

#ifndef L2_DISABLE
action set_stp_state(stp_state) {
    modify_field(l2_metadata.stp_state, stp_state);
}

table spanning_tree {
    reads {
        ingress_metadata.ifindex : exact;
        l2_metadata.stp_group: exact;
    }
    actions {
        set_stp_state;
    }
    size : SPANNING_TREE_TABLE_SIZE;
}
#endif /* L2_DISABLE */

control process_spanning_tree {
#ifndef L2_DISABLE
    if (l2_metadata.stp_group != STP_GROUP_NONE) {
        apply(spanning_tree);
    }
#endif /* L2_DISABLE */
}

#ifndef L2_DISABLE
action smac_miss() {
    modify_field(l2_metadata.l2_src_miss, TRUE);
}

action smac_hit(ifindex) {
    bit_xor(l2_metadata.l2_src_move, ingress_metadata.ifindex, ifindex);
}

table smac {
    reads {
        ingress_metadata.bd : exact;
        l2_metadata.lkp_mac_sa : exact;
    }
    actions {
        nop;
        smac_miss;
        smac_hit;
    }
    size : SMAC_TABLE_SIZE;
}

action dmac_hit(ifindex) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    modify_field(ingress_metadata.egress_bd, ingress_metadata.bd);
}

action dmac_multicast_hit(mc_index) {
    modify_field(intrinsic_metadata.eg_mcast_group, mc_index);
    modify_field(ingress_metadata.egress_bd, ingress_metadata.bd);
}

action dmac_miss() {
    modify_field(intrinsic_metadata.eg_mcast_group, ingress_metadata.uuc_mc_index);
    modify_field(ingress_metadata.egress_bd, ingress_metadata.bd);
}

action dmac_redirect_nexthop(nexthop_index) {
    modify_field(l2_metadata.l2_redirect, TRUE);
    modify_field(l2_metadata.l2_nexthop, nexthop_index);
    modify_field(l2_metadata.l2_nexthop_type, NEXTHOP_TYPE_SIMPLE);
}

action dmac_redirect_ecmp(ecmp_index) {
    modify_field(l2_metadata.l2_redirect, TRUE);
    modify_field(l2_metadata.l2_nexthop, ecmp_index);
    modify_field(l2_metadata.l2_nexthop_type, NEXTHOP_TYPE_ECMP);
}

action dmac_drop() {
    drop();
}

table dmac {
    reads {
        ingress_metadata.bd : exact;
        l2_metadata.lkp_mac_da : exact;
    }
    actions {
        nop;
        dmac_hit;
        dmac_multicast_hit;
        dmac_miss;
        dmac_redirect_nexthop;
        dmac_redirect_ecmp;
        dmac_drop;
    }
    size : DMAC_TABLE_SIZE;
    support_timeout: true;
}
#endif /* L2_DISABLE */

control process_mac {
#ifndef L2_DISABLE
    apply(smac);
    apply(dmac);
#endif /* L2_DISABLE */
}

#ifndef L2_DISABLE
field_list mac_learn_digest {
    ingress_metadata.bd;
    l2_metadata.lkp_mac_sa;
    ingress_metadata.ifindex;
}

action generate_learn_notify() {
    generate_digest(MAC_LEARN_RECEIVER, mac_learn_digest);
}

table learn_notify {
    reads {
        l2_metadata.l2_src_miss : ternary;
        l2_metadata.l2_src_move : ternary;
        l2_metadata.stp_state : ternary;
    }
    actions {
        nop;
        generate_learn_notify;
    }
    size : LEARN_NOTIFY_TABLE_SIZE;
}
#endif /* L2_DISABLE */

control process_mac_learning {
#ifndef L2_DISABLE
    if (tunnel_metadata.tunnel_terminate == FALSE) {
        apply(learn_notify);
    }
#endif /* L2_DISABLE */
}

action set_unicast() {
}

action set_unicast_and_ipv6_src_is_link_local() {
    modify_field(ingress_metadata.src_is_link_local, TRUE);
}

action set_multicast() {
}

action set_ip_multicast() {
    modify_field(multicast_metadata.ip_multicast, TRUE);
}

action set_ip_multicast_and_ipv6_src_is_link_local() {
    modify_field(multicast_metadata.ip_multicast, TRUE);
    modify_field(ingress_metadata.src_is_link_local, TRUE);
}

action set_broadcast() {
}

table validate_packet {
    reads {
        l2_metadata.lkp_mac_da : ternary;
#ifndef IPV6_DISABLE
        ipv6_metadata.lkp_ipv6_sa : ternary;
#endif /* IPV6_DISABLE */
    }
    actions {
        nop;
        set_unicast;
        set_unicast_and_ipv6_src_is_link_local;
        set_multicast;
        set_ip_multicast;
        set_ip_multicast_and_ipv6_src_is_link_local;
        set_broadcast;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}

control process_validate_packet {
    apply(validate_packet);
}

action rewrite_unicast_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
    modify_field(ethernet.dstAddr, egress_metadata.mac_da);
}

action rewrite_multicast_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
    modify_field(ethernet.dstAddr, 0x01005E000000);
    modify_field(ethernet.dstAddr, ipv4.dstAddr, 0x7FFFFF);
    add_to_field(ipv4.ttl, -1);
}

table mac_rewrite {
    reads {
        egress_metadata.smac_idx : exact;
        ipv4.dstAddr : ternary;
    }
    actions {
        nop;
        rewrite_unicast_mac;
        rewrite_multicast_mac;
    }
    size : MAC_REWRITE_TABLE_SIZE;
}

control process_mac_rewrite {
    if (l3_metadata.routed == TRUE) {
        apply(mac_rewrite);
    }
}

action set_egress_bd_properties() {
}

table egress_bd_map {
    reads {
        ingress_metadata.egress_bd : exact;
    }
    actions {
        nop;
        set_egress_bd_properties;
    }
    size : EGRESS_BD_MAPPING_TABLE_SIZE;
}

control process_egress_bd {
    apply(egress_bd_map);
}

action vlan_decap_nop() {
    modify_field(ethernet.etherType, l2_metadata.lkp_mac_type);
}

action remove_vlan_single_tagged() {
    remove_header(vlan_tag_[0]);
    modify_field(ethernet.etherType, l2_metadata.lkp_mac_type);
}

action remove_vlan_double_tagged() {
    remove_header(vlan_tag_[0]);
    remove_header(vlan_tag_[1]);
    modify_field(ethernet.etherType, l2_metadata.lkp_mac_type);
}

action remove_vlan_qinq_tagged() {
    remove_header(vlan_tag_[0]);
    remove_header(vlan_tag_[1]);
    modify_field(ethernet.etherType, l2_metadata.lkp_mac_type);
}

table vlan_decap {
    reads {
        egress_metadata.drop_exception : exact;
        vlan_tag_[0] : valid;
        vlan_tag_[1] : valid;
    }
    actions {
        vlan_decap_nop;
        remove_vlan_single_tagged;
        remove_vlan_double_tagged;
        remove_vlan_qinq_tagged;
    }
    size: VLAN_DECAP_TABLE_SIZE;
}

control process_vlan_decap {
    apply(vlan_decap);
}
