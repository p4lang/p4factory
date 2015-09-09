/*
 * Layer-2 processing
 */

header_type l2_metadata_t {
    fields {
        lkp_pkt_type : 3;
        lkp_mac_sa : 48;
        lkp_mac_da : 48;
        lkp_mac_type : 16;

        l2_nexthop : 16;                       /* next hop from l2 */
        l2_nexthop_type : 1;                   /* ecmp or nexthop */
        l2_redirect : 1;                       /* l2 redirect action */
        l2_src_miss : 1;                       /* l2 source miss */
        l2_src_move : IFINDEX_BIT_WIDTH;       /* l2 source interface mis-match */
        stp_group: 10;                         /* spanning tree group id */
        stp_state : 3;                         /* spanning tree port state */
        bd_stats_idx : 16;                     /* ingress BD stats index */
    }
}

metadata l2_metadata_t l2_metadata;

#ifndef L2_DISABLE
/*****************************************************************************/
/* Spanning tree lookup                                                      */
/*****************************************************************************/
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
/*****************************************************************************/
/* Source MAC lookup                                                         */
/*****************************************************************************/
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

/*****************************************************************************/
/* Destination MAC lookup                                                    */
/*****************************************************************************/
action dmac_hit(ifindex) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
}

action dmac_multicast_hit(mc_index) {
    modify_field(intrinsic_metadata.mcast_grp, mc_index);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}

action dmac_miss() {
    modify_field(ingress_metadata.egress_ifindex, IFINDEX_FLOOD);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
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
#ifdef OPENFLOW_ENABLE
        openflow_apply;
        openflow_miss;
#endif /* OPENFLOW_ENABLE */
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
/*****************************************************************************/
/* MAC learn notification                                                    */
/*****************************************************************************/
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
    apply(learn_notify);
#endif /* L2_DISABLE */
}


/*****************************************************************************/
/* Validate packet                                                           */
/*****************************************************************************/
action set_unicast() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
}

action set_unicast_and_ipv6_src_is_link_local() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(ipv6_metadata.ipv6_src_is_link_local, TRUE);
}

action set_multicast() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    add_to_field(l2_metadata.bd_stats_idx, 1);
}

action set_ip_multicast() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    add_to_field(l2_metadata.bd_stats_idx, 1);
    modify_field(multicast_metadata.ip_multicast, TRUE);
}

action set_ip_multicast_and_ipv6_src_is_link_local() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(ipv6_metadata.ipv6_src_is_link_local, TRUE);
    add_to_field(l2_metadata.bd_stats_idx, 1);
    modify_field(multicast_metadata.ip_multicast, TRUE);
}

action set_broadcast() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    add_to_field(l2_metadata.bd_stats_idx, 2);
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


/*****************************************************************************/
/* Egress BD lookup                                                          */
/*****************************************************************************/
action set_egress_bd_properties() {
}

table egress_bd_map {
    reads {
        egress_metadata.bd : exact;
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


/*****************************************************************************/
/* Egress VLAN decap                                                         */
/*****************************************************************************/
action remove_vlan_single_tagged() {
    modify_field(ethernet.etherType, vlan_tag_[0].etherType);
    remove_header(vlan_tag_[0]);
}

action remove_vlan_double_tagged() {
    modify_field(ethernet.etherType, vlan_tag_[1].etherType);
    remove_header(vlan_tag_[0]);
    remove_header(vlan_tag_[1]);
}

action remove_vlan_qinq_tagged() {
    modify_field(ethernet.etherType, vlan_tag_[1].etherType);
    remove_header(vlan_tag_[0]);
    remove_header(vlan_tag_[1]);
}

table vlan_decap {
    reads {
        vlan_tag_[0] : valid;
        vlan_tag_[1] : valid;
    }
    actions {
        nop;
        remove_vlan_single_tagged;
        remove_vlan_double_tagged;
        remove_vlan_qinq_tagged;
    }
    size: VLAN_DECAP_TABLE_SIZE;
}

control process_vlan_decap {
    apply(vlan_decap);
}
