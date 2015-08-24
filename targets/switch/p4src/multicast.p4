/*
 * Multicast processing
 */

header_type multicast_metadata_t {
    fields {
        ip_multicast : 1;                      /* packet is ip multicast */
        igmp_snooping_enabled : 1;             /* is IGMP snooping enabled on BD */
        mld_snooping_enabled : 1;              /* is MLD snooping enabled on BD */
        inner_replica : 1;                     /* is copy is due to inner replication */
        replica : 1;                           /* is this a replica */
#ifdef FABRIC_ENABLE
        mcast_grp : 16;
#endif /* FABRIC_ENABLE */
    }
}

metadata multicast_metadata_t multicast_metadata;

/*****************************************************************************/
/* Multicast HASH calculation for PRE                                        */
/*****************************************************************************/
field_list inner_ipv4_hash_fields {
    inner_ipv4.srcAddr;
    inner_ipv4.dstAddr;
    inner_ipv4.protocol;
    l3_metadata.lkp_inner_l4_sport;
    l3_metadata.lkp_inner_l4_dport;
}

field_list_calculation inner_ipv4_hash {
    input {
        inner_ipv4_hash_fields;
    }
    algorithm : crc16;
    output_width : LAG_BIT_WIDTH;
}

action compute_inner_ipv4_hash() {
    modify_field_with_hash_based_offset(intrinsic_metadata.mcast_hash,
                                        0, inner_ipv4_hash, 8192);
}

field_list inner_ipv6_hash_fields {
    inner_ipv6.srcAddr;
    inner_ipv6.dstAddr;
    inner_ipv6.nextHdr;
    l3_metadata.lkp_inner_l4_sport;
    l3_metadata.lkp_inner_l4_dport;
}

field_list_calculation inner_ipv6_hash {
    input {
        inner_ipv6_hash_fields;
    }
    algorithm : crc16;
    output_width : LAG_BIT_WIDTH;
}

action compute_inner_ipv6_hash() {
    modify_field_with_hash_based_offset(intrinsic_metadata.mcast_hash,
                                        0, inner_ipv6_hash, 8192);
}

field_list inner_non_ip_hash_fields {
    inner_ethernet.srcAddr;
    inner_ethernet.dstAddr;
    inner_ethernet.etherType;
}

field_list_calculation inner_non_ip_hash {
    input {
        inner_non_ip_hash_fields;
    }
    algorithm : crc16;
    output_width : LAG_BIT_WIDTH;
}

action compute_inner_non_ip_hash() {
    modify_field_with_hash_based_offset(intrinsic_metadata.mcast_hash,
                                        0, inner_non_ip_hash, 8192);
}

field_list lkp_ipv4_hash_fields {
    ipv4_metadata.lkp_ipv4_sa;
    ipv4_metadata.lkp_ipv4_da;
    l3_metadata.lkp_ip_proto;
    l3_metadata.lkp_l4_sport;
    l3_metadata.lkp_l4_dport;
}

field_list_calculation lkp_ipv4_hash {
    input {
        lkp_ipv4_hash_fields;
    }
    algorithm : crc16;
    output_width : LAG_BIT_WIDTH;
}

action compute_lkp_ipv4_hash() {
    modify_field_with_hash_based_offset(intrinsic_metadata.mcast_hash,
                                        0, lkp_ipv4_hash, 8192);
}

field_list lkp_ipv6_hash_fields {
    ipv6_metadata.lkp_ipv6_sa;
    ipv6_metadata.lkp_ipv6_da;
    l3_metadata.lkp_ip_proto;
    l3_metadata.lkp_l4_sport;
    l3_metadata.lkp_l4_dport;
}

field_list_calculation lkp_ipv6_hash {
    input {
        lkp_ipv6_hash_fields;
    }
    algorithm : crc16;
    output_width : LAG_BIT_WIDTH;
}

action compute_lkp_ipv6_hash() {
    modify_field_with_hash_based_offset(intrinsic_metadata.mcast_hash,
                                        0, lkp_ipv6_hash, 8192);
}

field_list lkp_non_ip_hash_fields {
    l2_metadata.lkp_mac_sa;
    l2_metadata.lkp_mac_da;
    l2_metadata.lkp_mac_type;
}

field_list_calculation lkp_non_ip_hash {
    input {
        lkp_non_ip_hash_fields;
    }
    algorithm : crc16;
    output_width : LAG_BIT_WIDTH;
}

action compute_lkp_non_ip_hash() {
    modify_field_with_hash_based_offset(intrinsic_metadata.mcast_hash,
                                        0, lkp_non_ip_hash, 8192);
}

table compute_multicast_hashes {
    reads {
        ingress_metadata.port_type : ternary;
        tunnel_metadata.tunnel_terminate : ternary;
        ipv4 : valid;
        ipv6 : valid;
        inner_ipv4 : valid;
        inner_ipv6 : valid;
    }
    actions {
        nop;
        compute_lkp_ipv4_hash;
        compute_inner_ipv4_hash;
        compute_lkp_non_ip_hash;
        compute_inner_non_ip_hash;
#ifndef IPV6_DISABLE
        compute_lkp_ipv6_hash;
        compute_inner_ipv6_hash;
#endif /* IPV6_DISABLE */
    }
}

control process_multicast_hashes {
#ifndef MULTICAST_DISABLE
    apply(compute_multicast_hashes);
#endif /* MULTICAST_DISABLE */
}


/*****************************************************************************/
/* Multicast flooding                                                        */
/*****************************************************************************/
action set_bd_flood_mc_index(mc_index) {
    modify_field(intrinsic_metadata.mcast_grp, mc_index);
}

table bd_flood {
    reads {
        ingress_metadata.bd : exact;
        l2_metadata.lkp_pkt_type : exact;
    }
    actions {
        nop;
        set_bd_flood_mc_index;
    }
    size : BD_FLOOD_TABLE_SIZE;
}

control process_multicast_flooding {
#ifndef MULTICAST_DISABLE
    apply(bd_flood);
#endif /* MULTICAST_DISABLE */
}


/*****************************************************************************/
/* Multicast replication processing                                          */
/*****************************************************************************/
#ifndef MULTICAST_DISABLE
action outer_replica_from_rid(bd, nexthop_index) {
    modify_field(egress_metadata.bd, bd);
    modify_field(multicast_metadata.replica, TRUE);
    modify_field(multicast_metadata.inner_replica, FALSE);
    modify_field(egress_metadata.routed, l3_metadata.outer_routed);
    modify_field(l3_metadata.nexthop_index, nexthop_index);
    bit_xor(egress_metadata.same_bd_check, bd, ingress_metadata.bd);
}

action inner_replica_from_rid(bd, nexthop_index) {
    modify_field(egress_metadata.bd, bd);
    modify_field(multicast_metadata.replica, TRUE);
    modify_field(multicast_metadata.inner_replica, TRUE);
    modify_field(egress_metadata.routed, l3_metadata.routed);
    modify_field(l3_metadata.nexthop_index, nexthop_index);
    bit_xor(egress_metadata.same_bd_check, bd, ingress_metadata.bd);
}

table rid {
    reads {
        intrinsic_metadata.egress_rid : exact;
    }
    actions {
        nop;
        outer_replica_from_rid;
        inner_replica_from_rid;
    }
    size : RID_TABLE_SIZE;
}

action set_replica_copy_bridged() {
    modify_field(egress_metadata.routed, FALSE);
}

table replica_type {
    reads {
        multicast_metadata.replica : exact;
        egress_metadata.same_bd_check : ternary;
    }
    actions {
        nop;
        set_replica_copy_bridged;
    }
    size : REPLICA_TYPE_TABLE_SIZE;
}
#endif

control process_replication {
#ifndef MULTICAST_DISABLE
    if(intrinsic_metadata.egress_rid != 0) {
        /* set info from rid */
        apply(rid);

        /*  routed or bridge replica */
        apply(replica_type);
    }
#endif /* MULTICAST_DISABLE */
}
