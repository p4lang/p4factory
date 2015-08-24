/*
 * Layer-3 processing
 */

/*
 * L3 Metadata
 */

header_type l3_metadata_t {
    fields {
        lkp_ip_type : 2;
        lkp_ip_proto : 8;
        lkp_ip_tc : 8;
        lkp_ip_ttl : 8;
        lkp_l4_sport : 16;
        lkp_l4_dport : 16;
        lkp_inner_l4_sport : 16;
        lkp_inner_l4_dport : 16;
        lkp_icmp_type : 8;
        lkp_icmp_code : 8;
        lkp_inner_icmp_type : 8;
        lkp_inner_icmp_code : 8;

        vrf : VRF_BIT_WIDTH;                   /* VRF */
        rmac_group : 10;                       /* Rmac group, for rmac indirection */
        rmac_hit : 1;                          /* dst mac is the router's mac */
        urpf_mode : 2;                         /* urpf mode for current lookup */
        urpf_hit : 1;                          /* hit in urpf table */
        urpf_check_fail :1;                    /* urpf check failed */
        urpf_bd_group : BD_BIT_WIDTH;          /* urpf bd group */
        fib_hit : 1;                           /* fib hit */
        fib_nexthop : 16;                      /* next hop from fib */
        fib_nexthop_type : 1;                  /* ecmp or nexthop */
        same_bd_check : BD_BIT_WIDTH;          /* ingress bd xor egress bd */
        nexthop_index : 16;                    /* nexthop/rewrite index */
        routed : 1;                            /* is packet routed? */
        outer_routed : 1;                      /* is outer packet routed? */
    }
}

metadata l3_metadata_t l3_metadata;


/*****************************************************************************/
/* Router MAC lookup                                                         */
/*****************************************************************************/
action rmac_hit() {
    modify_field(l3_metadata.rmac_hit, TRUE);
}

action rmac_miss() {
    modify_field(l3_metadata.rmac_hit, FALSE);
}

table rmac {
    reads {
        l3_metadata.rmac_group : exact;
        l2_metadata.lkp_mac_da : exact;
    }
    actions {
        rmac_hit;
        rmac_miss;
    }
    size : ROUTER_MAC_TABLE_SIZE;
}


/*****************************************************************************/
/* FIB hit actions for nexthops and ECMP                                     */
/*****************************************************************************/
action fib_hit_nexthop(nexthop_index) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.fib_nexthop, nexthop_index);
    modify_field(l3_metadata.fib_nexthop_type, NEXTHOP_TYPE_SIMPLE);
}

action fib_hit_ecmp(ecmp_index) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.fib_nexthop, ecmp_index);
    modify_field(l3_metadata.fib_nexthop_type, NEXTHOP_TYPE_ECMP);
}


#if !defined(L3_DISABLE) && !defined(URPF_DISABLE)
/*****************************************************************************/
/* uRPF BD check                                                             */
/*****************************************************************************/
action urpf_bd_miss() {
    modify_field(l3_metadata.urpf_check_fail, TRUE);
}

action urpf_miss() {
    modify_field(l3_metadata.urpf_check_fail, TRUE);
}

table urpf_bd {
    reads {
        l3_metadata.urpf_bd_group : exact;
        ingress_metadata.bd : exact;
    }
    actions {
        nop;
        urpf_bd_miss;
    }
    size : URPF_GROUP_TABLE_SIZE;
}
#endif /* L3_DISABLE && URPF_DISABLE */

control process_urpf_bd {
#if !defined(L3_DISABLE) && !defined(URPF_DISABLE)
    if ((l3_metadata.urpf_mode == URPF_MODE_STRICT) and
        (l3_metadata.urpf_hit == TRUE)) {
        apply(urpf_bd);
    }
#endif /* L3_DISABLE && URPF_DISABLE */
}


/*****************************************************************************/
/* Egress MAC rewrite                                                        */
/*****************************************************************************/
action rewrite_ipv4_unicast_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
    modify_field(ethernet.dstAddr, egress_metadata.mac_da);
    add_to_field(ipv4.ttl, -1);
}

action rewrite_ipv4_multicast_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
    modify_field(ethernet.dstAddr, 0x01005E000000, 0xFFFFFF800000);
    add_to_field(ipv4.ttl, -1);
}

action rewrite_ipv6_unicast_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
    modify_field(ethernet.dstAddr, egress_metadata.mac_da);
    add_to_field(ipv6.hopLimit, -1);
}

action rewrite_ipv6_multicast_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
    modify_field(ethernet.dstAddr, 0x333300000000, 0xFFFF00000000);
    add_to_field(ipv6.hopLimit, -1);
}

action rewrite_mpls_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
    modify_field(ethernet.dstAddr, egress_metadata.mac_da);
    add_to_field(mpls[0].ttl, -1);
}

table mac_rewrite {
    reads {
        egress_metadata.smac_idx : exact;
        ipv4 : valid;
        ipv6 : valid;
        mpls[0] : valid;
    }
    actions {
        nop;
        rewrite_ipv4_unicast_mac;
        rewrite_ipv4_multicast_mac;
#ifndef IPV6_DISABLED
        rewrite_ipv6_unicast_mac;
        rewrite_ipv6_multicast_mac;
#endif /* IPV6_DISABLED */
#ifndef MPLS_DISABLED
        rewrite_mpls_mac;
#endif /* MPLS_DISABLED */
    }
    size : MAC_REWRITE_TABLE_SIZE;
}

control process_mac_rewrite {
    if (egress_metadata.routed == TRUE) {
        apply(mac_rewrite);
    }
}


#if !defined(L3_DISABLE) && !defined(MTU_DISABLE)
/*****************************************************************************/
/* Egress MTU check                                                          */
/*****************************************************************************/
action mtu_check_pass() {
}

action mtu_check_fail() {
    modify_field(egress_metadata.drop_reason, 1);
}

table mtu {
    reads {
        egress_metadata.bd : exact;
        ethernet.etherType : exact;
        //standard_metadata.packet_length : range;
    }
    actions {
        nop;
        mtu_check_pass;
        mtu_check_fail;
    }
    size : IP_MTU_TABLE_SIZE;
}
#endif /* L3_DISABLE && MTU_DISABLE */

control process_mtu {
#if !defined(L3_DISABLE) && !defined(MTU_DISABLE)
    apply(mtu);
#endif /* L3_DISABLE && MTU_DISABLE */
}
