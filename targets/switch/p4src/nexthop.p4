/*
 * Nexthop related processing
 */

/*
 * nexthop metadata
 */
header_type nexthop_metadata_t {
    fields {
        nexthop_type : 1;                      /* final next hop index type */
    }
}

metadata nexthop_metadata_t nexthop_metadata;

/*****************************************************************************/
/* Forwarding result lookup and decisions                                    */
/*****************************************************************************/
action set_l2_redirect_action() {
    modify_field(l3_metadata.nexthop_index, l2_metadata.l2_nexthop);
    modify_field(nexthop_metadata.nexthop_type, l2_metadata.l2_nexthop_type);
}

action set_acl_redirect_action() {
    modify_field(l3_metadata.nexthop_index, acl_metadata.acl_nexthop);
    modify_field(nexthop_metadata.nexthop_type, acl_metadata.acl_nexthop_type);
}

action set_racl_redirect_action() {
    modify_field(l3_metadata.nexthop_index, acl_metadata.racl_nexthop);
    modify_field(nexthop_metadata.nexthop_type, acl_metadata.racl_nexthop_type);
    modify_field(l3_metadata.routed, TRUE);
}

action set_fib_redirect_action() {
    modify_field(l3_metadata.nexthop_index, l3_metadata.fib_nexthop);
    modify_field(nexthop_metadata.nexthop_type, l3_metadata.fib_nexthop_type);
    modify_field(l3_metadata.routed, TRUE);
    modify_field(intrinsic_metadata.mcast_grp, 0);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

action set_cpu_redirect_action() {
    modify_field(l3_metadata.routed, FALSE);
    modify_field(intrinsic_metadata.mcast_grp, 0);
    modify_field(ingress_metadata.egress_ifindex, CPU_PORT_ID);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

table fwd_result {
    reads {
        l2_metadata.l2_redirect : ternary;
        acl_metadata.acl_redirect : ternary;
        acl_metadata.racl_redirect : ternary;
        l3_metadata.rmac_hit : ternary;
        l3_metadata.fib_hit : ternary;
    }
    actions {
        nop;
        set_l2_redirect_action;
        set_fib_redirect_action;
        set_cpu_redirect_action;
#ifndef ACL_DISABLE
        set_acl_redirect_action;
        set_racl_redirect_action;
#endif /* ACL_DISABLE */
    }
    size : FWD_RESULT_TABLE_SIZE;
}

control process_fwd_results {
    apply(fwd_result);
}


/*****************************************************************************/
/* ECMP lookup                                                               */
/*****************************************************************************/
field_list l3_hash_fields {
    ipv4_metadata.lkp_ipv4_sa;
    ipv4_metadata.lkp_ipv4_da;
    l3_metadata.lkp_ip_proto;
    l3_metadata.lkp_l4_sport;
    l3_metadata.lkp_l4_dport;
}

field_list_calculation ecmp_hash {
    input {
        l3_hash_fields;
    }
    algorithm : crc16;
    output_width : ECMP_BIT_WIDTH;
}

action_selector ecmp_selector {
    selection_key : ecmp_hash;
}

action_profile ecmp_action_profile {
    actions {
        nop;
        set_ecmp_nexthop_details;
        set_ecmp_nexthop_details_for_post_routed_flood;
    }
    size : ECMP_SELECT_TABLE_SIZE;
    dynamic_action_selection : ecmp_selector;
}

table ecmp_group {
    reads {
        l3_metadata.nexthop_index : exact;
    }
    action_profile: ecmp_action_profile;
    size : ECMP_GROUP_TABLE_SIZE;
}

action set_nexthop_details(ifindex, bd) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.ingress_bd, bd);
}

action set_ecmp_nexthop_details(ifindex, bd, nhop_index) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    modify_field(l3_metadata.nexthop_index, nhop_index);
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.ingress_bd, bd);
}


/*****************************************************************************/
/* Nexthop lookup                                                            */
/*****************************************************************************/
/*
 * If dest mac is not know, then unicast packet needs to be flooded in
 * egress BD
 */
action set_nexthop_details_for_post_routed_flood(bd, uuc_mc_index) {
    modify_field(intrinsic_metadata.mcast_grp, uuc_mc_index);
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.ingress_bd, bd);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}

action set_ecmp_nexthop_details_for_post_routed_flood(bd, uuc_mc_index,
                                                      nhop_index) {
    modify_field(intrinsic_metadata.mcast_grp, uuc_mc_index);
    modify_field(l3_metadata.nexthop_index, nhop_index);
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.ingress_bd, bd);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}

table nexthop {
    reads {
        l3_metadata.nexthop_index : exact;
    }
    actions {
        nop;
        set_nexthop_details;
        set_nexthop_details_for_post_routed_flood;
    }
    size : NEXTHOP_TABLE_SIZE;
}

control process_nexthop {
    if (nexthop_metadata.nexthop_type == NEXTHOP_TYPE_ECMP) {
        /* resolve ecmp */
        apply(ecmp_group);
    } else {
        /* resolve nexthop */
        apply(nexthop);
    }
}
