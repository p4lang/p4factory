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

/*
 * L3 Metadata
 */
header_type l3_metadata_t {
    fields {
        lkp_ip_type : 2;                       /* packet type */
        lkp_ip_proto : 8;                      /* ip Protocol */
        lkp_ip_tc : 8;                         /* traffic class */
        lkp_ip_ttl : 8;                        /* time to live */
        lkp_l4_sport : 16;                     /* l4 source port */
        lkp_l4_dport : 16;                     /* l4 destination port */
        lkp_inner_l4_sport : 16;               /* l4 inner source port */
        lkp_inner_l4_dport : 16;               /* l4 inner destination port */
        outer_dscp : 8;                        /* outer dscp */
        outer_ttl : 8;                         /* outer ttl */
        vrf : VRF_BIT_WIDTH;                   /* VRF */
        fib_nexthop : 16;                      /* next hop from fib */
        rmac_group : 10;                       /* Rmac group, for rmac indirection */
        rmac_hit : 1;                          /* dst mac is the router's mac */
        fib_hit : 1;                           /* fib hit */
        fib_ecmp : 10;                         /* ecmp index from fib */
        ecmp_index : 10;                       /* final ecmp index */
        ecmp_offset : 14;                      /* offset into the ecmp table */
        nexthop_index : 16;                    /* final next hop index */
        ttl : 8;                               /* update ttl */
        ipv4_dstaddr_24b : 24;                 /* first 24b of ipv4 dst addr */
        routed : 1;                            /* is packet routed */
        l3_length : 16;                        /* l3 length */

        /* Egress Metadata */
        egress_routed : 1;                     /* is this replica routed */
        mtu_check_fail : 1;                    /* MTU check failed */
    }
}

metadata l3_metadata_t l3_metadata;

/* ROUTER_MAC_CONTROL_BLOCK */
action set_rmac_hit_flag() {
    modify_field(l3_metadata.rmac_hit, TRUE);
}

/*
 * Table: Router Mac
 * Lookup: Ingress
 * Packets destined to my mac will be routed
 */
table rmac {
    reads {
        l3_metadata.rmac_group : exact;
        l2_metadata.lkp_mac_da : exact;
    }
    actions {
        on_miss;
        set_rmac_hit_flag;
    }
    size : ROUTER_MAC_TABLE_SIZE;
}

/* NEXTHOP_CONTROL_BLOCK */
/*
 * Fib nexthop and ecmp actions
 */
action fib_hit_nexthop(nexthop_index) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.fib_nexthop, nexthop_index);
}

action fib_hit_ecmp(ecmp_index) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.fib_ecmp, ecmp_index);
}

/*
 * Field list: Ecmp Field list
 * Used in ecmp hashing
 */
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

/*
 * Table: ECMP
 * Lookup: Ingress
 * Derive nexthop to derive ingress port and rewrite information
 */
table ecmp_group {
    reads {
        l3_metadata.ecmp_index : exact;
    }
    action_profile: ecmp_action_profile;
    size : ECMP_GROUP_TABLE_SIZE;
}

action set_nexthop_details(ifindex, bd) {
    modify_field(l2_metadata.egress_ifindex, ifindex);
    modify_field(l2_metadata.egress_bd, bd);
}

action set_ecmp_nexthop_details(ifindex, bd, nhop_index) {
    modify_field(l2_metadata.egress_ifindex, ifindex);
    modify_field(l2_metadata.egress_bd, bd);
    modify_field(l3_metadata.nexthop_index, nhop_index);
}

/*
 * If dest mac is not known, then unicast packet needs to be flooded in
 * egress BD
 */
action set_nexthop_details_for_post_routed_flood(bd, uuc_mc_index) {
    modify_field(intrinsic_metadata.eg_mcast_group, uuc_mc_index);
    modify_field(l2_metadata.egress_bd, bd);
}

action set_ecmp_nexthop_details_for_post_routed_flood(bd, uuc_mc_index, nhop_index) {
    modify_field(intrinsic_metadata.eg_mcast_group, uuc_mc_index);
    modify_field(l2_metadata.egress_bd, bd);
    modify_field(l3_metadata.nexthop_index, nhop_index);
}

/*
 * Table: Nexthop
 * Lookup: Ingress
 * Derive egress port and bd
 */
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
    /* resolve ecmp */
    if (l3_metadata.ecmp_index != 0) {
        apply(ecmp_group);
    } else {
        /* resolve nexthop */
        apply(nexthop);
    }
}
