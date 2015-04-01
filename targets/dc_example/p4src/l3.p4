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

header_type l3_metadata_t {
    fields {
        lkp_ip_type : 2;
        lkp_ipv4_sa : 32;
        lkp_ipv4_da : 32;
        lkp_ip_proto : 8;
        lkp_ip_tc : 8;
        lkp_ip_ttl : 8;
        lkp_l4_sport : 16;
        lkp_l4_dport : 16;
        lkp_inner_l4_sport : 16;
        lkp_inner_l4_dport : 16;

        outer_dscp : 8;                        /* outer dscp */
        outer_ttl : 8;                         /* outer ttl */

        vrf : VRF_BIT_WIDTH;                   /* VRF */
        fib_nexthop : 16;                      /* next hop from fib */
        rmac_group : 10;                       /* Rmac group, for rmac indirection */
        rmac_hit : 1;                          /* dst mac is the router's mac */
        fib_hit : 1;                           /* fib hit */
        ipv4_unicast_enabled : 1;              /* is ipv4 unicast routing enabled on BD */
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

action set_valid_outer_ipv4_packet() {
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
    modify_field(l3_metadata.lkp_ipv4_sa, ipv4.srcAddr);
    modify_field(l3_metadata.lkp_ipv4_da, ipv4.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto, ipv4.protocol);
    modify_field(l3_metadata.lkp_ip_tc, ipv4.diffserv);
    modify_field(l3_metadata.lkp_ip_ttl, ipv4.ttl);
    modify_field(l3_metadata.l3_length, ipv4.totalLen);
}

action set_malformed_outer_ipv4_packet() {
}

table validate_outer_ipv4_packet {
    reads {
        ipv4.version : exact;
        ipv4.ihl : exact;
        ipv4.ttl : exact;
        ipv4.srcAddr : ternary;
        ipv4.dstAddr : ternary;
    }
    actions {
        set_valid_outer_ipv4_packet;
        set_malformed_outer_ipv4_packet;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}

control validate_outer_ipv4_header {
    /* validate input packet and perform basic validations */
    if (valid(ipv4)) {
        apply(validate_outer_ipv4_packet);
    }
}

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

action fib_hit_nexthop(nexthop_index) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.fib_nexthop, nexthop_index);
}

action fib_hit_ecmp(ecmp_index) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.fib_ecmp, ecmp_index);
}

table ipv4_fib_lpm {
    reads {
        l3_metadata.vrf : exact;
        l3_metadata.lkp_ipv4_da : lpm;
    }
    actions {
        fib_hit_nexthop;
        fib_hit_ecmp;
    }
    size : IPV4_LPM_TABLE_SIZE;
}

table ipv4_fib {
    reads {
        l3_metadata.vrf : exact;
        l3_metadata.lkp_ipv4_da : exact;
    }
    actions {
        on_miss;
        fib_hit_nexthop;
        fib_hit_ecmp;
    }
    size : IPV4_HOST_TABLE_SIZE;
}

control fib_lookup {
    /* fib lookup */
    apply(ipv4_fib) {
        on_miss {
            apply(ipv4_fib_lpm);
        }
    }
}

field_list l3_hash_fields {
    l3_metadata.lkp_ipv4_sa;
    l3_metadata.lkp_ipv4_da;
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
    selector : ecmp_selector;
}

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

control nexthop_lookup {
    /* resolve ecmp */
    if (l3_metadata.ecmp_index != 0) {
        apply(ecmp_group);
    } else {
        /* resolve nexthop */
        apply(nexthop);
    }
}
