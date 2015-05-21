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
 * nexthop metadata
 */
header_type nexthop_metadata_t {
    fields {
        nexthop_type : 1;                      /* final next hop index type */
    }
}

metadata nexthop_metadata_t nexthop_metadata;

action set_l2_redirect_action() {
    modify_field(l3_metadata.nexthop_index, l2_metadata.l2_nexthop);
    modify_field(nexthop_metadata.nexthop_type,
                 l2_metadata.l2_nexthop_type);
}

action set_acl_redirect_action() {
    modify_field(l3_metadata.nexthop_index, acl_metadata.acl_nexthop);
    modify_field(nexthop_metadata.nexthop_type,
                 acl_metadata.acl_nexthop_type);
}

action set_racl_redirect_action() {
    modify_field(l3_metadata.nexthop_index, acl_metadata.racl_nexthop);
    modify_field(nexthop_metadata.nexthop_type,
                 acl_metadata.racl_nexthop_type);
    modify_field(l3_metadata.routed, TRUE);
}

action set_fib_redirect_action() {
    modify_field(l3_metadata.nexthop_index, l3_metadata.fib_nexthop);
    modify_field(nexthop_metadata.nexthop_type,
                 l3_metadata.fib_nexthop_type);
    modify_field(l3_metadata.routed, TRUE);
    modify_field(intrinsic_metadata.eg_mcast_group, 0);
}

table fwd_result {
    reads {
        l2_metadata.l2_redirect : ternary;
        acl_metadata.acl_redirect : ternary;
        acl_metadata.racl_redirect : ternary;
        l3_metadata.fib_hit : ternary;
    }
    actions {
        nop;
        set_l2_redirect_action;
        set_acl_redirect_action;
        set_racl_redirect_action;
        set_fib_redirect_action;
    }
    size : FWD_RESULT_TABLE_SIZE;
}

control process_merge_results {
    apply(fwd_result);
}

field_list l3_hash_fields {
    ipv4_metadata.lkp_ipv4_sa;
    ipv4_metadata.lkp_ipv4_da;
    l3_metadata.lkp_ip_proto;
    ingress_metadata.lkp_l4_sport;
    ingress_metadata.lkp_l4_dport;
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
    modify_field(ingress_metadata.egress_bd, bd);
    bit_xor(ingress_metadata.same_bd_check, ingress_metadata.bd, bd);
}

action set_ecmp_nexthop_details(ifindex, bd, nhop_index) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    modify_field(ingress_metadata.egress_bd, bd);
    modify_field(l3_metadata.nexthop_index, nhop_index);
    bit_xor(ingress_metadata.same_bd_check, ingress_metadata.bd, bd);
}

/*
 * If dest mac is not know, then unicast packet needs to be flooded in
 * egress BD
 */
action set_nexthop_details_for_post_routed_flood(bd, uuc_mc_index) {
    modify_field(intrinsic_metadata.eg_mcast_group, uuc_mc_index);
    modify_field(ingress_metadata.egress_bd, bd);
    bit_xor(ingress_metadata.same_bd_check, ingress_metadata.bd, bd);
}

action set_ecmp_nexthop_details_for_post_routed_flood(bd, uuc_mc_index,
                                                      nhop_index) {
    modify_field(intrinsic_metadata.eg_mcast_group, uuc_mc_index);
    modify_field(ingress_metadata.egress_bd, bd);
    modify_field(l3_metadata.nexthop_index, nhop_index);
    bit_xor(ingress_metadata.same_bd_check, ingress_metadata.bd, bd);
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
