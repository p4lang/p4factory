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

/* FWD_RESULT_CONTROL_BLOCK */
action nop() {
}

action on_miss() {
}

action set_l2_redirect_action() {
    modify_field(l3_metadata.nexthop_index, l2_metadata.l2_nexthop);
    modify_field(l3_metadata.ecmp_index, l2_metadata.l2_ecmp);
    modify_field(l3_metadata.ttl, l3_metadata.lkp_ip_ttl);
}

action set_acl_redirect_action() {
    modify_field(l3_metadata.nexthop_index, acl_metadata.acl_nexthop);
    modify_field(l3_metadata.ecmp_index, acl_metadata.acl_ecmp);
}

action set_racl_redirect_action() {
    modify_field(l3_metadata.nexthop_index, acl_metadata.racl_nexthop);
    modify_field(l3_metadata.ecmp_index, acl_metadata.racl_ecmp);
    modify_field(l3_metadata.routed, TRUE);
    modify_field(l3_metadata.ttl, l3_metadata.lkp_ip_ttl);
    add_to_field(l3_metadata.ttl, -1);
}

action set_fib_redirect_action() {
    modify_field(l3_metadata.nexthop_index, l3_metadata.fib_nexthop);
    modify_field(l3_metadata.ecmp_index, l3_metadata.fib_ecmp);
    modify_field(l3_metadata.routed, TRUE);
    modify_field(l3_metadata.ttl, l3_metadata.lkp_ip_ttl);
    add_to_field(l3_metadata.ttl, -1);
}

/*
 * Table: Forward result
 * Lookup: Ingress
 * Derive nexthop based on priority
 */
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
    /* merge the results and decide whice one to use */
    apply(fwd_result);
}

/* REWRITE_CONTROL_BLOCK */
action set_l2_rewrite() {
    modify_field(l3_metadata.egress_routed, FALSE);
}

action set_ipv4_unicast_rewrite(smac_idx, dmac) {
    modify_field(l2_metadata.egress_smac_idx, smac_idx);
    modify_field(l2_metadata.egress_mac_da, dmac);
    modify_field(l3_metadata.egress_routed, TRUE);
    modify_field(ipv4.ttl, l3_metadata.ttl);
}

action set_ipv4_vxlan_rewrite(outer_bd, tunnel_src_index, tunnel_dst_index,
        smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(l2_metadata.egress_smac_idx, smac_idx);
    modify_field(l2_metadata.egress_mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_src_index, tunnel_src_index);
    modify_field(tunnel_metadata.tunnel_dst_index, tunnel_dst_index);
    modify_field(l3_metadata.egress_routed, TRUE);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV4_VXLAN);
}

action set_ipv4_geneve_rewrite(outer_bd, tunnel_src_index, tunnel_dst_index,
        smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(l2_metadata.egress_smac_idx, smac_idx);
    modify_field(l2_metadata.egress_mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_src_index, tunnel_src_index);
    modify_field(tunnel_metadata.tunnel_dst_index, tunnel_dst_index);
    modify_field(l3_metadata.egress_routed, TRUE);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV4_GENEVE);
}

action set_ipv4_nvgre_rewrite(outer_bd, tunnel_src_index, tunnel_dst_index,
        smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(l2_metadata.egress_smac_idx, smac_idx);
    modify_field(l2_metadata.egress_mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_src_index, tunnel_src_index);
    modify_field(tunnel_metadata.tunnel_dst_index, tunnel_dst_index);
    modify_field(l3_metadata.egress_routed, TRUE);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV4_NVGRE);
}

action set_ipv4_erspan_v2_rewrite(outer_bd, tunnel_src_index, tunnel_dst_index,
        smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(l2_metadata.egress_smac_idx, smac_idx);
    modify_field(l2_metadata.egress_mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_src_index, tunnel_src_index);
    modify_field(tunnel_metadata.tunnel_dst_index, tunnel_dst_index);
    modify_field(l3_metadata.egress_routed, TRUE);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV4_ERSPANV2);
}

action set_ipv6_unicast_rewrite(smac_idx, dmac) {
    modify_field(l2_metadata.egress_smac_idx, smac_idx);
    modify_field(l2_metadata.egress_mac_da, dmac);
    modify_field(l3_metadata.egress_routed, TRUE);
    modify_field(ipv6.hopLimit, l3_metadata.ttl);
}

action set_ipv6_vxlan_rewrite(outer_bd, tunnel_src_index, tunnel_dst_index,
        smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(l2_metadata.egress_smac_idx, smac_idx);
    modify_field(l2_metadata.egress_mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_src_index, tunnel_src_index);
    modify_field(tunnel_metadata.tunnel_dst_index, tunnel_dst_index);
    modify_field(l3_metadata.egress_routed, TRUE);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV6_VXLAN);
}

action set_ipv6_geneve_rewrite(outer_bd, tunnel_src_index, tunnel_dst_index,
        smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(l2_metadata.egress_smac_idx, smac_idx);
    modify_field(l2_metadata.egress_mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_src_index, tunnel_src_index);
    modify_field(tunnel_metadata.tunnel_dst_index, tunnel_dst_index);
    modify_field(l3_metadata.egress_routed, TRUE);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV6_GENEVE);
}

action set_ipv6_nvgre_rewrite(outer_bd, tunnel_src_index, tunnel_dst_index,
        smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(l2_metadata.egress_smac_idx, smac_idx);
    modify_field(l2_metadata.egress_mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_src_index, tunnel_src_index);
    modify_field(tunnel_metadata.tunnel_dst_index, tunnel_dst_index);
    modify_field(l3_metadata.egress_routed, TRUE);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV6_NVGRE);
}

action set_ipv6_erspan_v2_rewrite(outer_bd, tunnel_src_index, tunnel_dst_index,
        smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(l2_metadata.egress_smac_idx, smac_idx);
    modify_field(l2_metadata.egress_mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_src_index, tunnel_src_index);
    modify_field(tunnel_metadata.tunnel_dst_index, tunnel_dst_index);
    modify_field(l3_metadata.egress_routed, TRUE);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV6_ERSPANV2);
}

/*
 * Table: Rewrite
 * Lookup: Egress
 * Derives rewrite information for the packet in egress
 */
table rewrite {
    reads {
        l3_metadata.nexthop_index : exact;
    }
    actions {
        nop;
        set_l2_rewrite;
        set_ipv4_unicast_rewrite;
        set_ipv6_unicast_rewrite;
        set_ipv4_vxlan_rewrite;
        set_ipv6_vxlan_rewrite;
        set_ipv4_geneve_rewrite;
        set_ipv6_geneve_rewrite;
        set_ipv4_nvgre_rewrite;
        set_ipv6_nvgre_rewrite;
        set_ipv4_erspan_v2_rewrite;
        set_ipv6_erspan_v2_rewrite;
    }
    size : NEXTHOP_TABLE_SIZE;
}

control process_rewrite {
    /* apply nexthop_index based packet rewrites */
    apply(rewrite);
}

/* CPU_REWRITE_CONTROL_BLOCK */
action set_cpu_tx_rewrite() {
    modify_field(ethernet.etherType, cpu_header.etherType);
    remove_header(cpu_header);
}

action set_cpu_rx_rewrite() {
    add_header(cpu_header);
    modify_field(cpu_header.etherType, ethernet.etherType);
    modify_field(cpu_header.ingress_lif, standard_metadata.ingress_port);
}

/*
 * Table: cpu rewrite
 * Lookup: Egress
 * Send/Receive packet from CPU
 */
table cpu_rewrite {
    reads {
        standard_metadata.egress_port : ternary;
        standard_metadata.ingress_port : ternary;
    }
    actions {
        nop;
        set_cpu_tx_rewrite;
        set_cpu_rx_rewrite;
    }
    size : CPU_REWRITE_TABLE_SIZE;
}

control process_cpu_rewrite {
    apply(cpu_rewrite);
}
