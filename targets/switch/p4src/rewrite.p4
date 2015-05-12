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

action set_l2_rewrite() {
    modify_field(egress_metadata.routed, FALSE);
    modify_field(egress_metadata.bd, ingress_metadata.egress_bd);
}

action set_ipv4_unicast_rewrite(smac_idx, dmac) {
    modify_field(egress_metadata.smac_idx, smac_idx);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(egress_metadata.routed, TRUE);
    add_to_field(ipv4.ttl, -1);
    modify_field(egress_metadata.bd, ingress_metadata.egress_bd);
}

action set_ipv6_unicast_rewrite(smac_idx, dmac) {
    modify_field(egress_metadata.smac_idx, smac_idx);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(egress_metadata.routed, TRUE);
    add_to_field(ipv6.hopLimit, -1);
    modify_field(egress_metadata.bd, ingress_metadata.egress_bd);
}

action set_ipv4_vxlan_rewrite(outer_bd, tunnel_index, smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(egress_metadata.smac_idx, smac_idx);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV4_VXLAN);
}

action set_ipv6_vxlan_rewrite(outer_bd, tunnel_index, smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(egress_metadata.smac_idx, smac_idx);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV6_VXLAN);
}

action set_ipv4_geneve_rewrite(outer_bd, tunnel_index, smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(egress_metadata.smac_idx, smac_idx);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV4_GENEVE);
}

action set_ipv6_geneve_rewrite(outer_bd, tunnel_index, smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(egress_metadata.smac_idx, smac_idx);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV6_GENEVE);
}

action set_ipv4_nvgre_rewrite(outer_bd, tunnel_index, smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(egress_metadata.smac_idx, smac_idx);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV4_NVGRE);
}

action set_ipv6_nvgre_rewrite(outer_bd, tunnel_index, smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(egress_metadata.smac_idx, smac_idx);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV6_NVGRE);
}

action set_ipv4_erspan_v2_rewrite(outer_bd, tunnel_index, smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(egress_metadata.smac_idx, smac_idx);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV4_ERSPANV2);
}

action set_ipv6_erspan_v2_rewrite(outer_bd, tunnel_index, smac_idx, dmac) {
    modify_field(egress_metadata.bd, outer_bd);
    modify_field(egress_metadata.smac_idx, smac_idx);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV6_ERSPANV2);
}

#ifndef NAT_DISABLE
action set_nat_src_rewrite(src_ip) {
    modify_field(ipv4.srcAddr, src_ip);
}

action set_nat_dst_rewrite(dst_ip) {
    modify_field(ipv4.dstAddr, dst_ip);
}

action set_nat_src_dst_rewrite(src_ip, dst_ip) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(ipv4.dstAddr, dst_ip);
}

action set_nat_src_udp_rewrite(src_ip, src_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(udp.srcPort, src_port);
}

action set_nat_dst_udp_rewrite(dst_ip, dst_port) {
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(udp.dstPort, dst_port);
}

action set_nat_src_dst_udp_rewrite(src_ip, dst_ip, src_port, dst_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(udp.srcPort, src_port);
    modify_field(udp.dstPort, dst_port);
}

action set_nat_src_tcp_rewrite(src_ip, src_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(tcp.srcPort, src_port);
}

action set_nat_dst_tcp_rewrite(dst_ip, dst_port) {
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(tcp.dstPort, dst_port);
}

action set_nat_src_dst_tcp_rewrite(src_ip, dst_ip, src_port, dst_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(tcp.srcPort, src_port);
    modify_field(tcp.dstPort, dst_port);
}
#endif /* NAT_DISABLE */

table rewrite {
    reads {
        l3_metadata.nexthop_index : exact;
    }
    actions {
        nop;
        set_l2_rewrite;
        set_ipv4_unicast_rewrite;
#ifndef IPV6_DISABLE
        set_ipv6_unicast_rewrite;
#endif /* IPV6_DISABLE */
#ifndef MPLS_DISABLE
        set_mpls_swap_rewrite_l2;
        set_mpls_swap_push_rewrite_l2;
        set_mpls_push_rewrite_l2;
        set_mpls_swap_rewrite_l3;
        set_mpls_swap_push_rewrite_l3;
        set_mpls_push_rewrite_l3;
#endif /* MPLS_DISABLE */
#ifndef TUNNEL_DISABLE
        set_ipv4_vxlan_rewrite;
        set_ipv6_vxlan_rewrite;
        set_ipv4_geneve_rewrite;
        set_ipv6_geneve_rewrite;
        set_ipv4_nvgre_rewrite;
        set_ipv6_nvgre_rewrite;
        set_ipv4_erspan_v2_rewrite;
        set_ipv6_erspan_v2_rewrite;
#endif /* TUNNEL_DISABLE */
#ifndef NAT_DISABLE
        set_nat_src_rewrite;
        set_nat_dst_rewrite;
        set_nat_src_dst_rewrite;
        set_nat_src_udp_rewrite;
        set_nat_dst_udp_rewrite;
        set_nat_src_dst_udp_rewrite;
        set_nat_src_tcp_rewrite;
        set_nat_dst_tcp_rewrite;
        set_nat_src_dst_tcp_rewrite;
#endif /* NAT_DISABLE */
    }
    size : NEXTHOP_TABLE_SIZE;
}

control process_rewrite {
    apply(rewrite);
}
