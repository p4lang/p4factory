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

header_type tunnel_metadata_t {
    fields {
        /* Ingress Metadata */
        ingress_tunnel_type : 4;               /* tunnel type from parser */
        tunnel_terminate : 1;                  /* should tunnel be terminated */
        tunnel_vni : 24;                       /* tunnel id */
        tunnel_lif : 16;                       /* tunnel ingress logical interface */
        src_vtep_miss : 1;                     /* src vtep lookup failed */

        outer_bd : 8;                          /* outer BD */
        outer_rmac_group : 10;                 /* Rmac group, for rmac indirection */
        outer_rmac_hit : 1;                    /* dst mac is the router's mac */

        /* Egress Metadata */
        vnid : 24;                             /* tunnel vnid */
        egress_tunnel_type : 4;                /* type of tunnel */
        tunnel_src_index : 9;                  /* index to tunnel src ip */
        tunnel_dst_index : 14;                 /* index to tunnel dst ip */
    }
}

metadata tunnel_metadata_t tunnel_metadata;

action set_outer_rmac_hit_flag() {
    modify_field(tunnel_metadata.outer_rmac_hit, TRUE);
}

table outer_rmac {
    reads {
        tunnel_metadata.outer_rmac_group : exact;
        l2_metadata.lkp_mac_da : exact;
    }
    actions {
        nop;
        set_outer_rmac_hit_flag;
    }
    size : OUTER_ROUTER_MAC_TABLE_SIZE;
}

action set_src_vtep_miss_flag() {
    modify_field(tunnel_metadata.src_vtep_miss, TRUE);
}

action set_tunnel_lif(lif) {
    modify_field(tunnel_metadata.tunnel_lif, lif);
}

table ipv4_src_vtep {
    reads {
        l3_metadata.vrf : exact;
        l3_metadata.lkp_ipv4_sa : exact;
    }
    actions {
        nop;
        set_tunnel_lif;
        set_src_vtep_miss_flag;
    }
    size : SRC_TUNNEL_TABLE_SIZE;
}

action set_tunnel_termination_flag() {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
}

table ipv4_dest_vtep {
    reads {
        l3_metadata.vrf : exact;
        l3_metadata.lkp_ipv4_da : exact;
        l3_metadata.lkp_ip_proto : exact;
        l3_metadata.lkp_l4_dport : exact;
    }
    actions {
        nop;
        set_tunnel_termination_flag;
    }
    size : DEST_TUNNEL_TABLE_SIZE;
}

action terminate_tunnel_inner_ipv4(bd, vrf,
        rmac_group, bd_label,
        uuc_mc_index, bcast_mc_index, umc_mc_index,
        ipv4_unicast_enabled, igmp_snooping_enabled)
        {
    modify_field(l2_metadata.bd, bd);
    modify_field(l3_metadata.vrf, vrf);
    modify_field(l3_metadata.outer_dscp, l3_metadata.lkp_ip_tc);
    // This implements tunnel in 'uniform' mode i.e. the TTL from the outer IP
    // header is copied into the header of decapsulated packet.
    // For decapsulation, the TTL in the outer IP header is copied to
    // l3_metadata.lkp_ip_ttl in validate_outer_ipv4_packet action
    modify_field(l3_metadata.outer_ttl, l3_metadata.lkp_ip_ttl);
    add_to_field(l3_metadata.outer_ttl, -1);

    modify_field(l2_metadata.lkp_mac_sa, inner_ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, inner_ethernet.dstAddr);
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
    modify_field(l3_metadata.lkp_ipv4_sa, inner_ipv4.srcAddr);
    modify_field(l3_metadata.lkp_ipv4_da, inner_ipv4.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto, inner_ipv4.protocol);
    modify_field(l3_metadata.lkp_ip_tc, inner_ipv4.diffserv);
    modify_field(l3_metadata.lkp_l4_sport, l3_metadata.lkp_inner_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport, l3_metadata.lkp_inner_l4_dport);

    modify_field(l3_metadata.ipv4_unicast_enabled, ipv4_unicast_enabled);
    modify_field(mcast_metadata.igmp_snooping_enabled, igmp_snooping_enabled);
    modify_field(l3_metadata.rmac_group, rmac_group);
    modify_field(mcast_metadata.uuc_mc_index, uuc_mc_index);
    modify_field(mcast_metadata.umc_mc_index, umc_mc_index);
    modify_field(mcast_metadata.bcast_mc_index, bcast_mc_index);
    modify_field(l2_metadata.bd_label, bd_label);
    modify_field(l3_metadata.l3_length, inner_ipv4.totalLen);
}

table tunnel {
    reads {
        tunnel_metadata.tunnel_vni : exact;
        tunnel_metadata.ingress_tunnel_type : exact;
        inner_ipv4 : valid;
    }
    actions {
        terminate_tunnel_inner_ipv4;
    }
    size : VNID_MAPPING_TABLE_SIZE;
}

control tunnel_vtep_lookup {
#ifndef TUNNEL_DISABLE
    /* outer RMAC lookup for tunnel termination */
    apply(outer_rmac);

    /* src vtep table lookup */
    if (valid(ipv4)) {
        apply(ipv4_src_vtep);
    }

    if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
        /* check for ipv4 unicast tunnel termination  */
        if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and
            (l3_metadata.ipv4_unicast_enabled == TRUE)) {
            apply(ipv4_dest_vtep);
        }
    }
#endif /* TUNNEL_DISABLE */
}

control tunnel_terminate_lookup {
    apply(tunnel);
}

action decapsulate_vxlan_packet_inner_ipv4_udp() {
    copy_header(ethernet, inner_ethernet);
    add_header(ipv4);
    copy_header(ipv4, inner_ipv4);
    copy_header(udp, inner_udp);
    remove_header(inner_ethernet);
    remove_header(inner_ipv4);
    remove_header(inner_udp);
    remove_header(vxlan);
    modify_field(l3_metadata.ttl, l3_metadata.outer_ttl);
}

action decapsulate_vxlan_packet_inner_ipv4_tcp() {
    copy_header(ethernet, inner_ethernet);
    add_header(ipv4);
    copy_header(ipv4, inner_ipv4);
    add_header(tcp);
    copy_header(tcp, inner_tcp);
    remove_header(inner_ethernet);
    remove_header(inner_ipv4);
    remove_header(inner_tcp);
    remove_header(udp);
    remove_header(vxlan);
    modify_field(l3_metadata.ttl, l3_metadata.outer_ttl);
}

action decapsulate_geneve_packet_inner_ipv4_udp() {
    copy_header(ethernet, inner_ethernet);
    add_header(ipv4);
    copy_header(ipv4, inner_ipv4);
    copy_header(udp, inner_udp);
    remove_header(inner_ethernet);
    remove_header(inner_ipv4);
    remove_header(inner_udp);
    remove_header(genv);
    modify_field(l3_metadata.ttl, l3_metadata.outer_ttl);
}

action decapsulate_geneve_packet_inner_ipv4_tcp() {
    copy_header(ethernet, inner_ethernet);
    add_header(ipv4);
    copy_header(ipv4, inner_ipv4);
    add_header(tcp);
    copy_header(tcp, inner_tcp);
    remove_header(inner_ethernet);
    remove_header(inner_ipv4);
    remove_header(inner_tcp);
    remove_header(udp);
    remove_header(genv);
    modify_field(l3_metadata.ttl, l3_metadata.outer_ttl);
}

action decapsulate_nvgre_packet_inner_ipv4_udp() {
    copy_header(ethernet, inner_ethernet);
    add_header(ipv4);
    copy_header(ipv4, inner_ipv4);
    copy_header(udp, inner_udp);
    remove_header(inner_ethernet);
    remove_header(inner_ipv4);
    remove_header(inner_udp);
    remove_header(nvgre);
    remove_header(gre);
    modify_field(l3_metadata.ttl, l3_metadata.outer_ttl);
}

action decapsulate_nvgre_packet_inner_ipv4_tcp() {
    copy_header(ethernet, inner_ethernet);
    add_header(ipv4);
    copy_header(ipv4, inner_ipv4);
    add_header(tcp);
    copy_header(tcp, inner_tcp);
    remove_header(inner_ethernet);
    remove_header(inner_ipv4);
    remove_header(inner_tcp);
    remove_header(nvgre);
    remove_header(gre);
    modify_field(l3_metadata.ttl, l3_metadata.outer_ttl);
}

table tunnel_decap {
    reads {
        tunnel_metadata.ingress_tunnel_type : exact;
        inner_ipv4 : valid;
        inner_tcp : valid;
        inner_udp : valid;
    }
    actions {
        decapsulate_vxlan_packet_inner_ipv4_udp;
        decapsulate_vxlan_packet_inner_ipv4_tcp;
        decapsulate_geneve_packet_inner_ipv4_udp;
        decapsulate_geneve_packet_inner_ipv4_tcp;
        decapsulate_nvgre_packet_inner_ipv4_udp;
        decapsulate_nvgre_packet_inner_ipv4_tcp;
    }
    size : TUNNEL_DECAP_TABLE_SIZE;
}

action set_egress_bd_properties(vnid ) {
    modify_field(tunnel_metadata.vnid, vnid);
}

table egress_bd_map {
    reads {
        l2_metadata.egress_bd : exact;
    }
    actions {
        nop;
        set_egress_bd_properties;
    }
    size : EGRESS_VNID_MAPPING_TABLE_SIZE;
}

control tunnel_decap_lookup {
#ifndef TUNNEL_DISABLE
    /* perform tunnel decap */
    if (tunnel_metadata.tunnel_terminate == TRUE) {
        if (mcast_metadata.replica == FALSE) {
            apply(tunnel_decap);
        }
    }

    /* egress bd to vnid mapping */
    apply(egress_bd_map);
#endif /* TUNNEL_DISABLE */
}

action f_copy_ipv4_to_inner() {
    add_header(inner_ethernet);
    copy_header(inner_ethernet, ethernet);
    add_header(inner_ipv4);
    copy_header(inner_ipv4, ipv4);
    modify_field(inner_ipv4.ttl, l3_metadata.ttl);
    remove_header(ipv4);
}

action f_copy_ipv4_udp_to_inner() {
    f_copy_ipv4_to_inner();
    add_header(inner_udp);
    copy_header(inner_udp, udp);
    remove_header(udp);
}

action f_copy_ipv4_tcp_to_inner() {
    f_copy_ipv4_to_inner();
    add_header(inner_tcp);
    copy_header(inner_tcp, tcp);
    remove_header(tcp);
}

field_list entropy_hash_fields {
    inner_ethernet.srcAddr;
    inner_ethernet.dstAddr;
    inner_ethernet.etherType;
    inner_ipv4.srcAddr;
    inner_ipv4.dstAddr;
    inner_ipv4.protocol;
}

field_list_calculation entropy_hash {
    input {
        entropy_hash_fields;
    }
    algorithm : crc16;
    output_width : 16;
}

action f_insert_vxlan_header() {
    add_header(udp);
    add_header(vxlan);

    modify_field_with_hash_based_offset(udp.srcPort, 0, entropy_hash, 16384);
    modify_field(udp.dstPort, UDP_PORT_VXLAN);
    modify_field(udp.checksum, 0);
    modify_field(udp.length_, l3_metadata.l3_length);
    add_to_field(udp.length_, 30); // 8+8+14

    modify_field(vxlan.flags, 0x8);
    modify_field(vxlan.vni, tunnel_metadata.vnid);
}

action f_insert_ipv4_header(proto) {
    add_header(ipv4);
    modify_field(ipv4.protocol, proto);
    modify_field(ipv4.ttl, l3_metadata.ttl);
    modify_field(ipv4.version, 0x4);
    modify_field(ipv4.ihl, 0x5);
}

action ipv4_vxlan_inner_ipv4_udp_rewrite() {
    f_copy_ipv4_udp_to_inner();
    f_insert_vxlan_header();
    f_insert_ipv4_header(IP_PROTOCOLS_UDP);
    modify_field(ipv4.totalLen, l3_metadata.l3_length);
    add_to_field(ipv4.totalLen, 50);
}

action ipv4_vxlan_inner_ipv4_tcp_rewrite() {
    f_copy_ipv4_tcp_to_inner();
    f_insert_vxlan_header();
    f_insert_ipv4_header(IP_PROTOCOLS_UDP);
    modify_field(ipv4.totalLen, l3_metadata.l3_length);
    add_to_field(ipv4.totalLen, 50);
}

action f_insert_genv_header() {
    add_header(udp);
    add_header(genv);

    modify_field_with_hash_based_offset(udp.srcPort, 0, entropy_hash, 16384);
    modify_field(udp.dstPort, UDP_PORT_GENV);
    modify_field(udp.checksum, 0);
    modify_field(udp.length_, l3_metadata.l3_length);
    add_to_field(udp.length_, 30); // 8+8+14

    modify_field(genv.ver, 0);
    modify_field(genv.oam, 0);
    modify_field(genv.critical, 0);
    modify_field(genv.optLen, 0);
    modify_field(genv.protoType, 0x6558);
    modify_field(genv.vni, tunnel_metadata.vnid);
}

action ipv4_genv_inner_ipv4_udp_rewrite() {
    f_copy_ipv4_udp_to_inner();
    f_insert_genv_header();
    f_insert_ipv4_header(IP_PROTOCOLS_UDP);
    modify_field(ipv4.totalLen, l3_metadata.l3_length);
    add_to_field(ipv4.totalLen, 50);
}

action ipv4_genv_inner_ipv4_tcp_rewrite() {
    f_copy_ipv4_tcp_to_inner();
    f_insert_genv_header();
    f_insert_ipv4_header(IP_PROTOCOLS_UDP);
    modify_field(ipv4.totalLen, l3_metadata.l3_length);
    add_to_field(ipv4.totalLen, 50);
}

action f_insert_nvgre_header() {
    add_header(gre);
    add_header(nvgre);
    modify_field(gre.proto, 0x6558);
    modify_field(gre.K, 1);
    modify_field(gre.C, 0);
    modify_field(gre.S, 0);
    modify_field(nvgre.tni, tunnel_metadata.vnid);
}

action ipv4_nvgre_inner_ipv4_udp_rewrite() {
    f_copy_ipv4_udp_to_inner();
    f_insert_nvgre_header();
    f_insert_ipv4_header(IP_PROTOCOLS_GRE);
    modify_field(ipv4.totalLen, l3_metadata.l3_length);
    add_to_field(ipv4.totalLen, 42);
}

action ipv4_nvgre_inner_ipv4_tcp_rewrite() {
    f_copy_ipv4_tcp_to_inner();
    f_insert_nvgre_header();
    f_insert_ipv4_header(IP_PROTOCOLS_GRE);
    modify_field(ipv4.totalLen, l3_metadata.l3_length);
    add_to_field(ipv4.totalLen, 42);
}

action f_insert_erspan_v2_header() {
    add_header(gre);
    add_header(erspan_v2_header);
    modify_field(gre.proto, GRE_PROTOCOLS_ERSPAN_V2);
    modify_field(erspan_v2_header.version, 1);
    modify_field(erspan_v2_header.vlan, tunnel_metadata.vnid);
}

action ipv4_erspan_v2_inner_ipv4_udp_rewrite() {
    f_copy_ipv4_udp_to_inner();
    f_insert_erspan_v2_header();
    f_insert_ipv4_header(IP_PROTOCOLS_GRE);
    modify_field(ipv4.totalLen, l3_metadata.l3_length);
    add_to_field(ipv4.totalLen, 46);
}

action ipv4_erspan_v2_inner_ipv4_tcp_rewrite() {
    f_copy_ipv4_tcp_to_inner();
    f_insert_erspan_v2_header();
    f_insert_ipv4_header(IP_PROTOCOLS_GRE);
    modify_field(ipv4.totalLen, l3_metadata.l3_length);
    add_to_field(ipv4.totalLen, 46);
}


table tunnel_rewrite {
    reads {
        tunnel_metadata.egress_tunnel_type : exact;
        ipv4 : valid;
        tcp : valid;
        udp : valid;
    }
    actions {
/*
 * These actions encapsulate a packet.
 * Sequence of modifications in each action is:
 * 1. Add inner L3/L4 header. The type of these headers should be same as that
 *    of the packet being encapsulated.
 * 2. Copy outer L3/L4 headers to inner L3/L4 headers.
 * 3. Remove outer L3/L4 headers.
 * 4. Add outer L3 header and encapsulation header.
 * For each encapsulation type, we need 8 actions to handle 8 different
 * combinations:
 * Outer L3 (IPv4) X Inner L3 (IPv4) X Inner L4 (TCP/UDP)
 */
        ipv4_vxlan_inner_ipv4_udp_rewrite;
        ipv4_vxlan_inner_ipv4_tcp_rewrite;
        ipv4_genv_inner_ipv4_udp_rewrite;
        ipv4_genv_inner_ipv4_tcp_rewrite;
        ipv4_nvgre_inner_ipv4_udp_rewrite;
        ipv4_nvgre_inner_ipv4_tcp_rewrite;
        ipv4_erspan_v2_inner_ipv4_udp_rewrite;
        ipv4_erspan_v2_inner_ipv4_tcp_rewrite;
    }
    size : TUNNEL_REWRITE_TABLE_SIZE;
}

action rewrite_tunnel_ipv4_src(ip) {
    modify_field(ipv4.srcAddr, ip);
}

table tunnel_src_rewrite {
    reads {
        tunnel_metadata.tunnel_src_index : exact;
    }
    actions {
        rewrite_tunnel_ipv4_src;
    }
    size : DEST_TUNNEL_TABLE_SIZE;
}

action rewrite_tunnel_ipv4_dst(ip) {
    modify_field(ipv4.dstAddr, ip);
}

table tunnel_dst_rewrite {
    reads {
        tunnel_metadata.tunnel_dst_index : exact;
    }
    actions {
        rewrite_tunnel_ipv4_dst;
    }
    size : SRC_TUNNEL_TABLE_SIZE;
}

control tunnel_rewrite_lookup {
#ifndef TUNNEL_DISABLE
    if (tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_NONE) {
        /* tunnel rewrites */
        apply(tunnel_rewrite);

        /* rewrite tunnel src and dst ip */
        apply(tunnel_src_rewrite);
        apply(tunnel_dst_rewrite);
    }
#endif /* TUNNEL_DISABLE */
}
