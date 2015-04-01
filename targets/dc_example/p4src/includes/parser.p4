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

parser start {
    set_metadata(ingress_metadata.drop_0, 0);
    return parse_ethernet;
}

#define ETHERTYPE_CPU 0x9000, 0x010c
#define ETHERTYPE_VLAN 0x8100, 0x9100, 0x9200, 0x9300
#define ETHERTYPE_MPLS 0x8847
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_RARP 0x8035
#define ETHERTYPE_NSH 0x894f
#define ETHERTYPE_ETHERNET 0x6558
#define ETHERTYPE_ROCE 0x8915
#define ETHERTYPE_FCOE 0x8906
/* missing: vlan_3b, vlan_5b, ieee802_1q, ieee802_1ad */

#define IPV4_MULTICAST_MAC 0x01005E
#define IPV6_MULTICAST_MAC 0x3333

/* Tunnel types */
#define TUNNEL_TYPE_NONE               0
#define TUNNEL_TYPE_VXLAN              1
#define TUNNEL_TYPE_GRE                2
#define TUNNEL_TYPE_GENEVE             3 
#define TUNNEL_TYPE_NVGRE              4
#define TUNNEL_TYPE_MPLS               5

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0 mask 0xf800: parse_snap_header; /* < 1536 */
        ETHERTYPE_CPU : parse_cpu_header;
        ETHERTYPE_VLAN : parse_vlan;
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_IPV6 : parse_ipv6;
        ETHERTYPE_ARP : parse_arp_rarp;
        ETHERTYPE_RARP : parse_arp_rarp;
        ETHERTYPE_NSH : parse_nsh;
        ETHERTYPE_ROCE: parse_roce;
        ETHERTYPE_FCOE: parse_fcoe;
        default: ingress;
    }
}

header snap_header_t snap_header;

parser parse_snap_header {
    extract(snap_header);
    return ingress;
}

header roce_header_t roce;

parser parse_roce {
    extract(roce);
    return ingress;
}

header fcoe_header_t fcoe;

parser parse_fcoe {
    extract(fcoe);
    return ingress;
}

header cpu_header_t cpu_header;

parser parse_cpu_header {
    extract(cpu_header);
    set_metadata(ingress_metadata.ingress_bypass, 1);
    set_metadata(standard_metadata.egress_spec, latest.egress_lif);
    return select(latest.etherType) {
        0 mask 0xf800: parse_snap_header; /* < 1536 */
        ETHERTYPE_VLAN : parse_vlan;
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_IPV6 : parse_ipv6;
        ETHERTYPE_ARP : parse_arp_rarp;
        ETHERTYPE_RARP : parse_arp_rarp;
        ETHERTYPE_NSH : parse_nsh;
        ETHERTYPE_ROCE: parse_roce;
        ETHERTYPE_FCOE: parse_fcoe;
        default: ingress;
    }
}

#define VLAN_DEPTH 2
header vlan_tag_t vlan_tag_[VLAN_DEPTH];
header vlan_tag_3b_t vlan_tag_3b[VLAN_DEPTH];
header vlan_tag_5b_t vlan_tag_5b[VLAN_DEPTH];

parser parse_vlan {
    extract(vlan_tag_[next]);
    return select(latest.etherType) {
        ETHERTYPE_VLAN : parse_vlan;
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_IPV6 : parse_ipv6;
        ETHERTYPE_ARP : parse_arp_rarp;
        ETHERTYPE_RARP : parse_arp_rarp;
        default: ingress;
    }
}

#define IP_PROTOCOLS_ICMP 1
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define IP_PROTOCOLS_GRE 47
#define IP_PROTOCOLS_IPSEC_ESP 50
#define IP_PROTOCOLS_IPSEC_AH 51
#define IP_PROTOCOLS_ICMPV6 58
#define IP_PROTOCOLS_SCTP 132

header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

parser parse_ipv4 {
    extract(ipv4);
    set_metadata(l3_metadata.ipv4_dstaddr_24b, latest.dstAddr);
    return select(latest.fragOffset, latest.protocol) {
        IP_PROTOCOLS_ICMP : parse_icmp;
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
        IP_PROTOCOLS_GRE : parse_gre;
//        IP_PROTOCOLS_SCTP : parse_sctp;
        default: ingress;
    }
}

header ipv6_t ipv6;

parser parse_ipv6 {
    extract(ipv6);
    return select(latest.nextHdr) {
        IP_PROTOCOLS_ICMPV6 : parse_icmpv6;
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
        IP_PROTOCOLS_GRE : parse_gre;
//        IP_PROTOCOLS_SCTP : parse_sctp;
        default: ingress;
    }
}

header icmp_t icmp;

parser parse_icmp {
    extract(icmp);
    set_metadata(ingress_metadata.msg_type, icmp.code);
    return ingress;
}

header icmpv6_t icmpv6;

parser parse_icmpv6 {
    extract(icmpv6);
    set_metadata(ingress_metadata.msg_type, icmpv6.code);
    return ingress;
}

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    set_metadata(l3_metadata.lkp_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_l4_dport, latest.dstPort);
    return ingress;
}

#define UDP_PORT_VXLAN 4789
#define UDP_PORT_GENV 6081
// Check IANA UDP port number
 #define UDP_PORT_ROCE_V2 1021

header udp_t udp;

header roce_v2_header_t roce_v2;

parser parse_roce_v2 {
    extract(roce_v2);
    return ingress;
}

parser parse_udp {
    extract(udp);
    set_metadata(l3_metadata.lkp_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_l4_dport, latest.dstPort);
    return select(latest.dstPort) {
        UDP_PORT_VXLAN : parse_vxlan;
        UDP_PORT_GENV: parse_geneve;
        UDP_PORT_ROCE_V2: parse_roce_v2;
        default: ingress;
    }
}

header sctp_t sctp;

parser parse_sctp {
    extract(sctp);
    return ingress;
}


#define GRE_PROTOCOLS_NVGRE 0x6558
#define GRE_PROTOCOLS_GRE 0x6559
#define GRE_PROTOCOLS_ERSPAN_V1 0x88BE
#define GRE_PROTOCOLS_ERSPAN_V2 0x22EB

#define GRE_DEPTH 2

//header gre_t gre[GRE_DEPTH];
header gre_t gre;

#if 0
header_type gre_opt_t {
    fields {
        key : 32;
    }
}

header gre_opt_t gre_opt;

parser parse_gre_key {
    extract(gre_opt);
    set_metadata(tunnel_metadata.tunnel_vni, gre_opt.key);
    return ingress;
}
parser parse_gre_key2 {
    extract(gre_opt);
    set_metadata(tunnel_metadata.tunnel_vni, gre_opt.key);
    extract(gre_opt);
    return ingress;
}
parser parse_gre_key22 {
    extract(gre_opt);
    extract(gre_opt);
    set_metadata(tunnel_metadata.tunnel_vni, gre_opt.key);
    return ingress;
}
parser parse_gre_opt1 {
    extract(gre_opt);
    return ingress;
}
parser parse_gre_opt2 {
    extract(gre_opt);
    extract(gre_opt);
    return ingress;
}
parser parse_gre_opt3 {
    extract(gre_opt);
    extract(gre_opt);
    set_metadata(tunnel_metadata.tunnel_vni, gre_opt.key);
    extract(gre_opt);
    return ingress;
}

parser parse_gre_opts {
    return select(latest.C, latest.S, latest.K) {
        1 mask 0x0000 :  parse_gre_key;
        2 mask 0x0000 :  parse_gre_opt1;
        3 mask 0x0000 :  parse_gre_key2;
        4 mask 0x0000 :  parse_gre_opt1;
        5 mask 0x0000 :  parse_gre_key22;
        6 mask 0x0000 :  parse_gre_opt2;
        7 mask 0x0000 :  parse_gre_opt3;
        default: ingress;
    }
}
#endif

parser parse_gre {
    extract(gre);
    set_metadata(tunnel_metadata.ingress_tunnel_type, TUNNEL_TYPE_GRE);
//    parse_gre_opts;
    return select(latest.K, latest.proto) {
        GRE_PROTOCOLS_NVGRE : parse_nvgre;
//        GRE_PROTOCOLS_GRE : parse_gre;
        GRE_PROTOCOLS_ERSPAN_V1 : parse_erspan_v1;
        GRE_PROTOCOLS_ERSPAN_V2 : parse_erspan_v2;
        ETHERTYPE_NSH : parse_nsh;
        default: ingress;
    }
}

header nvgre_t nvgre;
header ethernet_t inner_ethernet;

header ipv4_t inner_ipv4;
header ipv6_t inner_ipv6;
header ipv4_t outer_ipv4;
header ipv6_t outer_ipv6;

field_list inner_ipv4_checksum_list {
        inner_ipv4.version;
        inner_ipv4.ihl;
        inner_ipv4.diffserv;
        inner_ipv4.totalLen;
        inner_ipv4.identification;
        inner_ipv4.flags;
        inner_ipv4.fragOffset;
        inner_ipv4.ttl;
        inner_ipv4.protocol;
        inner_ipv4.srcAddr;
        inner_ipv4.dstAddr;
}

field_list_calculation inner_ipv4_checksum {
    input {
        inner_ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field inner_ipv4.hdrChecksum {
    verify inner_ipv4_checksum if(valid(ipv4));
    update inner_ipv4_checksum if(valid(ipv4));
}

header udp_t outer_udp;

parser parse_nvgre {
    extract(nvgre);
    set_metadata(tunnel_metadata.ingress_tunnel_type, TUNNEL_TYPE_NVGRE);
    set_metadata(tunnel_metadata.tunnel_vni, latest.tni);
    return parse_inner_ethernet;
}

header erspan_header_v1_t erspan_v1_header;

parser parse_erspan_v1 {
    extract(erspan_v1_header);
    return ingress;
}

header erspan_header_v2_t erspan_v2_header;

parser parse_erspan_v2 {
    extract(erspan_v2_header);
    return ingress;
}

#define ARP_PROTOTYPES_ARP_RARP_IPV4 0x0800

header arp_rarp_t arp_rarp;

parser parse_arp_rarp {
    extract(arp_rarp);
    return select(latest.protoType) {
        ARP_PROTOTYPES_ARP_RARP_IPV4 : parse_arp_rarp_ipv4;
        default: ingress;
    }
}

header arp_rarp_ipv4_t arp_rarp_ipv4;

parser parse_arp_rarp_ipv4 {
    extract(arp_rarp_ipv4);
    return ingress;
}

header vxlan_t vxlan;

parser parse_vxlan {
    extract(vxlan);
    set_metadata(tunnel_metadata.ingress_tunnel_type, TUNNEL_TYPE_VXLAN);
    set_metadata(tunnel_metadata.tunnel_vni, latest.vni);
    return parse_inner_ethernet;
}

header genv_t genv;

header genv_opt_A_t genv_opt_A;
header genv_opt_B_t genv_opt_B;
header genv_opt_C_t genv_opt_C;

parser parse_geneve {
    extract(genv);
    set_metadata(tunnel_metadata.tunnel_vni, latest.vni);
    set_metadata(tunnel_metadata.ingress_tunnel_type, TUNNEL_TYPE_GENEVE);
    /*
    counter_init(counter_1, latest.optLen);
    return select(latest.optLen) {
        0 : parse_genv_inner;
        default : parse_genv_opts;
    }
    */
    return parse_genv_inner;
}

#if 0

parser parse_genv_opts {
    /* switching on combined class and type */
    return select(current(0, 24)) {
        GENV_OPTION_A_TYPE: parse_genv_opt_A;
        GENV_OPTION_B_TYPE: parse_genv_opt_B;
        GENV_OPTION_C_TYPE: parse_genv_opt_C;
    }
}

parser parse_genv_opt_A {
    extract(genv_opt_A);
    counter_decrement(counter_1, GENV_OPTION_A_LENGTH);
    return select(counter_1) {
        0 : parse_genv_inner;
        default : parse_genv_opts;
    }
}

parser parse_genv_opt_B {
    extract(genv_opt_B);
    counter_decrement(counter_1, GENV_OPTION_B_LENGTH);
    return select(counter_1) {
        0 : parse_genv_inner;
        default : parse_genv_opts;
    }
}

parser parse_genv_opt_C {
    extract(genv_opt_C);
    counter_decrement(counter_1, GENV_OPTION_C_LENGTH);
    return select(counter_1) {
        0 : parse_genv_inner;
        default : parse_genv_opts;
    }
}
#endif

parser parse_genv_inner {
    return select(genv.protoType) {
        ETHERTYPE_ETHERNET : parse_inner_ethernet;
        ETHERTYPE_IPV4 : parse_inner_ipv4;
        ETHERTYPE_IPV6 : parse_inner_ipv6;
        default : ingress;
    }
}

header nsh_t nsh;
header nsh_context_t nsh_context;

parser parse_nsh {
    extract(nsh);
    extract(nsh_context);
    return select(nsh.protoType) {
        ETHERTYPE_IPV4 : parse_inner_ipv4;
        ETHERTYPE_IPV6 : parse_inner_ipv6;
        ETHERTYPE_ETHERNET : parse_inner_ethernet;
        default: ingress;
    }
}

parser parse_inner_ipv4 {
    extract(inner_ipv4);
    return select(latest.fragOffset, latest.protocol) {
        IP_PROTOCOLS_ICMP : parse_inner_icmp;
        IP_PROTOCOLS_TCP : parse_inner_tcp;
        IP_PROTOCOLS_UDP : parse_inner_udp;
//        IP_PROTOCOLS_SCTP : parse_inner_sctp;
        default: ingress;
    }
}

header icmp_t inner_icmp;

parser parse_inner_icmp {
    extract(inner_icmp);
    return ingress;
}

header tcp_t inner_tcp;

parser parse_inner_tcp {
    extract(inner_tcp);
    set_metadata(l3_metadata.lkp_inner_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_inner_l4_dport, latest.dstPort);
    return ingress;
}

header udp_t inner_udp;

parser parse_inner_udp {
    extract(inner_udp);
    set_metadata(l3_metadata.lkp_inner_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_inner_l4_dport, latest.dstPort);
    return ingress;    
}

header sctp_t inner_sctp;

parser parse_inner_sctp {
    extract(inner_sctp);
    return ingress;
}

parser parse_inner_ipv6 {
    extract(inner_ipv6);
    return select(latest.nextHdr) {
        IP_PROTOCOLS_ICMPV6 : parse_inner_icmpv6;
        IP_PROTOCOLS_TCP : parse_inner_tcp;
        IP_PROTOCOLS_UDP : parse_inner_udp;
//        IP_PROTOCOLS_SCTP : parse_inner_sctp;
        default: ingress;
    }
}

header icmpv6_t inner_icmpv6;

parser parse_inner_icmpv6 {
    extract(inner_icmpv6);
    return ingress;
}

parser parse_inner_ethernet {
    extract(inner_ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_inner_ipv4;
        ETHERTYPE_IPV6 : parse_inner_ipv6;
        default: ingress;
    }
}

