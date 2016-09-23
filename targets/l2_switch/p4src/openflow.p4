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
 * Openflow Processing
 */

// Openflow features
//#define OPENFLOW_ENABLE_MPLS
//#define OPENFLOW_ENABLE_VLAN
//#define OPENFLOW_ENABLE_L3

// adds some handy stuff from switch.p4 for packet in/out 
#define OPENFLOW_PACKET_IN_OUT 

#define ingress_input_port standard_metadata.ingress_port
#define ingress_egress_port standard_metadata.egress_spec
#define egress_egress_port standard_metadata.egress_port
#define intrinsic_mcast_grp intrinsic_metadata.mcast_grp

header_type openflow_metadata_t {
    fields {
        index : 32;
        bmap : 32;
        group_id : 32;
        ofvalid : 1;
    }
}

metadata openflow_metadata_t openflow_metadata;

#ifndef CPU_PORT_ID
    #define CPU_PORT_ID 64
#endif

#define TRUE 1

#ifdef OPENFLOW_PACKET_IN_OUT
#define ETHERTYPE_BF_FABRIC 0x9000

#define FABRIC_HEADER_TYPE_MULTICAST   2
#define FABRIC_HEADER_TYPE_CPU         5

header_type fabric_header_t {
    fields {
        packetType : 3;
        headerVersion : 2;
        packetVersion : 2;
        pad1 : 1;

        fabricColor : 3;
        fabricQos : 5;

        dstDevice : 8;
        dstPortOrGroup : 16;
    }
}

header_type fabric_header_multicast_t {
    fields {
        routed : 1;
        outerRouted : 1;
        tunnelTerminate : 1;
        ingressTunnelType : 5;

        ingressIfindex : 16;
        ingressBd : 16;

        mcastGrp : 16;
    }
}

header_type fabric_header_cpu_t {
    fields {
        egressQueue : 5;
        txBypass : 1;
        reserved : 2;

        ingressPort: 16;
        ingressIfindex : 16;
        ingressBd : 16;

        reasonCode : 16;
        mcast_grp : 16;
    }
}

header_type fabric_payload_header_t {
    fields {
        etherType : 16;
    }
}

header fabric_header_t fabric_header;
header fabric_header_cpu_t fabric_header_cpu;
header fabric_header_multicast_t fabric_header_multicast;
header fabric_payload_header_t fabric_payload_header;


parser parse_fabric_header {
    extract(fabric_header);
    return select(latest.packetType) {
        FABRIC_HEADER_TYPE_MULTICAST : parse_fabric_header_multicast;
        FABRIC_HEADER_TYPE_CPU : parse_fabric_header_cpu;
        default : ingress;
    }
}

parser parse_fabric_header_multicast {
    extract(fabric_header_multicast);
    return parse_fabric_payload_header;
}

parser parse_fabric_header_cpu {
    extract(fabric_header_cpu);
    return parse_fabric_payload_header;
}

parser parse_fabric_payload_header {
    extract(fabric_payload_header);
    return select(latest.etherType) {
        // add more ethertypes here if you want
        default: ingress;
    }
}

action nop () {
}

// remove the comments in "terminate_cpu_packet" and "terminate_fabric_multicast_packet"
// as necessary. I'm just assuming these features aren't used (Except copying the
// ethertype from the fabric payload header, that's necessary but I don't want to
// assume you've named your ethernet header "ethernet" :) )

action terminate_cpu_packet() {
    modify_field(ingress_egress_port,
                 fabric_header.dstPortOrGroup);
//    modify_field(egress_metadata.bypass, fabric_header_cpu.txBypass);

    modify_field(ethernet.etherType, fabric_payload_header.etherType);
    remove_header(fabric_header);
    remove_header(fabric_header_cpu);
    remove_header(fabric_payload_header);
}

action terminate_fabric_multicast_packet() {
//    modify_field(tunnel_metadata.tunnel_terminate,
//                 fabric_header_multicast.tunnelTerminate);
//    modify_field(tunnel_metadata.ingress_tunnel_type,
//                 fabric_header_multicast.ingressTunnelType);
//    modify_field(l3_metadata.nexthop_index, 0);
//    modify_field(l3_metadata.routed, fabric_header_multicast.routed);
//    modify_field(l3_metadata.outer_routed,
//                 fabric_header_multicast.outerRouted);

    modify_field(intrinsic_mcast_grp,
                 fabric_header_multicast.mcastGrp);

    modify_field(ethernet.etherType, fabric_payload_header.etherType);
    remove_header(fabric_header);
    remove_header(fabric_header_multicast);
    remove_header(fabric_payload_header);
}

table packet_out {
    reads {
        fabric_header.packetType : exact;
    }
    actions {
        nop;
        terminate_cpu_packet;
        terminate_fabric_multicast_packet;
    }
}

#endif /* OPENFLOW_PACKET_IN_OUT */

/****************************************************************
 * Actions common to all openflow tables, sets a bitmap indicating
 * which OFPAT to be applied to packets in flow flow_id.
 ****************************************************************/

action openflow_apply(bmap, index, group_id) {
    modify_field(openflow_metadata.bmap, bmap);
    modify_field(openflow_metadata.index, index);
    modify_field(openflow_metadata.group_id, group_id);
    modify_field(openflow_metadata.ofvalid, TRUE);
//    modify_field(egress_metadata.bypass, TRUE);
}

action openflow_miss(reason, table_id) {
#ifdef OPENFLOW_PACKET_IN_OUT
    add_header(fabric_header);
    add_header(fabric_header_cpu);
    add_header(fabric_payload_header);
    
    modify_field(fabric_payload_header.etherType, ethernet.etherType);

    modify_field(fabric_header_cpu.ingressPort, ingress_input_port);
#endif

    modify_field(fabric_header_cpu.reasonCode, reason);

    shift_left(fabric_header_cpu.reasonCode, fabric_header_cpu.reasonCode, 8);
    bit_or(fabric_header_cpu.reasonCode, fabric_header_cpu.reasonCode, table_id);

    modify_field(ingress_egress_port, CPU_PORT_ID);
}

/****************************************************************
 * Egress openflow bitmap translation
 ****************************************************************/

action ofpat_group_egress_update(bmap) {
    bit_or (openflow_metadata.bmap, openflow_metadata.bmap, bmap);
}

table ofpat_group_egress {
    reads {
        openflow_metadata.group_id : exact;
        egress_egress_port : exact;
    }

    actions {
        ofpat_group_egress_update;
        nop;
    }
}

/****************************************************************
 * GROUPS 
 ****************************************************************/

action ofpat_group_ingress_uc(ifindex) {
    modify_field(ingress_egress_port, ifindex);
}

action ofpat_group_ingress_mc(mcindex) {
    modify_field(intrinsic_mcast_grp, mcindex);
}

table ofpat_group_ingress {
    reads {
        openflow_metadata.group_id : exact;
    }

    actions {
        ofpat_group_ingress_uc;
        ofpat_group_ingress_mc;
        nop;
    }
}

/****************************************************************
 * OFPAT_OUTPUT
 ****************************************************************/

action ofpat_output(egress_port) {
    modify_field(ingress_egress_port, egress_port);
// for switch.p4
//    modify_field(ingress_metadata.egress_ifindex, 0);
}

table ofpat_output {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        ingress_egress_port : ternary;
    }

    actions {
        ofpat_output;
        nop;
    }
}

#ifdef OPENFLOW_ENABLE_MPLS
/***************************************************************
 * OFPAT_SET_MPLS_TTL
 ***************************************************************/

action ofpat_set_mpls_ttl(ttl) {
    modify_field(mpls[0].ttl, ttl);
}

table ofpat_set_mpls_ttl {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        egress_egress_port : ternary;
    }

    actions {
        ofpat_set_mpls_ttl;
        nop;
    }
}

/***************************************************************
 * OFPAT_DEC_MPLS_TTL
 ***************************************************************/

action ofpat_dec_mpls_ttl() {
    add_to_field(mpls[0].ttl, -1);
}

table ofpat_dec_mpls_ttl {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        egress_egress_port : ternary;
    }

    actions {
        ofpat_dec_mpls_ttl;
        nop;
    }
}

/****************************************************************
 * OFPAT_PUSH_MPLS
 ****************************************************************/

action ofpat_push_mpls() {
    modify_field(ethernet.etherType, 0x8847);
    add_header(mpls[0]);
}

table ofpat_push_mpls {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        egress_egress_port : ternary;
    }

    actions {
        ofpat_push_mpls;
        nop;
    }
}

/***************************************************************
 * OFPAT_POP_MPLS
 ***************************************************************/

action ofpat_pop_mpls() {
    remove_header(mpls[0]);
}

table ofpat_pop_mpls {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        egress_egress_port : ternary;
    }

    actions {
        ofpat_pop_mpls;
        nop;
    }
}
#endif /* OPENFLOW_ENABLE_MPLS */
#ifdef OPENFLOW_ENABLE_VLAN
/***************************************************************
 * OFPAT_PUSH_VLAN
 ***************************************************************/

action ofpat_push_vlan() {
    modify_field(ethernet.etherType, 0x8100);
    add_header(vlan_tag_[0]);
    modify_field(vlan_tag_[0].etherType, 0x0800);
}

table ofpat_push_vlan {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        egress_egress_port : ternary;
    }

    actions {
        ofpat_push_vlan;
        nop;
    }
}

/***************************************************************
 * OFPAT_POP_VLAN
 ***************************************************************/

action ofpat_pop_vlan() {
    modify_field(ethernet.etherType, vlan_tag_[0].etherType);
    remove_header(vlan_tag_[0]);
}

table ofpat_pop_vlan {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        egress_egress_port : ternary;
    }
    
    actions {
        ofpat_pop_vlan;
        nop;
    }
}

/***************************************************************
 * OFPAT_SET_FIELD
 ***************************************************************/

action ofpat_set_vlan_vid(vid) {
    modify_field(vlan_tag_[0].vid, vid);
}

table ofpat_set_field {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        egress_egress_port : ternary;
    }

    actions {
        ofpat_set_vlan_vid;
        nop;
    }
}

#endif /* OPENFLOW_ENABLE_VLAN */

/****************************************************************
 * OFPAT_SET_QUEUE
 ****************************************************************/


 //TODO

#ifdef OPENFLOW_ENABLE_L3
/***************************************************************
 * OFPAT_SET_NW_TTL IPV4
 ***************************************************************/

action ofpat_set_nw_ttl_ipv4(ttl) {
    modify_field(ipv4.ttl, ttl);
}

table ofpat_set_nw_ttl_ipv4 {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        egress_egress_port : ternary;
    }

    actions {
        ofpat_set_nw_ttl_ipv4;
        nop;
    }
}

/***************************************************************
 * OFPAT_SET_NW_TTL IPV6
 ***************************************************************/

action ofpat_set_nw_ttl_ipv6(ttl) {
    modify_field(ipv6.hopLimit, ttl);
}

table ofpat_set_nw_ttl_ipv6 {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        egress_egress_port : ternary;
    }

    actions {
        ofpat_set_nw_ttl_ipv6;
        nop;
    }
}

/***************************************************************
 * OFPAT_DEC_NW_TTL IPV4
 ***************************************************************/

action ofpat_dec_nw_ttl_ipv4() {
    add_to_field(ipv4.ttl, -1);
}

table ofpat_dec_nw_ttl_ipv4 {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        egress_egress_port : ternary;
    }

    actions {
        ofpat_dec_nw_ttl_ipv4;
        nop;
    }
}

/***************************************************************
 * OFPAT_DEC_NW_TTL IPV6
 ***************************************************************/

action ofpat_dec_nw_ttl_ipv6(ttl) {
    add_to_field(ipv6.hopLimit, -1);
}

table ofpat_dec_nw_ttl_ipv6 {
    reads {
        openflow_metadata.index : ternary;
        openflow_metadata.group_id : ternary;
        egress_egress_port : ternary;
    }

    actions {
        ofpat_dec_nw_ttl_ipv6;
        nop;
    }
}
#endif /* OPENFLOW_ENABLE_L3 */

/***************************************************************
 * Main control block
 ***************************************************************/

control process_ofpat_ingress {
    if (openflow_metadata.bmap & 0x400000 == 0x400000) {
        apply(ofpat_group_ingress);
    }

    if (openflow_metadata.bmap & 0x1 == 1) {
        apply(ofpat_output);
    }
}

control process_ofpat_egress {
    apply(ofpat_group_egress);

#ifdef OPENFLOW_ENABLE_MPLS
    if (openflow_metadata.bmap & 0x100000 == 0x100000) {
        apply(ofpat_pop_mpls);
    }

    if (openflow_metadata.bmap & 0x80000 == 0x80000) {
        apply(ofpat_push_mpls);
    }

    if (openflow_metadata.bmap & 0x10000 == 0x10000) {
        apply(ofpat_dec_mpls_ttl);
    }

    if (openflow_metadata.bmap & 0x8000 == 0x8000) {
        apply(ofpat_set_mpls_ttl);
    }
#endif /* OPENFLOW_ENABLE_MPLS */
#ifdef OPENFLOW_ENABLE_VLAN
    if (openflow_metadata.bmap & 0x40000 == 0x40000) {
        apply(ofpat_pop_vlan);
    }

    if (openflow_metadata.bmap & 0x20000 == 0x20000) {
        apply(ofpat_push_vlan);
    }

    if (openflow_metadata.bmap & 0x2000000 == 0x2000000) {
        apply(ofpat_set_field);
    }
#endif /* OPENFLOW_ENABLE_VLAN */
#ifdef OPENFLOW_ENABLE_L3
    if (openflow_metadata.bmap & 0x1000000 == 0x1000000) {
        if ((valid(ipv4))) {
            apply(ofpat_dec_nw_ttl_ipv4);
        } else {
            if ((valid(ipv6))) {
                apply(ofpat_dec_nw_ttl_ipv6);
            }
        }
    }

    if (openflow_metadata.bmap & 0x800000 == 0x800000) {
        if (valid(ipv4)) {
            apply(ofpat_set_nw_ttl_ipv4);
        } else {
            if (valid(ipv6)) {
                apply(ofpat_set_nw_ttl_ipv6);
            }
        }
    }
#endif /* OPENFLOW_ENABLE_L3 */

    // oq (set queue)
}

