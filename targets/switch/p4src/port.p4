/*
 * Input processing - port and packet related
 */


/*****************************************************************************/
/* Validate outer packet header                                              */
/*****************************************************************************/
action set_valid_outer_unicast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

action set_valid_outer_unicast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

action set_valid_outer_unicast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

action set_valid_outer_unicast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

action set_valid_outer_multicast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

action set_valid_outer_multicast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

action set_valid_outer_multicast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

action set_valid_outer_multicast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

action set_valid_outer_broadcast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

action set_valid_outer_broadcast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

action set_valid_outer_broadcast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

action set_valid_outer_broadcast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(standard_metadata.egress_spec, INVALID_PORT_ID);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
}

table validate_outer_ethernet {
    reads {
        ethernet.dstAddr : ternary;
        vlan_tag_[0] : valid;
        vlan_tag_[1] : valid;
    }
    actions {
        set_valid_outer_unicast_packet_untagged;
        set_valid_outer_unicast_packet_single_tagged;
        set_valid_outer_unicast_packet_double_tagged;
        set_valid_outer_unicast_packet_qinq_tagged;
        set_valid_outer_multicast_packet_untagged;
        set_valid_outer_multicast_packet_single_tagged;
        set_valid_outer_multicast_packet_double_tagged;
        set_valid_outer_multicast_packet_qinq_tagged;
        set_valid_outer_broadcast_packet_untagged;
        set_valid_outer_broadcast_packet_single_tagged;
        set_valid_outer_broadcast_packet_double_tagged;
        set_valid_outer_broadcast_packet_qinq_tagged;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}

control validate_outer_ethernet_header {
    apply(validate_outer_ethernet);
}

control process_validate_outer_header {
    /* validate the ethernet header */
    validate_outer_ethernet_header();

    /* validate input packet and perform basic validations */
    if (valid(ipv4)) {
        validate_outer_ipv4_header();
    } else {
        if (valid(ipv6)) {
            validate_outer_ipv6_header();
        } else {
            if (valid(mpls[0])) {
                validate_mpls_header();
            }
        }
    }
}


/*****************************************************************************/
/* Ingress port lookup                                                       */
/*****************************************************************************/
action set_ifindex(ifindex, if_label, port_type) {
    modify_field(ingress_metadata.ifindex, ifindex);
    modify_field(acl_metadata.if_label, if_label);
    modify_field(ingress_metadata.port_type, port_type);
}

table ingress_port_mapping {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        set_ifindex;
    }
    size : PORTMAP_TABLE_SIZE;
}

control process_ingress_port_mapping {
    apply(ingress_port_mapping);
}


/*****************************************************************************/
/* Ingress port-vlan mapping lookup                                          */
/*****************************************************************************/
action set_bd(bd, vrf, rmac_group,
        ipv4_unicast_enabled, ipv6_unicast_enabled,
        ipv4_urpf_mode, ipv6_urpf_mode,
        igmp_snooping_enabled, mld_snooping_enabled,
        bd_label, stp_group, stats_idx) {
    modify_field(l3_metadata.vrf, vrf);
    modify_field(ipv4_metadata.ipv4_unicast_enabled, ipv4_unicast_enabled);
    modify_field(ipv6_metadata.ipv6_unicast_enabled, ipv6_unicast_enabled);
    modify_field(ipv4_metadata.ipv4_urpf_mode, ipv4_urpf_mode);
    modify_field(ipv6_metadata.ipv6_urpf_mode, ipv6_urpf_mode);
    modify_field(l3_metadata.rmac_group, rmac_group);
    modify_field(acl_metadata.bd_label, bd_label);
    modify_field(ingress_metadata.bd, bd);
    modify_field(ingress_metadata.outer_bd, bd);
    modify_field(l2_metadata.stp_group, stp_group);
    modify_field(l2_metadata.bd_stats_idx, stats_idx);

    modify_field(multicast_metadata.igmp_snooping_enabled, igmp_snooping_enabled);
    modify_field(multicast_metadata.mld_snooping_enabled, mld_snooping_enabled);
}

action_profile bd_action_profile {
    actions {
        set_bd;
    }
    size : BD_TABLE_SIZE;
}

table port_vlan_mapping {
    reads {
        ingress_metadata.ifindex : exact;
        vlan_tag_[0] : valid;
        vlan_tag_[0].vid : exact;
        vlan_tag_[1] : valid;
        vlan_tag_[1].vid : exact;
    }

    action_profile: bd_action_profile;
    size : PORT_VLAN_TABLE_SIZE;
}

control process_port_vlan_mapping {
    apply(port_vlan_mapping);
}


/*****************************************************************************/
/* Ingress BD stats based on packet type                                     */
/*****************************************************************************/
#ifndef STATS_DISABLE
counter ingress_bd_stats {
    type : packets_and_bytes;
    instance_count : BD_TABLE_SIZE;
}

action update_ingress_bd_stats() {
    count(ingress_bd_stats, l2_metadata.bd_stats_idx);
}

table ingress_bd_stats {
    actions {
        update_ingress_bd_stats;
    }
    size : BD_STATS_TABLE_SIZE;
}
#endif /* STATS_DISABLE */

control process_ingress_bd_stats {
#ifndef STATS_DISABLE
    apply(ingress_bd_stats);
#endif /* STATS_DISABLE */
}


/*****************************************************************************/
/* LAG lookup/resolution                                                     */
/*****************************************************************************/
field_list lag_hash_fields {
    l2_metadata.lkp_mac_sa;
    l2_metadata.lkp_mac_da;
    l2_metadata.lkp_mac_type;
    ipv4_metadata.lkp_ipv4_sa;
    ipv4_metadata.lkp_ipv4_da;
    l3_metadata.lkp_ip_proto;
    l3_metadata.lkp_l4_sport;
    l3_metadata.lkp_l4_dport;
}

field_list_calculation lag_hash {
    input {
        lag_hash_fields;
    }
    algorithm : crc16;
    output_width : LAG_BIT_WIDTH;
}

action_selector lag_selector {
    selection_key : lag_hash;
}

#ifdef FABRIC_ENABLE
action set_lag_remote_port(device, port) {
    modify_field(fabric_metadata.dst_device, device);
    modify_field(fabric_metadata.dst_port, port);
}
#endif /* FABRIC_ENABLE */

action set_lag_port(port) {
    modify_field(standard_metadata.egress_spec, port);
}

action set_lag_miss() {
}

action_profile lag_action_profile {
    actions {
        set_lag_miss;
        set_lag_port;
#ifdef FABRIC_ENABLE
        set_lag_remote_port;
#endif /* FABRIC_ENABLE */
    }
    size : LAG_GROUP_TABLE_SIZE;
    dynamic_action_selection : lag_selector;
}

table lag_group {
    reads {
        ingress_metadata.egress_ifindex : exact;
    }
    action_profile: lag_action_profile;
    size : LAG_SELECT_TABLE_SIZE;
}

control process_lag {
    apply(lag_group);
}


/*****************************************************************************/
/* Egress port lookup                                                        */
/*****************************************************************************/
action egress_port_type_normal() {
    modify_field(egress_metadata.port_type, PORT_TYPE_NORMAL);
}

action egress_port_type_fabric() {
    modify_field(egress_metadata.port_type, PORT_TYPE_FABRIC);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_FABRIC);
}

action egress_port_type_cpu() {
    modify_field(egress_metadata.port_type, PORT_TYPE_CPU);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_CPU);
}

table egress_port_mapping {
    reads {
        standard_metadata.egress_port : exact;
    }
    actions {
        egress_port_type_normal;
        egress_port_type_fabric;
        egress_port_type_cpu;
    }
    size : PORTMAP_TABLE_SIZE;
}


/*****************************************************************************/
/* Egress VLAN translation                                                   */
/*****************************************************************************/
action set_egress_packet_vlan_tagged(vlan_id) {
    add_header(vlan_tag_[0]);
    modify_field(vlan_tag_[0].etherType, ethernet.etherType);
    modify_field(vlan_tag_[0].vid, vlan_id);
    modify_field(ethernet.etherType, 0x8100);
}

action set_egress_packet_vlan_untagged() {
}

table egress_vlan_xlate {
    reads {
        standard_metadata.egress_port : exact;
        egress_metadata.bd : exact;
    }
    actions {
        set_egress_packet_vlan_tagged;
        set_egress_packet_vlan_untagged;
    }
    size : EGRESS_VLAN_XLATE_TABLE_SIZE;
}

control process_vlan_xlate {
    apply(egress_vlan_xlate);
}
