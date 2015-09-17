/*
 * ACL processing : MAC, IPv4, IPv6, RACL/PBR
 * Qos processing
 */

/*
 * ACL and QoS metadata
 */
header_type acl_metadata_t {
    fields {
        acl_deny : 1;                          /* ifacl/vacl deny action */
        racl_deny : 1;                         /* racl deny action */
        acl_nexthop : 16;                      /* next hop from ifacl/vacl */
        racl_nexthop : 16;                     /* next hop from racl */
        acl_nexthop_type : 1;                  /* ecmp or nexthop */
        racl_nexthop_type : 1;                 /* ecmp or nexthop */
        acl_redirect :   1;                    /* ifacl/vacl redirect action */
        racl_redirect : 1;                     /* racl redirect action */
        if_label : 15;                         /* if label for acls */
        bd_label : 16;                         /* bd label for acls */
        mirror_session_id : 10;                /* mirror session id */
    }
}
header_type qos_metadata_t {
    fields {
        outer_dscp : 8;                        /* outer dscp */
        marked_cos : 3;                        /* marked vlan cos value */
        marked_dscp : 8;                       /* marked dscp value */
        marked_exp : 3;                        /* marked exp value */
    }
}

header_type i2e_metadata_t {
    fields {
        ingress_tstamp : 32;
        mirror_session_id : 16;
    }
}

metadata acl_metadata_t acl_metadata;
metadata qos_metadata_t qos_metadata;
metadata i2e_metadata_t i2e_metadata;

#ifndef ACL_DISABLE
/*****************************************************************************/
/* ACL Actions                                                               */
/*****************************************************************************/
action acl_log() {
    modify_field(ingress_metadata.enable_dod, 0);
}

action acl_deny() {
    modify_field(acl_metadata.acl_deny, TRUE);
    modify_field(ingress_metadata.enable_dod, 0);
}

action acl_permit() {
    modify_field(ingress_metadata.enable_dod, 0);
}

field_list i2e_mirror_info {
    i2e_metadata.ingress_tstamp;
    i2e_metadata.mirror_session_id;
}

field_list e2e_mirror_info {
    i2e_metadata.mirror_session_id;
}

action acl_mirror(session_id) {
    modify_field(i2e_metadata.mirror_session_id, session_id);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
    modify_field(ingress_metadata.enable_dod, 0);
#ifndef __TARGET_BMV2__
    clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
#endif
}

action acl_redirect_nexthop(nexthop_index) {
    modify_field(acl_metadata.acl_redirect, TRUE);
    modify_field(acl_metadata.acl_nexthop, nexthop_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_SIMPLE);
    modify_field(ingress_metadata.enable_dod, 0);
}

action acl_redirect_ecmp(ecmp_index) {
    modify_field(acl_metadata.acl_redirect, TRUE);
    modify_field(acl_metadata.acl_nexthop, ecmp_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_ECMP);
    modify_field(ingress_metadata.enable_dod, 0);
}

action acl_dod_en() {
    modify_field(ingress_metadata.enable_dod, 1);
}
#endif /* ACL_DISABLE */


/*****************************************************************************/
/* MAC ACL                                                                   */
/*****************************************************************************/
#if !defined(ACL_DISABLE) && !defined(L2_DISABLE)
#ifndef STATS_DISABLE
counter mac_acl_stats {
    type : packets_and_bytes;
    direct : mac_acl;
}
#endif /* STATS_DISABLE */

table mac_acl {
    reads {
        acl_metadata.if_label : ternary;
        acl_metadata.bd_label : ternary;

        l2_metadata.lkp_mac_sa : ternary;
        l2_metadata.lkp_mac_da : ternary;
        l2_metadata.lkp_mac_type : ternary;
    }
    actions {
        nop;
        acl_log;
        acl_deny;
        acl_permit;
        acl_mirror;
    }
    size : INGRESS_MAC_ACL_TABLE_SIZE;
}
#endif /* !ACL_DISABLE && !L2_DISABLE */

control process_mac_acl {
#if !defined(ACL_DISABLE) && !defined(L2_DISABLE)
    apply(mac_acl);
#endif /* !ACL_DISABLE && !L2_DISABLE */
}


/*****************************************************************************/
/* IPv4 ACL                                                                  */
/*****************************************************************************/
#if !defined(ACL_DISABLE) && !defined(IPV4_DISABLE)
#ifndef STATS_DISABLE
counter ip_acl_stats {
    type : packets_and_bytes;
    direct : ip_acl;
}
#endif /* STATS_DISABLE */

table ip_acl {
    reads {
        acl_metadata.if_label : ternary;
        acl_metadata.bd_label : ternary;

        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        l3_metadata.lkp_l4_sport : ternary;
        l3_metadata.lkp_l4_dport : ternary;

        l3_metadata.lkp_icmp_type: ternary;
        l3_metadata.lkp_icmp_code: ternary;

        l2_metadata.lkp_mac_type : ternary;

        tcp.flags : ternary;
        l3_metadata.lkp_ip_ttl : ternary;
    }
    actions {
        nop;
        acl_log;
        acl_deny;
        acl_permit;
        acl_mirror;
        acl_dod_en;
        acl_redirect_nexthop;
        acl_redirect_ecmp;
    }
    size : INGRESS_IP_ACL_TABLE_SIZE;
}
#endif /* !ACL_DISABLE && !IPV4_DISABLE */


/*****************************************************************************/
/* IPv6 ACL                                                                  */
/*****************************************************************************/
#if !defined(ACL_DISABLE) && !defined(IPV6_DISABLE)
#ifndef STATS_DISABLE
counter ipv6_acl_stats {
    type : packets_and_bytes;
    direct : ipv6_acl;
}
#endif /* STATS_DISABLE */

table ipv6_acl {
    reads {
        acl_metadata.if_label : ternary;
        acl_metadata.bd_label : ternary;

        ipv6_metadata.lkp_ipv6_sa : ternary;
        ipv6_metadata.lkp_ipv6_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        l3_metadata.lkp_l4_sport : ternary;
        l3_metadata.lkp_l4_dport : ternary;

        l3_metadata.lkp_icmp_type : ternary;
        l3_metadata.lkp_icmp_code : ternary;

        l2_metadata.lkp_mac_type : ternary;

        tcp.flags : ternary;
        l3_metadata.lkp_ip_ttl : ternary;
    }
    actions {
        nop;
        acl_log;
        acl_deny;
        acl_permit;
        acl_mirror;
        acl_redirect_nexthop;
        acl_redirect_ecmp;
    }
    size : INGRESS_IPV6_ACL_TABLE_SIZE;
}
#endif /* !ACL_DISABLE && !IPV6_DISABLE */


/*****************************************************************************/
/* ACL Control flow                                                          */
/*****************************************************************************/
control process_ip_acl {
#ifndef ACL_DISABLE
    if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
#ifndef IPV4_DISABLE
        apply(ip_acl);
#endif /* IPV4_DISABLE */
    } else {
        if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
#ifndef IPV6_DISABLE
            apply(ipv6_acl);
#endif /* IPV6_DISABLE */
        }
    }
#endif /* ACL_DISABLE */
}


/*****************************************************************************/
/* Qos Processing                                                            */
/*****************************************************************************/
#if !defined(ACL_DISABLE) && !defined(QOS_DISABLE)
action apply_cos_marking(cos) {
    modify_field(qos_metadata.marked_cos, cos);
}

action apply_dscp_marking(dscp) {
    modify_field(qos_metadata.marked_dscp, dscp);
}

action apply_tc_marking(tc) {
    modify_field(qos_metadata.marked_exp, tc);
}

table qos {
    reads {
        acl_metadata.if_label : ternary;

        /* ip */
        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        l3_metadata.lkp_ip_tc : ternary;

        /* mpls */
        tunnel_metadata.mpls_exp : ternary;

        /* outer ip */
        qos_metadata.outer_dscp : ternary;
    }
    actions {
        nop;
        apply_cos_marking;
        apply_dscp_marking;
        apply_tc_marking;
    }
    size : INGRESS_QOS_ACL_TABLE_SIZE;
}
#endif /* !ACL_DISABLE && !QOS_DISABLE */

control process_qos {
#if !defined(ACL_DISABLE) && !defined(QOS_DISABLE)
    apply(qos);
#endif /* !ACL_DISABLE && !QOS_DISABLE */
}


/*****************************************************************************/
/* RACL actions                                                              */
/*****************************************************************************/
#ifndef ACL_DISABLE
action racl_log() {
}

action racl_deny() {
    modify_field(acl_metadata.racl_deny, TRUE);
}

action racl_permit() {
}

action racl_redirect_nexthop(nexthop_index) {
    modify_field(acl_metadata.racl_redirect, TRUE);
    modify_field(acl_metadata.racl_nexthop, nexthop_index);
    modify_field(acl_metadata.racl_nexthop_type, NEXTHOP_TYPE_SIMPLE);
}

action racl_redirect_ecmp(ecmp_index) {
    modify_field(acl_metadata.racl_redirect, TRUE);
    modify_field(acl_metadata.racl_nexthop, ecmp_index);
    modify_field(acl_metadata.racl_nexthop_type, NEXTHOP_TYPE_ECMP);
}
#endif /* ACL_DISABLE */


/*****************************************************************************/
/* IPv4 RACL                                                                 */
/*****************************************************************************/
#if !defined(ACL_DISABLE) && !defined(IPV4_DISABLE)
#ifndef STATS_DISABLE
counter ip_racl_stats {
    type : packets_and_bytes;
    direct : ipv4_racl;
}
#endif /* STATS_DISABLE */

table ipv4_racl {
    reads {
        acl_metadata.bd_label : ternary;

        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        l3_metadata.lkp_l4_sport : ternary;
        l3_metadata.lkp_l4_dport : ternary;
    }
    actions {
        nop;
        racl_log;
        racl_deny;
        racl_permit;
        racl_redirect_nexthop;
        racl_redirect_ecmp;
    }
    size : INGRESS_IP_RACL_TABLE_SIZE;
}
#endif /* !ACL_DISABLE && !IPV4_DISABLE */

control process_ipv4_racl {
#if !defined(ACL_DISABLE) && !defined(IPV4_DISABLE)
    apply(ipv4_racl);
#endif /* !ACL_DISABLE && !IPV4_DISABLE */
}


/*****************************************************************************/
/* IPv6 RACL                                                                 */
/*****************************************************************************/
#if !defined(ACL_DISABLE) && !defined(IPV6_DISABLE)
table ipv6_racl {
    reads {
        acl_metadata.bd_label : ternary;

        ipv6_metadata.lkp_ipv6_sa : ternary;
        ipv6_metadata.lkp_ipv6_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        l3_metadata.lkp_l4_sport : ternary;
        l3_metadata.lkp_l4_dport : ternary;
    }
    actions {
        nop;
        racl_log;
        racl_deny;
        racl_permit;
        racl_redirect_nexthop;
        racl_redirect_ecmp;
    }
    size : INGRESS_IP_RACL_TABLE_SIZE;
}
#endif /* !ACL_DISABLE && !IPV6_DISABLE */

control process_ipv6_racl {
#if !defined(ACL_DISABLE) && !defined(IPV6_DISABLE)
    apply(ipv6_racl);
#endif /* !ACL_DISABLE && !IPV6_DISABLE */
}


/*****************************************************************************/
/* System ACL                                                                */
/*****************************************************************************/
field_list mirror_info {
    ingress_metadata.ifindex;
    ingress_metadata.drop_reason;
    l3_metadata.lkp_ip_ttl;
}

action negative_mirror(clone_spec, drop_reason) {
    modify_field(ingress_metadata.drop_reason, drop_reason);
#ifndef __TARGET_BMV2__
    clone_ingress_pkt_to_egress(clone_spec, mirror_info);
#endif
    drop();
}

action redirect_to_cpu(reason_code) {
    modify_field(standard_metadata.egress_spec, CPU_PORT_ID);
    modify_field(intrinsic_metadata.mcast_grp, 0);
    modify_field(fabric_metadata.reason_code, reason_code);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

field_list cpu_info {
    ingress_metadata.ifindex;
    fabric_metadata.reason_code;
}

action copy_to_cpu(reason_code) {
    modify_field(fabric_metadata.reason_code, reason_code);
#ifndef __TARGET_BMV2__
    clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, cpu_info);
#endif
}

action drop_packet() {
    drop();
}

action congestion_mirror_set() {
    deflect_on_drop();
}

table system_acl {
    reads {
        acl_metadata.if_label : ternary;
        acl_metadata.bd_label : ternary;

        /* ip acl */
        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;

        /* mac acl */
        l2_metadata.lkp_mac_sa : ternary;
        l2_metadata.lkp_mac_da : ternary;
        l2_metadata.lkp_mac_type : ternary;

        ingress_metadata.ifindex : ternary;

        /* drop reasons */
        security_metadata.ipsg_check_fail : ternary;
        acl_metadata.acl_deny : ternary;
        acl_metadata.racl_deny: ternary;
        l3_metadata.urpf_check_fail : ternary;

        l3_metadata.rmac_hit : ternary;

        /*
         * other checks, routed link_local packet, l3 same if check,
         * expired ttl
         */
        l3_metadata.routed : ternary;
        ipv6_metadata.ipv6_src_is_link_local : ternary;
        l3_metadata.same_bd_check : ternary;
        l3_metadata.lkp_ip_ttl : ternary;
        l2_metadata.stp_state : ternary;
        ingress_metadata.control_frame: ternary;
        ipv4_metadata.ipv4_unicast_enabled : ternary;

        /* egress information */
        standard_metadata.egress_spec : ternary;

        /* deflect on drop (-ve mirror) */
        ingress_metadata.enable_dod: ternary;
    }
    actions {
        nop;
        redirect_to_cpu;
        copy_to_cpu;
        drop_packet;
        negative_mirror;
        congestion_mirror_set;
    }
    size : SYSTEM_ACL_SIZE;
}

control process_system_acl {
    apply(system_acl);
}


/*****************************************************************************/
/* Egress ACL                                                                */
/*****************************************************************************/
#ifndef ACL_DISABLE
action egress_port_mirror(session_id) {
    modify_field(i2e_metadata.mirror_session_id, session_id);
#ifndef __TARGET_BMV2__
    clone_egress_pkt_to_egress(session_id, e2e_mirror_info);
#endif
}

action egress_port_mirror_drop(session_id) {
    egress_port_mirror(session_id);
    drop();
}

table egress_acl {
    reads {
        standard_metadata.egress_port : exact;
        intrinsic_metadata.deflection_flag : exact;
    }
    actions {
        nop;
        egress_port_mirror;
        egress_port_mirror_drop;
    }
    size : EGRESS_ACL_TABLE_SIZE;
}
#endif /* ACL_DISABLE */

control process_egress_acl {
#ifndef ACL_DISABLE
    apply(egress_acl);
#endif /* ACL_DISABLE */
}
