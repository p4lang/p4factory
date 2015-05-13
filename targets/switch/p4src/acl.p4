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
 * acl metadata
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
    }
}

metadata acl_metadata_t acl_metadata;

#ifndef ACL_DISABLE
action acl_log() {
}

action acl_deny() {
    modify_field(acl_metadata.acl_deny, TRUE);
}

action acl_permit() {
}

action acl_mirror(session_id) {
    //modify_field(ingress_metadata.mirror_session_id, session_id);
    clone_ingress_pkt_to_egress(session_id);
}

action acl_redirect_nexthop(nexthop_index) {
    modify_field(acl_metadata.acl_redirect, TRUE);
    modify_field(acl_metadata.acl_nexthop, nexthop_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_SIMPLE);
}

action acl_redirect_ecmp(ecmp_index) {
    modify_field(acl_metadata.acl_redirect, TRUE);
    modify_field(acl_metadata.acl_nexthop, ecmp_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_ECMP);
}
#endif /* ACL_DISABLE */

#ifndef ACL_DISABLE
#ifndef L2_DISABLE
table mac_acl {
    reads {
        ingress_metadata.if_label : ternary;
        ingress_metadata.bd_label : ternary;

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
#endif /* L2_DISABLE */
#endif /* ACL_DISABLE */

control process_mac_acl {
#ifndef ACL_DISABLE
#ifndef L2_DISABLE
    apply(mac_acl);
#endif /* L2_DISABLE */
#endif /* ACL_DISABLE */
}

#ifndef ACL_DISABLE
#ifndef IPV4_DISABLE
table ip_acl {
    reads {
        ingress_metadata.if_label : ternary;
        ingress_metadata.bd_label : ternary;

        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        ingress_metadata.lkp_l4_sport : ternary;
        ingress_metadata.lkp_l4_dport : ternary;

        ingress_metadata.lkp_icmp_type: ternary;
        ingress_metadata.lkp_icmp_code: ternary;

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
    size : INGRESS_IP_ACL_TABLE_SIZE;
}
#endif /* IPV4_DISABLE */
#endif /* ACL_DISABLE */

#ifndef ACL_DISABLE
#ifndef IPV6_DISABLE
table ipv6_acl {
    reads {
        ingress_metadata.if_label : ternary;
        ingress_metadata.bd_label : ternary;

        ipv6_metadata.lkp_ipv6_sa : ternary;
        ipv6_metadata.lkp_ipv6_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        ingress_metadata.lkp_l4_sport : ternary;
        ingress_metadata.lkp_l4_dport : ternary;

        ingress_metadata.lkp_icmp_type : ternary;
        ingress_metadata.lkp_icmp_code : ternary;

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
#endif /* IPV6_DISABLE */
#endif /* ACL_DISABLE */

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

#ifndef ACL_DISABLE
#ifndef QOS_DISABLE
action apply_cos_marking(cos) {
    modify_field(ingress_metadata.marked_cos, cos);
}

action apply_dscp_marking(dscp) {
    modify_field(ingress_metadata.marked_dscp, dscp);
}

action apply_tc_marking(tc) {
    modify_field(ingress_metadata.marked_exp, tc);
}

table qos {
    reads {
        ingress_metadata.if_label : ternary;

        /* ip */
        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        l3_metadata.lkp_ip_tc : ternary;

        /* mpls */
        tunnel_metadata.mpls_exp : ternary;

        /* outer ip */
        ingress_metadata.outer_dscp : ternary;
    }
    actions {
        nop;
        apply_cos_marking;
        apply_dscp_marking;
        apply_tc_marking;
    }
    size : INGRESS_QOS_ACL_TABLE_SIZE;
}
#endif /* QOS_DISABLE */
#endif /* ACL_DISABLE */

control process_qos {
#ifndef ACL_DISABLE
#ifndef QOS_DISABLE
    apply(qos);
#endif /* QOS_DISABLE */
#endif /* ACL_DISABLE */
}

//#ifndef ACL_DISABLE
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
//#endif /* ACL_DISABLE */

#ifndef ACL_DISABLE
#ifndef IPV4_DISABLE
table ipv4_racl {
    reads {
        ingress_metadata.bd_label : ternary;

        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        ingress_metadata.lkp_l4_sport : ternary;
        ingress_metadata.lkp_l4_dport : ternary;
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
#endif /* IPV4_DISABLE */
#endif /* ACL_DISABLE */

control process_ipv4_racl {
#ifndef ACL_DISABLE
#ifndef IPV4_DISABLE
    apply(ipv4_racl);
#endif /* IPV4_DISABLE */
#endif /* ACL_DISABLE */
}

//#ifndef ACL_DISABLE
//#ifndef IPV6_DISABLE
table ipv6_racl {
    reads {
        ingress_metadata.bd_label : ternary;

        ipv6_metadata.lkp_ipv6_sa : ternary;
        ipv6_metadata.lkp_ipv6_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        ingress_metadata.lkp_l4_sport : ternary;
        ingress_metadata.lkp_l4_dport : ternary;
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
//#endif /* IPV6_DISABLE */
//#endif /* ACL_DISABLE */

control process_ipv6_racl {
//#ifndef ACL_DISABLE
//#ifndef IPV6_DISABLE
    apply(ipv6_racl);
//#endif /* IPV6_DISABLE */
//#endif /* ACL_DISABLE */
}

action redirect_to_cpu() {
    modify_field(standard_metadata.egress_spec, CPU_PORT_ID);
    modify_field(intrinsic_metadata.eg_mcast_group, 0);
}

action copy_to_cpu() {
    clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID);
}

action drop_packet() {
    drop();
}

table system_acl {
    reads {
        ingress_metadata.if_label : ternary;
        ingress_metadata.bd_label : ternary;

        /* ip acl */
        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;

        /* mac acl */
        l2_metadata.lkp_mac_sa : ternary;
        l2_metadata.lkp_mac_da : ternary;
        l2_metadata.lkp_mac_type : ternary;

        /* drop reasons */
        ingress_metadata.ipsg_check_fail : ternary;
        acl_metadata.acl_deny : ternary;
        acl_metadata.racl_deny: ternary;
        l3_metadata.urpf_check_fail : ternary;

        /*
         * other checks, routed link_local packet, l3 same if check,
         * expired ttl
         */
        l3_metadata.routed : ternary;
        ingress_metadata.src_is_link_local : ternary;
        ingress_metadata.same_bd_check : ternary;
        l3_metadata.lkp_ip_ttl : ternary;
        l2_metadata.stp_state : ternary;
        ingress_metadata.control_frame: ternary;
        ipv4_metadata.ipv4_unicast_enabled : ternary;

        /* egress information */
        standard_metadata.egress_spec : ternary;
    }
    actions {
        nop;
        redirect_to_cpu;
        copy_to_cpu;
        drop_packet;
    }
    size : SYSTEM_ACL_SIZE;
}

control process_system_acl {
    apply(system_acl);
}

#ifndef ACL_DISABLE
action egress_redirect_to_cpu() {
}

action egress_drop() {
    drop();
}

table egress_acl {
    reads {
        egress_metadata.drop_exception : ternary;
        ipv6.dstAddr : ternary;
        ipv6.nextHdr : exact;
    }
    actions {
        nop;
        egress_drop;
        egress_redirect_to_cpu;
    }
    size : EGRESS_ACL_TABLE_SIZE;
}
#endif /* ACL_DISABLE */

control process_egress_acl {
#ifndef ACL_DISABLE
    apply(egress_acl);
#endif /* ACL_DISABLE */
}
