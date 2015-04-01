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

header_type acl_metadata_t {
    fields {
        acl_deny : 1;                          /* ifacl/vacl deny action */
        racl_deny : 1;                         /* racl deny action */
        acl_nexthop : 16;                      /* next hop from ifacl/vacl */
        racl_nexthop : 16;                     /* next hop from racl */
        acl_ecmp : 10;                         /* ecmp index from ifacl */
        racl_ecmp : 10;                        /* ecmp index from racl */
        acl_redirect :   1;                    /* ifacl/vacl redirect action */
        racl_redirect : 1;                     /* racl redirect action */
    }
}

metadata acl_metadata_t acl_metadata;

action acl_log() {
}

action acl_deny() {
    modify_field(acl_metadata.acl_deny, TRUE);
}

action acl_permit() {
}

action acl_redirect_nexthop(nexthop_index) {
    modify_field(acl_metadata.acl_redirect, TRUE);
    modify_field(acl_metadata.acl_nexthop, nexthop_index);
}

action acl_redirect_ecmp(ecmp_index) {
    modify_field(acl_metadata.acl_redirect, TRUE);
    modify_field(acl_metadata.acl_ecmp, ecmp_index);
}

table mac_acl {
    reads {
        l2_metadata.if_label : ternary;
        l2_metadata.bd_label : ternary;

        l2_metadata.lkp_mac_sa : ternary;
        l2_metadata.lkp_mac_da : ternary;
        l2_metadata.lkp_mac_type : ternary;
    }
    actions {
        nop;
        acl_log;
        acl_deny;
        acl_permit;
    }
    size : INGRESS_MAC_ACL_TABLE_SIZE;
}

table ip_acl {
    reads {
        l2_metadata.if_label : ternary;
        l2_metadata.bd_label : ternary;

        l3_metadata.lkp_ipv4_sa : ternary;
        l3_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        l3_metadata.lkp_l4_sport : ternary;
        l3_metadata.lkp_l4_dport : ternary;

        l2_metadata.lkp_mac_type : ternary;
        ingress_metadata.msg_type : ternary; /* ICMP code */
        tcp : valid;
        tcp.flags : ternary;
        l3_metadata.ttl : ternary;
    }
    actions {
        nop;
        acl_log;
        acl_deny;
        acl_permit;
        acl_redirect_nexthop;
        acl_redirect_ecmp;
    }
    size : INGRESS_IP_ACL_TABLE_SIZE;
}

control ip_and_mac_acl_lookup {
#ifndef ACL_DISABLE
    /* port and vlan ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
        apply(mac_acl);
    } else {
        if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
            apply(ip_acl);
        }
   }
#endif /* ACL DISABLE */
}

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
}

action racl_redirect_ecmp(ecmp_index) {
    modify_field(acl_metadata.racl_redirect, TRUE);
    modify_field(acl_metadata.racl_ecmp, ecmp_index);
}

table ip_racl {
    reads {
        l2_metadata.bd_label : ternary;

        l3_metadata.lkp_ipv4_sa : ternary;
        l3_metadata.lkp_ipv4_da : ternary;
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

control ip_racl_lookup {
#ifndef ACL_DISABLE
    /* router ACL/PBR */
    apply(ip_racl);
#endif /* ACL_DISABLE */
}

action redirect_to_cpu() {
    modify_field(standard_metadata.egress_spec, CPU_PORT);
    modify_field(intrinsic_metadata.eg_mcast_group, 0);
}

action copy_to_cpu() {
    clone_ingress_pkt_to_egress(CPU_PORT);
}

action drop_packet() {
    modify_field(intrinsic_metadata.eg_mcast_group, 0);
    drop();
}

table system_acl {
    reads {
        l2_metadata.if_label : ternary;
        l2_metadata.bd_label : ternary;

        /* ip acl */
        l3_metadata.lkp_ipv4_sa : ternary;
        l3_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;

        /* mac acl */
        l2_metadata.lkp_mac_sa : ternary;
        l2_metadata.lkp_mac_da : ternary;
        l2_metadata.lkp_mac_type : ternary;

        /* drop reasons */
        acl_metadata.acl_deny : ternary;
        acl_metadata.racl_deny: ternary;

        /* other checks, routed link_local packet, l3 same if check, expired ttl */
        tunnel_metadata.src_vtep_miss : ternary;
        l3_metadata.routed : ternary;
        mcast_metadata.src_is_link_local : ternary;
        l3_metadata.ttl : ternary;
        l2_metadata.stp_state : ternary;
        ingress_metadata.control_frame: ternary;

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

control system_acl_lookup {
#ifndef ACL_DISABLE
    /* system acls */
    apply(system_acl);
#endif /* ACL_DISABLE */
}

action egress_redirect_to_cpu() {
}

table egress_system_acl {
    reads {
        l3_metadata.mtu_check_fail : ternary;
    }
    actions {
        nop;
        egress_redirect_to_cpu;
    }
    size : EGRESS_SYSTEM_ACL_TABLE_SIZE;
}

control egress_system_acl_lookup {
#ifndef ACL_DISABLE
    /* apply egress acl */
    apply(egress_system_acl);
#endif /* ACL_DISABLE */
}
