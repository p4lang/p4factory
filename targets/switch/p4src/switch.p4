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

#include "includes/p4features.h"
#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/sizes.p4"
#include "includes/intrinsic.p4"
#include "includes/defines.p4"

/* METADATA */
header_type ingress_metadata_t {
    fields {
        lkp_l4_sport : 16;
        lkp_l4_dport : 16;
        lkp_inner_l4_sport : 16;
        lkp_inner_l4_dport : 16;

        lkp_icmp_type : 8;
        lkp_icmp_code : 8;
        lkp_inner_icmp_type : 8;
        lkp_inner_icmp_code : 8;

        ifindex : IFINDEX_BIT_WIDTH;           /* input interface index - MSB bit lag*/
        vrf : VRF_BIT_WIDTH;                   /* VRF */

        outer_bd : BD_BIT_WIDTH;               /* outer BD */
        outer_dscp : 8;                        /* outer dscp */

        src_is_link_local : 1;                 /* source is link local address */
        bd : BD_BIT_WIDTH;                     /* BD */
        egress_bd : BD_BIT_WIDTH;              /* egress BD */
        uuc_mc_index : 16;                     /* unknown unicast multicast index */
        umc_mc_index : 16;                     /* unknown multicast multicast index */
        bcast_mc_index : 16;                   /* broadcast multicast index */

        if_label : 16;                         /* if label for acls */
        bd_label : 16;                         /* bd label for acls */

        ipsg_check_fail : 1;                   /* ipsg check failed */

        marked_cos : 3;                        /* marked vlan cos value */
        marked_dscp : 8;                       /* marked dscp value */
        marked_exp : 3;                        /* marked exp value */

        egress_ifindex : IFINDEX_BIT_WIDTH;    /* egress interface index */
        same_bd_check : BD_BIT_WIDTH;          /* ingress bd xor egress bd */

        ipv4_dstaddr_24b : 24;                 /* first 24b of ipv4 dst addr */
        drop_0 : 1;                            /* dummy */
        drop_reason : 8;                       /* drop reason for negative mirroring */
        control_frame: 1;                      /* control frame */
    }
}

header_type egress_metadata_t {
    fields {
        payload_length : 16;                   /* payload length for tunnels */
        smac_idx : 9;                          /* index into source mac table */
        bd : BD_BIT_WIDTH;                     /* egress inner bd */
        inner_replica : 1;                     /* is copy is due to inner replication */
        replica : 1;                           /* is this a replica */
        mac_da : 48;                           /* final mac da */
        routed : 1;                            /* is this replica routed */
        same_bd_check : BD_BIT_WIDTH;          /* ingress bd xor egress bd */


        drop_reason : 8;                       /* drop reason for negative mirroring */
        egress_bypass : 1;                     /* skip the entire egress pipeline */
        drop_exception : 8;                    /* MTU check fail, .. */
    }
}

metadata ingress_metadata_t ingress_metadata;
metadata egress_metadata_t egress_metadata;

#include "port.p4"
#include "l2.p4"
#include "l3.p4"
#include "ipv4.p4"
#include "ipv6.p4"
#include "tunnel.p4"
#include "acl.p4"
#include "multicast.p4"
#include "nexthop.p4"
#include "rewrite.p4"
#include "security.p4"
#include "egress_filter.p4"

action nop() {
}

action on_miss() {
}

control ingress {

    /* validate the ethernet header */
    validate_outer_ethernet_header();

    /* validate input packet and perform basic validations */
    if (valid(ipv4)) {
        validate_outer_ipv4_header();
    } else {
        if (valid(ipv6)) {
            validate_outer_ipv6_header();
        }
    }

    if (valid(mpls[0])) {
        validate_mpls_header();
    }

    /* input mapping - derive an ifindex */
    /*
     * skipping this lookup as phase 0 lookup will provide
     * an ifindex that maps all ports in a lag to a single value
     */
    process_port_mapping();

    process_storm_control();

    /* derive bd */
    process_port_vlan_mapping();
    process_spanning_tree();
    process_ip_sourceguard();

    /* outer RMAC lookup for tunnel termination */
    apply(outer_rmac) {
    set_outer_rmac_hit_flag {
            if (valid(ipv4)) {
                process_ipv4_vtep();
            } else {
                if (valid(ipv6)) {
                    process_ipv6_vtep();
                } else {
                    /* check for mpls tunnel termination */
                    if (valid(mpls[0])) {
                        process_mpls();
                    }
                }
            }
        }
    }

    /* perform tunnel termination */
    if (tunnel_metadata.tunnel_terminate == TRUE) {
        process_tunnel();
    }

#ifndef TUNNEL_DISABLE
    if ((security_metadata.storm_control_color != STORM_CONTROL_COLOR_RED) and
       ((not valid(mpls[0])) or
       (valid(mpls[0]) and (tunnel_metadata.tunnel_terminate == TRUE)))) {
#endif /* TUNNEL_DISABLE */

        /* validate packet */
        process_validate_packet();

        /* l2 lookups */
        process_mac();

        /* port and vlan ACL */
        if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
            process_mac_acl();
        } else {
            process_ip_acl();
        }

        process_qos();

        apply(rmac) {
            rmac_hit {
                if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and
                    (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
                    /* router ACL/PBR */
                    process_ipv4_racl();

                    process_ipv4_urpf();
                    process_ipv4_fib();

                } else {
                    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and
                        (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {

                        /* router ACL/PBR */
                        process_ipv6_racl();
                        process_ipv6_urpf();
                        process_ipv6_fib();
                    }
                }
                process_urpf_bd();
            }
        }
        /* merge the results and decide whice one to use */
#ifndef TUNNEL_DISABLE
    }
#endif /* TUNNEL_DISABLE */

    /* decide final forwarding choice */
    process_merge_results();

    /* ecmp/nexthop lookup */
    process_nexthop();

    /* resolve final egress port for unicast traffic */
    process_lag();

    /* generate learn notify digest if permitted */
    process_mac_learning();

    /* system acls */
    process_system_acl();
}

control egress {

    if (egress_metadata.egress_bypass == FALSE) {

        process_replication();

        process_vlan_decap();

        /* perform tunnel decap */
        process_tunnel_decap();

        /* egress bd properties */
        process_egress_bd();

        /* apply nexthop_index based packet rewrites */
        process_rewrite();

        /* rewrite source/destination mac if needed */
        process_mac_rewrite();

        /* perform tunnel decap */
        process_tunnel_encap();

        process_mtu();

        /* egress vlan translation */
        process_vlan_xlate();

        /* egress filter */
        process_egress_filter();

        /* apply egress acl */
        process_egress_acl();
    }
}
