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

#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/p4features.h"
#include "includes/intrinsic.p4"
#include "includes/sizes.p4"
#include "includes/constants.p4"
#include "l2.p4"
#include "l3.p4"
#include "ipv4.p4"
#include "ipv6.p4"
#include "tunnel.p4"
#include "multicast.p4"
#include "acl.p4"
#include "rewrite.p4"

/* METADATA */
header_type ingress_metadata_t {
    fields {
        lkp_icmp_type : 16;
        lkp_icmp_code : 16;

        lag_offset : 14;                       /* numer of lag members */

        ingress_bypass : 1;                    /* skip the entire ingress pipeline */
        drop_0 : 1;                            /* dummy */
        drop_reason : 8;                       /* drop reason */
        msg_type : 8;
        control_frame: 1;                      /* control frame */
    }
}

header_type egress_metadata_t {
    fields {
        drop_reason : 8;                       /* drop reason */
        egress_bypass : 1;                     /* skip the entire egress pipeline */
        bd : BD_BIT_WIDTH;                     /* egress inner bd */
    }
}

metadata ingress_metadata_t ingress_metadata;
metadata egress_metadata_t egress_metadata;

control ingress {

    /* Check to see the whole stage needs to be bypassed */
    if(ingress_metadata.ingress_bypass == FALSE) {
        /*validate outer l2 header */
        validate_outer_ethernet_header();
        if (valid(ipv4)) {
            /* validate outer ipv4 header */
            validate_outer_ipv4_header();
        } else {
            if (valid(ipv6)) {
                /* validate outer ipv6 header */
                validate_outer_ipv6_header();
            }
        }
        process_port_vlan_mapping();
        process_spanning_tree();

#ifndef TUNNEL_DISABLE
        process_tunnel_vtep();
        /* perform tunnel termination */
        if ((tunnel_metadata.src_vtep_miss == FALSE) and
            (((tunnel_metadata.outer_rmac_hit == TRUE) and
              (tunnel_metadata.tunnel_terminate == TRUE)) or
              ((l2_metadata.lkp_pkt_type == L2_MULTICAST) and
              (tunnel_metadata.tunnel_terminate == TRUE)))) {
            /* tunnel termination */
            process_tunnel_terminate();
        }
	    else
        {
#endif /* TUNNEL_DISABLE */
            process_bd();
#ifndef TUNNEL_DISABLE
        }
#endif /* TUNNEL_DISABLE */

        /* mac learning */
        process_smac_and_learn();
        /* ip and mac acl */
        process_ip_and_mac_acl();

        /* router mac lookup */
        apply(rmac) {
            on_miss {
                /* dmac lookup */
                process_dmac();
            }
            default {
                if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and
                    (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
                    /* ipv4 router acl */
                    process_ipv4_racl();
                    /* ipv4 fib */
                    process_ipv4_fib();
                } else {
                    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and
                        (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
                        /* ipv6 router acl */
                        process_ipv6_racl();
                        /* ipv6 fib */
                        process_ipv6_fib();
                    }
                }
            }
        }
        process_merge_results();
        /* nexthop */
        process_nexthop();
        /* link aggregation */
        process_lag();
        /* system acl */
        process_system_acl();
    }
}

control egress {
    if (egress_metadata.egress_bypass == FALSE) {
        /* process multicast replication */
        process_replication_id();
        /* decapculate tunnel header */
        process_tunnel_decap();
        /* rewrite info */
        process_rewrite();
        /* encapsulate tunnel header */
        process_tunnel_rewrite();
        /* rewrite smac, dmac */
        process_mac_rewrite();
        /* port pruning */
        process_prune();
        /* vlan translation */
        process_vlan_xlate();
        /* egress system acl */
        process_egress_system_acl();
        /* cpu rewrite */
        process_cpu_rewrite();
    }
}
