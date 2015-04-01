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
        validate_outer_ethernet_header();
        validate_outer_ipv4_header();
        port_vlan_mapping_lookup();
        spanning_tree_lookup();
        tunnel_vtep_lookup();

#ifndef TUNNEL_DISABLE
        /* perform tunnel termination */
        if ((tunnel_metadata.src_vtep_miss == FALSE) and
            (((tunnel_metadata.outer_rmac_hit == TRUE) and
              (tunnel_metadata.tunnel_terminate == TRUE)) or
             ((l2_metadata.lkp_pkt_type == L2_MULTICAST) and
              (tunnel_metadata.tunnel_terminate == TRUE)))) {
            tunnel_terminate_lookup();
        }
	    else
#endif /* TUNNEL_DISABLE */
        {
            bd_lookup();
        }

        smac_lookup_and_learn();
        ip_and_mac_acl_lookup();

        apply(rmac) {
                on_miss {
                    dmac_lookup();
                }
                default {
                    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and
                        (l3_metadata.ipv4_unicast_enabled == TRUE)) {
                        ip_racl_lookup();
                        fib_lookup();
                    }
                }
        }
        merge_results_lookup();
        nexthop_lookup();
        lag_lookup();
        system_acl_lookup();
    }
}

control egress {
    if (egress_metadata.egress_bypass == FALSE) {
        replication_id_lookup();
        tunnel_decap_lookup();
        rewrite_lookup();
        tunnel_rewrite_lookup();
        mac_rewrite_lookup();
        prune_and_xlate_lookup();
        egress_system_acl_lookup();
        cpu_rewrite_lookup();
    }
}


