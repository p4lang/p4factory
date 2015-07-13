#include "includes/p4features.h"
#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/sizes.p4"
#include "includes/defines.p4"
#include "includes/intrinsic.p4"

/* METADATA */
header_type ingress_metadata_t {
    fields {
        ifindex : IFINDEX_BIT_WIDTH;           /* input interface index - MSB bit lag*/
        egress_ifindex : IFINDEX_BIT_WIDTH;    /* egress interface index */
        port_type : 2;                         /* ingress port type */

        outer_bd : BD_BIT_WIDTH;               /* outer BD */
        bd : BD_BIT_WIDTH;                     /* BD */

        drop_reason : 8;                       /* drop reason */
        control_frame: 1;                      /* control frame */
        ingress_bd : 16;                       /* ingress_bd */
        ingress_ifindex : 16;                  /* source interface id */
    }
}

header_type egress_metadata_t {
    fields {
        port_type : 2;                         /* egress port type */
        payload_length : 16;                   /* payload length for tunnels */
        smac_idx : 9;                          /* index into source mac table */
        bd : BD_BIT_WIDTH;                     /* egress inner bd */
        outer_bd : BD_BIT_WIDTH;               /* egress inner bd */
        mac_da : 48;                           /* final mac da */
        routed : 1;                            /* is this replica routed */
        same_bd_check : BD_BIT_WIDTH;          /* ingress bd xor egress bd */

        drop_reason : 8;                       /* drop reason */
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
#include "fabric.p4"
#include "egress_filter.p4"

action nop() {
}

action on_miss() {
}

control ingress {

    /* input mapping - derive an ifindex */
    process_ingress_port_mapping();

    /* process outer packet headers */
    process_validate_outer_header();

    if (ingress_metadata.port_type == PORT_TYPE_NORMAL) {

        /* storm control */
        process_storm_control();

        /* derive bd */
        process_port_vlan_mapping();

        /* spanning tree state checks */
        process_spanning_tree();

        /* IPSG */
        process_ip_sourceguard();

        /* tunnel termination processing */
        process_tunnel();

#ifndef TUNNEL_DISABLE
        if ((security_metadata.storm_control_color != STORM_CONTROL_COLOR_RED)
            and
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
        process_fwd_results();

        /* ecmp/nexthop lookup */
        process_nexthop();

        /* update statistics */
        process_ingress_bd_stats();

        /* resolve final egress port for unicast traffic */
        process_lag();

        /* generate learn notify digest if permitted */
        process_mac_learning();
    } else {
        /* ingress fabric processing */
        process_ingress_fabric();
    }

    /* resolve fabric port to destination device */
    process_fabric_lag();

    /* compute hashes for multicast packets */
    process_multicast_hashes();

    /* system acls */
    process_system_acl();
}

control egress {

    /* multi-destination replication */
    process_replication();

    /* determine egress port properties */
    apply(egress_port_mapping) {
        egress_port_type_normal {
            /* strip vlan header */
            process_vlan_decap();

            /* perform tunnel decap */
            process_tunnel_decap();

            /* egress bd properties */
            process_egress_bd();

            /* apply nexthop_index based packet rewrites */
            process_rewrite();

            /* rewrite source/destination mac if needed */
            process_mac_rewrite();
        }
    }

    /* perform tunnel encap */
    process_tunnel_encap();

    if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
        /* egress mtu checks */
        process_mtu();

        /* egress vlan translation */
        process_vlan_xlate();
    }

    /* egress filter */
    process_egress_filter();

    /* apply egress acl */
    process_egress_acl();
}
