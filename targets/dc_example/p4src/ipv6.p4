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
 * ipv6 Metadata
 */
header_type ipv6_metadata_t {
    fields {
        lkp_ipv6_sa : 128;                     /* ipv6 source address */
        lkp_ipv6_da : 128;                     /* ipv6 destination address*/
        ipv6_unicast_enabled : 1;              /* is ipv6 unicast routing enabled on BD */
    }
}

metadata ipv6_metadata_t ipv6_metadata;

/* VALIDATE_OUTER_IPV6_CONTROL_BLOCK */
action set_valid_outer_ipv6_packet() {
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
    modify_field(ipv6_metadata.lkp_ipv6_sa, ipv6.srcAddr);
    modify_field(ipv6_metadata.lkp_ipv6_da, ipv6.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto, ipv6.nextHdr);
    modify_field(l3_metadata.lkp_ip_tc, ipv6.trafficClass);
    modify_field(l3_metadata.lkp_ip_ttl, ipv6.hopLimit);
}

action set_malformed_outer_ipv6_packet() {
}

/*
 * Table: Validate ipv6 packet
 * Lookup: Ingress
 * Validate and extract ipv6 header
 */
table validate_outer_ipv6_packet {
    reads {
        ipv6.version : exact;
        ipv6.hopLimit : exact;
        ipv6.srcAddr : ternary;
        ipv6.dstAddr : ternary;
    }
    actions {
        set_valid_outer_ipv6_packet;
        set_malformed_outer_ipv6_packet;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}

control validate_outer_ipv6_header {
#ifndef IPV6_DISABLE
    apply(validate_outer_ipv6_packet);
#endif /* IPV6_DISABLE */
}

/* IPV6_FIB_CONTROL_BLOCK */
/*
 * Actions are defined in l3.p4 since they are
 * common for both ipv4 and ipv6
 */
 
/*
 * Table: Ipv6 LPM Lookup
 * Lookup: Ingress
 * Ipv6 route lookup for longest prefix match entries
 */
table ipv6_fib_lpm {
    reads {
        l3_metadata.vrf : exact;
        ipv6_metadata.lkp_ipv6_da : lpm;
    }
    actions {
        on_miss;
        fib_hit_nexthop;
        fib_hit_ecmp;
    }
    size : IPV6_LPM_TABLE_SIZE;
}

/*
 * Table: Ipv6 Host Lookup
 * Lookup: Ingress
 * Ipv6 route lookup for /128 entries
 */
table ipv6_fib {
    reads {
        l3_metadata.vrf : exact;
        ipv6_metadata.lkp_ipv6_da : exact;
    }
    actions {
        on_miss;
        fib_hit_nexthop;
        fib_hit_ecmp;
    }
    size : IPV6_HOST_TABLE_SIZE;
}

control process_ipv6_fib {
#ifndef IPV6_DISABLE
    /* fib lookup */
    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and
        (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
        apply(ipv6_fib) {
            on_miss {
                apply(ipv6_fib_lpm);
            }
        }
    }
#endif /* IPV6_DISABLE */
}
