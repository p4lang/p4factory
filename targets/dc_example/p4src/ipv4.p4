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
 * ipv4 Metadata
 */
header_type ipv4_metadata_t {
    fields {
        lkp_ipv4_sa : 32;                      /* ipv4 source address */
        lkp_ipv4_da : 32;                      /* ipv4 destination address*/
        ipv4_unicast_enabled : 1;              /* is ipv4 unicast routing enabled on BD */
    }
}

metadata ipv4_metadata_t ipv4_metadata;

/* VALIDATE_OUTER_IPV4_CONTROL_BLOCK */
action set_valid_outer_ipv4_packet() {
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
    modify_field(ipv4_metadata.lkp_ipv4_sa, ipv4.srcAddr);
    modify_field(ipv4_metadata.lkp_ipv4_da, ipv4.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto, ipv4.protocol);
    modify_field(l3_metadata.lkp_ip_tc, ipv4.diffserv);
    modify_field(l3_metadata.lkp_ip_ttl, ipv4.ttl);
    modify_field(l3_metadata.l3_length, ipv4.totalLen);
}

action set_malformed_outer_ipv4_packet() {
}

/*
 * Table: Validate ipv4 packet
 * Lookup: Ingress
 * Validate and extract ipv4 header
 */
table validate_outer_ipv4_packet {
    reads {
        ipv4.version : exact;
        ipv4.ihl : exact;
        ipv4.ttl : exact;
        ipv4.srcAddr : ternary;
        ipv4.dstAddr : ternary;
    }
    actions {
        set_valid_outer_ipv4_packet;
        set_malformed_outer_ipv4_packet;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}

control validate_outer_ipv4_header {
    apply(validate_outer_ipv4_packet);
}

/* IPV4_FIB_CONTROL_BLOCK */
/*
 * Actions are defined in l3.p4 since they are
 * common for both ipv4 and ipv6
 */
 
/*
 * Table: Ipv4 LPM Lookup
 * Lookup: Ingress
 * Ipv4 route lookup for longest prefix match entries
 */
table ipv4_fib_lpm {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_da : lpm;
    }
    actions {
        fib_hit_nexthop;
        fib_hit_ecmp;
    }
    size : IPV4_LPM_TABLE_SIZE;
}

/*
 * Table: Ipv4 Host Lookup
 * Lookup: Ingress
 * Ipv4 route lookup for /32 entries
 */
table ipv4_fib {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_da : exact;
    }
    actions {
        on_miss;
        fib_hit_nexthop;
        fib_hit_ecmp;
    }
    size : IPV4_HOST_TABLE_SIZE;
}

control process_ipv4_fib {
    /* fib lookup */
    apply(ipv4_fib) {
        on_miss {
            apply(ipv4_fib_lpm);
        }
    }
}
