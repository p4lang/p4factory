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

#include "headers.p4"
#include "parser.p4"

#define PORT_VLAN_TABLE_SIZE                   32768
#define BD_TABLE_SIZE                          65536
#define IPV4_LPM_TABLE_SIZE                    16384
#define IPV4_HOST_TABLE_SIZE                   131072
#define NEXTHOP_TABLE_SIZE                     32768
#define REWRITE_MAC_TABLE_SIZE                 32768

#define VRF_BIT_WIDTH                          12
#define BD_BIT_WIDTH                           16
#define IFINDEX_BIT_WIDTH                      10

/* METADATA */
header_type ingress_metadata_t {
    fields {
        vrf : VRF_BIT_WIDTH;                   /* VRF */
        bd : BD_BIT_WIDTH;                     /* ingress BD */
        nexthop_index : 16;                    /* final next hop index */
    }
}

metadata ingress_metadata_t ingress_metadata;

action on_miss() {
}

action set_bd(bd) {
    modify_field(ingress_metadata.bd, bd);
}

table port_mapping {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        set_bd;
    }
    size : PORT_VLAN_TABLE_SIZE;
}

action set_vrf(vrf) {
    modify_field(ingress_metadata.vrf, vrf);
}

table bd {
    reads {
        ingress_metadata.bd : exact;
    }
    actions {
        set_vrf;
    }
    size : BD_TABLE_SIZE;
}

action fib_hit_nexthop(nexthop_index) {
    modify_field(ingress_metadata.nexthop_index, nexthop_index);
    subtract_from_field(ipv4.ttl, 1);
}

table ipv4_fib {
    reads {
        ingress_metadata.vrf : exact;
        ipv4.dstAddr : exact;
    }
    actions {
        on_miss;
        fib_hit_nexthop;
    }
    size : IPV4_HOST_TABLE_SIZE;
}

table ipv4_fib_lpm {
    reads {
        ingress_metadata.vrf : exact;
        ipv4.dstAddr : lpm;
    }
    actions {
        on_miss;
        fib_hit_nexthop;
    }
    size : IPV4_LPM_TABLE_SIZE;
}

action set_egress_details(egress_spec) {
    modify_field(standard_metadata.egress_spec, egress_spec);
}

table nexthop {
    reads {
        ingress_metadata.nexthop_index : exact;
    }
    actions {
        on_miss;
        set_egress_details;
    }
    size : NEXTHOP_TABLE_SIZE;
}

control ingress {
    if (valid(ipv4)) {
        /* derive ingress_metadata.bd */
        apply(port_mapping);

        /* derive ingress_metadata.vrf */
        apply(bd);

        /* fib lookup, set ingress_metadata.nexthop_index */
        apply(ipv4_fib) {
            on_miss {
                apply(ipv4_fib_lpm);
            }
        }

        /* derive standard_metadata.egress_spec from ingress_metadata.nexthop_index */
        apply(nexthop);
    }
}

action rewrite_src_dst_mac(smac, dmac) {
    modify_field(ethernet.srcAddr, smac);
    modify_field(ethernet.dstAddr, dmac);
}

table rewrite_mac {
    reads {
        ingress_metadata.nexthop_index : exact;
    }
    actions {
        on_miss;
        rewrite_src_dst_mac;
    }
    size : REWRITE_MAC_TABLE_SIZE;
}

control egress {
    /* set smac and dmac from ingress_metadata.nexthop_index */
    apply(rewrite_mac);
}
