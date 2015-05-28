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

/* P4 program for rocker device */

#include "includes/rocker_p4_features.h"
#include "includes/rocker_p4_headers.p4"
#include "includes/rocker_p4_parser.p4"

#define MAC_LEARN_RECEIVER  1024 // Must be 1024 for L2 learning
#define TRUE 1

/* METADATA */
header_type ingress_metadata_t {
    fields {
        fid         : 16;
        vrf         : 10;
        l3_hit      : 1;
        rmac_id     : 4;
    }
}

metadata ingress_metadata_t ingress_metadata;

header_type intrinsic_metadata_t {
    fields {
        /* dummy           : 16; */
        lf_field_list   : 32;
    }
}

metadata intrinsic_metadata_t intrinsic_metadata;

action nop () {
}

/* vlan mapping table and actions */
action port_vlan_hit(fid, vrf, rmac_id)
{
    modify_field(ingress_metadata.fid, fid);
    /* modify_field(intrinsic_metadata.dummy, fid); */
    modify_field(ingress_metadata.vrf, vrf);
    modify_field(ingress_metadata.rmac_id, rmac_id);
}

action port_vlan_miss() {
    drop();
}
#define PORT_VLAN_TABLE_SIZE  128

table port_vlan_mapping {
    reads {
        vlan_tag     : valid;
        vlan_tag.vid : exact;
        standard_metadata.ingress_port : exact;
    }
    actions {
        port_vlan_hit; // also used for untagged packets
        port_vlan_miss;
    }
    size : PORT_VLAN_TABLE_SIZE;
}

action rmac_miss() {
    /* continue with L2 forwarding */
}

action rmac_hit() {
    /* continue with L3 forwarding */
    /* set a flag */
}

table rmac {
    reads {
        ingress_metadata.rmac_id : exact;
        ethernet.da              : exact;
    }
    actions {
        rmac_miss;
        rmac_hit;
    }
}

action ipv4_hit_nh(bd, rmac, nh_da, nh_port) {
    /* setup post routed bd, mac da,sa and port */
    modify_field(standard_metadata.egress_spec, nh_port);
    /* change L2 header */
    modify_field(ethernet.da, nh_da);
    modify_field(ethernet.sa, rmac);
    modify_field(ingress_metadata.l3_hit, TRUE);
    /* decrement TTL */
    add_to_field(ipv4.ttl, -1);
}

action ipv4_hit_ecmp () {
    drop();
}

action ipv4_glean() {
    /* send to sup */
    modify_field(standard_metadata.egress_spec, CPU_PORT);
}

action ipv4_miss() {
}

table ipv4_hrt {
    reads {
        ingress_metadata.vrf : exact;
        ipv4.dip : exact;   /* XXX LPM */
    }
    actions {
        ipv4_hit_nh;
        ipv4_hit_ecmp;  /* XXX */
        ipv4_glean;     /* send to cpu */
        ipv4_miss;
    }
}

/* dmac table and actions */
#define MAC_TABLE_SIZE  1024
action dmac_hit(port) {
    modify_field(standard_metadata.egress_spec, port);
}

action dmac_miss() {
    /* flood the packet - TBD */
    /* let linux bridge take care of flooding */
    modify_field(standard_metadata.egress_spec, CPU_PORT);
}

table dmac {
    reads {
        ingress_metadata.fid    : exact;
        ethernet.da        : exact;
    }
    actions {
        dmac_hit;
        dmac_miss;
    }
    size : MAC_TABLE_SIZE;
    support_timeout: false;
}

field_list mac_learn_digest {
    ethernet.sa;
    ingress_metadata.fid;
    standard_metadata.ingress_port;
}

/* smac table and actions */
action smac_hit() {
}

action smac_miss() {
    /* send to CPU for learning */
    generate_digest(MAC_LEARN_RECEIVER, mac_learn_digest);
}

table smac {
    reads {
        ingress_metadata.fid    : exact;
        ethernet.sa        : exact;
    }
    actions {
      smac_hit;
      smac_miss;
    }
    size : MAC_TABLE_SIZE;
    support_timeout: false;
}

// ingress processing
control ingress {
    /* derive a vlan for port, drop if vlan is not allowed on the port */
    apply(port_vlan_mapping);
    /* smac lookup
     * send notification unknown-sa (smac_miss) to CPU
     * packet will be forwarded based on IP route lookup or
     * dmac lookup result
     */
    apply(smac);
    if (valid(ipv4)) {
        apply(rmac) {
            rmac_hit {
                apply(ipv4_hrt);
            }
        }
    }
    apply(dmac);    /* L2 forwarding */
}

control egress {
    /* no processing on egress - forwarding decision is already made */
}
