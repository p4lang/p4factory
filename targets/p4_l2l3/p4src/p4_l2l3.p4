// This is P4 sample source for p4_l2l3

#include "includes/p4_l2l3_features.h"
#include "includes/p4_l2l3_headers.p4"
#include "includes/p4_l2l3_parser.p4"

#define MAC_LEARN_RECEIVER  1024 // Must be 1024 for L2 learning

/* METADATA */
header_type ingress_metadata_t {
    fields {
        fid           : 16;
    }
}

metadata ingress_metadata_t ingress_metadata;

header_type intrinsic_metadata_t {
  fields {
    dummy   : 16;
    lf_field_list : 32;
  }
}

metadata intrinsic_metadata_t intrinsic_metadata;

action nop () {
}

/* vlan mapping table and actions */
action port_vlan_hit(fid)
{
    modify_field(ingress_metadata.fid, fid);
    modify_field(intrinsic_metadata.dummy, fid);
}

action port_vlan_miss() {
    drop();
}
#define PORT_VLAN_TABLE_SIZE  128

table port_vlan_mapping {
    reads {
        vlan_tag_     : valid;
        vlan_tag_.vid : exact;
        standard_metadata.ingress_port : exact;
    }
    actions {
        port_vlan_hit; // also used for untagged packets
        port_vlan_miss;
    }
    size : PORT_VLAN_TABLE_SIZE;
}

/* dmac table and actions */
#define MAC_TABLE_SIZE  1024
action dmac_hit(port) {
    modify_field(standard_metadata.egress_spec, port);
}

action dmac_miss() {
    /* flood the packet - TBD */
    /* let linux bridge take care of this */
    modify_field(standard_metadata.egress_spec, CPU_PORT);
}

table dmac {
    reads {
        ingress_metadata.fid    : exact;
        ethernet.dstAddr        : exact;
    }
    actions {
        dmac_hit;
        dmac_miss;
    }
    size : MAC_TABLE_SIZE;
    support_timeout: false;
}

field_list mac_learn_digest {
    ethernet.srcAddr;
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
        ethernet.srcAddr        : exact;
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
    /* derive a vlan for port drop if vlan is not allowed on the port */
    apply(port_vlan_mapping);
    /* Add router-mac check here for doing route-lookups */
    apply(dmac);    /* L2 forwarding */
    /* perform smac lookup,
     * send notification unknown-sa (smac_miss) to CPU
     * packet is forwarded based on dmac lookup result
     */
    apply(smac);
}

control egress {
    /* no processing on egress - forwarding decision is already made */
}
