//uncomment to enable openflow
//#define OPENFLOW_ENABLE

#ifdef OPENFLOW_ENABLE
    #include "openflow.p4"
#endif /* OPENFLOW_ENABLE */

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type intrinsic_metadata_t {
    fields {
        mcast_grp : 4;
        egress_rid : 4;
        mcast_hash : 16;
        lf_field_list: 32;
    }
}

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;
metadata intrinsic_metadata_t intrinsic_metadata;

parser parse_ethernet {
    extract(ethernet);
#ifdef OPENFLOW_ENABLE
    return select(latest.etherType) {
        ETHERTYPE_BF_FABRIC : fabric_header;
        default : ingress;
    }
#else
    return ingress;
#endif /* OPENFLOW_ENABLE */
}

action _drop() {
    drop();
}

action _nop() {
}

#define MAC_LEARN_RECEIVER 1024

field_list mac_learn_digest {
    ethernet.srcAddr;
    standard_metadata.ingress_port;
}

action mac_learn() {
    generate_digest(MAC_LEARN_RECEIVER, mac_learn_digest);
}

table smac {
    reads {
        ethernet.srcAddr : exact;
    }
    actions {mac_learn; _nop;}
    size : 512;
}

action forward(port) {
    modify_field(standard_metadata.egress_spec, port);
}

action broadcast() {
    modify_field(intrinsic_metadata.mcast_grp, 1);
}

table dmac {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {
        forward;
        broadcast;
#ifdef OPENFLOW_ENABLE
        openflow_apply;
        openflow_miss;
#endif /* OPENFLOW_ENABLE */
    }
    size : 512;
}

table mcast_src_pruning {
    reads {
        standard_metadata.instance_type : exact;
    }
    actions {_nop; _drop;}
    size : 1;
}

control ingress {
#ifdef OPENFLOW_ENABLE
    apply(packet_out) {
        nop {
#endif /* OPENFLOW_ENABLE */
            apply(smac);
            apply(dmac);
#ifdef OPENFLOW_ENABLE
        }
    }

    process_ofpat_ingress ();
#endif /* OPENFLOW_ENABLE */
}

control egress {
    if(standard_metadata.ingress_port == standard_metadata.egress_port) {
        apply(mcast_src_pruning);
    }

#ifdef OPENFLOW_ENABLE
    process_ofpat_egress();
#endif /*OPENFLOW_ENABLE */
}
