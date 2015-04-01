// This is P4 sample source for __PROJECT_NAME__
// Fill in these files with your P4 code

#include "includes/headers.p4"
#include "includes/parser.p4"

action set_egr(egress_spec) {
    modify_field(standard_metadata.egress_spec, egress_spec);
}

action _drop() {
    drop();
}

table forward {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {
        set_egr;
    }
}

table acl {
    reads {
        ethernet.dstAddr : ternary;
        ethernet.srcAddr : ternary;
    }
    actions {
        _drop;
    }
}

control ingress {
    apply(forward);
}

control egress {
    apply(acl);
}
