/*
 * Mirror processing
 */

action set_mirror_nhop(nhop_idx) {
    modify_field(l3_metadata.nexthop_index, nhop_idx);
}

table mirror_nhop {
    reads {
        i2e_metadata.mirror_session_id : exact;
    }
    actions {
        nop;
        set_mirror_nhop;
    }
    size : MIRROR_SESSIONS_TABLE_SIZE;
}
