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

header_type multicast_metadata_t {
    fields {
        ip_multicast : 1;                      /* packet is ip multicast */
        igmp_snooping_enabled : 1;             /* is IGMP snooping enabled on BD */
        mld_snooping_enabled : 1;              /* is MLD snooping enabled on BD */
        multicast_route_mc_index : 16;         /* multicast index from mfib */
        multicast_bridge_mc_index : 16;        /* multicast index from igmp/mld snoop */
    }
}

metadata multicast_metadata_t multicast_metadata;

#ifndef MULTICAST_DISABLE
action outer_replica_from_rid(bd, nexthop_index) {
    modify_field(ingress_metadata.egress_bd, bd);
    modify_field(egress_metadata.replica, TRUE);
    modify_field(egress_metadata.inner_replica, FALSE);
    modify_field(l3_metadata.nexthop_index, nexthop_index);
    bit_xor(egress_metadata.same_bd_check, bd, ingress_metadata.outer_bd);
}

action inner_replica_from_rid(bd, nexthop_index) {
    modify_field(ingress_metadata.egress_bd, bd);
    modify_field(egress_metadata.replica, TRUE);
    modify_field(egress_metadata.inner_replica, TRUE);
    modify_field(egress_metadata.routed, l3_metadata.routed);
    modify_field(l3_metadata.nexthop_index, nexthop_index);
    bit_xor(egress_metadata.same_bd_check, bd, ingress_metadata.bd);
}

table rid {
    reads {
        intrinsic_metadata.replication_id : exact;
    }
    actions {
        nop;
        outer_replica_from_rid;
        inner_replica_from_rid;
    }
    size : RID_TABLE_SIZE;
}

action set_replica_copy_bridged() {
    modify_field(egress_metadata.routed, FALSE);
}

table replica_type {
    reads {
        egress_metadata.replica : exact;
        egress_metadata.same_bd_check : ternary;
    }
    actions {
        nop;
        set_replica_copy_bridged;
    }
    size : REPLICA_TYPE_TABLE_SIZE;
}
#endif

control process_replication {
#ifndef MULTICAST_DISABLE
    if(intrinsic_metadata.replication_id != 0) {
        /* set info from rid */
        apply(rid);

        /*  routed or bridge replica */
        apply(replica_type);
    }
#endif /* MULTICAST_DISABLE */
}

