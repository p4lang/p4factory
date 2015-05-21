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
 * multicast metadata
 */
header_type multicast_metadata_t {
    fields {
        l2_multicast : 1;                      /* packet is l2 multicast */
        src_is_link_local : 1;                 /* source is link local address */
        igmp_snooping_enabled : 1;             /* is IGMP snooping enabled on BD */
        mld_snooping_enabled : 1;              /* is MLD snooping enabled on BD */
        uuc_mc_index : 16;                     /* unknown unicast multicast index */
        umc_mc_index : 16;                     /* unknown multicast multicast index */
        bcast_mc_index : 16;                   /* broadcast multicast index */
        multicast_bridge_mc_index : 16;        /* multicast index from igmp/mld snoop */
        replica : 1;                           /* is this a replica */
    }
}

metadata multicast_metadata_t mcast_metadata;

/* MULTICAST_CONTROL_BLOCK */
action replica_from_rid(bd) {
    modify_field(l2_metadata.egress_bd, bd);
    modify_field(mcast_metadata.replica, TRUE);
}

/*
 * Table: Replication ID
 * Lookup: Egress
 * Replication Id is unique id derived for every multicast packet
 * Rid derives egress bd
 */
table rid {
    reads {
        intrinsic_metadata.replication_id : exact;
    }
    actions {
        nop;
        replica_from_rid;
    }
    size : RID_TABLE_SIZE;
}

control process_replication_id {
#ifndef MULTICAST_DISABLE
    if(intrinsic_metadata.replication_id != 0) {
        /* set info from rid */
        apply(rid);
    }
#endif /* MULTICAST_DISABLE */
}

