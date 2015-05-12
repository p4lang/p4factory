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
 * L3 Metadata
 */

 header_type l3_metadata_t {
     fields {
        lkp_ip_type : 2;
        lkp_ip_proto : 8;
        lkp_ip_tc : 8;
        lkp_ip_ttl : 8;
        rmac_group : 10;                       /* Rmac group, for rmac indirection */
        rmac_hit : 1;                          /* dst mac is the router's mac */
        urpf_mode : 2;                         /* urpf mode for current lookup */
        urpf_hit : 1;                          /* hit in urpf table */
        urpf_check_fail :1;                    /* urpf check failed */
        urpf_bd_group : BD_BIT_WIDTH;          /* urpf bd group */
        fib_hit : 1;                           /* fib hit */
        fib_nexthop : 16;                      /* next hop from fib */
        fib_nexthop_type : 1;                  /* ecmp or nexthop */
        routed : 1;                            /* is packet routed */
        nexthop_index : 16;                    /* final next hop index */
     }
 }

 metadata l3_metadata_t l3_metadata;

action fib_hit_nexthop(nexthop_index) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.fib_nexthop, nexthop_index);
    modify_field(l3_metadata.fib_nexthop_type, NEXTHOP_TYPE_SIMPLE);
}

action fib_hit_ecmp(ecmp_index) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.fib_nexthop, ecmp_index);
    modify_field(l3_metadata.fib_nexthop_type, NEXTHOP_TYPE_ECMP);
}

action rmac_hit() {
    modify_field(l3_metadata.rmac_hit, TRUE);
    modify_field(ingress_metadata.egress_ifindex, CPU_PORT_ID);
    modify_field(intrinsic_metadata.eg_mcast_group, 0);
}

action rmac_miss() {
    modify_field(l3_metadata.rmac_hit, FALSE);
}

table rmac {
    reads {
        l3_metadata.rmac_group : exact;
        l2_metadata.lkp_mac_da : exact;
    }
    actions {
        rmac_hit;
        rmac_miss;
    }
    size : ROUTER_MAC_TABLE_SIZE;
}

#if !defined(L3_DISABLE) && !defined(URPF_DISABLE)
action urpf_bd_miss() {
    modify_field(l3_metadata.urpf_check_fail, TRUE);
}

action urpf_miss() {
    modify_field(l3_metadata.urpf_check_fail, TRUE);
}

table urpf_bd {
    reads {
        l3_metadata.urpf_bd_group : exact;
        ingress_metadata.bd : exact;
    }
    actions {
        nop;
        urpf_bd_miss;
    }
    size : URPF_GROUP_TABLE_SIZE;
}
#endif /* L3_DISABLE && URPF_DISABLE */

control process_urpf_bd {
#if !defined(L3_DISABLE) && !defined(URPF_DISABLE)
    if ((l3_metadata.urpf_mode == URPF_MODE_STRICT) and
        (l3_metadata.urpf_hit == TRUE)) {
        apply(urpf_bd);
    }
#endif /* L3_DISABLE && URPF_DISABLE */
}

#if !defined(L3_DISABLE) && !defined(MTU_DISABLE)
action mtu_check_pass() {
}

action mtu_check_fail() {
    modify_field(egress_metadata.drop_exception, 1);
}

table mtu {
    reads {
        egress_metadata.bd : exact;
        ethernet.etherType : exact;
        //standard_metadata.packet_length : range;
    }
    actions {
        nop;
        mtu_check_pass;
        mtu_check_fail;
    }
    size : IP_MTU_TABLE_SIZE;
}
#endif /* L3_DISABLE && MTU_DISABLE */

control process_mtu {
#if !defined(L3_DISABLE) && !defined(MTU_DISABLE)
    apply(mtu);
#endif /* L3_DISABLE && MTU_DISABLE */
}
