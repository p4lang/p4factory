"""
Openflow tests on an l2 table
"""
import sys
import os
import time


import logging
from oftest import config
import oftest.base_tests as base_tests
import ofp

from oftest.testutils import *
from oftest.parse import parse_mac

import openflow_base_tests

from utils import *

from p4_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *

sys.path.append(os.path.join(sys.path[0], '..', '..', '..', '..',
                             'targets', 'switch', 'openflow_mapping')) 
from l2 import *

### TODO: generate expected packets

#######################
# SOME OPENFLOW UTILS # 
#######################

# common shorthands
flow_add          = ofp.message.flow_add
flow_delete       = ofp.message.flow_delete
group_add         = ofp.message.group_add
group_mod         = ofp.message.group_mod
group_delete      = ofp.message.group_delete
table_stats_req   = ofp.message.table_stats_request
table_stats_reply = ofp.message.table_stats_reply
packet_in         = ofp.message.packet_in
packet_out        = ofp.message.packet_out
buf               = ofp.OFP_NO_BUFFER

# dmac table fields
eth_dst_addr = "l2_metadata_lkp_mac_da"
ingress_vlan = "ingress_metadata_bd"

TEST_ETH_DST = "00:01:02:03:04:05"
TEST_VLAN = 3

def get_oxm(field_obj):
    """
    Returns an oxm and an arg-dict for updating an arg-list to
    simple_tcp_packet
    """
    if field_obj.field == "OFPXMT_OFB_VLAN_VID":
        return (ofp.oxm.vlan_vid(field_obj.testval),
            {"vlan_vid": field_obj.testval, "dl_vlan_enable": True})
    elif field_obj.field == "OFPXMT_OFB_ETH_DST":
        return (ofp.oxm.eth_dst(parse_mac(field_obj.testval)),
            {"eth_dst": field_obj.testval})

def get_match(match_fields):
    """
    Returns a packet and an OXM list that the packet matches,
    according to match_fields.
    """
    match, args = ofp.match(), {}
    for _, field_obj in match_fields.items():
        oxm, pkt_arg = get_oxm(field_obj)
        match.oxm_list.append(oxm)
        args.update(pkt_arg)
    return (str(simple_tcp_packet(**args)), match)

def get_action(action, arg):
    if action == "OUTPUT":
        ofpaction = ofp.action.output(arg, ofp.OFPCML_NO_BUFFER)
    elif action == "PUSH_MPLS":
        ofpaction = ofp.action.push_mpls()
    elif action == "SET_MPLS_TTL":
        ofpaction = ofp.action.set_mpls_ttl(arg)
    elif action == "DEC_MPLS_TTL":
        ofpaction = ofp.action.dec_mpls_ttl()
    elif action == "POP_MPLS":
        ofpaction = ofp.action.pop_mpls()
    elif action == "SET_FIELD":
        oxm, _ = get_oxm(arg)
        ofpaction = ofp.action.set_field(oxm)
    elif action == "PUSH_VLAN":
        ofpaction = ofp.action.push_vlan()
    elif action == "GROUP":
        ofpaction = ofp.action.group(arg)
    elif action == "SET_NW_TTL":
        ofpaction = ofp.action.set_nw_ttl(arg)
    else: 
        logging.info("No get_action for %s", action)
        exit(1)
    return ofpaction

def get_apply_actions(actions):
    """
    Returns a 1 element list of APPLY_ACTIONS instructions,
    with actions specified in actions.
    """
    instruction = ofp.instruction.apply_actions()
    for action, arg in actions.items():
        instruction.actions.append(get_action(action, arg))
    return [instruction]

def get_group_all(gid, action_sets):
    buckets = []
    for b in action_sets:
        buckets.append(ofp.bucket(actions=[get_action(a, arg) for a, arg in b.items()]))
    return group_add(group_type=ofp.OFPGT_ALL, group_id=gid, buckets=buckets)

def get_group_mod(gid, action_sets):
    buckets = []
    for b in action_sets:
        buckets.append(ofp.bucket(actions=[get_action(a, arg) for a, arg in b.items()]))
    return group_mod(group_type=ofp.OFPGT_ALL, group_id=gid, buckets=buckets)

##############################
# TABLE/TEST SETUP FUNCTIONS #
##############################

def setup_default_table_configurations(client, sess_hdl, dev_tgt):
    ifindex = 1
    action_spec = dc_set_bd_action_spec_t(
                            action_bd=TEST_VLAN,
                            action_vrf=0,
                            action_rmac_group=0,
                            action_ipv4_unicast_enabled=True,
                            action_ipv6_unicast_enabled=False,
                            action_bd_label=0,
                            action_igmp_snooping_enabled=0,
                            action_mld_snooping_enabled=0,
                            action_ipv4_urpf_mode=0,
                            action_ipv6_urpf_mode=0,
                            action_stp_group=0,
                            action_stats_idx=0)
    
    mbr_hdl = client.bd_action_profile_add_member_with_set_bd(
                            sess_hdl, dev_tgt,
                            action_spec)
    match_spec = dc_port_vlan_mapping_match_spec_t(
                            ingress_metadata_ifindex=ifindex,
                            vlan_tag__0__valid=True,
                            vlan_tag__0__vid=TEST_VLAN,
                            vlan_tag__1__valid=0,
                            vlan_tag__1__vid=0)
    client.port_vlan_mapping_add_entry(
                            sess_hdl, dev_tgt,
                            match_spec, mbr_hdl)

def setup_pre(mc, sess_hdl, dev_tgt):
    mgrp_hdl = mc.mc_mgrp_create(sess_hdl, dev_tgt.dev_id, 1)
    port_map = [0] * 32
    lag_map = [0] * 32
    # port 1, port 2, port 3
    port_map[0] = (1 << 1) | (1 << 2) | (1 << 3)
    node_hdl = mc.mc_node_create(sess_hdl, dev_tgt.dev_id, 0,
                                 bytes_to_string(port_map),
                                 bytes_to_string(lag_map))
    mc.mc_associate_node(sess_hdl, dev_tgt.dev_id, mgrp_hdl, node_hdl)

def setup(self):
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        setup_default_table_configurations(self.client, sess_hdl, dev_tgt)
        setup_pre(self.mc, sess_hdl, dev_tgt)

##############
# TEST CASES #
##############

class Output(openflow_base_tests.OFTestInterface):
    """
    Forwards matching packet.
    """
    def __init__(self):
        openflow_base_tests.OFTestInterface.__init__(self, "dc")

    def runTest(self):
        setup(self)

        ports = sorted(config["port_map"].keys())
        table, out_port = openflow_tables["dmac"], ports[0]

        table.match_fields[eth_dst_addr].testval = TEST_ETH_DST 
        table.match_fields[ingress_vlan].testval = TEST_VLAN
        pkt, match = get_match(table.match_fields)

        output = {
            "OUTPUT": out_port
        }

        instr = get_apply_actions(output)
        req = flow_add(table_id=table.id, match=match, instructions=instr,
                       buffer_id=buf, priority=1, cookie=41)

        exp_pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=TEST_VLAN,
                                    eth_dst=TEST_ETH_DST)
        
        self.controller.message_send(req)
        do_barrier(self.controller)
        self.dataplane.send(ports[0], pkt)
        verify_packet(self, exp_pkt, out_port)

        req = flow_delete(cookie=41, table_id=0)
        self.controller.message_send(req)
        do_barrier(self.controller)

class NWTTL(openflow_base_tests.OFTestInterface):
    """
    Sets ttl of matching packet.
    """
    def __init__(self):
        openflow_base_tests.OFTestInterface.__init__(self, "dc")

    def runTest(self):
        setup(self)

        ttl, ports = 0x37, sorted(config["port_map"].keys())
        table, out_port = openflow_tables["dmac"], ports[2]
        table.match_fields[eth_dst_addr].testval = TEST_ETH_DST
        table.match_fields[ingress_vlan].testval = TEST_VLAN
        pkt, match = get_match(table.match_fields)

        nw = {
            "OUTPUT": out_port,
            "SET_NW_TTL" : ttl
        }

        instr = get_apply_actions(nw)
        req = flow_add(table_id=table.id, match=match, instructions=instr,
                       buffer_id=buf, priority=2, cookie=42)

        exp_pkt = str(simple_tcp_packet(ip_ttl=ttl, dl_vlan_enable=True,
            vlan_vid=TEST_VLAN, eth_dst=TEST_ETH_DST))

        self.controller.message_send(req)
        do_barrier(self.controller)
        self.dataplane.send(ports[0], pkt)
        verify_packets(self, exp_pkt, [out_port])

        req = flow_delete(cookie=42, table_id=0)
        self.controller.message_send(req)
        do_barrier(self.controller)

class GroupAdd(openflow_base_tests.OFTestInterface):
    """
    Create a group that pushes a vlan, sets vlan id
    and forwards out a port
    """
    def __init__(self):
        openflow_base_tests.OFTestInterface.__init__(self, "dc")

    def runTest(self):
        setup(self)

        group_id, ports = (1 << 24) + 4, sorted(config["port_map"].keys())
        outport1, outport2 = ports[0], ports[1]

        bucket1 = {
            "PUSH_VLAN": None,
            "SET_FIELD": OFMatchField("OFPXMT_OFB_VLAN_VID", val=10),
            "OUTPUT"   : outport1
        }

        bucket2 = {
            "PUSH_VLAN": None,
            "SET_FIELD": OFMatchField("OFPXMT_OFB_VLAN_VID", val=19),
            "OUTPUT"   : outport2
        }

        req = get_group_all(group_id, [bucket1, bucket2])
        self.controller.message_send(req)
        do_barrier(self.controller)

        table = openflow_tables["dmac"]
        table.match_fields[eth_dst_addr].testval = TEST_ETH_DST
        table.match_fields[ingress_vlan].testval = TEST_VLAN
        pkt, match = get_match(table.match_fields)

        groupall = {
            "GROUP": group_id
        }

        instr = get_apply_actions (groupall)
        req = flow_add(table_id=table.id, match=match, instructions=instr,
                       buffer_id=buf, priority=3, cookie=43)

        exp_pkt1 = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=10,
            eth_dst=TEST_ETH_DST)
        exp_pkt2 = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=19,
            eth_dst=TEST_ETH_DST)

        self.controller.message_send(req)
        do_barrier(self.controller)
        self.dataplane.send(ports[0], pkt)
        verify_packet(self, exp_pkt1, outport1)
        verify_packet(self, exp_pkt2, outport2)

        req = flow_delete(cookie=43, table_id=0)
        self.controller.message_send(req)
        do_barrier(self.controller)

        req = group_delete(group_type=ofp.OFPGT_ALL, group_id=(1 << 24) + 4)
        self.controller.message_send(req)
        do_barrier(self.controller)

class GroupMod(openflow_base_tests.OFTestInterface):
    """
    Modifies the group created in GroupAdd, then verifies.
    This test must be run after GroupAdd.
    """
    def __init__(self):
        openflow_base_tests.OFTestInterface.__init__(self, "dc")

    def runTest(self):
        setup(self)

        group_id, ports = (1 << 24) + 9, sorted(config["port_map"].keys())
        outport1, outport2 = ports[0], ports[1]

        bucket1 = {
            "PUSH_VLAN": None,
            "SET_FIELD": OFMatchField("OFPXMT_OFB_VLAN_VID", val=6),
            "OUTPUT"   : outport1
        }

        bucket2 = {
            "PUSH_VLAN": None,
            "SET_FIELD": OFMatchField("OFPXMT_OFB_VLAN_VID", val=4),
            "OUTPUT"   : outport2
        }

        req = get_group_all(group_id, [bucket1, bucket2])
        self.controller.message_send(req)
        do_barrier(self.controller)

        table = openflow_tables["dmac"]
        table.match_fields[eth_dst_addr].testval = TEST_ETH_DST
        table.match_fields[ingress_vlan].testval = TEST_VLAN
        pkt, match = get_match(table.match_fields)

        groupall = {
            "GROUP": group_id
        }

        instr = get_apply_actions (groupall)
        req = flow_add(table_id=table.id, match=match, instructions=instr,
                       buffer_id=buf, priority=3, cookie=44)

        exp_pkt1 = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=6,
            eth_dst=TEST_ETH_DST)
        exp_pkt2 = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=4,
            eth_dst=TEST_ETH_DST)

        self.controller.message_send(req)
        do_barrier(self.controller)
        self.dataplane.send(ports[0], pkt)
        verify_packet(self, exp_pkt1, outport1)
        verify_packet(self, exp_pkt2, outport2)

        outport1, outport2, outport3 = ports[1], ports[2], ports[3]

        bucket1 = {
            "SET_NW_TTL": 7,
            "OUTPUT": outport1
        }

        bucket2 = {
            "SET_NW_TTL": 17,
            "OUTPUT": outport2
        }

        bucket3 = {
            "SET_NW_TTL": 27,
            "OUTPUT": outport3
        }

        req = get_group_mod(group_id, [bucket1, bucket2, bucket3])
        self.controller.message_send(req)
        do_barrier(self.controller)

        exp_pkt1 = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=TEST_VLAN,
            ip_ttl=7, eth_dst=TEST_ETH_DST)
        exp_pkt2 = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=TEST_VLAN,
            ip_ttl=17, eth_dst=TEST_ETH_DST)
        exp_pkt3 = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=TEST_VLAN,
            ip_ttl=27, eth_dst=TEST_ETH_DST)

        self.dataplane.send(ports[0], pkt)
        verify_packet(self, exp_pkt1, outport1)
        verify_packet(self, exp_pkt2, outport2)
        verify_packet(self, exp_pkt3, outport3)

        req = flow_delete(cookie=44, table_id=0)
        self.controller.message_send(req)
        do_barrier(self.controller)

        req = group_delete(group_type=ofp.OFPGT_ALL, group_id=(1 << 24) + 9)
        self.controller.message_send(req)
        do_barrier(self.controller)

class TableStatsGet(openflow_base_tests.OFTestInterface):
    """
    """
    def __init__(self):
        openflow_base_tests.OFTestInterface.__init__(self, "dc")

    def runTest(self):
        setup(self)
        ports = sorted(config["port_map"].keys())
        out_port = ports[0]

        table = openflow_tables["dmac"]
        table.match_fields[eth_dst_addr].testval = TEST_ETH_DST 
        table.match_fields[ingress_vlan].testval = TEST_VLAN
        hit_pkt, match = get_match(table.match_fields)

        output = {
            "OUTPUT": out_port
        }

        instr = get_apply_actions(output)
        req = flow_add(table_id=table.id, match=match, instructions=instr,
                       buffer_id=buf, priority=1, cookie=45)
        self.controller.message_send(req)
        do_barrier(self.controller)

        num_hit_packets = 10
        for _ in xrange(num_hit_packets):
            self.dataplane.send(ports[0], hit_pkt)

        miss_pkt = str(simple_tcp_packet(eth_dst="00:77:22:55:99:11",
                       dl_vlan_enable=True, vlan_vid=3))

        num_miss_packets = 7
        for _ in xrange(num_miss_packets):
            self.dataplane.send(ports[0], miss_pkt)

        req = table_stats_req()
        self.controller.message_send(req)
        do_barrier(self.controller)

        entry = ofp.common.table_stats_entry(lookup_count=num_miss_packets + num_hit_packets,
                                       matched_count=num_hit_packets)
        reply = table_stats_reply(entries=[entry])
        verify_packets(self, reply, [6653])

        req = flow_delete(cookie=45, table_id=0)
        self.controller.message_send(req)
        do_barrier(self.controller)

class PacketIn(openflow_base_tests.OFTestInterface):
    """
    """
    def __init__(self):
        openflow_base_tests.OFTestInterface.__init__(self, "dc")

    def runTest(self):
        setup(self)

        ports = sorted(config["port_map"].keys())
        in_port = ports[0]

        table = openflow_tables["dmac"]
        table.match_fields[eth_dst_addr].testval = TEST_ETH_DST
        table.match_fields[ingress_vlan].testval = TEST_VLAN
        pkt, match = get_match(table.match_fields)

        output = {
            "OUTPUT": ofp.const.OFPP_CONTROLLER 
        }

        instr = get_apply_actions(output)
        req = flow_add(table_id=table.id, match=match, instructions=instr,
                       buffer_id=buf, priority=1, cookie=46)
        self.controller.message_send(req)
        do_barrier(self.controller)

        self.dataplane.send(in_port, pkt)
        verify_packet_in(self, str(pkt), in_port, ofp.const.OFPR_ACTION,
                         controller=self.controller)

        req = flow_delete(cookie=46, table_id=0)
        self.controller.message_send(req)
        do_barrier(self.controller)

