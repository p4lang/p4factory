"""
Openflow tests on an l2 table
"""

import sys
import os

import logging
from oftest import config
import oftest.base_tests as base_tests
import ofp

from oftest.testutils import *
from oftest.parse import parse_mac

import openflow_base_tests

from utils import *

sys.path.append(os.path.join(sys.path[0], '..', '..', '..', '..',
                             'targets', 'l2_switch', 'build', 'thrift')) 
from p4_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *

import sys
import os
import time

sys.path.append(os.path.join(sys.path[0], '..', '..', '..', '..',
                             'targets', 'l2_switch', 'openflow_mapping')) 
from l2 import *

### TODO: generate expected packets

# common shorthands
flow_add    = ofp.message.flow_add
flow_delete = ofp.message.flow_delete
group_add   = ofp.message.group_add
group_mod   = ofp.message.group_mod
buf         = ofp.OFP_NO_BUFFER

# dmac table fields
eth_dst_addr = "ethernet_dstAddr"

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
    elif action == "GROUP":
        ofpaction = ofp.action.group(arg)
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

def setup_default_table_configurations(client, sess_hdl, dev_tgt):
    result = client.smac_set_default_action_mac_learn(sess_hdl, dev_tgt)
    assert result == 0

    result = client.dmac_set_default_action_broadcast(sess_hdl, dev_tgt)
    assert result == 0

    result = client.mcast_src_pruning_set_default_action__nop(sess_hdl, dev_tgt)
    assert result == 0

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

def repopulate_openflow_defaults(client, sess_hdl, dev_tgt):
    result = client.packet_out_set_default_action_nop(sess_hdl, dev_tgt)

    match_spec = l2_switch_packet_out_match_spec_t(
        fabric_header_packetType = 5,
        fabric_header_cpu_reserved = 1) 

    result = client.packet_out_table_add_with_packet_out_unicast(
        sess_hdl, dev_tgt, match_spec)

    match_spec = l2_switch_packet_out_match_spec_t(
        fabric_header_packetType = 5,
        fabric_header_cpu_reserved = 2) 

    result = client.packet_out_table_add_with_packet_out_eth_flood(
        sess_hdl, dev_tgt, match_spec)

    result = client.ofpat_group_egress_set_default_action_nop(
        sess_hdl, dev_tgt)

def setup(self):
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        self.client.clean_all(sess_hdl, dev_tgt)

        setup_default_table_configurations(self.client, sess_hdl, dev_tgt)
        setup_pre(self.mc, sess_hdl, dev_tgt)

        repopulate_openflow_defaults(self.client, sess_hdl, dev_tgt)

class Output(openflow_base_tests.OFTestInterface):
    """
    Fowards a packet, relies on PDSetup being run first
    """
    def __init__(self):
        openflow_base_tests.OFTestInterface.__init__(self, "l2_switch")

    def runTest(self):
        setup(self)

        ports = sorted(config["port_map"].keys())
        table, out_port = openflow_tables["dmac"], ports[1]

        table.match_fields[eth_dst_addr].testval = "00:01:02:03:04:05"
        pkt, match = get_match(table.match_fields)

        output = {
            "OUTPUT": out_port
        }

        instr = get_apply_actions(output)
        req = flow_add(table_id=table.id, match=match, instructions=instr,
                       buffer_id=buf, priority=1, cookie=41)

        exp_pkt = simple_tcp_packet()
        
        self.controller.message_send(req)
        do_barrier(self.controller)
        self.dataplane.send(ports[-1], pkt)
        verify_packet(self, exp_pkt, out_port)

        req = flow_delete(cookie=41, table_id=0)
        self.controller.message_send(req)
        do_barrier(self.controller)

class PacketIn(openflow_base_tests.OFTestInterface):
    """
    """
    def __init__(self):
        openflow_base_tests.OFTestInterface.__init__(self, "l2_switch")

    def runTest(self):
        setup(self)

        ports = sorted(config["port_map"].keys())
        in_port = ports[0]

        table = openflow_tables["dmac"]
        table.match_fields[eth_dst_addr].testval = "00:01:02:03:04:05"
        pkt, match = get_match(table.match_fields)

        output = {
            "OUTPUT": ofp.const.OFPP_CONTROLLER 
        }

        instr = get_apply_actions(output)
        req = flow_add(table_id=table.id, match=match, instructions=instr,
                       buffer_id=buf, priority=1, cookie=42)
        self.controller.message_send(req)
        do_barrier(self.controller)

        self.dataplane.send(in_port, pkt)
        verify_packet_in(self, str(pkt), in_port, ofp.const.OFPR_ACTION,
                         controller=self.controller)

        req = flow_delete(cookie=42, table_id=0)
        self.controller.message_send(req)
        do_barrier(self.controller)
