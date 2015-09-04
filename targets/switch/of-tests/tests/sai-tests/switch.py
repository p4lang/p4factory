# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Thrift SAI interface basic tests
"""

import switch_sai_thrift

import time
import sys
import logging

import unittest
import random

import oftest.dataplane as dataplane
import sai_base_test

from oftest.testutils import *

import os

from utils import *

from switch_sai_thrift.ttypes import  *

this_dir = os.path.dirname(os.path.abspath(__file__))

switch_inited=0
port_list = []
table_attr_list = []

def verify_packet_list_any(test, pkt_list,  ofport_list):
    logging.debug("Checking for packet on given ports")
    (rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(timeout=1)
    test.assertTrue(rcv_pkt != None, "No packet received")

    i = 0
    match_found = 0
    for ofport in ofport_list:
        pkt = pkt_list[i]
        if ((str(rcv_pkt) == str(pkt)) and (ofport == rcv_port)):
            match_index = i
            match_found = 1
        i = i + 1
    test.assertTrue(match_found == 1, "Packet not received on expected port")
    return match_index

def switch_init(client):
    global switch_inited
    if switch_inited:
        return

    switch_attr_list = client.sai_thrift_get_switch_attribute()
    attr_list = switch_attr_list.attr_list
    for attribute in attr_list:
        if attribute.id == 0:
            print "max ports: " + attribute.value.u32
        elif attribute.id == 1:
            for x in attribute.value.objlist.object_id_list:
                port_list.append(x)
        else:
            print "unknown switch attribute"

    attr_value = sai_thrift_attribute_value_t(mac='00:77:66:55:44:33')
    attr = sai_thrift_attribute_t(id=22, value=attr_value)
    client.sai_thrift_set_switch_attribute(attr)
    switch_inited = 1

def sai_thrift_create_fdb(client, vlan_id, mac, port, mac_action):
    fdb_entry = sai_thrift_fdb_entry_t(mac_address=mac, vlan_id=vlan_id)
    #value 0 represents static entry, id=0, represents entry type
    fdb_attribute1_value = sai_thrift_attribute_value_t(u8=1)
    fdb_attribute1 = sai_thrift_attribute_t(id=0, value=fdb_attribute1_value)
    #value oid represents object id, id=1 represents port id
    fdb_attribute2_value = sai_thrift_attribute_value_t(oid=port)
    fdb_attribute2 = sai_thrift_attribute_t(id=1, value=fdb_attribute2_value)
    #value oid represents object id, id=1 represents port id
    fdb_attribute3_value = sai_thrift_attribute_value_t(u8=mac_action)
    fdb_attribute3 = sai_thrift_attribute_t(id=2, value=fdb_attribute3_value)
    fdb_attr_list = [fdb_attribute1, fdb_attribute2, fdb_attribute3]
    client.sai_thrift_create_fdb_entry(thrift_fdb_entry=fdb_entry, thrift_attr_list=fdb_attr_list)

def sai_thrift_delete_fdb(client, vlan_id, mac, port):
    fdb_entry = sai_thrift_fdb_entry_t(mac_address=mac, vlan_id=vlan_id)
    client.sai_thrift_delete_fdb_entry(thrift_fdb_entry=fdb_entry)

def sai_thrift_create_virtual_router(client, v4_enabled, v6_enabled):
    #v4 enabled
    vr_attribute1_value = sai_thrift_attribute_value_t(booldata=v4_enabled)
    vr_attribute1 = sai_thrift_attribute_t(id=0, value=vr_attribute1_value)
    #v6 enabled
    vr_attribute2_value = sai_thrift_attribute_value_t(booldata=v6_enabled)
    vr_attribute2 = sai_thrift_attribute_t(id=1, value=vr_attribute1_value)
    vr_attr_list = [vr_attribute1, vr_attribute2]
    vr_id = client.sai_thrift_create_virtual_router(thrift_attr_list=vr_attr_list)
    return vr_id

def sai_thrift_create_router_interface(client, vr_id, is_port, port_id, vlan_id, v4_enabled, v6_enabled, mac):
    #vrf attribute
    rif_attribute1_value = sai_thrift_attribute_value_t(oid=vr_id)
    rif_attribute1 = sai_thrift_attribute_t(id=0, value=rif_attribute1_value)
    if is_port:
        #port type and port id
        rif_attribute2_value = sai_thrift_attribute_value_t(u8=0)
        rif_attribute2 = sai_thrift_attribute_t(id=1, value=rif_attribute2_value)
        rif_attribute3_value = sai_thrift_attribute_value_t(oid=port_id)
        rif_attribute3 = sai_thrift_attribute_t(id=2, value=rif_attribute3_value)
    else:
        #vlan type and vlan id
        rif_attribute2_value = sai_thrift_attribute_value_t(u8=1)
        rif_attribute2 = sai_thrift_attribute_t(id=1, value=rif_attribute2_value)
        rif_attribute3_value = sai_thrift_attribute_value_t(u16=vlan_id)
        rif_attribute3 = sai_thrift_attribute_t(id=3, value=rif_attribute3_value)

    #v4_enabled
    rif_attribute4_value = sai_thrift_attribute_value_t(booldata=v4_enabled)
    rif_attribute4 = sai_thrift_attribute_t(id=5, value=rif_attribute4_value)
    #v6_enabled
    rif_attribute5_value = sai_thrift_attribute_value_t(booldata=v6_enabled)
    rif_attribute5 = sai_thrift_attribute_t(id=6, value=rif_attribute5_value)

    if mac:
        rif_attribute6_value = sai_thrift_attribute_value_t(mac=mac)
        rif_attribute6 = sai_thrift_attribute_t(id=4, value=rif_attribute6_value)
        rif_attr_list = [rif_attribute1, rif_attribute2, rif_attribute3, rif_attribute4, rif_attribute5, rif_attribute6]
    else:
        rif_attr_list = [rif_attribute1, rif_attribute2, rif_attribute3, rif_attribute4, rif_attribute5]

    rif_id = client.sai_thrift_create_router_interface(rif_attr_list)
    return rif_id

def sai_thrift_create_route(client, vr_id, addr_family, ip_addr, ip_mask, nhop):
    if addr_family == 0:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        mask = sai_thrift_ip_t(ip4=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=0, addr=addr, mask=mask)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        mask = sai_thrift_ip_t(ip6=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=1, addr=addr, mask=mask)
    route_attribute1_value = sai_thrift_attribute_value_t(oid=nhop)
    route_attribute1 = sai_thrift_attribute_t(id=2, value=route_attribute1_value)
    route = sai_thrift_unicast_route_entry_t(vr_id, ip_prefix)
    route_attr_list = [route_attribute1]
    client.sai_thrift_create_route(thrift_unicast_route_entry=route, thrift_attr_list=route_attr_list)

def sai_thrift_remove_route(client, vr_id, addr_family, ip_addr, ip_mask, nhop):
    if addr_family == 0:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        mask = sai_thrift_ip_t(ip4=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=0, addr=addr, mask=mask)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        mask = sai_thrift_ip_t(ip6=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=1, addr=addr, mask=mask)
    route = sai_thrift_unicast_route_entry_t(vr_id, ip_prefix)
    client.sai_thrift_remove_route(thrift_unicast_route_entry=route)

def sai_thrift_create_nhop(client, addr_family, ip_addr, rif_id):
    if addr_family == 0:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=0, addr=addr)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=1, addr=addr)
    nhop_attribute1_value = sai_thrift_attribute_value_t(ipaddr=ipaddr)
    nhop_attribute1 = sai_thrift_attribute_t(id=1, value=nhop_attribute1_value)
    nhop_attribute2_value = sai_thrift_attribute_value_t(oid=rif_id)
    nhop_attribute2 = sai_thrift_attribute_t(id=2, value=nhop_attribute2_value)
    nhop_attr_list = [nhop_attribute1, nhop_attribute2]
    nhop = client.sai_thrift_create_next_hop(thrift_attr_list=nhop_attr_list)
    return nhop

def sai_thrift_create_neighbor(client, addr_family, rif_id, ip_addr, dmac):
    if addr_family == 0:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=0, addr=addr)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=1, addr=addr)
    neighbor_attribute1_value = sai_thrift_attribute_value_t(mac=dmac)
    neighbor_attribute1 = sai_thrift_attribute_t(id=0, value=neighbor_attribute1_value)
    neighbor_attr_list = [neighbor_attribute1]
    neighbor_entry = sai_thrift_neighbor_entry_t(rif_id=rif_id, ip_address=ipaddr)
    client.sai_thrift_create_neighbor_entry(neighbor_entry, neighbor_attr_list)

def sai_thrift_remove_neighbor(client, addr_family, rif_id, ip_addr, dmac):
    if addr_family == 0:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=0, addr=addr)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=1, addr=addr)
    neighbor_entry = sai_thrift_neighbor_entry_t(rif_id=rif_id, ip_address=ipaddr)
    client.sai_thrift_remove_neighbor_entry(neighbor_entry)

def sai_thrift_create_next_hop_group(client, nhop_list):
    nhop_group_attribute1_value = sai_thrift_attribute_value_t(u8=0)
    nhop_group_attribute1 = sai_thrift_attribute_t(id=1, value=nhop_group_attribute1_value)
    nhop_objlist = sai_thrift_object_list_t(count=len(nhop_list), object_id_list=nhop_list)
    nhop_group_attribute2_value = sai_thrift_attribute_value_t(objlist=nhop_objlist)
    nhop_group_attribute2 = sai_thrift_attribute_t(id=2, value=nhop_group_attribute2_value)
    nhop_group_attr_list = [nhop_group_attribute1, nhop_group_attribute2]
    nhop_group = client.sai_thrift_create_next_hop_group(thrift_attr_list=nhop_group_attr_list)
    return nhop_group

def sai_thrift_create_lag(client, port_list):
    lag_port_list = sai_thrift_object_list_t(count=len(port_list), object_id_list=port_list)
    lag1_attr_value = sai_thrift_attribute_value_t(objlist=lag_port_list)
    lag1_attr = sai_thrift_attribute_t(id=0, value=lag1_attr_value)
    lag_attr_list = [lag1_attr]
    lag = client.sai_thrift_create_lag(lag_attr_list)
    return lag

def sai_thrift_create_stp_entry(client, vlan_list):
    vlanlist=sai_thrift_vlan_list_t(vlan_count=len(vlan_list), vlan_list=vlan_list)
    stp_attribute1_value = sai_thrift_attribute_value_t(vlanlist=vlanlist)
    stp_attribute1 = sai_thrift_attribute_t(id=0, value=stp_attribute1_value)
    stp_attr_list = [stp_attribute1]
    stp_id = client.sai_thrift_create_stp_entry(stp_attr_list)
    return stp_id

def sai_thrift_create_hostif_trap_group(client, queue_id, priority):
    attribute1_value = sai_thrift_attribute_value_t(u32=priority)
    attribute1 = sai_thrift_attribute_t(id=1, value=attribute1_value)
    attribute2_value = sai_thrift_attribute_value_t(u32=queue_id)
    attribute2 = sai_thrift_attribute_t(id=2, value=attribute2_value)
    attr_list = [attribute1, attribute2]
    trap_group_id = client.sai_thrift_create_hostif_trap_group(thrift_attr_list=attr_list)
    return trap_group_id

def sai_thrift_create_hostif_trap(client, trap_id, action, priority, channel, trap_group_id):
    attribute3_value = sai_thrift_attribute_value_t(u32=channel)
    attribute3 = sai_thrift_attribute_t(id=2, value=attribute3_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute3)
    attribute4_value = sai_thrift_attribute_value_t(oid=trap_group_id)
    attribute4 = sai_thrift_attribute_t(id=5, value=attribute4_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute4)
    attribute1_value = sai_thrift_attribute_value_t(u32=action)
    attribute1 = sai_thrift_attribute_t(id=0, value=attribute1_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute1)
    attribute2_value = sai_thrift_attribute_value_t(u32=priority)
    attribute2 = sai_thrift_attribute_t(id=1, value=attribute2_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute2)

def sai_thrift_create_hostif(client, rif_or_port_id, intf_name):
    attribute1_value = sai_thrift_attribute_value_t(u32=0)
    attribute1 = sai_thrift_attribute_t(id=0, value=attribute1_value)
    attribute2_value = sai_thrift_attribute_value_t(oid=rif_or_port_id)
    attribute2 = sai_thrift_attribute_t(id=1, value=attribute2_value)
    attribute3_value = sai_thrift_attribute_value_t(chardata=intf_name)
    attribute3 = sai_thrift_attribute_t(id=2, value=attribute3_value)
    attr_list = [attribute1, attribute2, attribute3]
    hif_id = client.sai_thrift_create_hostif(attr_list)
    return hif_id

class L2AccessToAccessVlanTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet port 1 -> port 2 [access vlan=10])"
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = 1

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_port1 = sai_thrift_vlan_port_t(port_id=port1, tagging_mode=0)
        vlan_port2 = sai_thrift_vlan_port_t(port_id=port2, tagging_mode=0)
        self.client.sai_thrift_add_ports_to_vlan(vlan_id, [vlan_port1, vlan_port2])

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=101,
                                ip_ttl=64)

        try:
            self.dataplane.send(2, str(pkt))
            verify_packets(self, pkt, [1])
        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_ports_from_vlan(vlan_id, [vlan_port1, vlan_port2])
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2TrunkToTrunkVlanTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet - port 1 -> port 2 [trunk vlan=10])"
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = 1

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_port1 = sai_thrift_vlan_port_t(port_id=port1, tagging_mode=1)
        vlan_port2 = sai_thrift_vlan_port_t(port_id=port2, tagging_mode=1)
        self.client.sai_thrift_add_ports_to_vlan(vlan_id, [vlan_port1, vlan_port2])

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64,
                                dl_vlan_enable=True,
                                vlan_vid=10)

        try:
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_ports_from_vlan(vlan_id, [vlan_port1, vlan_port2])
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2AccessToTrunkVlanTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet - port 1 -> port 2 [trunk vlan=10])"
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = 1

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_port1 = sai_thrift_vlan_port_t(port_id=port1, tagging_mode=1)
        vlan_port2 = sai_thrift_vlan_port_t(port_id=port2, tagging_mode=0)
        self.client.sai_thrift_add_ports_to_vlan(vlan_id, [vlan_port1, vlan_port2])

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_id=102,
                                ip_ttl=64,
                                pktlen=104)
        try:
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_ports_from_vlan(vlan_id, [vlan_port1, vlan_port2])
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2TrunkToAccessVlanTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet - port 1 -> port 2 [trunk vlan=10])"
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = 1

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_port1 = sai_thrift_vlan_port_t(port_id=port1, tagging_mode=0)
        vlan_port2 = sai_thrift_vlan_port_t(port_id=port2, tagging_mode=1)
        self.client.sai_thrift_add_ports_to_vlan(vlan_id, [vlan_port1, vlan_port2])

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64,
                                pktlen=96)
        try:
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_ports_from_vlan(vlan_id, [vlan_port1, vlan_port2])
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2StpTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet - port 1 -> port 2 [trunk vlan=10])"
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        vlan_list = [vlan_id]
        mac_action = 1

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_port1 = sai_thrift_vlan_port_t(port_id=port1, tagging_mode=0)
        vlan_port2 = sai_thrift_vlan_port_t(port_id=port2, tagging_mode=0)
        self.client.sai_thrift_add_ports_to_vlan(vlan_id, [vlan_port1, vlan_port2])

        stp_id = sai_thrift_create_stp_entry(self.client, vlan_list)
        self.client.sai_thrift_set_stp_port_state(stp_id, port1, 1)
        self.client.sai_thrift_set_stp_port_state(stp_id, port2, 1)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        try:
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=113,
                                ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=113,
                                ip_ttl=64)
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])

            self.client.sai_thrift_set_stp_port_state(stp_id, port2, 2)
            print "Sending packet port 1 (blocked) -> port 2 (192.168.0.1 -> 10.0.0.1 [id = 101])"
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=113,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=113,
                                    ip_ttl=64)
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [])
        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_stp_entry(stp_id)

            self.client.sai_thrift_remove_ports_from_vlan(vlan_id, [vlan_port1, vlan_port2])
            self.client.sai_thrift_delete_vlan(vlan_id)

class L3IPv4HostTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac_valid = 0
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = 0
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        try:
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv4LpmTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = 0
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.0'
        dmac1 = '00:11:22:33:44:55'
        nhop_ip1 = '20.20.20.1'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        try:
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv6HostTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (2000::1 -> 3000::1)"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = 1
        ip_addr1 = '1234:5678:9abc:def0:4422:1133:5577:99aa'
        ip_mask1 = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        pkt = simple_tcpv6_packet( eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ipv6_dst='1234:5678:9abc:def0:4422:1133:5577:99aa',
                                ipv6_src='2000::1',
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ipv6_dst='1234:5678:9abc:def0:4422:1133:5577:99aa',
                                ipv6_src='2000::1',
                                ipv6_hlim=63)
        try:
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv6LpmTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "IPv6 Lpm Test"
        print "Sending packet port 1 -> port 2 (2000::1 -> 3000::1, routing with 3000::0/120 route"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = 1
        ip_addr1 = '1234:5678:9abc:def0:4422:1133:5577:9900'
        ip_mask1 = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00'
        dmac1 = '00:11:22:33:44:55'
        nhop_ip1 = '3000::1'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)

        # send the test packet(s)
        pkt = simple_tcpv6_packet( eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ipv6_dst='1234:5678:9abc:def0:4422:1133:5577:99aa',
                                ipv6_src='2000::1',
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ipv6_dst='1234:5678:9abc:def0:4422:1133:5577:99aa',
                                ipv6_src='2000::1',
                                ipv6_hlim=63)
        try:
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv4EcmpHostTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)

        addr_family = 0
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id2)
        nhop_group1 = sai_thrift_create_next_hop_group(self.client, [nhop1, nhop2])
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)

        # send the test packet(s)
        try:
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=106,
                                ip_ttl=64)

            exp_pkt1 = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=106,
                                #ip_tos=3,
                                ip_ttl=63)
            exp_pkt2 = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:56',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=106,
                                #ip_tos=3,
                                ip_ttl=63)

            self.dataplane.send(3, str(pkt))
            verify_packet_list_any(self, [exp_pkt1, exp_pkt2], [1, 2])

            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.100.3',
                                    ip_id=106,
                                    ip_ttl=64)

            exp_pkt1 = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.100.3',
                                    ip_id=106,
                                    #ip_tos=3,
                                    ip_ttl=63)
            exp_pkt2 = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:56',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.100.3',
                                    ip_id=106,
                                    #ip_tos=3,
                                    ip_ttl=63)
            self.dataplane.send(3, str(pkt))
            verify_packet_list_any(self, [exp_pkt1, exp_pkt2], [1, 2])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
            self.client.sai_thrift_remove_next_hop_from_group(nhop_group1, [nhop1, nhop2])
            self.client.sai_thrift_remove_next_hop_group(nhop_group1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_next_hop(nhop2)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv6EcmpHostTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)

        addr_family =1
        ip_addr1 = '5000:1:1:0:0:0:0:1'
        ip_mask1 = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id2)
        nhop_group1 = sai_thrift_create_next_hop_group(self.client, [nhop1, nhop2])
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)

        # send the test packet(s)
        try:
            pkt = simple_tcpv6_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1234,
                                    ipv6_hlim=64)

            exp_pkt1 = simple_tcpv6_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1234,
                                    ipv6_hlim=63)
            exp_pkt2 = simple_tcpv6_packet(
                                    eth_dst='00:11:22:33:44:56',
                                    eth_src='00:77:66:55:44:33',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1234,
                                    ipv6_hlim=63)

            self.dataplane.send(3, str(pkt))
            verify_packet_list_any(self, [exp_pkt1, exp_pkt2], [1, 2])

            pkt = simple_tcpv6_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:45',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1248,
                                    ipv6_hlim=64)

            exp_pkt1 = simple_tcpv6_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1248,
                                    ipv6_hlim=63)
            exp_pkt2 = simple_tcpv6_packet(
                                    eth_dst='00:11:22:33:44:56',
                                    eth_src='00:77:66:55:44:33',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1248,
                                    ipv6_hlim=63)

            self.dataplane.send(3, str(pkt))
            verify_packet_list_any(self, [exp_pkt1, exp_pkt2], [1, 2])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
            self.client.sai_thrift_remove_next_hop_from_group(nhop_group1, [nhop1, nhop2])
            self.client.sai_thrift_remove_next_hop_group(nhop_group1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_next_hop(nhop2)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv4EcmpLpmTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        port4 = port_list[4]
        port5 = port_list[5]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)
        rif_id4 = sai_thrift_create_router_interface(self.client, vr_id, 1, port4, 0, v4_enabled, v6_enabled, mac)
        rif_id5 = sai_thrift_create_router_interface(self.client, vr_id, 1, port5, 0, v4_enabled, v6_enabled, mac)


        addr_family = 0
        ip_addr1 = '10.10.0.0'
        ip_mask1 = '255.255.0.0'
        nhop_ip1 = '11.11.11.11'
        nhop_ip2 = '22.22.22.22'
        nhop_ip3 = '33.33.33.33'
        nhop_ip4 = '44.44.44.44'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'
        dmac3 = '00:11:22:33:44:57'
        dmac4 = '00:11:22:33:44:58'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip1, rif_id1)
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip2, rif_id2)
        nhop3 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip3, rif_id3)
        nhop4 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip4, rif_id4)
        nhop_group1 = sai_thrift_create_next_hop_group(self.client, [nhop1, nhop2, nhop3, nhop4])
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, nhop_ip2, dmac2)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id3, nhop_ip3, dmac3)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id4, nhop_ip4, dmac4)

        # send the test packet(s)
        try:
            count = [0, 0, 0, 0]
            dst_ip = int(socket.inet_aton('10.10.10.1').encode('hex'),16)
            max_itrs = 100
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntoa(hex(dst_ip)[2:].zfill(8).decode('hex'))
                pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                        eth_src='00:22:22:22:22:22',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=64)

                exp_pkt1 = simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt2 = simple_tcp_packet(eth_dst='00:11:22:33:44:56',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt3 = simple_tcp_packet(eth_dst='00:11:22:33:44:57',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt4 = simple_tcp_packet(eth_dst='00:11:22:33:44:58',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)

                self.dataplane.send(5, str(pkt))
                rcv_idx = verify_packet_list_any(self,
                              [exp_pkt1, exp_pkt2, exp_pkt3, exp_pkt4],
                              [1, 2, 3, 4])
                count[rcv_idx] += 1
                dst_ip += 1

            for i in range(0, 4):
                self.assertTrue((count[i] >= ((max_itrs / 4) * 0.9)),
                        "Not all paths are equally balanced")
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, nhop_ip2, dmac2)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id3, nhop_ip3, dmac3)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id4, nhop_ip4, dmac4)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
            self.client.sai_thrift_remove_next_hop_from_group(nhop_group1, [nhop1, nhop2, nhop3, nhop4])
            self.client.sai_thrift_remove_next_hop_group(nhop_group1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_next_hop(nhop2)
            self.client.sai_thrift_remove_next_hop(nhop3)
            self.client.sai_thrift_remove_next_hop(nhop4)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)
            self.client.sai_thrift_remove_router_interface(rif_id4)
            self.client.sai_thrift_remove_router_interface(rif_id5)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv6EcmpLpmTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        port4 = port_list[4]
        port5 = port_list[5]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)
        rif_id4 = sai_thrift_create_router_interface(self.client, vr_id, 1, port4, 0, v4_enabled, v6_enabled, mac)
        rif_id5 = sai_thrift_create_router_interface(self.client, vr_id, 1, port5, 0, v4_enabled, v6_enabled, mac)

        addr_family = 1
        ip_addr1 = '6000:1:1:0:0:0:0:0'
        ip_mask1 = 'ffff:ffff:ffff:ffff:0:0:0:0'
        nhop_ip1 = '2000:1:1:0:0:0:0:1'
        nhop_ip2 = '3000:1:1:0:0:0:0:1'
        nhop_ip3 = '4000:1:1:0:0:0:0:1'
        nhop_ip4 = '5000:1:1:0:0:0:0:1'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'
        dmac3 = '00:11:22:33:44:57'
        dmac4 = '00:11:22:33:44:58'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip1, rif_id1)
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip2, rif_id2)
        nhop3 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip3, rif_id3)
        nhop4 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip4, rif_id4)
        nhop_group1 = sai_thrift_create_next_hop_group(self.client, [nhop1, nhop2, nhop3, nhop4])
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, nhop_ip2, dmac2)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id3, nhop_ip3, dmac3)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id4, nhop_ip4, dmac4)

        # send the test packet(s)
        try:
            count = [0, 0, 0, 0]
            dst_ip = socket.inet_pton(socket.AF_INET6, '6000:1:1:0:0:0:0:1')
            dst_ip_arr = list(dst_ip)
            max_itrs = 100
            sport = 0x1234
            dport = 0x50
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntop(socket.AF_INET6, dst_ip)
                #HACK: sport is a hack for hashing since the ecmp hash does not
                #include ipv6 sa and da.
                pkt = simple_tcpv6_packet(
                        eth_dst='00:77:66:55:44:33',
                        eth_src='00:22:22:22:22:22',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=64)
                exp_pkt1 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:55',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)
                exp_pkt2 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:56',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)
                exp_pkt3 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:57',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)
                exp_pkt4 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:58',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)

                self.dataplane.send(5, str(pkt))
                rcv_idx = verify_packet_list_any(self,
                              [exp_pkt1, exp_pkt2, exp_pkt3, exp_pkt4],
                              [1, 2, 3, 4])
                count[rcv_idx] += 1
                dst_ip_arr[15] = chr(ord(dst_ip_arr[15]) + 1)
                dst_ip = ''.join(dst_ip_arr)
                sport += 15
                dport += 20

            for i in range(0, 4):
                self.assertTrue((count[i] >= ((max_itrs / 4) * 0.9)),
                        "Not all paths are equally balanced")
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, nhop_ip2, dmac2)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id3, nhop_ip3, dmac3)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id4, nhop_ip4, dmac4)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
            self.client.sai_thrift_remove_next_hop_from_group(nhop_group1, [nhop1, nhop2, nhop3, nhop4])
            self.client.sai_thrift_remove_next_hop_group(nhop_group1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_next_hop(nhop2)
            self.client.sai_thrift_remove_next_hop(nhop3)
            self.client.sai_thrift_remove_next_hop(nhop4)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)
            self.client.sai_thrift_remove_router_interface(rif_id4)
            self.client.sai_thrift_remove_router_interface(rif_id5)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L2FloodTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print 'Flood test on ports 1, 2 and 3'
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_port1 = sai_thrift_vlan_port_t(port_id=port1, tagging_mode=0)
        vlan_port2 = sai_thrift_vlan_port_t(port_id=port2, tagging_mode=0)
        vlan_port3 = sai_thrift_vlan_port_t(port_id=port3, tagging_mode=0)
        self.client.sai_thrift_add_ports_to_vlan(vlan_id, [vlan_port1, vlan_port2, vlan_port3])

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=107,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=107,
                                ip_ttl=64)
        try:
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2, 3])
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1, 3])
            self.dataplane.send(3, str(pkt))
            verify_packets(self, exp_pkt, [1, 2])
        finally:
            self.client.sai_thrift_remove_ports_from_vlan(vlan_id, [vlan_port1, vlan_port2, vlan_port3])
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2LagTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        port4 = port_list[4]
        port5 = port_list[5]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = 1

        self.client.sai_thrift_create_vlan(vlan_id)

        lag_id1 = sai_thrift_create_lag(self.client, [port1, port2, port3, port4])

        vlan_port1 = sai_thrift_vlan_port_t(port_id=lag_id1, tagging_mode=0)
        vlan_port2 = sai_thrift_vlan_port_t(port_id=port5, tagging_mode=0)
        self.client.sai_thrift_add_ports_to_vlan(vlan_id, [vlan_port1, vlan_port2])

        sai_thrift_create_fdb(self.client, vlan_id, mac1, lag_id1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port5, mac_action)

        try:
            count = [0, 0, 0, 0]
            dst_ip = int(socket.inet_aton('10.10.10.1').encode('hex'),16)
            max_itrs = 100
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntoa(hex(dst_ip)[2:].zfill(8).decode('hex'))
                pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                        eth_src='00:22:22:22:22:22',
                                        ip_dst=dst_ip_addr,
                                        ip_src='192.168.8.1',
                                        ip_id=109,
                                        ip_ttl=64)

                exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                            eth_src='00:22:22:22:22:22',
                                            ip_dst=dst_ip_addr,
                                            ip_src='192.168.8.1',
                                            ip_id=109,
                                            ip_ttl=64)

                self.dataplane.send(5, str(pkt))
                rcv_idx = verify_packet_list_any(self,
                              [exp_pkt, exp_pkt, exp_pkt, exp_pkt],
                              [1, 2, 3, 4])
                count[rcv_idx] += 1
                dst_ip += 1

            print count
            for i in range(0, 4):
                self.assertTrue((count[i] >= ((max_itrs / 4) * 0.9)),
                        "Not all paths are equally balanced")

            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=109,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=109,
                                    ip_ttl=64)
            print "Sending packet port 1 (lag member) -> port 1"
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [5])
            print "Sending packet port 2 (lag member) -> port 1"
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [5])
            print "Sending packet port 3 (lag member) -> port 1"
            self.dataplane.send(3, str(pkt))
            verify_packets(self, exp_pkt, [5])
            print "Sending packet port 4 (lag member) -> port 1"
            self.dataplane.send(4, str(pkt))
            verify_packets(self, exp_pkt, [5])
        finally:

            self.client.sai_thrift_remove_ports_from_lag(lag_id1, [port1, port2, port3, port4])
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, lag_id1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port5)

            self.client.sai_thrift_remove_ports_from_vlan(vlan_id, [vlan_port1, vlan_port2])
            self.client.sai_thrift_remove_lag(lag_id1)
            self.client.sai_thrift_delete_vlan(vlan_id)

class L3IPv4LagTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        lag_id1 = sai_thrift_create_lag(self.client, [port1, port2])

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, lag_id1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)

        addr_family = 0
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        try:
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.0.1',
                                    ip_id=110,
                                    ip_ttl=64)

            exp_pkt = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.0.1',
                                    ip_id=110,
                                    ip_ttl=63)
            self.dataplane.send(3, str(pkt))
            verify_packets_any(self, exp_pkt, [1, 2])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_ports_from_lag(lag_id1, [port1, port2])
            self.client.sai_thrift_remove_lag(lag_id1)
            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv6LagTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        lag_id1 = sai_thrift_create_lag(self.client, [port1, port2])

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, lag_id1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)

        addr_family = 1
        ip_addr1 = '4001::1'
        ip_mask1 = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        try:
            pkt = simple_tcpv6_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst='4001::1',
                                    ipv6_src='5001::1',
                                    ipv6_hlim=64)

            exp_pkt = simple_tcpv6_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ipv6_dst='4001::1',
                                    ipv6_src='5001::1',
                                    ipv6_hlim=63)
            self.dataplane.send(3, str(pkt))
            verify_packets_any(self, exp_pkt, [1, 2])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_ports_from_lag(lag_id1, [port1, port2])
            self.client.sai_thrift_remove_lag(lag_id1)
            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3EcmpLagTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        port4 = port_list[4]
        port5 = port_list[5]
        port6 = port_list[6]
        port7 = port_list[7]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        lag_id1 = sai_thrift_create_lag(self.client, [port1, port2, port3])
        lag_id2 = sai_thrift_create_lag(self.client, [port4, port5])

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, lag_id1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, lag_id2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port6, 0, v4_enabled, v6_enabled, mac)
        rif_id4 = sai_thrift_create_router_interface(self.client, vr_id, 1, port7, 0, v4_enabled, v6_enabled, mac)

        addr_family = 0
        ip_addr1 = '10.10.0.0'
        ip_mask1 = '255.255.0.0'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'
        dmac3 = '00:11:22:33:44:57'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id2)
        nhop3 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id3)

        nhop_group1 = sai_thrift_create_next_hop_group(self.client, [nhop1, nhop2, nhop3])
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)

        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id3, ip_addr1, dmac3)

        try:
            count = [0, 0, 0, 0, 0, 0]
            dst_ip = int(socket.inet_aton('10.10.10.1').encode('hex'), 16)
            src_mac_start = '00:22:22:22:22:'
            max_itrs = 500
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntoa(hex(dst_ip)[2:].zfill(8).decode('hex'))
                src_mac = src_mac_start + str(i%99).zfill(2)
                pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                        eth_src=src_mac,
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=64)

                exp_pkt1 = simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt2 = simple_tcp_packet(eth_dst='00:11:22:33:44:56',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt3 = simple_tcp_packet(eth_dst='00:11:22:33:44:57',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)

                self.dataplane.send(7, str(pkt))
                rcv_idx = verify_packet_list_any(self,
                              [exp_pkt1, exp_pkt1, exp_pkt1,
                                  exp_pkt2, exp_pkt2, exp_pkt3],
                              [1, 2, 3, 4, 5, 6])
                count[rcv_idx] += 1
                dst_ip += 1

            print count
            ecmp_count = [count[0]+count[1]+count[2], count[3]+count[4],
                    count[5]]
            for i in range(0, 3):
                self.assertTrue((ecmp_count[i] >= ((max_itrs / 3) * 0.75)),
                        "Ecmp paths are not equally balanced")
            for i in range(0, 3):
                self.assertTrue((count[i] >= ((max_itrs / 9) * 0.75)),
                        "Lag path1 is not equally balanced")
            for i in range(3, 5):
                self.assertTrue((count[i] >= ((max_itrs / 6) * 0.75)),
                        "Lag path2 is not equally balanced")
        finally:
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)

            self.client.sai_thrift_remove_next_hop_from_group(nhop_group1, [nhop1, nhop2, nhop3])
            self.client.sai_thrift_remove_next_hop_group(nhop_group1)

            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)
            self.client.sai_thrift_remove_next_hop(nhop2)

            sai_thrift_remove_neighbor(self.client, addr_family, rif_id3, ip_addr1, dmac3)
            self.client.sai_thrift_remove_next_hop(nhop3)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)
            self.client.sai_thrift_remove_router_interface(rif_id4)

            self.client.sai_thrift_remove_ports_from_lag(lag_id1, [port1, port2, port3])
            self.client.sai_thrift_remove_lag(lag_id1)

            self.client.sai_thrift_remove_ports_from_lag(lag_id2, [port4, port5])
            self.client.sai_thrift_remove_lag(lag_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class IPAclTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = 0
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
#         try:
#             self.dataplane.send(2, str(pkt))
#             verify_packets(self, exp_pkt, [1])
#
#         finally:
        if True:

            # setup ACL to block based on Source IP
            attr_value = sai_thrift_attribute_value_t(u8=0)
            attr = sai_thrift_attribute_t(id=0x1004, value=attr_value)
            table_attr_list =  [attr]
            table_id = self.client.sai_thrift_create_acl_table(table_attr_list)

            attr_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(oid=table_id)))
            attr = sai_thrift_attribute_t(id=0, value=attr_value)
            attr1_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(u32=10)))
            attr1 = sai_thrift_attribute_t(id=1, value=attr1_value)
            # IPV4_SOURCE
            attr2_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(ip4="192.168.0.1"), mask =sai_thrift_acl_mask_t(ip4="255.255.255.255")))
            attr2 = sai_thrift_attribute_t(id=0x1004, value=attr2_value)
            port1 = port_list[1]
            port2 = port_list[2]
            ports = [port1, port2]
            acl_port_list = sai_thrift_object_list_t(count=len(ports), object_id_list=ports)
            # INPUT_PORTS
            attr3_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(objlist=acl_port_list)))
            attr3 = sai_thrift_attribute_t(id=0x1006, value=attr3_value)
            # Drop
            attr4_value = sai_thrift_attribute_value_t(u8=0)
            attr4 = sai_thrift_attribute_t(id=0x2001, value=attr4_value)

            entry_attr_list =  [attr, attr1, attr2, attr3, attr4]
            entry_id = self.client.sai_thrift_create_acl_entry(entry_attr_list)

            # send the same packet
            failed = 0
            self.dataplane.send(2, str(pkt))

            # ensure packet is dropped
            # check for absence of packet here!
            try:
                verify_packets(self, exp_pkt, [1])
                print 'FAILED - did not expect packet'
                failed = 1
            except:
                print 'Success'

            finally:
                if failed == 1:
                    self.assertFalse()


            # delete ACL
            self.client.sai_thrift_delete_acl_entry(entry_id)
            self.client.sai_thrift_delete_acl_table(table_id)

            # cleanup
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3SVIIPv4HostTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        vlan_id = 10

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_port1 = sai_thrift_vlan_port_t(port_id=port1, tagging_mode=0)
        self.client.sai_thrift_add_ports_to_vlan(vlan_id, [vlan_port1])

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        mac1 = ''
        mac2 = ''

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 0, 0, vlan_id, v4_enabled, v6_enabled, mac1)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac2)

        addr_family = 0
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:0a:00:00:00:01'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        ip_addr2 = '11.11.11.1'
        ip_mask2 = '255.255.255.255'
        dmac2 = '00:0b:00:00:00:01'
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, ip_addr2, rif_id2)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr2, ip_mask2, nhop2)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, ip_addr2, dmac2)

        try:
            # send the test packet(s)
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:0a:00:00:00:01',
                                ip_dst='11.11.11.1',
                                ip_src='10.10.10.1',
                                ip_id=105,
                                ip_ttl=64)
            exp_pkt = simple_tcp_packet(
                                eth_dst='00:0b:00:00:00:01',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='11.11.11.1',
                                ip_src='10.10.10.1',
                                ip_id=105,
                                ip_ttl=63)
            self.dataplane.send(1, str(pkt))
            verify_packets(self, exp_pkt, [2])

            # send the test packet(s)
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:0b:00:00:00:01',
                                ip_dst='10.10.10.1',
                                ip_src='11.11.11.1',
                                ip_id=105,
                                ip_ttl=64)
            exp_pkt = simple_tcp_packet(
                                eth_dst='00:0a:00:00:00:01',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='11.11.11.1',
                                ip_id=105,
                                ip_ttl=63)
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, ip_addr2, dmac2)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr2, ip_mask2, nhop2)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_next_hop(nhop2)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_ports_from_vlan(vlan_id, [vlan_port1])
            self.client.sai_thrift_delete_vlan(vlan_id)
            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv4MacRewriteTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1

        mac1 = '00:0a:00:00:00:01'
        mac2 = '00:0b:00:00:00:01'

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac1)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac2)

        addr_family = 0
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:0b:00:00:00:01',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:0a:00:00:00:01',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        try:
            self.dataplane.send(2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_virtual_router(vr_id)


