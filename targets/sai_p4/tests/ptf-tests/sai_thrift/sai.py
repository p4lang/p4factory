"""
Thrift API interface basic tests
"""

import p4_sai_rpc

import time
import sys
import logging

import unittest
import random

import ptf.dataplane as dataplane
import sai_base_test

from ptf.testutils import *
from ptf.thriftutils import *

import os

from p4_sai_rpc.ttypes import  *

this_dir = os.path.dirname(os.path.abspath(__file__))

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

def verify_packet_list(test, pkt_list,  ofport_list):
    logging.debug("Checking for packet on given ports")

    match_found = 0
    for ofport in ofport_list:
        (rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(timeout=2)
        test.assertTrue(rcv_pkt != None, "No packet received")
        index = ofport_list.index(rcv_port)
        pkt = pkt_list[index]
        if (str(rcv_pkt) == str(pkt)):
            match_found += 1
    test.assertTrue(match_found == len(pkt_list), "Packet not received on expected port")

def verify_packet_on_set_of_ports(test, pkt, ofport_list):
    logging.debug("Checking for packet on set of ports")
    match_found = 0
    for port_list in ofport_list:
        for port in port_list:
            (rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(timeout=1)
            if (str(rcv_pkt) == str(pkt)):
                match_found += 1
    test.assertTrue(match_found == len(ofport_list), "Packet not received on expected port")

class L2Test(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print 'L2 Test'
        list1 = []
        list1.append(sai_attribute(id = 3, value = sai_attribute_value(u32=1)))
        list1.append(sai_attribute(id = 5, value = sai_attribute_value(u32=0x22222200)))
        self.client.create_switch(sai_attribute_list(api_id=1, attr_list=list1))

        list1 = []
        list1.append(sai_attribute(id = 3, value = sai_attribute_value(u32=1)))
        list1.append(sai_attribute(id = 10, value = sai_attribute_value(u32=2)))
        self.client.create_port(sai_p4_sai_port_match_spec_t(1), sai_attribute_list(api_id=2, attr_list=list1))

        list1 = []
        list1.append(sai_attribute(id = 3, value = sai_attribute_value(u32=3)))
        list1.append(sai_attribute(id = 1, value = sai_attribute_value(u32=10)))
        self.client.create_router_interface(sai_p4_sai_router_interface_match_spec_t("00:12:34:56:78:90"), sai_attribute_list(api_id=9, attr_list=list1))

        list1 = []
        list1.append(sai_attribute(id = 2, value = sai_attribute_value(u32=2)))
        self.client.create_fdb(sai_p4_sai_fdb_match_spec_t(0, "00:11:11:11:11:11"), sai_attribute_list(api_id=3, attr_list=list1))

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=101,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=101,
                                ip_ttl=64)
        try:
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:
            print 'done'

        # delete entries
        self.client.delete_fdb(sai_p4_sai_fdb_match_spec_t(0, "00:11:11:11:11:11"))
        self.client.delete_router_interface(sai_p4_sai_router_interface_match_spec_t("00:12:34:56:78:90"))
        self.client.delete_port(sai_p4_sai_port_match_spec_t(1))
        self.client.delete_switch()



class L3Test(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print 'Simple L3 Test'
        list1 = []
        list1.append(sai_attribute(id = 3, value = sai_attribute_value(u32=1)))
        list1.append(sai_attribute(id = 5, value = sai_attribute_value(u32=0x22222200)))
        self.client.create_switch(sai_attribute_list(api_id=1, attr_list=list1))

        list1 = []
        list1.append(sai_attribute(id = 3, value = sai_attribute_value(u32=1)))
        self.client.create_port(sai_p4_sai_port_match_spec_t(1), sai_attribute_list(api_id=2, attr_list=list1))

        list1 = []
        list1.append(sai_attribute(id = 3, value = sai_attribute_value(u32=3)))
        list1.append(sai_attribute(id = 1, value = sai_attribute_value(u32=10)))
        self.client.create_router_interface(sai_p4_sai_router_interface_match_spec_t("00:12:34:56:78:90"), sai_attribute_list(api_id=9, attr_list=list1))

        list1 = []
        list1.append(sai_attribute(id = 1, value = sai_attribute_value(u32=1)))
        list1.append(sai_attribute(id = 3, value = sai_attribute_value(u32=0x22222200)))
        self.client.create_virtual_router(sai_p4_sai_virtual_router_match_spec_t(10), sai_attribute_list(api_id=5, attr_list=list1))


        list1 = []
        list1.append(sai_attribute(id = 2, value = sai_attribute_value(u32=1)))
        self.client.create_route(sai_p4_sai_route_match_spec_t(10, 0x0a000001, 32), sai_attribute_list(api_id=6, attr_list=list1))

        list1 = []
        list1.append(sai_attribute(id = 1, value = sai_attribute_value(u32=2)))
        self.client.create_next_hop(sai_p4_sai_next_hop_match_spec_t(1), sai_attribute_list(api_id=7, attr_list=list1))

        list1 = []
        list1.append(sai_attribute(id = 2, value = sai_attribute_value(u32=3)))
        list1.append(sai_attribute(id = 1, value = sai_attribute_value(u32=2)))
        self.client.create_neighbor(sai_p4_sai_neighbor_match_spec_t(10, 0x0a000001, 2), sai_attribute_list(api_id=10, attr_list=list1))

        pkt = simple_tcp_packet(eth_dst='00:12:34:56:78:90',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=101,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='02:00:00:00:00:00',
                                eth_src='00:22:22:22:00:00',
                                ip_dst='10.0.0.1',
                                ip_id=101,
                                ip_ttl=63)
        try:
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [3])
        finally:
            print 'done'
        # delete the entries
        self.client.delete_neighbor(sai_p4_sai_neighbor_match_spec_t(10, 0x0a000001, 2))
        self.client.delete_next_hop(sai_p4_sai_next_hop_match_spec_t(1))
        self.client.delete_route(sai_p4_sai_route_match_spec_t(10, 0x0a000001, 32))
        self.client.delete_virtual_router(sai_p4_sai_virtual_router_match_spec_t(10))
        self.client.delete_router_interface(sai_p4_sai_router_interface_match_spec_t("00:12:34:56:78:90"))

        self.client.delete_port(sai_p4_sai_port_match_spec_t(1))
        self.client.delete_switch()


