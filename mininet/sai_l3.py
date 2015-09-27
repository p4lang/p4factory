#!/usr/bin/python

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

##############################################################################
# Topology with two switches and two hosts. Uses SAI thrift APIs to configure
# the switches. Set 'DOCKER_IMAGE=bm-switchsai' when creating the docker image.
#
#       172.16.101.0/24         172.16.10.0/24         172.16.102.0./24
#  h1 ------------------- sw1 ------------------ sw2------- -------------h2
#     .5               .1     .1               .2   .1                  .5
##############################################################################

from mininet.net import Mininet, VERSION
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from distutils.version import StrictVersion
from p4_mininet import P4DockerSwitch

import os
import sys
import time
lib_path = os.path.abspath(os.path.join('..', 'targets', 'switch', 'tests',
                                        'pd_thrift'))
sys.path.append(lib_path)
import switch_sai_thrift.switch_sai_rpc as switch_sai_rpc
from switch_sai_thrift.ttypes import  *

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

def open_connection(port):
    transport = TSocket.TSocket('localhost', port)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    client = switch_sai_rpc.Client(protocol)
    transport.open()
    return transport, client

def close_connection(transport):
    transport.close()

def create_virtual_router(client, v4_enabled, v6_enabled):
    #v4 enabled
    vr_attribute1_value = sai_thrift_attribute_value_t(booldata=v4_enabled)
    vr_attribute1 = sai_thrift_attribute_t(id=0, value=vr_attribute1_value)
    #v6 enabled
    vr_attribute2_value = sai_thrift_attribute_value_t(booldata=v6_enabled)
    vr_attribute2 = sai_thrift_attribute_t(id=1, value=vr_attribute1_value)
    vr_attr_list = [vr_attribute1, vr_attribute2]
    vr_id = client.sai_thrift_create_virtual_router(thrift_attr_list=vr_attr_list)
    return vr_id

def create_router_interface(client, vr_id, is_port, port_id, vlan_id,
                            v4_enabled, v6_enabled):
    #vrf attribute
    rif_attribute1_value = sai_thrift_attribute_value_t(oid=vr_id)
    rif_attribute1 = sai_thrift_attribute_t(id=0, value=rif_attribute1_value)
    if is_port:
        #port type and port id
        rif_attribute2_value = sai_thrift_attribute_value_t(u8=0)
        rif_attribute2 = sai_thrift_attribute_t(id=1,
                                                value=rif_attribute2_value)
        rif_attribute3_value = sai_thrift_attribute_value_t(oid=port_id)
        rif_attribute3 = sai_thrift_attribute_t(id=2,
                                                value=rif_attribute3_value)
    else:
        #vlan type and vlan id
        rif_attribute2_value = sai_thrift_attribute_value_t(u8=1)
        rif_attribute2 = sai_thrift_attribute_t(id=1,
                                                value=rif_attribute2_value)
        rif_attribute3_value = sai_thrift_attribute_value_t(u16=vlan_id)
        rif_attribute3 = sai_thrift_attribute_t(id=3,
                                                value=rif_attribute3_value)

    #v4_enabled
    rif_attribute4_value = sai_thrift_attribute_value_t(booldata=v4_enabled)
    rif_attribute4 = sai_thrift_attribute_t(id=5, value=rif_attribute4_value)
    #v6_enabled
    rif_attribute5_value = sai_thrift_attribute_value_t(booldata=v6_enabled)
    rif_attribute5 = sai_thrift_attribute_t(id=6, value=rif_attribute5_value)
    rif_attr_list = [rif_attribute1, rif_attribute2, rif_attribute3,
                     rif_attribute4, rif_attribute5]
    rif_id = client.sai_thrift_create_router_interface(rif_attr_list)
    return rif_id

def create_route(client, vr_id, addr_family, ip_addr, ip_mask, nhop):
    if addr_family == 0:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        mask = sai_thrift_ip_t(ip4=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=0, addr=addr, mask=mask)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        mask = sai_thrift_ip_t(ip6=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=1, addr=addr, mask=mask)
    route_attribute1_value = sai_thrift_attribute_value_t(oid=nhop)
    route_attribute1 = sai_thrift_attribute_t(id=2,
                                              value=route_attribute1_value)
    route = sai_thrift_unicast_route_entry_t(vr_id, ip_prefix)
    route_attr_list = [route_attribute1]
    client.sai_thrift_create_route(thrift_unicast_route_entry=route,
                                   thrift_attr_list=route_attr_list)

def create_nhop(client, addr_family, ip_addr, rif_id):
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

def create_neighbor(client, addr_family, rif_id, ip_addr, dmac):
    if addr_family == 0:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=0, addr=addr)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=1, addr=addr)
    neighbor_attribute1_value = sai_thrift_attribute_value_t(mac=dmac)
    neighbor_attribute1 = sai_thrift_attribute_t(id=0,
                                           value=neighbor_attribute1_value)
    neighbor_attr_list = [neighbor_attribute1]
    neighbor_entry = sai_thrift_neighbor_entry_t(rif_id=rif_id,
                                                 ip_address=ipaddr)
    client.sai_thrift_create_neighbor_entry(neighbor_entry, neighbor_attr_list)

def cfg_switch1():
    port_list = []
    transport, client = open_connection(25000)
    switch_attr_list = client.sai_thrift_get_switch_attribute()
    attr_list = switch_attr_list.attr_list
    for attr in attr_list:
        if attr.id == 0:
            print 'max ports: ', attr.value.u32
        elif attr.id == 1:
            for x in attr.value.objlist.object_id_list:
                port_list.append(x)
        else:
            print 'unknown switch attribute'

    port1 = port_list[0]
    port2 = port_list[1]
    vr = create_virtual_router(client, v4_enabled=1, v6_enabled=1)

    attr_value = sai_thrift_attribute_value_t(mac='00:01:00:00:00:03')
    attr = sai_thrift_attribute_t(id=17, value=attr_value)
    client.sai_thrift_set_switch_attribute(attr)
    rif1 = create_router_interface(client, vr, 1, port1, 0, v4_enabled=1,
                                   v6_enabled=1)

    attr_value = sai_thrift_attribute_value_t(mac='00:01:00:00:00:04')
    attr = sai_thrift_attribute_t(id=17, value=attr_value)
    client.sai_thrift_set_switch_attribute(attr)
    rif2 = create_router_interface(client, vr, 1, port2, 0, v4_enabled=1,
                                   v6_enabled=1)

    nhop1 = create_nhop(client, 0, '172.16.101.5', rif1)
    create_neighbor(client, 0, rif1, '172.16.101.5', '00:03:00:00:00:01')

    nhop2 = create_nhop(client, 0, '172.16.10.2', rif2)
    create_neighbor(client, 0, rif2, '172.16.10.2', '00:02:00:00:00:04')

    create_route(client, vr, 0, '172.16.101.5', '255.255.255.255', nhop1)
    create_route(client, vr, 0, '172.16.10.2', '255.255.255.255', nhop2)
    create_route(client, vr, 0, '172.16.102.0', '255.255.255.0', nhop2)

    close_connection(transport)

def cfg_switch2():
    port_list = []
    transport, client = open_connection(25001)
    switch_attr_list = client.sai_thrift_get_switch_attribute()
    attr_list = switch_attr_list.attr_list
    for attr in attr_list:
        if attr.id == 0:
            print 'max ports: ', attr.value.u32
        elif attr.id == 1:
            for x in attr.value.objlist.object_id_list:
                port_list.append(x)
        else:
            print 'unknown switch attribute'

    port1 = port_list[0]
    port2 = port_list[1]
    vr = create_virtual_router(client, v4_enabled=1, v6_enabled=1)

    attr_value = sai_thrift_attribute_value_t(mac='00:02:00:00:00:03')
    attr = sai_thrift_attribute_t(id=17, value=attr_value)
    client.sai_thrift_set_switch_attribute(attr)
    rif1 = create_router_interface(client, vr, 1, port1, 0, v4_enabled=1,
                                   v6_enabled=1)

    attr_value = sai_thrift_attribute_value_t(mac='00:02:00:00:00:04')
    attr = sai_thrift_attribute_t(id=17, value=attr_value)
    client.sai_thrift_set_switch_attribute(attr)
    rif2 = create_router_interface(client, vr, 1, port2, 0, v4_enabled=1,
                                   v6_enabled=1)

    nhop1 = create_nhop(client, 0, '172.16.102.5', rif1)
    create_neighbor(client, 0, rif1, '172.16.102.5', '00:04:00:00:00:01')

    nhop2 = create_nhop(client, 0, '172.16.10.1', rif2)
    create_neighbor(client, 0, rif2, '172.16.10.1', '00:01:00:00:00:04')

    create_route(client, vr, 0, '172.16.102.5', '255.255.255.255', nhop1)
    create_route(client, vr, 0, '172.16.10.1', '255.255.255.255', nhop2)
    create_route(client, vr, 0, '172.16.101.0', '255.255.255.0', nhop2)
    close_connection(transport)

def main():
    net = Mininet( controller = None )

    # add hosts
    h1 = net.addHost( 'h1', ip = '172.16.101.5/24', mac = '00:03:00:00:00:01' )
    h2 = net.addHost( 'h2', ip = '172.16.102.5/24', mac = '00:04:00:00:00:01' )

    # add switch 1
    sw1 = net.addSwitch( 'sw1', target_name = "p4dockerswitch",
            cls = P4DockerSwitch, sai_port = 25000, pcap_dump = True )

    # add switch 2
    sw2 = net.addSwitch( 'sw2', target_name = "p4dockerswitch",
            cls = P4DockerSwitch, sai_port = 25001, pcap_dump = True )

    # add links
    if StrictVersion(VERSION) <= StrictVersion('2.2.0') :
        net.addLink( sw1, h1, port1 = 1 )
        net.addLink( sw1, sw2, port1 = 2, port2 = 2 )
        net.addLink( sw2, h2, port1 = 1 )
    else:
        net.addLink( sw1, h1, port1 = 1, fast=False )
        net.addLink( sw1, sw2, port1 = 2, port2 = 2, fast=False )
        net.addLink( sw2, h2, port1 = 1, fast=False )

    net.start()

    print 'Waiting 10 seconds for switches to intialize...'
    time.sleep(10)

    # configure hosts
    h1.setARP( ip = '172.16.101.1', mac = '00:01:00:00:00:03' )
    h2.setARP( ip = '172.16.102.1', mac = '00:02:00:00:00:03' )
    h1.setDefaultRoute( 'via 172.16.101.1' )
    h2.setDefaultRoute( 'via 172.16.102.1' )

    # configure switches
    cfg_switch1()
    cfg_switch2()

    CLI( net )

    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
