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
# Topology with two switches and two hosts. Uses SAI thrift API to configure
# the switches. Set 'DOCKER_IMAGE=bm-switchsai' when creating the docker image.
#
#                               172.16.10.0/24
#  h1 ------------------- sw1 ------------------ sw2------- -------------h2
#     .1                                                                .2
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

    vlan_id = 100
    client.sai_thrift_create_vlan(vlan_id)
    vlan_port1 = sai_thrift_vlan_port_t(port_id=port_list[0], tagging_mode=0)
    vlan_port2 = sai_thrift_vlan_port_t(port_id=port_list[1], tagging_mode=0)
    client.sai_thrift_add_ports_to_vlan(vlan_id, [vlan_port1, vlan_port2])
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

    vlan_id = 100
    client.sai_thrift_create_vlan(vlan_id)
    vlan_port1 = sai_thrift_vlan_port_t(port_id=port_list[0], tagging_mode=0)
    vlan_port2 = sai_thrift_vlan_port_t(port_id=port_list[1], tagging_mode=0)
    client.sai_thrift_add_ports_to_vlan(vlan_id, [vlan_port1, vlan_port2])
    close_connection(transport)

def main():
    net = Mininet( controller = None )

    # add hosts
    h1 = net.addHost( 'h1', ip = '172.16.10.1/24' )
    h2 = net.addHost( 'h2', ip = '172.16.10.2/24' )

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

    cfg_switch1()
    cfg_switch2()

    CLI( net )

    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
