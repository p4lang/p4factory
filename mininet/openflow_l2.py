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

########
# README
# 
# This script is for use with the switch target of the behavioral model.
# To run it, first build the behavioral model with an Openflow Agent,
# then start an instance of Ryu running the simple_switch_13.py app. Supply the IP 
# address of the Ryu instance to this script and you should be able to do "h1 ping h2."
########

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from p4_mininet import P4Switch, P4Host

import os
import sys
import time

lib_path = os.path.abspath(os.path.join('..', 'targets', 'switch',
                                        'build', 'thrift'))
sys.path.append(lib_path)

from switch_api.ttypes import  *
from switch_api import switch_api_rpc

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

import argparse

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--controller-ip', help='IPv4 address of openflow controller',
                    type=str, action="store", required=True)

parser_args = parser.parse_args()

device=0

def open_switchapi_connection():
    transport = TSocket.TSocket('localhost', 9091)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    client = switch_api_rpc.Client(protocol)
    transport.open()
    return transport, client

def close_switchapi_connection(transport):
    transport.close()

def cfg_switch():
    transport, client = open_switchapi_connection()

    client.switcht_api_init(device)
    vlan = client.switcht_api_vlan_create(device, 10)

    ifunion1 = interface_union(port_lag_handle = 0)
    ifinfo1 = switcht_interface_info_t(device=0, type=2,
                     u=ifunion1, mac='00:77:66:55:44:33', label=0)
    vlan_if1 = client.switcht_api_interface_create(device, ifinfo1)
    vlan_port1 = switcht_vlan_port_t(handle=vlan_if1, tagging_mode=0)
    client.switcht_api_vlan_ports_add(device, vlan, vlan_port1)

    ifunion2 = interface_union(port_lag_handle = 1)
    ifinfo2 = switcht_interface_info_t(device=0, type=2,
                     u=ifunion2, mac='00:77:66:55:44:34', label=0)
    vlan_if2 = client.switcht_api_interface_create(device, ifinfo2)
    vlan_port2 = switcht_vlan_port_t(handle=vlan_if2, tagging_mode=0)
    client.switcht_api_vlan_ports_add(device, vlan, vlan_port2)

    client.switcht_api_vlan_learning_enabled_set(vlan, 0)

    close_switchapi_connection(transport)

class OpenflowEnabledP4Switch(P4Switch):
    """
    Overrides the startup routine for P4Switch in order to
    provide specialize arguments.
    """
    def start( self, controllers ):
        "Start up a new P4 switch"
        print "Starting P4 switch", self.name
        args = [self.sw_path]
        args.extend(['--of-ip', parser_args.controller_ip])
        args.extend(['--no-veth'])
        for intf in self.intfs.values():
            if not intf.IP():
                args.extend( ['-i', intf.name] )
        if not self.pcap_dump:
            args.append( '--no-cli' )
        args.append( self.opts )

        logfile = '/tmp/p4ns.%s.log' % self.name

        print ' '.join(args)
        self.cmd( ' '.join(args) + ' >' + logfile + ' 2>&1 </dev/null &' )
        print "switch has been started"

class SingleSwitchTopo(Topo):
    "Single switch connected to 2 hosts."
    def __init__(self, sw_path, **opts):
        Topo.__init__(self, **opts)
        switch = self.addSwitch('s1', sw_path=sw_path, thrift_port=22222, pcap_dump=True)
        
        host1 = self.addHost('h1', ip = "10.0.10.1/24", mac = '00:04:00:00:00:01')
        host2 = self.addHost('h2', ip = "10.0.10.2/24", mac = '00:04:00:00:00:02')
        self.addLink(host1, switch)
        self.addLink(host2, switch)

def main():
    behavioral_model = os.path.join(sys.path[0], '../targets/switch/behavioral-model')
    topo = SingleSwitchTopo(behavioral_model)
    net = Mininet(topo=topo, host=P4Host, switch=OpenflowEnabledP4Switch,
                  controller=None )
    net.start()

    h1 = net.get('h1')
    h1.setARP("10.0.0.1", "00:aa:bb:00:00:00")
    h1.setDefaultRoute("dev eth0 via 10.0.0.1")
    h1.describe()

    h2 = net.get('h2')
    h2.setARP("10.0.1.1", "00:aa:bb:00:00:01")
    h2.setDefaultRoute("dev eth0 via 10.0.1.1")
    h2.describe()

    cfg_switch()

    time.sleep(1)

    print "Ready !"

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
