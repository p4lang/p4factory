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
from subprocess import Popen

import argparse

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--controller-ip', help='IPv4 address of openflow controller',
                    type=str, action="store", required=True)

parser_args = parser.parse_args()

import importlib
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.protocol import TMultiplexedProtocol

root_dir = os.path.dirname(os.path.realpath(__file__))
pd_dir = os.path.join(root_dir, '../targets/switch/tests/pd_thrift')
ptf_dir = os.path.join(root_dir, '..', 'submodules', 'ptf')
utils_dir = os.path.join(root_dir, '..', 'testutils')

sys.path.append(pd_dir)
sys.path.append(ptf_dir)
sys.path.append(utils_dir)

from p4_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *
from utils import *

def setup_bd(client, conn_mgr):
    """
    Instantiates port_vlan_mapping table entry setting bd == 0
    for untagged packets on ifindex 1.
    """
    sess_hdl = conn_mgr.client_init(16)
    dev_tgt = DevTarget_t(0, hex_to_i16(0xffff))
    ifindices = [1, 2]

    for ifindex in ifindices:
        action_spec = dc_set_bd_action_spec_t(
                                action_bd=0,
                                action_vrf=0,
                                action_rmac_group=0,
                                action_ipv4_unicast_enabled=True,
                                action_ipv6_unicast_enabled=True,
                                action_bd_label=0,
                                action_igmp_snooping_enabled=0,
                                action_mld_snooping_enabled=0,
                                action_ipv4_urpf_mode=0,
                                action_ipv6_urpf_mode=0,
                                action_stp_group=0,
                                action_stats_idx=0,
                                action_learning_enabled=0)
        
        mbr_hdl = client.bd_action_profile_add_member_with_set_bd(
                                sess_hdl, dev_tgt,
                                action_spec)
        match_spec = dc_port_vlan_mapping_match_spec_t(
                                ingress_metadata_ifindex=ifindex,
                                vlan_tag__0__valid=0,
                                vlan_tag__0__vid=0,
                                vlan_tag__1__valid=0,
                                vlan_tag__1__vid=0)
        client.port_vlan_mapping_add_entry(
                                sess_hdl, dev_tgt,
                                match_spec, mbr_hdl)

def configure_switch():
    p4_name = "dc"
    p4_client_module = importlib.import_module(".".join(["p4_pd_rpc", p4_name]))
    mc_client_module = importlib.import_module(".".join(["mc_pd_rpc", "mc"]))
    conn_mgr_client_module = importlib.import_module(".".join(["conn_mgr_pd_rpc", "conn_mgr"]))

    transport = TSocket.TSocket('localhost', 9090)
    transport = TTransport.TBufferedTransport(transport)
    bprotocol = TBinaryProtocol.TBinaryProtocol(transport)

    mc_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "mc")
    conn_mgr_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "conn_mgr")
    p4_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, p4_name)

    client = p4_client_module.Client(p4_protocol)
    mc = mc_client_module.Client(mc_protocol)
    conn_mgr = conn_mgr_client_module.Client(conn_mgr_protocol)
    transport.open()

    setup_bd(client, conn_mgr)

    transport.close()

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
        args.extend(['-t'])
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

    configure_switch()

    time.sleep(1)

    print "Ready !"

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
