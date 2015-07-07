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
# Topology with two switches and two hosts
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

def main():
    net = Mininet( controller = None )

    # add hosts
    h1 = net.addHost( 'h1', ip = '172.16.10.1/24' )
    h2 = net.addHost( 'h2', ip = '172.16.10.2/24' )

    # add switch 1
    sw1 = net.addSwitch( 'sw1', target_name = "p4dockerswitch",
            cls = P4DockerSwitch,
            start_program = "/p4factory/tools/startup.sh",
            thrift_port = 22000, pcap_dump = True )

    # add switch 2
    sw2 = net.addSwitch( 'sw2', target_name = "p4dockerswitch",
            cls = P4DockerSwitch,
            start_program = "/p4factory/tools/startup.sh",
            thrift_port = 22001, pcap_dump = True )

    # add links
    if StrictVersion(VERSION) <= StrictVersion('2.2.0') :
        net.addLink( sw1, h1, port1 = 1 )
        net.addLink( sw1, sw2, port1 = 2, port2 = 2 )
        net.addLink( sw2, h2, port1 = 1 )
    else:
        net.addLink( sw1, h1, port1 = 1, fast=False )
        net.addLink( sw1, sw2, port1 = 2, port2 = 2, fast=False )
        net.addLink( sw2, h2, port1 = 1, fast=False )

    # configure switch 1
    sw1.cmd( 'brctl addbr vlan100' )
    sw1.cmd( 'brctl addif vlan100 swp1' )
    sw1.cmd( 'brctl addif vlan100 swp2' )
    sw1.cmd( 'ip link set vlan100 up' )

    # configure switch 2
    sw2.cmd( 'brctl addbr vlan100' )
    sw2.cmd( 'brctl addif vlan100 swp1' )
    sw2.cmd( 'brctl addif vlan100 swp2' )
    sw2.cmd( 'ip link set vlan100 up' )

    net.start()

    CLI( net )

    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
