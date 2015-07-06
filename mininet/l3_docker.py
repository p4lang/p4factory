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
#       172.16.101.0/24         172.16.10.0/24         172.16.102.0./24
#  h1 ------------------- sw1 ------------------ sw2------- -------------h2
#     .5               .1     .1               .2   .1                  .5
##############################################################################

from mininet.net import Mininet, VERSION
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from distutils.version import StrictVersion
from p4_mininet import P4DockerSwitch

def main():
    net = Mininet( controller = None )

    # add hosts
    h1 = net.addHost( 'h1', ip = '172.16.101.5/24', mac = '00:04:00:00:00:02' )
    h2 = net.addHost( 'h2', ip = '172.16.102.5/24', mac = '00:05:00:00:00:02' )

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
    sw1.cmd( 'ip link set dev swp1 address 00:01:00:00:00:01' )
    sw1.cmd( 'ip link set dev swp2 address 00:01:00:00:00:02' )
    sw1.cmd( 'ip address add 172.16.101.1/24 broadcast + dev swp1' )
    sw1.cmd( 'ip address add 172.16.10.1/24 broadcast + dev swp2' )
    sw1.cmd( 'ip neigh add 172.16.101.5 lladdr 00:04:00:00:00:02 dev swp1' )
    sw1.cmd( 'ip neigh add 172.16.10.2 lladdr 00:02:00:00:00:02 dev swp2' )
    sw1.cmd( 'ip route add 172.16.102/24 nexthop via 172.16.10.2' )

    # configure switch 2
    sw2.cmd( 'ip link set dev swp1 address 00:02:00:00:00:01' )
    sw2.cmd( 'ip link set dev swp2 address 00:02:00:00:00:02' )
    sw2.cmd( 'ip address add 172.16.102.1/24 broadcast + dev swp1' )
    sw2.cmd( 'ip address add 172.16.10.2/24 broadcast + dev swp2' )
    sw2.cmd( 'ip neigh add 172.16.102.5 lladdr 00:05:00:00:00:02 dev swp1' )
    sw2.cmd( 'ip neigh add 172.16.10.1 lladdr 00:01:00:00:00:02 dev swp2' )
    sw2.cmd( 'ip route add 172.16.101/24 nexthop via 172.16.10.1' )

    net.start()

    # configure hosts
    h1.setARP( ip = '172.16.101.1', mac = '00:01:00:00:00:01' )
    h2.setARP( ip = '172.16.102.1', mac = '00:02:00:00:00:01' )
    h1.setDefaultRoute( 'via 172.16.101.1' )
    h2.setDefaultRoute( 'via 172.16.102.1' )

    CLI( net )

    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
