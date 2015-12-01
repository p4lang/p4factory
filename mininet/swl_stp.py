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
# Topology with four switches and two hosts with STP
#
#              sw3----sw4
#              |  \  /  |
#              |   \/   |
#              |   /\   |
#              |  /  \  |
#              sw1----sw2
#              |        |
#              |        |
#              h1       h2
#
# The topology runs mstpd. To workaround an issue of running msptd inside
# docker containers, copy the script 'configs/bridge-stp' to /sbin/bridge-stp
# on the host operating system. This script is invoked by the Kernel when a
# bridge is create to determine if it has to run the spanning tree protocol
# or some other process is responsible for it.
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
            cls = P4DockerSwitch, config_fs = 'configs/sw1/stp',
            pcap_dump = True )

    # add switch 2
    sw2 = net.addSwitch( 'sw2', target_name = "p4dockerswitch",
            cls = P4DockerSwitch, config_fs = 'configs/sw2/stp',
            pcap_dump = True )

    # add switch 3
    sw3 = net.addSwitch( 'sw3', target_name = "p4dockerswitch",
            cls = P4DockerSwitch, config_fs = 'configs/sw3/stp',
            pcap_dump = True )

    # add switch 4
    sw4 = net.addSwitch( 'sw4', target_name = "p4dockerswitch",
            cls = P4DockerSwitch, config_fs = 'configs/sw4/stp',
            pcap_dump = True )

    # add links
    if StrictVersion(VERSION) <= StrictVersion('2.2.0') :
        net.addLink( sw1, h1, port1 = 4 )
        net.addLink( sw2, h2, port1 = 4 )
        net.addLink( sw1, sw2, port1 = 1, port2 = 1 )
        net.addLink( sw1, sw3, port1 = 2, port2 = 1 )
        net.addLink( sw1, sw4, port1 = 3, port2 = 1 )
        net.addLink( sw2, sw3, port1 = 2, port2 = 2 )
        net.addLink( sw2, sw4, port1 = 3, port2 = 2 )
        net.addLink( sw3, sw4, port1 = 3, port2 = 3 )
    else:
        net.addLink( sw1, h1, port1 = 4, fast = False )
        net.addLink( sw2, h2, port1 = 4, fast = False )
        net.addLink( sw1, sw2, port1 = 1, port2 = 1, fast = False )
        net.addLink( sw1, sw3, port1 = 2, port2 = 1, fast = False )
        net.addLink( sw1, sw4, port1 = 3, port2 = 1, fast = False )
        net.addLink( sw2, sw3, port1 = 2, port2 = 2, fast = False )
        net.addLink( sw2, sw4, port1 = 3, port2 = 2, fast = False )
        net.addLink( sw3, sw4, port1 = 3, port2 = 3, fast = False )

    net.start()

    CLI( net )

    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
