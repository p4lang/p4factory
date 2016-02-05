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
# Topology with one switch (one routed port, one L3 virtual interface with
# three ports) and four hosts
#
#       172.16.101.0/24         172.16.102.0./24
#  h1 ------------------- sw1 ---+----------------h2 (.5)
#     .5               .1     .1 |
#                                +--------------- h3 (.6)
#                                |
#                                ---------------- h4 (.7)
#
##############################################################################

from docker.p4model import *
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet, VERSION
from distutils.version import StrictVersion
import sys

def main(cli=0):
    net = Mininet( controller=None )

    # add hosts
    h1 = net.addHost( 'h1', ip = '172.16.101.5/24', mac = '00:04:00:00:00:02' )
    h2 = net.addHost( 'h2', ip = '172.16.102.5/24', mac = '00:05:00:00:00:02' )
    h3 = net.addHost( 'h3', ip = '172.16.102.6/24', mac = '00:06:00:00:00:02' )
    h4 = net.addHost( 'h4', ip = '172.16.102.7/24', mac = '00:07:00:00:00:02' )

    # add switch
    sw_model_dir = '/p4factory/targets/switch/'
    sw1_fs_map = []
    sw1_fs_map.append( [ os.getcwd() + '/' + 'configs/sw1/l3vi', '/configs' ] )
    sw1 = net.addSwitch( 'sw1', cls=BmDockerSwitch, image='p4dockerswitch',
                         fs_map=sw1_fs_map, model_dir=sw_model_dir )

    # add links
    if StrictVersion(VERSION) <= StrictVersion('2.2.0') :
        net.addLink( sw1, h1, port1 = 1 )
        net.addLink( sw1, h2, port1 = 2 )
        net.addLink( sw1, h3, port1 = 3 )
        net.addLink( sw1, h4, port1 = 4 )
    else:
        net.addLink( sw1, h1, port1 = 1, fast=False )
        net.addLink( sw1, h2, port1 = 2, fast=False )
        net.addLink( sw1, h3, port1 = 3, fast=False )
        net.addLink( sw1, h4, port1 = 4, fast=False )

    net.start()

    # configure hosts
    h1.setDefaultRoute( 'via 172.16.101.1' )
    h2.setDefaultRoute( 'via 172.16.102.1' )
    h3.setDefaultRoute( 'via 172.16.102.1' )
    h4.setDefaultRoute( 'via 172.16.102.1' )

    result = 0

    if cli:
        CLI( net )
    else:
        hosts = net.hosts

        # ping hosts
        print "PING BETWEEN THE HOSTS"
        result = net.ping( hosts, 30 )

        # print host arp table & routes
        for host in hosts:
            print "ARP ENTRIES ON HOST"
            print host.cmd( 'arp -n' )
            print "HOST ROUTES"
            print host.cmd( 'route' )
            print "HOST INTERFACE LIST"
            intfList = host.intfNames()
            print intfList

        if result != 0:
            print "PING FAILED BETWEEN HOSTS %s" % ( hosts )
        else:
            print "PING SUCCESSFUL!!!"

    net.stop()
    return result

if __name__ == '__main__':
    args = sys.argv
    setLogLevel( 'info' )
    cli = 0
    if "--cli" in args:
        cli = 1
    main(cli)
