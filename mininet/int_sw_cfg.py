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
import pdb
lib_path = os.path.abspath(os.path.join('..', 'targets', 'switch', 'of-tests', 'pd_thrift'))
sys.path.append(lib_path)
import switch_api_thrift.switch_api_rpc as bfn_api_rpc

from switch_api_thrift.ttypes import  *

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

def open_connection(port):
    transport = TSocket.TSocket('localhost', port)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    client = bfn_api_rpc.Client(protocol)
    transport.open()
    return transport, client

def close_connection(transport):
    transport.close()

def cfg_switch1():
    port_list = []
    device = 0
    transport, client = open_connection(26000)
    print "INT Config SW1"

    client.switcht_api_init(device)

    client.switcht_INT_transit_enable(device, 0x11111111, 1)

    close_connection(transport)

def main():
    cfg_switch1()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()

