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

"""
Base classes for test cases

Tests will usually inherit from one of these classes to have the controller
and/or dataplane automatically set up.
"""

import os
import logging
import unittest


import oftest
from oftest import config
import oftest.dataplane as dataplane

################################################################
#
# Thrift interface base tests
#
################################################################

import switch_api_thrift.switch_api_rpc as switch_api_rpc
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol


class ThriftBaseTest(unittest.TestCase):
    def __str__(self):
        return self.id().replace('.runTest', '')

    def setUp(self):
        oftest.open_logfile(str(self))
        logging.info("** START TEST CASE " + str(self))

    def tearDown(self):
        logging.info("** END TEST CASE " + str(self))

class ThriftInterface(ThriftBaseTest):

    def setUp(self):
        ThriftBaseTest.setUp(self)

        # Set up thrift client and contact server
        self.transport = TSocket.TSocket('localhost', 9091)
        self.transport = TTransport.TBufferedTransport(self.transport)
        self.protocol = TBinaryProtocol.TBinaryProtocol(self.transport)

        self.client = switch_api_rpc.Client(self.protocol)
        self.transport.open()

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        ThriftBaseTest.tearDown(self)
        self.transport.close()

class ThriftInterfaceDataPlane(ThriftInterface):
    """
    Root class that sets up the thrift interface and dataplane
    """
    def setUp(self):
        ThriftInterface.setUp(self)
        self.dataplane = oftest.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        ThriftInterface.tearDown(self)
