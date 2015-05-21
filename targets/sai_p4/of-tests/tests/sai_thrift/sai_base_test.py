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

import p4_sai_rpc.sai_p4_sai as p4_sai_rpc
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

        self.client = p4_sai_rpc.Client(self.protocol)
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
