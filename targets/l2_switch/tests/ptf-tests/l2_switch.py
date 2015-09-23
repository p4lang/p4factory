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

import ptf.dataplane as dataplane
import pd_base_tests

from ptf.testutils import *
from ptf.thriftutils import *

from p4_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *


def setup_default_table_configurations(client, sess_hdl, dev_tgt):
    client.clean_all(sess_hdl, dev_tgt)

    result = client.smac_set_default_action_mac_learn(sess_hdl, dev_tgt)
    assert result == 0

    result = client.dmac_set_default_action_broadcast(sess_hdl, dev_tgt)
    assert result == 0

    result = client.mcast_src_pruning_set_default_action__nop(sess_hdl, dev_tgt)
    assert result == 0

def setup_pre(mc, sess_hdl, dev_tgt):
    mgrp_hdl = mc.mc_mgrp_create(sess_hdl, dev_tgt.dev_id, 1)
    port_map = [0] * 32
    lag_map = [0] * 32
    # port 1, port 2, port 3
    port_map[0] = (1 << 1) | (1 << 2) | (1 << 3)
    node_hdl = mc.mc_node_create(sess_hdl, dev_tgt.dev_id, 0,
                                 bytes_to_string(port_map),
                                 bytes_to_string(lag_map))
    mc.mc_associate_node(sess_hdl, dev_tgt.dev_id, mgrp_hdl, node_hdl)


class SimpleReplicationTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "l2_switch")

    def runTest(self):
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        setup_default_table_configurations(self.client, sess_hdl, dev_tgt)
        setup_pre(self.mc, sess_hdl, dev_tgt)

        # 5 is instance_type for replicated packets
        match_spec = l2_switch_mcast_src_pruning_match_spec_t(5)
        self.client.mcast_src_pruning_table_add_with__drop(
            sess_hdl, dev_tgt, match_spec
        )

        pkt = simple_ip_packet(ip_dst='10.0.0.2',
                               ip_id=101,
                               ip_ttl=64)
        send_packet(self, 2, str(pkt))
        exp_pkt = pkt
        verify_packets(self, exp_pkt, [1, 3]) # port 2 should have been pruned
