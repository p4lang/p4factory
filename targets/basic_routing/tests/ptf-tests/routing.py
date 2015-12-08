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

priority = 100

def setup_default_table_configurations(client, sess_hdl, dev_tgt):
    client.clean_all(sess_hdl, dev_tgt)

    result = client.ipv4_fib_set_default_action_on_miss(sess_hdl, dev_tgt)
    assert result == 0

    result = client.ipv4_fib_lpm_set_default_action_on_miss(sess_hdl, dev_tgt)
    assert result == 0

    result = client.rewrite_mac_set_default_action_on_miss(sess_hdl, dev_tgt)
    assert result == 0


class TwoBdLpmTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "basic_routing")

    def runTest(self):
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        setup_default_table_configurations(self.client, sess_hdl, dev_tgt)

        # Add ports 1 and 2 to BD 10.
        for port in [1, 2]:
            result = self.client.port_mapping_table_add_with_set_bd(
                sess_hdl, dev_tgt, basic_routing_port_mapping_match_spec_t(port),
                basic_routing_set_bd_action_spec_t(10))
            assert result == port - 1

        # Add ports 3 and 4 to BD 20.
        for port in [3, 4]:
            result = self.client.port_mapping_table_add_with_set_bd(
                sess_hdl, dev_tgt, basic_routing_port_mapping_match_spec_t(port),
                basic_routing_set_bd_action_spec_t(20))
            assert result == port - 1

        # Add both BDs to same VRF.
        for expected_result, bd in enumerate([10, 20]):
            result = self.client.bd_table_add_with_set_vrf(
                sess_hdl, dev_tgt, basic_routing_bd_match_spec_t(bd),
                basic_routing_set_vrf_action_spec_t(30))
            assert result == expected_result

        lpm_entries = [ ('192.168.0.0', 16, 1), ('10.0.0.0', 8, 3) ]
        for expected_result, lpm_entry in enumerate(lpm_entries):
            prefix, prefix_length, nexthop_index = lpm_entry
            result = self.client.ipv4_fib_lpm_table_add_with_fib_hit_nexthop(
                sess_hdl, dev_tgt, basic_routing_ipv4_fib_lpm_match_spec_t(ingress_metadata_vrf=30, ipv4_dstAddr=ipv4Addr_to_i32(prefix), ipv4_dstAddr_prefix_length=prefix_length),
                basic_routing_fib_hit_nexthop_action_spec_t(nexthop_index))

        for expected_result, nexthop_index in enumerate(range(1,5)):
            result = self.client.nexthop_table_add_with_set_egress_details(
                sess_hdl, dev_tgt, basic_routing_nexthop_match_spec_t(nexthop_index),
                basic_routing_set_egress_details_action_spec_t(nexthop_index))
            assert result == expected_result
            dst_mac = '00:%02d:%02d:%02d:%02d:%02d' % tuple([nexthop_index for i in range(0, 5)])
            src_mac = '01:%02d:%02d:%02d:%02d:%02d' % tuple([nexthop_index for i in range(0, 5)])
            result = self.client.rewrite_mac_table_add_with_rewrite_src_dst_mac(
                sess_hdl, dev_tgt, basic_routing_rewrite_mac_match_spec_t(nexthop_index),
                basic_routing_rewrite_src_dst_mac_action_spec_t(macAddr_to_string(src_mac), macAddr_to_string(dst_mac)))
            assert result == expected_result

        pkt = simple_ip_packet(ip_dst='10.0.0.2',
                               ip_id=101,
                               ip_ttl=64)
        exp_pkt = simple_ip_packet(eth_dst='00:03:03:03:03:03',
                                   eth_src='01:03:03:03:03:03',
                                   ip_dst='10.0.0.2',
                                   ip_id=101,
                                   ip_ttl=63)
        send_packet(self, 2, str(pkt))
        verify_packets(self, exp_pkt, [3])

        pkt = simple_ip_packet(ip_dst='192.168.1.2',
                               ip_id=101,
                               ip_ttl=64)
        exp_pkt = simple_ip_packet(eth_dst='00:01:01:01:01:01',
                                   eth_src='01:01:01:01:01:01',
                                   ip_dst='192.168.1.2',
                                   ip_id=101,
                                   ip_ttl=63)
        send_packet(self, 4, str(pkt))
        verify_packets(self, exp_pkt, [1])
