#!/usr/bin/python
# Copyright 2015-present Barefoot Networks, Inc.
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

import os
from int_cfg import *

def run_cfg():

  vxlan_id = 10
  vxlan_group = '239.0.0.10'
  vxlan_mtu = 1300

  h1_vxlan_cfg = VxlanConfig( vxlan_id, vxlan_group, '10.2.1.1', 24, '00:11:22:33:44:51', vxlan_mtu  )
  h2_vxlan_cfg = VxlanConfig( vxlan_id, vxlan_group, '10.2.1.2', 24, '00:11:22:33:44:52', vxlan_mtu  )
  h3_vxlan_cfg = VxlanConfig( vxlan_id, vxlan_group, '10.2.1.3', 24, '00:11:22:33:44:53', vxlan_mtu  )
  h4_vxlan_cfg = VxlanConfig( vxlan_id, vxlan_group, '10.2.1.4', 24, '00:11:22:33:44:54', vxlan_mtu  )

  host_cfgs = {
    'h1' : HostConfig( name = 'h1', mac = '00:c0:a0:a0:00:01', ip = '10.0.1.1', prefix_len = 24, vxlan_cfg = h1_vxlan_cfg ),
    'h2' : HostConfig( name = 'h2', mac = '00:c0:a0:a0:00:02', ip = '10.0.2.2', prefix_len = 24, vxlan_cfg = h2_vxlan_cfg ),
    'h3' : HostConfig( name = 'h3', mac = '00:c0:a0:a0:00:03', ip = '10.0.3.3', prefix_len = 24, vxlan_cfg = h3_vxlan_cfg ),
    'h4' : HostConfig( name = 'h4', mac = '00:c0:a0:a0:00:04', ip = '10.0.4.4', prefix_len = 24, vxlan_cfg = h4_vxlan_cfg )
  }

  leaf1_port_cfgs = [
    PortConfig( port_no = 0, ip = '10.0.1.100', prefix_len = 24, mac = '00:01:00:00:00:01' ),
    PortConfig( port_no = 1, ip = '10.0.2.100', prefix_len = 24, mac = '00:01:00:00:00:02' ),
  ] 

  leaf2_port_cfgs = [
    PortConfig( port_no = 0, ip = '10.0.3.100', prefix_len = 24, mac = '00:02:00:00:00:01' ),
    PortConfig( port_no = 1, ip = '10.0.4.100', prefix_len = 24, mac = '00:02:00:00:00:02' ),
  ]

  switch_cfgs = [
    SwitchConfig( name       = 'leaf1', 
                  port_cfgs  = leaf1_port_cfgs,
                  swapi_port = 26000,
                  config_fs  = 'configs/leaf1/l3_int_ref_topo',
                  switch_id  = 0x000000A1, pps=400, qdepth=15 ),
    SwitchConfig( name       = 'leaf2',
                  port_cfgs  = leaf2_port_cfgs,
                  swapi_port = 26001,
                  config_fs  = 'configs/leaf2/l3_int_ref_topo',
                  switch_id  = 0x000000A2, pps=400, qdepth=15 ),
    SwitchConfig( name       = 'spine1',
                  port_cfgs  = [],
                  swapi_port = 26002,
                  config_fs  = 'configs/spine1/l3_int_ref_topo',
                  switch_id  = 0x000000B1, pps=400, qdepth=15 ),
    SwitchConfig( name       = 'spine2',
                  port_cfgs  = [],
                  swapi_port = 26003,
                  config_fs  = 'configs/spine2/l3_int_ref_topo',
                  switch_id  = 0x000000B2, pps=400, qdepth=15 ),
  ]

  link_cfgs = [
    LinkConfig( 'leaf1', 'h1', 0 ),
    LinkConfig( 'leaf1', 'h2', 1 ),
    LinkConfig( 'leaf1', 'spine1', 2, 0 ),
    LinkConfig( 'leaf1', 'spine2', 3, 0 ),

    LinkConfig( 'leaf2', 'h3', 0 ),
    LinkConfig( 'leaf2', 'h4', 1 ),
    LinkConfig( 'leaf2', 'spine1', 2, 1 ),
    LinkConfig( 'leaf2', 'spine2', 3, 1 ),
  ]

  mgr = NetworkManager( host_cfgs.values(), switch_cfgs, link_cfgs )
  net = mgr.setupAndStartNetwork()

  h1 = net.get('h1')
  h2 = net.get('h2')
  h3 = net.get('h3')
  h4 = net.get('h4')

  h1.cmd("iperf -s &")
  h2.cmd("iperf -s &")
  h3.cmd("iperf -s &")
  h4.cmd("iperf -s &")

  # TODO: start iperf clients
  h1.cmd("iperf -c 10.2.1.4 -t 3000 > /dev/null &")
  h3.cmd("iperf -c 10.2.1.2 -t 3000 > /dev/null &")

  CLI(net)

  mgr.cleanup()
  net.stop()


# cleanup from previous run
os.system('./int_cleanup.sh > /dev/null 2>&1')
run_cfg()
