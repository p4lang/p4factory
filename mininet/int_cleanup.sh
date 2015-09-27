#!/bin/bash
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


sudo docker stop $(sudo docker ps -q)
ip link delete vm-eth21
ip link delete vm-eth22
ip link delete vm-eth23
ip link delete vm-eth24
ip link delete veth-t1
ifconfig testbr1 down
brctl delbr testbr1

sudo kill $(ps aux | grep '../apps/int/monitor/monitor.py\|preprocessor.py\|iperf\|client_msg_handler.py\|ping' | awk '{print $2}')
