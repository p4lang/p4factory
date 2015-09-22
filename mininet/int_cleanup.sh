#!/bin/bash

sudo docker stop $(sudo docker ps -q)
ip link delete vm-eth21
ip link delete vm-eth22
ip link delete vm-eth23
ip link delete vm-eth24
ip link delete veth-t1
ifconfig testbr1 down
brctl delbr testbr1

sudo kill $(ps aux | grep '../apps/int/monitor/monitor.py\|preprocessor.py\|iperf\|client_msg_handler.py\|ping' | awk '{print $2}')
