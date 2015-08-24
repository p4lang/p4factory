#!/bin/bash

brctl addbr vlan100
brctl addif vlan100 swp1
brctl addif vlan100 swp2
ip link set vlan100 up
