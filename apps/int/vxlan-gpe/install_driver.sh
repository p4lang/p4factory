#!/bin/bash

modprobe -r vxlan
cp vxlan.ko /lib/modules/$(uname -r)/kernel/drivers/net
modprobe vxlan
