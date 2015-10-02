#!/bin/bash

l1hdl=`cat l1.hdl`
l2hdl=`cat l2.hdl`
mgrphdl=`cat mgrp.hdl`

python ../../cli/pd_cli.py -p l2_switch -i p4_pd_rpc.l2_switch -s $PWD/tests/pd_thrift:$PWD/../../testutils -m "mc_l2_node_destroy $l2hdl" -c localhost:22222
python ../../cli/pd_cli.py -p l2_switch -i p4_pd_rpc.l2_switch -s $PWD/tests/pd_thrift:$PWD/../../testutils -m "mc_l1_node_destroy $l1hdl" -c localhost:22222
python ../../cli/pd_cli.py -p l2_switch -i p4_pd_rpc.l2_switch -s $PWD/tests/pd_thrift:$PWD/../../testutils -m "mc_mgrp_destroy $mgrphdl" -c localhost:22222
