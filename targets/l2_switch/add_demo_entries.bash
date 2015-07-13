python ../../cli/pd_cli.py -p l2_switch -i p4_pd_rpc.l2_switch -s $PWD/of-tests/pd_thrift:$PWD/../../submodules/oft-infra -m "set_default_action smac mac_learn" -c localhost:22222
python ../../cli/pd_cli.py -p l2_switch -i p4_pd_rpc.l2_switch -s $PWD/of-tests/pd_thrift:$PWD/../../submodules/oft-infra -m "set_default_action dmac broadcast" -c localhost:22222
python ../../cli/pd_cli.py -p l2_switch -i p4_pd_rpc.l2_switch -s $PWD/of-tests/pd_thrift:$PWD/../../submodules/oft-infra -m "set_default_action mcast_src_pruning _nop" -c localhost:22222
mgrphdl=`python ../../cli/pd_cli.py -p l2_switch -i p4_pd_rpc.l2_switch -s $PWD/of-tests/pd_thrift:$PWD/../../submodules/oft-infra -m "mc_mgrp_create 1" -c localhost:22222 | awk '{print $NF;}'`
echo $mgrphdl > mgrp.hdl
l1hdl=`python ../../cli/pd_cli.py -p l2_switch -i p4_pd_rpc.l2_switch -s $PWD/of-tests/pd_thrift:$PWD/../../submodules/oft-infra -m "mc_l1_node_create 0" -c localhost:22222 | awk '{print $NF;}'`
echo $l1hdl > l1.hdl
python ../../cli/pd_cli.py -p l2_switch -i p4_pd_rpc.l2_switch -s $PWD/of-tests/pd_thrift:$PWD/../../submodules/oft-infra -m "mc_l1_associate_node $mgrphdl $l1hdl" -c localhost:22222
l2hdl=`python ../../cli/pd_cli.py -p l2_switch -i p4_pd_rpc.l2_switch -s $PWD/of-tests/pd_thrift:$PWD/../../submodules/oft-infra -m "mc_l2_node_create $l1hdl 30 -1" -c localhost:22222 | awk '{print $NF;}'`
echo $l2hdl > l2.hdl

