switch.p4 with bmv2
===================

This directory lets you run the switch.p4 program using the new behavioral-model
code, which we call bmv2.

Unlike in the original behavioral-model code (p4c-behavioral), the data plane
and the application run in 2 different processes, and you will have to run these
2 processes (first the switch, then the application) before running the tests.

Building the application / drivers executable
---------------------------------------------

As with the original behavioral-model, you can choose to use the auto-generated
API, switchapi or switchsai:

To build the drivers with only the auto-generated API in a thrift server,

    make bm

To build the drivers with the switchapi library (*drivers-switchapi*),

    make bm-switchapi

When built with this option, there are thrift servers on ports 9090 and 9091
for the auto-generated table APIs and the switchapi library APIs respectively.

To build the drivers with the SAI API library (*drivers-switchsai*),

    make bm-switchsai

When built with this option, there are thrift servers on ports 9090, 9091 and
9092 for the auto-generated table APIs, the switchapi library APIs and the SAI
library APIs respectively.

**Note: because compilation can take a long time, do not hesitate to use
  parallel `make` if you have enough resources on your machine. For example, to
  run 4 simultaneous jobs: `make -j4 bm`**

Running Tests
-------------

You first need to start the data plane,

    ./run_bm.sh

You can then run the drivers in a second terminal, with one of the following
commands (depending on what you built),

     sudo ./drivers             # auto-generated PD API (with RPC server)
     sudo ./drivers-switchapi   # PD API + switchapi (with RPC servers)
     sudo ./drivers-switchsai   # PD API + switchapi + switchsai (with RPC servers)

You can then go up one directory in a third terminal and run the tests.

To run the pd thrift testcases,

    sudo ./run_tests.py --test-dir tests/ptf-tests/pd-tests switch

To run the api thrift testcases. Because 3 of the unit tests are not working yet
with the new behavioral-model (*MirrorAclTest_e2e*, *MirrorAclTest_i2e_erspan*,
*MirrorAclTest_i2e*), you need to set the environment variable `BMV2_TEST` to
`1` before running the test script. These 3 tests will then be skipped.

    sudo BMV2_TEST=1 ./run_tests.py --test-dir tests/ptf-tests/api-tests switch

To run the SAI thrift testcases,

    sudo ./run_tests.py --test-dir tests/ptf-tests/sai-tests switch
