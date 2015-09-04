switch.p4 with bmv2
===================

This directory lets you run the switch.p4 using the new behavioral-model code,
which we call bmv2. All but 3 of the unit tests work with bmv2.

Unlike in the original behavioral-model code (p4c-behavioral), the switch and
the application run in 2 different processes, and you will have to run these 2
processes (first the switch, then the application) before running the tests.

Building the application / drivers executable
---------------------------------------------

As with the original behavioral-model, you can choose to use the auto-generated
API or switchapi:

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

Running Tests
-------------

You first need to start the switch,

    ./run.sh

You can then run the drivers in a second terminal, with one of the following
commands (depending on what you built),

     sudo ./drivers
     sudo ./drivers-switchapi
     sudo ./drivers-switchsai

You can then go up one directory in a third terminal and run the tests.

To run the pd thrift testcases,

    sudo ./run_tests.py --test-dir of-tests/tests/pd-tests switch

To run the api thrift testcases,

    sudo ./run_tests.py --test-dir of-tests/tests/api-tests switch

To run the SAI thrift testcases,

    sudo ./run_tests.py --test-dir of-tests/tests/sai-tests switch
