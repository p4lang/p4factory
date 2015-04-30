
Sample SAI p4

This target defines a logical pipeline to describe the SAI API (v0.9.1).

SAI Preview version(v 0.1)

Basic SAI header file autogeneration from the sai_p4.p4

Makefile to build the SAI wrappers and autogenerate the handlers to
run the softswitch with SAI interfaces on a pipeline

Sample test functions (in C, in process callable) and using of-test framework

Sample L2 and L3 tests (sudo ./run_tests.py --test-dir of-tests/tests/sai_thrift sai.L3Test or sudo ./run_tests.py --test-dir of-tests/tests/sai_thrift sai.L2Test)


To run:

1. In targets/sai_p4, type make (or make bm)

2. This should result in behavioral-model executable.

3. Run as: sudo ./behavioral-model

4. In another shell run the tests using SAI thrift IPC to test

5. To terminate control 'C'


Status:

Currently the basic pipeline WITHOUT VLAN and ECMP groups is implemented.

Create and remove SAI functions implemented with the autogeneration from P4 program

TODO:

1. set and get attribute

2. VLAN and ECMP group functions (fucntion prototypes are in sai_templ.h.txt)

3. ACL and QoS table implementations

Soon to be updated!


