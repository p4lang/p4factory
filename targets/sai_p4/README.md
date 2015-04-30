Sample SAI Pipeline (v0.1)
==========================
This target implements a logical pipeline which can be used to generate v0.9.1 of SAI API.

Details
=======
1. Basic SAI header file autogeneration from the sai_p4.p4
2. Makefile to 
   a. Build the SAI wrappers
   b. Auto-generate the handlers to run the softswitch with SAI interfaces
3. Sample test functions (in C, in process callable) and using of-test framework
4. Sample L2 and L3 tests

Run
===

1. Build behavioral-model
   In targets/sai_p4, type make (or make bm).
   This should result in behavioral-model executable.

2. Run behavioral-model
   In tragets/sai_p4, type sudo ./behavioral-model

3. Run tests
   In another shell run the tests using SAI thrift IPC to test
   sudo ./run_tests.py --test-dir of-tests/tests/sai_thrift sai.L3Test
   or
   sudo ./run_tests.py --test-dir of-tests/tests/sai_thrift sai.L2Test

4. To terminate behavioral-model
   Type Control+'C' in the shell running the behavioral-model


Notes
=====

Currently the pipeline is defined WITHOUT VLAN and ECMP groups.

Create and Remove SAI functions are auto-generated from P4 program

Coming soon
===========

1. Set and Get attributes
2. VLAN and ECMP group functions (function prototypes are in sai_templ.h.txt)
3. ACL and QoS table implementations
