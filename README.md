P4 Model Repository
========

This repository maintains a sample set of the P4 programs and allows building P4 for the P4
Behavioral Model.

Quickstart
========
To install all the Ubuntu 14.04 dependencies, run 

    ./install.sh

Before running the simulator, you need to create veth interfaces that the
simulator can connect to. To create them, you need to run:  

    sudo p4factory/tools/veth_setup.sh


To validate you installation and test the simulator on a simple P4 target, do
the following:  

    cd p4factory/targets/basic_routing/  
    make bm  
    sudo ./behavioral-model  

To run a simple test, run this in a different terminal:  

    cd p4factory/targets/basic_routing/  
    sudo python run_tests.py --test-dir of-tests/tests/  

Mininet Integration
========

We provide a Mininet integration for one of our existing targets: simple_router  

To run it, do the following:  

    cd p4factory/targets/simple_router/  
    make bm  
    ./run_demo.bash  
    
To install some table entries, run in a different terminal:  

    ./run_add_demo_entries.bash  

You can then type commands in the Mininet CLI:  

    mininet> h1 ping h2

Building and Running a Target
========

Each targeted P4 program is set up in a directory under targets/. Inside the target directory 
is a Makefile with the instructions on how to build the behavioral model for that P4 program.

To build the target "project_name":

    cd targets/project_name
    make bm
This should result in an executable in the same directory called "behavioral_mode"

Creating a New Target
========

To add a new target, cd to targets/ and run:

    p4factory/tools/newtarget.py project_name

where project_name is the name of the P4 program (without the .p4 extension). This will create a new 
directory in targets/ called project_name/, set it up to build the behavioral model, and create a 
template for the P4 program there named project_name.p4. Then, edit that file or copy your P4 
program to that file and make in that directory.

P4 Dependency Graph Generator
========

The relationships between tables of more complex P4 program can be difficult to comprehend.  The p4c-graphs utility parses through the the P4 program and generates a dependency graph using graphviz.  The dependency graph can be generated with the following command:

    p4c-graphs <p4 code>

The resulting files can be viewed using xdot or with a PNG viewer.

