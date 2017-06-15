Important: git submodules
========
We often update the submodules for this repo. This is why we recommend that you
run the following command whenever pulling the latest version of master:

    git submodule update --init --recursive

Quickstart
========
To install all the Ubuntu 14.04 dependencies, run

    ./install_deps.sh

Before running the simulator, you need to create veth interfaces that the
simulator can connect to. To create them, you need to run:

    sudo p4factory/tools/veth_setup.sh

We use autoconf tools to generate makefiles. Run the following commands
to prepare your workspace.

    cd p4factory
    ./autogen.sh
    ./configure

To validate your installation and test the simulator on a simple P4 target, do
the following:

    cd p4factory/targets/basic_routing/
    make bm
    sudo ./behavioral-model

To run a simple test, run this in a different terminal:

    cd p4factory/targets/basic_routing/
    sudo python run_tests.py --test-dir tests/ptf-tests/

Building and Running a Target
========

Each P4 program (called a 'target') is set up in a directory under targets/.
Inside the target directory is a Makefile with the instructions on how to build
the behavioral model for that P4 program.

To build the target "project_name":

    cd targets/project_name
    make bm

This should result in an executable in the same directory called
"behavioral_model"

To add Openflow support to a target, please refer [here](https://github.com/p4lang/p4ofagent).

Integration with Mininet
========

Integration with Mininet provides a way to instantiate a network of nodes each
running a data plane described in P4.

We provide a Mininet integration for one of our existing targets: simple_router

To run it, do the following:

    cd p4factory/targets/simple_router/
    make bm
    ./run_demo.bash

To install some table entries, run the following (in a different terminal):

    ./run_add_demo_entries.bash

You can then type commands in the Mininet CLI:

    mininet> h1 ping h2

Integration with Mininet and Docker
========

Integration with Mininet and Docker provides a way to instantiate a network
of nodes with each node running a data plane described in P4 along with its
own control plane instance (eg. Quagga) packaged into a Linux container
(Docker).

Mininet: Install Mininet from http://mininet.org/download/.

Docker: Install Docker from http://docs.docker.com/linux/started/.

Please see README.md under submodules/switch for a specific example on how to build
the docker image and run the test topologies.

Creating a New Target
========

To add a new target, cd to targets/ and run:

    p4factory/tools/newtarget.py project_name

where project_name is the name of the P4 program (without the .p4 extension).
This will create a new directory in targets/ called project_name/, set it up
to build the behavioral model, and create a template for the P4 program there
named project_name.p4. Then, edit that file or copy your P4 program to that
file and make in that directory.

P4 Dependency Graph Generator
========

The relationships between tables of more complex P4 program can be difficult
to comprehend.  The p4-graphs utility parses through the the P4 program and
generates a dependency graph using graphviz.  The dependency graph can be
generated with the following command:

    p4-graphs <p4 code>

The resulting files can be viewed using xdot or with a PNG viewer.

Towards a better behavioral model: bmv2
========

We have released a new version of the behavioral model, written in C++. Some
targets already support this new model -in addition to the original version,
p4c-behavioral. If you see a target with a bmv2 directory, it means the new
model is supported and you can try it out!

The new model splits the switch logic and the auto-generated PD API (drivers)
into 2 different processes.

For example, the l2_switch target supports bmv2. To run the code, you can do the
following:

      cd targets/l2_switch/bmv2/
      make bm
      ./run_bm.sh       # to start the data plane 
      sudo ./drivers    # in a second terminal, to start the PD APIs (RPC server)

You can then run the tests in a third terminal, by going up one directory:

    sudo python run_tests.py --test-dir tests/ptf-tests/

The switch.p4 target already supports bmv2. For more information take a look at
the [bmv2 README](targets/switch/bmv2/README.md).


The new behavioral model code is also hosted on p4lang, in [this
repository](https://github.com/p4lang/behavioral-model).
