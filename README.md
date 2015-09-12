P4 Model Repository
========

[![Build Status](https://travis-ci.org/p4lang/p4factory.svg?branch=master)](https://travis-ci.org/p4lang/p4factory)

This repository maintains a sample set of the P4 programs and allows building
P4 for the P4 Behavioral Model.

Important: git submodules
========
We often update the submodules for this repo. This is why we recommend that you
run the following command whenever pulling the latest version of master:

    git submodule update --init --recursive

Quickstart
========
To install all the Ubuntu 14.04 dependencies, run

    ./install.sh

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
    sudo python run_tests.py --test-dir of-tests/tests/

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

To build the docker image for a target, include the file "makefiles/docker.mk"
in the Makefile, set the variable DOCKER_IMAGE to the Makefile target to build
and build the target "docker-image".

For example:

    # In target/switch/Makefile, add the following lines
    DOCKER_IMAGE := bm-switchlink
    include ${MAKEFILES_DIR}/docker.mk

    # To build the docker image
    make docker-image

The docker image is called "p4dockerswitch".

Sample output:

    sudo docker images
    REPOSITORY          TAG                 IMAGE ID            CREATED             VIRTUAL SIZE
    p4dockerswitch      latest              84f6c028ad6c        14 hours ago        1.234 GB
    ubuntu              14.04               6d4946999d4f        3 weeks ago         188.3 MB

We provide a few topologies that showcase Mininet and Docker integration.

SAI:

    mininet/sai_l2.py : Simple L2 topology with two switches and two hosts.

    mininet/sai_l3.py : Simple L3 topology with two switches and two hosts.

Switchlink with SAI:

    mininet/swl_l2.py : Simple L2 topology with two switches and two hosts.
                        The topology is loop free (no spanning tree protocol).

    mininet/swl_stp.py : L2 topology with four switches and two hosts. It runs
                         MSTPD to form a loop free topology.

    mininet/swl_l3_static.py : Simple L3 topology with two switches and two
                               hosts. The setup is statically configured.

    mininet/swl_ospf.py : Simple L3 topology with two switches and two hosts.
                          The setup runs OSPF (Quagga) to learn and advertise
                          networks.

    mininet/swl_bgp.py : Simple L3 topology with two switches and two hosts.
                         The setup runs EBGP (Quagga) to learn and advertise
                         networks.

Please see README.md under target/switch for a specific example on how to build
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
to comprehend.  The p4c-graphs utility parses through the the P4 program and
generates a dependency graph using graphviz.  The dependency graph can be
generated with the following command:

    p4c-graphs <p4 code>

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

    sudo python run_tests.py --test-dir of-tests/tests/

The switch.p4 target already supports bmv2. For more information take a look at
the [bmv2 README](targets/switch/bmv2/README.md).

The new behavioral model code is also hosted on p4lang, in [this
repository](https://github.com/p4lang/behavioral-model).
