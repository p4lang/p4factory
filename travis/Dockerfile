FROM      ubuntu:14.04
MAINTAINER Antonin Bas <antonin@barefootnetworks.com>

RUN apt-get update
RUN apt-get install -y \
    automake \
    bridge-utils \
    build-essential \
    ethtool \
    git \
    libboost-dev \
    libboost-filesystem-dev \
    libboost-program-options-dev \
    libboost-system-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libedit-dev \
    libevent-dev \
    libglib2.0-dev \
    libhiredis-dev \
    libjudy-dev \
    libnl-route-3-dev \
    libpcap0.8 \
    libpcap0.8-dev \
    libtool \
    libssl-dev \
    openssh-server \
    packit \
    pkg-config \
    python-dev \
    python-pygraph \
    python-pygraphviz \
    python-setuptools \
    python-thrift \
    python-yaml \
    redis-server \
    redis-tools \
    libgmp-dev \
    python-pip

ADD p4factory /p4factory

# install thrift
RUN bash /p4factory/submodules/bm/build/travis/install-thrift.sh

# install nanomsg
RUN bash /p4factory/submodules/bm/build/travis/install-nanomsg.sh

# install scapy
RUN mkdir -p /tmp/scapy ; \
    cd /tmp/scapy ; \
    git clone https://github.com/p4lang/scapy-vxlan.git ; \
    cd scapy-vxlan ; \
    python setup.py install ; \
    rm -fr /tmp/scapy

# install p4-hlir
RUN mkdir -p /tmp/p4-hlir ; \
    cd /tmp/p4-hlir ; \
    git clone https://github.com/p4lang/p4-hlir.git ; \
    cd p4-hlir ; \
    python setup.py install ; \
    rm -fr /tmp/p4-hlir

RUN pip install -r /p4factory/submodules/p4c-bm/requirements.txt
