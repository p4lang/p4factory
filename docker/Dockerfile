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
    quagga \
    redis-server \
    redis-tools \
    subversion \
    tshark \
    xterm

# install thrift
RUN mkdir -p /tmp/thrift ; \
    cd /tmp/thrift ; \
    wget -q http://archive.apache.org/dist/thrift/0.9.2/thrift-0.9.2.tar.gz ; \
    tar xvzf thrift-0.9.2.tar.gz; \
    cd thrift-0.9.2; \
    ./configure ; cd test/cpp ; ln -s . .libs ; cd ../.. ; \
    make -j 4 install; ldconfig ; \
    rm -fr /tmp/thrift

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

# install mstpd
RUN mkdir -p /third-party/diffs
COPY diffs/mstpd.diff /third-party/diffs/mstpd.diff
RUN cd /third-party; \
    svn checkout svn://svn.code.sf.net/p/mstpd/code/trunk mstpd; \
    cd mstpd; patch -p0 -i /third-party/diffs/mstpd.diff; make install

# install ctypesgen
RUN mkdir -p /tmp/ctypesgen ; \
    cd /tmp/ctypesgen ; \
    git clone https://github.com/davidjamesca/ctypesgen.git ; \
    cd ctypesgen ; \
    python setup.py install ; \
    rm -fr /tmp/ctypesgen

ADD p4factory /p4factory

ENV VTYSH_PAGER more
