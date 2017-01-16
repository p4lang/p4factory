FROM      ubuntu:14.04
MAINTAINER Antonin Bas <antonin@barefootnetworks.com>

RUN apt-get update
RUN apt-get install -y \
    automake \
    bridge-utils \
    build-essential \
    cmake \
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
    libffi-dev \
    libgmp-dev \
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
    python-pip \
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

RUN pip install tenjin

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

RUN mkdir -p /tmp/install_tmp ; \
    cd install_tmp ; \
    wget -c http://archive.apache.org/dist/thrift/0.9.2/thrift-0.9.2.tar.gz ; \
    tar zxvf thrift-0.9.2.tar.gz ; \
    cd thrift-0.9.2 ; \
    ./configure --with-cpp=yes --with-c_glib=no --with-java=no --with-ruby=no --with-erlang=no --with-go=no --with-nodejs=no ; \
    make -j4 ; \
    make install ; \
    ldconfig ; \
    cd .. ; \
    wget https://github.com/nanomsg/nanomsg/archive/1.0.0.tar.gz -O nanomsg-1.0.0.tar.gz ; \
    tar -xzvf nanomsg-1.0.0.tar.gz ; \
    cd nanomsg-1.0.0 ; \
    mkdir build ; \
    cd build ; \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr ; \
    cmake --build . ; \
    cmake --build . --target install ; \
    cd ../../ ; \
    git clone https://github.com/nanomsg/nnpy.git ; \
    cd nnpy ; \
    git checkout c7e718a5173447c85182dc45f99e2abcf9cd4065 ; \
    ldconfig ; \
    pip install cffi ; \
    pip install . ; \
    cd ../..; \
    rm -rf /tmp/install_tmp

ENV VTYSH_PAGER more
