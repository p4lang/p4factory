# installation script for ubuntu 14.04
trap 'exit' ERR

sudo apt-get update

sudo apt-get install -y automake bison doxygen ethtool flex g++ git \
ipython ipython-notebook libany-moose-perl libboost-dev libboost-filesystem-dev \
libboost-program-options-dev libboost-system-dev libboost-test-dev libbsd-dev \
libedit-dev libevent-dev libfreetype6-dev libhiredis-dev libjudy-dev libpcap-dev \
libpng-dev libssl-dev libtool libyaml-0-2 libbz2-dev mininet openssl pkg-config python-dev \
python-dpkt python-jsonpickle python-imaging-tk python-matplotlib python-nose python-numpy \
python-pandas python-pip python-pygraph python-pygraphviz python-scipy \
python-setuptools python-sympy python-yaml redis-server thrift-compiler \
wireshark libgmp-dev

sudo pip install --upgrade thrift
sudo pip install tenjin
sudo pip install ctypesgen
sudo pip install crc16

# build thrift from sources
mkdir install_tmp

cd install_tmp
wget -c http://archive.apache.org/dist/thrift/0.9.2/thrift-0.9.2.tar.gz
tar zxvf thrift-0.9.2.tar.gz
cd thrift-0.9.2
./configure
cd test/cpp ; ln -s . .libs ; cd ../..
make -j4
sudo make install
sudo ldconfig
cd ..

# Install libnanomsg
wget -c http://download.nanomsg.org/nanomsg-0.5-beta.tar.gz
tar zxvf nanomsg-0.5-beta.tar.gz
cd nanomsg-0.5-beta
./configure
make -j4
sudo make install
sudo ldconfig
cd ..

# Install high level interpreter and scapy

git clone https://github.com/p4lang/p4-hlir.git
cd p4-hlir
sudo python setup.py install
cd ..

# Install P4 dependency graph generator

git clone https://github.com/p4lang/p4c-graphs.git
cd p4c-graphs
sudo python setup.py install
cd ..

sudo apt-get remove python-scapy
git clone https://github.com/p4lang/scapy-vxlan.git
cd scapy-vxlan
sudo python setup.py install
cd ..

cd ..

# rm -rf install_tmp
