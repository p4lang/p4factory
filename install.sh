# installation script for ubuntu 14.04

sudo apt-get install -y automake bison doxygen ethtool flex g++ git \
ipython ipython-notebook libany-moose-perl libboost-dev libboost-filesystem-dev \
libboost-program-options-dev libboost-system-dev libboost-test-dev libbsd-dev \
libedit-dev libevent-dev libfreetype6-dev libhiredis-dev libjudy-dev libpcap-dev \
libpng-dev libssl-dev libtool libyaml-0-2 libbz2-dev mininet openssl pkg-config python-dev \
python-dpkt python-jsonpickle python-imaging-tk python-matplotlib python-nose python-numpy \
python-pandas python-pip python-pygraph python-pygraphviz python-scipy \
python-setuptools python-sympy python-thrift python-yaml redis-server thrift-compiler \
wireshark

# build thrift from sources
mkdir install_tmp

cd install_tmp
wget -c http://archive.apache.org/dist/thrift/0.9.1/thrift-0.9.1.tar.gz
tar zxvf thrift-0.9.1.tar.gz
cd thrift-0.9.1
./configure
cd test/cpp ; ln -s . .libs ; cd ../..
make -j4
sudo make install
sudo ldconfig
cd ..

# Install high level interpreter and scapy

git clone https://github.com/p4lang/p4-hlir.git
cd p4-hlir
sudo python setup.py install
cd ..

sudo apt-get remove python-scapy
git clone https://github.com/p4lang/scapy-vxlan.git
cd scapy-vxlan
sudo python setup.py install
cd ..

cd ..

# rm -rf install_tmp
