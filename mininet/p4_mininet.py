# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os, subprocess, select, time, re, pty
from mininet.util import isShellBuiltin

from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.log import setLogLevel, info

class P4Host(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)

        self.defaultIntf().rename("eth0")

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r

    def describe(self):
        print "**********"
        print self.name
        print "default interface: %s\t%s\t%s" %(
            self.defaultIntf().name,
            self.defaultIntf().IP(),
            self.defaultIntf().MAC()
        )
        print "**********"

class P4Switch(Switch):
    """P4 virtual switch"""
    listenerPort = 11111
    thriftPort = 22222

    def __init__( self, name, sw_path = "dc_full",
                  thrift_port = None,
                  pcap_dump = False,
                  verbose = False, **kwargs ):
        Switch.__init__( self, name, **kwargs )
        self.sw_path = sw_path
        self.verbose = verbose
        logfile = '/tmp/p4ns.%s.log' % self.name
        self.output = open(logfile, 'w')
        self.thrift_port = thrift_port
        self.pcap_dump = pcap_dump

    @classmethod
    def setup( cls ):
        pass

    def start( self, controllers ):
        "Start up a new P4 switch"
        print "Starting P4 switch", self.name
        args = [self.sw_path]
        args.extend( ['--name', self.name] )
        args.extend( ['--dpid', self.dpid] )
        for intf in self.intfs.values():
            if not intf.IP():
                args.extend( ['-i', intf.name] )
        args.extend( ['--listener', '127.0.0.1:%d' % self.listenerPort] )
        self.listenerPort += 1
        # FIXME
        if self.thrift_port:
            thrift_port = self.thrift_port
        else:
            thrift_port =  self.thriftPort
            self.thriftPort += 1
        args.extend( ['--pd-server', '127.0.0.1:%d' % thrift_port] )
        if not self.pcap_dump:
            args.append( '--no-cli' )
        args.append( self.opts )

        logfile = '/tmp/p4ns.%s.log' % self.name

        print ' '.join(args)

        self.cmd( ' '.join(args) + ' >' + logfile + ' 2>&1 </dev/null &' )
        #self.cmd( ' '.join(args) + ' > /dev/null 2>&1 < /dev/null &' )

        print "switch has been started"

    def stop( self ):
        "Terminate IVS switch."
        self.output.flush()
        self.cmd( 'kill %' + self.sw_path )
        self.cmd( 'wait' )
        self.deleteIntfs()

    def attach( self, intf ):
        "Connect a data port"
        print "Connecting data port", intf, "to switch", self.name
        self.cmd( 'p4ns-ctl', 'add-port', '--datapath', self.name, intf )

    def detach( self, intf ):
        "Disconnect a data port"
        self.cmd( 'p4ns-ctl', 'del-port', '--datapath', self.name, intf )

    def dpctl( self, *args ):
        "Run dpctl command"
        pass

# Based on code from
# http://techandtrains.com/2014/08/21/docker-container-as-mininet-host/
class P4DockerSwitch(Switch):
    """P4 virtual switch running in a docker conatiner"""
    def __init__( self, name, target_name = 'p4dockerswitch',
                  thrift_port = None, target_dir = 'switch',
                  sai_port = None,
                  swapi_port = None,
                  pcap_dump = False,
                  verbose = False,
                  start_program = '/p4factory/tools/start.sh',
                  config_fs = None,
                  pps = 0,
                  qdepth = 0,
                  **kwargs ):

        self.verbose = verbose
        self.pcap_dump = pcap_dump
        self.start_program = start_program
        self.config_fs = config_fs
        self.target_name = target_name
        self.target_dir = target_dir
        self.thrift_port = thrift_port
        self.sai_port = sai_port
        self.swapi_port = swapi_port
        self.pps = pps
        self.qdepth = qdepth
        Switch.__init__( self, name, **kwargs )
        self.inNamespace = True

    @classmethod
    def setup( cls ):
        pass

    def sendCmd( self, *args, **kwargs ):
        assert not self.waiting
        printPid = kwargs.get( 'printPid', True )
        # Allow sendCmd( [ list ] )
        if len( args ) == 1 and type( args[ 0 ] ) is list:
            cmd = args[ 0 ]
        # Allow sendCmd( cmd, arg1, arg2... )
        elif len( args ) > 0:
            cmd = args
        # Convert to string
        if not isinstance( cmd, str ):
            cmd = ' '.join( [ str( c ) for c in cmd ] )
        if not re.search( r'\w', cmd ):
            # Replace empty commands with something harmless
            cmd = 'echo -n'
        self.lastCmd = cmd
        printPid = printPid and not isShellBuiltin( cmd )
        if len( cmd ) > 0 and cmd[ -1 ] == '&':
            # print ^A{pid}\n{sentinel}
            cmd += ' printf "\\001%d\\012" $! '
        else:
            pass
        self.write( cmd + '\n' )
        self.lastPid = None
        self.waiting = True

    def popen( self, *args, **kwargs ):
        mncmd = [ 'docker', 'exec', "mininet-"+self.name ]
        return Switch.popen( self, *args, mncmd=mncmd, **kwargs )

    def stop( self ):
        dev_null = open(os.devnull, 'w')
        subprocess.call( ['docker stop mininet-' + self.name],
                         stdin=dev_null, stdout=dev_null,
                         stderr=dev_null, shell=True )
        subprocess.call( ['docker rm mininet-' + self.name],
                         stdin=dev_null, stdout=dev_null,
                         stderr=dev_null, shell=True )
        dev_null.close()

    def terminate( self ):
        self.stop()

    def start( self, controllers ):
        print "Starting P4 docker switch", self.name
        path = '/p4factory/targets/switch/behavioral-model'
        args = [ 'echo \"' +  path ]
        args.extend( ['--name', self.name] )
        args.extend( ['--dpid', self.dpid] )
        args.extend( ['--pd-server', '127.0.0.1:22000'] )
        if not self.pcap_dump:
            args.append( '--no-pcap' )
        for intf in self.intfs.values():
            if not intf.IP():
                args.extend( ['-i', intf.name] )
        args.extend( ['--pps', self.pps] )
        args.extend( ['--qdepth', self.qdepth] )
        # Enable it for verbose logs from model
        #args.append( '-t' )
        args.append( '--no-veth' )
        args.append( '>& /tmp/model.log &' )
        args.append( '\" >> /p4factory/tools/bm_start.sh' )
        self.cmd( args )

        bm_cmd = ['docker', 'exec', 'mininet-' + self.name,
                  '/p4factory/tools/bm_start.sh' ]
        bmp = subprocess.Popen( bm_cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, close_fds=False )
        bmp.wait()

    def startShell( self ):
        self.stop()
        docker_name = self.target_name

        args = ['docker', 'run', '-ti', '--rm', '--privileged=true']
        args.extend( ['--hostname=' + self.name, '--name=mininet-' + self.name] )
        if self.thrift_port is not None:
            args.extend( ['-p', '%d:22000' % self.thrift_port] )
        if self.sai_port is not None:
            args.extend( ['-p', '%d:9092' % self.sai_port] )
        if self.swapi_port is not None:
            args.extend( ['-p', '%d:9091' % self.swapi_port] )
        args.extend( ['-e', 'DISPLAY'] )
        args.extend( ['-v', '/tmp/.X11-unix:/tmp/.X11-unix'] )
        if self.config_fs is not None:
            args.extend( ['-v',
                          os.getcwd() + '/' + self.config_fs + ':/configs'] )
        args.extend( [docker_name, self.start_program] )

        master, slave = pty.openpty()
        self.shell = subprocess.Popen( args,
                                       stdin=slave, stdout=slave, stderr=slave,
                                       close_fds=True,
                                       preexec_fn=os.setpgrp )
        os.close( slave )
        ttyobj = os.fdopen( master, 'rw' )
        self.stdin = ttyobj
        self.stdout = ttyobj
        self.pid = self.shell.pid
        self.pollOut = select.poll()
        self.pollOut.register( self.stdout )
        self.outToNode[ self.stdout.fileno() ] = self
        self.inToNode[ self.stdin.fileno() ] = self
        self.execed = False
        self.lastCmd = None
        self.lastPid = None
        self.readbuf = ''
        self.waiting = False

        #Wait for prompt
        time.sleep(1)

        pid_cmd = ['docker', 'inspect', '--format=\'{{ .State.Pid }}\'',
                   'mininet-' + self.name ]
        pidp = subprocess.Popen( pid_cmd, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, close_fds=False )
        pidp.wait()
        ps_out = pidp.stdout.readlines()
        self.pid = int(ps_out[0])
        self.cmd( 'export PS1=\"\\177\"; printf "\\177"' )
        self.cmd( 'stty -echo; set +m' )
