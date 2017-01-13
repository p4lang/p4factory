from docker_node import *

class BmDockerSwitch( DockerSwitch ):
    def __init__( self, name, model_dir=None, pcap_dump=False, **kwargs ):
        self.pcap_dump = pcap_dump
        if model_dir is None:
            self.model_dir = '/p4factory/targets/switch/'
        else:
            self.model_dir = model_dir
        DockerSwitch.__init__( self, name, **kwargs )

    def start( self, controllers ):
        # load the startup configuration
        self.cmd( '/p4factory/tools/startv2.sh' )

        # start the model
        cmds = [ 'echo \"' ]
        cmds.append( '#!/bin/bash\n' )
        cmds.append( self.model_dir + '/behavioral-model' )
        cmds.extend( [ '--name', self.name ] )
        if not self.pcap_dump:
            cmds.append( '--no-pcap' )
        for intf in self.intfs.values():
            if not intf.IP():
                cmds.extend( [ '-i', intf.name ] )
        cmds.append( '--no-veth' )
        cmds.append( '>& /tmp/model.log &' )
        cmds.append( '\" >> /tmp/start.sh' )
        self.cmd( cmds )

        bm_cmd = [ 'docker', 'exec', self.name, '/bin/bash', '/tmp/start.sh' ]
        bmp = subprocess.Popen( bm_cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, close_fds=True )
        bmp.wait()


class Bmv2DockerSwitch( DockerSwitch ):
    def __init__( self, name, model_dir=None, pcap_dump=False, thrift_port=10001,
                  json_file='switch.json', driver_name='bmswitchp4_drivers', 
                  log_file=None, nanolog=None, **kwargs ):
        self.log_file = log_file
        self.nanolog = nanolog
        self.pcap_dump = pcap_dump
        self.thrift_port = thrift_port

        self.json_file = json_file
        self.driver_name = driver_name

        if model_dir is None:
            self.model_dir = '/p4factory/bmv2/install/bin/'
        else:
            self.model_dir = model_dir

        DockerSwitch.__init__( self, name, **kwargs )

    def start( self, controllers ):
        # load the startup configuration
        self.cmd( '/p4factory/tools/startv2.sh' )
        self.cmd( '/p4factory/tools/disable_ipv6.sh' )

        # start the model
        cmds = [ 'echo \"' ]
        cmds.append( '#!/bin/bash\n' )
	cmds.append( 'LD_LIBRARY_PATH=$LD_LIBRARY_PATH=:%s/../lib' % self.model_dir )
        cmds.append( self.model_dir + '/simple_switch' )
        cmds.extend( [ '--thrift-port', self.thrift_port ] )

        if self.log_file:
            cmds.extend( [ '--log-file', self.log_file ] )

        if self.nanolog:
            cmds.extend( [ '--nanolog', self.nanolog ] )

        if self.pcap_dump:
            cmds.append( '--pcap' )

        for i, intf in enumerate( self.intfs.values() ):
            if not intf.IP():
                cmds.extend( [ '-i', '%d@%s' % ( i, intf.name ) ] )

        cmds.extend( [ '-i', '64@veth250' ] )
        cmds.append( os.path.join( self.model_dir,
                     '../share/bmpd/switch/%s' % self.json_file )) 
        cmds.append( '>& /tmp/bmv2_model.log &' )
        cmds.append( '\" >> /tmp/start.sh' )
        self.cmd( cmds )

        #cmds = [ 'echo \"sleep 10\" >> /tmp/start.sh' ]
        cmds = [ 'echo \"sleep 3\" >> /tmp/start.sh' ]
        self.cmd( cmds )

        # start the driver
        cmds = [ 'echo \"' ]
	cmds.append( 'LD_LIBRARY_PATH=$LD_LIBRARY_PATH:%s/../lib:%s/../lib/bmpd/switch' % (self.model_dir,self.model_dir) )
        cmds.append( os.path.join( self.model_dir, self.driver_name ))
        cmds.append( '>& /tmp/bmv2_driver.log &' )
        cmds.append( '\" >> /tmp/start.sh' )
        self.cmd( cmds )

        bm_cmd = [ 'docker', 'exec', self.name, '/bin/bash', '/tmp/start.sh' ]
        bmp = subprocess.Popen( bm_cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, close_fds=True )
        bmp.wait()
