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
