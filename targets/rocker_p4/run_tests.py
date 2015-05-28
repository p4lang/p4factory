#!/usr/bin/env python
import sys
import os
from subprocess import Popen

root_dir = os.path.dirname(os.path.realpath(__file__))
pd_dir = os.path.join(root_dir, 'of-tests')

oft_path = os.path.join(root_dir, '..', '..', 'submodules', 'oft-infra', 'oft')

if __name__ == "__main__":
    args = sys.argv[1:]
    args += ["--pd-thrift-path", pd_dir]
    args += ["--enable-erspan", "--enable-vxlan", "--enable-geneve"]
    child = Popen([oft_path] + args)
    child.wait()
    sys.exit(child.returncode)
