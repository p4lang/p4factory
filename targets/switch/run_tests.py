#!/usr/bin/env python

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

import sys
import os
from subprocess import Popen
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--test-dir", required=False,
                    default=os.path.join("..", "..", "submodules", "switch",
                                         "tests", "ptf-tests", "pd-tests"),
                    help="directory containing the tests (default ../../submodules/switch/tests/ptf-tests/pd-tests)")
args, unknown_args = parser.parse_known_args()

root_dir = os.path.dirname(os.path.realpath(__file__))
pd_dir = os.path.join(root_dir, 'tests', 'pd_thrift')
testutils_dir = os.path.join(root_dir, '..', '..', 'testutils')

ptf_path = os.path.join(root_dir, '..', '..', 'submodules', 'ptf', 'ptf')

max_ports = 9
cpu_port = 64
cpu_veth = 251

if __name__ == "__main__":
    new_args = unknown_args
    new_args += ["--pypath", pd_dir]
    new_args += ["--pypath", testutils_dir]
    new_args += ["--test-dir", args.test_dir]
    for port in xrange(max_ports):
        new_args += ["--interface", "%d@veth%d" % (port, 2 * port + 1)]
    new_args += ["--interface", "%s@veth%s" % (cpu_port, cpu_veth)]
    child = Popen([ptf_path] + new_args)
    child.wait()
    sys.exit(child.returncode)
