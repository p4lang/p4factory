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

root_dir = os.path.dirname(os.path.realpath(__file__))
oft_path = os.path.join(root_dir, '..', '..', 'submodules', 'oftest', 'oft')

if __name__ == "__main__":
    new_args = [] 
    new_args += ["-S 127.0.0.1", "-V1.3"]
    new_args += ["--interface", "0@veth1"]
    new_args += ["--interface", "2@veth5"]
    new_args += ["--interface", "3@veth7"]
    new_args += ["--interface", "4@veth9"]
    new_args += ["--interface", "5@veth11"]
    new_args += ["--interface", "6@veth13"]
    new_args += ["--interface", "7@veth15"]
    new_args += ["--test-dir", os.path.join("..", "..", "submodules", "switch", "tests", "of-tests")]

    child = Popen([oft_path] + new_args)
    child.wait()
    sys.exit(child.returncode)
