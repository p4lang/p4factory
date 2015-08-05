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

docker-image :
	@echo "    Building docker image for target ${DOCKER_IMAGE}"
	@rm -fr /tmp/docker_tmp
	@mkdir -p /tmp/docker_tmp/p4factory
	@cp -r ${P4FACTORY}/docker/* /tmp/docker_tmp
	@cp -rf ${P4FACTORY}/* /tmp/docker_tmp/p4factory
	@cp /tmp/docker_tmp/init.py /tmp/docker_tmp/p4factory/submodules/init.py
	@cp /tmp/docker_tmp/start.sh /tmp/docker_tmp/p4factory/tools/start.sh
	@cp /tmp/docker_tmp/bm_start.sh /tmp/docker_tmp/p4factory/tools/bm_start.sh
	@echo -n "RUN cd /p4factory ; ./autogen.sh ; ./configure ; " \
		>> /tmp/docker_tmp/Dockerfile
	@echo -n "cd /p4factory/targets/$(notdir ${TARGET_ROOT}) ; " \
		>> /tmp/docker_tmp/Dockerfile
	@echo "make clean ; make -j4 ${DOCKER_IMAGE}" >> /tmp/docker_tmp/Dockerfile
	@echo "CMD /bin/bash" >> /tmp/docker_tmp/Dockerfile
	@sudo docker build -t p4dockerswitch /tmp/docker_tmp
	@rm -fr /tmp/docker_tmp
