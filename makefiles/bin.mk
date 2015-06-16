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

ifndef BINARY
  $(error BINARY not defined)
endif

ifndef $(BINARY)_LINK_LIBS
  $(error $(BINARY)_LIBRARIES not defined)
endif

ifdef COVERAGE
COVERAGE_FLAGS := --coverage
endif

${BINARY}_BINARY := ${BIN_DIR}/${BINARY}
$($(BINARY)_BINARY) : $($(BINARY)_LINK_LIBS)
	@echo "    Linking$(LINFO): $(notdir $@)"
	$(VERBOSE)g++ $(DEBUG_FLAGS) $(COVERAGE_FLAGS) -o $@ -Wl,--start-group $+ -Wl,--end-group $(EXTRA_LINK_LIBS) $(LDFLAGS)

CLEAN_DIRECTORIES := $(CLEAN_DIRECTORIES) $(BINARY)
