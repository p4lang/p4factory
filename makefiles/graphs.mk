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

###############################################################################
#
# 
#
###############################################################################
ifndef TARGET_ROOT
  $(error P4 program root not defined in TARGET_ROOT)
endif

ifndef BUILD_DIR
  $(error Build directory not defined in BUILD_DIR)
endif

ifndef P4_NAME
  $(error P4 program name not defined in P4_NAME)
endif

ifndef P4_INPUT
  $(error P4 input file not defined in P4_INPUT)
endif

ifndef P4C_GRAPHS
P4C_GRAPHS := ${SUBMODULE_P4C_GRAPHS}/p4c_dot/shell.py
endif

GRAPHS_DIR := ${BUILD_DIR}/graphs
MAKE_DIR := ${GRAPHS_DIR}
include ${MAKEFILES_DIR}/makedir.mk

graphs: ${P4_INPUT} graphs
	@echo Create ${P4_NAME} graphs
	@${P4C_GRAPHS} ${P4_INPUT} --gen-dir=${BUILD_DIR}/graphs
