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

ifndef MAKEFILES_DIR
  $(error MAKEFILES_DIR not defined)
endif

ifndef VERBOSE
VERBOSE = @
else
ifeq ($(VERBOSE),0)
override VERBOSE = @
else
override VERBOSE =
endif
endif

BUILD_DIR := ${TARGET_ROOT}/build/
MAKE_DIR := ${BUILD_DIR}
include ${MAKEFILES_DIR}/makedir.mk

BIN_DIR := ${BUILD_DIR}/bin
MAKE_DIR := ${BIN_DIR}
include ${MAKEFILES_DIR}/makedir.mk

include ${MAKEFILES_DIR}/bm.mk
include ${MAKEFILES_DIR}/graphs.mk

.DEFAULT_GOAL := all

clean :
	@echo Cleaning Files
	@rm -rf ${CLEAN_TARGETS}
	@echo Cleaning Directories
	@rm -rf ${CLEAN_DIRECTORIES}
	@$(foreach d,${SUBMODULES_CLEAN},${MAKE} -C ${d} $@ && ) true
