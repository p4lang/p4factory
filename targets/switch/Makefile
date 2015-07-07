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

################################################################
#
# Makefile for switch P4 project
#
################################################################

export TARGET_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# force main.c to be recompiled, in case switchapi was enabled / disabled
TOUCH_MAIN := $(shell touch main.c)

include ../../init.mk

ifndef P4FACTORY
P4FACTORY := $(TARGET_ROOT)/../..
endif
MAKEFILES_DIR := ${P4FACTORY}/makefiles

# This target's P4 name
export P4_INPUT := p4src/switch.p4
export P4_NAME := switch
export P4_PREFIX := dc

include ${MAKEFILES_DIR}/common.mk
DOCKER_IMAGE := bm-switchsai
include ${MAKEFILES_DIR}/docker.mk

SWITCHAPI_LIB := $(LIB_DIR)/libswitchapi.a
SWITCHAPI_THRIFT_LIB := $(LIB_DIR)/switchapi_thrift.a
SWITCHAPI_THRIFT_PY_OUTPUT_DIR := ${TARGET_ROOT}/of-tests/pd_thrift/switch_api_thrift
include ${SUBMODULE_SWITCHAPI}/libswitchapi.mk

###################################
#BUILD SWITCH API
###################################
BINARY := bm-switchapi
${BINARY}_LINK_LIBS := ${SWITCHAPI_LIB} ${bm_LINK_LIBS} ${SWITCHAPI_THRIFT_LIB} ${BM_LIB} ${p4utils_LIB}
bm-switchapi : EXTRA_LINK_LIBS := -lpthread -lpcap -lhiredis -lJudy -lthrift -ledit
include ${MAKEFILES_DIR}/bin.mk
ifndef bm-switchapi_BINARY
  $(error Output binary not defined in bm-switchapi_BINARY)
endif

bm-switchapi : export LIB_SWITCHAPI_ENABLE=1
bm-switchapi : GLOBAL_CFLAGS += -DSWITCHAPI_ENABLE=1
bm-switchapi : $(BM_LIB) $(SWITCHAPI_LIB) $(SWITCHAPI_THRIFT_LIB) switchapi_THRIFT
switchapi_THRIFT : ${GEN_THRIFT_PY_MODULE}
	mkdir -p ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}
	cp -r ${THRIFT_TEMP_DIR}/switch_api/* ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}/
	rm -r ${THRIFT_TEMP_DIR}/switch_api/
	cp -r ${THRIFT_TEMP_DIR}/* ${BM_THRIFT_PY_OUTPUT_DIR}/
bm-switchapi : ${bm-switchapi_BINARY}
	cp ${bm-switchapi_BINARY} behavioral-model

###################################
#BUILD SWITCH SAI
###################################
SWITCHSAI_LIB := $(LIB_DIR)/libswitchsai.a
SWITCHSAI_THRIFT_LIB := $(LIB_DIR)/switchsai_thrift.a
SWITCHSAI_THRIFT_PY_OUTPUT_DIR := ${TARGET_ROOT}/of-tests/pd_thrift/switch_sai_thrift
include ${SUBMODULE_SWITCHSAI}/libswitchsai.mk

BINARY := bm-switchsai
${BINARY}_LINK_LIBS := ${bm-switchapi_LINK_LIBS} ${SWITCHSAI_LIB} ${SWITCHSAI_THRIFT_LIB}
bm-switchsai : EXTRA_LINK_LIBS := -lpthread -lpcap -lhiredis -lJudy -lthrift -ledit
include ${MAKEFILES_DIR}/bin.mk
ifndef bm-switchsai_BINARY
  $(error Output binary not defined in bm-switchsai_BINARY)
endif

bm-switchsai : export LIB_SWITCHSAI_ENABLE=1
bm-switchsai : export LIB_SWITCHAPI_ENABLE=1
bm-switchsai : GLOBAL_CFLAGS += -DSWITCHAPI_ENABLE=1
bm-switchsai : GLOBAL_CFLAGS += -DSWITCHSAI_ENABLE=1
bm-switchsai : $(BM_LIB) $(SWITCHAPI_LIB) $(SWITCHSAI_LIB) $(SWITCHSAI_THRIFT_LIB) switchsai_THRIFT
switchsai_THRIFT : ${GEN_THRIFT_PY_MODULE}
	mkdir -p ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}
	mkdir -p ${SWITCHSAI_THRIFT_PY_OUTPUT_DIR}
	cp -r ${THRIFT_TEMP_DIR}/switch_api/* ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}/
	rm -r ${THRIFT_TEMP_DIR}/switch_api/
	cp -r ${THRIFT_TEMP_DIR}/switch_sai/* ${SWITCHSAI_THRIFT_PY_OUTPUT_DIR}/
	rm -r ${THRIFT_TEMP_DIR}/switch_sai/
	cp -r ${THRIFT_TEMP_DIR}/* ${BM_THRIFT_PY_OUTPUT_DIR}/
bm-switchsai : ${bm-switchsai_BINARY}
	cp ${bm-switchsai_BINARY} behavioral-model

all: bm

.PHONY: bm-switchapi bm-switchsai
