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

empty :=
space := $(empty) $(empty)

export TARGET_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# force main.c to be recompiled, in case switchapi was enabled / disabled
TOUCH_MAIN := $(shell touch main.c)

include ../../../init.mk

ifndef P4FACTORY
P4FACTORY := $(TARGET_ROOT)/../../..
endif
MAKEFILES_DIR := ${P4FACTORY}/makefiles

# This target's P4 name
export P4_INPUT := ../../../submodules/switch/p4src/switch.p4
export P4_NAME := switch
export P4_PREFIX := dc

SUBMODULES_CLEAN := $(SUBMODULE_SWITCH)
# SUBMODULES_CLEAN := $(SUBMODULE_SWITCHAPI)
# SUBMODULES_CLEAN += $(SUBMODULE_SWITCHSAI)
# SUBMODULES_CLEAN += $(SUBMODULE_SWITCHLINK)

include $(MAKEFILES_DIR)/bmv2_common.mk


###################################
#BUILD SWITCH API
###################################

LIB_DIR := ${TARGET_ROOT}/build/
MAKE_DIR := ${LIB_DIR}
include ${MAKEFILES_DIR}/makedir.mk

SWITCHAPI_INC := ../../../submodules/switch/p4src/includes
SWITCHAPI_INC += $(BMV2_PD_INC)
SWITCHAPI_INC += ${C_INCLUDE_PATH}
SWITCHAPI_INC += ${TARGET_ROOT}
SWITCHAPI_INC := $(subst $(space),:,$(SWITCHAPI_INC))

SWITCHAPI_LIB := $(SUBMODULE_SWITCHAPI)/.libs/libswitchapi.a
SWITCHAPI_SRC_DIR := $(SUBMODULE_SWITCHAPI)/src
${SWITCHAPI_LIB} : bmv2-pd FORCE $(BM_LIB)
	@${MAKE} -C $(SUBMODULE_SWITCHAPI) C_INCLUDE_PATH=$(SWITCHAPI_INC) \
		CPLUS_INCLUDE_PATH=$(SWITCHAPI_INC)

BINARY := drivers-switchapi
${BINARY}_LINK_LIBS := ${SWITCHAPI_LIB} $(BUILD_DIR)/main.o $(PD_LIBS)
drivers-switchapi : EXTRA_LINK_LIBS := -lpthread -lpcap -lhiredis \
	-lJudy -lthrift -ledit
include ${MAKEFILES_DIR}/bin.mk
ifndef drivers-switchapi_BINARY
	$(error Output binary not defined in drivers-switchapi_BINARY)
endif

SWITCHAPI_THRIFT_PY_OUTPUT_DIR := ${TARGET_ROOT}/../tests/pd_thrift/switch_api_thrift
THRIFT_INPUT_FILES := ${SWITCHAPI_SRC_DIR}/switch_api.thrift
THRIFT_DEP_FILES := ${SWITCHAPI_SRC_DIR}/switch_api.thrift
THRIFT_SERVICE_NAMES := switch_api_rpc
include ${MAKEFILES_DIR}/thrift-py.mk

switchapi_THRIFT : ${GEN_THRIFT_PY_MODULE} FORCE
	@echo "Copying python thrift files"
	@mkdir -p ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}
	@cp -r ${THRIFT_TEMP_DIR}/switch_api/* ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}/
	@rm -r ${THRIFT_TEMP_DIR}/switch_api/

# @cp -r ${THRIFT_TEMP_DIR}/* ${BM_THRIFT_PY_OUTPUT_DIR}/

drivers-switchapi : export LIB_SWITCHAPI_ENABLE=1
drivers-switchapi : GLOBAL_CFLAGS += -DSWITCHAPI_ENABLE=1 -g
drivers-switchapi : $(SWITCHAPI_LIB)
drivers-switchapi : ${drivers-switchapi_BINARY} switchapi_THRIFT
	cp -r $(BMV2_THRIFT_PY_DIR)/* $(TARGET_ROOT)/../tests/pd_thrift/

###################################
#BUILD SWITCH SAI
###################################

SWITCHSAI_INC += $(SWITCHAPI_INC):$(SUBMODULE_SWITCHAPI)/inc

SWITCHSAI_LIB := $(SUBMODULE_SWITCHSAI)/.libs/libswitchsai.a
SWITCHSAI_SRC_DIR := $(SUBMODULE_SWITCHSAI)/src
${SWITCHSAI_LIB} : FORCE $(BM_LIB)
	@${MAKE} -C $(SUBMODULE_SWITCHSAI) C_INCLUDE_PATH=$(SWITCHSAI_INC)

BINARY := drivers-switchsai
${BINARY}_LINK_LIBS := ${drivers-switchapi_LINK_LIBS} ${SWITCHSAI_LIB}
drivers-switchsai : EXTRA_LINK_LIBS := -lpthread -lpcap -lhiredis \
	-lJudy -lthrift -ledit
include ${MAKEFILES_DIR}/bin.mk
ifndef drivers-switchsai_BINARY
	$(error Output binary not defined in drivers-switchsai_BINARY)
endif

SWITCHSAI_THRIFT_PY_OUTPUT_DIR := ${TARGET_ROOT}/../tests/pd_thrift/switch_sai_thrift
SWITCHSAI_HEADER_FILES_DIR := $(SUBMODULE_SWITCHSAI)/submodules/ocpsai/sai/inc
THRIFT_INPUT_FILES := ${SWITCHSAI_SRC_DIR}/switch_sai.thrift
THRIFT_DEP_FILES := ${SWITCHSAI_SRC_DIR}/switch_sai.thrift
THRIFT_SERVICE_NAMES := switch_sai_rpc
include ${MAKEFILES_DIR}/thrift-py.mk

switchsai_THRIFT : switchapi_THRIFT FORCE
	@mkdir -p ${SWITCHSAI_THRIFT_PY_OUTPUT_DIR}
	@cp -r ${THRIFT_TEMP_DIR}/switch_sai/* ${SWITCHSAI_THRIFT_PY_OUTPUT_DIR}/
	@rm -r ${THRIFT_TEMP_DIR}/switch_sai/
	@ctypesgen.py -I/usr/include -I$(SWITCHSAI_HEADER_FILES_DIR) $(SWITCHSAI_HEADER_FILES_DIR)/*.h -o ${SWITCHSAI_THRIFT_PY_OUTPUT_DIR}/sai_headers.py

drivers-switchsai : export LIB_SWITCHSAI_ENABLE=1
drivers-switchsai : export LIB_SWITCHAPI_ENABLE=1
drivers-switchsai : GLOBAL_CFLAGS += -DSWITCHAPI_ENABLE=1 -g
drivers-switchsai : GLOBAL_CFLAGS += -DSWITCHSAI_ENABLE=1
drivers-switchsai : $(SWITCHAPI_LIB) $(SWITCHSAI_LIB)
drivers-switchsai : ${drivers-switchsai_BINARY} switchsai_THRIFT
	@echo "DONE!"

bm-switchapi: bmv2 bmv2-pd drivers-switchapi

bm-switchsai: bmv2 bmv2-pd drivers-switchsai

clean-local :
	@$(foreach d,${SUBMODULES_CLEAN},${MAKE} -C ${d} clean && ) true

.PHONY: bm-switchapi clean-local FORCE
