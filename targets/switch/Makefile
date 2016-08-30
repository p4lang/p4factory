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

include ../../init.mk

ifndef P4FACTORY
P4FACTORY := $(TARGET_ROOT)/../..
endif
MAKEFILES_DIR := ${P4FACTORY}/makefiles

# This target's P4 name
export P4_INPUT := $(ROOT)/submodules/switch/p4src/switch.p4
export P4_NAME := switch
export P4_PREFIX := dc

export TARGET_PARAMS := -DRATE_LIMITING
SUBMODULES_CLEAN := $(SUBMODULE_SWITCH)
SUBMODULES_CLEAN += $(SUBMODULE_P4OFAGENT)

include ${MAKEFILES_DIR}/common.mk
DOCKER_IMAGE := bm-switchlink
include ${MAKEFILES_DIR}/docker.mk

###################################
#BUILD SWITCH API
###################################
SWITCHAPI_INC := ${TARGET_ROOT}/build/inc
SWITCHAPI_INC += $(P4FACTORY)/modules/p4utils/module/inc
SWITCHAPI_INC += ${C_INCLUDE_PATH}
SWITCHAPI_INC += ${TARGET_ROOT}
SWITCHAPI_INC := $(subst $(space),:,$(SWITCHAPI_INC))

SWITCHAPI_LIB := $(SUBMODULE_SWITCHAPI)/libswitchapi.a
SWITCHAPI_SRC_DIR := $(SUBMODULE_SWITCHAPI)/src
${SWITCHAPI_LIB} : FORCE $(BM_LIB)
	@${MAKE} -C $(SUBMODULE_SWITCHAPI) C_INCLUDE_PATH=$(SWITCHAPI_INC) \
		CPLUS_INCLUDE_PATH=$(SWITCHAPI_INC) CFLAGS="$(GLOBAL_CFLAGS)"

BINARY := bm-switchapi
${BINARY}_LINK_LIBS := ${SWITCHAPI_LIB} ${bm_LINK_LIBS} ${BM_LIB} ${p4utils_LIB}
bm-switchapi : EXTRA_LINK_LIBS := -lpthread -lpcap -lhiredis \
	-lJudy -lthrift -ledit
include ${MAKEFILES_DIR}/bin.mk
ifndef bm-switchapi_BINARY
	$(error Output binary not defined in bm-switchapi_BINARY)
endif

SWITCHAPI_THRIFT_PY_OUTPUT_DIR := ${TARGET_ROOT}/tests/pd_thrift/switch_api_thrift
THRIFT_INPUT_FILES := ${SWITCHAPI_SRC_DIR}/switch_api.thrift
THRIFT_DEP_FILES := ${SWITCHAPI_SRC_DIR}/switch_api.thrift
SWITCHAPI_HEADER_FILES_DIR := ${SUBMODULE_SWITCHAPI}/include/switchapi
SWITCHAPI_THIRDPARTY_INC := ${SUBMODULE_SWITCHAPI}/third-party/tommyds/include
P4_INC := ${SUBMODULE_SWITCHAPI}/../p4src/includes/
THRIFT_SERVICE_NAMES := switch_api_rpc
include ${MAKEFILES_DIR}/thrift-py.mk

switchapi_THRIFT : ${GEN_THRIFT_PY_MODULE}
	@echo "Copying python thrift files"
	@mkdir -p ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}
	@cp -r ${THRIFT_TEMP_DIR}/switch_api/* ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}/
	@rm -r ${THRIFT_TEMP_DIR}/switch_api/
	@cp -r ${THRIFT_TEMP_DIR}/* ${BM_THRIFT_PY_OUTPUT_DIR}/
	@ctypesgen.py -I/usr/include -I${SWITCHAPI_HEADER_FILES_DIR} \
		-I${SWITCHAPI_THIRDPARTY_INC} -I${P4_INC} \
		${SWITCHAPI_HEADER_FILES_DIR}/*.h \
		-o ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}/switch_api_headers.py > /dev/null 2>&1

bm-switchapi : export LIB_SWITCHAPI_ENABLE=1 GLOBAL_CFLAGS += -DUSE_SWITCHAPI=1
bm-switchapi : GLOBAL_CFLAGS += -DSWITCHAPI_ENABLE=1 ${TARGET_PARAMS}
bm-switchapi : $(BM_LIB) $(SWITCHAPI_LIB)
bm-switchapi : ${bm-switchapi_BINARY} switchapi_THRIFT
	cp ${bm-switchapi_BINARY} behavioral-model

###################################
#BUILD SWITCH SAI
###################################
SWITCHSAI_INC := ${TARGET_ROOT}/build/inc
SWITCHSAI_INC += $(P4FACTORY)/modules/p4utils/module/inc
SWITCHSAI_INC += $(ROOT)/modules/BMI/module/inc
SWITCHSAI_INC += ${C_INCLUDE_PATH}
SWITCHSAI_INC += ${TARGET_ROOT}
SWITCHSAI_INC += $(SUBMODULE_SWITCHSAI)/submodules/SAI/inc
SWITCHSAI_INC := $(subst $(space),:,$(SWITCHSAI_INC))

SWITCHSAI_LIB := $(SUBMODULE_SWITCHSAI)/libswitchsai.a
SWITCHSAI_SRC_DIR := $(SUBMODULE_SWITCHSAI)/src
${SWITCHSAI_LIB} : FORCE $(BM_LIB)
	@${MAKE} -C $(SUBMODULE_SWITCHSAI) libswitchsai.a \
		CPPFLAGS=-DSAI_BMLIB C_INCLUDE_PATH=$(SWITCHSAI_INC)

BINARY := bm-switchsai
${BINARY}_LINK_LIBS := ${bm-switchapi_LINK_LIBS} ${SWITCHSAI_LIB}
bm-switchsai : EXTRA_LINK_LIBS := -lpthread -lpcap -lhiredis \
	-lJudy -lthrift -ledit
include ${MAKEFILES_DIR}/bin.mk
ifndef bm-switchsai_BINARY
	$(error Output binary not defined in bm-switchsai_BINARY)
endif

SWITCHSAI_THRIFT_PY_OUTPUT_DIR := ${TARGET_ROOT}/tests/pd_thrift/switch_sai_thrift
SWITCHSAI_HEADER_FILES_DIR := $(SUBMODULE_SWITCHSAI)/submodules/SAI/inc
THRIFT_INPUT_FILES := ${SWITCHSAI_SRC_DIR}/switch_sai.thrift
THRIFT_DEP_FILES := ${SWITCHSAI_SRC_DIR}/switch_sai.thrift
THRIFT_SERVICE_NAMES := switch_sai_rpc
include ${MAKEFILES_DIR}/thrift-py.mk

switchsai_THRIFT : ${GEN_THRIFT_PY_MODULE}
	@echo "Copying python thrift files"
	@mkdir -p ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}
	@mkdir -p ${SWITCHSAI_THRIFT_PY_OUTPUT_DIR}
	@cp -r ${THRIFT_TEMP_DIR}/switch_api/* ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}/
	@rm -r ${THRIFT_TEMP_DIR}/switch_api/
	@cp -r ${THRIFT_TEMP_DIR}/switch_sai/* ${SWITCHSAI_THRIFT_PY_OUTPUT_DIR}/
	@rm -r ${THRIFT_TEMP_DIR}/switch_sai/
	@cp ${SWITCHAPI_THRIFT_PY_INPUT_DIR}/switch_api_headers.py ${SWITCHAPI_THRIFT_PY_OUTPUT_DIR}/
	@ctypesgen.py -I/usr/include -I$(SWITCHSAI_HEADER_FILES_DIR) $(SWITCHSAI_HEADER_FILES_DIR)/*.h \
		-o ${SWITCHSAI_THRIFT_PY_OUTPUT_DIR}/sai_headers.py > /dev/null 2>&1
	@cp -r ${THRIFT_TEMP_DIR}/* ${BM_THRIFT_PY_OUTPUT_DIR}/

bm-switchsai : export LIB_SWITCHSAI_ENABLE=1
bm-switchsai : export LIB_SWITCHAPI_ENABLE=1
bm-switchsai : GLOBAL_CFLAGS += -DSWITCHAPI_ENABLE=1 ${TARGET_PARAMS}
bm-switchsai : GLOBAL_CFLAGS += -DSWITCHSAI_ENABLE=1
bm-switchsai : $(BM_LIB) $(SWITCHAPI_LIB) $(SWITCHSAI_LIB)
bm-switchsai : ${bm-switchsai_BINARY} switchsai_THRIFT
	cp ${bm-switchsai_BINARY} behavioral-model
	ar -M <libp4.mri

###################################
#BUILD SWITCHLINK
###################################
SWITCHLINK_LIB := $(SUBMODULE_SWITCHLINK)/libswitchlink.a
SWITCHLINK_INC += $(P4FACTORY)/modules/p4utils/module/inc
SWITCHLINK_INC += ${C_INCLUDE_PATH}
SWITCHLINK_INC := $(subst $(space),:,$(SWITCHLINK_INC))
${SWITCHLINK_LIB} : FORCE
	@${MAKE} -C $(SUBMODULE_SWITCHLINK) C_INCLUDE_PATH=$(SWITCHLINK_INC)

BINARY := bm-switchlink
${BINARY}_LINK_LIBS := ${bm-switchsai_LINK_LIBS} ${SWITCHLINK_LIB}
bm-switchlink : EXTRA_LINK_LIBS := -lpthread -lpcap -lhiredis -lJudy -lthrift \
	$(shell pkg-config --libs libnl-route-3.0)
include ${MAKEFILES_DIR}/bin.mk
ifndef bm-switchlink_BINARY
	$(error Output binary not defined in bm-switchlink_BINARY)
endif

bm-switchlink : export LIB_SWITCHSAI_ENABLE=1
bm-switchlink : export LIB_SWITCHAPI_ENABLE=1
bm-switchlink : GLOBAL_CFLAGS += -DSWITCHAPI_ENABLE=1 ${TARGET_PARAMS}
bm-switchlink : GLOBAL_CFLAGS += -DSWITCHSAI_ENABLE=1
bm-switchlink : GLOBAL_CFLAGS += -DSWITCHLINK_ENABLE=1
bm-switchlink : $(BM_LIB) $(SWITCHAPI_LIB) $(SWITCHSAI_LIB) switchsai_THRIFT
bm-switchlink : ${bm-switchlink_BINARY} 
	cp ${bm-switchlink_BINARY} behavioral-model

###################################
#BUILD P4OFAGENT
###################################
P4OFAGENT_LIB := $(SUBMODULE_P4OFAGENT)/libp4ofagent.a
P4OFAGENT_INC += $(P4FACTORY)/modules/p4utils/module/inc
P4OFAGENT_INC += $(TARGET_ROOT)/build/inc
P4OFAGENT_INC += ${C_INCLUDE_PATH}
P4OFAGENT_INC := $(subst $(space),:,$(P4OFAGENT_INC))

${P4OFAGENT_LIB} : FORCE $(BM_LIB)
	@${MAKE} -C $(SUBMODULE_P4OFAGENT) p4ofagent C_INCLUDE_PATH=$(P4OFAGENT_INC)

BINARY := bm-p4ofagent
${BINARY}_LINK_LIBS := $(P4OFAGENT_LIB) $(BM_PLUGIN_LIBS) \
	$(SWITCHAPI_LIB) ${bm-p4ofagent_LINK_LIBS} ${bm_LINK_LIBS} \
	${BM_LIB} ${p4utils_LIB}
bm-p4ofagent : EXTRA_LINK_LIBS := -lpthread -lpcap -lhiredis \
	-lJudy -lthrift -ledit $(P4OFAGENT_LIB) -lrt

include ${MAKEFILES_DIR}/bin.mk
ifndef bm-p4ofagent_BINARY
	$(error Output binary not defined in bm-p4ofagent_BINARY)
endif

bm-p4ofagent : BM_PARAMS += --plugin of
bm-p4ofagent : BM_PARAMS += --openflow-mapping-dir $(TARGET_ROOT)/openflow_mapping
bm-p4ofagent : BM_PARAMS += --openflow-mapping-mod l2
bm-p4ofagent : BM_PARAMS += -DOPENFLOW_ENABLE
bm-p4ofagent : export LIB_P4OFAGENT_ENABLE=1
bm-switchapi : export LIB_SWITCHAPI_ENABLE=1
bm-p4ofagent : GLOBAL_CFLAGS += -DENABLE_PLUGIN_OPENFLOW
bm-p4ofagent : GLOBAL_CFLAGS += -DSWITCHAPI_ENABLE
bm-p4ofagent : GLOBAL_CFLAGS += -I$(SUBMODULE_P4OFAGENT)
bm-p4ofagent : $(BM_LIB) $(SWITCHAPI_LIB) $(P4OFAGENT_LIB) switchapi_THRIFT
bm-p4ofagent : ${bm-p4ofagent_BINARY}
	cp ${bm-p4ofagent_BINARY} behavioral-model

all: bm

.PHONY: bm-switchapi bm-switchsai bm-switchlink bm-p4ofagent FORCE
