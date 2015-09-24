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

THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

# These indicate Linux specific implementations to be used for
# various features
GLOBAL_CFLAGS += -DINDIGO_LINUX_LOGGING
GLOBAL_CFLAGS += -DINDIGO_LINUX_TIME
GLOBAL_CFLAGS += -DINDIGO_FAULT_ON_ASSERT
GLOBAL_CFLAGS += -DINDIGO_MEM_STDLIB
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MODULES_INIT=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
GLOBAL_CFLAGS += -DLIBPCAP_USE_FIX
GLOBAL_CFLAGS += -DDEBUG
# uCli support for modules
#GLOBAL_CFLAGS += -DUCLI_CONFIG_INCLUDE_FGETS_LOOP=1
#GLOBAL_CFLAGS += -DUCLI_CONFIG_INCLUDE_ELS_LOOP=1
#GLOBAL_CFLAGS += -DSOCKET_MANAGER_CONFIG_INCLUDE_UCLI=1
#GLOBAL_CFLAGS += -DVPI_CONFIG_INCLUDE_UCLI=1
#GLOBAL_CFLAGS += -DCONFIGURATION_CONFIG_INCLUDE_UCLI=1
GLOBAL_CFLAGS += -g -Wall -Wno-unused-function -Werror

GLOBAL_INCLUDES += -I $(TARGET_ROOT)/p4src/includes

LIB_DIR := ${BUILD_DIR}/lib
MAKE_DIR := ${LIB_DIR}
include ${MAKEFILES_DIR}/makedir.mk

OBJ_DIR := $(BUILD_DIR)/obj
MAKE_DIR := ${OBJ_DIR}
include ${MAKEFILES_DIR}/makedir.mk

PUBLIC_INC_PATH := ${BUILD_DIR}/inc
P4_PUBLIC_INC_PATH := ${PUBLIC_INC_PATH}/p4sim

BM_LIB := ${LIB_DIR}/bm.a

DEBUG_FLAGS += -g

#include ${MAKEFILES_DIR}/indigo.mk

# Used in all includes of module.mk.
MODULE_BASE_DIR := $(P4FACTORY)

MODULE := p4utils
MODULE_LIB := $(LIB_DIR)/p4utils.a
include $(MAKEFILES_DIR)/module.mk
ifndef p4utils_OBJS_C
  $(error No object files defined in p4utils_OBJS_C)
endif
$(p4utils_OBJS_C) : MODULE_INFO := p4utils

MODULE := p4ns_common
MODULE_LIB := $(LIB_DIR)/p4ns_common.a
include $(MAKEFILES_DIR)/module.mk
ifndef p4ns_common_OBJS_C
  $(error No object files defined in p4ns_common_OBJS_C)
endif
$(p4ns_common_OBJS_C) : MODULE_INFO := p4ns_common

MODULE := BMI
MODULE_LIB := $(LIB_DIR)/BMI.a
include $(MAKEFILES_DIR)/module.mk
ifndef BMI_OBJS_C
  $(error No object files defined in BMI_OBJS_C)
endif
$(BMI_OBJS_C) : MODULE_INFO := BMI

P4_INCLUDES_DIR := $(TARGET_ROOT)/p4src/includes
BM_THRIFT_PY_OUTPUT_DIR := ${TARGET_ROOT}/tests/pd_thrift
MAKE_DIR := ${BM_THRIFT_PY_OUTPUT_DIR}
include ${MAKEFILES_DIR}/makedir.mk

include ${SUBMODULE_P4C_BEHAVIORAL}/p4c-bm.mk
ifndef GEN_THRIFT_PY_MODULE
  $(error p4c-bm does not define thrift-generated Python files in GEN_THRIFT_PY_MODULE)
endif
ifndef PD_PUBLIC_HEADERS_DIR
  $(error p4c-bm does not define PD headers in PD_PUBLIC_HEADERS_DIR
endif

GLOBAL_INCLUDES += -I $(PUBLIC_INC_PATH)

SRC_FILES := $(notdir $(wildcard ${TARGET_ROOT}/*.c))
OBJ_FILES := $(addprefix $(OBJ_DIR)/, $(SRC_FILES:%.c=%.o))
$(OBJ_FILES) : $(OBJ_DIR)/%.o : %.c ${BM_TENJIN_TARGET}
	@echo Compiling : $(notdir $@)
	$(VERBOSE)gcc -o $@ $(COVERAGE_FLAGS) $(DEBUG_FLAGS) $(GLOBAL_INCLUDES) -I $(PUBLIC_INC_PATH) $(GLOBAL_CFLAGS) $(MAIN_CFLAGS) -c $<

ifdef PLUGIN_LIBS
BM_PLUGIN_LIBS := $(addprefix $(LIB_DIR)/, $(PLUGIN_LIBS))
endif

BINARY := bm
bm_LINK_LIBS := $(OBJ_FILES) $(BM_LIB) $(p4utils_LIB) $(p4ns_common_LIB) $(BMI_LIB) $(addprefix $(LIBRARY_DIR)/, $(LIBRARY_TARGETS)) $(addprefix $(LIBRARY_DIR)/, $(LIBRARY_TARGETS))  $(BM_PLUGIN_LIBS)
bm : EXTRA_LINK_LIBS := ${BM_LIB} ${BM_LIBS_OPTIONAL} ${p4utils_LIB} ${BM_LIB} -lpthread -lpcap -lhiredis -lJudy -lthrift -ledit
include ${MAKEFILES_DIR}/bin.mk

bm : ${BM_LIB} $(bm_BINARY) ${GEN_THRIFT_PY_MODULE}
	cp ${bm_BINARY} behavioral-model
	cp -r ${THRIFT_TEMP_DIR}/* ${BM_THRIFT_PY_OUTPUT_DIR}/

.PHONY: bm
