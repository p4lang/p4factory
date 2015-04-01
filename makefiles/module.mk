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
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

ifndef BUILD_DIR
$(error BUILD_DIR not defined)
endif

ifndef MODULE
$(error MODULE not defined)
endif

ifndef MODULE_LIB
$(error MODULE_LIB not defined)
endif

ifndef $(MODULE)_DIR
  ifdef MODULE_BASE_DIR
    # We are assuming a big-code type directory structure here.
    $(MODULE)_DIR := $(MODULE_BASE_DIR)/modules/$(MODULE)/module
  else
    $(error $(MODULE)_DIR and MODULE_BASE_DIR not defined)
  endif
endif

ifdef PD_PUBLIC_HEADERS_DIR
  P4_PREREQ := ${PD_PUBLIC_HEADERS_DIR}/pd.h
endif

$(MODULE)_SRC_DIR := $($(MODULE)_DIR)/src
$(MODULE)_INC_DIR := $($(MODULE)_DIR)/inc
$(MODULE)_SOURCES_C := $(wildcard $($(MODULE)_SRC_DIR)/*.c)
$(MODULE)_SOURCES_CPP := $(wildcard $($(MODULE)_SRC_DIR)/*.cpp)

# We are not using += assignment here to ensure that both sides are expanded
# immediately.
GLOBAL_INCLUDES := $(GLOBAL_INCLUDES) -I $($(MODULE)_INC_DIR)/

$(MODULE)_BUILD_DIR := $(BUILD_DIR)/$(MODULE)
$(MODULE)_BUILD_OBJ_DIR := $($(MODULE)_BUILD_DIR)/obj
MAKE_DIR := $($(MODULE)_BUILD_DIR)
include $(THIS_DIR)/makedir.mk
MAKE_DIR := $($(MODULE)_BUILD_OBJ_DIR)
include $(THIS_DIR)/makedir.mk

ifdef COVERAGE
COVERAGE_FLAGS := --coverage
endif

$(MODULE)_OBJS_C := $(addprefix $($(MODULE)_BUILD_OBJ_DIR)/, $(notdir $($(MODULE)_SOURCES_C:%.c=%.o)))
$($(MODULE)_BUILD_OBJ_DIR)/%.o : $($(MODULE)_SRC_DIR)/%.c ${P4_PREREQ}
	@echo "    Compiling : $(MODULE_INFO)::$(notdir $@)"
	$(VERBOSE)gcc -o $@ $(COVERAGE_FLAGS) $(DEBUG_FLAGS) $(GLOBAL_INCLUDES) $(GLOBAL_CFLAGS) $(MODULE_INCLUDES) -MD -c $<

$(MODULE)_OBJS_CPP := $(addprefix $($(MODULE)_BUILD_OBJ_DIR)/, $(notdir $($(MODULE)_SOURCES_CPP:%.cpp=%.o)))
$($(MODULE)_BUILD_OBJ_DIR)/%.o : $($(MODULE)_SRC_DIR)/%.cpp ${P4_PREREQ}
	@echo "    Compiling : $(MODULE_INFO)::$(notdir $@)"
	$(VERBOSE)g++ -o $@ $(COVERAGE_FLAGS) $(DEBUG_FLAGS) $(GLOBAL_INCLUDES) $(GLOBAL_CFLAGS) $(MODULE_INCLUDES) -MD -std=c++11 -c $<

# Include the auto-generated .d dependency files. gcc/g++ generate the .d file
# when -MD option is used.
-include $($(MODULE)_OBJS_C:.o=.d)
-include $($(MODULE)_OBJS_CPP:.o=.d)

$(MODULE)_LIB := $(MODULE_LIB)
$($(MODULE)_LIB) : MODULE_INCLUDES := -I $($(MODULE)_INC_DIR)/$(MODULE)
$($(MODULE)_LIB) : $($(MODULE)_PREREQ) $($(MODULE)_OBJS_C) $($(MODULE)_OBJS_CPP)
	@echo "    Creating : $(notdir $@)"
	$(VERBOSE)ar -rc $@ $^
