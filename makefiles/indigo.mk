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

THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

ifndef TOOLCHAIN
TOOLCHAIN := gcc-local
endif

MODULE := indigo

include $(BUILDER)/standardinit.mk

DEPENDMODULES := uCli AIM VPI murmur indigo IOF
DEPENDMODULES += SocketManager timer_wheel Configuration ELS OS cjson BigList
include $(BUILDER)/dependmodules.mk

# These indicate Linux specific implementations to be used for
# various features
GLOBAL_CFLAGS += -DINDIGO_LINUX_LOGGING
GLOBAL_CFLAGS += -DINDIGO_LINUX_TIME
GLOBAL_CFLAGS += -DINDIGO_FAULT_ON_ASSERT
GLOBAL_CFLAGS += -DINDIGO_MEM_STDLIB
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MODULES_INIT=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
GLOBAL_CFLAGS += -DNO_LOCI_TYPES
GLOBAL_CFLAGS += -DLIBPCAP_USE_FIX
GLOBAL_CFLAGS += -DDEBUG
# uCli support for modules
#GLOBAL_CFLAGS += -DUCLI_CONFIG_INCLUDE_FGETS_LOOP=1
GLOBAL_CFLAGS += -DUCLI_CONFIG_INCLUDE_ELS_LOOP=1
GLOBAL_CFLAGS += -DSOCKET_MANAGER_CONFIG_INCLUDE_UCLI=1
GLOBAL_CFLAGS += -DVPI_CONFIG_INCLUDE_UCLI=1
GLOBAL_CFLAGS += -DCONFIGURATION_CONFIG_INCLUDE_UCLI=1

LIBRARY := indigo

GLOBAL_CFLAGS += -DNO_LOCI_TYPES

include $(BUILDER)/targets.mk
