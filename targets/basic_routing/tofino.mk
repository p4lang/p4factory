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
# Makefile for basic_routing P4 project
#
################################################################

export TARGET_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

include ../../init.mk

# This target's P4 name
export P4_INPUT := p4src/basic_routing.p4
export P4_NAME := basic_routing

# Common defines targets for P4 programs
COMMON_DIR := ${ROOT}/targets/common
include ${COMMON_DIR}/common.mk

# Put custom targets in basic_routing-local.mk
-include basic_routing-local.mk

