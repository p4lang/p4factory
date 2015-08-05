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

ifndef THRIFT_INPUT_FILES
  $(error Thrift input files not defined in THRIFT_INPUT_FILES)
endif

ifndef THRIFT_DEP_FILES
  $(error Thrift dep files not defined in THRIFT_DEP_FILES)
endif

ifndef THRIFT_SERVICE_NAMES
  $(error Thrift service names not defined in THRIFT_SERVICE_NAMES)
endif

ifndef BUILD_DIR
  $(error Build directory not defined in BUILD_DIR)
endif

THRIFT_TEMP_DIR := ${BUILD_DIR}/thrift
MAKE_DIR := ${THRIFT_TEMP_DIR}
include ${THIS_DIR}/makedir.mk

ifndef THRIFT_INPUT_FILES_ALL
  THRIFT_INPUT_FILES_ALL :=
endif
THRIFT_INPUT_FILES_ALL += ${THRIFT_INPUT_FILES}

ifndef THRIFT_DEP_FILES_ALL
  THRIFT_DEP_FILES_ALL :=
endif
THRIFT_DEP_FILES_ALL += ${THRIFT_DEP_FILES}

# We expect the Python namespace in the Thrift file to be same as the Thrift
# source file name.
THRIFT_FILE_PREFIXS := $(basename $(notdir ${THRIFT_INPUT_FILES}))

THRIFT_PY_OUTPUT_BASENAMES_PREREQ := __init__.py

THRIFT_PY_MODULES := $(addprefix ${THRIFT_TEMP_DIR}/, ${THRIFT_FILE_PREFIXS})

ifndef THRIFT_PY_PREREQS_ALL
  THRIFT_PY_PREREQS_ALL := 
endif
THRIFT_PY_PREREQS = $(addsuffix /${THRIFT_PY_OUTPUT_BASENAMES_PREREQ}, ${THRIFT_PY_MODULES})
THRIFT_PY_PREREQS_ALL += ${THRIFT_PY_PREREQS}

ifndef GEN_THRIFT_PY_MODULE
  GEN_THRIFT_PY_MODULE :=
endif
GEN_THRIFT_PY_MODULE += ${THRIFT_PY_MODULES}

${THRIFT_PY_MODULES}: ${THRIFT_PY_PREREQS}

${THRIFT_PY_PREREQS}: ${THRIFT_DEP_FILES_ALL}
	@echo "Generating python thrift files"
	@$(foreach t,${THRIFT_INPUT_FILES_ALL},thrift -r --gen py --out ${THRIFT_TEMP_DIR}/${${THRIFT_TEMP_DIR}_THRIFT_DIR} ${t} && ) true
