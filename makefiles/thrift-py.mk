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

ifndef THRIFT_INPUT_FILE
  $(error Thrift input file not defined in THRIFT_INPUT_FILE)
endif

ifndef THRIFT_SERVICE_NAME
  $(error Thrift service name not defined in THRIFT_SERVICE_NAME)
endif

ifndef BUILD_DIR
  $(error Build directory not defined in BUILD_DIR)
endif

THRIFT_TEMP_DIR := ${BUILD_DIR}/thrift
MAKE_DIR := ${THRIFT_TEMP_DIR}
include ${THIS_DIR}/makedir.mk

# We expect the Python namespace in the Thrift file to be same as the Thrift
# source file name.
THRIFT_FILE_PREFIX := $(basename $(notdir ${THRIFT_INPUT_FILE}))

THRIFT_PY_OUTPUT_BASENAMES := $(addprefix ${THRIFT_SERVICE_NAME}, .py -remote)
THRIFT_PY_OUTPUT_BASENAMES += constants.py ttypes.py
THRIFT_PY_OUTPUT_BASENAMES_PREREQ := __init__.py

# ${THRIFT_FILE_PREFIX}_THRIFT_PY will contain a list of all Thrift-generated
# Python files. Can be useful for copying the generated files to a different
# directory.
${THRIFT_FILE_PREFIX}_THRIFT_PY := $(addprefix ${THRIFT_TEMP_DIR}/${THRIFT_FILE_PREFIX}/, ${THRIFT_PY_OUTPUT_BASENAMES})
${THRIFT_FILE_PREFIX}_THRIFT_PY += $(addprefix ${THRIFT_TEMP_DIR}/${THRIFT_FILE_PREFIX}/, ${THRIFT_PY_OUTPUT_BASENAMES_PREREQ})
${THRIFT_FILE_PREFIX}_THRIFT_PY_PREREQ := $(addprefix ${THRIFT_TEMP_DIR}/${THRIFT_FILE_PREFIX}/, ${THRIFT_PY_OUTPUT_BASENAMES_PREREQ})

$(filter-out ${${THRIFT_FILE_PREFIX}_THRIFT_PY_PREREQ}, ${${THRIFT_FILE_PREFIX}_THRIFT_PY}) : ${${THRIFT_FILE_PREFIX}_THRIFT_PY_PREREQ}
${${THRIFT_FILE_PREFIX}_THRIFT_PY_PREREQ} : ${THRIFT_INPUT_FILE}
	thrift --gen py --out ${THRIFT_TEMP_DIR}/${${THRIFT_TEMP_DIR}_THRIFT_DIR} $<
