################################################################
#
# Makefile for __PROJECT_NAME__ P4 project
#
################################################################

export TARGET_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

include ../../init.mk

ifndef P4FACTORY
P4FACTORY := $(TARGET_ROOT)/../..
endif
MAKEFILES_DIR := ${P4FACTORY}/makefiles

# This target's P4 name
export P4_INPUT := p4src/__PROJECT_NAME__.p4
export P4_NAME := __PROJECT_NAME__

# Common defines targets for P4 programs
include ${MAKEFILES_DIR}/common.mk

# Put custom targets in __PROJECT_NAME__-local.mk
-include __PROJECT_NAME__-local.mk

all:bm

