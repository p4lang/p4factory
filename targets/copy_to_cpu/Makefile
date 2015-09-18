################################################################
#
# Makefile for copy_to_cpu P4 project
#
################################################################

export TARGET_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

include ../../init.mk

ifndef P4FACTORY
P4FACTORY := $(TARGET_ROOT)/../..
endif
MAKEFILES_DIR := ${P4FACTORY}/makefiles

# This target's P4 name
export P4_INPUT := p4src/copy_to_cpu.p4
export P4_NAME := copy_to_cpu

include ${MAKEFILES_DIR}/common.mk

all: bm
