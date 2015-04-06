################################################################
#
# Makefile for basic_routing P4 project
#
################################################################

export TARGET_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

include ../../init.mk

ifndef P4FACTORY
P4FACTORY := $(TARGET_ROOT)/../..
endif
MAKEFILES_DIR := ${P4FACTORY}/makefiles

# This target's P4 name
export P4_INPUT := p4src/p4_l2l3.p4
export P4_NAME := p4_l2l3

include ${MAKEFILES_DIR}/common.mk

all: bm
