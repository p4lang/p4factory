################################################################
#
# Makefile for rocker_p4 P4 project
#
################################################################

export TARGET_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

include ../../init.mk

ifndef P4FACTORY
P4FACTORY := $(TARGET_ROOT)/../..
endif
MAKEFILES_DIR := ${P4FACTORY}/makefiles

# This target's P4 name
export P4_INPUT := p4src/rocker_p4.p4
export P4_NAME := rocker_p4

export PLUGIN_ROCKER := 1

# Common defines targets for P4 programs
include ${MAKEFILES_DIR}/common.mk
BM_PARAMS += --plugin="rocker"

# Put custom targets in rocker_p4-local.mk
#-include rocker_p4-local.mk

FILE_SRC := build/bm/plugin/rocker/src
rocker: bm
		# Build files needed for rocker driver
		echo "Building files for Rocker driver and QEMU device...."
		-rm -rf build/rocker/driver
		-rm -rf build/rocker/device
		@mkdir -p build/rocker/driver
		@mkdir -p build/rocker/device
		@cp $(FILE_SRC)/rocker_p4_enums.h  build/rocker/driver/$(P4_NAME)_enums.h
		@cp $(FILE_SRC)/rocker_p4_pd.h     build/rocker/driver/$(P4_NAME)_pd.h
		@cp $(FILE_SRC)/rocker_p4_tables.h build/rocker/driver/$(P4_NAME)_tables.h
		@cp $(FILE_SRC)/rocker_p4_pd.c     build/rocker/driver/$(P4_NAME)_pd.c
		@cp ./p4src/includes/rocker_p4_features.h build/rocker/device/$(P4_NAME)_features.h
		@cp ./build/lib/bm.a 	build/rocker/device/$(P4_NAME)_bm.a
		@cp ./build/lib/p4utils.a 	build/rocker/device/p4utils.a
		@cp ./build/inc/p4_sim/rmt.h 	build/rocker/device/$(P4_NAME)_rmt.h
		@cp $(FILE_SRC)/rocker_p4_enums.h  build/rocker/device/$(P4_NAME)_enums.h
		@cp $(FILE_SRC)/rocker_p4_tables.h build/rocker/device/$(P4_NAME)_tables.h
		@cp $(FILE_SRC)/rocker_p4_lf.h build/rocker/device/$(P4_NAME)_lf.h
		@cp $(FILE_SRC)/rocker_p4_tables_if.h build/rocker/device/$(P4_NAME)_tables_if.h
