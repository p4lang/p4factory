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
FILE_SRC := ../../submodules/p4c-behavioral/p4c_bm

# This target's P4 name
export P4_INPUT := p4src/p4_l2l3.p4
export P4_NAME := p4_l2l3

include ${MAKEFILES_DIR}/common.mk

all: bm

rocker: all
		# Build files needed for rocker driver
		echo "Building files for Rocker driver and QEMU device...."
		@(cd ../../submodules/p4c-behavioral/p4c_bm; ./shell.py --templates-dir rocker/templates --gen-dir rocker ../../../targets/$(P4_NAME)/p4src/$(P4_NAME).p4)
		# Move files needed t=for rocker driver and rocker qemu device in one directory
		# This will change once all git repoes are combined a sub modules
		@mkdir -p build/rocker/driver
		@mkdir -p build/rocker/device
		-rm -f build/rocker/driver/*
		-rm -f build/rocker/device/*
		@cp $(FILE_SRC)/rocker/src/rocker_p4_enums.h  build/rocker/driver/rocker_$(P4_NAME)_enums.h
		@cp $(FILE_SRC)/rocker/src/rocker_p4_pd.h     build/rocker/driver/rocker_$(P4_NAME)_pd.h
		@cp $(FILE_SRC)/rocker/src/rocker_p4_tables.h build/rocker/driver/rocker_$(P4_NAME)_tables.h
		@cp $(FILE_SRC)/rocker/src/rocker_p4_pd.c     build/rocker/driver/rocker_$(P4_NAME)_pd.c
		@cp $(FILE_SRC)/rocker/src/rocker_p4_lf.h     build/rocker/driver/rocker_$(P4_NAME)_lf.h
		@cp ./p4src/includes/$(P4_NAME)_features.h build/rocker/device/rocker_$(P4_NAME)_features.h
		@cp ./build/lib/bm.a 											build/rocker/device/$(P4_NAME)_bm.a
		@cp ./build/lib/p4utils.a 									build/rocker/device/p4utils.a
		@cp ./build/inc/p4_sim/rmt.h 							build/rocker/device/rocker_p4_rmt.h
		@cp $(FILE_SRC)/rocker/src/rocker_p4_enums.h  					build/rocker/device/rocker_$(P4_NAME)_enums.h
		@cp $(FILE_SRC)/rocker/src/rocker_p4_tables.h 					build/rocker/device/rocker_$(P4_NAME)_tables.h
		@cp $(FILE_SRC)/rocker/src/rocker_p4_lf.h 							build/rocker/device/rocker_$(P4_NAME)_lf.h
		@cp $(FILE_SRC)/rocker/src/rocker_p4_tables_if.h 			build/rocker/device/rocker_$(P4_NAME)_tables_if.h
