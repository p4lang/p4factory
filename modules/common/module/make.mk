###############################################################################
#
# 
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
common_INCLUDES := -I $(THIS_DIR)inc
common_INTERNAL_INCLUDES := -I $(THIS_DIR)src
common_DEPENDMODULE_ENTRIES := init:common ucli:common

