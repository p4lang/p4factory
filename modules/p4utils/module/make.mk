###############################################################################
#
# 
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
p4utils_INCLUDES := -I $(THIS_DIR)inc -I $(THIS_DIR)/inc/p4utils
p4utils_INTERNAL_INCLUDES := -I $(THIS_DIR)src
p4utils_DEPENDMODULE_ENTRIES := init:p4utils ucli:p4utils

