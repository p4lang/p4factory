###############################################################################
#
# 
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
p4ns_common_INCLUDES := -I $(THIS_DIR)inc
p4ns_common_INTERNAL_INCLUDES := -I $(THIS_DIR)src
p4ns_common_DEPENDMODULE_ENTRIES := init:p4ns_common ucli:p4ns_common

