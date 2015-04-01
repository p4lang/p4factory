###############################################################################
#
# common Unit Test Makefile.
#
###############################################################################
UMODULE := common
UMODULE_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/utest.mk
