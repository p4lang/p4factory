###############################################################################
#
# p4utils Unit Test Makefile.
#
###############################################################################
UMODULE := p4utils
UMODULE_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/utest.mk
