###############################################################################
#
# p4ns_common Unit Test Makefile.
#
###############################################################################
UMODULE := p4ns_common
UMODULE_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/utest.mk
