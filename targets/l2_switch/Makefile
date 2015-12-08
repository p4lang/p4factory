################################################################
#
# Makefile for l2_switch P4 project
#
################################################################

empty :=
space := $(empty) $(empty)

export TARGET_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

include ../../init.mk

ifndef P4FACTORY
P4FACTORY := $(TARGET_ROOT)/../..
endif
MAKEFILES_DIR := ${P4FACTORY}/makefiles

# This target's P4 name
export P4_INPUT := p4src/l2_switch.p4
export P4_NAME := l2_switch

include ${MAKEFILES_DIR}/common.mk

SUBMODULES_CLEAN += $(SUBMODULE_P4OFAGENT)

###################################
#BUILD P4OFAGENT
###################################
P4OFAGENT_LIB := $(SUBMODULE_P4OFAGENT)/libp4ofagent.a
P4OFAGENT_INC += $(P4FACTORY)/modules/p4utils/module/inc
P4OFAGENT_INC += $(TARGET_ROOT)/build/inc
P4OFAGENT_INC += ${C_INCLUDE_PATH}
P4OFAGENT_INC := $(subst $(space),:,$(P4OFAGENT_INC))

$(P4OFAGENT_LIB) : FORCE $(BM_LIB)
	@${MAKE} -C $(SUBMODULE_P4OFAGENT) p4ofagent C_INCLUDE_PATH=$(P4OFAGENT_INC)

BINARY := bm-p4ofagent
$(BINARY)_LINK_LIBS := $(P4OFAGENT_LIB) $(BM_PLUGIN_LIBS) \
	$(bm-p4ofagent_LINK_LIBS) $(bm_LINK_LIBS) \
	$(BM_LIB) $(p4utils_LIB)
bm-p4ofagent : EXTRA_LINK_LIBS := -lpthread -lpcap -lhiredis \
    -lJudy -lthrift -ledit $(P4OFAGENT_LIB)

include $(MAKEFILES_DIR)/bin.mk
ifndef bm-p4ofagent_BINARY
    $(error Output binary not defined in bm-p4ofagent_BINARY)
endif

bm-p4ofagent : BM_PARAMS += --plugin of
bm-p4ofagent : BM_PARAMS += --openflow-mapping-dir $(TARGET_ROOT)/openflow_mapping
bm-p4ofagent : BM_PARAMS += --openflow-mapping-mod l2
bm-p4ofagent : BM_PARAMS += -DOPENFLOW_ENABLE
bm-p4ofagent : export LIB_P4OFAGENT_ENABLE=1
bm-p4ofagent : GLOBAL_CFLAGS += -DENABLE_PLUGIN_OPENFLOW
bm-p4ofagent : GLOBAL_CFLAGS += -I$(SUBMODULE_P4OFAGENT)
bm-p4ofagent : $(P4OFAGENT_LIB) ${bm-p4ofagent_BINARY} ${GEN_THRIFT_PY_MODULE}
	cp ${bm-p4ofagent_BINARY} behavioral-model

all: bm

.PHONY: bm-p4ofagent FORCE
