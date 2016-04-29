ifndef VERBOSE
VERBOSE = @
else
ifeq ($(VERBOSE),0)
override VERBOSE = @
else
override VERBOSE =
endif
endif

BUILD_DIR := ${TARGET_ROOT}/build/
MAKE_DIR := ${BUILD_DIR}
include ${MAKEFILES_DIR}/makedir.mk

include $(MAKEFILES_DIR)/bmv2.mk

GLOBAL_INCLUDES := $(addprefix -I, $(BMV2_PD_INC))

$(BUILD_DIR)/main.o: $(TARGET_ROOT)/main.c bmv2-pd
	@echo Compiling : $(notdir $@)
	$(VERBOSE)gcc -o $@ $(GLOBAL_INCLUDES) $(GLOBAL_CFLAGS) -c $<

PD_LIBS := -L$(BMV2_PD_LIB_DIR)/ -Wl,-rpath=$(BMV2_PD_LIB_DIR) -lpd -lpdthrift
PD_LIBS += -L$(BMV2_PDFIXED_LIB_DIR)/ -Wl,-rpath=$(BMV2_PDFIXED_LIB_DIR) -lbmpdfixed -lbmpdfixedthrift

$(PD_LIBS): FORCE

BIN_DIR := $(TARGET_ROOT)
BINARY := drivers
${BINARY}_LINK_LIBS := $(BUILD_DIR)/main.o $(PD_LIBS)
drivers : EXTRA_LINK_LIBS := -lpthread -lJudy -lthrift
include ${MAKEFILES_DIR}/bin.mk
ifndef drivers_BINARY
	$(error Output binary not defined in drivers_BINARY)
endif

THRIFT_PY_OUTPUT_DIR := $(TARGET_ROOT)/../tests/pd_thrift/
MAKE_DIR := ${THRIFT_PY_OUTPUT_DIR}
include ${MAKEFILES_DIR}/makedir.mk

# -f necessary because some destination files may already exist and be protected
drivers : bmv2-pd
drivers : ${drivers_BINARY} FORCE
	cp -rf $(BMV2_THRIFT_PY_DIR)/* $(THRIFT_PY_OUTPUT_DIR)
	cp -rf $(BMV2_THRIFT_FIXED_PY_DIR)/* $(THRIFT_PY_OUTPUT_DIR)

bm: bmv2 bmv2-pd drivers

.DEFAULT_GOAL := bm

clean : bmv2-clean clean-local
	@echo Cleaning Files
	@rm -rf ${CLEAN_TARGETS}
	@echo Cleaning Directories
	@rm -rf ${CLEAN_DIRECTORIES}

.PHONY: bm clean FORCE
