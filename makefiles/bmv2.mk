BMV2_PD_DIR = $(BUILD_DIR)/bmv2_pd/

BMV2_P4C_MAIN := $(SUBMODULE_P4C_BM)/p4c_bm/__main__.py

BMV2_PD_ENV := 'P4_PATH=$(TARGET_ROOT)/$(P4_INPUT)' 'P4_NAME=$(P4_NAME)' 'P4_PREFIX=$(P4_PREFIX)'
BMV2_PD_ENV += 'P4C_BM=$(BMV2_P4C_MAIN)'
BMV2_PD_ENV += 'CPPFLAGS=-I$(BUILD_DIR)/inst/include'

BMV2_EXE := $(TARGET_ROOT)/$(P4_NAME)_bmv2

$(BMV2_PD_DIR):
	@echo $(BUILD_DIR)
	@echo $(BMV2_PD_DIR)
	mkdir -p $(BMV2_PD_DIR)

bmv2-pd.ts: $(BMV2_EXE) | $(BMV2_PD_DIR)
	echo $(BMV2_EXE)
	cd $(BMV2_PD_DIR); $(SUBMODULE_P4_BUILD)/configure --with-bmv2 --prefix=/inst $(BMV2_PD_ENV); cd -;
	@touch $@

bmv2-pd: $(P4_INPUT) bmv2-pd.ts
	@echo $(BUILD_DIR)
	$(MAKE) -C $(BMV2_PD_DIR)
	$(MAKE) -C $(BMV2_PD_DIR) 'DESTDIR=$(BUILD_DIR)' install

BMV2_PD_INC := $(BUILD_DIR)/inst/include

BMV2_PD_LIB_DIR := $(BUILD_DIR)/inst/lib/bmpd/$(P4_NAME)/
BMV2_PDFIXED_LIB_DIR := $(BUILD_DIR)/inst/lib/

PYTHON_VERSION = $(shell python -c "import sys; print sys.version[:3],")
PYTHON_SITE_PACKAGES = $(BUILD_DIR)/inst/lib/python$(PYTHON_VERSION)/site-packages
BMV2_THRIFT_FIXED_PY_DIR = $(PYTHON_SITE_PACKAGES)/bm/pdfixed/
BMV2_THRIFT_PY_DIR = $(PYTHON_SITE_PACKAGES)/bmpd/$(P4_NAME)/

$(BMV2_EXE):
	$(MAKE) -C $(SUBMODULE_BM)
	$(MAKE) -C $(SUBMODULE_BM) 'DESTDIR=$(BUILD_DIR)' install
	ln -sf $(SUBMODULE_BM)/targets/simple_switch/simple_switch $(BMV2_EXE)

BMV2_JSON := $(TARGET_ROOT)/$(P4_NAME)_bmv2.json

$(BMV2_JSON): $(P4_INPUT)
	$(BMV2_P4C_MAIN) --json $@ $<

bmv2 :$(BMV2_EXE) $(BMV2_JSON)

bmv2-clean:
	$(MAKE) -C $(SUBMODULE_BM) clean
	if test -f $(SUBMODULE_P4_BUILD)/Makefile; then \
		$(MAKE) -C $(SUBMODULE_P4_BUILD) clean; \
	fi
	rm -f $(BMV2_EXE) $(BMV2_JSON)
	rm -f bmv2-pd.ts

.PHONY: bmv2-clean bmv2 bmv2-pd
