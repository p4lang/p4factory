################################################################
#
#        Copyright 2013, Big Switch Networks, Inc. 
#        Copyright 2013, Barefoot Networks, Inc. 
# 
# Licensed under the Eclipse Public License, Version 1.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
# 
#        http://www.eclipse.org/legal/epl-v10.html
# 
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the
# License.
#
################################################################

#
# The root of of our repository is here:
#
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

#
# Resolve submodule dependencies. 
# Please keep alphabetized

ifndef SUBMODULE_BM
  ifdef SUBMODULES
    SUBMODULE_BM := $(SUBMODULES)/bm
  else
    SUBMODULE_BM := $(ROOT)/submodules/bm
    SUBMODULES_LOCAL += bm
  endif
endif

ifndef SUBMODULE_OFT_INFRA
  ifdef SUBMODULES
    SUBMODULE_OFT_INFRA := $(SUBMODULES)/oft-infra
  else
    SUBMODULE_OFT_INFRA := $(ROOT)/submodules/oft-infra
    SUBMODULES_LOCAL += oft-infra
  endif
endif

ifndef SUBMODULE_P4C_BEHAVIORAL
  ifdef SUBMODULES
    SUBMODULE_P4C_BEHAVIORAL := $(SUBMODULES)/p4c-behavioral
  else
    SUBMODULE_P4C_BEHAVIORAL := $(ROOT)/submodules/p4c-behavioral
    SUBMODULES_LOCAL += p4c-behavioral
  endif
endif

ifndef SUBMODULE_P4C_BM
  ifdef SUBMODULES
    SUBMODULE_P4C_BM := $(SUBMODULES)/p4c-bm
  else
    SUBMODULE_P4C_BM := $(ROOT)/submodules/p4c-bm
    SUBMODULES_LOCAL += p4c-bm
  endif
endif

ifndef SUBMODULE_P4C_GRAPHS
  ifdef SUBMODULES
    SUBMODULE_P4C_GRAPHS := $(SUBMODULES)/p4c-graphs
  else
    SUBMODULE_P4C_GRAPHS := $(ROOT)/submodules/p4c-graphs
    SUBMODULES_LOCAL += p4c-graphs
  endif
endif

ifndef SUBMODULE_SWITCHAPI
  ifdef SUBMODULES
    SUBMODULE_SWITCHAPI := $(SUBMODULES)/switchapi
  else
    SUBMODULE_SWITCHAPI := $(ROOT)/submodules/switchapi
    SUBMODULES_LOCAL += switchapi
  endif
endif

ifndef SUBMODULE_SWITCHSAI
  ifdef SUBMODULES
    SUBMODULE_SWITCHSAI := $(SUBMODULES)/switchsai
  else
    SUBMODULE_SWITCHSAI := $(ROOT)/submodules/switchsai
    SUBMODULES_LOCAL += switchsai
  endif
endif

ifndef SUBMODULE_SWITCHLINK
  ifdef SUBMODULES
    SUBMODULE_SWITCHLINK:= $(SUBMODULES)/switchlink
  else
	SUBMODULE_SWITCHLINK := $(ROOT)/submodules/switchlink
    SUBMODULES_LOCAL += switchlink
  endif
endif

ifndef SUBMODULE_P4OFAGENT
  ifdef SUBMODULES
    SUBMODULE_P4OFAGENT:= $(SUBMODULES)/p4ofagent
  else
	SUBMODULE_P4OFAGENT := $(ROOT)/submodules/p4ofagent
    SUBMODULES_LOCAL += p4ofagent
  endif
endif

ifdef SUBMODULES_LOCAL
  SUBMODULES_LOCAL_UPDATE := $(shell python $(ROOT)/submodules/init.py --update $(SUBMODULES_LOCAL))
  ifneq ($(lastword $(SUBMODULES_LOCAL_UPDATE)),submodules:ok.)
    $(info Local submodule update failed.)
    $(info Result:)
    $(info $(SUBMODULES_LOCAL_UPDATE))
    $(error Abort)
  endif
endif

export SUBMODULE_BM
export SUBMODULE_OFT_INFRA
export SUBMODULE_P4C_BEHAVIORAL
export SUBMODULE_P4C_BM
export SUBMODULE_P4C_GRAPHS
export SUBMODULE_SWITCHAPI
export SUBMODULE_SWITCHSAI
export SUBMODULE_SWITCHLINK
export SUBMODULE_P4OFAGENT

MODULE_DIRS := $(ROOT)/modules

.show-submodules:
	@echo bm @ $(SUBMODULE_BM)
	@echo oft_infra @ $(SUBMODULE_OFT_INFRA)
	@echo p4c_behavioral @ $(SUBMODULE_P4C_BEHAVIORAL)
	@echo p4c_bm @ $(SUBMODULE_P4C_BM)
	@echo p4c_graphs @ $(SUBMODULE_P4C_GRAPHS)
	@echo switchapi @ $(SUBMODULE_SWITCHAPI)
	@echo switchsai @ $(SUBMODULE_SWITCHSAI)
	@echo switchlink @ $(SUBMODULE_SWITCHLINK)
	@echo p4ofagent @ $(SUBMODULE_P4OFAGENT)

