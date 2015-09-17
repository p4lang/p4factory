cd submodules/switchapi/ && ./autogen.sh && cd -
cd submodules/switchsai/ && ./autogen.sh && cd -
cd submodules/switchlink/ && ./autogen.sh && cd -
# For some reason, the first run of autogen.sh fails. Everyhting is fine when we
# run it twice. We are trying to fix this, but we are not able to reproduce this
# issue on a fresh clone of the behavioral-model repository...
cd submodules/bm/ && ./autogen.sh > /dev/null; ./autogen.sh && cd -
cd submodules/p4c-bm/pd_mk/ && ./autogen.sh && cd -
cd submodules/p4ofagent && ./autogen.sh && cd -
