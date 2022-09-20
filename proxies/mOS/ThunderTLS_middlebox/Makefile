TARGET = tls_middlebox

######################################################################
# GCC and compilation options
######################################################################
GCC = $(CC)
GCC_OPT = -m64 -Wall -Werror -fgnu89-inline
GCC_OPT += -DNDEBUG -O3 -g -DNETSTAT -DINFO -DDBGERR -DDBGCERR
GCC_OPT += $(DBG_OPT)
ifeq ($V,) # no echo
    export MSG=@echo
    export HIDE=@
else
    export MSG=@\#
    export HIDE=
endif

######################################################################
# LIBRARIES AND INCLUDES
######################################################################
MTCP_FLD    = ../core
MTCP_INC    =-I$(MTCP_FLD)/include
MTCP_TARGET = $(MTCP_FLD)/lib/libmtcp.a
LIBS        += -lmtcp -lssl -lcrypto -lnuma -lpthread -lrt
LIB_DIR     += -L$(MTCP_FLD)/lib
UTIL_INC    = -I../util/include

# I/O library parameter (PSIO or DPDK)
LIBS    += -m64 -g -pthread -lrt -march=native -Wl,-export-dynamic -L$(RTE_SDK)/$(RTE_TARGET)/lib -Wl,-lnuma -Wl,-lmtcp -Wl,-lpthread -Wl,-lrt -Wl,-ldl $(shell cat $(RTE_SDK)/$(RTE_TARGET)/lib/ldflags.txt)

# DPDK HEADER
DPDK_INC=$(RTE_SDK)/$(RTE_TARGET)/include
# CFLAGS for DPDK-related compilation
include $(RTE_SDK)/mk/rte.vars.mk
INC = -DENABLE_DPDK -I${DPDK_INC} -include $(DPDK_INC)/rte_config.h

######################################################################

default: $(TARGET)
SRCS-y := $(TARGET).c thash.c

$(MTCP_TARGET):
	cd $(MTCP_FLD)/src && make	

$(TARGET): $(MTCP_TARGET) $(TARGET).c
	$(MSG) "   CC $<"
	$(HIDE) $(GCC) $(GCC_OPT) -o $@ $(SRCS-y) $(MTCP_INC) $(CMN_INC) $(UTIL_INC) $(INC) $(LIB_DIR) $(LIBS)

clean:
	rm -rf *~ *.o $(TARGET) logs/*

cleanall: clean
	rm -rf Makefile


