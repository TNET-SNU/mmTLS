TARGET = my_ips

######################################################################
# GCC and compilation options
######################################################################
GCC = $(CC)
GCC_OPT = -m64 -Wall -Werror -fgnu89-inline -fcommon
# GCC_OPT += -DNDEBUG -O3 -g -DNETSTAT -DINFO -DDBGERR -DDBGCERR
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
LIBS        += -lmtcp -lssl -lcrypto -lnuma -lpthread -lrt -lhs
LIB_DIR     += -L$(MTCP_FLD)/lib
UTIL_INC    = -I../util/include

# DPDK HEADER
PKGCONF = pkg-config
DPDK_CFLAGS = $(shell $(PKGCONF) --cflags libdpdk)
DPDK_LDFLAGS += $(shell $(PKGCONF) --libs libdpdk)
INC += ${DPDK_CFLAGS}
LIBS += -pthread -lrt ${MTCP_FLD}/lib/libmtcp.a -lnuma -lmtcp -lpthread -libverbs -lm -lrt -ldl -lgmp ${DPDK_LDFLAGS}
######################################################################

default: $(TARGET)
SRCS-y := mmtls.c $(TARGET).c dpi.c

$(MTCP_TARGET):
	cd $(MTCP_FLD)/src && make	

$(TARGET): $(MTCP_TARGET) $(TARGET).c
	$(MSG) "   CC $<"
	$(HIDE) $(GCC) $(GCC_OPT) -o $@ $(SRCS-y) $(MTCP_INC) $(CMN_INC) $(UTIL_INC) $(INC) $(LIB_DIR) $(LIBS)

clean:
	rm -rf *~ *.o $(TARGET) logs/*

cleanall: clean
	rm -rf Makefile
