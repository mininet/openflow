#
# Hardware library dependency file definitions.
#

if NF2
#
# NetFPGA hardware library
#
noinst_LIBRARIES += hw-lib/libnf2.a

hw_lib_libnf2_a_SOURCES =		\
	hw-lib/nf2/hw_flow.c	\
	hw-lib/nf2/hw_flow.h	\
	hw-lib/nf2/nf2_lib.c	\
	hw-lib/nf2/nf2_lib.h	\
	hw-lib/nf2/nf2_drv.c	\
	hw-lib/nf2/nf2_drv.h	\
	hw-lib/nf2/nf2.h	\
	hw-lib/nf2/debug.h	\
	hw-lib/nf2/reg_defines_openflow_switch.h	\
	hw-lib/nf2/nf2util.c	\
	hw-lib/nf2/nf2util.h

hw_lib_nf2_a_CPPFLAGS = $(AM_CPPFLAGS) $(OF_CPP_FLAGS) -DHWTABLE_NO_DEBUG
hw_lib_nf2_a_CPPFLAGS += -I hw-lib/nf2
hw_lib_nf2_a_CPPFLAGS += -I $(HW_SYSTEM)/include

endif
