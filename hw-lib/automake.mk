#
# Hardware library dependency file definitions.
#

# Sample name
if LB4G
#
# Sample library
#
noinst_LIBRARIES += hw-lib/libskeleton.a

hw_lib_libskeleton_a_SOURCES =		\
	hw-lib/skeleton/of_hw_platform.h	\
	hw-lib/skeleton/txrx.c		\
	hw-lib/skeleton/txrx.h		\
	hw-lib/skeleton/hw_drv.c		\
	hw-lib/skeleton/hw_drv.h		\
	hw-lib/skeleton/hw_flow.c		\
	hw-lib/skeleton/hw_flow.h		\
	hw-lib/skeleton/port.c		\
	hw-lib/skeleton/port.h		\
	hw-lib/skeleton/debug.h

hw_lib_libskeleton_a_CPPFLAGS = $(AM_CPPFLAGS) $(OF_CPP_FLAGS)
hw_lib_libskeleton_a_CPPFLAGS += -I hw-lib/skeleton
hw_lib_libskeleton_a_CPPFLAGS += -I $(HW_SYSTEM)/include
hw_lib_libskeleton_a_CPPFLAGS += -DSAMPLE_PLAT
hw_lib_libskeleton_a_CPPFLAGS += -DSKELETON

endif
