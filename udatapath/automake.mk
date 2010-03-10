#
# Build udatapath as binary
#

bin_PROGRAMS += udatapath/ofdatapath
man_MANS += udatapath/ofdatapath.8

udatapath_ofdatapath_SOURCES = \
	udatapath/chain.c \
	udatapath/chain.h \
	udatapath/crc32.c \
	udatapath/crc32.h \
	udatapath/datapath.c \
	udatapath/datapath.h \
	udatapath/dp_act.c \
	udatapath/dp_act.h \
	udatapath/of_ext_msg.c \
	udatapath/of_ext_msg.h \
	udatapath/udatapath.c \
	udatapath/private-msg.c \
	udatapath/private-msg.h \
	udatapath/switch-flow.c \
	udatapath/switch-flow.h \
	udatapath/table.h \
	udatapath/table-hash.c \
	udatapath/table-linear.c

udatapath_ofdatapath_LDADD = lib/libopenflow.a $(SSL_LIBS) $(FAULT_LIBS)
udatapath_ofdatapath_CPPFLAGS = $(AM_CPPFLAGS)

EXTRA_DIST += udatapath/ofdatapath.8.in
DISTCLEANFILES += udatapath/ofdatapath.8

if BUILD_HW_LIBS

# Options for each platform
if NF2
udatapath_ofdatapath_LDADD += hw-lib/libnf2.a
udatapath_ofdatapath_CPPFLAGS += -DOF_HW_PLAT -DUSE_NETDEV -g
noinst_LIBRARIES += hw-lib/libnf2.a
endif

endif

if BUILD_HW_LIBS
#
# Build udatapath as a library
#

noinst_LIBRARIES += udatapath/libudatapath.a

udatapath_libudatapath_a_SOURCES = \
	udatapath/chain.c \
	udatapath/chain.h \
	udatapath/crc32.c \
	udatapath/crc32.h \
	udatapath/datapath.c \
	udatapath/datapath.h \
	udatapath/dp_act.c \
	udatapath/dp_act.h \
	udatapath/of_ext_msg.c \
	udatapath/of_ext_msg.h \
	udatapath/udatapath.c \
	udatapath/private-msg.c \
	udatapath/private-msg.h \
	udatapath/switch-flow.c \
	udatapath/switch-flow.h \
	udatapath/table.h \
	udatapath/table-hash.c \
	udatapath/table-linear.c

udatapath_libudatapath_a_CPPFLAGS = $(AM_CPPFLAGS)
udatapath_libudatapath_a_CPPFLAGS += -DOF_HW_PLAT -DUDATAPATH_AS_LIB -g

endif
