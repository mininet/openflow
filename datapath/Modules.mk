# Some modules should be built and distributed, e.g. openflow.
#
# Some modules should be distributed but not built, e.g. we do not build
# veth if the kernel in question already has it.
#
# Some modules should be built but not distributed, e.g. third-party
# hwtable modules.
both_modules = ofdatapath
build_modules = $(both_modules)	# Modules to build
dist_modules = $(both_modules)	# Modules to distribute

ofdatapath_sources = \
	chain.c \
	crc32.c \
	datapath.c \
	dp_act.c \
	dp_dev.c \
	dp_notify.c \
	flow.c \
	forward.c \
	private-msg.c \
	table-hash.c \
	table-linear.c

ofdatapath_headers = \
	chain.h \
	compat.h \
	crc32.h \
	datapath.h \
	dp_dev.h \
	flow.h \
	forward.h \
	dp_act.h \
	private-msg.h \
	table.h

dist_sources = $(foreach module,$(dist_modules),$($(module)_sources))
dist_headers = $(foreach module,$(dist_modules),$($(module)_headers))
build_sources = $(foreach module,$(build_modules),$($(module)_sources))
build_headers = $(foreach module,$(build_modules),$($(module)_headers))
build_links = $(notdir $(build_sources))
build_objects = $(notdir $(patsubst %.c,%.o,$(build_sources)))
