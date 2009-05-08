# Specify the module to build.
build_modules += ofdatapath_netfpga
dist_modules += ofdatapath_netfpga

# Specify the source files that comprise the module.
ofdatapath_netfpga_sources = \
	hwtable_nf2/nf2_flowtable.c \
	hwtable_nf2/nf2_procfs.c \
	hwtable_nf2/nf2_openflow.c \
	hwtable_nf2/nf2_lib.c

ofdatapath_netfpga_headers = \
	hwtable_nf2/nf2.h \
	hwtable_nf2/nf2_reg.h \
	hwtable_nf2/nf2_hwapi.h \
	hwtable_nf2/nf2_flowtable.h \
	hwtable_nf2/nf2_procfs.h \
	hwtable_nf2/nf2_openflow.h \
	hwtable_nf2/nf2_lib.h
