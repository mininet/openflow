# Specify the module to build.
all_modules += hwtable_nf2

# Specify the source files that comprise the module.
hwtable_nf2_sources = \
	hwtable_nf2/nf2_flowtable.c \
	hwtable_nf2/nf2_openflow.c \
	hwtable_nf2/nf2_lib.c 

hwtable_nf2_headers = \
	hwtable_nf2/nf2.h \
	hwtable_nf2/nf2_reg.h \
	hwtable_nf2/nf2_hwapi.h \
	hwtable_nf2/nf2_flowtable.h \
	hwtable_nf2/nf2_openflow.h \
	hwtable_nf2/nf2_lib.h
