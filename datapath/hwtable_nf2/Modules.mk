# Specify the module to build.
all_modules += hwtable_nf2

# Specify the source files that comprise the module.
hwtable_nf2_sources = \
	hwtable_nf2/hwtable_nf2.c \
	hwtable_nf2/nf2_of_lib.c \
	hwtable_nf2/nf2_openflow.c 

hwtable_nf2_headers = \
	hwtable_nf2/nf2_export.h \
	hwtable_nf2/nf2_openflow.h \
	hwtable_nf2/nf2.h \
	hwtable_nf2/reg_defines.h \
	hwtable_nf2/hwtable_nf2.h
