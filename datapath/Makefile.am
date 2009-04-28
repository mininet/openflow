SUBDIRS = 
if L26_ENABLED
SUBDIRS += linux-2.6
endif
if L24_ENABLED
SUBDIRS += linux-2.4
endif

EXTRA_DIST = $(dist_headers) $(dist_sources)
EXTRA_DIST += hwtable_dummy/Modules.mk hwtable_dummy/hwtable_dummy.c
EXTRA_DIST += hwtable_nf2/Modules.mk hwtable_nf2/nf2_flowtable.c hwtable_nf2/nf2.h hwtable_nf2/nf2_lib.c hwtable_nf2/nf2_openflow.c hwtable_nf2/nf2_reg.h hwtable_nf2/nf2_flowtable.h hwtable_nf2/nf2_hwapi.h hwtable_nf2/nf2_lib.h hwtable_nf2/nf2_openflow.h

# Suppress warnings about GNU extensions in Modules.mk files.
AUTOMAKE_OPTIONS = -Wno-portability

include Modules.mk
include linux-2.4/Modules.mk
include linux-2.6/Modules.mk
