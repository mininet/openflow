# Specify the module to build.
all_modules += hwtable-nf2

# Specify the source files that comprise the module.
hwtable-nf2_sources = \
	hwtable-nf2/hwtable-nf2.c hwtable-nf2/nf2_of_lib.c \
<<<<<<< HEAD:datapath/hwtable-nf2/Modules.mk
	hwtable-nf2/nf2_openflow.c 

hwtable-nf2_headers = \
=======
	hwtable-nf2/nf2_openflow.c \
>>>>>>> 2fab6137faf699b4a54177d0262b2a8d7b4bd189:datapath/hwtable-nf2/Modules.mk
	hwtable-nf2/nf2_export.h hwtable-nf2/nf2_openflow.h \
	hwtable-nf2/nf2.h hwtable-nf2/reg_defines.h \
	hwtable-nf2/hwtable-nf2.h
