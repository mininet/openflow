ofdatapath_sources += \
	linux-2.6/compat-2.6/genetlink-openflow.c \
	linux-2.6/compat-2.6/random32.c
ofdatapath_headers += \
	linux-2.6/compat-2.6/compat26.h \
	linux-2.6/compat-2.6/include/asm-generic/bug.h \
	linux-2.6/compat-2.6/include/linux/dmi.h \
	linux-2.6/compat-2.6/include/linux/icmp.h \
	linux-2.6/compat-2.6/include/linux/if_arp.h \
	linux-2.6/compat-2.6/include/linux/ip.h \
	linux-2.6/compat-2.6/include/linux/ipv6.h \
	linux-2.6/compat-2.6/include/linux/jiffies.h \
	linux-2.6/compat-2.6/include/linux/lockdep.h \
	linux-2.6/compat-2.6/include/linux/mutex.h \
	linux-2.6/compat-2.6/include/linux/netfilter_ipv4.h \
	linux-2.6/compat-2.6/include/linux/netlink.h \
	linux-2.6/compat-2.6/include/linux/random.h \
	linux-2.6/compat-2.6/include/linux/rculist.h \
	linux-2.6/compat-2.6/include/linux/skbuff.h \
	linux-2.6/compat-2.6/include/linux/tcp.h \
	linux-2.6/compat-2.6/include/linux/timer.h \
	linux-2.6/compat-2.6/include/linux/types.h \
	linux-2.6/compat-2.6/include/linux/udp.h \
	linux-2.6/compat-2.6/include/linux/workqueue.h \
	linux-2.6/compat-2.6/include/net/checksum.h \
	linux-2.6/compat-2.6/include/net/genetlink.h \
	linux-2.6/compat-2.6/include/net/netlink.h

#dist_modules += veth
#build_modules += $(if $(BUILD_VETH),veth)
veth_sources = linux-2.6/compat-2.6/veth.c
veth_headers = 
