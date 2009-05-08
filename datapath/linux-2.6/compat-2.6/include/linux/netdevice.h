#ifndef __LINUX_NETDEVICE_WRAPPER_H
#define __LINUX_NETDEVICE_WRAPPER_H 1

#include_next <linux/netdevice.h>

#ifndef to_net_dev
#define to_net_dev(class) container_of(class, struct net_device, class_dev)
#endif

#endif
