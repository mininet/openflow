#ifndef BRC_SYSFS_H
#define BRC_SYSFS_H 1

struct datapath;

#include <linux/version.h>
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,18)
/* brc_sysfs_dp.c */
int brc_sysfs_add_dp(struct datapath *dp);
int brc_sysfs_del_dp(struct datapath *dp);

/* brc_sysfs_if.c */
int brc_sysfs_add_if(struct net_bridge_port *p);
int brc_sysfs_del_if(struct net_bridge_port *p);
#else
static inline int brc_sysfs_add_dp(struct datapath *dp) { return 0; }
static inline int brc_sysfs_del_dp(struct datapath *dp) { return 0; }
static inline int brc_sysfs_add_if(struct net_bridge_port *p) { return 0; }
static inline int brc_sysfs_del_if(struct net_bridge_port *p) { return 0; }
#endif

#endif /* brc_sysfs.h */

