#ifndef DP_DEV_H
#define DP_DEV_H 1

struct dp_dev {
	struct net_device_stats stats;
	struct datapath *dp;
	struct sk_buff_head xmit_queue;
	struct work_struct xmit_work;
};

int dp_dev_setup(struct datapath *, const char *);
void dp_dev_destroy(struct datapath *);
int dp_dev_recv(struct net_device *, struct sk_buff *);
int is_dp_dev(struct net_device *);
struct datapath *dp_dev_get_dp(struct net_device *);

#endif /* dp_dev.h */
