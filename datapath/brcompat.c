#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/completion.h>
#include <linux/etherdevice.h>
#include <linux/if_bridge.h>
#include <linux/netdevice.h>
#include <net/genetlink.h>

#include "compat.h"
#include "openflow/openflow-netlink.h"
#include "openflow/brcompat-netlink.h"
#include "brc_sysfs.h"
#include "datapath.h"
#include "dp_dev.h"

static struct genl_family brc_genl_family;
static struct genl_multicast_group brc_mc_group;

/* Completion for vswitchd to notify the ioctl that the operation
 * completed. */
static DECLARE_COMPLETION(dp_act_done);
 
/* Time to wait for vswitchd to respond to a datapath action (in
 * milliseconds) */
#define DP_ACT_TIMEOUT 5000 

/* Positive errno as a result of a datapath action.  Calls that make
 * use of this variable are serialized by the br_ioctl_mutex. */
static int dp_act_err;

int brc_send_dp_add_del(const char *dp_name, int add);
int brc_send_port_add_del(struct net_device *dev, struct net_device *port, 
		int add);


static int
get_dp_ifindices(int *indices, int num)
{
	int i, index = 0;

	rcu_read_lock();
	for (i=0; i < DP_MAX && index < num; i++) {
		struct datapath *dp = dp_get_by_idx(i);
		if (!dp)
			continue;
		indices[index++] = dp->netdev->ifindex;
	}
	rcu_read_unlock();

	return index;
}

static void
get_port_ifindices(struct datapath *dp, int *ifindices, int num)
{
	struct net_bridge_port *p;

	rcu_read_lock();
	list_for_each_entry_rcu (p, &dp->port_list, node) {
		if (p->port_no < num)
			ifindices[p->port_no] = p->dev->ifindex;
	}
	rcu_read_unlock();
}

/* Legacy deviceless bridge ioctl's.  Called with br_ioctl_mutex. */
static int
old_deviceless(void __user *uarg)
{
	unsigned long args[3];

	if (copy_from_user(args, uarg, sizeof(args)))
		return -EFAULT;

	switch (args[0]) {
	case BRCTL_GET_BRIDGES: { 
		int *indices;
		int ret = 0;

		if (args[2] >= 2048)
			return -ENOMEM;

		indices = kcalloc(args[2], sizeof(int), GFP_KERNEL);
		if (indices == NULL)
			return -ENOMEM;

		args[2] = get_dp_ifindices(indices, args[2]);

		ret = copy_to_user((void __user *)args[1], indices, 
				args[2]*sizeof(int)) ? -EFAULT : args[2];

		kfree(indices);
		return ret;
	}

	case BRCTL_DEL_BRIDGE: 
	case BRCTL_ADD_BRIDGE: { 
		char dp_name[IFNAMSIZ];

		if (copy_from_user(dp_name, (void __user *)args[1], IFNAMSIZ))
			return -EFAULT;

		dp_name[IFNAMSIZ-1] = 0;
		if (args[0] == BRCTL_ADD_BRIDGE) 
			return brc_send_dp_add_del(dp_name, 1);

		return brc_send_dp_add_del(dp_name, 0);
	}
	}

	return -EOPNOTSUPP;
}

/* Called with the br_ioctl_mutex. */
static int
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
brc_ioctl_deviceless_stub(unsigned int cmd, void __user *uarg)
#else
brc_ioctl_deviceless_stub(struct net *net, unsigned int cmd, void __user *uarg)
#endif
{
	switch (cmd) {
	case SIOCGIFBR:
	case SIOCSIFBR: 
		return old_deviceless(uarg);

	case SIOCBRADDBR:
	case SIOCBRDELBR: {
		char dp_name[IFNAMSIZ];

		if (copy_from_user(dp_name, uarg, IFNAMSIZ))
			return -EFAULT;

		dp_name[IFNAMSIZ-1] = 0;
		return brc_send_dp_add_del(dp_name, cmd == SIOCBRADDBR);
	}
	}

	return -EOPNOTSUPP;
}

/* Legacy ioctl's through SIOCDEVPRIVATE.  Called with rtnl_lock. */
static int
old_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct dp_dev *dp_dev = netdev_priv(dev);
	struct datapath *dp = dp_dev->dp;
	unsigned long args[4];

	if (copy_from_user(args, rq->ifr_data, sizeof(args)))
		return -EFAULT;

	switch (args[0]) {
	case BRCTL_ADD_IF:
	case BRCTL_DEL_IF: {
		struct net_device *port;
		int err;

		port = dev_get_by_index(&init_net, args[1]);
		if (!port) 
			return -EINVAL;

		err = brc_send_port_add_del(dev, port, args[0] == BRCTL_ADD_IF);
		dev_put(port);
		return err;
	}

	case BRCTL_GET_BRIDGE_INFO: {
		struct __bridge_info b;
		uint64_t id = 0;
		int i;

		memset(&b, 0, sizeof(struct __bridge_info));

		for (i=0; i<ETH_ALEN; i++) 
			id |= (uint64_t)dev->dev_addr[i] << (8*(ETH_ALEN-1 - i));
		b.bridge_id = cpu_to_be64(id);
		b.stp_enabled = 0;

		if (copy_to_user((void __user *)args[1], &b, sizeof(b)))
			return -EFAULT;

		return 0;
	}

	case BRCTL_GET_PORT_LIST: {
		int num, *indices;

		num = args[2];
		if (num < 0)
			return -EINVAL;
		if (num == 0)
			num = 256;
		if (num > OFPP_MAX)
			num = OFPP_MAX;

		indices = kcalloc(num, sizeof(int), GFP_KERNEL);
		if (indices == NULL)
			return -ENOMEM;

		get_port_ifindices(dp, indices, num);
		if (copy_to_user((void __user *)args[1], indices, num*sizeof(int)))
			num = -EFAULT;
		kfree(indices);
		return num;
	}
	}

	return -EOPNOTSUPP;
}

/* Called with the rtnl_lock. */
static int
brc_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	int err;

	switch (cmd) {
		case SIOCDEVPRIVATE:
			err = old_dev_ioctl(dev, rq, cmd);
			break;

		case SIOCBRADDIF:
		case SIOCBRDELIF: {
			struct net_device *port;

			port = dev_get_by_index(&init_net, rq->ifr_ifindex);
			if (!port) 
				return -EINVAL;

			err = brc_send_port_add_del(dev, port, cmd == SIOCBRADDIF);
			dev_put(port);
			break;
		}

		default:
			err = -EOPNOTSUPP;
			break;
	}

	return err;
}


static struct genl_family brc_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = BRC_GENL_FAMILY_NAME,
	.version = 1,
	.maxattr = BRC_GENL_A_MAX,
};

static int brc_genl_query(struct sk_buff *skb, struct genl_info *info)
{
	int err = -EINVAL;
	struct sk_buff *ans_skb;
	void *data;

	ans_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!ans_skb) 
		return -ENOMEM;

	data = genlmsg_put_reply(ans_skb, info, &brc_genl_family,
				 0, BRC_GENL_C_QUERY_MC);
	if (data == NULL) {
		err = -ENOMEM;
		goto err;
	}
	NLA_PUT_U32(ans_skb, BRC_GENL_A_MC_GROUP, brc_mc_group.id);

	genlmsg_end(ans_skb, data);
	return genlmsg_reply(ans_skb, info);

err:
nla_put_failure:
	kfree_skb(ans_skb);
	return err;
}

static struct genl_ops brc_genl_ops_query_dp = {
	.cmd = BRC_GENL_C_QUERY_MC,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privelege. */
	.policy = NULL,
	.doit = brc_genl_query,
	.dumpit = NULL
};

/* Attribute policy: what each attribute may contain.  */
static struct nla_policy brc_genl_policy[BRC_GENL_A_MAX + 1] = {
	[BRC_GENL_A_ERR_CODE] = { .type = NLA_U32 }
};

static int
brc_genl_dp_result(struct sk_buff *skb, struct genl_info *info)
{
	dp_act_err = nla_get_u32(info->attrs[BRC_GENL_A_ERR_CODE]);
	complete(&dp_act_done);

	return 0;
}

static struct genl_ops brc_genl_ops_dp_result = {
	.cmd = BRC_GENL_C_DP_RESULT,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privelege. */
	.policy = brc_genl_policy,
	.doit = brc_genl_dp_result,
	.dumpit = NULL
};

int brc_send_dp_add_del(const char *dp_name, int add)
{
	struct sk_buff *skb;
	void *data;
	int retval;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		return -ENOMEM;

	if (add)
		data = genlmsg_put(skb, 0, 0, &brc_genl_family, 0, 
				   BRC_GENL_C_DP_ADD);
	else
		data = genlmsg_put(skb, 0, 0, &brc_genl_family, 0, 
				   BRC_GENL_C_DP_DEL);
	if (!data)
		goto err;

	NLA_PUT_STRING(skb, BRC_GENL_A_DP_NAME, dp_name);

	init_completion(&dp_act_done);

	genlmsg_end(skb, data);
	retval = genlmsg_multicast(skb, 0, brc_mc_group.id, GFP_KERNEL);
	if (retval < 0) 
		return retval;

	if (!wait_for_completion_timeout(&dp_act_done, 
				msecs_to_jiffies(DP_ACT_TIMEOUT))) 
		return -EIO;

	/* The value is returned as a positive errno, so make it negative */
	if (dp_act_err) 
		return -dp_act_err;

	return 0;

nla_put_failure:
err:
	kfree_skb(skb);
	return -ENOMEM;
}

int brc_send_port_add_del(struct net_device *dev, struct net_device *port, 
		int add)
{
	struct dp_dev *dp_dev = netdev_priv(dev);
	struct datapath *dp = dp_dev->dp;
	struct sk_buff *skb;
	void *data;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		return -ENOMEM;

	if (add) {
		/* Only add the port if it's not attached to a datapath. */
		if (port->br_port != NULL) {
			kfree_skb(skb);
			return -EBUSY;
		}
		data = genlmsg_put(skb, 0, 0, &brc_genl_family, 0, 
				   BRC_GENL_C_PORT_ADD);
	} else {
		/* Only delete the port if it's attached to this datapath. */
		if (port->br_port == NULL || port->br_port->dp != dp) {
			kfree_skb(skb);
			return -ENOENT;
		}
		data = genlmsg_put(skb, 0, 0, &brc_genl_family, 0, 
				   BRC_GENL_C_PORT_DEL);
	}
	if (!data)
		goto err;

	NLA_PUT_STRING(skb, BRC_GENL_A_DP_NAME, dev->name);
	NLA_PUT_STRING(skb, BRC_GENL_A_PORT_NAME, port->name);

	genlmsg_end(skb, data);
	return genlmsg_multicast(skb, 0, brc_mc_group.id, GFP_KERNEL);

nla_put_failure:
err:
	kfree_skb(skb);
	return -EINVAL;
}

int brc_add_dp(struct datapath *dp)
{
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
#if CONFIG_SYSFS
	brc_sysfs_add_dp(dp);
#endif

	return 0;
}

int brc_del_dp(struct datapath *dp) 
{
#if CONFIG_SYSFS
	brc_sysfs_del_dp(dp);
#endif
	module_put(THIS_MODULE);

	return 0;
}

static int 
__init brc_init(void)
{
	int i;
	int err;

	printk("OpenFlow Bridge Compatibility, built "__DATE__" "__TIME__"\n");

	rcu_read_lock();
	for (i=0; i<DP_MAX; i++) {
		if (dp_get_by_idx(i)) {
			rcu_read_unlock();
			printk(KERN_EMERG "brcompat: no datapaths may exist!\n");
			return -EEXIST;
		}
	}
	rcu_read_unlock();

	/* Set the bridge ioctl handler */
	brioctl_set(brc_ioctl_deviceless_stub);

	/* Set the OpenFlow device ioctl handler */
	dp_ioctl_hook = brc_dev_ioctl;

	/* Register hooks for datapath adds and deletes */
	dp_add_dp_hook = brc_add_dp;
	dp_del_dp_hook = brc_del_dp;

	/* Register hooks for interface adds and deletes */
#if CONFIG_SYSFS
	dp_add_if_hook = brc_sysfs_add_if;
	dp_del_if_hook = brc_sysfs_del_if;
#endif

	/* Register generic netlink family to communicate changes to
	 * userspace. */
	err = genl_register_family(&brc_genl_family);
	if (err)
		goto error;

	err = genl_register_ops(&brc_genl_family, &brc_genl_ops_query_dp);
	if (err != 0) 
		goto err_unregister;

	err = genl_register_ops(&brc_genl_family, &brc_genl_ops_dp_result);
	if (err != 0) 
		goto err_unregister;

	strcpy(brc_mc_group.name, "brcompat");
	err = genl_register_mc_group(&brc_genl_family, &brc_mc_group);
	if (err < 0)
		goto err_unregister;

	return 0;

err_unregister:
	genl_unregister_family(&brc_genl_family);
error:
	printk(KERN_EMERG "brcompat: failed to install!");
	return err;
}

static void 
brc_cleanup(void)
{
	/* Unregister hooks for datapath adds and deletes */
	dp_add_dp_hook = NULL;
	dp_del_dp_hook = NULL;
	
	/* Unregister hooks for interface adds and deletes */
	dp_add_if_hook = NULL;
	dp_del_if_hook = NULL;

	/* Unregister ioctl hooks */
	dp_ioctl_hook = NULL;
	brioctl_set(NULL);

	genl_unregister_family(&brc_genl_family);
}

module_init(brc_init);
module_exit(brc_cleanup);

MODULE_DESCRIPTION("OpenFlow bridge compatibility");
MODULE_AUTHOR("Copyright (c) 2009 The Board of Trustees of The Leland Stanford Junior University");
MODULE_LICENSE("GPL");
