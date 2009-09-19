#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>

#include "datapath.h"
#include "dp_dev.h"
#include "forward.h"


static struct dp_dev *dp_dev_priv(struct net_device *netdev) 
{
	return netdev_priv(netdev);
}

struct datapath *dp_dev_get_dp(struct net_device *netdev)
{
	return dp_dev_priv(netdev)->dp;
}
EXPORT_SYMBOL(dp_dev_get_dp);

static struct net_device_stats *dp_dev_get_stats(struct net_device *netdev)
{
	struct dp_dev *dp_dev = dp_dev_priv(netdev);
	return &dp_dev->stats;
}

int dp_dev_recv(struct net_device *netdev, struct sk_buff *skb) 
{
	int len = skb->len;
	struct dp_dev *dp_dev = dp_dev_priv(netdev);
	skb->dev = netdev;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, netdev);
	if (in_interrupt())
		netif_rx(skb);
	else
		netif_rx_ni(skb);
	netdev->last_rx = jiffies;
	dp_dev->stats.rx_packets++;
	dp_dev->stats.rx_bytes += len;
	return len;
}

static int dp_dev_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (netif_running(dev))
		return -EBUSY;
	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	return 0;
}

static int dp_dev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct dp_dev *dp_dev = dp_dev_priv(netdev);
	struct datapath *dp = dp_dev->dp;

	/* By orphaning 'skb' we will screw up socket accounting slightly, but
	 * the effect is limited to the device queue length.  If we don't
	 * do this, then the sk_buff will be destructed eventually, but it is
	 * harder to predict when. */
	skb_orphan(skb);

	/* We are going to modify 'skb', by sticking it on &dp_dev->xmit_queue,
	 * so we need to have our own clone.  (At any rate, fwd_port_input()
	 * will need its own clone, so there's no benefit to queuing any other
	 * way.) */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return 0;

	dp_dev->stats.tx_packets++;
	dp_dev->stats.tx_bytes += skb->len;

	if (skb_queue_len(&dp_dev->xmit_queue) >= dp->netdev->tx_queue_len) {
		/* Queue overflow.  Stop transmitter. */
		netif_stop_queue(dp->netdev);

		/* We won't see all dropped packets individually, so overrun
		 * error is appropriate. */
		dp_dev->stats.tx_fifo_errors++;
	}
	skb_queue_tail(&dp_dev->xmit_queue, skb);
	dp->netdev->trans_start = jiffies;

	schedule_work(&dp_dev->xmit_work);

	return 0;
}

static void dp_dev_do_xmit(struct work_struct *work)
{
	struct dp_dev *dp_dev = container_of(work, struct dp_dev, xmit_work);
	struct datapath *dp = dp_dev->dp;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&dp_dev->xmit_queue)) != NULL) {
		skb_reset_mac_header(skb);
		rcu_read_lock();
		fwd_port_input(dp->chain, skb, dp->local_port);
		rcu_read_unlock();
	}
	netif_wake_queue(dp->netdev);
}

static int dp_dev_open(struct net_device *netdev)
{
	netif_start_queue(netdev);
	return 0;
}

static int dp_dev_stop(struct net_device *netdev)
{
	netif_stop_queue(netdev);
	return 0;
}

static void dp_getinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strcpy(info->driver, "openflow");
	sprintf(info->version, "0x%d", OFP_VERSION);
	strcpy(info->fw_version, "N/A");
	strcpy(info->bus_info, "N/A");
}

static struct ethtool_ops dp_ethtool_ops = {
	.get_drvinfo = dp_getinfo,
	.get_link = ethtool_op_get_link,
	.get_sg = ethtool_op_get_sg,
	.get_tx_csum = ethtool_op_get_tx_csum,
	.get_tso = ethtool_op_get_tso,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
static const struct net_device_ops dp_netdev_ops = {
	.ndo_init = NULL,
	.ndo_uninit = NULL,
	.ndo_open = dp_dev_open,
	.ndo_stop = dp_dev_stop,
	.ndo_start_xmit = dp_dev_xmit,
	.ndo_select_queue = NULL,
	.ndo_change_rx_flags = NULL,
	.ndo_set_rx_mode = NULL,
	.ndo_set_multicast_list = NULL,
	.ndo_set_mac_address = dp_dev_mac_addr,
	.ndo_validate_addr = NULL,
	.ndo_do_ioctl = NULL,
	.ndo_set_config = NULL,
	.ndo_change_mtu = NULL,
	.ndo_tx_timeout = NULL,
	.ndo_get_stats = dp_dev_get_stats,
	.ndo_vlan_rx_register = NULL,
	.ndo_vlan_rx_add_vid = NULL,
	.ndo_vlan_rx_kill_vid = NULL,
	.ndo_poll_controller = NULL
};
#endif

static void
do_setup(struct net_device *netdev)
{
	ether_setup(netdev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
	netdev->netdev_ops = &dp_netdev_ops;
#else
	netdev->do_ioctl = dp_ioctl_hook;
	netdev->get_stats = dp_dev_get_stats;
	netdev->hard_start_xmit = dp_dev_xmit;
	netdev->open = dp_dev_open;
	netdev->stop = dp_dev_stop;
	netdev->set_mac_address = dp_dev_mac_addr;
#endif
	SET_ETHTOOL_OPS(netdev, &dp_ethtool_ops);
	netdev->tx_queue_len = 100;

	netdev->flags = IFF_BROADCAST | IFF_MULTICAST;

	random_ether_addr(netdev->dev_addr);

	/* Set the OUI to the Nicira one. */
	netdev->dev_addr[0] = 0x00;
	netdev->dev_addr[1] = 0x23;
	netdev->dev_addr[2] = 0x20;

	/* Set the top bits to indicate random Nicira address. */
	netdev->dev_addr[3] |= 0xc0;
}

/* Create a datapath device associated with 'dp'.  If 'dp_name' is null,
 * the device name will be of the form 'of<dp_idx>'.
 *
 * Called with RTNL lock and dp_mutex.*/
int dp_dev_setup(struct datapath *dp, const char *dp_name)
{
	struct dp_dev *dp_dev;
	struct net_device *netdev;
	char dev_name[IFNAMSIZ];
	int err;

	if (dp_name) {
		if (strlen(dp_name) >= IFNAMSIZ)
			return -EINVAL;
		strncpy(dev_name, dp_name, sizeof(dev_name));
	} else
		snprintf(dev_name, sizeof dev_name, "of%d", dp->dp_idx);

	netdev = alloc_netdev(sizeof(struct dp_dev), dev_name, do_setup);
	if (!netdev)
		return -ENOMEM;

	err = register_netdevice(netdev);
	if (err) {
		free_netdev(netdev);
		return err;
	}

	dp_dev = dp_dev_priv(netdev);
	dp_dev->dp = dp;
	skb_queue_head_init(&dp_dev->xmit_queue);
	INIT_WORK(&dp_dev->xmit_work, dp_dev_do_xmit);
	dp->netdev = netdev;
	return 0;
}

/* Called with RTNL lock and dp_mutex.*/
void dp_dev_destroy(struct datapath *dp)
{
	struct dp_dev *dp_dev = dp_dev_priv(dp->netdev);

	netif_tx_disable(dp->netdev);
	synchronize_net();
	skb_queue_purge(&dp_dev->xmit_queue);
	unregister_netdevice(dp->netdev);
}

int is_dp_dev(struct net_device *netdev) 
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
	return netdev->netdev_ops->ndo_open == dp_dev_open;

#else
	return netdev->open == dp_dev_open;
#endif
}
