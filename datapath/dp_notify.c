/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008, 2009 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

/* Handle changes to managed devices */

#include <linux/netdevice.h>

#include "datapath.h"


static int dp_device_event(struct notifier_block *unused, unsigned long event, 
		void *ptr) 
{
	struct net_device *dev = ptr;
	struct net_bridge_port *p = dev->br_port;
	unsigned long int flags;


	/* Check if monitored port */
	if (!p)
		return NOTIFY_DONE;

	spin_lock_irqsave(&p->lock, flags);
	switch (event) {
		case NETDEV_UNREGISTER:
			spin_unlock_irqrestore(&p->lock, flags);
			mutex_lock(&dp_mutex);
			dp_del_switch_port(p);
			mutex_unlock(&dp_mutex);
			return NOTIFY_DONE;
			break;
	}
	spin_unlock_irqrestore(&p->lock, flags);

	return NOTIFY_DONE;
}

struct notifier_block dp_device_notifier = {
	.notifier_call = dp_device_event
};
