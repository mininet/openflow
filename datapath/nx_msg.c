/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2008 Nicira Networks
 */

#include "chain.h"
#include "datapath.h"
#include "openflow/nicira-ext.h"
#include "nx_msg.h"


int
nx_recv_msg(struct sw_chain *chain, const struct sender *sender,
		const void *msg)
{
	const struct nicira_header *nh = msg;

	switch (ntohl(nh->subtype)) {

	case NXT_FLOW_END_CONFIG: {
		return 0;
	}

	default:
		dp_send_error_msg(chain->dp, sender, OFPET_BAD_REQUEST,
				  OFPBRC_BAD_SUBTYPE, msg, ntohs(nh->header.length));
		return -EINVAL;
	}

	return -EINVAL;
}
