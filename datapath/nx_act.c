/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2008 Nicira Networks
 */

/* Functions for Nicira-extended actions. */
#include "openflow/nicira-ext.h"
#include "dp_act.h"
#include "nx_act.h"

uint16_t
nx_validate_act(struct datapath *dp, const struct sw_flow_key *key,
		const struct nx_action_header *nah, uint16_t len)
{
	if (len < sizeof *nah) 
		return OFPBAC_BAD_LEN;

	return OFPBAC_BAD_VENDOR_TYPE;
}

struct sk_buff *
nx_execute_act(struct sk_buff *skb, const struct sw_flow_key *key,
		const struct nx_action_header *nah)
{
	return skb;
}

