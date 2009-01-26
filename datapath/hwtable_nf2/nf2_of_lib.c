#include <linux/etherdevice.h>
#include "compat.h"
#include "hwtable_nf2/hwtable_nf2.h"
#include "crc32.h"
#include "hwtable_nf2/nf2_logging.h"

/* For NetFPGA */
#include "hwtable_nf2/nf2.h"
#include "hwtable_nf2/reg_defines.h"
#include "hwtable_nf2/nf2_export.h"

#define MAX_INT_32 0xFFFFFFFF

struct list_head wildcard_free_list;

struct sw_flow_nf2* exact_free_list[OPENFLOW_NF2_EXACT_TABLE_SIZE];

struct net_device* nf2_get_net_device(void)
{
	return dev_get_by_name(&init_net, "nf2c0");
}

void nf2_free_net_device(struct net_device* dev)
{
	dev_put(dev);
}

/*
 * Checks to see if the actions requested by the flow are capable of being
 * done in the NF2 hardware. Returns 1 if yes, 0 for no.
 */
int nf2_are_actions_supported(struct sw_flow *flow)
{
        struct sw_flow_actions *sfa;
        size_t actions_len;
        uint8_t *p;

        sfa = flow->sf_acts;
        actions_len = sfa->actions_len;
        p = (uint8_t *)sfa->actions;

        while (actions_len > 0) {
                struct ofp_action_header *ah = (struct ofp_action_header *)p;
                struct ofp_action_output *oa = (struct ofp_action_output *)p;
                size_t len = ntohs(ah->len);
                LOG("Action Support Chk: Len of this action: %i\n", len);
                LOG("Action Support Chk: Len of actions    : %i\n", actions_len);

                // Currently only support the output port(s) action
                if (ah->type != htons(OFPAT_OUTPUT)) {
                        LOG("Flow action type %#0x not supported in hardware\n",
                               ntohs(ah->type));
                        return 0;
                }

                // Only support ports 0-3(incl. IN_PORT), ALL, FLOOD.
                // Let CONTROLLER/LOCAL fall through
                if (!(ntohs(oa->port) < 4) &&
		    !(ntohs(oa->port) == OFPP_ALL) &&
		    !(ntohs(oa->port) == OFPP_FLOOD) &&
		    !(ntohs(oa->port) == OFPP_IN_PORT)) {

                        LOG("Flow action output port %#0x is not supported in hardware\n",
			    ntohs(oa->port));
                        return 0;
                }
                p += len;
                actions_len -= len;
        }
        return 1;
}

/*
 * Write all 0's out to an exact entry position
 */
void nf2_clear_of_exact(uint32_t pos)
{
	nf2_of_entry_wrap entry;
	nf2_of_action_wrap action;
	struct net_device* dev = NULL;

	memset(&entry, 0, sizeof(nf2_of_entry_wrap));
	memset(&action, 0, sizeof(nf2_of_action_wrap));

	if ((dev = nf2_get_net_device())) {
		nf2_write_of_exact(dev, pos, &entry, &action);
		nf2_free_net_device(dev);
	}
}

/*
 * Write all 0's out to a wildcard entry position
 */
void nf2_clear_of_wildcard(uint32_t pos)
{
	nf2_of_entry_wrap entry;
	nf2_of_mask_wrap mask;
	nf2_of_action_wrap action;
	struct net_device* dev = NULL;

	memset(&entry, 0, sizeof(nf2_of_entry_wrap));
	memset(&mask, 0, sizeof(nf2_of_mask_wrap));
	memset(&action, 0, sizeof(nf2_of_action_wrap));

	if ((dev = nf2_get_net_device())) {
		nf2_write_of_wildcard(dev, pos, &entry, &mask, &action);
		nf2_free_net_device(dev);
	}
}

int init_exact_free_list(void)
{
	struct sw_flow_nf2* sfw = NULL;
	int i;

	for (i = 0; i < (OPENFLOW_NF2_EXACT_TABLE_SIZE); ++i) {
		sfw = kzalloc(sizeof(struct sw_flow_nf2), GFP_ATOMIC);
		if (sfw == NULL) {
			return 1;
		}
		sfw->pos = i;
		sfw->type = NF2_TABLE_EXACT;
		add_free_exact(sfw);
		sfw = NULL;
	}

	return 0;
}

int init_wildcard_free_list(void)
{
	struct sw_flow_nf2* sfw = NULL;
	int i;
	INIT_LIST_HEAD(&wildcard_free_list);

	for (i = 0; i < (OPENFLOW_WILDCARD_TABLE_SIZE-8); ++i) {
		sfw = kzalloc(sizeof(struct sw_flow_nf2), GFP_ATOMIC);
		if (sfw == NULL) {
			return 1;
		}
		sfw->pos = i;
		sfw->type = NF2_TABLE_WILDCARD;
		add_free_wildcard(sfw);
		sfw = NULL;
	}

	return 0;
}

/*
 * Called when the table is being deleted
 */
void destroy_exact_free_list(void)
{
	struct sw_flow_nf2* sfw = NULL;
	int i;

	for (i = 0; i < (OPENFLOW_NF2_EXACT_TABLE_SIZE); ++i) {
		sfw = exact_free_list[i];
		if (sfw) {
			kfree(sfw);
		}
		sfw = NULL;
	}
}

/*
 * Called when the table is being deleted
 */
void destroy_wildcard_free_list(void)
{
	struct sw_flow_nf2* sfw = NULL;
	struct list_head *next = NULL;

	while (!list_empty(&wildcard_free_list)) {
		next = wildcard_free_list.next;
		sfw = list_entry(next, struct sw_flow_nf2, node);
		list_del(&sfw->node);
		kfree(sfw);
	}
}

/*
 * Setup the wildcard table by adding static flows that will handle
 * misses by sending them up to the cpu ports, and handle packets coming
 * back down from the cpu by sending them out the corresponding port.
 */
int nf2_write_static_wildcard(void)
{
	nf2_of_entry_wrap entry;
	nf2_of_mask_wrap mask;
	nf2_of_action_wrap action;
	int i;
	struct net_device *dev;

	if ((dev = nf2_get_net_device())) {
		memset(&entry, 0x00, sizeof(nf2_of_entry_wrap));
		memset(&mask, 0xFF, sizeof(nf2_of_mask_wrap));
		// Only non-wildcard section is the source port
		mask.entry.src_port = 0;
		memset(&action, 0, sizeof(nf2_of_action_wrap));

		// write the catch all entries to send to the cpu
		for (i = 0; i < 4; ++i) {
			entry.entry.src_port = i * 2;
			action.action.forward_bitmask = 0x1 << ((i * 2) + 1);
			nf2_write_of_wildcard(dev, (OPENFLOW_WILDCARD_TABLE_SIZE-4) +i,
					      &entry, &mask, &action);
		}

		// write the entries to send out packets coming from the cpu
		for (i = 0; i < 4; ++i) {
			entry.entry.src_port = (i * 2) + 1;
			action.action.forward_bitmask = 0x1 << (i * 2);
			nf2_write_of_wildcard(dev, (OPENFLOW_WILDCARD_TABLE_SIZE-8)+i,
					      &entry, &mask, &action);
		}

		nf2_free_net_device(dev);

		return 0;
	} else {
		return 1;
	}
}

/*
 * Populate a nf2_of_entry_wrap with entries from a struct sw_flow
 */
void nf2_populate_of_entry(nf2_of_entry_wrap *key, struct sw_flow *flow)
{
	int i;

	key->entry.transp_dst = ntohs(flow->key.tp_dst);
	key->entry.transp_src = ntohs(flow->key.tp_src);
	key->entry.ip_proto = flow->key.nw_proto;
	key->entry.ip_dst = ntohl(flow->key.nw_dst);
	key->entry.ip_src = ntohl(flow->key.nw_src);
	key->entry.eth_type = ntohs(flow->key.dl_type);
	// Blame Jad for applying endian'ness to character arrays
	for (i = 0; i < 6; ++i) {
		key->entry.eth_dst[i] = flow->key.dl_dst[5 - i];
	}
	for (i = 0; i < 6; ++i) {
		key->entry.eth_src[i] = flow->key.dl_src[5 - i];
	}

	key->entry.src_port = ntohs(flow->key.in_port)*2;
	key->entry.vlan_id = ntohs(flow->key.dl_vlan);
}

static uint32_t make_nw_wildcard(int n_wild_bits)
{
	n_wild_bits &= (1u << OFPFW_NW_SRC_BITS) - 1;
	return n_wild_bits < 32 ? ((1u << n_wild_bits) - 1) : 0xFFFFFFFF;
}

/*
 * Populate a nf2_of_mask_wrap with entries from a struct sw_flow's wildcards
 */
void nf2_populate_of_mask(nf2_of_mask_wrap *mask, struct sw_flow *flow)
{
	int i;

	if (OFPFW_IN_PORT & flow->key.wildcards) {
		mask->entry.src_port = 0xFF;
	}
	if (OFPFW_DL_VLAN & flow->key.wildcards) {
		mask->entry.vlan_id = 0xFFFF;
	}
	if (OFPFW_DL_SRC & flow->key.wildcards) {
		for (i = 0; i < 6; ++i) {
			mask->entry.eth_src[i] = 0xFF;
		}
	}
	if (OFPFW_DL_DST & flow->key.wildcards) {
		for (i = 0; i < 6; ++i) {
			mask->entry.eth_dst[i] = 0xFF;
		}
	}
	if (OFPFW_DL_TYPE & flow->key.wildcards)
		mask->entry.eth_type = 0xFFFF;
	if ((OFPFW_NW_SRC_ALL & flow->key.wildcards) ||
	    (OFPFW_NW_SRC_MASK & flow->key.wildcards))
		mask->entry.ip_src = make_nw_wildcard(flow->key.wildcards >> OFPFW_NW_SRC_SHIFT);
	if ((OFPFW_NW_DST_ALL & flow->key.wildcards) ||
	    (OFPFW_NW_DST_MASK & flow->key.wildcards))
		mask->entry.ip_dst = make_nw_wildcard(flow->key.wildcards >> OFPFW_NW_DST_SHIFT);
	if (OFPFW_NW_PROTO & flow->key.wildcards)
		mask->entry.ip_proto = 0xFF;
	if (OFPFW_TP_SRC & flow->key.wildcards)
		mask->entry.transp_src = 0xFFFF;
	if (OFPFW_TP_DST & flow->key.wildcards)
		mask->entry.transp_dst = 0xFFFF;

	mask->entry.pad = 0x0000;
}

/*
 * Populate an nf2_of_action_wrap
 */
void nf2_populate_of_action(nf2_of_action_wrap *action,
			    nf2_of_entry_wrap *entry, nf2_of_mask_wrap *mask,
			    struct sw_flow *flow)
{
        unsigned short port = 0;
        int j;
        struct sw_flow_actions *sfa;
        size_t actions_len;
        uint8_t *p;

        sfa = flow->sf_acts;
        actions_len = sfa->actions_len;
        p = (uint8_t *)sfa->actions;

        // zero it out for now
        memset(action, 0, sizeof(nf2_of_action_wrap));

        while (actions_len > 0) {
                struct ofp_action_header *ah = (struct ofp_action_header *)p;
                size_t len = ntohs(ah->len);
                LOG("Action Populate: Len of this action: %i\n", len);
                LOG("Action Populate: Len of actions    : %i\n", actions_len);

                if (ah->type == htons(OFPAT_OUTPUT)) {
                        struct ofp_action_output *oa = (struct ofp_action_output *)p;
                        port = ntohs(oa->port);
                        LOG("Action Type: %i Output Port: %i\n",
			    ntohs(ah->type), port);

                        if (port < 4)  {
                                // bitmask for output port(s), evens are phys odds cpu
                                action->action.forward_bitmask |= (1 << (port * 2));
                                LOG("Output Port: %i Forward Bitmask: %x\n",
				    port, action->action.forward_bitmask);
                        } else if (port == OFPP_IN_PORT) {
                                // send out to input port
                                action->action.forward_bitmask |= (1 << (entry->entry.src_port));
                                LOG("Output Port = Input Port  Forward Bitmask: %x\n",
				    action->action.forward_bitmask);
                        } else if ((port == OFPP_ALL) || (port == OFPP_FLOOD)) {
                                // Send out all ports except the source
                                for (j = 0; j < 4; ++j) {
                                        if ((j*2) != entry->entry.src_port) {
                                                // bitmask for output port(s), evens are phys odds cpu
                                                action->action.forward_bitmask |= (1 << (j * 2));
                                                LOG("Output Port: %i Forward Bitmask: %x\n",
						    port, action->action.forward_bitmask);
                                        }
                                }
                        }
                }
                p += len;
                actions_len -= len;
        }
}

/*
 * Add a free hardware entry back to the exact pool
 */
void add_free_exact(struct sw_flow_nf2* sfw)
{
	// clear the node entry
	INIT_LIST_HEAD(&sfw->node);

	// Critical section, adding to the actual list
	exact_free_list[sfw->pos] = sfw;
}

/*
 * Add a free hardware entry back to the wildcard pool
 */
void add_free_wildcard(struct sw_flow_nf2* sfw)
{
	// clear the hw values
	sfw->hw_packet_count = 0;
	sfw->hw_byte_count = 0;

	// Critical section, adding to the actual list
	list_add_tail(&sfw->node, &wildcard_free_list);
}

/*
 * Hashes the entry to find where it should exist in the exact table
 * returns NULL on failure
 */
struct sw_flow_nf2* get_free_exact(nf2_of_entry_wrap *entry)
{
	unsigned int poly1 = 0x04C11DB7;
	unsigned int poly2 = 0x1EDC6F41;
	struct sw_flow_nf2 *sfw = NULL;
	unsigned int hash = 0x0;
	unsigned int index = 0x0;

	struct crc32 crc;
	crc32_init(&crc, poly1);
	hash = crc32_calculate(&crc, entry, sizeof(nf2_of_entry_wrap));

	// the bottom 15 bits of hash == the index into the table
	index = 0x7FFF & hash;

	// if this index is free, grab it
	sfw = exact_free_list[index];
	exact_free_list[index] = NULL;

	if (sfw != NULL) {
		return sfw;
	}

	// try the second index
	crc32_init(&crc, poly2);
	hash = crc32_calculate(&crc, entry, sizeof(nf2_of_entry_wrap));
	// the bottom 15 bits of hash == the index into the table
	index = 0x7FFF & hash;

	// if this index is free, grab it
	sfw = exact_free_list[index];
	exact_free_list[index] = NULL;

	// return whether its good or not
	return sfw;
}

/*
 * Get the first free position in the wildcard hardware table
 * to write into
 */
struct sw_flow_nf2* get_free_wildcard(void)
{
	struct sw_flow_nf2 *sfw = NULL;
	struct list_head *next = NULL;

	// Critical section, pulling the first available from the list
	if (list_empty(&wildcard_free_list)) {
		// empty :(
		sfw = NULL;
	} else {
		next = wildcard_free_list.next;
		sfw = list_entry(next, struct sw_flow_nf2, node);
		list_del_init(&sfw->node);
	}

	return sfw;
}

/*
 * Retrieves the type of table this flow should go into
 */
int nf2_get_table_type(struct sw_flow *flow)
{
	if (flow->key.wildcards != 0) {
		LOG("--- TABLE TYPE: WILDCARD ---\n");
		return NF2_TABLE_WILDCARD;
	} else {
		LOG("--- TABLE TYPE: EXACT ---\n");
		return NF2_TABLE_EXACT;
	}
}

/*
 * Returns 1 if this flow contains an action outputting to all ports except
 * input port, 0 otherwise. We support OFPP_ALL and OFPP_FLOOD actions, however
 * since we do not perform the spanning tree protocol (STP) then OFPP_FLOOD is
 * equivalent to OFPP_ALL.
 */
int is_action_forward_all(struct sw_flow *flow)
{
        struct sw_flow_actions *sfa;
        size_t actions_len;
        uint8_t *p;

        sfa = flow->sf_acts;
        actions_len = sfa->actions_len;
        p = (uint8_t *)sfa->actions;

        while (actions_len > 0) {
                struct ofp_action_header *ah = (struct ofp_action_header *)p;
                struct ofp_action_output *oa = (struct ofp_action_output *)p;
                size_t len = ntohs(ah->len);
                LOG("Fwd Action Chk: Action type: %x\n", ntohs(ah->type));
                LOG("Fwd Action Chk: Output port: %x\n", ntohs(oa->port));
                LOG("Fwd Action Chk: Len of this action: %i\n", len);
                LOG("Fwd Action Chk: Len of actions    : %i\n", actions_len);
                // Currently only support the output port(s) action
                if ((ntohs(ah->type) == OFPAT_OUTPUT) &&
		    ((ntohs(oa->port) == OFPP_ALL) ||
                         (ntohs(oa->port) == OFPP_FLOOD))) {
                        return 1;
                }
                p += len;
                actions_len -= len;
        }

        return 0;
}

/*
 * Attempts to build and write the flow to hardware.
 * Returns 0 on success, 1 on failure.
 */
int nf2_build_and_write_flow(struct sw_flow *flow)
{
	struct sw_flow_nf2 *sfw = NULL;
	struct sw_flow_nf2 *sfw_next = NULL;

	struct net_device *dev;
	int num_entries = 0;
	int i, table_type;
	nf2_of_entry_wrap key;
	nf2_of_mask_wrap mask;
	nf2_of_action_wrap action;

	memset(&key, 0, sizeof(nf2_of_entry_wrap));
	memset(&mask, 0, sizeof(nf2_of_mask_wrap));
	memset(&action, 0, sizeof(nf2_of_action_wrap));

	if (!(dev = nf2_get_net_device())) {
		// failure getting net device
		LOG("Failure getting net device struct\n");
		return 1;
	}

	table_type = nf2_get_table_type(flow);
	switch (table_type) {
	default:
		break;

	case NF2_TABLE_EXACT:
		LOG("---Exact Entry---\n");
		nf2_populate_of_entry(&key, flow);
		nf2_populate_of_action(&action, &key, NULL, flow);
		sfw = get_free_exact(&key);
		if (sfw == NULL) {
			LOG("Collision getting free exact match entry\n");
			// collision
			return 1;
		}

		// set the active bit on this entry
		key.entry.pad = 0x8000;
		nf2_write_of_exact(dev, sfw->pos, &key, &action);
		flow->private = (void*)sfw;
		break;

	case NF2_TABLE_WILDCARD:
		LOG("---Wildcard Entry---\n");
		// if action is all out and source port is wildcarded
		if ((is_action_forward_all(flow)) &&
		    (flow->key.wildcards & OFPFW_IN_PORT)) {
			LOG("Grab four wildcard tables\n");
			if (!(sfw = get_free_wildcard())) {
				LOG("No free wildcard entries found.");
				// no free entries
				return 1;
			}
			// try to get 3 more positions
			for (i = 0; i < 3; ++i) {
				if(!(sfw_next = get_free_wildcard())) {
					break;
				}
				list_add_tail(&sfw_next->node, &sfw->node);
				++num_entries;
			}

			if (num_entries < 3) {
				// failed to get enough entries, return them and exit
				nf2_delete_private((void*)sfw);
				return 1;
			}

			nf2_populate_of_entry(&key, flow);
			nf2_populate_of_mask(&mask, flow);

			// set first entry's src port to 0, remove wildcard mask on src
			key.entry.src_port = 0;
			mask.entry.src_port = 0;
			nf2_populate_of_action(&action, &key, &mask, flow);
			nf2_write_of_wildcard(dev, sfw->pos, &key, &mask, &action);

			i = 1;
			sfw_next = list_entry(sfw->node.next, struct sw_flow_nf2, node);
			// walk through and write the remaining 3 entries
			while (sfw_next != sfw) {
				key.entry.src_port = i*2;
				nf2_populate_of_action(&action, &key, &mask, flow);
				nf2_write_of_wildcard(dev, sfw_next->pos, &key, &mask, &action);
				sfw_next = list_entry(sfw_next->node.next,
						      struct sw_flow_nf2, node);
				++i;
			}
			flow->private = (void*)sfw;
		} else {
			/* Get a free position here, and write to it */
			if ((sfw = get_free_wildcard())) {
				nf2_populate_of_entry(&key, flow);
				nf2_populate_of_mask(&mask, flow);
				nf2_populate_of_action(&action, &key, &mask, flow);
				if (nf2_write_of_wildcard(dev, sfw->pos, &key, &mask, &action)) {
					// failure writing to hardware
					add_free_wildcard(sfw);
					LOG("Failure writing to hardware\n");
					return 1;
				} else {
					// success writing to hardware, store the position
					flow->private = (void*)sfw;
				}
			} else {
				// hardware is full, return 0
				LOG("No free wildcard entries found.");
				return 1;
			}
		}
		break;
	}

	nf2_free_net_device(dev);
	return 0;
}

void nf2_delete_private(void* private)
{
	struct sw_flow_nf2 *sfw = (struct sw_flow_nf2*)private;
	struct sw_flow_nf2 *sfw_next;
	struct list_head *next;

	switch (sfw->type) {
	default:
		break;

	case NF2_TABLE_EXACT:
		nf2_clear_of_exact(sfw->pos);
		add_free_exact(sfw);
		break;

	case NF2_TABLE_WILDCARD:
		while (!list_empty(&sfw->node)) {
			next = sfw->node.next;
			sfw_next = list_entry(next, struct sw_flow_nf2, node);
			list_del_init(&sfw_next->node);
			// Immediately zero out the entry in hardware
			nf2_clear_of_wildcard(sfw_next->pos);
			// add it back to the pool
			add_free_wildcard(sfw_next);
		}

		// zero the core entry
		nf2_clear_of_wildcard(sfw->pos);

		// add back the core entry
		add_free_wildcard(sfw);
		break;
	}
}

int nf2_modify_acts(struct sw_table *swt, struct sw_flow *flow)
{
        struct sw_flow_nf2 *sfw = (struct sw_flow_nf2*)flow->private;
        struct net_device *dev;
        nf2_of_entry_wrap key;
        nf2_of_mask_wrap mask;
        nf2_of_action_wrap action;

        memset(&key, 0, sizeof(nf2_of_entry_wrap));
        memset(&mask, 0, sizeof(nf2_of_mask_wrap));
        memset(&action, 0, sizeof(nf2_of_action_wrap));

        dev = nf2_get_net_device();

        switch (sfw->type) {
	default:
		break;

	case NF2_TABLE_EXACT:
		nf2_populate_of_entry(&key, flow);
		nf2_populate_of_action(&action, &key, NULL, flow);
		key.entry.pad= 0x8000;
		nf2_modify_write_of_exact(dev, sfw->pos, &action);
		break;

	case NF2_TABLE_WILDCARD:
		if (flow->key.wildcards & OFPFW_IN_PORT) {
			return 0;
		} else {
			nf2_populate_of_entry(&key, flow);
			nf2_populate_of_mask(&mask, flow);
			nf2_populate_of_action(&action, &key, &mask, flow);
			nf2_modify_write_of_wildcard(dev, sfw->pos,
						     &key, &mask, &action);
		}
		break;
        }

        nf2_free_net_device(dev);
        return 1;
}

uint64_t nf2_get_packet_count(struct net_device *dev, struct sw_flow_nf2 *sfw)
{
	uint32_t count = 0;
	uint32_t hw_count = 0;
	uint64_t total = 0;
	struct sw_flow_nf2 *sfw_next = NULL;

	switch (sfw->type) {
	default:
		break;

	case NF2_TABLE_EXACT:
		count = nf2_get_exact_packet_count(dev, sfw->pos);
		total = count;
		break;

	case NF2_TABLE_WILDCARD:
		sfw_next = sfw;
		do {
			hw_count = nf2_get_wildcard_packet_count(dev, sfw_next->pos);
			if (hw_count >= sfw_next->hw_packet_count) {
				count = hw_count - sfw_next->hw_packet_count;
				sfw_next->hw_packet_count = hw_count;
			} else {
				// wrapping occurred
				count = (MAX_INT_32 - sfw_next->hw_packet_count) + hw_count;
				sfw_next->hw_packet_count = hw_count;
			}
			total += count;
			sfw_next = list_entry(sfw_next->node.next,
					      struct sw_flow_nf2, node);
		} while (sfw_next != sfw);
		break;
	}

	LOG("Return nf2_get_packet_count value: %llu\n", total);
	return total;
}

uint64_t nf2_get_byte_count(struct net_device *dev, struct sw_flow_nf2 *sfw)
{
	uint32_t count = 0;
	uint32_t hw_count = 0;
	uint64_t total = 0;
	struct sw_flow_nf2 *sfw_next = NULL;

	switch (sfw->type) {
	default:
		break;

	case NF2_TABLE_EXACT:
		count = nf2_get_exact_byte_count(dev, sfw->pos);
		total = count;
		break;

	case NF2_TABLE_WILDCARD:
		sfw_next = sfw;
		do {
			hw_count = nf2_get_wildcard_byte_count(dev, sfw_next->pos);
			if (hw_count >= sfw_next->hw_byte_count) {
				count = hw_count - sfw_next->hw_byte_count;
				sfw_next->hw_byte_count = hw_count;
			} else {
				// wrapping occurred
				count = (MAX_INT_32 - sfw_next->hw_byte_count) + hw_count;
				sfw_next->hw_byte_count = hw_count;
			}

			total += count;
			sfw_next = list_entry(sfw_next->node.next,
					      struct sw_flow_nf2, node);
		} while (sfw_next != sfw);
		break;
	}

	LOG("Return nf2_get_byte_count value: %llu\n", total);
	return total;
}
