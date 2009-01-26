/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/if_arp.h>

#include "chain.h"
#include "table.h"
#include "flow.h"
#include "datapath.h"

#include "hwtable_nf2/nf2_logging.h"

/* For NetFPGA */
#include "hwtable_nf2/reg_defines.h"
#include "hwtable_nf2/nf2_openflow.h"
#include "hwtable_nf2/hwtable_nf2.h"

static int table_nf2_delete(struct sw_table *swt, const struct sw_flow_key *key,
			    uint16_t out_port, uint16_t priority, int strict);

static int table_nf2_modify(struct sw_table *swt,
			    const struct sw_flow_key *key, uint16_t priority,
			    int strict, const struct ofp_action_header *actions,
			    size_t actions_len);

static void table_nf2_rcu_callback(struct rcu_head *rcu)
{
	struct sw_flow *flow = container_of(rcu, struct sw_flow, rcu);
	flow_free(flow);
}

static void table_nf2_flow_deferred_free(struct sw_flow *flow)
{
	call_rcu(&flow->rcu, table_nf2_rcu_callback);
}

static struct sw_flow *table_nf2_lookup(struct sw_table *swt,
					const struct sw_flow_key *key)
{
	struct sw_table_nf2 *td = (struct sw_table_nf2 *)swt;
	struct sw_flow *flow;
	list_for_each_entry (flow, &td->flows, node) {
		if (flow_matches_1wild(key, &flow->key)) {
			return flow;
		}
	}
	return NULL;
}

static int table_nf2_insert(struct sw_table *swt, struct sw_flow *flow)
{
	struct sw_table_nf2 *tb = (struct sw_table_nf2 *)swt;

	/* xxx Do whatever needs to be done to insert an entry in hardware.
	 * xxx If the entry can't be inserted, return 0.  This stub code
	 * xxx doesn't do anything yet, so we're going to return 0...you
	 * xxx shouldn't.
	 */

	/* Delete flows that match exactly. */
	table_nf2_delete(swt, &flow->key, OFPP_NONE, flow->priority, true);

	if (nf2_are_actions_supported(flow)) {
		LOG("---Actions are supported---\n");
		if (nf2_build_and_write_flow(flow)) {
			LOG("---build and write flow failed---\n");
			// failed
			return 0;
		}
	} else {
		// unsupported actions or no netdevice
		return 0;
	}


	atomic_inc(&tb->n_flows);

	list_add_rcu(&flow->node, &tb->flows);
	list_add_rcu(&flow->iter_node, &tb->iter_flows);

	return 1;
}

static int do_delete(struct sw_table *swt, struct sw_flow *flow)
{
	if (flow && flow->private) {
		list_del_rcu(&flow->node);
		list_del_rcu(&flow->iter_node);

		// This function will send the private object back to the free lists
		nf2_delete_private(flow->private);

		table_nf2_flow_deferred_free(flow);

		return 1;
	}

	return 0;
}

static int table_nf2_delete(struct sw_table *swt,
			    const struct sw_flow_key *key, uint16_t out_port,
			    uint16_t priority, int strict)
{
	struct sw_table_nf2 *td = (struct sw_table_nf2 *)swt;
	struct sw_flow *flow;
	unsigned int count = 0;

	list_for_each_entry (flow, &td->flows, node) {
		if (flow_matches_desc(&flow->key, key, strict)
		    && (!strict || (flow->priority == priority))
		    && flow_has_out_port(flow, out_port))
			count += do_delete(swt, flow);
	}
	if (count)
		atomic_sub(count, &td->n_flows);
	return count;
}

static int table_nf2_modify(struct sw_table *swt,
			    const struct sw_flow_key *key, uint16_t priority,
			    int strict, const struct ofp_action_header *actions,
			    size_t actions_len)
{
	struct sw_table_nf2 *td = (struct sw_table_nf2 *)swt;
	struct sw_flow *flow;
	unsigned int count = 0;

	list_for_each_entry(flow, &td->flows, node) {
		if (flow_matches_desc(&flow->key, key, strict)
		    && (!strict || (flow->priority == priority))) {
			flow_replace_acts(flow, actions, actions_len);
			if (nf2_are_actions_supported(flow)) {
				LOG("---Action Modify: Actions are supported---\n");
				count += nf2_modify_acts(swt, flow);
			}
		} else {
			LOG("---unsupported actions or no netdevice---\n");
			return 0;
		}
	}
	return count;
}

static int table_nf2_timeout(struct datapath *dp, struct sw_table *swt)
{
	struct sw_table_nf2 *td = (struct sw_table_nf2 *)swt;
	struct sw_flow *flow;
	struct sw_flow_nf2 *sfw;
	int del_count = 0;
	uint64_t packet_count = 0;
	struct net_device* dev;
	int reason;

	dev = nf2_get_net_device();

	mutex_lock(&dp_mutex);
	list_for_each_entry (flow, &td->flows, node) {
		/* xxx Retrieve the packet count associated with this entry
		 * xxx and store it in "packet_count".
		 */

		sfw = flow->private;
		if (sfw) {
			packet_count = flow->packet_count + nf2_get_packet_count(dev, sfw);
			flow->byte_count += nf2_get_byte_count(dev, sfw);
		}

		if ((packet_count > flow->packet_count)
		    && (flow->idle_timeout != OFP_FLOW_PERMANENT)) {
			flow->packet_count = packet_count;
			flow->used = jiffies;
		}

		reason = flow_timeout(flow);
		if (reason >= 0) {
			if (dp->flags & OFPC_SEND_FLOW_EXP) {
				dp_send_flow_expired(dp, flow, reason);
			}
			del_count += do_delete(swt, flow);
		}
	}
	mutex_unlock(&dp_mutex);

	nf2_free_net_device(dev);

	if (del_count)
		atomic_sub(del_count, &td->n_flows);
	return del_count;
}

static void table_nf2_destroy(struct sw_table *swt)
{
	struct sw_table_nf2 *td = (struct sw_table_nf2 *)swt;
	struct sw_flow_nf2* sfw = NULL;

	/* xxx This table is being destroyed, so free any data that you
	 * xxx don't want to leak.
	 */

	if (td) {
		while (!list_empty(&td->flows)) {
			struct sw_flow *flow = list_entry(td->flows.next,
							  struct sw_flow, node);
			list_del(&flow->node);
			if (flow->private) {
				sfw = (struct sw_flow_nf2*)flow->private;
				if (sfw->type == NF2_TABLE_EXACT) {
					add_free_exact(sfw);
				} else if (sfw->type == NF2_TABLE_WILDCARD) {
					add_free_wildcard(sfw);
				}
				flow->private = NULL;
			}
			flow_free(flow);
		}
		kfree(td);
	}

	destroy_exact_free_list();
	destroy_wildcard_free_list();
}

static int table_nf2_iterate(struct sw_table *swt,
			     const struct sw_flow_key *key, uint16_t out_port,
			     struct sw_table_position *position,
			     int (*callback)(struct sw_flow *, void *),
			     void *private)
{
	struct sw_table_nf2 *tl = (struct sw_table_nf2 *) swt;
	struct sw_flow *flow;
	unsigned long start;

	start = ~position->private[0];
	list_for_each_entry (flow, &tl->iter_flows, iter_node) {
		if (flow->serial <= start && flow_matches_2wild(key, &flow->key)
		    && flow_has_out_port(flow, out_port)) {
			int error = callback(flow, private);
			if (error) {
				position->private[0] = ~flow->serial;
				return error;
			}
		}
	}
	return 0;
}

unsigned long int matched_cnt(void)
{
	unsigned long int cnt;
	struct net_device *dev;

	dev = nf2_get_net_device();
	cnt = nf2_get_matched_count(dev);
	nf2_free_net_device(dev);
	return cnt;
}

unsigned long int lookup_cnt(void)
{
	unsigned long int cnt;
	struct net_device *dev;

	dev = nf2_get_net_device();
	cnt = nf2_get_missed_count(dev);
	nf2_free_net_device(dev);
	return (cnt + matched_cnt());
}

static void table_nf2_stats(struct sw_table *swt,
			    struct sw_table_stats *stats)
{
	struct sw_table_nf2 *td = (struct sw_table_nf2 *)swt;

	stats->name = "nf2";
	stats->wildcards = OPENFLOW_WILDCARD_TABLE_SIZE-8;
	stats->n_flows = atomic_read(&td->n_flows);
	stats->max_flows = td->max_flows;
	stats->n_lookup = lookup_cnt();
	stats->n_matched = matched_cnt();
}

static struct sw_table *table_nf2_create(void)
{
	struct sw_table_nf2 *td;
	struct sw_table *swt;
	struct net_device *dev;

	// initialize the card
	dev = nf2_get_net_device();
	nf2_reset_card(dev);
	nf2_free_net_device(dev);

	td = kzalloc(sizeof *td, GFP_KERNEL);
	if (td == NULL)
		return NULL;

	swt = &td->swt;
	swt->lookup = table_nf2_lookup;
	swt->insert = table_nf2_insert;
	swt->modify = table_nf2_modify;
	swt->delete = table_nf2_delete;
	swt->timeout = table_nf2_timeout;
	swt->destroy = table_nf2_destroy;
	swt->iterate = table_nf2_iterate;
	swt->stats = table_nf2_stats;
	swt->n_lookup = (unsigned long long)lookup_cnt();
	swt->n_matched = (unsigned long long)matched_cnt();

#define RESERVED_FOR_CPU2NETFPGA 8
	td->max_flows = OPENFLOW_NF2_EXACT_TABLE_SIZE
		+ OPENFLOW_WILDCARD_TABLE_SIZE
		- RESERVED_FOR_CPU2NETFPGA;

	atomic_set(&td->n_flows, 0);
	INIT_LIST_HEAD(&td->flows);
	INIT_LIST_HEAD(&td->iter_flows);
	td->next_serial = 0;

	init_wildcard_free_list();
	nf2_write_static_wildcard();
	LOG("initialized wildcard free list\n");

	init_exact_free_list();
	LOG("initialized exact free list\n");

	return swt;
}

static int __init nf2_init(void)
{
	return chain_set_hw_hook(table_nf2_create, THIS_MODULE);
}
module_init(nf2_init);

static void nf2_cleanup(void)
{
	chain_clear_hw_hook();
}
module_exit(nf2_cleanup);

MODULE_DESCRIPTION("NetFPGA OpenFlow Hardware Table Driver");
MODULE_AUTHOR("Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University");
MODULE_LICENSE("GPL");
