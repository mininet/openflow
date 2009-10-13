/*-
 * Copyright (c) 2008, 2009
 *      The Board of Trustees of The Leland Stanford Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation that
 * others will use, modify and enhance the Software and contribute those
 * enhancements back to the community. However, since we would like to make the
 * Software available for broadest use, with as few restrictions as possible
 * permission is hereby granted, free of charge, to any person obtaining a copy
 * of this Software to deal in the Software under the copyrights without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any derivatives
 * without specific, written prior permission.
 */

#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/delay.h>
#include <linux/if_arp.h>

#include "chain.h"
#include "table.h"
#include "flow.h"
#include "datapath.h"

/* Max number of flow entries supported by the hardware */
#define TMPL_MAX_FLOWS	8192

/* sw_flow private data for dummy table entries. */
struct tmpl_flow {
	struct list_head nodes;
	/* XXX: If per-entry data is needed, define it here. */
};

struct tmpl_flowtable {
	struct sw_table flowtab;
	unsigned int max_flows;
	atomic_t num_flows;
	struct list_head flows;
	struct list_head iter_flows;
	unsigned long int next_serial;
};

static struct sw_flow *tmpl_flowtable_lookup(struct sw_table *,
					     const struct sw_flow_key *);
static int tmpl_install_flow(struct sw_table *, struct sw_flow *);
static int tmpl_modify_flow(struct sw_table *, const struct sw_flow_key *,
			    uint16_t, int, const struct ofp_action_header *,
			    size_t);
static int do_uninstall(struct datapath *, struct sw_table *, struct sw_flow *,
			enum ofp_flow_removed_reason);
static int tmpl_uninstall_flow(struct datapath *, struct sw_table *,
			       const struct sw_flow_key *,
			       uint16_t, uint16_t, int);
static int tmpl_flow_timeout(struct datapath *, struct sw_table *);
static void tmpl_destroy_flowtable(struct sw_table *);
static int tmpl_iterate_flowtable(struct sw_table *, const struct sw_flow_key *,
				  uint16_t, struct sw_table_position *,
				  int (*)(struct sw_flow *, void *), void *);
static void tmpl_get_flowstats(struct sw_table *, struct sw_table_stats *);
static struct sw_table *tmpl_create_flowtable(void);
static int __init tmpl_startup(void);
static void tmpl_cleanup(void);

static struct sw_flow *
tmpl_flowtable_lookup(struct sw_table *flowtab, const struct sw_flow_key *key)
{
	struct tmpl_flowtable *myflowtab = (struct tmpl_flowtable *)flowtab;
	struct sw_flow *flow;

	list_for_each_entry(flow, &myflowtab->flows, node) {
		if (flow_matches_1wild(key, &flow->key)) {
			return flow;
		}
	}

	return NULL;
}

static int
tmpl_install_flow(struct sw_table *flowtab, struct sw_flow *flow)
{
	/* XXX: Use a data cache? */
	flow->private = kzalloc(sizeof(struct tmpl_flow), GFP_ATOMIC);
	if (flow->private == NULL)
		return 0;

	/* XXX: Do whatever needs to be done to insert an entry in hardware.
	 * If the entry can't be inserted, return 0.  This stub code doesn't
	 * do anything yet, so we're going to return 0... you shouldn't (and
	 * you should update n_flows in struct tmpl_flowtable, too).
	 */
	kfree(flow->private);
	return 0;
}

static int
tmpl_modify_flow(struct sw_table *flowtab, const struct sw_flow_key *key,
		 uint16_t priority, int strict,
		 const struct ofp_action_header *actions, size_t actions_len)
{
	struct tmpl_flowtable *myflowtab = (struct tmpl_flowtable *)flowtab;
	struct sw_flow *flow;
	unsigned int count = 0;

	list_for_each_entry(flow, &myflowtab->flows, node) {
		if (flow_matches_desc(&flow->key, key, strict)
		    && (!strict || (flow->priority == priority))) {
			flow_replace_acts(flow, actions, actions_len);
			/* XXX: Do whatever is necessary to modify the entry
			 * in hardware
			 */
			count++;
		}
	}

	return count;
}

static int
do_uninstall(struct datapath *dpinst, struct sw_table *flowtab,
	     struct sw_flow *flow, enum ofp_flow_removed_reason reason)
{
	/* XXX: Remove the entry from hardware.  If you need to do any other
	 * clean-up associated with the entry, do it here.
	 */
	dp_send_flow_end(dpinst, flow, reason);
	list_del_rcu(&flow->node);
	list_del_rcu(&flow->iter_node);
	flow_deferred_free(flow);
	return 1;
}

static int
tmpl_uninstall_flow(struct datapath *dpinst, struct sw_table *flowtab,
		    const struct sw_flow_key *key, uint16_t out_port,
		    uint16_t priority, int strict)
{
	struct tmpl_flowtable *myflowtab = (struct tmpl_flowtable *)flowtab;
	struct sw_flow *flow;
	unsigned int count = 0;

	list_for_each_entry(flow, &myflowtab->flows, node) {
		if (flow_matches_desc(&flow->key, key, strict)
		    && (!strict || (flow->priority == priority)))
			count += do_uninstall(dpinst, flowtab,
					      flow, OFPRR_DELETE);
	}

	if (count != 0)
		atomic_sub(count, &myflowtab->num_flows);
	return count;
}

static int
tmpl_flow_timeout(struct datapath *dpinst, struct sw_table *flowtab)
{
	struct tmpl_flowtable *myflowtab = (struct tmpl_flowtable *)flowtab;
	struct sw_flow *flow;
	int num_uninst_flows = 0;
	uint64_t num_forw_packets = 0;
	uint64_t num_forw_bytes = 0;
	int reason;

	mutex_lock(&dp_mutex);
	list_for_each_entry(flow, &myflowtab->flows, node) {
		/* XXX: Retrieve the packet and byte counts associated with this
		 * entry and store them in "packet_count" and "byte_count".
		 */
#if 0
		num_forw_pakcets = flow->packet_count + get_hwmib(...);
		num_forw_bytes = flow->byte_count + get_hwmib(...);
#endif
		if (num_forw_packets > flow->packet_count
		    && flow->idle_timeout != OFP_FLOW_PERMANENT) {
			flow->packet_count = num_forw_packets;
			flow->byte_count = num_forw_bytes;
			flow->used = get_jiffies_64();
		}
		reason = flow_timeout(flow);
		if (reason >= 0) {
			num_uninst_flows += do_uninstall(dpinst, flowtab,
							 flow, reason);
		}
	}
	mutex_unlock(&dp_mutex);

	if (num_uninst_flows != 0)
		atomic_sub(num_uninst_flows, &myflowtab->num_flows);
	return num_uninst_flows;
}

static void
tmpl_destroy_flowtable(struct sw_table *flowtab)
{
	struct tmpl_flowtable *myflowtab = (struct tmpl_flowtable *)flowtab;

	if (myflowtab == NULL) {
		return;
	}

	/* XXX: This table is being destroyed, so free any data that you
	 * don't want to leak.
	 */
	while (!list_empty(&myflowtab->flows)) {
		struct sw_flow *flow = list_entry(myflowtab->flows.next,
						  struct sw_flow, node);
		list_del(&flow->node);
		flow_free(flow);
	}

	kfree(myflowtab);
}

static int
tmpl_iterate_flowtable(struct sw_table *flowtab, const struct sw_flow_key *key,
		       uint16_t out_port, struct sw_table_position *position,
		       int (*callback) (struct sw_flow *, void *),
		       void *private)
{
	struct tmpl_flowtable *myflowtab = (struct tmpl_flowtable *)flowtab;
	struct sw_flow *flow;
	unsigned long start;
	int error = 0;

	start = ~position->private[0];
	list_for_each_entry(flow, &myflowtab->iter_flows, iter_node) {
		if (flow->serial <= start
		    && flow_matches_2wild(key, &flow->key)) {
			error = callback(flow, private);
			if (error) {
				position->private[0] = ~flow->serial;
				return error;
			}
		}
	}

	return error;
}

static void
tmpl_get_flowstats(struct sw_table *flowtab, struct sw_table_stats *stats)
{
	struct tmpl_flowtable *myflowtab = (struct tmpl_flowtable *)flowtab;

	stats->name = "template";
	stats->wildcards = OFPFW_ALL;	/* XXX: Set this appropriately */
	stats->n_flows = atomic_read(&myflowtab->num_flows);
	stats->max_flows = myflowtab->max_flows;
	stats->n_matched = flowtab->n_matched;
}

static struct sw_table *
tmpl_create_flowtable(void)
{
	struct tmpl_flowtable *myflowtab;
	struct sw_table *flowtab;

	myflowtab = kzalloc(sizeof(*myflowtab), GFP_KERNEL);
	if (myflowtab == NULL)
		return NULL;

	flowtab = &myflowtab->flowtab;
	flowtab->lookup = tmpl_flowtable_lookup;
	flowtab->insert = tmpl_install_flow;
	flowtab->modify = tmpl_modify_flow;
	flowtab->delete = tmpl_uninstall_flow;
	flowtab->timeout = tmpl_flow_timeout;
	flowtab->destroy = tmpl_destroy_flowtable;
	flowtab->iterate = tmpl_iterate_flowtable;
	flowtab->stats = tmpl_get_flowstats;

	myflowtab->max_flows = TMPL_MAX_FLOWS;
	atomic_set(&myflowtab->num_flows, 0);
	INIT_LIST_HEAD(&myflowtab->flows);
	INIT_LIST_HEAD(&myflowtab->iter_flows);
	myflowtab->next_serial = 0;

	return flowtab;
}

static int __init
tmpl_startup(void)
{
	return chain_set_hw_hook(tmpl_create_flowtable, THIS_MODULE);
}

static void
tmpl_cleanup(void)
{
	chain_clear_hw_hook();
}

module_init(tmpl_startup);
module_exit(tmpl_cleanup);

MODULE_DESCRIPTION("Fastpath Extension Template for OpenFlow Switch");
MODULE_AUTHOR("Copyright (c) 2008, 2009 "
	      "The Board of Trustees of The Leland Stanford Junior University");
MODULE_LICENSE("GPL");
