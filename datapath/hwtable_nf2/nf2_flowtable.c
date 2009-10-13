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
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/if_arp.h>

#include "chain.h"
#include "table.h"
#include "flow.h"
#include "datapath.h"

#include "hwtable_nf2/nf2_reg.h"
#include "hwtable_nf2/nf2_flowtable.h"
#include "hwtable_nf2/nf2_openflow.h"
#include "hwtable_nf2/nf2_lib.h"
#include "hwtable_nf2/nf2_procfs.h"

struct nf2_flowtable {
	struct sw_table flowtab;
	spinlock_t lock;
	unsigned int max_flows;
	atomic_t num_flows;
	struct list_head flows;
	struct list_head iter_flows;
	unsigned long int next_serial;
};

static struct sw_flow *nf2_lookup_flowtable(struct sw_table *,
					    const struct sw_flow_key *);
static int nf2_install_flow(struct sw_table *, struct sw_flow *);
static int nf2_modify_flow(struct sw_table *, const struct sw_flow_key *,
			   uint16_t, int, const struct ofp_action_header *,
			   size_t);
static void deferred_uninstall_callback(struct rcu_head *);
static void do_deferred_uninstall(struct sw_flow *);
static int do_uninstall(struct datapath *, struct sw_table *, struct sw_flow *,
			enum ofp_flow_removed_reason);
static int nf2_has_conflict(struct sw_table *, const struct sw_flow_key *,
			    uint16_t, int);
static int nf2_uninstall_flow(struct datapath *, struct sw_table *,
			      const struct sw_flow_key *, uint16_t,
			      uint16_t, int);
static int nf2_flow_timeout(struct datapath *, struct sw_table *);
static void nf2_destroy_flowtable(struct sw_table *);
static int nf2_iterate_flowtable(struct sw_table *,
				 const struct sw_flow_key *,
				 uint16_t, struct sw_table_position *,
				 int (*)(struct sw_flow *, void *), void *);
unsigned long int get_lookup_matched_stats(void);
unsigned long int get_lookup_stats(void);
static void nf2_get_flowstats(struct sw_table *, struct sw_table_stats *);
static struct sw_table *nf2_create_flowtable(void);
static int __init nf2_startup(void);
static void nf2_cleanup(void);

static struct sw_flow *
nf2_lookup_flowtable(struct sw_table *flowtab, const struct sw_flow_key *key)
{
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct sw_flow *flow;

	list_for_each_entry(flow, &nf2flowtab->flows, node) {
		if (flow_matches_1wild(key, &flow->key)) {
			return flow;
		}
	}

	return NULL;
}

static int
nf2_install_flow(struct sw_table *flowtab, struct sw_flow *flow)
{
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;

	/* Delete flows that match exactly. */
	nf2_uninstall_flow(NULL, flowtab, &flow->key, OFPP_NONE,
			   flow->priority, true);

	if (nf2_are_actions_supported(flow)) {
		if (nf2_build_and_write_flow(flow)) {
			return 0;
		}
	} else {
		/* Unsupported actions or no netdevice. */
		return 0;
	}

	atomic_inc(&nf2flowtab->num_flows);
	list_add_rcu(&flow->node, &nf2flowtab->flows);
	list_add_rcu(&flow->iter_node, &nf2flowtab->iter_flows);
	return 1;
}

static int
nf2_modify_flow(struct sw_table *flowtab, const struct sw_flow_key *key,
		uint16_t priority, int strict,
		const struct ofp_action_header *actions, size_t actions_len)
{
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct sw_flow *flow;
	unsigned int count = 0;

	list_for_each_entry(flow, &nf2flowtab->flows, node) {
		if (flow_matches_desc(&flow->key, key, strict)
		    && (!strict || flow->priority == priority)) {
			flow_replace_acts(flow, actions, actions_len);
			if (nf2_are_actions_supported(flow)) {
				count += nf2_modify_acts(flowtab, flow);
			}
		} else {
			return 0;
		}
	}

	return count;
}

static int
nf2_has_conflict(struct sw_table *flowtab, const struct sw_flow_key *key,
		 uint16_t priority, int strict)
{
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct sw_flow *flow;

	list_for_each_entry(flow, &nf2flowtab->flows, node) {
		if (flow_matches_desc(&flow->key, key, strict)
		    && (flow->priority == priority)) {
			return true;
		}
	}
	return false;
}

static void
deferred_uninstall_callback(struct rcu_head *rcu)
{
	struct sw_flow *flow = container_of(rcu, struct sw_flow, rcu);

	flow_free(flow);
}

static void
do_deferred_uninstall(struct sw_flow *flow)
{
	call_rcu(&flow->rcu, deferred_uninstall_callback);
}

static int
do_uninstall(struct datapath *dpinst, struct sw_table *flowtab,
	     struct sw_flow *flow, enum ofp_flow_removed_reason reason)
{
	if (flow != NULL && flow->private != NULL) {
		if (dpinst != NULL)
			dp_send_flow_end(dpinst, flow, reason);
		list_del_rcu(&flow->node);
		list_del_rcu(&flow->iter_node);
		nf2_delete_private(flow->private);
		do_deferred_uninstall(flow);
		return 1;
	}

	return 0;
}

static int
nf2_uninstall_flow(struct datapath *dpinst, struct sw_table *flowtab,
		   const struct sw_flow_key *key, uint16_t out_port,
		   uint16_t priority, int strict)
{
	struct net_device *netdev;
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct sw_flow *flow;
	struct nf2_flow *nf2flow;
	unsigned int count = 0;

	netdev = nf2_get_net_device();
	if (netdev == NULL)
		return 0;

	list_for_each_entry(flow, &nf2flowtab->flows, node) {
		if (flow_matches_desc(&flow->key, key, strict)
		    && (!strict || flow->priority == priority)
		    && flow_has_out_port(flow, out_port)) {
			nf2flow = flow->private;
			if (nf2flow != NULL) {
				flow->packet_count
					+= nf2_get_packet_count(netdev,
								nf2flow);
				flow->byte_count += nf2_get_byte_count(netdev,
								       nf2flow);
			}
			count += do_uninstall(dpinst, flowtab,
					      flow, OFPRR_DELETE);
		}
	}
	if (count != 0)
		atomic_sub(count, &nf2flowtab->num_flows);

	nf2_free_net_device(netdev);

	return count;
}

static int
nf2_flow_timeout(struct datapath *dpinst, struct sw_table *flowtab)
{
	struct net_device *netdev;
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct sw_flow *flow;
	struct nf2_flow *nf2flow;
	int num_uninst_flows = 0;
	uint64_t num_forw_packets = 0;
	int reason;

	netdev = nf2_get_net_device();
	if (netdev == NULL)
		return num_uninst_flows;

	mutex_lock(&dp_mutex);
	list_for_each_entry(flow, &nf2flowtab->flows, node) {
		nf2flow = flow->private;
		if (nf2flow != NULL) {
			num_forw_packets = flow->packet_count
				+ nf2_get_packet_count(netdev, nf2flow);
			flow->byte_count += nf2_get_byte_count(netdev, nf2flow);
		}
		if (num_forw_packets > flow->packet_count
		    && flow->idle_timeout != OFP_FLOW_PERMANENT) {
			flow->packet_count = num_forw_packets;
			flow->used = get_jiffies_64();
		}
		reason = flow_timeout(flow);
		if (reason >= 0) {
			num_uninst_flows += do_uninstall(dpinst, flowtab,
							 flow, reason);
		}
	}
	mutex_unlock(&dp_mutex);

	nf2_clear_watchdog(netdev);

	nf2_free_net_device(netdev);

	if (num_uninst_flows != 0)
		atomic_sub(num_uninst_flows, &nf2flowtab->num_flows);
	return num_uninst_flows;
}

static void
nf2_destroy_flowtable(struct sw_table *flowtab)
{
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct nf2_flow *nf2flow = NULL;

	if (nf2flowtab == NULL)
		return;

	while (!list_empty(&nf2flowtab->flows)) {
		struct sw_flow *flow = list_entry(nf2flowtab->flows.next,
						  struct sw_flow, node);

		list_del(&flow->node);
		if (flow->private) {
			nf2flow = (struct nf2_flow *)flow->private;

			if (nf2flow->type == NF2_TABLE_EXACT) {
				nf2_add_free_exact(nf2flow);
			} else if (nf2flow->type == NF2_TABLE_WILDCARD) {
				nf2_add_free_wildcard(nf2flow);
			}
			flow->private = NULL;
		}
		flow_free(flow);
	}
	kfree(nf2flowtab);

	nf2_destroy_exact_freelist();
	nf2_destroy_wildcard_freelist();
}

static int
nf2_iterate_flowtable(struct sw_table *flowtab, const struct sw_flow_key *key,
		      uint16_t out_port, struct sw_table_position *position,
		      int (*callback) (struct sw_flow *, void *), void *private)
{
	unsigned long start;
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct sw_flow *flow;
	int error = 0;

	start = ~position->private[0];
	list_for_each_entry(flow, &nf2flowtab->iter_flows, iter_node) {
		if (flow->serial <= start && flow_matches_2wild(key, &flow->key)
		    && flow_has_out_port(flow, out_port)) {
			error = callback(flow, private);
			if (error != 0) {
				position->private[0] = ~flow->serial;
				return error;
			}
		}
	}

	return error;
}

unsigned long int
get_lookup_stats(void)
{
	struct net_device *netdev;
	unsigned long int num_searched = 0;

	netdev = nf2_get_net_device();
	if (netdev == NULL)
		return num_searched;

	num_searched = nf2_get_missed_count(netdev);
	nf2_free_net_device(netdev);
	num_searched += get_lookup_matched_stats();
	return num_searched;
}

unsigned long int
get_lookup_matched_stats(void)
{
	struct net_device *netdev;
	unsigned long int num_matched = 0;

	netdev = nf2_get_net_device();
	if (netdev == NULL)
		return num_matched;

	num_matched = nf2_get_matched_count(netdev);
	nf2_free_net_device(netdev);
	return num_matched;
}

static void
nf2_get_flowstats(struct sw_table *flowtab, struct sw_table_stats *stats)
{
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;

	stats->name = "nf2";
	stats->wildcards = OPENFLOW_WILDCARD_TABLE_SIZE - 8;
	stats->n_flows = atomic_read(&nf2flowtab->num_flows);
	stats->max_flows = nf2flowtab->max_flows;
	stats->n_lookup = get_lookup_stats();
	stats->n_matched = get_lookup_matched_stats();
}

static struct sw_table *
nf2_create_flowtable(void)
{
	struct net_device *netdev;
	struct nf2_flowtable *nf2flowtab;
	struct sw_table *flowtab;

	netdev = nf2_get_net_device();
	if (netdev == NULL)
		return NULL;

	nf2_reset_card(netdev);
	nf2_free_net_device(netdev);

	nf2flowtab = kzalloc(sizeof(*nf2flowtab), GFP_KERNEL);
	if (nf2flowtab == NULL) {
		nf2_free_net_device(netdev);
		return NULL;
	}

	flowtab = &nf2flowtab->flowtab;
	flowtab->n_lookup = (unsigned long long)get_lookup_stats();
	flowtab->n_matched = (unsigned long long)get_lookup_matched_stats();
	flowtab->lookup = nf2_lookup_flowtable;
	flowtab->insert = nf2_install_flow;
	flowtab->modify = nf2_modify_flow;
	flowtab->has_conflict = nf2_has_conflict;
	flowtab->delete = nf2_uninstall_flow;
	flowtab->timeout = nf2_flow_timeout;
	flowtab->destroy = nf2_destroy_flowtable;
	flowtab->iterate = nf2_iterate_flowtable;
	flowtab->stats = nf2_get_flowstats;
#define RESERVED_FOR_CPU2NETFPGA	8
	nf2flowtab->max_flows = OPENFLOW_NF2_EXACT_TABLE_SIZE
		+ OPENFLOW_WILDCARD_TABLE_SIZE - RESERVED_FOR_CPU2NETFPGA;
	atomic_set(&nf2flowtab->num_flows, 0);
	INIT_LIST_HEAD(&nf2flowtab->flows);
	INIT_LIST_HEAD(&nf2flowtab->iter_flows);
	nf2flowtab->next_serial = 0;

	nf2_init_wildcard_freelist();
	nf2_write_static_wildcard();
	nf2_init_exact_freelist();

	return flowtab;
}

static int __init
nf2_startup(void)
{
	nf2_create_procfs();
	return chain_set_hw_hook(nf2_create_flowtable, THIS_MODULE);
}

static void
nf2_cleanup(void)
{
	nf2_remove_procfs();
	chain_clear_hw_hook();
}

module_init(nf2_startup);
module_exit(nf2_cleanup);

MODULE_DESCRIPTION("NetFPGA Fastpath Extension for OpenFlow Switch");
MODULE_AUTHOR("Copyright (c) 2008, 2009 "
	      "The Board of Trustees of The Leland Stanford Junior University");
MODULE_LICENSE("GPL");
