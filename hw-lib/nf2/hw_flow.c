/*-
 * Copyright (c) 2008, 2009, 2010
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

#include <stdlib.h>

#include <openflow/of_hw_api.h>
#include "list.h"
#include "udatapath/switch-flow.h"
#include "udatapath/datapath.h"
#include "reg_defines_openflow_switch.h"
#include "nf2util.h"
#include "hw_flow.h"
#include "nf2_drv.h"
#include "nf2_lib.h"
#include "debug.h"

struct nf2_flowtable {
	struct of_hw_driver hw_driver;
	unsigned int max_flows;
	unsigned int num_flows;
	struct list flows;
	struct list iter_flows;
	unsigned long int next_serial;
};

static struct sw_flow *nf2_lookup_flowtable(struct sw_table *,
					    const struct sw_flow_key *);
static int nf2_install_flow(struct sw_table *, struct sw_flow *);
static int nf2_modify_flow(struct sw_table *, const struct sw_flow_key *,
			   uint16_t, int, const struct ofp_action_header *,
			   size_t);
static int do_uninstall(struct sw_flow *, struct list *);
static int nf2_has_conflict(struct sw_table *, const struct sw_flow_key *,
			    uint16_t, int);
static int nf2_uninstall_flow_wrap(struct datapath *, struct sw_table *,
			      const struct sw_flow_key *, uint16_t,
			      uint16_t, int);
static int nf2_uninstall_flow(struct datapath *, struct sw_table *,
			      const struct sw_flow_key *, uint16_t,
			      uint16_t, int, int);
static void nf2_flow_timeout(struct sw_table *, struct list *);

static void nf2_destroy_flowtable(struct sw_table *);
static int nf2_iterate_flowtable(struct sw_table *,
				 const struct sw_flow_key *,
				 uint16_t, struct sw_table_position *,
				 int (*)(struct sw_flow *, void *), void *);
static void nf2_get_flowstats(struct sw_table *, struct sw_table_stats *);
static int nf2_get_portstats(of_hw_driver_t *, int, struct ofp_port_stats *);

#if !defined(HWTABLE_NO_DEBUG)
int of_hw_debug = DBG_LVL_WARN;
#endif

#define DELETE_FLOW 0
#define KEEP_FLOW 1

static struct sw_flow *
nf2_lookup_flowtable(struct sw_table *flowtab, const struct sw_flow_key *key)
{
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct sw_flow *flow;

	LIST_FOR_EACH(flow, struct sw_flow, node, &nf2flowtab->flows) {
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
			   flow->priority, true, KEEP_FLOW);

	if (nf2_are_actions_supported(flow)) {
		if (nf2_build_and_write_flow(flow)) {
			/* Not successful */
			return 0;
		}
	} else {
		/* Unsupported actions or no device. */
		return 0;
	}

	nf2flowtab->num_flows++;
	list_push_front(&nf2flowtab->flows, &flow->node);
	list_push_front(&nf2flowtab->iter_flows, &flow->iter_node);

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

	LIST_FOR_EACH(flow, struct sw_flow, node, &nf2flowtab->flows) {
		if (flow_matches_desc(&flow->key, key, strict)
		    && (!strict || flow->priority == priority)) {
			flow_replace_acts(flow, actions, actions_len);
			if (nf2_are_actions_supported(flow)) {
				count += nf2_modify_acts(flow);
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

	LIST_FOR_EACH(flow, struct sw_flow, node, &nf2flowtab->flows) {

		if (flow_matches_2desc(&flow->key, key, strict)
		    && (flow->priority == priority)) {
			return true;
		}
	}

	return false;
}

static int
do_uninstall(struct sw_flow *flow, struct list *deleted)
{
	if (flow != NULL && flow->private != NULL) {
		list_remove(&flow->node);
		list_remove(&flow->iter_node);
		list_push_back(deleted, &flow->node);
		return 1;
	}

	return 0;
}

static int
nf2_uninstall_flow_wrap(struct datapath *dpinst, struct sw_table *flowtab,
		   const struct sw_flow_key *key, uint16_t out_port,
		   uint16_t priority, int strict)
{
	return nf2_uninstall_flow(dpinst, flowtab, key, out_port,
	                          priority, strict, DELETE_FLOW);
}

static int
nf2_uninstall_flow(struct datapath *dpinst, struct sw_table *flowtab,
		   const struct sw_flow_key *key, uint16_t out_port,
		   uint16_t priority, int strict, int keep_flow)
{
	struct nf2device *dev;
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct sw_flow *flow, *n;
	struct nf2_flow *nf2flow;
	unsigned int count = 0;
	struct list deleted;
	list_init(&deleted);

	dev = nf2_get_net_device();
	if (dev == NULL)
		return 0;

	LIST_FOR_EACH_SAFE (flow, n, struct sw_flow, node, &nf2flowtab->flows) {
		if (flow_matches_desc(&flow->key, key, strict)
		    && (!strict || flow->priority == priority)
		    && flow_has_out_port(flow, out_port)) {
			nf2flow = flow->private;

			if (nf2flow != NULL) {
				flow->packet_count
					+= nf2_get_packet_count(dev,
								nf2flow);
				flow->byte_count += nf2_get_byte_count(dev,
								       nf2flow);
			}
			count += do_uninstall(flow, &deleted);
			if (keep_flow == KEEP_FLOW) {
				/* Delete private in sw_flow here */
				nf2_delete_private(flow->private);
			}
		}
	}
	nf2flowtab->num_flows -= count;

	nf2_free_net_device(dev);

	if (keep_flow == DELETE_FLOW) {
		/* Notify DP of deleted flows and delete the flow */
		LIST_FOR_EACH_SAFE (flow, n, struct sw_flow, node, &deleted) {
			dp_send_flow_end(dpinst, flow, flow->reason);
			list_remove(&flow->node);
			nf2_delete_private(flow->private);
			flow_free(flow);
			}
	}

	return count;
}

static void
nf2_flow_timeout(struct sw_table *flowtab, struct list *deleted)
{
	struct nf2device *dev;
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct sw_flow *flow, *n;
	struct nf2_flow *nf2flow;
	int num_uninst_flows = 0;
	uint64_t num_forw_packets = 0;
	uint64_t now = time_msec();

	dev = nf2_get_net_device();
	if (dev == NULL) {
		DBG_ERROR("Could not open NetFPGA device\n");
		return;
	}

	/* LOCK; */
	/* FIXME */
	LIST_FOR_EACH_SAFE (flow, n, struct sw_flow, node, &nf2flowtab->flows) {
		nf2flow = flow->private;
		if (nf2flow != NULL) {
			num_forw_packets = flow->packet_count
				+ nf2_get_packet_count(dev, nf2flow);
			flow->byte_count += nf2_get_byte_count(dev, nf2flow);
		}
		if (num_forw_packets > flow->packet_count) {
			flow->packet_count = num_forw_packets;
			flow->used = now;
		}

		if (flow_timeout(flow)) {
			num_uninst_flows += do_uninstall(flow, deleted);
			nf2_delete_private(flow->private);
		}
	}

	/* UNLOCK; */

	nf2_clear_watchdog(dev);
	nf2_free_net_device(dev);

	nf2flowtab->num_flows -= num_uninst_flows;
}

static void
nf2_destroy_flowtable(struct sw_table *flowtab)
{
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct nf2_flow *nf2flow = NULL;

	if (nf2flowtab == NULL)
		return;

	while (!list_is_empty(&nf2flowtab->flows)) {
		struct sw_flow *flow
			= CONTAINER_OF(list_front(&nf2flowtab->flows),
						  struct sw_flow, node);
		list_remove(&flow->node);
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
	free(nf2flowtab);

	nf2_destroy_exact_freelist();
	nf2_destroy_wildcard_freelist();
}

static int
nf2_iterate_flowtable(struct sw_table *flowtab, const struct sw_flow_key *key,
		      uint16_t out_port, struct sw_table_position *position,
		      int (*callback) (struct sw_flow *, void *),
		      void *private)
{
	unsigned long start;
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct sw_flow *flow;
	int error = 0;

	start = ~position->private[0];
	LIST_FOR_EACH(flow, struct sw_flow, iter_node, &nf2flowtab->iter_flows) {
		if (flow->serial <= start
		    && flow_matches_2wild(key, &flow->key)
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

static void
nf2_get_flowstats(struct sw_table *flowtab, struct sw_table_stats *stats)
{
	struct nf2_flowtable *nf2flowtab = (struct nf2_flowtable *)flowtab;
	struct nf2device *dev;
	unsigned long int num_matched = 0;
	unsigned long int num_missed = 0;

	dev = nf2_get_net_device();
	if (dev == NULL) {
		DBG_VERBOSE("Could not open NetFPGA device\n");
	} else {
		num_matched = nf2_get_matched_count(dev);
		num_missed = nf2_get_missed_count(dev);
		nf2_free_net_device(dev);
	}

	stats->name = "nf2";
	stats->wildcards = OPENFLOW_WILDCARD_TABLE_SIZE
	                 - RESERVED_FOR_CPU2NETFPGA;
	stats->n_flows = nf2flowtab->num_flows;
	stats->max_flows = nf2flowtab->max_flows;
	stats->n_lookup = num_matched + num_missed;
	stats->n_matched = num_matched;
}

static int
nf2_get_portstats(of_hw_driver_t *hw_drv, int of_port,
			struct ofp_port_stats *stats)
{
	int nf2_port;
	struct nf2_port_info *nf2portinfo;
	struct nf2device *dev;

	if ((of_port > NF2_PORT_NUM) || (of_port <= 0)) {
		return 1;
	}
	nf2_port = of_port - 1;

	nf2portinfo = calloc(1, sizeof(struct nf2_port_info));
	if (nf2portinfo == NULL) {
		return 1;
	}

	dev = nf2_get_net_device();
	if (dev == NULL) {
		free(nf2portinfo);
		return 1;
	}

	if (nf2_get_port_info(dev, nf2_port, nf2portinfo)) {
		nf2_free_net_device(dev);
		free(nf2portinfo);
		return 1;
	}

	stats->rx_packets = (uint64_t)(nf2portinfo->rx_q_num_pkts_stored);
	stats->rx_dropped = (uint64_t)(nf2portinfo->rx_q_num_pkts_dropped_full
	                  + nf2portinfo->rx_q_num_pkts_dropped_bad);
	stats->rx_bytes = (uint64_t)(nf2portinfo->rx_q_num_bytes_pushed);
	stats->tx_packets = (uint64_t)(nf2portinfo->tx_q_num_pkts_sent);
	stats->tx_bytes = (uint64_t)(nf2portinfo->tx_q_num_bytes_pushed);

	/* Not supported */
	stats->tx_dropped = -1;
	stats->rx_errors = -1;
	stats->tx_errors = -1;
	stats->rx_frame_err = -1;
	stats->rx_over_err = -1;
	stats->rx_crc_err = -1;
	stats->collisions = -1;

	nf2_free_net_device(dev);
	free(nf2portinfo);
	return 0;
}

/*
 * Create and initialize a new hardware datapath object
 */

of_hw_driver_t *
new_of_hw_driver(struct datapath *dp)
{
	struct sw_table *sw_tab;
	of_hw_driver_t *hw_drv;
	struct nf2device *dev;
	struct nf2_flowtable *nf2flowtab;

	dev = nf2_get_net_device();
	if (dev == NULL) {
		return NULL;
	}
	nf2_reset_card(dev);
	nf2_free_net_device(dev);

	nf2flowtab = calloc(1, sizeof(*nf2flowtab));
	if (nf2flowtab == NULL) {
		return NULL;
	}

	/* These all point to the same place */
	hw_drv = &nf2flowtab->hw_driver;
	sw_tab = &hw_drv->sw_table;

	sw_tab->n_lookup = 0;
	sw_tab->n_matched = 0;

	/* Fill out the function pointers */
	sw_tab->lookup = nf2_lookup_flowtable;
	sw_tab->insert = nf2_install_flow;
	sw_tab->modify = nf2_modify_flow;
	sw_tab->has_conflict = nf2_has_conflict;

	sw_tab->delete = nf2_uninstall_flow_wrap;
	sw_tab->timeout = nf2_flow_timeout;

	sw_tab->destroy = nf2_destroy_flowtable;
	sw_tab->iterate = nf2_iterate_flowtable;
	sw_tab->stats = nf2_get_flowstats;

	nf2flowtab->max_flows = OPENFLOW_NF2_EXACT_TABLE_SIZE
	    + OPENFLOW_WILDCARD_TABLE_SIZE - RESERVED_FOR_CPU2NETFPGA;
	nf2flowtab->num_flows = 0;
	list_init(&nf2flowtab->flows);
	list_init(&nf2flowtab->iter_flows);
	nf2flowtab->next_serial = 0;

	if (nf2_init_wildcard_freelist()) {
		DBG_ERROR("Could not create wildcard freelist\n");
		free(nf2flowtab);
		return NULL;
	}
	if (nf2_write_static_wildcard()) {
		DBG_ERROR("Could not create wildcard freelist\n");
		free(nf2flowtab);
		return NULL;
	}
	if (nf2_init_exact_freelist()) {
		DBG_ERROR("Could not create exact freelist\n");
		free(nf2flowtab);
		return NULL;
	}

	hw_drv->table_stats_get = NULL;
	hw_drv->port_stats_get = nf2_get_portstats;
	hw_drv->flow_stats_get = NULL;
	hw_drv->aggregate_stats_get = NULL;

	hw_drv->port_add = NULL;
	hw_drv->port_remove = NULL;
	hw_drv->port_link_get = NULL;
	hw_drv->port_enable_set = NULL;
	hw_drv->port_enable_get = NULL;
	hw_drv->port_queue_config = NULL;
	hw_drv->port_queue_remove = NULL;
	hw_drv->port_change_register = NULL;

	hw_drv->packet_send = NULL;
	hw_drv->packet_receive_register = NULL;

	hw_drv->ioctl = NULL;

	return hw_drv;
}
