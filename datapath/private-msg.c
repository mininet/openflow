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

#include "openflow/private-ext.h"

#include "chain.h"
#include "datapath.h"
#include "table.h"
#include "private-msg.h"

struct emerg_flow_context {
	struct sw_chain *chain;
};

static void flush_working(struct sw_chain *);
static int protection_callback(struct sw_flow *, void *);
static void do_protection(struct sw_chain *);

static void
flush_working(struct sw_chain *chain)
{
	struct sw_flow_key key;
	int num_deleted = 0;

	memset(&key, 0, sizeof(key));
	key.wildcards = OFPFW_ALL;
	num_deleted = chain_delete(chain, &key, OFPP_NONE, 0, 0, 0);
}

static int
protection_callback(struct sw_flow *flow, void *private_)
{
	struct emerg_flow_context *private
		= (struct emerg_flow_context *)private_;
	struct sw_flow_actions *actions = flow->sf_acts;
	struct ofp_match match;
	struct sw_flow *tgtflow = NULL;
	int error = 0;

	tgtflow = flow_alloc(actions->actions_len, GFP_ATOMIC);
	if (tgtflow == NULL) {
		return -ENOMEM;
	}

	/* Dup w/o idle and hard timeout. */
	memset(&match, 0, sizeof(match));
	flow_fill_match(&match, &flow->key);
	flow_extract_match(&tgtflow->key, &match);
	/* Fill out flow. */
	tgtflow->priority = flow->priority;
	tgtflow->idle_timeout = OFP_FLOW_PERMANENT;
	tgtflow->hard_timeout = OFP_FLOW_PERMANENT;
	tgtflow->send_flow_rem = flow->send_flow_rem;
	tgtflow->emerg_flow = 0;
	flow_setup_actions(tgtflow, actions->actions, actions->actions_len);

	error = chain_insert(private->chain, tgtflow, 0);
	if (error)
		flow_free(tgtflow);

	return error;
}

static void
do_protection(struct sw_chain *chain)
{
	struct emerg_flow_context private;
	struct sw_flow_key key;
	struct sw_table_position position;
	struct sw_table *table = chain->emerg_table;
	int error = 0;

	memset(&private, 0, sizeof(private));
	private.chain = chain;
	memset(&key, 0, sizeof(key));
	key.wildcards = OFPFW_ALL;
	memset(&position, 0, sizeof(position));

	error = table->iterate(table, &key, OFPP_NONE,
			       &position, protection_callback, &private);
}

int
private_recv_msg(struct sw_chain *chain, const struct sender *sender,
		 const void *ofph)
{
	int error = 0;
	struct private_vxhdr *vxhdr = (struct private_vxhdr *)ofph;
	struct private_vxopt *vxopt = (struct private_vxopt *)(vxhdr + 1);

	switch (ntohs(vxopt->pvo_type)) {
	case PRIVATEOPT_PROTOCOL_STATS_REQUEST:
	case PRIVATEOPT_PROTOCOL_STATS_REPLY:
		break;
	case PRIVATEOPT_EMERG_FLOW_PROTECTION:
		flush_working(chain);
		do_protection(chain);
		break;
	case PRIVATEOPT_EMERG_FLOW_RESTORATION:
		/* Nothing to do because we assume that a re-connected
		 * controller will do flush current working flow table. */
		break;
	default:
		error = -EINVAL;
	}

	return error;
}
