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

#include <config.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>

#include "openflow/openflow.h"
#include "openflow/private-ext.h"

#include "ofpbuf.h"
#include "util.h"
#include "xtoxll.h"
#include "rconn.h"
#include "vconn.h"
#include "secchan.h"
#include "status.h"
#include "timeval.h"
#include "sat-math.h"
#include "ofpstat.h"
#include "protocol-stat.h"
#define THIS_MODULE VLM_protocol_stat
#include "vlog.h"

#define COPY_OFPS(dst_ofps, src_ofps, tag)			\
do {								\
	(dst_ofps)->tag = htonll((src_ofps)->tag);		\
} while (0)

#define COPY_OFP_STAT(dst_ofps, src_ofps)			\
do {								\
	COPY_OFPS(dst_ofps, src_ofps, ofps_total);		\
	COPY_OFPS(dst_ofps, src_ofps, ofps_unknown);		\
								\
	COPY_OFPS(dst_ofps, src_ofps, ofps_hello);		\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error);		\
	COPY_OFPS(dst_ofps, src_ofps, ofps_echo_request);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_echo_reply);		\
	COPY_OFPS(dst_ofps, src_ofps, ofps_vendor);		\
	COPY_OFPS(dst_ofps, src_ofps, ofps_feats_request);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_feats_reply);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_get_config_request);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_get_config_reply);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_set_config);		\
	COPY_OFPS(dst_ofps, src_ofps, ofps_packet_in);		\
	COPY_OFPS(dst_ofps, src_ofps, ofps_flow_removed);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_port_status);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_packet_out);		\
	COPY_OFPS(dst_ofps, src_ofps, ofps_flow_mod);		\
	COPY_OFPS(dst_ofps, src_ofps, ofps_port_mod);		\
	COPY_OFPS(dst_ofps, src_ofps, ofps_stats_request);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_stats_reply);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_barrier_request);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_barrier_reply);	\
								\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_type.hello_fail);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_type.bad_request);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_type.bad_action);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_type.flow_mod_fail);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_type.unknown);	\
								\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.hf_incompat);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.hf_eperm);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.br_bad_version);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.br_bad_type);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.br_bad_stat);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.br_bad_vendor);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.br_eperm);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.ba_bad_type);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.ba_bad_len);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.ba_bad_vendor);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.ba_bad_vendor_type); \
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.ba_bad_out_port);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.ba_eperm);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.fmf_all_tables_full); \
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.fmf_overlap);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.fmf_eperm);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_error_code.unknown);	\
								\
	COPY_OFPS(dst_ofps, src_ofps, ofps_flow_mod_ops.add);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_flow_mod_ops.modify);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_flow_mod_ops.delete);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_flow_mod_ops.delete_strict);	\
	COPY_OFPS(dst_ofps, src_ofps, ofps_flow_mod_ops.unknown);	\
} while (0)

struct protocol_stat_context {
	const struct settings *settings;
	const struct secchan *secchan;
	struct rconn *local_rconn;
	struct rconn *remote_rconn;
	struct ofpstat ofps_rcvd;
	struct ofpstat ofps_sent;
};

static bool protocol_stat_remote_packet_cb(struct relay *, void *);

static bool
protocol_stat_remote_packet_cb(struct relay *relay, void *context_)
{
	struct protocol_stat_context *context = context_;
	struct rconn *mgmt_rconn = relay->halves[HALF_REMOTE].rconn;
	struct ofpbuf *qbuf = relay->halves[HALF_REMOTE].rxbuf;
	struct ofpbuf *pbuf = NULL;
	struct private_vxhdr *qvxhdr = NULL;
	struct private_vxhdr *pvxhdr = NULL;
	struct private_vxopt *qvxopt = NULL;
	struct private_vxopt *pvxopt = NULL;
	struct ofpstat *ofps = NULL;
	struct ofpstat ofps_rcvd;
	struct ofpstat ofps_sent;
	int error = 0;

	if (qbuf->size < sizeof(*qvxhdr))
		return false;
	qvxhdr = qbuf->data;
	if (qvxhdr->ofp_hdr.type != OFPT_VENDOR)
		return false;
	if (ntohl(qvxhdr->ofp_vxid) != PRIVATE_VENDOR_ID) {
		return false;
	}
	qvxopt = (struct private_vxopt *)(qvxhdr + 1);
	if (ntohs(qvxopt->pvo_type) != PRIVATEOPT_PROTOCOL_STATS_REQUEST) {
		return true;
	}

	pvxhdr = make_openflow_xid(sizeof(*pvxhdr) + sizeof(*pvxopt)
				   + (sizeof(*ofps) * 2),
				   OFPT_VENDOR, qvxhdr->ofp_hdr.xid, &pbuf);
	pvxopt = (struct private_vxopt *)(pvxhdr + 1);
	pvxhdr->ofp_vxid = qvxhdr->ofp_vxid;
	pvxopt->pvo_type = htons(PRIVATEOPT_PROTOCOL_STATS_REPLY);
	pvxopt->pvo_len = htons(sizeof(*ofps) * 2);

	rconn_update_protocol_stat(context->remote_rconn,
				   &ofps_rcvd, &ofps_sent);
	ofps = (struct ofpstat *)((uint8_t *)(pvxhdr + 1) + sizeof(*pvxopt));
	COPY_OFP_STAT(ofps, &ofps_rcvd);
	ofps = ofps + 1;
	COPY_OFP_STAT(ofps, &ofps_sent);

	error = rconn_send(mgmt_rconn, pbuf, NULL);
	if (error && error != EAGAIN) {
		VLOG_WARN("send failed (%s)", strerror(error));
	}

	return true;
}

void
protocol_stat_start(struct secchan *secchan, const struct settings *settings,
		    struct rconn *local_rconn, struct rconn *remote_rconn)
{
	struct protocol_stat_context *context = NULL;
	static struct hook_class protocol_stat_hook_class = {
		NULL,		/* local_packet_cb */
		protocol_stat_remote_packet_cb,	/* remote_packet_cb */
		NULL,		/* periodic_cb */
		NULL,		/* wait_cb */
		NULL,		/* closing_cb */
	};

	context = xmalloc(sizeof(*context));
	context->settings = settings;
	context->secchan = secchan;
	context->local_rconn = local_rconn;
	context->remote_rconn = remote_rconn;
	memset(&context->ofps_rcvd, 0, sizeof(context->ofps_rcvd));
	memset(&context->ofps_sent, 0, sizeof(context->ofps_sent));

	add_hook(secchan, &protocol_stat_hook_class, context);
}
