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

#include <arpa/inet.h>

#include <config.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>

#include "openflow/openflow.h"
#include "openflow/private-ext.h"

#include "util.h"
#include "vconn.h"
#include "rconn.h"
#include "secchan.h"
#include "status.h"
#include "timeval.h"
#include "sat-math.h"
#include "ofpbuf.h"
#include "emerg-flow.h"
#define THIS_MODULE VLM_emerg_flow
#include "vlog.h"

struct emerg_flow_context {
	const struct settings *settings;
	const struct secchan *secchan;
	struct rconn *local_rconn;
	struct rconn *remote_rconn;
	int prev_state;
	int state;
};

static void emerg_flow_status_cb(struct status_reply *, void *);
static void emerg_flow_periodic_cb(void *);

static void
emerg_flow_status_cb(struct status_reply *status_reply, void *context_)
{
	struct emerg_flow_context *context = context_;

	status_reply_put(status_reply, "state=%s",
			 context->state == PRIVATEOPT_EMERG_FLOW_RESTORATION
			 ? "restoration"
			 : context->state == PRIVATEOPT_EMERG_FLOW_PROTECTION
			 ? "protection" : "unknown");
}

static void
emerg_flow_periodic_cb(void *context_)
{
	struct emerg_flow_context *context = context_;
	struct ofpbuf *buf = NULL;
	struct private_vxhdr *vxhdr = NULL;
	struct private_vxopt *vxopt = NULL;
	int error = 0;

	if (rconn_is_connected(context->remote_rconn)) {
		if (context->state == PRIVATEOPT_EMERG_FLOW_PROTECTION) {
			context->prev_state = context->state;
			context->state = PRIVATEOPT_EMERG_FLOW_RESTORATION;
		} else {
			return;
		}
	} else {
		if (context->state == PRIVATEOPT_EMERG_FLOW_RESTORATION) {
			context->prev_state = context->state;
			context->state = PRIVATEOPT_EMERG_FLOW_PROTECTION;
		} else {
			return;
		}
	}

	vxhdr = (struct private_vxhdr *)make_openflow
		(sizeof(*vxhdr) + sizeof(*vxopt), OFPT_VENDOR, &buf);
	vxopt = (struct private_vxopt *)(vxhdr + 1);
	vxhdr->ofp_vxid = htonl(PRIVATE_VENDOR_ID);
	vxopt->pvo_type = htons(context->state);
	vxopt->pvo_len = htons(0);

	error = rconn_send(context->local_rconn, buf, NULL);
	if (error && error != EAGAIN) {
		VLOG_WARN("send failed (%s)", strerror(error));
	}
}

void
emerg_flow_start(struct secchan *secchan, const struct settings *settings,
		 struct switch_status *switch_status,
		 struct rconn *local_rconn, struct rconn *remote_rconn)
{
	struct emerg_flow_context *context = NULL;
	static struct hook_class emerg_flow_hook_class = {
		NULL,		/* local_packet_cb */
		NULL,		/* remote_packet_cb */
		emerg_flow_periodic_cb,	/* periodic_cb */
		NULL,		/* wait_cb */
		NULL,		/* closing_cb */
	};

	context = xmalloc(sizeof(*context));
	context->settings = settings;
	context->secchan = secchan;
	context->local_rconn = local_rconn;
	context->remote_rconn = remote_rconn;
	context->prev_state = PRIVATEOPT_EMERG_FLOW_PROTECTION;
	context->state = PRIVATEOPT_EMERG_FLOW_PROTECTION;

	switch_status_register_category(switch_status, "emerg-flow",
					emerg_flow_status_cb, context);
	add_hook(secchan, &emerg_flow_hook_class, context);
}
