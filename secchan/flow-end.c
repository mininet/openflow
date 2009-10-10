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

#include <config.h>
#include "flow-end.h"
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "secchan.h"
#include "ofpbuf.h"
#include "vconn.h"
#include "rconn.h"
#include "socket-util.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_flow_end
#include "vlog.h"

struct flow_end_data {
    struct rconn *remote_rconn;
    struct rconn *local_rconn;
};

static int
udp_open(char *dst)
{
    char *save_ptr;
    const char *host_name;
    const char *port_string;
    struct sockaddr_in sin;
    int retval;
    int fd;

    /* Glibc 2.7 has a bug in strtok_r when compiling with optimization that
     * can cause segfaults here:
     * http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
     * Using "::" instead of the obvious ":" works around it. */
    host_name = strtok_r(dst, "::", &save_ptr);
    port_string = strtok_r(NULL, "::", &save_ptr);
    if (!host_name) {
        ofp_error(0, "%s: bad peer name format", dst);
        return -EAFNOSUPPORT;
    }
    if (!port_string) {
        ofp_error(0, "%s: bad port format", dst);
        return -EAFNOSUPPORT;
    }

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    if (lookup_ip(host_name, &sin.sin_addr)) {
        return -ENOENT;
    }
    sin.sin_port = htons(atoi(port_string));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        VLOG_ERR("%s: socket: %s", dst, strerror(errno));
        return -errno;
    }

    retval = set_nonblocking(fd);
    if (retval) {
        close(fd);
        return -retval;
    }

    retval = connect(fd, (struct sockaddr *) &sin, sizeof sin);
    if (retval < 0) {
        int error = errno;
        VLOG_ERR("%s: connect: %s", dst, strerror(error));
        close(fd);
        return -error;
    }

    return fd;
}

static void 
send_ofp_expired(const struct nx_flow_end *nfe, const struct flow_end_data *fe)
{
    struct ofp_flow_removed *ofe;
    struct ofpbuf *b;

    if ((nfe->reason != NXFER_IDLE_TIMEOUT) 
            && (nfe->reason != NXFER_HARD_TIMEOUT)
            && (nfe->reason != NXFER_DELETE)) {
        return;
    }

    ofe = make_openflow(sizeof(*ofe), OFPT_FLOW_REMOVED, &b);
    ofe->match = nfe->match;
    ofe->priority = nfe->priority;
    if (nfe->reason == NXFER_IDLE_TIMEOUT) {
        ofe->reason = OFPRR_IDLE_TIMEOUT;
    } else if (nfe->reason == NXFER_HARD_TIMEOUT) {
        ofe->reason = OFPRR_HARD_TIMEOUT;
    } else {
        ofe->reason = OFPRR_DELETE;
    }
    /* 'duration' is in seconds, but we keeping track of milliseconds. */
    ofe->duration = htonl((ntohll(nfe->end_time)-ntohll(nfe->init_time))/1000);
    ofe->idle_timeout = nfe->idle_timeout;
    ofe->packet_count = nfe->packet_count;
    ofe->byte_count = nfe->byte_count;

    rconn_send(fe->remote_rconn, b, NULL);
}

static bool
flow_end_local_packet_cb(struct relay *r, void *flow_end_)
{
    struct flow_end_data *fe = flow_end_;
    struct ofpbuf *msg = r->halves[HALF_LOCAL].rxbuf;
    struct nicira_header *request = msg->data;
    struct nx_flow_end *nfe = msg->data;


    if (msg->size < sizeof(*nfe)) {
        return false;
    }
    request = msg->data;
    if (request->header.type != OFPT_VENDOR
        || request->vendor != htonl(NX_VENDOR_ID)
        || request->subtype != htonl(NXT_FLOW_END)) {
        return false;
    }

    if (nfe->send_flow_exp) {
        send_ofp_expired(nfe, fe);
    }

    /* We always consume these Flow End messages. */
    return true;
}

static bool
flow_end_remote_packet_cb(struct relay *r, void *flow_end_)
{
    struct flow_end_data *fe = flow_end_;
    struct ofpbuf *msg = r->halves[HALF_REMOTE].rxbuf;
    struct ofp_switch_config *osc = msg->data;

    /* Check for OFPT_SET_CONFIG messages to see if the controller wants
     * to receive 'flow expired' messages.  If so, we need to intercept
     * the datapath's 'flow end' meta-messages and convert. */

    if ((msg->size < sizeof(*osc)) 
            || (osc->header.type != OFPT_SET_CONFIG)) {
        return false;
    }

    /* Perform any processing of set config messages here */

    return false;
}

static struct hook_class flow_end_hook_class = {
    flow_end_local_packet_cb,   /* local_packet_cb */
    flow_end_remote_packet_cb,  /* remote_packet_cb */
    NULL,                       /* periodic_cb */
    NULL,                       /* wait_cb */
    NULL,                       /* closing_cb */
};

void
flow_end_start(struct secchan *secchan,
               struct rconn *local, struct rconn *remote)
{
    struct flow_end_data *fe;

    fe = xcalloc(1, sizeof *fe);

    fe->remote_rconn = remote;
    fe->local_rconn = local;

    add_hook(secchan, &flow_end_hook_class, fe);
}
