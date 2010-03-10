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

/* Interface exported by OpenFlow module. */

#ifndef DATAPATH_H
#define DATAPATH_H 1

#include <stdbool.h>
#include <stdint.h>
#include "openflow/nicira-ext.h"
#include "ofpbuf.h"
#include "timeval.h"
#include "list.h"
#include "netdev.h"

/* FIXME:  Can declare struct of_hw_driver instead */
#if defined(OF_HW_PLAT)
#include <openflow/of_hw_api.h>
#endif

struct rconn;
struct pvconn;
struct sw_flow;
struct sender;

struct sw_queue {
    struct list node; /* element in port.queues */
    unsigned long long int tx_packets;
    unsigned long long int tx_bytes;
    unsigned long long int tx_errors;
    uint32_t queue_id;
    uint16_t class_id; /* internal mapping from OF queue_id to tc class_id */
    struct sw_port *port; /* reference to the parent port */
    /* keep it simple for now, only one property (assuming min_rate) */
    uint16_t property; /* one from OFPQT_ */
    uint16_t min_rate;
};

#define MAX_HW_NAME_LEN 32
enum sw_port_flags {
    SWP_USED             = 1 << 0,    /* Is port being used */
    SWP_HW_DRV_PORT      = 1 << 1,    /* Port controlled by HW driver */
};
#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
#define IS_HW_PORT(p) ((p)->flags & SWP_HW_DRV_PORT)
#else
#define IS_HW_PORT(p) 0
#endif

#define PORT_IN_USE(p) (((p) != NULL) && (p)->flags & SWP_USED)

struct sw_port {
    uint32_t config;            /* Some subset of OFPPC_* flags. */
    uint32_t state;             /* Some subset of OFPPS_* flags. */
    uint32_t flags;             /* SWP_* flags above */
    struct datapath *dp;
    struct netdev *netdev;
    char hw_name[OFP_MAX_PORT_NAME_LEN];
    struct list node; /* Element in datapath.ports. */
    unsigned long long int rx_packets, tx_packets;
    unsigned long long int rx_bytes, tx_bytes;
    unsigned long long int tx_dropped;
    uint16_t port_no;
    /* port queues */
    uint16_t num_queues;
    struct sw_queue queues[NETDEV_MAX_QUEUES];
    struct list queue_list; /* list of all queues for this port */
};

#if defined(OF_HW_PLAT)
struct hw_pkt_q_entry {
    struct ofpbuf *buffer;
    struct hw_pkt_q_entry *next;
    of_port_t port_no;
    int reason;
};
#endif

#define DP_MAX_PORTS 255
BUILD_ASSERT_DECL(DP_MAX_PORTS <= OFPP_MAX);

struct datapath {
    /* Remote connections. */
    struct list remotes;        /* All connections (including controller). */

    /* Listeners. */
    struct pvconn **listeners;
    size_t n_listeners;

    time_t last_timeout;

    /* Unique identifier for this datapath */
    uint64_t  id;
    char dp_desc[DESC_STR_LEN];	/* human readible comment to ID this DP */

    struct sw_chain *chain;  /* Forwarding rules. */

    /* Configuration set from controller. */
    uint16_t flags;
    uint16_t miss_send_len;

    /* Switch ports. */
    struct sw_port ports[DP_MAX_PORTS];
    struct sw_port *local_port;  /* OFPP_LOCAL port, if any. */
    struct list port_list; /* All ports, including local_port. */

#if defined(OF_HW_PLAT)
    /* Although the chain maintains the pointer to the HW driver
     * for flow operations, the datapath needs the port functions
     * in the driver structure
     */
    of_hw_driver_t *hw_drv;
    struct hw_pkt_q_entry *hw_pkt_list_head, *hw_pkt_list_tail;
#endif
};

int dp_new(struct datapath **, uint64_t dpid);
int dp_add_port(struct datapath *, const char *netdev, uint16_t);
int dp_add_local_port(struct datapath *, const char *netdev, uint16_t);
void dp_add_pvconn(struct datapath *, struct pvconn *);
void dp_run(struct datapath *);
void dp_wait(struct datapath *);
void dp_send_error_msg(struct datapath *, const struct sender *,
                  uint16_t, uint16_t, const void *, size_t);
void dp_send_flow_end(struct datapath *, struct sw_flow *,
                      enum ofp_flow_removed_reason);
void dp_output_port(struct datapath *, struct ofpbuf *, int in_port, 
                    int out_port, uint32_t queue_id, bool ignore_no_fwd);
void dp_output_control(struct datapath *, struct ofpbuf *, int in_port,
        size_t max_len, int reason);
struct sw_port * dp_lookup_port(struct datapath *, uint16_t);
struct sw_queue * dp_lookup_queue(struct sw_port *, uint32_t);

int udatapath_cmd(int argc, char *argv[]);

#endif /* datapath.h */
