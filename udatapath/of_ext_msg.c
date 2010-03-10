/* Copyright (c) 2009 The Board of Trustees of The Leland Stanford
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

#include <errno.h>
#include <arpa/inet.h>
#include "openflow/openflow-ext.h"
#include "of_ext_msg.h"
#include "netdev.h"
#include "datapath.h"

#define THIS_MODULE VLM_experimental
#include "vlog.h"

static int
new_queue(struct sw_port * port, struct sw_queue * queue,
          uint32_t queue_id, uint16_t class_id,
          struct ofp_queue_prop_min_rate * mr)
{
    memset(queue, '\0', sizeof *queue);
    queue->port = port;
    queue->queue_id = queue_id;
    /* class_id is the internal mapping to class. It is the offset
     * in the array of queues for each port. Note that class_id is
     * local to port, so we don't have any conflict.
     * tc uses 16-bit class_id, so we cannot use the queue_id
     * field */
    queue->class_id = class_id;
    queue->property = ntohs(mr->prop_header.property);
    queue->min_rate = ntohs(mr->rate);

    list_push_back(&port->queue_list, &queue->node);

    return 0;
}

static int
port_add_queue(struct sw_port *p, uint32_t queue_id,
               struct ofp_queue_prop_min_rate * mr)
{
    int queue_no;
    for (queue_no = 1; queue_no < p->num_queues; queue_no++) {
        struct sw_queue *q = &p->queues[queue_no];
        if (!q->port) {
            return new_queue(p,q,queue_id,queue_no,mr);
        }
    }
    return EXFULL;
}

static int
port_delete_queue(struct sw_port *p UNUSED, struct sw_queue *q)
{
    list_remove(&q->node);
    memset(q,'\0', sizeof *q);
    return 0;
}

static void
recv_of_exp_queue_delete(struct datapath *dp,
                         const struct sender *sender,
                         const void *oh)
{
    struct sw_port *p;
    struct sw_queue *q;
    struct openflow_queue_command_header * ofq_delete;
    struct ofp_packet_queue *opq;

    uint16_t port_no;
    uint32_t queue_id;

    ofq_delete = (struct openflow_queue_command_header *)oh;
    opq = (struct ofp_packet_queue *)ofq_delete->body;
    port_no = ntohs(ofq_delete->port);
    queue_id = ntohl(opq->queue_id);

    p = dp_lookup_port(dp,port_no);
    if (p->netdev) {
        q = dp_lookup_queue(p,queue_id);
        if (q) {
            netdev_delete_class(p->netdev,q->class_id);
            port_delete_queue(p,q);
        }
        else {
            dp_send_error_msg(dp, sender, OFPET_QUEUE_OP_FAILED,
                              OFPQOFC_BAD_PORT, oh,
                              ntohs(ofq_delete->header.header.length));
        }
    }
    else {
        dp_send_error_msg(dp, sender, OFPET_QUEUE_OP_FAILED,
                          OFPQOFC_BAD_PORT, oh,
                          ntohs(ofq_delete->header.header.length));
    }
}

/** Modifies/adds a queue. It first searches if a queue with
 * id exists for this port. If yes it modifies it, otherwise adds
 * a new configuration.
 *
 * @param dp the related datapath
 * @param sender request source
 * @param oh the openflow message for queue mod.
 */
static void
recv_of_exp_queue_modify(struct datapath *dp,
                         const struct sender *sender UNUSED,
                         const void *oh)
{
    struct sw_port *p;
    struct sw_queue *q;
    struct openflow_queue_command_header * ofq_modify;
    struct ofp_packet_queue *opq;
    struct ofp_queue_prop_min_rate *mr;

    int error = 0;
    uint16_t port_no;
    uint32_t queue_id;


    ofq_modify = (struct openflow_queue_command_header *)oh;
    opq = (struct ofp_packet_queue *)ofq_modify->body;
    mr = (struct ofp_queue_prop_min_rate*)opq->properties;

    /* Currently, we only accept queues with a single, min-rate property */
    if ((ntohs(opq->len) != 24) ||
        ntohs(mr->prop_header.property) != OFPQT_MIN_RATE) {
        VLOG_ERR("Unknown queue configuration");
        dp_send_error_msg(dp, sender, OFPET_QUEUE_OP_FAILED,
                          OFQ_ERR_DISCIPLINE, oh,
                          ntohs(ofq_modify->header.header.length));
        return;
    }



    port_no = ntohs(ofq_modify->port);
    queue_id = ntohl(opq->queue_id);

    p = dp_lookup_port(dp, port_no);
    if (PORT_IN_USE(p)) {
        q = dp_lookup_queue(p, queue_id);
        if (q) {
            /* queue exists - modify it */
            error = netdev_change_class(p->netdev,q->class_id, ntohs(mr->rate));
            if (error) {
                VLOG_ERR("Failed to update queue %d", queue_id);
                dp_send_error_msg(dp, sender, OFPET_QUEUE_OP_FAILED,
                                  OFPQOFC_EPERM, oh,
                                  ntohs(ofq_modify->header.header.length));
            }
            else {
                q->property = ntohs(mr->prop_header.property);
                q->min_rate = ntohs(mr->rate);
            }
        }
        else {
            /* create new queue */
            error = port_add_queue(p,queue_id, mr);
            if (error == EXFULL) {
                dp_send_error_msg(dp, sender, OFPET_QUEUE_OP_FAILED,
                                  OFPQOFC_EPERM, oh,
                                  ntohs(ofq_modify->header.header.length));
                return;
            }
            q = dp_lookup_queue(p, queue_id);
            error = netdev_setup_class(p->netdev,q->class_id, ntohs(mr->rate));
            if (error) {
                VLOG_ERR("Failed to configure queue %d", queue_id);
                dp_send_error_msg(dp, sender, OFPET_QUEUE_OP_FAILED,
                                  OFPQOFC_BAD_QUEUE, oh,
                                  ntohs(ofq_modify->header.header.length));
            }
        }
    }
    else {
        dp_send_error_msg(dp, sender, OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT,
                          oh, ntohs(ofq_modify->header.header.length));
        VLOG_ERR("Failed to create/modify queue - port %d doesn't exist",
                 port_no);
    }
    if (!error) {
        if (IS_HW_PORT(p)) {
#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
            error = dp->hw_drv->port_queue_config(dp->hw_drv, port_no,
                                                  queue_id, ntohs(mr->rate));
            if (error < 0) {
                VLOG_ERR("Failed to update HW port %d queue %d",
                         port_no, queue_id);
            }
#endif
        }
    }
}
/**
 * Parses a set dp_desc message and uses it to set
 *  the dp_desc string in dp
 */
static void
recv_of_set_dp_desc(struct datapath *dp,
                         const struct sender *sender UNUSED,
                         const struct ofp_extension_header * exth)
{
    struct openflow_ext_set_dp_desc * set_dp_desc = (struct openflow_ext_set_dp_desc * )
        exth;
    strncpy(dp->dp_desc, set_dp_desc->dp_desc, DESC_STR_LEN);
    dp->dp_desc[DESC_STR_LEN-1] = 0;        // force null for safety
}

/**
 * Receives an experimental message and pass it
 * to the appropriate handler
 */
int of_ext_recv_msg(struct datapath *dp, const struct sender *sender,
        const void *oh)
{
    const struct ofp_extension_header  *ofexth = oh;

    switch (ntohl(ofexth->subtype)) {
    case OFP_EXT_QUEUE_MODIFY: {
        recv_of_exp_queue_modify(dp,sender,oh);
        return 0;
    }
    case OFP_EXT_QUEUE_DELETE: {
        recv_of_exp_queue_delete(dp,sender,oh);
        return 0;
    }
    case OFP_EXT_SET_DESC:
        recv_of_set_dp_desc(dp,sender,ofexth);
        return 0;
    default:
        VLOG_ERR("Received unknown command of type %d",
                 ntohl(ofexth->subtype));
        return -EINVAL;
    }

    return -EINVAL;
}
