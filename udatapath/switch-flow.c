/* Copyright (c) 2008, 2009 The Board of Trustees of The Leland Stanford
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
#include "switch-flow.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "timeval.h"

#define THIS_MODULE VLM_chain
#include "vlog.h"

/* Internal function used to compare fields in flow. */
static inline int
flow_fields_match(const struct flow *a, const struct flow *b, uint32_t w,
                  uint32_t src_mask, uint32_t dst_mask)
{
    return ((w & OFPFW_IN_PORT || a->in_port == b->in_port)
            && (w & OFPFW_DL_VLAN || a->dl_vlan == b->dl_vlan)
            && (w & OFPFW_DL_VLAN_PCP || a->dl_vlan_pcp == b->dl_vlan_pcp)
            && (w & OFPFW_DL_SRC || eth_addr_equals(a->dl_src, b->dl_src))
            && (w & OFPFW_DL_DST || eth_addr_equals(a->dl_dst, b->dl_dst))
            && (w & OFPFW_DL_TYPE || a->dl_type == b->dl_type)
            && (w & OFPFW_NW_TOS || a->nw_tos == b->nw_tos)
            && (w & OFPFW_NW_PROTO || a->nw_proto == b->nw_proto)
            && !((a->nw_src ^ b->nw_src) & src_mask)
            && !((a->nw_dst ^ b->nw_dst) & dst_mask)
            && (w & OFPFW_TP_SRC || a->tp_src == b->tp_src)
            && (w & OFPFW_TP_DST || a->tp_dst == b->tp_dst));
}

static uint32_t make_nw_mask(int n_wild_bits)
{
    n_wild_bits &= (1u << OFPFW_NW_SRC_BITS) - 1;
    return n_wild_bits < 32 ? htonl(~((1u << n_wild_bits) - 1)) : 0;
}

/* Returns nonzero if 'a' and 'b' match, that is, if their fields are equal
 * modulo wildcards in 'b', zero otherwise. */
inline int
flow_matches_1wild(const struct sw_flow_key *a, const struct sw_flow_key *b)
{
    return flow_fields_match(&a->flow, &b->flow, b->wildcards,
                             b->nw_src_mask, b->nw_dst_mask);
}

/* Returns nonzero if 'a' and 'b' match, that is, if their fields are equal
 * modulo wildcards in 'a' or 'b', zero otherwise. */
inline int
flow_matches_2wild(const struct sw_flow_key *a, const struct sw_flow_key *b)
{
    return flow_fields_match(&a->flow, &b->flow, a->wildcards | b->wildcards,
                             a->nw_src_mask & b->nw_src_mask,
                             a->nw_dst_mask & b->nw_dst_mask);
}

/* Returns nonzero if 't' (the table entry's key) and 'd' (the key 
 * describing the match) match, that is, if their fields are 
 * equal modulo wildcards, zero otherwise.  If 'strict' is nonzero, the
 * wildcards must match in both 't_key' and 'd_key'.  Note that the
 * table's wildcards are ignored unless 'strict' is set. */
int
flow_matches_desc(const struct sw_flow_key *t, const struct sw_flow_key *d, 
        int strict)
{
    if (strict && d->wildcards != t->wildcards) {
        return 0;
    }
    return flow_matches_1wild(t, d);
}

/* Returns nonzero if 't' (the table entry's key) and 'd' (the key
 * describing the match) match, that is, if their fields are
 * equal modulo 't' or 'd' wildcards, zero otherwise.  If 'strict' is nonzero, the
 * wildcards must match in both 't_key' and 'd_key'.  Note that the
 * table's wildcards are ignored unless 'strict' is set. */
int
flow_matches_2desc(const struct sw_flow_key *t, const struct sw_flow_key *d,
        int strict)
{
    if (strict && d->wildcards != t->wildcards) {
        return 0;
    }
    return flow_matches_2wild(t, d);
}

void
flow_extract_match(struct sw_flow_key* to, const struct ofp_match* from)
{
    to->wildcards = ntohl(from->wildcards) & OFPFW_ALL;
    to->flow.dl_vlan_pcp = from->dl_vlan_pcp;
    to->flow.in_port = from->in_port;
    to->flow.dl_vlan = from->dl_vlan;
    memcpy(to->flow.dl_src, from->dl_src, ETH_ADDR_LEN);
    memcpy(to->flow.dl_dst, from->dl_dst, ETH_ADDR_LEN);
    to->flow.dl_type = from->dl_type;

    to->flow.nw_tos = to->flow.nw_proto = to->flow.nw_src = to->flow.nw_dst = 0;
    to->flow.tp_src = to->flow.tp_dst = 0;
    memset(to->flow.pad, 0, sizeof(to->flow.pad));

#define OFPFW_TP (OFPFW_TP_SRC | OFPFW_TP_DST)
#define OFPFW_NW (OFPFW_NW_TOS | OFPFW_NW_PROTO | OFPFW_NW_SRC_MASK | OFPFW_NW_DST_MASK)
    if (to->wildcards & OFPFW_DL_TYPE) {
        /* Can't sensibly match on network or transport headers if the
         * data link type is unknown. */
        to->wildcards |= OFPFW_NW | OFPFW_TP;
    } else if (from->dl_type == htons(ETH_TYPE_IP)) {
        to->flow.nw_tos   = from->nw_tos & 0xfc;
        to->flow.nw_proto = from->nw_proto;
        to->flow.nw_src   = from->nw_src;
        to->flow.nw_dst   = from->nw_dst;

        if (to->wildcards & OFPFW_NW_PROTO) {
            /* Can't sensibly match on transport headers if the network
             * protocol is unknown. */
            to->wildcards |= OFPFW_TP;
        } else if (from->nw_proto == IPPROTO_TCP 
                || from->nw_proto == IPPROTO_UDP
                || from->nw_proto == IPPROTO_ICMP) {
            to->flow.tp_src = from->tp_src;
            to->flow.tp_dst = from->tp_dst;
        } else {
            /* Transport layer fields are undefined.  Mark them as
             * exact-match to allow such flows to reside in table-hash,
             * instead of falling into table-linear. */
            to->wildcards &= ~OFPFW_TP;
        }
    } else if (from->dl_type == htons(ETH_TYPE_ARP)) {
        to->flow.nw_src   = from->nw_src;
        to->flow.nw_dst   = from->nw_dst;
        to->flow.nw_proto = from->nw_proto;

        /* Transport layer fields are undefined.  Mark them as
         * exact-match to allow such flows to reside in table-hash,
         * instead of falling into table-linear. */
        to->wildcards &= ~OFPFW_TP;
    } else {
        /* Network and transport layer fields are undefined.  Mark them
         * as exact-match to allow such flows to reside in table-hash,
         * instead of falling into table-linear. */
        to->wildcards &= ~(OFPFW_NW | OFPFW_TP);
    }

	/* We set these late because code above adjusts to->wildcards. */
	to->nw_src_mask = make_nw_mask(to->wildcards >> OFPFW_NW_SRC_SHIFT);
	to->nw_dst_mask = make_nw_mask(to->wildcards >> OFPFW_NW_DST_SHIFT);
}

/* Allocates and returns a new flow with room for 'actions_len' actions. 
 * Returns the new flow or a null pointer on failure. */
struct sw_flow *
flow_alloc(size_t actions_len)
{
    struct sw_flow_actions *sfa;
    size_t size = sizeof *sfa + actions_len;
    struct sw_flow *flow = calloc(1, sizeof *flow);
    if (!flow)
        return NULL;

    sfa = calloc(1, size);
    if (!sfa) {
        free(flow);
        return NULL;
    }
    sfa->actions_len = actions_len;
    flow->sf_acts = sfa;
    return flow;
}

/* Setup the action on the flow, just after it was created with flow_alloc().
 * Jean II */
void
flow_setup_actions(struct sw_flow *                    flow,
		   const struct ofp_action_header *     actions,
		   int                                  actions_len)
{
	/* Make sure we don't blow the allocation */
	if (actions_len > flow->sf_acts->actions_len)
		ofp_fatal(0,
			  "flow_setup_actions: actions_len is too big (%d > %lu)",
			  actions_len, (unsigned long)flow->sf_acts->actions_len);

	flow->used = flow->created = time_msec();
	flow->sf_acts->actions_len = actions_len;
	flow->byte_count = 0;
	flow->packet_count = 0;
	memcpy(flow->sf_acts->actions, actions, actions_len);
}

/* Frees 'flow' immediately. */
void
flow_free(struct sw_flow *flow)
{
    if (!flow) {
        return; 
    }
    free(flow->sf_acts);
    free(flow);
}

/* Copies 'actions' into a newly allocated structure for use by 'flow'
 * and frees the structure that defined the previous actions. */
void flow_replace_acts(struct sw_flow *flow, 
        const struct ofp_action_header *actions, size_t actions_len)
{
    struct sw_flow_actions *sfa;
    int size = sizeof *sfa + actions_len;

    sfa = malloc(size);
    if (unlikely(!sfa))
        return;

    sfa->actions_len = actions_len;
    memcpy(sfa->actions, actions, actions_len);

    free(flow->sf_acts);
    flow->sf_acts = sfa;

    return;
}

/* Prints a representation of 'key' to the kernel log. */
void
print_flow(const struct sw_flow_key *key)
{
    const struct flow *f = &key->flow;

    VLOG_INFO("wild %08x port %04x vlan-vid %04x vlan-pcp %02x "
              "src-mac %02x:%02x:%02x:%02x:%02x:%02x "
              "dst-mac %02x:%02x:%02x:%02x:%02x:%02x "
              "frm-type %04x ip-tos %02x ip-src %u.%u.%u.%u ip-dst %u.%u.%u.%u "
              "ip-proto %04x tp-src %d tp-dst %d pad %02x%02x%02x\n",
           key->wildcards, ntohs(f->in_port),
           ntohs(f->dl_vlan), f->dl_vlan_pcp,
           f->dl_src[0], f->dl_src[1], f->dl_src[2],
           f->dl_src[3], f->dl_src[4], f->dl_src[5],
           f->dl_dst[0], f->dl_dst[1], f->dl_dst[2],
           f->dl_dst[3], f->dl_dst[4], f->dl_dst[5],
           ntohs(f->dl_type),
           f->nw_tos,
           ((unsigned char *)&f->nw_src)[0],
           ((unsigned char *)&f->nw_src)[1],
           ((unsigned char *)&f->nw_src)[2],
           ((unsigned char *)&f->nw_src)[3],
           ((unsigned char *)&f->nw_dst)[0],
           ((unsigned char *)&f->nw_dst)[1],
           ((unsigned char *)&f->nw_dst)[2],
           ((unsigned char *)&f->nw_dst)[3],
           f->nw_proto,
           ntohs(f->tp_src), ntohs(f->tp_dst),
           f->pad[0], f->pad[1], f->pad[2]);
}

bool flow_timeout(struct sw_flow *flow)
{
    uint64_t now = time_msec();
    if (flow->idle_timeout != OFP_FLOW_PERMANENT
            && now > flow->used + flow->idle_timeout * 1000) {
        flow->reason = OFPRR_IDLE_TIMEOUT;
        return true;
    } else if (flow->hard_timeout != OFP_FLOW_PERMANENT
            && now > flow->created + flow->hard_timeout * 1000) {
        flow->reason = OFPRR_HARD_TIMEOUT;
        return true;
    } else {
        return false;
    }
}

/* Returns nonzero if 'flow' contains an output action to 'out_port' or
 * has the value OFPP_NONE. 'out_port' is in network-byte order. */
int flow_has_out_port(struct sw_flow *flow, uint16_t out_port)
{
    struct sw_flow_actions *sf_acts = flow->sf_acts;
    size_t actions_len = sf_acts->actions_len;
    uint8_t *p = (uint8_t *)sf_acts->actions;

    if (out_port == htons(OFPP_NONE))
        return 1;

    while (actions_len > 0) {
        struct ofp_action_header *ah = (struct ofp_action_header *)p;
        size_t len = ntohs(ah->len);

        if (ah->type == htons(OFPAT_OUTPUT)) {
            struct ofp_action_output *oa = (struct ofp_action_output *)p;
            if (oa->port == out_port) {
                return 1;
            }
        }
        p += len;
        actions_len -= len;
    }

    return 0;
}

void flow_used(struct sw_flow *flow, struct ofpbuf *buffer)
{
    flow->used = time_msec();

    flow->packet_count++;
    flow->byte_count += buffer->size;
}
