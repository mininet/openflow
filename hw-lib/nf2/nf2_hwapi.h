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

#ifndef HATABLE_NF2_NF2_OPENFLOW_H_
#define HATABLE_NF2_NF2_OPENFLOW_H_

#define OPENFLOW_NF2_EXACT_TABLE_SIZE	32768
#define WATCHDOG_ENABLE 1
#define WATCHDOG_DISABLE 0

#pragma pack(push)		/* push current alignment to stack */
#pragma pack(1)			/* set alignment to 1 byte boundary */

#define NF2_OF_ENTRY_WORD_LEN	8
struct nf2_of_entry {
	uint16_t transp_dst;
	uint16_t transp_src;
	uint8_t ip_proto;
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t eth_type;
	uint8_t eth_dst[6];
	uint8_t eth_src[6];
	uint8_t src_port;
	uint8_t ip_tos;
	uint16_t vlan_id;
	uint8_t pad;
};

typedef union nf2_of_entry_wrap {
	struct nf2_of_entry entry;
	uint32_t raw[NF2_OF_ENTRY_WORD_LEN];
} nf2_of_entry_wrap;

typedef nf2_of_entry_wrap nf2_of_mask_wrap;
#define NF2_OF_MASK_WORD_LEN	8

struct nf2_of_action {
	uint16_t forward_bitmask;
	uint16_t nf2_action_flag;
	uint16_t vlan_id;
	uint8_t vlan_pcp;
	uint8_t eth_src[6];
	uint8_t eth_dst[6];
	uint32_t ip_src;
	uint32_t ip_dst;
	uint8_t ip_tos;
	uint16_t transp_src;
	uint16_t transp_dst;
	uint8_t reserved[18];
};

#define NF2_OF_ACTION_WORD_LEN	10
typedef union nf2_of_action_wrap {
	struct nf2_of_action action;
	uint32_t raw[10];
} nf2_of_action_wrap;

struct nf2_of_exact_counters {
	uint32_t pkt_count:25;
	uint8_t last_seen:7;
	uint32_t byte_count;
};

#define NF2_OF_EXACT_COUNTERS_WORD_LEN	2
typedef union nf2_of_exact_counters_wrap {
	struct nf2_of_exact_counters counters;
	uint32_t raw[NF2_OF_EXACT_COUNTERS_WORD_LEN];
} nf2_of_exact_counters_wrap;

#define NF2_PORT_NUM 4
struct nf2_all_ports_info_addr {
	unsigned int rx_q_num_pkts_stored_reg[NF2_PORT_NUM];
	unsigned int rx_q_num_pkts_dropped_full_reg[NF2_PORT_NUM];
	unsigned int rx_q_num_pkts_dropped_bad_reg[NF2_PORT_NUM];
	unsigned int rx_q_num_words_pushed_reg[NF2_PORT_NUM];
	unsigned int rx_q_num_bytes_pushed_reg[NF2_PORT_NUM];
	unsigned int rx_q_num_pkts_dequeued_reg[NF2_PORT_NUM];
	unsigned int rx_q_num_pkts_in_queue_reg[NF2_PORT_NUM];
	unsigned int tx_q_num_pkts_in_queue_reg[NF2_PORT_NUM];
	unsigned int tx_q_num_pkts_sent_reg[NF2_PORT_NUM];
	unsigned int tx_q_num_words_pushed_reg[NF2_PORT_NUM];
	unsigned int tx_q_num_bytes_pushed_reg[NF2_PORT_NUM];
	unsigned int tx_q_num_pkts_enqueued_reg[NF2_PORT_NUM];
};

struct nf2_port_info {
	uint32_t rx_q_num_pkts_stored;
	uint32_t rx_q_num_pkts_dropped_full;
	uint32_t rx_q_num_pkts_dropped_bad;
	uint32_t rx_q_num_words_pushed;
	uint32_t rx_q_num_bytes_pushed;
	uint32_t rx_q_num_pkts_dequeued;
	uint32_t rx_q_num_pkts_in_queue;
	uint32_t tx_q_num_pkts_in_queue;
	uint32_t tx_q_num_pkts_sent;
	uint32_t tx_q_num_words_pushed;
	uint32_t tx_q_num_bytes_pushed;
	uint32_t tx_q_num_pkts_enqueued;
};

#pragma pack(pop)		/* XXX: Restore original alignment from stack */

void nf2_reset_card(struct nf2device *);
void nf2_clear_watchdog(struct nf2device *);
int nf2_write_of_wildcard(struct nf2device *, int, nf2_of_entry_wrap *,
			  nf2_of_mask_wrap *, nf2_of_action_wrap *);
int nf2_write_of_exact(struct nf2device *, int, nf2_of_entry_wrap *,
		       nf2_of_action_wrap *);
int nf2_modify_write_of_wildcard(struct nf2device *, int, nf2_of_entry_wrap *,
				 nf2_of_mask_wrap *, nf2_of_action_wrap *);
int nf2_modify_write_of_exact(struct nf2device *, int, nf2_of_action_wrap *);
unsigned int nf2_get_exact_packet_count(struct nf2device *, int);
unsigned int nf2_get_exact_byte_count(struct nf2device *, int);
unsigned int nf2_get_wildcard_packet_count(struct nf2device *, int);
unsigned int nf2_get_wildcard_byte_count(struct nf2device *, int);
unsigned long int nf2_get_matched_count(struct nf2device *);
unsigned long int nf2_get_missed_count(struct nf2device *);
int nf2_get_port_info(struct nf2device *, int, struct nf2_port_info *);

#endif
