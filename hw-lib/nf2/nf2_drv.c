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
#include <unistd.h>
#include <time.h>

#include "udatapath/switch-flow.h"
#include "udatapath/table.h"
#include "timeval.h"
#include "reg_defines_openflow_switch.h"
#include "nf2.h"
#include "nf2util.h"
#include "hw_flow.h"
#include "nf2_drv.h"
#include "nf2_lib.h"
#include "debug.h"

static void log_entry(nf2_of_entry_wrap *);
static void log_entry_raw(nf2_of_entry_wrap *);
static void log_mask(nf2_of_mask_wrap *);
static void log_mask_raw(nf2_of_mask_wrap *);
static void log_action(nf2_of_action_wrap *);
static void log_action_raw(nf2_of_action_wrap *);
static void log_watchdog_info(struct nf2device *);
static void nf2_get_all_ports_info_addr(struct nf2_all_ports_info_addr *);

static void
log_entry(nf2_of_entry_wrap *entry)
{
	int i;

	DBG_VERBOSE("log entry\n");
#ifdef HWTABLE_NO_DEBUG
	return;
#else

	// Log the physical source port
	DBG_VERBOSE("E psrc[%i] ", entry->entry.src_port / 2);

	// Log the link layer source
	DBG_VERBOSE("dlsrc[");
	for (i = 5; i > 0; --i) {
		DBG_VERBOSE("%0X:", entry->entry.eth_src[i]);
	}
	DBG_VERBOSE("%0X] ", entry->entry.eth_src[0]);

	// Log the link layer dest
	DBG_VERBOSE("dldst[");
	for (i = 5; i > 0; --i) {
		DBG_VERBOSE("%0X:", entry->entry.eth_dst[i]);
	}
	DBG_VERBOSE("%0X] ", entry->entry.eth_dst[0]);

	// Log the link layer type
	DBG_VERBOSE("dltype[%0X] ", entry->entry.eth_type);

	// Log the link layer vlan
	DBG_VERBOSE("dlvlan[%0X] ", entry->entry.vlan_id);

	// Log the network source
	DBG_VERBOSE("nwsrc[");
	DBG_VERBOSE("%0i.", (entry->entry.ip_src >> 24) & 0xFF);
	DBG_VERBOSE("%0i.", (entry->entry.ip_src >> 16) & 0xFF);
	DBG_VERBOSE("%0i.", (entry->entry.ip_src >> 8) & 0xFF);
	DBG_VERBOSE("%0i", entry->entry.ip_src & 0xFF);
	DBG_VERBOSE("] ");

	// Log the network dest
	DBG_VERBOSE("nwdst[");
	DBG_VERBOSE("%0i.", (entry->entry.ip_dst >> 24) & 0xFF);
	DBG_VERBOSE("%0i.", (entry->entry.ip_dst >> 16) & 0xFF);
	DBG_VERBOSE("%0i.", (entry->entry.ip_dst >> 8) & 0xFF);
	DBG_VERBOSE("%0i", entry->entry.ip_dst & 0xFF);
	DBG_VERBOSE("] ");

	// Log the network TOS
	DBG_VERBOSE("nwtos[0x%0X] ", entry->entry.ip_tos);

	// Log the transport source port
	DBG_VERBOSE("tsrc[%i] ", entry->entry.transp_src);

	// Log the transport dest port
	DBG_VERBOSE("tdst[%i]\n", entry->entry.transp_dst);
#endif
}

static void
log_entry_raw(nf2_of_entry_wrap *entry)
{
#ifdef HWTABLE_NO_DEBUG
	return;
#else
	int i;
	unsigned char *c;

	DBG_VERBOSE("E ");
	c = (unsigned char *)entry;
	for (i = 0; i < sizeof(nf2_of_entry_wrap); ++i) {
		if (!(i % 4)) {
			DBG_VERBOSE(" ");
		}
		DBG_VERBOSE("%02x", c[i]);
	}
	DBG_VERBOSE("\n");
#endif
}

static void
log_mask(nf2_of_mask_wrap *mask)
{
#ifdef HWTABLE_NO_DEBUG
	return;
#else
	int i;

	// Log the physical source port
	DBG_VERBOSE("M psrc[%0X] ", mask->entry.src_port / 2);

	// Log the link layer source
	DBG_VERBOSE("dlsrc[");
	for (i = 5; i > 0; --i) {
		DBG_VERBOSE("%0X:", mask->entry.eth_src[i]);
	}
	DBG_VERBOSE("%0X] ", mask->entry.eth_src[0]);

	// Log the link layer dest
	DBG_VERBOSE("dldst[");
	for (i = 5; i > 0; --i) {
		DBG_VERBOSE("%0X:", mask->entry.eth_dst[i]);
	}
	DBG_VERBOSE("%0X] ", mask->entry.eth_dst[0]);

	// Log the link layer type
	DBG_VERBOSE("dltype[%0X] ", mask->entry.eth_type);

	// Log the link layer vlan
	DBG_VERBOSE("dlvlan[%0X] ", mask->entry.vlan_id);

	// Log the network source
	DBG_VERBOSE("nwsrc[");
	DBG_VERBOSE("%0X.", (mask->entry.ip_src >> 24) & 0xFF);
	DBG_VERBOSE("%0X.", (mask->entry.ip_src >> 16) & 0xFF);
	DBG_VERBOSE("%0X.", (mask->entry.ip_src >> 8) & 0xFF);
	DBG_VERBOSE("%0X", mask->entry.ip_src & 0xFF);
	DBG_VERBOSE("] ");

	// Log the network dest
	DBG_VERBOSE("nwdst[");
	DBG_VERBOSE("%0X.", (mask->entry.ip_dst >> 24) & 0xFF);
	DBG_VERBOSE("%0X.", (mask->entry.ip_dst >> 16) & 0xFF);
	DBG_VERBOSE("%0X.", (mask->entry.ip_dst >> 8) & 0xFF);
	DBG_VERBOSE("%0X", mask->entry.ip_dst & 0xFF);
	DBG_VERBOSE("] ");

	// Log the network TOS
	DBG_VERBOSE("nwtos[0x%0X] ", mask->entry.ip_tos);

	// Log the transport source port
	DBG_VERBOSE("tsrc[%0X] ", mask->entry.transp_src);

	// Log the transport dest port
	DBG_VERBOSE("tdst[%0X]\n", mask->entry.transp_dst);
#endif
}

static void
log_mask_raw(nf2_of_mask_wrap *mask)
{
#ifdef HWTABLE_NO_DEBUG
	return;
#else
	int i;
	unsigned char *c;

	DBG_VERBOSE("M ");
	c = (unsigned char *)mask;
	for (i = 0; i < sizeof(nf2_of_mask_wrap); ++i) {
		if (!(i % 4)) {
			DBG_VERBOSE(" ");
		}
		DBG_VERBOSE("%02x", c[i]);
	}
	DBG_VERBOSE("\n");
#endif
}

static void
log_action(nf2_of_action_wrap *action)
{
#ifdef HWTABLE_NO_DEBUG
	return;
#else
	int i;

	DBG_VERBOSE("A Output P[");
	for (i = 0; i < 4; ++i) {
		if (action->action.forward_bitmask & (1 << (i * 2))) {
			DBG_VERBOSE("%i", i);
		}
	}
	DBG_VERBOSE("] CPU[");
	for (i = 0; i < 4; ++i) {
		if (action->action.forward_bitmask & (1 << (1 + (i * 2)))) {
			DBG_VERBOSE("%i", i);
		}
	}
	DBG_VERBOSE("]\n");

	// Log the link layer source
	if (action->action.nf2_action_flag & (1 << OFPAT_SET_DL_SRC)) {
		DBG_VERBOSE("A Modify: dlsrc: new value [");
		for (i = 5; i > 0; --i) {
			DBG_VERBOSE("%0X:", action->action.eth_src[i]);
		}
		DBG_VERBOSE("%0X]\n", action->action.eth_src[0]);
	}

	// Log the link layer dest
	if (action->action.nf2_action_flag & (1 << OFPAT_SET_DL_DST)) {
		DBG_VERBOSE("A Modify: dldst: new value [");
		for (i = 5; i > 0; --i) {
			DBG_VERBOSE("%0X:", action->action.eth_dst[i]);
		}
		DBG_VERBOSE("%0X]\n", action->action.eth_dst[0]);
	}

	// Log the link layer vlan id
	if (action->action.nf2_action_flag & (1 << OFPAT_SET_VLAN_VID)) {
		DBG_VERBOSE("A Modify: dlvlanid: new value [%0X]\n",
		    action->action.vlan_id);
	}

	// Log the link layer vlan pcp
	if (action->action.nf2_action_flag & (1 << OFPAT_SET_VLAN_PCP)) {
		DBG_VERBOSE("A Modify: dlvlanpcp: new value [%0X]\n",
		    action->action.vlan_pcp);
	}

	// Log the link layer vlan strip
	if (action->action.nf2_action_flag & (1 << OFPAT_STRIP_VLAN)) {
		DBG_VERBOSE("A Modify: dlvlan strip\n");
	}

	// Log the network source
	if (action->action.nf2_action_flag & (1 << OFPAT_SET_NW_SRC)) {
		DBG_VERBOSE("A Modify: nwsrc: new value [");
		DBG_VERBOSE("%0i.", (action->action.ip_src >> 24) & 0xFF);
		DBG_VERBOSE("%0i.", (action->action.ip_src >> 16) & 0xFF);
		DBG_VERBOSE("%0i.", (action->action.ip_src >> 8) & 0xFF);
		DBG_VERBOSE("%0i", action->action.ip_src & 0xFF);
		DBG_VERBOSE("]\n");
	}

	// Log the network dest
	if (action->action.nf2_action_flag & (1 << OFPAT_SET_NW_DST)) {
		DBG_VERBOSE("A Modify: nwdst: new value [");
		DBG_VERBOSE("%0i.", (action->action.ip_dst >> 24) & 0xFF);
		DBG_VERBOSE("%0i.", (action->action.ip_dst >> 16) & 0xFF);
		DBG_VERBOSE("%0i.", (action->action.ip_dst >> 8) & 0xFF);
		DBG_VERBOSE("%0i", action->action.ip_dst & 0xFF);
		DBG_VERBOSE("]\n");
	}

	// Log the network TOS
	if (action->action.nf2_action_flag & (1 << OFPAT_SET_NW_TOS)) {
		DBG_VERBOSE("A Modify: nwtos: new value [%0X]\n",
		    action->action.ip_tos & 0xFF);
	}

	// Log the transport source port
	if (action->action.nf2_action_flag & (1 << OFPAT_SET_TP_SRC)) {
		DBG_VERBOSE("A Modify: tsrc: new value [%0X]\n",
		    action->action.transp_src);
	}

	// Log the transport dest port
	if (action->action.nf2_action_flag & (1 << OFPAT_SET_TP_DST)) {
		DBG_VERBOSE("A Modify: tdst: new value [%0X]\n",
		    action->action.transp_dst);
	}
#endif
}

static void
log_action_raw(nf2_of_action_wrap *action)
{
#ifdef HWTABLE_NO_DEBUG
	return;
#else
	int i;
	unsigned char *c;

	DBG_VERBOSE("A ");
	c = (unsigned char *)action;
	for (i = 0; i < sizeof(nf2_of_action_wrap); ++i) {
		if (!(i % 4)) {
			DBG_VERBOSE(" ");
		}
		DBG_VERBOSE("%02x", c[i]);
	}
	DBG_VERBOSE("\n");
#endif
}

void
nf2_reset_card(struct nf2device *dev)
{
	volatile unsigned int val;

	/* If we are operating on a NetFPGA enabled box, reset the card */
	readReg(dev, CPCI_REG_CTRL, (void *)&val);
	val |= 0x100;
	writeReg(dev, CPCI_REG_CTRL, val);
	DBG_VERBOSE("Reset the NetFPGA.\n");
	sleep(2);
}

void
nf2_clear_watchdog(struct nf2device *dev)
{
	volatile unsigned int enable_status;

#ifndef NF2_WATCHDOG
	return;
#endif
	log_watchdog_info(dev);

	readReg(dev, WDT_ENABLE_FLG_REG, (void *)&enable_status);
	enable_status &= 0x1;

	if (enable_status == WATCHDOG_DISABLE) {
		enable_status = WATCHDOG_ENABLE;
		writeReg(dev, WDT_ENABLE_FLG_REG, enable_status);
	}
}

/* Write a wildcard entry to the specified device and row. The row consists of
 * the actual entry, its mask that specifies wildcards, as well as the action(s)
 * to be taken if the row is matched
 */
int
nf2_write_of_wildcard(struct nf2device *dev, int row,
		      nf2_of_entry_wrap *entry, nf2_of_mask_wrap *mask,
		      nf2_of_action_wrap *action)
{
	int i;
	unsigned int val;

	DBG_VERBOSE("** Begin wildcard entry write to row: %i\n", row);
	log_entry(entry);
	log_mask(mask);
	log_action(action);
	log_entry_raw(entry);
	log_mask_raw(mask);
	log_action_raw(action);

	for (i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		writeReg(dev,
			       OPENFLOW_WILDCARD_LOOKUP_CMP_0_REG
			       + (4 * i), entry->raw[i]);
	}

	for (i = 0; i < NF2_OF_MASK_WORD_LEN; ++i) {
		writeReg(dev,
			       OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_0_REG
			       + (4 * i), mask->raw[i]);
	}

	for (i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		writeReg(dev,
			       OPENFLOW_WILDCARD_LOOKUP_ACTION_0_REG
			       + (4 * i), action->raw[i]);
	}

	// Reset the stats for the row
	val = 0;
	writeReg(dev,
		       OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG + (4 * row),
		       val);
	writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG + (4 * row),
		       val);
	writeReg(dev,
		       OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_0_REG + (4 * row),
		       val);
	writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_WRITE_ADDR_REG, row);

	DBG_VERBOSE("** End wildcard entry write to row: %i time(msec): %llu\n",
		    row, time_msec());

	return 0;
}

int
nf2_write_of_exact(struct nf2device *dev, int row,
		   nf2_of_entry_wrap *entry, nf2_of_action_wrap *action)
{
	int i;
	unsigned int val;
	unsigned int index = row << 7;

	DBG_VERBOSE("** Begin exact match entry write to row: %i\n", row);
	log_entry(entry);
	log_action(action);
	log_entry_raw(entry);
	log_action_raw(action);

	for (i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		writeReg(dev, SRAM_BASE_ADDR + index
			       + (4 * i), entry->raw[i]);
	}

	// blank out the counters
	val = 0;
	for (i = 0; i < NF2_OF_EXACT_COUNTERS_WORD_LEN; ++i) {
		writeReg(dev, SRAM_BASE_ADDR + index
			       + sizeof(nf2_of_entry_wrap)
			       + (4 * i), val);
	}

	// write the actions
	for (i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		writeReg(dev, SRAM_BASE_ADDR + index
			       + sizeof(nf2_of_entry_wrap)
			       + sizeof(nf2_of_exact_counters_wrap)
			       + (4 * i), action->raw[i]);
	}

	DBG_VERBOSE
	    ("** End exact match entry write to row: %i time(msec): %llu\n",
	     row, time_msec());

	return 0;
}

/* Write wildcard action(s) to the specified device and row. */
int
nf2_modify_write_of_wildcard(struct nf2device *dev, int row,
			     nf2_of_entry_wrap *entry, nf2_of_mask_wrap *mask,
			     nf2_of_action_wrap *action)
{
	int i;
	unsigned int bytes_reg_val;
	unsigned int pkts_reg_val;
	unsigned int last_reg_val;

	DBG_VERBOSE("** Begin wildcard modified action write to row: %i\n",
		    row);
	log_entry(entry);
	log_mask(mask);
	log_action(action);
	log_entry_raw(entry);
	log_mask_raw(mask);
	log_action_raw(action);

	writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, row);
	readReg(dev,
		      OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG + (4 * row),
		      &bytes_reg_val);
	readReg(dev,
		      OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG + (4 * row),
		      &pkts_reg_val);
	readReg(dev,
		      OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_0_REG + (4 * row),
		      &last_reg_val);

	for (i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_0_REG
			       + (4 * i), entry->raw[i]);
	}

	for (i = 0; i < NF2_OF_MASK_WORD_LEN; ++i) {
		writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_0_REG
			       + (4 * i), mask->raw[i]);
	}

	for (i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_ACTION_0_REG
			       + (4 * i), action->raw[i]);
	}

	writeReg(dev,
		       OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG + (4 * row),
		       bytes_reg_val);
	writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG + (4 * row),
		       pkts_reg_val);
	writeReg(dev,
		       OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_0_REG + (4 * row),
		       last_reg_val);
	writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_WRITE_ADDR_REG, row);

	DBG_VERBOSE
	    ("** End wildcard modified action write to row: %i time(msec): %llu\n",
	     row, time_msec());
	DBG_VERBOSE("   Bytes hit count: %d\n", bytes_reg_val);
	DBG_VERBOSE("   Pkts  hit count: %d\n", pkts_reg_val);
	DBG_VERBOSE("   Last seen      : %d\n", last_reg_val);

	return 0;
}

int
nf2_modify_write_of_exact(struct nf2device *dev, int row,
			  nf2_of_action_wrap *action)
{
	int i;
	unsigned int index = row << 7;

	DBG_VERBOSE("** Begin exact match modified action write to row: %i\n",
		    row);
	log_action(action);
	log_action_raw(action);

	// write the actions
	for (i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		writeReg(dev, SRAM_BASE_ADDR + index
			       + sizeof(nf2_of_entry_wrap)
			       + sizeof(nf2_of_exact_counters_wrap)
			       + (4 * i), action->raw[i]);
	}

	DBG_VERBOSE
	    ("** End exact match modified action write to row: %i time(msec): %llu\n",
	     row, time_msec());

	return 0;
}

unsigned int
nf2_get_exact_packet_count(struct nf2device *dev, int row)
{
	unsigned int val = 0;
	unsigned int index = 0;

	/* TODO: Need to scrape data from all 4 registers
	 * in the case of a wildcarded source port and
	 * forward all action type
	 */
	nf2_of_exact_counters_wrap counters;
	memset(&counters, 0, sizeof(nf2_of_exact_counters_wrap));

	// build the index to our counters
	index = row << 7;

	// Read the first word into our struct, to not disturb the byte count
	readReg(dev,
		      SRAM_BASE_ADDR + index + sizeof(nf2_of_entry_wrap),
		      &counters.raw[0]);
	val = counters.counters.pkt_count;

	DBG_VERBOSE
	    ("** Exact match packet count(delta) row: %i count: %i time(msec): %llu\n",
	     row, val, time_msec());

	return val;
}

unsigned int
nf2_get_exact_byte_count(struct nf2device *dev, int row)
{
	unsigned int val = 0;
	unsigned int index = 0;

	/* TODO: Need to scrape data from all 4 registers
	 * in the case of a wildcarded source port and
	 * forward all action type
	 */
	nf2_of_exact_counters_wrap counters;
	memset(&counters, 0, sizeof(nf2_of_exact_counters_wrap));

	// build the index to our counters
	index = row << 7;

	// Read the second word into our struct, to not disturb the packet count
	readReg(dev, SRAM_BASE_ADDR + index +
		      sizeof(nf2_of_entry_wrap) + 4, &counters.raw[1]);
	val = counters.counters.byte_count;

	DBG_VERBOSE
	    ("** Exact match byte count(delta) row: %i count: %i time(msec): %llu\n",
	     row, val, time_msec());

	return val;
}

unsigned int
nf2_get_wildcard_packet_count(struct nf2device *dev, int row)
{
	unsigned int val = 0;

	writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, row);
	readReg(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG
		      + (4 * row), &val);

	DBG_VERBOSE
	    ("** Wildcard packet count(sum) row: %i count: %i time(msec): %llu\n",
	     row, val, time_msec());

	return val;
}

unsigned int
nf2_get_wildcard_byte_count(struct nf2device *dev, int row)
{
	unsigned int val = 0;

	writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, row);
	readReg(dev, OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG
		      + (4 * row), &val);

	DBG_VERBOSE
	    ("** Wildcard byte count(sum) row: %i count: %i time(msec): %llu\n",
	     row, val, time_msec());

	return val;
}

unsigned long int
nf2_get_matched_count(struct nf2device *dev)
{
	unsigned int val_wild = 0;
	unsigned int val_exact = 0;

	readReg(dev, OPENFLOW_LOOKUP_WILDCARD_HITS_REG, &val_wild);
	readReg(dev, OPENFLOW_LOOKUP_EXACT_HITS_REG, &val_exact);

	DBG_VERBOSE("** Wildcard Matched count: %i time(msec): %llu\n",
		    val_wild, time_msec());
	DBG_VERBOSE("** Exact Matched count: %i time(msec): %llu\n",
		    val_exact, time_msec());

	return ((unsigned long int)(val_wild + val_exact));
}

unsigned long int
nf2_get_missed_count(struct nf2device *dev)
{
	unsigned int val_wild = 0;
	unsigned int val_exact = 0;

	readReg(dev, OPENFLOW_LOOKUP_WILDCARD_MISSES_REG, &val_wild);
	readReg(dev, OPENFLOW_LOOKUP_EXACT_MISSES_REG, &val_exact);

	DBG_VERBOSE("** Wildcard Missed count: %i time(msec): %llu\n",
		    val_wild, time_msec());
	DBG_VERBOSE("** Exact Missed count: %i time(msec): %llu\n",
		    val_exact, time_msec());

	return ((unsigned long int)(val_wild + val_exact));
}

static void
log_watchdog_info(struct nf2device *dev)
{
#ifdef HWTABLE_NO_DEBUG
        return;
#else
#define CLK_CYCLE 8
	unsigned int nf2wdtinfo;
	unsigned int elapsed_time;
	readReg(dev, WDT_COUNTER_REG, &nf2wdtinfo);
	elapsed_time = nf2wdtinfo * CLK_CYCLE / 1000000;
	DBG_VVERB
	    ("%u (msec) passed since the watchdog counter has been cleared last time\n",
	      elapsed_time);
	DBG_VVERB("NetFPGA WDT now clearing\n");
#endif
}

static void
nf2_get_all_ports_info_addr(struct nf2_all_ports_info_addr *nf2addr)
{
	nf2addr->rx_q_num_pkts_stored_reg[0]
		= MAC_GRP_0_RX_QUEUE_NUM_PKTS_STORED_REG;
	nf2addr->rx_q_num_pkts_dropped_full_reg[0]
		= MAC_GRP_0_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG;
	nf2addr->rx_q_num_pkts_dropped_bad_reg[0]
		= MAC_GRP_0_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG;
	nf2addr->rx_q_num_words_pushed_reg[0]
		= MAC_GRP_0_RX_QUEUE_NUM_WORDS_PUSHED_REG;
	nf2addr->rx_q_num_bytes_pushed_reg[0]
		= MAC_GRP_0_RX_QUEUE_NUM_BYTES_PUSHED_REG;
	nf2addr->rx_q_num_pkts_dequeued_reg[0]
		= MAC_GRP_0_RX_QUEUE_NUM_PKTS_DEQUEUED_REG;
	nf2addr->rx_q_num_pkts_in_queue_reg[0]
		= MAC_GRP_0_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG;
	nf2addr->tx_q_num_pkts_in_queue_reg[0]
		= MAC_GRP_0_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG;
	nf2addr->tx_q_num_pkts_sent_reg[0]
		= MAC_GRP_0_TX_QUEUE_NUM_PKTS_SENT_REG;
	nf2addr->tx_q_num_words_pushed_reg[0]
		= MAC_GRP_0_TX_QUEUE_NUM_WORDS_PUSHED_REG;
	nf2addr->tx_q_num_bytes_pushed_reg[0]
		= MAC_GRP_0_TX_QUEUE_NUM_BYTES_PUSHED_REG;
	nf2addr->tx_q_num_pkts_enqueued_reg[0]
		= MAC_GRP_0_TX_QUEUE_NUM_PKTS_ENQUEUED_REG;

	nf2addr->rx_q_num_pkts_stored_reg[1]
		= MAC_GRP_1_RX_QUEUE_NUM_PKTS_STORED_REG;
	nf2addr->rx_q_num_pkts_dropped_full_reg[1]
		= MAC_GRP_1_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG;
	nf2addr->rx_q_num_pkts_dropped_bad_reg[1]
		= MAC_GRP_1_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG;
	nf2addr->rx_q_num_words_pushed_reg[1]
		= MAC_GRP_1_RX_QUEUE_NUM_WORDS_PUSHED_REG;
	nf2addr->rx_q_num_bytes_pushed_reg[1]
		= MAC_GRP_1_RX_QUEUE_NUM_BYTES_PUSHED_REG;
	nf2addr->rx_q_num_pkts_dequeued_reg[1]
		= MAC_GRP_1_RX_QUEUE_NUM_PKTS_DEQUEUED_REG;
	nf2addr->rx_q_num_pkts_in_queue_reg[1]
		= MAC_GRP_1_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG;
	nf2addr->tx_q_num_pkts_in_queue_reg[1]
		= MAC_GRP_1_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG;
	nf2addr->tx_q_num_pkts_sent_reg[1]
		= MAC_GRP_1_TX_QUEUE_NUM_PKTS_SENT_REG;
	nf2addr->tx_q_num_words_pushed_reg[1]
		= MAC_GRP_1_TX_QUEUE_NUM_WORDS_PUSHED_REG;
	nf2addr->tx_q_num_bytes_pushed_reg[1]
		= MAC_GRP_1_TX_QUEUE_NUM_BYTES_PUSHED_REG;
	nf2addr->tx_q_num_pkts_enqueued_reg[1]
		= MAC_GRP_1_TX_QUEUE_NUM_PKTS_ENQUEUED_REG;

	nf2addr->rx_q_num_pkts_stored_reg[2]
		= MAC_GRP_2_RX_QUEUE_NUM_PKTS_STORED_REG;
	nf2addr->rx_q_num_pkts_dropped_full_reg[2]
		= MAC_GRP_2_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG;
	nf2addr->rx_q_num_pkts_dropped_bad_reg[2]
		= MAC_GRP_2_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG;
	nf2addr->rx_q_num_words_pushed_reg[2]
		= MAC_GRP_2_RX_QUEUE_NUM_WORDS_PUSHED_REG;
	nf2addr->rx_q_num_bytes_pushed_reg[2]
		= MAC_GRP_2_RX_QUEUE_NUM_BYTES_PUSHED_REG;
	nf2addr->rx_q_num_pkts_dequeued_reg[2]
		= MAC_GRP_2_RX_QUEUE_NUM_PKTS_DEQUEUED_REG;
	nf2addr->rx_q_num_pkts_in_queue_reg[2]
		= MAC_GRP_2_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG;
	nf2addr->tx_q_num_pkts_in_queue_reg[2]
		= MAC_GRP_2_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG;
	nf2addr->tx_q_num_pkts_sent_reg[2]
		= MAC_GRP_2_TX_QUEUE_NUM_PKTS_SENT_REG;
	nf2addr->tx_q_num_words_pushed_reg[2]
		= MAC_GRP_2_TX_QUEUE_NUM_WORDS_PUSHED_REG;
	nf2addr->tx_q_num_bytes_pushed_reg[2]
		= MAC_GRP_2_TX_QUEUE_NUM_BYTES_PUSHED_REG;
	nf2addr->tx_q_num_pkts_enqueued_reg[2]
		= MAC_GRP_2_TX_QUEUE_NUM_PKTS_ENQUEUED_REG;

	nf2addr->rx_q_num_pkts_stored_reg[3]
		= MAC_GRP_3_RX_QUEUE_NUM_PKTS_STORED_REG;
	nf2addr->rx_q_num_pkts_dropped_full_reg[3]
		= MAC_GRP_3_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG;
	nf2addr->rx_q_num_pkts_dropped_bad_reg[3]
		= MAC_GRP_3_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG;
	nf2addr->rx_q_num_words_pushed_reg[3]
		= MAC_GRP_3_RX_QUEUE_NUM_WORDS_PUSHED_REG;
	nf2addr->rx_q_num_bytes_pushed_reg[3]
		= MAC_GRP_3_RX_QUEUE_NUM_BYTES_PUSHED_REG;
	nf2addr->rx_q_num_pkts_dequeued_reg[3]
		= MAC_GRP_3_RX_QUEUE_NUM_PKTS_DEQUEUED_REG;
	nf2addr->rx_q_num_pkts_in_queue_reg[3]
		= MAC_GRP_3_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG;
	nf2addr->tx_q_num_pkts_in_queue_reg[3]
		= MAC_GRP_3_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG;
	nf2addr->tx_q_num_pkts_sent_reg[3]
		= MAC_GRP_3_TX_QUEUE_NUM_PKTS_SENT_REG;
	nf2addr->tx_q_num_words_pushed_reg[3]
		= MAC_GRP_3_TX_QUEUE_NUM_WORDS_PUSHED_REG;
	nf2addr->tx_q_num_bytes_pushed_reg[3]
		= MAC_GRP_3_TX_QUEUE_NUM_BYTES_PUSHED_REG;
	nf2addr->tx_q_num_pkts_enqueued_reg[3]
		= MAC_GRP_3_TX_QUEUE_NUM_PKTS_ENQUEUED_REG;
}

int
nf2_get_port_info(struct nf2device *dev, int nf_port,
                  struct nf2_port_info *nf2portinfo)
{
	struct nf2_all_ports_info_addr *nf2addr;

	if ((nf_port >= NF2_PORT_NUM) || (nf_port < 0)) {
		DBG_ERROR("Illegal port number\n");
		return 1;
	}

	nf2addr = calloc(1, sizeof(struct nf2_all_ports_info_addr));
	if (nf2addr == NULL) {
		DBG_ERROR("Could not allocate memory for port information gathering\n");
		return 1;
	}
	nf2_get_all_ports_info_addr(nf2addr);

	readReg(dev, nf2addr->rx_q_num_pkts_stored_reg[nf_port],
		      &(nf2portinfo->rx_q_num_pkts_stored));
	readReg(dev, nf2addr->rx_q_num_pkts_dropped_full_reg[nf_port],
		      &(nf2portinfo->rx_q_num_pkts_dropped_full));
	readReg(dev, nf2addr->rx_q_num_pkts_dropped_bad_reg[nf_port],
		      &(nf2portinfo->rx_q_num_pkts_dropped_bad));
	readReg(dev, nf2addr->rx_q_num_words_pushed_reg[nf_port],
		      &(nf2portinfo->rx_q_num_words_pushed));
	readReg(dev, nf2addr->rx_q_num_bytes_pushed_reg[nf_port],
		      &(nf2portinfo->rx_q_num_bytes_pushed));
	readReg(dev, nf2addr->rx_q_num_pkts_dequeued_reg[nf_port],
		      &(nf2portinfo->rx_q_num_pkts_dequeued));
	readReg(dev, nf2addr->rx_q_num_pkts_in_queue_reg[nf_port],
		      &(nf2portinfo->rx_q_num_pkts_in_queue));
	readReg(dev, nf2addr->tx_q_num_pkts_in_queue_reg[nf_port],
		      &(nf2portinfo->tx_q_num_pkts_in_queue));
	readReg(dev, nf2addr->tx_q_num_pkts_sent_reg[nf_port],
		      &(nf2portinfo->tx_q_num_pkts_sent));
	readReg(dev, nf2addr->tx_q_num_words_pushed_reg[nf_port],
		      &(nf2portinfo->tx_q_num_words_pushed));
	readReg(dev, nf2addr->tx_q_num_bytes_pushed_reg[nf_port],
		      &(nf2portinfo->tx_q_num_bytes_pushed));
	readReg(dev, nf2addr->tx_q_num_pkts_enqueued_reg[nf_port],
		      &(nf2portinfo->tx_q_num_pkts_enqueued));
	free(nf2addr);
	return 0;
}
