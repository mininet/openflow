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

#include <linux/delay.h>
#include <linux/time.h>
#include <linux/etherdevice.h>

#include "flow.h"
#include "table.h"

#include "hwtable_nf2/nf2.h"
#include "hwtable_nf2/nf2_reg.h"
#include "hwtable_nf2/nf2_hwapi.h"
#include "hwtable_nf2/nf2_flowtable.h"
#include "hwtable_nf2/nf2_openflow.h"
#include "hwtable_nf2/nf2_lib.h"

static void log_entry(nf2_of_entry_wrap *);
static void log_entry_raw(nf2_of_entry_wrap *);
static void log_mask(nf2_of_mask_wrap *);
static void log_mask_raw(nf2_of_mask_wrap *);
static void log_action(nf2_of_action_wrap *);
static void log_action_raw(nf2_of_action_wrap *);
static struct nf2_all_ports_info_addr *nf2_get_all_ports_info_addr(void);

static void
log_entry(nf2_of_entry_wrap *entry)
{
#ifndef NF2_DEBUG
	return;
#else
	int i;

	// Log the physical source port
	NF2DEBUGMSG("E psrc[%i] ", entry->entry.src_port / 2);

	// Log the link layer source
	NF2DEBUGMSG("dlsrc[");
	for (i = 5; i > 0; --i) {
		NF2DEBUGMSG("%0X:", entry->entry.eth_src[i]);
	}
	NF2DEBUGMSG("%0X] ", entry->entry.eth_src[0]);

	// Log the link layer dest
	NF2DEBUGMSG("dldst[");
	for (i = 5; i > 0; --i) {
		NF2DEBUGMSG("%0X:", entry->entry.eth_dst[i]);
	}
	NF2DEBUGMSG("%0X] ", entry->entry.eth_dst[0]);

	// Log the link layer type
	NF2DEBUGMSG("dltype[%0X] ", entry->entry.eth_type);

	// Log the link layer vlan
	NF2DEBUGMSG("dlvlan[%0X] ", entry->entry.vlan_id);

	// Log the network source
	NF2DEBUGMSG("nwsrc[");
	NF2DEBUGMSG("%0i.", (entry->entry.ip_src >> 24) & 0xFF);
	NF2DEBUGMSG("%0i.", (entry->entry.ip_src >> 16) & 0xFF);
	NF2DEBUGMSG("%0i.", (entry->entry.ip_src >> 8) & 0xFF);
	NF2DEBUGMSG("%0i", entry->entry.ip_src & 0xFF);
	NF2DEBUGMSG("] ");

	// Log the network dest
	NF2DEBUGMSG("nwdst[");
	NF2DEBUGMSG("%0i.", (entry->entry.ip_dst >> 24) & 0xFF);
	NF2DEBUGMSG("%0i.", (entry->entry.ip_dst >> 16) & 0xFF);
	NF2DEBUGMSG("%0i.", (entry->entry.ip_dst >> 8) & 0xFF);
	NF2DEBUGMSG("%0i", entry->entry.ip_dst & 0xFF);
	NF2DEBUGMSG("] ");

	// Log the transport source port
	NF2DEBUGMSG("tsrc[%i] ", entry->entry.transp_src);

	// Log the transport dest port
	NF2DEBUGMSG("tdst[%i]\n", entry->entry.transp_dst);
#endif
}

static void
log_entry_raw(nf2_of_entry_wrap *entry)
{
#ifndef NF2_DEBUG
	return;
#else
	int i;
	unsigned char *c;

	NF2DEBUGMSG("E ");
	c = (unsigned char *)entry;
	for (i = 0; i < sizeof(nf2_of_entry_wrap); ++i) {
		if (!(i % 4)) {
			NF2DEBUGMSG(" ");
		}
		NF2DEBUGMSG("%02x", c[i]);
	}
	NF2DEBUGMSG("\n");
#endif
}

static void
log_mask(nf2_of_mask_wrap *mask)
{
#ifndef NF2_DEBUG
	return;
#else
	int i;

	// Log the physical source port
	NF2DEBUGMSG("M psrc[%0X] ", mask->entry.src_port / 2);

	// Log the link layer source
	NF2DEBUGMSG("dlsrc[");
	for (i = 5; i > 0; --i) {
		NF2DEBUGMSG("%0X:", mask->entry.eth_src[i]);
	}
	NF2DEBUGMSG("%0X] ", mask->entry.eth_dst[0]);

	// Log the link layer dest
	NF2DEBUGMSG("dldst[");
	for (i = 5; i > 0; --i) {
		NF2DEBUGMSG("%0X:", mask->entry.eth_dst[i]);
	}
	NF2DEBUGMSG("%0X] ", mask->entry.eth_dst[0]);

	// Log the link layer type
	NF2DEBUGMSG("dltype[%0X] ", mask->entry.eth_type);

	// Log the link layer vlan
	NF2DEBUGMSG("dlvlan[%0X] ", mask->entry.vlan_id);

	// Log the network source
	NF2DEBUGMSG("nwsrc[");
	NF2DEBUGMSG("%0X.", (mask->entry.ip_src >> 24) & 0xFF);
	NF2DEBUGMSG("%0X.", (mask->entry.ip_src >> 16) & 0xFF);
	NF2DEBUGMSG("%0X.", (mask->entry.ip_src >> 8) & 0xFF);
	NF2DEBUGMSG("%0X", mask->entry.ip_src & 0xFF);
	NF2DEBUGMSG("] ");

	// Log the network dest
	NF2DEBUGMSG("nwdst[");
	NF2DEBUGMSG("%0X.", (mask->entry.ip_dst >> 24) & 0xFF);
	NF2DEBUGMSG("%0X.", (mask->entry.ip_dst >> 16) & 0xFF);
	NF2DEBUGMSG("%0X.", (mask->entry.ip_dst >> 8) & 0xFF);
	NF2DEBUGMSG("%0X", mask->entry.ip_dst & 0xFF);
	NF2DEBUGMSG("] ");

	// Log the transport source port
	NF2DEBUGMSG("tsrc[%0X] ", mask->entry.transp_src);

	// Log the transport dest port
	NF2DEBUGMSG("tdst[%0X]\n", mask->entry.transp_dst);
#endif
}

static void
log_mask_raw(nf2_of_mask_wrap *mask)
{
#ifndef NF2_DEBUG
	return;
#else
	int i;
	unsigned char *c;

	NF2DEBUGMSG("M ");
	c = (unsigned char *)mask;
	for (i = 0; i < sizeof(nf2_of_mask_wrap); ++i) {
		if (!(i % 4)) {
			NF2DEBUGMSG(" ");
		}
		NF2DEBUGMSG("%02x", c[i]);
	}
	NF2DEBUGMSG("\n");
#endif
}

static void
log_action(nf2_of_action_wrap *action)
{
#ifndef NF2_DEBUG
	return;
#else
	int i;

	NF2DEBUGMSG("A Output P[");
	for (i = 0; i < 4; ++i) {
		if (action->action.forward_bitmask & (1 << (i * 2))) {
			NF2DEBUGMSG("%i", i);
		}
	}
	NF2DEBUGMSG("] CPU[");
	for (i = 0; i < 4; ++i) {
		if (action->action.forward_bitmask & (1 << (1 + (i * 2)))) {
			NF2DEBUGMSG("%i", i);
		}
	}
	NF2DEBUGMSG("]\n");
#endif
}

static void
log_action_raw(nf2_of_action_wrap *action)
{
#ifndef NF2_DEBUG
	return;
#else
	int i;
	unsigned char *c;

	NF2DEBUGMSG("A ");
	c = (unsigned char *)action;
	for (i = 0; i < sizeof(nf2_of_action_wrap); ++i) {
		if (!(i % 4)) {
			NF2DEBUGMSG(" ");
		}
		NF2DEBUGMSG("%02x", c[i]);
	}
	NF2DEBUGMSG("\n");
#endif
}

void
nf2_reset_card(struct net_device *dev)
{
	volatile unsigned int val;

	if (dev == NULL) {
		return;
	}

	/* If we are operating on a NetFPGA enabled box, reset the card */
	printk(KERN_INFO "openflowswitch-netfpga2: Resetting the NetFPGA.\n");
	nf2k_reg_read(dev, WDT_CPCI_REG_CTRL, (void *)&val);
	val |= 0x100;
	nf2k_reg_write(dev, WDT_CPCI_REG_CTRL, (void *)&val);
	printk(KERN_INFO "openflowswitch-netfpga2: Reset the NetFPGA.\n");
	ssleep(2);
}

void
nf2_clear_watchdog(struct net_device *dev)
{
	volatile unsigned int enable_status;

#ifndef NF2_WATCHDOG
	return;
#endif
	if (dev == NULL) {
		return;
	}

	nf2k_reg_read(dev, WDT_ENABLE_FLG_REG, (void *)&enable_status);
	enable_status &= 0x1;

	if (enable_status == WATCHDOG_DISABLE) {
		enable_status = WATCHDOG_ENABLE;
		nf2k_reg_write(dev, WDT_ENABLE_FLG_REG, (void *)&enable_status);
	}
	return;
}

/* Write a wildcard entry to the specified device and row. The row consists of
 * the actual entry, its mask that specifies wildcards, as well as the action(s)
 * to be taken if the row is matched
 */
int
nf2_write_of_wildcard(struct net_device *dev, int row,
		      nf2_of_entry_wrap *entry, nf2_of_mask_wrap *mask,
		      nf2_of_action_wrap *action)
{
	int i;
	int val;
	struct timeval t;

	NF2DEBUGMSG("** Begin wildcard entry write to row: %i\n", row);
	log_entry(entry);
	log_mask(mask);
	log_action(action);
	log_entry_raw(entry);
	log_mask_raw(mask);
	log_action_raw(action);

	for (i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		nf2k_reg_write(dev,
			       OPENFLOW_WILDCARD_LOOKUP_CMP_0_REG
			       + (4 * i), &(entry->raw[i]));
	}

	for (i = 0; i < NF2_OF_MASK_WORD_LEN; ++i) {
		nf2k_reg_write(dev,
			       OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_0_REG
			       + (4 * i), &(mask->raw[i]));
	}

	for (i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		nf2k_reg_write(dev,
			       OPENFLOW_WILDCARD_LOOKUP_ACTION_0_REG
			       + (4 * i), &(action->raw[i]));
	}

	// Reset the stats for the row
	val = 0;
	nf2k_reg_write(dev,
		       OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG + (4 * row),
		       &val);
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG + (4 * row),
		       &val);
	nf2k_reg_write(dev,
		       OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_0_REG + (4 * row),
		       &val);
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_WRITE_ADDR_REG, &row);

	do_gettimeofday(&t);
	NF2DEBUGMSG("** End wildcard entry write to row: %i time: %i.%i\n",
		    row, (int)t.tv_sec, (int)t.tv_usec);

	return 0;
}

int
nf2_write_of_exact(struct net_device *dev, int row,
		   nf2_of_entry_wrap *entry, nf2_of_action_wrap *action)
{
	int i;
	int val;
	struct timeval t;
	unsigned int index = row << 7;

	NF2DEBUGMSG("** Begin exact match entry write to row: %i\n", row);
	log_entry(entry);
	log_action(action);
	log_entry_raw(entry);
	log_action_raw(action);

	for (i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		nf2k_reg_write(dev, SRAM_BASE_ADDR + index
			       + (4 * i), &(entry->raw[i]));
	}

	// blank out the counters
	val = 0;
	for (i = 0; i < NF2_OF_EXACT_COUNTERS_WORD_LEN; ++i) {
		nf2k_reg_write(dev, SRAM_BASE_ADDR + index
			       + sizeof(nf2_of_entry_wrap)
			       + (4 * i), &val);
	}

	// write the actions
	for (i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		nf2k_reg_write(dev, SRAM_BASE_ADDR + index
			       + sizeof(nf2_of_entry_wrap)
			       + sizeof(nf2_of_exact_counters_wrap)
			       + (4 * i), &(action->raw[i]));
	}

	do_gettimeofday(&t);
	NF2DEBUGMSG("** End exact match entry write to row: %i time: %i.%i\n",
		    row, (int)t.tv_sec, (int)t.tv_usec);

	return 0;
}

/* Write wildcard action(s) to the specified device and row. */
int
nf2_modify_write_of_wildcard(struct net_device *dev, int row,
			     nf2_of_entry_wrap *entry, nf2_of_mask_wrap *mask,
			     nf2_of_action_wrap *action)
{
	int i;
	int bytes_reg_val;
	int pkts_reg_val;
	int last_reg_val;
	struct timeval t;

	NF2DEBUGMSG("** Begin wildcard modified action write to row: %i\n",
		    row);
	log_entry(entry);
	log_mask(mask);
	log_action(action);
	log_entry_raw(entry);
	log_mask_raw(mask);
	log_action_raw(action);

	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, &row);
	nf2k_reg_read(dev,
		      OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG + (4 * row),
		      &bytes_reg_val);
	nf2k_reg_read(dev,
		      OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG + (4 * row),
		      &pkts_reg_val);
	nf2k_reg_read(dev,
		      OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_0_REG + (4 * row),
		      &last_reg_val);

	for (i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_0_REG
			       + (4 * i), &(entry->raw[i]));
	}

	for (i = 0; i < NF2_OF_MASK_WORD_LEN; ++i) {
		nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_0_REG
			       + (4 * i), &(mask->raw[i]));
	}

	for (i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_ACTION_0_REG
			       + (4 * i), &(action->raw[i]));
	}

	nf2k_reg_write(dev,
		       OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG + (4 * row),
		       &bytes_reg_val);
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG + (4 * row),
		       &pkts_reg_val);
	nf2k_reg_write(dev,
		       OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_0_REG + (4 * row),
		       &last_reg_val);
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_WRITE_ADDR_REG, &row);

	do_gettimeofday(&t);
	NF2DEBUGMSG
		("** End wildcard modified action write to row: %i time: %i.%i\n",
		 row, (int)t.tv_sec, (int)t.tv_usec);
	NF2DEBUGMSG("   Bytes hit count: %d\n", bytes_reg_val);
	NF2DEBUGMSG("   Pkts  hit count: %d\n", pkts_reg_val);
	NF2DEBUGMSG("   Last seen      : %d\n", last_reg_val);

	return 0;
}

int
nf2_modify_write_of_exact(struct net_device *dev, int row,
			  nf2_of_action_wrap *action)
{
	int i;
	struct timeval t;
	unsigned int index = row << 7;

	NF2DEBUGMSG("** Begin exact match modified action write to row: %i\n",
		    row);
	log_action(action);
	log_action_raw(action);

	// write the actions
	for (i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		nf2k_reg_write(dev, SRAM_BASE_ADDR + index
			       + sizeof(nf2_of_entry_wrap)
			       + sizeof(nf2_of_exact_counters_wrap)
			       + (4 * i), &(action->raw[i]));
	}

	do_gettimeofday(&t);
	NF2DEBUGMSG
		("** End exact match modified action write to row: %i time: %i.%i\n",
		 row, (int)t.tv_sec, (int)t.tv_usec);

	return 0;
}

unsigned int
nf2_get_exact_packet_count(struct net_device *dev, int row)
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
	nf2k_reg_read(dev,
		      SRAM_BASE_ADDR + index + sizeof(nf2_of_entry_wrap),
		      &counters);
	val = counters.counters.pkt_count;

	NF2DEBUGMSG("** Exact match packet count request row: %i count: %i\n",
		    row, val);

	return val;
}

unsigned int
nf2_get_exact_byte_count(struct net_device *dev, int row)
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
	nf2k_reg_read(dev, SRAM_BASE_ADDR + index +
		      sizeof(nf2_of_entry_wrap) + 4, &counters.raw[1]);
	val = counters.counters.byte_count;

	NF2DEBUGMSG("** Exact match byte count request row: %i count: %i\n",
		    row, val);

	return val;
}

unsigned int
nf2_get_wildcard_packet_count(struct net_device *dev, int row)
{
	unsigned int val = 0;
#ifdef NF2_DEBUG
	struct timeval t;
#endif

	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, &row);
	nf2k_reg_read(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG
		      + (4 * row), &val);

#ifdef NF2_DEBUG
	do_gettimeofday(&t);
	NF2DEBUGMSG
		("** Wildcard packet count request row: %i count: %i time: %i.%i\n",
		 row, val, (int)t.tv_sec, (int)t.tv_usec);
#endif

	return val;
}

unsigned int
nf2_get_wildcard_byte_count(struct net_device *dev, int row)
{
	unsigned int val = 0;
#ifdef NF2_DEBUG
	struct timeval t;
#endif

	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, &row);
	nf2k_reg_read(dev, OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG
		      + (4 * row), &val);

#ifdef NF2_DEBUG
	do_gettimeofday(&t);
	NF2DEBUGMSG
		("** Wildcard byte count request row: %i count: %i time: %i.%i\n",
		 row, val, (int)t.tv_sec, (int)t.tv_usec);
#endif

	return val;
}

unsigned long int
nf2_get_matched_count(struct net_device *dev)
{
	unsigned int val_wild = 0;
	unsigned int val_exact = 0;
#ifdef NF2_DEBUG
	struct timeval t;
#endif

	nf2k_reg_read(dev, OPENFLOW_LOOKUP_WILDCARD_HITS_REG, &val_wild);
	nf2k_reg_read(dev, OPENFLOW_LOOKUP_EXACT_HITS_REG, &val_exact);

#ifdef NF2_DEBUG
	do_gettimeofday(&t);
	NF2DEBUGMSG("** Wildcard Matched count: %i time: %i.%i\n",
		    val_wild, (int)t.tv_sec, (int)t.tv_usec);
	NF2DEBUGMSG("** Exact Matched count: %i time: %i.%i\n",
		    val_exact, (int)t.tv_sec, (int)t.tv_usec);
#endif

	return ((unsigned long int)(val_wild + val_exact));
}

unsigned long int
nf2_get_missed_count(struct net_device *dev)
{
	unsigned int val_wild = 0;
	unsigned int val_exact = 0;
#ifdef NF2_DEBUG
	struct timeval t;
#endif

	nf2k_reg_read(dev, OPENFLOW_LOOKUP_WILDCARD_MISSES_REG, &val_wild);
	nf2k_reg_read(dev, OPENFLOW_LOOKUP_EXACT_MISSES_REG, &val_exact);

#ifdef NF2_DEBUG
	do_gettimeofday(&t);
	NF2DEBUGMSG("** Wildcard Missed count: %i time: %i.%i\n",
		    val_wild, (int)t.tv_sec, (int)t.tv_usec);
	NF2DEBUGMSG("** Exact Missed count: %i time: %i.%i\n",
		    val_exact, (int)t.tv_sec, (int)t.tv_usec);
#endif

	return ((unsigned long int)(val_wild + val_exact));
}

struct nf2_device_info *
nf2_get_device_info(struct net_device *dev)
{
	struct nf2_device_info *nf2devinfo;
	int i;

	nf2devinfo = kzalloc(sizeof(struct nf2_device_info), GFP_KERNEL);
	if (nf2devinfo == NULL)
		return NULL;

	// Read the version and revision
	nf2k_reg_read(dev, DEV_ID_DEVICE_ID_REG, &(nf2devinfo->nf2_device_id));
	nf2k_reg_read(dev, DEV_ID_REVISION_REG, &(nf2devinfo->nf2_device_rev));

	// Read the design name string
	for (i = 0; i < (DEVICE_STR_LEN / 4) - 2; i++) {
		nf2k_reg_read(dev, DEV_ID_DEV_STR_0_REG + i * 4,
			      (uint32_t *)(nf2devinfo->nf2_device_str + i * 4));
		*(uint32_t *)(nf2devinfo->nf2_device_str + i * 4)
			= ntohl(*(uint32_t *)
				(nf2devinfo->nf2_device_str + i * 4));
	}
	nf2devinfo->nf2_device_str[DEVICE_STR_LEN - 1] = '\0';

	return nf2devinfo;
}

struct nf2_match_info *
nf2_get_match_info(struct net_device *dev)
{
	struct nf2_match_info *nf2matchinfo;

	nf2matchinfo = kzalloc(sizeof(struct nf2_match_info), GFP_KERNEL);
	if (nf2matchinfo == NULL)
		return NULL;

	nf2k_reg_read(dev, OPENFLOW_LOOKUP_WILDCARD_MISSES_REG,
		      &(nf2matchinfo->wildcard_misses));
	nf2k_reg_read(dev, OPENFLOW_LOOKUP_WILDCARD_HITS_REG,
		      &(nf2matchinfo->wildcard_hits));
	nf2k_reg_read(dev, OPENFLOW_LOOKUP_EXACT_MISSES_REG,
		      &(nf2matchinfo->exact_misses));
	nf2k_reg_read(dev, OPENFLOW_LOOKUP_EXACT_HITS_REG,
		      &(nf2matchinfo->exact_hits));

	return nf2matchinfo;
}

unsigned int
nf2_get_watchdog_info(struct net_device *dev)
{
	unsigned int nf2wdtinfo = 0;

	nf2k_reg_read(dev, WDT_COUNTER_REG, &nf2wdtinfo);
	return nf2wdtinfo;
}

static struct nf2_all_ports_info_addr *
nf2_get_all_ports_info_addr(void)
{
	struct nf2_all_ports_info_addr *nf2addr;

	nf2addr = kzalloc(sizeof(struct nf2_all_ports_info_addr), GFP_KERNEL);
	if (nf2addr == NULL)
		return NULL;

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

	return nf2addr;
}

struct nf2_all_ports_info *
nf2_get_all_ports_info(struct net_device *dev)
{
	struct nf2_all_ports_info *nf2portinfo;
	struct nf2_all_ports_info_addr *nf2addr;
	int i;

	nf2portinfo = kzalloc(sizeof(struct nf2_all_ports_info), GFP_KERNEL);
	if (nf2portinfo == NULL)
		return NULL;
	nf2addr = nf2_get_all_ports_info_addr();
	if (nf2addr == NULL)
		return NULL;

	for (i = 0; i < NF2_PORT_NUM; i++) {
		nf2k_reg_read(dev, nf2addr->rx_q_num_pkts_stored_reg[i],
			      &(nf2portinfo->port[i].rx_q_num_pkts_stored));
		nf2k_reg_read(dev, nf2addr->rx_q_num_pkts_dropped_full_reg[i],
			      &(nf2portinfo
				->port[i].rx_q_num_pkts_dropped_full));
		nf2k_reg_read(dev, nf2addr->rx_q_num_pkts_dropped_bad_reg[i],
			      &(nf2portinfo
				->port[i].rx_q_num_pkts_dropped_bad));
		nf2k_reg_read(dev, nf2addr->rx_q_num_words_pushed_reg[i],
			      &(nf2portinfo->port[i].rx_q_num_words_pushed));
		nf2k_reg_read(dev, nf2addr->rx_q_num_bytes_pushed_reg[i],
			      &(nf2portinfo->port[i].rx_q_num_bytes_pushed));
		nf2k_reg_read(dev, nf2addr->rx_q_num_pkts_dequeued_reg[i],
			      &(nf2portinfo->port[i].rx_q_num_pkts_dequeued));
		nf2k_reg_read(dev, nf2addr->rx_q_num_pkts_in_queue_reg[i],
			      &(nf2portinfo->port[i].rx_q_num_pkts_in_queue));
		nf2k_reg_read(dev, nf2addr->tx_q_num_pkts_in_queue_reg[i],
			      &(nf2portinfo->port[i].tx_q_num_pkts_in_queue));
		nf2k_reg_read(dev, nf2addr->tx_q_num_pkts_sent_reg[i],
			      &(nf2portinfo->port[i].tx_q_num_pkts_sent));
		nf2k_reg_read(dev, nf2addr->tx_q_num_words_pushed_reg[i],
			      &(nf2portinfo->port[i].tx_q_num_words_pushed));
		nf2k_reg_read(dev, nf2addr->tx_q_num_bytes_pushed_reg[i],
			      &(nf2portinfo->port[i].tx_q_num_bytes_pushed));
		nf2k_reg_read(dev, nf2addr->tx_q_num_pkts_enqueued_reg[i],
			      &(nf2portinfo->port[i].tx_q_num_pkts_enqueued));
	}
	return nf2portinfo;
}
