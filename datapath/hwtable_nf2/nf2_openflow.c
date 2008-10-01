#include <linux/delay.h>
#include <linux/time.h>
#include "hwtable_nf2/nf2_openflow.h"
#include "hwtable_nf2/nf2.h"
#include "hwtable_nf2/reg_defines.h"
#include "hwtable_nf2/nf2_export.h"
#include "hwtable_nf2/nf2_logging.h"

void nf2_reset_card(struct net_device *dev) {
	unsigned int val;

	/* If we are operating on a NetFPGA enabled box, reset the card */
	if (dev) {

		printk("openflow: Resetting the NetFPGA.\n");
		nf2k_reg_read(dev, CPCI_REG_CTRL, &val);
		val |= 0x100;
		nf2k_reg_write(dev, CPCI_REG_CTRL, &val);
		printk("openflow: Reset the NetFPGA.\n");
		ssleep(2);
	}
}

void logEntry(nf2_of_entry_wrap* entry) {

#ifndef NF2_DEBUG
	return;
#endif

	int i;

	// Log the physical source port
	LOG("E psrc[%i] ", entry->entry.src_port / 2);

	// Log the link layer source
	LOG("dlsrc[");
	for (i=5; i > 0; --i) {
		LOG("%0X:", entry->entry.eth_src[i]);
	}
	LOG("%0X] ", entry->entry.eth_dst[0]);

	// Log the link layer dest
	LOG("dldst[");
	for (i=5; i > 0; --i) {
		LOG("%0X:", entry->entry.eth_dst[i]);
	}
	LOG("%0X] ", entry->entry.eth_dst[0]);

	// Log the link layer type
	LOG("dltype[%0X] ", entry->entry.eth_type);

	// Log the link layer vlan
	LOG("dlvlan[%0X] ", entry->entry.vlan_id);

	// Log the network source
	LOG("nwsrc[");
	LOG("%0i.", (entry->entry.ip_src >> 24) & 0xFF);
	LOG("%0i.", (entry->entry.ip_src >> 16) & 0xFF);
	LOG("%0i.", (entry->entry.ip_src >> 8) & 0xFF);
	LOG("%0i", entry->entry.ip_src & 0xFF);
	LOG("] ");

	// Log the network dest
	LOG("nwdst[");
	LOG("%0i.", (entry->entry.ip_dst >> 24) & 0xFF);
	LOG("%0i.", (entry->entry.ip_dst >> 16) & 0xFF);
	LOG("%0i.", (entry->entry.ip_dst >> 8) & 0xFF);
	LOG("%0i", entry->entry.ip_dst & 0xFF);
	LOG("] ");

	// Log the transport source port
	LOG("tsrc[%i] ", entry->entry.transp_src);

	// Log the transport dest port
	LOG("tdst[%i]\n", entry->entry.transp_dst);
}

void logEntryRaw(nf2_of_entry_wrap* entry) {
#ifndef NF2_DEBUG
	return;
#endif

	int i;
	unsigned char* c;

	LOG("E ");
	c = (unsigned char*)entry;
	for (i = 0; i < sizeof(nf2_of_entry_wrap); ++i) {
		if (!(i % 4)) {
			LOG(" ");
		}
		LOG("%02x", c[i]);
	}
	LOG("\n");
}

void logMask(nf2_of_mask_wrap* mask) {
#ifndef NF2_DEBUG
	return;
#endif

	int i;

	// Log the physical source port
	LOG("M psrc[%0X] ", mask->entry.src_port / 2);

	// Log the link layer source
	LOG("dlsrc[");
	for (i=5; i > 0; --i) {
		LOG("%0X:", mask->entry.eth_src[i]);
	}
	LOG("%0X] ", mask->entry.eth_dst[0]);

	// Log the link layer dest
	LOG("dldst[");
	for (i=5; i > 0; --i) {
		LOG("%0X:", mask->entry.eth_dst[i]);
	}
	LOG("%0X] ", mask->entry.eth_dst[0]);

	// Log the link layer type
	LOG("dltype[%0X] ", mask->entry.eth_type);

	// Log the link layer vlan
	LOG("dlvlan[%0X] ", mask->entry.vlan_id);

	// Log the network source
	LOG("nwsrc[");
	LOG("%0X.", (mask->entry.ip_src >> 24) & 0xFF);
	LOG("%0X.", (mask->entry.ip_src >> 16) & 0xFF);
	LOG("%0X.", (mask->entry.ip_src >> 8) & 0xFF);
	LOG("%0X", mask->entry.ip_src & 0xFF);
	LOG("] ");

	// Log the network dest
	LOG("nwdst[");
	LOG("%0X.", (mask->entry.ip_dst >> 24) & 0xFF);
	LOG("%0X.", (mask->entry.ip_dst >> 16) & 0xFF);
	LOG("%0X.", (mask->entry.ip_dst >> 8) & 0xFF);
	LOG("%0X", mask->entry.ip_dst & 0xFF);
	LOG("] ");

	// Log the transport source port
	LOG("tsrc[%0X] ", mask->entry.transp_src);

	// Log the transport dest port
	LOG("tdst[%0X]\n", mask->entry.transp_dst);
}

void logMaskRaw(nf2_of_mask_wrap* mask) {
#ifndef NF2_DEBUG
	return;
#endif

	int i;
	unsigned char* c;

	LOG("M ");
	c = (unsigned char*)mask;
	for (i = 0; i < sizeof(nf2_of_mask_wrap); ++i) {
		if (!(i % 4)) {
			LOG(" ");
		}
		LOG("%02x", c[i]);
	}
	LOG("\n");
}

void logAction(nf2_of_action_wrap* action) {
#ifndef NF2_DEBUG
	return;
#endif

	int i;

	LOG("A Output P[");
	for (i=0; i < 4; ++i) {
		if (action->action.forward_bitmask & (1 << (i*2))) {
			LOG("%i", i);
		}
	}
	LOG("] CPU[");
	for (i=0; i < 4; ++i) {
		if (action->action.forward_bitmask & (1 << (1+(i*2)))) {
			LOG("%i", i);
		}
	}
	LOG("]\n");
}

void logActionRaw(nf2_of_action_wrap* action) {
#ifndef NF2_DEBUG
	return;
#endif

	int i;
	unsigned char* c;

	LOG("A ");
	c = (unsigned char*)action;
	for (i = 0; i < sizeof(nf2_of_action_wrap); ++i) {
		if (!(i % 4)) {
			LOG(" ");
		}
		LOG("%02x", c[i]);
	}
	LOG("\n");
}

/*
 * Write a wildcard entry to the specified device and row. The row consists of
 * the actual entry, its mask that specifies wildcards, as well as the action(s)
 * to be taken if the row is matched
 */
int nf2_write_of_wildcard(struct net_device *dev, int row,
	nf2_of_entry_wrap* entry, nf2_of_mask_wrap* mask,
	nf2_of_action_wrap* action) {

	int i;
	int val;
	struct timeval t;

	LOG("** Begin wildcard entry write to row: %i\n", row);
	logEntry(entry);
	logMask(mask);
	logAction(action);
	logEntryRaw(entry);
	logMaskRaw(mask);
	logActionRaw(action);

	for	(i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_BASE_REG + (4*i),
			&(entry->raw[i]));
	}

	for	(i = 0; i < NF2_OF_MASK_WORD_LEN; ++i) {
		nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_BASE_REG +
			(4*i), &(mask->raw[i]));
	}

	for	(i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_ACTION_BASE_REG +
			(4*i), &(action->raw[i]));
	}

	// reset the stats for the row
	val = 0;
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_BASE_REG, &val);
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_BASE_REG, &val);
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_REG, &val);

	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_WRITE_ADDR_REG, &row);
	do_gettimeofday(&t);
	LOG("** End wildcard entry write to row: %i\ time: %i.%i\n", row,
			(int)t.tv_sec, (int)t.tv_usec);

	return 0;
}

int nf2_write_of_exact(struct net_device *dev, int row,
	nf2_of_entry_wrap* entry, nf2_of_action_wrap* action) {

	int i;
	int val;
	unsigned char* c;
	struct timeval t;

	unsigned int index = row << 7;

	LOG("** Begin exact match entry write to row: %i\n", row);
	logEntry(entry);
	logAction(action);
	logEntryRaw(entry);
	logActionRaw(action);

	for	(i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		nf2k_reg_write(dev, SRAM_BASE_ADDR_REG + index + (4*i), &(entry->raw[i]));
	}

	// blank out the counters
	val = 0;
	for	(i = 0; i < NF2_OF_EXACT_COUNTERS_WORD_LEN; ++i) {
		nf2k_reg_write(dev, SRAM_BASE_ADDR_REG + index +
			sizeof(nf2_of_entry_wrap) + (4*i), &val);
	}

	// write the actions
	for	(i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		nf2k_reg_write(dev, SRAM_BASE_ADDR_REG + index +
			sizeof(nf2_of_entry_wrap) + sizeof(nf2_of_exact_counters_wrap) +
			(4*i), &(action->raw[i]));
	}

	do_gettimeofday(&t);
	LOG("** End exact match entry write to row: %i\ time: %i.%i\n", row,
			(int)t.tv_sec, (int)t.tv_usec);

	return 0;
}

unsigned int nf2_get_exact_packet_count(struct net_device *dev, int row) {
	unsigned int val = 0;
	int i;
	unsigned char* c;
	nf2_of_exact_counters_wrap counters;
	memset(&counters, 0, sizeof(nf2_of_exact_counters_wrap));

	// build the index to our counters
	unsigned int index = row << 7;

	// Read the first word into our struct, to not disturb the byte count
	nf2k_reg_read(dev, SRAM_BASE_ADDR_REG + index + sizeof(nf2_of_entry_wrap),
		&counters);
	val = counters.counters.pkt_count;

	LOG("** Exact match packet count request row: %i count: %i\n", row, val);
	return val;
}

unsigned int nf2_get_exact_byte_count(struct net_device *dev, int row) {
	unsigned int val = 0;
	int i;
	unsigned char* c;
	nf2_of_exact_counters_wrap counters;
	memset(&counters, 0, sizeof(nf2_of_exact_counters_wrap));

	// build the index to our counters
	unsigned int index = row << 7;

	// Read the second word into our struct, to not disturb the packet count
	nf2k_reg_read(dev, SRAM_BASE_ADDR_REG + index +
		sizeof(nf2_of_entry_wrap) + 4, &counters.raw[1]);
	val = counters.counters.byte_count;

	LOG("** Exact match byte count request row: %i count: %i\n", row, val);
	return val;
}

unsigned int nf2_get_wildcard_packet_count(struct net_device *dev, int row) {
	unsigned int val = 0;
	struct timeval t;

	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, &row);
	nf2k_reg_read(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_BASE_REG+(4*row), &val);

#ifdef NF2_DEBUG
	do_gettimeofday(&t);
	LOG("** Wildcard packet count request row: %i count: %i time: %i.%i\n", row, val,
			(int)t.tv_sec, (int)t.tv_usec);
#endif
	return val;
}

unsigned int nf2_get_wildcard_byte_count(struct net_device *dev, int row) {
	unsigned int val = 0;
	struct timeval t;

	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, &row);
	nf2k_reg_read(dev, OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_BASE_REG+(4*row), &val);
#ifdef NF2_DEBUG
	do_gettimeofday(&t);
	LOG("** Wildcard byte count request row: %i count: %i time: %i.%i\n", row, val,
			(int)t.tv_sec, (int)t.tv_usec);
#endif
	return val;
}
