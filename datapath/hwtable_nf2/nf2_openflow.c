#include <linux/time.h>
#include "hwtable_nf2/nf2_openflow.h"
#include "hwtable_nf2/nf2.h"
#include "hwtable_nf2/reg_defines.h"
#include "hwtable_nf2/nf2_export.h"

void nf2_reset_card(struct net_device *dev) {
	unsigned int val = 0x00010100;
	
	/* If we are operating on a NetFPGA enabled box, reset the card */
	if (dev) {
		printk("openflow: Resetting the NetFPGA.\n");		
		nf2k_reg_write(dev, CPCI_REG_CTRL, &val);
		printk("openflow: Reset the NetFPGA.\n");	
	}
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
	unsigned char* c;
	struct timeval t;
		
	printk("Entry: ");
	for	(i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_BASE_REG + (4*i),
			&(entry->raw[i]));
	}
	c = (unsigned char*)entry;
	for (i = 0; i < sizeof(nf2_of_entry_wrap); ++i) {
		if (!(i % 4)) {
			printk(" ");
		}
		printk("%02x", c[i]);
	}
	printk("\n");
	
	printk("Mask: ");
	for	(i = 0; i < NF2_OF_MASK_WORD_LEN; ++i) {
		nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_BASE_REG + 
			(4*i), &(mask->raw[i]));
	}
	c = (unsigned char*)mask;
	for (i = 0; i < sizeof(nf2_of_mask_wrap); ++i) {
		if (!(i % 4)) {
			printk(" ");
		}
		printk("%02x", c[i]);
	}
	printk("\n");

	printk("Action: ");
	for	(i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_ACTION_BASE_REG + 
			(4*i), &(action->raw[i]));
	}
	c = (unsigned char*)action;
	for (i = 0; i < sizeof(nf2_of_action_wrap); ++i) {
		if (!(i % 4)) {
			printk(" ");
		}
		printk("%02x", c[i]);
	}
	printk("\n");
	
	// reset the stats for the row
	val = 0;
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_BASE_REG, &val);
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_BASE_REG, &val);
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_REG, &val);

	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_WRITE_ADDR_REG, &row);
	do_gettimeofday(&t);
	printk("NF2 - wrote wildcard entry to position: %i at time: %i.%i\n", row, 
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
		
	printk("Index: %x\n", index);
		
	printk("Entry: \n");
	for	(i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		nf2k_reg_write(dev, SRAM_BASE_ADDR_REG + index + (4*i), &(entry->raw[i]));
		printk("Writing %08x into address %08x\n", entry->raw[i], SRAM_BASE_ADDR_REG + index + (4*i));
	}
	c = (unsigned char*)entry;
	for (i = 0; i < sizeof(nf2_of_entry_wrap); ++i) {
		if (!(i % 4)) {
			printk(" ");
		}
		printk("%02x", c[i]);
	}
	printk("\n");

	// blank out the counters
	val = 0;
	for	(i = 0; i < NF2_OF_EXACT_COUNTERS_WORD_LEN; ++i) {
		nf2k_reg_write(dev, SRAM_BASE_ADDR_REG + index + 
			sizeof(nf2_of_entry_wrap) + (4*i), &val);
		printk("Writing %08x into address %08x\n", 0, SRAM_BASE_ADDR_REG + index + sizeof(nf2_of_entry_wrap) + (4*i));
	}
	
	// write the actions
	printk("Action: ");
	for	(i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		nf2k_reg_write(dev, SRAM_BASE_ADDR_REG + index + 
			sizeof(nf2_of_entry_wrap) + sizeof(nf2_of_exact_counters_wrap) + 
			(4*i), &(action->raw[i]));
		printk("Writing %08x into address %08x\n", action->raw[i], SRAM_BASE_ADDR_REG + index + sizeof(nf2_of_entry_wrap) + sizeof(nf2_of_exact_counters_wrap) + (4*i));
	}
	c = (unsigned char*)action;
	for (i = 0; i < sizeof(nf2_of_action_wrap); ++i) {
		if (!(i % 4)) {
			printk(" ");
		}
		printk("%02x", c[i]);
	}
	printk("\n");
	
	do_gettimeofday(&t);
	printk("NF2 - wrote exact entry to position: %i at time: %i.%i\n", row, 
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
	
	printk("---Row: %i Packet Count: %i ---\n", row, val);
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
	
	printk("---Row: %i Byte Count: %i ---\n", row, val);
	return val;
}

unsigned int nf2_get_wildcard_packet_count(struct net_device *dev, int row) {
	unsigned int val = 0;
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, &row);
	nf2k_reg_read(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_BASE_REG+(4*row), &val);
	printk("---Row: %i Packet Count: %i ---\n", row, val);
	return val;
}

unsigned int nf2_get_wildcard_byte_count(struct net_device *dev, int row) {
	unsigned int val = 0;
	nf2k_reg_write(dev, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, &row);
	nf2k_reg_read(dev, OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_BASE_REG+(4*row), &val);
	//printk("---Row: %i Byte Count: %i ---\n", row, val);
	return val;
}
