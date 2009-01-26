#ifndef NF2_OPENFLOW_H_
#define NF2_OPENFLOW_H_

#include <linux/types.h>
#include <linux/etherdevice.h>

#define OPENFLOW_NF2_EXACT_TABLE_SIZE 32768

#pragma pack(push)  /* push current alignment to stack */
#pragma pack(1)     /* set alignment to 1 byte boundary */

#define NF2_OF_ENTRY_WORD_LEN 8
struct nf2_of_entry {
	uint16_t 	transp_dst;
	uint16_t 	transp_src;
	uint8_t 	ip_proto;
	uint32_t 	ip_dst;
	uint32_t	ip_src;
	uint16_t	eth_type;
	uint8_t		eth_dst[6];
	uint8_t		eth_src[6];
	uint8_t		src_port;
	uint16_t	vlan_id;
	uint16_t	pad;	
};

typedef union nf2_of_entry_wrap {
	struct nf2_of_entry entry;
	uint32_t			raw[NF2_OF_ENTRY_WORD_LEN];	
} nf2_of_entry_wrap;

typedef nf2_of_entry_wrap nf2_of_mask_wrap;
#define NF2_OF_MASK_WORD_LEN 8

struct nf2_of_action {
	uint16_t	forward_bitmask;
	uint16_t	pkt_trim_action;
	uint16_t	vlan_mod_action;
	uint8_t		reserved[34];	
};

#define NF2_OF_ACTION_WORD_LEN 10
typedef union nf2_of_action_wrap {
	struct nf2_of_action 	action;
	uint32_t				raw[10];
} nf2_of_action_wrap;

struct nf2_of_exact_counters {
	uint32_t	pkt_count : 25;
	uint8_t		last_seen : 7;
	uint32_t	byte_count;
};

#define NF2_OF_EXACT_COUNTERS_WORD_LEN 2
typedef union nf2_of_exact_counters_wrap {
	struct nf2_of_exact_counters	counters;
	uint32_t	raw[NF2_OF_EXACT_COUNTERS_WORD_LEN];
} nf2_of_exact_counters_wrap;

#pragma pack(pop)   /* restore original alignment from stack */

int nf2_write_of_wildcard(struct net_device *dev, int row, 
			  nf2_of_entry_wrap* entry, nf2_of_mask_wrap* mask, 
			  nf2_of_action_wrap* action);
int nf2_write_of_exact(struct net_device *dev, int row, 
		       nf2_of_entry_wrap* entry, nf2_of_action_wrap* action);

int nf2_modify_write_of_wildcard(struct net_device *dev, int row,
				 nf2_of_entry_wrap* entry, nf2_of_mask_wrap* mask,
				 nf2_of_action_wrap* action);
int nf2_modify_write_of_exact(struct net_device *dev, int row,
			      nf2_of_action_wrap* action);

void nf2_reset_card(struct net_device *dev);

/* Functions to get the packet and byte counts for exact rows */
unsigned int nf2_get_exact_packet_count(struct net_device *dev, int row);
unsigned int nf2_get_exact_byte_count(struct net_device *dev, int row);

/* Functions to get the packet and byte counts for wildcard rows */
unsigned int nf2_get_wildcard_packet_count(struct net_device *dev, int row);
unsigned int nf2_get_wildcard_byte_count(struct net_device *dev, int row);

/* Functions to get the table-matched and table-missed counts */
unsigned long int nf2_get_matched_count(struct net_device *dev);
unsigned long int nf2_get_missed_count(struct net_device *dev);

#endif /* NF2_OPENFLOW_H_ */
