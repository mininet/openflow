#ifndef HWTABLENF2_H_
#define HWTABLENF2_H_

#include <linux/list.h>

#include "flow.h"
#include "table.h"

#include "nf2_openflow.h"

struct sw_flow_nf2 {
	struct list_head node;
	uint32_t pos;
	uint32_t type;
	uint32_t hw_packet_count;
	uint32_t hw_byte_count;
};

struct sw_table_nf2 {
	struct sw_table swt;

	spinlock_t lock;
	unsigned int max_flows;
	atomic_t n_flows;
	struct list_head flows;
	struct list_head iter_flows;
	unsigned long int next_serial;
};

enum nf2_of_table_type {
	NF2_TABLE_EXACT,
	NF2_TABLE_WILDCARD
};

/* Functions to convert between OpenFlow and NetFPGA structs */
void nf2_populate_of_entry(nf2_of_entry_wrap *key, struct sw_flow *flow);
void nf2_populate_of_mask(nf2_of_mask_wrap *mask, struct sw_flow *flow);
void nf2_populate_of_action(nf2_of_action_wrap *action,
			    nf2_of_entry_wrap *entry, nf2_of_mask_wrap *mask,
			    struct sw_flow *flow);
void nf2_clear_of_wildcard(uint32_t pos);

/* Function to check if the actions specified by a flow are supported by hw */
int nf2_are_actions_supported(struct sw_flow *flow);

/* Retrieve a net_device struct for the NetFPGA */
struct net_device* nf2_get_net_device(void);
/* Free a net_device struct */
void nf2_free_net_device(struct net_device* dev);

void add_free_exact(struct sw_flow_nf2* sfw);
void add_free_wildcard(struct sw_flow_nf2* sfw);
int nf2_write_static_wildcard(void);

int init_exact_free_list(void);
int init_wildcard_free_list(void);

void destroy_exact_free_list(void);
void destroy_wildcard_free_list(void);

struct sw_flow_nf2* get_free_wildcard(void);
int nf2_get_table_type(struct sw_flow *flow);
int nf2_build_and_write_flow(struct sw_flow *flow);
void nf2_delete_private(void* private);

int nf2_modify_acts(struct sw_table *swt, struct sw_flow *flow);

uint64_t nf2_get_packet_count(struct net_device *dev, struct sw_flow_nf2 *sfw);
uint64_t nf2_get_byte_count(struct net_device *dev, struct sw_flow_nf2 *sfw);

#endif	/* HWTABLENF2_H_ */
