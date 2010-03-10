#ifndef SAMPLE_PLATFORM_HW_FLOW_H
#define SAMPLE_PLATFORM_HW_FLOW_H 1

/*
 * Hardware Flow operations:  The glue between software flows and
 * actual hardware table entries.
 */

#include <openflow/openflow.h>
#include <of_hw_api.h>

#include "of_hw_platform.h"

/* DEBUG for HW flow lists */
#define HW_FLOW_MAGIC 0xba5eba11
#define HW_FLOW_MAKE_VALID(hf) (hf)->magic = HW_FLOW_MAGIC
#define HW_FLOW_IS_VALID(hf) \
    (((hf) != NULL) && ((hf)->magic == HW_FLOW_MAGIC))

/* Some flows require multiple HW entries */
#define HW_FLOWS_PER_FLOW_MAX (2)

/* The glue between SW flows and HW entries */
typedef struct hw_flow {
    struct sw_flow *flow;    /* Corresponding SW flow */
    of_hw_driver_t *hw_drv;  /* DP for this flow; MAY BE NULL for internal */
    int entry_count;  /* SW flow may require multiple HW table entries */
    entry_control_t *entry_list[HW_FLOWS_PER_FLOW_MAX];
    uint32 hw_packet_count;
    uint32 hw_byte_count;
    uint32 magic; /* DEBUG */
} hw_flow_t;

/* Extra info needed by hardware about flow entry;
 * determined during supported check; all in host order
 *
 * For smac, dmac, vid and priority, if these are changed at ingress
 * and a remote rule is necessary, the remote rule must have the
 * rewrite values to match.  This is indicated if value is not -1.
 */
typedef struct hw_flow_extra_s {
    int source_port;     /* If single source port, what is it */
    int dest_port;       /* If one dest port, what is it */
    /* If multi dest ports, one pbmp per device */
    FIXME dports;
    int dest_count;      /* Drop (0), unicast (1), multicast (>1) */
    uint32 local_reason; /* Why forwarded to CPU */
    int cosq;            /* For enqueue action */
} hw_flow_extra_t;

/* Driver functions */
extern int of_hw_flow_install(struct sw_table *flowtab, struct sw_flow *flow);
extern int of_hw_flow_modify(struct sw_table *flowtab,
    const struct sw_flow_key *key, uint16_t priority, int strict,
    const struct ofp_action_header *actions, size_t actions_len);
extern int of_hw_flow_delete(struct datapath *dp, struct sw_table *flowtab,
    const struct sw_flow_key *key, uint16_t out_port,
    uint16_t priority, int strict);
extern void of_hw_flow_timeout(struct sw_table *flowtab,
                                struct list *deleted);
extern struct sw_flow *of_hw_flow_lookup(struct sw_table *flowtab,
    const struct sw_flow_key *key);


extern int of_hw_sw_flow_stat_update(struct sw_flow *flow, int *used,
    int force_sync);
extern int of_hw_flow_stats_get(of_hw_driver_t *hw_drv, struct ofp_match,
    struct ofp_flow_stats **stats, int *count);
extern int of_hw_aggregate_stats_get(struct ofp_match,
    struct ofp_aggregate_stats_reply *stats);

/* Controls a single FP (HW table flow) entry */
struct entry_control_s {
    /* These must be persistent; update fp_entry_remove if you change this */
    int index; /* This entry-s index in field_control list */

    int in_use;
    hw_flow_t *hw_flow;

    /*
     * HW specific info
     */
    FIXME;

    unsigned long int used_check; /* Last counter; for checking if used */
    unsigned long int last_counter; /* pkts or bytes, see stat_sel above */
    unsigned long int counter_last_check;   /* Track entry usage by cntr */
    unsigned long int total_counter; /* FIXME: u64? */
};

/* Driver associated with a HW entry */
#define HW_ENTRY_DRIVER(ent) ((ent)->hw_flow->hw_drv)

/* FP control structure */
struct field_control_s {
    /* HW Specific info */
    FIXME;
    int entry_count;   /* How many entries in use */
    entry_control_t entry_list[FIELD_ENTRY_MAX]; /* Instantiation of entries */
};

/* FIXME:  Do we need reference counts on stat objects? */

extern int of_hw_fp_setup(void);
extern int of_hw_table_stats_update(of_hw_driver_int_t *hw_drv,
    unsigned long *matched, unsigned long *missed);

extern void of_hw_flow_remove_all(of_hw_driver_int_t *hw_int);


#endif /* SAMPLE_PLATFORM_HW_FLOW_H */
