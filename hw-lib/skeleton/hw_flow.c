/*
 * Functions related to hardware flow processing; this is the glue
 * and administration between upper level flow operations and lower
 * level field processor operations.
 */

#include <arpa/inet.h>
#include <openflow/openflow.h>
#include <of_hw_api.h>

#include "os.h"
#include "debug.h"
#include "hw_drv.h"
#include "port.h"
#include "hw_flow.h"
#include "udatapath/switch-flow.h"
#include "udatapath/datapath.h"
#include "lib/packets.h"

static field_control_t field_control;

/****************************************************************
 *
 * SW/HW flow correlation book keeping routines
 *
 ****************************************************************/

/* Allocate and initialize a HW flow control structure. */
static hw_flow_t *
hw_flow_create(struct sw_flow *flow)
{
    hw_flow_t *hw_flow;

    if ((hw_flow = ALLOC(sizeof(*hw_flow))) != NULL) {
        memset(hw_flow, 0, sizeof(*hw_flow));
        HW_FLOW_MAKE_VALID(hw_flow);
        hw_flow->flow = flow;
        flow->private = (void *)hw_flow;
    }

    return hw_flow;
}

/* Remove an FP entry from a device */
static int
HW_entry_remove(entry_control_t *entry)
{
    FIXME;

    return 0;
}

/****************************************************************
 *
 * Flow stats operations
 *
 ****************************************************************/

/*
 * Read and convert the stats for an FP entry; maintains state
 * of last counter value read and accumulates differences.
 *
 * Assumes mutex held.
 */
static int
entry_stat_update(entry_control_t *ent, int *used)
{
    unsigned long int cur_counter;

    FIXME_get_current_stats(cur_counter);

    ent->total_counter += cur_counter - ent->last_counter;
    ent->last_counter = cur_counter;

    if (used != NULL) {
        *used |= (ent->used_check != cur_counter);
        ent->used_check = cur_counter;
    }

    return 0;
}

/*
 * Get the stats for an OF (SW) flow object from HW tables
 * NOTE:  This will clear any existing value from the flow
 * counters; if SW table counters need to be added in, that
 * should be done after this calculation.
 *
 * If used is non-NULL, it will be filled with a boolean
 * indication of whether the flow's counters have changed
 * from their current state.
 *
 * Assumes mutex held.
 *
 * If force_sync is true, will sync SW counters with HW first
 */
int
of_hw_sw_flow_stat_update(struct sw_flow *flow, int *used, int force_sync)
{
    entry_control_t *ent;
    hw_flow_t *hw_flow;
    int idx;

    if (used != NULL) {
        *used = false;
    }
    hw_flow = (hw_flow_t *)(flow->private);
    if (!HW_FLOW_IS_VALID(hw_flow)) {
        DBG_ERROR("BAD HW FLOW OBJECT %p for flow %p\n", hw_flow, flow);
        return -1;
    }
    ASSERT(hw_flow->entry_count <= HW_FLOWS_PER_FLOW_MAX);

    if (force_sync) {
        FIXME_sync_hw_stats();
    }

    /* FIXME:  Will this accumulate and clear HW counters? */
    hw_flow->hw_byte_count = hw_flow->hw_packet_count = 0;
    for (idx = 0; idx < hw_flow->entry_count; idx++) {
        ent = hw_flow->entry_list[idx];

        if (entry_stat_update(ent, used) < 0) {
            DBG_WARN("Warning: could not get stats for flow\n");
            continue;
        }
        FIXME_update proper hw_flow counters;
    }
    flow->packet_count = hw_flow->hw_packet_count;
    flow->byte_count = hw_flow->hw_byte_count;

    return 0;
}

/* Read all the stats from the chip and update counters in flow tab */
/* Index 0 holds default rule that indicates a missed count */
/* ASSUMES LOCK HELD */
int
of_hw_table_stats_update(of_hw_driver_int_t *hw_drv, unsigned long *matched,
                          unsigned long *missed)
{
    struct sw_flow *flow, *n;
    of_hw_driver_int_t *hw_int;

    hw_int = (of_hw_driver_int_t *)hw_drv;
    *matched = 0;
    *missed = 0;

    if (STATS_BYTES(hw_int->stat_sel)) { /* Lookup count not supported */
        return -1;
    }

    LIST_FOR_EACH_SAFE (flow, n, struct sw_flow, node, &hw_int->flows) {
        if (flow->private != NULL) {
            TRY_NR(of_hw_sw_flow_stat_update(flow, NULL, false),
                   "update flow stat");
            *matched += flow->packet_count;
        }
    }

    /*
     * FIXME: To get missed stats, query entry 0 of HW table.
     * This isn't really correct if there are entries in the SW datapath
     *
     * FIXME:  If there are multiple data paths, should have one
     * default entry qualifying on ports in that datapath with
     * another entry dropping any packets on other ports.
     */
    {
        field_control_t *fc;
        entry_control_t *ent;

        fc = &field_control;
        ent = &fc->entry_list[0];
        ASSERT(ent->in_use);
        TRY_NR(entry_stat_update(ent, NULL), "tab: entry_stat_update");
        *missed += ent->total_counter;
    }

    return 0;
}

/*
 * Remove the FP entry or entries associated to a SW flow from the HW;
 *
 */
static int
hw_flow_remove(struct sw_flow *flow)
{
    field_control_t *fc;
    entry_control_t *ent;
    hw_flow_t *hw_flow;
    int idx;

#if 0 /* Do not remove entries (debugging) */
    return 0;
#endif

    if (flow == NULL) {
        return 0;
    }

    hw_flow = (hw_flow_t *)(flow->private);
    DBG_VERBOSE("Removing hw flow %p, flow %p\n", hw_flow, flow);
    if (!HW_FLOW_IS_VALID(hw_flow)) {
        return 0;
    }
    ASSERT(hw_flow->entry_count <= HW_FLOWS_PER_FLOW_MAX);

    TRY_NR(of_hw_sw_flow_stat_update(flow, NULL, true),
           "rmv flow stat update");
    for (idx = 0; idx < hw_flow->entry_count; idx++) {
        ent = hw_flow->entry_list[idx];
        ASSERT(ent != NULL);

        TRY_NR(HW_entry_remove(ent), "HW_entry_remove");
        hw_flow->entry_list[idx] = NULL;
    }
    FREE(hw_flow);
    flow->private = NULL;

    return 0;
}


/****************************************************************
 *
 * Important support routines related to FP setup, actions, flows
 *
 ****************************************************************/

/* ASSERT: of_port belongs to datapath */
static void
add_dport_to_extra(of_hw_driver_int_t *hw_int, int of_port,
                   hw_flow_extra_t *extra)
{
    ASSERT(OF_PORT_IN_DP(hw_int, of_port));

    extra->dest_port = MAP_OF_PORT_TO_HW_PORT(hw_int, of_port);
    FIXME_update extra->dest_count if appropriate;
}

/* Set up flood/all bitmaps
 * NOTE:  Assumes source port is not wildcarded.
 */
static void
mcast_bitmaps_set(of_hw_driver_int_t *hw_int, hw_flow_extra_t *extra,
                  int dest_port)
{
    FIXME;
}

/*
 * Validate actions for a flow relative to HW capabilities;
 *
 * Bool:  true means supported, false not supported
 *
 * Accumulate additional info about the flow in extra.  Specifically,
 * this determines the output ports on each physical device related
 * to the flow.
 *
 * FIXME:  No-flood ports are currently not specified
 */

static int
actions_supported_check(of_hw_driver_int_t *hw_int,
                        const struct sw_flow_key *key,
                        const struct ofp_action_header *actions,
                        size_t actions_len,
                        hw_flow_extra_t *extra)
{
    uint8_t *p;
    int src_port; /* Port in host order */
    int dest_port; /* Port in host order */
    int action;
    int src_is_wc = false;  /* Is source wildcarded? */

    ANNOUNCE_LOCATION;
    ASSERT(extra != NULL);

    FIXME("probably needs work for your platform");

    p = (uint8_t *)actions;
    src_port = ntohs(key->flow.in_port);

    src_is_wc = key->wildcards & OFPFW_IN_PORT;
    if (!src_is_wc) {
        if (OF_PORT_IN_DP(hw_int, src_port)) {
            extra->source_port = MAP_TO_HW_PORT(hw_int, src_port);
        } else {
            DBG_WARN("Source port %d not in DP %d\n", src_port,
                     hw_int->dp_idx);
            return false;
        }
    } else {
        extra->source_port = -1;
        if (of_hw_drv_instances > 1) {
            DBG_WARN("Source port WC not supported w/ multi-DP\n");
            return false;  /* Not currently supported w/ multiple datapaths */
        }
        /* NOTE/FIXME:  Source wildcard with multiple output ports requires
         * using a per-port hardware flow rule to allow filtering of
         * the source port.  (Currently not supported and checked below.)
         */
    }

    while (actions_len > 0) {
        struct ofp_action_header *ah = (struct ofp_action_header *)p;
        struct ofp_action_output *oa = (struct ofp_action_output *)p;
        size_t len = ntohs(ah->len);

        action = ntohs(ah->type);
        DBG_VVERB("action chk %d\n", action);
        /* Currently supported: output port(s) action */
        if ((action < 0) || (action > ACTION_LAST)) {
            DBG_WARN("Unknown action id %d\n", action);
            return false;
        }

        if (action_map[action] == ACTION_NOT_SUPPORTED) {
            DBG_WARN("Action %d not supported\n", action);
            return false;
        }

        /* Support front panel ports plus IN_PORT, ALL, FLOOD. */
        if ((action == OFPAT_OUTPUT) || (action == OFPAT_ENQUEUE)) {
            /* FIXME:  For now, using the fact that enqueue and output
             * actions are the same at the start of the structure
             */
            dest_port = ntohs(oa->port);
            if (dest_port == OFPP_TABLE) { /* Unsupported */
                DBG_WARN("Warning:  TABLE output action seen\n");
                return false;
            } else if (OF_PORT_IN_DP(hw_int, dest_port)) {
                add_dport_to_extra(hw_int, dest_port, extra);
            } else if ((dest_port == OFPP_FLOOD) || (dest_port == OFPP_ALL)) {
                mcast_bitmaps_set(hw_int, extra, dest_port);
            } else if (dest_port == OFPP_IN_PORT) {
                if (src_is_wc) {
                    DBG_WARN("Warning: IN_PORT action on source wildcard\n");
                    return false;
                }
                add_dport_to_extra(hw_int, src_port, extra);
            } else if (dest_port == OFPP_CONTROLLER) {
                /* Controller/local are implemented with a "copy to CPU"
                 * action and a special reason code; Don't count as output port
                 */
                extra->local_reason |= CPU_REASON_TO_CONTROLLER;
            } else if (dest_port == OFPP_LOCAL) {
                extra->local_reason |= CPU_REASON_TO_LOCAL;
            } else {  /* NORMAL */
                //    DBG_WARN("Output action to port 0x%x not supported\n",
                //       dest_port);
                //        return false;  /* FIXME: Ignore bad ports for now */
            }
            if (action == OFPAT_ENQUEUE) {
                uint32 qid;
                struct ofp_action_enqueue *ea;
                ea = (struct ofp_action_enqueue *)p;
                qid = ntohl(ea->queue_id);
                if ((extra->cosq = of_hw_qid_find(dest_port, qid)) < 0) {
                    DBG_WARN("Warning: qid %d, port %d, map to cos failed\n",
                             qid, dest_port);
                }
            }
        }
        p += len;
        actions_len -= len;
    }

    if (src_is_wc && (extra->dest_count > 1)) {
        DBG_WARN("Warning: multi dest w/ src wildcard\n");
        return false;
    }

    DBG_VERBOSE("Actions supported\n");
    return true;
}

/****************************************************************
 *
 * FP Table management and manipulation routines
 *
 ****************************************************************/

/*
 * Functions related to hardware flow table manipulation and maintenance
 */

/* Set up field control structure; should be idempotent */
static void
field_control_init(void)
{
    field_control_t *fc;
    int idx;

    fc = &field_control;
    fc->entry_count = 0;
    for (idx = 0; idx < FIELD_ENTRY_MAX; idx++) {
        fc->entry_list[idx].in_use = 0;
        fc->entry_list[idx].hw_flow = NULL;
        fc->entry_list[idx].index = idx;
        fc->entry_list[idx].last_counter = 0;
        fc->entry_list[idx].counter_last_check = 0;
        fc->entry_list[idx].total_counter = 0;
    }
}

/* Alloc HW entry control structure, add qualification, actions and install */
static int
hw_entry_install(of_hw_driver_int_t *hw_int,
                 struct sw_flow *flow, hw_flow_t *hw_flow,
                 hw_flow_extra_t *extra)
{

    /* Install HW entry */
    FIXME;
}

/*
 * hw_flow_install
 *
 *   Install HW table entries corresponding to the given SW flow
 */
static int
hw_flow_install(of_hw_driver_int_t *hw_int, struct sw_flow *flow,
                hw_flow_extra_t *extra)
{
    hw_flow_t *hw_flow;

    /* Allocate the HW flow object */
    if ((hw_flow = hw_flow_create(flow)) == NULL) {
        DBG_ERROR("failed to create hw flow struct\n");
        return -1;
    }

    DBG_VERBOSE("hw flow install: sw %p. hw %p\n", flow, hw_flow);
    TRY(hw_entry_install(hw_int, 0, flow, hw_flow, extra),
        "local entry");

    return 0;
}

/****************************************************************
 *
 * The driver APIs
 *
 ****************************************************************/

/*
 * Install a flow.
 *
 * First, check that the flow is supported; simultaneously, build
 * up the "extra" information needed by the hardware for its installation.
 * This includes bitmaps of the ports to which the packet will be
 * forwarded (on local and remote devices if appropriate).
 *
 * Then look to see if the flow should overwrite an existing entry.
 * If so, just remove that entry.
 *
 * Then call hw_flow_install which does all the actual HW changes
 * based on the flow and on extra.
 */

/* NOTE: Returns 1 if flow installed, not normal error code */
int
of_hw_flow_install(struct sw_table *sw_tab, struct sw_flow *flow)
{
    hw_flow_extra_t extra;
    of_hw_driver_int_t *hw_int;
    int hw_rc = 0;
    int sw_insert_done = 0;
    struct sw_flow *f;

    hw_int = (of_hw_driver_int_t *)sw_tab;

    DBG_VERBOSE("flow install %p\n", flow);
    memset(&extra, 0, sizeof(extra));
    extra.cosq = -1;

    if (!actions_supported_check(hw_int, &flow->key, flow->sf_acts->actions,
                                 flow->sf_acts->actions_len, &extra)) {
        /* Unsupported actions */
        DBG_VERBOSE("HW install failed: Unsupported actions\n");
        return 0;
    }

    /* LOCK; */
    /* Go through list looking for matching flows */
    LIST_FOR_EACH (f, struct sw_flow, node, &hw_int->flows) {
        if (f->priority == flow->priority
                && f->key.wildcards == flow->key.wildcards
                && flow_matches_2wild(&f->key, &flow->key)) {
            /* Just remove the HW flow; install other below */
            TRY_NR(hw_flow_remove(f), "hw_flow_remove for replace");
            flow->serial = f->serial;
            list_replace(&flow->node, &f->node);
            list_replace(&flow->iter_node, &f->iter_node);
            sw_insert_done = 1;
            flow_free(f);
            break;
        }
        if (f->priority < flow->priority) {
            break;
        }
    }

    /* ASSERT: sw_insert_done OR f points to insertion point for flow */

    hw_rc = hw_flow_install(hw_int, flow, &extra);

    if (hw_rc < 0) {
        hw_int->insert_errors++;
        if (sw_insert_done) { /* Remove from SW list */
            list_remove(&flow->node);
            list_remove(&flow->iter_node);
            flow_free(flow);
            hw_int->n_flows--;
        }
    } else {
        hw_int->n_flows++;
        hw_int->n_inserts++;
        if (!sw_insert_done) {
            flow->serial = hw_int->next_serial++;
            list_insert(&f->node, &flow->node);
            list_push_front(&hw_int->iter_flows, &flow->iter_node);
        }
    }
    /* UNLOCK */

    if (hw_rc < 0) {
        DBG_WARN("Could not install flow in HW\n");
        if (sw_insert_done) { /* Remove from SW list */
            DBG_WARN("Removed matching flow but could not replace in HW\n");
        }
        return 0;
    }

    return 1;
}

/* FIXME: Change API to return list of deleted flows? */
/*        Would make this easier */
/* Remove a flow or flows from the HW and SW tracking tables */
int
of_hw_flow_delete(struct datapath *dp, struct sw_table *sw_tab,
                   const struct sw_flow_key *key, uint16_t out_port,
                   uint16_t priority, int strict)
{
    of_hw_driver_int_t *hw_int = (of_hw_driver_int_t *)sw_tab;
    struct sw_flow *flow, *n;
    int count = 0;
    struct list deleted;

    DBG_VERBOSE("delete: dp %p, idx %d, key %p, out 0x%x, prio %d, strict %d\n",
                dp, hw_int->dp_idx, key, out_port, priority, strict);

    list_init(&deleted);

    /* LOCK; */
    LIST_FOR_EACH_SAFE (flow, n, struct sw_flow, node, &hw_int->flows) {
        if (flow_matches_desc(&flow->key, key, strict)
                && flow_has_out_port(flow, out_port)
                && (!strict || (flow->priority == priority))) {
            TRY_NR(hw_flow_remove(flow), "hw flow remove");
            list_remove(&flow->node);
            list_remove(&flow->iter_node);
            list_push_back(&deleted, &flow->node);
            count++;
        }
    }
    /* UNLOCK; */

    /* Notify DP of deleted flows */
    LIST_FOR_EACH_SAFE (flow, n, struct sw_flow, node, &deleted) {
        dp_send_flow_end(dp, flow, flow->reason);
        list_remove(&flow->node);
        flow_free(flow);
    }

    return count;
}


/*
 * Modify an existing flow
 *
 * We chicken out and just de-install/re-install in HW
 */
int
of_hw_flow_modify(struct sw_table *sw_tab, const struct sw_flow_key *key,
                   uint16_t priority, int strict,
                   const struct ofp_action_header *actions, size_t actions_len)
{
    of_hw_driver_int_t *hw_int = (of_hw_driver_int_t *)sw_tab;
    struct sw_flow *flow;
    int count = 0;
    hw_flow_extra_t extra;

    memset(&extra, 0, sizeof(extra));
    extra.cosq = -1;
#if defined(PLATFORM_HAS_REMOTES)
    extra.new_vid = -1;
    extra.new_pcp = -1;
#endif

    if (!actions_supported_check(hw_int, &flow->key, actions,
                                 actions_len, &extra)) {
        /* Unsupported actions */
        DBG_VERBOSE("Mod actions-supported failed: Unsupported actions\n");
        return 0;
    }

    /* LOCK; */
    LIST_FOR_EACH (flow, struct sw_flow, node, &hw_int->flows) {
        if (flow_matches_desc(&flow->key, key, strict)
                && (!strict || (flow->priority == priority))) {
            /* Change the flow, de-install from HW and re-install */
            TRY_NR(hw_flow_remove(flow), "hw_flow_remove modify");
            flow_replace_acts(flow, actions, actions_len);
            TRY_NR(hw_flow_install(hw_int, flow, &extra),
                   "hw_flow_install modify");
            /* FIXME: Clear stats on flow if updated? */
            count++;
        }
    }
    /*     UNLOCK; */

    return count;
}

/*
 * Update stats
 * Call sw tracking table timeout
 * Iterate the deleted object list and call HW flow remove
 */
void
of_hw_flow_timeout(struct sw_table *sw_tab, struct list *deleted)
{
    of_hw_driver_int_t *hw_int = (of_hw_driver_int_t *)sw_tab;
    struct sw_flow *flow, *n;
    int used;
    uint64_t now = time_msec();

    /* LOCK; */
    /* FIXME */
    LIST_FOR_EACH_SAFE (flow, n, struct sw_flow, node, &hw_int->flows) {
        if (of_hw_sw_flow_stat_update(flow, &used, false) == 0) {
            if (used) {
                flow->used = now;
            } else {
                if (flow_timeout(flow)) {
                    DBG_VERBOSE("Flow %p expired\n", flow);
                    list_remove(&flow->node);
                    list_remove(&flow->iter_node);
                    list_push_back(deleted, &flow->node);
                    ASSERT(flow->private != NULL);
                    TRY_NR(hw_flow_remove(flow), "hw flow remove, timeout");
                    hw_int->n_flows--;
                }
            }
        }
    }

    /* UNLOCK; */
}

struct sw_flow *
of_hw_flow_lookup(struct sw_table *sw_tab, const struct sw_flow_key *key)
{
    of_hw_driver_int_t *hw_int = (of_hw_driver_int_t *)sw_tab;
    struct sw_flow *flow;

    LIST_FOR_EACH (flow, struct sw_flow, node, &hw_int->flows) {
        if (flow_matches_1wild(key, &flow->key))
            return flow;
    }
    return NULL;
}

int
of_hw_flow_stats_get(of_hw_driver_t *hw_drv, struct ofp_match match,
                      struct ofp_flow_stats **stats, int *count)
{
    DBG_WARN("FIXME FLOW STATS GET\n");
    return 0;
}

int
of_hw_aggregate_stats_get(struct ofp_match match,
                           struct ofp_aggregate_stats_reply *stats)
{
    DBG_WARN("FIXME AGGREGATE STATS GET\n");
    return 0;
}

void
of_hw_flow_remove_all(of_hw_driver_int_t *hw_int)
{
    struct sw_flow *flow, *n;

    /* FIXME:  Other de-init?  Keep count of DPs? */
    LIST_FOR_EACH_SAFE (flow, n, struct sw_flow, node, &hw_int->flows) {
        TRY_NR(hw_flow_remove(flow), "hw_flow_remove all");
        list_remove(&flow->node);
        list_remove(&flow->iter_node);
    }
}
