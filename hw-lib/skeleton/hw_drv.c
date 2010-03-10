/*
 * Skeleton hardware datapath, internal implemenation
 *
 */
#include <of_hw_api.h>

#include <string.h>
#include <stdlib.h>

#include "list.h"

#include "os.h"
#include "debug.h"
#include "of_hw_platform.h"
#include "hw_drv.h"
#include "hw_flow.h"
#include "port.h"
#include "txrx.h"
#include "udatapath/switch-flow.h"

/****************************************************************
 *
 * Hardware resource management section
 *
 ****************************************************************/

static int global_init_done = 0;
int of_hw_drv_instances = 0;

#if !defined(HWTABLE_NO_DEBUG)
int of_hw_debug = DBG_LVL_WARN;
#endif

/* Internal initialization of HW datapath structures */
static int
hw_drv_global_init(int init_hw)
{
    HW_DRV_MUTEX_INIT;
    of_hw_ports_init();

    if (init_hw) { /* Do hardware initialization */
        TRY(PLATFORM_INIT(), "PLATFORM INIT");
        TRY_NR(of_hw_fp_setup(), "global FP setup");
    }

    global_init_done = 1;
    return 0;
}

/* Skeleton capabilities structure */
static of_hw_driver_caps_t of_hw_caps = {
    .flags = ,
    .max_flows = ,
    .wc_supported = OFPFW_ALL,
    .actions_supported = OFPAT_XXX,
    .ofpc_flags = OFPC_XXX
};

/* Initialize the internal HW datapath structure */
static int
hw_drv_int_init(of_hw_driver_int_t *hw_int, struct datapath *dp)
{
    static int dp_idx = 0;

    /* Fill in caps object */
    memcpy(&hw_int->hw_driver.caps, &of_hw_caps, sizeof(of_hw_caps));
    hw_int->dp = dp;
    hw_int->dp_idx = dp_idx++;

    hw_int->n_flows = 0;
    list_init(&hw_int->flows);
    list_init(&hw_int->iter_flows);
    hw_int->next_serial = 0;

    return 0;
}

/****************************************************************
 *
 * Driver functions
 *
 ****************************************************************/

/*
 * of_hw_ioctl
 *
 * HW IOCTL function
 */

static int
of_hw_ioctl(of_hw_driver_t *hw_drv, uint32_t op, void **io_param,
             int *io_len UNUSED)
{
    int val;
    of_hw_driver_int_t *hw_int;
    int rv = 0;

    hw_int = (of_hw_driver_int_t *)hw_drv;

    switch (op) {
    case OF_HW_IOCTL_TABLE_DEBUG_SET:
        val = *(int *)(*io_param);
        DBG_WARN("Changing table debug value to %d\n", val);
        /* FIXME:  Use HW driver for debug level? */
        hw_int->table_debug_level = val;
        of_hw_debug = val;
        break;
    case OF_HW_IOCTL_PORT_DEBUG_SET:
        val = *(int *)(*io_param);
        DBG_WARN("Changing port debug value to %d\n", val);
        hw_int->port_debug_level = val;
        break;
    case OF_HW_IOCTL_BYTE_PKT_CNTR_SET:
        val = *(int *)(*io_param);
        if ((val != OF_HW_CNTR_PACKETS) &&
                (val != OF_HW_CNTR_BYTES)) {
            DBG_ERROR("Bad byte/pkt counters select value %d\n", val);
        } else {
            hw_int->stat_sel = val;
        }
        break;
    default:
        rv = -1; /* Change to UNSUPPORTED */
        break;
    }

    return 0;
}

static void
of_hw_table_destroy(struct sw_table *table)
{
    of_hw_driver_int_t *hw_int;

    hw_int = (of_hw_driver_int_t *)table;
    if (hw_int != NULL && hw_int->dp != NULL) {
        DBG_WARN("Table destroy called for dp idx %d\n",
                 hw_int->dp_idx);
    } else {
        DBG_ERROR("Table destroy called on NULL dp\n");
    }

    delete_of_hw_driver(&hw_int->hw_driver);
}

static int
of_hw_table_iterate(struct sw_table *table,
                     const struct sw_flow_key *key, uint16_t out_port,
                     struct sw_table_position *position,
                     int (*callback)(struct sw_flow *flow, void *private),
                     void *private)
{

    of_hw_driver_int_t *hw_int;
    struct sw_flow *flow;
    unsigned long start;

    hw_int = (of_hw_driver_int_t *)table;
    if (hw_int != NULL) {
        start = ~position->private[0];
        LIST_FOR_EACH (flow, struct sw_flow, iter_node, &hw_int->iter_flows) {
            if (flow->serial <= start
                    && flow_matches_2wild(key, &flow->key)
                    && flow_has_out_port(flow, out_port)) {
                int error;

                /* Update stats as that's what's generally used */
                TRY_NR(of_hw_sw_flow_stat_update(flow, NULL, false),
                       "sw flow stat update");
                error = callback(flow, private);
                if (error) {
                    position->private[0] = ~(flow->serial - 1);
                    return error;
                }
            }
        }
    } else {
        DBG_ERROR("Table iterate called on NULL driver or SW flow table\n");
        return -1;
    }

    return 0;
}

static const char *hw_drv_name = "HW FlowDriver";

static void
of_hw_sw_table_stats(struct sw_table *table, struct sw_table_stats *stats)
{
    of_hw_driver_int_t *hw_int;
    unsigned long matched = 0;
    unsigned long missed = 0;

    hw_int = (of_hw_driver_int_t *)table;
    stats->name = hw_drv_name;
    stats->wildcards = OFPFW_ALL;
    stats->n_flows = hw_int->n_flows;
    stats->max_flows = of_hw_caps.max_flows;
    /* FIXME:  Collect stats */
    TRY_NR(of_hw_table_stats_update(hw_int, &matched, &missed),
           "of_hw_table_stats_update");
    stats->n_lookup = missed + matched;
    stats->n_matched = matched;
}

static int
of_hw_table_stats_get(of_hw_driver_t *hw_drv, struct ofp_table_stats *stats)
{
    DBG_WARN("TABLE STATS FIXME\n");
    return 0;
}

/*
 * Create and initialize a new hardware datapath object
 */

of_hw_driver_t *
new_of_hw_driver(struct datapath *dp)
{
    struct sw_table *sw_tab;
    of_hw_driver_t *hw_drv;
    of_hw_driver_int_t *hw_int;

    if (!global_init_done) {
        if (hw_drv_global_init(1) < 0) {
            REPORT_ERROR("HW driver global init failed\n");
            return NULL;
        }
    }
    hw_int = ALLOC(sizeof(*hw_int));
    if (hw_int == NULL) {
        REPORT_ERROR("Could not allocate HW driver\n");
        return NULL;
    }
    memset(hw_int, 0, sizeof(*hw_int));

    if (hw_drv_int_init(hw_int, dp) < 0) {
        FREE(hw_int);
        return NULL;
    }


    /* These all point to the same place */
    hw_drv = &hw_int->hw_driver;
    sw_tab = &hw_drv->sw_table;

    sw_tab->n_lookup = 0;
    sw_tab->n_matched = 0;

    /* Fill out the function pointers */
    sw_tab->lookup = of_hw_flow_lookup;
    sw_tab->insert = of_hw_flow_install;
    sw_tab->modify = of_hw_flow_modify;
    sw_tab->delete = of_hw_flow_delete;
    sw_tab->timeout = of_hw_flow_timeout;

    sw_tab->destroy = of_hw_table_destroy;
    sw_tab->iterate = of_hw_table_iterate;
    sw_tab->stats = of_hw_sw_table_stats;

    hw_drv->table_stats_get =of_hw_table_stats_get;
    hw_drv->port_stats_get = of_hw_port_stats_get;
    hw_drv->flow_stats_get = NULL;
    hw_drv->aggregate_stats_get = NULL;

    hw_drv->port_add = of_hw_port_add;
    hw_drv->port_remove = of_hw_port_remove;
    hw_drv->port_link_get = of_hw_port_link_get;
    hw_drv->port_enable_set = of_hw_port_enable_set;
    hw_drv->port_enable_get = of_hw_port_enable_get;
    hw_drv->port_queue_config = of_hw_port_queue_config;
    hw_drv->port_queue_remove = of_hw_port_queue_remove;
    hw_drv->port_change_register = of_hw_port_change_register;

    hw_drv->packet_send = of_hw_packet_send;
    hw_drv->packet_receive_register = of_hw_packet_receive_register;

    hw_drv->ioctl = of_hw_ioctl;

    ++of_hw_drv_instances;

    return hw_drv;
}

/*
 * Deallocate a hardware datapath object
 * If clear_hw is set, the HW structures related to the
 * datapath are also cleared.
 *
 * In general, clear_hw should be set for now.
 */
void
delete_of_hw_driver(of_hw_driver_t *hw_drv)
{
    int idx;
    of_hw_driver_int_t *hw_int;

    hw_int = (of_hw_driver_int_t *)hw_drv;

    /* Clear the port table of ownership for this dp */
    FOREACH_DP_PORT(idx, hw_drv) {
        of_hw_ports[idx].owner = NULL;
    }

    of_hw_flow_remove_all(hw_int);

    FREE(hw_drv);
    --of_hw_drv_instances;
}
