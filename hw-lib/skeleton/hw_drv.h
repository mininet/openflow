#ifndef OF_HW_DRV_H
#define OF_HW_DRV_H 1

#include <of_hw_api.h>
#include "of_hw_platform.h"
#include "list.h"

/****************************************************************
 *
 * High Level Design Notes
 *
 * Hardware tables are managed field_control_t and entry_control_t
 * structures in hw_flow.h; these roughly mirror the HW structure
 * and are preallocated.
 *
 * The glue between these and SW flows are provided by the HW flow
 * objects (also in hw_flow.h) which are dynamically allocated and
 * logically extend the SW flow object.
 *
 * A linear table of HW flow objects is maintained, mostly drawn
 * from the existing table-linear.c implementation in udatapath.
 *
 */

/****************************************************************
 * Hardware independent port mapping macros
 ****************************************************************/

/* Map ports using software data structures and DP check; independent of HW */
#define OF_PORT_IN_DP(_hwdrv, _i)  (((_i) < OF_HW_MAX_PORT) && \
    (of_hw_ports[_i].owner == (of_hw_driver_t *)(_hwdrv)))

#define OF_PORT_TO_HW_PORT(_hwdrv, _i) \
    (OF_PORT_IN_DP(_hwdrv, _i) ? of_hw_ports[_i].port : -1)

/* TBD: Define flow tracking objects */

/****************************************************************
 *
 * Hardware datapath internal control structure
 * Extends generic hardware datapath structure
 * (which currently extends software table structure)
 *
 ****************************************************************/

/* Counts the number of instances */
extern int of_hw_drv_instances;

typedef struct of_hw_driver_int {
    of_hw_driver_t hw_driver;
    struct datapath *dp; /* Owning datapath */

    /* Maintain a linked list of flows for tracking  */
    struct list flows;       /* The main list */
    struct list iter_flows;  /* For iteration operation */
    unsigned long int next_serial;

    /* Callback function for received packets. */
    of_packet_in_f rx_handler;
    void *rx_cookie;

    /* Callback function for port change notification */
    of_port_change_f port_change;
    void *port_change_cookie;

    /* Lock object? */

    //    struct list sw_flows;
    //    struct list iter_sw_flows;
    //    struct sw_flow *iter_state; /* Place tracker for interrupted iterations */

    /* Stats */
    uint32_t n_flows;     /* Current number of flows in table */
    uint32_t n_inserts;   /* Total inserts */
    uint32_t rx_pkt_alloc_failures;
    uint32_t insert_errors;

    /* Configuration */
    /* Port bitmap of ports in DP by device */
    FIXME port_bitmap;
    FIXME flood_bitmap;
    int stat_sel;       /* Packets or bytes */
    int dp_idx;         /* In HW dp, but not SW dp */

    int table_debug_level;
    int port_debug_level;
} of_hw_driver_int_t;

/* HW_DRV_MUTEX object ? */

#define HW_DRV_MUTEX_INIT /* TBD */
#define HW_DRV_LOCK /* TBD */
#define HW_DRV_UNLOCK /* TBD */

#define HW_INT(hw_drv) ((of_hw_driver_int_t *)hw_drv)

#endif /* OF_HW_DRV_H */
