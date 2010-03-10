/*
 * Port related HW datapath functions
 */

#include <openflow/openflow.h>
#include <of_hw_api.h>

#include "xtoxll.h"
#include "hw_drv.h"
#include "of_hw_platform.h"
#include "port.h"
#include "debug.h"

/* Single set of HW port objects managed here; indexed by OF port num */
of_hw_port_t of_hw_ports[OF_HW_MAX_PORT];

/* Check if hw DP and port are valid and if port belongs to the DP */
#define CHECK_PORT(_drv, _p) do {                                   \
    if ((_drv) == NULL) return -1;                                  \
    if (((_p) < 1) || ((_p) > OF_HW_MAX_PORT)) {                   \
        REPORT_ERROR("bad port number");                            \
        return -1;                                                  \
    }                                                               \
    if (!(OF_PORT_IN_DP(((of_hw_driver_int_t *)(_drv)), (_p)))) {   \
        REPORT_ERROR("DP does not own port");                       \
        return -1;                                                  \
    }                                                               \
} while (0)


/*
 * Queue configuration section
 *
 * Port queue:  Per port structure for queue related information
 * Queue map: Indicated queue is mapped and what OF qid its mapped to as
 *     well as queue properties (min-bw).  Indexed by OF port number;
 *     per port instance of array
 *
 */

typedef struct queue_map_s {
        int in_use;
        uint32_t qid; /* OF queue name */
        int min_bw;   /* OF value, tenths of a percent */
} queue_map_t;

typedef struct port_queue_s {
    int speed; /* In Mbps */
    queue_map_t queue_map[NUM_COS_QUEUES];
} port_queue_t;

static port_queue_t port_queue[OF_HW_MAX_PORT];

/* Return the cos for the queue matching qid if found; else -1.
 * Assumes lock held
 */
static int
qid_find(int of_port, uint32_t qid)
{
    struct queue_map_s *qm;
    int cosq;

    qm = port_queue[of_port].queue_map;
    for (cosq = 0; cosq < NUM_COS_QUEUES; cosq++) {
        if (qm[cosq].in_use && (qid == qm[cosq].qid)) {
            return cosq;
        }
    }

    return -1;
}

/* Return the cos for the queue matching qid if found; else -1.
 * Assumes lock held
 */
int
of_hw_qid_find(int of_port, uint32_t qid)
{
    int cosq;

    /* LOCK */
    cosq = qid_find(of_port, qid);
    /* UNLOCK */

    return cosq;
}

/*
 * Map an OF qid to a COS queue index; if not present, add it if possible
 * Assumes lock held
 */
static int
qid_find_add(int of_port, uint32_t qid)
{
    struct queue_map_s *qm;
    int cosq;

    cosq = qid_find(of_port, qid);
    if (cosq >= 0) {
        return cosq;
    }

    /* Not found; add queue */
    for (cosq = 0; cosq < NUM_COS_QUEUES; cosq++) {
        qm = port_queue[of_port].queue_map;
        if (!qm[cosq].in_use) {
            qm[cosq].in_use = true;
            qm[cosq].qid = qid;
            return cosq;
        }
    }

    return -1;
}

/*
 * Port speed has changed; requires queue b/w to change
 */
static void
port_speed_change_reconfig(of_hw_driver_int_t *hw_int, int of_port)
{
    int cosq;
    struct queue_map_s *qm;
    int rv;

    /* LOCK */
    for (cosq = 0; cosq < NUM_COS_QUEUES; cosq++) {
        qm = port_queue[of_port].queue_map;
        if (qm[cosq].in_use) {
            /* FIXME:  Calc and program values for HW for min-bw */
            if (rv < 0) {
                DBG_ERROR("ERROR: Set min BW for queue on port %d "
                          "link change\n", of_port);
            }
        }
    }
    /* UNLOCK */
}


/* Internal handler for port link status changes */

/* FIXME */
static void
of_hw_linkscan_handler(...)
{
    int of_port;
    of_hw_driver_int_t *hw_int;

    /* Assumes speed, linkstatus from HW */
    /* Map port to internal port object */
    of_port = HW_MAP_TO_PORT();
    if ((of_port < 0) || (of_port > OF_HW_MAX_PORT)) {
        return;
    }

    /* LOCK */
    hw_int = (of_hw_driver_int_t *)(of_hw_ports[of_port].owner);
    if (hw_int != NULL) {
        if (port_queue[of_port].speed != speed) {
            port_queue[of_port].speed = speed;
            port_speed_change_reconfig(hw_int, of_port);
        }
    }
    /* Record in local struct */
    of_hw_ports[of_port].link = linkstatus != 0;
    if ((hw_int != NULL) && (hw_int->port_change != NULL)) {
        hw_int->port_change(of_port, linkstatus != 0,
                            hw_int->port_change_cookie);
    }
    /* UNLOCK */
}

static int linkscan_registered;

/*
 * of_hw_ports_init
 *     Set up hardware port map
 */
void
of_hw_ports_init(void)
{
    int i;

    for (i = 0; i < OF_HW_MAX_PORT; i++) {
        of_hw_ports[i].owner = NULL;
        of_hw_ports[i].port = MAP_OF_PORT_TO_HW_PORT(i);
    }

    /* FIXME:  REGISTER FOR LINK CHANGE CALLBACK */
    /* Always register linkscan handler */
    linkscan_registered = 1;

    /* Get current link status for each port; ignore errors for bad ports */
    for (i = 0; i < OF_HW_MAX_PORT; i++) {
        /* FIXME */
        HW_LINK_STATUS_GET(of_hw_ports[i].port, &of_hw_ports[i].link);
    }
}


#define HTON64 htonll

/* Get port stats into a standard openflow port stats structure */
int
of_hw_port_stats_get(of_hw_driver_t *hw_drv, int of_port,
                      struct ofp_port_stats *stats)
{
    uint64 v1, v2;

    CHECK_PORT(hw_drv, of_port);


#if 0    /* FIXME;  Get stats from HW */
    HW_STAT(of_port, snmpIfInNUcastPkts, &v1);
    HW_STAT(of_port, snmpIfInUcastPkts, &v2);
    v1 += v2;
    stats->rx_packets = HTON64(v1);
    HW_STAT(of_port,  snmpIfOutNUcastPkts, &v1);
    HW_STAT(of_port, snmpIfOutUcastPkts, &v2);
    v1 += v2;
    stats->tx_packets = HTON64(v1);
    HW_STAT(of_port, snmpIfInOctets, &v1);
    stats->rx_bytes = HTON64(v1);
    HW_STAT(of_port, snmpIfOutOctets, &v1);
    stats->tx_bytes = HTON64(v1);
    HW_STAT(of_port, snmpIfInDiscards, &v1);
    stats->rx_dropped = HTON64(v1);
    HW_STAT(of_port, snmpIfOutDiscards, &v1);
    stats->tx_dropped = HTON64(v1);
    HW_STAT(of_port, snmpIfInErrors, &v1);
    stats->rx_errors = HTON64(v1);
    HW_STAT(of_port, snmpIfOutErrors, &v1);
    stats->tx_errors = HTON64(v1);
#endif

    v1 = UINT64_C(0xffffffffffffffff);
    stats->rx_frame_err = HTON64(v1);
    stats->rx_over_err = HTON64(v1);
    stats->rx_crc_err = HTON64(v1);
    stats->collisions = HTON64(v1);

    return 0;
}

/*
 * port_add/remove(table, port)
 *
 * The indicated port has been added to/removed from the datapath
 * Add also maps the of_port number to the hw_port indicated
 *
 * SPEC CHANGE:  If of_port passed is less than 0, use the passed
 * port name to determine the port number and attach to that value;
 *
 * Returns the of_port number or -1 on error
 */
int
of_hw_port_add(of_hw_driver_t *hw_drv, int of_port, const char *hw_name)
{
    int hw_idx;
    of_hw_port_t *port_ctl;
    of_hw_driver_int_t *hw_int;

    if (hw_drv == NULL) {
        return -1;
    }

    hw_idx = hw_port_name_to_index(hw_name);
    if (of_port < 0) {
        of_port = hw_idx + 1;
    } else if (hw_idx + 1 != of_port) {
        DBG_WARN("Add Port:  OF port %d does not match name %s\n",
                   of_port, hw_name);
    }

    if (of_port >= OF_HW_MAX_PORT) {
        DBG_ERROR("Add Port:  Bad port number %d\n", of_port);
        return -1;
    }

    hw_int = (of_hw_driver_int_t *)hw_drv;
    port_ctl = &of_hw_ports[of_port];

    HW_DRV_LOCK;
    if (port_ctl->owner == NULL) {
        port_ctl->owner = hw_drv;
        /* FIXME:  port bitmaps in HW structure */
    } else if (port_ctl->owner != hw_drv) {
        DBG_ERROR("Add Port:  OF port %d owned by other DP\n", of_port);
    } else {
        DBG_WARN("Add Port:  OF port %d already added\n", of_port);
    }
    HW_DRV_UNLOCK;

    return of_port;
}

int
of_hw_port_remove(of_hw_driver_t *hw_drv, of_port_t of_port)
{
    of_hw_port_t *port_ctl;
    of_hw_driver_int_t *hw_int;
    int rc = 0;

    if (hw_drv == NULL) {
        return -1;
    }

    if ((of_port < 1) || (of_port >= OF_HW_MAX_PORT)) {
        DBG_ERROR("Remove Port:  Bad port number %d\n", of_port);
        return -1;
    }

    hw_int = (of_hw_driver_int_t *)hw_drv;
    port_ctl = &of_hw_ports[of_port];

    HW_DRV_LOCK;
    if (port_ctl->owner == NULL) {
        DBG_WARN("Remove Port:  OF port %d already free\n", of_port);
    } else if (port_ctl->owner != hw_drv) {
        DBG_ERROR("Remove Port:  OF port %d owned by other DP\n", of_port);
        rc = -1;
    } else {
        port_ctl->owner = NULL;
    }
    /* FIXME UPDATE HW port bitmaps in hw_int */
    HW_DRV_UNLOCK;

    return rc;
}


/*
 * port_link_get(table, port)
 * port_enable_set(table, port, enable)
 * port_enable_get(table, port)
 *
 * Get/set the indicated properties of a port.  Only real ports
 * set with port_add are supported.
 */
int
of_hw_port_link_get(of_hw_driver_t *hw_drv, int of_port)
{
    int rc;
    int link;

    CHECK_PORT(hw_drv, of_port);

    if (linkscan_registered) {
        return of_hw_ports[of_port].link;
    }

    if ((rc = HW_LINK_GET(of_hw_ports[of_port].port, &link)) < 0) {
        DBG_ERROR("link_get: error %d port %d\n", rc, of_port);
        /* Return link down on error */
        return 0;
    }

    return link ? 1 : 0;
}

int
of_hw_port_enable_set(of_hw_driver_t *hw_drv, int of_port, int enable)
{
    int rc;

    CHECK_PORT(hw_drv, of_port);

    if ((rc = HW_PORT_ENABLE_SET(of_hw_ports[of_port].port, enable)) < 0) {
        DBG_ERROR("of_hw_port_enable_set: error %d port %d\n",
                  rc, of_port);
        return rc;
    }

    return 0;
}

int
of_hw_port_enable_get(of_hw_driver_t *hw_drv, int of_port)
{
    int rc;
    int enable;

    CHECK_PORT(hw_drv, of_port);

    if ((rc = HW_PORT_ENABLE_GET(of_hw_ports[of_port].port, &enable)) < 0) {
        DBG_ERROR("of_hw_port_enable_get: error %d port %d\n",
                  rc, of_port);
        return rc;
    }

    return enable ? 1 : 0;
}


/*
 * port_change_register
 *
 * Register a callback function to receive port change notifications
 * from ports in this datapath; only one callback per datapath is
 * supported.
 */
int
of_hw_port_change_register(of_hw_driver_t *hw_drv, of_port_change_f callback,
                            void *cookie)
{
    of_hw_driver_int_t *dp_int;

    dp_int = (of_hw_driver_int_t *)hw_drv;
    dp_int->port_change = callback;
    dp_int->port_change_cookie = cookie;

    return 0;
}

/*
 * Init COS queue setup.  The queues number is fixed at 8.  Deficit
 * round robin is the discipline, initially with all equal weights.
 * As queues are configured with min bandwidth reservations, the
 * weights are adjusted to ensure the requested targets.
 *
 * For now, these are device generic; may need to specialize in the
 * future.
 */

int
of_hw_cos_setup(int num_cos)
{
    /* FIXME: Set up COS queues */

    return 0;
}

/*
 * Add and/or configure an output queue on a port.
 *
 * If qid exists, update.  If not, look for an unreferenced queue and
 * set the qid to that value.
 *
 * Note that when a port state changes, may need to re-configure
 * the bandwidth values for the port's queues.
 */

int
of_hw_port_queue_config(of_hw_driver_t *hw_drv, int of_port, uint32_t qid,
                         int min_bw) /* In tenths of a percent */
{
    int min_kbps;
    of_hw_driver_int_t *hw_int;
    int cosq;
    struct queue_map_s *qm;
    int rv;

    hw_int = (of_hw_driver_int_t *)hw_drv;

    CHECK_PORT(hw_int, of_port);

    /* LOCK */
    /* Get the current bandwidth of the port (cached?) */
    if ((cosq = qid_find_add(of_port, qid)) < 0) {
        DBG_ERROR("Could not add queue: of port %d, qid %d\n", of_port, qid);
        /* UNLOCK */
        return -1;
    }
    qm = &port_queue[of_port].queue_map[qid];
    qm->min_bw = min_bw;

    HW_SET_MIN_BW(...);
    /* UNLOCK */

    return (rv != 0) ? -1 : 0;
}

/* Remove a queue from a port; this potentially affects the queue
 * configuration otherwise we would not worry about it here.
 * Return -1 if not found; 0 on success
 */

int
of_hw_port_queue_remove(of_hw_driver_t *hw_drv, int of_port, uint32_t qid)
{
    int cosq;

    (void)hw_drv;
    /* LOCK */
    if ((cosq = qid_find(of_port, qid)) == -1) {
        /* UNLOCK */
        return -1;
    }

    /* Do we need to update stats or DRR weights or anything? */

    port_queue[of_port].queue_map[cosq].in_use = false;

    /* UNLOCK */
    return 0;
}
