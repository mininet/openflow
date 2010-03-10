#ifndef OF_HW_PORT_H
#define OF_HW_PORT_H 1

#include <openflow/openflow.h>
#include <of_hw_api.h>
#include "of_hw_platform.h"

#define NUM_COS_QUEUES 8

/* Define port mapping object indexed by OF number */
typedef struct of_hw_port_s {
    of_hw_driver_t *owner;  /* Owner of this port */
    int port;     /* Physical port number on device */
    int link;     /* Link state */
    /* TBD:  Keep track of link state and don't transmit if down? */
    /* Add other physical info here as needed */
} of_hw_port_t;

extern of_hw_port_t of_hw_ports[OF_HW_MAX_PORT];

#define FOREACH_DP_PORT(_idx, _drv)                 \
    for (_idx = 0; _idx < OF_HW_MAX_PORT; _idx++)  \
        if (of_hw_ports[_idx].owner == (of_hw_driver_t *)(_drv))

extern int of_hw_cos_setup(int num_cos);
extern int of_hw_qid_find(int of_port, uint32_t qid);

extern void of_hw_ports_init(void);
extern int of_hw_port_stats_get(of_hw_driver_t *hw_drv, int of_port,
    struct ofp_port_stats *stats);
extern int of_hw_port_add(of_hw_driver_t *hw_drv, int of_port,
    const char *hw_name);
extern int of_hw_port_remove(of_hw_driver_t *hw_drv, of_port_t of_port);
extern int of_hw_port_link_get(of_hw_driver_t *hw_drv, int of_port);
extern int of_hw_port_enable_set(of_hw_driver_t *hw_drv, int of_port,
    int enable);
extern int of_hw_port_enable_get(of_hw_driver_t *hw_drv, int of_port);
extern int of_hw_port_queue_config(of_hw_driver_t *hw_drv, int of_port,
    uint32_t qid, int min_bw); /* In tenths of a percent */
extern int of_hw_port_queue_remove(of_hw_driver_t *hw_drv, int of_port,
    uint32_t qid);
extern int of_hw_port_change_register(of_hw_driver_t *hw_drv,
    of_port_change_f callback, void *cookie);

#endif /* OF_HW_PORT_H */
