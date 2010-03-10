/*
 * Transmit and receive related functions for hardware platforms
 */

#include <of_hw_api.h>
#include "os.h"
#include "hw_drv.h"
#include "txrx.h"
#include "port.h"
#include "debug.h"
#include "of_hw_platform.h"

static int pkt_count, failures, prev_success, free_count, error_free;
static void
tx_pkt_callback(...)
{
    of_packet_t *of_pkt = cookie;

    /* os_pkt_free(of_pkt->os_pkt); */
    FREE(of_pkt);
    /* ... */
    ++free_count;
}

/*
 * tx_packet_send(table, of_port, pkt, flags)
 *
 * Send packet to an openflow port.
 *
 * Proposed flags:
 *     APPLY_FLOW_TABLE:  If set, and if the hardware supports
 *     it, send the packet through the flow table with the source
 *     port being the local CPU port.  (Would be nice to have
 *     a flexible source port indicated; could hide in flags...)
 *
 * Assumes buffer in pkt struct can be used for sending data
 *
 *
 */
int
of_hw_packet_send(of_hw_driver_t *hw_drv, int of_port, of_packet_t *pkt,
                  uint32_t flags)
{
    /* FIXME:  Code to prepare and send pkt */
    return 0;
}

/* Callback function registered with HW */
static int
of_hw_rx(...)
{
    /* Sample RX handler */
    int of_port;
    of_hw_driver_int_t *hw_drv;
    of_packet_t *of_pkt;
    int pkt_len;

    /* map receive port to of_port */
    /* map received packet to of_pkt */
    /* Call callback */

    of_port = of_hw_port_to_of_port(receive_port);
    if (of_port < 0) {
        return hw_not_handled;
    }

    /* LOCK */
    hw_drv = (of_hw_driver_int_t *)(of_hw_ports[of_port].owner);
    if ((hw_drv == NULL) || (hw_drv->rx_handler == NULL)) {
        /* UNLOCK */
        return hw_not_handled;
    }

    of_pkt = ALLOC(sizeof(of_packet_t));
    if (of_pkt == NULL) {
        ++hw_drv->rx_pkt_alloc_failures;
        /* UNLOCK */
        return hw_not_handled;
    }
    pkt_len = pkt->tot_len;

    /* FIXME:  FOR NOW, COPY DATA INTO NEW BUFFER;  */
    of_pkt->data = ALLOC(pkt_len);
    if (of_pkt->data == NULL) {
        FREE(of_pkt);
        /* UNLOCK */
        return hw_not_handled;
    }

    /* Handle VLAN tagging if needed */
    /* Coy pkt data appropriately */

    /* FIXME:  Determine reason (dflt rule or directed) */
    /* FIXME:  Return code interpretation? */
    /* OFPR_NO_MATCH,      No matching flow. */
    /* OFPR_ACTION         Action explicitly output to controller. */
    hw_drv->rx_handler(of_port, of_pkt, 0, hw_drv->rx_cookie);
    /* UNLOCK */

    return hw_handled;
}

static int rx_registered = 0;

/*
 * packet_receive_register
 *
 * Register a callback function to receive packets from ports in
 * this datapath
 */
int
of_hw_packet_receive_register(of_hw_driver_t *hw_drv,
                              of_packet_in_f callback, void *cookie)
{
    of_hw_driver_int_t *dp_int;
    int rv;

    /* Register for link status changes */
    if (!rx_registered) {
        /* Set up low level pkt receive for callback */
        rx_registered = 1;
    }

    dp_int = (of_hw_driver_int_t *)hw_drv;
    dp_int->rx_handler = callback;
    dp_int->rx_cookie = cookie;

    return 0;
}
