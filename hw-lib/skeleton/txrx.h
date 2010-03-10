#ifndef OF_HW_TXRX_H
#define OF_HW_TXRX_H 1

#include <openflow/openflow.h>
#include <of_hw_api.h>

extern int of_hw_packet_send(of_hw_driver_t *hw_drv, int of_port,
    of_packet_t *pkt, uint32_t flags);
extern int of_hw_packet_receive_register(of_hw_driver_t *hw_drv,
    of_packet_in_f callback, void *cookie);

#endif /* OF_HW_TXRX_H */
