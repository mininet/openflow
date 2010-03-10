
/*
 * OS abstractions
 */

#ifndef OF_HW_OS_H
#define OF_HW_OS_H 1

#include <stdlib.h>

#define ALLOC(bytes) malloc(bytes)
#define FREE(ptr) free(ptr)

#define PKT_ALLOC(bytes) TBD
#define PKT_FREE(ptr) TBD

#define MUTEX_DECLARE(name) TBD
#define MUTEX_INIT(name) TBD
#define MUTEX_LOCK(name) TBD
#define MUTEX_UNLOCK(name) TBD

#define TIME_NOW(time) TBD
#define TIME_DIFF(diff, early, late) TBD

/* FIXME */
#include <ofpbuf.h>
#define os_pkt_free(pkt) ofpbuf_delete(pkt)

#endif /* OF_HW_OS_H */
