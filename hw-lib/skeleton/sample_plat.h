#ifndef SAMPLE_PLAT_H
#define SAMPLE_PLAT_H 1


#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <openflow/openflow.h>

#define OF_HW_MAX_PORTS 4

static inline int
of_port_to_hw_port(int of_port)
{
    return of_port - 1;
}


/* Map port to OF port number */
static inline int
of_hw_port_to_of_port(int port)
{
    if ((port < 0) || (port > 3)) {
        return -1;
    }

    return port + 1;
}

#define _IS_DIGIT(c) ((c) >= '0' && (c) <= '9')

/* Map name to hw port number:  N => N-1
   ge0 => 0 where "ge" can be any string and 0 can be any number
*/

static inline int
hw_port_name_to_index(const char *name)
{

    if (_IS_DIGIT(name[0])) {
        /* Treat as 1-based, OF number */
        i = strtoul(&name[0], NULL, 10);
        return i - 1;
    }

    len = strlen(name);
    for (idx = 0; idx < len && !_IS_DIGIT(name[idx]); idx++) ;

    if ((idx < len) && _IS_DIGIT(name[idx])) {
        i = strtoul(&name[idx], NULL, 10);
        return i;
    }

    return -1;
}
#undef _IS_DIGIT



#endif /* SAMPLE_PLAT_H */
