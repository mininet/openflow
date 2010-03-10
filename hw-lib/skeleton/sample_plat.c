/*
 * sample_plat.c
 *
 * FIXME: Standard confidential header
 *
 * $Id: $
 */

/*
 * Sample hardware initialization functions
 */

#include "debug.h"
#include "of_hw_platform.h"

#if defined(SAMPLE_PLAT)

#include "port.h"

/* sample_plat_port_setup
 *
 * Set up linkscan and necessary spanning tree for ports
 * Disable VLAN dropping
 */
static int
sample_plat_port_setup(...)
{

    return 0;
}

#if defined(OF_HW_DP_MAIN) && defined(SAMPLE_HW_PLAT)

/* If defined, need to do init here */

/*
 * sample_plat_pre_init
 *
 * Turn off everything that might cause problems during init
 */

static int
sample_plat_pre_init(void)
{
    /* bring system down to known state */
    return 0;
}

/*
 */
int
sample_plat_init(void)
{
    /* Init system */

    /* First, clear out everything */
    sample_plat_pre_init();

    /* ... */

    sample_plat_port_setup(...);

    return 0;
}

/* FIXME:  Deal with initial FP setup */

#else /* Not stand alone init; Other code does init */

int
sample_plat_init(void)
{
    DBG_WARN("sample_plat_init\n");

    TRY(sample_plat_port_setup(...), "sample plat init port setup");

    return 0;
}

#endif

#endif /* SAMPLE_PLAT */
