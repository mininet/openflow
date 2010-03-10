#ifndef HW_LIB_SKELETON_PLATFORM_H
#define HW_LIB_SKELETON_PLATFORM_H 1

#if defined(OF_HW_DP_MAIN)
#define P printf
#else
#define P printf
#endif

/*
 * General Hardware Switch platform defines
 *
 * Also includes platform specific definitions based on make defines
 */

#define OF_HW_MAX_PORT 64

/* Reasons that a packet is being forwarded to the controller;  */
#define CPU_REASON_DEFAULT        (1 << 0)
#define CPU_REASON_TO_CONTROLLER  (1 << 1)
#define CPU_REASON_TO_LOCAL       (1 << 2)

#define EXACT_MATCH_PRIORITY TBD

/****************************************************************
 *
 * Platform specific defines and linkage
 *
 * Implicitly we have a "driver" for the board which includes
 * hardware specific information including HW to OF port mapping
 *
 ****************************************************************/

#if defined(OF_SAMPLE_PLAT)
#include "sample_plat.h"
#endif

#endif /* HW_LIB_SKELETON_PLATFORM_H */
