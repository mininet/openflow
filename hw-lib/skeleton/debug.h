
#ifndef OF_HW_DEBUG_H
#define OF_HW_DEBUG_H 1

#include <stdio.h>
#include <openflow/openflow.h>

#if !defined(HWTABLE_NO_DEBUG)
extern int of_hw_debug;
#define dbg_send(mod, lvl, fmt, args...) \
    if (of_hw_debug >= (lvl)) fprintf(stderr, fmt, ##args)
#endif

#define DBG_LVL_NONE      -1 /* All output off */
#define DBG_LVL_ERROR     0  /* Default value */
#define DBG_LVL_ALWAYS    0  /* For requested dump output */
#define DBG_LVL_WARN      1
#define DBG_LVL_VERBOSE   2
#define DBG_LVL_VVERB     3  /* Include success indications */

/* Sorry for the lazy syntax here. */
#define DBG_CHECK(lvl) (((lvl) >= 0) && (of_hw_debug >= (lvl)))
#define DBG_ERROR(fmt, args...)   dbg_send(0, DBG_LVL_ERROR, fmt, ##args)
#define DBG_ALWAYS(fmt, args...)  dbg_send(0, DBG_LVL_ALWAYS, fmt, ##args)
#define DBG_WARN(fmt, args...)    dbg_send(0, DBG_LVL_WARN, fmt, ##args)
#define DBG_VERBOSE(fmt, args...) dbg_send(0, DBG_LVL_VERBOSE, fmt, ##args)
#define DBG_VVERB(fmt, args...)   dbg_send(0, DBG_LVL_VVERB, fmt, ##args)
#define DBG_NONE(fmt, args...)
/* Same as DEBUG_ALWAYS */
#define DEBUGK(fmt, args...)      dbg_send(0, DBG_LVL_ALWAYS, fmt, ##args)

#define REPORT_ERROR(str) \
    DBG_ERROR("ERROR: %s:%d. %s\n", __FUNCTION__, __LINE__, str)

/* Default debugging location string */
#define ANNOUNCE_LOCATION DBG_VVERB("%s: %d\n", __FUNCTION__, __LINE__)
#define DBG_INCR(cnt) (++(cnt))

/* Should assert return? Not presently */
#define ASSERT(cond)                                                    \
    if (!(cond)) DBG_ERROR("ASSERTION %s IN %s FAILED LINE %d\n",       \
                           #cond, __FUNCTION__, __LINE__)

/* DEBUG for HW flow lists */
#define HW_FLOW_MAGIC 0xba5eba11
#define HW_FLOW_MAKE_VALID(hf) (hf)->magic = HW_FLOW_MAGIC
#define HW_FLOW_IS_VALID(hf) \
    (((hf) != NULL) && ((hf)->magic == HW_FLOW_MAGIC))

/*
 * Carry out an operation and check for error, optionally returning
 * from the calling routine.  To avoid compiler
 * warnings in routines with void return, we give two macros.
 *
 * WARNING: This check uses rv != 0 (not just rv < 0).
 */

#define TRY(op, str) do {                                       \
        int rv;                                                 \
        if (((rv = (op)) < 0)) {                                \
            DBG_ERROR("ERROR %d: %s\n", rv, str);               \
            return rv;                                          \
        } else {                                                \
            DBG_NONE("%s: success\n", str);                     \
        }                                                       \
    } while (0)

#define TRY_NR(op, str) do {                                    \
        int rv;                                                 \
        if (((rv = (op)) != 0)) {                               \
            DBG_ERROR("ERROR %d: %s\n", rv, str);               \
        } else {                                                \
            DBG_NONE("%s: success\n", str);                     \
        }                                                       \
    } while (0)

#else  /* No debugging */

#define DBG_CHECK(lvl) 0
#define ANNOUNCE_LOCATION
#define ACT_STRING(action) ""
#define DBG_INCR(cnt)
#define DBG_ERROR(fmt, args...)
#define DBG_ALWAYS(fmt, args...)
#define DBG_WARN(fmt, args...)
#define DBG_VERBOSE(fmt, args...)
#define DBG_VVERB(fmt, args...)
#define DBG_NONE(fmt, args...)
#define DEBUGK(fmt, args...)
#define REPORT_ERROR(str)

#define ASSERT(cond)

#define HW_FLOW_MAKE_VALID(hf)
#define HW_FLOW_IS_VALID(hf) 1

#define TRY(op, str) do {                                       \
        int rv;                                                 \
        if (((rv = (op)) != 0)) return rv;                      \
    } while (0)

#define TRY_NR(op, str) (void)op

#endif /* !defined(HWTABLE_NO_DEBUG) */

#endif /* OF_HW_DEBUG_H */
