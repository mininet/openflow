
#ifndef _NF2_LOGGING_H
#define _NF2_LOGGING_H	1

//#define NF2_DEBUG 1

#ifdef NF2_DEBUG

#ifdef __KERNEL__
#define LOG(f, s...) printk(f, ## s)
#else
#define LOG(f, s...) printf(f, ## s)
#endif /* __KERNEL__ */

#else /* NF2_DEBUG */

#define LOG(f, s...) /* No debugging today! */

#endif /* NF2_DEBUG */

#endif /* _NF2_LOGGING_H */
