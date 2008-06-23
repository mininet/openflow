#ifndef __ASM_MIPS_ATOMIC_H_WRAPPER
#define __ASM_MIPS_ATOMIC_H_WRAPPER 1

#include_next <asm/atomic.h>

#define atomic_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))

#endif /* asm/atomic.h */
