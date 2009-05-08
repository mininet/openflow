/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#ifndef BITMAP_H
#define BITMAP_H 1

#include <limits.h>
#include <stdlib.h>
#include "util.h"

#define BITMAP_ULONG_BITS (sizeof(unsigned long) * CHAR_BIT)

static inline unsigned long *
bitmap_unit__(const unsigned long *bitmap, size_t offset)
{
    return (unsigned long *) &bitmap[offset / BITMAP_ULONG_BITS];
}

static inline unsigned long
bitmap_bit__(size_t offset)
{
    return 1UL << (offset % BITMAP_ULONG_BITS);
}

static inline unsigned long *
bitmap_allocate(size_t n_bits)
{
    return xcalloc(1, ROUND_UP(n_bits, BITMAP_ULONG_BITS));
}

static inline void
bitmap_free(unsigned long *bitmap)
{
    free(bitmap);
}

static inline bool
bitmap_is_set(const unsigned long *bitmap, size_t offset)
{
    return (*bitmap_unit__(bitmap, offset) & bitmap_bit__(offset)) != 0;
}

static inline void
bitmap_set1(unsigned long *bitmap, size_t offset)
{
    *bitmap_unit__(bitmap, offset) |= bitmap_bit__(offset);
}

static inline void
bitmap_set0(unsigned long *bitmap, size_t offset)
{
    *bitmap_unit__(bitmap, offset) &= ~bitmap_bit__(offset);
}

static inline void
bitmap_set(unsigned long *bitmap, size_t offset, bool value)
{
    if (value) {
        bitmap_set1(bitmap, offset);
    } else {
        bitmap_set0(bitmap, offset);
    }
}

void bitmap_set_multiple(unsigned long *, size_t start, size_t count,
                         bool value);
bool bitmap_equal(const unsigned long *, const unsigned long *, size_t n);

#endif /* bitmap.h */
