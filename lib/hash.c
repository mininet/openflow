/* Copyright (c) 2008, 2009 The Board of Trustees of The Leland Stanford
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
#include <config.h>
#include "hash.h"
#include <string.h>

/* This is the public domain lookup3 hash by Bob Jenkins from
 * http://burtleburtle.net/bob/c/lookup3.c, modified for style. */
#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

#define mix(a, b, c)                            \
    do {                                        \
      a -= c; a ^= rot(c,  4); c += b;          \
      b -= a; b ^= rot(a,  6); a += c;          \
      c -= b; c ^= rot(b,  8); b += a;          \
      a -= c; a ^= rot(c, 16); c += b;          \
      b -= a; b ^= rot(a, 19); a += c;          \
      c -= b; c ^= rot(b,  4); b += a;          \
    } while (0)

#define final(a, b, c)                          \
    do {                                        \
      c ^= b; c -= rot(b, 14);                  \
      a ^= c; a -= rot(c, 11);                  \
      b ^= a; b -= rot(a, 25);                  \
      c ^= b; c -= rot(b, 16);                  \
      a ^= c; a -= rot(c,  4);                  \
      b ^= a; b -= rot(a, 14);                  \
      c ^= b; c -= rot(b, 24);                  \
    } while (0)

/* Returns the hash of the 'n' 32-bit words at 'p', starting from 'basis'.
 * 'p' must be properly aligned. */
uint32_t
hash_words(const uint32_t *p, size_t n, uint32_t basis)
{
    uint32_t a, b, c;

    a = b = c = 0xdeadbeef + (((uint32_t) n) << 2) + basis;

    while (n > 3) {
        a += p[0];
        b += p[1];
        c += p[2];
        mix(a, b, c);
        n -= 3;
        p += 3;
    }

    switch (n) {
    case 3:
        c += p[2];
        /* fall through */
    case 2:
        b += p[1];
        /* fall through */
    case 1:
        a += p[0];
        final(a, b, c);
        /* fall through */
    case 0:
        break;
    }
    return c;
}

/* Returns the hash of the 'n' bytes at 'p', starting from 'basis'. */
uint32_t
hash_bytes(const void *p_, size_t n, uint32_t basis)
{
    const uint8_t *p = p_;
    uint32_t a, b, c;
    uint32_t tmp[3];

    a = b = c = 0xdeadbeef + n + basis;

    while (n >= sizeof tmp) {
        memcpy(tmp, p, sizeof tmp);
        a += tmp[0];
        b += tmp[1];
        c += tmp[2];
        mix(a, b, c);
        n -= sizeof tmp;
        p += sizeof tmp;
    }

    if (n) {
        tmp[0] = tmp[1] = tmp[2] = 0;
        memcpy(tmp, p, n);
        a += tmp[0];
        b += tmp[1];
        c += tmp[2];
        final(a, b, c);
    }

    return c;
}
