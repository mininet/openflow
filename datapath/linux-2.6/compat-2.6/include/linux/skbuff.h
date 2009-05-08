#ifndef __LINUX_SKBUFF_WRAPPER_H
#define __LINUX_SKBUFF_WRAPPER_H 1

#include_next <linux/skbuff.h>

#include <linux/version.h>

#ifndef HAVE_SKB_COPY_FROM_LINEAR_DATA_OFFSET
static inline void skb_copy_from_linear_data_offset(const struct sk_buff *skb,
                                                    const int offset, void *to,
                                                    const unsigned int len)
{
	memcpy(to, skb->data + offset, len);
}

static inline void skb_copy_to_linear_data_offset(struct sk_buff *skb,
                                                  const int offset,
                                                  const void *from,
                                                  const unsigned int len)
{
	memcpy(skb->data + offset, from, len);
}

#endif	/* !HAVE_SKB_COPY_FROM_LINEAR_DATA_OFFSET */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
static inline int __skb_cow(struct sk_buff *skb, unsigned int headroom,
                            int cloned)
{
	int delta = 0;

	if (headroom < NET_SKB_PAD)
		headroom = NET_SKB_PAD;
	if (headroom > skb_headroom(skb))
		delta = headroom - skb_headroom(skb);

	if (delta || cloned)
		return pskb_expand_head(skb, ALIGN(delta, NET_SKB_PAD), 0,
					GFP_ATOMIC);
	return 0;
}

static inline int skb_cow_head(struct sk_buff *skb, unsigned int headroom)
{
	return __skb_cow(skb, headroom, skb_header_cloned(skb));
}
#endif  /* linux < 2.6.23 */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
/* Emulate Linux 2.6.17 and later behavior, in which kfree_skb silently ignores 
 * null pointer arguments. */
#define kfree_skb(skb) kfree_skb_maybe_null(skb)
static inline void kfree_skb_maybe_null(struct sk_buff *skb)
{
	if (likely(skb != NULL))
		(kfree_skb)(skb);
}
#endif


#ifndef CHECKSUM_PARTIAL
/* Note that CHECKSUM_PARTIAL is not implemented, but this allows us to at
 * least test against it: see update_csum() in forward.c. */
#define CHECKSUM_PARTIAL 3
#endif
#ifndef CHECKSUM_COMPLETE
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

#ifdef HAVE_MAC_RAW
#define mac_header mac.raw
#define network_header nh.raw
#endif

#ifndef HAVE_SKBUFF_HEADER_HELPERS
static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
	return skb->h.raw;
}

static inline void skb_reset_transport_header(struct sk_buff *skb)
{
	skb->h.raw = skb->data;
}

static inline void skb_set_transport_header(struct sk_buff *skb,
			const int offset)
{
	skb->h.raw = skb->data + offset;
}

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
	return skb->nh.raw;
}

static inline void skb_set_network_header(struct sk_buff *skb, const int offset)
{
	skb->nh.raw = skb->data + offset;
}

static inline unsigned char *skb_mac_header(const struct sk_buff *skb)
{
	return skb->mac.raw;
}

static inline void skb_reset_mac_header(struct sk_buff *skb)
{
	skb->mac_header = skb->data;
}

static inline void skb_set_mac_header(struct sk_buff *skb, const int offset)
{
	skb->mac.raw = skb->data + offset;
}

static inline int skb_transport_offset(const struct sk_buff *skb)
{
    return skb_transport_header(skb) - skb->data;
}

static inline int skb_network_offset(const struct sk_buff *skb)
{
	return skb_network_header(skb) - skb->data;
}

static inline void skb_copy_to_linear_data(struct sk_buff *skb,
					   const void *from,
					   const unsigned int len)
{
	memcpy(skb->data, from, len);
}
#endif	/* !HAVE_SKBUFF_HEADER_HELPERS */

#endif
