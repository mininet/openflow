#ifndef __LINUX_TCP_WRAPPER_H
#define __LINUX_TCP_WRAPPER_H 1

#include <linux/version.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
#undef dev_get_by_name
#endif

#include_next <linux/tcp.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
/*----------------------------------------------------------------------------
 * In 2.6.24, a namespace argument became required for dev_get_by_name. */
#define net_init NULL

#define dev_get_by_name(net, name) \
		dev_get_by_name((name))

#endif /* linux kernel <= 2.6.23 */

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)) && \
	(RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(5,2)))

#ifdef __KERNEL__
static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
        return tcp_hdr(skb)->doff * 4;
}
#endif /* __KERNEL__ */

#endif /* linux kernel < 2.6.22 */

#endif
