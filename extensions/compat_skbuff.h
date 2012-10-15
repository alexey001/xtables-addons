#ifndef COMPAT_SKBUFF_H
#define COMPAT_SKBUFF_H 1

struct tcphdr;
struct udphdr;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 30)
static inline void skb_dst_set(struct sk_buff *skb, struct dst_entry *dst)
{
	skb->dst = dst;
}

static inline struct dst_entry *skb_dst(const struct sk_buff *skb)
{
	return skb->dst;
}

static inline struct rtable *skb_rtable(const struct sk_buff *skb)
{
	return (void *)skb->dst;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
#	define skb_ifindex(skb) (skb)->iif
#	define skb_nfmark(skb) (((struct sk_buff *)(skb))->mark)
#else
#	define skb_ifindex(skb) (skb)->skb_iif
#	define skb_nfmark(skb) (((struct sk_buff *)(skb))->mark)
#endif

#ifdef CONFIG_NETWORK_SECMARK
#	define skb_secmark(skb) ((skb)->secmark)
#else
#	define skb_secmark(skb) 0
#endif

#endif /* COMPAT_SKBUFF_H */
