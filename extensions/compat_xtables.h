#ifndef _XTABLES_COMPAT_H
#define _XTABLES_COMPAT_H 1

#include <linux/kernel.h>
#include <linux/version.h>
#include "compat_skbuff.h"
#include "compat_xtnu.h"

#define DEBUGP Use__pr_debug__instead

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
#	warning Kernels below 2.6.25 not supported.
#endif

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#	if !defined(CONFIG_NF_CONNTRACK_MARK)
#		warning You have CONFIG_NF_CONNTRACK enabled, but CONFIG_NF_CONNTRACK_MARK is not (please enable).
#	endif
#	include <net/netfilter/nf_conntrack.h>
#else
#	warning You need CONFIG_NF_CONNTRACK.
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
#	define xt_match              xtnu_match
#	define xt_register_match     xtnu_register_match
#	define xt_unregister_match   xtnu_unregister_match
#	define xt_register_matches   xtnu_register_matches
#	define xt_unregister_matches xtnu_unregister_matches
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
#	define ipt_unregister_table(tbl) ipt_unregister_table(&init_net, (tbl))
#	define ip6t_unregister_table(tbl) ip6t_unregister_table(&init_net, (tbl))
#else
#	define ipt_unregister_table(tbl) ipt_unregister_table(tbl)
#	define ip6t_unregister_table(tbl) ip6t_unregister_table(tbl)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
#	define rt_dst(rt)	(&(rt)->dst)
#else
#	define rt_dst(rt)	(&(rt)->u.dst)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
#	define nf_nat_ipv4_multi_range_compat nf_nat_multi_range_compat
#	define nf_nat_ipv4_range nf_nat_range
#	define NF_NAT_RANGE_MAP_IPS IP_NAT_RANGE_MAP_IPS
#	define ipv6_skip_exthdr xtnu_ipv6_skip_exthdr
#endif

#if !defined(NIP6) && !defined(NIP6_FMT)
#	define NIP6(addr) \
		ntohs((addr).s6_addr16[0]), \
		ntohs((addr).s6_addr16[1]), \
		ntohs((addr).s6_addr16[2]), \
		ntohs((addr).s6_addr16[3]), \
		ntohs((addr).s6_addr16[4]), \
		ntohs((addr).s6_addr16[5]), \
		ntohs((addr).s6_addr16[6]), \
		ntohs((addr).s6_addr16[7])
#	define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#endif
#if !defined(NIPQUAD) && !defined(NIPQUAD_FMT)
#	define NIPQUAD(addr) \
		((const unsigned char *)&addr)[0], \
		((const unsigned char *)&addr)[1], \
		((const unsigned char *)&addr)[2], \
		((const unsigned char *)&addr)[3]
#	define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
#	define ipv6_find_hdr xtnu_ipv6_find_hdr
#endif

#define ip_route_me_harder    xtnu_ip_route_me_harder
#define skb_make_writable     xtnu_skb_make_writable
#define xt_target             xtnu_target
#define xt_register_target    xtnu_register_target
#define xt_unregister_target  xtnu_unregister_target
#define xt_register_targets   xtnu_register_targets
#define xt_unregister_targets xtnu_unregister_targets

#define xt_request_find_match xtnu_request_find_match

#endif /* _XTABLES_COMPAT_H */
