/*
 *	API compat layer
 *	written by Jan Engelhardt <jengelh [at] medozas de>, 2008 - 2010
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License, either
 *	version 2 of the License, or any later version.
 */
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_arp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
#	include <linux/export.h>
#endif
#include "compat_skbuff.h"
#include "compat_xtnu.h"
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
#	define WITH_IPV6 1
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
static bool xtnu_match_run(const struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out,
    const struct xt_match *cm, const void *matchinfo, int offset,
    unsigned int protoff, bool *hotdrop)
{
	struct xtnu_match *nm = xtcompat_numatch(cm);
	bool lo_ret;
	struct xt_action_param local_par;
	local_par.in        = in;
	local_par.out       = out;
	local_par.match     = cm;
	local_par.matchinfo = matchinfo;
	local_par.fragoff   = offset;
	local_par.thoff     = protoff;
	local_par.hotdrop   = false;
	local_par.family    = NFPROTO_UNSPEC; /* don't have that info */

	if (nm == NULL || nm->match == NULL)
		return false;
	lo_ret = nm->match(skb, &local_par);
	*hotdrop = local_par.hotdrop;
	return lo_ret;
}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28) && \
    LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
static bool xtnu_match_run(const struct sk_buff *skb,
    const struct xt_match_param *par)
{
	struct xtnu_match *nm = xtcompat_numatch(par->match);
	struct xt_action_param local_par;
	bool ret;

	local_par.in        = par->in;
	local_par.out       = par->out;
	local_par.match     = par->match;
	local_par.matchinfo = par->matchinfo;
	local_par.fragoff   = par->fragoff;
	local_par.thoff     = par->thoff;
	local_par.hotdrop   = false;
	local_par.family    = par->family;

	if (nm == NULL || nm->match == NULL)
		return false;
	ret = nm->match(skb, &local_par);
	*par->hotdrop = local_par.hotdrop;
	return ret;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
static bool xtnu_match_check(const char *table, const void *entry,
    const struct xt_match *cm, void *matchinfo, unsigned int hook_mask)
{
	struct xtnu_match *nm = xtcompat_numatch(cm);
	struct xt_mtchk_param local_par = {
		.table     = table,
		.entryinfo = entry,
		.match     = cm,
		.matchinfo = matchinfo,
		.hook_mask = hook_mask,
		.family    = NFPROTO_UNSPEC,
	};

	if (nm == NULL)
		return false;
	if (nm->checkentry == NULL)
		return true;
	return nm->checkentry(&local_par) == 0;
}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28) && \
    LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
static bool xtnu_match_check(const struct xt_mtchk_param *par)
{
	struct xtnu_match *nm = xtcompat_numatch(par->match);

	if (nm == NULL)
		return false;
	if (nm->checkentry == NULL)
		return true;
	return nm->checkentry(par) == 0;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
static void xtnu_match_destroy(const struct xt_match *cm, void *matchinfo)
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
{
	struct xtnu_match *nm = xtcompat_numatch(cm);
	struct xt_mtdtor_param local_par = {
		.match     = cm,
		.matchinfo = matchinfo,
		.family    = NFPROTO_UNSPEC,
	};

	if (nm != NULL && nm->destroy != NULL)
		nm->destroy(&local_par);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
int xtnu_register_match(struct xtnu_match *nt)
{
	struct xt_match *ct;
	char *tmp;
	int ret;

	ct = kzalloc(sizeof(struct xt_match), GFP_KERNEL);
	if (ct == NULL)
		return -ENOMEM;

	tmp = (char *)ct->name;
	memcpy(tmp, nt->name, sizeof(nt->name));
	tmp = (char *)(ct->name + sizeof(ct->name) - sizeof(void *));
	*(tmp-1) = '\0';
	memcpy(tmp, &nt, sizeof(void *));

	ct->revision   = nt->revision;
	ct->family     = nt->family;
	ct->table      = (char *)nt->table;
	ct->hooks      = nt->hooks;
	ct->proto      = nt->proto;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
	ct->match      = xtnu_match_run;
	ct->checkentry = xtnu_match_check;
	ct->destroy    = xtnu_match_destroy;
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
	ct->match      = xtnu_match_run;
	ct->checkentry = xtnu_match_check;
	ct->destroy    = nt->destroy;
#else
	ct->match      = nt->match;
	ct->checkentry = xtnu_match_check;
	ct->destroy    = nt->destroy;
#endif
	ct->matchsize  = nt->matchsize;
	ct->me         = nt->me;

	nt->__compat_match = ct;
	ret = xt_register_match(ct);
	if (ret != 0)
		kfree(ct);
	return ret;
}
EXPORT_SYMBOL_GPL(xtnu_register_match);

int xtnu_register_matches(struct xtnu_match *nt, unsigned int num)
{
	unsigned int i;
	int ret;

	for (i = 0; i < num; ++i) {
		ret = xtnu_register_match(&nt[i]);
		if (ret < 0) {
			if (i > 0)
				xtnu_unregister_matches(nt, i);
			return ret;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(xtnu_register_matches);

void xtnu_unregister_match(struct xtnu_match *nt)
{
	xt_unregister_match(nt->__compat_match);
	kfree(nt->__compat_match);
}
EXPORT_SYMBOL_GPL(xtnu_unregister_match);

void xtnu_unregister_matches(struct xtnu_match *nt, unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; ++i)
		xtnu_unregister_match(&nt[i]);
}
EXPORT_SYMBOL_GPL(xtnu_unregister_matches);
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
static unsigned int xtnu_target_run(struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out,
    unsigned int hooknum, const struct xt_target *ct, const void *targinfo)
{
	struct xtnu_target *nt = xtcompat_nutarget(ct);
	struct xt_action_param local_par;

	local_par.in       = in;
	local_par.out      = out;
	local_par.hooknum  = hooknum;
	local_par.target   = ct;
	local_par.targinfo = targinfo;
	local_par.family   = NFPROTO_UNSPEC;

	if (nt != NULL && nt->target != NULL)
		return nt->target(&skb, &local_par);
	return XT_CONTINUE;
}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28) && \
    LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
static unsigned int
xtnu_target_run(struct sk_buff *skb, const struct xt_target_param *par)
{
	struct xtnu_target *nt = xtcompat_nutarget(par->target);
	struct xt_action_param local_par;

	local_par.in       = par->in;
	local_par.out      = par->out;
	local_par.hooknum  = par->hooknum;
	local_par.target   = par->target;
	local_par.targinfo = par->targinfo;
	local_par.family   = par->family;

	return nt->target(&skb, &local_par);
}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
static unsigned int
xtnu_target_run(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct xtnu_target *nt = xtcompat_nutarget(par->target);

	return nt->target(&skb, par);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
static bool xtnu_target_check(const char *table, const void *entry,
    const struct xt_target *ct, void *targinfo, unsigned int hook_mask)
{
	struct xtnu_target *nt = xtcompat_nutarget(ct);
	struct xt_tgchk_param local_par = {
		.table     = table,
		.entryinfo = entry,
		.target    = ct,
		.targinfo  = targinfo,
		.hook_mask = hook_mask,
		.family    = NFPROTO_UNSPEC,
	};

	if (nt == NULL)
		return false;
	if (nt->checkentry == NULL)
		/* this is valid, just like if there was no function */
		return true;
	return nt->checkentry(&local_par) == 0;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28) && \
    LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
static bool xtnu_target_check(const struct xt_tgchk_param *par)
{
	struct xtnu_target *nt = xtcompat_nutarget(par->target);

	if (nt == NULL)
		return false;
	if (nt->checkentry == NULL)
		return true;
	return nt->checkentry(par) == 0;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
static void xtnu_target_destroy(const struct xt_target *ct, void *targinfo)
{
	struct xtnu_target *nt = xtcompat_nutarget(ct);
	struct xt_tgdtor_param local_par = {
		.target   = ct,
		.targinfo = targinfo,
		.family   = NFPROTO_UNSPEC,
	};

	if (nt != NULL && nt->destroy != NULL)
		nt->destroy(&local_par);
}
#endif

int xtnu_register_target(struct xtnu_target *nt)
{
	struct xt_target *ct;
	char *tmp;
	int ret;

	ct = kzalloc(sizeof(struct xt_target), GFP_KERNEL);
	if (ct == NULL)
		return -ENOMEM;

	tmp = (char *)ct->name;
	memcpy(tmp, nt->name, sizeof(nt->name));
	tmp = (char *)(ct->name + sizeof(ct->name) - sizeof(void *));
	*(tmp-1) = '\0';
	memcpy(tmp, &nt, sizeof(void *));

	ct->revision   = nt->revision;
	ct->family     = nt->family;
	ct->table      = (char *)nt->table;
	ct->hooks      = nt->hooks;
	ct->proto      = nt->proto;
	ct->target     = xtnu_target_run;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
	ct->checkentry = xtnu_target_check;
	ct->destroy    = xtnu_target_destroy;
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
	ct->checkentry = xtnu_target_check;
	ct->destroy    = nt->destroy;
#else
	ct->checkentry = nt->checkentry;
	ct->destroy    = nt->destroy;
#endif
	ct->targetsize = nt->targetsize;
	ct->me         = nt->me;

	nt->__compat_target = ct;
	ret = xt_register_target(ct);
	if (ret != 0)
		kfree(ct);
	return ret;
}
EXPORT_SYMBOL_GPL(xtnu_register_target);

int xtnu_register_targets(struct xtnu_target *nt, unsigned int num)
{
	unsigned int i;
	int ret;

	for (i = 0; i < num; ++i) {
		ret = xtnu_register_target(&nt[i]);
		if (ret < 0) {
			if (i > 0)
				xtnu_unregister_targets(nt, i);
			return ret;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(xtnu_register_targets);

void xtnu_unregister_target(struct xtnu_target *nt)
{
	xt_unregister_target(nt->__compat_target);
	kfree(nt->__compat_target);
}
EXPORT_SYMBOL_GPL(xtnu_unregister_target);

void xtnu_unregister_targets(struct xtnu_target *nt, unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; ++i)
		xtnu_unregister_target(&nt[i]);
}
EXPORT_SYMBOL_GPL(xtnu_unregister_targets);

struct xt_match *xtnu_request_find_match(unsigned int af, const char *name,
    uint8_t revision)
{
	static const char *const xt_prefix[] = {
		[AF_UNSPEC] = "x",
		[AF_INET]   = "ip",
		[AF_INET6]  = "ip6",
#ifdef AF_ARP
		[AF_ARP]    = "arp",
#elif defined(NF_ARP) && NF_ARP != AF_UNSPEC
		[NF_ARP]    = "arp",
#endif
	};
	struct xt_match *match;

	match = try_then_request_module(xt_find_match(af, name, revision),
		"%st_%s", xt_prefix[af], name);
	if (IS_ERR(match) || match == NULL)
		return NULL;

	return match;
}
EXPORT_SYMBOL_GPL(xtnu_request_find_match);

int xtnu_ip_route_me_harder(struct sk_buff **pskb, unsigned int addr_type)
{
	return ip_route_me_harder(*pskb, addr_type);
}
EXPORT_SYMBOL_GPL(xtnu_ip_route_me_harder);

int xtnu_skb_make_writable(struct sk_buff **pskb, unsigned int len)
{
	return skb_make_writable(*pskb, len);
}
EXPORT_SYMBOL_GPL(xtnu_skb_make_writable);

void *HX_memmem(const void *space, size_t spacesize,
    const void *point, size_t pointsize)
{
	size_t i;

	if (pointsize > spacesize)
		return NULL;
	for (i = 0; i <= spacesize - pointsize; ++i)
		if (memcmp(space + i, point, pointsize) == 0)
			return (void *)space + i;
	return NULL;
}
EXPORT_SYMBOL_GPL(HX_memmem);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0) && defined(WITH_IPV6)
int xtnu_ipv6_skip_exthdr(const struct sk_buff *skb, int start,
    uint8_t *nexthdrp, __be16 *fragoffp)
{
	return ipv6_skip_exthdr(skb, start, nexthdrp);
}
EXPORT_SYMBOL_GPL(xtnu_ipv6_skip_exthdr);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0) && defined(WITH_IPV6)
int xtnu_ipv6_find_hdr(const struct sk_buff *skb, unsigned int *offset,
    int target, unsigned short *fragoff, int *fragflg)
{
	return ipv6_find_hdr(skb, offset, target, fragoff);
}
EXPORT_SYMBOL_GPL(xtnu_ipv6_find_hdr);
#endif

MODULE_LICENSE("GPL");
