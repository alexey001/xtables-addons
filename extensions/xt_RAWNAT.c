/*
 *	"RAWNAT" target extension for Xtables - untracked NAT
 *	Copyright © Jan Engelhardt, 2008 - 2009
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_arp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/ip_fib.h>
#include "compat_xtables.h"
#include "xt_RAWNAT.h"

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#	define WITH_IPV6 1
#endif


static __be32 *tabdnat;
static __be32 *tabsnat;
static __be32 *tabclas[4];

static struct semaphore ipt_rnat_userspace_mutex;

#define BASEIP  ((192 ) | (168 << 8)) 

/*struct xt_rawnat_tginfo {
	union nf_inet_addr addr;
	__u8 mask;
	int match;
	int table;
};*/


static inline __be32
remask(__be32 addr, __be32 repl, unsigned int shift)
{
	uint32_t mask = (shift == 32) ? 0 : (~(uint32_t)0 >> shift);
	return htonl((ntohl(addr) & mask) | (ntohl(repl) & ~mask));
}

static struct net *pick_net(struct sk_buff *skb)
{
#ifdef CONFIG_NET_NS
	const struct dst_entry *dst;

	if (skb->dev != NULL)
		return dev_net(skb->dev);
	dst = skb_dst(skb);
	if (dst != NULL && dst->dev != NULL)
		return dev_net(dst->dev);
#endif
	return &init_net;
}

struct fib_table *fib_get_table(struct net *net, u32 id)
{
	struct fib_table *tb;
	struct hlist_head *head;
	unsigned int h;

	if (id == 0)
		id = RT_TABLE_MAIN;
	h = id & (FIB_TABLE_HASHSZ - 1);

	rcu_read_lock();
	head = &net->ipv4.fib_table_hash[h];
	hlist_for_each_entry_rcu(tb, head, tb_hlist) {
		if (tb->tb_id == id) {
			rcu_read_unlock();
			return tb;
		}
	}
	rcu_read_unlock();
	return NULL;
}

#ifdef WITH_IPV6
static void
rawnat_ipv6_mask(__be32 *addr, const __be32 *repl, unsigned int mask)
{
	switch (mask) {
	case 0:
		break;
	case 1 ... 31:
		addr[0] = remask(addr[0], repl[0], mask);
		break;
	case 32:
		addr[0] = repl[0];
		break;
	case 33 ... 63:
		addr[0] = repl[0];
		addr[1] = remask(addr[1], repl[1], mask - 32);
		break;
	case 64:
		addr[0] = repl[0];
		addr[1] = repl[1];
		break;
	case 65 ... 95:
		addr[0] = repl[0];
		addr[1] = repl[1];
		addr[2] = remask(addr[2], repl[2], mask - 64);
	case 96:
		addr[0] = repl[0];
		addr[1] = repl[1];
		addr[2] = repl[2];
		break;
	case 97 ... 127:
		addr[0] = repl[0];
		addr[1] = repl[1];
		addr[2] = repl[2];
		addr[3] = remask(addr[3], repl[3], mask - 96);
		break;
	case 128:
		addr[0] = repl[0];
		addr[1] = repl[1];
		addr[2] = repl[2];
		addr[3] = repl[3];
		break;
	}
}
#endif

static void rawnat4_update_l4(struct sk_buff *skb, __be32 oldip, __be32 newip)
{
	struct iphdr *iph = ip_hdr(skb);
	void *transport_hdr = (void *)iph + ip_hdrlen(skb);
	struct tcphdr *tcph;
	struct udphdr *udph;
	bool cond;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		tcph = transport_hdr;
		inet_proto_csum_replace4(&tcph->check, skb, oldip, newip, true);
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		udph = transport_hdr;
		cond = udph->check != 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
		cond |= skb->ip_summed == CHECKSUM_PARTIAL;
#endif
		if (cond) {
			inet_proto_csum_replace4(&udph->check, skb,
				oldip, newip, true);
			if (udph->check == 0)
				udph->check = CSUM_MANGLED_0;
		}
		break;
	}
}

static unsigned int rawnat4_writable_part(const struct iphdr *iph)
{
	unsigned int wlen = sizeof(*iph);

	switch (iph->protocol) {
	case IPPROTO_TCP:
		wlen += sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		wlen += sizeof(struct udphdr);
		break;
	}
	return wlen;
}

static unsigned int
rawsnat_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_rawnat_tginfo *info = par->targinfo;
	struct iphdr *iph;
	__be32 new_addr;

	iph = ip_hdr(skb);
	new_addr = remask(iph->saddr, info->addr.ip, info->mask);
	if (iph->saddr == new_addr)
		return XT_CONTINUE;

	if (!skb_make_writable(skb, rawnat4_writable_part(iph)))
		return NF_DROP;

	iph = ip_hdr(skb);
	csum_replace4(&iph->check, iph->saddr, new_addr);
	rawnat4_update_l4(skb, iph->saddr, new_addr);
	iph->saddr = new_addr;
	return XT_CONTINUE;
}

static unsigned int
rawdnat_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_rawnat_tginfo *info = par->targinfo;
	struct iphdr *iph;
	__be32 new_addr;

	iph = ip_hdr(skb);
	new_addr = remask(iph->daddr, info->addr.ip, info->mask);
	if (iph->daddr == new_addr)
		return XT_CONTINUE;

	if (!skb_make_writable(skb, rawnat4_writable_part(iph)))
		return NF_DROP;

	iph = ip_hdr(skb);

	csum_replace4(&iph->check, iph->daddr, new_addr);
	rawnat4_update_l4(skb, iph->daddr, new_addr);
	//printk("test ip: %ld\n", iph->daddr);
	iph->daddr = new_addr;
	return XT_CONTINUE;
}

static unsigned int
tabsnat_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *iph;
	__be32 new_addr;

	iph = ip_hdr(skb);

	new_addr = tabsnat[iph->saddr >> 16];

	if (new_addr == 0)
		return XT_CONTINUE;

	if (iph->saddr == new_addr)
		return XT_CONTINUE;

	if (!skb_make_writable(skb, rawnat4_writable_part(iph)))
		return NF_DROP;

	iph = ip_hdr(skb);
	csum_replace4(&iph->check, iph->saddr, new_addr);
	rawnat4_update_l4(skb, iph->saddr, new_addr);
	iph->saddr = new_addr;
	return XT_CONTINUE;
}

static unsigned int
tabdnat_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *iph;
	__be32 new_addr;

	iph = ip_hdr(skb);
	new_addr = tabdnat[iph->daddr >> 16];

	if (new_addr == 0)
		return XT_CONTINUE;

	if (iph->daddr == new_addr)
		return XT_CONTINUE;

	if (!skb_make_writable(skb, rawnat4_writable_part(iph)))
		return NF_DROP;

	iph = ip_hdr(skb);

	csum_replace4(&iph->check, iph->daddr, new_addr);
	rawnat4_update_l4(skb, iph->daddr, new_addr);
	//printk("test ip: %ld\n", iph->daddr);
	iph->daddr = new_addr;
	return XT_CONTINUE;
}

static unsigned int
tabclas_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *iph;
        struct fib_table *ft;
        struct net *net;
        struct fib_result fib_res = { 0 };
        struct flowi4 fl4 = { 0 };
        int error;

	const struct xt_rawnat_tginfo *info = par->targinfo;
	__be32 priority;

	iph = ip_hdr(skb);

        if (info->rtable > 1)
          {
            net=pick_net(skb);
            ft=fib_get_table(net,info->rtable);
            if (!ft)
              return XT_CONTINUE;
            if (info->match == 0) fl4.daddr=ntohl(iph->daddr);
            else
              fl4.daddr=ntohl(iph->saddr);


            //error=fib_table_lookup(ft,&fl4,&fib_res,FIB_LOOKUP_NOREF);
            error=fib_table_lookup(ft,&fl4,&fib_res,0);
            printk("Recv 1 err: %i ip: %X RT: %i FT: %p \n",error,fl4.daddr,info->rtable,ft);
            if (!error)
              {
                struct fib_nh *nh=&FIB_RES_NH(fib_res); 
                priority=nh->nh_tclassid;
              }
              else priority=0;
          }
        else
          {
	if (info->match == 0)
		priority = tabclas[info->table - 3][iph->daddr >> 16];
	else
		priority = tabclas[info->table - 3][iph->saddr >> 16];
          }

	if (priority == 0)
		return XT_CONTINUE;

	skb->priority = priority;
	skb_nfmark(skb) = priority;
	return XT_CONTINUE;
}



#ifdef WITH_IPV6
static bool rawnat6_prepare_l4(struct sk_buff *skb, unsigned int *l4offset,
    unsigned int *l4proto)
{
	static const unsigned int types[] =
		{IPPROTO_TCP, IPPROTO_UDP, IPPROTO_UDPLITE};
	unsigned int i;
	int err;
        unsigned short frag;

	*l4proto = NEXTHDR_MAX;

	for (i = 0; i < ARRAY_SIZE(types); ++i) {
          err = ipv6_find_hdr(skb, l4offset, types[i], &frag, NULL);
		if (err >= 0) {
			*l4proto = types[i];
			break;
		}
		if (err != -ENOENT)
			return false;
	}

	switch (*l4proto) {
	case IPPROTO_TCP:
		if (!skb_make_writable(skb, *l4offset + sizeof(struct tcphdr)))
			return false;
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		if (!skb_make_writable(skb, *l4offset + sizeof(struct udphdr)))
			return false;
		break;
	}

	return true;
}

static void rawnat6_update_l4(struct sk_buff *skb, unsigned int l4proto,
    unsigned int l4offset, const struct in6_addr *oldip,
    const struct in6_addr *newip)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	struct tcphdr *tcph;
	struct udphdr *udph;
	unsigned int i;
	bool cond;

	switch (l4proto) {
	case IPPROTO_TCP:
		tcph = (void *)iph + l4offset;
		for (i = 0; i < 4; ++i)
			inet_proto_csum_replace4(&tcph->check, skb,
				oldip->s6_addr32[i], newip->s6_addr32[i], true);
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		udph = (void *)iph + l4offset;
		cond = udph->check;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
		cond |= skb->ip_summed == CHECKSUM_PARTIAL;
#endif
		if (cond) {
			for (i = 0; i < 4; ++i)
				inet_proto_csum_replace4(&udph->check, skb,
					oldip->s6_addr32[i],
					newip->s6_addr32[i], true);
			if (udph->check == 0)
				udph->check = CSUM_MANGLED_0;
		}
		break;
	}
}

static unsigned int
rawsnat_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_rawnat_tginfo *info = par->targinfo;
	unsigned int l4offset, l4proto;
	struct ipv6hdr *iph;
	struct in6_addr new_addr;

	iph = ipv6_hdr(skb);
	memcpy(&new_addr, &iph->saddr, sizeof(new_addr));
	rawnat_ipv6_mask(new_addr.s6_addr32, info->addr.ip6, info->mask);
	if (ipv6_addr_cmp(&iph->saddr, &new_addr) == 0)
		return XT_CONTINUE;
	if (!rawnat6_prepare_l4(skb, &l4offset, &l4proto))
		return NF_DROP;
	iph = ipv6_hdr(skb);
	rawnat6_update_l4(skb, l4proto, l4offset, &iph->saddr, &new_addr);
	memcpy(&iph->saddr, &new_addr, sizeof(new_addr));
	return XT_CONTINUE;
}

static unsigned int
rawdnat_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_rawnat_tginfo *info = par->targinfo;
	unsigned int l4offset, l4proto;
	struct ipv6hdr *iph;
	struct in6_addr new_addr;

	iph = ipv6_hdr(skb);
	memcpy(&new_addr, &iph->daddr, sizeof(new_addr));
	rawnat_ipv6_mask(new_addr.s6_addr32, info->addr.ip6, info->mask);
	if (ipv6_addr_cmp(&iph->daddr, &new_addr) == 0)
		return XT_CONTINUE;
	if (!rawnat6_prepare_l4(skb, &l4offset, &l4proto))
		return NF_DROP;
	iph = ipv6_hdr(skb);
	rawnat6_update_l4(skb, l4proto, l4offset, &iph->daddr, &new_addr);
	memcpy(&iph->daddr, &new_addr, sizeof(new_addr));
	return XT_CONTINUE;
}
#endif

static int rawnat_tg_check(const struct xt_tgchk_param *par)
{
	if (strcmp(par->table, "raw") == 0 ||
	    strcmp(par->table, "rawpost") == 0)
		return 0;

	printk(KERN_ERR KBUILD_MODNAME " may only be used in the \"raw\" or "
	       "\"rawpost\" table.\n");
	return -EINVAL;
}

static int tabclas_tg_check(const struct xt_tgchk_param *par)
{
	if (strcmp(par->table, "mangle") == 0)
		return 0;

	printk(KERN_ERR KBUILD_MODNAME " may only be used in the \"mangle\".\n");
	return -EINVAL;
}

static int ipt_rnat_set_ctl(struct sock *sk, int cmd,
			void *user, unsigned int len)
{
	struct ipt_rnat_handle_sockopt handle;
	int ret = -EINVAL;
	__be32 *table;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
	case IPT_SO_SET_RAWNAT_IP:
		if (len != sizeof(struct ipt_rnat_handle_sockopt)) {
			printk("RAWNAT: ipt_rnat_set_ctl: wrong data size (%u != %zu) "
				"for IPT_SO_SET_RAWNAT_IP\n",
				len, sizeof(struct ipt_rnat_handle_sockopt));
			break;
		}

		if (copy_from_user(&handle, user, len)) {
			printk("ACCOUNT: ipt_rnat_set_ctl: copy_from_user failed for "
				"IPT_SO_SET_RAWNAT_IP\n");
			break;
		}

		table = tabdnat;
		if (handle.tab_num == 2)
			table = tabsnat;
		else if ((handle.tab_num >= 3) && (handle.tab_num <= 6)) 
			table = tabclas[handle.tab_num-3];
		down(&ipt_rnat_userspace_mutex);
		table[(handle.ip >> 16)] = handle.repl_ip;
		up(&ipt_rnat_userspace_mutex);
		printk("added %i -> %i to table %i\n", handle.ip, handle.repl_ip, handle.tab_num);
		ret = 0;
		break;

	case IPT_SO_SET_RAWNAT_FREE_IP: {
		if (len != sizeof(struct ipt_rnat_handle_sockopt)) {
			printk("RAWNAT: ipt_rnat_set_ctl: wrong data size (%u != %zu) "
				"for IPT_SO_SET_RAWNAT_FREE_IP\n",
				len, sizeof(struct ipt_rnat_handle_sockopt));
			break;
		}

		if (copy_from_user(&handle, user, len)) {
			printk("ACCOUNT: ipt_rnat_set_ctl: copy_from_user failed for "
				"IPT_SO_SET_RAWNAT_FREE_IP\n");
			break;
		}

		table = tabdnat;
		if (handle.tab_num == 2)
			table = tabsnat;
		else if ((handle.tab_num >= 3) && (handle.tab_num <= 6))
			table = tabclas[handle.tab_num-3];

		down(&ipt_rnat_userspace_mutex);
		memset(table, 0, sizeof(__be32)*0xFFFF);
		up(&ipt_rnat_userspace_mutex);
		printk("flushed table %i\n", handle.tab_num);
		ret = 0;
		break;

	}
	default:
		printk("ACCOUNT: ipt_acc_set_ctl: unknown request %i\n", cmd);
	}

	return ret;
}

static int ipt_rnat_get_ctl(struct sock *sk, int cmd, void *user, int *len)
{
	struct ipt_rnat_handle_sockopt handle;
	int ret = -EINVAL;
	__be32 *table;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
	case IPT_SO_GET_RAWNAT_GET_DATA:
		if (*len <= sizeof(struct ipt_rnat_handle_sockopt)) {
			printk("RAWNAT: ipt_rnat_set_ctl: wrong data size (%u != %zu) "
				"for IPT_SO_SET_RAWNAT_IP\n",
				*len, sizeof(struct ipt_rnat_handle_sockopt));
			break;
		}

		if (copy_from_user(&handle, user, sizeof(struct ipt_rnat_handle_sockopt))) {
			printk("ACCOUNT: ipt_rnat_set_ctl: copy_from_user failed for "
				"IPT_SO_SET_RAWNAT_IP\n");
			break;
		}

		table = tabdnat;
		if (handle.tab_num == 2)
			table = tabsnat;
		else if ((handle.tab_num >= 3) && (handle.tab_num <= 6))
			table = tabclas[handle.tab_num-3];

		if (*len >= sizeof(__be32)*0xFFFF) {

			if (copy_to_user(user, table, sizeof(__be32)*0xFFFF)) {
				return -EFAULT;
				break;
			}
			ret = 0;
		}
		break;

	default:
		printk("ACCOUNT: ipt_acc_get_ctl: unknown request %i\n", cmd);
	}

	return ret;
}


static struct xt_target rawnat_tg_reg[] __read_mostly = {
	{
		.name       = "RAWSNAT",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = rawsnat_tg4,
		.targetsize = sizeof(struct xt_rawnat_tginfo),
		.checkentry = rawnat_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "TABSNAT",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = tabsnat_tg4,
		.targetsize = 0,
		.checkentry = rawnat_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "TABCLAS",
		.revision   = 0,
		.family     = NFPROTO_UNSPEC,
		.hooks      = (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_FORWARD) |
		              (1 << NF_INET_POST_ROUTING),
		.target     = tabclas_tg4,
		.targetsize = sizeof(struct xt_rawnat_tginfo),
		.checkentry = tabclas_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "TABCLAS",
		.revision   = 0,
		.family     = NFPROTO_ARP,
		.hooks      = (1 << NF_ARP_OUT) | (1 << NF_ARP_FORWARD),
		.target     = tabclas_tg4,
		.targetsize = sizeof(struct xt_rawnat_tginfo),
		.checkentry = tabclas_tg_check,
		.me         = THIS_MODULE,
	},
#ifdef WITH_IPV6
	{
		.name       = "RAWSNAT",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = rawsnat_tg6,
		.targetsize = sizeof(struct xt_rawnat_tginfo),
		.checkentry = rawnat_tg_check,
		.me         = THIS_MODULE,
	},
#endif
	{
		.name       = "RAWDNAT",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = rawdnat_tg4,
		.targetsize = sizeof(struct xt_rawnat_tginfo),
		.checkentry = rawnat_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "TABDNAT",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = tabdnat_tg4,
		.targetsize = 0,
		.checkentry = rawnat_tg_check,
		.me         = THIS_MODULE,
	},
#ifdef WITH_IPV6
	{
		.name       = "RAWDNAT",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = rawdnat_tg6,
		.targetsize = sizeof(struct xt_rawnat_tginfo),
		.checkentry = rawnat_tg_check,
		.me         = THIS_MODULE,
	},
#endif
};

static struct nf_sockopt_ops ipt_rnat_sockopts = {
	.pf = PF_INET,
	.set_optmin = IPT_SO_SET_RAWNAT_IP,
	.set_optmax = IPT_SO_SET_RAWNAT_MAX+1,
	.set = ipt_rnat_set_ctl,
	.get_optmin = IPT_SO_GET_RAWNAT_PREPARE_READ,
	.get_optmax = IPT_SO_GET_RAWNAT_MAX+1,
	.get = ipt_rnat_get_ctl
};

static int __init rawnat_tg_init(void)
{
	sema_init(&ipt_rnat_userspace_mutex, 1);

	tabdnat = kmalloc(sizeof(__be32)*0xFFFF, GFP_KERNEL);
	memset(tabdnat, 0, sizeof(__be32)*0xFFFF);
	tabsnat = kmalloc(sizeof(__be32)*0xFFFF, GFP_KERNEL);
	memset(tabsnat, 0, sizeof(__be32)*0xFFFF);

	tabclas[0] = kmalloc(sizeof(__be32)*0xFFFF, GFP_KERNEL);
	memset(tabclas[0], 0, sizeof(__be32)*0xFFFF);
	tabclas[1] = kmalloc(sizeof(__be32)*0xFFFF, GFP_KERNEL);
	memset(tabclas[1], 0, sizeof(__be32)*0xFFFF);
	tabclas[2] = kmalloc(sizeof(__be32)*0xFFFF, GFP_KERNEL);
	memset(tabclas[2], 0, sizeof(__be32)*0xFFFF);
	tabclas[3] = kmalloc(sizeof(__be32)*0xFFFF, GFP_KERNEL);
	memset(tabclas[3], 0, sizeof(__be32)*0xFFFF);

	printk(KERN_ALERT "TABNAT/TABCLASS loaded\n");

	/* Register setsockopt */
	if (nf_register_sockopt(&ipt_rnat_sockopts) < 0) {
		printk("ACCOUNT: Can't register sockopts. Aborting\n");
		goto error_cleanup;
	}

	return xt_register_targets(rawnat_tg_reg, ARRAY_SIZE(rawnat_tg_reg));

error_cleanup:
	if (tabdnat)
		kfree(tabdnat);
	if (tabsnat)
		kfree(tabsnat);
	return -EINVAL;
}

static void __exit rawnat_tg_exit(void)
{

	xt_unregister_targets(rawnat_tg_reg, ARRAY_SIZE(rawnat_tg_reg));

	nf_unregister_sockopt(&ipt_rnat_sockopts);

	if (tabdnat)
		kfree(tabdnat);
	if (tabsnat)
		kfree(tabsnat);
}

module_init(rawnat_tg_init);
module_exit(rawnat_tg_exit);
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>, Vlad Dubrov <vlad@centrlan.net>");
MODULE_DESCRIPTION("Xtables: conntrack-less raw NAT, table raw NAT, table CLASSIFY");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_RAWSNAT");
MODULE_ALIAS("ipt_RAWDNAT");
MODULE_ALIAS("ipt_TABCLAS");
MODULE_ALIAS("ip6t_RAWSNAT");
MODULE_ALIAS("ip6t_RAWDNAT");
