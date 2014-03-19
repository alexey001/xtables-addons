/*
 *	"RAWNAT" target extension for iptables
 *	Copyright © Jan Engelhardt, 2008 - 2009
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <netinet/in.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include "xt_RAWNAT.h"
#include "compat_user.h"

enum {
	FLAGS_TO = 1 << 0,
};

static const struct option tabsnat_tg_opts[] = {
	{},
};

static void tabsnat_tg_help(void)
{
	printf(
"TABSNAT target options:\n"
);
}

static int
tabsnat_tg4_parse(int c, char **argv, int invert, unsigned int *flags,
                  const void *entry, struct xt_entry_target **target)
{

	return true;
}

static void tabsnat_tg_check(unsigned int flags)
{
}

static void
tabsnat_tg4_print(const void *entry, const struct xt_entry_target *target,
                  int numeric)
{
}


static void
tabsnat_tg4_save(const void *entry, const struct xt_entry_target *target)
{
}


static struct xtables_target tabsnat_tg_reg[] = {
	{
		.version       = XTABLES_VERSION,
		.name          = "TABSNAT",
		.revision      = 0,
		.family        = NFPROTO_IPV4,
		.size          = 0,
		.userspacesize = 0,
		.help          = tabsnat_tg_help,
		.parse         = tabsnat_tg4_parse,
		.final_check   = tabsnat_tg_check,
		.print         = tabsnat_tg4_print,
		.save          = tabsnat_tg4_save,
		.extra_opts    = tabsnat_tg_opts,
	},
};

static void _init(void)
{
	xtables_register_targets(tabsnat_tg_reg,
		sizeof(tabsnat_tg_reg) / sizeof(*tabsnat_tg_reg));
}
