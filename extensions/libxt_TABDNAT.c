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

static const struct option tabdnat_tg_opts[] = {
	{},
};

static void tabdnat_tg_help(void)
{
	printf(
"TABDNAT target options:\n"
"    --to-destination addr[/mask]    Address or network to map to\n"
);
}

static int
tabdnat_tg4_parse(int c, char **argv, int invert, unsigned int *flags,
                  const void *entry, struct xt_entry_target **target)
{

	return true;
}

static void tabdnat_tg_check(unsigned int flags)
{
}

static void
tabdnat_tg4_print(const void *entry, const struct xt_entry_target *target,
                  int numeric)
{
}


static void
tabdnat_tg4_save(const void *entry, const struct xt_entry_target *target)
{
}


static struct xtables_target tabdnat_tg_reg[] = {
	{
		.version       = XTABLES_VERSION,
		.name          = "TABDNAT",
		.revision      = 0,
		.family        = NFPROTO_IPV4,
		.size          = 0,
		.userspacesize = 0,
		.help          = tabdnat_tg_help,
		.parse         = tabdnat_tg4_parse,
		.final_check   = tabdnat_tg_check,
		.print         = tabdnat_tg4_print,
		.save          = tabdnat_tg4_save,
		.extra_opts    = tabdnat_tg_opts,
	},
};

static void _init(void)
{
	xtables_register_targets(tabdnat_tg_reg,
		sizeof(tabdnat_tg_reg) / sizeof(*tabdnat_tg_reg));
}
