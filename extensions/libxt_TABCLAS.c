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

static const struct option tabclas_tg_opts[] = {
	{.name = "cmatch", .has_arg = true, .val = 'm'},
	{.name = "ctable", .has_arg = true, .val = 't'},
	{.name = "rtable", .has_arg = true, .val = 'r'},
	{},
};

static void tabclas_tg_help(void)
{
	printf(
"TABCLAS target options:\n"
"    --cmatch [dst/src]    Match destination or source address\n"
"    --ctable [3,4,5,6]    Table to set priority from\n"
"    --from-rtable [table num 2-254]    Route table to set priority from route realm\n"
);
}

static int
tabclas_tg4_parse(int c, char **argv, int invert, unsigned int *flags,
                  const void *entry, struct xt_entry_target **target)
{

	struct xt_rawnat_tginfo *info = (void *)(*target)->data;

	switch (c) {
	case 'm':
		if (strcmp(optarg, "dst") == 0)
			info->match = 0;
		else if (strcmp(optarg, "src") == 0)
			info->match = 1;
		else xtables_param_act(XTF_BAD_VALUE, "TABCLAS",
				"--cmatch", optarg);
		*flags |= XT_TABCLAS_MATCH;
		return true;
		break;
	case 't':
		if (!xtables_strtoui(optarg, NULL, &info->table, 3, 6))
			xtables_param_act(XTF_BAD_VALUE, "TABCLAS",
				"--ctable", optarg);
		*flags |= XT_TABCLAS_TABLE;
		return true;
		break;
	case 'r':
		if (!xtables_strtoui(optarg, NULL, &info->table, 2, 254))
			xtables_param_act(XTF_BAD_VALUE, "TABCLAS",
				"--rtable", optarg);
		*flags |= XT_TABCLAS_RTABLE;
		return true;
		break;

	}
	return false;
}

static void tabclas_tg_check(unsigned int flags)
{
  if ((!(flags & XT_TABCLAS_MATCH)) || (!(flags & (XT_TABCLAS_TABLE | XT_TABCLAS_RTABLE))))
		xtables_error(PARAMETER_PROBLEM, "TABCLAS: "
			"--cmatch and --ctable are required.");
}

static void
tabclas_tg4_print(const void *entry, const struct xt_entry_target *target,
                  int numeric)
{
	const struct xt_rawnat_tginfo *info = (const void *)target->data;

	printf(" cmatch %s ctable %d rtable %d", info->match ? "src" : "dst", info->table, info->rtable);

}


static void
tabclas_tg4_save(const void *entry, const struct xt_entry_target *target)
{
	const struct xt_rawnat_tginfo *info = (const void *)target->data;

	printf(" --cmatch %s --ctable %d ", info->match ? "src" : "dst", info->table);
}


static struct xtables_target tabclas_tg_reg[] = {
	{
		.version       = XTABLES_VERSION,
		.name          = "TABCLAS",
		.revision      = 0,
		.family		= NFPROTO_UNSPEC,
		.size          = XT_ALIGN(sizeof(struct xt_rawnat_tginfo)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_rawnat_tginfo)),
		.help          = tabclas_tg_help,
		.parse         = tabclas_tg4_parse,
		.final_check   = tabclas_tg_check,
		.print         = tabclas_tg4_print,
		.save          = tabclas_tg4_save,
		.extra_opts    = tabclas_tg_opts,
	},
};

static void _init(void)
{
	xtables_register_targets(tabclas_tg_reg,
		sizeof(tabclas_tg_reg) / sizeof(*tabclas_tg_reg));
}
