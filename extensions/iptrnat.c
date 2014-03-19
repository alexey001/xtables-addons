/***************************************************************************
 *   Copyright (C) 2004-2006 by Intra2net AG                               *
 *   opensource@intra2net.com                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Lesser General Public License           *
 *   version 2.1 as published by the Free Software Foundation;             *
 *                                                                         *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>

#include <arpa/inet.h>
#include <linux/types.h>
#include <xtables.h>
#include "xt_RAWNAT.h"
#include <linux/netfilter/x_tables.h>

#define TC_H_MAJ_MASK (0xFFFF0000U)
#define TC_H_MIN_MASK (0x0000FFFFU)
#define TC_H_MAJ(h) ((h)&TC_H_MAJ_MASK)
#define TC_H_MIN(h) ((h)&TC_H_MIN_MASK)
#define TC_H_MAKE(maj,min) (((maj)&TC_H_MAJ_MASK)|((min)&TC_H_MIN_MASK))


struct ipt_RNAT_context
{
	int sockfd;
	struct ipt_rnat_handle_sockopt handle;

	unsigned int data_size;
	__be32 *data;

	char *error_str;
};


bool exit_now;

static int CLASSIFY_string_to_priority(const char *s, unsigned int *p)
{
	unsigned int i, j;

	if (sscanf(s, "%x:%x", &i, &j) != 2)
		return 1;
	
	*p = TC_H_MAKE(i<<16, j);
	return 0;
}

static void
CLASSIFY_print_class(unsigned int priority, int numeric)
{
	printf("%x:%x ", TC_H_MAJ(priority)>>16, TC_H_MIN(priority));
}

int ipt_RNAT_init(struct ipt_RNAT_context *ctx)
{
	memset(ctx, 0, sizeof(struct ipt_RNAT_context));

	ctx->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (ctx->sockfd < 0) {
		ctx->sockfd = -1;
		ctx->error_str = "Can't open socket to kernel. "
		                 "Permission denied or ipt_RNAT module not loaded";
		return -1;
	}

	// 4096 bytes default buffer should save us from reallocations
	// as it fits 200 concurrent active clients
	if ((ctx->data = malloc(sizeof(__be32)*0xFFFF)) == NULL) {
		close(ctx->sockfd);
		ctx->sockfd = -1;
		ctx->error_str = "Out of memory for data buffer";
		return -1;
	}
	ctx->data_size = sizeof(__be32)*0xFFFF;

	return 0;
}

void ipt_RNAT_deinit(struct ipt_RNAT_context *ctx)
{
	free(ctx->data);
	ctx->data = NULL;

	close(ctx->sockfd);
	ctx->sockfd = -1;
}


int ipt_RNAT_add_ip(struct ipt_RNAT_context *ctx, int tab, __be32 ip, __be32 repl)
{
	struct ipt_rnat_handle_sockopt handle;

	handle.tab_num = tab;
	handle.ip = ip;
	handle.repl_ip = repl;
	
	if (setsockopt(ctx->sockfd, IPPROTO_IP,
	    IPT_SO_SET_RAWNAT_IP, &handle, sizeof(struct ipt_rnat_handle_sockopt)) < 0) {
		ctx->error_str = "Can't add ip";
		return -1;
	}

	return 0;
}

int ipt_RNAT_del_ip(struct ipt_RNAT_context *ctx, int tab, __be32 ip)
{
	struct ipt_rnat_handle_sockopt handle;

	handle.tab_num = tab;
	handle.ip = ip;
	handle.repl_ip = 0;
	
	if (setsockopt(ctx->sockfd, IPPROTO_IP,
	    IPT_SO_SET_RAWNAT_IP, &handle, sizeof(struct ipt_rnat_handle_sockopt)) < 0) {
		ctx->error_str = "Can't delete ip";
		return -1;
	}

	return 0;
}

int ipt_RNAT_flush(struct ipt_RNAT_context *ctx, int tab)
{
	struct ipt_rnat_handle_sockopt handle;

	handle.tab_num = tab;
	
	if (setsockopt(ctx->sockfd, IPPROTO_IP,
	    IPT_SO_SET_RAWNAT_FREE_IP, &handle, sizeof(struct ipt_rnat_handle_sockopt)) < 0) {
		ctx->error_str = "Can't flush";
		return -1;
	}

	return 0;
}

int ipt_RNAT_get_table(struct ipt_RNAT_context *ctx, int tab)
{
	struct ipt_rnat_handle_sockopt handle;

	handle.tab_num = tab;
	memcpy(ctx->data, &handle, sizeof(struct ipt_rnat_handle_sockopt));
	
	if (getsockopt(ctx->sockfd, IPPROTO_IP,
	    IPT_SO_GET_RAWNAT_GET_DATA, ctx->data, &ctx->data_size) < 0) {
		ctx->error_str = "Can't get table";
		return -1;
	}

	return 0;
}

static void sig_term(int signr)
{
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	exit_now = true;
}

static char *addr_to_dotted(unsigned int addr)
{
	static char buf[16];
	const unsigned char *bytep;

	addr = htonl(addr);
	bytep = (const unsigned char *)&addr;
	snprintf(buf, sizeof(buf), "%u.%u.%u.%u", bytep[3], bytep[2], bytep[1], bytep[0]);
	return buf;
}

static void show_usage(void)
{
	printf("Unknown command line option. Try: [-a] [-d] [-f] [-l]\n");
	printf("[-a -t table -i ip -r dst] add ip\n");
	printf("[-a -t table -i ip -c xx:yyyy] add priority\n");
	printf("[-d -t table -i ip] delete ip\n");
	printf("[-f -t table] flush table\n");
	printf("[-l -t table] list table contents\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	struct ipt_RNAT_context ctx;
	struct ipt_acc_handle_ip *entry;
	int i;
	char optchar;
	bool doAddIP = false, doDelIP = false, doTableList = false;
	bool doFlush = false;
	__be32 src_ip;
	__be32 dst_ip;

	int table_number = 1;
	
	const char *name;

	//printf("\nlibxt_RNAT_cl userspace tool \n\n");

	if (argc == 1)
	{
		show_usage();
		exit(0);
	}

	while ((optchar = getopt(argc, argv, "adlft:i:r:c:")) != -1)
	{
		switch (optchar)
		{
		case 'a':
			doAddIP = true;
			break;
		case 'd':
			doDelIP = true;
			break;
		case 'l':
			doTableList = true;
			break;
		case 'f':
			doFlush = true;
			break;
		case 't':
			table_number = atoi(optarg);
			break;
		case 'i':
			src_ip = inet_addr(optarg);
			break;
		case 'r':
			dst_ip = inet_addr(optarg);
			break;
		case 'c':
			CLASSIFY_string_to_priority(optarg, &dst_ip);
			break;
			
		case '?':
		default:
			show_usage();
			exit(0);
			break;
		}
	}

	// install exit handler
	if (signal(SIGTERM, sig_term) == SIG_ERR)
	{
		printf("can't install signal handler for SIGTERM\n");
		exit(-1);
	}
	if (signal(SIGINT, sig_term) == SIG_ERR)
	{
		printf("can't install signal handler for SIGINT\n");
		exit(-1);
	}
	if (signal(SIGQUIT, sig_term) == SIG_ERR)
	{
		printf("can't install signal handler for SIGQUIT\n");
		exit(-1);
	}

	if (ipt_RNAT_init(&ctx))
	{
		printf("Init failed: %s\n", ctx.error_str);
		exit(-1);
	}

	// Get handle usage?
	if (doAddIP)
	{
		int rtn = ipt_RNAT_add_ip(&ctx, table_number, src_ip, dst_ip);
		if (rtn < 0)
		{
			printf("doAddIP failed: %s\n", ctx.error_str);
			exit(-1);
		}

	}

	if (doDelIP)
	{
		int rtn = ipt_RNAT_del_ip(&ctx, table_number, src_ip);
		if (rtn < 0)
		{
			printf("doDelIP failed: %s\n", ctx.error_str);
			exit(-1);
		}

	}

	if (doFlush)
	{
		int rtn = ipt_RNAT_flush(&ctx, table_number);
		if (rtn < 0)
		{
			printf("doFlush failed: %s\n", ctx.error_str);
			exit(-1);
		}

	}

	if (doTableList)
	{
		int rtn = ipt_RNAT_get_table(&ctx, table_number);
		if (rtn < 0)
		{
			printf("doTableList failed: %s\n", ctx.error_str);
			exit(-1);
		}
		for (i=0; i<0xFFFF; i++) {
			if (ctx.data[i]) {
				printf("%s ", addr_to_dotted(i << 16));
				if (table_number < 3) {
					printf("%s\n", addr_to_dotted(ctx.data[i]));
				} else {
					CLASSIFY_print_class(ctx.data[i], 0);
					printf("\n");
				}
			}
		}

	}


	//printf("Finished.\n");
	ipt_RNAT_deinit(&ctx);
	return EXIT_SUCCESS;
}
