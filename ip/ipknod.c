// SPDX-License-Identifier: GPL-2.0-or-later
/* ipknod.c	the GPUs knod links can run a NIC on
 *
 * Authors:	Taehee Yoo <ap420073@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/genetlink.h>
#include <linux/knod.h>

#include "utils.h"
#include "ip_common.h"
#include "json_print.h"
#include "libgenl.h"
#include "libnetlink.h"

static void usage(void)
{
	fprintf(stderr,
		"Usage:	ip knod list\n"
		"	ip knod help\n");
	exit(-1);
}

static struct rtnl_handle genl_rth = { .fd = -1 };
static int genl_family = -1;

#define KNOD_BUFLEN	1024
#define KNOD_REQUEST(_req, _cmd, _flags)			\
	GENL_REQUEST(_req, KNOD_BUFLEN, genl_family, 0,		\
		     KNOD_FAMILY_VERSION, _cmd, _flags)

static const char *knod_type_name(__u32 type)
{
	switch (type) {
	case KNOD_ACCEL_TYPE_GPU:
		return "gpu";
	case KNOD_ACCEL_TYPE_DPU:
		return "dpu";
	}
	return "unknown";
}

static const char *knod_feature_name(__u32 feature)
{
	switch (feature) {
	case KNOD_FEATURE_NONE:
		return "none";
	case KNOD_FEATURE_BPF:
		return "bpf";
	case KNOD_FEATURE_IPSEC:
		return "ipsec";
	}
	return "unknown";
}

static int print_knod_accel(struct nlmsghdr *n, void *arg)
{
	struct rtattr *tb[KNOD_A_ACCEL_MAX + 1];
	int len = n->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

	if (n->nlmsg_type != genl_family)
		return 0;
	if (len < 0)
		return -1;
	parse_rtattr(tb, KNOD_A_ACCEL_MAX,
		     (void *)NLMSG_DATA(n) + GENL_HDRLEN, len);
	if (!tb[KNOD_A_ACCEL_ID])
		return 0;

	open_json_object(NULL);
	print_uint(PRINT_ANY, "id", "id %u ",
		   rta_getattr_u32(tb[KNOD_A_ACCEL_ID]));
	if (tb[KNOD_A_ACCEL_NAME])
		print_string(PRINT_ANY, "name", "name %s ",
			     rta_getattr_str(tb[KNOD_A_ACCEL_NAME]));
	if (tb[KNOD_A_ACCEL_TYPE])
		print_string(PRINT_ANY, "type", "type %s ",
			     knod_type_name(rta_getattr_u32(tb[KNOD_A_ACCEL_TYPE])));
	if (tb[KNOD_A_ACCEL_FEATURE_ENA])
		print_string(PRINT_ANY, "feature", "feature %s",
			     knod_feature_name(rta_getattr_u32(tb[KNOD_A_ACCEL_FEATURE_ENA])));
	close_json_object();
	print_nl();
	return 0;
}

static int knod_list(void)
{
	KNOD_REQUEST(req, KNOD_CMD_ACCEL_GET, NLM_F_REQUEST | NLM_F_DUMP);

	if (rtnl_send(&genl_rth, &req.n, req.n.nlmsg_len) < 0) {
		perror("Cannot send list request");
		return -1;
	}
	new_json_obj(json);
	if (rtnl_dump_filter(&genl_rth, print_knod_accel, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		delete_json_obj();
		return -2;
	}
	delete_json_obj();
	return 0;
}

int do_ipknod(int argc, char **argv)
{
	if (argc > 0 && strcmp(*argv, "help") == 0)
		usage();

	if (genl_init_handle(&genl_rth, KNOD_FAMILY_NAME, &genl_family))
		exit(1);

	if (argc == 0 || strcmp(*argv, "list") == 0 ||
	    strcmp(*argv, "show") == 0)
		return knod_list();

	fprintf(stderr, "Command \"%s\" is unknown, try \"ip knod help\".\n",
		*argv);
	exit(-1);
}
