// SPDX-License-Identifier: GPL-2.0-or-later
/* ipknod.c	knod: the GPUs, the NICs a knod link can run, the links
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
#include "ll_map.h"

static void usage(void)
{
	fprintf(stderr,
		"Usage:	ip knod list\n"
		"	ip knod set id ID feature { none | bpf | ipsec }\n"
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

/* A reply's attributes, @max of them, in @tb. */
static int knod_parse(struct nlmsghdr *n, struct rtattr **tb, int max)
{
	int len = n->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

	if (n->nlmsg_type != genl_family || len < 0)
		return -1;
	parse_rtattr(tb, max, (void *)NLMSG_DATA(n) + GENL_HDRLEN, len);
	return 0;
}

static int print_knod_accel(struct nlmsghdr *n, void *arg)
{
	struct rtattr *tb[KNOD_A_ACCEL_MAX + 1];

	if (knod_parse(n, tb, KNOD_A_ACCEL_MAX) || !tb[KNOD_A_ACCEL_ID])
		return 0;

	open_json_object(NULL);
	print_string(PRINT_FP, NULL, "%s", "gpu ");
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

static int print_knod_nic(struct nlmsghdr *n, void *arg)
{
	struct rtattr *tb[KNOD_A_NIC_MAX + 1];

	if (knod_parse(n, tb, KNOD_A_NIC_MAX) || !tb[KNOD_A_NIC_IFINDEX])
		return 0;

	open_json_object(NULL);
	print_string(PRINT_FP, NULL, "%s", "nic ");
	print_string(PRINT_ANY, "ifname", "%s",
		     ll_index_to_name(rta_getattr_u32(tb[KNOD_A_NIC_IFINDEX])));
	close_json_object();
	print_nl();
	return 0;
}

static int print_knod_dev(struct nlmsghdr *n, void *arg)
{
	struct rtattr *tb[KNOD_A_DEV_MAX + 1];

	if (knod_parse(n, tb, KNOD_A_DEV_MAX) || !tb[KNOD_A_DEV_NIC_IFINDEX])
		return 0;

	open_json_object(NULL);
	print_string(PRINT_FP, NULL, "%s", "link ");
	if (tb[KNOD_A_DEV_LINK_IFINDEX])
		print_string(PRINT_ANY, "ifname", "%s ",
			     ll_index_to_name(rta_getattr_u32(tb[KNOD_A_DEV_LINK_IFINDEX])));
	print_string(PRINT_ANY, "nic", "nic %s ",
		     ll_index_to_name(rta_getattr_u32(tb[KNOD_A_DEV_NIC_IFINDEX])));
	if (tb[KNOD_A_DEV_ACCEL_ID])
		print_uint(PRINT_ANY, "id", "id %u",
			   rta_getattr_u32(tb[KNOD_A_DEV_ACCEL_ID]));
	close_json_object();
	print_nl();
	return 0;
}

/* Dump @cmd's objects as @key, each through @filter. */
static int knod_dump(__u8 cmd, const char *key, rtnl_filter_t filter)
{
	KNOD_REQUEST(req, cmd, NLM_F_REQUEST | NLM_F_DUMP);
	int err = 0;

	if (rtnl_send(&genl_rth, &req.n, req.n.nlmsg_len) < 0) {
		perror("Cannot send list request");
		return -1;
	}
	open_json_array(PRINT_JSON, key);
	if (rtnl_dump_filter(&genl_rth, filter, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		err = -2;
	}
	close_json_array(PRINT_JSON, NULL);
	return err;
}

/* The GPUs, the NICs a knod link can run, and the links there are. */
static int knod_list(void)
{
	int err;

	ll_init_map(&rth);
	new_json_obj(json);
	open_json_object(NULL);
	err = knod_dump(KNOD_CMD_ACCEL_GET, "gpus", print_knod_accel);
	if (!err)
		err = knod_dump(KNOD_CMD_NIC_GET, "nics", print_knod_nic);
	if (!err)
		err = knod_dump(KNOD_CMD_DEV_GET, "links", print_knod_dev);
	close_json_object();
	delete_json_obj();
	return err;
}

static int knod_set(int argc, char **argv)
{
	KNOD_REQUEST(req, KNOD_CMD_ACCEL_SET, NLM_F_REQUEST);
	__u32 id = 0, feature = KNOD_FEATURE_NONE;
	bool have_id = false, have_feature = false;

	while (argc > 0) {
		if (strcmp(*argv, "id") == 0) {
			NEXT_ARG();
			if (get_u32(&id, *argv, 0))
				invarg("invalid id", *argv);
			have_id = true;
		} else if (strcmp(*argv, "feature") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "none") == 0)
				feature = KNOD_FEATURE_NONE;
			else if (strcmp(*argv, "bpf") == 0)
				feature = KNOD_FEATURE_BPF;
			else if (strcmp(*argv, "ipsec") == 0)
				feature = KNOD_FEATURE_IPSEC;
			else
				invarg("feature is none, bpf or ipsec", *argv);
			have_feature = true;
		} else {
			usage();
		}
		argc--;
		argv++;
	}
	if (!have_id || !have_feature)
		usage();

	addattr32(&req.n, KNOD_BUFLEN, KNOD_A_ACCEL_ID, id);
	addattr32(&req.n, KNOD_BUFLEN, KNOD_A_ACCEL_FEATURE_ENA, feature);
	if (rtnl_talk(&genl_rth, &req.n, NULL) < 0)
		return -1;
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
	if (strcmp(*argv, "set") == 0)
		return knod_set(argc - 1, argv + 1);

	fprintf(stderr, "Command \"%s\" is unknown, try \"ip knod help\".\n",
		*argv);
	exit(-1);
}
