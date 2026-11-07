/* SPDX-License-Identifier: GPL-2.0-or-later */
/* iplink_knod.c	knod device support: a NIC run by a GPU
 *
 * Authors:	Taehee Yoo <ap420073@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>

#include "utils.h"
#include "ip_common.h"

static void print_explain(struct link_util *lu, FILE *f)
{
	fprintf(f,
		"Usage: ... link DEV %s id ID\n"
		"\n"
		"ID: the GPU's knod id\n",
		lu->id);
}

static int knod_parse_opt(struct link_util *lu, int argc, char **argv,
			  struct nlmsghdr *n)
{
	__u32 id;

	while (argc > 0) {
		if (strcmp(*argv, "id") == 0) {
			NEXT_ARG();
			if (get_u32(&id, *argv, 0))
				invarg("invalid id", *argv);
			addattr32(n, 1024, IFLA_KNOD_ID, id);
		} else if (strcmp(*argv, "help") == 0) {
			print_explain(lu, stderr);
			return -1;
		} else {
			fprintf(stderr, "%s: unknown option \"%s\"?\n",
				lu->id, *argv);
			print_explain(lu, stderr);
			return -1;
		}
		argc--;
		argv++;
	}
	return 0;
}

static void knod_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	if (!tb)
		return;
	if (tb[IFLA_KNOD_ID])
		print_uint(PRINT_ANY, "id", "id %u ",
			   rta_getattr_u32(tb[IFLA_KNOD_ID]));
}

static void knod_print_help(struct link_util *lu, int argc, char **argv,
			    FILE *f)
{
	print_explain(lu, f);
}

struct link_util knod_link_util = {
	.id		= "knod",
	.maxattr	= IFLA_KNOD_MAX,
	.parse_opt	= knod_parse_opt,
	.print_opt	= knod_print_opt,
	.print_help	= knod_print_help,
};
