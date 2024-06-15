/*
 * Copyright (c) 2023 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "stringlist.h"
#include "externs.h"

int nameserver_usage(void);
int nameserver4_valid(char *);
int nameserver6_valid(char *);
int resolvd_is_disabled(void);

int
nameserver_usage(void)
{
	printf("%% nameserver IP-address1 [IP-address2 ... IP-address5]\n");
	printf("%% no nameserver\n");
	return (0);
}

int
nameserver4_valid(char *addrstr)
{
	struct in_addr addr4;
	int ret;

	ret = inet_pton(AF_INET, addrstr, &addr4);
	if (ret == -1) {
		printf("%% inet_pton: %s", strerror(errno));
		return (0);
	}
	return (ret == 1);
}

int
nameserver6_valid(char *addrstr)
{
	struct in6_addr addr6;
	int ret;

	ret = inet_pton(AF_INET6, addrstr, &addr6);
	if (ret == -1) {
		printf("%% inet_pton: %s", strerror(errno));
		return (0);
	}
	return (ret == 1);
}

int
resolvd_is_disabled(void)
{
	int dbflag = db_select_flag_x_dbflag_rtable("ctl", "resolvd", 0);
	return (dbflag == DB_X_DISABLE_ALWAYS); 
}

int
nameserverset(int argc, char *argv[])
{
	int i, set = 1;

	if (argc < 2)
		return nameserver_usage();

	if (NO_ARG(argv[0])) {
		argv++;
		argc--;
		if (argc != 1)
			return nameserver_usage();
		set = 0;
	} else {
		if (argc > 6)
			return nameserver_usage();

		for (i = 1; i < argc; i++) {
			if (!nameserver4_valid(argv[i]) &&
			    !nameserver6_valid(argv[i])) {
				printf("%% invalid address: %s\n", argv[i]);
				return (1);
			}
		}
	}

	/*
	 * Always clear existing nameservers, even before setting new ones.
	 * resolvd will do likewise when it receives new proposals for lo0.
	 * So this ensures consistency between the nameservers table in our
	 * DB and /etc/resolv.conf.
	 */
	if (db_delete_nameservers() < 0) {
		printf("%% nameservers db deletion error\n");
		return (1);
	}

	if (set) {
		for (i = 1; i < argc; i++) {
			if (db_insert_nameserver(argv[i]) < 0) {
				printf("%% nameservers db insertion error\n");
				return (1);
			}
		}
	}

	argv[0] = "lo0";
	return rtnameserver(argc, argv, 0 /* always use rtable 0 */);
}

void
conf_nameserver(FILE *output)
{
	StringList *nameservers;
	int i;

	nameservers = sl_init();

	if (db_select_nameservers(nameservers) < 0) {
		printf("%% database failure select nameservers\n");
		sl_free(nameservers, 1);
		return;
	}

	if (nameservers->sl_cur > 0) {
		fprintf(output, "nameserver");
		for (i = 0; i < nameservers->sl_cur; i++)
			fprintf(output, " %s", nameservers->sl_str[i]);
		fprintf(output, "\n");
	}

	sl_free(nameservers, 1);
}
