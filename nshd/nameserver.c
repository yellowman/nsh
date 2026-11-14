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
#include "settings.h"
#include "facts.h"
#include "args.h"


/* nameserver: up to NAMESERVERS addresses; "no nameserver" takes none */

int
nameserver_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	struct in_addr ns4[NAMESERVERS];
	struct in6_addr ns6[NAMESERVERS];
	char addr[NAMESERVERS][INET6_ADDRSTRLEN];
	size_t n4 = 0, n6 = 0;
	int i, n;

	for (n = 0; set && n < NAMESERVERS && v[n].type != FACT_NONE; n++)
		if (v[n].v.a.family == FACT_INET) {
			memcpy(&ns4[n4++], v[n].v.a.bytes, sizeof(*ns4));
			inet_ntop(AF_INET, v[n].v.a.bytes, addr[n],
			    sizeof(addr[n]));
		} else {
			memcpy(&ns6[n6++], v[n].v.a.bytes, sizeof(*ns6));
			inet_ntop(AF_INET6, v[n].v.a.bytes, addr[n],
			    sizeof(addr[n]));
		}

	if (cand != NULL) {
		char line[256] = "nameserver";

		for (i = 0; i < n; i++) {
			strlcat(line, " ", sizeof(line));
			strlcat(line, addr[i], sizeof(line));
		}
		return cand_setting(cand, set ? ST_ON : ST_OFF, "%s", line);
	}

	/*
	 * Always clear existing nameservers, even before setting new ones.
	 * resolvd will do likewise when it receives new proposals for lo0.
	 * So this ensures consistency between the nameservers table in our
	 * DB and /etc/resolv.conf.
	 */
	if (db_delete_nameservers() < 0) {
		printf("%% nameservers db deletion error\n");
		return -1;
	}

	for (i = 0; i < n; i++) {
		if (db_insert_nameserver(addr[i]) < 0) {
			printf("%% nameservers db insertion error\n");
			return -1;
		}
	}

	/* "no nameserver" proposes none, whatever addresses it was given */
	if (rtnameserver("lo0", ns4, n4, ns6, n6, 0 /* always rtable 0 */))
		return (-1);
	return (0);
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
