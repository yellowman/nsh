/* $nsh: sysctl.c,v 1.10 2008/02/06 22:48:53 chris Exp $ */
/*
 * Copyright (c) 2003 Chris Cappuccio <chris@nmedia.net>
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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_ether.h>
#include <netinet/ip_ipip.h>
#include <netinet/ip_gre.h>
#include <netinet/ip_ipcomp.h>
#include <netinet/ip_esp.h>
#include <netinet/ip_ah.h>
#include "externs.h"

/*
 * sysctl_inet: get or set an int value from PF_INET tree
 *
 * val - value to set in sysctl
 * read - are we just reading the value (1), or setting it? (0)
 */

int
sysctl_inet(int mib2, int mib3, int val, int read)
{
	int mib[4], old;
	int *valp;
	size_t len;

	if (read)
		valp = NULL;
	else
		valp = &val;

	mib[0] = CTL_NET;
	mib[1] = PF_INET;
	mib[2] = mib2;
	mib[3] = mib3;

	len = sizeof(old);

	if (sysctl(mib, 4, &old, &len, valp, sizeof(int)) == -1) {
		if (read && errno != ENOPROTOOPT)
			printf("%% sysctl_inet: sysctl: %s\n", strerror(errno));
		return(-1);
	}

	return(old);
}

static struct ipsysctl {
	char *name;
	int mib2;
	int mib3;
	int32_t def_larg;
} ipsysctls[] = {
	{ "forwarding",	IPPROTO_IP,	IPCTL_FORWARDING,	0	},
	{ "ipip",	IPPROTO_IPIP,	IPIPCTL_ALLOW,		0	},
	{ "gre",	IPPROTO_GRE,	GRECTL_ALLOW,		0	},
	{ "wccp",	IPPROTO_GRE,	GRECTL_WCCP,		0	},
	{ "mobileip",	IPPROTO_MOBILE,	MOBILEIPCTL_ALLOW,	0	},
	{ "etherip",	IPPROTO_ETHERIP,ETHERIPCTL_ALLOW,	0	},
	{ "ipcomp",	IPPROTO_IPCOMP,	IPCOMPCTL_ENABLE,	0	},
	{ "esp",	IPPROTO_ESP,	ESPCTL_ENABLE,		0	},
	{ "ah",		IPPROTO_AH,	AHCTL_ENABLE,		0	},
	{ "sourceroute",IPPROTO_IP,	IPCTL_SOURCEROUTE,	0	},
	{ "encdebug",	IPPROTO_IP,	IPCTL_ENCDEBUG,		0	},
	{ "maxqueue",	IPPROTO_IP,	IPCTL_IPPORT_MAXQUEUE,	DEFAULT_MAXQUEUE },
	{ "send-redirects",IPPROTO_IP,	IPCTL_SENDREDIRECTS,	0	},
	{ "directed-broadcast",IPPROTO_IP, IPCTL_DIRECTEDBCAST,	0	},
#ifdef notyet
	{ "default-mtu",IPPROTO_IP,	IPCTL_DEFMTU,		DEFAULT_MTU },
#endif
	{ "default-ttl",IPPROTO_IP,	IPCTL_DEFTTL,		DEFAULT_TTL },
	{ 0,		0,		0,			0 }
};

int
ipsysctl(int set, char *cmd, char *arg)
{
	int32_t larg;
	const char *errmsg = NULL;
	struct ipsysctl *x;

	x = (struct ipsysctl *) genget(cmd, (char **)ipsysctls,
	    sizeof(struct ipsysctl));
	if (x == 0) {
		printf("%% Invalid argument %s\n", cmd);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", cmd);
		return 0;
	}

	if (arg) {
		larg = strtonum(arg, 0, INT_MAX, &errmsg);
		if (errmsg) {
			printf("%% Invalid argument %s: %s\n", arg, errmsg);
			return(0);
		}
	} else if (set)
		larg = 1;
	else
		larg = x->def_larg;

	sysctl_inet(x->mib2, x->mib3, larg, 0);

	return(1);
}

void
conf_ipsysctl(FILE *output)
{
	int tmp;

	if ((tmp = sysctl_inet(IPPROTO_IP, IPCTL_FORWARDING, 0, 1)) == 1)
		fprintf(output, "ip forwarding\n");
	else if (tmp == 0)
		fprintf(output, "no ip forwarding\n");
	if (sysctl_inet(IPPROTO_IPIP, IPIPCTL_ALLOW, 0, 1) == 1)
		fprintf(output, "ip ipip\n");
	if (sysctl_inet(IPPROTO_GRE, GRECTL_ALLOW, 0, 1) == 1)
		fprintf(output, "ip gre\n");
	if (sysctl_inet(IPPROTO_GRE, GRECTL_WCCP, 0, 1) == 1)
		fprintf(output, "ip wccp\n");
	if (sysctl_inet(IPPROTO_MOBILE, MOBILEIPCTL_ALLOW, 0, 1) == 1)
		fprintf(output, "ip mobileip\n");
	if (sysctl_inet(IPPROTO_ETHERIP, ETHERIPCTL_ALLOW, 0, 1) == 1)
		fprintf(output, "ip etherip\n");
	if (sysctl_inet(IPPROTO_IPCOMP, IPCOMPCTL_ENABLE, 0, 1) == 1)
		fprintf(output, "ip ipcomp\n");
	if (sysctl_inet(IPPROTO_ESP, ESPCTL_ENABLE, 0, 1) == 0)
		fprintf(output, "no ip esp\n");
	if (sysctl_inet(IPPROTO_AH, AHCTL_ENABLE, 0, 1) == 0)
		fprintf(output, "no ip ah\n");
	if (sysctl_inet(IPPROTO_IP, IPCTL_SOURCEROUTE, 0, 1) == 1)
		fprintf(output, "ip sourceroute\n");
	/*
	 * Your kernel must have option ENCDEBUG for this to do anything
	 */
	if (sysctl_inet(IPPROTO_IP, IPCTL_ENCDEBUG, 0, 1) == 1)
		fprintf(output, "ip encdebug\n");
	if ((tmp = sysctl_inet(IPPROTO_IP, IPCTL_IPPORT_MAXQUEUE, 0, 1)) !=
	    DEFAULT_MAXQUEUE && tmp != -1)
		fprintf(output, "ip maxqueue %i\n", tmp);
	if (sysctl_inet(IPPROTO_IP, IPCTL_SENDREDIRECTS, 0, 1) == 0)
		fprintf(output, "no ip send-redirects\n");
	if (sysctl_inet(IPPROTO_IP, IPCTL_DIRECTEDBCAST, 0, 1) == 1)
		fprintf(output, "ip directed-broadcast\n");
#ifdef notyet
	if ((tmp = sysctl_inet(IPPROTO_IP, IPCTL_DEFMTU, 0, 1)) !=
	    DEFAULT_MTU && tmp != -1)
		fprintf(output, "ip default-mtu %i\n", tmp);
#endif
	if ((tmp = sysctl_inet(IPPROTO_IP, IPCTL_DEFTTL, 0, 1)) !=
	    DEFAULT_TTL && tmp != -1)
		fprintf(output, "ip default-ttl %i\n", tmp);
}
