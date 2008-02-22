/* $nsh: sysctl.c,v 1.11 2008/02/22 01:08:41 chris Exp $ */
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
	int enable;
} ipsysctls[] = {
	{ "forwarding",	IPPROTO_IP,	IPCTL_FORWARDING,	0, 2	},
	{ "ipip",	IPPROTO_IPIP,	IPIPCTL_ALLOW,		0, 1	},
	{ "gre",	IPPROTO_GRE,	GRECTL_ALLOW,		0, 1	},
	{ "wccp",	IPPROTO_GRE,	GRECTL_WCCP,		0, 1	},
	{ "mobileip",	IPPROTO_MOBILE,	MOBILEIPCTL_ALLOW,	0, 1	},
	{ "etherip",	IPPROTO_ETHERIP,ETHERIPCTL_ALLOW,	0, 1	},
	{ "ipcomp",	IPPROTO_IPCOMP,	IPCOMPCTL_ENABLE,	0, 1	},
	{ "esp",	IPPROTO_ESP,	ESPCTL_ENABLE,		0, 0	},
	{ "ah",		IPPROTO_AH,	AHCTL_ENABLE,		0, 0	},
	{ "sourceroute",IPPROTO_IP,	IPCTL_SOURCEROUTE,	0, 1	},
	{ "encdebug",	IPPROTO_IP,	IPCTL_ENCDEBUG,		0, 1	},
	{ "maxqueue",	IPPROTO_IP,	IPCTL_IPPORT_MAXQUEUE,	DEFAULT_MAXQUEUE, 1 },
	{ "send-redirects",IPPROTO_IP,	IPCTL_SENDREDIRECTS,	0, 0	},
	{ "directed-broadcast",IPPROTO_IP, IPCTL_DIRECTEDBCAST,	0, 1	},
#ifdef notyet
	{ "default-mtu",IPPROTO_IP,	IPCTL_DEFMTU,		DEFAULT_MTU, 1 },
#endif
	{ "default-ttl",IPPROTO_IP,	IPCTL_DEFTTL,		DEFAULT_TTL, 1 },
	{ 0,		0,		0,			0, 0	}
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

	if (set) {
		if (arg) {
			larg = strtonum(arg, 0, INT_MAX, &errmsg);
			if (errmsg) {
				printf("%% Invalid argument %s: %s\n", arg,
				    errmsg);
				return(0);
			}
		} else
			larg = 1;
	} else
		larg = x->def_larg;

	sysctl_inet(x->mib2, x->mib3, larg, 0);

	return(1);
}

void
conf_ipsysctl(FILE *output)
{
	int tmp = 0;
	struct ipsysctl *x;

	for (x = &ipsysctls[0]; x->name != NULL; tmp = 0, x++) {
		if (x->def_larg) {	/* this sysctl takes a value */
			tmp = sysctl_inet(x->mib2, x->mib3, 0, 1);
			if (tmp == x->def_larg || tmp == -1)
				continue;
			fprintf(output, "ip %s %i\n", x->name, tmp);
			continue;
		}
		switch(x->enable) {	/* on/off */
		case 0:	/* default is enabled */
			if (sysctl_inet(x->mib2, x->mib3, 0, 1) == 0)
				fprintf(output, "no ip %s\n", x->name);
			break;
		case 1: /* default is not enabled */
			if (sysctl_inet(x->mib2, x->mib3, 0, 1) == 1)
				fprintf(output, "ip %s\n", x->name);
			break;
		case 2: /* show either way */
			if ((tmp = sysctl_inet(x->mib2, x->mib3, 0, 1)) == 1)
				fprintf(output, "ip %s\n", x->name);
			else if (tmp == 0)
				fprintf(output, "no ip %s\n", x->name);
			break;
		}
	}
}
