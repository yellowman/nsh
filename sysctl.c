/* $nsh: sysctl.c,v 1.14 2009/03/25 16:09:04 chris Exp $ */
/*
 * Copyright (c) 2003-2009 Chris Cappuccio <chris@nmedia.net>
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
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_ether.h>
#include <netinet/ip_ipip.h>
#include <netinet/ip_gre.h>
#include <netinet/ip_ipcomp.h>
#include <netinet/ip_esp.h>
#include <netinet/ip_ah.h>
#include <netinet/ip_carp.h>
#include "externs.h"

#define	MIB_STOP	INT_MAX

/*
 * sysctl_int: get or set an int value
 *
 * val - value to set in sysctl
 * read - are we just reading the value (1), or setting it? (0)
 */

int
sysctl_int(int mib[], int val, int read)
{
	int i, old, *valp;
	size_t len;

	if (read)
		valp = NULL;
	else
		valp = &val;

	len = sizeof(old);

	for (i = 0; i < 6; i++)
		if (mib[i] == MIB_STOP)
			break;

	if (sysctl(mib, i, &old, &len, valp, sizeof(int)) == -1) {
		if (read && errno != ENOPROTOOPT)
			printf("%% sysctl_int: sysctl: %s\n", strerror(errno));
		return(-1);
	}

	return(old);
}

static struct ipsysctl {
	char *name;
	int mib[6];
	int32_t def_larg;	/* default value, or 0 for on/off sysctls */
	int enable;		/* if on/off sysctl, 0 disable by default, 1 enable by default, 2 always show enable or disable */
} ipsysctls[] = {
	{ "carp",		{ CTL_NET, PF_INET, IPPROTO_CARP, CARPCTL_ALLOW, MIB_STOP, 0 },			0, 0    },
	{ "carp-log",		{ CTL_NET, PF_INET, IPPROTO_CARP, CARPCTL_LOG, MIB_STOP, 0 },			2, 0	},
	{ "carp-preempt",	{ CTL_NET, PF_INET, IPPROTO_CARP, CARPCTL_PREEMPT, MIB_STOP, 0 },		0, 1    },
	{ "forwarding",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_FORWARDING, MIB_STOP, 0 },		0, 2	},
	{ "ipip",		{ CTL_NET, PF_INET, IPPROTO_IPIP, IPIPCTL_ALLOW, MIB_STOP, 0 },			0, 1	},
	{ "gre",		{ CTL_NET, PF_INET, IPPROTO_GRE, GRECTL_ALLOW, MIB_STOP, 0 },			0, 1	},
	{ "wccp",		{ CTL_NET, PF_INET, IPPROTO_GRE, GRECTL_WCCP, MIB_STOP, 0 },			0, 1	},
	{ "mobileip",		{ CTL_NET, PF_INET, IPPROTO_MOBILE, MOBILEIPCTL_ALLOW, MIB_STOP, 0 },		0, 1	},
	{ "etherip",		{ CTL_NET, PF_INET, IPPROTO_ETHERIP,ETHERIPCTL_ALLOW, MIB_STOP, 0 },		0, 1	},
	{ "ipcomp",		{ CTL_NET, PF_INET, IPPROTO_IPCOMP, IPCOMPCTL_ENABLE, MIB_STOP, 0 },		0, 1	},
	{ "esp",		{ CTL_NET, PF_INET, IPPROTO_ESP, ESPCTL_ENABLE, MIB_STOP, 0 },			0, 0	},
	{ "esp-udpencap",	{ CTL_NET, PF_INET, IPPROTO_ESP, ESPCTL_UDPENCAP_ENABLE, MIB_STOP, 0 },		0, 0	},
	{ "esp-udpencap-port",	{ CTL_NET, PF_INET, IPPROTO_ESP, ESPCTL_UDPENCAP_PORT, MIB_STOP, 0 },		ESP_UDPENCAP_PORT, 0 },
	{ "ah",			{ CTL_NET, PF_INET, IPPROTO_AH,	AHCTL_ENABLE, MIB_STOP, 0 },			0, 0	},
	{ "sourceroute",	{ CTL_NET, PF_INET, IPPROTO_IP,	IPCTL_SOURCEROUTE, MIB_STOP, 0 },		0, 1	},
	{ "encdebug",		{ CTL_NET, PF_INET, IPPROTO_IP,	IPCTL_ENCDEBUG, MIB_STOP, 0 },			0, 1	},
	{ "ifq-maxlen",		{ CTL_NET, PF_INET, IPPROTO_IP,	IPCTL_IFQUEUE, IFQCTL_MAXLEN, MIB_STOP },	IFQ_MAXLEN, 0 },
	{ "send-redirects",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_SENDREDIRECTS, MIB_STOP, 0 },		0, 0	},
	{ "directed-broadcast",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_DIRECTEDBCAST, MIB_STOP, 0 },		0, 1	},
	{ "multipath",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_MULTIPATH, MIB_STOP, 0 },			0, 1	},
#ifdef notyet
	{ "default-mtu",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_DEFMTU, MIB_STOP, 0 },			DEFAULT_MTU, 0 },
#endif
	{ "default-ttl",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_DEFTTL, MIB_STOP, 0 },			DEFAULT_TTL, 0 },
	{ 0, { 0, 0, 0, 0, 0, 0 }, 0, 0	}
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

	sysctl_int(x->mib, larg, 0);

	return(1);
}

void
conf_ipsysctl(FILE *output)
{
	int tmp = 0;
	struct ipsysctl *x;

	for (x = &ipsysctls[0]; x->name != NULL; tmp = 0, x++) {
		if (x->def_larg) {	/* this sysctl takes a value */
			tmp = sysctl_int(x->mib, 0, 1);
			if (tmp == x->def_larg || tmp == -1)
				continue;
			fprintf(output, "ip %s %i\n", x->name, tmp);
			continue;
		}
		switch(x->enable) {	/* on/off */
		case 0:	/* default is enabled */
			if (sysctl_int(x->mib, 0, 1) == 0)
				fprintf(output, "no ip %s\n", x->name);
			break;
		case 1: /* default is not enabled */
			if (sysctl_int(x->mib, 0, 1) == 1)
				fprintf(output, "ip %s\n", x->name);
			break;
		case 2: /* show either way */
			if ((tmp = sysctl_int(x->mib, 0, 1)) == 1)
				fprintf(output, "ip %s\n", x->name);
			else if (tmp == 0)
				fprintf(output, "no ip %s\n", x->name);
			break;
		}
	}
}
