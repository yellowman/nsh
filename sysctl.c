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
#include <net/pipex.h>
#include <netinet/in.h>
#include <netinet/ip_ether.h>
#include <netinet/ip_ipip.h>
#include <netinet/ip_gre.h>
#include <netinet/ip_ipcomp.h>
#include <netinet/ip_esp.h>
#include <netinet/ip_ah.h>
#include <netinet/ip_carp.h>
#include <netmpls/mpls.h>
#include <ddb/db_var.h>
#include "externs.h"
#include "sysctl.h"

#define	MIB_STOP	INT_MAX

#define IFQ_MAXLEN	256

void conf_sysctl(FILE *, char *, struct ipsysctl *);

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
		if (read && errno != ENOPROTOOPT) {
			printf("%% sysctl_int: sysctl: %s\n", strerror(errno));
			for (i = 0; i < 6; i++) {
				printf("%% mib[%i] == %i\n",i,mib[i]);
		                if (mib[i] == MIB_STOP)
					break;
			}
		}
		return(-1);
	}

	return(old);
}

struct sysctltab sysctls[] = {
	{ "ip",		PF_INET,	iptab,		ipsysctls },
	{ "ip6",	PF_INET6,	ip6tab,		ip6sysctls },
	{ "mpls",	PF_MPLS,	mplstab,	mplssysctls },
	{ "ddb",	PF_DECnet,	ddbtab,		ddbsysctls },
	{ "pipex",	PF_PIPEX,	pipextab,	pipexsysctls },
	{ 0,		0,		0,		0 }
};

struct ipsysctl ipsysctls[] = {
{ "carp",		{ CTL_NET, PF_INET, IPPROTO_CARP, CARPCTL_ALLOW, MIB_STOP, 0 },		0, 0    },
{ "carp-log",		{ CTL_NET, PF_INET, IPPROTO_CARP, CARPCTL_LOG, MIB_STOP, 0 },		2, 0	},
{ "carp-preempt",	{ CTL_NET, PF_INET, IPPROTO_CARP, CARPCTL_PREEMPT, MIB_STOP, 0 },	0, 1    },
{ "forwarding",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_FORWARDING, MIB_STOP, 0 },	0, 2	},
{ "mforwarding",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_MFORWARDING, MIB_STOP, 0 },	0, 1,   },
{ "ipip",		{ CTL_NET, PF_INET, IPPROTO_IPIP, IPIPCTL_ALLOW, MIB_STOP, 0 },		0, 1	},
{ "gre",		{ CTL_NET, PF_INET, IPPROTO_GRE, GRECTL_ALLOW, MIB_STOP, 0 },		0, 1	},
{ "wccp",		{ CTL_NET, PF_INET, IPPROTO_GRE, GRECTL_WCCP, MIB_STOP, 0 },		0, 1	},
{ "mobileip",		{ CTL_NET, PF_INET, IPPROTO_MOBILE, MOBILEIPCTL_ALLOW, MIB_STOP, 0 },	0, 1	},
{ "etherip",		{ CTL_NET, PF_INET, IPPROTO_ETHERIP,ETHERIPCTL_ALLOW, MIB_STOP, 0 },	0, 1	},
{ "ipcomp",		{ CTL_NET, PF_INET, IPPROTO_IPCOMP, IPCOMPCTL_ENABLE, MIB_STOP, 0 },	0, 1	},
{ "esp",		{ CTL_NET, PF_INET, IPPROTO_ESP, ESPCTL_ENABLE, MIB_STOP, 0 },		0, 0	},
{ "esp-udpencap",	{ CTL_NET, PF_INET, IPPROTO_ESP, ESPCTL_UDPENCAP_ENABLE, MIB_STOP, 0 },	0, 0	},
{ "esp-udpencap-port",	{ CTL_NET, PF_INET, IPPROTO_ESP, ESPCTL_UDPENCAP_PORT, MIB_STOP, 0 },	ESP_UDPENCAP_PORT, 0 },
{ "ah",			{ CTL_NET, PF_INET, IPPROTO_AH,	AHCTL_ENABLE, MIB_STOP, 0 },		0, 0	},
{ "sourceroute",	{ CTL_NET, PF_INET, IPPROTO_IP,	IPCTL_SOURCEROUTE, MIB_STOP, 0 },	0, 1	},
{ "encdebug",		{ CTL_NET, PF_INET, IPPROTO_IP,	IPCTL_ENCDEBUG, MIB_STOP, 0 },		0, 1	},
{ "ifq-maxlen",		{ CTL_NET, PF_INET, IPPROTO_IP,	IPCTL_IFQUEUE, IFQCTL_MAXLEN, MIB_STOP }, IFQ_MAXLEN, 0 },
{ "send-redirects",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_SENDREDIRECTS, MIB_STOP, 0 },	0, 0	},
{ "directed-broadcast",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_DIRECTEDBCAST, MIB_STOP, 0 },	0, 1	},
{ "multipath",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_MULTIPATH, MIB_STOP, 0 },		0, 1	},
#ifdef notyet
{ "default-mtu",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_DEFMTU, MIB_STOP, 0 },		DEFAULT_MTU, 0 },
#endif
{ "default-ttl",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_DEFTTL, MIB_STOP, 0 },		DEFAULT_TTL, 0 },
{ 0, { 0, 0, 0, 0, 0, 0 }, 0, 0	}
};

struct ipsysctl ip6sysctls[] = {
{ "forwarding",		{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_FORWARDING, MIB_STOP, 0 },	0, 1    },
{ "multipath",		{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MULTIPATH, MIB_STOP, 0 },	0, 1	},
{ "mforwarding",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MFORWARDING, MIB_STOP, 0 },	0, 1	},
{ "v6only",		{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_V6ONLY, MIB_STOP, 0 },	0, 0	},
{ "maxifprefixes",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MAXIFPREFIXES, MIB_STOP, 0 }, DEFAULT_MAXIFPREFIXES, 0	},
{ "maxifdefrouters",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MAXIFDEFROUTERS, MIB_STOP, 0 }, DEFAULT_MAXIFDEFROUTERS, 0 },
{ "maxdynroutes", 	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MAXDYNROUTES, MIB_STOP, 0 },	DEFAULT_MAXDYNROUTES, 0 },
{ 0, { 0, 0, 0, 0, 0, 0 }, 0, 0 }
};

struct ipsysctl mplssysctls[] = {
{ "ttl",		{ CTL_NET, PF_MPLS, MPLSCTL_DEFTTL, MIB_STOP, 0 },			DEFAULT_MTTL, 0	},
{ "mapttl-ip",		{ CTL_NET, PF_MPLS, MPLSCTL_MAPTTL_IP, MIB_STOP, 0 },			0, 0	},
{ "mapttl-ip6",		{ CTL_NET, PF_MPLS, MPLSCTL_MAPTTL_IP6, MIB_STOP, 0 },			0, 1	},
{ 0, { 0, 0, 0, 0, 0, 0 }, 0, 0 }
};

struct ipsysctl ddbsysctls[] = {
{ "panic",		{ CTL_DDB, DBCTL_PANIC, MIB_STOP, 0 },					0, 0	},
{ "console",		{ CTL_DDB, DBCTL_CONSOLE, MIB_STOP, 0 },				0, 1	},
{ "log",		{ CTL_DDB, DBCTL_LOG, MIB_STOP, 0 },					0, 0	},
{ 0, { 0, 0, 0, 0, 0, 0 }, 0, 0 }
};

struct ipsysctl pipexsysctls[] = {
{ "enable",		{ CTL_NET, PF_PIPEX, PIPEXCTL_ENABLE, MIB_STOP, 0 },			0, 1	},
{ 0, { 0, 0, 0, 0, 0, 0 }, 0, 0 }
};

int
ipsysctl(int set, char *cmd, char *arg, int type)
{
	int32_t larg;
	const char *errmsg = NULL;
	struct ipsysctl *x;
	struct sysctltab *stab;

	for (stab = sysctls; stab-> name != NULL; stab++)
		if(stab->pf == type)
			break;
	if (stab->pf != type) {
		printf("%% table lookup failed (%d)\n", type);
		return 0;
	}

	x = (struct ipsysctl *) genget(cmd, (char **)stab->sysctl,
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
conf_sysctls(FILE *output)
{
	struct sysctltab *stab;

	for (stab = sysctls; stab->name != 0; stab++)
		conf_sysctl(output, stab->name, stab->sysctl);
}

void
conf_sysctl(FILE *output, char *prefix, struct ipsysctl *x)
{
	int tmp = 0;

	for (; x != NULL && x->name != NULL; tmp = 0, x++) {
		if (x->def_larg) {	/* this sysctl takes a value */
			tmp = sysctl_int(x->mib, 0, 1);
			if (tmp == x->def_larg || tmp == -1)
				continue;
			fprintf(output, "%s %s %i\n", prefix, x->name, tmp);
			continue;
		}
		switch(x->enable) {	/* on/off */
		case 0:	/* default is enabled */
			if (sysctl_int(x->mib, 0, 1) == 0)
				fprintf(output, "no %s %s\n", prefix, x->name);
			break;
		case 1: /* default is not enabled */
			if (sysctl_int(x->mib, 0, 1) == 1)
				fprintf(output, "%s %s\n", prefix, x->name);
			break;
		case 2: /* show either way */
			if ((tmp = sysctl_int(x->mib, 0, 1)) == 1)
				fprintf(output, "%s %s\n", prefix, x->name);
			else if (tmp == 0)
				fprintf(output, "no %s %s\n", prefix, x->name);
			break;
		}
	}
}
