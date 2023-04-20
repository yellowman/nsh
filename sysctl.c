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

#define	DEFAULT_ARPTIMEOUT		1200	/* net.inet.ip.arptimeout */
#define	DEFAULT_ARPDOWN			20	/* net.inet.ip.arpdown */
#define	DEFAULT_TTL			64	/* net.inet.ip.defttl */
#define	DEFAULT_MTTL			255	/* net.mpls.ttl */
#define	ESP_UDPENCAP_PORT		4500	/* net.inet.esp.udpencap_port */
#define	DEFAULT_MAXQUEUE		300	/* net.inet.ip.maxqueue */
#define	DEFAULT_MTUDISCTIMEOUT		600	/* net.inet.ip.mtudisctimeout */
#define	DEFAULT_IPSEC_TIMEOUT		86400	/* net.inet.ip.ipsec-timeout */
#define	DEFAULT_IPSEC_SOFT_TIMEOUT	80000	/* net.inet.ip.ipsec-soft-timeout */
#define	DEFAULT_IPSEC_EXPIRE_ACQUIRE	30	/* net.inet.ip.ipsec-expire-acquire */
#define	DEFAULT_IPSEC_FIRSTUSE		7200	/* net.inet.ip.ipsec-firstuse */
#define	DEFAULT_IPSEC_SOFT_FIRSTUSE	3600	/* net.inet.ip.ipsec-soft-firstuse */
#define	DEFAULT_IPSEC_INVALID_LIFE	60	/* net.inet.ip.ipsec-invalid-life */
#define	DEFAULT_MAXFRAGPACKETS		200	/* net.inet6.ip6.maxfragpackets */
#define	DEFAULT_MAXFRAGS		200	/* net.inet6.ip6.maxfrags */
#define	DEFAULT_PORTFIRST		1024	/* net.inet.ip.portfirst */
#define	DEFAULT_PORTLAST		49151	/* net.inet.ip.portlast */
#define	DEFAULT_PORTHIFIRST		49152	/* net.inet.ip.porthifirst */
#define	DEFAULT_PORTHILAST		65535	/* net.inet.ip.porthilast */

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
		if (!read) {
			printf("%% sysctl_int: sysctl: %s\n", strerror(errno));
		} else if (errno != ENOPROTOOPT) {
			printf("%% sysctl_int: sysctl: %s\n", strerror(errno));
			for (i = 0; i < 6; i++) {
		                if (mib[i] == MIB_STOP)
					break;
				printf("%% mib[%i] == %i\n",i,mib[i]);
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
{ "etherip",		{ CTL_NET, PF_INET, IPPROTO_ETHERIP,ETHERIPCTL_ALLOW, MIB_STOP, 0 },	0, 1	},
{ "ipcomp",		{ CTL_NET, PF_INET, IPPROTO_IPCOMP, IPCOMPCTL_ENABLE, MIB_STOP, 0 },	0, 1	},
{ "esp",		{ CTL_NET, PF_INET, IPPROTO_ESP, ESPCTL_ENABLE, MIB_STOP, 0 },		0, 1	},
{ "esp-udpencap",	{ CTL_NET, PF_INET, IPPROTO_ESP, ESPCTL_UDPENCAP_ENABLE, MIB_STOP, 0 },	0, 0	},
{ "esp-udpencap-port",	{ CTL_NET, PF_INET, IPPROTO_ESP, ESPCTL_UDPENCAP_PORT, MIB_STOP, 0 },	ESP_UDPENCAP_PORT, 0 },
{ "ah",			{ CTL_NET, PF_INET, IPPROTO_AH,	AHCTL_ENABLE, MIB_STOP, 0 },		0, 0	},
{ "sourceroute",	{ CTL_NET, PF_INET, IPPROTO_IP,	IPCTL_SOURCEROUTE, MIB_STOP, 0 },	0, 1	},
{ "encdebug",		{ CTL_NET, PF_INET, IPPROTO_IP,	IPCTL_ENCDEBUG, MIB_STOP, 0 },		0, 1	},
{ "send-redirects",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_SENDREDIRECTS, MIB_STOP, 0 },	0, 0	},
{ "directed-broadcast",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_DIRECTEDBCAST, MIB_STOP, 0 },	0, 1	},
{ "multipath",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_MULTIPATH, MIB_STOP, 0 },		0, 1	},
{ "arptimeout",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_ARPTIMEOUT, MIB_STOP, 0 },        DEFAULT_ARPTIMEOUT, 0 },
{ "arpdown",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_ARPDOWN, MIB_STOP, 0 },           DEFAULT_ARPDOWN, 0 },
{ "maxqueue",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPPORT_MAXQUEUE, MIB_STOP, 0 },	0, 1	},
{ "mtudisc",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_MTUDISC, MIB_STOP, 0 },		0, 0	},
{ "mtudisctimeout",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_MTUDISCTIMEOUT, MIB_STOP, 0},	DEFAULT_MTUDISCTIMEOUT, 0	},
{ "ipsec-timeout",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_TIMEOUT, MIB_STOP, 0},	DEFAULT_IPSEC_TIMEOUT, 0	},
{ "ipsec-soft-timeout",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_SOFT_TIMEOUT, MIB_STOP, 0},	DEFAULT_IPSEC_SOFT_TIMEOUT, 0	},
{ "ipsec-allocs",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_ALLOCATIONS, MIB_STOP, 0},	0, 1	},
{ "ipsec-soft-allocs",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_SOFT_ALLOCATIONS, MIB_STOP, 0}, 0, 1},
{ "ipsec-bytes",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_BYTES, MIB_STOP, 0},	0, 1	},
{ "ipsec-soft-bytes",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_SOFT_BYTES, MIB_STOP, 0},	0, 1	},
{ "ipsec-expire-acquire", { CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_EXPIRE_ACQUIRE, MIB_STOP, 0}, DEFAULT_IPSEC_EXPIRE_ACQUIRE, 0 },
{ "ipsec-firstuse",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_FIRSTUSE, MIB_STOP, 0}, DEFAULT_IPSEC_FIRSTUSE, 0 },
{ "ipsec-soft-firstuse",{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_SOFT_FIRSTUSE, MIB_STOP, 0}, DEFAULT_IPSEC_SOFT_FIRSTUSE, 0 },
{ "ipsec-invalid-life",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_EMBRYONIC_SA_TIMEOUT, MIB_STOP, 0}, DEFAULT_IPSEC_INVALID_LIFE, 0 },
{ "ipsec-pfs",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_REQUIRE_PFS, MIB_STOP, 0 },	1, 0 },
{ "portfirst",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPPORT_FIRSTAUTO, MIB_STOP, 0 },	DEFAULT_PORTFIRST, 0 },
{ "portlast",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPPORT_LASTAUTO, MIB_STOP, 0 },   DEFAULT_PORTLAST, 0 },
{ "porthifirst",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPPORT_HIFIRSTAUTO, MIB_STOP, 0 }, DEFAULT_PORTHIFIRST, 0 },
{ "porthilast",		{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPPORT_HILASTAUTO, MIB_STOP, 0 },	DEFAULT_PORTHILAST, 0 },
{ "default-ttl",	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_DEFTTL, MIB_STOP, 0 },		DEFAULT_TTL, 0 },
{ 0, { 0, 0, 0, 0, 0, 0 }, 0, 0	}
};

struct ipsysctl ip6sysctls[] = {
{ "forwarding",		{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_FORWARDING, MIB_STOP, 0 },	0, 1    },
{ "multipath",		{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MULTIPATH, MIB_STOP, 0 },	0, 1	},
{ "mforwarding",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MFORWARDING, MIB_STOP, 0 },	0, 1	},
{ "maxdynroutes", 	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MAXDYNROUTES, MIB_STOP, 0 },	DEFAULT_MAXDYNROUTES, 0 },
{ "send-redirect",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_SENDREDIRECTS, MIB_STOP, 0 },0, 0	},
{ "hoplimit",		{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_DEFHLIM, MIB_STOP, 0},	0, 1	},
{ "defmcasthlim",       { CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_DEFMCASTHLIM, MIB_STOP, 0},	1, 0	},
{ "maxfragpackets",     { CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MAXFRAGPACKETS, MIB_STOP, 0}, DEFAULT_MAXFRAGPACKETS, 0 },
{ "maxfrags",   	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MAXFRAGS, MIB_STOP, 0}, DEFAULT_MAXFRAGS, 0 },
{ "mtudisctimeout",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MTUDISCTIMEOUT, MIB_STOP, 0}, 0, 1  },
{ "multicast_mtudisc",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_MCAST_PMTU, MIB_STOP, 0}, 0, 1  },
{ "log_interval",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_LOG_INTERVAL, MIB_STOP, 0}, 0, 1  },
{ "auto_flowlabel",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_AUTO_FLOWLABEL, MIB_STOP, 0}, 0, 0  },
{ "neighborgcthresh",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_NEIGHBORGCTHRESH, MIB_STOP, 0 }, DEFAULT_NEIGHBORGCTHRESH , 0 },
{ "hdrnestlimit",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_HDRNESTLIMIT, MIB_STOP, 0 }, 0, 1  },
{ "dad_count",		{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_DAD_COUNT, MIB_STOP, 0}, 0, 0  },
{ "dad_pending",	{ CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_DAD_PENDING, MIB_STOP, 0}, 0, 1  },
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

	for (; x != NULL && x->name != NULL; x++) {
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
