/* From: $OpenBSD: /usr/src/sbin/route/show.c,v 1.61 2007/09/05 20:30:21 claudio Exp $	*/
/*
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* From: $OpenBSD: /usr/src/sbin/route/route.c,v 1.43 2001/07/07 18:26:20 deraadt Exp $ */
/*
 * Copyright (c) 1983, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* From: $OpenBSD: /usr/src/usr.sbin/arp/arp.c,v 1.63 2015/01/16 06:40:15 deraadt Exp $ */
/*
 * Copyright (c) 1984, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Sun Microsystems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (C) 1995, 1996, 1997, 1998, and 1999 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright (c) 1984, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Sun Microsystems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Based on:
 * "@(#) Copyright (c) 1984, 1993\n\
 *	The Regents of the University of California.  All rights reserved.\n";
 *
 * "@(#)arp.c	8.2 (Berkeley) 1/2/94";
 */

/*
 * How nsh prints the facts of routing: routes, a route lookup, IPsec
 * flows, and the ARP and NDP tables. The kinds of these records are
 * defined here too.
 */

#include <sys/param.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/pfkeyv2.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip_ipsp.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ctype.h>
#include <paths.h>
#include <sys/file.h>
#include <sys/time.h>
#include <net/bpf.h>
#include <limits.h>
#include <ifaddrs.h>
#include <sys/queue.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include "externs.h"
#include "facts.h"
#include "showfacts.h"

/* 
 * column widths; each followed by one space
 * width of destination/gateway column
 * strlen("fe80::aaaa:bbbb:cccc:dddd@gif0") == 30, strlen("/128") == 4
 */
#define	WID_DST(af)	((af) == AF_INET6 ? 34 : 18)
#define	WID_GW(af)	((af) == AF_INET6 ? 30 : 18)
#include "ip.h"
#include "settings.h"

char	*any_ntoa(const struct sockaddr *);
char	*link_print(struct sockaddr *);

/*
 * Definitions for showing gateway flags.
 */
struct bits {
	int	b_mask;
	char	b_val;
};
static const struct bits bits[] = {
	{ RTF_UP,	'U' },
	{ RTF_GATEWAY,	'G' },
	{ RTF_HOST,	'H' },
	{ RTF_REJECT,	'R' },
	{ RTF_BLACKHOLE, 'B' },
	{ RTF_DYNAMIC,	'D' },
	{ RTF_MODIFIED,	'M' },
	{ RTF_DONE,	'd' }, /* Completed -- for routing messages only */
	{ RTF_CLONING,	'C' },
	{ RTF_LLINFO,	'L' },
	{ RTF_STATIC,	'S' },
	{ RTF_PROTO1,	'1' },
	{ RTF_PROTO2,	'2' },
	{ RTF_PROTO3,	'3' },
	{ RTF_CLONED,	'c' },
	{ RTF_MPLS,	'T' },
	{ 0, 0 }
};

void	pr_rthdr(int);
void	pr_flags(int);

void	pr_family(int);
void	p_encap(struct sockaddr *, struct sockaddr *, int);
void	p_sockaddr(struct sockaddr *, struct sockaddr *, int, int);
void	p_flags(int, char *);

/*
 * nsh print
 */
void
pr_flags(int af)
{
	printf("Flags: U - up, G - gateway, H - host, L - link layer, R - reject (unreachable),\n");
	printf("       D - dynamic, S - static, T - MPLS, c - CLONED, l - LOCAL\n");
}

/*
 * Print header for routing table columns.
 */
void
pr_rthdr(int af)
{
	if (af != PF_KEY)
		printf("%-*.*s %-*.*s %-6.6s %6.6s %8.8s %6.6s  %s\n",
		    WID_DST(af), WID_DST(af), "Destination",
		    WID_GW(af), WID_GW(af), "Gateway",
		    "Flags", "Refs", "Use", "Mtu", "Interface");
	else
		printf("%-18s %-5s %-18s %-5s %-5s %-22s\n",
		    "Source", "Port", "Destination",
		    "Port", "Proto", "SA(Address/Proto/Type/Direction)");
}

/* a route, as the table has it */
static struct facts_field route_fields[] = {
	[RT_DST] =	{ "destination",	FACT_ADDRESS },
	[RT_MASK] =	{ "netmask",		FACT_ADDRESS },
	[RT_GATEWAY] =	{ "gateway",		FACT_ADDRESS },
	[RT_GWTYPE] =	{ "gateway-type",	FACT_U64 },
	[RT_GWNAME] =	{ "gateway-name",	FACT_STRING },
	[RT_FLAGS] =	{ "flags",		FACT_U64 },
	[RT_REFS] =	{ "refs",		FACT_U64 },
	[RT_USE] =	{ "use",		FACT_U64 },
	[RT_MTU] =	{ "mtu",		FACT_U64 },
	[RT_LOCKS] =	{ "locks",		FACT_U64 },
	[RT_PRIORITY] =	{ "priority",		FACT_U64 },
	[RT_IF] =	{ "interface",		FACT_STRING },
};
struct facts_kind kind_route = { "route", route_fields, RT_NFIELDS };

void
route_facts_init(void)
{
	facts_bitnames(&route_fields[RT_FLAGS], routeflags);
	facts_bitnames(&route_fields[RT_LOCKS], metricnames);
	if_typenames(&route_fields[RT_GWTYPE]);
	lookup_facts_init();
}

/* a route as show route printed it, the table's headers first */
void
route_render(struct frec *r, int *count)
{
	struct sockaddr_storage	 dst, mask, gw;
	const char		*ifname;
	int interesting = RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_DYNAMIC |
	    RTF_LLINFO | RTF_STATIC | RTF_REJECT | RTF_MPLS | RTF_CLONED |
	    RTF_LOCAL;
	int			 af, flags;

	if (!fsockaddr(r, RT_DST, &dst))
		return;
	af = dst.ss_family;
	if ((*count)++ == 0) {
		pr_flags(af);
		pr_family(af);
		pr_rthdr(af);
	}
	flags = fu(r, RT_FLAGS, 0);
	p_sockaddr((struct sockaddr *)&dst, fsockaddr(r, RT_MASK, &mask) ?
	    (struct sockaddr *)&mask : NULL, flags, WID_DST(af));
	if (sdl_build(r, RT_GATEWAY, RT_GWTYPE, RT_GWNAME, &gw) ||
	    fsockaddr(r, RT_GATEWAY, &gw))
		p_sockaddr((struct sockaddr *)&gw, NULL, RTF_HOST, WID_GW(af));
	else
		printf("%-*s ", WID_GW(af), "");
	p_flags(flags & interesting, "%-6.6s ");
	printf("%6u %8llu ", (u_int)fu(r, RT_REFS, 0),
	    (unsigned long long)fu(r, RT_USE, 0));
	if (fu(r, RT_MTU, 0))
		printf("%6u ", (u_int)fu(r, RT_MTU, 0));
	else
		printf("%6s ", "-");
	putchar((fu(r, RT_LOCKS, 0) & RTV_MTU) ? 'L' : ' ');
	ifname = fs(r, RT_IF);
	printf(" %.16s", ifname ? ifname : "(null)");
	putchar('\n');
}

/* an IPsec flow, as the SPD has it */
static const struct facts_name flow_satypes[] = {
	{ SADB_SATYPE_ESP,	"esp" },
	{ SADB_SATYPE_AH,	"ah" },
	{ SADB_X_SATYPE_IPCOMP,	"ipcomp" },
	{ SADB_X_SATYPE_IPIP,	"ipip" },
};
static const struct facts_name flow_types[] = {
	{ SADB_X_FLOW_TYPE_USE,		"use" },
	{ SADB_X_FLOW_TYPE_REQUIRE,	"require" },
	{ SADB_X_FLOW_TYPE_ACQUIRE,	"acquire" },
	{ SADB_X_FLOW_TYPE_DENY,	"deny" },
	{ SADB_X_FLOW_TYPE_BYPASS,	"bypass" },
	{ SADB_X_FLOW_TYPE_DONTACQ,	"dontacq" },
};
static const struct facts_name flow_directions[] = {
	{ IPSP_DIRECTION_IN,	"in" },
	{ IPSP_DIRECTION_OUT,	"out" },
};
static struct facts_field flow_fields[] = {
	[FLOW_SRC] =		{ "source",		FACT_ADDRESS },
	[FLOW_SRCMASK] =	{ "source-mask",	FACT_ADDRESS },
	[FLOW_SRCPORT] =	{ "source-port",	FACT_U64 },
	[FLOW_DST] =		{ "destination",	FACT_ADDRESS },
	[FLOW_DSTMASK] =	{ "destination-mask",	FACT_ADDRESS },
	[FLOW_DSTPORT] =	{ "destination-port",	FACT_U64 },
	[FLOW_PROTO] =		{ "protocol",		FACT_U64 },
	[FLOW_PEER] =		{ "peer",		FACT_ADDRESS },
	[FLOW_SATYPE] =		{ "sa-type",		FACT_U64, FACT_VALUES,
				    flow_satypes, nitems(flow_satypes) },
	[FLOW_TYPE] =		{ "type",		FACT_U64, FACT_VALUES,
				    flow_types, nitems(flow_types) },
	[FLOW_DIRECTION] =	{ "direction",		FACT_U64, FACT_VALUES,
				    flow_directions, nitems(flow_directions) },
};
struct facts_kind kind_flow = { "ipsec-flow", flow_fields, FLOW_NFIELDS };

/* "/" and value's name in names, or dflt */
static void
flow_name(const struct facts_name *names, size_t n, uint64_t value,
    const char *dflt)
{
	size_t	 i;

	for (i = 0; i < n; i++)
		if (names[i].value == value) {
			printf("/%s", names[i].name);
			return;
		}
	printf("/%s", dflt);
}

/* a flow's source or destination, with its port */
static void
flow_encap(struct frec *r, int addr, int mask, int port)
{
	struct sockaddr_storage	 sa, m;

	fsockaddr(r, addr, &sa);
	fsockaddr(r, mask, &m);
	switch (sa.ss_family) {
	case AF_INET:
		((struct sockaddr_in *)&sa)->sin_port = htons(fu(r, port, 0));
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)&sa)->sin6_port =
		    htons(fu(r, port, 0));
		break;
	}
	p_encap((struct sockaddr *)&sa, (struct sockaddr *)&m,
	    WID_DST(sa.ss_family));
}

/* a flow as show sadb printed it, the SPD's headers first */
void
sadb_render(struct frec *r, int *count)
{
	struct sockaddr_storage	 peer;

	if (!fhas(r, FLOW_SRC) || !fhas(r, FLOW_DST))
		return;
	if ((*count)++ == 0) {
		printf("\n%% Encap:\n");
		pr_rthdr(PF_KEY);
	}
	flow_encap(r, FLOW_SRC, FLOW_SRCMASK, FLOW_SRCPORT);
	flow_encap(r, FLOW_DST, FLOW_DSTMASK, FLOW_DSTPORT);
	printf("%-6u", (u_int)fu(r, FLOW_PROTO, 0));
	if (fsockaddr(r, FLOW_PEER, &peer))
		p_sockaddr((struct sockaddr *)&peer, NULL, 0, -1);
	else
		printf("none");
	flow_name(flow_satypes, nitems(flow_satypes), fu(r, FLOW_SATYPE, 0),
	    "<unknown>");
	flow_name(flow_types, nitems(flow_types), fu(r, FLOW_TYPE, 0),
	    "<unknown type>");
	flow_name(flow_directions, nitems(flow_directions),
	    fu(r, FLOW_DIRECTION, 0), "<unknown>");
	printf("\n");
}

/*
 * Print address family header before a section of the routing table.
 */
void
pr_family(int af)
{
	char *afname;

	switch (af) {
	case AF_INET:
		afname = "IPv4";
		break;
	case AF_INET6:
		afname = "IPv6";
		break;
	case PF_KEY:
		afname = "Encap";
		break;
	default:
		afname = NULL;
		break;
	}
	if (afname)
		printf("\n%% %s:\n", afname);
	else
		printf("\n%% Protocol Family %d:\n", af);
}

void
p_encap(struct sockaddr *sa, struct sockaddr *mask, int width)
{
	char 		*cp;
	unsigned short	 port = 0;

	if (mask)
		cp = netname(sa, mask);
	else
		cp = routename(sa);

	switch (sa->sa_family) {
	case AF_INET:
		port = ntohs(((struct sockaddr_in *)sa)->sin_port);
		break;
	case AF_INET6:
		port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
		break;
	}
	if (width < 0)
		printf("%s", cp);
	else {
		printf("%-*s %-5u ", width, cp, port);
	}
}

void
p_sockaddr(struct sockaddr *sa, struct sockaddr *mask, int flags, int width)
{
	char *cp;

	switch (sa->sa_family) {
	case AF_INET6:
	    {
		in6_fillscopeid((struct sockaddr_in6 *)sa);
		if (flags & RTF_HOST)
			cp = routename(sa);
		else
			cp = netname(sa, mask);
		break;
	    }
	default:
		if ((flags & RTF_HOST) || mask == NULL)
			cp = routename(sa);
		else
			cp = netname(sa, mask);
		break;
	}
	if (width < 0)
		printf("%s", cp);
	else {
			printf("%-*s ", width, cp);
	}
}

void
p_flags(int f, char *format)
{
	char name[33], *flags;
	const struct bits *p = bits;

	for (flags = name; p->b_mask && flags < &name[sizeof(name) - 2]; p++)
		if (p->b_mask & f)
			*flags++ = p->b_val;
	*flags = '\0';
	printf(format, name);
}

static char line_show[MAXHOSTNAMELEN];
static char domain[MAXHOSTNAMELEN];

char *
routename(struct sockaddr *sa)
{
	char *cp = NULL;
	static int first = 1;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

	if (first) {
		first = 0;
		if (gethostname(domain, sizeof(domain)) == 0 &&
		    (cp = strchr(domain, '.')))
			(void)strlcpy(domain, cp + 1, sizeof(domain));
		else
			domain[0] = '\0';
		cp = NULL;
	}

	switch (sa->sa_family) {
	case AF_INET:
		if (sa->sa_len == 0)
			return "0.0.0.0";
		else
			return
			    (routename4(((struct sockaddr_in *)sa)->
			    sin_addr.s_addr));

	case AF_INET6:
		if (sa->sa_len == sizeof(struct sockaddr_in6))
			in6_fillscopeid(sin6);
		return (routename6(sin6));

	case AF_LINK:
		return (link_print(sa));

	case AF_UNSPEC:
		if (sa->sa_len == sizeof(struct sockaddr_rtlabel)) {
			static char name[RTLABEL_LEN];
			struct sockaddr_rtlabel *sr;

			sr = (struct sockaddr_rtlabel *)sa;
			(void)strlcpy(name, sr->sr_label, sizeof(name));
			return (name);
		}
		/* FALLTHROUGH */
	default:
		(void)snprintf(line_show, sizeof(line_show), "(%d) %s",
		    sa->sa_family, any_ntoa(sa));
		break;
	}
	return (line_show);
}

void
in6_fillscopeid(struct sockaddr_in6 *sin6)
{
	if ((IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_INTFACELOCAL(&sin6->sin6_addr)) &&
	    sin6->sin6_scope_id == 0) {
		sin6->sin6_scope_id =
		    ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
		sin6->sin6_addr.s6_addr[2] = sin6->sin6_addr.s6_addr[3] = 0;
	}
}

char *
routename4(in_addr_t in)
{
	struct in_addr	 ina;

	ina.s_addr = in;
	strlcpy(line_show, inet_ntoa(ina), sizeof(line_show));

	return (line_show);
}

char *
routename6(struct sockaddr_in6 *sin6)
{
	if (getnameinfo((struct sockaddr *)sin6, sin6->sin6_len,
	    line_show, sizeof(line_show), NULL, 0, NI_NUMERICHOST) != 0)
		strncpy(line_show, "", sizeof(line_show));

	return (line_show);
}

/*
 * Return the name of the network whose address is given.
 * The address is assumed to be that of a net or subnet, not a host.
 */
char *
netname4(in_addr_t in, struct sockaddr_in *maskp)
{
	in_addr_t mask;
	int mbits;

	if (maskp->sin_len == 0) {
		/*
		 * annoying.  why can't the kernel just tell the truth?
		 */
		maskp->sin_addr.s_addr = 0;
	}
	in = ntohl(in);
	mask = maskp ? ntohl(maskp->sin_addr.s_addr) : 0;
	mbits = mask ? 33 - ffs(mask) : 0;
#define C(x)	((x) & 0xff)
	snprintf(line_show, sizeof(line_show), "%u.%u.%u.%u/%d", C(in >> 24),
	    C(in >> 16), C(in >> 8), C(in), mbits);
#undef C
	return (line_show);
}

char *
netname6(struct sockaddr_in6 *sa6, struct sockaddr_in6 *mask)
{
	struct sockaddr_in6 sin6;
	u_char *p;
	int masklen, final = 0, illegal = 0;
	int i, lim, error;
	char hbuf[NI_MAXHOST];

	sin6 = *sa6;

	masklen = 0;
	if (mask) {
		lim = mask->sin6_len - offsetof(struct sockaddr_in6, sin6_addr);
		lim = lim < (int)sizeof(struct in6_addr) ?
		    lim : (int)sizeof(struct in6_addr);
		for (p = (u_char *)&mask->sin6_addr, i = 0; i < lim; p++) {
			if (final && *p) {
				illegal++;
				continue;
			}

			switch (*p & 0xff) {
			case 0xff:
				masklen += 8;
				break;
			case 0xfe:
				masklen += 7;
				final++;
				break;
			case 0xfc:
				masklen += 6;
				final++;
				break;
			case 0xf8:
				masklen += 5;
				final++;
				break;
			case 0xf0:
				masklen += 4;
				final++;
				break;
			case 0xe0:
				masklen += 3;
				final++;
				break;
			case 0xc0:
				masklen += 2;
				final++;
				break;
			case 0x80:
				masklen += 1;
				final++;
				break;
			case 0x00:
				final++;
				break;
			default:
				final++;
				illegal++;
				break;
			}

			i++;
		}
	} else
		masklen = 128;

	/* This will warn us if the kernel supplies an insane mask */
	if (illegal)
		printf("%% netname6: illegal prefixlen\n");

	error = getnameinfo((struct sockaddr *)&sin6, sin6.sin6_len,
	    hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST);
	if (error)
		hbuf[0] = '\0';

	snprintf(line_show, sizeof(line_show), "%s/%d", hbuf, masklen);
	return (line_show);
}

/*
 * Return the name of the network whose address is given.
 * The address is assumed to be that of a net or subnet, not a host.
 */
char *
netname(struct sockaddr *sa, struct sockaddr *mask)
{
	switch (sa->sa_family) {

	case AF_INET:
		return netname4(((struct sockaddr_in *)sa)->sin_addr.s_addr,
		    (struct sockaddr_in *)mask);
	case AF_INET6:
		return netname6((struct sockaddr_in6 *)sa,
		    (struct sockaddr_in6 *)mask);
	case AF_LINK:
		return (link_print(sa));
	default:
		snprintf(line_show, sizeof(line_show), "af %d: %s",
		    sa->sa_family, any_ntoa(sa));
		break;
	}
	return (line_show);
}

static const char hexlist[] = "0123456789abcdef";

char *
any_ntoa(const struct sockaddr *sa)
{
	static char obuf[240];
	const char *in = sa->sa_data;
	char *out = obuf;
	int len = sa->sa_len - offsetof(struct sockaddr, sa_data);

	*out++ = 'Q';
	do {
		*out++ = hexlist[(*in >> 4) & 15];
		*out++ = hexlist[(*in++)    & 15];
		*out++ = '.';
	} while (--len > 0 && (out + 3) < &obuf[sizeof(obuf) - 1]);
	out[-1] = '\0';
	return (obuf);
}

char *
link_print(struct sockaddr *sa)
{
	struct sockaddr_dl	*sdl = (struct sockaddr_dl *)sa;
	u_char			*lla = (u_char *)sdl->sdl_data + sdl->sdl_nlen;

	if (sdl->sdl_nlen == 0 && sdl->sdl_alen == 0 &&
	    sdl->sdl_slen == 0)
		return "";
	switch (sdl->sdl_type) {
	case IFT_ETHER:
	case IFT_CARP:
		return (ether_ntoa((struct ether_addr *)lla));
	default:
		return (link_ntoa(sdl));
	}
}

void	 bprintf(FILE *, int, u_char *);

char metricnames[] =
"\011pksent\010rttvar\7rtt\6ssthresh\5sendpipe\4recvpipe\3expire\2hopcount\1mtu";

char routeflags[] =
"\1UP\2GATEWAY\3HOST\4REJECT\5DYNAMIC\6MODIFIED\7DONE\010MASK_PRESENT\011CLONING\013LLINFO\014STATIC\017PROTO2\020PROTO1";

char ifnetflags[] =
"\1UP\2BROADCAST\3DEBUG\4LOOPBACK\5PTP\6NOTRAILERS\7RUNNING\010NOARP\011PROMISC\012ALLMULTI\013OACTIVE\014SIMPLEX\015LINK0\016LINK1\017LINK2\020MULTICAST";

char addrnames[] =
"\1DST\2GATEWAY\3NETMASK\4GENMASK\5IFP\6IFA\7AUTHOR\010BRD";

/* the route the kernel would use, as facts */
static struct facts_field lookup_fields[] = {
	[LK_QUERY] =	{ "query",		FACT_ADDRESS },
	[LK_ERRNO] =	{ "errno",		FACT_U64 },
	[LK_RTERRNO] =	{ "reply-errno",	FACT_U64 },
	[LK_DST] =	{ "destination",	FACT_ADDRESS },
	[LK_MASK] =	{ "netmask",		FACT_ADDRESS },
	[LK_GATEWAY] =	{ "gateway",		FACT_ADDRESS },
	[LK_GWTYPE] =	{ "gateway-type",	FACT_U64 },
	[LK_GWNAME] =	{ "gateway-name",	FACT_STRING },
	[LK_GENMASK] =	{ "genmask",		FACT_ADDRESS },
	[LK_IFP] =	{ "link",		FACT_ADDRESS },
	[LK_IFPTYPE] =	{ "link-type",		FACT_U64 },
	[LK_IFPNAME] =	{ "interface",		FACT_STRING },
	[LK_IFA] =	{ "interface-address",	FACT_ADDRESS },
	[LK_BRD] =	{ "broadcast",		FACT_ADDRESS },
	[LK_LABEL] =	{ "label",		FACT_STRING },
	[LK_FLAGS] =	{ "flags",		FACT_U64 },
	[LK_ADDRS] =	{ "addresses",		FACT_U64 },
	[LK_MTU] =	{ "mtu",		FACT_U64 },
	[LK_HOPCOUNT] =	{ "hopcount",		FACT_U64 },
	[LK_EXPIRE] =	{ "expires",		FACT_I64 },
	[LK_LOCKS] =	{ "locks",		FACT_U64 },
	[LK_INITS] =	{ "inits",		FACT_U64 },
};
struct facts_kind kind_lookup = { "route-lookup", lookup_fields,
    LK_NFIELDS };

void
lookup_facts_init(void)
{
	facts_bitnames(&lookup_fields[LK_FLAGS], routeflags);
	facts_bitnames(&lookup_fields[LK_ADDRS], addrnames);
	facts_bitnames(&lookup_fields[LK_LOCKS], metricnames);
	facts_bitnames(&lookup_fields[LK_INITS], metricnames);
	if_typenames(&lookup_fields[LK_GWTYPE]);
	if_typenames(&lookup_fields[LK_IFPTYPE]);
}

/* a lookup, as print_getmsg() printed it */
void
lookup_render(struct frec *r)
{
	struct sockaddr_storage	 q, sa;
	struct sockaddr		*s = (struct sockaddr *)&sa;
	const struct facts_value *qv;
	char			 buf[INET6_ADDRSTRLEN];
	int			 e, flags, addrs, i;

	if (fhas(r, LK_ERRNO)) {
		e = fu(r, LK_ERRNO, 0);
		buf[0] = '\0';
		if ((qv = FV(r, LK_QUERY, FACT_ADDRESS)) != NULL)
			inet_ntop(qv->v.a.family == FACT_INET6 ? AF_INET6 :
			    AF_INET, qv->v.a.bytes, buf, sizeof(buf));
		if (e == ESRCH || e == ENETUNREACH)
			printf("%% Unable to find route: %s\n", buf);
		else
			printf("%% ip_route: rtmsg: %s\n", strerror(e));
		return;
	}
	fsockaddr(r, LK_QUERY, &q);
	printf("%% route lookup for:\t%s\n", routename((struct sockaddr *)&q));
	if (fhas(r, LK_RTERRNO)) {
		e = fu(r, LK_RTERRNO, 0);
		printf("%% print_getmsg: RTM_GET: %s (errno %d)\n",
		    strerror(e), e);
		return;
	}
	flags = fu(r, LK_FLAGS, 0);
	addrs = fu(r, LK_ADDRS, 0);
	if (fsockaddr(r, LK_DST, &sa))
		printf("\tdestination:\t%s\n", routename(s));
	if (fsockaddr(r, LK_MASK, &sa))
		printf("\tnetmask:\t%s\n", routename(s));
	if ((sdl_build(r, LK_GATEWAY, LK_GWTYPE, LK_GWNAME, &sa) ||
	    fsockaddr(r, LK_GATEWAY, &sa)) && flags & RTF_GATEWAY)
		printf("\tgateway:\t%s\n", routename(s));
	if (fs(r, LK_IFPNAME) != NULL)
		printf("\tinterface:\t%s\n", fs(r, LK_IFPNAME));
	if (verbose) {
		printf("\tflags:\t");
		bprintf(stdout, flags, routeflags);
		printf("\n");
	}
	if (fs(r, LK_LABEL) != NULL)
		printf("\tlabel:\t\t%s\n", fs(r, LK_LABEL));
	if (fu(r, LK_MTU, 0))
		printf("\tmtu:\t\t%u\n", (u_int)fu(r, LK_MTU, 0));
	if (fu(r, LK_HOPCOUNT, 0))
		printf("\thopcount:\t%u\n", (u_int)fu(r, LK_HOPCOUNT, 0));
	if (FV(r, LK_EXPIRE, FACT_I64) != NULL)
		printf("\texpires:\t%lld sec\n",
		    (long long)FV(r, LK_EXPIRE, FACT_I64)->v.i);

#define RTA_IGN (RTA_DST|RTA_GATEWAY|RTA_NETMASK|RTA_IFP|RTA_IFA|RTA_BRD)
	if (verbose) {
		printf("%% locks: ");
		bprintf(stdout, fu(r, LK_LOCKS, 0), metricnames);
		printf(" inits: ");
		bprintf(stdout, fu(r, LK_INITS, 0), metricnames);
		printf("\n");
		if (addrs == 0)
			return;
		printf("%% sockaddrs: ");
		bprintf(stdout, addrs, addrnames);
		putchar('\n');
		/* each address, in the order of the bits that name it */
		for (i = 1; i; i <<= 1) {
			if ((i & addrs) == 0)
				continue;
			switch (i) {
			case RTA_DST:
				fsockaddr(r, LK_DST, &sa);
				break;
			case RTA_GATEWAY:
				if (!sdl_build(r, LK_GATEWAY, LK_GWTYPE,
				    LK_GWNAME, &sa))
					fsockaddr(r, LK_GATEWAY, &sa);
				break;
			case RTA_NETMASK:
				fsockaddr(r, LK_MASK, &sa);
				break;
			case RTA_GENMASK:
				fsockaddr(r, LK_GENMASK, &sa);
				break;
			case RTA_IFP:
				sdl_build(r, LK_IFP, LK_IFPTYPE, LK_IFPNAME,
				    &sa);
				break;
			case RTA_IFA:
				fsockaddr(r, LK_IFA, &sa);
				break;
			case RTA_BRD:
				fsockaddr(r, LK_BRD, &sa);
				break;
			case RTA_LABEL:
				printf(" %s", fs(r, LK_LABEL) ?
				    fs(r, LK_LABEL) : "");
				continue;
			default:
				continue;
			}
			printf(" %s", sa.ss_family ? routename(s) : "");
		}
		putchar('\n');
	} else if (addrs & ~RTA_IGN) {
		printf("\tsockaddrs:\t");
		bprintf(stdout, addrs, addrnames);
		putchar('\n');
	}
#undef RTA_IGN
}

void
bprintf(FILE *fp, int b, u_char *s)
{
	int i;
	int gotsome = 0;

	if (b == 0)
		return;
	while ((i = *s++)) {
		if ((b & (1 << (i-1)))) {
			if (gotsome == 0)
				i = '<';
			else
				i = ',';
			(void) putc(i, fp);
			gotsome = 1;
			for (; (i = *s) > 32; s++)
				(void) putc(i, fp);
		} else
			while (*s > 32)
				s++;
	}
	if (gotsome)
		(void) putc('>', fp);
}

#define W_ADDR	36
#define W_LL	17
#define W_IF	6

/* the table's headers */
void
arp_header(void)
{
	printf("%-*.*s %-*.*s %*.*s %-10.10s %5s\n",
	    W_ADDR, W_ADDR, "Host", W_LL, W_LL, "Ethernet Address",
	    W_IF, W_IF, "Netif", "Expire", "Flags");
}

/* an address the table does not have */
void
arp_noentry(const char *host)
{
	printf("%% %-*.*s no entry\n", W_ADDR, W_ADDR, host);
}

/* an entry, as facts */
static struct facts_field arp_fields[] = {
	[ARP_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[ARP_LLADDR] =	{ "link-address",	FACT_ADDRESS },
	[ARP_IF] =	{ "interface",		FACT_STRING },
	[ARP_FLAGS] =	{ "flags",		FACT_U64 },
	[ARP_PROXY] =	{ "proxy",		FACT_U64 },
	[ARP_EXPIRE] =	{ "expire",		FACT_TIME },
};
struct facts_kind kind_arp = { "arp-entry", arp_fields, ARP_NFIELDS };

void
arp_facts_init(void)
{
	facts_bitnames(&arp_fields[ARP_FLAGS], routeflags);
}

/*
 * Display an arp entry
 */
void
arp_render(struct frec *r)
{
	const struct facts_value *e;
	struct sockaddr_storage sa, ll;
	const char *ifname;
	char *host;
	int addrwidth, llwidth, ifwidth ;
	uint64_t flags;
	struct timeval now;

	gettimeofday(&now, 0);

	fsockaddr(r, ARP_ADDRESS, &sa);
	fsockaddr(r, ARP_LLADDR, &ll);
	host = inet_ntoa(((struct sockaddr_in *)&sa)->sin_addr);

	addrwidth = strlen(host);
	if (addrwidth < W_ADDR)
		addrwidth = W_ADDR;
	llwidth = strlen(ether_str((struct sockaddr_dl *)&ll));
	if (W_ADDR + W_LL - addrwidth > llwidth)
		llwidth = W_ADDR + W_LL - addrwidth;
	ifname = fs(r, ARP_IF);
	if (!ifname)
		ifname = "?";
	ifwidth = strlen(ifname);
	if (W_ADDR + W_LL + W_IF - addrwidth - llwidth > ifwidth)
		ifwidth = W_ADDR + W_LL + W_IF - addrwidth - llwidth;

	printf("%-*.*s %-*.*s %*.*s", addrwidth, addrwidth, host,
	    llwidth, llwidth, ether_str((struct sockaddr_dl *)&ll), ifwidth,
	    ifwidth, ifname);

	flags = fu(r, ARP_FLAGS, 0);
	e = FV(r, ARP_EXPIRE, FACT_TIME);
	if (flags & (RTF_PERMANENT_ARP|RTF_LOCAL))
		printf(" %-10.10s", "permanent");
	else if (e == NULL)
		printf(" %-10.10s", "static");
	else if (e->v.t.sec > now.tv_sec)
		printf(" %-10.10s",
		    sec2str(e->v.t.sec - now.tv_sec));
	else
		printf(" %-10.10s", "expired");

	printf(" %s%s%s\n",
	    (flags & RTF_LOCAL) ? "l" : "",
	    fu(r, ARP_PROXY, 0) ? "P" : "",
	    (flags & RTF_ANNOUNCE) ? "p" : "");
}

char *
ether_str(struct sockaddr_dl *sdl)
{
	static char hbuf[NI_MAXHOST];
	u_char *cp;

	if (sdl->sdl_alen) {
		cp = (u_char *)LLADDR(sdl);
		snprintf(hbuf, sizeof(hbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
		    cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]);
	} else
		snprintf(hbuf, sizeof(hbuf), "(incomplete)");

	return hbuf;
}

char *
sec2str(time_t total)
{
	static char result[256];
	int days, hours, mins, secs;
	int first = 1;
	char *p = result;
	char *ep = &result[sizeof(result)];
	int n;

	days = total / 3600 / 24;
	hours = (total / 3600) % 24;
	mins = (total / 60) % 60;
	secs = total % 60;

	if (days) {
		first = 0;
		n = snprintf(p, ep - p, "%dd", days);
		if (n < 0 || n >= ep - p)
			return "?";
		p += n;
	}
	if (!first || hours) {
		first = 0;
		n = snprintf(p, ep - p, "%dh", hours);
		if (n < 0 || n >= ep - p)
			return "?";
		p += n;
	}
	if (!first || mins) {
		n = snprintf(p, ep - p, "%dm", mins);
		if (n < 0 || n >= ep - p)
			return "?";
		p += n;
	}
	snprintf(p, ep - p, "%ds", secs);

	return result;
}

#undef W_ADDR
#undef W_LL
#undef W_IF
/*
 * strlen("2001:0db8:3333:4444:5555:6666:7777:8888") == 39
 */
#define W_ADDR	39
#define W_LL	17
#define W_IF	7

/* a neighbor, as facts; with no state, the kernel would not say */
static struct facts_field ndp_fields[] = {
	[NDP_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[NDP_LLADDR] =	{ "link-address",	FACT_ADDRESS },
	[NDP_IF] =	{ "interface",		FACT_STRING },
	[NDP_FLAGS] =	{ "flags",		FACT_U64 },
	[NDP_EXPIRE] =	{ "expire",		FACT_TIME },
	[NDP_STATE] =	{ "state",		FACT_I64 },
	[NDP_ROUTER] =	{ "router",		FACT_U64 },
	[NDP_PROBES] =	{ "probes",		FACT_U64 },
	[NDP_ERRNO] =	{ "info-errno",		FACT_U64 },
};
struct facts_kind kind_ndp = { "ndp-entry", ndp_fields, NDP_NFIELDS };

static const struct facts_name ndp_states[] = {
	{ (uint64_t)ND6_LLINFO_NOSTATE,	"nostate" },
	{ ND6_LLINFO_INCOMPLETE,	"incomplete" },
	{ ND6_LLINFO_REACHABLE,		"reachable" },
	{ ND6_LLINFO_STALE,		"stale" },
	{ ND6_LLINFO_DELAY,		"delay" },
	{ ND6_LLINFO_PROBE,		"probe" },
};

void
ndp_facts_init(void)
{
	facts_bitnames(&ndp_fields[NDP_FLAGS], routeflags);
	ndp_fields[NDP_STATE].naming = FACT_VALUES;
	ndp_fields[NDP_STATE].names = ndp_states;
	ndp_fields[NDP_STATE].nnames = nitems(ndp_states);
}

/* the cache's headers */
void
ndp_header(void)
{
	printf("%-*.*s %-*.*s %*.*s %-9.9s %1s %5s\n",
	    W_ADDR, W_ADDR, "Neighbor", W_LL, W_LL, "Linklayer Address",
	    W_IF, W_IF, "Netif", "Expire", "S", "Flags");
}

/*
 * A neighbor, as ndpdump() printed it; failed is its address if the
 * kernel would say no more of it, else empty
 */
void
ndp_render(struct frec *r, char *failed, size_t len)
{
	const struct facts_value *e, *st;
	struct sockaddr_storage sa, ll;
	struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&sa;
	struct timeval now;
	const char *ifname;
	char host[NI_MAXHOST];
	int addrwidth, llwidth, ifwidth, isrouter = 0, prbs = 0;
	int64_t expire;
	uint64_t flags;

	fsockaddr(r, NDP_ADDRESS, &sa);
	fsockaddr(r, NDP_LLADDR, &ll);
	if (getnameinfo((struct sockaddr *)sin, sin->sin6_len, host,
	    sizeof(host), NULL, 0, NI_NUMERICHOST) != 0)
		host[0] = '\0';
	gettimeofday(&now, 0);

	addrwidth = strlen(host);
	if (addrwidth < W_ADDR)
		addrwidth = W_ADDR;
	llwidth = strlen(ether_str((struct sockaddr_dl *)&ll));
	if (W_ADDR + W_LL - addrwidth > llwidth)
		llwidth = W_ADDR + W_LL - addrwidth;
	ifname = fs(r, NDP_IF);
	if (!ifname)
		ifname = "?";
	ifwidth = strlen(ifname);
	if (W_ADDR + W_LL + W_IF - addrwidth - llwidth > ifwidth)
		ifwidth = W_ADDR + W_LL + W_IF - addrwidth - llwidth;

	printf("%-*.*s %-*.*s %*.*s", addrwidth, addrwidth, host,
	    llwidth, llwidth, ether_str((struct sockaddr_dl *)&ll), ifwidth,
	    ifwidth, ifname);

	/* Print neighbor discovery specific information */
	if (fhas(r, NDP_ERRNO))
		printf("%% getnbrinfo: ioctl(SIOCGNBRINFO_IN6): %s\n",
		    strerror(fu(r, NDP_ERRNO, 0)));
	if ((st = FV(r, NDP_STATE, FACT_I64)) != NULL) {
		e = FV(r, NDP_EXPIRE, FACT_TIME);
		expire = e != NULL ? e->v.t.sec : 0;
		if (expire > now.tv_sec) {
			printf(" %-9.9s",
			    sec2str(expire - now.tv_sec));
		} else if (expire == 0)
			printf(" %-9.9s", "permanent");
		else
			printf(" %-9.9s", "expired");

		switch (st->v.i) {
		case ND6_LLINFO_NOSTATE:
			 printf(" N");
			 break;
		case ND6_LLINFO_INCOMPLETE:
			 printf(" I");
			 break;
		case ND6_LLINFO_REACHABLE:
			 printf(" R");
			 break;
		case ND6_LLINFO_STALE:
			 printf(" S");
			 break;
		case ND6_LLINFO_DELAY:
			 printf(" D");
			 break;
		case ND6_LLINFO_PROBE:
			 printf(" P");
			 break;
		default:
			 printf(" ?");
			 break;
		}

		isrouter = fu(r, NDP_ROUTER, 0);
		prbs = fu(r, NDP_PROBES, 0);
		failed[0] = '\0';
	} else {
		printf("  ");
		strlcpy(failed, routename6(sin), len);
	}

	flags = fu(r, NDP_FLAGS, 0);
	printf(" %s%s%s",
	    (flags & RTF_LOCAL) ? "l" : "",
	    isrouter ? "R" : "",
	    (flags & RTF_ANNOUNCE) ? "p" : "");

	if (prbs)
		printf(" %d", prbs);

	printf("\n");
}

/* after the neighbors, the messages for failed and nohost, if set */
void
ndp_end(const char *failed, const char *nohost)
{
	if (failed[0] != '\0')
		printf("\n%% %s: failed to get neighbor information\n",
		    failed);
	if (nohost != NULL)
		printf("%s -- no entry\n", nohost);
}
