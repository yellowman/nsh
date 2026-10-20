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

#include "externs.h"
#include "facts.h"
#include "showfacts.h"

char	*any_ntoa(const struct sockaddr *);
char	*link_print(struct sockaddr *);

#define PLEN  (LONG_BIT / 4 + 2)

#define PFKEYV2_CHUNK sizeof(u_int64_t)

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
void	index_pfk(struct sadb_msg *, void **);

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
 * The SPD's flows, as the kernel dumps them: NULL if it cannot, said
 * why, but for a kernel without IPsec
 */
struct rtdump *
sadb_dump(void)
{
	struct rtdump	*spd;
	size_t		 needed;
	char		*p;
	int		 mib[4] = { CTL_NET, PF_KEY, PF_KEY_V2,
			    NET_KEY_SPD_DUMP };

	if ((spd = calloc(1, sizeof(*spd))) == NULL) {
		printf("%% sadb_dump: %s\n", strerror(errno));
		return (NULL);
	}
	for (;;) {
		if (sysctl(mib, 4, NULL, &needed, NULL, 0) == -1) {
			if (errno != ENOPROTOOPT)
				printf("%% sadb_dump: spd-sysctl-estimate: "
				    "%s\n", strerror(errno));
			break;
		}
		if ((p = realloc(spd->buf, needed)) == NULL) {
			printf("%% sadb_dump: spd malloc: %s\n",
			    strerror(errno));
			break;
		}
		spd->buf = p;
		if (sysctl(mib, 4, spd->buf, &needed, NULL, 0) == 0) {
			spd->lim = spd->buf + needed;
			return (spd);
		}
		/* the SPD grew since it was estimated */
		if (errno != ENOMEM) {
			printf("%% sadb_dump: spd sysctl: %s\n",
			    strerror(errno));
			break;
		}
	}
	freertdump(spd);
	return (NULL);
}

/* 
 * column widths; each followed by one space
 * width of destination/gateway column
 * strlen("fe80::aaaa:bbbb:cccc:dddd@gif0") == 30, strlen("/128") == 4
 */
#define	WID_DST(af)	((af) == AF_INET6 ? 34 : 18)
#define	WID_GW(af)	((af) == AF_INET6 ? 30 : 18)

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

static void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int	i;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			sa = (struct sockaddr *)((char *)(sa) +
			    ROUNDUP(sa->sa_len));
		} else
			rti_info[i] = NULL;
	}
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

/* a link address's type and name, as facts */
void
facts_sdl(struct facts_value *type, struct facts_value *name, char *buf,
    size_t len, struct sockaddr *sa)
{
	struct sockaddr_dl	*sdl = (struct sockaddr_dl *)sa;

	if (sa == NULL || sa->sa_family != AF_LINK)
		return;
	facts_u64(type, sdl->sdl_type);
	if (sdl->sdl_nlen == 0)
		return;
	snprintf(buf, len, "%.*s", sdl->sdl_nlen, sdl->sdl_data);
	facts_string(name, buf);
}

/*
 * The routes of rt, from *cur, that are of af, as facts: budget at
 * most. 1 if there are more, 0 if not, -1 if a record failed.
 */
int
route_facts(struct facts_out *o, struct rtdump *rt, char **cur, int af,
    int budget)
{
	struct facts_value	 v[RT_NFIELDS];
	struct rt_msghdr	*rtm;
	struct sockaddr		*sa, *rti_info[RTAX_MAX];
	char			 ifbuf[IF_NAMESIZE], gwname[IFNAMSIZ + 1];
	int			 n = 0;

	for (; *cur < rt->lim; *cur += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)*cur;
		if (n == budget)
			return (1);
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		sa = (struct sockaddr *)(*cur + rtm->rtm_hdrlen);
		if ((af != AF_UNSPEC && sa->sa_family != af) ||
		    sa->sa_family == AF_KEY)
			continue;
		get_rtaddrs(rtm->rtm_addrs, sa, rti_info);
		if (rti_info[RTAX_DST] == NULL)
			continue;
		memset(v, 0, sizeof(v));
		facts_sockaddr(&v[RT_DST], rti_info[RTAX_DST]);
		facts_sockaddr(&v[RT_MASK], rti_info[RTAX_NETMASK]);
		facts_sockaddr(&v[RT_GATEWAY], rti_info[RTAX_GATEWAY]);
		facts_sdl(&v[RT_GWTYPE], &v[RT_GWNAME], gwname,
		    sizeof(gwname), rti_info[RTAX_GATEWAY]);
		facts_u64(&v[RT_FLAGS], rtm->rtm_flags);
		facts_u64(&v[RT_REFS], rtm->rtm_rmx.rmx_refcnt);
		facts_u64(&v[RT_USE], rtm->rtm_rmx.rmx_pksent);
		facts_u64(&v[RT_MTU], rtm->rtm_rmx.rmx_mtu);
		facts_u64(&v[RT_LOCKS], rtm->rtm_rmx.rmx_locks);
		facts_u64(&v[RT_PRIORITY], rtm->rtm_priority);
		if (if_indextoname(rtm->rtm_index, ifbuf) != NULL)
			facts_string(&v[RT_IF], ifbuf);
		if (facts_record(o, &kind_route, v) == -1)
			return (-1);
		n++;
	}
	return (0);
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

/* the address an extension of msg holds, or NULL */
static struct sockaddr *
flow_sa(void **headers, int ext)
{
	struct sadb_address	*saddr = headers[ext];

	return (saddr != NULL ? (struct sockaddr *)(saddr + 1) : NULL);
}

static uint16_t
flow_port(struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (ntohs(((struct sockaddr_in *)sa)->sin_port));
	case AF_INET6:
		return (ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
	}
	return (0);
}

/*
 * The flows of spd, from *cur, as facts: budget at most. 1 if there
 * are more, 0 if not, -1 if a record failed.
 */
int
sadb_facts(struct facts_out *o, struct rtdump *spd, char **cur, int budget)
{
	struct facts_value	 v[FLOW_NFIELDS];
	struct sadb_msg		*msg;
	struct sadb_protocol	*sap, *saft;
	struct sockaddr		*src, *srcmask, *dst, *dstmask;
	void			*headers[SADB_EXT_MAX + 1];
	int			 n = 0;

	for (; *cur < spd->lim; *cur += msg->sadb_msg_len * PFKEYV2_CHUNK) {
		msg = (struct sadb_msg *)*cur;
		if (msg->sadb_msg_len == 0)
			break;
		if (n == budget)
			return (1);
		bzero(headers, sizeof(headers));
		index_pfk(msg, headers);
		sap = headers[SADB_X_EXT_PROTOCOL];
		saft = headers[SADB_X_EXT_FLOW_TYPE];
		/* always set, and bypass and deny flows have no peer */
		if ((src = flow_sa(headers, SADB_X_EXT_SRC_FLOW)) == NULL ||
		    (srcmask = flow_sa(headers, SADB_X_EXT_SRC_MASK)) ==
		    NULL ||
		    (dst = flow_sa(headers, SADB_X_EXT_DST_FLOW)) == NULL ||
		    (dstmask = flow_sa(headers, SADB_X_EXT_DST_MASK)) ==
		    NULL || sap == NULL || saft == NULL)
			continue;
		memset(v, 0, sizeof(v));
		facts_sockaddr(&v[FLOW_SRC], src);
		facts_sockaddr(&v[FLOW_SRCMASK], srcmask);
		facts_u64(&v[FLOW_SRCPORT], flow_port(src));
		facts_sockaddr(&v[FLOW_DST], dst);
		facts_sockaddr(&v[FLOW_DSTMASK], dstmask);
		facts_u64(&v[FLOW_DSTPORT], flow_port(dst));
		facts_u64(&v[FLOW_PROTO], sap->sadb_protocol_proto);
		facts_sockaddr(&v[FLOW_PEER],
		    flow_sa(headers, SADB_EXT_ADDRESS_DST));
		facts_u64(&v[FLOW_SATYPE], msg->sadb_msg_satype);
		facts_u64(&v[FLOW_TYPE], saft->sadb_protocol_proto);
		facts_u64(&v[FLOW_DIRECTION], saft->sadb_protocol_direction);
		if (facts_record(o, &kind_flow, v) == -1)
			return (-1);
		n++;
	}
	return (0);
}

/* "/" and what names says value is, or dflt */
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

void
in6_clearscopeid(struct sockaddr_in6 *sin6)
{
	if ((IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_INTFACELOCAL(&sin6->sin6_addr)) &&
	    *(u_int16_t *)&sin6->sin6_addr.s6_addr[2] == 0 &&
	    sin6->sin6_scope_id) {
		*(u_int16_t *)&sin6->sin6_addr.s6_addr[2] =
		    htons(sin6->sin6_scope_id & 0xffff);
		sin6->sin6_scope_id = 0;
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

void
index_pfk(struct sadb_msg *msg, void **headers)
{
	struct sadb_ext	*ext;

	for (ext = (struct sadb_ext *)(msg + 1);
	    (size_t)((u_int8_t *)ext - (u_int8_t *)msg) <
	    msg->sadb_msg_len * PFKEYV2_CHUNK && ext->sadb_ext_len > 0;
	    ext = (struct sadb_ext *)((u_int8_t *)ext +
	    ext->sadb_ext_len * PFKEYV2_CHUNK)) {
		switch (ext->sadb_ext_type) {
		case SADB_EXT_ADDRESS_SRC:
			headers[SADB_EXT_ADDRESS_SRC] = (void *)ext;
			break;
		case SADB_EXT_ADDRESS_DST:
			headers[SADB_EXT_ADDRESS_DST] = (void *)ext;
			break;
		case SADB_X_EXT_PROTOCOL:
			headers[SADB_X_EXT_PROTOCOL] = (void *)ext;
			break;
		case SADB_X_EXT_SRC_FLOW:
			headers[SADB_X_EXT_SRC_FLOW] = (void *)ext;
			break;
		case SADB_X_EXT_DST_FLOW:
			headers[SADB_X_EXT_DST_FLOW] = (void *)ext;
			break;
		case SADB_X_EXT_SRC_MASK:
			headers[SADB_X_EXT_SRC_MASK] = (void *)ext;
			break;
		case SADB_X_EXT_DST_MASK:
			headers[SADB_X_EXT_DST_MASK] = (void *)ext;
			break;
		case SADB_X_EXT_FLOW_TYPE:
			headers[SADB_X_EXT_FLOW_TYPE] = (void *)ext;
		default:
			/* Ignore. */
			break;
		}
	}
}
