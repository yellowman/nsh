/* $nsh: show.c,v 1.15 2012/05/20 20:11:01 chris Exp $ */
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
	{ RTF_MASK,	'm' }, /* Mask Present -- for routing messages only */
	{ RTF_CLONING,	'C' },
	{ RTF_XRESOLVE,	'X' },
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

void	p_rtentry(struct rt_msghdr *);
void	p_pfkentry(struct sadb_msg *);
void	pr_family(int);
void	p_encap(struct sockaddr *, struct sockaddr *, int);
void	p_protocol(struct sadb_protocol *, struct sockaddr *, struct
	    sadb_protocol *, int);
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
	printf("       D - dynamic, S - static, T - MPLS\n");
}

/*
 * Print routing tables.
 */
void
p_rttables(int af, u_int tableid, int flags)
{
	struct rt_msghdr *rtm;
	struct sadb_msg *msg;
	char *next, *buf = NULL, *lim = NULL;
	size_t needed;
	int mib[7];
	struct sockaddr *sa;
	struct rtdump *rtdump;

	rtdump = getrtdump(af, flags, tableid);

	if (rtdump) {
		for (next = rtdump->buf; next < rtdump->lim; next += rtm->rtm_msglen) {
			rtm = (struct rt_msghdr *)next;
			if (rtm->rtm_version != RTM_VERSION)
				continue;
			sa = (struct sockaddr *)(next + rtm->rtm_hdrlen);
			if (af != AF_UNSPEC && sa->sa_family != af)
				continue;
			if (next == rtdump->buf) {
				/* start of the loop? print headers */
				pr_flags(sa->sa_family);
				pr_family(sa->sa_family);
				pr_rthdr(sa->sa_family);
			}
			p_rtentry(rtm);
		}
		freertdump(rtdump);
	}

	if (af != 0 && af != PF_KEY)
		return;

	mib[0] = CTL_NET;
	mib[1] = PF_KEY;
	mib[2] = PF_KEY_V2;
	mib[3] = NET_KEY_SPD_DUMP;
	mib[4] = mib[5] = 0;

	if (sysctl(mib, 4, NULL, &needed, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% p_rttables: spd-sysctl-estimate: %s\n",
			    strerror(errno));
		return;
	}
	if (needed > 0) {
		if ((buf = malloc(needed)) == 0) {
			printf("%% p_rttables: spd malloc: %s\n",
			    strerror(errno));
			return;
		}
		if (sysctl(mib, 4, buf, &needed, NULL, 0) == -1) {
			free(buf);
			printf("%% p_rttables: spd sysctl: %s\n",
			    strerror(errno));
			return;
		}
		lim = buf + needed;
	}

	if (buf) {
		printf("\n%% Encap:\n");

		for (next = buf; next < lim; next += msg->sadb_msg_len *
		    PFKEYV2_CHUNK) {
			msg = (struct sadb_msg *)next;
			if (msg->sadb_msg_len == 0)
				break;
			if (next == buf)
				pr_rthdr(PF_KEY);
			p_pfkentry(msg);
		}
		free(buf);
		buf = NULL;
	} else {
		printf("%% SADB empty\n");
	}
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

/*
 * Print a routing table entry.
 */
void
p_rtentry(struct rt_msghdr *rtm)
{
	struct sockaddr	*sa = (struct sockaddr *)((char *)rtm + rtm->rtm_hdrlen);
	struct sockaddr	*mask, *rti_info[RTAX_MAX];
	char		 ifbuf[IF_NAMESIZE];
	int interesting = RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_DYNAMIC |
	    RTF_LLINFO | RTF_STATIC | RTF_REJECT | RTF_MPLS;

	if (sa->sa_family == AF_KEY)
		return;

	get_rtaddrs(rtm->rtm_addrs, sa, rti_info);

	mask = rti_info[RTAX_NETMASK];
	if ((sa = rti_info[RTAX_DST]) == NULL)
		return;

	p_sockaddr(sa, mask, rtm->rtm_flags, WID_DST(sa->sa_family));
	p_sockaddr(rti_info[RTAX_GATEWAY], NULL, RTF_HOST,
	    WID_GW(sa->sa_family));
	p_flags(rtm->rtm_flags & interesting, "%-6.6s ");
	printf("%6u %8llu ", rtm->rtm_rmx.rmx_refcnt,
	    rtm->rtm_rmx.rmx_pksent);
	if (rtm->rtm_rmx.rmx_mtu)
		printf("%6u ", rtm->rtm_rmx.rmx_mtu);
	else
		printf("%6s ", "-");
	putchar((rtm->rtm_rmx.rmx_locks & RTV_MTU) ? 'L' : ' ');
	printf(" %.16s", if_indextoname(rtm->rtm_index, ifbuf));
	putchar('\n');
}

/*
 * Print a pfkey/encap entry.
 */
void
p_pfkentry(struct sadb_msg *msg)
{
	struct sadb_address	*saddr;
	struct sadb_protocol	*sap, *saft;
	struct sockaddr		*sa, *mask;
	void			*headers[SADB_EXT_MAX + 1];

	bzero(headers, sizeof(headers));
	index_pfk(msg, headers);

	/* These are always set */
	saddr = headers[SADB_X_EXT_SRC_FLOW];
	sa = (struct sockaddr *)(saddr + 1);
	saddr = headers[SADB_X_EXT_SRC_MASK];
	mask = (struct sockaddr *)(saddr + 1);
	p_encap(sa, mask, WID_DST(sa->sa_family));

	/* These are always set, too. */
	saddr = headers[SADB_X_EXT_DST_FLOW];
	sa = (struct sockaddr *)(saddr + 1);
	saddr = headers[SADB_X_EXT_DST_MASK];
	mask = (struct sockaddr *)(saddr + 1);
	p_encap(sa, mask, WID_DST(sa->sa_family));

	/* Bypass and deny flows do not set SADB_EXT_ADDRESS_DST! */
	sap = headers[SADB_X_EXT_PROTOCOL];
	saft = headers[SADB_X_EXT_FLOW_TYPE];
	saddr = headers[SADB_EXT_ADDRESS_DST];
	if (saddr)
		sa = (struct sockaddr *)(saddr + 1);
	else
		sa = NULL;
	p_protocol(sap, sa, saft, msg->sadb_msg_satype);

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
p_protocol(struct sadb_protocol *sap, struct sockaddr *sa, struct sadb_protocol
    *saft, int proto)
{
	printf("%-6u", sap->sadb_protocol_proto);

	if (sa)
		p_sockaddr(sa, NULL, 0, -1);
	else
		printf("none");

	switch (proto) {
	case SADB_SATYPE_ESP:
		printf("/esp");
		break;
	case SADB_SATYPE_AH:
		printf("/ah");
		break;
	case SADB_X_SATYPE_IPCOMP:
		printf("/ipcomp");
		break;
	case SADB_X_SATYPE_IPIP:
		printf("/ipip");
		break;
	default:
		printf("/<unknown>");
	}

	switch(saft->sadb_protocol_proto) {
	case SADB_X_FLOW_TYPE_USE:
		printf("/use");
		break;
	case SADB_X_FLOW_TYPE_REQUIRE:
		printf("/require");
		break;
	case SADB_X_FLOW_TYPE_ACQUIRE:
		printf("/acquire");
		break;
	case SADB_X_FLOW_TYPE_DENY:
		printf("/deny");
		break;
	case SADB_X_FLOW_TYPE_BYPASS:
		printf("/bypass");
		break;
	case SADB_X_FLOW_TYPE_DONTACQ:
		printf("/dontacq");
		break;
	default:
		printf("/<unknown type>");
	}

	switch(saft->sadb_protocol_direction) {
	case IPSP_DIRECTION_IN:
		printf("/in");
		break;
	case IPSP_DIRECTION_OUT:
		printf("/out");
		break;
	default:
		printf("/<unknown>");
	}
}

void
p_sockaddr(struct sockaddr *sa, struct sockaddr *mask, int flags, int width)
{
	char *cp;

	switch (sa->sa_family) {
	case AF_INET6:
	    {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;

		in6_fillscopeid(sa6);
		if (flags & RTF_HOST)
			cp = routename((struct sockaddr *)sa6);
		else
			cp = netname((struct sockaddr *)sa6, mask);
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
			return("0.0.0.0");
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
		strncpy(line_show, "invalid", sizeof(line_show));

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
		snprintf(hbuf, sizeof(hbuf), "invalid");

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
