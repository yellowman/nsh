/* From: $OpenBSD: show.c,v 1.20 2001/07/07 18:26:20 deraadt Exp $ */

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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netns/ns.h>
#include <netinet/ip_ipsp.h>
#include <arpa/inet.h>

#include <sys/sysctl.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "externs.h"

#define WID_DST		19	/* width of destination column */
#define WID_GW		18	/* width of gateway column */

/*
 * Definitions for showing gateway flags.
 */
struct bits {
	short	b_mask;
	char	b_val;
};

static int old_af;

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
	{ 0 }
};

void p_sockaddr(struct sockaddr *, struct sockaddr *, int, int);
static void p_rtentry(struct rt_msghdr *);
static void p_flags(int, char *);
static void pr_rthdr(void);
static void pr_family(int);

/*
 * Print routing tables.
 */
int
show(af)
	int af;
{
	struct rt_msghdr *rtm;
	char *buf = NULL, *next, *lim = NULL;
	size_t needed;
	int mib[6];
        struct sockaddr *sa;

	old_af = 0;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = 0;
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)	{
		perror("%% route-sysctl-estimate");
		return 1;
	}

	if (needed > 0) {
		if ((buf = malloc(needed)) == 0) {
			printf("%% show: out of space\r\n");
			return 1;
		}
		if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
			perror("%% sysctl of routing table");
			free(buf);
			return 1;
		}
		lim  = buf + needed;
	}

	if (!verbose) {
		printf("Flags: U - up, G - gateway, H - host, L - link layer, R - reject (unreachable),\r\n");
		printf("       D - dynamic, S - static\r\n\r\n");
	}

	if (buf) {
		for (next = buf; next < lim; next += rtm->rtm_msglen) {
			rtm = (struct rt_msghdr *)next;
			sa = (struct sockaddr *)(rtm + 1);
			if (af && sa->sa_family != af)
				continue;
			if (verbose)
				print_rtmsg(rtm,rtm->rtm_msglen);
			else
				p_rtentry(rtm);
		}
		free(buf);
	}
}

/*
 * Print header for routing table columns.
 */
static void
pr_rthdr()
{
	printf("%-*.*s %-*.*s %-6.6s %10s\n",
	    WID_DST, WID_DST, "Destination",
	    WID_GW, WID_GW, "Gateway",
	    "Flags", "Packets");
}

/*
 * Print a routing table entry.
 */

static void
p_rtentry(rtm)
	struct rt_msghdr *rtm;
{
	struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	in_addr_t mask;
	int af, interesting = RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_DYNAMIC | RTF_LLINFO | RTF_STATIC | RTF_REJECT;

	af = sa->sa_family;
	if (old_af != af) {
		old_af = af;
		pr_family(af);
		pr_rthdr();
	}

	if (rtm->rtm_addrs == RTA_DST)
		p_sockaddr(sa, 0, 0, 36);
	else {
		if (af = AF_INET)
			p_sockaddr(sa, (struct sockaddr *)sin, rtm->rtm_flags,
			    WID_DST);
		else
			p_sockaddr(sa, 0, rtm->rtm_flags, WID_DST);
		sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) + (char *)sa);
		p_sockaddr(sa, 0, 0, WID_GW);
	}
	p_flags(rtm->rtm_flags & interesting, "%-6.6s ");
	printf("%10lu\r\n", (int)rtm->rtm_rmx.rmx_pksent);
}

/*
static void
p_rtentry(rtm)
	struct rt_msghdr *rtm;
{
	struct sockaddr *dst = NULL, *gate = NULL, *mask = NULL;
	struct sockaddr_dl *ifp = NULL;
	struct sockaddr *sa;
	char *cp, dst_str[32];
	int i, af = 0, interesting = RTF_UP | RTF_GATEWAY | RTF_HOST;
	int width = 18, mbits, addr;

	if (rtm->rtm_version != RTM_VERSION) {
		printf("%% routing message verison %d not understood\r\n",
		    rtm->rtm_version);
		return;
	}

	if (rtm->rtm_errno) {
		printf("%% RTM_GET: %s (errno %d)\r\n", strerror(rtm->rtm_errno),
		    rtm->rtm_errno);
		return;
	}
	cp = ((char *)(rtm + 1));
	if (rtm->rtm_addrs)
		for (i = 1; i; i <<= 1)
			if (i & rtm->rtm_addrs) {
				sa = (struct sockaddr *)cp;
				switch (i) {
				case RTA_DST:
					dst = sa;
					break;
				case RTA_GATEWAY:
					gate = sa;
					break;
				case RTA_NETMASK:
					mask = sa;
					break;
				case RTA_IFP:
					if (sa->sa_family == AF_LINK &&
					   ((struct sockaddr_dl *)sa)->sdl_nlen)
						ifp = (struct sockaddr_dl *)sa;
					break;
				}
				ADVANCE(cp, sa);
			}

	if (!(dst && mask))
		return;

	af = sa->sa_family;
	if (old_af != af) {
		old_af = af;
		pr_family(af);
	}

	mask->sa_family = dst->sa_family;

	addr = ntohl(((struct sockaddr_in *)mask)->sin_addr.s_addr);

	printf("addr %d\n",addr);
	mbits = addr ? 33 - ffs(addr) : 0;

	snprintf(dst_str, sizeof(dst_str), "%s/%d", routename(dst), mbits);

	(void)printf("%-*s", width, dst_str);
	if (gate && rtm->rtm_flags & RTF_GATEWAY)
		(void)printf("%-*s", width, routename(gate));
	else
		(void)printf("%-*s", width, ifp->sdl_data);
	if (ifp)
		(void)printf("(%-*.*s) ", 6,
		    ifp->sdl_nlen, ifp->sdl_data);
	p_flags(rtm->rtm_flags & interesting, "%-6.6s ");
	printf("%8d \r\n", (int)rtm->rtm_rmx.rmx_mtu);
}
*/

/*
 * Print address family header before a section of the routing table.
 */
static void
pr_family(af)
	int af;
{
	char *afname;

	switch (af) {
	case AF_INET:
		afname = "IPv4";
		break;
#ifdef INET6
	case AF_INET6:
		afname = "IPv6";
		break;
#endif /* INET6 */
	default:
		afname = NULL;
		break;
	}

	if (afname)
		printf("%% %s routing table:\r\n", afname);
	else
		printf("%% Protocol Family %d:\r\n", af);
}

void
p_sockaddr(sa, mask, flags, width)
	struct sockaddr *sa, *mask;
	int flags, width;
{
	char workbuf[128], *cplim;
	char *cp = workbuf;
	size_t n;

	switch (sa->sa_family) {
	case AF_INET:
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;
		struct sockaddr_in *msin = (struct sockaddr_in *)mask;

		/*cp = (sin->sin_addr.s_addr == 0) ? "default" :*/
		cp = ((flags & RTF_HOST) || mask == NULL ?
		    routename(sa) :
		    netname(sin->sin_addr.s_addr, msin->sin_addr.s_addr));
		break;
	}

#ifdef INET6
	case AF_INET6:
	{
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
#ifdef KAME_SCOPEID
		struct in6_addr *in6 = &sa6->sin6_addr;

		/*
		 * XXX: This is a special workaround for KAME kernels.
		 * sin6_scope_id field of SA should be set in the future.
		 */
		if (IN6_IS_ADDR_LINKLOCAL(in6) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(in6)) {
			/* XXX: override is ok? */
			sa6->sin6_scope_id =
			    (u_int32_t)ntohs(*(u_short *)&in6->s6_addr[2]);
			*(u_short *)&in6->s6_addr[2] = 0;
		}
#endif

		if (flags & RTF_HOST)
			cp = routename6(sa6);
		else if (mask) {
			cp = netname6(sa6,
			    &((struct sockaddr_in6 *)mask)->sin6_addr);
		} else
			cp = netname6(sa6, NULL);
		break;
	}
#endif

	case AF_LINK:
	{
		struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;

		if (sdl->sdl_nlen == 0 && sdl->sdl_alen == 0 &&
		    sdl->sdl_slen == 0)
			(void) snprintf(workbuf, sizeof workbuf,
			    "link#%d", sdl->sdl_index);
		else switch (sdl->sdl_type) {
			case IFT_ETHER:
			{
				int i;
				u_char *lla = (u_char *)sdl->sdl_data +
				    sdl->sdl_nlen;

				cplim = "";
				for (i = 0; i < sdl->sdl_alen; i++, lla++) {
					n = snprintf(cp,
					    workbuf + sizeof (workbuf) - cp,
					    "%s%x", cplim, *lla);
					cplim = ":";
					if (n == -1)    /* What else to do ? */
						continue;
					if (n >= workbuf +
					    sizeof (workbuf) - cp)
						n = workbuf +
						    sizeof (workbuf) - cp - 1;
					cp += n;
				}
				cp = workbuf;
				break;
			}
			default:
				cp = link_ntoa(sdl);
			break;
		}
		break;
	}

	default:
	{
		u_char *s = (u_char *)sa->sa_data, *slim;

		slim = sa->sa_len + (u_char *) sa;
		cplim = cp + sizeof(workbuf) - 6;
		n = snprintf(cp, cplim - cp, "(%d)", sa->sa_family);
		if (n >= cplim - cp)
			n = cplim - cp - 1;
		if (n > 0)
			cp += n;
		while (s < slim && cp < cplim) {
			n = snprintf(cp, workbuf + sizeof (workbuf) - cp,
			    " %02x", *s++);
			if (n >= workbuf + sizeof (workbuf) - cp)
				n = workbuf + sizeof (workbuf) - cp - 1;
			if (n > 0)
				cp += n;
			if (s < slim) {
				n = snprintf(cp,
				    workbuf + sizeof (workbuf) - cp,
				    "%02x", *s++);
				if (n >= workbuf + sizeof (workbuf) - cp)
					n = workbuf + sizeof (workbuf) - cp - 1;
				if (n > 0)
					cp += n;
			}
		}
		cp = workbuf;
	 }
	}
	if (width < 0 )
		printf("%s ", cp);
	else {
		if (nflag)
			printf("%-*s ", width, cp);
		else
			printf("%-*.*s ", width, width, cp);
	}
}

static void
p_flags(f, format)
	int f;
	char *format;
{
	char name[33], *flags;
	const struct bits *p = bits;

	for (flags = name; p->b_mask && flags < &name[sizeof name-2]; p++)
		if (p->b_mask & f)
			*flags++ = p->b_val;
	*flags = '\0';
	printf(format, name);
}

