/* $nsh: routepr.c,v 1.9 2003/09/18 19:44:23 chris Exp $ */
/* From: $OpenBSD: /usr/src/usr.bin/netstat/route.c,v 1.45 2002/02/16 21:27:50 millert Exp $ */

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
#define _KERNEL
#include <net/route.h>
#undef _KERNEL
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef IPX
#include <netipx/ipx.h>
#endif

#ifdef ATALK
#include <netatalk/at.h>
#endif

#include <sys/sysctl.h>

#include <arpa/inet.h>

#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef INET
#define INET
#endif

#include <sys/socket.h>
#include <netinet/ip_ipsp.h>

#include "externs.h"

#define kget(p, d) (kread((u_long)(p), (char *)&(d), sizeof (d)))

char *mylink_ntoa(const struct sockaddr_dl *);

struct radix_node_head *rt_tables[AF_MAX+1];

/*
 * Definitions for showing gateway flags.
 */
struct bits {
	short	b_mask;
	char	b_val;
} bits[] = {
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
	{ 0, 0 }
};

static union {
	struct		sockaddr u_sa;
	u_int32_t	u_data[64];
	int		u_dummy;	/* force word-alignment */
} pt_u;

int	do_rtent = 0;
struct	rtentry rtentry;
struct	radix_node rnode;
struct	radix_mask rmask;

char	*routename(in_addr_t);
char	*netname(in_addr_t, in_addr_t);
#ifdef IPX
char	*ipx_print(struct sockaddr *);
#endif
void	routepr(u_long, int);
#ifdef IPX
void	upHex(char *);
#endif

static struct sockaddr *kgetsa(struct sockaddr *);
static void p_tree(struct radix_node *);
static void p_sockaddr(struct sockaddr *, struct sockaddr *, int, int);
static void p_flags(int, char *);
static void p_rtentry(struct rtentry *);
static void encap_print(struct rtentry *);
static void pr_family(int);
static void pr_rthdr(int);
static void pr_encaphdr(void);

/*
 * Print routing tables.
 */
void
routepr(rtree, af)
	u_long rtree;
	int af;
{
	struct radix_node_head *rnh, head;
	int i;

	if (rtree == 0) {
		printf("%% routepr: rt_tables: symbol not in namelist\n");
		return;
	}

	printf("Flags: U - up, G - gateway, H - host, L - link layer, R - reject (unreachable),\n");
	printf("       D - dynamic, S - static\n");

	kget(rtree, rt_tables);
	for (i = 0; i <= AF_MAX; i++) {
		if ((rnh = rt_tables[i]) == 0)
			continue;
		kget(rnh, head);
		if (af == AF_UNSPEC || af == i) {
			pr_family(i);
			do_rtent = 1;
			if (i != PF_KEY)
				pr_rthdr(i);
			else
				pr_encaphdr();
			p_tree(head.rnh_treetop);
		}
	}
}

/*
 * Print address family header before a section of the routing table.
 */
void
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
#endif
	case AF_NS:
		afname = "XNS";
		break;
	case AF_IPX:
		afname = "IPX";
		break;
	case AF_ISO:
		afname = "ISO";
		break;
	case AF_CCITT:
		afname = "X.25";
		break;
	case PF_KEY:
		afname = "Encap";
		break;
	case AF_APPLETALK:
		afname = "AppleTalk";
		break;
	default:
		afname = NULL;
		break;
	}
	if (afname)
		printf("\n%% %s routing table:\n", afname);
	else
		printf("\n%% Protocol Family %d:\n", af);
}

/* column widths; each followed by one space */
#ifndef INET6
#define	WID_DST(af)	18	/* width of destination column */
#define	WID_GW(af)	18	/* width of gateway column */
#else
/* width of destination/gateway column */
#ifdef KAME_SCOPEID
/* strlen("fe80::aaaa:bbbb:cccc:dddd@gif0") == 30, strlen("/128") == 4 */
#define	WID_DST(af)	((af) == AF_INET6 ? 34 : 18)
#define	WID_GW(af)	((af) == AF_INET6 ? 30 : 18)
#else
/* strlen("fe80::aaaa:bbbb:cccc:dddd") == 25, strlen("/128") == 4 */
#define	WID_DST(af)	((af) == AF_INET6 ? 29 : 18)
#define	WID_GW(af)	((af) == AF_INET6 ? 25 : 18)
#endif
#endif /* INET6 */

/*
 * Print header for routing table columns.
 */
void
pr_rthdr(af)
	int af;
{

	printf("%-*.*s %-*.*s %-6.6s  %6.6s  %6.7s %6.6s  %s\n",
		WID_DST(af), WID_DST(af), "Destination",
		WID_GW(af), WID_GW(af), "Gateway",
		"Flags", "Refs", "Packets", "Mtu", "Interface");
}

/*
 * Print header for PF_KEY entries.
 */
void
pr_encaphdr()
{
	printf("%-18s %-5s %-18s %-5s %-5s %-22s\n",
	    "Source", "Port", "Destination",
	    "Port", "Proto", "SA(Address/Proto/Type/Direction)");
}

static struct sockaddr *
kgetsa(dst)
	struct sockaddr *dst;
{

	kget(dst, pt_u.u_sa);
	if (pt_u.u_sa.sa_len > sizeof (pt_u.u_sa))
		kread((u_long)dst, (char *)pt_u.u_data, pt_u.u_sa.sa_len);
	return (&pt_u.u_sa);
}

static void
p_tree(rn)
	struct radix_node *rn;
{

again:
	kget(rn, rnode);
	if (rnode.rn_b < 0) {
		if (rnode.rn_flags & RNF_ROOT) {
		} else if (do_rtent) {
			kget(rn, rtentry);
			p_rtentry(&rtentry);
		} else {
			p_sockaddr(kgetsa((struct sockaddr *)rnode.rn_key),
			    0, 0, 44);
			putchar('\n');
		}
		if ((rn = rnode.rn_dupedkey))
			goto again;
	} else {
		rn = rnode.rn_r;
		p_tree(rnode.rn_l);
		p_tree(rn);
	}
}

char	nbuf[25];

static void
p_sockaddr(sa, mask, flags, width)
	struct sockaddr *sa, *mask;
	int flags, width;
{
	char workbuf[128], *cplim;
	char *cp = workbuf;
	int n;

	switch (sa->sa_family) {
	case AF_INET:
	    {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;
		struct sockaddr_in *msin = (struct sockaddr_in *)mask;

		cp = (flags & RTF_HOST) || mask == NULL ?
		    routename(sin->sin_addr.s_addr) :
		    netname(sin->sin_addr.s_addr, msin->sin_addr.s_addr);

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
		    sa6->sin6_scope_id = (u_int32_t)ntohs(*(u_short *)&in6->s6_addr[2]);
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

#ifdef IPX
	case AF_IPX:
		cp = ipx_print(sa);
		break;
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
				if (n == -1)	/* What else to do ? */
				  continue;
				if (n >= workbuf + sizeof (workbuf) - cp)
					n = workbuf + sizeof (workbuf) - cp - 1;
				cp += n;
			}
			cp = workbuf;
			break;
		    }
		default:
			cp = (char *)mylink_ntoa(sdl);
			break;
		}
		break;
	    }

#ifdef ATALK
	case AF_APPLETALK:
	    {
		/* XXX could do better */
		cp = atalk_print(sa,11);
		break;
	    }
#endif
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
	else
		printf("%-*s ", width, cp);
}

static void
p_flags(f, format)
	int f;
	char *format;
{
	char name[33], *flags;
	struct bits *p = bits;

	for (flags = name; p->b_mask; p++)
		if (p->b_mask & f)
			*flags++ = p->b_val;
	*flags = '\0';
	printf(format, name);
}

static void
p_rtentry(rt)
	struct rtentry *rt;
{
	static struct ifnet ifnet, *lastif;
	struct sockaddr_storage sock1, sock2;
	struct sockaddr *sa = (struct sockaddr *)&sock1;
	struct sockaddr *mask = (struct sockaddr *)&sock2;
	int interesting = RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_DYNAMIC | RTF_LLINFO | RTF_STATIC | RTF_REJECT;
	
	bcopy(kgetsa(rt_key(rt)), sa, sizeof(struct sockaddr));
	if (sa->sa_len > sizeof(struct sockaddr))
		bcopy(kgetsa(rt_key(rt)), sa, sa->sa_len);

	if (sa->sa_family == PF_KEY) {
		encap_print(rt);
		return;
	}

	if (rt_mask(rt)) {
		bcopy(kgetsa(rt_mask(rt)), mask, sizeof(struct sockaddr));
		if (sa->sa_len > sizeof(struct sockaddr))
			bcopy(kgetsa(rt_mask(rt)), mask, sa->sa_len);
	} else
		mask = 0;
	
	p_sockaddr(sa, mask, rt->rt_flags, WID_DST(sa->sa_family));
	p_sockaddr(kgetsa(rt->rt_gateway), 0, RTF_HOST, WID_GW(sa->sa_family));
	p_flags(rt->rt_flags & interesting, "%-6.6s ");
	printf("%6d %9ld ", rt->rt_refcnt, rt->rt_use);
	if (rt->rt_rmx.rmx_mtu)
		printf("%6ld ", rt->rt_rmx.rmx_mtu);
	else
		printf("%6s ", "-");
	putchar((rt->rt_rmx.rmx_locks & RTV_MTU) ? 'L' : ' ');
	if (rt->rt_ifp) {
		if (rt->rt_ifp != lastif) {
			kget(rt->rt_ifp, ifnet);
			lastif = rt->rt_ifp;
		}
		printf(" %.16s%s", ifnet.if_xname,
			rt->rt_nodes[0].rn_dupedkey ? " =>" : "");
	}
	putchar('\n');
/*
	if (verbose) {
		printf("\texpire   %10lu%c  recvpipe %10ld%c  "
		       "sendpipe %10ld%c\n",
			rt->rt_rmx.rmx_expire,
			(rt->rt_rmx.rmx_locks & RTV_EXPIRE) ? 'L' : ' ',
			rt->rt_rmx.rmx_recvpipe,
			(rt->rt_rmx.rmx_locks & RTV_RPIPE) ? 'L' : ' ',
			rt->rt_rmx.rmx_sendpipe,
			(rt->rt_rmx.rmx_locks & RTV_SPIPE) ? 'L' : ' ');
		printf("\tssthresh %10lu%c  rtt      %10ld%c  "
		       "rttvar   %10ld%c\n",
			rt->rt_rmx.rmx_ssthresh,
			(rt->rt_rmx.rmx_locks & RTV_SSTHRESH) ? 'L' : ' ',
			rt->rt_rmx.rmx_rtt,
			(rt->rt_rmx.rmx_locks & RTV_RTT) ? 'L' : ' ',
			rt->rt_rmx.rmx_rttvar,
			(rt->rt_rmx.rmx_locks & RTV_RTTVAR) ? 'L' : ' ');
	}	
*/
}

char *
routename(in)
	in_addr_t in;
{
	char *cp;
	static char line[MAXHOSTNAMELEN];
	static char domain[MAXHOSTNAMELEN];
	static int first = 1;

	if (first) {
		first = 0;
		if (gethostname(domain, sizeof domain) == 0 &&
		    (cp = strchr(domain, '.')))
			(void) strlcpy(domain, cp + 1, sizeof(domain));
		else
			domain[0] = '\0';
	}
	cp = 0;
	if (cp) {
		strlcpy(line, cp, sizeof(line));
	} else {
#define C(x)	((x) & 0xff)
		in = ntohl(in);
		snprintf(line, sizeof line, "%u.%u.%u.%u",
		    C(in >> 24), C(in >> 16), C(in >> 8), C(in));
	}
	return (line);
}

/*
 * Return the name of the network whose address is given.
 * The address is assumed to be that of a net or subnet, not a host.
 */
char *
netname(in, mask)
	in_addr_t in, mask;
{
	char *cp = 0;
	static char line[MAXHOSTNAMELEN];
	int mbits;

	in = ntohl(in);
	mask = ntohl(mask);
	mbits = mask ? 33 - ffs(mask) : 0;
	if (cp) {
		strlcpy(line, cp, sizeof(line));
	} else
		snprintf(line, sizeof line, "%u.%u.%u.%u/%d", C(in >> 24),
			C(in >> 16), C(in >> 8), C(in), mbits);
	return (line);
}

#undef C

#ifdef INET6
char *
netname6(sa6, mask)
	struct sockaddr_in6 *sa6;
	struct in6_addr *mask;
{
	static char line[MAXHOSTNAMELEN + 1];
	struct sockaddr_in6 sin6;
	u_char *p;
	u_char *lim;
	int masklen, final = 0, illegal = 0;
	int i;
	char hbuf[NI_MAXHOST];
#ifdef NI_WITHSCOPEID
	int flag = NI_WITHSCOPEID;
#else
	int flag = 0;
#endif
	int error;

	sin6 = *sa6;
	
	masklen = 0;
	lim = (u_char *)(mask + 1);
	i = 0;
	if (mask) {
		for (p = (u_char *)mask; p < lim; p++) {
			if (final && *p) {
				illegal++;
				sin6.sin6_addr.s6_addr[i++] = 0x00;
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

			if (!illegal)
				sin6.sin6_addr.s6_addr[i++] &= *p;
			else
				sin6.sin6_addr.s6_addr[i++] = 0x00;
		}
	} else
		masklen = 128;

	if (masklen == 0 && IN6_IS_ADDR_UNSPECIFIED(&sin6.sin6_addr))
		return("default");

	if (illegal)
		printf("%% illegal prefixlen\n");

	flag |= NI_NUMERICHOST;
	error = getnameinfo((struct sockaddr *)&sin6, sin6.sin6_len,
	    hbuf, sizeof(hbuf), NULL, 0, flag);
	if (error)
		snprintf(hbuf, sizeof(hbuf), "invalid");

	snprintf(line, sizeof(line), "%s/%d", hbuf, masklen);
	return line;
}

char *
routename6(sa6)
	struct sockaddr_in6 *sa6;
{
	static char line[NI_MAXHOST];
#ifdef NI_WITHSCOPEID
	const int niflag = NI_NUMERICHOST | NI_WITHSCOPEID;
#else
	const int niflag = NI_NUMERICHOST;
#endif
	if (getnameinfo((struct sockaddr *)sa6, sa6->sin6_len,
			line, sizeof(line), NULL, 0, niflag) != 0)
		strlcpy(line, "", sizeof(line));
	return line;
}
#endif /*INET6*/

#ifdef IPX
u_short ipx_nullh[] = {0,0,0};
u_short ipx_bh[] = {0xffff,0xffff,0xffff};

char *
ipx_print(sa)
	struct sockaddr *sa;
{
	struct sockaddr_ipx *sipx = (struct sockaddr_ipx*)sa;
	struct ipx_addr work;
	union { union ipx_net net_e; u_long long_e; } net;
	in_port_t port;
	static char mybuf[50], cport[10], chost[25];
	char *host = "";
	char *q;

	work = sipx->sipx_addr;
	port = ntohs(work.ipx_port);
	work.ipx_port = 0;
	net.net_e = work.ipx_net;
	if (ipx_nullhost(work) && net.long_e == 0) {
		if (port != 0) {
			snprintf(mybuf, sizeof mybuf, "*.%xH", port);
			upHex(mybuf);
		} else
			snprintf(mybuf, sizeof mybuf, "*.*");
		return (mybuf);
	}

	if (bcmp(ipx_bh, work.ipx_host.c_host, 6) == 0) {
		host = "any";
	} else if (bcmp(ipx_nullh, work.ipx_host.c_host, 6) == 0) {
		host = "*";
	} else {
		q = work.ipx_host.c_host;
		snprintf(chost, sizeof chost, "%02x:%02x:%02x:%02x:%02x:%02x",
		    q[0], q[1], q[2], q[3], q[4], q[5]);
		host = chost;
	}
	if (port)
		snprintf(cport, sizeof cport, ".%xH", htons(port));
	else
		*cport = 0;

	snprintf(mybuf, sizeof mybuf, "%xH.%s%s", ntohl(net.long_e),
	    host, cport);
	upHex(mybuf);
	return(mybuf);
}

char *
ipx_phost(sa)
	struct sockaddr *sa;
{
	struct sockaddr_ipx *sipx = (struct sockaddr_ipx *)sa;
	struct sockaddr_ipx work;
	static union ipx_net ipx_zeronet;
	char *p;

	work = *sipx;
	work.sipx_addr.ipx_port = 0;
	work.sipx_addr.ipx_net = ipx_zeronet;

	p = ipx_print((struct sockaddr *)&work);
	if (strncmp("0H.", p, 3) == 0)
		p += 3;
	return(p);
}
#endif

static void
encap_print(rt)
	struct rtentry *rt;
{
	struct sockaddr_encap sen1, sen2, sen3;
	struct ipsec_policy ipo;

#ifdef INET6
	struct sockaddr_in6 s61, s62;
	char ip6addr[64];
#endif /* INET6 */

	bcopy(kgetsa(rt_key(rt)), &sen1, sizeof(sen1));
	bcopy(kgetsa(rt_mask(rt)), &sen2, sizeof(sen2));
	bcopy(kgetsa(rt->rt_gateway), &sen3, sizeof(sen3));

	if (sen1.sen_type == SENT_IP4)
	{
	    printf("%-18s %-5u ", netname(sen1.sen_ip_src.s_addr,
					  sen2.sen_ip_src.s_addr),
		   ntohs(sen1.sen_sport));

	    printf("%-18s %-5u %-5u ", netname(sen1.sen_ip_dst.s_addr,
					       sen2.sen_ip_dst.s_addr),
		   ntohs(sen1.sen_dport), sen1.sen_proto);
	}

#ifdef INET6
	if (sen1.sen_type == SENT_IP6)
	{
	    bzero(&s61, sizeof(s61));
	    bzero(&s62, sizeof(s62));
	    s61.sin6_family = s62.sin6_family = AF_INET6;
	    s61.sin6_len = s62.sin6_len = sizeof(s61);
	    bcopy(&sen1.sen_ip6_src, &s61.sin6_addr, sizeof(struct in6_addr));
	    bcopy(&sen2.sen_ip6_src, &s62.sin6_addr, sizeof(struct in6_addr));

	    printf("%-42s %-5u ", netname6(&s61, &s62.sin6_addr),
		   ntohs(sen1.sen_ip6_sport));

	    bzero(&s61, sizeof(s61));
	    bzero(&s62, sizeof(s62));
	    s61.sin6_family = s62.sin6_family = AF_INET6;
	    s61.sin6_len = s62.sin6_len = sizeof(s61);
	    bcopy(&sen1.sen_ip6_dst, &s61.sin6_addr, sizeof(struct in6_addr));
	    bcopy(&sen2.sen_ip6_dst, &s62.sin6_addr, sizeof(struct in6_addr));

	    printf("%-42s %-5u %-5u ", netname6(&s61, &s62.sin6_addr),
		   ntohs(sen1.sen_ip6_dport), sen1.sen_ip6_proto);
	}
#endif /* INET6 */

	if (sen3.sen_type == SENT_IPSP)
	{
	    char hostn[NI_MAXHOST];

	    kget(sen3.sen_ipsp, ipo);

	    if (getnameinfo(&ipo.ipo_dst.sa, ipo.ipo_dst.sa.sa_len,
	        hostn, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0);
	 	    strlcpy(hostn, "none", NI_MAXHOST);

	    printf("%s", hostn);

	    printf("/%-u", ipo.ipo_sproto);

	    switch (ipo.ipo_type)
	    {
		case IPSP_IPSEC_REQUIRE:
		    printf("/require");
		    break;

		case IPSP_IPSEC_ACQUIRE:
		    printf("/acquire");
		    break;

		case IPSP_IPSEC_USE:
		    printf("/use");
		    break;

		case IPSP_IPSEC_DONTACQ:
		    printf("/dontacq");
		    break;

		case IPSP_PERMIT:
		    printf("/permit");
		    break;

		case IPSP_DENY:
		    printf("/deny");
		    break;

		default:
		    printf("/<unknown type!>");
	    }

	    if ((ipo.ipo_addr.sen_type == SENT_IP4 &&
		 ipo.ipo_addr.sen_direction == IPSP_DIRECTION_IN) ||
		(ipo.ipo_addr.sen_type == SENT_IP6 &&
		 ipo.ipo_addr.sen_ip6_direction == IPSP_DIRECTION_IN))
	      printf("/in\n");
	    else
	      if ((ipo.ipo_addr.sen_type == SENT_IP4 &&
		   ipo.ipo_addr.sen_direction == IPSP_DIRECTION_OUT) ||
		  (ipo.ipo_addr.sen_type == SENT_IP6 &&
		   ipo.ipo_addr.sen_ip6_direction == IPSP_DIRECTION_OUT))
		printf("/out\n");
	      else
		printf("/<unknown>\n");
	}
}

#ifdef IPX
void
upHex(p0)
	char *p0;
{
	char *p = p0;
	for (; *p; p++) switch (*p) {

	case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
		*p += ('A' - 'a');
	}
}
#endif

