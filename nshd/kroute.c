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

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>
#include <sys/signal.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <paths.h>
#include "ip.h"
#define _WANT_SO_
#include "externs.h"
#include "facts.h"
#include "showfacts.h"
static struct	rt_metrics	rt_metrics;

/* declared in externs.h */
union	sockunion so_dst, so_gate, so_mask, so_ifp;
struct	rtmsg m_rtmsg;

int	rtm_addrs;
u_long	rtm_inits;

char	*mylink_ntoa(const struct sockaddr_dl *);


/*
 * caller must freertdump() if rtdump not NULL
 */
struct rtdump *getrtdump(int af, int flags, int tableid)
{
	size_t needed;
	int mib[7];
	struct rtdump *rtdump;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;	/* protocol */
	mib[3] = af;	/* wildcard address family */
	mib[4] = flags ? NET_RT_FLAGS : NET_RT_DUMP;
	mib[5] = flags;
	mib[6] = tableid;

	if ((rtdump = malloc(sizeof(struct rtdump))) == NULL) {
		printf("%% getrtdump: rtdump malloc: %s\n", strerror(errno));
		return NULL;
	}
	rtdump->buf = NULL;

	while (1) {
		char *p;
		if (sysctl(mib, 7, NULL, &needed, NULL, 0) < 0) {
			if (errno != ENOENT)
				printf("%% getrtdump: unable to get estimate: %s\n",
				    strerror(errno));
			return NULL;
		}
		if (needed == 0)
			break;
		if ((p = realloc(rtdump->buf, needed)) == NULL) {
			printf("%% getrtdump: realloc: %s\n", strerror(errno));
			freertdump(rtdump);
			return NULL;
		}
		rtdump->buf = p;
		if (sysctl(mib, 7, rtdump->buf, &needed, NULL, 0) < 0) {
			if (errno == ENOMEM)
				continue;
			printf("%% getrtdump: sysctl routing table: %s\n",
			    strerror(errno));
			freertdump(rtdump);
			return NULL;
		}
		rtdump->lim = rtdump->buf + needed;
		break;
	}
	if (rtdump->buf == NULL) {
		free(rtdump);
		return NULL;
	}

	return rtdump;
}

void
freertdump(struct rtdump *rtdump)
{
	free(rtdump->buf);
	free(rtdump);
}

/*
 * Purge entries in the routing table where the first two
 * sockaddrs match requested address families
 */
void
flushroutes(int af, int af2, int flush_verbose)
{
	int rlen, seqno, s;
	char *next;
	struct rt_msghdr *rtm;
	struct sockaddr *sa, *sa2;
	struct rtdump *rtdump;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		printf("%% Unable to open routing socket: %s\n",
		    strerror(errno));
		return;
	}

	shutdown(s, 0); /* Don't want to read back our messages */
	rtdump = getrtdump(af, 0, cli_rtable);
	if (rtdump == NULL) {
		close(s);
		return;
	}

	seqno = 0;
	for (next = rtdump->buf; next < rtdump->lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if ((rtm->rtm_flags & (RTF_GATEWAY|RTF_STATIC|RTF_LLINFO)) == 0)
			continue;
		if (verbose) {
			printf("\n%% Read message:\n");
			print_rtmsg(rtm);
		}
		if (af2 == AF_LINK) {
			if ((rtm->rtm_flags & RTF_LLINFO) == 0 ||
			    (rtm->rtm_flags & RTF_LOCAL))
				continue;
			if (rtm->rtm_addrs) {
				struct sockaddr_dl *sdl = NULL;
				char *cp;
				unsigned int i;

				cp = ((char *)rtm + rtm->rtm_hdrlen);
				for (i = 1; i && sdl == NULL; i <<= 1) {
					if ((i & rtm->rtm_addrs) == 0)
						continue;
					sa = (struct sockaddr *)cp;
					switch (i) {
					case RTA_IFP:
						sdl = (struct sockaddr_dl *)sa;
						break;
					default:
						break;
					}
					ADVANCE(cp, sa);
				}
				if (sdl) {
					switch (sdl->sdl_type) {
					case IFT_ETHER:
					case IFT_FDDI:
					case IFT_ISO88023:
					case IFT_ISO88024:
					case IFT_ISO88025:
					case IFT_CARP:
						break;
					default:
						continue;
					}
				}
			}
		}
		sa = (struct sockaddr *)((char *)rtm + rtm->rtm_hdrlen);
		sa2 = (struct sockaddr *)(ROUNDUP(sa->sa_len) + (char *)sa);
		if (sa->sa_family != af) {
			if (verbose) {
				printf("%% Ignoring message ");
				printf("(af %d requested, message ", af);
				printf("af %d)\n", sa->sa_family);
			}
			continue;
		}
		if (sa2->sa_family != af2) {
			if (verbose) {
				printf("%% Ignoring message ");
				printf("(af2 %d requested, message ", af);
				printf("af %d)\n", sa2->sa_family);
			}
			continue;
		}
		rtm->rtm_type = RTM_DELETE;
		rtm->rtm_seq = seqno;
		rlen = write(s, next, rtm->rtm_msglen);
		if (rlen < (int)rtm->rtm_msglen) {
			if (errno == ESRCH) {
				if (flush_verbose) {
					printf("%% No such route to delete:");
					print_addrs((char *)rtm +
					    rtm->rtm_hdrlen, rtm->rtm_addrs);
					putchar('\n');
					fflush(stdout);
				}
				seqno++;
				continue;
			}
			printf("%% Unable to write to routing socket: %s\n",
			    strerror(errno));
			break;
		}
		seqno++;
		if (verbose) {
			printf("\n%% Wrote message:\n");
			print_rtmsg(rtm);
		} else if (flush_verbose) {
			printf("%% %-20.20s ", routename(sa));
			printf("%-20.20s flushed\n", routename(sa2));
		}
	}
	if (verbose)
		printf("\n");
	if (!seqno)
		printf("%% No entires found to flush\n");
	else
		printf("%% %d routing table entr%s flushed\n", seqno,
		    seqno == 1 ? "y" : "ies");
	freertdump(rtdump);
	close(s);
	return;
}

static char hexlist[] = "0123456789abcdef";

/* print 00:00:00:00:00:00 style, not if:00.00.00.00.00.00 */
char *
mylink_ntoa(const struct sockaddr_dl *sdl)
{
	static char obuf[64];
	char *out = obuf;
	int i;
	u_char *in = (u_char *)LLADDR(sdl);
	u_char *inlim = in + sdl->sdl_alen;
	int firsttime = 1;

	if (sdl->sdl_nlen) {
		/* skip interface name */
		out += sdl->sdl_nlen;
	}
	while (in < inlim) {
		if (firsttime)
			firsttime = 0;
		else
			*out++ = ':';
		i = *in++;
		if (i > 0xf) {
			out[1] = hexlist[i & 0xf];
			i >>= 4;
			out[0] = hexlist[i];
			out += 2;
		} else
			*out++ = hexlist[i];
	}
	*out = 0;
	return (obuf);
}

int
prefixlen(int len, struct sockaddr_in6 *sin6)
{
	int q, r;

	q = len >> 3;
	r = len & 7;
	memset((void *)&sin6->sin6_addr, 0,
		sizeof(sin6->sin6_addr));
	if (q > 0)
		memset((void *)&sin6->sin6_addr, 0xff, q);
	if (r > 0)
		*((u_char *)&sin6->sin6_addr + q) = (0xff00 >> r) & 0xff;
	return len;
}

/* what an RTM_GET found, kept until the request is done */
static struct facts_value lookup_v[LK_NFIELDS];
static int		 lookup_kept;

/* what an RTM_GET found, or err if the kernel took no request */
static void
lookup_record(struct rt_msghdr *rtm, int err)
{
	struct facts_value	*v = lookup_v;
	struct sockaddr		*sa, *dst = NULL, *mask = NULL;
	struct sockaddr_rtlabel	*sr;
	static char		 gwname[IFNAMSIZ + 1], ifpname[IFNAMSIZ + 1];
	static char		 label[RTLABEL_LEN];
	char			*cp;
	int			 i;

	memset(lookup_v, 0, sizeof(lookup_v));
	lookup_kept = 1;
	facts_sockaddr(&v[LK_QUERY], &so_dst.sa);
	if (rtm == NULL)
		facts_u64(&v[LK_ERRNO], err);
	else if (rtm->rtm_errno)
		facts_u64(&v[LK_RTERRNO], rtm->rtm_errno);
	if (rtm == NULL || rtm->rtm_errno)
		return;

	cp = ((char *)rtm + rtm->rtm_hdrlen);
	for (i = 1; i && rtm->rtm_addrs; i <<= 1) {
		if ((i & rtm->rtm_addrs) == 0)
			continue;
		sa = (struct sockaddr *)cp;
		switch (i) {
		case RTA_DST:
			dst = sa;
			break;
		case RTA_GATEWAY:
			facts_sockaddr(&v[LK_GATEWAY], sa);
			facts_sdl(&v[LK_GWTYPE], &v[LK_GWNAME], gwname,
			    sizeof(gwname), sa);
			break;
		case RTA_NETMASK:
			mask = sa;
			break;
		case RTA_GENMASK:
			facts_sockaddr(&v[LK_GENMASK], sa);
			break;
		case RTA_IFP:
			facts_sockaddr(&v[LK_IFP], sa);
			facts_sdl(&v[LK_IFPTYPE], &v[LK_IFPNAME], ifpname,
			    sizeof(ifpname), sa);
			break;
		case RTA_IFA:
			facts_sockaddr(&v[LK_IFA], sa);
			break;
		case RTA_BRD:
			facts_sockaddr(&v[LK_BRD], sa);
			break;
		case RTA_LABEL:
			sr = (struct sockaddr_rtlabel *)sa;
			strlcpy(label, sr->sr_label, sizeof(label));
			facts_string(&v[LK_LABEL], label);
			break;
		}
		ADVANCE(cp, sa);
	}
	if (dst && mask)
		mask->sa_family = dst->sa_family;       /* XXX */
	facts_sockaddr(&v[LK_DST], dst);
	facts_sockaddr(&v[LK_MASK], mask);
	facts_u64(&v[LK_FLAGS], rtm->rtm_flags);
	facts_u64(&v[LK_ADDRS], rtm->rtm_addrs);
	facts_u64(&v[LK_MTU], rtm->rtm_rmx.rmx_mtu);
	facts_u64(&v[LK_HOPCOUNT], rtm->rtm_rmx.rmx_hopcount);
	if (rtm->rtm_rmx.rmx_expire)
		facts_i64(&v[LK_EXPIRE], rtm->rtm_rmx.rmx_expire - time(0));
	facts_u64(&v[LK_LOCKS], rtm->rtm_rmx.rmx_locks);
	facts_u64(&v[LK_INITS], rtm->rtm_inits);
}

/* the route the kernel would use in table for query, as facts */
int
lookup_facts(struct facts_out *o, char *query, int table)
{
	ip_t			 dest;
	struct rt_metrics	 metrics;
	int			 v = verbose;

	memset(&dest, 0, sizeof(dest));
	memset(&metrics, 0, sizeof(metrics));
	parse_ip_pfx(query, NO_NETMASK, &dest);	/* it says what is wrong */
	if (dest.family == 0)
		return (0);
	lookup_kept = 0;
	verbose = 0;	/* the request rtmsg() echoes is nsh's, not a fact */
	ip_route(&dest, NULL, RTM_GET, RTF_UP, table, metrics, 0);
	verbose = v;
	/* record it now that verbose is back, as nsh may render it at once */
	if (lookup_kept)
		return (facts_record(o, &kind_lookup, lookup_v));
	return (0);
}

/*
 * this function converts ip_t to sockaddr_in, sets up rtm_addrs based
 * on what the user/calling function supplied, and calls rtmsg()
 *
 * if destination bitlength is -1 then we ignore the netmask,
 * if bitlength is 0 then we make sure to set a zero netmask.
 *
 * if rtmsg returns -1 then errno is checked, if it returns something
 * that we know about then we try and give a sensible error message
 */
int
ip_route(ip_t *dest, ip_t *gate, u_short cmd, int flags, int tableid,
    struct rt_metrics metrics, int inits)
{
	int l;
	int len = dest->bitlen;
	static char line_kroute[MAXHOSTNAMELEN];

	rtm_addrs = 0, rtm_inits = inits;
	rt_metrics = metrics;
	memset(&so_dst, 0, sizeof (so_dst));
	memset(&so_gate, 0, sizeof (so_gate));
	memset(&so_mask, 0, sizeof (so_mask));
	memset(&so_ifp, 0, sizeof(so_ifp));

	if (cmd == RTM_GET) {
		so_ifp.sa.sa_family = AF_LINK;
		so_ifp.sa.sa_len = sizeof(struct sockaddr_dl);
		rtm_addrs |= RTA_IFP;
	}

	switch(dest->family) {
	case AF_INET:
		if (len == 32)
			flags |= RTF_HOST;
		so_dst.sin.sin_addr.s_addr = dest->addr.in.s_addr;
		so_dst.sin.sin_len = sizeof (struct sockaddr_in);
		so_dst.sin.sin_family = AF_INET;
		rtm_addrs |= RTA_DST;

		if (gate && (gate->family == dest->family)) {
			so_gate.sin.sin_addr.s_addr = gate->addr.in.s_addr;
			so_gate.sin.sin_len = sizeof (struct sockaddr_in);
			so_gate.sin.sin_family = AF_INET;
			rtm_addrs |= RTA_GATEWAY;
		}

		if (len >= 0) {
			so_mask.sin.sin_len = sizeof (struct sockaddr_in);
			so_mask.sin.sin_family = AF_INET;
			if (len == 0)
				so_mask.sin.sin_addr.s_addr = 0;
			else
				so_mask.sin.sin_addr.s_addr =
				    htonl(0xffffffff << (32 - len));
			rtm_addrs |= RTA_NETMASK;
		}
		break;

	case AF_INET6:
		if (len == 128)
			flags |= RTF_HOST;
		so_dst.sin6.sin6_addr = dest->addr.in6;
		so_dst.sin6.sin6_len = sizeof (struct sockaddr_in6);
		so_dst.sin6.sin6_family = AF_INET6;
		rtm_addrs |= RTA_DST;

		if (gate && (gate->family == dest->family)) {
			so_gate.sin6.sin6_addr = gate->addr.in6;
			if (!IN6_IS_ADDR_UNSPECIFIED(&so_gate.sin6.sin6_addr)) {
				so_gate.sin6.sin6_len = sizeof (struct sockaddr_in6);
				so_gate.sin6.sin6_family = AF_INET6;
				rtm_addrs |= RTA_GATEWAY;
			}
		}

		if (len >= 0) {
			so_mask.sin6.sin6_len = sizeof (struct sockaddr_in6);
			so_mask.sin6.sin6_family = AF_INET6;
			rtm_addrs |= RTA_NETMASK;
			prefixlen(len, &so_mask.sin6);
		}
		break;
	default:
		printf("%% ip_route: can't handle af %d\n", dest->family);
		return 1;
		break;
	}
	if ((l = rtmsg(cmd, flags, 0, 0, tableid)) < 0) {
		if (cmd == RTM_ADD && gate &&
		    (errno == ESRCH || errno == ENETUNREACH))
			printf("%% Gateway is unreachable: %s\n",
			    inet_ntop(gate->family, &gate->addr,
			    line_kroute, sizeof(line_kroute)));
		else if (cmd == RTM_GET)
			lookup_record(NULL, errno);
		else if (cmd == RTM_DELETE && errno == ESRCH)
			printf("%% No such route to delete: %s\n",
			    inet_ntop(dest->family, &dest->addr,
			    line_kroute, sizeof(line_kroute)));
		else if (cmd == RTM_ADD && errno == EEXIST)
			printf("%% Route already exists: %s\n",
			    inet_ntop(dest->family, &dest->addr,
			    line_kroute, sizeof(line_kroute)));
		else
			printf("%% ip_route: rtmsg: %s\n", strerror(errno));
		return 1;
	} else if (cmd == RTM_GET)
		/* ip_route is also used by 'show route' */
		lookup_record(&m_rtmsg.m_rtm, 0);
	return 0;
}

/*
 * handle routing messages for route get, route set, arp set
 * we return -1 when caller handles error message (set) or 0 when
 * there is no error or we displayed the error message (get)
 */
int
rtmsg(int cmd, int flags, int proxy, int export, int tableid)
{
	static int seq;
	struct rt_msghdr *rtm;
	char *cp = m_rtmsg.m_space;
	int l, s;

	rtm = &m_rtmsg.m_rtm;

	errno = 0;
	memset(&m_rtmsg, 0, sizeof(m_rtmsg));
	rtm->rtm_type = cmd;
	if(flags)
		rtm->rtm_flags = flags;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_tableid = tableid;
	rtm->rtm_hdrlen = sizeof(*rtm);
	rtm->rtm_seq = ++seq;
	rtm->rtm_addrs = rtm_addrs;
	rtm->rtm_rmx = rt_metrics;
	rtm->rtm_inits = rtm_inits;

	if (proxy) {
		if (export)
			so_dst.sinarp.sin_other = SIN_PROXY;
		else {
			rtm->rtm_addrs |= RTA_NETMASK;
			rtm->rtm_flags &= ~RTF_HOST;
		}
	}

#define NEXTADDR(w, u)							\
	if (rtm_addrs & (w)) {						\
		l = ROUNDUP(u.sa.sa_len); memcpy(cp, &(u), l); cp += l;	\
	}

	NEXTADDR(RTA_DST, so_dst);
	NEXTADDR(RTA_GATEWAY, so_gate);
	NEXTADDR(RTA_NETMASK, so_mask);
	NEXTADDR(RTA_IFP, so_ifp);

	rtm->rtm_msglen = l = cp - (char *)&m_rtmsg;
	if (verbose)
		print_rtmsg(rtm);

	if (candidate && cmd != RTM_GET)
		return route_cand(rtm);

	if ((s = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
		printf("%% Unable to open routing socket: %s\n",
		    strerror(errno));
		return 1;
	}

	if ((write(s, (char *)&m_rtmsg, l)) < 0) {
		/* on a write, the calling function will notify user of error */
		close(s);
		return (-1);
	}
	if (cmd == RTM_GET) {
		do {
			l = read(s, (char *)&m_rtmsg, sizeof(m_rtmsg));
		} while (l > 0 && (rtm->rtm_seq != seq || rtm->rtm_pid != pid));
		if (l < 0)
			/* on a get we notify the user */
			printf("%% rtmsg: read from routing socket: %s\n",
			    strerror(errno));
	}

	close(s);
	return (l);
}

int
rtnameserver(int argc, char *argv[], int tableid)
{
	struct rt_msghdr         rtm;
	struct sockaddr_rtdns    rtdns;
	struct iovec             iov[3];
	struct addrinfo	 hints, *res;
	struct in_addr           ns4[5];
	struct in6_addr          ns6[5];
	size_t			 ns4_count = 0, ns6_count = 0;
	long			 pad = 0;
	unsigned int		 if_index;
	int			 error = 0, iovcnt = 0, padlen, i, s;
	char			*if_name, buf[INET6_ADDRSTRLEN];

	if (argc <= 0) {
		printf("%% rtnameserver: no interface name provided\n");
		return (1);
	}

	if_name = *argv;
	argc--;
	argv++;

	if ((if_index = if_nametoindex(if_name)) == 0) {
		printf("%% rtnameserver: unknown interface: %s\n", if_name);
		return (1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

#ifndef nitems
#define nitems(_a)      (sizeof((_a)) / sizeof((_a)[0]))
#endif

	for (; argc > 0 && ns4_count + ns6_count < 5; argc--, argv++) {
		error = getaddrinfo(*argv, NULL, &hints, &res);
		if (error) {
			printf("%% rtnameserver: %s\n", gai_strerror(error));
			continue;
		}
		if (res == NULL) {
			printf("%% rtnameserver: %s: unknown\n", *argv);
			continue;
		}

		switch (res->ai_addr->sa_family) {
		case AF_INET:
			memcpy(&ns4[ns4_count++],
			    &((struct sockaddr_in *)res->ai_addr)->sin_addr,
			    sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(&ns6[ns6_count++],
			    &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
			    sizeof(struct in6_addr));
			break;
		default:
			break;
		}
		freeaddrinfo(res);
	}

	if (verbose) {
		for (i = 0; i < ns4_count; i++)
			printf("v4: %s\n", inet_ntop(AF_INET, &ns4[i], buf,
			    sizeof(buf)));
		for (i = 0; i < ns6_count; i++)
			printf("v6: %s\n", inet_ntop(AF_INET6, &ns6[i], buf,
			    sizeof(buf)));
	}

	memset(&rtm, 0, sizeof(rtm));

	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_type = RTM_PROPOSAL;
	rtm.rtm_msglen = sizeof(rtm);
	rtm.rtm_tableid = tableid;
	rtm.rtm_index = if_index;
	rtm.rtm_seq = 1;
	rtm.rtm_priority = RTP_PROPOSAL_STATIC;
	rtm.rtm_addrs = RTA_DNS;
	rtm.rtm_flags = RTF_UP;

	iov[iovcnt].iov_base = &rtm;
	iov[iovcnt++].iov_len = sizeof(rtm);

	iov[iovcnt].iov_base = &rtdns;
	iov[iovcnt++].iov_len = sizeof(rtdns);
	rtm.rtm_msglen += sizeof(rtdns);

	padlen = ROUNDUP(sizeof(rtdns)) - sizeof(rtdns);
	if (padlen > 0) {
		iov[iovcnt].iov_base = &pad;
		iov[iovcnt++].iov_len = padlen;
		rtm.rtm_msglen += padlen;
	}

	memset(&rtdns, 0, sizeof(rtdns));
	rtdns.sr_family = AF_INET;
	rtdns.sr_len = 2 + ns4_count * sizeof(struct in_addr);
	memcpy(rtdns.sr_dns, ns4, rtdns.sr_len - 2);

	s = socket(AF_ROUTE, SOCK_RAW, AF_UNSPEC);
	if (s == -1) {
		printf("%% rtnameserver: socket: %s\n", strerror(errno));
		return (1);
	}

	if (writev(s, iov, iovcnt) == -1) {
		printf("%% rtnameserver: failed to send routing message: %s\n",
		    strerror(errno));
		error = 1;
	}

	rtm.rtm_seq++;

	memset(&rtdns, 0, sizeof(rtdns));
	rtdns.sr_family = AF_INET6;
	rtdns.sr_len = 2 + ns6_count * sizeof(struct in6_addr);
	memcpy(rtdns.sr_dns, ns6, rtdns.sr_len - 2);

	if (writev(s, iov, iovcnt) == -1) {
		printf("%% rtnameserver: failed to send routing message: %s\n",
		    strerror(errno));
		error = 1;
	}

	close(s);
	return (error);
}
