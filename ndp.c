/*	$OpenBSD: ndp.c,v 1.107 2022/12/28 21:30:17 jmc Exp $	*/
/*	$KAME: ndp.c,v 1.101 2002/07/17 08:46:33 itojun Exp $	*/

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
 * ndp - display, set, delete and flush neighbor cache
 */


#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>

#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <err.h>
#include "externs.h"

/* packing rule for routing socket */
#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

static int tflag;
static int rtsock = -1;
static int repeat = 0;

char host_buf[NI_MAXHOST];		/* getnameinfo() */
char ifix_buf[IFNAMSIZ];		/* if_indextoname() */

static int getsocket(void);
int parse_host(const char *, struct sockaddr_in6 *);
int ndpset(int, char **);
void ndpget(const char *);
int ndpdelete(const char *);
void ndpdump(struct sockaddr_in6 *, int);
static struct in6_nbrinfo *getnbrinfo(struct in6_addr *, int, int);
int ndp_ether_aton(const char *, u_char *);
int rtmsg_ndp(int);
int rtget_ndp(struct sockaddr_in6 **, struct sockaddr_dl **);

static int
getsocket(void)
{
	socklen_t len = sizeof(cli_rtable);

	if (rtsock >= 0)
		return rtsock;
	rtsock = socket(AF_ROUTE, SOCK_RAW, 0);
	if (rtsock == -1) {
		printf("%% routing socket: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(rtsock, AF_ROUTE, ROUTE_TABLEFILTER, &cli_rtable,
	    len) == -1) {
		printf("%% ROUTE_TABLEFILTER: %s", strerror(errno));
		return -1;
	}

	return rtsock;
}

int
parse_host(const char *host, struct sockaddr_in6 *sin6)
{
	struct addrinfo hints, *res;
	int gai_error;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_flags = AI_NUMERICHOST;

	gai_error = getaddrinfo(host, NULL, &hints, &res);
	if (gai_error) {
		warnx("%% %s: %s", host, gai_strerror(gai_error));
		return 1;
	}
	*sin6 = *(struct sockaddr_in6 *)res->ai_addr;
	freeaddrinfo(res);
	return 0;
}

#if 0	/* we don't support ipv6addr/128 type proxying. */
static struct	sockaddr_in6 so_mask = {sizeof(so_mask), AF_INET6 };
#endif
static struct	sockaddr_in6 blank_sin = {sizeof(blank_sin), AF_INET6 }, sin_m;
static struct	sockaddr_dl blank_sdl = {sizeof(blank_sdl), AF_LINK }, sdl_m;
static struct	sockaddr_dl ifp_m = { sizeof(ifp_m), AF_LINK };
static time_t	expire_time;
static int	flags, found_entry;

/*
 * Set an individual neighbor cache entry
 */
int
ndpset(int argc, char *argv[])
{
	struct sockaddr_in6 *sin = &sin_m;
	struct sockaddr_dl *sdl;
	struct rt_msghdr *rtm = &(m_rtmsg.m_rtm);
	char *eaddr, *host;
	u_char *ea;
	int set = 1, i;

	sdl_m = blank_sdl;
	sin_m = blank_sin;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	}

	if ((set && (argc < 3 || argc > 5)) || (!set && argc != 2)) {
		printf("%% %s <inet6 addr> <ether addr> [temp] [proxy]\n",
		    argv[0]);
		printf("%% no %s <inet6 addr>\n", argv[0]);
		return 1;
	}

	if (!set)
		return ndpdelete(argv[1]);

	if (argc >= 3) {
		host = argv[1];
		eaddr = argv[2];
	} else {
		host = argv[1];
		eaddr = NULL;
	}

	if (getsocket() < 0)
		return 1;

	if (parse_host(host, sin))
		return 1;
	ea = (u_char *)LLADDR(&sdl_m);
	if (ndp_ether_aton(eaddr, ea) == 0)
		sdl_m.sdl_alen = 6;
	expire_time = 0;
	flags = 0;
	for (i = 3; i < argc; i++) {
		if (isprefix(argv[i], "temp")) {
			struct timeval now;

			gettimeofday(&now, 0);
			expire_time = now.tv_sec + 20 * 60;
		} else if (isprefix(argv[i], "proxy")) {
			flags |= RTF_ANNOUNCE;
		} else {
			printf("%% invalid parameter: %s\n", argv[i]);
			return (0);
		}
	}

	if (rtget_ndp(&sin, &sdl)) {
		printf("%% RTM_GET(%s) failed", host);
		return 1;
	}

	if (IN6_ARE_ADDR_EQUAL(&sin->sin6_addr, &sin_m.sin6_addr) &&
	    sin->sin6_scope_id == sin_m.sin6_scope_id) {
		if (sdl->sdl_family == AF_LINK &&
		    (rtm->rtm_flags & RTF_LLINFO) &&
		    !(rtm->rtm_flags & RTF_GATEWAY)) {
			switch (sdl->sdl_type) {
			case IFT_ETHER: case IFT_FDDI: case IFT_ISO88023:
			case IFT_ISO88024: case IFT_ISO88025:
				goto overwrite;
			}
		}
		/*
		 * IPv4 arp command retries with sin_other = SIN_PROXY here.
		 */
		warnx("%% ndpset: cannot configure a new entry");
		return 1;
	}

overwrite:
	if (sdl->sdl_family != AF_LINK) {
		printf("%% cannot intuit interface index and type for %s\n",
		    host);
		return (1);
	}
	sdl_m.sdl_type = sdl->sdl_type;
	sdl_m.sdl_index = sdl->sdl_index;
	return (rtmsg_ndp(RTM_ADD));
}

/*
 * Display an individual neighbor cache entry
 */
void
ndpget(const char *host)
{
	struct sockaddr_in6 *sin = &sin_m;

	sin_m = blank_sin;
	if (parse_host(host, sin))
		return;

	found_entry = 0;
	ndpdump(sin, 0);
	if (found_entry == 0)
		printf("%s -- no entry\n", host);
}

/*
 * Delete a neighbor cache entry
 */
int
ndpdelete(const char *host)
{
	struct sockaddr_in6 *sin = &sin_m;
	struct rt_msghdr *rtm = &m_rtmsg.m_rtm;
	struct sockaddr_dl *sdl;

	getsocket();
	sin_m = blank_sin;
	if (parse_host(host, sin))
		return 1;
	if (rtget_ndp(&sin, &sdl)) {
		printf("%% RTM_GET(%s) failed", host);
		return 1;
	}

	if (IN6_ARE_ADDR_EQUAL(&sin->sin6_addr, &sin_m.sin6_addr) &&
	    sin->sin6_scope_id == sin_m.sin6_scope_id) {
		if (sdl->sdl_family == AF_LINK && rtm->rtm_flags & RTF_LLINFO) {
			if (rtm->rtm_flags & RTF_LOCAL)
				return (0);
			if (!(rtm->rtm_flags & RTF_GATEWAY))
				goto delete;
		}
		/*
		 * IPv4 arp command retries with sin_other = SIN_PROXY here.
		 */
		return 1;
	}

delete:
	if (sdl->sdl_family != AF_LINK) {
		printf("%% cannot locate %s\n", host);
		return (1);
	}
	if (rtmsg_ndp(RTM_DELETE) == 0)
		printf("%% %s deleted\n", host);

	return 0;
}

/*
 * strlen("2001:0db8:3333:4444:5555:6666:7777:8888") == 39
 */
#define W_ADDR	39
#define W_LL	17
#define W_IF	7

/*
 * Dump the entire neighbor cache
 */
void
ndpdump(struct sockaddr_in6 *addr, int cflag)
{
	int mib[7];
	size_t needed;
	char *lim, *buf = NULL, *next;
	struct rt_msghdr *rtm;
	struct sockaddr_in6 *sin;
	struct sockaddr_dl *sdl;
	struct in6_nbrinfo *nbi;
	struct timeval now;
	int addrwidth;
	int llwidth;
	int ifwidth;
	char *ifname;

	/* Print header */
	if (!tflag && !cflag)
		printf("%-*.*s %-*.*s %*.*s %-9.9s %1s %5s\n",
		    W_ADDR, W_ADDR, "Neighbor", W_LL, W_LL, "Linklayer Address",
		    W_IF, W_IF, "Netif", "Expire", "S", "Flags");

again:;
	lim = NULL;
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET6;
	mib[4] = NET_RT_FLAGS;
	mib[5] = RTF_LLINFO;
	mib[6] = cli_rtable;
	while (1) {
		if (sysctl(mib, 7, NULL, &needed, NULL, 0) == -1) {
			printf("%% sysctl(PF_ROUTE estimate): %s\n",
			    strerror(errno));
			return;
		}
		if (needed == 0)
			break;
		if ((buf = realloc(buf, needed)) == NULL) {
			printf("%% realloc: %s\n", strerror(errno));
			return;
		}
		if (sysctl(mib, 7, buf, &needed, NULL, 0) == -1) {
			if (errno == ENOMEM)
				continue;
			printf("%% sysctl(PF_ROUTE, NET_RT_FLAGS): %s\n",
			    strerror(errno));
			return;
		}
		lim = buf + needed;
		break;
	}

	for (next = buf; next && lim && next < lim; next += rtm->rtm_msglen) {
		int isrouter = 0, prbs = 0;

		rtm = (struct rt_msghdr *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		sin = (struct sockaddr_in6 *)(next + rtm->rtm_hdrlen);
#ifdef __KAME__
		{
			struct in6_addr *in6 = &sin->sin6_addr;
			if ((IN6_IS_ADDR_LINKLOCAL(in6) ||
			    IN6_IS_ADDR_MC_LINKLOCAL(in6) ||
			    IN6_IS_ADDR_MC_INTFACELOCAL(in6)) &&
			    sin->sin6_scope_id == 0) {
				sin->sin6_scope_id = (u_int32_t)
				    ntohs(*(u_short *)&in6->s6_addr[2]);
				*(u_short *)&in6->s6_addr[2] = 0;
			}
		}
#endif
		sdl = (struct sockaddr_dl *)((char *)sin + ROUNDUP(sin->sin6_len));

		/*
		 * Some OSes can produce a route that has the LINK flag but
		 * has a non-AF_LINK gateway (e.g. fe80::xx%lo0 on FreeBSD
		 * and BSD/OS, where xx is not the interface identifier on
		 * lo0).  Such routes entry would annoy getnbrinfo() below,
		 * so we skip them.
		 * XXX: such routes should have the GATEWAY flag, not the
		 * LINK flag.  However, there is rotten routing software
		 * that advertises all routes that have the GATEWAY flag.
		 * Thus, KAME kernel intentionally does not set the LINK flag.
		 * What is to be fixed is not ndp, but such routing software
		 * (and the kernel workaround)...
		 */
		if (sdl->sdl_family != AF_LINK)
			continue;

		if (!(rtm->rtm_flags & RTF_HOST))
			continue;

		if (addr) {
			if (!IN6_ARE_ADDR_EQUAL(&addr->sin6_addr,
			    &sin->sin6_addr) || addr->sin6_scope_id !=
			    sin->sin6_scope_id)
				continue;
			found_entry = 1;
		} else if (IN6_IS_ADDR_MULTICAST(&sin->sin6_addr))
			continue;
		getnameinfo((struct sockaddr *)sin, sin->sin6_len, host_buf,
		    sizeof(host_buf), NULL, 0, NI_NUMERICHOST);
		if (cflag) {
			if (rtm->rtm_flags & RTF_CLONED)
				ndpdelete(host_buf);
			continue;
		}
		gettimeofday(&now, 0);
		if (tflag) {
			char buf[sizeof("00:00:00")];
			struct tm *tm;

			tm = localtime(&now.tv_sec);
			if (tm != NULL) {
				strftime(buf, sizeof(buf), "%H:%M:%S", tm);
				printf("%s.%06ld ", buf, now.tv_usec);
			}
		}

		addrwidth = strlen(host_buf);
		if (addrwidth < W_ADDR)
			addrwidth = W_ADDR;
		llwidth = strlen(ether_str(sdl));
		if (W_ADDR + W_LL - addrwidth > llwidth)
			llwidth = W_ADDR + W_LL - addrwidth;
		ifname = if_indextoname(sdl->sdl_index, ifix_buf);
		if (!ifname)
			ifname = "?";
		ifwidth = strlen(ifname);
		if (W_ADDR + W_LL + W_IF - addrwidth - llwidth > ifwidth)
			ifwidth = W_ADDR + W_LL + W_IF - addrwidth - llwidth;

		printf("%-*.*s %-*.*s %*.*s", addrwidth, addrwidth, host_buf,
		    llwidth, llwidth, ether_str(sdl), ifwidth, ifwidth, ifname);

		/* Print neighbor discovery specific information */
		nbi = getnbrinfo(&sin->sin6_addr, sdl->sdl_index, 1);
		if (nbi) {
			if (nbi->expire > now.tv_sec) {
				printf(" %-9.9s",
				    sec2str(nbi->expire - now.tv_sec));
			} else if (nbi->expire == 0)
				printf(" %-9.9s", "permanent");
			else
				printf(" %-9.9s", "expired");

			switch (nbi->state) {
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

			isrouter = nbi->isrouter;
			prbs = nbi->asked;
		} else {
			warnx("%% failed to get neighbor information");
			printf("  ");
		}

		printf(" %s%s%s",
		    (rtm->rtm_flags & RTF_LOCAL) ? "l" : "",
		    isrouter ? "R" : "",
		    (rtm->rtm_flags & RTF_ANNOUNCE) ? "p" : "");

		if (prbs)
			printf(" %d", prbs);

		printf("\n");
	}

	if (repeat) {
		printf("\n");
		fflush(stdout);
		sleep(repeat);
		goto again;
	}

	free(buf);
}

static struct in6_nbrinfo *
getnbrinfo(struct in6_addr *addr, int ifindex, int warning)
{
	static struct in6_nbrinfo nbi;
	int s;

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
		printf("%% socket: %s\n", strerror(errno));
		return NULL;
	}

	bzero(&nbi, sizeof(nbi));
	if_indextoname(ifindex, nbi.ifname);
	nbi.addr = *addr;
	if (ioctl(s, SIOCGNBRINFO_IN6, (caddr_t)&nbi) == -1) {
		if (warning)
			warn("%% ioctl(SIOCGNBRINFO_IN6)");
		close(s);
		return(NULL);
	}

	close(s);
	return(&nbi);
}

int
ndp_ether_aton(const char *a, u_char *n)
{
	int i, o[6];

	i = sscanf(a, "%x:%x:%x:%x:%x:%x", &o[0], &o[1], &o[2],
	    &o[3], &o[4], &o[5]);
	if (i != 6) {
		warnx("%% invalid Ethernet address '%s'", a);
		return (1);
	}
	for (i = 0; i < 6; i++)
		n[i] = o[i];
	return (0);
}

int
rtmsg_ndp(int cmd)
{
	static int seq;
	struct rt_msghdr *rtm = &m_rtmsg.m_rtm;
	char *cp = m_rtmsg.m_space;
	int l;

	errno = 0;
	if (cmd == RTM_DELETE)
		goto doit;
	bzero((char *)&m_rtmsg, sizeof(m_rtmsg));
	rtm->rtm_flags = flags;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_tableid = cli_rtable;

	switch (cmd) {
	default:
		errx(1, "internal wrong cmd");
	case RTM_ADD:
		rtm->rtm_addrs |= RTA_GATEWAY;
		if (expire_time) {
			rtm->rtm_rmx.rmx_expire = expire_time;
			rtm->rtm_inits = RTV_EXPIRE;
		}
		rtm->rtm_flags |= (RTF_HOST | RTF_STATIC);
#if 0	/* we don't support ipv6addr/128 type proxying. */
		if (rtm->rtm_flags & RTF_ANNOUNCE) {
			rtm->rtm_flags &= ~RTF_HOST;
			rtm->rtm_addrs |= RTA_NETMASK;
		}
#endif
		/* FALLTHROUGH */
	case RTM_GET:
		rtm->rtm_addrs |= (RTA_DST | RTA_IFP);
	}

#define NEXTADDR(w, s)							\
	if (rtm->rtm_addrs & (w)) {					\
		memcpy(cp, &(s), sizeof(s));				\
		ADVANCE(cp, (struct sockaddr *)&(s));			\
	}

#ifdef __KAME__
	{
		struct sockaddr_in6 sin6 = sin_m;
		struct in6_addr *in6 = &sin6.sin6_addr;
		if (IN6_IS_ADDR_LINKLOCAL(in6) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(in6) ||
		    IN6_IS_ADDR_MC_INTFACELOCAL(in6)) {
			*(u_int16_t *)& in6->s6_addr[2] =
			    htons(sin6.sin6_scope_id);
			sin6.sin6_scope_id = 0;
		}
		NEXTADDR(RTA_DST, sin6);
	}
#else
	NEXTADDR(RTA_DST, sin_m);
#endif
	NEXTADDR(RTA_GATEWAY, sdl_m);
#if 0	/* we don't support ipv6addr/128 type proxying. */
	memset(&so_mask.sin6_addr, 0xff, sizeof(so_mask.sin6_addr));
	NEXTADDR(RTA_NETMASK, so_mask);
#endif
	NEXTADDR(RTA_IFP, ifp_m);

	rtm->rtm_msglen = cp - (char *)&m_rtmsg;
doit:
	l = rtm->rtm_msglen;
	rtm->rtm_seq = ++seq;
	rtm->rtm_type = cmd;
	if ((write(rtsock, (char *)&m_rtmsg, l)) == -1) {
		if (errno != ESRCH || cmd != RTM_DELETE) {
			printf("%% rtmsg_ndp: writing to routing socket: %s\n",
			    strerror(errno));
		}
	}
	do {
		l = read(rtsock, (char *)&m_rtmsg, sizeof(m_rtmsg));
	} while (l > 0 && (rtm->rtm_version != RTM_VERSION ||
	    rtm->rtm_seq != seq || rtm->rtm_pid != pid));
	if (l == -1)
		warn("%% read from routing socket");
	return (0);
}

int
rtget_ndp(struct sockaddr_in6 **sinp, struct sockaddr_dl **sdlp)
{
	struct rt_msghdr *rtm = &(m_rtmsg.m_rtm);
	struct sockaddr_in6 *sin = NULL;
	struct sockaddr_dl *sdl = NULL;
	struct sockaddr *sa;
	char *cp;
	unsigned int i;

	if (rtmsg_ndp(RTM_GET) < 0)
		return (1);

	if (rtm->rtm_addrs) {
		cp = ((char *)rtm + rtm->rtm_hdrlen);
		for (i = 1; i; i <<= 1) {
			if (i & rtm->rtm_addrs) {
				sa = (struct sockaddr *)cp;
				switch (i) {
				case RTA_DST:
					sin = (struct sockaddr_in6 *)sa;
					break;
				case RTA_IFP:
					sdl = (struct sockaddr_dl *)sa;
					break;
				default:
					break;
				}
				ADVANCE(cp, sa);
			}
		}
	}

	if (sin == NULL || sdl == NULL)
		return (1);

#ifdef __KAME__
	{
		static struct sockaddr_in6 ksin;
		struct in6_addr *in6;

		/* do not damage the route message, we need it for delete */
		ksin = *sin;
		sin = &ksin;
		in6 = &sin->sin6_addr;

		if ((IN6_IS_ADDR_LINKLOCAL(in6) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(in6) ||
		    IN6_IS_ADDR_MC_INTFACELOCAL(in6)) &&
		    sin->sin6_scope_id == 0) {
			sin->sin6_scope_id = (u_int32_t)ntohs(*(u_short *)
			    &in6->s6_addr[2]);
			*(u_short *)&in6->s6_addr[2] = 0;
		}
	}
#endif
	*sinp = sin;
	*sdlp = sdl;

	return (0);
}
