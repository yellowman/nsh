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
/*
 * Copyright (c) 1997, 1998, 1999
 * The Regents of the University of Michigan ("The Regents") and Merit Network,
 * Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 3.  All advertising materials mentioning features or use of 
 *     this software must display the following acknowledgement:  
 *       This product includes software developed by the University of Michigan,
 *       Merit Network, Inc., and their contributors. 
 * 4.  Neither the name of the University, Merit Network, nor the
 *     names of their contributors may be used to endorse or
 *     promote products derived from this software without 
 *     specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  
 *
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>
#include <sys/signal.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>
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
#include "externs.h"
#include "ip.h"

short ns_nullh[] = {0,0,0};
short ns_bh[] = {-1,-1,-1};

union   sockunion {
	struct  sockaddr sa;
	struct  sockaddr_in sin;
#ifdef INET6
	struct  sockaddr_in6 sin6;
#endif
	struct  sockaddr_dl sdl;
} so_dst, so_gate, so_mask, so_genmask, so_ifa, so_ifp;

typedef union sockunion *sup;
pid_t	pid;
int	rtm_addrs, af, s;
int	debugonly = 0;
u_long  rtm_inits;

char	*routename_sa(struct sockaddr *);
char	*any_ntoa(const struct sockaddr *);

void	 flushroutes(int);
int	 monitor(void);
#ifdef INET6
static int prefixlen(char *);
#endif
void	 print_rtmsg(struct rt_msghdr *, int);
void	 pmsg_common(struct rt_msghdr *);
void	 pmsg_addrs(char *, int);
void	 bprintf(FILE *, int, u_char *);
int	 kernel_route(ip_t *, ip_t *, u_short);

/*
 * Purge all entries in the routing tables not
 * associated with network interfaces.
 */
void
flushroutes(af)
	int af;
{
	size_t needed;
	int mib[6], rlen, seqno;
	char *buf = NULL, *next, *lim = NULL;
	struct rt_msghdr *rtm;
	struct sockaddr *sa;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		perror("% Unable to open routing socket");
		return;
	}

	shutdown(s, 0); /* Don't want to read back our messages */
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;		/* protocol */
	mib[3] = 0;		/* wildcard address family */
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;		/* no flags */
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		printf("%% route-sysctl-estimate\n");
		close(s);
		return;
	}
	if (needed) {
		if ((buf = malloc(needed)) == NULL) {
			printf("%% flushroutes: malloc\n");
			close(s);
			return;
		}
		if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
			printf("%% flushroutes: actual retrieval of routing table\n");
			free(buf);
			close(s);
			return;
		}
		lim = buf + needed;
	}
	if (verbose) {
		(void) printf("%% Examining routing table from sysctl\n");
		 if (af)
			printf("%% (address family %d)\n", af);
	}
	if (buf == NULL) {
		printf ("%% No routing table to flush\n");
		close(s);
		return;
	}

	seqno = 0;		/* ??? */
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if (verbose)
			print_rtmsg(rtm, rtm->rtm_msglen);
		if ((rtm->rtm_flags & (RTF_GATEWAY|RTF_STATIC|RTF_LLINFO)) == 0)
			continue;
		sa = (struct sockaddr *)(rtm + 1);
		if (af) {
			if (sa->sa_family != af)
				continue;
		}
		if (sa->sa_family == AF_KEY)
			continue;  /* Don't flush SPD */
		if (debugonly)
			continue;
		rtm->rtm_type = RTM_DELETE;
		rtm->rtm_seq = seqno;
		rlen = write(s, next, rtm->rtm_msglen);
		if (rlen < (int)rtm->rtm_msglen) {
			(void) fprintf(stderr,
			    "route: write to routing socket: %s\n",
			    strerror(errno));
			(void) printf("%% flushroutes: got only %d for rlen\n", rlen);
			break;
		}
		seqno++;
		{
			struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
			(void) printf("%-20.20s ", routename_sa(sa));
/*rtm->rtm_flags & RTF_HOST ?
			    routename_sa(sa) : netname(sa));*/
			sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) +
			     (char *)sa);
			(void) printf("%-20.20s ", routename_sa(sa));
			(void) printf("deleted\n");
		}
	}
	free(buf);
	close(s);
}

static char hexlist[] = "0123456789abcdef";

char *
any_ntoa(sa)
	const struct sockaddr *sa;
{
	static char obuf[240];
	const char *in = sa->sa_data;
	char *out = obuf;
	int len = sa->sa_len;

/*	*out++ = 'Q'; */
	do {
		*out++ = hexlist[(*in >> 4) & 15];
		*out++ = hexlist[(*in++)    & 15];
		*out++ = '.';
	} while (--len > 0 && (out + 3) < &obuf[sizeof obuf-1]);
	out[-1] = '\0';
	return (obuf);
}

char *
routename_sa(sa)
	struct sockaddr *sa;
{
	char *cp = NULL;
	static char line[MAXHOSTNAMELEN];
	static char domain[MAXHOSTNAMELEN];
	static int first = 1;

	if (first) {
		first = 0;
		if (gethostname(domain, sizeof domain) == 0 &&
		    (cp = strchr(domain, '.')))
			(void) strcpy(domain, cp + 1);
		else
			domain[0] = 0;
		cp = NULL;
	}

	if (sa->sa_len == 0)
		strcpy(line, "0.0.0.0");
	else switch (sa->sa_family) {

	case AF_INET:
	    {	struct in_addr in;
		in = ((struct sockaddr_in *)sa)->sin_addr;

		if (in.s_addr == INADDR_ANY || sa->sa_len < 4)
			cp = "0.0.0.0";
		strlcpy(line, cp ? cp : inet_ntoa(in), sizeof line);
		break;
	    }

#ifdef INET6
	case AF_INET6:
	    {
		struct sockaddr_in6 sin6;
		int niflags;

#ifdef NI_WITHSCOPEID
		niflags = NI_WITHSCOPEID;
#else
		niflags = 0;
#endif
		niflags |= NI_NUMERICHOST;
		memset(&sin6, 0, sizeof(sin6));
		memcpy(&sin6, sa, sa->sa_len);
		sin6.sin6_len = sizeof(struct sockaddr_in6);
		sin6.sin6_family = AF_INET6;
#ifdef __KAME__
		if (sa->sa_len == sizeof(struct sockaddr_in6) &&
		    (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr) ||
		     IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr)) &&
		    sin6.sin6_scope_id == 0) {
			sin6.sin6_scope_id =
			    ntohs(*(u_int16_t *)&sin6.sin6_addr.s6_addr[2]);
			sin6.sin6_addr.s6_addr[2] = 0;
			sin6.sin6_addr.s6_addr[3] = 0;
		}
#endif
		if (getnameinfo((struct sockaddr *)&sin6, sin6.sin6_len,
		    line, sizeof(line), NULL, 0, niflags) != 0)
			strncpy(line, "invalid", sizeof(line));
		break;
	    }
#endif

	case AF_LINK:
		return (link_ntoa((struct sockaddr_dl *)sa));

	default:
		(void) snprintf(line, sizeof line, "(%d) %s",
		    sa->sa_family, any_ntoa(sa));
		break;
	}
	return (line);
}

#ifdef INET6
int
prefixlen(s)
	char *s;
{
	int len = atoi(s), q, r;

	rtm_addrs |= RTA_NETMASK;
	if (len < -1 || len > 129) {
		(void) fprintf(stderr, "%s: bad value\n", s);
		exit(1);
	}

	q = len >> 3;
	r = len & 7;
	so_mask.sin6.sin6_family = AF_INET6;
	so_mask.sin6.sin6_len = sizeof(struct sockaddr_in6);
	memset((void *)&so_mask.sin6.sin6_addr, 0,
		sizeof(so_mask.sin6.sin6_addr));
	if (q > 0)
		memset((void *)&so_mask.sin6.sin6_addr, 0xff, q);
	if (r > 0)
		*((u_char *)&so_mask.sin6.sin6_addr + q) = (0xff00 >> r) & 0xff;
	return (len);
}
#endif

int
monitor()
{
	int n, saveverbose;
	char msg[2048];

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		perror("% Unable to open routing socket");
		return 1;
	}
	saveverbose = verbose;
	verbose = 1;

	for(;;) {
		time_t now;
		n = read(s, msg, 2048);
		now = time(NULL);
		(void) printf("got message of size %d on %s", n, ctime(&now));
		print_rtmsg((struct rt_msghdr *)msg, n);
	}

	verbose = saveverbose;
	close(s);
	return(0);
}

struct m_rtmsg {
	struct	rt_msghdr m_rtm;
	char	m_space[512];
};

char *msgtypes[] = {
	"",
	"RTM_ADD: Add Route",
	"RTM_DELETE: Delete Route",
	"RTM_CHANGE: Change Metrics or flags",
	"RTM_GET: Report Metrics",
	"RTM_LOSING: Kernel Suspects Partitioning",
	"RTM_REDIRECT: Told to use different route",
	"RTM_MISS: Lookup failed on this address",
	"RTM_LOCK: fix specified metrics",
	"RTM_OLDADD: caused by SIOCADDRT",
	"RTM_OLDDEL: caused by SIOCDELRT",
	"RTM_RESOLVE: Route created by cloning",
	"RTM_NEWADDR: address being added to iface",
	"RTM_DELADDR: address being removed from iface",
	"RTM_IFINFO: iface status change",
	0,
};

char metricnames[] =
"\011pksent\010rttvar\7rtt\6ssthresh\5sendpipe\4recvpipe\3expire\2hopcount\1mtu";
char routeflags[] =
"\1UP\2GATEWAY\3HOST\4REJECT\5DYNAMIC\6MODIFIED\7DONE\010MASK_PRESENT\011CLONING\012XRESOLVE\013LLINFO\014STATIC\017PROTO2\020PROTO1";
char ifnetflags[] =
"\1UP\2BROADCAST\3DEBUG\4LOOPBACK\5PTP\6NOTRAILERS\7RUNNING\010NOARP\011PPROMISC\012ALLMULTI\013OACTIVE\014SIMPLEX\015LINK0\016LINK1\017LINK2\020MULTICAST";
char addrnames[] =
"\1DST\2GATEWAY\3NETMASK\4GENMASK\5IFP\6IFA\7AUTHOR\010BRD";

void
print_rtmsg(rtm, msglen)
	struct rt_msghdr *rtm;
	int msglen;
{
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;

	if (verbose == 0)
		return;
	if (rtm->rtm_version != RTM_VERSION) {
		(void) printf("routing message version %d not understood\n",
		    rtm->rtm_version);
		return;
	}
	(void)printf("%% %s: len %d, ", msgtypes[rtm->rtm_type], rtm->rtm_msglen);
	switch (rtm->rtm_type) {
	case RTM_IFINFO:
		ifm = (struct if_msghdr *)rtm;
		(void) printf("if# %d, flags:", ifm->ifm_index);
		bprintf(stdout, ifm->ifm_flags, ifnetflags);
		pmsg_addrs((char *)(ifm + 1), ifm->ifm_addrs);
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
		ifam = (struct ifa_msghdr *)rtm;
		(void) printf("metric %d, flags:", ifam->ifam_metric);
		bprintf(stdout, ifam->ifam_flags, routeflags);
		pmsg_addrs((char *)(ifam + 1), ifam->ifam_addrs);
		break;
	default:
		(void) printf("pid: %d, seq %d, errno %d, flags:",
			rtm->rtm_pid, rtm->rtm_seq, rtm->rtm_errno);
		bprintf(stdout, rtm->rtm_flags, routeflags);
		pmsg_common(rtm);
	}
}

void
pmsg_common(rtm)
	struct rt_msghdr *rtm;
{
	(void) printf("\nlocks: ");
	bprintf(stdout, rtm->rtm_rmx.rmx_locks, metricnames);
	(void) printf(" inits: ");
	bprintf(stdout, rtm->rtm_inits, metricnames);
	pmsg_addrs(((char *)(rtm + 1)), rtm->rtm_addrs);
}

void
pmsg_addrs(cp, addrs)
	char	*cp;
	int	addrs;
{
	struct sockaddr *sa;
	int i;

	if (addrs == 0)
		return;
	(void) printf("\nsockaddrs: ");
	bprintf(stdout, addrs, addrnames);
	(void) putchar('\n');
	for (i = 1; i; i <<= 1)
		if (i & addrs) {
			sa = (struct sockaddr *)cp;
			(void) printf(" %s", routename_sa(sa));
			ADVANCE(cp, sa);
		}
	(void) putchar('\n');
	(void) fflush(stdout);
}

void
bprintf(fp, b, s)
	FILE *fp;
	int b;
	u_char *s;
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

/*
 * Adapted from merit's mrtd (hence the copyright above) which appears to
 * have adapted from 4.4bsd, as it looks like this was rtmsg() at one point
 */
int
kernel_route(ip_t *dest, ip_t *gate, u_short cmd)
{
	int rlen;
	struct m_rtmsg m_rtmsg;
	char *cp = m_rtmsg.m_space;

	int flags, rtm_addrs;
	static int seq = 0;
	struct rt_metrics rt_metrics;
	register int l;
	int len = dest->bitlen;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {  
		perror("% Unable to open routing socket");
		return(1);
	}

	bzero ((char *) &m_rtmsg, sizeof(m_rtmsg));
	bzero ((char *) &rt_metrics, sizeof (rt_metrics));
	bzero (&so_dst, sizeof (so_dst));
	bzero (&so_gate, sizeof (so_gate));
	bzero (&so_mask, sizeof (so_mask));
	bzero (&so_genmask, sizeof (so_genmask));
	bzero (&so_ifp, sizeof (so_ifp));
	bzero (&so_ifa, sizeof (so_ifa));

	m_rtmsg.m_rtm.rtm_type = cmd;

	rtm_addrs = 0;
	flags = RTF_UP | RTF_STATIC;

	if (dest->family == AF_INET) {
		if (len == 32)
			flags |= RTF_HOST;
		so_dst.sin.sin_addr.s_addr = dest->addr.sin.s_addr;
		so_dst.sin.sin_len = sizeof (struct sockaddr_in);
		so_dst.sin.sin_family = AF_INET;
		rtm_addrs |= RTA_DST;

		if (gate) {
			so_gate.sin.sin_addr.s_addr = gate->addr.sin.s_addr;
			so_gate.sin.sin_len = sizeof (struct sockaddr_in);
			so_gate.sin.sin_family = AF_INET;
			rtm_addrs |= RTA_GATEWAY;
			flags |= RTF_GATEWAY;
		}

		so_mask.sin.sin_len = sizeof (struct sockaddr_in);
		so_mask.sin.sin_family = AF_INET;
		so_mask.sin.sin_addr.s_addr = htonl(0xffffffff << (32 - len));
		rtm_addrs |= RTA_NETMASK;

	} else if (dest->family == AF_INET6) {
#ifdef INET6
		if (len == 128)
			flags |= RTF_HOST;
		so_dst.sin6.sin6_addr = dest->addr.sin;
		so_dst.sin6.sin6_len = sizeof (struct sockaddr_in6);
		so_dst.sin6.sin6_family = AF_INET6;
		rtm_addrs |= RTA_DST;
		if (gate && !prefix_is_unspecified (gate)) {
			memcpy (&so_gate.sin6.sin6_addr, prefix_tochar (gate), 16);
			so_gate.sin6.sin6_len = sizeof (struct sockaddr_in6);
			so_gate.sin6.sin6_family = AF_INET6;
			rtm_addrs |= RTA_GATEWAY;
			flags |= RTF_GATEWAY;
			/* KAME IPV6 still requires an index here */
			if (IN6_IS_ADDR_LINKLOCAL (&so_gate.sin6.sin6_addr)) {
				so_gate.sin6.sin6_addr.s6_addr[2] = index >> 8;;
				so_gate.sin6.sin6_addr.s6_addr[3] = index;
			}
		}
		so_mask.sin6.sin6_len = sizeof (struct sockaddr_in6);
		so_mask.sin6.sin6_family = AF_INET6;
		so_mask.sin6.sin6_addr = htonl(0xffffffffffffffffffffffffffffffff << (128 - len));
		rtm_addrs |= RTA_NETMASK;
#else
		close(s);
		return(0);
#endif
	} else {
		close(s);
		return(0);
	}

#if 0
	if (gate && prefix_is_loopback (gate))
		flags |= RTF_REJECT;
#endif

#define NEXTADDRP(w, u)							      \
	if (rtm_addrs & (w)) {						      \
		int l;						 	      \
		l = ROUNDUP(u.sa.sa_len); bcopy((char *)&(u), cp, l); cp += l;\
	}

	m_rtmsg.m_rtm.rtm_flags = flags;
	m_rtmsg.m_rtm.rtm_version = RTM_VERSION;
	m_rtmsg.m_rtm.rtm_seq = ++seq;
	m_rtmsg.m_rtm.rtm_addrs = rtm_addrs;
	m_rtmsg.m_rtm.rtm_rmx = rt_metrics;
	/*m_rtmsg.m_rtm.rtm_inits = 0; */
	NEXTADDRP (RTA_DST, so_dst);
	NEXTADDRP (RTA_GATEWAY, so_gate);
	NEXTADDRP (RTA_NETMASK, so_mask);
	NEXTADDRP (RTA_GENMASK, so_genmask);
	NEXTADDRP (RTA_IFP, so_ifp);
	NEXTADDRP (RTA_IFA, so_ifa);

	m_rtmsg.m_rtm.rtm_msglen = l = cp - (char *) &m_rtmsg;

	if(verbose)
		print_rtmsg((struct rt_msghdr *)&m_rtmsg, m_rtmsg.m_rtm.rtm_msglen);

	if ((rlen = write (s, (char *) &m_rtmsg, l)) < 0) {
		if (errno == ESRCH || errno == ENETUNREACH)
			printf("%% Gateway is unreachable: %s\n",
			    inet_ntoa(gate->addr.sin));
		else
			perror("% Writing to routing socket"); 
		close(s);
		return(-1);
	}
	close(s);
	return(1);
}
