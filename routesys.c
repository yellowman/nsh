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
#include "ip.h"
#include "externs.h"

short ns_nullh[] = {0,0,0};
short ns_bh[] = {-1,-1,-1};

int 	sigflag = 0;

union   sockunion {
	struct  sockaddr sa;
	struct  sockaddr_in sin;
#ifdef INET6
	struct  sockaddr_in6 sin6;
#endif
	struct  sockaddr_dl sdl;
} so_dst, so_gate, so_mask, so_ifp; /* no thanks:, so_genmask, so_ifa; */

typedef union sockunion *sup;
int	rtm_addrs;
u_long  rtm_inits;

char	*routename_sa(struct sockaddr *);
char	*any_ntoa(const struct sockaddr *);
char	*mylink_ntoa(const struct sockaddr_dl *);
char	*touch;

void	 flushroutes(int, int);
int	 monitor(void);
int	 rtmsg(int, int);
#ifdef INET6
static int prefixlen(char *);
#endif
void	 print_rtmsg(struct rt_msghdr *, int);
void	 print_getmsg(struct rt_msghdr *, int);
void	 pmsg_common(struct rt_msghdr *);
void	 pmsg_addrs(char *, int);
void	 bprintf(FILE *, int, u_char *);
int	 ip_route(ip_t *, ip_t *, u_short);

/*
 * caller must freertdump() if rtdump not null
 */
struct rtdump *getrtdump(int s)
{
	size_t needed;
	int mib[6];
	struct rtdump *rtdump;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;	/* protocol */
	mib[3] = 0;	/* wildcard address family */
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;	/* no flags */

	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		printf("%% getrtdump: unable to get estimate: %s\n",
		    strerror(errno));
		return(NULL);
	}

	if ((rtdump = malloc(sizeof(struct rtdump))) == NULL) {
		printf("%% getrtdump: rtdump malloc: %s\n", strerror(errno));
		return(NULL);
	}

	if (needed) {
		if ((rtdump->buf = malloc(needed)) == NULL) {
			printf("%% getrtdump: malloc: %s\n", strerror(errno));
			free(rtdump);
			return(NULL);
		}
		if (sysctl(mib, 6, rtdump->buf, &needed, NULL, 0) < 0) {
			printf("%% getrtdump: sysctl routing table: %s\n",
			    strerror(errno));
			freertdump(rtdump);
			return(NULL);
		}
		rtdump->lim = rtdump->buf + needed;
	}
	if (rtdump->buf == NULL) {
		printf ("%% No routing table\n");
		free(rtdump);
		return(NULL);
	}

	return(rtdump);
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
flushroutes(int af, int af2)
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
	rtdump = getrtdump(s);
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
			print_rtmsg(rtm, rtm->rtm_msglen);
		}
		sa = (struct sockaddr *)(rtm + 1);
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
			printf("%% Unable to write to routing socket: %s\n",
			    strerror(errno));
			break;
		}
		seqno++;
		if (verbose) {
			printf("\n%% Wrote message:\n");
			print_rtmsg(rtm, rlen);
		} else {
			printf("%% %-20.20s ", routename_sa(sa));
			printf("%-20.20s flushed\n", routename_sa(sa2));
		}
	}
	if (verbose)
		printf("\n");
	if (!seqno)
		printf("%% No entires found to flush\n");
	freertdump(rtdump);
	close(s);
	return;
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

/*	*out++ = 'Q'; */ /* WTF ? */
	do {
		*out++ = hexlist[(*in >> 4) & 15];
		*out++ = hexlist[(*in++)    & 15];
		*out++ = '.';
	} while (--len > 0 && (out + 3) < &obuf[sizeof obuf-1]);
	out[-1] = '\0';
	return (obuf);
}

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
		return (mylink_ntoa((struct sockaddr_dl *)sa));

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
		printf("%% prefixlen: %s: bad value\n", s);
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

static void
_monitor_sig(int signo)
{
	sigflag = signo;
	return;
}

int
monitor()
{
	int s, m, n, saveverbose;
	fd_set fds; 
	struct timeval to;
	char msg[2048];

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		printf("%% Unable to open routing socket: %s\n",
		    strerror(errno));
		return 1;
	}
	saveverbose = verbose;
	verbose = 1;

	/* set up signal handler */
	if (signal (SIGINT, _monitor_sig) == SIG_ERR) {
		perror (strerror(errno));
		verbose = saveverbose;
		close (s);
		return (0);
	}

	printf("%% Entering monitor mode ... press ENTER or ^C to leave ...\n");

	for(; sigflag != SIGINT ;) {
		time_t now;

		FD_ZERO (&fds);
		FD_SET (s, &fds);
		FD_SET (0, &fds);
		to.tv_sec = 1;
		to.tv_usec = 0;

		m = select (s + 1, &fds, NULL, NULL, &to);

		if (m < 0) {
			printf ("%% select: %s\n", strerror(errno));
			break;
		}

		if (m > 0) {
			if (FD_ISSET (s, &fds)) {
				ioctl (s, FIONBIO, 1); 	/* non-blocking io */
				n = read (s, msg, 2048);
				now = time(NULL);
				printf("%% Message of size %d on %s", n, ctime(&now));
				print_rtmsg((struct rt_msghdr *)msg, n);
			}
			if (FD_ISSET (0, &fds)) 
				break; 
		}
	}

	sigflag = -1;
	verbose = saveverbose;
	close(s);
	return(0);
}

struct {
	struct	rt_msghdr m_rtm;
	char	m_space[512];
} m_rtmsg;

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
"\1UP\2BROADCAST\3DEBUG\4LOOPBACK\5PTP\6NOTRAILERS\7RUNNING\010NOARP\011PROMISC\012ALLMULTI\013OACTIVE\014SIMPLEX\015LINK0\016LINK1\017LINK2\020MULTICAST";

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
		(void) printf("%% routing message version %d not understood\n",
		    rtm->rtm_version);
		return;
	}
	(void)printf("%% %s: len %d, ", msgtypes[rtm->rtm_type], rtm->rtm_msglen);
	switch (rtm->rtm_type) {
	case RTM_IFINFO:
		ifm = (struct if_msghdr *)rtm;
		(void) printf("if# %d\n", ifm->ifm_index);
		bprintf(stdout, ifm->ifm_flags, ifnetflags);
		pmsg_addrs((char *)(ifm + 1), ifm->ifm_addrs);
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
		ifam = (struct ifa_msghdr *)rtm;
		(void) printf("metric %d\n", ifam->ifam_metric);
		bprintf(stdout, ifam->ifam_flags, routeflags);
		pmsg_addrs((char *)(ifam + 1), ifam->ifam_addrs);
		break;
	default:
		(void) printf("pid: %d, seq %d, errno %d, flags:",
			rtm->rtm_pid, rtm->rtm_seq, rtm->rtm_errno);
		bprintf(stdout, rtm->rtm_flags, routeflags);
		printf("\n");
		pmsg_common(rtm);
	}
}

void
print_getmsg(rtm, msglen)
	struct rt_msghdr *rtm;
	int msglen;
{
	struct sockaddr *dst = NULL, *gate = NULL, *mask = NULL;
	struct sockaddr_dl *ifp = NULL;
	struct sockaddr *sa;
	char *cp;
	int i;

#if 0
	(void) printf("%% route lookup for: %s\n", routename_sa(&so_dst.sa));
#endif
	if (rtm->rtm_msglen > msglen) {
		printf("%% message length mismatch, in packet %d,"
		    " returned %d\n", rtm->rtm_msglen, msglen);
	}
	if (rtm->rtm_errno)  {
		(void) printf("%% RTM_GET: %s (errno %d)\n", 
		    strerror(rtm->rtm_errno), rtm->rtm_errno);
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
	if (dst && mask)
		mask->sa_family = dst->sa_family;       /* XXX */
	if (dst)
		(void)printf("%% destination: %s\n", routename_sa(dst));
	if (mask)
		(void)printf("%% netmask: %s\n", routename_sa(mask));
	if (gate && rtm->rtm_flags & RTF_GATEWAY)
		(void)printf("%% gateway: %s\n", routename_sa(gate));
	if (ifp)
		(void)printf("%% interface: %.*s\n",
		    ifp->sdl_nlen, ifp->sdl_data);
	if (verbose) {
		(void)printf("%% flags: ");
		bprintf(stdout, rtm->rtm_flags, routeflags);
		printf("\n");
	}

#define lock(f) ((rtm->rtm_rmx.rmx_locks & __CONCAT(RTV_,f)) ? 'L' : ' ')

	/*
	 * we ignore most statistics and locks right now for simplicity
	 */
	if (rtm->rtm_rmx.rmx_mtu)
		printf("%% mtu: %d\n", (int)rtm->rtm_rmx.rmx_mtu);
	if (rtm->rtm_rmx.rmx_hopcount)
		printf("%% hopcount: %d\n", (int)rtm->rtm_rmx.rmx_hopcount);
	if (rtm->rtm_rmx.rmx_expire) {
		rtm->rtm_rmx.rmx_expire -= time(0);
		printf("%% expires: %d sec\n", (int)rtm->rtm_rmx.rmx_expire);
	}

#define RTA_IGN (RTA_DST|RTA_GATEWAY|RTA_NETMASK|RTA_IFP|RTA_IFA|RTA_BRD)
        if (verbose)
                pmsg_common(rtm);
        else if (rtm->rtm_addrs &~ RTA_IGN) {
		(void) printf("%% sockaddrs: ");
		bprintf(stdout, rtm->rtm_addrs, addrnames);
		putchar('\n');
	}
#undef  RTA_IGN
}

void
pmsg_common(rtm)
	struct rt_msghdr *rtm;
{
	(void) printf("%% locks: ");
	bprintf(stdout, rtm->rtm_rmx.rmx_locks, metricnames);
	(void) printf(" inits: ");
	bprintf(stdout, rtm->rtm_inits, metricnames);
	printf("\n");
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
	(void) printf("%% sockaddrs: ");
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
ip_route(ip_t *dest, ip_t *gate, u_short cmd)
{
	int flags;
	int len = dest->bitlen;

	rtm_addrs = 0;
	memset(&so_dst, 0, sizeof (so_dst));
	memset(&so_gate, 0, sizeof (so_gate));
	memset(&so_mask, 0, sizeof (so_mask));
	memset(&so_ifp, 0, sizeof(so_ifp));

	if (cmd == RTM_GET) {
		so_ifp.sa.sa_family = AF_LINK;
		so_ifp.sa.sa_len = sizeof(struct sockaddr_dl);
		rtm_addrs |= RTA_IFP;
	}

	flags = RTF_UP | RTF_STATIC;

	switch(dest->family) {
	case AF_INET:
	  {
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

		if (len >= 0) {
			so_mask.sin.sin_len = sizeof (struct sockaddr_in);
			so_mask.sin.sin_family = AF_INET;
			if(len == 0)
				so_mask.sin.sin_addr.s_addr = 0;
			else
				so_mask.sin.sin_addr.s_addr =
				    htonl(0xffffffff << (32 - len));
			rtm_addrs |= RTA_NETMASK;
		}
	  }
		break;

#ifdef INET6
	case AF_INET6:
	  {
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
	  }
		break;
#endif
	default:
		printf("%% ip_route: Internal error\n");
		return(0);
		break;
	}
	if (rtmsg(cmd, flags) < 0) {
		if (cmd == RTM_ADD && gate &&
		    (errno == ESRCH || errno == ENETUNREACH))
			printf("%% Gateway is unreachable: %s\n",
			    inet_ntoa(gate->addr.sin)); /* XXX IPv6 */
		else if (cmd == RTM_GET &&
		    (errno == ESRCH || errno == ENETUNREACH))
			printf("%% Unable to find route: %s\n",
			    inet_ntoa(dest->addr.sin));
		else
			printf("%% ip_route: rtmsg: %s\n", strerror(errno));
	}
	return(0);
}

/*
 * handle routing messages for route get, route set, arp set
 * we return -1 when caller handles error message (set) or 0 when
 * there is no error or we displayed the error message (get)
 */
int
rtmsg(cmd, flags)
	int cmd, flags;
{
	static int seq;
	int rlen;
	char *cp = m_rtmsg.m_space;
	int l, s;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		printf("%% Unable to open routing socket: %s\n",
		    strerror(errno));
		return(1);
	}

#define NEXTADDR(w, u)							\
	if (rtm_addrs & (w)) {						\
	    l = ROUNDUP(u.sa.sa_len); memcpy(cp, &(u), l); cp += l;	\
	}

	errno = 0;
	memset(&m_rtmsg, 0, sizeof(m_rtmsg));
#define rtm m_rtmsg.m_rtm
	rtm.rtm_type = cmd;
	rtm.rtm_flags = flags;
	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_seq = ++seq;
	rtm.rtm_addrs = rtm_addrs;
#if 0 /* deal with this later when our cmdline handles metrics... */
	rtm.rtm_rmx = rt_metrics;
#endif
	rtm.rtm_inits = rtm_inits;

	NEXTADDR(RTA_DST, so_dst);
	NEXTADDR(RTA_GATEWAY, so_gate);
	NEXTADDR(RTA_NETMASK, so_mask);
	NEXTADDR(RTA_IFP, so_ifp);
	rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;
	if (verbose)
		print_rtmsg(&rtm, l);
	if ((rlen = write(s, (char *)&m_rtmsg, l)) < 0) {
		/* on a write, the calling function will notify user of error */
		close(s);
		return (-1);
	}
	if (cmd == RTM_GET) {
		do {
			l = read(s, (char *)&m_rtmsg, sizeof(m_rtmsg));
		} while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));
		if (l < 0)
			/* on a get we notify the user */
			printf("%% rtmsg: read from routing socket: %s\n",
			    strerror(errno));
		else
			print_getmsg(&rtm, l);
	}
#undef rtm
	close(s);
	return (0);
}
