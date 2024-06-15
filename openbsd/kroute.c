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

int 	sigflag = 0;
static struct	rt_metrics	rt_metrics;

/* declared in externs.h */
union	sockunion so_dst, so_gate, so_mask, so_ifp;
struct	rtmsg m_rtmsg;

int	rtm_addrs;
u_long	rtm_inits;

char	*mylink_ntoa(const struct sockaddr_dl *);

void	 flushroutes(int, int);
void	 print_rtmsg(struct rt_msghdr *);
void	 print_getmsg(struct rt_msghdr *, int);
void	 pmsg_common(struct rt_msghdr *);
void	 pmsg_addrs(char *, int);
void	 bprintf(FILE *, int, u_char *);

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
		return(NULL);
	}
	rtdump->buf = NULL;

	while (1) {
		if (sysctl(mib, 7, NULL, &needed, NULL, 0) < 0) {
			if (errno != ENOENT)
				printf("%% getrtdump: unable to get estimate: %s\n",
				    strerror(errno));
			return(NULL);
		}
		if (needed == 0)
			break;
		if ((rtdump->buf = realloc(rtdump->buf, needed)) == NULL) {
			printf("%% getrtdump: realloc: %s\n", strerror(errno));
			free(rtdump);
			return(NULL);
		}
		if (sysctl(mib, 7, rtdump->buf, &needed, NULL, 0) < 0) {
			if (errno == ENOMEM)
				continue;
			printf("%% getrtdump: sysctl routing table: %s\n",
			    strerror(errno));
			freertdump(rtdump);
			return(NULL);
		}
		rtdump->lim = rtdump->buf + needed;
		break;
	}
	if (rtdump->buf == NULL) {
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
	rtdump = getrtdump(af, 0, 0);
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
			printf("%% Unable to write to routing socket: %s\n",
			    strerror(errno));
			break;
		}
		seqno++;
		if (verbose) {
			printf("\n%% Wrote message:\n");
			print_rtmsg(rtm);
		} else {
			printf("%% %-20.20s ", routename(sa));
			printf("%-20.20s flushed\n", routename(sa2));
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

static void
_monitor_sig(int signo)
{
	sigflag = signo;
	return;
}

int
monitor(int argc, char **argv)
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
				print_rtmsg((struct rt_msghdr *)msg);
			}
			if (FD_ISSET (0, &fds)) 
				break; 
		}
	}

	sigflag = -1;
	verbose = saveverbose;
	(void)signal(SIGINT, (sig_t)intr);
	close(s);
	return(0);
}

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
"\1UP\2GATEWAY\3HOST\4REJECT\5DYNAMIC\6MODIFIED\7DONE\010MASK_PRESENT\011CLONING\013LLINFO\014STATIC\017PROTO2\020PROTO1";

char ifnetflags[] =
"\1UP\2BROADCAST\3DEBUG\4LOOPBACK\5PTP\6NOTRAILERS\7RUNNING\010NOARP\011PROMISC\012ALLMULTI\013OACTIVE\014SIMPLEX\015LINK0\016LINK1\017LINK2\020MULTICAST";

char addrnames[] =
"\1DST\2GATEWAY\3NETMASK\4GENMASK\5IFP\6IFA\7AUTHOR\010BRD";

void
print_rtmsg(rtm)
	struct rt_msghdr *rtm;
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
	(void)printf("%% %s: len %d, table %d, ", msgtypes[rtm->rtm_type], rtm->rtm_msglen,
	    rtm->rtm_tableid);
	switch (rtm->rtm_type) {
	case RTM_IFINFO:
		ifm = (struct if_msghdr *)rtm;
		(void) printf("if# %d\n", ifm->ifm_index);
		bprintf(stdout, ifm->ifm_flags, ifnetflags);
		pmsg_addrs((char *)ifm + ifm->ifm_hdrlen, ifm->ifm_addrs);
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
		ifam = (struct ifa_msghdr *)rtm;
		(void) printf("metric %d\n", ifam->ifam_metric);
		bprintf(stdout, ifam->ifam_flags, routeflags);
		pmsg_addrs((char *)ifam + ifam->ifam_hdrlen, ifam->ifam_addrs);
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
	struct sockaddr_rtlabel *sa_rl = NULL;
	struct sockaddr *sa;
	char *cp;
	int i;

	(void) printf("%% route lookup for:\t%s\n", routename(&so_dst.sa));
	if (rtm->rtm_msglen > msglen) {
		printf("%% message length mismatch, in packet %d,"
		    " returned %d\n", rtm->rtm_msglen, msglen);
	}
	if (rtm->rtm_errno)  {
		(void) printf("%% print_getmsg: RTM_GET: %s (errno %d)\n", 
		    strerror(rtm->rtm_errno), rtm->rtm_errno);
		return;
	}
	cp = ((char *)rtm + rtm->rtm_hdrlen);
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
				case RTA_LABEL:
					sa_rl = (struct sockaddr_rtlabel *)sa;
					break;
				}
				ADVANCE(cp, sa);
			}
	if (dst && mask)
		mask->sa_family = dst->sa_family;       /* XXX */
	if (dst)
		(void)printf("\tdestination:\t%s\n", routename(dst));
	if (mask)
		(void)printf("\tnetmask:\t%s\n", routename(mask));
	if (gate && rtm->rtm_flags & RTF_GATEWAY)
		(void)printf("\tgateway:\t%s\n", routename(gate));
	if (ifp)
		(void)printf("\tinterface:\t%.*s\n",
		    ifp->sdl_nlen, ifp->sdl_data);
	if (verbose) {
		(void)printf("\tflags:\t");
		bprintf(stdout, rtm->rtm_flags, routeflags);
		printf("\n");
	}
	if (sa_rl != NULL)
		printf("\tlabel:\t\t%s\n", sa_rl->sr_label);

#define lock(f) ((rtm->rtm_rmx.rmx_locks & __CONCAT(RTV_,f)) ? 'L' : ' ')

	/*
	 * we ignore most statistics and locks right now for simplicity
	 */
	if (rtm->rtm_rmx.rmx_mtu)
		printf("\tmtu:\t\t%u\n", rtm->rtm_rmx.rmx_mtu);
	if (rtm->rtm_rmx.rmx_hopcount)
		printf("\thopcount:\t%u\n", rtm->rtm_rmx.rmx_hopcount);
	if (rtm->rtm_rmx.rmx_expire) {
		rtm->rtm_rmx.rmx_expire -= time(0);
		printf("\texpires:\t%lld sec\n", rtm->rtm_rmx.rmx_expire);
	}

#define RTA_IGN (RTA_DST|RTA_GATEWAY|RTA_NETMASK|RTA_IFP|RTA_IFA|RTA_BRD)
        if (verbose)
                pmsg_common(rtm);
        else if (rtm->rtm_addrs &~ RTA_IGN) {
		(void) printf("\tsockaddrs:\t");
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
	pmsg_addrs(((char *)rtm + rtm->rtm_hdrlen), rtm->rtm_addrs);
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
			(void) printf(" %s", routename(sa));
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
ip_route(ip_t *dest, ip_t *gate, u_short cmd, int flags, int tableid,
    struct rt_metrics rt_metrics, int inits)
{
	int l;
	int len = dest->bitlen;
	static char line_kroute[MAXHOSTNAMELEN];

	rtm_addrs = 0, rtm_inits = inits;
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
		return(0);
		break;
	}
	if ((l = rtmsg(cmd, flags, 0, 0, tableid)) < 0) {
		if (cmd == RTM_ADD && gate &&
		    (errno == ESRCH || errno == ENETUNREACH))
			printf("%% Gateway is unreachable: %s\n",
			    inet_ntop(gate->family, &gate->addr,
			    line_kroute, sizeof(line_kroute)));
		else if (cmd == RTM_GET &&
		    (errno == ESRCH || errno == ENETUNREACH))
			printf("%% Unable to find route: %s\n",
			    inet_ntop(dest->family, &dest->addr,
			    line_kroute, sizeof(line_kroute)));
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
	} else if (cmd == RTM_GET)
		/* ip_route is also used by 'show route' */
		print_getmsg(&m_rtmsg.m_rtm, l);
	return(0);
}

/*
 * handle routing messages for route get, route set, arp set
 * we return -1 when caller handles error message (set) or 0 when
 * there is no error or we displayed the error message (get)
 */
int
rtmsg(cmd, flags, proxy, export, tableid)
	int cmd, flags, proxy, export, tableid;
{
	static int seq;
	struct rt_msghdr *rtm;
	char *cp = m_rtmsg.m_space;
	int l, s;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	rtm = &m_rtmsg.m_rtm;

	if (s < 0) {
		printf("%% Unable to open routing socket: %s\n",
		    strerror(errno));
		return(1);
	}

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
		printf("%% rtnameserver: unknown interface: %s", if_name);
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
			printf("%% rtnameserver: %s", gai_strerror(error));
			continue;
		}
		if (res == NULL) {
			printf("%% rtnameserver: %s: unknown", *argv);
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
			printf("v4: %s", inet_ntop(AF_INET, &ns4[i], buf,
			    sizeof(buf)));
		for (i = 0; i < ns6_count; i++)
			printf("v6: %s", inet_ntop(AF_INET6, &ns6[i], buf,
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
		close(s);
		return (1);
	}

	if (writev(s, iov, iovcnt) == -1) {
		printf("%% rtnameserver: failed to send routing message: %s",
		    strerror(errno));
		error = 1;
	}

	rtm.rtm_seq++;

	memset(&rtdns, 0, sizeof(rtdns));
	rtdns.sr_family = AF_INET6;
	rtdns.sr_len = 2 + ns6_count * sizeof(struct in6_addr);
	memcpy(rtdns.sr_dns, ns6, rtdns.sr_len - 2);

	if (writev(s, iov, iovcnt) == -1) {
		printf("%% rtnameserver: failed to send routing message: %s",
		    strerror(errno));
		error = 1;
	}

	close(s);
	return (error);
}
