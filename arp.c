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

#include <sys/file.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <paths.h>
#include <unistd.h>
#include <limits.h>
#include <ifaddrs.h>
#include "externs.h"

/* ROUNDUP() is nasty, but it is identical to what's in the kernel. */
#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

int rtget(struct sockaddr_inarp **, struct sockaddr_dl **, int, int, int);
int arpdelete(const char *, const char *);
int arpsearch(FILE *, char *, in_addr_t addr, void (*action)(FILE *, char *,
	struct sockaddr_dl *sdl, struct sockaddr_inarp *sin,
	struct rt_msghdr *rtm));
void print_entry(FILE *, char *, struct sockaddr_dl *sdl,
	struct sockaddr_inarp *sin, struct rt_msghdr *rtm);
void nuke_entry(struct sockaddr_dl *sdl,
	struct sockaddr_inarp *sin, struct rt_msghdr *rtm);
void conf_arp_entry(FILE *, char *, struct sockaddr_dl *,
	struct sockaddr_inarp *, struct rt_msghdr *);
int getinetaddr(const char *, struct in_addr *);
static int getsocket(void);
int rtmsg_arp(int, int, int, int);

static int s = -1;

extern int h_errno;

#define F_GET		1
#define F_SET		2
#define F_FILESET	3
#define F_DELETE	4

static int
getsocket(void)
{
	socklen_t len = sizeof(cli_rtable);

	if (s >= 0)
		return s;
	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		printf("%% getsocket: socket: %s\n", strerror(errno));
		return s;
	}
	if (setsockopt(s, PF_ROUTE, ROUTE_TABLEFILTER, &cli_rtable, len) < 0) {
		printf("%% getsocket: setsockopt: %s\n", strerror(errno));
		return -1;
	}

	return s;
}

static struct sockaddr_in	so_1mask = { 8, 0, 0, { 0xffffffff } };
static struct sockaddr_inarp	blank_sin = { sizeof(blank_sin), AF_INET }, sin_m;
static struct sockaddr_dl	blank_sdl = { sizeof(blank_sdl), AF_LINK }, sdl_m;
static struct sockaddr_dl	ifp_m = { sizeof(ifp_m), AF_LINK };
static time_t			expire_time;

int
rtget(struct sockaddr_inarp **sinp, struct sockaddr_dl **sdlp,
    int flags, int doing_proxy, int export_only)
{
	struct rt_msghdr *rtm = &(m_rtmsg.m_rtm);
	struct sockaddr_inarp *sin = NULL;
	struct sockaddr_dl *sdl = NULL;
	struct sockaddr *sa;
	char *cp;
	unsigned int i;

	if (rtmsg_arp(RTM_GET, flags, doing_proxy, export_only) < 0)
		return (1);

	if (rtm->rtm_addrs) {
		cp = ((char *)rtm + rtm->rtm_hdrlen);
		for (i = 1; i; i <<= 1) {
			if (i & rtm->rtm_addrs) {
				sa = (struct sockaddr *)cp;
				switch (i) {
				case RTA_DST:
					sin = (struct sockaddr_inarp *)sa;
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

	*sinp = sin;
	*sdlp = sdl;

	return (0);
}

/*
 * Set an individual arp entry
 */
int
arpset(int argc, char *argv[])
{
	struct sockaddr_inarp *sin;
	struct sockaddr_dl *sdl;
	struct rt_msghdr *rtm;
	char *eaddr, *host;
	struct ether_addr *ea = NULL;
	int flags = 0, set = 1, doing_proxy, export_only, i;

	sin = &sin_m;
	rtm = &(m_rtmsg.m_rtm);

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	}

	if ((set && (argc < 3 || argc > 6)) || (!set && argc != 3)) {
		printf("%% %s <inet addr> <ether addr> [temp | permanent] "
		    "[pub]\n", argv[0]);
		printf("%% no %s <inet addr> [ether addr]\n", argv[0]);
		return(1);
	}

	if (!set) {
		return(arpdelete(argv[1], NULL));
	}

	if (argc >= 3) {
		host = argv[1];
		eaddr = argv[2];
	} else {
		host = argv[1];
		eaddr = NULL;
	}
	if (getsocket() < 0)
		return (1);
	sdl_m = blank_sdl;		/* struct copy */
	sin_m = blank_sin;		/* struct copy */
	if (getinetaddr(host, &sin->sin_addr) == -1)
		return (1);
	if (set) {
		ea = ether_aton(eaddr);
		if (ea == NULL) {
			printf("%% arpset: invalid ethernet"
			    " address: %s\n", eaddr);
			return (0);
		}
	}
	memcpy(LLADDR(&sdl_m), ea, sizeof(*ea));
	sdl_m.sdl_alen = 6;
	expire_time = 0;
	doing_proxy = flags = export_only = 0;
	for (i = 3; i < argc; i++) {
		if (isprefix(argv[i], "temp")) {
			struct timeval now;

			gettimeofday(&now, 0);
			expire_time = now.tv_sec + 20 * 60;
			if (flags & RTF_PERMANENT_ARP) {
				/* temp or permanent, not both */
				printf("%% temp or permanent, not both\n");
				return (0);
			}
		} else if (isprefix(argv[i], "pub")) {
			flags |= RTF_ANNOUNCE;
			doing_proxy = SIN_PROXY;
		} else if (isprefix(argv[i], "permanent")) {
			flags |= RTF_PERMANENT_ARP;
			if (expire_time != 0) {
				/* temp or permanent, not both */
				printf("%% temp or permanent, not both\n");
				return (0);
			}
		} else {
			printf("%% invalid parameter: %s\n", argv[i]);
			return (0);
		}
	}

tryagain:
	if (rtget(&sin, &sdl, flags, doing_proxy, export_only) < 0) {
		printf("%% %s\n", host);
		return (1);
	}
	if (sin->sin_addr.s_addr == sin_m.sin_addr.s_addr) {
		if (sdl->sdl_family == AF_LINK &&
		    (rtm->rtm_flags & RTF_LLINFO) &&
		    !(rtm->rtm_flags & RTF_GATEWAY))
			switch (sdl->sdl_type) {
			case IFT_ETHER:
			case IFT_FDDI:
			case IFT_ISO88023:
			case IFT_ISO88024:
			case IFT_ISO88025:
			case IFT_CARP:
				goto overwrite;
			}

		if (doing_proxy == 0) {
			printf("%% arpset: can only proxy for %s\n", host);
			return (1);
		}
		if (sin_m.sin_other & SIN_PROXY) {
			printf("%% arpset: proxy entry exists for non 802 device\n");
			return (1);
		}
		sin_m.sin_other = SIN_PROXY;
		export_only = 1;
		goto tryagain;
	}

overwrite:
	if (sdl->sdl_family != AF_LINK) {
		printf("%% arpset: cannot intuit interface index and type for %s\n", host);
		return (1);
	}
	sdl_m.sdl_type = sdl->sdl_type;
	sdl_m.sdl_index = sdl->sdl_index;
	return (rtmsg_arp(RTM_ADD, flags, doing_proxy, export_only));
}

#define W_ADDR	36
#define W_LL	17
#define W_IF	6

/*
 * Display an individual arp entry
 */
int
arpget(const char *host)
{
	struct sockaddr_inarp *sin;
	int found_entry;

	sin = &sin_m;
	sin_m = blank_sin;		/* struct copy */
	if (getinetaddr(host, &sin->sin_addr) == -1) {
		printf("%% arpget: getinetaddr: failure %s\n", strerror(errno));
		return (1);
	}

	printf("%-*.*s %-*.*s %*.*s %-10.10s %5s\n",
	    W_ADDR, W_ADDR, "Host", W_LL, W_LL, "Ethernet Address",
	    W_IF, W_IF, "Netif", "Expire", "Flags");

	found_entry = arpsearch(NULL, "", sin->sin_addr.s_addr, print_entry);
	if (found_entry == 0) {
		printf("%% %-*.*s no entry\n", W_ADDR, W_ADDR,
		    inet_ntoa(sin->sin_addr));
		return (1);
	}
	return (0);
}

/*
 * Delete an arp entry
 */
int
arpdelete(const char *host, const char *info)
{
	struct sockaddr_inarp *sin;
	struct rt_msghdr *rtm;
	struct sockaddr_dl *sdl;
	int doing_proxy = 0, export_only = 0;

	sin = &sin_m;
	rtm = &m_rtmsg.m_rtm;

	if (info && isprefix((char *)info, "proxy"))
		export_only = 1;
	if (getsocket() < 0)
		return (1);
	sin_m = blank_sin;		/* struct copy */
	if (getinetaddr(host, &sin->sin_addr) == -1)
		return (1);
tryagain:
	if (rtget(&sin, &sdl, 0, doing_proxy, export_only) < 0) {
		printf("%% %s\n", host);
		return (1);
	}
	if (sin->sin_addr.s_addr == sin_m.sin_addr.s_addr) {
		if (sdl->sdl_family == AF_LINK && rtm->rtm_flags & RTF_LLINFO) {
			if (rtm->rtm_flags & RTF_LOCAL)
				return (0);
		    	if (!(rtm->rtm_flags & RTF_GATEWAY))
				switch (sdl->sdl_type) {
				case IFT_ETHER:
				case IFT_FDDI:
				case IFT_ISO88023:
				case IFT_ISO88024:
				case IFT_ISO88025:
				case IFT_CARP:
					goto delete;
				}
		}
	}

	if (sin_m.sin_other & SIN_PROXY) {
		printf("%% arpdelete: can't locate %s\n", host);
		return (1);
	} else {
		sin_m.sin_other = SIN_PROXY;
		goto tryagain;
	}
delete:
	if (sdl->sdl_family != AF_LINK) {
		printf("%% cannot locate %s\n", host);
		return (1);
	}
	if (rtmsg_arp(RTM_DELETE, 0, doing_proxy, export_only)) {
		printf("%% delete failure: %s\n", strerror(errno));
		return (1);
	}
	return (0);
}

/*
 * Search the entire arp table, and do some action on matching entries.
 */
int
arpsearch(FILE *output, char *delim, in_addr_t addr, void (*action)
    (FILE *output, char *delim, struct sockaddr_dl *sdl,
    struct sockaddr_inarp *sin, struct rt_msghdr *rtm))
{
	char *next;
	struct rt_msghdr *rtm;
	struct sockaddr_inarp *sin;
	struct sockaddr_dl *sdl;
	struct rtdump *rtdump;
	int found_entry = 0;

	rtdump = getrtdump(AF_INET, RTF_LLINFO, 0);
	if (rtdump == NULL)
		return 0;
	for (next = rtdump->buf; next < rtdump->lim; next += rtm->rtm_msglen)
	{
		rtm = (struct rt_msghdr *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		sin = (struct sockaddr_inarp *)(next + rtm->rtm_hdrlen);
		sdl = (struct sockaddr_dl *)(sin + 1);
		if (addr) {
			if (addr != sin->sin_addr.s_addr)
				continue;
			found_entry = 1;
		}
		(*action)(output, delim, sdl, sin, rtm);
	}
	freertdump(rtdump);
	return(found_entry);
}

/*
 * Dump the entire ARP table
 */
void
arpdump(void)
{
	printf("%-*.*s %-*.*s %*.*s %-10.10s %5s\n",
	    W_ADDR, W_ADDR, "Host", W_LL, W_LL, "Ethernet Address",
	    W_IF, W_IF, "Netif", "Expire", "Flags");

	arpsearch(NULL, "", 0, print_entry);
}

void
conf_arp(FILE *output, char *delim)
{
	arpsearch(output, delim, 0, conf_arp_entry);
}

void
conf_arp_entry(FILE *output, char *delim, struct sockaddr_dl *sdl,
    struct sockaddr_inarp *sin, struct rt_msghdr *rtm)
{
	char *host;

        if (output == NULL) {
		printf("%% conf_arp_entry: unprepared\n");
		return;
	}

	host = inet_ntoa(sin->sin_addr);

	if ((rtm->rtm_flags & RTF_LOCAL) || rtm->rtm_rmx.rmx_expire != 0)
		return;

	fprintf(output, "%s%s %s", delim, host, ether_str(sdl));
	if (rtm->rtm_flags & RTF_PERMANENT_ARP)
		fputs(" permanent", output);
	if (rtm->rtm_flags & RTF_ANNOUNCE)
		fputs(" pub", output);
	fputs("\n", output);
}

/*
 * Display an arp entry
 */
void
print_entry(FILE *output, char *delim, struct sockaddr_dl *sdl,
    struct sockaddr_inarp *sin, struct rt_msghdr *rtm)
{
	char ifix_buf[IFNAMSIZ], *ifname, *host;
	int addrwidth, llwidth, ifwidth ;
	struct timeval now;

	if (output != NULL) {
		printf("%% print_entry: unprepared\n");
		return;
	}

	gettimeofday(&now, 0);

	host = inet_ntoa(sin->sin_addr);

	addrwidth = strlen(host);
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

	printf("%s%-*.*s %-*.*s %*.*s", delim, addrwidth, addrwidth, host,
	    llwidth, llwidth, ether_str(sdl), ifwidth, ifwidth, ifname);

	if (rtm->rtm_flags & (RTF_PERMANENT_ARP|RTF_LOCAL))
		printf(" %-10.10s", "permanent");
	else if (rtm->rtm_rmx.rmx_expire == 0)
		printf(" %-10.10s", "static");
	else if (rtm->rtm_rmx.rmx_expire > now.tv_sec)
		printf(" %-10.10s",
		    sec2str(rtm->rtm_rmx.rmx_expire - now.tv_sec));
	else
		printf(" %-10.10s", "expired");

	printf(" %s%s%s\n",
	    (rtm->rtm_flags & RTF_LOCAL) ? "l" : "",
	    (sin->sin_other & SIN_PROXY) ? "P" : "",
	    (rtm->rtm_flags & RTF_ANNOUNCE) ? "p" : "");
}

/*
 * Nuke an arp entry
 */
void
nuke_entry(struct sockaddr_dl *sdl, struct sockaddr_inarp *sin,
    struct rt_msghdr *rtm)
{
	char ip[20];

	strlcpy(ip, inet_ntoa(sin->sin_addr), sizeof(ip));
	arpdelete(ip, NULL);
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

	return(hbuf);
}

/* -1 error */
int
rtmsg_arp(int cmd, int flags, int doing_proxy, int export_only)
{
	static int seq;
	struct rt_msghdr *rtm;
	char *cp;
	int l;

	rtm = &m_rtmsg.m_rtm;
	cp = m_rtmsg.m_space;
	errno = 0;

	if (cmd == RTM_DELETE)
		goto doit;
	memset(&m_rtmsg, 0, sizeof(m_rtmsg));
	rtm->rtm_flags = flags;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_hdrlen = sizeof(*rtm);
	rtm->rtm_tableid = cli_rtable;

	switch (cmd) {
	default:
		printf("%% rtmsg_arp: internal wrong cmd\n");
		return(-1);
		/*NOTREACHED*/
	case RTM_ADD:
		rtm->rtm_addrs |= RTA_GATEWAY;
		rtm->rtm_rmx.rmx_expire = expire_time;
		rtm->rtm_inits = RTV_EXPIRE;
		rtm->rtm_flags |= (RTF_HOST | RTF_STATIC);
		sin_m.sin_other = 0;
		if (doing_proxy) {
			if (export_only)
				sin_m.sin_other = SIN_PROXY;
			else {
				rtm->rtm_addrs |= RTA_NETMASK;
				rtm->rtm_flags &= ~RTF_HOST;
			}
		}
		/* FALLTHROUGH */
	case RTM_GET:
		rtm->rtm_addrs |= (RTA_DST | RTA_IFP);
	}

#define NEXTADDR(w, s)					\
	if (rtm->rtm_addrs & (w)) {			\
		memcpy(cp, &s, sizeof(s));		\
		ADVANCE(cp, (struct sockaddr *)&(s));	\
	}

	NEXTADDR(RTA_DST, sin_m);
	NEXTADDR(RTA_GATEWAY, sdl_m);
	NEXTADDR(RTA_NETMASK, so_1mask);
	NEXTADDR(RTA_IFP, ifp_m);

	rtm->rtm_msglen = cp - (char *)&m_rtmsg;
doit:
	l = rtm->rtm_msglen;
	rtm->rtm_seq = ++seq;
	rtm->rtm_type = cmd;
	if (write(s, (char *)&m_rtmsg, l) < 0)
		if (errno != ESRCH || cmd != RTM_DELETE) {
			printf("%% rtmsg_arp: writing to routing socket: %s\n",
			    strerror(errno));
			return (-1);
		}

	do {
		l = read(s, (char *)&m_rtmsg, sizeof(m_rtmsg));
	} while (l > 0 && (rtm->rtm_version != RTM_VERSION ||
	    rtm->rtm_seq != seq || rtm->rtm_pid != pid));

	if (l < 0)
		printf("%% rtmsg_arp: read from routing socket\n");
	return (0);
}

int
getinetaddr(const char *host, struct in_addr *inap)
{
	struct hostent *hp;

	if (inet_aton(host, inap) == 1)
		return (0);
	if ((hp = gethostbyname(host)) == NULL) {
		printf("%% getinetaddr: %s: %s\n", host, hstrerror(h_errno));
		return (-1);
	}
	memcpy(inap, hp->h_addr, sizeof(*inap));
	return (0);
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

	return(result);
}
