/* $nsh: arp.c,v 1.6 2012/05/20 20:11:01 chris Exp $ */
/* From: $OpenBSD: /usr/src/usr.sbin/arp/arp.c,v 1.40 2007/08/24 13:12:16 claudio Exp $ */
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

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

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
#define _WANT_SO_
#include "externs.h"

int delete(const char *, const char *);
int search(in_addr_t addr, void (*action)(struct sockaddr_dl *sdl,
	struct sockaddr_inarp *sin, struct rt_msghdr *rtm));
void print_entry(struct sockaddr_dl *sdl,
	struct sockaddr_inarp *sin, struct rt_msghdr *rtm);
int arpget(const char *);
int arpset(int, char **);

struct sockaddr_inarp	blank_sin = { sizeof(blank_sin), AF_INET };
struct sockaddr_dl	blank_sdl = { sizeof(blank_sdl), AF_LINK };
struct sockaddr_in	blank_mask = { 8, 0, 0, { 0xffffffff } };

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
	int doing_proxy, export_only;
	int flags = 0, set = 1, tableid = 0;

	sin = &so_dst.sinarp;
	rtm = &(m_rtmsg.m_rtm);

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	}

	if ((set && argc != 3) || (!set && (argc < 2 || argc > 3))) {
		printf("%% %s <inet addr> <ether addr>\n", argv[0]);
		printf("%% no %s <inet addr> [ether addr]\n", argv[0]);
		return(1);
	}

	if (!set) {
		return(delete(argv[1], NULL));
	}

	if (argc == 3) {
		host = argv[1];
		eaddr = argv[2];
	} else {
		host = argv[1];
		eaddr = NULL;
	}

	memcpy(&so_gate, &blank_sdl, sizeof(so_gate));
	memcpy(&so_dst, &blank_sin, sizeof(so_dst));
	memcpy(&so_mask, &blank_mask, sizeof(so_mask));

	if (inet_aton(host, &sin->sin_addr) < 1) {
		printf("%% invalid IP address %s: %s\n", host, strerror(errno));
		return (1);
	}
	if (set) {
		struct ether_addr *ea;

		ea = ether_aton(eaddr);
		if (ea == NULL) {
			printf("%% invalid ethernet address (%s)\n", eaddr);
			return (1);
		}
		memcpy(LLADDR(&so_gate.sdl), ea, sizeof(*ea));
	}

	so_gate.sdl.sdl_alen = ETHER_ADDR_LEN;
	doing_proxy = flags = export_only = 0;
	if (isprefix(argv[0], "proxy-arp")) {
		flags |= RTF_ANNOUNCE;
		doing_proxy = SIN_PROXY;
	}
	flags |= RTF_PERMANENT_ARP;

tryagain:
	rtm_addrs = RTA_DST | RTA_GATEWAY;
	if (rtmsg(RTM_GET, flags, doing_proxy, export_only, tableid) < 0) {
		printf("%% RTM_GET %s: %s\n", host, strerror(errno));
	}
	sin = (struct sockaddr_inarp *)((char *)rtm + rtm->rtm_hdrlen);
	sdl = (struct sockaddr_dl *)(ROUNDUP(sin->sin_len) + (char *)sin);
	if (sin->sin_addr.s_addr == so_dst.sinarp.sin_addr.s_addr) {
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
			printf("%% set: can only proxy for %s\n", host);
			return (1);
		}
		if (so_dst.sinarp.sin_other & SIN_PROXY) {
			printf("%% set: proxy entry exists for non 802 device\n");
			return (1);
		}
		so_dst.sinarp.sin_other = SIN_PROXY;
		export_only = 1;
		goto tryagain;
	}

overwrite:
	if (sdl->sdl_family != AF_LINK) {
		printf("%% cannot match arp entry %s\n", host);
		return (1);
	}
	rtm_addrs = RTA_GATEWAY | RTA_DST;
	flags |= RTF_HOST | RTF_STATIC;
	so_gate.sdl.sdl_type = sdl->sdl_type;
	so_gate.sdl.sdl_index = sdl->sdl_index;
	memcpy(&so_mask, &blank_mask, sizeof(so_mask));
	if (rtmsg(RTM_ADD, flags, doing_proxy, export_only, tableid) < 0) {
		printf("%% RTM_ADD %s: %s\n", host, strerror(errno));
	}
	return (errno);
}

/*
 * Display an individual arp entry
 */
int
arpget(const char *host)
{
	struct sockaddr_inarp *sin;
	int found_entry;

	sin = &so_dst.sinarp;

	memcpy(&so_gate, &blank_sdl, sizeof(so_gate));
	memcpy(&so_dst, &blank_sin, sizeof(so_dst));

	if (inet_aton(host, &sin->sin_addr) <  1) {
		printf("%% arpget: inet_aton: %s\n",strerror(errno));
		return(1);
	}
	memcpy(&so_mask, &blank_mask, sizeof(struct sockaddr_in));
	found_entry = search(sin->sin_addr.s_addr, print_entry);
	if (found_entry == 0) {
		printf("%% %s -- no entry\n", inet_ntoa(sin->sin_addr));
		return(1);
	}
	return (0);
}

/*
 * Delete an arp entry
 */
int
delete(const char *host, const char *info)
{
	struct sockaddr_inarp *sin;
	struct rt_msghdr *rtm;
	struct sockaddr_dl *sdl;
	int export_only = 0, tableid = 0;

	sin = &so_dst.sinarp;
	rtm = &(m_rtmsg.m_rtm);

	if (info && strncmp(info, "pro", 3) )
		export_only = 1;

        memcpy(&so_dst, &blank_sin, sizeof(so_dst));
	memcpy(&so_mask, &blank_mask, sizeof(so_mask));

	if (inet_aton(host, &sin->sin_addr) < 1) {
		printf("%% delete: inet_aton: %s\n", strerror(errno));
		return (1);
	}
tryagain:
	rtm_addrs = RTA_DST;
	if (rtmsg(RTM_GET, 0, 0, 0, tableid) < 0) {
		printf("%% RTM_GET: %s not found\n", host);
		return (1);
	}
	sin = (struct sockaddr_inarp *)((char *)rtm + rtm->rtm_hdrlen);
	sdl = (struct sockaddr_dl *)(ROUNDUP(sin->sin_len) + (char *)sin);
	if (sin->sin_addr.s_addr == so_dst.sin.sin_addr.s_addr)
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
				goto delete;
			}

	if (so_dst.sinarp.sin_other & SIN_PROXY) {
		printf("%% can't locate %s\n", host);
		return (1);
	} else {
		so_dst.sinarp.sin_other = SIN_PROXY;
		goto tryagain;
	}
delete:
	if (sdl->sdl_family != AF_LINK) {
		printf("%% cannot locate %s\n", host);
		return (1);
	}
	if (rtmsg(RTM_DELETE, 0, 0, export_only, tableid) < 0) {
		printf("%% delete failure: %s\n", strerror(errno));
		return (1);
	}
	return (0);
}

/*
 * Search the entire arp table, and do some action on matching entries.
 */
int
search(in_addr_t addr, void (*action)(struct sockaddr_dl *sdl,
    struct sockaddr_inarp *sin, struct rt_msghdr *rtm))
{
	char *next;
	struct rt_msghdr *rtm;
	struct sockaddr_inarp *sin;
	struct sockaddr_dl *sdl;
	struct rtdump *rtdump;
	int found_entry = 0;

	rtdump = getrtdump(0, RTF_LLINFO, 0);
	if (rtdump == NULL)
		return 0;
	for (next = rtdump->buf; next < rtdump->lim; next += rtm->rtm_msglen) {
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
		(*action)(sdl, sin, rtm);
	}
	freertdump(rtdump);
	return(found_entry);
}

/*
 * Display an arp entry
 */
void
print_entry(struct sockaddr_dl *sdl, struct sockaddr_inarp *sin,
    struct rt_msghdr *rtm)
{
	char ifname[IFNAMSIZ];
	printf("%s at ", inet_ntoa(sin->sin_addr));
	if (sdl->sdl_alen)
		printf("%s", mylink_ntoa(sdl));
	else
		printf("(incomplete)");
	if (if_indextoname(sdl->sdl_index, ifname) != NULL)
		printf(" on %s", ifname);
	if (rtm->rtm_flags & RTF_PERMANENT_ARP)
		printf(" permanent");
	if (rtm->rtm_rmx.rmx_expire == 0)
		printf(" static");
	if (sin->sin_other & SIN_PROXY)
		printf(" published (proxy only)");
	if (rtm->rtm_addrs & RTA_NETMASK) {
		sin = (struct sockaddr_inarp *)
		    (ROUNDUP(sdl->sdl_len) + (char *)sdl);
		if (sin->sin_addr.s_addr == 0xffffffff)
			printf(" published");
		if (sin->sin_len != 8)
			printf("(weird sockaddr length %d)", sin->sin_len);
	}
	printf("\n");
}
