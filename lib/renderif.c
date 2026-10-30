/*
 * Copyright (c) 2002-2008 Chris Cappuccio <chris@nmedia.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*-
 * Copyright (c) 1997, 1998, 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2004 Chris Cappuccio <chris@nmedia.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* From: $OpenBSD: ifconfig.c,v 1.430 2020/11/06 21:24:47 kn Exp $	*/

/* From: $OpenBSD: ifconfig.c,v 1.453 2022/03/07 08:13:13 stsp Exp $	*/

/* From: $OpenBSD: ifconfig.c,v 1.174 2006/08/29 17:22:00 henning Exp $  */
/*
 * Copyright (c) 2006
 *      Manuel Pata.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* From: $OpenBSD: brconfig.c,v 1.27 2003/09/26 03:29:59 deraadt Exp $ */
/*
 * Copyright (c) 1999, 2000 Jason L. Wright (jason@thought.net)
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2026 Chris Cappuccio <chris@nmedia.net>
 * Copyright (c) 2017, 2021 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * How nsh prints the facts of interfaces: each interface with its
 * addresses, media, carp, wireguard, umb and trunk records, VLANs,
 * bridges, the addresses show ip lists, and what dhcpleased and slaacd
 * report. The kinds of these records are defined here too.
 */

#include <sys/tree.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <netmpls/mpls.h>
#include <netdb.h>
#include <net/if_vlan_var.h>
#include <net/if_pflow.h>
#include <net/if_media.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/limits.h>
#include <netinet/ip_carp.h>
#include <time.h>
#include <net/if_wg.h>
#include <stddef.h>
#include <resolv.h>
#include <util.h>
#include <dev/usb/mbim.h>
#include <dev/usb/if_umb.h>
#include <net/if_trunk.h>
#include <net/if_bridge.h>
#include <err.h>
#include <sysexits.h>
#include <sys/time.h>
#include <strings.h>

#include "ip.h"
#include "bridge.h"
#include "stringlist.h"
#include "externs.h"
#include "ctl.h"
#include "settings.h"
#include "facts.h"
#include "showfacts.h"
#include "kfacts.h"

/* lifted right from ifconfig.c */
#define HWFEATURESBITS							\
	"\024\1CSUM_IPv4\2CSUM_TCPv4\3CSUM_UDPv4"			\
	"\5VLAN_MTU\6VLAN_HWTAGGING\10CSUM_TCPv6"			\
	"\11CSUM_UDPv6\20WOL"
#include "session.h"
#include "kernel.h"

char *iftype(int int_type);

static const struct {
	char *name;
	u_int8_t type;
} iftypes[] = {
	/* OpenBSD-specific types */
	{ "Packet Filter Logging",	IFT_PFLOG },
	{ "Packet Filter State Synchronization", IFT_PFSYNC },
	{ "pflow Accounting Data",	IFT_PFLOW },
	{ "IPsec Encapsulation",	IFT_ENC },
	{ "Generic Tunnel",		IFT_GIF },
	{ "Common Address Redundancy Protocol",	IFT_CARP },
	{ "Bluetooth",			IFT_BLUETOOTH },
	{ "Mobile Broadband Interface",	IFT_MBIM },
	{ "Wireguard",			IFT_WIREGUARD },
	/* IANA-assigned types */
	{ "Ethernet",			IFT_ETHER },
	{ "USB",			IFT_USB },
	{ "Transparent bridge",		IFT_BRIDGE },
	{ "HDLC",			IFT_HDLC },
	{ "IEEE 802.1Q",		IFT_L2VLAN },
	{ "Layer 3 Virtual LAN",	IFT_L3IPVLAN },
	{ "Virtual",			IFT_PROPVIRTUAL },
	{ "MPLS Tunnel Virtual",	IFT_MPLSTUNNEL },
	{ "MPLS Provider Edge",		IFT_MPLS },
	{ "IEEE 802.3ad Link Aggregate", IFT_IEEE8023ADLAG },
	{ "PPP",			IFT_PPP },
	{ "Loopback",			IFT_LOOP },
	{ "Network Tunnel",		IFT_TUNNEL },
	{ "Coffee Pot",			IFT_COFFEE },
	{ "IEEE 802.11",		IFT_IEEE80211 },
	{ "Unspecified",		IFT_OTHER },
};

/* an interface, and its addresses, as facts */
static struct facts_field interface_fields[] = {
	[IF_NAME] =		{ "name",		FACT_STRING },
	[IF_DESCR] =		{ "description",	FACT_STRING },
	[IF_BRIDGE] =		{ "bridge",		FACT_U64 },
	[IF_FLAGS] =		{ "flags",		FACT_U64 },
	[IF_LASTCHANGE] =	{ "last-change",	FACT_TIME },
	[IF_TYPE] =		{ "type",		FACT_U64 },
	[IF_LLADDR] =		{ "hardware-address",	FACT_ADDRESS },
	[IF_LINK] =		{ "link",		FACT_STRING },
	[IF_RDOMAIN] =		{ "rdomain",		FACT_U64 },
	[IF_MTU] =		{ "mtu",		FACT_U64 },
	[IF_HARDMTU] =		{ "hardmtu",		FACT_U64 },
	[IF_BAUDRATE] =		{ "line-rate",		FACT_U64 },
	[IF_IPACKETS] =		{ "input-packets",	FACT_U64 },
	[IF_IBYTES] =		{ "input-bytes",	FACT_U64 },
	[IF_IERRORS] =		{ "input-errors",	FACT_U64 },
	[IF_IQDROPS] =		{ "input-drops",	FACT_U64 },
	[IF_OPACKETS] =		{ "output-packets",	FACT_U64 },
	[IF_OBYTES] =		{ "output-bytes",	FACT_U64 },
	[IF_OERRORS] =		{ "output-errors",	FACT_U64 },
	[IF_NOPROTO] =		{ "unsupported",	FACT_U64 },
	[IF_COLLISIONS] =	{ "collisions",		FACT_U64 },
	[IF_CAPABILITIES] =	{ "hardware-features",	FACT_U64 },
	[IF_MEDIACOUNT] =	{ "media-count",	FACT_U64 },
	[IF_MEDIASTATUS] =	{ "media-status",	FACT_U64 },
	[IF_TUNSRC] =		{ "tunnel-source",	FACT_ADDRESS },
	[IF_TUNDST] =		{ "tunnel-destination",	FACT_ADDRESS },
	[IF_TUNPORT] =		{ "tunnel-port",	FACT_U64 },
	[IF_TUNRDOMAIN] =	{ "tunnel-rdomain",	FACT_U64 },
	[IF_TUNTTL] =		{ "tunnel-ttl",		FACT_U64 },
	[IF_VNETID] =		{ "vnetid",		FACT_U64 },
	[IF_PARENT] =		{ "parent",		FACT_STRING },
	[IF_SSID] =		{ "ssid",		FACT_STRING },
	[IF_POWERSAVE] =	{ "powersave",		FACT_U64 },
	[IF_CARPBALANCING] =	{ "carp-balancing",	FACT_U64 },
	[IF_CARPPEER] =		{ "carp-peer",		FACT_ADDRESS },
	[IF_CARPDEV] =		{ "carp-device",	FACT_STRING },
	[IF_CARPADVBASE] =	{ "carp-advbase",	FACT_U64 },
	[IF_WGPUBLIC] =		{ "wireguard-public-key", FACT_STRING },
	[IF_TRUNKPARENT] =	{ "trunk-parent",	FACT_STRING },
	[IF_TRUNKFLAGS] =	{ "trunk-port-flags",	FACT_U64 },
	[IF_TRUNKPROTO] =	{ "trunk-protocol",	FACT_U64 },
};
struct facts_kind kind_interface = { "interface", interface_fields,
    IF_NFIELDS };

static struct facts_field address_fields[] = {
	[ADDR_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[ADDR_MASK] =		{ "netmask",		FACT_ADDRESS },
	[ADDR_DST] =		{ "destination",	FACT_ADDRESS },
	[ADDR_BRD] =		{ "broadcast",		FACT_ADDRESS },
	[ADDR_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_address = { "address", address_fields, ADDR_NFIELDS };

/* the names of interface types, for f */
void
if_typenames(struct facts_field *f)
{
	struct facts_name	*names;
	size_t			 i;

	if ((names = calloc(nitems(iftypes), sizeof(*names))) == NULL)
		return;
	for (i = 0; i < nitems(iftypes); i++) {
		names[i].value = iftypes[i].type;
		names[i].name = iftypes[i].name;
	}
	f->naming = FACT_VALUES;
	f->names = names;
	f->nnames = nitems(iftypes);
}

/* a VLAN, as facts */
static struct facts_field vlan_fields[] = {
	[VLAN_NAME] =		{ "name",		FACT_STRING },
	[VLAN_VNETID] =		{ "vnetid",		FACT_U64 },
	[VLAN_FLAGS] =		{ "flags",		FACT_U64 },
	[VLAN_RDOMAIN] =	{ "rdomain",		FACT_U64 },
	[VLAN_PARENT] =		{ "parent",		FACT_STRING },
	[VLAN_BRIDGE] =		{ "bridge",		FACT_STRING },
	[VLAN_DESCR] =		{ "description",	FACT_STRING },
};
struct facts_kind kind_vlan = { "vlan", vlan_fields, VLAN_NFIELDS };

void
if_facts_init(void)
{
	facts_bitnames(&interface_fields[IF_FLAGS], ifnetflags);
	if_typenames(&interface_fields[IF_TYPE]);
	facts_bitnames(&interface_fields[IF_CAPABILITIES], HWFEATURESBITS);
	carp_balnames(&interface_fields[IF_CARPBALANCING]);
	trunk_names(&interface_fields[IF_TRUNKPROTO],
	    &interface_fields[IF_TRUNKFLAGS]);
	facts_bitnames(&vlan_fields[VLAN_FLAGS], ifnetflags);
}

/* an interface, as show interface printed it */
void
if_render(struct frecs *rs, FILE *outfile)
{
	struct frec		*ifr = TAILQ_LAST(rs, frecs), *a;
	struct sockaddr_storage	 ss, ms, ds;
	struct sockaddr_in	*sin = (struct sockaddr_in *)&ss;
	struct sockaddr_in	*sinmask = (struct sockaddr_in *)&ms;
	struct sockaddr_in	*sindest = (struct sockaddr_in *)&ds;
	struct sockaddr_in6	*sin6 = (struct sockaddr_in6 *)&ss;
	struct sockaddr_in6	*sin6mask = (struct sockaddr_in6 *)&ms;
	struct sockaddr_in6	*sin6dest = (struct sockaddr_in6 *)&ds;
	const struct facts_value *t;
	struct timeval		 tv;
	char			 src[NI_MAXHOST], dst[NI_MAXHOST];
	time_t			 c;
	int			 br, flags, days, hours, mins, pntd, ippntd = 0;
	uint64_t		 type, ib, ip, ob, op;

	if (ifr == NULL || ifr->k != &kind_interface)
		return;
	br = fu(ifr, IF_BRIDGE, 0);
	flags = fu(ifr, IF_FLAGS, 0);

	fprintf(outfile, "%% %s", fs(ifr, IF_NAME));
	if (fs(ifr, IF_DESCR) != NULL)
		fprintf(outfile, " (%s)", fs(ifr, IF_DESCR));
	fputc('\n', outfile);

	fprintf(outfile, "  %s is %s", br ? "Bridge" : "Interface",
	    flags & IFF_UP ? "up" : "down");

	if ((t = FV(ifr, IF_LASTCHANGE, FACT_TIME)) != NULL &&
	    t->v.t.sec) {
		gettimeofday(&tv, (struct timezone *)0);
		c = difftime(tv.tv_sec, t->v.t.sec);
		days = c / (24 * 60 * 60);
		c %= (24 * 60 * 60);
		hours = c / (60 * 60);
		c %= (60 * 60);
		mins = c / 60;
		c %= 60;
		fprintf(outfile, " (last change ");
		if (days)
			fprintf(outfile, "%id ", days);
		fprintf(outfile, "%02i:%02i:%02i)", hours, mins, (int)c);
	}

	fprintf(outfile, ", protocol is %s\n",
	    flags & IFF_RUNNING ? "up" : "down");

	type = fu(ifr, IF_TYPE, 0);
	fprintf(outfile, "  Interface type %s", iftype(type));
	if (type != IFT_WIREGUARD) {
		if (flags & IFF_BROADCAST)
			fprintf(outfile, " (Broadcast)");
		else if (flags & IFF_POINTOPOINT)
			fprintf(outfile, " (PointToPoint)");
	}
	if ((t = FV(ifr, IF_LLADDR, FACT_ADDRESS)) != NULL &&
	    t->v.a.len == ETHER_ADDR_LEN)
		fprintf(outfile, ", hardware address %s",
		    ether_ntoa((struct ether_addr *)t->v.a.bytes));
	fputc('\n', outfile);

	wg_render(rs, ifr, outfile);
	umb_render(rs, outfile);
	trunk_render(rs, ifr, outfile);
	media_render(rs, ifr, outfile);

	/*
	 * Print interface IP address, and broadcast or
	 * destination if available.  But, don't print broadcast
	 * if it is what we would expect given the ip and netmask!
	 */
	for (a = NULL; (a = frec_next(rs, a, &kind_address)) != NULL; ) {
		if (!fsockaddr(a, ADDR_ADDRESS, &ss))
			continue;
		fsockaddr(a, ADDR_MASK, &ms);
		if (!ippntd)
			fprintf(outfile, "  Internet address");
		fprintf(outfile, "%s %s", ippntd ? "," : "",
		    ss.ss_family == AF_INET ?
		    netname4(sin->sin_addr.s_addr, sinmask) :
		    netname6(sin6, sin6mask));
		ippntd = 1;

		switch (ss.ss_family) {
		case AF_INET:
			if (flags & IFF_POINTOPOINT) {
				if (fsockaddr(a, ADDR_DST, &ds))
					fprintf(outfile, " (Destination %s)",
					    routename4(
					    sindest->sin_addr.s_addr));
			} else if (flags & IFF_BROADCAST &&
			    fsockaddr(a, ADDR_BRD, &ds)) {
				/*
				 * no reason to show the broadcast addr
				 * if it is standard (this should always
				 * be true unless someone has messed up their
				 * network or they are playing around...)
				 */
				if (ntohl(sindest->sin_addr.s_addr) !=
				    in4_brdaddr(sin->sin_addr.s_addr,
				    sinmask->sin_addr.s_addr) &&
				    ntohl(sindest->sin_addr.s_addr) !=
				    INADDR_ANY)
					fprintf(outfile, " (Broadcast %s)",
					    inet_ntoa(sindest->sin_addr));
			}
			break;
		case AF_INET6:
			if (flags & IFF_POINTOPOINT &&
			    fsockaddr(a, ADDR_DST, &ds))
				fprintf(outfile, " (Destination %s)",
				    routename6(sin6dest));
			break;
		}
	}
	if (ippntd)
		fputc('\n', outfile);

	if (!br) {
		/* a tunnel with a destination port, as phys_status() said */
		if (fu(ifr, IF_TUNPORT, 0) > 0 &&
		    fsockaddr(ifr, IF_TUNSRC, &ss) &&
		    fsockaddr(ifr, IF_TUNDST, &ds) &&
		    getnameinfo((struct sockaddr *)&ss, ss.ss_len, src,
		    sizeof(src), 0, 0, NI_NUMERICHOST) == 0 &&
		    getnameinfo((struct sockaddr *)&ds, ds.ss_len, dst,
		    sizeof(dst), 0, 0, NI_NUMERICHOST) == 0) {
			fprintf(outfile, "  Tunnel source %s destination %s",
			    src, dst);
			if (fu(ifr, IF_TUNRDOMAIN, 0) != 0)
				fprintf(outfile, " destination rdomain %i",
				    (int)fu(ifr, IF_TUNRDOMAIN, 0));
			if (fu(ifr, IF_TUNTTL, 0) != 0)
				fprintf(outfile, " ttl %i",
				    (int)fu(ifr, IF_TUNTTL, 0));
			fputc('\n', outfile);
		}
		carp_render(rs, ifr, outfile);

		fputc(' ', outfile);
		if (fhas(ifr, IF_VNETID))
			fprintf(outfile, " vnetid %llu,",
			    (unsigned long long)fu(ifr, IF_VNETID, 0));
		if (fs(ifr, IF_PARENT) != NULL)
			fprintf(outfile, " parent %s,", fs(ifr, IF_PARENT));
		if (fhas(ifr, IF_RDOMAIN))
			fprintf(outfile, " rdomain %d,",
			    (int)fu(ifr, IF_RDOMAIN, 0));

		/*
		 * Display MTU, line rate
		 */
		fprintf(outfile, " MTU %u bytes", (u_int)fu(ifr, IF_MTU, 0));
		if (fu(ifr, IF_HARDMTU, 0))
			fprintf(outfile, " (hardmtu %u)",
			    (u_int)fu(ifr, IF_HARDMTU, 0));
		if (fu(ifr, IF_BAUDRATE, 0))
			fprintf(outfile, ", Line Rate %llu %s",
			    (unsigned long long)(MBPS(fu(ifr, IF_BAUDRATE, 0)) ?
			    MBPS(fu(ifr, IF_BAUDRATE, 0)) :
			    fu(ifr, IF_BAUDRATE, 0) / 1000),
			    MBPS(fu(ifr, IF_BAUDRATE, 0)) ? "Mbps" : "Kbps");

		fputc('\n', outfile);
	}

	if (fs(ifr, IF_SSID) != NULL) {
		fprintf(outfile, "  SSID %s", fs(ifr, IF_SSID));
		if (fhas(ifr, IF_POWERSAVE))
			fprintf(outfile, ", powersaving (%d ms)\n",
			    (int)fu(ifr, IF_POWERSAVE, 0));
		fputc('\n', outfile);
	}

	/*
	 * Display remaining info from if_data structure
	 */
	ip = fu(ifr, IF_IPACKETS, 0);
	ib = fu(ifr, IF_IBYTES, 0);
	op = fu(ifr, IF_OPACKETS, 0);
	ob = fu(ifr, IF_OBYTES, 0);
	fprintf(outfile, "  %llu packets input, %llu bytes, %llu errors, "
	    "%llu drops\n", (unsigned long long)ip, (unsigned long long)ib,
	    (unsigned long long)fu(ifr, IF_IERRORS, 0),
	    (unsigned long long)fu(ifr, IF_IQDROPS, 0));
	fprintf(outfile, "  %llu packets output, %llu bytes, %llu errors, "
	    "%llu unsupported\n", (unsigned long long)op,
	    (unsigned long long)ob,
	    (unsigned long long)fu(ifr, IF_OERRORS, 0),
	    (unsigned long long)fu(ifr, IF_NOPROTO, 0));
	if (ib && ip && (ib / ip) >= ETHERMIN) {
		/* < ETHERMIN means byte counter probably rolled over */
		fprintf(outfile, "  %llu input", (unsigned long long)(ib / ip));
		pntd = 1;
	} else
		pntd = 0;
	if (ob && op && (ob / op) >= ETHERMIN) {
		/* < ETHERMIN means byte counter probably rolled over */
		fprintf(outfile, "%s%llu output", pntd ? ", " : "  ",
		    (unsigned long long)(ob / op));
		pntd = 1;
	}
	if (pntd)
		fprintf(outfile, " (average bytes/packet)\n");

	switch (type) {
	/*
	 * These appear to be the only interface types to increase collision
	 * count in the OpenBSD 3.2 kernel.
	 */
	case IFT_ETHER:
	case IFT_SLIP:
	case IFT_PROPVIRTUAL:
	case IFT_IEEE80211:
		fprintf(outfile, "  %llu collisions\n",
		    (unsigned long long)fu(ifr, IF_COLLISIONS, 0));
		break;
	default:
		break;
	}

	if (verbose) {
		if (flags) {
			fprintf(outfile, "  Flags:\n    ");
			bprintf(outfile, flags, ifnetflags);
			fputc('\n', outfile);
		}
		fprintf(outfile, "  Hardware features:\n    ");
		bprintf(outfile, fu(ifr, IF_CAPABILITIES, 0), HWFEATURESBITS);
		fputc('\n', outfile);
		if (br)
			bridge_render(rs, outfile);
		media_render_supported(rs, ifr, outfile);
	}
}

/* an interface, as show interface status printed it */
void
if_render_status(struct frecs *rs, FILE *outfile)
{
	struct frec	*ifr = TAILQ_LAST(rs, frecs);
	const char	*link_state_desc, *ifm_type = NULL, *ifm_subtype = NULL;
	uint64_t	 current = 0, active = 0, seen_options = 0;
	char		 ifm_options_current[128];
	char		 ifm_options_active[128];

	if (ifr == NULL || ifr->k != &kind_interface ||
	    !fhas(ifr, IF_RDOMAIN))
		return;
	ifm_options_current[0] = '\0';
	ifm_options_active[0] = '\0';

	media_status_words(rs, &current, &active);
	link_state_desc = fs(ifr, IF_LINK);
	if (link_state_desc == NULL && fu(ifr, IF_MEDIACOUNT, 0) > 0)
		link_state_desc = media_linkstate(rs, ifr);

	/* Avoid displaying "unknown" for any non-physical interface. */
	if (link_state_desc == NULL || strcmp(link_state_desc, "unknown") == 0)
		link_state_desc = "-";

	get_ifm_options_str(ifm_options_current, sizeof(ifm_options_current),
	    current, &seen_options);
	if (IFM_OPTIONS(current) != IFM_OPTIONS(active)) {
		get_ifm_options_str(ifm_options_active,
		    sizeof(ifm_options_active), active, &seen_options);
	}

	ifm_type = get_ifm_type_str(active);
	/* Avoid displaying "autoselect" for any non-physical interface. */
	if (IFM_SUBTYPE(active) != IFM_AUTO)
		ifm_subtype = get_ifm_subtype_str(active);

	fprintf(outfile, "  %-7s %-7s %-15s %10u  %s%s%s%s%s%s%s\n",
	    fs(ifr, IF_NAME),
	    (fu(ifr, IF_FLAGS, 0) & IFF_UP) ? "up" : "down", link_state_desc,
	    (u_int)fu(ifr, IF_RDOMAIN, 0),
	    ifm_type ? ifm_type : "",
	    ifm_type ? " " : "",
	    ifm_subtype ? ifm_subtype : "",
	    ifm_subtype ? " " : "",
	    ifm_options_current,
	    ifm_options_current[0] != '\0' ? " " : "",
	    ifm_options_active[0] != '\0' ? ifm_options_active : "");
}

/* an address, as facts; what configured an IPv4 one, where known */
static const struct facts_name ip_sources[] = {
	{ NSH_IP_FLAG_DHCP,	"dhcp" },
	{ NSH_IP_FLAG_IPCP,	"ipcp" },
	{ NSH_IP_FLAG_STATIC,	"static" },
};
static const struct facts_name ip_flags6[] = {
	{ IN6_IFF_ANYCAST,	"anycast" },
	{ IN6_IFF_TENTATIVE,	"tentative" },
	{ IN6_IFF_DUPLICATED,	"duplicated" },
	{ IN6_IFF_DETACHED,	"detached" },
	{ IN6_IFF_DEPRECATED,	"deprecated" },
	{ IN6_IFF_AUTOCONF,	"autoconf" },
	{ IN6_IFF_TEMPORARY,	"temporary" },
};
static struct facts_field ip_fields[] = {
	[IP_ADDRESS] =	{ "address",	FACT_ADDRESS },
	[IP_MASK] =	{ "netmask",	FACT_ADDRESS },
	[IP_IF] =	{ "interface",	FACT_STRING },
	[IP_RDOMAIN] =	{ "rdomain",	FACT_U64 },
	[IP_FLAGS6] =	{ "flags",	FACT_U64, FACT_BITS, ip_flags6,
			    nitems(ip_flags6) },
	[IP_SOURCE] =	{ "configured-by", FACT_U64, FACT_VALUES, ip_sources,
			    nitems(ip_sources) },
};
struct facts_kind kind_ip = { "ip-address", ip_fields, IP_NFIELDS };

struct ip_tree_entry {
	RB_ENTRY(ip_tree_entry) entry;
	u_short family;		/* AF_INET | AF_INET6 */
	const char *ifname;
	int rdomain;
	int flags;		/* custom IPv4 address flags */
	int flags6;		/* IN6_IFF_ flags */
	union {
		struct in_addr in;
		struct in6_addr in6;
	} addr;
};

static inline int
ip_tree_cmp(const struct ip_tree_entry *e1, const struct ip_tree_entry *e2)
{
	int cmp;

	if (e1->family < e2->family)
		return -1;
	if (e1->family > e2->family)
		return 1;

	if (e1->family == AF_INET) {
		cmp = memcmp(&e1->addr.in, &e2->addr.in,
		    sizeof(struct in_addr));
	} else {
		cmp = memcmp(&e1->addr.in6, &e2->addr.in6,
		    sizeof(struct in6_addr));
	}

	if (cmp == 0) {
		if (e1->rdomain < e2->rdomain)
			return -1;
		if (e1->rdomain > e2->rdomain)
			return 1;
	}

	return cmp;
}

RB_HEAD(ip_tree, ip_tree_entry);
RB_PROTOTYPE(ip_tree, ip_tree_entry, entry, ip_tree_cmp);
RB_GENERATE(ip_tree, ip_tree_entry, entry, ip_tree_cmp);

/* the addresses in rs, as show_ip() printed them, sorted */
void
ip_render(struct frecs *rs)
{
	struct sockaddr_storage ss;
	char buf[INET6_ADDRSTRLEN];
	char flagsbuf[64];
	struct ip_tree tree;
	struct ip_tree_entry *e = NULL;
	struct frec *r;
	int max_addr_strlen = 0;
	size_t addr_strlen;

	RB_INIT(&tree);

	/* Collect IPs */
	for (r = NULL; (r = frec_next(rs, r, &kind_ip)) != NULL; ) {
		if (!fsockaddr(r, IP_ADDRESS, &ss) ||
		    (ss.ss_family != AF_INET && ss.ss_family != AF_INET6))
			continue;

		e = calloc(1, sizeof(*e));
		if (e == NULL) {
			printf("%% show_ip: calloc: %s\n", strerror(errno));
			goto done;
		}

		e->family = ss.ss_family;
		e->ifname = fs(r, IP_IF) != NULL ? fs(r, IP_IF) : "";
		e->rdomain = fu(r, IP_RDOMAIN, 0);
		e->flags = fu(r, IP_SOURCE, 0);
		e->flags6 = fu(r, IP_FLAGS6, 0);
		if (e->family == AF_INET)
			e->addr.in = ((struct sockaddr_in *)&ss)->sin_addr;
		else
			e->addr.in6 = ((struct sockaddr_in6 *)&ss)->sin6_addr;
		if (inet_ntop(e->family, &e->addr, buf, sizeof(buf)) == NULL) {
			printf("%% inet_ntop: %s\n", strerror(errno));
			goto done;
		}

		if (RB_INSERT(ip_tree, &tree, e) != NULL)
			free(e);
		e = NULL;

		addr_strlen = strlen(buf);
		if (max_addr_strlen < addr_strlen)
			max_addr_strlen = addr_strlen;
	}

	/* Show IPs */
	printf("%-*s  Interface  RDomain  Type\n",
	    max_addr_strlen, "Address");
	RB_FOREACH(e, ip_tree, &tree) {
		void *addr;
		flagsbuf[0] = '\0';
		if (e->family == AF_INET) {
			addr = &e->addr.in;
			if (e->flags & NSH_IP_FLAG_DHCP)
				strlcat(flagsbuf, " dhcp", sizeof(flagsbuf));
			if (e->flags & NSH_IP_FLAG_IPCP) {
				strlcat(flagsbuf, " autoconf",
				    sizeof(flagsbuf));
			}
			if (e->flags & NSH_IP_FLAG_STATIC)
				strlcat(flagsbuf, " static", sizeof(flagsbuf));
		} else {
			addr = &e->addr.in6;
			if (e->flags6 & IN6_IFF_AUTOCONF) {
				strlcat(flagsbuf, " autoconf",
				    sizeof(flagsbuf));
			}
			if (e->flags6 & IN6_IFF_TEMPORARY) {
				strlcat(flagsbuf, " temporary",
				    sizeof(flagsbuf));
			}
			if (IN6_IS_ADDR_LINKLOCAL(&e->addr.in6)) {
				strlcat(flagsbuf, " link-local",
				    sizeof(flagsbuf));
			} else if ((e->flags6 & (IN6_IFF_AUTOCONF |
			    IN6_IFF_TEMPORARY)) == 0) {
				strlcat(flagsbuf, " static",
				    sizeof(flagsbuf));
			}
		}

		if (inet_ntop(e->family, addr, buf, sizeof(buf)) == NULL) {
			printf("%% inet_ntop: %s\n", strerror(errno));
			continue;
		}

		printf("%-*s  %-9s %8d %s\n", max_addr_strlen, buf,
		    e->ifname, e->rdomain, flagsbuf);
	}
done:
	free(e);
	while ((e = RB_MIN(ip_tree, &tree))) {
		RB_REMOVE(ip_tree, &tree, e);
		free(e);
	}
}

u_int32_t
in4_netaddr(u_int32_t addr, u_int32_t mask)
{
	u_int32_t net;

	net = ntohl(addr) & ntohl(mask);

	return (net);
}

u_int32_t
in4_brdaddr(u_int32_t addr, u_int32_t mask)
{
	u_int32_t net, bcast;

	net = in4_netaddr(addr, mask);
	bcast = net | ~ntohl(mask);

	return bcast;
}

char *
iftype(int int_type)
{
	u_int i;

	for (i = 0; i < nitems(iftypes); i++)
		if (int_type == iftypes[i].type)
			return iftypes[i].name;

	if (verbose)
		printf("%% iftype: int_type %x\n", int_type);
	return "Unknown";
}

/* a VLAN, as show_vlan() printed it, and the headers before the first */
void
vlan_render(struct frec *r, int n)
{
	const char *name, *parent, *bridgename, *description;
	char vnetid_str[5];

	if (n == 0)
		puts("% Interface  Tag   Status  Type    "
		    "RDomain  Parent  Bridge   Description");

	if ((name = fs(r, VLAN_NAME)) == NULL)
		name = "";
	if ((parent = fs(r, VLAN_PARENT)) == NULL)
		parent = "-";
	if ((bridgename = fs(r, VLAN_BRIDGE)) == NULL)
		bridgename = "-";
	if ((description = fs(r, VLAN_DESCR)) == NULL)
		description = "";

	if (!fhas(r, VLAN_VNETID))
		strlcpy(vnetid_str, "-", sizeof(vnetid_str));
	else
		snprintf(vnetid_str, sizeof(vnetid_str), "%d",
		    (int)fu(r, VLAN_VNETID, 0));

	printf("  %-10s %-5s %-7s %-8s %6d  %-7s %-8s %s\n",
	   name, vnetid_str, (fu(r, VLAN_FLAGS, 0) & IFF_UP) ? "up" : "down",
	    isprefix("vlan", (char *)name) ? "802.1Q" : "802.1ad",
	    (int)fu(r, VLAN_RDOMAIN, 0), parent, bridgename, description);
}

/* no VLAN of tag start, or between start and end */
void
vlan_none(int start_vnetid, int end_vnetid)
{
	if (end_vnetid == -1)
		printf("%% no VLAN with tag %d configured\n",
		    start_vnetid);
	else
		printf("%% no VLANs with tag between %d and %d "
		    "configured\n", start_vnetid, end_vnetid);
}

const char *get_media_type_string(uint64_t);
const char *get_media_subtype_string(uint64_t);
void print_media_word(uint64_t, int, int, FILE *);

static const uint64_t ifm_status_valid_list[] =
    IFM_STATUS_VALID_LIST;

static const struct ifmedia_status_description ifm_status_descriptions[] =
    IFM_STATUS_DESCRIPTIONS;

static const struct ifmedia_description ifm_type_descriptions[] =
    IFM_TYPE_DESCRIPTIONS;

static const struct ifmedia_description ifm_subtype_descriptions[] =
    IFM_SUBTYPE_DESCRIPTIONS;

static const struct ifmedia_description ifm_option_descriptions[] =
    IFM_OPTION_DESCRIPTIONS;

const char *
get_ifm_linkstate_str(struct ifmediareq *ifmr)
{
	const uint64_t ifm_status_valid_list[] = IFM_STATUS_VALID_LIST;
	const struct ifmedia_status_description *ifms;
	int bitno;

	if ((ifmr->ifm_status & IFM_AVALID) == 0)
		return NULL;

	for (bitno = 0; ifm_status_valid_list[bitno] != 0; bitno++) {
		for (ifms = ifm_status_descriptions;
		    ifms->ifms_valid != 0; ifms++) {
			if (ifms->ifms_type != IFM_TYPE(ifmr->ifm_current) ||
			    ifms->ifms_valid != ifm_status_valid_list[bitno])
				continue;
			return IFM_STATUS_DESC(ifms, ifmr->ifm_status);
		}
	}

	return NULL;
}

const char *
get_ifm_options_str(char *buf, size_t size, uint64_t ifmw,
    uint64_t *seen_options)
{
	const struct ifmedia_description *desc;

	buf[0] = '\0';

	/* Find options. */
	for (desc = ifm_option_descriptions; desc->ifmt_string != NULL;
	     desc++) {
		if (IFM_TYPE_MATCH(desc->ifmt_word, ifmw) &&
		  (IFM_OPTIONS(ifmw) & IFM_OPTIONS(desc->ifmt_word)) != 0 &&
		    (*seen_options & IFM_OPTIONS(desc->ifmt_word)) == 0) {
			if (buf[0] != '\0')
				strlcat(buf, " ", size);
			strlcat(buf, desc->ifmt_string, size);
			*seen_options |= IFM_OPTIONS(desc->ifmt_word);
		}
	}

	return buf;
}

const char *
get_ifm_type_str(uint64_t mword)
{
	const struct ifmedia_description *desc;

	for (desc = ifm_type_descriptions; desc->ifmt_string != NULL;
	     desc++) {
		if (IFM_TYPE(mword) == desc->ifmt_word)
			return (desc->ifmt_string);
	}

	return NULL;
}

const char     *
get_ifm_subtype_str(uint64_t mword)
{
	const struct ifmedia_description *desc;

	for (desc = ifm_subtype_descriptions; desc->ifmt_string != NULL;
	     desc++) {
		if (IFM_TYPE_MATCH(desc->ifmt_word, mword) &&
		    IFM_SUBTYPE(desc->ifmt_word) == IFM_SUBTYPE(mword))
			return (desc->ifmt_string);
	}

	return NULL;
}

const char     *
get_media_type_string(uint64_t mword)
{
	const char *s;

	s = get_ifm_type_str(mword);
	if (s != NULL)
		return (s);

	return ("<unknown type>");
}

const char     *
get_media_subtype_string(uint64_t mword)
{
	const char *s;

	s = get_ifm_subtype_str(mword);
	if (s != NULL)
		return (s);

	return ("<unknown subtype>");
}

void
print_media_word(uint64_t ifmw, int print_type, int as_syntax, FILE *outfile)
{
	const struct ifmedia_description *desc;
	uint64_t	seen_option = 0;

	if (print_type)
		fprintf(outfile, "%s ", get_media_type_string(ifmw));
	fprintf(outfile, "%s%s", as_syntax ? "media " : "",
	       get_media_subtype_string(ifmw));
	if (IFM_INST(ifmw) != 0)
		fprintf(outfile, " %lld", IFM_INST(ifmw));

	/* Find options. */
	for (desc = ifm_option_descriptions; desc->ifmt_string != NULL;
	     desc++) {
		if (IFM_TYPE_MATCH(desc->ifmt_word, ifmw) &&
		  (IFM_OPTIONS(ifmw) & IFM_OPTIONS(desc->ifmt_word)) != 0 &&
		    (seen_option & IFM_OPTIONS(desc->ifmt_word)) == 0) {
			if (seen_option == 0)
				fprintf(outfile, "%s",
				    as_syntax ? ", mediaopt " : " ");
			fprintf(outfile, "%s%s", seen_option ? "," : "",
			       desc->ifmt_string);
			seen_option |= IFM_OPTIONS(desc->ifmt_word);
		}
	}
}

/* a media word, current, active or supported, as facts */
static struct facts_name media_roles[] = {
	{ MEDIA_CURRENT, "current" },
	{ MEDIA_ACTIVE, "active" },
	{ MEDIA_SUPPORTED, "supported" },
};
static struct facts_field media_fields[] = {
	[MEDIA_ROLE] =		{ "role",	FACT_U64, FACT_VALUES,
				    media_roles, 3 },
	[MEDIA_WORD] =		{ "word",	FACT_U64 },
	[MEDIA_TYPE] =		{ "type",	FACT_STRING },
	[MEDIA_SUBTYPE] =	{ "subtype",	FACT_STRING },
	[MEDIA_INSTANCE] =	{ "instance",	FACT_U64 },
	[MEDIA_OPTIONS] =	{ "options",	FACT_STRING },
	[MEDIA_IF] =		{ "interface",	FACT_STRING },
};
struct facts_kind kind_media = { "media", media_fields, MEDIA_NFIELDS };

void
media_facts_init(void)
{
}

/* the word of rs's media record of role, or 0 */
static uint64_t
media_word(struct frecs *rs, uint64_t role, int *found)
{
	struct frec	*r;

	for (r = NULL; (r = frec_next(rs, r, &kind_media)) != NULL; )
		if (fu(r, MEDIA_ROLE, -1) == role) {
			if (found)
				*found = 1;
			return (fu(r, MEDIA_WORD, 0));
		}
	return (0);
}

void
media_status_words(struct frecs *rs, uint64_t *current, uint64_t *active)
{
	*current = media_word(rs, MEDIA_CURRENT, NULL);
	*active = media_word(rs, MEDIA_ACTIVE, NULL);
}

/* the link state media says, as get_ifm_linkstate_str() did */
const char *
media_linkstate(struct frecs *rs, struct frec *ifr)
{
	struct ifmediareq	 ifmr;

	memset(&ifmr, 0, sizeof(ifmr));
	ifmr.ifm_current = media_word(rs, MEDIA_CURRENT, NULL);
	ifmr.ifm_status = fu(ifr, IF_MEDIASTATUS, 0);
	return (get_ifm_linkstate_str(&ifmr));
}

/* media, as media_status() printed it */
void
media_render(struct frecs *rs, struct frec *ifr, FILE *outfile)
{
	uint64_t	 current, active, status;
	int		 found = 0;

	current = media_word(rs, MEDIA_CURRENT, &found);
	if (!found)
		return;
	if (fu(ifr, IF_MEDIACOUNT, 0) == 0) {
		if (verbose)
			printf("%% %s: No media types?\n", fs(ifr, IF_NAME));
		return;
	}
	active = media_word(rs, MEDIA_ACTIVE, NULL);
	status = fu(ifr, IF_MEDIASTATUS, 0);

	fprintf(outfile, "  Media type ");
	print_media_word(current, 0, 0, outfile);
	if (active != current) {
		fprintf(outfile, " (");
		print_media_word(active, 0, 0, outfile);
		fputc(')', outfile);
	}

	if (status & IFM_AVALID) {
		const struct ifmedia_status_description *ifms;
		int bitno, printed = 0;

		fprintf(outfile, ", status ");
		for (bitno = 0; ifm_status_valid_list[bitno] != 0; bitno++) {
			for (ifms = ifm_status_descriptions;
			     ifms->ifms_valid != 0; ifms++) {
				if (ifms->ifms_type != IFM_TYPE(current) ||
				    ifms->ifms_valid !=
				      ifm_status_valid_list[bitno])
					continue;
				fprintf(outfile, "%s%s", printed ? ", " : "",
				    IFM_STATUS_DESC(ifms, status));
				printed = 1;
				break;
			}
		}
		if (printed == 0)
			fprintf(outfile, "unknown");
	}
	fputc('\n', outfile);
}

/* what media an interface supports, as media_supported() printed it */
void
media_render_supported(struct frecs *rs, struct frec *ifr, FILE *outfile)
{
	struct frec	*r;
	uint64_t	 word;
	int		 type, printed_type;

	for (type = IFM_NMIN; type <= IFM_NMAX; type += IFM_NMIN) {
		printed_type = 0;
		for (r = NULL; (r = frec_next(rs, r, &kind_media)) != NULL; ) {
			if (fu(r, MEDIA_ROLE, -1) != MEDIA_SUPPORTED)
				continue;
			word = fu(r, MEDIA_WORD, 0);
			if (IFM_TYPE(word) != type)
				continue;
			if (printed_type == 0) {
				fprintf(outfile,
				    "  Supported media types on %s:\n",
				    fs(ifr, IF_NAME));
				printed_type = 1;
			}
			fprintf(outfile, "    ");
			print_media_word(word, 0, 1, outfile);
			fputc('\n', outfile);
		}
	}
}

static const char *carp_bal_modes[] = { CARP_BAL_MODES };

/* a carp interface's vhids, as facts */
static struct facts_field carp_fields[] = {
	[CARPV_VHID] =		{ "vhid",	FACT_U64 },
	[CARPV_STATE] =		{ "state",	FACT_U64 },
	[CARPV_ADVSKEW] =	{ "advskew",	FACT_U64 },
	[CARPV_IF] =		{ "interface",	FACT_STRING },
};
struct facts_kind kind_carp = { "carp-vhid", carp_fields, CARPV_NFIELDS };

/* names for the values of f, from a table of strings */
static void
carp_names(struct facts_field *f, const char **names, size_t n)
{
	struct facts_name	*fn;
	size_t			 i;

	if ((fn = calloc(n, sizeof(*fn))) == NULL)
		return;
	for (i = 0; i < n; i++) {
		fn[i].value = i;
		fn[i].name = names[i];
	}
	f->naming = FACT_VALUES;
	f->names = fn;
	f->nnames = n;
}

void
carp_balnames(struct facts_field *f)
{
	carp_names(f, carp_bal_modes, nitems(carp_bal_modes));
}

void
carp_facts_init(void)
{
	static const char *carp_states[] = { CARP_STATES };

	carp_names(&carp_fields[CARPV_STATE], carp_states,
	    nitems(carp_states));
}

/* carp, as carp_state() printed it */
void
carp_render(struct frecs *rs, struct frec *ifr, FILE *outfile)
{
	const char	*carp_states[] = { CARP_STATES };
	const char	*state = NULL, *carpdev;
	struct frec	*r, *first;
	struct in_addr	 peer;
	const struct facts_value *pv;
	uint64_t	 bal;
	int		 i, pntd = 0;

	if (!fhas(ifr, IF_CARPBALANCING))
		return;

	bal = fu(ifr, IF_CARPBALANCING, 0);
	if (bal <= CARP_BAL_MAXID) {
		fprintf(outfile, "  CARP balancing mode %s",
		    carp_bal_modes[bal]);
		pntd = 1;
	}

	if ((pv = FV(ifr, IF_CARPPEER, FACT_ADDRESS)) != NULL) {
		memcpy(&peer, pv->v.a.bytes, sizeof(peer));
		fprintf(outfile, " peer %s", inet_ntoa(peer));
		pntd = 1;
	}
	if (pntd)
		fputc('\n', outfile);

	if ((first = frec_next(rs, NULL, &kind_carp)) == NULL)
		return;
	carpdev = fs(ifr, IF_CARPDEV);
	if (carpdev == NULL || carpdev[0] == '\0')
		carpdev = "none";

	for (i = 0, r = first; r != NULL; i++,
	    r = frec_next(rs, r, &kind_carp)) {
		if (fu(r, CARPV_STATE, 0) <= CARP_MAXSTATE)
			state = carp_states[fu(r, CARPV_STATE, 0)];
		if (frec_next(rs, first, &kind_carp) == NULL) {
			fprintf(outfile, "  CARP state %s, "
			    "device %s vhid %u advbase %d advskew %u\n", state,
			    carpdev, (u_int)fu(r, CARPV_VHID, 0),
			    (int)fu(ifr, IF_CARPADVBASE, 0),
			    (u_int)fu(r, CARPV_ADVSKEW, 0));
		} else {
			if (i == 0) {
				fprintf(outfile,
				    "  CARP device %s advbase %d\n", carpdev,
				    (int)fu(ifr, IF_CARPADVBASE, 0));
			}
			fprintf(outfile, "  CARP state %s vhid %u advskew %u\n",
			    state, (u_int)fu(r, CARPV_VHID, 0),
			    (u_int)fu(r, CARPV_ADVSKEW, 0));
		}
	}
}

/* a wg interface's peers, as facts */
static struct facts_field wgpeer_fields[] = {
	[WGP_PUBLIC] =		{ "public-key",		FACT_STRING },
	[WGP_DESCR] =		{ "description",	FACT_STRING },
	[WGP_HANDSHAKE] =	{ "last-handshake",	FACT_TIME },
	[WGP_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_wgpeer = { "wg-peer", wgpeer_fields, WGP_NFIELDS };

/* wg, as show_wg() printed it */
void
wg_render(struct frecs *rs, struct frec *ifr, FILE *outfile)
{
	const struct facts_value	*t;
	struct frec			*r;
	struct timespec			 now;
	const char			*s;

	if ((s = fs(ifr, IF_WGPUBLIC)) != NULL)
		fprintf(outfile, "  Wireguard publickey %s\n", s);

	for (r = NULL; (r = frec_next(rs, r, &kind_wgpeer)) != NULL; ) {
		s = fs(r, WGP_PUBLIC);
		fprintf(outfile, "  Wireguard peer %s", s != NULL ? s : "");
		if ((s = fs(r, WGP_DESCR)) != NULL && s[0] != '\0')
			fprintf(outfile, " (%s)\n", s);
		if ((t = FV(r, WGP_HANDSHAKE, FACT_TIME)) != NULL &&
		    t->v.t.sec != 0) {
			timespec_get(&now, TIME_UTC);
			fprintf(outfile, " last handshake: %lld seconds ago\n",
			    (long long)(now.tv_sec - t->v.t.sec));
		}
		putc('\n', outfile);
	}
}

void	umb_printclasses(char *, int, FILE *);

static const struct umb_valdescr umb_regstate[] = MBIM_REGSTATE_DESCRIPTIONS;
static const struct umb_valdescr umb_dataclass[] = MBIM_DATACLASS_DESCRIPTIONS;
static const struct umb_valdescr umb_simstate[] = MBIM_SIMSTATE_DESCRIPTIONS;
static const struct umb_valdescr umb_istate[] = UMB_INTERNAL_STATE_DESCRIPTIONS;

/* 3GPP 24.008 cause codes */
static const struct umb_valdescr umb_nwerrors[] = {
	{ 2, "SIM not activated" },
	{ 4, "Roaming not supported" },
	{ 6, "SIM reported stolen" },
	{ 7, "No GPRS subscription" },
	{ 8, "GPRS and non-GPRS services not allowed" },
	{ 11, "Subscription expired" },
	{ 12, "Subscription does not cover current location" },
	{ 13, "No roaming in this location" },
	{ 14, "GPRS not supported" },
	{ 15, "No subscription for the service" },
	{ 17, "Registration failed" },
	{ 22, "Network congestion" },
	{ 0, NULL }
};

static const struct umb_valdescr umb_pinstates[] = {
	{ UMB_PIN_REQUIRED, "required" },
	{ UMB_PIN_UNLOCKED, "valid" },
	{ UMB_PUK_REQUIRED, "locked (PUK required)" },
	{ 0, NULL }
};

static const struct umb_valdescr umb_cellclasses[] = {
	{ MBIM_CELLCLASS_GSM, "GSM" },
	{ MBIM_CELLCLASS_CDMA, "CDMA" },
	{ 0, NULL }
};

/* a umb interface, and its name servers, as facts */
static struct facts_field umb_fields[] = {
	[UMB_ERROR] =		{ "error",		FACT_U64 },
	[UMB_ROAMING] =		{ "roaming",		FACT_U64 },
	[UMB_REGSTATE] =	{ "registration",	FACT_U64 },
	[UMB_ROAMINGTEXT] =	{ "roaming-text",	FACT_STRING },
	[UMB_CLASSES] =		{ "available-classes",	FACT_U64 },
	[UMB_STATE] =		{ "state",		FACT_U64 },
	[UMB_CELLCLASS] =	{ "cell-type",		FACT_U64 },
	[UMB_HIGHESTCLASS] =	{ "cell-class",		FACT_U64 },
	[UMB_RSSI] =		{ "rssi",		FACT_I64 },
	[UMB_UPLINK] =		{ "uplink-speed",	FACT_U64 },
	[UMB_DOWNLINK] =	{ "downlink-speed",	FACT_U64 },
	[UMB_SIMSTATE] =	{ "sim-state",		FACT_U64 },
	[UMB_PINSTATE] =	{ "pin-state",		FACT_U64 },
	[UMB_PINLEFT] =		{ "pin-attempts-left",	FACT_I64 },
	[UMB_SID] =		{ "subscriber-id",	FACT_STRING },
	[UMB_ICCID] =		{ "icc-id",		FACT_STRING },
	[UMB_PROVIDER] =	{ "provider",		FACT_STRING },
	[UMB_PROVIDERID] =	{ "provider-id",	FACT_STRING },
	[UMB_HWINFO] =		{ "device",		FACT_STRING },
	[UMB_DEVID] =		{ "device-id",		FACT_STRING },
	[UMB_FWINFO] =		{ "firmware",		FACT_STRING },
	[UMB_PHONE] =		{ "phone-number",	FACT_STRING },
	[UMB_APN] =		{ "apn",		FACT_STRING },
	[UMB_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_umb = { "umb", umb_fields, UMB_NFIELDS };

static struct facts_field umbdns_fields[] = {
	[UMBDNS_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[UMBDNS_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_umbdns = { "umb-name-server", umbdns_fields,
    UMBDNS_NFIELDS };

/* names for f from a table of the kernel's, as bits or values */
static void
umb_names(struct facts_field *f, uint8_t naming,
    const struct umb_valdescr *vd)
{
	struct facts_name	*fn;
	size_t			 i, n;

	for (n = 0; vd[n].descr != NULL; n++)
		;
	if ((fn = calloc(n, sizeof(*fn))) == NULL)
		return;
	for (i = 0; i < n; i++) {
		fn[i].value = (uint32_t)vd[i].val;
		fn[i].name = vd[i].descr;
	}
	f->naming = naming;
	f->names = fn;
	f->nnames = n;
}

void
umb_facts_init(void)
{
	umb_names(&umb_fields[UMB_ERROR], FACT_VALUES, umb_nwerrors);
	umb_names(&umb_fields[UMB_REGSTATE], FACT_VALUES, umb_regstate);
	umb_names(&umb_fields[UMB_CLASSES], FACT_BITS, umb_dataclass);
	umb_names(&umb_fields[UMB_STATE], FACT_VALUES, umb_istate);
	umb_names(&umb_fields[UMB_CELLCLASS], FACT_VALUES, umb_cellclasses);
	umb_names(&umb_fields[UMB_HIGHESTCLASS], FACT_VALUES, umb_dataclass);
	umb_names(&umb_fields[UMB_SIMSTATE], FACT_VALUES, umb_simstate);
	umb_names(&umb_fields[UMB_PINSTATE], FACT_VALUES, umb_pinstates);
}

/* r's string i, or "" */
static const char *
umb_s(struct frec *r, int i)
{
	const char	*s = fs(r, i);

	return (s != NULL ? s : "");
}

/* umb, as show_umb() printed it */
void
umb_render(struct frecs *rs, FILE *outfile)
{
	const struct umb_valdescr *vd;
	const struct facts_value *a;
	struct frec	*r, *d;
	const char	*sid, *iccid, *provider, *providerid, *hwinfo, *devid;
	const char	*fwinfo, *pn, *apn;
	char		 astr[INET6_ADDRSTRLEN];
	uint64_t	 err, up, down, pin;
	int		 n;

	if ((r = frec_next(rs, NULL, &kind_umb)) == NULL)
		return;

	if ((err = fu(r, UMB_ERROR, 0)) != 0) {
		fprintf(outfile, "  error: ");
		for (vd = umb_nwerrors; vd->descr != NULL; vd++)
			if ((uint32_t)vd->val == err)
				break;
		if (vd->descr != NULL)
			fprintf(outfile, "%s", vd->descr);
		else
			fprintf(outfile, "Error code %d", (int)err);
		putc('\n', outfile);
	}

	fprintf(outfile, "  roaming %s registration %s",
	    fu(r, UMB_ROAMING, 0) ? "enabled" : "disabled",
	    umb_val2descr(umb_regstate, (int)fu(r, UMB_REGSTATE, 0)));
	if (umb_s(r, UMB_ROAMINGTEXT)[0])
		fprintf(outfile, " [%s]", umb_s(r, UMB_ROAMINGTEXT));
	fputc('\n', outfile);

	umb_printclasses("available classes", (int)fu(r, UMB_CLASSES, 0),
	    outfile);
	fprintf(outfile, "  state %s cell-class %s",
	    umb_val2descr(umb_istate, (int)fu(r, UMB_STATE, 0)),
	    umb_val2descr(umb_dataclass, (int)fu(r, UMB_HIGHESTCLASS, 0)));
	if ((a = FV(r, UMB_RSSI, FACT_I64)) != NULL && a->v.i != 0)
		fprintf(outfile, " rssi %ddBm", (int)a->v.i);
	up = fu(r, UMB_UPLINK, 0);
	down = fu(r, UMB_DOWNLINK, 0);
	if (up != 0 || down != 0) {
		char s[2][FMT_SCALED_STRSIZE];
		if (fmt_scaled(up, s[0]) != 0)
			snprintf(s[0], sizeof (s[0]), "%llu",
			    (unsigned long long)up);
		if (fmt_scaled(down, s[1]) != 0)
			snprintf(s[1], sizeof (s[1]), "%llu",
			    (unsigned long long)down);
		fprintf(outfile, " speed %sbps up %sbps down", s[0], s[1]);
	}
	fputc('\n', outfile);

	fprintf(outfile, "  SIM %s PIN ",
	    umb_val2descr(umb_simstate, (int)fu(r, UMB_SIMSTATE, 0)));
	pin = fu(r, UMB_PINSTATE, 0);
	for (vd = umb_pinstates; vd->descr != NULL; vd++)
		if ((uint32_t)vd->val == pin)
			break;
	if (vd->descr != NULL)
		fprintf(outfile, "%s", vd->descr);
	else
		fprintf(outfile, "unknown state (%d)", (int)pin);
	if ((a = FV(r, UMB_PINLEFT, FACT_I64)) != NULL)
		fprintf(outfile, " (%d attempts left)", (int)a->v.i);
	fputc('\n', outfile);

	sid = umb_s(r, UMB_SID);
	iccid = umb_s(r, UMB_ICCID);
	provider = umb_s(r, UMB_PROVIDER);
	providerid = umb_s(r, UMB_PROVIDERID);
	if (sid[0] || iccid[0]) {
		fprintf(outfile, "  ");
		n = 0;
		if (sid[0])
			fprintf(outfile, "%ssubscriber-id %s",
			    n++ ? " " : "", sid);
		if (iccid[0])
			fprintf(outfile, "%sICC-id %s", n++ ? " " : "", iccid);
		fputc('\n', outfile);
	}

	hwinfo = umb_s(r, UMB_HWINFO);
	devid = umb_s(r, UMB_DEVID);
	fwinfo = umb_s(r, UMB_FWINFO);
	if (hwinfo[0] || devid[0] || fwinfo[0]) {
		fprintf(outfile, "  ");
		n = 0;
		if (hwinfo[0])
			fprintf(outfile, "%sdevice %s", n++ ? " " : "", hwinfo);
		if (devid[0]) {
			fprintf(outfile, "%s", n++ ? " " : "");
			switch (fu(r, UMB_CELLCLASS, 0)) {
			case MBIM_CELLCLASS_GSM:
				fprintf(outfile, "IMEI");
				break;
			case MBIM_CELLCLASS_CDMA:
				n = strlen(devid);
				if (n == 8 || n == 11) {
					fprintf(outfile, "ESN");
					break;
				} else if (n == 14 || n == 18) {
					fprintf(outfile, "MEID");
					break;
				}
				/*FALLTHROUGH*/
			default:
				fprintf(outfile, "ID");
				break;
			}
			fprintf(outfile, " %s", devid);
		}
		if (fwinfo[0])
			fprintf(outfile, "%sfirmware %s", n++ ? " " : "",
			    fwinfo);
		fputc('\n', outfile);
	}

	pn = umb_s(r, UMB_PHONE);
	apn = umb_s(r, UMB_APN);
	if (pn[0] || apn[0] || provider[0] || providerid[0]) {
		fprintf(outfile, "  ");
		n = 0;
		if (pn[0])
			fprintf(outfile, "%sphone# %s", n++ ? " " : "", pn);
		if (apn[0])
			fprintf(outfile, "%sAPN %s", n++ ? " " : "", apn);
		if (provider[0])
			fprintf(outfile, "%sprovider %s", n++ ? " " : "",
			    provider);
		if (providerid[0])
			fprintf(outfile, "%sprovider-id %s", n ? " " : "",
			    providerid);
		fputc('\n', outfile);
	}

	for (d = NULL, n = 0; (d = frec_next(rs, d, &kind_umbdns)) != NULL; ) {
		if ((a = FV(d, UMBDNS_ADDRESS, FACT_ADDRESS)) == NULL ||
		    (a->v.a.family != FACT_INET && a->v.a.family != FACT_INET6))
			continue;
		fprintf(outfile, "%s %s", n++ ? "" : "  dns",
		    inet_ntop(a->v.a.family == FACT_INET ? AF_INET : AF_INET6,
		    a->v.a.bytes, astr, sizeof(astr)));
	}

	if (n)
		fputc('\n', outfile);
}

void
umb_printclasses(char *tag, int c, FILE *outfile)
{
	int	 i;
	char	*sep = "";

	fprintf(outfile, "  %s: ", tag);
	i = 0;
	while (umb_dataclass[i].descr) {
		if (umb_dataclass[i].val & c) {
			fprintf(outfile, "%s%s", sep, umb_dataclass[i].descr);
			sep = ",";
		}
		i++;
	}
	fputc('\n', outfile);
}

static struct trunk_protos tpr[] = TRUNK_PROTOS;

/* a trunk's ports, as facts */
static struct facts_field trunkport_fields[] = {
	[TPORT_NAME] =		{ "name",	FACT_STRING },
	[TPORT_FLAGS] =		{ "flags",	FACT_U64 },
	[TPORT_IF] =		{ "interface",	FACT_STRING },
};
struct facts_kind kind_trunkport = { "trunk-port", trunkport_fields,
    TPORT_NFIELDS };

/* names for a trunk protocol field and a trunk port flags field */
void
trunk_names(struct facts_field *proto, struct facts_field *flags)
{
	struct facts_name	*fn;
	size_t			 i;

	facts_bitnames(flags, TRUNK_PORT_BITS);
	if ((fn = calloc(nitems(tpr), sizeof(*fn))) == NULL)
		return;
	for (i = 0; i < nitems(tpr); i++) {
		fn[i].value = tpr[i].tpr_proto;
		fn[i].name = tpr[i].tpr_name;
	}
	proto->naming = FACT_VALUES;
	proto->names = fn;
	proto->nnames = nitems(tpr);
}

void
trunk_facts_init(void)
{
	facts_bitnames(&trunkport_fields[TPORT_FLAGS], TRUNK_PORT_BITS);
}

/* trunk, as show_trunk() printed it */
void
trunk_render(struct frecs *rs, struct frec *ifr, FILE *outfile)
{
	struct frec *r;
	int i, pntd = 0;

	if (fs(ifr, IF_TRUNKPARENT) != NULL) {
		fprintf(outfile, "  Trunk parent %s ", fs(ifr, IF_TRUNKPARENT));
		bprintf(outfile, fu(ifr, IF_TRUNKFLAGS, 0), TRUNK_PORT_BITS);
		fputc('\n', outfile);
	}

	if (!fhas(ifr, IF_TRUNKPROTO))
		return;
	for (i = 0; i < TRUNK_PROTO_MAX; i++)
		if (fu(ifr, IF_TRUNKPROTO, 0) == tpr[i].tpr_proto) {
			fprintf(outfile, "  Trunkproto %s", tpr[i].tpr_name);
			pntd = 1;
			break;
		}
	for (r = NULL; (r = frec_next(rs, r, &kind_trunkport)) != NULL; ) {
		if (fs(r, TPORT_NAME) == NULL)
			continue;
		fprintf(outfile, " (%s ", fs(r, TPORT_NAME));
		bprintf(outfile, fu(r, TPORT_FLAGS, 0), TRUNK_PORT_BITS);
		putc(')', outfile);
		pntd = 1;
	}
	if (pntd)
		fputc('\n', outfile);
}

char *stpstates[] = {
	"disabled",
	"listening",
	"learning",
	"forwarding",
	"blocking",
};

/* a bridge's members, and the addresses it learned, as facts */
static struct facts_field bridgemember_fields[] = {
	[BRM_NAME] =		{ "name",	FACT_STRING },
	[BRM_FLAGS] =		{ "flags",	FACT_U64 },
	[BRM_STATE] =		{ "stp-state",	FACT_U64 },
	[BRM_IF] =		{ "interface",	FACT_STRING },
};
struct facts_kind kind_bridgemember = { "bridge-member", bridgemember_fields,
    BRM_NFIELDS };

static struct facts_field bridgeaddr_fields[] = {
	[BRA_ADDRESS] =		{ "address",	FACT_ADDRESS },
	[BRA_MEMBER] =		{ "member",	FACT_STRING },
	[BRA_AGE] =		{ "age",	FACT_U64 },
	[BRA_FLAGS] =		{ "flags",	FACT_U64 },
	[BRA_IF] =		{ "interface",	FACT_STRING },
};
struct facts_kind kind_bridgeaddr = { "bridge-address", bridgeaddr_fields,
    BRA_NFIELDS };

/* a bridge, after its members, as show bridge shows it */
static struct facts_field bridge_fields[] = {
	[BR_NAME] =		{ "name",		FACT_STRING },
	[BR_FLAGS] =		{ "flags",		FACT_U64 },
	[BR_DESCR] =		{ "description",	FACT_STRING },
};
struct facts_kind kind_bridge = { "bridge", bridge_fields, BR_NFIELDS };

void
bridge_facts_init(void)
{
	static struct facts_name	 states[nitems(stpstates)];
	size_t				 i;

	facts_bitnames(&bridgemember_fields[BRM_FLAGS], IFBIFBITS);
	for (i = 0; i < nitems(stpstates); i++) {
		states[i].value = i;
		states[i].name = stpstates[i];
	}
	bridgemember_fields[BRM_STATE].naming = FACT_VALUES;
	bridgemember_fields[BRM_STATE].names = states;
	bridgemember_fields[BRM_STATE].nnames = nitems(stpstates);
	facts_bitnames(&bridgeaddr_fields[BRA_FLAGS], IFBAFBITS);
	facts_bitnames(&bridge_fields[BR_FLAGS], ifnetflags);
}

/* r's string i, or "" */
static const char *
bridge_s(struct frec *r, int i)
{
	const char	*s = fs(r, i);

	return (s != NULL ? s : "");
}

/* a bridge's STP members and learned addresses, as show_int() printed */
void
bridge_render(struct frecs *rs, FILE *outfile)
{
	const struct facts_value *a;
	struct ether_addr ea;
	struct frec *r;
	uint64_t state;
	int n;

	for (n = 0, r = NULL; (r = frec_next(rs, r, &kind_bridgemember)); )
		if (fu(r, BRM_FLAGS, 0) & IFBIF_STP)
			n++;
	if (n) {
		fprintf(outfile, "  STP member state%s:\n", n > 1 ?  "s" : "");
		for (r = NULL; (r = frec_next(rs, r, &kind_bridgemember)); ) {
			if (!(fu(r, BRM_FLAGS, 0) & IFBIF_STP))
				continue;
			state = fu(r, BRM_STATE, 0);
			if (state < nitems(stpstates))
				fprintf(outfile, "    %s: %s\n",
				    bridge_s(r, BRM_NAME), stpstates[state]);
			else
				fprintf(outfile, "    %s: %llu\n",
				    bridge_s(r, BRM_NAME),
				    (unsigned long long)state);
		}
	}

	if (frec_next(rs, NULL, &kind_bridgeaddr) != NULL) {
		fprintf(outfile, "  Learned addresses:\n");
		fprintf(outfile, "    address           member age\n");
	}
	for (r = NULL; (r = frec_next(rs, r, &kind_bridgeaddr)); ) {
		memset(&ea, 0, sizeof(ea));
		if ((a = FV(r, BRA_ADDRESS, FACT_ADDRESS)) != NULL &&
		    a->v.a.len == sizeof(ea))
			memcpy(&ea, a->v.a.bytes, sizeof(ea));
		fprintf(outfile, "    %s %-6s %u ", ether_ntoa(&ea),
		    bridge_s(r, BRA_MEMBER), (u_int)fu(r, BRA_AGE, 0));
		bprintf(outfile, fu(r, BRA_FLAGS, 0), IFBAFBITS);
		fputc('\n', outfile);
	}
}

/*
 * Bridge b and its members in rs, as show_bridge() printed them, and the
 * headers before the first
 */
void
bridge_show_render(struct frecs *rs, struct frec *b, int n)
{
	struct frec *r;
	const char *name;
	int totlen, len;
	char buf[1024], tmp[256], *p, *member;

	if (n == 0)
		puts("% Bridge    Status  Member Interfaces");

	/* as bridge_list() lists them */
	buf[0] = '\0';
	for (r = NULL; (r = frec_next(rs, r, &kind_bridgemember)); ) {
		if ((name = fs(r, BRM_NAME)) == NULL || name[0] == '\0' ||
		    (fu(r, BRM_FLAGS, 0) & IFBIF_SPAN))
			continue;
		snprintf(tmp, sizeof(tmp), "%s%s", buf[0] ? " " : "", name);
		strlcat(buf, tmp, sizeof(buf));
	}

	len = printf("  %-9s %-7s", bridge_s(b, BR_NAME),
	    (fu(b, BR_FLAGS, 0) & IFF_UP) ? "up" : "down");
	if (len < 0) {
		printf("\n%% show_bridge: printf failed: %s\n",
		    strerror(errno));
		return;
	}
	totlen = len;

	p = buf;
	while ((member = strsep(&p, " ")) != NULL) {
		if (totlen + strlen(member) >= 80) {
			printf("\n                   ");
			len = 19;
			totlen = len;
		}

		len = printf(" %s", member);
		if (len < 0) {
			printf("\n%% show_bridge: printf failed: %s\n",
			    strerror(errno));
			return;
		}
		totlen += len;
	}
	printf("\n");

	printf("            Description: %s\n", fs(b, BR_DESCR) != NULL ?
	    fs(b, BR_DESCR) : "-");
}

/* a lease, after its routes and name servers */
static struct facts_field dhcp_fields[] = {
	[DHCP_IF] =		{ "interface",		FACT_STRING },
	[DHCP_STATE] =		{ "state",		FACT_STRING },
	[DHCP_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[DHCP_MASK] =		{ "netmask",		FACT_ADDRESS },
	[DHCP_REQUESTED] =	{ "requested",		FACT_TIME },
	[DHCP_LEASE] =		{ "lease-time",		FACT_U64 },
	[DHCP_SERVER] =		{ "server",		FACT_ADDRESS },
};
struct facts_kind kind_dhcplease = { "dhcp-lease", dhcp_fields,
    DHCP_NFIELDS };

static struct facts_field dhcproute_fields[] = {
	[DHCPR_DEST] =		{ "destination",	FACT_ADDRESS },
	[DHCPR_MASK] =		{ "netmask",		FACT_ADDRESS },
	[DHCPR_GW] =		{ "gateway",		FACT_ADDRESS },
	[DHCPR_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_dhcproute = { "dhcp-route", dhcproute_fields,
    DHCPR_NFIELDS };

static struct facts_field dhcpns_fields[] = {
	[DHCPNS_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[DHCPNS_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_dhcpns = { "dhcp-name-server", dhcpns_fields,
    DHCPNS_NFIELDS };

#define PROPOSAL_FIELDS \
	[SP_ID] =		{ "id",			FACT_I64 }, \
	[SP_STATE] =		{ "state",		FACT_STRING }, \
	[SP_TIMEOUT] =		{ "timeout",		FACT_I64 }, \
	[SP_WHEN] =		{ "when",		FACT_TIME }, \
	[SP_SEEN] =		{ "seen",		FACT_TIME }, \
	[SP_IF] =		{ "interface",		FACT_STRING }

/* an interface slaacd knows, after its other records */
static struct facts_field slaac_fields[] = {
	[SLAAC_IF] =		{ "interface",		FACT_STRING },
	[SLAAC_INDEX] =		{ "index",		FACT_U64 },
	[SLAAC_RUNNING] =	{ "running",		FACT_U64 },
	[SLAAC_TEMPORARY] =	{ "temporary",		FACT_U64 },
	[SLAAC_LLADDR] =	{ "link-address",	FACT_ADDRESS },
	[SLAAC_INET6] =		{ "link-local",		FACT_ADDRESS },
};
struct facts_kind kind_slaacif = { "slaac-interface", slaac_fields,
    SLAAC_NFIELDS };

static struct facts_field slaacra_fields[] = {
	[SRA_ROUTER] =		{ "router",		FACT_ADDRESS },
	[SRA_WHEN] =		{ "when",		FACT_TIME },
	[SRA_SEEN] =		{ "seen",		FACT_TIME },
	[SRA_HOPLIMIT] =	{ "hop-limit",		FACT_U64 },
	[SRA_MANAGED] =		{ "managed",		FACT_U64 },
	[SRA_OTHER] =		{ "other",		FACT_U64 },
	[SRA_LIFETIME] =	{ "router-lifetime",	FACT_U64 },
	[SRA_PREF] =		{ "preference",		FACT_STRING },
	[SRA_REACHABLE] =	{ "reachable-time",	FACT_U64 },
	[SRA_RETRANS] =		{ "retransmit-time",	FACT_U64 },
	[SRA_MTU] =		{ "mtu",		FACT_U64 },
	[SRA_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_slaacra = { "slaac-router-advertisement",
    slaacra_fields, SRA_NFIELDS };

static struct facts_field slaacprefix_fields[] = {
	[SPFX_PREFIX] =		{ "prefix",		FACT_ADDRESS },
	[SPFX_LEN] =		{ "prefix-length",	FACT_U64 },
	[SPFX_ONLINK] =		{ "on-link",		FACT_U64 },
	[SPFX_AUTONOMOUS] =	{ "autonomous",		FACT_U64 },
	[SPFX_VLTIME] =		{ "valid-lifetime",	FACT_U64 },
	[SPFX_PLTIME] =		{ "preferred-lifetime",	FACT_U64 },
	[SPFX_ROUTER] =		{ "router",		FACT_ADDRESS },
	[SPFX_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_slaacprefix = { "slaac-prefix", slaacprefix_fields,
    SPFX_NFIELDS };

static struct facts_field slaacrdns_fields[] = {
	[SRDNS_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[SRDNS_LIFETIME] =	{ "lifetime",		FACT_U64 },
	[SRDNS_ROUTER] =	{ "router",		FACT_ADDRESS },
	[SRDNS_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_slaacrdns = { "slaac-name-server", slaacrdns_fields,
    SRDNS_NFIELDS };

static struct facts_field slaacaddr_fields[] = {
	PROPOSAL_FIELDS,
	[SADDR_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[SADDR_PREFIX] =	{ "prefix",		FACT_ADDRESS },
	[SADDR_LEN] =		{ "prefix-length",	FACT_U64 },
	[SADDR_TEMPORARY] =	{ "temporary",		FACT_U64 },
	[SADDR_VLTIME] =	{ "valid-lifetime",	FACT_U64 },
	[SADDR_PLTIME] =	{ "preferred-lifetime",	FACT_U64 },
};
struct facts_kind kind_slaacaddr = { "slaac-address-proposal",
    slaacaddr_fields, SADDR_NFIELDS };

static struct facts_field slaacdfr_fields[] = {
	PROPOSAL_FIELDS,
	[SDFR_ROUTER] =		{ "router",		FACT_ADDRESS },
	[SDFR_LIFETIME] =	{ "router-lifetime",	FACT_U64 },
	[SDFR_PREF] =		{ "preference",		FACT_STRING },
};
struct facts_kind kind_slaacdfr = { "slaac-router-proposal",
    slaacdfr_fields, SDFR_NFIELDS };

static struct facts_field slaacdns_fields[] = {
	PROPOSAL_FIELDS,
	[SDNS_ROUTER] =		{ "router",		FACT_ADDRESS },
	[SDNS_LIFETIME] =	{ "lifetime",		FACT_U64 },
	[SDNS_SERVER] =		{ "name-server[0]",	FACT_ADDRESS },
	[SDNS_SERVER + 1] =	{ "name-server[1]",	FACT_ADDRESS },
	[SDNS_SERVER + 2] =	{ "name-server[2]",	FACT_ADDRESS },
	[SDNS_SERVER + 3] =	{ "name-server[3]",	FACT_ADDRESS },
	[SDNS_SERVER + 4] =	{ "name-server[4]",	FACT_ADDRESS },
	[SDNS_SERVER + 5] =	{ "name-server[5]",	FACT_ADDRESS },
	[SDNS_SERVER + 6] =	{ "name-server[6]",	FACT_ADDRESS },
	[SDNS_SERVER + 7] =	{ "name-server[7]",	FACT_ADDRESS },
};
struct facts_kind kind_slaacdns = { "slaac-name-server-proposal",
    slaacdns_fields, SDNS_NFIELDS };

/* fact i of r, a string, or empty */
static const char *
str(struct frec *r, int i)
{
	return (fs(r, i) != NULL ? fs(r, i) : "");
}

/* a proposal's id */
static long long
prop_id(struct frec *r)
{
	const struct facts_value	*v;

	return ((v = FV(r, SP_ID, FACT_I64)) != NULL ? v->v.i : 0);
}

/* seconds since fact i of r, a time, by this clock */
static long long
ago(struct frec *r, int i)
{
	const struct facts_value	*v;
	struct timespec			 now, t, d;

	if ((v = FV(r, i, FACT_TIME)) == NULL)
		return (0);
	clock_gettime(CLOCK_REALTIME, &now);
	t.tv_sec = v->v.t.sec;
	t.tv_nsec = v->v.t.nsec;
	timespecsub(&now, &t, &d);
	return (d.tv_sec);
}

/* fact i of r, a time, as slaacctl prints one */
static const char *
when(struct frec *r, int i, char *buf, size_t len)
{
	const struct facts_value	*v;
	struct tm			*tm;
	time_t				 t;

	buf[0] = '\0';
	if ((v = FV(r, i, FACT_TIME)) != NULL) {
		t = v->v.t.sec;
		if ((tm = localtime(&t)) != NULL)
			strftime(buf, len, "%F %T", tm);
	}
	return (buf);
}

/* fact i of r, an address, as numbers, its scope too */
static const char *
host(struct frec *r, int i, char *buf, size_t len)
{
	struct sockaddr_storage	 ss;

	if (!fsockaddr(r, i, &ss) || getnameinfo((struct sockaddr *)&ss,
	    ss.ss_len, buf, len, NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV))
		buf[0] = '\0';
	return (buf);
}

/* a lease, after its routes and name servers, as dhcpleasectl -l */
static void
dhcp_render(struct frecs *rs, struct frec *o)
{
	struct sockaddr_storage	 dst, mask;
	struct frec		*r;
	long long		 d, h, m, s;
	char			 ipbuf[NI_MAXHOST], maskbuf[NI_MAXHOST];
	char			 gwbuf[NI_MAXHOST];
	int			 n = 0;

	printf("%s [%s]\n", fs(o, DHCP_IF) != NULL ? fs(o, DHCP_IF) :
	    "unknown", str(o, DHCP_STATE));
	if (fhas(o, DHCP_ADDRESS)) {
		printf("\tinet %s netmask %s\n",
		    host(o, DHCP_ADDRESS, ipbuf, sizeof(ipbuf)),
		    host(o, DHCP_MASK, maskbuf, sizeof(maskbuf)));
		for (r = NULL; (r = frec_next(rs, r, &kind_dhcproute)); ) {
			fsockaddr(r, DHCPR_DEST, &dst);
			fsockaddr(r, DHCPR_MASK, &mask);
			host(r, DHCPR_GW, gwbuf, sizeof(gwbuf));
			if (((struct sockaddr_in *)&dst)->sin_addr.s_addr ==
			    INADDR_ANY &&
			    ((struct sockaddr_in *)&mask)->sin_addr.s_addr ==
			    INADDR_ANY)
				printf("\tdefault gateway %s\n", gwbuf);
			else
				printf("\troute %s/%d gateway %s\n",
				    host(r, DHCPR_DEST, ipbuf, sizeof(ipbuf)),
				    33 - ffs(ntohl(((struct sockaddr_in *)
				    &mask)->sin_addr.s_addr)), gwbuf);
		}
		for (r = NULL; (r = frec_next(rs, r, &kind_dhcpns)); n++)
			printf("%s %s", n == 0 ? "\tnameservers" : "",
			    host(r, DHCPNS_ADDRESS, ipbuf, sizeof(ipbuf)));
		if (n)
			printf("\n");

		s = (long long)fu(o, DHCP_LEASE, 0) - ago(o, DHCP_REQUESTED);
		if (s < 0)
			s = 0;

		if (s > 86400) {
			d = s / 86400;

			/* round up */
			if (s - d * 86400 > 43200)
				d++;
			printf("\tlease %lld day%s\n", d, d > 1 ? "s" : "");
		} else if (s > 3600) {
			h = s / 3600;

			/* round up */
			if (s - h * 3600 > 1800)
				h++;
			printf("\tlease %lld hour%s\n", h, h > 1 ? "s" : "");
		} else if (s > 60) {
			m = s / 60;

			/* round up */
			if (s - m * 60 > 30)
				m++;
			printf("\tlease %lld minute%s\n", m, m > 1 ? "s" : "");
		} else
			printf("\tlease %lld second%s\n", s, s > 1 ? "s" : "");
	}
	if (fhas(o, DHCP_SERVER))
		printf("\tdhcp server %s\n",
		    host(o, DHCP_SERVER, ipbuf, sizeof(ipbuf)));
}

/* vltime and pltime, as slaacctl prints them */
static void
lifetimes(const char *indent, uint64_t vltime, uint64_t pltime)
{
	if (vltime == ND6_INFINITE_LIFETIME)
		printf("%svltime: %10s, ", indent, "infinity");
	else
		printf("%svltime: %10u, ", indent, (u_int)vltime);
	if (pltime == ND6_INFINITE_LIFETIME)
		printf("pltime: %10s", "infinity");
	else
		printf("pltime: %10u", (u_int)pltime);
}

/* when a proposal was updated, and its timeout, as slaacctl prints them */
static void
updated(struct frec *r, int timeout_first)
{
	const struct facts_value	*t;
	char				 whenbuf[255];
	long long			 diff;

	diff = ago(r, SP_SEEN);
	t = FV(r, SP_TIMEOUT, FACT_I64);
	if (!timeout_first)
		printf("\t\tupdated: %s; %llds ago",
		    when(r, SP_WHEN, whenbuf, sizeof(whenbuf)), diff);
	if (t != NULL)
		printf(", timeout: %10llds\n", (long long)t->v.i - diff);
	else
		printf("\n");
	if (timeout_first)
		printf("\t\tupdated: %s; %llds ago\n",
		    when(r, SP_WHEN, whenbuf, sizeof(whenbuf)), diff);
}

/*
 * An interface slaacd knows, after its other records, as slaacctl
 * show interface prints it
 */
static void
slaac_render(struct frecs *rs, struct frec *o)
{
	const struct facts_kind		*prev = NULL;
	const struct facts_value	*v;
	struct ether_addr		 ea;
	struct frec			*r;
	char				 hbuf[NI_MAXHOST], whenbuf[255];
	char				 ntopbuf[NI_MAXHOST];
	int				 i;

	printf("%s:\n", fs(o, SLAAC_IF) != NULL ? fs(o, SLAAC_IF) :
	    "unknown");
	printf("\t index: %3u ", (u_int)fu(o, SLAAC_INDEX, 0));
	printf("running: %3s ", fu(o, SLAAC_RUNNING, 0) ? "yes" : "no");
	printf("temporary: %3s\n", fu(o, SLAAC_TEMPORARY, 0) ? "yes" :
	    "no");
	memset(&ea, 0, sizeof(ea));
	if ((v = FV(o, SLAAC_LLADDR, FACT_ADDRESS)) != NULL)
		memcpy(&ea, v->v.a.bytes, v->v.a.len < sizeof(ea) ?
		    v->v.a.len : sizeof(ea));
	printf("\tlladdr: %s\n", ether_ntoa(&ea));
	printf("\t inet6: %s\n", host(o, SLAAC_INET6, hbuf, sizeof(hbuf)));

	TAILQ_FOREACH(r, rs, entry) {
		if (r->k == &kind_slaacra) {
			printf("\tRouter Advertisement from %s\n",
			    host(r, SRA_ROUTER, hbuf, sizeof(hbuf)));
			printf("\t\treceived: %s; %llds ago\n",
			    when(r, SRA_WHEN, whenbuf, sizeof(whenbuf)),
			    ago(r, SRA_SEEN));
			printf("\t\tCur Hop Limit: %3u, M: %d, O: %d, Router "
			    "Lifetime: %5us\n", (u_int)fu(r, SRA_HOPLIMIT, 0),
			    fu(r, SRA_MANAGED, 0) ? 1 : 0,
			    fu(r, SRA_OTHER, 0) ? 1 : 0,
			    (u_int)fu(r, SRA_LIFETIME, 0));
			printf("\t\tDefault Router Preference: %s\n",
			    str(r, SRA_PREF));
			printf("\t\tReachable Time: %9ums, Retrans Timer: "
			    "%9ums\n", (u_int)fu(r, SRA_REACHABLE, 0),
			    (u_int)fu(r, SRA_RETRANS, 0));
			if (fu(r, SRA_MTU, 0))
				printf("\t\tMTU: %u bytes\n",
				    (u_int)fu(r, SRA_MTU, 0));
		} else if (r->k == &kind_slaacprefix) {
			printf("\t\tprefix: %s/%u\n", host(r, SPFX_PREFIX,
			    ntopbuf, sizeof(ntopbuf)),
			    (u_int)fu(r, SPFX_LEN, 0));
			printf("\t\t\tOn-link: %d, Autonomous "
			    "address-configuration: %d\n",
			    fu(r, SPFX_ONLINK, 0) ? 1 : 0,
			    fu(r, SPFX_AUTONOMOUS, 0) ? 1 : 0);
			lifetimes("\t\t\t", fu(r, SPFX_VLTIME, 0),
			    fu(r, SPFX_PLTIME, 0));
			printf("\n");
		} else if (r->k == &kind_slaacrdns) {
			printf("\t\trdns: %s, lifetime: %u\n",
			    host(r, SRDNS_ADDRESS, ntopbuf, sizeof(ntopbuf)),
			    (u_int)fu(r, SRDNS_LIFETIME, 0));
		} else if (r->k == &kind_slaacaddr) {
			if (prev != r->k)
				printf("\tAddress proposals\n");
			printf("\t\tid: %4lld, state: %15s, temporary: %s\n",
			    prop_id(r), str(r, SP_STATE), fu(r, SADDR_TEMPORARY, 0) ?
			    "y" : "n");
			lifetimes("\t\t", fu(r, SADDR_VLTIME, 0),
			    fu(r, SADDR_PLTIME, 0));
			updated(r, 1);
			printf("\t\t%s, %s/%u\n",
			    host(r, SADDR_ADDRESS, hbuf, sizeof(hbuf)),
			    host(r, SADDR_PREFIX, ntopbuf, sizeof(ntopbuf)),
			    (u_int)fu(r, SADDR_LEN, 0));
		} else if (r->k == &kind_slaacdfr) {
			if (prev != r->k)
				printf("\tDefault router proposals\n");
			printf("\t\tid: %4lld, state: %15s\n",
			    prop_id(r), str(r, SP_STATE));
			printf("\t\trouter: %s\n",
			    host(r, SDFR_ROUTER, hbuf, sizeof(hbuf)));
			printf("\t\trouter lifetime: %10u\n",
			    (u_int)fu(r, SDFR_LIFETIME, 0));
			printf("\t\tPreference: %s\n", str(r, SDFR_PREF));
			updated(r, 0);
		} else if (r->k == &kind_slaacdns) {
			if (prev != r->k)
				printf("\trDNS proposals\n");
			printf("\t\tid: %4lld, state: %15s\n",
			    prop_id(r), str(r, SP_STATE));
			printf("\t\trouter: %s\n",
			    host(r, SDNS_ROUTER, hbuf, sizeof(hbuf)));
			printf("\t\trdns lifetime: %10u\n",
			    (u_int)fu(r, SDNS_LIFETIME, 0));
			printf("\t\trdns:\n");
			for (i = 0; i < SLAAC_RDNS; i++)
				if (fhas(r, SDNS_SERVER + i))
					printf("\t\t\t%s\n", host(r,
					    SDNS_SERVER + i, ntopbuf,
					    sizeof(ntopbuf)));
			updated(r, 0);
		}
		prev = r->k;
	}
}

/* what dhcpleased or slaacd knows of interface o, after its other records */
void
autoconf_render(struct frecs *rs, struct frec *o)
{
	if (o->k == &kind_dhcplease)
		dhcp_render(rs, o);
	else
		slaac_render(rs, o);
}
