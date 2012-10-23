/* $nsh: if.c,v 1.53 2012/05/21 14:46:11 chris Exp $ */
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

#include <stdio.h>
#include <ctype.h>
#include <tzfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
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
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <limits.h>
#include "ip.h"
#include "externs.h"
#include "bridge.h"

char *iftype(int int_type);
char *get_hwdaddr(char *ifname);
void pack_ifaliasreq(struct ifaliasreq *, ip_t *, struct in_addr *, char *);
void pack_in6aliasreq(struct in6_aliasreq *, ip_t *, struct sockaddr_in6 *,
    char *);
void ipv6ll_db_store(struct sockaddr_in6 *, struct sockaddr_in6 *, int, char *);

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
	{ "IPv6-IPv4 TCP relay",	IFT_FAITH },
	{ "Ethernet Bridge",		IFT_BRIDGE },
	{ "Common Address Redundancy Protocol",	IFT_CARP },
	/* IANA-assigned types */
	{ "ATM Logical",		IFT_ATMLOGICAL },
	{ "ATM Virtual",		IFT_ATMVIRTUAL },
	{ "ATM",			IFT_ATM },
	{ "Ethernet",			IFT_ETHER },
	{ "HDLC",			IFT_HDLC },
	{ "IEEE 802.1Q",		IFT_L2VLAN },
	{ "Virtual",			IFT_PROPVIRTUAL },
	{ "MPLS Tunnel Virtual",	IFT_MPLSTUNNEL },
	{ "MPLS Provider Edge",		IFT_MPLS },
	{ "IEEE 802.3ad Link Aggregate", IFT_IEEE8023ADLAG },
	{ "PPP",			IFT_PPP },
	{ "Loopback",			IFT_LOOP },
	{ "ISDN BRI",			IFT_ISDNBASIC },
	{ "ISDN PRI",			IFT_ISDNPRIMARY },
	{ "V.35",			IFT_V35 },
	{ "HSSI",			IFT_HSSI },
	{ "Network Tunnel",		IFT_TUNNEL },
	{ "Coffee Pot",			IFT_COFFEE },
	{ "IEEE 802.11",		IFT_IEEE80211 },
	{ "Unspecified",		IFT_OTHER },
};

int
show_int(int argc, char **argv)
{
	struct ifaddrs *ifap, *ifa;
	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr, ifrdesc;
	struct if_data if_data;
	struct sockaddr_in *sin, *sinmask, *sindest;
	struct sockaddr_in6 *sin6, *sin6mask, *sin6dest;
	struct timeval tv;
	struct vlanreq vreq;

	short tmp;
	int ifs, br, flags, days, hours, mins, pntd;
	int ippntd = 0;
	int buf3;
	time_t c;
	char *type, *lladdr, *ifname = NULL;

	char tmp_str[512], tmp_str2[512], ifdescr[IFDESCRSIZE];

	if (argc == 3)
		ifname = argv[2];

	/*
	 * Show all interfaces when no ifname specified.
	 */
	if (ifname == NULL) {
		if ((ifn_list = if_nameindex()) == NULL) {
			printf("%% show_int: if_nameindex failed\n");
			return 0;
		}
		for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
			char *args[] = { NULL, NULL, ifnp->if_name };

			show_int(3, args);
		}
		if_freenameindex(ifn_list);
		return(0);
	} else if (!is_valid_ifname(ifname)) {
		printf("%% interface %s not found\n", ifname);
		return(1);
	}

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% show_int: %s\n", strerror(errno));
		return(1);
	}

	if (!(br = is_bridge(ifs, (char *)ifname)))
		br = 0;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	/*
	 * Show up/down status and last change time
	 */
	flags = get_ifflags(ifname, ifs);

	ifr.ifr_data = (caddr_t)&if_data;
	if (ioctl(ifs, SIOCGIFDATA, (caddr_t)&ifr) < 0) {
		printf("%% show_int: SIOCGIFDATA: %s\n", strerror(errno));
		close(ifs);
		return(1);
	}

	printf("%% %s", ifname);

	/* description */
	memset(&ifrdesc, 0, sizeof(ifrdesc));
	strlcpy(ifrdesc.ifr_name, ifname, sizeof(ifrdesc.ifr_name));
	ifrdesc.ifr_data = (caddr_t)&ifdescr;
	if (ioctl(ifs, SIOCGIFDESCR, &ifrdesc) == 0 && strlen(ifrdesc.ifr_data))
		printf(" (%s)", ifrdesc.ifr_data);

	putchar('\n');

	printf("  %s is %s", br ? "Bridge" : "Interface",
	    flags & IFF_UP ? "up" : "down");

	if (if_lastchange.tv_sec) {
		gettimeofday(&tv, (struct timezone *)0);
		c = difftime(tv.tv_sec, if_lastchange.tv_sec);
		days = c / SECSPERDAY;
		c %= SECSPERDAY;
		hours = c / SECSPERHOUR;
		c %= SECSPERHOUR;
		mins = c / SECSPERMIN;
		c %= SECSPERMIN;
		printf(" (last change ");
		if (days)
			printf("%id ", days);
		printf("%02i:%02i:%02i)", hours, mins, c);
	}

	printf(", protocol is %s", flags & IFF_RUNNING ? "up" : "down");
	printf("\n");

	type = iftype(if_type);

	printf("  Interface type %s", type);
	if (flags & IFF_BROADCAST)
		printf(" (Broadcast)");
	else if (flags & IFF_POINTOPOINT)
		printf(" (PointToPoint)");

	if ((lladdr = get_hwdaddr(ifname)) != NULL)
		printf(", hardware address %s", lladdr);
	printf("\n");

	show_trunk(ifs, ifname);
	media_status(ifs, ifname, "  Media type ");

	/*
	 * Print interface IP address, and broadcast or
	 * destination if available.  But, don't print broadcast
	 * if it is what we would expect given the ip and netmask!
	 */
	if (getifaddrs(&ifap) != 0) {
		printf("%% show_int: getifaddrs failed: %s\n",
		    strerror(errno));
		return(1);
	}
 
	/*
	 * Cycle through getifaddrs for interfaces with our
	 * desired name that sport AF_INET, print the IP and
	 * related information.
	 */
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strncmp(ifname, ifa->ifa_name, IFNAMSIZ))
			continue;

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)ifa->ifa_addr;
			sinmask = (struct sockaddr_in *)ifa->ifa_netmask;
			if (sin->sin_addr.s_addr == 0)
				continue;
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			sin6mask = (struct sockaddr_in6 *)ifa->ifa_netmask;
			if (sin6->sin6_addr.s6_addr == 0)
				continue;
			in6_fillscopeid(sin6);
			break;
		default:
			continue;
		}
		
		if (!ippntd)
			printf("  Internet address");

		printf("%s %s", ippntd ? "," : "", ifa->ifa_addr->sa_family == AF_INET ?
		    netname4(sin->sin_addr.s_addr, sinmask) : netname6(sin6, sin6mask));

		ippntd = 1;

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			if (flags & IFF_POINTOPOINT) {
				sindest = (struct sockaddr_in *)ifa->ifa_dstaddr;
				printf(" (Destination %s)", routename4(sindest));
			} else if (flags & IFF_BROADCAST) {
				sindest = (struct sockaddr_in *)ifa->ifa_broadaddr;
				/*
				 * no reason to show the broadcast addr
				 * if it is standard (this should always
				 * be true unless someone has messed up their
				 * network or they are playing around...)
				 */
				if (ntohl(sindest->sin_addr.s_addr) !=
				    in4_brdaddr(sin->sin_addr.s_addr,
				    sinmask->sin_addr.s_addr))
					printf(" (Broadcast %s)",
					    inet_ntoa(sindest->sin_addr));
			}
			break;
		case AF_INET6:
			if (flags & IFF_POINTOPOINT) {
				sin6dest = (struct sockaddr_in6 *)ifa->ifa_dstaddr;
				in6_fillscopeid(sin6dest);
				printf(" (Destination %s)", routename6(sin6dest));
			}
			break;
		default:
			printf(" unknown");
			break;
		}
	}

	if (ippntd) {
		ippntd = 0;
		printf("\n");
	}
	freeifaddrs(ifap);

	if (!br) {
		if (phys_status(ifs, ifname, tmp_str, tmp_str2,
		    sizeof(tmp_str), sizeof(tmp_str2), &buf3) > 0) {
			printf("  Tunnel source %s destination %s",
			    tmp_str, tmp_str2);
			if (&buf3 != NULL)
				printf(" destination rdomain %i", buf3);
			printf("\n");
		}
		carp_state(ifs, ifname);

		printf(" ");
		if (ioctl(ifs, SIOCGIFRDOMAIN, (caddr_t)&ifr) != -1)
			printf(" Routing Domain %d,", ifr.ifr_rdomainid);
		/*
		 * Display MTU, line rate
		 */
		printf(" MTU %u bytes", if_mtu);
		if (if_baudrate)
			printf(", Line Rate %qu %s\n",
			    MBPS(if_baudrate) ? MBPS(if_baudrate) :
			    if_baudrate / 1000,
			    MBPS(if_baudrate) ? "Mbps" : "Kbps");
		else
			printf("\n");
 
		memset(&vreq, 0, sizeof(struct vlanreq));
		ifr.ifr_data = (caddr_t)&vreq;

		if (ioctl(ifs, SIOCGETVLAN, (caddr_t)&ifr) != -1)
			if(vreq.vlr_tag || (vreq.vlr_parent[0] != '\0'))
				printf("  802.1Q vlan tag %d, parent %s\n",
				    vreq.vlr_tag, vreq.vlr_parent[0] == '\0' ?
				    "<none>" : vreq.vlr_parent);
	}

	if (get_nwinfo(ifname, tmp_str, sizeof(tmp_str), NWID) != 0) {
		printf("  SSID %s", tmp_str);
		if(get_nwinfo(ifname, tmp_str, sizeof(tmp_str), NWKEY) != 0)
			printf(", key %s", tmp_str);
		if ((tmp = get_nwinfo(ifname, tmp_str, sizeof(tmp_str),
		    POWERSAVE)) != 0)
			printf(", powersaving (%s ms)\n", tmp_str);
		printf("\n");
	}

	/*
	 * Display remaining info from if_data structure
	 */
	printf("  %qu packets input, %qu bytes, %qu errors, %qu drops\n",
	    if_ipackets, if_ibytes, if_ierrors, if_iqdrops);
	printf("  %qu packets output, %qu bytes, %qu errors, %qu unsupported\n",
	    if_opackets, if_obytes, if_oerrors, if_noproto);
	if (if_ibytes && if_ipackets && (if_ibytes / if_ipackets) >= ETHERMIN) {
		/* < ETHERMIN means byte counter probably rolled over */
		printf("  %qu input", if_ibytes / if_ipackets);
		pntd = 1;
	} else
		pntd = 0;
	if (if_obytes && if_opackets && (if_obytes / if_opackets) >= ETHERMIN) {
		/* < ETHERMIN means byte counter probably rolled over */
		printf("%s%qu output", pntd ? ", " : "  ",
		    if_obytes / if_opackets);
		pntd = 1;
	}
	if (pntd)
		printf(" (average bytes/packet)\n");

	switch(if_type) {
	/*
	 * These appear to be the only interface types to increase collision
	 * count in the OpenBSD 3.2 kernel.
	 */
	case IFT_ETHER:
	case IFT_SLIP:
	case IFT_PROPVIRTUAL:
	case IFT_IEEE80211:
		printf("  %qu collisions\n", if_collisions);
		break;
	default:
		break;
	}

	if(verbose) {
		if (flags) {
			printf("  Flags:\n    ");
			bprintf(stdout, flags, ifnetflags);
			printf("\n");
		}
		if (br) {
			if ((tmp = bridge_list(ifs, ifname, "    ", tmp_str,
			    sizeof(tmp_str), SHOW_STPSTATE))) {
				printf("  STP member state%s:\n", tmp > 1 ?
				    "s" : "");
				printf("%s", tmp_str);
			}
			bridge_addrs(ifs, ifname, "  ", "    ");
		}
		media_supported(ifs, ifname, "  ", "    ");
	}

	close(ifs);
	return(0);
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

	return(bcast);
}

char *
get_hwdaddr(char *ifname)
{
	int i, found = 0;
	char *val = NULL;
	struct ifaddrs *ifap, *ifa;
	struct ether_addr *ea;
	struct sockaddr_dl *sdl = NULL;

	if (getifaddrs(&ifap) != 0) {
		printf("%% get_hwdaddr: getifaddrs: %s\n", strerror(errno));
		return(NULL);
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next)
		if (ifa->ifa_addr->sa_family == AF_LINK &&
		    (strcmp(ifname, ifa->ifa_name) == 0)) {
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			found++;
			break;
		}

	if (found && sdl && sdl->sdl_alen)
		switch(sdl->sdl_type) {
		case IFT_ETHER:
		case IFT_IEEE80211:
			ea = (struct ether_addr *)LLADDR(sdl);
			val = ether_ntoa(ea);
			for (found = 0, i = 0; i < ETHER_ADDR_LEN; i++)
				if (ea->ether_addr_octet[i] == 0)
					found++;
			if (found == ETHER_ADDR_LEN)
				val = NULL;
			break;
		default:
			val = NULL;
			break;
		}

	freeifaddrs(ifap);

	return(val);
}

char *
iftype(int int_type)
{
	u_int i;

	for (i = 0; i < sizeof(iftypes) / sizeof(iftypes[0]); i++)
		if (int_type == iftypes[i].type)
			return(iftypes[i].name);

	if (verbose)
		printf("%% iftype: int_type %x\n", int_type);
	return("Unknown");
}

int 
get_ifdata(char *ifname, int type)
{
	int ifs, value = 0;
	struct ifreq ifr;
	struct if_data if_data;

	if (type == IFDATA_MTU)
		value = 576;			 /* default MTU */
	/*
	 * We don't set a default for IFDATA_BAUDRATE because we detect
	 * a failure at 0
	 */

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return (value);
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&if_data;
	if (ioctl(ifs, SIOCGIFDATA, (caddr_t)&ifr) == 0) {
		if (type == IFDATA_MTU)
			value = if_mtu;
		else if (type == IFDATA_BAUDRATE)
			value = if_baudrate;
	}
	close(ifs);
	return (value);
}

/*
 * returns 1 if one valid, matching interface name is found
 * returns 0 for no valid or failure
 */
int
is_valid_ifname(char *ifname)
{
	struct if_nameindex *ifn_list, *ifnp;
	int count = 0;

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% is_valid_ifname: if_nameindex failed\n");
		return(0);
	}
	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		if (strcasecmp(ifname, ifnp->if_name) == 0)
			count++;
	}
	if_freenameindex(ifn_list);

	if (count == 1)
		return(1);
	else
		return(0);
}

int
get_ifflags(char *ifname, int ifs)
{
	int flags;
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		printf("%% get_ifflags: SIOCGIFFLAGS: %s\n", strerror(errno));
		flags = 0;
	} else
		flags = ifr.ifr_flags;
	return(flags);
}

/*
 * similar to set_ifflag in bridge.c but does not care about
 * existing flags
 */
int
set_ifflags(char *ifname, int ifs, int flags)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	ifr.ifr_flags = flags;

	if (ioctl(ifs, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
		printf("%% get_ifflags: SIOCSIFFLAGS: %s\n", strerror(errno));
	}

        return(0);
}

int
get_ifxflags(char *ifname, int ifs)
{
	int flags;
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCGIFXFLAGS, (caddr_t)&ifr) < 0) {
		printf("%% get_ifxflags: SIOCGIFXFLAGS: %s\n", strerror(errno));
		flags = 0;
	} else
		flags = ifr.ifr_flags;
	return(flags);
}

int
set_ifxflags(char *ifname, int ifs, int flags)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	ifr.ifr_flags = flags;

	if (ioctl(ifs, SIOCSIFXFLAGS, (caddr_t)&ifr) < 0) {
		printf("%% get_ifxflags: SIOCSIFXFLAGS: %s\n", strerror(errno));
	}

	return(0);
}

int
intip(char *ifname, int ifs, int argc, char **argv)
{
	int s, set, flags, argcmax;
	char *msg, *cmdname;
	ip_t ip;
	/* ipv4 structures */
	struct in_addr destbcast;
	struct ifaliasreq ip4req;
	/* ipv6 structures */
	struct in6_aliasreq ip6req;
	struct sockaddr_in6 sin6dest;

	memset(&sin6dest, 0, sizeof(sin6dest));
	memset(&ip, 0, sizeof(ip));

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	/*
	 * We use this function for ip and alias setup since they are
	 * the same thing.
	 */
	if (isprefix(argv[0], "alias")) {
		cmdname = "alias";
	} else if (isprefix(argv[0], "ip")) {
		cmdname = "ip";
	} else {
		printf("%% intip: Internal error\n");
		return 0;
	}

	argc--;
	argv++;

	flags = get_ifflags(ifname, ifs);
	if (flags & IFF_POINTOPOINT) {
		argcmax = 2;
		msg = "destination";
	} else if (flags & IFF_BROADCAST) {
		argcmax = 2;
		msg = "broadcast";
	} else {
		argcmax = 1;
		msg = NULL;
	}

	if (argc < 1 || argc > argcmax) {
		printf("%% %s <address>/<bits> %s%s%s\n", cmdname,
		    msg ? "[" : "", msg ? msg : "", msg ? "]" : "");
		printf("%% %s <address>/<netmask> %s%s%s\n", cmdname,
		    msg ? "[" : "", msg ? msg : "", msg ? "]" : "");
		printf("%% no %s <address>[/bits]\n", cmdname);
		printf("%% no %s <address>[/netmask]\n", cmdname);
		return(0);
	}

	/* ignore 'address' keyword, don't print error */
	if (isprefix(argv[0], "address")) {
		argc--;
		argv++;
	}

	if (isprefix(argv[0], "dhcp")) {
		char *args[] = { PKILL, "dhclient", ifname, '\0' };
		char *args_set[] = { DHCLIENT, ifname, '\0' };
		char leasefile[sizeof(LEASEPREFIX)+1+IFNAMSIZ];

		if (set)
			cmdargs(DHCLIENT, args_set);
		else {
			cmdargs(PKILL, args);
			snprintf(leasefile, sizeof(leasefile), "%s.%s",
			    LEASEPREFIX, ifname);
			rmtemp(leasefile);
		}
		return(0);
	}

	parse_ip(argv[0], NO_NETMASK, &ip);

	if (ip.family == 0)
		/* bad IP specified */
		return(0);

	if (set && flags & IFF_BROADCAST && ip.bitlen == -1) {
		printf("%% Netmask not specified\n");
		return(0);
	}
	
	if (ip.bitlen == -1)
		ip.bitlen = 0;
	switch(ip.family) {
	case AF_INET:
		if (argc == 2 && !inet_aton(argv[1], &destbcast)) {
			printf("%% Invalid %s address\n", msg);
			return(0);
		}
		pack_ifaliasreq(&ip4req, &ip, &destbcast, ifname);
		/* do it */
		if (ioctl(ifs, set ? SIOCAIFADDR : SIOCDIFADDR, &ip4req) < 0)
			printf("%% intip: SIOC%sIFADDR: %s\n", set ? "A" : "D",
			    strerror(errno));
		break;
	case AF_INET6:
		if (argc == 2 && !inet_pton(AF_INET6, argv[1], &sin6dest)) {
			printf("%% Invalid %s address\n", msg);
			return(0);
		}
		pack_in6aliasreq(&ip6req, &ip, &sin6dest, ifname);
		/* get inet6 socket */
		s = socket(PF_INET6, SOCK_DGRAM, 0);
		if (s < 0) {
			printf("%% socket failed: %s\n", strerror(errno));
			return(0);
		}
		/* do it */
		if (ioctl(s, set ? SIOCAIFADDR_IN6 : SIOCDIFADDR_IN6, &ip6req)
		    < 0) {
			if (!set && errno == EADDRNOTAVAIL)
				printf("%% IP address not found on %s\n",
				    ifname);
			else
				printf("%% intip: SIOC%sIFADDR_IN6: %s\n",
				    set ? "A" : "D", strerror(errno));
		} else {
			ipv6ll_db_store(
			    (struct sockaddr_in6 *)&ip6req.ifra_addr,
			    (struct sockaddr_in6 *)&ip6req.ifra_prefixmask,
			    set ? DB_X_ENABLE : DB_X_REMOVE, ifname);
		}
		close(s);
		break;
	default:
		printf("%% unknown address family: %d\n", ip.family);
		break;
	}
	return(0);
}

void
pack_ifaliasreq(struct ifaliasreq *ip4req, ip_t *ip,
    struct in_addr *destbcast, char *ifname)
{
	struct sockaddr_in *sin;

	memset(ip4req, 0, sizeof(ip4req));

	/* set IP address */
	sin = (struct sockaddr_in *)&ip4req->ifra_addr;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_addr.s_addr = ip->addr.sin.s_addr;
	/* set netmask */
	sin = (struct sockaddr_in *)&ip4req->ifra_mask;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_addr.s_addr = htonl(0xffffffff << (32 - ip->bitlen));
	/* set destination/broadcast address */
	if (destbcast->s_addr != 0) {
		sin = (struct sockaddr_in *)&ip4req->ifra_dstaddr;
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(struct sockaddr_in);
		sin->sin_addr.s_addr = destbcast->s_addr;
	}
	/* set interface name */
	strlcpy(ip4req->ifra_name, ifname, sizeof(ip4req->ifra_name));
}

void
pack_in6aliasreq(struct in6_aliasreq *ip6req, ip_t *ip,
    struct sockaddr_in6 *sin6dest, char *ifname)
{
	struct sockaddr_in6 *sin6;

	memset(ip6req, 0, sizeof(ip6req));

	/* set IP address */
	sin6 = (struct sockaddr_in6 *)&ip6req->ifra_addr;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_addr = ip->addr.sin6;
	/* set prefixmask */
	sin6 = (struct sockaddr_in6 *)&ip6req->ifra_prefixmask;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	prefixlen(ip->bitlen, sin6);
	/* set infinite lifetime */
	ip6req->ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
	ip6req->ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	/* set destination address */
	if (sin6dest->sin6_family != 0) {
		sin6 = (struct sockaddr_in6 *)&ip6req->ifra_dstaddr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(struct sockaddr_in6);
		sin6->sin6_addr = sin6dest->sin6_addr;
	}
	/* set interface name */
	strlcpy(ip6req->ifra_name, ifname, sizeof(ip6req->ifra_name));
}

void
ipv6ll_db_store(struct sockaddr_in6 *sin6, struct sockaddr_in6 *sin6mask,
    int dbflag, char *ifname)
{
	/*
	 * If linklocal, store a version that will match conf output
	 * with no scope id, ifname in separate database field
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_INTFACELOCAL(&sin6->sin6_addr)) {
		sin6->sin6_addr.s6_addr[2] = sin6->sin6_addr.s6_addr[3] = 0;
		sin6->sin6_scope_id = 0;
		db_delete_flag_x_ctl_data("ipv6linklocal", ifname,
		    netname6(sin6, sin6mask));
		if (dbflag != DB_X_REMOVE)
			db_insert_flag_x("ipv6linklocal", ifname, 0,
			    dbflag, netname6(sin6, sin6mask));
	}
}

/*
 * addr/port parsing lifted from sbin/ifconfig/ifconfig.c
 */
int
intpflow(char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	struct pflowreq preq;
	struct addrinfo hints, *sender, *receiver;
	int ecode, set;
	char *ip, *port, buf[MAXHOSTNAMELEN+sizeof (":65535")];
	const char *errmsg = NULL;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if ((set && argc < 4) || (set && argc == 5) || (set && argc >= 4 &&
		(!isprefix(argv[0], "sender") || !isprefix(argv[2], "receiver") ||
		(argc == 6 && !isprefix(argv[4], "version"))))) {
		printf("%% pflow sender <x.x.x.x> receiver <x.x.x.x:port> [version 5|9|10]\n");
		printf("%% no pflow [sender x.x.x.x receiver x.x.x.x:port version 5|9|10]\n");
		return(0);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM; /*dummy*/

	if (set) {
		if ((ecode = getaddrinfo(argv[1], NULL, &hints, &sender)) != 0) {
			printf("%% Invalid sender %s: %s\n", argv[2],
			    gai_strerror(ecode));
			return(0);
		}

		if (sender->ai_addr->sa_family != AF_INET) {
			printf("%% Only IPv4 addresses supported for the sender\n");
			freeaddrinfo(sender);
			return(0);
		}

	        if (strchr(argv[3], ':') == NULL) {
			printf("%% Receiver has no port specified\n");
			freeaddrinfo(sender);
			return(0);
		}

		if (strlcpy(buf, argv[3], sizeof(buf)) >= sizeof(buf)) {
			printf("%% Receiver value too large\n");
			freeaddrinfo(sender);
			return(0);
		}

		port = strchr(buf, ':');
		*port++ = '\0';
		ip = buf;
 
		if ((ecode = getaddrinfo(ip, port, &hints, &receiver)) != 0) {
			printf("%% Invalid receiver %s: %s\n", ip,
			    gai_strerror(ecode));
			freeaddrinfo(sender);
			return(0);
		}

		if (receiver->ai_addr->sa_family != AF_INET) {
			printf("%% Only IPv4 addresses supported for the receiver\n");
			freeaddrinfo(sender);
			freeaddrinfo(receiver);
			return(0);
		}
	}

	bzero(&ifr, sizeof(ifr));     
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	bzero((char *)&preq, sizeof(struct pflowreq));
	ifr.ifr_data = (caddr_t)&preq;

	if (set) {
		preq.sender_ip.s_addr = ((struct sockaddr_in *)
		    sender->ai_addr)->sin_addr.s_addr;
		preq.receiver_ip.s_addr = ((struct sockaddr_in *)
		    receiver->ai_addr)->sin_addr.s_addr;
		preq.receiver_port = (u_int16_t) ((struct sockaddr_in *)
		    receiver->ai_addr)->sin_port;
		if (argc == 6) {
			preq.version = strtonum(argv[5], 5, PFLOW_PROTO_MAX, &errmsg);
			preq.addrmask = PFLOW_MASK_VERSION;
	                if (errmsg) {
				printf("%% Invalid pflow version %s: %s\n", argv[0], errmsg);
				goto done;
			}
                }

	}
	preq.addrmask |= PFLOW_MASK_SRCIP | PFLOW_MASK_DSTIP | PFLOW_MASK_DSTPRT;
	if (ioctl(ifs, SIOCSETPFLOW, (caddr_t)&ifr) == -1)
		printf("%% Unable to set pflow parameters: %s\n", strerror(errno));

done:
	if (set) {
		freeaddrinfo(sender);
		freeaddrinfo(receiver);
	}

	return(0);
}

int
intmtu(char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	int set;
	const char *errmsg = NULL;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% mtu <mtu>\n");
		printf("%% no mtu [mtu]\n");
		return(0);
	}

	if (set) {
		ifr.ifr_mtu = strtonum(argv[0], 0, INT_MAX, &errmsg);
		if (errmsg) {
			printf("%% Invalid MTU %s: %s\n", argv[0], errmsg);
			return(0);
		}
	} else
		ifr.ifr_mtu = default_mtu(ifname);

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFMTU, (caddr_t)&ifr) < 0)
		printf("%% intmtu: SIOCSIFMTU: %s\n", strerror(errno));

	return(0);
}

int
intkeepalive(char *ifname, int ifs, int argc, char **argv)
{
	struct ifkalivereq ikar;
	int set;
	const char *errmsg = NULL;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if ((!set && argc > 2) || (set && argc != 2)) {
		printf("%% keepalive <period> <count>\n");
		printf("%% no keepalive [period] [count]\n");
		return(0);
	}

	bzero(&ikar, sizeof(ikar));

	if (set) {
		ikar.ikar_timeo = strtonum(argv[0], 1, 3600, &errmsg);
		if (errmsg) {
			printf("%% Invalid period %s: %s\n", argv[0], errmsg);
			return(0);
		}
		ikar.ikar_cnt = strtonum(argv[1], 2, 600, &errmsg);
		if (errmsg) {
			printf("%% Invalid count %s: %s\n", argv[1], errmsg);
			return(0);
		}
	}

	strlcpy(ikar.ikar_name, ifname, sizeof(ikar.ikar_name));
	if (ioctl(ifs, SIOCSETKALIVE, (caddr_t)&ikar) < 0) {
		if (errno == ENOTTY)
			printf("%% Keepalive not available on this interface\n");
		else
			printf("%% intkeepalive: SIOCSETKALIVE: %s\n", strerror(errno));
	}

	return(0);
}

int
intlabel(char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	struct shim_hdr shim;
	int set;
	const char *errmsg = NULL;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% label <mplslabel>\n");
		printf("%% no label [mplslabel]\n");
		return(0);
	}

	bzero(&shim, sizeof(shim));
	ifr.ifr_data = (caddr_t)&shim;

	if (set) {
		shim.shim_label = strtonum(argv[0], 0, MPLS_LABEL_MAX, &errmsg);
		if (errmsg) {
			printf("%% Invalid MPLS Label %s: %s\n", argv[0], errmsg);
			return(0);
		}
	} else
		shim.shim_label = 0;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSETLABEL, (caddr_t)&ifr) < 0) {
		if (errno == ENOTTY)
			printf("%% MPLS label not supported on this device (mpe only)\n");
		else
			printf("%% intlabel: SIOCSETLABEL: %s\n", strerror(errno));
	}
	return(0);
}

int
intdhcrelay(char *ifname, int ifs, int argc, char **argv)
{
	char *cmd[] = { DHCRELAY, "-i", ifname, NULL, '\0' };
	int set, alen;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% dhcrelay <relayserver>\n");
		printf("%% no dhcrelay [relayserver]\n");
		return(0);
	}

	/* XXX validate argv[0] IP address */
	cmd[3] = argv[0];

	if (set) {
		flag_x("dhcrelay", ifname, DB_X_ENABLE, argv[0]);
		cmdargs(DHCRELAY, cmd);
	} else {
		char server[24], argue[SIZE_CONF_TEMP];
		char *killcmd[] = { PKILL, "-xf", NULL, '\0' };

		if ((alen = conf_dhcrelay(ifname, server, sizeof(server))) < 1) {
			if (alen == 0)
				printf("%% No relay configured for %s\n", ifname);
			else
				printf("%% int_dhcrelay: conf_dhcrelay failed: %d\n", alen);
			return(0);
		}

		/* if dhcrelay not relaying to specified dhcp server, bail out */
		if (argc && strcmp(server, argv[0]) != 0) {
			printf("%% Server expected: %s (not %s)\n", server, argv[0]);
			return(0);
		}

		flag_x("dhcrelay", ifname, DB_X_REMOVE, NULL);

		/* setup argument list as one argument for pkill -xf */
		snprintf(argue, sizeof(argue), "%s %s %s %s", cmd[0], cmd[1], cmd[2], server);
		killcmd[2] = argue;

		cmdargs(PKILL, killcmd);
	}
	return(0);
}

int
intmetric(char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	int set;
	const char *errmsg = NULL;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% metric <metric>\n");
		printf("%% no metric [metric]\n");
		return(0);
	}

	if (set)
		ifr.ifr_metric = strtonum(argv[0], 0, ULONG_MAX, &errmsg);
	else
		ifr.ifr_metric = 0;

	if (errmsg) {
		printf("%% Invalid metric %s: %s\n", argv[0], errmsg);
		return(0);
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFMETRIC, (caddr_t)&ifr) < 0)
		printf("%% intmetric: SIOCSIFMETRIC: %s\n", strerror(errno));

	return(0);
}

int
intvlan(char *ifname, int ifs, int argc, char **argv)
{
	const char *errmsg = NULL;
	struct ifreq ifr;
	struct vlanreq vreq;
	int set;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if ((set && argc != 3) || (!set && argc > 3) ||
	    (argc == 3 && !isprefix(argv[1], "parent"))) {
		printf("%% vlan <tag> parent <parent interface>\n");
		printf("%% no vlan [tag] [parent <parent interface>]\n");
		return 0;
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	bzero(&vreq, sizeof(vreq));

	ifr.ifr_data = (caddr_t)&vreq;

	if (ioctl(ifs, SIOCGETVLAN, (caddr_t)&ifr) == -1) {
		switch(errno) {
		case ENOTTY:
			printf("%% This interface does not support vlan"
			    " tagging\n");
			break;
		default:
			printf("%% intvlan: SIOCGETVLAN: %s\n",
			    strerror(errno));
		}
		return(0);
	}

	if (set) {
		if (!is_valid_ifname(argv[2]) || is_bridge(ifs, argv[2])) {
			printf("%% Invalid vlan parent %s\n", argv[2]);
			return 0;
		}
		strlcpy(vreq.vlr_parent, argv[2], sizeof(vreq.vlr_parent));
		vreq.vlr_tag = strtonum(argv[0], 0, 4096, &errmsg);
		if (errmsg) {
			printf("%% Invalid vlan tag %s: %s", argv[0], errmsg);
			return 0;
		}
		if (vreq.vlr_tag != EVL_VLANOFTAG(vreq.vlr_tag)) {
			printf("%% Invalid vlan tag %s\n", argv[0]);
			return 0;
		}
	} else {
		bzero(&vreq.vlr_parent, sizeof(vreq.vlr_parent));
		vreq.vlr_tag = 0;
	}

	if (ioctl(ifs, SIOCSETVLAN, (caddr_t)&ifr) == -1) {
		switch(errno) {
		case EBUSY:
			printf("%% Please disconnect the current vlan parent"
			    " before setting a new one\n");
			return 0;
			break;
		default:
			printf("%% intvlan: SIOCSETVLAN: %s\n",
			    strerror(errno));
			return 0;
		}
	}

	return 0;
}

int
intgroup(char *ifname, int ifs, int argc, char **argv)
{
	int set, i;
	char *ioc;
	struct ifgroupreq ifgr;
	unsigned long ioctype;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if (argc < 1) {
		printf("%% group <group-name> [group-name ...]\n");
		printf("%% no group <group-name> [group-name ...]\n");
		return 0;
	}

	for (i = 0; i < argc; i++) {
		/* Validate supplied argument(s) before applying them */
		if (isdigit(argv[i][strlen(argv[i]) - 1])) {
			printf("%% Group names may not end with a digit\n");
			return 0;
		}
		if (strlen(argv[i]) >= IFNAMSIZ) {
			printf("%% Group name too long (%s)\n", argv[i]);
			return 0;
		}
	}

	if (set) {
		ioctype=SIOCAIFGROUP;
		ioc="SIOCAIFGROUP";
	} else {
		ioctype=SIOCDIFGROUP;
		ioc="SIOCDIFGROUP";
	}

	for (i = 0; i < argc; i++) {
		bzero(&ifgr, sizeof(ifgr));
		strlcpy(ifgr.ifgr_name, ifname, IFNAMSIZ);
		strlcpy(ifgr.ifgr_group, argv[i], IFNAMSIZ);

		if (ioctl(ifs, ioctype, (caddr_t)&ifgr) == -1) {
			switch(errno) {
			case EEXIST:
				break;
			default:
				printf("%% intgroup: %s: %s\n", ioc,
				    strerror(errno));
				break;
			}
		}
	}

	return 0;
}

int
intrtlabel(char *ifname, int ifs, int argc, char **argv)
{
	int set;
	struct ifreq ifr;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	bzero(&ifr, sizeof(ifr));

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (set) {
		if (strlen(argv[0]) >= RTLABEL_LEN) {
			printf("%% label too long (max %d char)\n",
			    RTLABEL_LEN - 1);
			return 0;
		}
		ifr.ifr_data = (caddr_t)argv[0];
	} else {
		ifr.ifr_data = (caddr_t)(const char *)"";
	}

	if (ioctl(ifs, SIOCSIFRTLABEL, &ifr) == -1)
		printf("%% intrtlabel: SIOCSIFRTLABEL: %s\n", strerror(errno));

	return 0;
}

int
intflags(char *ifname, int ifs, int argc, char **argv)
{
	int set, value, flags;

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	if (isprefix(argv[0], "debug")) {
		/* debug */
		value = IFF_DEBUG;
	} else if (isprefix(argv[0], "shutdown")) {
		/* shutdown */
		value = -IFF_UP;
	} else if (isprefix(argv[0], "arp")) {
		/* arp */
		value = -IFF_NOARP;
	} else {
		printf("%% intflags: Internal error\n");
		return(0);
	}

	flags = get_ifflags(ifname, ifs);
	if (value < 0) {
		/*
		 * Idea from ifconfig.  If value is negative then
		 * we just reverse the operation. (e.g. 'shutdown' is
		 * the opposite of the IFF_UP flag)
		 */
		if (set) {
			value = -value;
			flags &= ~value;
		} else {
			value = -value;
			flags |= value;
		}
	} else if (value > 0) {
		if (set)
			flags |= value;
		else
			flags &= ~value;
	} else {
		printf("%% intflags: value internal error\n");
	}
	set_ifflags(ifname, ifs, flags);
	return(0);
}

int
intxflags(char *ifname, int ifs, int argc, char **argv)
{
	int set, value, flags;

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	if (isprefix(argv[0], "autoconfprivacy")) {
		value = -IFXF_INET6_NOPRIVACY;
	} else if (isprefix(argv[0], "mpls")) {
		value = IFXF_MPLS;
	} else if (isprefix(argv[0], "inet6")) {
		value = -IFXF_NOINET6;
	} else if (isprefix(argv[0], "wol")) {
		value = IFXF_WOL;
	} else {
		printf("%% intxflags: Internal error\n");
		return(0);
	}

	flags = get_ifxflags(ifname, ifs);
	if (value < 0) {
		if (set) {
			value = -value;
			flags &= ~value;
		} else {
			value = -value;
			flags |= value;
		}
	} else if (value > 0) {
		if (set)
			flags |= value;
		else
			flags &= ~value;
	} else {
		printf("%% intxflags: value internal error\n");
	}
	set_ifxflags(ifname, ifs, flags);
	return(0);
}

int
intlink(char *ifname, int ifs, int argc, char **argv)
{
	const char *errmsg = NULL;
	int set, i, flags, value = 0;

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	argv++;
	argc--;

	if ((set && argc < 1) || argc > 3) {
		printf("%% link <012>\n");
		printf("%% no link [012]\n");
		return(0);
	}

	flags = get_ifflags(ifname, ifs);

	if (!set && argc == 0) {
		/*
		 * just 'no link' was specified.  so we remove all flags
		 */
		flags &= ~IFF_LINK0 & ~IFF_LINK1 & ~IFF_LINK2;
	} else 
	for (i = 0; i < argc; i++) {
		int a;

		a = strtonum(argv[i], 0, 2, &errmsg);
		if (errmsg) {
			printf("%% Invalid link flag %s: %s\n", argv[i],
			    errmsg);
			return(0);
		}
		switch(a) {
		case 0:
			value = IFF_LINK0;
			break;
		case 1:
			value = IFF_LINK1;
			break;
		case 2:
			value = IFF_LINK2;
			break;
		}

		if (set)
			flags |= value;
		else
			flags &= ~value;
	}

	set_ifflags(ifname, ifs, flags);

	return(0);
}

int
intnwid(char *ifname, int ifs, int argc, char **argv)
{
	struct ieee80211_nwid nwid;
	struct ifreq ifr;
	int set, len;

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	argv++;
	argc--;

	if ((set && argc != 1) || (!set && argc > 1)) {
		printf("%% nwid <nwid>\n");
		printf("%% no nwid [nwid]\n");
		return(0);
	}

	len = sizeof(nwid.i_nwid);

	if (set) {
		if (get_string(argv[0], NULL, nwid.i_nwid, &len) == NULL) {
			printf("%% intnwid: bad input\n");
			return(0);
		}
	} else
		len = 0; /* nwid "" */

	nwid.i_len = len;
	ifr.ifr_data = (caddr_t)&nwid;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCS80211NWID, (caddr_t)&ifr) < 0)
		printf("%% intnwid: SIOCS80211NWID: %s\n", strerror(errno));

	return(0);
}

int
intpowersave(char *ifname, int ifs, int argc, char **argv)
{
	const char *errmsg = NULL;
	struct ieee80211_power power;
	int  set;

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	argv++;
	argc--;

 	if (argc > 1) {
		printf("%% powersave [milisec]\n");
		printf("%% no powersave [milisec]\n");
	}

	strlcpy(power.i_name, ifname, sizeof(power.i_name));

	if (ioctl(ifs, SIOCG80211POWER, (caddr_t)&power) == -1) {
		printf("%% intpowersave: SIOCG80211POWER: %s\n",
		    strerror(errno));
		return(0);
	}

	if (argc == 1)
		power.i_maxsleep = strtonum(argv[0], 0, 1000, &errmsg);
		if (errmsg) {
			printf("%% Power save invalid %s: %s", argv[0], errmsg);
			return(0);
		}
	else
		power.i_maxsleep = DEFAULT_POWERSAVE;
	power.i_enabled = set;

	if (ioctl(ifs, SIOCS80211POWER, (caddr_t)&power) == -1) {
		printf("%% intpowersave: SIOCS80211POWER: %s\n",
		    strerror(errno));
		return(0);
	}

	return(0);
}

int
intlladdr(char *ifname, int ifs, int argc, char **argv)
{
	char *lladdr, llorig[IFNAMSIZ+1];
	struct ether_addr *addr;
	struct ifreq ifr;
	FILE *llfile;
#define LLPREFIX "/var/run/lladdr"
	char llfn[sizeof(LLPREFIX)+IFNAMSIZ+1];
	int set;

	if (NO_ARG(argv[0])) {
		argv++;
		argc--;
		set = 0;
	} else
		set = 1;

	if (set && argc < 2) {
		printf ("%% lladdr <link level address|random>\n");
		printf ("%% no lladdr\n");
		return(0);
	}

	if ((lladdr = get_hwdaddr(ifname)) == NULL) {
		printf("%% Failed to retrieve current link level address\n");
		return(1);
	}

	/*
	 * the expectation here is that, on first run of the lladdr command,
	 * after system boot, /var/run/lladdr.%s will not exist and so we
	 * will ALWAYS create it with the interface's current lladdr.
	 * this file is used if 'no lladdr' is ever specified, that way
	 * we know exactly what address to revert back to.  also, conf_lladdr
	 * always knows about the default address this way.  finally, because
	 * the output to /var/run/lladdr.%s is generated from get_hwdaddr,
	 * and the comparisons will be with new data generated from get_hwdaddr
	 * it will always have the same case and format for easy comparison.
	 */
	snprintf(llfn, sizeof(llfn), "%s.%s", LLPREFIX, ifname);
	if ((llfile = fopen(llfn, "r")) == NULL) {
		/* llfn not around? create it */
		if (set && ((llfile = fopen(llfn, "w")) != NULL)) {
			fprintf(llfile, "%s", lladdr);
			fclose(llfile);
		} else if (set) {
			printf("%% Failed to open %s for writing: %s\n", llfn,
			    strerror(errno));
			return(1);
		} else {
			switch(errno) {
			case ENOENT:
				printf("%% No saved lladdr to revert back\n");
				break;
			default:
				printf("%% Failed to read %s: %s\n", llfn,
				    strerror(errno));
			}
			return(1);
		}
	} else {
		fgets(llorig, sizeof(llorig), llfile);
		fclose(llfile);
		if (!set && unlink(llfn) != 0)
			printf("%% Failed to remove %s: %s\n", llfn,
			    strerror(errno));
	}

	/* At this point, llorig will always represent the booted lladdr */

	if (set && isprefix(argv[1], "random")) {
		struct ether_addr eabuf;

		arc4random_buf(&eabuf, sizeof eabuf);
		eabuf.ether_addr_octet[0] &= 0xfc;
		addr = &eabuf;
	} else {
		addr = ether_aton(set ? argv[1] : llorig);
		if (addr == NULL) {
			if (set) {
				printf("%% MAC addresses must be six hexadecimal "
				    "fields, up to two digits each,\n");
				printf("%% separated with colons (1:23:45:ab:cd:ef)\n");
				return(1);
			} else {
				printf("%% %s corrupted, unable to retrieve original "
				    "lladdr\n", llfn);
				return(1);
			}
		} 
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	ifr.ifr_addr.sa_family = AF_LINK;
	bcopy(addr, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
	if(ioctl(ifs, SIOCSIFLLADDR, (caddr_t)&ifr) < 0) {
		switch(errno) {
		case EINVAL:
			printf("%% Requested link level address denied\n");
			break;
		default:
			printf("%% intlladdr: SIOCSIFLLADDR: %s\n",
			    strerror(errno));
		}
		return(1);
	}

	return(0);
}

int
intrdomain(char *ifname, int ifs, int argc, char **argv)
{
	int set, rdomain;
	const char *errmsg = NULL;
	struct ifreq ifr;

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	argv++;
	argc--;

	if (set && argc < 1) {
		printf("%% rdomain <routing domain number>\n");
		printf("%% no rdomain\n");
		return(0);
	}

	rdomain = strtonum(argv[0], 0, RT_TABLEID_MAX, &errmsg);
	if (errmsg) {
		printf("%% Routing domain %s invalid (%s)\n", argv[0], errmsg);
		return(0);
	}

	if (set)
		ifr.ifr_rdomainid = rdomain;
	else
		ifr.ifr_rdomainid = 0;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFRDOMAIN, &ifr) < 0)
		printf("%% intrdomain: SIOCSIFRDOMAIN: %s\n", strerror(errno));

	return(0);
}

int
intdesc(char *ifname, int ifs, int argc, char **argv)
{
	int set;
	char desc[IFDESCRSIZE];
	struct ifreq ifr;

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	argv++;
	argc--;

	if (set && argc < 1) {
		printf("%% description <text of description>\n");
		printf("%% no description\n");
		return(0);
	}

	argvtostring(argc, argv, desc, sizeof(desc));

	if (set)
		ifr.ifr_data = (caddr_t)&desc;
	else
		ifr.ifr_data = (caddr_t)"";
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFDESCR, &ifr) < 0)
		printf("%% intdesc: SIOCSIFDESCR: %s\n", strerror(errno));

	return(0);
}
