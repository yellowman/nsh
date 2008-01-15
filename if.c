/* $nsh: if.c,v 1.34 2008/01/15 07:34:34 chris Exp $ */
/*
 * Copyright (c) 2002-2007
 *      Chris Cappuccio.  All rights reserved.
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
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_vlan_var.h>
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

static const struct {
	char *name;
	u_int8_t type;
} iftypes[] = {
	/* OpenBSD-specific types */
	{ "Packet Filter Logging",	IFT_PFLOG },
	{ "Packet Filter State Synchronization", IFT_PFSYNC },
	{ "IPsec Loopback",		IFT_ENC },      
	{ "Generic Tunnel",		IFT_GIF },
	{ "IPv6-IPv4 TCP relay",	IFT_FAITH },
	{ "Ethernet Bridge",		IFT_BRIDGE },
	/* IANA-assigned types */
	{ "Token Ring",			IFT_ISO88025 },
	{ "ISO over IP",		IFT_EON },
	{ "XNS over IP",		IFT_NSIP },
	{ "X.25 to IMP",		IFT_X25DDN },
	{ "ATM Data Exchange Interface", IFT_ATMDXI },
	{ "ATM Logical",		IFT_ATMLOGICAL },
	{ "ATM Virtual",		IFT_ATMVIRTUAL },
	{ "ATM",			IFT_ATM },
	{ "Ethernet",			IFT_ETHER },
	{ "ARCNET",			IFT_ARCNET },
	{ "HDLC",			IFT_HDLC },
	{ "IEEE 802.1Q",		IFT_L2VLAN },
	{ "Virtual",			IFT_PROPVIRTUAL },
	{ "PPP",			IFT_PPP },
	{ "SLIP",			IFT_SLIP },
	{ "Loopback",			IFT_LOOP },
	{ "ISDN S",			IFT_ISDNS },
	{ "ISDN U",			IFT_ISDNU },
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
show_int(char *ifname)
{
	struct ifaddrs *ifap, *ifa;
	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr;
	struct if_data if_data;
	struct sockaddr_in sin, sin2, sin3;
	struct timeval tv;
	struct vlanreq vreq;

	short tmp;
	int ifs, br, flags, days, hours, mins, pntd;
	int ippntd = 0;
	time_t c;
	char *type, *lladdr;
	const char *carp;

	char tmp_str[512], tmp_str2[512];

	/*
	 * Show all interfaces when no ifname specified.
	 */
	if (ifname == 0) {
		if ((ifn_list = if_nameindex()) == NULL) {
			printf("%% show_int: if_nameindex failed\n");
			return 1;
		}
		for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
			show_int(ifnp->if_name);
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

	printf("%% %s\n", ifname);
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

		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;

		sin.sin_addr = ((struct sockaddr_in *)ifa->ifa_addr)->
		    sin_addr;
		sin2.sin_addr = ((struct sockaddr_in *)ifa->ifa_netmask)->
		    sin_addr;

		if (sin.sin_addr.s_addr == 0 || sin2.sin_addr.s_addr == 0)
			continue;

		if (!ippntd)
			printf("  Internet address");

		printf("%s %s", ippntd ? "," : "",
		    netname4(sin.sin_addr.s_addr, &sin2));

		ippntd = 1;

		if (flags & IFF_POINTOPOINT) {
			sin3.sin_addr = ((struct sockaddr_in *)
			ifa->ifa_dstaddr)->sin_addr;
			printf(" (Destination %s)", inet_ntoa(sin3.sin_addr));
		} else if (flags & IFF_BROADCAST) {
			sin3.sin_addr =
			    ((struct sockaddr_in *)ifa->ifa_broadaddr)->
			    sin_addr;
			/*
			 * no reason to show the broadcast addr
			 * if it is standard (this should always
			 * be true unless someone has messed up their
			 * network or they are playing around...)
			 */
			if (ntohl(sin3.sin_addr.s_addr) !=
			    in4_brdaddr(sin.sin_addr.s_addr,
			    sin2.sin_addr.s_addr))
				printf(" (Broadcast %s)",
				    inet_ntoa(sin3.sin_addr));
		}
	}

	if (ippntd) {
		ippntd = 0;
		printf("\n");
	}
	freeifaddrs(ifap);

	if (!br) {
		if (phys_status(ifs, ifname, tmp_str, tmp_str2, sizeof(tmp_str),
		    sizeof(tmp_str2)) > 0)
			printf("  Tunnel source %s destination %s\n",
			    tmp_str, tmp_str2);
		if ((carp = carp_state(ifs, ifname)) != NULL)
			printf("  CARP state %s\n", carp);
		/*
		 * Display MTU, line rate, and ALTQ token rate info
		 * (if available)
		 */
		printf("  MTU %u bytes", if_mtu);
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

	if (get_nwinfo(ifname, tmp_str, sizeof(tmp_str), NWID) != NULL) {
		printf("  SSID %s", tmp_str);
		if(get_nwinfo(ifname, tmp_str, sizeof(tmp_str), NWKEY) != NULL)
			printf(", key %s", tmp_str);
		if ((tmp = get_nwinfo(ifname, tmp_str, sizeof(tmp_str),
		    POWERSAVE) != NULL))
			printf(", powersaving (%s ms)\n", tmp_str);
		printf("\n");
		if (is_wavelan(ifs, ifname)) {
			wi_dumpstats(ifname);
			if (wi_porttype(ifname) == WI_PORT_HOSTAP)
				wi_dumpstations(ifname);
			else {
				printf("  Q/S/N: ");
				wi_printlevels(ifname);
				printf("\n");
			}
		}
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
intip(char *ifname, int ifs, int argc, char **argv)
{
	int set, alias, flags, argcmax;
	ip_t ip;
	struct in_addr destbcast;
	struct ifaliasreq addreq, ridreq;
	struct sockaddr_in *sin;
	char  *msg, *cmdname;

	memset(&addreq, 0, sizeof(addreq));
	memset(&ridreq, 0, sizeof(ridreq));

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
	if (CMP_ARG(argv[0], "a")) {
		alias = 1;
		cmdname = "alias";
	} else if (CMP_ARG(argv[0], "i")) {
		alias = 0;
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

	if (CMP_ARG(argv[0], "d")) {
		char *args[] = { PKILL, "dhclient", ifname, '\0' };
		char leasefile[sizeof(LEASEPREFIX)+1+IFNAMSIZ];

		if (set)
			cmdarg(DHCLIENT, ifname);
		else {
			cmdargs(PKILL, args);
			snprintf(leasefile, sizeof(leasefile), "%s.%s",
			    LEASEPREFIX, ifname);
			rmtemp(leasefile);
		}
		return(0);
	}

	ip = parse_ip(argv[0], NO_NETMASK);

	if (ip.family == 0)
		/* bad IP specified */
		return(0);

	if (ip.bitlen == -1) {
		printf("%% Netmask not specified\n");
		return(0);
	}
	
	if (argc == 2)
		if (!inet_aton(argv[1], &destbcast)) {
			printf("%% Invalid %s address\n", msg);
			return(0);
		}
	
	strlcpy(addreq.ifra_name, ifname, sizeof(addreq.ifra_name));
	strlcpy(ridreq.ifra_name, ifname, sizeof(ridreq.ifra_name));

	if (!set) {
		sin = (struct sockaddr_in *)&ridreq.ifra_addr;
		sin->sin_len = sizeof(ridreq.ifra_addr);
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ip.addr.sin.s_addr;
	}

	if (!alias || !set) {
		/*
		 * Here we remove the top IP on the interface before we
		 * might add another one, or we delete the specified IP.
		 */
		if (ioctl(ifs, SIOCDIFADDR, &ridreq) < 0)
			if (!set)
				printf("%% intip: SIOCDIFADDR: %s\n",
				    strerror(errno));
	}

	if (set) {
		sin = (struct sockaddr_in *)&addreq.ifra_addr;
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(addreq.ifra_addr);
		sin->sin_addr.s_addr = ip.addr.sin.s_addr;
		sin = (struct sockaddr_in *)&addreq.ifra_mask;
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(addreq.ifra_mask);
		sin->sin_addr.s_addr = htonl(0xffffffff << (32 - ip.bitlen));
		if (argc == 2) {
			sin = (struct sockaddr_in *)&addreq.ifra_dstaddr;
			sin->sin_family = AF_INET;
			sin->sin_len = sizeof(addreq.ifra_dstaddr);
			sin->sin_addr.s_addr = destbcast.s_addr;
		}
		if (ioctl(ifs, SIOCAIFADDR, &addreq) < 0)
			printf("%% intip: SIOCAIFADDR: %s\n", strerror(errno));
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
	struct vlanreq vreq, preq;
	int set;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if ((set && (argc < 3 || argc > 5)) || (!set && argc > 5) ||
	    argc == 4 ||
	    (argc > 3 && !CMP_ARG(argv[1], "pa")) ||
	    (argc > 5 && !CMP_ARG(argv[3], "pr"))) {
		printf("%% vlan <tag> parent <parent interface> [priority <priority>]\n");
		printf("%% no vlan [tag] [parent <parent interface>] [priority <priority>]\n");
		return 0;
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	bzero(&vreq, sizeof(vreq));
	bzero(&preq, sizeof(preq));

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
		if (argc == 5) {
			preq.vlr_tag = strtonum(argv[4], 0, 7, &errmsg);
			if (errmsg) {
				printf("%% Invalid vlan priority %s: %s\n",
				    argv[4], errmsg);
				return 0;
			}
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

	ifr.ifr_data = (caddr_t)&preq;
	if (ioctl(ifs, SIOCSETVLANPRIO, (caddr_t)&ifr) == -1)
		printf("%% intvlan: SIOCSETVLANPRIO: %s\n", strerror(errno));

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
				printf("%% Group already applied to"
				    " interface (%s)\n", argv[i]);
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

	if (CMP_ARG(argv[0], "d")) {
		/* debug */
		value = IFF_DEBUG;
	} else if (CMP_ARG(argv[0], "s")) {
		/* shutdown */
		value = -IFF_UP;
	} else if (CMP_ARG(argv[0], "a")) {
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
		printf ("%% lladdr <link level address>\n");
		printf ("%% no lladdr\n");
		return(1);
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

	addr = ether_aton(set ? argv[1] : llorig); /* XXX Non-ethernet type ? */
	if(addr == NULL) {		/* XXX Non-ethernet... */
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

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;	/* XXX */
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
intdesc(char *ifname, int ifs, int argc, char **argv)
{
	int set, i;
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

	for (i = 0; (set && i < argc); i++) {
		snprintf(desc, sizeof(desc), "%s%s%s", i == 0 ? "" : desc,
		    i != 0 ? " " : "", argv[i]);
	}

	if (set)
		ifr.ifr_data = (caddr_t)&desc;
	else
		ifr.ifr_data = (caddr_t)"";
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFDESCR, &ifr) < 0)
		printf("%% intdesc: SIOCSIFDESCR: %s\n", strerror(errno));

	return(0);
}
