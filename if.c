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
#include "ip.h"
#include "bridge.h"
#include "stringlist.h"
#include "externs.h"

char *iftype(int int_type);
const char *get_linkstate(int, int);
void show_int_status(char *, int);
char *get_hwdaddr(char *ifname);
void pack_ifaliasreq(struct ifaliasreq *, ip_t *, struct in_addr *, char *);
void pack_in6aliasreq(struct in6_aliasreq *, ip_t *, struct in6_addr *, char *);
void ipv6ll_db_store(struct sockaddr_in6 *, struct sockaddr_in6 *, int, char *);
void printifhwfeatures(int, char *);
void intipusage(const char *, const char *);
int run_ipcp(char *, int, int);
void show_vnet_parent(int, char *);
void pwe3usage(void);
int show_vlan(int, int);

static struct ifmpwreq imrsave;
static char imrif[IFNAMSIZ];

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

void imr_init(char *ifname)
{
	if (strcmp(ifname, imrif) == 0)
			return;
	strlcpy (imrif, ifname, IFNAMSIZ);
	memset (&imrsave, 0, sizeof(imrsave));
}

const char *
get_linkstate(int mt, int link_state)
{
	const struct if_status_description if_status_descriptions[] =
		LINK_STATE_DESCRIPTIONS;
	const struct if_status_description *p;
	static char buf[8];

	for (p = if_status_descriptions; p->ifs_string != NULL; p++) {
		if (LINK_STATE_DESC_MATCH(p, mt, link_state))
			return (p->ifs_string);
	}
	snprintf(buf, sizeof(buf), "[#%d]", link_state);
	return buf;
}

void
show_int_status(char *ifname, int ifs)
{
	struct ifreq ifr;
	struct ifmediareq ifmr;
	int flags;
	struct if_data if_data;
	struct sockaddr_dl *sdl = NULL;
	const char *link_state_desc = NULL;
	struct ifaddrs *ifap, *ifa;
	uint64_t *media_list = NULL, seen_options = 0;
	const char *ifm_type = NULL, *ifm_subtype = NULL;
	char ifm_options_current[128];
	char ifm_options_active[128];

	ifm_options_current[0] = '\0';
	ifm_options_active[0] = '\0';

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	flags = get_ifflags(ifname, ifs);
	ifr.ifr_data = (caddr_t)&if_data;
	if (ioctl(ifs, SIOCGIFDATA, (caddr_t)&ifr) < 0) {
		printf("%% show_int_status: SIOCGIFDATA: %s\n",
		    strerror(errno));
		return;
	}
	if (ioctl(ifs, SIOCGIFRDOMAIN, (caddr_t)&ifr) == -1) {
		printf("%% show_int_status: SIOCGIFRDOMAIN: %s\n",
		    strerror(errno));
		return;
	}

	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));

	if (getifaddrs(&ifap) != 0) {
		printf("%% show_int_status: getifaddrs: %s\n",
		    strerror(errno));
		return;
	}
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_LINK &&
		    (strcmp(ifname, ifa->ifa_name) == 0)) {
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			link_state_desc = get_linkstate(sdl->sdl_type,
			    if_data.ifi_link_state);
			break;
		}
	}

	if (ioctl(ifs, SIOCGIFMEDIA, (caddr_t)&ifmr) != -1 &&
	    ifmr.ifm_count > 0) {
		media_list = calloc(ifmr.ifm_count, sizeof(*media_list));
		if (media_list == NULL) {
			printf("%% show_int_status: calloc: %s\n",
			    strerror(errno));
			return;
		}
		ifmr.ifm_ulist = media_list;
		if (ioctl(ifs, SIOCGIFMEDIA, (caddr_t)&ifmr) == -1) {
			printf("%% show_int_status: SIOCGIFMEDIA: %s\n",
			    strerror(errno));
			return;
		}
		if (link_state_desc == NULL)
			link_state_desc = get_ifm_linkstate_str(&ifmr);
	}

	/* Avoid displaying "unknown" for any non-physical interface. */
	if (link_state_desc == NULL || strcmp(link_state_desc, "unknown") == 0)
		link_state_desc = "-";

	get_ifm_options_str(ifm_options_current, sizeof(ifm_options_current),
	    ifmr.ifm_current, &seen_options);
	if (IFM_OPTIONS(ifmr.ifm_current) != IFM_OPTIONS(ifmr.ifm_active)) {
		get_ifm_options_str(ifm_options_active,
		    sizeof(ifm_options_active), ifmr.ifm_active, &seen_options);
	}

	ifm_type = get_ifm_type_str(ifmr.ifm_active);
	/* Avoid displaying "autoselect" for any non-physical interface. */
	if (IFM_SUBTYPE(ifmr.ifm_active) != IFM_AUTO)
		ifm_subtype = get_ifm_subtype_str(ifmr.ifm_active);


	printf("  %-7s %-7s %-15s %10u  %s%s%s%s%s%s%s\n", ifname,
	    (flags & IFF_UP) ? "up" : "down", link_state_desc,
	    ifr.ifr_rdomainid,
	    ifm_type ? ifm_type : "",
	    ifm_type ? " " : "",
	    ifm_subtype ? ifm_subtype : "",
	    ifm_subtype ? " " : "",
	    ifm_options_current,
	    ifm_options_current[0] != '\0' ? " " : "",
	    ifm_options_active[0] != '\0' ? ifm_options_active : "");

	free(media_list);
}

int
show_int(int argc, char **argv)
{
	struct ifaddrs *ifap, *ifa;
	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr, ifrdesc;
	struct if_data if_data;
	struct sockaddr_in *sin = NULL, *sinmask = NULL, *sindest;
	struct sockaddr_in6 *sin6 = NULL, *sin6mask = NULL, *sin6dest;
	struct timeval tv;

	short tmp;
	int ifs, br, flags, days, hours, mins, pntd;
	int ippntd = 0;
	int physrt, physttl;
	time_t c;
	char *type, *lladdr;
	char ifname[IFNAMSIZ];

	char tmp_str[512], tmp_str2[512], ifdescr[IFDESCRSIZE];

	memset(ifname, 0, sizeof(ifname));

	if (argc == 4) {
		/*
		 * Allow "interface-name interface-number" as some
		 * network switches do: interface em 0
		 */
		const char *errstr;
		strlcpy(ifname, argv[2], sizeof(ifname));
		strtonum(argv[3], 0, INT_MAX, &errstr);
		if (errstr) {
			printf("%% interface unit %s is %s\n", argv[3], errstr);
			return(1);
		}
		strlcat(ifname, argv[3], sizeof(ifname));
		printf("%% Interface name is %s not \"%s %s\"\n",
		    ifname, argv[2], argv[3]);
	} if (argc == 3)
		strlcpy(ifname, argv[2], sizeof(ifname));

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% show_int: %s\n", strerror(errno));
		return(1);
	}

	/*
	 * Show all interfaces when no ifname specified.
	 */
	if (ifname[0] == '\0') {
		if ((ifn_list = if_nameindex()) == NULL) {
			printf("%% show_int: if_nameindex failed\n");
			close(ifs);
			return 0;
		}
		for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
			char *args[] = { NULL, NULL, ifnp->if_name };

			show_int(3, args);
		}
		if_freenameindex(ifn_list);
		close(ifs);
		return(0);
	} else if (isprefix(ifname, "status")) {
		if ((ifn_list = if_nameindex()) == NULL) {
			printf("%% show_int: if_nameindex failed\n");
			close(ifs);
			return 0;
		}
		puts("% Name    Status  Link        Routing-Domain  Media");
		for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++)
			show_int_status(ifnp->if_name, ifs);
		if_freenameindex(ifn_list);
		close(ifs);
		return(0);
	} else if (!is_valid_ifname(ifname)) {
		printf("%% interface %s not found\n", ifname);
		close(ifs);
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
	if (ioctl(ifs, SIOCGIFDESCR, &ifrdesc) == 0 &&
	    strlen(ifrdesc.ifr_data))
		printf(" (%s)", ifrdesc.ifr_data);

	putchar('\n');

	printf("  %s is %s", br ? "Bridge" : "Interface",
	    flags & IFF_UP ? "up" : "down");

	if (if_data.ifi_lastchange.tv_sec) {
		gettimeofday(&tv, (struct timezone *)0);
		c = difftime(tv.tv_sec, if_data.ifi_lastchange.tv_sec);
		days = c / (24 * 60 * 60);
		c %= (24 * 60 * 60);
		hours = c / (60 * 60);
		c %= (60 * 60);
		mins = c / 60;
		c %= 60;
		printf(" (last change ");
		if (days)
			printf("%id ", days);
		printf("%02i:%02i:%02i)", hours, mins, (int)c);
	}

	printf(", protocol is %s", flags & IFF_RUNNING ? "up" : "down");
	printf("\n");

	type = iftype(if_data.ifi_type);

	printf("  Interface type %s", type);
	if (if_data.ifi_type != IFT_WIREGUARD) {
		if (flags & IFF_BROADCAST)
			printf(" (Broadcast)");
		else if (flags & IFF_POINTOPOINT)
			printf(" (PointToPoint)");
	}

	if ((lladdr = get_hwdaddr(ifname)) != NULL)
		printf(", hardware address %s", lladdr);
	printf("\n");

	show_wg(ifs, ifname);
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
		if (ifa->ifa_addr == NULL)
			continue;
		if (strncmp(ifname, ifa->ifa_name, IFNAMSIZ))
			continue;

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)ifa->ifa_addr;
			sinmask = (struct sockaddr_in *)ifa->ifa_netmask;
			if (sin->sin_addr.s_addr == INADDR_ANY)
				continue;
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			sin6mask = (struct sockaddr_in6 *)ifa->ifa_netmask;
			if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
				continue;
			in6_fillscopeid(sin6);
			break;
		default:
			continue;
		}
		
		if (!ippntd) 
			printf("  Internet address");

		printf("%s %s", ippntd ? "," : "", ifa->ifa_addr->sa_family
		    == AF_INET ? netname4(sin->sin_addr.s_addr, sinmask) :
		    netname6(sin6, sin6mask));

		ippntd = 1;

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			if (flags & IFF_POINTOPOINT) {
				sindest = (struct sockaddr_in *)
				    ifa->ifa_dstaddr;
				printf(" (Destination %s)",
				    routename4(sindest->sin_addr.s_addr));
			} else if (flags & IFF_BROADCAST) {
				sindest = (struct sockaddr_in *)
				    ifa->ifa_broadaddr;
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
					printf(" (Broadcast %s)",
					    inet_ntoa(sindest->sin_addr));
			}
			break;
		case AF_INET6:
			if (flags & IFF_POINTOPOINT) {
				sin6dest = (struct sockaddr_in6 *)
				    ifa->ifa_dstaddr;
				in6_fillscopeid(sin6dest);
				printf(" (Destination %s)",
				    routename6(sin6dest));
			}
			break;
		default:
			printf(" unknown");
			break;
		}
	}

	if (ippntd) {
		printf("\n");
	}
	freeifaddrs(ifap);

	if (!br) {
		if (phys_status(ifs, ifname, tmp_str, tmp_str2,
		    sizeof(tmp_str), sizeof(tmp_str2)) > 0) {
			printf("  Tunnel source %s destination %s",
			    tmp_str, tmp_str2);
			if (((physrt = get_physrtable(ifs, ifname)) != 0))
				printf(" destination rdomain %i", physrt);
			if (((physttl = get_physttl(ifs, ifname)) != 0))
				printf(" ttl %i", physttl);
			printf("\n");
		}
		carp_state(ifs, ifname);

		printf(" ");
		show_vnet_parent(ifs, ifname);
		if (ioctl(ifs, SIOCGIFRDOMAIN, (caddr_t)&ifr) != -1)
			printf(" rdomain %d,", ifr.ifr_rdomainid);

		/*
		 * Display MTU, line rate
		 */
		printf(" MTU %u bytes", if_data.ifi_mtu);
		if (ioctl(ifs, SIOCGIFHARDMTU, (caddr_t)&ifr) != -1) {
			if (ifr.ifr_hardmtu)
				printf(" (hardmtu %u)", ifr.ifr_hardmtu);
		}
		if (if_data.ifi_baudrate)
			printf(", Line Rate %qu %s",
			    MBPS(if_data.ifi_baudrate) ?
			    MBPS(if_data.ifi_baudrate) :
			    if_data.ifi_baudrate / 1000,
			    MBPS(if_data.ifi_baudrate) ? "Mbps" : "Kbps");

		printf("\n");
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
	    if_data.ifi_ipackets, if_data.ifi_ibytes, if_data.ifi_ierrors,
	    if_data.ifi_iqdrops);
	printf("  %qu packets output, %qu bytes, %qu errors, %qu unsupported\n",
	    if_data.ifi_opackets, if_data.ifi_obytes, if_data.ifi_oerrors,
	    if_data.ifi_noproto);
	if (if_data.ifi_ibytes && if_data.ifi_ipackets &&
	    (if_data.ifi_ibytes / if_data.ifi_ipackets) >= ETHERMIN) {
		/* < ETHERMIN means byte counter probably rolled over */
		printf("  %qu input", if_data.ifi_ibytes /
		    if_data.ifi_ipackets);
		pntd = 1;
	} else
		pntd = 0;
	if (if_data.ifi_obytes && if_data.ifi_opackets &&
	    (if_data.ifi_obytes / if_data.ifi_opackets) >= ETHERMIN) {
		/* < ETHERMIN means byte counter probably rolled over */
		printf("%s%qu output", pntd ? ", " : "  ",
		    if_data.ifi_obytes / if_data.ifi_opackets);
		pntd = 1;
	}
	if (pntd)
		printf(" (average bytes/packet)\n");

	switch(if_data.ifi_type) {
	/*
	 * These appear to be the only interface types to increase collision
	 * count in the OpenBSD 3.2 kernel.
	 */
	case IFT_ETHER:
	case IFT_SLIP:
	case IFT_PROPVIRTUAL:
	case IFT_IEEE80211:
		printf("  %qu collisions\n", if_data.ifi_collisions);
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
		printifhwfeatures(ifs, ifname);
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

int
show_autoconf(int argc, char **argv)
{
	struct if_nameindex *ifn_list, *ifnp;
	char *ifname = NULL;
	char outpath[PATH_MAX];
	int ifs = -1, fd = -1, nullfd = -1, ifxflags;
	int have_output = 0;

	if (argc == 3) {
		ifname = argv[2];
		if (!is_valid_ifname(ifname)) {
			printf("%% interface %s not found\n", ifname);
			return (1);
		}
	}

	nullfd = open("/dev/null", O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
	if (nullfd == -1) {
		printf("%% open /dev/null: %s\n", strerror(errno));
		return (1);
	}

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% socket: %s\n", strerror(errno));
		close(nullfd);
		return (1);
	}

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% if_nameindex: %s\n", strerror(errno));
		close(nullfd);
		close(ifs);
		return (1);
	}

	strlcpy(outpath, "/tmp/nsh-XXXXXX", sizeof(outpath));
	fd = mkstemp(outpath);
	if (fd == -1) {
		printf("%% mkstemp: %s\n", strerror(errno));
		close(nullfd);
		close(ifs);
		if_freenameindex(ifn_list);
		return (1);
	}

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		if (ifname && strcmp(ifname, ifnp->if_name) != 0)
			continue;

		ifxflags = get_ifxflags(ifnp->if_name, ifs);
#ifdef IFXF_AUTOCONF4		/* 6.6+ */
		if ((ifxflags & IFXF_AUTOCONF4) && dhcpleased_is_running()) {
			char *args[] = { DHCPLEASECTL, "-l",
			    ifnp->if_name, NULL };
			cmdargs_output(DHCPLEASECTL, args, fd, nullfd);
			have_output = 1;
		}
#endif
		if ((ifxflags & IFXF_AUTOCONF6) && slaacd_is_running()) {
			char *args[] = { SLAACCTL, "show", "interface",
			    ifnp->if_name, NULL };
			cmdargs_output(SLAACCTL, args, fd, nullfd);
			have_output = 1;
		}
	}

	if (have_output)
		more(outpath);

	unlink(outpath);
	if_freenameindex(ifn_list);
	close(nullfd);
	close(fd);
	close(ifs);
	return (0);
}

void
show_vnet_parent(int ifs, char *ifname)
{
	struct if_parent ifp;
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCGVNETID, (caddr_t)&ifr) != -1)
		printf(" vnetid %llu,", ifr.ifr_vnetid);
	bzero(&ifp, sizeof(ifp));
	strlcpy(ifp.ifp_name, ifname, sizeof(ifp.ifp_name));
	if (ioctl(ifs, SIOCGIFPARENT, (caddr_t)&ifp) != -1)
		printf(" parent %s,", ifp.ifp_parent);
}

/* lifted right from ifconfig.c */
#define HWFEATURESBITS							\
	"\024\1CSUM_IPv4\2CSUM_TCPv4\3CSUM_UDPv4"			\
	"\5VLAN_MTU\6VLAN_HWTAGGING\10CSUM_TCPv6"			\
	"\11CSUM_UDPv6\20WOL"

/* lifted right from ifconfig.c */
void
printifhwfeatures(int ifs, char *ifname)
{
	struct ifreq	ifr;
	struct if_data	ifrdat;

	bzero(&ifrdat, sizeof(ifrdat));
	ifr.ifr_data = (caddr_t)&ifrdat;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCGIFDATA, (caddr_t)&ifr) == -1) {
		printf("%% printifhwfeatures: SIOCGIFDATA: %s\n",
		    strerror(errno));
		return;
	}
	printf("  Hardware features:\n    ");
	bprintf(stdout, (u_int)ifrdat.ifi_capabilities, HWFEATURESBITS);
	putchar('\n');
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

	for (i = 0; i < nitems(iftypes); i++)
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
			value = if_data.ifi_mtu;
		else if (type == IFDATA_BAUDRATE)
			value = if_data.ifi_baudrate;
		else if (type == IFDATA_IFTYPE)
			value = if_data.ifi_type;
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
		printf("%% set_ifflags: SIOCSIFFLAGS: %s\n", strerror(errno));
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
		printf("%% get_ifxflags: SIOCGIFXFLAGS: %s\n",
		    strerror(errno));
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
		printf("%% set_ifxflags: SIOCSIFXFLAGS: %s\n",
		    strerror(errno));
	}

	return(0);
}

/* addaf, removeaf heavily derived from sbin/ifconfig/ifconfig.c */
int
addaf(char *ifname, int af, int ifs)
{
	struct if_afreq	ifar;

	strlcpy(ifar.ifar_name, ifname, sizeof(ifar.ifar_name));
	ifar.ifar_af = af;
	if (ioctl(ifs, SIOCIFAFATTACH, (caddr_t)&ifar) < 0) {
		printf("%% addaf: SIOCIFAFATTACH: %s\n",
		    strerror(errno));
		return(1);
	}
	return(0);
}

int
removeaf(char *ifname, int af, int ifs)
{
	struct if_afreq	ifar;

	strlcpy(ifar.ifar_name, ifname, sizeof(ifar.ifar_name));
	ifar.ifar_af = af;
	if (ioctl(ifs, SIOCIFAFDETACH, (caddr_t)&ifar) < 0) {
		printf("%% removeaf: SIOCIFAFDETACH: %s\n",
		    strerror(errno));
		return(1);
	}
	return(0);
}

int
check_daemon_control_socket(const char *sockname)
{
	int sock, error;
	struct sockaddr_un sun;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		printf("socket: %s\n", strerror(errno));
		return 0;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, sockname, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		printf("socket path too long: %s\n", sockname);
		return 0;
	}

	error = connect(sock, (struct sockaddr *)&sun, sizeof(sun));
	close(sock);

	return error ? 0 : 1;
}

int
dhcpleased_is_running(void)
{
	return check_daemon_control_socket(DHCPLEASED_SOCK);
}

int
slaacd_is_running(void)
{
	return check_daemon_control_socket(SLAACD_SOCK);
}

struct ghs intiphelp[] = {
	{ "<address>/<prefixlen>", "IP address parameter", CMPL0 NULL, 0 },
	{ "<address>/<netmask>", "IP address parameter", CMPL0 NULL, 0 },
	{ "autoconf", "Use automatic configuration", CMPL0 NULL, 0 },
	{ "dhcp", "Use DHCP", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs intip6help[] = {
	{ "<address>/<prefixlen>", "IPv6 address parameter", CMPL0 NULL, 0 },
	{ "autoconf", "Use stateless address autoconfiguration (SLAAC)", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};


void
intipusage(const char *cmdname, const char *msg)
{
	printf("%% %s <address>/<bits> %s%s%s\n", cmdname,
	    msg ? "[" : "", msg ? msg : "", msg ? "]" : "");
	printf("%% %s <address>/<netmask> %s%s%s\n", cmdname,
	    msg ? "[" : "", msg ? msg : "", msg ? "]" : "");
	printf("%% no %s [<address>[/prefix-len]]\n", cmdname);
	printf("%% no %s [<address>[/netmask]]\n", cmdname);
}

int
intip(char *ifname, int ifs, int argc, char **argv)
{
	int s, set, flags, argcmax;
	int argc0 = argc;
	char **argv0 = argv;
	char *msg, *cmdname;
	ip_t ip;
	/* ipv4 structures */
	struct in_addr in4dest;
	struct ifaliasreq ip4req;
	/* ipv6 structures */
	struct in6_addr in6dest;
	struct in6_aliasreq ip6req;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	/*
	 * We use this function for address and alias setup since they are
	 * the same thing.
	 */
	if (isprefix(argv[0], "address")) {
		cmdname = "address";
	} else if (isprefix(argv[0], "alias")) {
		cmdname = "alias";
	} else if (isprefix(argv[0], "ip")) {
		cmdname = "ip";
	} else if (isprefix(argv[0], "inet")) {
		cmdname = "inet";
	} else if (isprefix(argv[0], "inet6")) {
		cmdname = "inet6";
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

	if (argc == 0) {
		/*
		 * The inet and inet6 commands allow for removing all
		 * addresses in the corresponding address family.
		 */
		if (!set &&
		    (strcmp(cmdname, "inet") == 0 ||
		    strcmp(cmdname, "inet6") == 0)) {
			intaf(ifname, ifs, argc0, argv0);
			return(0);
		}

		/*
		 * The inet6 command allows for enabling IPv6 link-local.
		 */
		if (set && strcmp(cmdname, "inet6") == 0) {
			intaf(ifname, ifs, argc0, argv0);
			return(0);
		}
		
		intipusage(cmdname, msg);
		return(0);
	} else if (argc < 1 || argc > argcmax) {
		intipusage(cmdname, msg);
		return(0);
	}

	/* ignore 'address' keyword, don't print error */
	if (strcmp(cmdname, "ip") == 0 &&
	    (isprefix(argv[0], "address") && !isprefix(argv[0], "autoconf"))) {
		argc--;
		argv++;
	}

	/*
	 * Enable IPv4 DHCP with any of the following commands:
	 *   inet dhcp, ip dhcp, inet autoconf, ip autoconf
	 * Disable IPv4 DHCP if "no" is given for any of these commands.
	 */
	if (strcmp(cmdname, "inet6") != 0 &&
	    (isprefix(argv[0], "dhcp") || isprefix(argv[0], "autoconf"))) {
		if (dhcpleased_is_running()) {
			/*
			 * dhclient(8) has gone away as of OpenBSD 7.2+.
			 * dhcpleased(8) should always be running and will
			 * only take action once the autoconf4 flag is set.
			 */
			char *args[3] = { "no", "autoconf4", NULL };
			char *args_set[2] = { "autoconf4", NULL };
			char **argv_dhcp;
			int argc_dhcp;
			if (set) {
				argv_dhcp = args_set;
				argc_dhcp = nitems(args_set) - 1;
			} else {
				argv_dhcp = args;
				argc_dhcp = nitems(args) - 1;
			}
			return intxflags(ifname, ifs, argc_dhcp, argv_dhcp);
		} else {
			/*
			 * On OpenBSD 7.2, dhclient(8) is just a stub and will
			 * likewise set the autoconf4 flag for dhcpleased(8).
			 * On earlier releases, dhclient(8) will get a lease.
			 */
			char *args[] = { PKILL, "dhclient", ifname, NULL };
			char *args_set[] = { DHCLIENT, ifname, NULL };
			char leasefile[sizeof(LEASEPREFIX)+1+IFNAMSIZ];

			if (set)
				cmdargs(DHCLIENT, args_set);
			else {
				cmdargs(PKILL, args);
				snprintf(leasefile, sizeof(leasefile), "%s.%s",
				    LEASEPREFIX, ifname);
				rmtemp(leasefile);
			}
			return (0);
		}
	}

	/* Enable IPv6 SLAAC with "inet6 autoconf" and disable it with "no". */
	if (strcmp(cmdname, "inet6") == 0 && isprefix(argv[0], "autoconf")) {
		char *args[3] = { "no", "autoconf6", NULL };
		char *args_set[2] = { "autoconf6", NULL };
		char **argv_xflags;
		int argc_xflags;
		if (set) {
			argv_xflags = args_set;
			argc_xflags = nitems(args_set) - 1;
		} else {
			argv_xflags = args;
			argc_xflags = nitems(args) - 1;
		}
		return intxflags(ifname, ifs, argc_xflags, argv_xflags);
	}

	memset(&ip, 0, sizeof(ip));
	parse_ip_pfx(argv[0], NO_NETMASK, &ip);

	if (ip.family == 0)
		/* bad IP specified */
		return(0);

	/* The inet6 command is IPv6-only. */
	if (strcmp(cmdname, "inet6") == 0 && ip.family != AF_INET6) {
		printf("%% %s is not a valid IPv6 address\n", argv[0]);
		return(0);
	}

	if (set && !(flags & IFF_POINTOPOINT) && ip.bitlen == -1) {
		printf("%% Netmask not specified\n");
		return(0);
	}
	
	if (ip.bitlen == -1) {
		/*
		 * No netmask specified, set the field at 0.
		 * The kernel mostly ignores netmask for PTP interfaces,
		 * but won't allow anything less than a /128 for an IPv6
		 * PTP interface.
		 */
		if (!(flags & IFF_POINTOPOINT))
			ip.bitlen = 0;
		else if (ip.family == AF_INET)
			ip.bitlen = 32;
		else if (ip.family == AF_INET6)
			ip.bitlen = 128;
	}

	switch(ip.family) {
	case AF_INET:
		memset(&in4dest, 0, sizeof(in4dest));
		if (argc == 2 && !inet_pton(AF_INET, argv[1], &in4dest)) {
			printf("%% Invalid %s address\n", msg);
			return(0);
		}
		memset(&ip4req, 0, sizeof(ip4req));
		pack_ifaliasreq(&ip4req, &ip, &in4dest, ifname);
		/* do it */
		if (ioctl(ifs, set ? SIOCAIFADDR : SIOCDIFADDR, &ip4req) < 0)
			printf("%% intip: SIOC%sIFADDR: %s\n", set ? "A" : "D",
			    strerror(errno));
		break;
	case AF_INET6:
		memset(&in6dest, 0, sizeof(in6dest));
		if (argc == 2 && parse_ipv6(argv[1], &in6dest) != 0) {
			printf("%% Invalid destination address %s\n", argv[1]);
			return(0);
		}
		memset(&ip6req, 0, sizeof(ip6req));
		pack_in6aliasreq(&ip6req, &ip, &in6dest, ifname);
		/* get inet6 socket */
		s = socket(PF_INET6, SOCK_DGRAM, 0);
		if (s < 0) {
			printf("%% socket failed: %s\n", strerror(errno));
			return(0);
		}
		/* turn on inet6 */
		addaf(ifname, AF_INET6, ifs);
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

	/*
	 * Some interfaces, such as vport(4), will not come UP
	 * automatically when the first IP address is added.
	 */
	if (set) {
		flags = get_ifflags(ifname, ifs);
		if ((flags & IFF_UP) == 0)
			set_ifflags(ifname, ifs, flags | IFF_UP);
	}

	return(0);
}

int
intipcp(char *ifname, int ifs, int argc, char **argv)
{
	int set;

	/* Only pppoe(4) interfaces make use of sppp(4). */
	if (!is_pppoe(ifname, ifs)) {
		printf("%% %s: not a PPPoE interface\n", ifname);
		return 0;
	}

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;
	
	if (set)
		db_insert_flag_x("pppoeipaddrmode", ifname, 0, 0, "ipcp");
	else
		db_insert_flag_x("pppoeipaddrmode", ifname, 0, 0, "static");

	pppoe_ipcp(ifname, ifs, set);

	return 0;
}

int
run_ipcp(char *ifname, int ifs, int set)
{
	char *args[3] = { "no", "ipcp", NULL };
	char *args_set[2] = { "ipcp", NULL };
	char **argv_ipcp;
	int argc_ipcp;
	if (set) {
		argv_ipcp = args_set;
		argc_ipcp = nitems(args_set) - 1;
	} else {
		argv_ipcp = args;
		argc_ipcp = nitems(args) - 1;
	}

	return intipcp(ifname, ifs, argc_ipcp, argv_ipcp);
}

void
pack_ifaliasreq(struct ifaliasreq *ip4req, ip_t *ip,
    struct in_addr *in4dest, char *ifname)
{
	struct sockaddr_in *sin;
	in_addr_t mask;

	/* set IP address */
	sin = (struct sockaddr_in *)&ip4req->ifra_addr;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	memcpy(&sin->sin_addr.s_addr, &ip->addr.in.s_addr,
	    sizeof(in_addr_t));
	/* set netmask */
	sin = (struct sockaddr_in *)&ip4req->ifra_mask;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	mask = htonl(0xffffffff << (32 - ip->bitlen));
	memcpy(&sin->sin_addr.s_addr, &mask, sizeof(in_addr_t));
	/* set destination/broadcast address */
	if (in4dest->s_addr != 0) {
		sin = (struct sockaddr_in *)&ip4req->ifra_dstaddr;
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(struct sockaddr_in);
		memcpy(&sin->sin_addr.s_addr, &in4dest->s_addr,
		    sizeof(in_addr_t));
	}
	/* set interface name */
	strlcpy(ip4req->ifra_name, ifname, sizeof(ip4req->ifra_name));
}

void
pack_in6aliasreq(struct in6_aliasreq *ip6req, ip_t *ip,
    struct in6_addr *in6dest, char *ifname)
{
	struct sockaddr_in6 *sin6;

	/* set IP address */
	sin6 = (struct sockaddr_in6 *)&ip6req->ifra_addr;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	memcpy(&sin6->sin6_addr, &ip->addr.in6, sizeof(struct in6_addr));
	/* set prefixmask */
	sin6 = (struct sockaddr_in6 *)&ip6req->ifra_prefixmask;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	prefixlen(ip->bitlen, sin6);
	/* set infinite lifetime */
	ip6req->ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
	ip6req->ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	/* set destination address */
	if (!IN6_IS_ADDR_UNSPECIFIED(in6dest)) {
		sin6 = (struct sockaddr_in6 *)&ip6req->ifra_dstaddr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(struct sockaddr_in6);
		memcpy(&sin6->sin6_addr, in6dest, sizeof(struct in6_addr));
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
		db_delete_flag_x_ctl("ipv6linklocal", ifname, 0);
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

	/* convert to nopt() */
	if ((set && argc < 4) || (set && argc == 5) || (set &&
	    (argc == 4 || argc == 6) && (!isprefix(argv[0], "sender") ||
	    !isprefix(argv[2], "receiver") ||
	    (argc == 6 && !isprefix(argv[4], "version"))))) {
		printf("%% pflow sender <x.x.x.x> receiver <x.x.x.x:port> "
		    "[version 5|9|10]\n"
		    "%% no pflow [sender x.x.x.x receiver x.x.x.x:port "
		    "version 5|9|10]\n");
		return(0);
	}

	if (set) {
	        if (strchr(argv[3], ':') == NULL) {
			printf("%% Receiver has no port specified\n");
			return(0);
		}
	}

	bzero(&ifr, sizeof(ifr));     
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	bzero(&preq, sizeof(struct pflowreq));
	ifr.ifr_data = (caddr_t)&preq;

	preq.addrmask = PFLOW_MASK_SRCIP | PFLOW_MASK_DSTIP;
	if (set) {
		if (pflow_addr(argv[1], &preq.flowsrc) < 0)
			return(0);
		if (pflow_addr(argv[3], &preq.flowdst) < 0)
			return(0);
		if (argc == 6) {
			preq.version = strtonum(argv[5], 5, PFLOW_PROTO_MAX,
			    &errmsg);
			preq.addrmask |= PFLOW_MASK_VERSION;
	                if (errmsg) {
				printf("%% Invalid pflow version %s: %s\n",
				    argv[0], errmsg);
				return(0);
			}
                }
	}

	if (ioctl(ifs, SIOCSETPFLOW, (caddr_t)&ifr) == -1)
		printf("%% Unable to set pflow parameters: %s\n",
		    strerror(errno));

	return(0);
}

int
intpatch(char *ifname, int ifs, int argc, char **argv)
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

	if ((set && argc != 1) || (!set && argc > 1)) {
		printf("%% patch <pair interface>\n");
		printf("%% no patch [pair interface]\n");
		return 0;
	}

	bzero(&ifr, sizeof(ifr));

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (set) {
		if ((ifr.ifr_index = if_nametoindex(argv[0])) == 0) {
			printf("%% invalid interface %s\n", argv[0]);
			return 0;
		}
	} else {
		ifr.ifr_index = 0;
	}
	if (ioctl(ifs, SIOCSIFPAIR, &ifr) == -1)
		printf("%% intpatch: SIOCSIFPAIR: %s\n", strerror(errno));

	return 0;
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
			printf("%% Keepalive not available on %s\n", ifname);
		else
			printf("%% intkeepalive: SIOCSETKALIVE: %s\n",
			    strerror(errno));
	}

	return(0);
}

#define MPLSLABEL 1
#define TUNNELDOMAIN 2
#define TXPRIO 3
#define RXPRIO 4

static struct mplsc {
	char *name;
	char *descr;
	int type;
} mplscs[] = {
	{ "mplslabel",	"local mpls label", 	MPLSLABEL	},
	{ "tunneldomain","rdomain",		TUNNELDOMAIN	},
	{ "txprio",	"priority or packet|payload", 	TXPRIO	},
	{ "rxprio",	"priority or packet|payload|outer", RXPRIO },
	{ 0,		0,			0		}
};

/* from ifconfig.c */
int
intmpls(char *ifname, int ifs, int argc, char **argv)
{
	int set;
	unsigned long cmd;
	struct ifreq ifr;
	struct shim_hdr shim;
	struct mplsc *x;
	const char *errstr;

	bzero(&ifr, sizeof(ifr));

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	x=(struct mplsc *) genget(argv[0], (char **)mplscs, sizeof(struct mplsc));
	if (x == 0) {
		printf("%% Internal error - Invalid argument %s\n", argv[0]);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[0]);
		return 0;
	}

	argc--;
	argv++;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% %s <%s>\n", x->name, x->descr);
		printf("%% no %s [%s]\n", x->name, x->descr);
		return(0);
	}

	switch(x->type) {
	case MPLSLABEL:
		if (set) {
			bzero(&shim, sizeof(shim));
			ifr.ifr_data = (caddr_t)&shim;

			shim.shim_label = strtonum(argv[0], 0, MPLS_LABEL_MAX,
			    &errstr);
			if (errstr) {
				printf("%% Invalid MPLS Label %s: %s\n",
				    argv[0], errstr);
				return(0);
			}
			cmd = SIOCSETLABEL;
		} else {
			cmd = SIOCDELLABEL;
		}
		break;
	case TUNNELDOMAIN:
		if (set) {
			ifr.ifr_rdomainid =
			    strtonum(argv[0], 0, RT_TABLEID_MAX, &errstr);
			if (errstr) {
				printf("%% intmpls: rdomain %s: %s\n", argv[0],
				    errstr);
				return(0);
			}
		} else {
			ifr.ifr_rdomainid = 0;
		}
		cmd = SIOCSLIFPHYRTABLE;
		break;
	case TXPRIO:
		if (set) {
			if (isprefix(argv[0], "packet"))
				ifr.ifr_hdrprio = IF_HDRPRIO_PACKET;
			else if (isprefix(argv[0], "payload"))
				ifr.ifr_hdrprio = IF_HDRPRIO_PAYLOAD;
			else {
				ifr.ifr_hdrprio = strtonum(argv[0],
				    IF_HDRPRIO_MIN, IF_HDRPRIO_MAX, &errstr);
				if (errstr) {
					printf("%% intmpls: txprio %s: %s\n",
					    argv[0], errstr);
					return(0);
				}
			}
		} else {
			ifr.ifr_hdrprio = 0;
		}
		cmd = SIOCSTXHPRIO;
		break;
	case RXPRIO:
		if (set) {
			if (isprefix(argv[0], "packet"))
				ifr.ifr_hdrprio = IF_HDRPRIO_PACKET;
			else if (isprefix(argv[0], "payload"))
				ifr.ifr_hdrprio = IF_HDRPRIO_PAYLOAD;
			else if (isprefix(argv[0], "outer"))
				ifr.ifr_hdrprio = IF_HDRPRIO_OUTER;
			else {
				ifr.ifr_hdrprio = strtonum(argv[0],
				    IF_HDRPRIO_MIN, IF_HDRPRIO_MAX, &errstr);
				if (errstr) {
					printf("%% intmpls: txprio %s: %s\n",
					    argv[0], errstr);
					return(0);
				}
			}
		} else {
			ifr.ifr_hdrprio = 0;
		}
		cmd = SIOCSRXHPRIO;
		break;
	default:
		printf("%% intmpls: Internal error\n");
		return(0);
		break;
	}

	if (ioctl(ifs, cmd, (caddr_t)&ifr) < 0) {
		if (errno == ENOTTY)
			printf("%% MPLS not supported on %s\n", ifname);
		else
			printf("%% intmpls: ioctl: %s\n",
			    strerror(errno));
	}

	return (0);
}

void
pwe3usage(void)
{
	printf("%% pwe neighbor <neighbor label> <neighbor ip>...\n");
	printf("%% pwe cw...\n");
	printf("%% pwe fat...\n");
	printf("%% no pwe neighbor <neighbor label> <neighbor ip>...\n");
	printf("%% no pwe cw...\n");
	printf("%% no pwe fat...\n");
}

int
intpwe3(char *ifname, int ifs, int argc, char **argv)
{
	int set, ch, error;
	unsigned long cmd;
	caddr_t arg;
	const char *errstr;

	struct ifreq ifr;

	struct if_laddrreq req;
	struct addrinfo hints, *res;
	struct sockaddr_mpls *smpls = (struct sockaddr_mpls *)&req.dstaddr;

	bzero(&ifr, sizeof(ifr));
	bzero(&req, sizeof(req));
	bzero(&hints, sizeof(hints));

	/* command options for 'pwe' */
	static struct nopts pwe3opts[] = {
		{ "cw",		no_arg,		'c' },
		{ "fat",	no_arg,		'f' },
		{ "neighbor",	req_2arg,	'n' },
		{ NULL,		0,		0 }
	};

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	/* usage? */
	if (argc < 1) {
		pwe3usage();
		return(0);
	}

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	strlcpy(req.iflr_name, ifname, IFNAMSIZ);

	/* parse */
	noptind = 0;
	while ((ch = nopt(argc, argv, pwe3opts)) != -1)
		switch (ch) {
		case 'c':	/* cw */
			if (set) {
				cmd = SIOCSPWE3CTRLWORD;
				ifr.ifr_pwe3 = 1;
			} else {
				cmd = SIOCSPWE3CTRLWORD;
				ifr.ifr_pwe3 = 0;
			}
			arg = (caddr_t)&ifr;
			break;
		case 'f':	/* fat */
			if (set) {
				cmd = SIOCSPWE3FAT;
				ifr.ifr_pwe3 = 1;
			} else {
				cmd = SIOCSPWE3FAT;
				ifr.ifr_pwe3 = 0;
			}
			arg = (caddr_t)&ifr;
			break;
		case 'n':	/* neighbor */
			if (set) {
				hints.ai_family = AF_UNSPEC;
				hints.ai_socktype = SOCK_DGRAM;
				error = getaddrinfo(argv[noptind - 1], NULL, &hints, &res);
				if (error != 0) {
					printf("%% intpwe3: neighbor %s: %s\n",
					    argv[noptind - 1], gai_strerror(error));
					return (0);
				}
				smpls->smpls_len = sizeof(*smpls);
				smpls->smpls_family = AF_MPLS;
				smpls->smpls_label = strtonum(argv[noptind - 2],
				    (MPLS_LABEL_RESERVED_MAX + 1), MPLS_LABEL_MAX,
				    &errstr);
				if (errstr != NULL) {
					printf("%% intpwe3: invalid label %s: %s\n",
					    argv[noptind - 2], errstr);
					return (0);
				}
				if (res->ai_addrlen > sizeof(req.addr)) {
					printf("%% intpwe3: invalid address %s\n",
					    argv[noptind - 2]);
					return (0);
				}
				memcpy(&req.addr, res->ai_addr, res->ai_addrlen);
				freeaddrinfo(res);
				cmd = SIOCSPWE3NEIGHBOR;
			} else {
				cmd = SIOCDPWE3NEIGHBOR;
			}
			arg = (caddr_t)&req;
		break;
	}

	if (argc - noptind != 0) {
		/* leftover salmon */
		printf("%% %s", nopterr);
		if (argv[noptind])
			printf(": %s", argv[noptind]);
		printf("\n");
		pwe3usage();
		return(0);
	}

	if (ioctl(ifs, cmd, arg) < 0) {
		if (errno == ENOTTY)
			printf("%% PWE3 not supported on %s\n", ifname);
		else
			printf("%% intpwe3: ioctl: %s\n",
			    strerror(errno));
	}

	return (0);
}

int
intdhcrelay(char *ifname, int ifs, int argc, char **argv)
{
	char *cmd[] = { DHCRELAY, "-i", ifname, NULL, NULL };
	int set, alen;
	struct in_addr notused;

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

	if (argc) {
		if (inet_pton(AF_INET, argv[0], &notused)) {
			cmd[3] = argv[0];
		} else {
			printf("%% Not a valid IPv4 address: %s\n", argv[0]);
			return 0;
		}
	}

	if (set) {
		flag_x("dhcrelay", ifname, DB_X_ENABLE, argv[0]);
		cmdargs(DHCRELAY, cmd);
	} else {
		char server[24], argue[SIZE_CONF_TEMP];
		char *killcmd[] = { PKILL, "-xf", NULL, NULL };

		if ((alen = conf_dhcrelay(ifname, server, sizeof(server))) < 1)
		{
			if (alen == 0)
				printf("%% No relay configured for %s\n",
				    ifname);
			else
				printf("%% int_dhcrelay: conf_dhcrelay failed:"
				    " %d\n", alen);
			return(0);
		}

		/* bail if dhcrelay not relaying to specified dhcp server */
		if (argc && strcmp(server, argv[0]) != 0) {
			printf("%% Server expected: %s (not %s)\n", server,
			    argv[0]);
			return(0);
		}

		flag_x("dhcrelay", ifname, DB_X_REMOVE, NULL);

		/* setup argument list as one argument for pkill -xf */
		snprintf(argue, sizeof(argue), "%s %s %s %s", cmd[0], cmd[1],
		    cmd[2], server);
		killcmd[2] = argue;

		cmdargs(PKILL, killcmd);
	}
	return(0);
}

int
intmetric(char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	int set, max;
	unsigned long theioctl;
	char *type;
	const char *errmsg = NULL;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	if (isprefix(argv[0], "metric")) {
		type = "metric";
		max = INT_MAX;
		theioctl = SIOCSIFMETRIC;
	} else if (isprefix(argv[0], "priority")) {
		type = "priority";
		max = 15;
		theioctl = SIOCSIFPRIORITY;
	} else {
		printf("%% intmetric internal failure\n");
		return(0);
	}

	argc--;
	argv++;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% %s <%s>\n", type, type);
		printf("%% no %s [%s]\n", type, type);
		return(0);
	}

	if (set) {
		int num;

		num = strtonum(argv[0], 0, max, &errmsg);
		if (errmsg) {
			printf("%% Invalid %s %s: %s\n", type, argv[0],
			    errmsg);
			return(0);
		}
		ifr.ifr_metric = num;
	} else {
		ifr.ifr_metric = 0;
	}

	if (errmsg) {
		printf("%% Invalid %s %s: %s\n", type, argv[0], errmsg);
		return(0);
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, theioctl, (caddr_t)&ifr) < 0)
		printf("%% intmetric: SIOCSIF%s: %s\n", type,
		    strerror(errno));

	return(0);
}

int
intllprio(char *ifname, int ifs, int argc, char **argv)
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

	if ((!set && argc > 2) || (set && argc != 2)) {
		printf("%% llpriority <priority>\n");
		printf("%% no llpriority [priority]\n");
		return(0);
	}

	if (set) {
		int num;

		num = strtonum(argv[1], 0, 15, &errmsg);
		if (errmsg) {
			printf("%% Invalid llpriority %s: %s\n", argv[0],
			    errmsg);
			return(0);
		}
		ifr.ifr_llprio = num;
	} else {
		ifr.ifr_llprio = DEFAULT_LLPRIORITY;
	}

	if (errmsg) {
		printf("%% Invalid llpriority %s: %s\n", argv[0], errmsg);
		return(0);
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFLLPRIO, (caddr_t)&ifr) < 0)
		printf("%% intllprio: SIOCSIFLLPRIO: %s\n", strerror(errno));

	return(0);
}

int
intgroup(char *ifname, int ifs, int argc, char **argv)
{
	int set, i;
	struct ifgroupreq ifgr;

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
		if (isdigit((unsigned char)argv[i][strlen(argv[i]) - 1])) {
			printf("%% Group names may not end with a digit\n");
			return 0;
		}
		if (strlen(argv[i]) >= IFNAMSIZ) {
			printf("%% Group name too long (%s)\n", argv[i]);
			return 0;
		}
	}

	for (i = 0; i < argc; i++) {
		bzero(&ifgr, sizeof(ifgr));
		strlcpy(ifgr.ifgr_name, ifname, IFNAMSIZ);
		strlcpy(ifgr.ifgr_group, argv[i], IFNAMSIZ);

		if (ioctl(ifs, set ? SIOCAIFGROUP : SIOCDIFGROUP,
		    (caddr_t)&ifgr) == -1) {
			switch(errno) {
			case EEXIST:
				break;
			default:
				printf("%% intgroup: SIOC%sIFGROUP: %s\n",
				    set ? "S" : "D", strerror(errno));
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
		if (argc < 1) {
			printf("%% rtlabel <route-label>\n");
			printf("%% no rtlabel [route-label]\n");
			return 0;
		}
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
intparent(char *ifname, int ifs, int argc, char **argv)
{
	int set;
	struct if_parent ifp;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if ((set && argc != 1) || (!set && argc > 1)) {
                printf("%% parent <parent interface>\n");
                printf("%% no parent [parent interface]\n");
                return 0;
        }

	bzero(&ifp, sizeof(ifp));

	strlcpy(ifp.ifp_name, ifname, IFNAMSIZ);

	if (set && strlcpy(ifp.ifp_parent, argv[0], sizeof(ifp.ifp_parent)) >=
	    sizeof(ifp.ifp_parent)) {
		printf("%% parent name too long\n");
		return 0;
	}

	if (ioctl(ifs, set ? SIOCSIFPARENT : SIOCDIFPARENT, &ifp) == -1)
		printf("%% intparent: SIOC%sIFPARENT: %s\n", set ? "S" : "D",
		    strerror(errno));

	return 0;
}

int
intflags(char *ifname, int ifs, int argc, char **argv)
{
	int set, value, flags, iftype;

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
	} else if (isprefix(argv[0], "staticarp")) {
		/* staticarp */
		value = IFF_STATICARP;
	} else {
		printf("%% intflags: Internal error\n");
		return(0);
	}

	/*
	 * wg(4) sets IFF_NOARP by default and this should not be changed.
	 * The kernel doesn't prevent this flag from being cleared (as of 7.2).
	 */
	iftype = get_ifdata(ifname, IFDATA_IFTYPE);
	if (iftype == IFT_WIREGUARD &&
	    (value == -IFF_NOARP || value == IFF_STATICARP)) {
		printf("%% wireguard interfaces do not support ARP\n");
		return (0);
	}

	flags = get_ifflags(ifname, ifs);
	/*
	 * If static ARP is requested while ARP is disabled entirely then
	 * re-enable ARP to send responses to requests for our own address.
	 * A configuration with both STATICARP and NOARP set amounts to NOARP.
	 */
	if (value == IFF_STATICARP && (flags & IFF_NOARP))
		flags &= ~IFF_NOARP;
	/* Likewise, disable STATICARP if ARP is being disabled entirely. */
	if (value == -IFF_NOARP && (flags & IFF_STATICARP))
		flags &= ~IFF_STATICARP;

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
intaf(char *ifname, int ifs, int argc, char **argv)
{
	int set;

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	if (argc > 1) {
		printf("%% Invalid argument\n");
		return(1);
	}

	/* Do not use isprefix() here because it would always be ambiguous. */
	if (strcmp(argv[0], "inet6") == 0) {
		if (set)
			addaf(ifname, AF_INET6, ifs);
		else
			removeaf(ifname, AF_INET6, ifs);
	} else if (strcmp(argv[0], "inet") == 0) {
		if (set)
			addaf(ifname, AF_INET, ifs);
		else
			removeaf(ifname, AF_INET, ifs);
	} else {
		printf("%% intaf: unknown address family %s\n", argv[0]);
	}
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
#ifdef IFXF_INET6_NOPRIVACY	/* pre-6.9 */
		value = -IFXF_INET6_NOPRIVACY;
#endif
#ifdef IFXF_AUTOCONF6TEMP	/* 6.9+ */
		value = IFXF_AUTOCONF6TEMP;
	} else if (isprefix(argv[0], "temporary")) {
		value = IFXF_AUTOCONF6TEMP;
#endif
#ifdef IFXF_MONITOR		/* 6.9+ */
	} else if (isprefix(argv[0], "monitor")) {
		value = IFXF_MONITOR;
#endif
#ifdef IFXF_AUTOCONF4		/* 6.6+ */
	} else if (isprefix(argv[0], "autoconf4")) {
		/* Have "autoconf4" on pppoe(4) do the right thing. */
		if (is_pppoe(ifname, ifs))
			return run_ipcp(ifname, ifs, set);

		value = IFXF_AUTOCONF4;
#endif
	} else if (isprefix(argv[0], "autoconf6")) {
		value = IFXF_AUTOCONF6;
	} else if (isprefix(argv[0], "mpls")) {
		value = IFXF_MPLS;
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

	if (argc == 1) {
		power.i_maxsleep = strtonum(argv[0], 0, 1000, &errmsg);
		if (errmsg) {
			printf("%% Power save invalid %s: %s", argv[0],
			    errmsg);
			return(0);
		}
	} else {
		power.i_maxsleep = DEFAULT_POWERSAVE;
	}
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
	StringList *hwdaddr;
	char *lladdr, llorig[sizeof("00:00:00:00:00:00") + 1];
	struct ether_addr *addr;
	struct ifreq ifr;
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

	hwdaddr = sl_init();
	if (db_select_flag_x_ctl(hwdaddr, "lladdr", ifname) < 0) {
		printf("%% database failure select flag x ctl\n");
		sl_free(hwdaddr, 1);
		return(1);
	}
	if (hwdaddr->sl_cur > 0) {
		strlcpy(llorig, hwdaddr->sl_str[0], sizeof(llorig));
		if (!set && db_delete_flag_x_ctl("lladdr", ifname, 0) < 0) {
				printf("%% database delete failure\n");
				sl_free(hwdaddr, 1);
				return(1);
		}
	} else {
		strlcpy(llorig, lladdr, sizeof(llorig));
		if (set && db_insert_flag_x("lladdr", ifname, 0, DB_X_ENABLE,
		    llorig) < 0) {
			printf("%% database delete failure\n");
			sl_free(hwdaddr, 1);
			return(1);
		}
		if (!set) {
			printf("%% No stored lladdr to reinstate\n");
			sl_free(hwdaddr, 1);
			return(1);
		}
	}
	sl_free(hwdaddr, 1);

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
				printf("%% MAC addresses are six hexadecimal "
				    "fields, up to two digits each,\n"
				    " %% separated with colons"
				    " (1:23:45:ab:cd:ef)\n");
				return(1);
			} else {
				printf("%% database corrupted, unable to "
				    " retrieve original lladdr\n");
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

int
intvnetflowid(char *ifname, int ifs, int argc, char **argv)
{
	int set;
	struct ifreq ifr;

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

 	argv++;
	argc--;

	if (set && argc != 0) {
		printf("%% vnetflowid\n");
		printf("%% no vnetlowid\n");
		return(0);
	}

	if (set)
		ifr.ifr_vnetid = 1;
	else
		ifr.ifr_vnetid = 0;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSVNETFLOWID, &ifr) < 0)
		printf("%% intvnetflowid: SIOCSVNETFLOWID: %s\n", strerror(errno));

	return(0);
}

int
show_vlan(int start_vnetid, int end_vnetid)
{
	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr;
	struct if_parent ifp;
	int ifs, vnetid, flags, bridx;
	const char *parent, *description, *bridgename;
	char ifdescr[IFDESCRSIZE];
	char vnetid_str[5];
	int found_vnetid = 0, header_shown = 0;
	char ifix_buf[IFNAMSIZ];

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% show_vlan: %s\n", strerror(errno));
		return 0;
	}

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% show_vlan: if_nameindex failed\n");
		close(ifs);
		return 0;
	}

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		if (!isprefix("vlan", ifnp->if_name) &&
		    !isprefix("svlan", ifnp->if_name))
			continue;

		memset(&ifr, 0, sizeof(ifr));
		if (strlcpy(ifr.ifr_name, ifnp->if_name,
		    sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
			printf("%% %s: interface name is too long\n",
			   ifnp->if_name);
			continue;
		}

		vnetid = -1;
		if (ioctl(ifs, SIOCGVNETID, &ifr) == -1) {
			if (errno != EADDRNOTAVAIL) {
				printf("%% %s: SIOCGVNETID: %s\n",
				   ifnp->if_name, strerror(errno));
				continue;
			}
		} else if (ifr.ifr_vnetid >= 0)
			vnetid = ifr.ifr_vnetid;

		if (start_vnetid != -1) {
			if (end_vnetid != -1) {
				if (vnetid < start_vnetid)
					continue;
			} else if (vnetid != start_vnetid)
				continue;
		}
		if (end_vnetid != -1 && vnetid > end_vnetid)
			continue;
		found_vnetid = 1;

		if (!header_shown) {
			puts("% Interface  Tag   Status  Type     "
			    "Parent  Bridge   Description");
			header_shown = 1;
		}

		memset(&ifp, 0, sizeof(ifp));
		if (strlcpy(ifp.ifp_name, ifnp->if_name,
		    sizeof(ifp.ifp_name)) >= sizeof(ifp.ifp_name)) {
			printf("%% %s: interface name is too long\n",
			   ifnp->if_name);
			continue;
		}
		parent = "-";
		if (ioctl(ifs, SIOCGIFPARENT, &ifp) == -1) {
			if (errno != EADDRNOTAVAIL) {
				printf("%% %s: SIOCGIFPARENT: %s\n",
				   ifnp->if_name, strerror(errno));
				continue;
			}
		} else
			parent = ifp.ifp_parent;

		flags = get_ifflags(ifnp->if_name, ifs);

		memset(ifdescr, 0, sizeof(ifdescr));
		ifr.ifr_data = (caddr_t)&ifdescr;
		if (ioctl(ifs, SIOCGIFDESCR, &ifr) == 0)
			description = ifr.ifr_data;
		else
			description = "";

		if (vnetid == -1)
			strlcpy(vnetid_str, "-", sizeof(vnetid_str));
		else
			snprintf(vnetid_str, sizeof(vnetid_str), "%d", vnetid);

		bridx = bridge_member_search(ifs, ifnp->if_name);
		if (bridx)
			bridgename = if_indextoname(bridx, ifix_buf);
		else
			bridgename = "-";

		printf("  %-10s %-5s %-7s %-8s %-7s %-8s %s\n", ifnp->if_name,
		    vnetid_str, (flags & IFF_UP) ? "up" : "down",
		    isprefix("vlan", ifnp->if_name) ? "802.1Q" : "802.1ad",
		    parent, bridgename, description);
	}

	if (!found_vnetid) {
		if (end_vnetid == -1)
			printf("%% no VLAN with tag %d configured\n",
			    start_vnetid);
		else
			printf("%% no VLANs with tag between %d and %d "
			    "configured\n", start_vnetid, end_vnetid);
	}

	if_freenameindex(ifn_list);
	close(ifs);
	return 0;
}

int
show_vlans(int argc, char **argv)
{
	long long start_vnetid = -1, end_vnetid = -1;
	const char *errstr;

	switch (argc) {
	case 2:
		show_vlan(-1, -1);
		break;
	case 3:
		start_vnetid = strtonum(argv[2], EVL_VLID_NULL,
		    EVL_VLID_MAX, &errstr);
		if (errstr) {
			printf("%% VLAN tag %s is %s\n", argv[2], errstr);
			break;
		}
		show_vlan(start_vnetid, -1);
		break;
	case 4:
		start_vnetid = strtonum(argv[2], EVL_VLID_NULL,
		    EVL_VLID_MAX, &errstr);
		if (errstr) {
			printf("%% VLAN tag %s is %s\n", argv[2], errstr);
			break;
		}
		end_vnetid = strtonum(argv[3], EVL_VLID_NULL,
		    EVL_VLID_MAX, &errstr);
		if (errstr) {
			printf("%% VLAN tag %s is %s\n", argv[3], errstr);
			break;
		}
		if (start_vnetid >= end_vnetid) {
			printf("%% VLAN Start Tag must be smaller "
			    "than VLAN End Tag\n");
			break;
		}
		show_vlan(start_vnetid, end_vnetid);
		break;
	}
	return 0;
}
