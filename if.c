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
#include "ip.h"
#include "bridge.h"
#include "stringlist.h"
#include "externs.h"
#include "ctl.h"
#include "settings.h"
#include "facts.h"
#include "showfacts.h"

char *iftype(int int_type);
const char *get_linkstate(int, int);
char *get_hwdaddr(char *ifname);
void pack_ifaliasreq(struct ifaliasreq *, ip_t *, struct in_addr *, char *);
void pack_in6aliasreq(struct in6_aliasreq *, ip_t *, struct in6_addr *, char *);
void ipv6ll_db_store(struct sockaddr_in6 *, struct sockaddr_in6 *, int, char *);
void intipusage(const char *, const char *);
int run_ipcp(char *, int, int);
void pwe3usage(void);
int show_vlan(int, int);

/* lifted right from ifconfig.c */
#define HWFEATURESBITS							\
	"\024\1CSUM_IPv4\2CSUM_TCPv4\3CSUM_UDPv4"			\
	"\5VLAN_MTU\6VLAN_HWTAGGING\10CSUM_TCPv6"			\
	"\11CSUM_UDPv6\20WOL"

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

void
imr_init(char *ifname)
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

/*
 * An interface, as show interface shows it: the records of what is
 * on it, its addresses, media and the rest, then its own, which ends
 * them. With detail, the media it supports, and a bridge's members
 * and the addresses it learned.
 */
int
if_facts(struct facts_out *o, char *ifname, int detail)
{
	struct facts_value	 v[IF_NFIELDS], av[ADDR_NFIELDS];
	struct ifreq		 ifr, ifrdesc;
	struct if_laddrreq	 req;
	struct if_parent	 ifp;
	struct if_data		 if_data;
	struct ifaddrs		*ifap = NULL, *ifa;
	struct sockaddr_dl	*sdl;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	static char		 ifdescr[IFDESCRSIZE], ssid[512], ps[512];
	static char		 parent[IFNAMSIZ];
	const char		*errstr;
	int			 ifs, flags, i, r = 0;

	if (!is_valid_ifname(ifname))
		return (facts_message(o, "%% interface %s not found\n",
		    ifname));
	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return (facts_message(o, "%% show_int: %s\n",
		    strerror(errno)));

	memset(v, 0, sizeof(v));
	facts_string(&v[IF_NAME], ifname);
	facts_u64(&v[IF_BRIDGE], is_bridge(ifs, ifname) ? 1 : 0);
	flags = get_ifflags(ifname, ifs);
	facts_u64(&v[IF_FLAGS], (u_int)flags);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&if_data;
	if (ioctl(ifs, SIOCGIFDATA, (caddr_t)&ifr) < 0) {
		r = facts_message(o, "%% show_int: SIOCGIFDATA: %s\n",
		    strerror(errno));
		close(ifs);
		return (r);
	}

	memset(&ifrdesc, 0, sizeof(ifrdesc));
	strlcpy(ifrdesc.ifr_name, ifname, sizeof(ifrdesc.ifr_name));
	ifdescr[0] = '\0';
	ifrdesc.ifr_data = (caddr_t)&ifdescr;
	if (ioctl(ifs, SIOCGIFDESCR, &ifrdesc) == 0 && strlen(ifdescr))
		facts_string(&v[IF_DESCR], ifdescr);

	if (if_data.ifi_lastchange.tv_sec)
		facts_time(&v[IF_LASTCHANGE], if_data.ifi_lastchange.tv_sec,
		    if_data.ifi_lastchange.tv_usec * 1000);
	facts_u64(&v[IF_TYPE], if_data.ifi_type);
	facts_u64(&v[IF_MTU], if_data.ifi_mtu);
	facts_u64(&v[IF_BAUDRATE], if_data.ifi_baudrate);
	facts_u64(&v[IF_IPACKETS], if_data.ifi_ipackets);
	facts_u64(&v[IF_IBYTES], if_data.ifi_ibytes);
	facts_u64(&v[IF_IERRORS], if_data.ifi_ierrors);
	facts_u64(&v[IF_IQDROPS], if_data.ifi_iqdrops);
	facts_u64(&v[IF_OPACKETS], if_data.ifi_opackets);
	facts_u64(&v[IF_OBYTES], if_data.ifi_obytes);
	facts_u64(&v[IF_OERRORS], if_data.ifi_oerrors);
	facts_u64(&v[IF_NOPROTO], if_data.ifi_noproto);
	facts_u64(&v[IF_COLLISIONS], if_data.ifi_collisions);
	facts_u64(&v[IF_CAPABILITIES], (u_int)if_data.ifi_capabilities);

	if (ioctl(ifs, SIOCGIFRDOMAIN, (caddr_t)&ifr) != -1)
		facts_u64(&v[IF_RDOMAIN], ifr.ifr_rdomainid);
	if (ioctl(ifs, SIOCGIFHARDMTU, (caddr_t)&ifr) != -1 &&
	    ifr.ifr_hardmtu)
		facts_u64(&v[IF_HARDMTU], ifr.ifr_hardmtu);

	wg_facts(o, ifs, ifname, v);
	umb_facts(o, ifs, ifname);
	trunk_facts(o, ifs, ifname, v);
	media_facts(o, ifs, ifname, v, detail);

	if (getifaddrs(&ifap) != 0) {
		r = facts_message(o, "%% show_int: getifaddrs failed: %s\n",
		    strerror(errno));
		close(ifs);
		return (r);
	}
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL ||
		    strncmp(ifname, ifa->ifa_name, IFNAMSIZ))
			continue;
		memset(av, 0, sizeof(av));
		switch (ifa->ifa_addr->sa_family) {
		case AF_LINK:
			/* the hardware address, and how the link is */
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (v[IF_LINK].type == FACT_NONE)
				facts_string(&v[IF_LINK], get_linkstate(
				    sdl->sdl_type, if_data.ifi_link_state));
			if (sdl->sdl_alen == ETHER_ADDR_LEN &&
			    (sdl->sdl_type == IFT_ETHER ||
			    sdl->sdl_type == IFT_IEEE80211) &&
			    v[IF_LLADDR].type == FACT_NONE)
				for (i = 0; i < ETHER_ADDR_LEN; i++)
					if (LLADDR(sdl)[i] != 0) {
						facts_sockaddr(&v[IF_LLADDR],
						    ifa->ifa_addr);
						break;
					}
			continue;
		case AF_INET:
			sin = (struct sockaddr_in *)ifa->ifa_addr;
			if (sin->sin_addr.s_addr == INADDR_ANY)
				continue;
			if (flags & IFF_POINTOPOINT)
				facts_sockaddr(&av[ADDR_DST], ifa->ifa_dstaddr);
			else if (flags & IFF_BROADCAST)
				facts_sockaddr(&av[ADDR_BRD],
				    ifa->ifa_broadaddr);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
				continue;
			if (flags & IFF_POINTOPOINT)
				facts_sockaddr(&av[ADDR_DST], ifa->ifa_dstaddr);
			break;
		default:
			continue;
		}
		facts_sockaddr(&av[ADDR_ADDRESS], ifa->ifa_addr);
		facts_sockaddr(&av[ADDR_MASK], ifa->ifa_netmask);
		facts_string(&av[ADDR_IF], ifname);
		if (facts_record(o, &kind_address, av) == -1)
			r = -1;
	}

	/* a tunnel's endpoints */
	memset(&req, 0, sizeof(req));
	strlcpy(req.iflr_name, ifname, sizeof(req.iflr_name));
	if (ioctl(ifs, SIOCGLIFPHYADDR, (caddr_t)&req) == 0) {
		facts_sockaddr(&v[IF_TUNSRC], (struct sockaddr *)&req.addr);
		facts_sockaddr(&v[IF_TUNDST], (struct sockaddr *)&req.dstaddr);
		if (req.dstaddr.ss_family == AF_INET)
			facts_u64(&v[IF_TUNPORT], ntohs(((struct sockaddr_in *)
			    &req.dstaddr)->sin_port));
		else if (req.dstaddr.ss_family == AF_INET6)
			facts_u64(&v[IF_TUNPORT], ntohs(((struct sockaddr_in6 *)
			    &req.dstaddr)->sin6_port));
		facts_u64(&v[IF_TUNRDOMAIN], get_physrtable(ifs, ifname));
		facts_u64(&v[IF_TUNTTL], get_physttl(ifs, ifname));
	}
	carp_facts(o, ifs, ifname, v);
	if (ioctl(ifs, SIOCGVNETID, (caddr_t)&ifr) != -1)
		facts_u64(&v[IF_VNETID], ifr.ifr_vnetid);
	memset(&ifp, 0, sizeof(ifp));
	strlcpy(ifp.ifp_name, ifname, sizeof(ifp.ifp_name));
	if (ioctl(ifs, SIOCGIFPARENT, (caddr_t)&ifp) != -1) {
		strlcpy(parent, ifp.ifp_parent, sizeof(parent));
		facts_string(&v[IF_PARENT], parent);
	}

	/* the key nsh.db keeps for a network is for no one here */
	if (get_nwinfo(ifname, ssid, sizeof(ssid), NWID) != 0) {
		facts_string(&v[IF_SSID], ssid);
		if (get_nwinfo(ifname, ps, sizeof(ps), POWERSAVE) != 0) {
			i = strtonum(ps, 0, INT_MAX, &errstr);
			if (errstr == NULL)
				facts_u64(&v[IF_POWERSAVE], i);
		}
	}

	if (detail && v[IF_BRIDGE].v.u)
		bridge_facts(o, ifs, ifname);

	freeifaddrs(ifap);
	close(ifs);
	if (facts_record(o, &kind_interface, v) == -1)
		r = -1;
	return (r);
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

/* show interface [status|name]: asked of nshd, and rendered here */
int
show_int(int argc, char **argv, ...)
{
	FILE		*outfile;
	va_list		 ap;
	char		 ifname[IFNAMSIZ];

	memset(ifname, 0, sizeof(ifname));

	va_start(ap, argv);
	outfile = va_arg(ap, FILE *);
	va_end(ap);

	if (argc == 4) {
		/*
		 * Allow "interface-name interface-number" as some
		 * network switches do: interface em 0
		 */
		const char *errstr;
		size_t len2 = strlen(argv[2]);
		strlcpy(ifname, argv[2], sizeof(ifname));
		strtonum(argv[3], 0, INT_MAX, &errstr);
		if (errstr) {
			printf("%% interface unit %s is %s\n", argv[3], errstr);
			return -1;
		}
		if (len2 > 0 && isdigit((unsigned char)(argv[2][len2 - 1]))) {
			printf("%% interface unit %s is redundant\n", argv[3]);
			return -1;
		}
		strlcat(ifname, argv[3], sizeof(ifname));
		printf("%% Interface name is %s not \"%s %s\"\n",
		    ifname, argv[2], argv[3]);
	} if (argc == 3)
		strlcpy(ifname, argv[2], sizeof(ifname));

	if (ifname[0] == '\0')
		return (facts_show(outfile, "interface%s",
		    verbose ? " detail" : ""));
	if (isprefix(ifname, "status"))
		return (facts_show(outfile, "interface status"));
	if (!is_valid_ifname(ifname)) {
		printf("%% interface %s not found\n", ifname);
		return -1;
	}
	return (facts_show(outfile, "interface %s%s", ifname,
	    verbose ? " detail" : ""));
}

/* show autoconf: asked of nshd, and rendered here */
int
show_autoconf(int argc, char **argv, ...)
{
	char *ifname = NULL;

	if (argc == 3) {
		ifname = argv[2];
		if (!is_valid_ifname(ifname)) {
			printf("%% interface %s not found\n", ifname);
			return -1;
		}
	}
	return (facts_show(stdout, "autoconf%s%s", ifname ? " " : "",
	    ifname ? ifname : ""));
}

/* what configured an IPv4 address */
#define NSH_IP_FLAG_DHCP	0x01
#define NSH_IP_FLAG_IPCP	0x02
#define NSH_IP_FLAG_STATIC	0x04

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

/* what configured ifa's IPv4 address; dhcpleased leases on autoconf4 */
static int
ip_source(struct ifaddrs *ifa, int s)
{
	struct in_addr	 addr, mask;

	addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
	mask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
	if ((get_ifxflags(ifa->ifa_name, s) & IFXF_AUTOCONF4) &&
	    dhcpleased_has_lease(ifa->ifa_name, &addr, &mask))
		return (NSH_IP_FLAG_DHCP);
	if (is_pppoe(ifa->ifa_name, s) &&
	    pppoe_show_ipaddrmode(ifa->ifa_name) == NSH_PPPOE_IPADDR_IPCP)
		return (NSH_IP_FLAG_IPCP);
	return (NSH_IP_FLAG_STATIC);
}

/*
 * Every address of af, or of each family, as facts; with source, what
 * configured each IPv4 one, as only root may learn
 */
int
ip_facts(struct facts_out *o, int af, int source)
{
	struct facts_value v[IP_NFIELDS];
	struct ifaddrs *ifap, *ifa;
	struct in6_ifreq ifr6;
	struct ifreq ifr;
	int s, r = 0;

	s = socket(PF_INET6, SOCK_DGRAM, 0);
	if (s < 0) {
		printf("%% show_ip: socket: %s\n", strerror(errno));
		return (-1);
	}

	if (getifaddrs(&ifap) != 0) {
		printf("%% show_ip: getifaddrs: %s\n", strerror(errno));
		close(s);
		return (-1);
	}

	for (ifa = ifap; ifa && r != -1; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != AF_INET &&
		    ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (af != AF_UNSPEC && ifa->ifa_addr->sa_family != af)
			continue;

		memset(v, 0, sizeof(v));
		facts_sockaddr(&v[IP_ADDRESS], ifa->ifa_addr);
		facts_sockaddr(&v[IP_MASK], ifa->ifa_netmask);
		facts_string(&v[IP_IF], ifa->ifa_name);
		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, ifa->ifa_name, sizeof(ifr.ifr_name));
		if (ioctl(s, SIOCGIFRDOMAIN, (caddr_t)&ifr) != -1)
			facts_u64(&v[IP_RDOMAIN], ifr.ifr_rdomainid);

		if (ifa->ifa_addr->sa_family == AF_INET) {
			if (source)
				facts_u64(&v[IP_SOURCE], ip_source(ifa, s));
		} else {
			memset(&ifr6, 0, sizeof(ifr6));
			strlcpy(ifr6.ifr_name, ifa->ifa_name,
			    sizeof(ifr6.ifr_name));
			memcpy(&ifr6.ifr_addr, ifa->ifa_addr,
			    sizeof(ifr6.ifr_addr));
			if (ioctl(s, SIOCGIFAFLAG_IN6, (caddr_t)&ifr6) == 0)
				facts_u64(&v[IP_FLAGS6],
				    ifr6.ifr_ifru.ifru_flags6);
		}
		r = facts_record(o, &kind_ip, v);
	}

	freeifaddrs(ifap);
	close(s);
	return (r);
}

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

/* show ip, show inet and show inet6: asked of nshd, and rendered here */
int
show_ip(int argc, char **argv, ...)
{
	if (strcmp(argv[1], "inet") == 0)
		return facts_show(stdout, "ip inet");
	if (strcmp(argv[1], "inet6") == 0)
		return facts_show(stdout, "ip inet6");
	return facts_show(stdout, "ip");
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
get_hwdaddr(char *ifname)
{
	int i, found = 0;
	char *val = NULL;
	struct ifaddrs *ifap, *ifa;
	struct ether_addr *ea;
	struct sockaddr_dl *sdl = NULL;

	if (getifaddrs(&ifap) != 0) {
		printf("%% get_hwdaddr: getifaddrs: %s\n", strerror(errno));
		return NULL;
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

	return val;
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
		else if (type == IFDATA_CAPABILITIES)
			value = if_data.ifi_capabilities;
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
		return 0;
	}
	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		if (strcasecmp(ifname, ifnp->if_name) == 0)
			count++;
	}
	if_freenameindex(ifn_list);

	if (count == 1)
		return 1;
	else
		return 0;
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
	return flags;
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
		return -1;
	}

	return 0;
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
	return flags;
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
		return -1;
	}

	return 0;
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
		return -1;
	}
	return 0;
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
		return -1;
	}
	return 0;
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


/* The options after an IPv6 address (ip6_opts()) */
static struct nopts ip6optlist[] = {
	{ "anycast",	no_arg,		'a' },
	{ "eui64",	no_arg,		'e' },
	{ "vltime",	req_arg,	'v' },
	{ "pltime",	req_arg,	'p' },
	{ NULL,		0,		0 }
};

struct ip6opts {
	int anycast;
	int eui64;
	u_int32_t vltime;	/* ND6_INFINITE_LIFETIME if not given */
	u_int32_t pltime;
};

/*
 * Read the options after an IPv6 address: anycast, eui64, and vltime
 * and pltime in seconds. An omitted pltime is the vltime, as
 * in6_update_ifa() refuses a pltime longer than the vltime. Returns 0,
 * or -1 after saying why not.
 */
static int
ip6_opts(int argc, char **argv, struct ip6opts *o)
{
	const char *errstr;
	u_int32_t t;
	int ch, pltime = 0;

	memset(o, 0, sizeof(*o));
	o->vltime = o->pltime = ND6_INFINITE_LIFETIME;
	noptind = 0;
	while (noptind < argc && (ch = nopt(argc, argv, ip6optlist)) != -1) {
		switch (ch) {
		case 'a':
			o->anycast = 1;
			break;
		case 'e':
			o->eui64 = 1;
			break;
		case 'v':
		case 'p':
			/* a vltime of 0 adds no address */
			t = strtonum(argv[noptind - 1], 1,
			    ND6_INFINITE_LIFETIME - 1, &errstr);
			if (errstr) {
				printf("%% %s %s: %s\n", ch == 'v' ? "vltime" :
				    "pltime", argv[noptind - 1], errstr);
				return -1;
			}
			if (ch == 'v')
				o->vltime = t;
			else {
				o->pltime = t;
				pltime = 1;
			}
			break;
		}
	}
	if (noptind < argc) {
		printf("%% %s: %s\n", nopterr, argv[noptind]);
		return -1;
	}
	if (!pltime)
		o->pltime = o->vltime;
	if (o->pltime > o->vltime) {
		printf("%% pltime must not be longer than vltime\n");
		return -1;
	}
	return 0;
}

/*
 * eui64: the interface ID of name's link-local address goes in the low
 * 64 bits of a, which must be 0, as ifconfig(8) does it
 */
static int
ip6_eui64(char *name, struct in6_addr *a)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in6 *sin6;
	int found = 0;

	if (memcmp(&a->s6_addr[8], &in6addr_any.s6_addr[8], 8) != 0) {
		printf("%% eui64: the address already has an interface ID\n");
		return -1;
	}
	if (getifaddrs(&ifap) != 0) {
		printf("%% eui64: getifaddrs: %s\n", strerror(errno));
		return -1;
	}
	for (ifa = ifap; ifa != NULL && !found; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL ||
		    ifa->ifa_addr->sa_family != AF_INET6 ||
		    strcmp(ifa->ifa_name, name) != 0)
			continue;
		sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
			memcpy(&a->s6_addr[8], &sin6->sin6_addr.s6_addr[8], 8);
			found = 1;
		}
	}
	freeifaddrs(ifap);
	if (!found)
		printf("%% eui64: %s has no link-local address\n", name);
	return found ? 0 : -1;
}

/*
 * What conf_ifaddrs() prints after an IPv6 address for its options. A
 * pltime the same as the vltime goes without saying.
 */
void
ip6_optstr(char *buf, size_t len, int anycast, u_int32_t vltime,
    u_int32_t pltime)
{
	char t[sizeof(" pltime 4294967295")];

	buf[0] = '\0';
	if (anycast)
		strlcat(buf, " anycast", len);
	if (vltime != ND6_INFINITE_LIFETIME) {
		snprintf(t, sizeof(t), " vltime %u", vltime);
		strlcat(buf, t, len);
	}
	if (pltime != ND6_INFINITE_LIFETIME && pltime != vltime) {
		snprintf(t, sizeof(t), " pltime %u", pltime);
		strlcat(buf, t, len);
	}
}

/*
 * An address as conf_ifaddrs() prints it, a link-local one with its
 * scope after it instead of in it
 */
static void
cand_addrstr(int af, void *addr, char *ifname, char *buf, size_t len)
{
	struct in6_addr ll;

	if (af == AF_INET6 && IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)addr)) {
		memcpy(&ll, addr, sizeof(ll));
		ll.s6_addr[2] = ll.s6_addr[3] = 0;
		if (inet_ntop(af, &ll, buf, len) == NULL)
			buf[0] = '\0';
		strlcat(buf, "%", len);
		strlcat(buf, ifname, len);
	} else if (inet_ntop(af, addr, buf, len) == NULL)
		buf[0] = '\0';
}

/*
 * Does a link-local address given with a %scope name another interface?
 * in6_check_embed_scope() refuses it. parse_ipv6() puts the scope in
 * the address, where the kernel keeps it.
 */
static int
cand_otherscope(struct in6_addr *a, char *ifname)
{
	u_int16_t id;

	if (!IN6_IS_ADDR_LINKLOCAL(a))
		return 0;
	memcpy(&id, &a->s6_addr[2], sizeof(id));
	if (id == 0 || id == htons(if_nametoindex(ifname)))
		return 0;
	printf("%% The scope of a link-local address on %s must be %s\n",
	    ifname, ifname);
	return 1;
}

/*
 * Has the candidate an address line of family af, or of any family if
 * af is 0? An IPv6 address has a ':' and an IPv4 address has none.
 */
static int
cand_hasaddr(int af)
{
	char *l;
	size_t n;

	for (n = 0; (l = cand_line("inet", n)) != NULL; n++)
		if (af == 0 || (strchr(l, ':') != NULL) == (af == AF_INET6))
			return 1;
	return 0;
}

/*
 * The shutdown line, after the candidate's addresses change. An address
 * brings the interface up (intip()), as turning on autoconf4, autoconf6
 * or temporary does (SIOCSIFXFLAGS). conf_ifflags() prints "no shutdown"
 * for an interface that is up only when no address line says so already,
 * and for pppoe always. -1 if the line could not be set, as a handler
 * returns.
 */
int
cand_upline(char *ifname, int bringup)
{
	if (cand_ispppoe(ifname))
		return bringup ? cand_setting(ST_OFF, "shutdown") : 0;
	if (!bringup && cand_state("shutdown") == ST_ON)
		return 0;		/* down, and stays down */
	if (cand_hasaddr(0) || cand_state("autoconf4") == ST_ON)
		return cand_setting(ST_DEFAULT, "shutdown");
	return cand_setting(ST_OFF, "shutdown");
}

/* no inet, no inet6 in configure private: each address of family af goes */
static int
cand_noaf(char *ifname, int af)
{
	char line[1024], *l;
	size_t n = 0;
	int r = 0;

	while ((l = cand_line("inet", n)) != NULL) {
		if ((strchr(l, ':') != NULL) != (af == AF_INET6)) {
			n++;
			continue;
		}
		strlcpy(line, l, sizeof(line));
		if (cand_setting(ST_OFF, "%s", line) == -1)
			r = -1;
		if ((l = cand_line("inet", n)) != NULL && strcmp(l, line) == 0)
			n++;		/* it did not go */
	}
	if (cand_upline(ifname, 0) == -1)
		r = -1;
	return r;
}

/*
 * intip() in configure private: the address line, as conf_ifaddrs()
 * prints it. What in_ioctl() or in6_update_ifa() would refuse, and an
 * address conf_ifaddr_dhcp() would not print, is refused here.
 */
static int
cand_ip(char *ifname, int set, int flags, ip_t *ip, int argc, char **argv,
    char *msg, struct ip6opts *o)
{
	char addr[INET6_ADDRSTRLEN + IFNAMSIZ];
	char dest[INET6_ADDRSTRLEN + IFNAMSIZ];
	char opts[sizeof(" anycast vltime 4294967295 pltime 4294967295")];
	struct in_addr in4dest;
	struct in6_addr in6dest;
	in_addr_t mask;
	int pppoe = cand_ispppoe(ifname), bitlen;

	if (ip->family == AF_INET6 && cand_otherscope(&ip->addr.in6, ifname))
		return -1;
	cand_addrstr(ip->family, &ip->addr, ifname, addr, sizeof(addr));
	if (!set) {
		if (cand_setting(ST_OFF, "inet %s", addr) == -1)
			return -1;
		return cand_upline(ifname, 0);
	}
	if (pppoe ? cand_state("autoconf4") != ST_OFF :
	    ip->family == AF_INET && cand_state("autoconf4") == ST_ON) {
		printf("%% %s takes its %saddresses from %s,"
		    " set \"no autoconf4\" first\n", ifname,
		    pppoe ? "" : "IPv4 ", pppoe ? "IPCP" : "DHCP");
		return -1;
	}
	dest[0] = '\0';

	switch (ip->family) {
	case AF_INET:
		memset(&in4dest, 0, sizeof(in4dest));
		if (argc == 2 && !inet_pton(AF_INET, argv[1], &in4dest)) {
			printf("%% Invalid %s address\n", msg);
			return -1;
		}
		if (flags & IFF_POINTOPOINT) {
			/* conf_ifaddrs() prints no prefix length */
			if (in4dest.s_addr != INADDR_ANY)
				cand_addrstr(AF_INET, &in4dest, ifname, dest,
				    sizeof(dest));
			if (cand_setting(ST_ON, "inet %s%s%s", addr,
			    dest[0] ? " " : "", dest) == -1)
				return -1;
			break;
		}
		/* nor the broadcast address the kernel would choose */
		mask = htonl(0xffffffffULL << (32 - ip->bitlen));
		if (in4dest.s_addr != INADDR_ANY && ntohl(in4dest.s_addr) !=
		    in4_brdaddr(ip->addr.in.s_addr, mask))
			cand_addrstr(AF_INET, &in4dest, ifname, dest,
			    sizeof(dest));
		if (cand_setting(ST_ON, "inet %s/%d%s%s", addr, ip->bitlen,
		    dest[0] ? " " : "", dest) == -1)
			return -1;
		break;
	case AF_INET6:
		if (argc == 2 && !(flags & IFF_POINTOPOINT)) {
			printf("%% An IPv6 address has no %s address\n", msg);
			return -1;
		}
		memset(&in6dest, 0, sizeof(in6dest));
		if (argc == 2 && parse_ipv6(argv[1], &in6dest) != 0) {
			printf("%% Invalid destination address %s\n", argv[1]);
			return -1;
		}
		if (cand_otherscope(&in6dest, ifname))
			return -1;
		bitlen = ip->bitlen == -1 ? 128 : ip->bitlen;
		if (bitlen == 0) {
			printf("%% An IPv6 prefix length must be 1 or more\n");
			return -1;
		}
		ip6_optstr(opts, sizeof(opts), o->anycast, o->vltime,
		    o->pltime);
		if (!(flags & IFF_POINTOPOINT)) {
			if (cand_setting(ST_ON, "inet %s/%d%s", addr, bitlen,
			    opts) == -1)
				return -1;
			break;
		}
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6dest)) {
			if (bitlen != 128) {
				printf("%% With a destination address, the"
				    " prefix length must be 128\n");
				return -1;
			}
			cand_addrstr(AF_INET6, &in6dest, ifname, dest,
			    sizeof(dest));
		}
		/* conf_ifaddrs() prints no prefix length */
		if (cand_setting(ST_ON, "inet %s%s%s%s", addr,
		    dest[0] ? " " : "", dest, opts) == -1)
			return -1;
		break;
	default:
		printf("%% unknown address family: %d\n", ip->family);
		return -1;
	}
	return cand_upline(ifname, 1);
}

void
intipusage(const char *cmdname, const char *msg)
{
	printf("%% %s <address>/<bits> %s%s%s\n", cmdname,
	    msg ? "[" : "", msg ? msg : "", msg ? "]" : "");
	printf("%% %s <address>/<netmask> %s%s%s\n", cmdname,
	    msg ? "[" : "", msg ? msg : "", msg ? "]" : "");
	printf("%% %s <IPv6 address>/<bits> ... [anycast] [eui64]"
	    " [vltime <seconds>] [pltime <seconds>]\n", cmdname);
	printf("%% no %s [<address>[/prefix-len]]\n", cmdname);
	printf("%% no %s [<address>[/netmask]]\n", cmdname);
}

int
intip(int argc, char **argv, ...)
{
	int s, set, flags, argcmax, i, nopts, r = 0;
	int argc0 = argc;
	char **argv0 = argv;
	char *msg, *cmdname, **optv;
	ip_t ip;
	struct ip6opts o;
	/* ipv4 structures */
	struct in_addr in4dest;
	struct ifaliasreq ip4req;
	/* ipv6 structures */
	struct in6_addr in6dest;
	struct in6_aliasreq ip6req;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	argc--;
	argv++;

	flags = candidate ? cand_getflags(ifname, ifs) :
	    get_ifflags(ifname, ifs);
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

	/* after the address and a destination or broadcast address, options */
	for (i = 1; i < argc; i++)
		if (genget(argv[i], (char **)ip6optlist,
		    sizeof(struct nopts)) != 0)
			break;
	nopts = argc > i ? argc - i : 0;
	optv = argv + argc - nopts;
	argc -= nopts;

	if (argc == 0) {
		/*
		 * The inet and inet6 commands allow for removing all
		 * addresses in the corresponding address family.
		 */
		if (!set &&
		    (strcmp(cmdname, "inet") == 0 ||
		    strcmp(cmdname, "inet6") == 0)) {
			if (candidate)
				return cand_noaf(ifname,
				    strcmp(cmdname, "inet6") == 0 ?
				    AF_INET6 : AF_INET);
			return intaf(ifname, ifs, argc0, argv0);
		}

		/*
		 * The inet6 command allows for enabling IPv6 link-local.
		 */
		if (set && strcmp(cmdname, "inet6") == 0) {
			if (candidate) {
				printf("%% inet6 without an address is not"
				    " saved in the configuration\n");
				return -1;
			}
			return intaf(ifname, ifs, argc0, argv0);
		}

		intipusage(cmdname, msg);
		return -1;
	} else if (argc < 1 || argc > argcmax) {
		intipusage(cmdname, msg);
		return -1;
	}

	/* ignore 'address' keyword, don't print error */
	if (strcmp(cmdname, "ip") == 0 &&
	    (isprefix(argv[0], "address") && !isprefix(argv[0], "autoconf"))) {
		argc--;
		argv++;
	}

	if (nopts > 0 &&
	    (isprefix(argv[0], "dhcp") || isprefix(argv[0], "autoconf"))) {
		intipusage(cmdname, msg);
		return -1;
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
			return intxflags(argc_dhcp, argv_dhcp, ifname, ifs);
		} else {
			printf("%% cannot get DHCP leases because dhcpleased "
			    "is not running\n");
			return -1;
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
		return intxflags(argc_xflags, argv_xflags, ifname, ifs);
	}

	memset(&ip, 0, sizeof(ip));
	parse_ip_pfx(argv[0], NO_NETMASK, &ip);

	if (ip.family == 0)
		/* bad IP specified */
		return 0;

	/* The inet6 command is IPv6-only. */
	if (strcmp(cmdname, "inet6") == 0 && ip.family != AF_INET6) {
		printf("%% %s is not a valid IPv6 address\n", argv[0]);
		return -1;
	}

	if (set && !(flags & IFF_POINTOPOINT) && ip.bitlen == -1) {
		printf("%% Netmask not specified\n");
		return -1;
	}

	/* no takes them as well, and an eui64 address is one to delete */
	if (nopts > 0 && ip.family != AF_INET6) {
		printf("%% anycast, eui64, vltime and pltime go with an IPv6"
		    " address\n");
		return -1;
	}
	if (ip6_opts(nopts, optv, &o) == -1)
		return -1;
	if (o.eui64) {
		/* the link-local address the interface ID comes from */
		if (!candidate && addaf(ifname, AF_INET6, ifs) == -1)
			return -1;
		if (ip6_eui64(ifname, &ip.addr.in6) == -1)
			return -1;
	}

	if (candidate)
		return cand_ip(ifname, set, flags, &ip, argc, argv, msg, &o);

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
			return -1;
		}
		memset(&ip4req, 0, sizeof(ip4req));
		pack_ifaliasreq(&ip4req, &ip, &in4dest, ifname);
		/* do it */
		if (ioctl(ifs, set ? SIOCAIFADDR : SIOCDIFADDR, &ip4req) < 0) {
			printf("%% intip: SIOC%sIFADDR: %s\n", set ? "A" : "D",
			    strerror(errno));
			r = -1;
		}
		break;
	case AF_INET6:
		memset(&in6dest, 0, sizeof(in6dest));
		if (argc == 2 && parse_ipv6(argv[1], &in6dest) != 0) {
			printf("%% Invalid destination address %s\n", argv[1]);
			return -1;
		}
		memset(&ip6req, 0, sizeof(ip6req));
		pack_in6aliasreq(&ip6req, &ip, &in6dest, ifname);
		ip6req.ifra_lifetime.ia6t_vltime = o.vltime;
		ip6req.ifra_lifetime.ia6t_pltime = o.pltime;
		if (o.anycast)
			ip6req.ifra_flags |= IN6_IFF_ANYCAST;
		/* get inet6 socket */
		s = socket(PF_INET6, SOCK_DGRAM, 0);
		if (s < 0) {
			printf("%% socket failed: %s\n", strerror(errno));
			return -1;
		}
		/* turn on inet6: an address needs it, a removal does not */
		if (addaf(ifname, AF_INET6, ifs) == -1 && set) {
			close(s);
			return -1;
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
			r = -1;
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
		return -1;
	}

	/*
	 * Some interfaces, such as vport(4), will not come UP
	 * automatically when the first IP address is added.
	 */
	if (set && r == 0) {
		flags = get_ifflags(ifname, ifs);
		if ((flags & IFF_UP) == 0)
			r = set_ifflags(ifname, ifs, flags | IFF_UP);
	}

	return r;
}

int
intipcp(char *ifname, int ifs, int argc, char **argv)
{
	int set;

	/* Only pppoe(4) interfaces make use of sppp(4). */
	if (!is_pppoe(ifname, ifs)) {
		printf("%% %s: not a PPPoE interface\n", ifname);
		return -1;
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
	mask = htonl(0xffffffffULL << (32 - ip->bitlen));
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
 * pflow in configure private. The line has the addresses as
 * pflow_status() prints them and the version; one the command leaves
 * out is the candidate's, or the kernel's default.
 */
static int
cand_pflow(char *ifname, int set, struct pflowreq *preq)
{
	char src[PFLOW_ADDRSTRLEN], dst[PFLOW_ADDRSTRLEN], *l;
	const char *errmsg;
	int version = PFLOW_PROTO_DEFAULT;

	if (!cand_takes(ifname, SIOCSETPFLOW)) {
		printf("%% pflow not supported on %s\n", ifname);
		return -1;
	}
	if (!set)
		return cand_setting(ST_DEFAULT, "pflow");
	if (pflow_addrstr(&preq->flowsrc, src) ||
	    pflow_addrstr(&preq->flowdst, dst)) {
		printf("%% pflow needs a sender and a receiver address\n");
		return -1;
	}
	if (preq->flowsrc.ss_family != preq->flowdst.ss_family) {
		printf("%% sender and receiver address families do not"
		    " match\n");
		return -1;
	}
	if (preq->addrmask & PFLOW_MASK_VERSION)
		version = preq->version;
	else if ((l = cand_line("pflow", 0)) != NULL &&
	    (l = strrchr(l, ' ')) != NULL)
		version = strtonum(l + 1, PFLOW_PROTO_5, PFLOW_PROTO_MAX,
		    &errmsg);
	return cand_setting(ST_ON, "pflow sender %s receiver %s version %d",
	    src, dst, version);
}

/*
 * addr/port parsing lifted from sbin/ifconfig/ifconfig.c
 */
int
intpflow(int argc, char **argv, ...)
{
	struct ifreq ifr;
	struct pflowreq preq;
	int set;
	const char *errmsg = NULL;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		    "[version 5|10]\n"
		    "%% no pflow [sender x.x.x.x receiver x.x.x.x:port "
		    "version 5|10]\n");
		return -1;
	}

	if (set) {
	        if (strchr(argv[3], ':') == NULL) {
			printf("%% Receiver has no port specified\n");
			return -1;
		}
	}

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	bzero(&preq, sizeof(struct pflowreq));
	ifr.ifr_data = (caddr_t)&preq;

	preq.addrmask = PFLOW_MASK_SRCIP | PFLOW_MASK_DSTIP;
	if (set) {
		if (pflow_addr(argv[1], &preq.flowsrc) < 0)
			return -1;
		if (pflow_addr(argv[3], &preq.flowdst) < 0)
			return -1;
		if (argc == 6) {
			preq.version = strtonum(argv[5], 5, PFLOW_PROTO_MAX,
			    &errmsg);
			preq.addrmask |= PFLOW_MASK_VERSION;
	                if (errmsg) {
				printf("%% Invalid pflow version %s: %s\n",
				    argv[5], errmsg);
				return -1;
			}
			/* pflowioctl() takes these */
			if (preq.version != PFLOW_PROTO_5 &&
			    preq.version != PFLOW_PROTO_10) {
				printf("%% Invalid pflow version %s: 5 or 10\n",
				    argv[5]);
				return -1;
			}
                }
	}

	if (candidate)
		return cand_pflow(ifname, set, &preq);

	if (ioctl(ifs, SIOCSETPFLOW, (caddr_t)&ifr) == -1) {
		printf("%% Unable to set pflow parameters: %s\n",
		    strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * patch in configure private. conf_patch() prints a pair's patch line on
 * both ends, so the peer's block changes too, and pair_ioctl()'s refusals
 * are refused first: a pair patched to itself, or to anything but a pair
 * (ENODEV), or to one patched elsewhere (EBUSY). Patching to a new peer
 * unpatches the old one.
 */
static int
cand_patch(char *ifname, char *peer)
{
	char old[IFNAMSIZ], *l;

	if (!cand_takes(ifname, SIOCSIFPAIR)) {
		printf("%% patch not supported on %s\n", ifname);
		return -1;
	}
	if (peer != NULL) {
		if (strcmp(peer, ifname) == 0) {
			printf("%% %s cannot be patched to itself\n", ifname);
			return -1;
		}
		if (!cand_hasif(peer)) {
			printf("%% interface %s not found\n", peer);
			return -1;
		}
		if (!cand_takes(peer, SIOCSIFPAIR)) {
			printf("%% %s is not a pair interface\n", peer);
			return -1;
		}
		if ((l = cand_ifline(peer, "patch", 0)) != NULL &&
		    strcmp(l + strlen("patch "), ifname) != 0) {
			printf("%% %s is patched to %s\n", peer,
			    l + strlen("patch "));
			return -1;
		}
	}
	old[0] = '\0';
	if ((l = cand_line("patch", 0)) != NULL)
		strlcpy(old, l + strlen("patch "), sizeof(old));
	if (old[0] != '\0' && (peer == NULL || strcmp(old, peer) != 0) &&
	    cand_ifsetting(old, ST_DEFAULT, "patch") == -1)
		return -1;
	if (peer == NULL)
		return cand_setting(ST_DEFAULT, "patch");
	if (cand_setting(ST_ON, "patch %s", peer) == -1)
		return -1;
	return cand_ifsetting(peer, ST_ON, "patch %s", ifname);
}

int
intpatch(int argc, char **argv, ...)
{
	int set;
	struct ifreq ifr;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	if (candidate)
		return cand_patch(ifname, set ? argv[0] : NULL);

	bzero(&ifr, sizeof(ifr));

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (set) {
		if ((ifr.ifr_index = if_nametoindex(argv[0])) == 0) {
			printf("%% invalid interface %s\n", argv[0]);
			return -1;
		}
	} else {
		ifr.ifr_index = 0;
	}
	if (ioctl(ifs, SIOCSIFPAIR, &ifr) == -1) {
		printf("%% intpatch: SIOCSIFPAIR: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intmtu(int argc, char **argv, ...)
{
	struct ifreq ifr;
	int set;
	const char *errmsg = NULL;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	if (set) {
		ifr.ifr_mtu = strtonum(argv[0], 0, INT_MAX, &errmsg);
		if (errmsg) {
			printf("%% Invalid MTU %s: %s\n", argv[0], errmsg);
			return -1;
		}
	} else
		ifr.ifr_mtu = default_mtu(ifname);

	if (candidate) {
		if (set && default_mtu(ifname) == MTU_IGNORE) {
			printf("%% The configuration does not keep the mtu"
			    " of %s\n", ifname);
			return -1;
		}
		if (conf_mtu_shown(ifname, ifr.ifr_mtu))
			return cand_setting(ST_ON, "mtu %d", ifr.ifr_mtu);
		return cand_setting(ST_DEFAULT, "mtu");
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFMTU, (caddr_t)&ifr) < 0) {
		printf("%% intmtu: SIOCSIFMTU: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intkeepalive(int argc, char **argv, ...)
{
	struct ifkalivereq ikar;
	int set;
	const char *errmsg = NULL;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	bzero(&ikar, sizeof(ikar));

	if (set) {
		ikar.ikar_timeo = strtonum(argv[0], 1, 3600, &errmsg);
		if (errmsg) {
			printf("%% Invalid period %s: %s\n", argv[0], errmsg);
			return -1;
		}
		/* the kernel takes at most 256 */
		ikar.ikar_cnt = strtonum(argv[1], 2, 256, &errmsg);
		if (errmsg) {
			printf("%% Invalid count %s: %s\n", argv[1], errmsg);
			return -1;
		}
	}

	if (candidate) {
		if (!cand_takes(ifname, SIOCSETKALIVE)) {
			printf("%% Keepalive not available on %s\n", ifname);
			return -1;
		}
		if (set)
			return cand_setting(ST_ON, "keepalive %d %d",
			    ikar.ikar_timeo, ikar.ikar_cnt);
		return cand_setting(ST_DEFAULT, "keepalive");
	}

	strlcpy(ikar.ikar_name, ifname, sizeof(ikar.ikar_name));
	if (ioctl(ifs, SIOCSETKALIVE, (caddr_t)&ikar) < 0) {
		if (errno == ENOTTY)
			printf("%% Keepalive not available on %s\n", ifname);
		else
			printf("%% intkeepalive: SIOCSETKALIVE: %s\n",
			    strerror(errno));
		return -1;
	}

	return 0;
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

/* A txprio or rxprio line, as conf_ifmetrics() prints it */
static int
cand_hdrprio(char *name, int prio, int def)
{
	if (prio == def)
		return cand_setting(ST_DEFAULT, "%s", name);
	switch (prio) {
	case IF_HDRPRIO_PACKET:
		return cand_setting(ST_ON, "%s packet", name);
	case IF_HDRPRIO_PAYLOAD:
		return cand_setting(ST_ON, "%s payload", name);
	case IF_HDRPRIO_OUTER:
		return cand_setting(ST_ON, "%s outer", name);
	}
	return cand_setting(ST_ON, "%s %d", name, prio);
}

/* intmpls() in configure private */
static int
cand_mpls(char *ifname, int type, int set, struct ifreq *ifr,
    struct shim_hdr *shim)
{
	switch (type) {
	case MPLSLABEL:
		if (set)
			return cand_setting(ST_ON, "mplslabel %u",
			    shim->shim_label);
		return cand_setting(ST_DEFAULT, "mplslabel");
	case TUNNELDOMAIN:
		if (ifr->ifr_rdomainid != 0)
			return cand_setting(ST_ON, "tunneldomain %d",
			    ifr->ifr_rdomainid);
		return cand_setting(ST_DEFAULT, "tunneldomain");
	case TXPRIO:
		return cand_hdrprio("txprio", ifr->ifr_hdrprio,
		    default_txprio(ifname));
	case RXPRIO:
		return cand_hdrprio("rxprio", ifr->ifr_hdrprio,
		    default_rxprio(ifname));
	}
	printf("%% cand_mpls: Internal error\n");
	return -1;
}

/* from ifconfig.c */
int
intmpls(int argc, char **argv, ...)
{
	int set;
	unsigned long cmd;
	struct ifreq ifr;
	struct shim_hdr shim;
	struct mplsc *x;
	const char *errstr;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	} else if (Ambiguous(x)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[0]);
		return -1;
	}

	argc--;
	argv++;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% %s <%s>\n", x->name, x->descr);
		printf("%% no %s [%s]\n", x->name, x->descr);
		return -1;
	}

	switch(x->type) {
	case MPLSLABEL:
		if (set) {
			bzero(&shim, sizeof(shim));
			ifr.ifr_data = (caddr_t)&shim;

			/* the kernel keeps 0 to 15 for itself */
			shim.shim_label = strtonum(argv[0],
			    MPLS_LABEL_RESERVED_MAX + 1, MPLS_LABEL_MAX, &errstr);
			if (errstr) {
				printf("%% Invalid MPLS Label %s: %s\n",
				    argv[0], errstr);
				return -1;
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
				return -1;
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
					return -1;
				}
			}
		} else {
			ifr.ifr_hdrprio = default_txprio(ifname);
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
					printf("%% intmpls: rxprio %s: %s\n",
					    argv[0], errstr);
					return -1;
				}
			}
		} else {
			ifr.ifr_hdrprio = default_rxprio(ifname);
		}
		cmd = SIOCSRXHPRIO;
		break;
	default:
		printf("%% intmpls: Internal error\n");
		return -1;
	}

	if (candidate) {
		if (!cand_takes(ifname, cmd)) {
			printf("%% %s not supported on %s\n", x->name, ifname);
			return -1;
		}
		return cand_mpls(ifname, x->type, set, &ifr, &shim);
	}

	if (ioctl(ifs, cmd, (caddr_t)&ifr) < 0) {
		if (errno == ENOTTY)
			printf("%% MPLS not supported on %s\n", ifname);
		else
			printf("%% intmpls: ioctl: %s\n",
			    strerror(errno));
		return -1;
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

/*
 * pwe in configure private. conf_pwe3() prints the neighbor, cw and fat
 * on one line, so the command changes what the candidate's line says.
 * nei, cw and fat are what intpwe3() parsed.
 */
static int
cand_pwe3(char *ifname, int set, int nei, int cw, int fat,
    struct if_laddrreq *req)
{
	char line[1024], neighbor[sizeof(" neighbor 1048575 ") + NI_MAXHOST];
	char host[NI_MAXHOST], *l, *w, *p;
	int error;

	if ((nei && !cand_takes(ifname, set ? SIOCSPWE3NEIGHBOR :
	    SIOCDPWE3NEIGHBOR)) ||
	    (cw != -1 && !cand_takes(ifname, SIOCSPWE3CTRLWORD)) ||
	    (fat != -1 && !cand_takes(ifname, SIOCSPWE3FAT))) {
		printf("%% PWE3 not supported on %s\n", ifname);
		return -1;
	}

	neighbor[0] = '\0';
	if ((l = cand_line("pwe", 0)) != NULL) {
		/* pwe [neighbor label address] [cw] [fat] */
		strlcpy(line, l, sizeof(line));
		strtok_r(line, " ", &p);
		while ((w = strtok_r(NULL, " ", &p)) != NULL) {
			if (strcmp(w, "neighbor") == 0) {
				w = strtok_r(NULL, " ", &p);
				l = strtok_r(NULL, " ", &p);
				if (w != NULL && l != NULL)
					snprintf(neighbor, sizeof(neighbor),
					    " neighbor %s %s", w, l);
			} else if (strcmp(w, "cw") == 0 && cw == -1)
				cw = 1;
			else if (strcmp(w, "fat") == 0 && fat == -1)
				fat = 1;
		}
	}
	if (nei && !set)
		neighbor[0] = '\0';
	else if (nei) {
		error = getnameinfo((struct sockaddr *)&req->addr,
		    req->addr.ss_len, host, sizeof(host), NULL, 0,
		    NI_NUMERICHOST);
		if (error != 0) {
			printf("%% intpwe3: getnameinfo: %s\n",
			    gai_strerror(error));
			return -1;
		}
		snprintf(neighbor, sizeof(neighbor), " neighbor %u %s",
		    ((struct sockaddr_mpls *)&req->dstaddr)->smpls_label, host);
	}

	if (neighbor[0] == '\0' && cw != 1 && fat != 1)
		return cand_setting(ST_DEFAULT, "pwe");
	return cand_setting(ST_ON, "pwe%s%s%s", neighbor,
	    cw == 1 ? " cw" : "", fat == 1 ? " fat" : "");
}

/* One pwe ioctl, saying why not if the kernel refuses it */
static int
pwe3_ioctl(int ifs, char *ifname, unsigned long cmd, caddr_t arg)
{
	if (ioctl(ifs, cmd, arg) == 0)
		return 0;
	if (errno == ENOTTY)
		printf("%% PWE3 not supported on %s\n", ifname);
	else
		printf("%% intpwe3: ioctl: %s\n", strerror(errno));
	return -1;
}

int
intpwe3(int argc, char **argv, ...)
{
	int set, ch, error, cw = -1, fat = -1, nei = 0;
	const char *errstr;
	struct ifreq ifr;
	struct if_laddrreq req;
	struct addrinfo hints, *res;
	struct sockaddr_mpls *smpls = (struct sockaddr_mpls *)&req.dstaddr;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	strlcpy(req.iflr_name, ifname, IFNAMSIZ);

	/* parse all of it, then make each change */
	noptind = 0;
	while ((ch = nopt(argc, argv, pwe3opts)) != -1)
		switch (ch) {
		case 'c':	/* cw */
			cw = set;
			break;
		case 'f':	/* fat */
			fat = set;
			break;
		case 'n':	/* neighbor */
			nei = 1;
			if (!set)
				break;
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_DGRAM;
			error = getaddrinfo(argv[noptind - 1], NULL, &hints,
			    &res);
			if (error != 0) {
				printf("%% intpwe3: neighbor %s: %s\n",
				    argv[noptind - 1], gai_strerror(error));
				return -1;
			}
			smpls->smpls_len = sizeof(*smpls);
			smpls->smpls_family = AF_MPLS;
			smpls->smpls_label = strtonum(argv[noptind - 2],
			    (MPLS_LABEL_RESERVED_MAX + 1), MPLS_LABEL_MAX,
			    &errstr);
			if (errstr != NULL) {
				printf("%% intpwe3: invalid label %s: %s\n",
				    argv[noptind - 2], errstr);
				freeaddrinfo(res);
				return -1;
			}
			if (res->ai_addrlen > sizeof(req.addr)) {
				printf("%% intpwe3: invalid address %s\n",
				    argv[noptind - 1]);
				freeaddrinfo(res);
				return -1;
			}
			memcpy(&req.addr, res->ai_addr, res->ai_addrlen);
			freeaddrinfo(res);
			break;
		}

	if (argc - noptind != 0) {
		/* leftover salmon */
		printf("%% %s", nopterr);
		if (argv[noptind])
			printf(": %s", argv[noptind]);
		printf("\n");
		pwe3usage();
		return -1;
	}

	if (candidate)
		return cand_pwe3(ifname, set, nei, cw, fat, &req);

	if (nei && pwe3_ioctl(ifs, ifname, set ? SIOCSPWE3NEIGHBOR :
	    SIOCDPWE3NEIGHBOR, (caddr_t)&req) == -1)
		return -1;
	if (cw != -1) {
		ifr.ifr_pwe3 = cw;
		if (pwe3_ioctl(ifs, ifname, SIOCSPWE3CTRLWORD,
		    (caddr_t)&ifr) == -1)
			return -1;
	}
	if (fat != -1) {
		ifr.ifr_pwe3 = fat;
		if (pwe3_ioctl(ifs, ifname, SIOCSPWE3FAT, (caddr_t)&ifr) == -1)
			return -1;
	}

	return (0);
}

int
intdhcrelay(int argc, char **argv, ...)
{
	char *cmd[] = { DHCRELAY, "-i", NULL, NULL, NULL };
	int set, alen, r;
	struct in_addr notused;
	va_list ap;
	char *ifname;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	va_end(ap);

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
		return -1;
	}

	if (argc) {
		if (inet_pton(AF_INET, argv[0], &notused)) {
			cmd[3] = argv[0];
		} else {
			printf("%% Not a valid IPv4 address: %s\n", argv[0]);
			return -1;
		}
	}

	if (candidate) {
		char *l;

		if (set)
			return cand_setting(ST_ON, "dhcrelay %s", argv[0]);
		if ((l = cand_line("dhcrelay", 0)) == NULL) {
			printf("%% No relay configured for %s\n", ifname);
			return -1;
		}
		l += strlen("dhcrelay ");
		if (argc && strcmp(l, argv[0]) != 0) {
			printf("%% Server expected: %s (not %s)\n", l, argv[0]);
			return -1;
		}
		return cand_setting(ST_DEFAULT, "dhcrelay");
	}

	if (set) {
		flag_x("dhcrelay", ifname, DB_X_ENABLE, argv[0]);
		if (cmdargs(DHCRELAY, cmd) != 0)
			return -1;
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
			return -1;
		}

		/* bail if dhcrelay not relaying to specified dhcp server */
		if (argc && strcmp(server, argv[0]) != 0) {
			printf("%% Server expected: %s (not %s)\n", server,
			    argv[0]);
			return -1;
		}

		flag_x("dhcrelay", ifname, DB_X_REMOVE, NULL);

		/* setup argument list as one argument for pkill -xf */
		snprintf(argue, sizeof(argue), "%s %s %s %s", cmd[0], cmd[1],
		    cmd[2], server);
		killcmd[2] = argue;

		/* 1: no dhcrelay ran */
		r = cmdargs(PKILL, killcmd);
		if (r == -1 || r > 1)
			return -1;
	}
	return 0;
}

int
intmetric(int argc, char **argv, ...)
{
	struct ifreq ifr;
	int set, max;
	unsigned long theioctl;
	char *type;
	const char *errmsg = NULL;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	argc--;
	argv++;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% %s <%s>\n", type, type);
		printf("%% no %s [%s]\n", type, type);
		return -1;
	}

	if (set) {
		int num;

		num = strtonum(argv[0], 0, max, &errmsg);
		if (errmsg) {
			printf("%% Invalid %s %s: %s\n", type, argv[0],
			    errmsg);
			return -1;
		}
		ifr.ifr_metric = num;
	} else {
		ifr.ifr_metric = 0;
	}

	if (errmsg) {
		printf("%% Invalid %s %s: %s\n", type, argv[0], errmsg);
		return -1;
	}

	if (candidate) {
		if (ifr.ifr_metric != 0)
			return cand_setting(ST_ON, "%s %d", type,
			    ifr.ifr_metric);
		return cand_setting(ST_DEFAULT, "%s", type);
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, theioctl, (caddr_t)&ifr) < 0) {
		printf("%% intmetric: SIOCSIF%s: %s\n", type,
		    strerror(errno));
		return -1;
	}

	return 0;
}

int
intllprio(int argc, char **argv, ...)
{
	struct ifreq ifr;
	int set;
	const char *errmsg = NULL;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	if ((!set && argc > 2) || (set && argc != 2)) {
		printf("%% llpriority <priority>\n");
		printf("%% no llpriority [priority]\n");
		return -1;
	}

	if (set) {
		int num;

		num = strtonum(argv[1], 0, 15, &errmsg);
		if (errmsg) {
			printf("%% Invalid llpriority %s: %s\n", argv[1],
			    errmsg);
			return -1;
		}
		ifr.ifr_llprio = num;
	} else {
		ifr.ifr_llprio = default_llpriority(ifname);
	}

	if (errmsg) {
		printf("%% Invalid llpriority %s: %s\n", argv[1], errmsg);
		return -1;
	}

	if (candidate) {
		if (ifr.ifr_llprio != default_llpriority(ifname))
			return cand_setting(ST_ON, "llpriority %d",
			    ifr.ifr_llprio);
		return cand_setting(ST_DEFAULT, "llpriority");
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFLLPRIO, (caddr_t)&ifr) < 0) {
		printf("%% intllprio: SIOCSIFLLPRIO: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intgroup(int argc, char **argv, ...)
{
	int set, i, r = 0;
	struct ifgroupreq ifgr;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	for (i = 0; i < argc; i++) {
		/* Validate supplied argument(s) before applying them */
		if (isdigit((unsigned char)argv[i][strlen(argv[i]) - 1])) {
			printf("%% Group names may not end with a digit\n");
			return -1;
		}
		if (strlen(argv[i]) >= IFNAMSIZ) {
			printf("%% Group name too long (%s)\n", argv[i]);
			return -1;
		}
	}

	if (candidate) {
		char groups[1024];
		size_t need = 0;

		for (i = 0; i < argc; i++)
			need += strlen(argv[i]) + 1;
		if (need > sizeof(groups)) {
			printf("%% Too many groups\n");
			return -1;
		}
		argvtostring(argc, argv, groups, sizeof(groups));
		return cand_setting(set ? ST_ON : ST_OFF, "group %s", groups);
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
				r = -1;
				break;
			}
		}
	}

	return r;
}

int
intrtlabel(int argc, char **argv, ...)
{
	int set;
	struct ifreq ifr;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
			return -1;
		}
		if (strlen(argv[0]) >= RTLABEL_LEN) {
			printf("%% label too long (max %d char)\n",
			    RTLABEL_LEN - 1);
			return -1;
		}
		ifr.ifr_data = (caddr_t)argv[0];
	} else {
		ifr.ifr_data = (caddr_t)(const char *)"";
	}

	if (candidate) {
		if (set)
			return cand_setting(ST_ON, "rtlabel %s", argv[0]);
		return cand_setting(ST_DEFAULT, "rtlabel");
	}

	if (ioctl(ifs, SIOCSIFRTLABEL, &ifr) == -1) {
		printf("%% intrtlabel: SIOCSIFRTLABEL: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intparent(int argc, char **argv, ...)
{
	int set, ret;
	unsigned long cmd;
	struct if_parent ifp;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
                return -1;
        }

	bzero(&ifp, sizeof(ifp));

	strlcpy(ifp.ifp_name, ifname, IFNAMSIZ);

	if (set && strlcpy(ifp.ifp_parent, argv[0], sizeof(ifp.ifp_parent)) >=
	    sizeof(ifp.ifp_parent)) {
		printf("%% parent name too long\n");
		return -1;
	}

	cmd = (set ? SIOCSIFPARENT : SIOCDIFPARENT);
	if (candidate) {
		if (!cand_takes(ifname, cmd)) {
			printf("%% parent not supported on %s\n", ifname);
			return -1;
		}
		if (!set)
			return cand_setting(ST_DEFAULT, "parent");
		if (strcmp(argv[0], ifname) == 0) {
			printf("%% %s cannot be its own parent\n", ifname);
			return -1;
		}
		if (!cand_hasif(argv[0])) {
			printf("%% interface %s not found\n", argv[0]);
			return -1;
		}
		return cand_setting(ST_ON, "parent %s", argv[0]);
	}
	ret = ioctl(ifs, cmd, &ifp);
	if (ret == -1) {
		int cmd_errno = errno;
		if (errno == EBUSY) {
			int flags = get_ifflags(ifname, ifs);
			if (flags & IFF_UP) {
				/* Put interface down, retry, and put it up. */
				if (set_ifflags(ifname, ifs, flags & ~IFF_UP)
				    == -1)
					return -1;
				ret = ioctl(ifs, cmd, &ifp);
				if (ret == -1)
					cmd_errno = errno;
				if (set_ifflags(ifname, ifs, flags) == -1)
					return -1;
			}
		}
		if (ret == -1) {
			printf("%% intparent: SIOC%sIFPARENT: %s\n",
			    set ? "S" : "D", strerror(cmd_errno));
			return -1;
		}
	}

	return 0;
}

/*
 * intflags() in configure private: the lines conf_ifflags() would
 * print once the flag is set or cleared.
 */
static int
cand_ifflags(char *ifname, int value, int set)
{
	switch (value) {
	case IFF_DEBUG:
		return cand_setting(set ? ST_ON : ST_OFF, "debug");
	case IFF_STATICARP:
		if (!set)
			return cand_setting(ST_OFF, "staticarp");
		/* static ARP turns ARP back on, as below */
		if (cand_setting(ST_ON, "arp") == -1)
			return -1;
		return cand_setting(ST_ON, "staticarp");
	case -IFF_NOARP:
		if (set)
			return cand_setting(ST_ON, "arp");
		/* turning ARP off turns static ARP off too */
		if (cand_setting(ST_OFF, "staticarp") == -1)
			return -1;
		return cand_setting(ST_OFF, "arp");
	case -IFF_UP:
		if (set)
			return cand_setting(ST_ON, "shutdown");
		return cand_upline(ifname, 1);
	}
	printf("%% cand_ifflags: value internal error\n");
	return -1;
}

int
intflags(int argc, char **argv, ...)
{
	int set, value, flags, iftype;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	/*
	 * wg(4) sets IFF_NOARP by default and this should not be changed.
	 * The kernel doesn't prevent this flag from being cleared (as of 7.2).
	 */
	iftype = candidate ? cand_gettype(ifname) :
	    get_ifdata(ifname, IFDATA_IFTYPE);
	if (iftype == IFT_WIREGUARD &&
	    (value == -IFF_NOARP || value == IFF_STATICARP)) {
		printf("%% wireguard interfaces do not support ARP\n");
		return -1;
	}

	if (candidate)
		return cand_ifflags(ifname, value, set);

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
		return -1;
	}
	return set_ifflags(ifname, ifs, flags);
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
		return -1;
	}

	/* Do not use isprefix() here because it would always be ambiguous. */
	if (strcmp(argv[0], "inet6") == 0)
		return set ? addaf(ifname, AF_INET6, ifs) :
		    removeaf(ifname, AF_INET6, ifs);
	if (strcmp(argv[0], "inet") == 0)
		return set ? addaf(ifname, AF_INET, ifs) :
		    removeaf(ifname, AF_INET, ifs);
	printf("%% intaf: unknown address family %s\n", argv[0]);
	return -1;
}

/*
 * autoconf4 in configure private. conf_ifaddr_dhcp() prints no IPv4
 * address with autoconf4, and none at all for pppoe, where autoconf4
 * means IPCP and is the default; there "no autoconf4" is a line too.
 */
static int
cand_autoconf4(char *ifname, int set)
{
	int pppoe = cand_ispppoe(ifname), was = cand_state("autoconf4");

	if (set && cand_hasaddr(pppoe ? 0 : AF_INET)) {
		printf("%% Remove the %saddresses of %s first\n",
		    pppoe ? "" : "IPv4 ", ifname);
		return -1;
	}
	if (pppoe)
		return cand_setting(set ? ST_ON : ST_OFF, "autoconf4");
	if (cand_setting(set ? ST_ON : ST_DEFAULT, "autoconf4") == -1)
		return -1;
	return cand_upline(ifname, set && was != ST_ON);
}

/* intxflags() in configure private, for the flags conf_ifxflags() prints */
static int
cand_ifxflags(char *ifname, int value, int set)
{
	char *name;
	int was;

	switch (value) {
	case IFXF_MPLS:
		name = "mpls";
		break;
	case IFXF_AUTOCONF6:
		name = "autoconf6";
		break;
	case IFXF_AUTOCONF6TEMP:
		name = "temporary";
		break;
	case IFXF_MONITOR:
		name = "monitor";
		break;
	case IFXF_WOL:
		/* SIOCSIFXFLAGS: ENOTSUP without IFCAP_WOL */
		if (set && if_nametoindex(ifname) != 0 &&
		    !(get_ifdata(ifname, IFDATA_CAPABILITIES) & IFCAP_WOL)) {
			printf("%% %s does not support wake on LAN\n", ifname);
			return -1;
		}
		name = "wol";
		break;
	default:
		printf("%% cand_ifxflags: value internal error\n");
		return -1;
	}
	was = cand_state(name);
	if (cand_setting(set ? ST_ON : ST_OFF, "%s", name) == -1)
		return -1;
	if (set && was != ST_ON &&
	    (value == IFXF_AUTOCONF6 || value == IFXF_AUTOCONF6TEMP))
		return cand_upline(ifname, 1);
	return 0;
}

int
intxflags(int argc, char **argv, ...)
{
	int set, value, flags;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	if (isprefix(argv[0], "autoconfprivacy")) {
		value = IFXF_AUTOCONF6TEMP;
	} else if (isprefix(argv[0], "temporary")) {
		value = IFXF_AUTOCONF6TEMP;
	} else if (isprefix(argv[0], "monitor")) {
		value = IFXF_MONITOR;
	} else if (isprefix(argv[0], "autoconf4")) {
		if (candidate)
			return cand_autoconf4(ifname, set);
		/* Have "autoconf4" on pppoe(4) do the right thing. */
		if (is_pppoe(ifname, ifs))
			return run_ipcp(ifname, ifs, set);

		value = IFXF_AUTOCONF4;
	} else if (isprefix(argv[0], "autoconf6")) {
		value = IFXF_AUTOCONF6;
	} else if (isprefix(argv[0], "mpls")) {
		value = IFXF_MPLS;
	} else if (isprefix(argv[0], "wol")) {
		value = IFXF_WOL;
	} else {
		printf("%% intxflags: Internal error\n");
		return -1;
	}

	if (candidate)
		return cand_ifxflags(ifname, value, set);

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
		return -1;
	}
	return set_ifxflags(ifname, ifs, flags);
}

/* The link flags the candidate's link line sets */
static int
cand_linkflags(void)
{
	char line[sizeof("link 0 1 2")], *l, *w, *p;
	int flags = 0;

	if ((l = cand_line("link", 0)) == NULL)
		return 0;
	strlcpy(line, l, sizeof(line));
	strtok_r(line, " ", &p);
	while ((w = strtok_r(NULL, " ", &p)) != NULL)
		flags |= strcmp(w, "0") == 0 ? IFF_LINK0 :
		    strcmp(w, "1") == 0 ? IFF_LINK1 :
		    strcmp(w, "2") == 0 ? IFF_LINK2 : 0;
	return flags;
}

int
intlink(int argc, char **argv, ...)
{
	const char *errmsg = NULL;
	int set, i, flags, value = 0;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	flags = candidate ? cand_linkflags() : get_ifflags(ifname, ifs);

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
			return -1;
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

	if (candidate) {
		if (!(flags & (IFF_LINK0|IFF_LINK1|IFF_LINK2)))
			return cand_setting(ST_DEFAULT, "link");
		return cand_setting(ST_ON, "link%s%s%s",
		    flags & IFF_LINK0 ? " 0" : "",
		    flags & IFF_LINK1 ? " 1" : "",
		    flags & IFF_LINK2 ? " 2" : "");
	}

	return set_ifflags(ifname, ifs, flags);
}

int
intnwid(int argc, char **argv, ...)
{
	struct ieee80211_nwid nwid;
	struct ifreq ifr;
	int set, len;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	len = sizeof(nwid.i_nwid);

	if (set) {
		if (get_string(argv[0], NULL, nwid.i_nwid, &len) == NULL) {
			printf("%% intnwid: bad input\n");
			return -1;
		}
	} else
		len = 0; /* nwid "" */

	if (candidate)
		return cand_nwid(ifname, nwid.i_nwid, len);

	nwid.i_len = len;
	ifr.ifr_data = (caddr_t)&nwid;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCS80211NWID, (caddr_t)&ifr) < 0) {
		printf("%% intnwid: SIOCS80211NWID: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intpowersave(int argc, char **argv, ...)
{
	const char *errmsg = NULL;
	struct ieee80211_power power;
	int  set, maxsleep;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	if (argc == 1) {
		maxsleep = strtonum(argv[0], 0, 1000, &errmsg);
		if (errmsg) {
			printf("%% Power save invalid %s: %s\n", argv[0],
			    errmsg);
			return -1;
		}
	} else {
		maxsleep = DEFAULT_POWERSAVE;
	}

	if (candidate)
		return cand_powersave(ifname, set, maxsleep);

	strlcpy(power.i_name, ifname, sizeof(power.i_name));

	if (ioctl(ifs, SIOCG80211POWER, (caddr_t)&power) == -1) {
		printf("%% intpowersave: SIOCG80211POWER: %s\n",
		    strerror(errno));
		return -1;
	}

	power.i_maxsleep = maxsleep;
	power.i_enabled = set;

	if (ioctl(ifs, SIOCS80211POWER, (caddr_t)&power) == -1) {
		printf("%% intpowersave: SIOCS80211POWER: %s\n",
		    strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * lladdr in configure private. conf_lladdr() prints the address only
 * when it differs from the one the interface had, which intlladdr() keeps
 * in the database when it first changes it. The kernel takes an address
 * only for an Ethernet interface, and no multicast address (EINVAL).
 */
static int
cand_lladdr(char *ifname, char *arg)
{
	StringList *orig;
	struct ether_addr *ea, eabuf;
	char addr[sizeof("00:00:00:00:00:00")], *cur;
	int i, same = 0;

	if (arg == NULL)
		return cand_setting(ST_DEFAULT, "lladdr");
	if (cand_gettype(ifname) != IFT_ETHER) {
		printf("%% %s has no Ethernet address to set\n", ifname);
		return -1;
	}
	if (isprefix(arg, "random")) {
		arc4random_buf(&eabuf, sizeof(eabuf));
		eabuf.ether_addr_octet[0] &= 0xfc;
		ea = &eabuf;
	} else if ((ea = ether_aton(arg)) == NULL) {
		printf("%% MAC addresses are six hexadecimal fields, up to two"
		    " digits each,\n%% separated with colons"
		    " (1:23:45:ab:cd:ef)\n");
		return -1;
	}
	if (ETHER_IS_MULTICAST(ea->ether_addr_octet)) {
		printf("%% %s is a multicast address\n", arg);
		return -1;
	}
	for (i = 0; i < ETHER_ADDR_LEN && ea->ether_addr_octet[i] == 0; i++)
		;
	if (i == ETHER_ADDR_LEN) {
		printf("%% The configuration does not keep a zero lladdr\n");
		return -1;
	}
	strlcpy(addr, ether_ntoa(ea), sizeof(addr));

	if (if_nametoindex(ifname) != 0) {
		orig = sl_init();
		if (db_select_flag_x_ctl(orig, "lladdr", ifname) < 0)
			printf("%% lladdr database select failed\n");
		else if (orig->sl_cur > 0)
			same = strcmp(orig->sl_str[0], addr) == 0;
		else
			same = (cur = get_hwdaddr(ifname)) != NULL &&
			    strcmp(cur, addr) == 0;
		sl_free(orig, 1);
	}
	if (same)
		return cand_setting(ST_DEFAULT, "lladdr");
	return cand_setting(ST_ON, "lladdr %s", addr);
}

int
intlladdr(int argc, char **argv, ...)
{
	StringList *hwdaddr;
	char *lladdr, llorig[sizeof("00:00:00:00:00:00") + 1];
	struct ether_addr *addr;
	struct ifreq ifr;
	int set;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);


	if (NO_ARG(argv[0])) {
		argv++;
		argc--;
		set = 0;
	} else
		set = 1;

	if (set && argc < 2) {
		printf ("%% lladdr <link level address|random>\n");
		printf ("%% no lladdr\n");
		return -1;
	}

	if (candidate)
		return cand_lladdr(ifname, set ? argv[1] : NULL);

	if ((lladdr = get_hwdaddr(ifname)) == NULL) {
		printf("%% Failed to retrieve current link level address\n");
		return -1;
	}

	hwdaddr = sl_init();
	if (db_select_flag_x_ctl(hwdaddr, "lladdr", ifname) < 0) {
		printf("%% database failure select flag x ctl\n");
		sl_free(hwdaddr, 1);
		return -1;
	}
	if (hwdaddr->sl_cur > 0) {
		strlcpy(llorig, hwdaddr->sl_str[0], sizeof(llorig));
		if (!set && db_delete_flag_x_ctl("lladdr", ifname, 0) < 0) {
				printf("%% database delete failure\n");
				sl_free(hwdaddr, 1);
				return -1;
		}
	} else {
		strlcpy(llorig, lladdr, sizeof(llorig));
		if (set && db_insert_flag_x("lladdr", ifname, 0, DB_X_ENABLE,
		    llorig) < 0) {
			printf("%% database delete failure\n");
			sl_free(hwdaddr, 1);
			return -1;
		}
		if (!set) {
			printf("%% No stored lladdr to reinstate\n");
			sl_free(hwdaddr, 1);
			return -1;
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
				return -1;
			} else {
				printf("%% database corrupted, unable to "
				    " retrieve original lladdr\n");
				return -1;
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
		return -1;
	}

	return 0;
}

int
intrdomain(int argc, char **argv, ...)
{
	int set, rdomain;
	const char *errmsg = NULL;
	struct ifreq ifr;
	va_list ap;
	char *ifname;
	int ifs; 

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}
	if (set) {
		rdomain = strtonum(argv[0], 0, RT_TABLEID_MAX, &errmsg);
		if (errmsg) {
			printf("%% Routing domain %s invalid (%s)\n", argv[0], errmsg);
			return -1;
		}
		ifr.ifr_rdomainid = rdomain;
	}
	else
		ifr.ifr_rdomainid = 0;
	if (candidate) {
		if (ifr.ifr_rdomainid > 0)
			return cand_setting(ST_ON, "rdomain %d",
			    ifr.ifr_rdomainid);
		return cand_setting(ST_DEFAULT, "rdomain");
	}
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFRDOMAIN, &ifr) < 0) {
		printf("%% intrdomain: SIOCSIFRDOMAIN: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intdesc(int argc, char **argv, ...)
{
	int set;
	char desc[IFDESCRSIZE];
	struct ifreq ifr;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	argvtostring(argc, argv, desc, sizeof(desc));

	if (candidate) {
		if (set && desc[0] != '\0')
			return cand_setting(ST_ON, "description %s", desc);
		return cand_setting(ST_OFF, "description");
	}

	if (set)
		ifr.ifr_data = (caddr_t)&desc;
	else
		ifr.ifr_data = (caddr_t)"";
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFDESCR, &ifr) < 0) {
		printf("%% intdesc: SIOCSIFDESCR: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intvnetflowid(int argc, char **argv, ...)
{
	int set;
	struct ifreq ifr;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

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
		return -1;
	}

	if (candidate) {
		if (!cand_takes(ifname, SIOCSVNETFLOWID)) {
			printf("%% vnetflowid not supported on %s\n", ifname);
			return -1;
		}
		return cand_setting(set ? ST_ON : ST_OFF, "vnetflowid");
	}

	if (set)
		ifr.ifr_vnetid = 1;
	else
		ifr.ifr_vnetid = 0;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSVNETFLOWID, &ifr) < 0) {
		printf("%% intvnetflowid: SIOCSVNETFLOWID: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

/* the VLANs of tag start, or from start to end, or every one */
int
vlan_facts(struct facts_out *o, int start_vnetid, int end_vnetid)
{
	struct facts_value v[VLAN_NFIELDS];
	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr;
	struct if_parent ifp;
	int ifs, vnetid, bridx, r = 0;
	char ifdescr[IFDESCRSIZE];
	char ifix_buf[IFNAMSIZ];

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% show_vlan: %s\n", strerror(errno));
		return (-1);
	}

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% show_vlan: if_nameindex failed\n");
		close(ifs);
		return (-1);
	}

	for (ifnp = ifn_list; ifnp->if_name != NULL && r != -1; ifnp++) {
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

		memset(v, 0, sizeof(v));
		facts_string(&v[VLAN_NAME], ifnp->if_name);
		if (vnetid != -1)
			facts_u64(&v[VLAN_VNETID], vnetid);

		memset(&ifp, 0, sizeof(ifp));
		if (strlcpy(ifp.ifp_name, ifnp->if_name,
		    sizeof(ifp.ifp_name)) >= sizeof(ifp.ifp_name)) {
			printf("%% %s: interface name is too long\n",
			   ifnp->if_name);
			continue;
		}
		if (ioctl(ifs, SIOCGIFPARENT, &ifp) == -1) {
			if (errno != EADDRNOTAVAIL) {
				printf("%% %s: SIOCGIFPARENT: %s\n",
				   ifnp->if_name, strerror(errno));
				continue;
			}
		} else
			facts_string(&v[VLAN_PARENT], ifp.ifp_parent);

		if (ioctl(ifs, SIOCGIFRDOMAIN, (caddr_t)&ifr) != -1)
			facts_u64(&v[VLAN_RDOMAIN], ifr.ifr_rdomainid);

		facts_u64(&v[VLAN_FLAGS], get_ifflags(ifnp->if_name, ifs));

		memset(ifdescr, 0, sizeof(ifdescr));
		ifr.ifr_data = (caddr_t)&ifdescr;
		if (ioctl(ifs, SIOCGIFDESCR, &ifr) == 0)
			facts_string(&v[VLAN_DESCR], ifdescr);

		bridx = bridge_member_search(ifs, ifnp->if_name);
		if (bridx && if_indextoname(bridx, ifix_buf) != NULL)
			facts_string(&v[VLAN_BRIDGE], ifix_buf);

		r = facts_record(o, &kind_vlan, v);
	}

	if_freenameindex(ifn_list);
	close(ifs);
	return (r);
}

/* a VLAN, as show_vlan() printed it, the headers before the first */
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

int
show_vlans(int argc, char **argv, ...)
{
	long long start_vnetid = -1, end_vnetid = -1;
	const char *errstr;

	switch (argc) {
	case 2:
		return facts_show(stdout, "vlan");
	case 3:
		start_vnetid = strtonum(argv[2], EVL_VLID_NULL,
		    EVL_VLID_MAX, &errstr);
		if (errstr) {
			printf("%% VLAN tag %s is %s\n", argv[2], errstr);
			return -1;
		}
		return facts_show(stdout, "vlan %lld", start_vnetid);
	case 4:
		start_vnetid = strtonum(argv[2], EVL_VLID_NULL,
		    EVL_VLID_MAX, &errstr);
		if (errstr) {
			printf("%% VLAN tag %s is %s\n", argv[2], errstr);
			return -1;
		}
		end_vnetid = strtonum(argv[3], EVL_VLID_NULL,
		    EVL_VLID_MAX, &errstr);
		if (errstr) {
			printf("%% VLAN tag %s is %s\n", argv[3], errstr);
			return -1;
		}
		if (start_vnetid >= end_vnetid) {
			printf("%% VLAN Start Tag must be smaller "
			    "than VLAN End Tag\n");
			return -1;
		}
		return facts_show(stdout, "vlan %lld %lld", start_vnetid,
		    end_vnetid);
	}
	return 0;
}
