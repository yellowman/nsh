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
#include "args.h"
#include "showfacts.h"
#include "kfacts.h"
#include "session.h"
const char *get_linkstate(int, int);
char *get_hwdaddr(char *ifname);
void pack_ifaliasreq(struct ifaliasreq *, ip_t *, struct in_addr *, char *);
void pack_in6aliasreq(struct in6_aliasreq *, ip_t *, struct in6_addr *, char *);
void ipv6ll_db_store(struct sockaddr_in6 *, struct sockaddr_in6 *, int, char *);
void intipusage(const char *, const char *);
int run_ipcp(char *, int, int, struct cand *);
void pwe3usage(void);
int show_vlan(int, int);

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

	/*
	 * a tunnel's endpoints: its source, with vxlan's port, and its
	 * destination, which mgre and vxlan in endpoint mode do not have
	 */
	memset(&req, 0, sizeof(req));
	strlcpy(req.iflr_name, ifname, sizeof(req.iflr_name));
	if (ioctl(ifs, SIOCGLIFPHYADDR, (caddr_t)&req) == 0) {
		facts_sockaddr(&v[IF_TUNSRC], (struct sockaddr *)&req.addr);
		facts_sockaddr(&v[IF_TUNDST], (struct sockaddr *)&req.dstaddr);
		if (req.addr.ss_family == AF_INET)
			facts_u64(&v[IF_TUNPORT], ntohs(((struct sockaddr_in *)
			    &req.addr)->sin_port));
		else if (req.addr.ss_family == AF_INET6)
			facts_u64(&v[IF_TUNPORT], ntohs(((struct sockaddr_in6 *)
			    &req.addr)->sin6_port));
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

	/* do not report the network key stored in nsh.db */
	if (get_nwinfo(ifname, ssid, sizeof(ssid), NWID) != 0) {
		facts_string(&v[IF_SSID], ssid);
		if (get_nwinfo(ifname, ps, sizeof(ps), POWERSAVE) != 0) {
			i = strtonum(ps, 0, INT_MAX, &errstr);
			if (errstr == NULL)
				facts_u64(&v[IF_POWERSAVE], i);
		}
	}

	/*
	 * a bridge's members and learned addresses, or bpe's, nvgre's or
	 * vxlan's learned addresses
	 */
	if (detail && (v[IF_BRIDGE].v.u || bridge_learns(ifs, ifname)))
		bridge_facts(o, ifs, ifname);

	freeifaddrs(ifap);
	close(ifs);
	if (facts_record(o, &kind_interface, v) == -1)
		r = -1;
	return (r);
}

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

/*
 * ioctl(s, cmd, data) for a change to ifname. vxlan, the gre family, bpe
 * and vlan refuse some changes with EBUSY while the interface runs: then
 * the interface is taken down for the change, and brought up again.
 */
int
ioctl_down(int s, char *ifname, u_long cmd, void *data)
{
	int flags, r, e;

	if ((r = ioctl(s, cmd, data)) != -1 || errno != EBUSY)
		return r;
	if (!((flags = get_ifflags(ifname, s)) & IFF_UP)) {
		errno = EBUSY;
		return -1;
	}
	if (set_ifflags(ifname, s, flags & ~IFF_UP) == -1)
		return -1;
	r = ioctl(s, cmd, data);
	e = errno;
	if (set_ifflags(ifname, s, flags) == -1)
		return -1;
	errno = e;
	return r;
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
			/*
			 * a vltime of 0 adds no address, and a pltime of 0
			 * adds a deprecated one
			 */
			t = strtonum(argv[noptind - 1], ch == 'v' ? 1 : 0,
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
	struct in6_addr ll;
	int found;

	if (memcmp(&a->s6_addr[8], &in6addr_any.s6_addr[8], 8) != 0) {
		printf("%% eui64: the address already has an interface ID\n");
		return -1;
	}
	if ((found = kf_ll6(name, &ll)) == -1) {
		printf("%% eui64: getifaddrs: %s\n", strerror(errno));
		return -1;
	}
	if (!found) {
		printf("%% eui64: %s has no link-local address\n", name);
		return -1;
	}
	memcpy(&a->s6_addr[8], &ll.s6_addr[8], 8);
	return 0;
}

/*
 * What conf_ifaddrs() prints after an IPv6 address for its options. A
 * pltime equal to the vltime is not printed.
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
	if (id == 0 || id == htons(kf_index(ifname)))
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
cand_hasaddr(struct cand *cand, int af)
{
	char *l;
	size_t n;

	for (n = 0; (l = cand_line(cand, "inet", n)) != NULL; n++)
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
cand_upline(struct cand *cand, char *ifname, int bringup)
{
	if (cand_ispppoe(ifname))
		return bringup ? cand_setting(cand, ST_OFF, "shutdown") : 0;
	if (!bringup && cand_state(cand, "shutdown") == ST_ON)
		return 0;		/* down, and stays down */
	if (cand_hasaddr(cand, 0) || cand_state(cand, "autoconf4") == ST_ON)
		return cand_setting(cand, ST_DEFAULT, "shutdown");
	return cand_setting(cand, ST_OFF, "shutdown");
}

/* no inet, no inet6 in configure private: remove every address of af */
static int
cand_noaf(struct cand *cand, char *ifname, int af)
{
	char line[1024], *l;
	size_t n = 0;
	int r = 0;

	while ((l = cand_line(cand, "inet", n)) != NULL) {
		if ((strchr(l, ':') != NULL) != (af == AF_INET6)) {
			n++;
			continue;
		}
		strlcpy(line, l, sizeof(line));
		if (cand_setting(cand, ST_OFF, "%s", line) == -1)
			r = -1;
		if ((l = cand_line(cand, "inet", n)) != NULL &&
		    strcmp(l, line) == 0)
			n++;		/* it was not removed */
	}
	if (cand_upline(cand, ifname, 0) == -1)
		r = -1;
	return r;
}

/*
 * intip() in configure private: the address line, as conf_ifaddrs()
 * prints it. What in_ioctl() or in6_update_ifa() would refuse, and an
 * address conf_ifaddr_dhcp() would not print, is refused here.
 */
static int
cand_ip(struct cand *cand, char *ifname, int set, int flags, ip_t *ip, int argc,
    char **argv, char *msg, struct ip6opts *o)
{
	char addr[INET6_ADDRSTRLEN + IFNAMSIZ];
	char dest[INET6_ADDRSTRLEN + IFNAMSIZ];
	char opts[sizeof(" anycast vltime 4294967295 pltime 4294967295")];
	struct in_addr in4dest;
	struct in6_addr in6dest;
	int pppoe = cand_ispppoe(ifname), bitlen;

	if (ip->family == AF_INET6 && cand_otherscope(&ip->addr.in6, ifname))
		return -1;
	cand_addrstr(ip->family, &ip->addr, ifname, addr, sizeof(addr));
	if (!set) {
		if (cand_setting(cand, ST_OFF, "inet %s", addr) == -1)
			return -1;
		return cand_upline(cand, ifname, 0);
	}
	if (pppoe ? cand_state(cand, "autoconf4") != ST_OFF :
	    ip->family == AF_INET && cand_state(cand, "autoconf4") == ST_ON) {
		printf("%% %s takes its %saddresses from %s,"
		    " set \"no autoconf4\" first\n", ifname,
		    pppoe ? "" : "IPv4 ", pppoe ? "IPCP" : "DHCP");
		return -1;
	}
	/* carpioctl() takes an address only once there is a carpdev (EINVAL) */
	if (cand_takes(ifname, SIOCSVH) &&
	    cand_line(cand, "carpdev", 0) == NULL) {
		printf("%% %s needs a carpdev before an address\n", ifname);
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
			if (cand_setting(cand, ST_ON, "inet %s%s%s", addr,
			    dest[0] ? " " : "", dest) == -1)
				return -1;
			break;
		}
		/* nor the broadcast address, which intip() checked */
		if (cand_setting(cand, ST_ON, "inet %s/%d", addr,
		    ip->bitlen) == -1)
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
			if (cand_setting(cand, ST_ON, "inet %s/%d%s", addr,
			    bitlen, opts) == -1)
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
		if (cand_setting(cand, ST_ON, "inet %s%s%s%s", addr,
		    dest[0] ? " " : "", dest, opts) == -1)
			return -1;
		break;
	default:
		printf("%% unknown address family: %d\n", ip->family);
		return -1;
	}
	return cand_upline(cand, ifname, 1);
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

static int xflags_set(int, int, char *, int, struct cand *);

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
	struct cand *cand;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	cand = va_arg(ap, struct cand *);
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

	flags = cand != NULL ? cand_getflags(ifname, ifs) :
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

	/* options follow the address and a destination or broadcast address */
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
			if (cand != NULL)
				return cand_noaf(cand, ifname,
				    strcmp(cmdname, "inet6") == 0 ?
				    AF_INET6 : AF_INET);
			return intaf(ifname, ifs, argc0, argv0);
		}

		/*
		 * The inet6 command allows for enabling IPv6 link-local.
		 */
		if (set && strcmp(cmdname, "inet6") == 0) {
			if (cand != NULL) {
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
		if (kf_dhcpleased()) {
			/*
			 * dhclient(8) has gone away as of OpenBSD 7.2+.
			 * dhcpleased(8) should always be running and will
			 * only take action once the autoconf4 flag is set.
			 */
			return xflags_set(IFXF_AUTOCONF4, set, ifname,
			    ifs, cand);
		} else {
			printf("%% cannot get DHCP leases because dhcpleased "
			    "is not running\n");
			return -1;
		}
	}

	/* Enable IPv6 SLAAC with "inet6 autoconf" and disable it with "no". */
	if (strcmp(cmdname, "inet6") == 0 && isprefix(argv[0], "autoconf"))
		return xflags_set(IFXF_AUTOCONF6, set, ifname, ifs, cand);

	memset(&ip, 0, sizeof(ip));
	parse_ip_pfx(argv[0], NO_NETMASK, &ip);

	if (ip.family == 0)
		/* bad IP specified */
		return -1;

	/* The inet6 command is IPv6-only. */
	if (strcmp(cmdname, "inet6") == 0 && ip.family != AF_INET6) {
		printf("%% %s is not a valid IPv6 address\n", argv[0]);
		return -1;
	}

	if (set && !(flags & IFF_POINTOPOINT) && ip.bitlen == -1) {
		printf("%% Netmask not specified\n");
		return -1;
	}
	/*
	 * The kernel takes an IPv4 prefix length of 0 as the address
	 * class's, and sets the broadcast address the mask makes,
	 * whatever is given (in_ifinit())
	 */
	if (set && ip.family == AF_INET && !(flags & IFF_POINTOPOINT)) {
		struct in_addr brd;

		if (ip.bitlen == 0) {
			printf("%% An IPv4 prefix length must be 1 or more\n");
			return -1;
		}
		if (argc == 2 && inet_pton(AF_INET, argv[1], &brd) == 1 &&
		    ntohl(brd.s_addr) != in4_brdaddr(ip.addr.in.s_addr,
		    htonl(0xffffffffULL << (32 - ip.bitlen)))) {
			printf("%% %s is not the broadcast address of %s/%d\n",
			    argv[1], argv[0], ip.bitlen);
			return -1;
		}
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
		if (cand == NULL && addaf(ifname, AF_INET6, ifs) == -1)
			return -1;
		if (ip6_eui64(ifname, &ip.addr.in6) == -1)
			return -1;
	}

	if (cand != NULL)
		return cand_ip(cand, ifname, set, flags, &ip, argc,
		    argv, msg, &o);

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
intipcp(char *ifname, int ifs, int argc, char **argv, struct cand *cand)
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

	return pppoe_ipcp(ifname, ifs, set, cand);
}

int
run_ipcp(char *ifname, int ifs, int set, struct cand *cand)
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

	return intipcp(ifname, ifs, argc_ipcp, argv_ipcp, cand);
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

/* 1 if ss holds an address, and a port when port is 1 (pflowvalidsockaddr()) */
static int
pflow_valid(struct sockaddr_storage *ss, int port)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	switch (ss->ss_family) {
	case AF_INET:
		return sin->sin_addr.s_addr != INADDR_ANY &&
		    (!port || sin->sin_port != 0);
	case AF_INET6:
		return !IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) &&
		    (!port || sin6->sin6_port != 0);
	}
	return 0;
}

/*
 * pflow in configure private. The line has the addresses as
 * pflow_status() prints them and the version; a version the command
 * leaves out is the candidate's, or the kernel's default.
 */
static int
cand_pflow(struct cand *cand, char *ifname, int set, struct pflowreq *preq)
{
	char src[PFLOW_ADDRSTRLEN], dst[PFLOW_ADDRSTRLEN], *l;
	const char *errmsg;
	int version = PFLOW_PROTO_DEFAULT;

	if (!cand_takes(ifname, SIOCSETPFLOW)) {
		printf("%% pflow not supported on %s\n", ifname);
		return -1;
	}
	if (!set)
		return cand_setting(cand, ST_DEFAULT, "pflow");
	/* intpflow_apply() has checked both addresses */
	pflow_addrstr(&preq->flowsrc, src);
	pflow_addrstr(&preq->flowdst, dst);
	if (preq->addrmask & PFLOW_MASK_VERSION)
		version = preq->version;
	else if ((l = cand_line(cand, "pflow", 0)) != NULL &&
	    (l = strrchr(l, ' ')) != NULL)
		version = strtonum(l + 1, PFLOW_PROTO_5, PFLOW_PROTO_MAX,
		    &errmsg);
	return cand_setting(cand, ST_ON,
	    "pflow sender %s receiver %s version %d", src, dst, version);
}

/*
 * pflow: the sender's address and the receiver's address and port, each
 * as "a.b.c.d:port" or "[v6addr]:port", and the version. "no pflow"
 * takes none
 */

int
intpflow_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	struct ifreq ifr;
	struct pflowreq preq;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	bzero(&preq, sizeof(struct pflowreq));
	ifr.ifr_data = (caddr_t)&preq;

	preq.addrmask = PFLOW_MASK_SRCIP | PFLOW_MASK_DSTIP;
	if (set) {
		args_sockaddr(&v[0], v[1].type != FACT_NONE ? v[1].v.i : 0,
		    &preq.flowsrc);
		args_sockaddr(&v[2], v[3].type != FACT_NONE ? v[3].v.i : 0,
		    &preq.flowdst);
		/*
		 * pflow_set() opens no socket without a receiver address
		 * and port, and sobind() refuses a sender of another
		 * family. conf_pflow() prints no line without a sender.
		 */
		if (!pflow_valid(&preq.flowsrc, 0)) {
			printf("%% pflow needs a sender address\n");
			return -1;
		}
		if (!pflow_valid(&preq.flowdst, 1)) {
			printf("%% pflow needs a receiver address and port\n");
			return -1;
		}
		if (preq.flowsrc.ss_family != preq.flowdst.ss_family) {
			printf("%% sender and receiver address families do not"
			    " match\n");
			return -1;
		}
		if (v[4].type != FACT_NONE) {
			preq.version = v[4].v.i;
			preq.addrmask |= PFLOW_MASK_VERSION;
			/* pflowioctl() takes these */
			if (preq.version != PFLOW_PROTO_5 &&
			    preq.version != PFLOW_PROTO_10) {
				printf("%% Invalid pflow version %d: 5 or 10\n",
				    preq.version);
				return -1;
			}
		}
	}

	if (cand != NULL)
		return cand_pflow(cand, ifname, set, &preq);

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
cand_patch(struct cand *cand, char *ifname, char *peer)
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
		if (!cand_hasif(cand, peer)) {
			printf("%% interface %s not found\n", peer);
			return -1;
		}
		if (!cand_takes(peer, SIOCSIFPAIR)) {
			printf("%% %s is not a pair interface\n", peer);
			return -1;
		}
		if ((l = cand_ifline(cand, peer, "patch", 0)) != NULL &&
		    strcmp(l + strlen("patch "), ifname) != 0) {
			printf("%% %s is patched to %s\n", peer,
			    l + strlen("patch "));
			return -1;
		}
	}
	old[0] = '\0';
	if ((l = cand_line(cand, "patch", 0)) != NULL)
		strlcpy(old, l + strlen("patch "), sizeof(old));
	if (old[0] != '\0' && (peer == NULL || strcmp(old, peer) != 0) &&
	    cand_ifsetting(cand, old, ST_DEFAULT, "patch") == -1)
		return -1;
	if (peer == NULL)
		return cand_setting(cand, ST_DEFAULT, "patch");
	if (cand_setting(cand, ST_ON, "patch %s", peer) == -1)
		return -1;
	return cand_ifsetting(cand, peer, ST_ON, "patch %s", ifname);
}

int
intpatch_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	struct ifreq ifr;
	char pair[IFNAMSIZ] = "";

	if (set)
		args_string(&v[0], pair, sizeof(pair));
	if (cand != NULL)
		return cand_patch(cand, ifname, set ? pair : NULL);

	bzero(&ifr, sizeof(ifr));

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (set) {
		if ((ifr.ifr_index = if_nametoindex(pair)) == 0) {
			printf("%% invalid interface %s\n", pair);
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
intmtu_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	struct ifreq ifr;
	int max;

	/* nor has a default to go back to */
	if (default_mtu(ifname) == MTU_IGNORE) {
		printf("%% The configuration does not manage the mtu of %s\n",
		    ifname);
		return -1;
	}
	ifr.ifr_mtu = set ? v[0].v.i : default_mtu(ifname);
	/* sppp takes 128 or more, and pppoe no more than its dev allows */
	if (strncmp(ifname, "pppoe", strlen("pppoe")) == 0) {
		max = pppoe_maxmtu(ifs, ifname, cand);
		if (ifr.ifr_mtu < 128 || ifr.ifr_mtu > max) {
			printf("%% %s takes an mtu of 128 to %d\n", ifname,
			    max);
			return -1;
		}
	}

	if (cand != NULL) {
		if (conf_mtu_shown(ifname, ifr.ifr_mtu))
			return cand_setting(cand, ST_ON, "mtu %d", ifr.ifr_mtu);
		return cand_setting(cand, ST_DEFAULT, "mtu");
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFMTU, (caddr_t)&ifr) < 0) {
		printf("%% intmtu: SIOCSIFMTU: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intkeepalive_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	struct ifkalivereq ikar;

	bzero(&ikar, sizeof(ikar));
	if (set) {
		ikar.ikar_timeo = v[0].v.i;
		ikar.ikar_cnt = v[1].v.i;
	}

	if (cand != NULL) {
		if (!cand_takes(ifname, SIOCSETKALIVE)) {
			printf("%% Keepalive not available on %s\n", ifname);
			return -1;
		}
		if (set)
			return cand_setting(cand, ST_ON, "keepalive %d %d",
			    ikar.ikar_timeo, ikar.ikar_cnt);
		return cand_setting(cand, ST_DEFAULT, "keepalive");
	}

	strlcpy(ikar.ikar_name, ifname, sizeof(ikar.ikar_name));
	if (ioctl_down(ifs, ifname, SIOCSETKALIVE, (caddr_t)&ikar) < 0) {
		if (errno == ENOTTY)
			printf("%% Keepalive not available on %s\n", ifname);
		else
			printf("%% intkeepalive: SIOCSETKALIVE: %s\n",
			    strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * The drivers whose SIOCSTXHPRIO and SIOCSRXHPRIO refuse payload
 * (if_txhprio_l2_check(), if_rxhprio_l2_check()). They carry Ethernet,
 * which has no IP header to take a priority from or to give one to.
 */
static const char *l2hprios[] = {
	"bpe", "egre", "eoip", "etherip", "mpw", "nvgre", "svlan", "veb",
	"vlan", "vxlan"
};

/* A txprio or rxprio line, as conf_ifmetrics() prints it */
static int
cand_hdrprio(struct cand *cand, char *name, int prio, int def)
{
	if (prio == def)
		return cand_setting(cand, ST_DEFAULT, "%s", name);
	switch (prio) {
	case IF_HDRPRIO_PACKET:
		return cand_setting(cand, ST_ON, "%s packet", name);
	case IF_HDRPRIO_PAYLOAD:
		return cand_setting(cand, ST_ON, "%s payload", name);
	case IF_HDRPRIO_OUTER:
		return cand_setting(cand, ST_ON, "%s outer", name);
	}
	return cand_setting(cand, ST_ON, "%s %d", name, prio);
}

/* intmpls() in configure private */
static int
cand_mpls(struct cand *cand, char *ifname, int type, int set, struct ifreq *ifr,
    struct shim_hdr *shim)
{
	switch (type) {
	case MPLSLABEL:
		if (set)
			return cand_setting(cand, ST_ON, "mplslabel %u",
			    shim->shim_label);
		return cand_setting(cand, ST_DEFAULT, "mplslabel");
	case TUNNELDOMAIN:
		if (ifr->ifr_rdomainid != 0)
			return cand_setting(cand, ST_ON, "tunneldomain %d",
			    ifr->ifr_rdomainid);
		return cand_setting(cand, ST_DEFAULT, "tunneldomain");
	case TXPRIO:
		return cand_hdrprio(cand, "txprio", ifr->ifr_hdrprio,
		    default_txprio(ifname));
	case RXPRIO:
		return cand_hdrprio(cand, "rxprio", ifr->ifr_hdrprio,
		    default_rxprio(ifname));
	}
	printf("%% cand_mpls: Internal error\n");
	return -1;
}

/* from ifconfig.c */
int
intmpls_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	size_t i;
	unsigned long cmd;
	struct ifreq ifr;
	struct shim_hdr shim;
	int type;

	bzero(&ifr, sizeof(ifr));
	bzero(&shim, sizeof(shim));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	type = c->code;
	switch (type) {
	case MPLSLABEL:
		if (set) {
			ifr.ifr_data = (caddr_t)&shim;
			shim.shim_label = v[0].v.i;
			cmd = SIOCSETLABEL;
		} else
			cmd = SIOCDELLABEL;
		break;
	case TUNNELDOMAIN:
		ifr.ifr_rdomainid = set ? v[0].v.i : 0;
		/* SIOCSLIFPHYRTABLE needs the table (EINVAL) */
		if (set && !rtable_there(ifr.ifr_rdomainid, cand))
			return -1;
		cmd = SIOCSLIFPHYRTABLE;
		break;
	case TXPRIO:
		ifr.ifr_hdrprio = set ? v[0].v.i : default_txprio(ifname);
		cmd = SIOCSTXHPRIO;
		break;
	default:
		ifr.ifr_hdrprio = set ? v[0].v.i : default_rxprio(ifname);
		cmd = SIOCSRXHPRIO;
		break;
	}
	if ((cmd == SIOCSTXHPRIO || cmd == SIOCSRXHPRIO) &&
	    ifr.ifr_hdrprio == IF_HDRPRIO_PAYLOAD)
		for (i = 0; i < nitems(l2hprios); i++)
			if (isprefix((char *)l2hprios[i], ifname)) {
				printf("%% %s takes no %s payload\n", ifname,
				    c->name);
				return -1;
			}

	if (cand != NULL) {
		if (!cand_takes(ifname, cmd)) {
			printf("%% %s not supported on %s\n", c->name, ifname);
			return -1;
		}
		return cand_mpls(cand, ifname, type, set, &ifr, &shim);
	}

	if (ioctl_down(ifs, ifname, cmd, (caddr_t)&ifr) < 0) {
		if (errno == ENOTTY)
			printf("%% MPLS not supported on %s\n", ifname);
		else
			printf("%% intmpls: ioctl: %s\n",
			    strerror(errno));
		return -1;
	}

	return (0);
}

/*
 * 1 if ss is a unicast address, else 0. mpw_set_neighbor() refuses any
 * other neighbor (EINVAL).
 */
static int
pwe3_unicast(struct sockaddr_storage *ss)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	if (ss->ss_family == AF_INET)
		return sin->sin_addr.s_addr != INADDR_ANY &&
		    !IN_MULTICAST(ntohl(sin->sin_addr.s_addr));
	return !IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) &&
	    !IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr);
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
cand_pwe3(struct cand *cand, char *ifname, int set, int nei, int cw, int fat,
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
	if ((l = cand_line(cand, "pwe", 0)) != NULL) {
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
		return cand_setting(cand, ST_DEFAULT, "pwe");
	return cand_setting(cand, ST_ON, "pwe%s%s%s", neighbor,
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

/*
 * pwe: cw, fat, and the neighbor's label and address, in any order
 * (intpwe3_parse()). A "no" line names what it takes away, and has no
 * label or address
 */
static struct nopts pwe3opts[] = {
	{ "cw",		no_arg,		'c' },
	{ "fat",	no_arg,		'f' },
	{ "neighbor",	req_2arg,	'n' },
	{ NULL,		0,		0 }
};

/* pwe's words, as nopt() reads them, into its values */
int
intpwe3_parse(const struct argcmd *c, int argc, char **argv,
    struct argvals *a)
{
	int ch;

	if (argc < 1) {
		pwe3usage();
		return -1;
	}
	noptind = 0;
	while ((ch = nopt(argc, argv, pwe3opts)) != -1)
		switch (ch) {
		case 'c':	/* cw */
			facts_i64(&a->v[0], 1);
			break;
		case 'f':	/* fat */
			facts_i64(&a->v[1], 1);
			break;
		case 'n':	/* neighbor */
			facts_i64(&a->v[2], 1);
			if (a->set && (args_word(c, &c->args[4], a,
			    argv[noptind - 1], &a->v[4]) == -1 ||
			    args_word(c, &c->args[3], a, argv[noptind - 2],
			    &a->v[3]) == -1))
				return -1;
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
	return 0;
}

int
intpwe3_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	int cw = -1, fat = -1, nei = v[2].type != FACT_NONE;
	char host[NI_MAXHOST];
	struct ifreq ifr;
	struct if_laddrreq req;
	struct sockaddr_mpls *smpls = (struct sockaddr_mpls *)&req.dstaddr;

	bzero(&ifr, sizeof(ifr));
	bzero(&req, sizeof(req));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	strlcpy(req.iflr_name, ifname, IFNAMSIZ);
	if (v[0].type != FACT_NONE)
		cw = set;
	if (v[1].type != FACT_NONE)
		fat = set;
	if (nei && set) {
		if (v[3].type == FACT_NONE || v[4].type == FACT_NONE) {
			printf("%% pwe neighbor <neighbor label> "
			    "<neighbor ip>\n");
			return -1;
		}
		smpls->smpls_len = sizeof(*smpls);
		smpls->smpls_family = AF_MPLS;
		smpls->smpls_label = v[3].v.i;
		args_sockaddr(&v[4], 0, &req.addr);
		if (!pwe3_unicast(&req.addr)) {
			if (getnameinfo((struct sockaddr *)&req.addr,
			    req.addr.ss_len, host, sizeof(host), NULL, 0,
			    NI_NUMERICHOST) != 0)
				strlcpy(host, "?", sizeof(host));
			printf("%% neighbor %s is not a unicast address\n",
			    host);
			return -1;
		}
	}

	if (cand != NULL)
		return cand_pwe3(cand, ifname, set, nei, cw, fat, &req);

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

/* dhcrelay: the IPv4 address of the server to relay to */

int
intdhcrelay_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	char *cmd[] = { DHCRELAY, "-i", NULL, NULL, NULL };
	char server[INET_ADDRSTRLEN];
	int alen, r, given = v[0].type != FACT_NONE;

	cmd[2] = ifname;
	if (given) {
		inet_ntop(AF_INET, v[0].v.a.bytes, server, sizeof(server));
		cmd[3] = server;
	}

	if (cand != NULL) {
		char *l;

		if (set)
			return cand_setting(cand, ST_ON, "dhcrelay %s", server);
		if ((l = cand_line(cand, "dhcrelay", 0)) == NULL) {
			printf("%% No relay configured for %s\n", ifname);
			return -1;
		}
		l += strlen("dhcrelay ");
		if (given && strcmp(l, server) != 0) {
			printf("%% Server expected: %s (not %s)\n", l, server);
			return -1;
		}
		return cand_setting(cand, ST_DEFAULT, "dhcrelay");
	}

	if (set) {
		/* kept only once it runs */
		if (cmdargs(DHCRELAY, cmd) != 0)
			return -1;
		if (flag_x("dhcrelay", ifname, DB_X_ENABLE, server) == -1)
			return -1;
	} else {
		char was[24], argue[SIZE_CONF_TEMP];
		char *killcmd[] = { PKILL, "-xf", NULL, NULL };

		if ((alen = conf_dhcrelay(ifname, was, sizeof(was))) < 1)
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
		if (given && strcmp(was, server) != 0) {
			printf("%% Server expected: %s (not %s)\n", was,
			    server);
			return -1;
		}

		if (flag_x("dhcrelay", ifname, DB_X_REMOVE, NULL) == -1)
			return -1;

		/* setup argument list as one argument for pkill -xf */
		snprintf(argue, sizeof(argue), "%s %s %s %s", cmd[0], cmd[1],
		    cmd[2], was);
		killcmd[2] = argue;

		/* pkill exits 1 if no dhcrelay was running */
		r = cmdargs(PKILL, killcmd);
		if (r == -1 || r > 1)
			return -1;
	}
	return 0;
}

/*
 * Refuse a dhcrelay6 destination, dest, whose interface, dev, is not
 * there, or is in another rdomain than ifname's, because the relay's
 * routing table cannot reach it.
 */
static int
dhcrelay6_dest(char *ifname, int ifs, char *dest, char *dev, struct cand *cand)
{
	char *l;
	int rd, devrd;

	if (cand != NULL) {
		if (!cand_hasif(cand, dev)) {
			printf("%% %s: no interface %s\n", dest, dev);
			return -1;
		}
		l = cand_line(cand, "rdomain", 0);
		rd = l != NULL ? atoi(l + strlen("rdomain ")) : 0;
		l = cand_ifline(cand, dev, "rdomain", 0);
		devrd = l != NULL ? atoi(l + strlen("rdomain ")) : 0;
	} else {
		if (!is_valid_ifname(dev)) {
			printf("%% %s: no interface %s\n", dest, dev);
			return -1;
		}
		rd = get_rdomain(ifs, ifname);
		devrd = get_rdomain(ifs, dev);
	}
	if (rd != devrd) {
		printf("%% %s: %s is in rdomain %d, and %s in rdomain %d\n",
		    dest, dev, devrd, ifname, rd);
		return -1;
	}
	return 0;
}

/*
 * dhcrelay6 relays the DHCPv6 requests that ifname hears. Each
 * destination is an interface, or an IPv6 address, a %, and the
 * interface to send on. dhcrelay6 has no rdomain code of its own, so
 * nsh starts it in the routing table of ifname's rdomain, and each
 * destination's interface must be in that rdomain too. Setting
 * dhcrelay6 again stops the relay that runs before it starts the new
 * one, so a commit can start it again after a new rdomain. Its values:
 * each destination's interface, and the address of each that has one
 * (intdhcrelay6_parse())
 */

/*
 * dhcrelay6's destinations, which dhcrelay6 would refuse unless each is
 * an interface, or an IPv6 address, a % and an interface
 */
int
intdhcrelay6_parse(const struct argcmd *c, int argc, char **argv,
    struct argvals *a)
{
	char addr[INET6_ADDRSTRLEN], *l;
	struct in6_addr in6;
	size_t len;
	int i;

	if ((a->set && argc < 1) || argc > DHCRELAY6_DESTS) {
		printf("%% dhcrelay6 <destination> [destination ...]\n");
		printf("%% no dhcrelay6 [destination ...]\n");
		printf("%% at most %d destinations\n", DHCRELAY6_DESTS);
		return -1;
	}
	for (i = 0; i < argc; i++) {
		if ((l = strchr(argv[i], '%')) != NULL) {
			/* the address before the %, and the interface after */
			len = l - argv[i];
			if (len < sizeof(addr)) {
				memcpy(addr, argv[i], len);
				addr[len] = '\0';
			}
			if (len >= sizeof(addr) || inet_pton(AF_INET6, addr,
			    &in6) != 1) {
				printf("%% %s: not an IPv6 address, a %% and "
				    "an interface\n", argv[i]);
				return -1;
			}
			facts_address(&a->v[DHCRELAY6_DESTS + i], FACT_INET6,
			    &in6, sizeof(in6), 0);
			l++;
		} else if (inet_pton(AF_INET6, argv[i], &in6) == 1) {
			printf("%% %s: an address needs a %% and the "
			    "interface to send on\n", argv[i]);
			return -1;
		} else
			l = argv[i];
		if (args_word(c, &c->args[0], a, l, &a->v[i]) == -1)
			return -1;
	}
	return 0;
}

int
intdhcrelay6_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	char *cmd[7 + DHCRELAY6_DESTS + 1] = { ROUTE, "-T", NULL, "exec",
	    DHCRELAY6, "-i", NULL };
	char *killcmd[] = { PKILL, "-xf", NULL, NULL };
	char dest[DHCRELAY6_DESTS][64], dests[sizeof(dest)], was[sizeof(dests)];
	char argue[sizeof(dests) + 64], rd[16], dev[IFNAMSIZ];
	char addr[INET6_ADDRSTRLEN], *l;
	int i, n, r, rdomain;

	dests[0] = '\0';
	for (n = 0; n < DHCRELAY6_DESTS && v[n].type != FACT_NONE; n++) {
		args_string(&v[n], dev, sizeof(dev));
		if (v[DHCRELAY6_DESTS + n].type != FACT_NONE) {
			inet_ntop(AF_INET6, v[DHCRELAY6_DESTS + n].v.a.bytes,
			    addr, sizeof(addr));
			snprintf(dest[n], sizeof(dest[n]), "%s%%%s", addr, dev);
		} else
			strlcpy(dest[n], dev, sizeof(dest[n]));
		if (dhcrelay6_dest(ifname, ifs, dest[n], dev, cand) == -1)
			return -1;
		if (n > 0)
			strlcat(dests, " ", sizeof(dests));
		strlcat(dests, dest[n], sizeof(dests));
	}
	for (i = n; i < DHCRELAY6_DESTS; i++)
		if (v[DHCRELAY6_DESTS + i].type != FACT_NONE) {
			printf("%% dhcrelay6: an address without its "
			    "interface\n");
			return -1;
		}

	if (cand != NULL) {
		if (set)
			return cand_setting(cand, ST_ON, "dhcrelay6 %s", dests);
		if ((l = cand_line(cand, "dhcrelay6", 0)) == NULL) {
			printf("%% No DHCPv6 relay configured for %s\n", ifname);
			return -1;
		}
		l += strlen("dhcrelay6 ");
		if (n && strcmp(l, dests) != 0) {
			printf("%% Destinations expected: %s (not %s)\n", l,
			    dests);
			return -1;
		}
		return cand_setting(cand, ST_DEFAULT, "dhcrelay6");
	}

	/* stop the relay that runs, if any */
	if (conf_dhcrelay6(ifname, was, sizeof(was)) > 0) {
		if (!set && n && strcmp(was, dests) != 0) {
			printf("%% Destinations expected: %s (not %s)\n", was,
			    dests);
			return -1;
		}
		/* as one argument for pkill -xf */
		snprintf(argue, sizeof(argue), "%s -i %s %s", DHCRELAY6,
		    ifname, was);
		killcmd[2] = argue;
		/* pkill exits 1 if no dhcrelay6 was running */
		r = cmdargs(PKILL, killcmd);
		if (r == -1 || r > 1)
			return -1;
		if (flag_x("dhcrelay6", ifname, DB_X_REMOVE, NULL) == -1)
			return -1;
	} else if (!set) {
		printf("%% No DHCPv6 relay configured for %s\n", ifname);
		return -1;
	}
	if (!set)
		return 0;

	if ((rdomain = get_rdomain(ifs, ifname)) == -1) {
		printf("%% %s: rdomain: %s\n", ifname, strerror(errno));
		return -1;
	}
	snprintf(rd, sizeof(rd), "%d", rdomain);
	cmd[2] = rd;
	cmd[6] = ifname;
	for (i = 0; i < n; i++)
		cmd[7 + i] = dest[i];
	/* kept only once it runs */
	if (cmdargs(ROUTE, cmd) != 0)
		return -1;
	return flag_x("dhcrelay6", ifname, DB_X_ENABLE, dests);
}

int
intmetric_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	struct ifreq ifr;

	ifr.ifr_metric = set ? v[0].v.i : 0;
	if (cand != NULL) {
		if (ifr.ifr_metric != 0)
			return cand_setting(cand, ST_ON, "%s %d", c->name,
			    ifr.ifr_metric);
		return cand_setting(cand, ST_DEFAULT, "%s", c->name);
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, c->code == IFPRIORITY ? SIOCSIFPRIORITY : SIOCSIFMETRIC,
	    (caddr_t)&ifr) < 0) {
		printf("%% intmetric: SIOCSIF%s: %s\n", c->name,
		    strerror(errno));
		return -1;
	}

	return 0;
}

int
intllprio_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	struct ifreq ifr;

	ifr.ifr_llprio = set ? v[0].v.i : default_llpriority(ifname);
	if (cand != NULL) {
		if (ifr.ifr_llprio != default_llpriority(ifname))
			return cand_setting(cand, ST_ON, "llpriority %d",
			    ifr.ifr_llprio);
		return cand_setting(cand, ST_DEFAULT, "llpriority");
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFLLPRIO, (caddr_t)&ifr) < 0) {
		printf("%% intllprio: SIOCSIFLLPRIO: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intgroup_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	int i, n, r = 0;
	struct ifgroupreq ifgr;
	char group[GROUP_NAMES][IFNAMSIZ], groups[GROUP_NAMES * IFNAMSIZ] = "";

	for (n = 0; n < GROUP_NAMES && v[n].type != FACT_NONE; n++)
		args_string(&v[n], group[n], sizeof(group[n]));
	for (i = 0; i < n; i++) {
		/* the kernel keeps every interface in all, and egress */
		if (set && (strcmp(group[i], "all") == 0 ||
		    strcmp(group[i], "egress") == 0)) {
			printf("%% The kernel keeps group %s\n", group[i]);
			return -1;
		}
		if (isdigit((unsigned char)group[i][strlen(group[i]) - 1])) {
			printf("%% Group names may not end with a digit\n");
			return -1;
		}
	}

	if (cand != NULL) {
		for (i = 0; i < n; i++) {
			if (i > 0)
				strlcat(groups, " ", sizeof(groups));
			strlcat(groups, group[i], sizeof(groups));
		}
		return cand_setting(cand, set ? ST_ON : ST_OFF,
		    "group %s", groups);
	}

	for (i = 0; i < n; i++) {
		bzero(&ifgr, sizeof(ifgr));
		strlcpy(ifgr.ifgr_name, ifname, IFNAMSIZ);
		strlcpy(ifgr.ifgr_group, group[i], IFNAMSIZ);

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
intrtlabel_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	struct ifreq ifr;
	char label[RTLABEL_LEN] = "";

	if (set)
		args_string(&v[0], label, sizeof(label));
	if (cand != NULL) {
		if (set)
			return cand_setting(cand, ST_ON, "rtlabel %s", label);
		return cand_setting(cand, ST_DEFAULT, "rtlabel");
	}

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_data = (caddr_t)label;
	if (ioctl(ifs, SIOCSIFRTLABEL, &ifr) == -1) {
		printf("%% intrtlabel: SIOCSIFRTLABEL: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intparent_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	unsigned long cmd;
	struct if_parent ifp;
	char parent[IFNAMSIZ] = "";

	bzero(&ifp, sizeof(ifp));
	strlcpy(ifp.ifp_name, ifname, IFNAMSIZ);
	if (set) {
		args_string(&v[0], parent, sizeof(parent));
		strlcpy(ifp.ifp_parent, parent, sizeof(ifp.ifp_parent));
	}

	cmd = (set ? SIOCSIFPARENT : SIOCDIFPARENT);
	if (cand != NULL) {
		if (!cand_takes(ifname, cmd)) {
			printf("%% parent not supported on %s\n", ifname);
			return -1;
		}
		if (!set)
			return cand_setting(cand, ST_DEFAULT, "parent");
		if (strcmp(parent, ifname) == 0) {
			printf("%% %s cannot be its own parent\n", ifname);
			return -1;
		}
		if (!cand_hasif(cand, parent)) {
			printf("%% interface %s not found\n", parent);
			return -1;
		}
		/* a parent's TCP large receive offload goes off */
		if (cand_ifsetting(cand, parent, ST_DEFAULT, "tcplro") == -1)
			return -1;
		return cand_setting(cand, ST_ON, "parent %s", parent);
	}
	if (ioctl_down(ifs, ifname, cmd, &ifp) == -1) {
		printf("%% intparent: SIOC%sIFPARENT: %s\n",
		    set ? "S" : "D", strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * intflags() in configure private: the lines conf_ifflags() would
 * print once the flag is set or cleared.
 */
static int
cand_ifflags(struct cand *cand, char *ifname, int value, int set)
{
	switch (value) {
	case IFF_DEBUG:
		return cand_setting(cand, set ? ST_ON : ST_OFF, "debug");
	case IFF_STATICARP:
		if (!set)
			return cand_setting(cand, ST_OFF, "staticarp");
		/* static ARP turns ARP back on, as below */
		if (cand_setting(cand, ST_ON, "arp") == -1)
			return -1;
		return cand_setting(cand, ST_ON, "staticarp");
	case -IFF_NOARP:
		if (set)
			return cand_setting(cand, ST_ON, "arp");
		/* turning ARP off turns static ARP off too */
		if (cand_setting(cand, ST_OFF, "staticarp") == -1)
			return -1;
		return cand_setting(cand, ST_OFF, "arp");
	case -IFF_UP:
		if (set)
			return cand_setting(cand, ST_ON, "shutdown");
		/* pfsync_up() needs a syncdev (ENXIO) */
		if (cand_takes(ifname, SIOCSETPFSYNC) &&
		    cand_line(cand, "syncdev", 0) == NULL) {
			printf("%% %s needs a syncdev to come up\n", ifname);
			return -1;
		}
		return cand_upline(cand, ifname, 1);
	}
	printf("%% cand_ifflags: value internal error\n");
	return -1;
}

int
intflags_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	/* a negative flag is one the command clears (shutdown clears IFF_UP) */
	int value = c->code, flags, iftype;

	/*
	 * wg(4) sets IFF_NOARP by default and this should not be changed.
	 * The kernel doesn't prevent this flag from being cleared (as of 7.2).
	 */
	iftype = cand != NULL ? cand_gettype(cand, ifname) :
	    get_ifdata(ifname, IFDATA_IFTYPE);
	if (iftype == IFT_WIREGUARD &&
	    (value == -IFF_NOARP || value == IFF_STATICARP)) {
		printf("%% wireguard interfaces do not support ARP\n");
		return -1;
	}

	if (cand != NULL)
		return cand_ifflags(cand, ifname, value, set);

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
cand_autoconf4(struct cand *cand, char *ifname, int set)
{
	int pppoe = cand_ispppoe(ifname), was = cand_state(cand, "autoconf4");

	if (set && cand_hasaddr(cand, pppoe ? 0 : AF_INET)) {
		printf("%% Remove the %saddresses of %s first\n",
		    pppoe ? "" : "IPv4 ", ifname);
		return -1;
	}
	if (pppoe)
		return cand_setting(cand, set ? ST_ON : ST_OFF, "autoconf4");
	if (cand_setting(cand, set ? ST_ON : ST_DEFAULT, "autoconf4") == -1)
		return -1;
	return cand_upline(cand, ifname, set && was != ST_ON);
}

/* intxflags() in configure private, for the flags conf_ifxflags() prints */
static int
cand_ifxflags(struct cand *cand, char *ifname, int value, int set)
{
	char *name, *owner;
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
	case -IFXF_INET6_NOSOII:
		name = "soii";
		break;
	case IFXF_MONITOR:
		name = "monitor";
		break;
	case IFXF_LRO:
		/* SIOCSIFXFLAGS: ENOTSUP without IFCAP_LRO, EBUSY on a port */
		if (set && (kf_index(ifname) == 0 ||
		    !(kf_caps(ifname) & IFCAP_LRO))) {
			printf("%% %s does not support TCP large receive "
			    "offload\n", ifname);
			return -1;
		}
		if (set &&
		    ((owner = cand_listowner(cand, ifname, "member",
		    ifname)) != NULL ||
		    (owner = cand_listowner(cand, ifname, "span",
		    ifname)) != NULL)) {
			printf("%% %s is a port of %s, which turns its TCP "
			    "large receive offload off\n", ifname, owner);
			return -1;
		}
		name = "tcplro";
		break;
	case IFXF_WOL:
		/* SIOCSIFXFLAGS: ENOTSUP without IFCAP_WOL */
		if (set && kf_index(ifname) != 0 &&
		    !(kf_caps(ifname) & IFCAP_WOL)) {
			printf("%% %s does not support wake on LAN\n", ifname);
			return -1;
		}
		name = "wol";
		break;
	default:
		printf("%% cand_ifxflags: value internal error\n");
		return -1;
	}
	was = cand_state(cand, name);
	if (cand_setting(cand, set ? ST_ON : ST_OFF, "%s", name) == -1)
		return -1;
	if (set && was != ST_ON &&
	    (value == IFXF_AUTOCONF6 || value == IFXF_AUTOCONF6TEMP))
		return cand_upline(cand, ifname, 1);
	return 0;
}

/*
 * Set an extended flag, or clear it. A negative one is a flag the kernel
 * holds the other way: soii is on unless IFXF_INET6_NOSOII is
 */
static int
xflags_set(int value, int set, char *ifname, int ifs, struct cand *cand)
{
	int flags;

	if (value == IFXF_AUTOCONF4) {
		if (cand != NULL)
			return cand_autoconf4(cand, ifname, set);
		/* Have "autoconf4" on pppoe(4) do the right thing. */
		if (is_pppoe(ifname, ifs))
			return run_ipcp(ifname, ifs, set, cand);
	}
	if (cand != NULL)
		return cand_ifxflags(cand, ifname, value, set);

	flags = get_ifxflags(ifname, ifs);
	/* a pseudo interface would turn its parent's on: set that one */
	if (value == IFXF_LRO && set && (flags & IFXF_CLONED)) {
		printf("%% %s does not support TCP large receive offload\n",
		    ifname);
		return -1;
	}
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

/* its row's code is the flag (commands.c) */
int
intxflags_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	return xflags_set(c->code, set, ifname, ifs, cand);
}

/* The link flags the candidate's link line sets */
static int
cand_linkflags(struct cand *cand)
{
	char line[sizeof("link 0 1 2")], *l, *w, *p;
	int flags = 0;

	if ((l = cand_line(cand, "link", 0)) == NULL)
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
intlink_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	int flags, bits;

	flags = cand != NULL ? cand_linkflags(cand) : get_ifflags(ifname, ifs);
	/* "no link" with no flags clears every link flag */
	bits = v[0].type != FACT_NONE ? v[0].v.i :
	    IFF_LINK0 | IFF_LINK1 | IFF_LINK2;
	if (set)
		flags |= bits;
	else
		flags &= ~bits;

	if (cand != NULL) {
		if (!(flags & (IFF_LINK0|IFF_LINK1|IFF_LINK2)))
			return cand_setting(cand, ST_DEFAULT, "link");
		return cand_setting(cand, ST_ON, "link%s%s%s",
		    flags & IFF_LINK0 ? " 0" : "",
		    flags & IFF_LINK1 ? " 1" : "",
		    flags & IFF_LINK2 ? " 2" : "");
	}

	return set_ifflags(ifname, ifs, flags);
}

/* nwid: the network ID, text or 0x and hex digits (get_string()) */

int
intnwid_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	struct ieee80211_nwid nwid;
	struct ifreq ifr;
	int len = 0;	/* no nwid: nwid "" */

	memset(&nwid, 0, sizeof(nwid));
	if (set) {
		len = v[0].v.str.len;
		memcpy(nwid.i_nwid, v[0].v.str.s, len);
	}

	if (cand != NULL)
		return cand_nwid(cand, ifname, nwid.i_nwid, len);

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
intpowersave_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	struct ieee80211_power power;
	int maxsleep;

	maxsleep = v[0].type != FACT_NONE ? v[0].v.i : DEFAULT_POWERSAVE;

	if (cand != NULL)
		return cand_powersave(cand, ifname, set, maxsleep);

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
 * when it differs from the one the interface had, which
 * intlladdr_apply() keeps in the database when it first changes it. The
 * kernel takes an address only for an Ethernet interface.
 */
static int
cand_lladdr(struct cand *cand, char *ifname, struct ether_addr *ea)
{
	char addr[sizeof("00:00:00:00:00:00")], *cur;
	int same = 0;

	if (ea == NULL)
		return cand_setting(cand, ST_DEFAULT, "lladdr");
	if (cand_gettype(cand, ifname) != IFT_ETHER) {
		printf("%% %s has no Ethernet address to set\n", ifname);
		return -1;
	}
	strlcpy(addr, ether_ntoa(ea), sizeof(addr));
	if (kf_index(ifname) != 0)
		same = (cur = kf_lladdr(ifname)) != NULL &&
		    strcmp(cur, addr) == 0;
	if (same)
		return cand_setting(cand, ST_DEFAULT, "lladdr");
	return cand_setting(cand, ST_ON, "lladdr %s", addr);
}

/*
 * lladdr: a MAC address, or random, for which config makes one
 * (intlladdr_parse()). "no lladdr" puts back the one the interface had
 */

/*
 * lladdr's address, or a random one for random. The kernel takes no
 * multicast address (EINVAL), and conf_lladdr() prints no zero one
 */
int
intlladdr_parse(const struct argcmd *c, int argc, char **argv,
    struct argvals *a)
{
	struct ether_addr ea;
	int i;

	if (a->set && argc < 1) {
		printf ("%% lladdr <link level address|random>\n");
		printf ("%% no lladdr\n");
		return -1;
	}
	if (!a->set)
		return 0;
	if (isprefix(argv[0], "random")) {
		arc4random_buf(&ea, sizeof(ea));
		ea.ether_addr_octet[0] &= 0xfc;
		facts_address(&a->v[0], FACT_LINK, &ea, sizeof(ea), 0);
		return 0;
	}
	if (args_word(c, &c->args[0], a, argv[0], &a->v[0]) == -1)
		return -1;
	memcpy(&ea, a->v[0].v.a.bytes, sizeof(ea));
	if (ETHER_IS_MULTICAST(ea.ether_addr_octet)) {
		printf("%% %s is a multicast address\n", argv[0]);
		return -1;
	}
	for (i = 0; i < ETHER_ADDR_LEN && ea.ether_addr_octet[i] == 0; i++)
		;
	if (i == ETHER_ADDR_LEN) {
		printf("%% The configuration does not keep a zero lladdr\n");
		return -1;
	}
	return 0;
}

int
intlladdr_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	StringList *hwdaddr;
	char *lladdr, llorig[sizeof("00:00:00:00:00:00") + 1];
	struct ether_addr *addr, ea;
	struct ifreq ifr;

	if (set)
		memcpy(&ea, v[0].v.a.bytes, sizeof(ea));
	if (cand != NULL)
		return cand_lladdr(cand, ifname, set ? &ea : NULL);

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

	if (set)
		addr = &ea;
	else if ((addr = ether_aton(llorig)) == NULL) {
		printf("%% database corrupted, unable to "
		    " retrieve original lladdr\n");
		return -1;
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
intrdomain_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	int unit, cur;
	const char *errmsg = NULL;
	struct ifreq ifr, cur_ifr;
	char *l;

	ifr.ifr_rdomainid = set ? v[0].v.i : 0;
	/*
	 * Each rdomain has its own loopback, lo<rdomain>, which
	 * if_setrdomain() keeps in it (EPERM)
	 */
	unit = strncmp(ifname, "lo", 2) == 0 ?
	    strtonum(ifname + 2, 0, RT_TABLEID_MAX, &errmsg) : -1;
	if (unit != -1 && errmsg == NULL) {
		if (cand != NULL)
			cur = (l = cand_line(cand, "rdomain", 0)) != NULL ?
			    atoi(l + strlen("rdomain ")) : 0;
		else {
			bzero(&cur_ifr, sizeof(cur_ifr));
			strlcpy(cur_ifr.ifr_name, ifname,
			    sizeof(cur_ifr.ifr_name));
			cur = ioctl(ifs, SIOCGIFRDOMAIN, &cur_ifr) == 0 ?
			    cur_ifr.ifr_rdomainid : -1;
		}
		if (cur == unit && ifr.ifr_rdomainid != unit) {
			printf("%% %s is the loopback of rdomain %d, and stays"
			    " in it\n", ifname, unit);
			return -1;
		}
	}
	if (cand != NULL) {
		if (ifr.ifr_rdomainid > 0)
			return cand_setting(cand, ST_ON, "rdomain %d",
			    ifr.ifr_rdomainid);
		return cand_setting(cand, ST_DEFAULT, "rdomain");
	}
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFRDOMAIN, &ifr) < 0) {
		printf("%% intrdomain: SIOCSIFRDOMAIN: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intdesc_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	char desc[IFDESCRSIZE] = "";
	struct ifreq ifr;

	if (set)
		args_string(&v[0], desc, sizeof(desc));
	if (cand != NULL) {
		if (set && desc[0] != '\0')
			return cand_setting(cand, ST_ON,
			    "description %s", desc);
		return cand_setting(cand, ST_OFF, "description");
	}

	ifr.ifr_data = (caddr_t)&desc;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFDESCR, &ifr) < 0) {
		printf("%% intdesc: SIOCSIFDESCR: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
intvnetflowid_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	struct ifreq ifr;

	if (cand != NULL) {
		if (!cand_takes(ifname, SIOCSVNETFLOWID)) {
			printf("%% vnetflowid not supported on %s\n", ifname);
			return -1;
		}
		if (set && cand_vnetflowid(cand) == -1)
			return -1;
		return cand_setting(cand, set ? ST_ON : ST_OFF, "vnetflowid");
	}

	if (set)
		ifr.ifr_vnetid = 1;
	else
		ifr.ifr_vnetid = 0;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl_down(ifs, ifname, SIOCSVNETFLOWID, &ifr) < 0) {
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
