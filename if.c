/*
 * Copyright (c) 2002
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
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_ieee80211.h>
#include <net/if_vlan_var.h>
#include <arpa/inet.h>
#include <limits.h>
#include "externs.h"
#include "bridge.h"

int
show_int(const char *ifname)
{
	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr;
	struct if_data if_data;
	struct sockaddr_in sin, sin2;
	struct timeval tv;
	struct vlanreq vreq;

	in_addr_t mask;
	short tmp;
	int ifs, br, mbits, flags, days, hours, mins, pntd;
	int noaddr = 0;
	time_t c;
	char *type;

	u_long rate, bucket;
	char rate_str[64], bucket_str[64], tmp_str[4096];

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
		perror("% show_int");
		return(1);
	}

	if (!(br = is_bridge(ifs, (char *)ifname)))
		br = 0;

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	/*
	 * Show up/down status and last change time
	 */
	flags = get_ifflags(ifname, ifs);

	ifr.ifr_data = (caddr_t)&if_data;
	if (ioctl(ifs, SIOCGIFDATA, (caddr_t)&ifr) < 0) {
		perror("% show_int: SIOCGIFDATA");
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

	/*
	 * Display interface type
	 */
	switch(if_type) {
	/*
	 * Here we include all types that are used anywhere
	 * in the 3.0 kernel.
	 */
	/* OpenBSD */
	case IFT_PFLOG:
		type = "Packet Filter Logging";
		break;
	case IFT_ENC:
		type = "IPsec Loopback";
		break;
	case IFT_GIF:
		type = "Generic Tunnel";
		break;
	case IFT_FAITH:
		type = "IPv6-IPv4 TCP relay";
		break;
	case IFT_BRIDGE:
		type = "Ethernet Bridge";
		break;
	/* IANA */
	case IFT_ISO88025:
		type = "Token Ring";
		break;
	case IFT_EON:
		type = "ISO over IP";
		break;
	case IFT_NSIP:
		type = "XNS over IP";
		break;
	case IFT_X25DDN:
		type = "X.25 to IMP";
		break;
	case IFT_ATMDXI:
	case IFT_ATMFUNI:
	case IFT_ATMIMA:
	case IFT_ATMLOGICAL:
	case IFT_ATMVIRTUAL:
		type = "ATM Virtual";
		break;
	case IFT_ATM:
		type = "ATM";
		break;
	case IFT_FDDI:
		type = "FDDI";
		break;
	case IFT_ETHER:
		type = "Ethernet";
		break;
	case IFT_ARCNET:
		type = "ARCNET";
		break;
	case IFT_HDLC:
		type = "HDLC";
		break;
	case IFT_L2VLAN:
		type = "IEEE 802.1Q Virtual";
		break;
	case IFT_PROPVIRTUAL:
		type = "Virtual";
		break;
	case IFT_PPP:
		type = "PPP";
		break;
	case IFT_SLIP:
		type = "SLIP";
		break;
	case IFT_LOOP:
		type = "Loopback";
		break;
	case IFT_ISDNS:
	case IFT_ISDNU:
	case IFT_ISDNBASIC:
	case IFT_ISDNPRIMARY:
		type = "ISDN";
		break;
	case IFT_V35:
		type = "V.35";
		break;
	case IFT_HSSI:
		type = "HSSI";
		break;
	case IFT_TUNNEL:
		type = "Network Tunnel";
		break;
	case IFT_IEEE80211:
		type = "IEEE 802.11 Wireless";
		break;
	case IFT_OTHER:
	default:
		type = "Unknown";
		break;
	}
	printf("  Interface type %s", type);
	if (flags & IFF_BROADCAST)
		printf(" (Broadcast)");
	else if (flags & IFF_POINTOPOINT)
		printf(" (PointToPoint)");
	printf("\n");

	/*
	 * Display IP address and CIDR netmask
	 */
	if (ioctl(ifs, SIOCGIFADDR, (caddr_t)&ifr) < 0) {
		if (errno == EADDRNOTAVAIL) {
			noaddr = 1;
		} else {
			perror("% show_int: SIOCGIFADDR");
			close(ifs);
			return(1);
		}
	}
 
	if (!noaddr) {
		sin.sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

		if (ioctl(ifs, SIOCGIFNETMASK, (caddr_t)&ifr) < 0)
			if (errno != EADDRNOTAVAIL) {
				perror("% show_int: SIOCGIFNETMASK");
				close(ifs);
				return(1);
			}
		sin2.sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

		mask = ntohl(sin2.sin_addr.s_addr);
		mbits = mask ? 33 - ffs(mask) : 0;

		printf("  Internet address is %s/%i\n",
		    inet_ntoa(sin.sin_addr), mbits);
	}

	if (!br) {
		/*
		 * Display MTU, line rate, and ALTQ token rate info
		 * (if available)
		 */
		printf("  MTU %li bytes", if_mtu);
		if (if_baudrate)
			printf(", Line Rate %li %s\n",
			    MBPS(if_baudrate) ? MBPS(if_baudrate) :
			    if_baudrate / 1000,
			    MBPS(if_baudrate) ? "Mbps" : "Kbps");
		else
			printf("\n");
 
		rate = get_tbr(ifname, TBR_RATE);
		bucket = get_tbr(ifname, TBR_BUCKET);

		if(rate && bucket) {
			if (MBPS(rate))
				snprintf(rate_str, sizeof(rate_str),
				    "%.2f Mbps",
				    (double)rate/1000.0/1000.0);
			else
				snprintf(rate_str, sizeof(rate_str),
				    "%.2f Kbps",
				    (double)rate/1000.0);

			if (bucket < 10240)
				snprintf(bucket_str, sizeof(bucket_str),
				    "%lu bytes",
				    bucket);
			else
				snprintf(bucket_str, sizeof(bucket_str),
				    "%.2f Kbytes",
				    (double)bucket/1024.0);

			printf("  Token Rate %s, Bucket %s\n", rate_str,
			    bucket_str);
		}

		memset(&vreq, 0, sizeof(struct vlanreq));
		ifr.ifr_data = (caddr_t)&vreq;

		if (ioctl(ifs, SIOCGETVLAN, (caddr_t)&ifr) != -1) {
			if(vreq.vlr_tag || (vreq.vlr_parent[0] != '\0')) {
				printf("  vlan tag %d on parent %s\n",
				    vreq.vlr_tag, vreq.vlr_parent[0] == '\0' ?
				    "<none>" : vreq.vlr_parent);
			}
		}
		close(ifs);
	}

	/*
	 * Display remaining info from if_data structure
	 */
	printf("  %lu packets input, %lu bytes, %lu errors, %lu drops\n",
	    if_ipackets, if_ibytes, if_ierrors, if_iqdrops);
	printf("  %lu packets output, %lu bytes, %lu errors, %lu unsupported\n",
	    if_opackets, if_obytes, if_oerrors, if_noproto);
	switch(if_type) {
	case IFT_ETHER:
	case IFT_SLIP:
	case IFT_PROPVIRTUAL:
		printf("  %lu collisions\n", if_collisions);
		break;
	default:
		break;
	}
	if (if_ibytes && if_ipackets) {
		printf("  %lu avg input size", if_ibytes / if_ipackets);
		pntd = 1;
	} else
		pntd = 0;
	if (if_obytes && if_opackets) {
		printf("%s%lu avg output size", pntd ? ", " : "  ",
		    if_obytes / if_opackets);
		pntd = 1;
	}
	if (pntd)
		printf("\n");

	if(verbose) {
		if (flags) {
			printf("  Flags:\n    ");
			bprintf(stdout, flags, ifnetflags);
			printf("\n");
		}
		if (br) {
			if (tmp = bridge_list(ifs, ifname, "    ", tmp_str,
			    sizeof(tmp_str), SHOW_STPSTATE)) {
				printf("  STP member state%s:\n", tmp > 1 ?
				    "s" : "");
				printf("%s", tmp_str);
			}
			bridge_addrs(ifs, ifname, "  ", "    ");
		}
	}

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

int 
get_ifdata(const char *ifname, int type)
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
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
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
is_valid_ifname(const char *ifname)
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
get_ifflags(const char *ifname, int ifs)
{
	int flags;
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		perror("% get_ifflags: SIOCGIFFLAGS");
		flags = 0;
	} else
		flags = ifr.ifr_flags;
	return(flags);
}

int
set_ifflags(const char *ifname, int ifs, int flags)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	ifr.ifr_flags = flags;

	if (ioctl(ifs, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
		perror("% get_ifflags: SIOCSIFFLAGS");
	}

        return(0);
}

#define DELETE 0
#define ADD 1

int
intip(const char *ifname, int ifs, int argc, char **argv)
{
	int cmd, alias, flags, argcmax;
	struct in_addr ip, mask, destbcast;
	struct ifaliasreq addreq, ridreq;
	struct sockaddr_in *sin;
	char *q, *msg, *cmdname;

	memset(&addreq, 0, sizeof(addreq));
	memset(&ridreq, 0, sizeof(ridreq));

	if (strncasecmp(argv[0], "no", 2) == 0) {
		cmd = DELETE;
		argc--;
		argv++;
	} else
		cmd = ADD;

	/*
	 * We use this function for ip and alias setup since they are
	 * the same thing.
	 */
	if (strncasecmp(argv[0], "a", 1) == 0) {
		alias = 1;
		cmdname = "alias";
	} else {
		alias = 0;
		cmdname = "ip";
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

	q = strchr(argv[0], '/');
	if (q)
		*q = '\0';
	else if (cmd != DELETE) {
		printf("%% Netmask not specified\n");
		return(0);
	}
	if (!(inet_aton(argv[0], &ip) && strchr(argv[0], '.'))) {
		printf("%% %s is not an IP address\n", argv[0]);
		return(0);
	}

	if (q) {
		char *s;

		s = q + 1;
		if (!(inet_aton(s, &mask) && strchr(s, '.'))) {
			if(strspn(s, "0123456789") == strlen(s)) {
				int bits;

				/* assume bits after slash */
				bits = strtoul(s, 0, 0);
				if (bits > 32) {
					printf("%% Invalid bit length\n");
					return(0);
				}
				mask.s_addr = htonl(0xffffffff << (32 - bits));
			} else {
				printf("%% Invalid address mask\n");
				return(0);
			}
		}
	} else {
		mask.s_addr = htonl(0xffffffff);
	}
	
	if (argc == 2)
		if (!inet_aton(argv[1], &destbcast)) {
			printf("%% Invalid %s address\n", msg);
			return(0);
		}
	
	strlcpy(addreq.ifra_name, ifname, sizeof(addreq.ifra_name));
	strlcpy(ridreq.ifra_name, ifname, sizeof(ridreq.ifra_name));

	if (cmd == DELETE) {
		sin = (struct sockaddr_in *)&ridreq.ifra_addr;
		sin->sin_len = sizeof(ridreq.ifra_addr);
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ip.s_addr;
	}

	if (!alias || cmd == DELETE) {
		/*
		 * Here we remove the top IP on the interface before we
		 * might add another one, or we delete the specified IP.
		 */
		if (ioctl(ifs, SIOCDIFADDR, &ridreq) < 0)
			if (cmd == DELETE)
				perror("% intip: SIOCDIFADDR");
	}

	if (cmd == ADD) {
		sin = (struct sockaddr_in *)&addreq.ifra_addr;
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(addreq.ifra_addr);
		sin->sin_addr.s_addr = ip.s_addr;
		sin = (struct sockaddr_in *)&addreq.ifra_mask;
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(addreq.ifra_mask);
		sin->sin_addr.s_addr = mask.s_addr;
		if (argc == 2) {
			sin = (struct sockaddr_in *)&addreq.ifra_dstaddr;
			sin->sin_family = AF_INET;
			sin->sin_len = sizeof(addreq.ifra_dstaddr);
			sin->sin_addr.s_addr = destbcast.s_addr;
		}
		if (ioctl(ifs, SIOCAIFADDR, &addreq) < 0)
			perror("% intip: SIOCAIFADDR");
	}

	return(0);
}

int
intmtu(const char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	int cmd;

	if (strncasecmp(argv[0], "no", 2) == 0) {
		cmd = DELETE;
		argc--;
		argv++;
	} else
		cmd = ADD;

	argc--;
	argv++;

	if ((cmd == DELETE && argc != 0) || (cmd == ADD && argc != 1)) {
		printf("%% mtu <mtu>\n");
		printf("%% no mtu\n");
		return(0);
	}

	if (cmd == ADD)
		ifr.ifr_mtu = atoi(argv[0]);
	else
		ifr.ifr_mtu = default_mtu(ifname);

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFMTU, (caddr_t)&ifr) < 0)
		perror("% intmtu: SIOCSIFMTU");

	return(0);
}

int
intmetric(const char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	int cmd;

	if (strncasecmp(argv[0], "no", 2) == 0) {
		cmd = DELETE;
		argc--;
		argv++;
	} else
		cmd = ADD;

	argc--;
	argv++;

	if ((cmd == DELETE && argc != 0) || (cmd == ADD && argc != 1)) {
		printf("%% metric <metric>\n");
		printf("%% no metric\n");
		return(0);
	}

	if (cmd == ADD)
		ifr.ifr_metric = atoi(argv[0]);
	else
		ifr.ifr_metric = 0;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSIFMETRIC, (caddr_t)&ifr) < 0)
		perror("% intmetric: SIOCSIFMETRIC");

	return(0);
}

int
intflags(const char *ifname, int ifs, int argc, char **argv)
{
	int set, value, flags;

	if (strncasecmp(argv[0], "no", 2) == 0) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	if (strncasecmp(argv[0], "d", 1) == 0) {
		/* debug */
		value = IFF_DEBUG;
	} else if (strncasecmp(argv[0], "s", 1) == 0) {
		/* shutdown */
		value = -IFF_UP;
	} else if (strncasecmp(argv[0], "a", 1) == 0) {
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
intlink(const char *ifname, int ifs, int argc, char **argv)
{
	int set, i, flags, value;
	char *s;

	if (strncasecmp(argv[0], "no", 2) == 0) {
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
		flags &= ~IFF_LINK0&~IFF_LINK1&~IFF_LINK2;
	} else 
	for (i = 0; i < argc; i++) {
		int a;

		a = strlen(argv[i]);
		if (a > 1 || a != strspn(argv[i], "012")) {
			printf("%% Invalid argument: %s\n", argv[i]);
			return(0);
		}

		a = atoi(argv[i]);
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
intnwid(const char *ifname, int ifs, int argc, char **argv)
{
	struct ieee80211_nwid nwid;
	struct ifreq ifr;
	struct if_data if_data;
	int set, len;

	if (strncasecmp(argv[0], "no", 2) == 0) {
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
		memset(&nwid, 0, sizeof(struct ieee80211_nwid));

	nwid.i_len = len;
	ifr.ifr_data = (caddr_t)&nwid;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCS80211NWID, (caddr_t)&ifr) < 0)
		perror("% intnwid: SIOCS80211NWID");

	return(0);
}

int
intpowersave(const char *ifname, int ifs, int argc, char **argv)
{
	struct ieee80211_power power;
	int  set;

	if (strncasecmp(argv[0], "no", 2) == 0) {
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
		perror("% intpowersave: SIOCG80211POWER");
		return(0);
	}

	if (argc == 1)
		power.i_maxsleep = atoi(argv[0]);
	else if (set)
		power.i_maxsleep = 100;	/* default 100 milliseconds */
	power.i_enabled = set;

	if (ioctl(ifs, SIOCS80211POWER, (caddr_t)&power) == -1) {
		perror("% intpowersave: SIOCS80211POWER");
		return(0);
	}

	return(0);
}
