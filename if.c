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
#include <net/if_vlan_var.h>
#include <arpa/inet.h>
#include <limits.h>
#include "externs.h"

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
	int ifs, mbits, flags, days, hours, mins;
	int noaddr = 0;
	time_t c;
	char *type;

	u_long rate, bucket;
	char rate_str[64], bucket_str[64];

	/*
	 * Show all interfaces when no ifname specified.
	 */
	if (ifname == 0) {
		if ((ifn_list = if_nameindex()) == NULL) {
			printf("%% show_int: if_namindex failed\n");
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
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	/*
	 * Show up/down status and last change time
	 */
	if (ioctl(ifs, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		perror("% show_int: SIOCGIFFLAGS");
		close(ifs);
		return(1);
	}
	flags = ifr.ifr_flags;

	ifr.ifr_data = (caddr_t)&if_data;
	if (ioctl(ifs, SIOCGIFDATA, (caddr_t)&ifr) < 0) {
		perror("% show_int: SIOCGIFDATA");
		close(ifs);
		return(1);
	}

	printf("%% %s\n", ifname);
	printf("  Interface is %s", flags & IFF_UP ? "up" : "down");

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

	printf(", protocol is %s\n", flags & IFF_RUNNING ? "up" : "down");

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
	printf("  Interface type %s\n", type);

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

	/*
	 * Display MTU, line rate, and ALTQ token rate info if applicable
	 */
	printf("  MTU %li bytes", if_mtu);
	if (if_baudrate)
		printf(", Line Rate %li %s\n",
		    MBPS(if_baudrate) ? MBPS(if_baudrate) : if_baudrate / 1000,
		    MBPS(if_baudrate) ? "Mbps" : "Kbps");
	else
		printf("\n");
 
	rate = get_tbr(ifname, TBR_RATE);
	bucket = get_tbr(ifname, TBR_BUCKET);

	if(rate && bucket) {
		if (MBPS(rate))
			snprintf(rate_str, sizeof(rate_str), "%.2f Mbps",
			    (double)rate/1000.0/1000.0);
		else
			snprintf(rate_str, sizeof(rate_str), "%.2f Kbps",
			    (double)rate/1000.0);

		if (bucket < 10240)
			snprintf(bucket_str, sizeof(bucket_str),  "%lu bytes",
			    bucket);
		else
			snprintf(bucket_str, sizeof(bucket_str), "%.2f Kbytes",
			    (double)bucket/1024.0);

		printf("  Token Rate %s, Bucket %s\n", rate_str, bucket_str);
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

	if(verbose && flags) {
		printf("  Flags ");
		bprintf(stdout, flags, ifnetflags);
		printf("\n");
        }

	return(0);
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
		if (strncasecmp(ifname, ifnp->if_name,
		    strlen(ifnp->if_name)) == 0)
			count++;
	}
	if_freenameindex(ifn_list);

	if (count == 1)
		return(1);
	else
		return(0);
}

