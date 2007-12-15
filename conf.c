/* $nsh: conf.c,v 1.30 2007/12/15 22:39:23 chris Exp $ */
/*
 * Copyright (c) 2002, 2005
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
#include <pwd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_vlan_var.h>
#include <net/route.h>
#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <limits.h>
#include "externs.h"
#include "bridge.h"

#define IPSIZ  256	/*
			 * max theoretical size of ipv4 or ipv6
			 * text representation
			 */
#define TMPSIZ 1024	/* size of temp strings */

char *routename_sa(struct sockaddr *);
void conf_interfaces(FILE *);
void conf_print_rtm(FILE *, struct rt_msghdr *, char *, int);
int conf_ifaddrs(FILE *, char *, int);
void conf_brcfg(FILE *, int, struct if_nameindex *, char *);
void conf_ifmetrics(FILE *, int, struct if_data, char *);
void conf_pfrules(FILE *);

static const struct {
	char *name;
	int mtu;
} defmtus[] = {
	/* Current as of 8/20/05 */
	{ "gre",	1476 },
	{ "gif",	1280 },
	{ "tun",	3000 },
	{ "sl",		296 },
	{ "enc",	1536 },
	{ "pflog",	33224 },
	{ "lo",		33224 },
};

int
conf(FILE *output)
{
	char cpass[_PASSWORD_LEN+1];
	char hostbuf[MAXHOSTNAMELEN];

	fprintf(output, "!\n");

	gethostname (hostbuf, sizeof(hostbuf));
	fprintf(output, "hostname %s\n", hostbuf);
	if(read_pass(cpass, sizeof(cpass)))
		fprintf(output, "enable secret blowfish %s\n", cpass);
	else
		printf("%% Unable to read run-time crypt repository:"
		    " %s\n", strerror(errno));

	conf_interfaces(output);

	fprintf(output, "!\n");

	/*
	 * check out how sysctls are doing these days
	 *
	 * Each of these options, like most other things in the config output
	 * (such as interface flags), must display if the kernel's default
	 * setting is not currently set.
	 */
	conf_ipsysctl(output);

	fprintf(output, "!\n");

	/*
	 * print static arp and route entries in configuration file format
	 */
	conf_routes(output, "arp ", AF_INET, (RTF_LLINFO & RTF_STATIC));
	conf_routes(output, "route ", AF_INET, RTF_STATIC);

	fprintf(output, "!\n");

	conf_pfrules(output);

	return(0);
}

void conf_pfrules(FILE *output)
{
	FILE *pfconf;
	char tmp_str[TMPSIZ];

	/*
	 * print pf rules
	 */
	if ((pfconf = fopen(PFCONF_TEMP, "r")) != NULL) {
		fprintf(output, "pf rules\n");
		for (;;) {
			if(fgets(tmp_str, TMPSIZ, pfconf) == NULL)
				break;
			if(tmp_str[0] == 0)
				break;
			fprintf(output, " %s", tmp_str);
		}
		fclose(pfconf);
		fprintf(output, "!\n");
		fprintf(output, "pf action\n enable\n reload\n");
	} else if (verbose)
		printf("%% PFCONF_TEMP: %s\n", strerror(errno));
}

void conf_interfaces(FILE *output)
{
	FILE *dhcpif, *llfile;
	int ifs, flags, ippntd, br;
#define LEASEPREFIX     "/var/db/dhclient.leases"
#define	LLPREFIX	"/var/run/lladdr"
	char leasefile[sizeof(LEASEPREFIX)+IFNAMSIZ+1];
	char *lladdr, llorig[IFNAMSIZ+1];
	char llfn[sizeof(LLPREFIX)+IFNAMSIZ+1];

	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr;
	struct if_data if_data;
	struct vlanreq vreq;

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% conf_interfaces: if_nameindex failed\n");
		return;
	}

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% conf_interfaces socket: %s\n", strerror(errno));
		if_freenameindex(ifn_list);
		return;
	}

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		strlcpy(ifr.ifr_name, ifnp->if_name, sizeof(ifr.ifr_name));

		if (ioctl(ifs, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
			printf("%% conf: SIOCGIFFLAGS: %s\n", strerror(errno));
			continue;
		}
		flags = ifr.ifr_flags;

		ifr.ifr_data = (caddr_t)&if_data;
		if (ioctl(ifs, SIOCGIFDATA, (caddr_t)&ifr) < 0) {
			printf("%% conf: SIOCGIFDATA: %s\n", strerror(errno));
			continue;
		}

		/*
		 * Keep in mind that the order in which things are displayed
		 * here is important.  For instance, we want to setup the
		 * vlan tag before setting the IP address since the vlan
		 * must know what parent to inherit the parent interface
		 * flags from before it is brought up.  Another example of
		 * this would be that we need to setup the members on a
		 * bridge before we setup flags on them.
		 */

		/*
		 * set interface/bridge mode
		 */
		fprintf(output, "!\n");
		if (!(br = is_bridge(ifs, ifnp->if_name)))
			br = 0;
		fprintf(output, "%s %s\n", br ? "bridge" : "interface",
		    ifnp->if_name);

		/*
		 * print lladdr if necessary
		 * this is a heavy handed way of doing this, for something
		 * that is more likely to not be set by default... and,
		 * get_hwdaddr() is part of the dead weight...
		 * soekris 486s run in spite of such measures to destroy them
		 */
		if ((lladdr = get_hwdaddr(ifnp->if_name)) != NULL) {
			/* We assume lladdr only useful if we can get_hwdaddr */
			snprintf(llfn, sizeof(llfn), "%s.%s", LLPREFIX,
			    ifnp->if_name);
			if ((llfile = fopen(llfn, "r"))) {
				fgets(llorig, sizeof(llorig), llfile);
				if (strcmp(llorig, lladdr) != 0) {
					fprintf(output, " lladdr %s\n",
					    lladdr);
				}
			}
		}
		 
		/*
		 * print vlan tag, parent if available.  if a tag is set
		 * but there is no parent, discard.
		 */
		memset(&vreq, 0, sizeof(struct vlanreq));
		ifr.ifr_data = (caddr_t)&vreq;  

		if (ioctl(ifs, SIOCGETVLAN, (caddr_t)&ifr) != -1) {
			if(vreq.vlr_tag && (vreq.vlr_parent[0] != '\0'))
				fprintf(output, " vlan %d %s\n",
				    vreq.vlr_tag, vreq.vlr_parent);
		}

		snprintf(leasefile, sizeof(leasefile), "%s.%s",
		    LEASEPREFIX, ifnp->if_name);
		if ((dhcpif = fopen(leasefile, "r"))) {
			fprintf(output, " ip dhcp\n");
			fclose(dhcpif);
			ippntd = 1;
		} else {
			ippntd = conf_ifaddrs(output, ifnp->if_name, flags);
		}

		if (br) {
			conf_brcfg(output, ifs, ifn_list, ifnp->if_name);
		} else {
			conf_media_status(output, ifs, ifnp->if_name);
			conf_ifmetrics(output, ifs, if_data, ifnp->if_name);
			conf_pfsync(output, ifs, ifnp->if_name);
			conf_carp(output, ifs, ifnp->if_name);
			conf_trunk(output, ifs, ifnp->if_name);
		}

		/*
		 * print various flags
		 */
		if (flags & IFF_DEBUG)
			fprintf(output, " debug\n");
		if (flags & (IFF_LINK0|IFF_LINK1|IFF_LINK2)) {
			fprintf(output, " link ");
			if(flags & IFF_LINK0)
				fprintf(output, "0 ");
			if(flags & IFF_LINK1)
				fprintf(output, "1 ");
			if(flags & IFF_LINK2)
				fprintf(output, "2");
			fprintf(output, "\n");
		}
		if (flags & IFF_NOARP)
			fprintf(output, " no arp\n");
		/*
		 * ip X/Y turns the interface up (just like 'no shutdown')
		 * ...but if we never had an ip address set and the interface
		 * is up, we need to save this state explicitly.
		 */
		if (!ippntd && (flags & IFF_UP))
			fprintf(output, " no shutdown\n");
		else if (!(flags & IFF_UP))
			fprintf(output, " shutdown\n");

	}
	close(ifs);
	if_freenameindex(ifn_list);
}

void conf_ifmetrics(FILE *output, int ifs, struct if_data if_data,
    char *ifname)
{
	char tmpa[IPSIZ], tmpb[IPSIZ], tmpc[TMPSIZ];

	/*
	 * Various metrics valid for non-bridge interfaces
	 */
	if (phys_status(ifs, ifname, tmpa, tmpb, IPSIZ, IPSIZ) > 0)
		/* future os may use this for more than tunnel? */
		fprintf(output, " tunnel %s %s\n", tmpa, tmpb);

	/*
	 * print interface mtu, metric
	 *
	 * ignore interfaces named "pfsync" since their mtu
	 * is dynamic and controlled by the kernel
	 */
	if (!CMP_ARG(ifname, "pfsync") && if_mtu != default_mtu(ifname))
		fprintf(output, " mtu %u\n", if_mtu);
	if (if_metric)
		fprintf(output, " metric %u\n", if_metric);

	if (get_nwinfo(ifname, tmpc, TMPSIZ, NWID) != NULL) {
		fprintf(output, " nwid %s\n", tmpc);
		if (get_nwinfo(ifname, tmpc, TMPSIZ, NWKEY) != NULL)
			fprintf(output, " nwkey %s\n", tmpc);
		if (get_nwinfo(ifname, tmpc, TMPSIZ, TXPOWER) != NULL)
			fprintf(output, " txpower %s\n", tmpc);
		if (get_nwinfo(ifname, tmpc, TMPSIZ, POWERSAVE) != NULL)
			fprintf(output, " powersave %s\n", tmpc);
	}
}

void conf_brcfg(FILE *output, int ifs, struct if_nameindex *ifn_list,
    char *ifname)
{
	struct if_nameindex *br_ifnp;

	char tmp_str[TMPSIZ];
	long l_tmp;

	if ((l_tmp = bridge_cfg(ifs, ifname, PRIORITY))
	    != -1 && l_tmp != DEFAULT_PRIORITY)
		fprintf(output, " priority %lu\n", l_tmp);
	if ((l_tmp = bridge_cfg(ifs, ifname, HELLOTIME))
	    != -1 && l_tmp != DEFAULT_HELLOTIME)
		fprintf(output, " hellotime %lu\n", l_tmp);
	if ((l_tmp = bridge_cfg(ifs, ifname, FWDDELAY))
	    != -1 && l_tmp != DEFAULT_FWDDELAY)
		fprintf(output, " fwddelay %lu\n", l_tmp);
	if ((l_tmp = bridge_cfg(ifs, ifname, MAXAGE))
	    != -1 && l_tmp != DEFAULT_MAXAGE)
		fprintf(output, " maxage %lu\n", l_tmp);
	if ((l_tmp = bridge_cfg(ifs, ifname, MAXADDR))
	    != -1 && l_tmp != DEFAULT_MAXADDR)
		fprintf(output, " maxaddr %lu\n", l_tmp);
	if ((l_tmp = bridge_cfg(ifs, ifname, TIMEOUT))
	    != -1 && l_tmp != DEFAULT_TIMEOUT)
		fprintf(output, " timeout %lu\n", l_tmp);

	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, MEMBER))
		fprintf(output, " member %s\n", tmp_str);
	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, STP))
		fprintf(output, " stp %s\n", tmp_str);
	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, SPAN))
		fprintf(output, " span %s\n", tmp_str);
	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, NOLEARNING))
		fprintf(output, " no learning %s\n", tmp_str);
	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, NODISCOVER))
		fprintf(output, " no discover %s\n", tmp_str);
	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, BLOCKNONIP))
		fprintf(output, " blocknonip %s\n", tmp_str);
	if (bridge_list(ifs, ifname, " ", tmp_str, TMPSIZ, CONF_IFPRIORITY))
		fprintf(output, "%s", tmp_str);
	if (bridge_list(ifs, ifname, " ", tmp_str, TMPSIZ, CONF_IFCOST))
		fprintf(output, "%s", tmp_str);
	bridge_confaddrs(ifs, ifname, " static ", output);

	for (br_ifnp = ifn_list; br_ifnp->if_name != NULL; br_ifnp++)
		/* try all interface names for member rules */
		bridge_rules(ifs, ifname, br_ifnp->if_name, " rule ",
		    output);
}

int conf_ifaddrs(FILE *output, char *ifname, int flags)
{
	struct ifaddrs *ifa, *ifap;
	struct sockaddr_in sin, sin2, sin3;
	char *iptype;
	int ippntd;

	/*
	 * Print interface IP address, and broadcast or
	 * destination if available.  But, don't print broadcast
	 * if it is what we would expect given the ip and netmask!
	 */
	if (getifaddrs(&ifap) != 0) {
		printf("%% conf: getifaddrs failed: %s\n",
		strerror(errno));
		return(-1);
	}

	/*
	 * This short controls whether or not we print 'ip ....'
	 * or 'alias ....'
	 */
	ippntd = 0;

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
                
		sin.sin_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;

		if (sin.sin_addr.s_addr == 0)
			continue;
 
		sin2.sin_addr =
		    ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;

		if (ippntd) {
			iptype = "alias";
		} else {
			iptype = "ip";
			ippntd = 1;
		}

		fprintf(output, " %s %s", iptype,
		    (char *)netname(sin.sin_addr.s_addr,
		    sin2.sin_addr.s_addr));

		if (flags & IFF_POINTOPOINT) {
			sin3.sin_addr =
			    ((struct sockaddr_in *)ifa->ifa_dstaddr)->sin_addr;
			fprintf(output, " %s", inet_ntoa(sin3.sin_addr));
		} else if (flags & IFF_BROADCAST) {
			sin3.sin_addr =
			    ((struct sockaddr_in *)ifa->ifa_broadaddr)->
			    sin_addr;
			/*
			 * no reason to save the broadcast addr
			 * if it is standard (this should always 
			 * be true unless someone has messed up their
			 * network or they are playing around...)
			 */
			if (ntohl(sin3.sin_addr.s_addr) !=
			    in4_brdaddr(sin.sin_addr.s_addr,
			    sin2.sin_addr.s_addr))
				fprintf(output, " %s",
				    inet_ntoa(sin3.sin_addr));
		}
		fprintf(output, "\n");
	}
	freeifaddrs(ifap);

	return ippntd;
}

int
default_mtu(char *ifname)
{
	int i;

	for (i = 0; i < sizeof(defmtus) / sizeof(defmtus[0]); i++)
		if (strncasecmp(defmtus[i].name, ifname,
		    strlen(defmtus[i].name)) == 0)
			return(defmtus[i].mtu);

	return(DEFAULT_MTU); /* default mtu */
}

/*
 * Show IPv4/6 or ARP entries from the routing table
 */
int
conf_routes(FILE *output, char *delim, int af, int flags)
{
	int s;
	char *next;
	struct rt_msghdr *rtm;
	struct rtdump *rtdump;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		printf("%% Unable to open routing socket: %s\n",
		    strerror(errno));
		return(-1);
	}

	rtdump = getrtdump(s);
	if (rtdump == NULL) {
		close(s);
		return(-1);
	}

	/* walk through routing table */
	for (next = rtdump->buf; next < rtdump->lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if ((rtm->rtm_flags & flags) == 0)
			continue;
		if (!rtm->rtm_errno) {
			if (rtm->rtm_addrs)
				conf_print_rtm(output, rtm, delim, af);
		} else if (verbose)
			printf("%% conf_routes: rtm: %s (errno %d)\n",
			    strerror(rtm->rtm_errno), rtm->rtm_errno);
	}
	freertdump(rtdump);
	close(s);
	return(1);
}

void
conf_print_rtm(FILE *output, struct rt_msghdr *rtm, char *delim, int af)
{
	int i;
	char *cp;
	struct sockaddr *dst = NULL, *gate = NULL, *mask = NULL;
	struct sockaddr *sa;

	cp = ((char *)(rtm + 1));
	for (i = 1; i; i <<= 1)
		if (i & rtm->rtm_addrs) {
			sa = (struct sockaddr *)cp;
			switch (i) {
			case RTA_DST:
				if (sa->sa_family == af)
					dst = sa;
				break;
			case RTA_GATEWAY:
				if (sa->sa_family == af)
					gate = sa;
				break;
			case RTA_NETMASK:
				/* netmasks will not have a valid sa_family */
				mask = sa;
				break;
			}
			ADVANCE(cp, sa);
		}
	if (dst && mask && gate && (af == AF_INET)) {
		/* print ipv4 routes */
		struct sockaddr_in *dstin = (struct sockaddr_in *)dst;
		struct sockaddr_in *maskin = (struct sockaddr_in *)mask;
		if (mask->sa_len == 0) {
			/*
			 * Technique gleaned from routename_sa():
			 * This is annoying.  Why can't the kernel return 0
			 * for s_addr instead of just 0 for sa_len
			 * and some bullshit value for s_addr???
			 * Maybe we should be checking sa_len more often....
			 */
			maskin->sin_addr.s_addr = 0;
		}
		fprintf(output, "%s%s ", delim,
		    (char *)netname(dstin->sin_addr.s_addr,
		    maskin->sin_addr.s_addr));
		fprintf(output, "%s\n", routename_sa(gate));
	} else
#ifdef INET6
	{
		/* print ipv6 routes */
		struct sockaddr_in6 *dstin = (struct sockaddr_in6 *)dst;
		struct sockaddr_in6 *maskin = (struct sockaddr_in6 *mask;
		if (mask->sa_len == 0) {
			/* same gripe as above */
			maskin->sin6_addr.s_addr = 0;
		}
		fprintf(output, "%s%s ", delim,
		    (char *)netname6(dst, maskin->sin6_addr);
		fprintf(output, "%s\n", routename6(gate));
	} else
#endif
	if (dst && gate && (af == AF_LINK))
		/* print arp table */
		fprintf(output, "%s%s %s\n", delim, routename_sa(dst),
		    routename_sa(gate));
}
