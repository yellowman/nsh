/* $nsh: conf.c,v 1.17 2003/09/18 20:03:15 chris Exp $ */
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
#include <net/route.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <limits.h>
#include "externs.h"
#include "bridge.h"

char *routename_sa(struct sockaddr *);
void conf_print_rtm(FILE *, struct rt_msghdr *, char *, int);

static const struct {
	char *name;
	int mtu;
} defmtus[] = {
	/* Current as of 9/18/03 */
	{ "gre",	1450 },
	{ "gif",	1280 },
	{ "tun",	3000 },
	{ "sl",		296 },
	{ "enc",	1536 },
	{ "pfsync",	1896 },
	{ "pflog",	33224 },
	{ "lo",		33224 },
};

int
conf(FILE *output)
{
	struct ifaddrs *ifap, *ifa;
	struct if_nameindex *ifn_list, *ifnp, *br_ifnp;
	struct ifreq ifr;
	struct if_data if_data;
	struct sockaddr_in sin, sin2, sin3;
	struct vlanreq vreq;

	FILE *pfconf;
	short ippntd, br;
	int ifs, flags, tmp;
	long l_tmp;

	char *iptype;
	char hostbuf[MAXHOSTNAMELEN];
	char tmp_str[4096], tmp_str2[1024];

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% conf: if_nameindex failed\n");
		return(1);
	}
	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% conf socket: %s\n", strerror(errno));
		return(1);
	}

	/* ready? begin. print the hostname ... */
	fprintf(output, "!\n");
	gethostname (hostbuf, sizeof(hostbuf));
	fprintf(output, "hostname %s\n", hostbuf);

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
		 * interface does not have IFF_BROADCAST set until it
		 * inherts the parent's flags.  Or, for a bridge,
		 * we need to setup the members before we setup flags on
		 * them...You know, uhh...things of that nature..
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

		/*
		 * Print interface IP address, and broadcast or
		 * destination if available.  But, don't print broadcast
		 * if it is what we would expect given the ip and netmask!
		 */
		if (getifaddrs(&ifap) != 0) {
			printf("%% conf: getifaddrs failed: %s\n",
			    strerror(errno));
			return(1);
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
			if (strncmp(ifnp->if_name, ifa->ifa_name, IFNAMSIZ))
				continue;

			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;
		
			sin.sin_addr = ((struct sockaddr_in *)ifa->ifa_addr)->
			    sin_addr;

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
				    ((struct sockaddr_in *)
				    ifa->ifa_dstaddr)->sin_addr;
				fprintf(output, " %s",
				    inet_ntoa(sin3.sin_addr));
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

		if (!br) { /* no shirt, no shoes, no problem */

			if (phys_status(ifs, ifnp->if_name, tmp_str, tmp_str2,
			    sizeof(tmp_str), sizeof(tmp_str2)) > 0)
			/* future os may use this for more than tunnel? */
			fprintf(output, " tunnel %s %s\n", tmp_str, tmp_str2);

			conf_media_status(output, ifs, ifnp->if_name);

			/*
			 * print interface mtu, metric
			 */
			if(if_mtu != default_mtu(ifnp->if_name))
				fprintf(output, " mtu %li\n", if_mtu);
			if(if_metric)
				fprintf(output, " metric %li\n", if_metric);

			if (get_nwinfo(ifnp->if_name, tmp_str, sizeof(tmp_str),
			    NWID) != NULL) {
				fprintf(output, " nwid %s\n", tmp_str);
				if (get_nwinfo(ifnp->if_name, tmp_str,
				    sizeof(tmp_str), NWKEY) != NULL)
					fprintf(output, " nwkey %s\n", tmp_str);
				if ((tmp = get_nwpowersave(ifs, ifnp->if_name))
				    != NULL)
				{
					if (tmp != DEFAULT_POWERSAVE)
						fprintf(output,
						    " powersave %i\n", tmp);
				}
			}
		}

		if (br) {
			if ((l_tmp = bridge_cfg(ifs, ifnp->if_name, PRIORITY))
			    != -1 && l_tmp != DEFAULT_PRIORITY)
				fprintf(output, " priority %lu\n", l_tmp);
			if ((l_tmp = bridge_cfg(ifs, ifnp->if_name, HELLOTIME))
			    != -1 && l_tmp != DEFAULT_HELLOTIME)
				fprintf(output, " hellotime %lu\n", l_tmp);
			if ((l_tmp = bridge_cfg(ifs, ifnp->if_name, FWDDELAY))
			    != -1 && l_tmp != DEFAULT_FWDDELAY)
				fprintf(output, " fwddelay %lu\n", l_tmp);
			if ((l_tmp = bridge_cfg(ifs, ifnp->if_name, MAXAGE))
			    != -1 && l_tmp != DEFAULT_MAXAGE)
				fprintf(output, " maxage %lu\n", l_tmp);
			if ((l_tmp = bridge_cfg(ifs, ifnp->if_name, MAXADDR))
			    != -1 && l_tmp != DEFAULT_MAXADDR)
				fprintf(output, " maxaddr %lu\n", l_tmp);
			if ((l_tmp = bridge_cfg(ifs, ifnp->if_name, TIMEOUT))
			    != -1 && l_tmp != DEFAULT_TIMEOUT)
				fprintf(output, " timeout %lu\n", l_tmp);

			if (bridge_list(ifs, ifnp->if_name, NULL, tmp_str,
			    sizeof(tmp_str), MEMBER))
				fprintf(output, " member %s\n", tmp_str);
			if (bridge_list(ifs, ifnp->if_name, NULL, tmp_str,
			    sizeof(tmp_str), STP))
				fprintf(output, " stp %s\n", tmp_str);
			if (bridge_list(ifs, ifnp->if_name, NULL, tmp_str,
			    sizeof(tmp_str), SPAN))
				fprintf(output, " span %s\n", tmp_str);
			if (bridge_list(ifs, ifnp->if_name, NULL, tmp_str,
			    sizeof(tmp_str), NOLEARNING))
				fprintf(output, " no learning %s\n", tmp_str);
			if (bridge_list(ifs, ifnp->if_name, NULL, tmp_str,
			    sizeof(tmp_str), NODISCOVER))
				fprintf(output, " no discover %s\n", tmp_str);
			if (bridge_list(ifs, ifnp->if_name, NULL, tmp_str,
			    sizeof(tmp_str), BLOCKNONIP))
				fprintf(output, " blocknonip %s\n", tmp_str);
			if (bridge_list(ifs, ifnp->if_name, " ", tmp_str,
			    sizeof(tmp_str), CONF_IFPRIORITY))
				fprintf(output, "%s", tmp_str);
			bridge_confaddrs(ifs, ifnp->if_name, " static ",
			    output);
			for (br_ifnp = ifn_list; br_ifnp->if_name != NULL;
			    br_ifnp++)
				/* try all interface names for member rules */
				bridge_rules(ifs, ifnp->if_name,
				    br_ifnp->if_name, " rule ", output);
		}

		/*
		 * print various flags
		 */
		if (flags & IFF_DEBUG)
			fprintf(output, " debug\n");
		if(flags & (IFF_LINK0|IFF_LINK1|IFF_LINK2)) {
			fprintf(output, " link ");
			if(flags & IFF_LINK0)
				fprintf(output, "0 ");
			if(flags & IFF_LINK1)
				fprintf(output, "1 ");
			if(flags & IFF_LINK2)
				fprintf(output, "2");
			fprintf(output, "\n");
		}
		if(flags & IFF_NOARP)
			fprintf(output, " no arp\n");
		/*
		 * ip X/Y turns the interface up (just like 'no shutdown')
		 * ...but if we never had an ip address set and the interface
		 * is up, we need to save this state explicitly.
		 */
		if(!ippntd && (flags & IFF_UP))
			fprintf(output, " no shutdown\n");
		else if(!(flags & IFF_UP))
			fprintf(output, " shutdown\n");

        }
	close(ifs);
	if_freenameindex(ifn_list);

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

	/*
	 * print pf rules
	 */
	if ((pfconf = fopen(PFCONF_TEMP, "r")) != NULL) {
		fprintf(output, "pf rules\n");
		for (;;) {
			if(fgets(tmp_str, sizeof(tmp_str), pfconf) == NULL)
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

	return(0);
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
