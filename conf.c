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
conf(FILE *output)
{
	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr;
	struct if_data if_data;
	struct sockaddr_in sin, sin2;
	struct vlanreq vreq;

	in_addr_t mask;
	int ifs, mbits, flags;
	int noaddr;

	u_long rate, bucket;
	char rate_str[64], bucket_str[64];

	if ((ifn_list = if_nameindex()) == NULL) {
		fprintf(output, "%% save: if_nameindex failed\n");
		return(1);
	}
	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("% save");
		return(1);
	}

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		strncpy(ifr.ifr_name, ifnp->if_name, sizeof(ifr.ifr_name));

		if (ioctl(ifs, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
			perror("% save: SIOCGIFFLAGS");
			close(ifs);
			continue;
		}
		flags = ifr.ifr_flags;

		ifr.ifr_data = (caddr_t)&if_data;
		if (ioctl(ifs, SIOCGIFDATA, (caddr_t)&ifr) < 0) {
			perror("% save: SIOCGIFDATA");
			close(ifs);
			continue;
		}

		/*
		 * set interface mode
		 */
		fprintf(output, "interface %s\n", ifnp->if_name);

		/*
		 * print interface IP address if available
		 */
		if (ioctl(ifs, SIOCGIFADDR, (caddr_t)&ifr) < 0) {
			if (errno == EADDRNOTAVAIL) {
				noaddr = 1;
			} else {
				perror("% save: SIOCGIFADDR");
				close(ifs);
				continue;
			}
		} else {
			noaddr = 0;
		}
 
		if (!noaddr) {
			sin.sin_addr =
			    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

			if (ioctl(ifs, SIOCGIFNETMASK, (caddr_t)&ifr) < 0)
				if (errno != EADDRNOTAVAIL) {
					perror("% save: SIOCGIFNETMASK");
					close(ifs);
					continue;
				}
			sin2.sin_addr =
			    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

			mask = ntohl(sin2.sin_addr.s_addr);
			mbits = mask ? 33 - ffs(mask) : 0;

			fprintf(output, " ip %s/%i\n", inet_ntoa(sin.sin_addr), mbits);
		}

		/*
		 * print interface mtu
		 */
		fprintf(output, " mtu %li\n", if_mtu);
 
		/*
		 * print rate if available, print bucket value only if
		 * it is not equivalent to the default value.  we try
		 * to print values in megabits/kilobits only when they
		 * round off to an integer value
		 */
		rate = get_tbr(ifnp->if_name, TBR_RATE);
		bucket = get_tbr(ifnp->if_name, TBR_BUCKET);

		if(rate && bucket) {
			if (ROUNDMBPS(rate))
				snprintf(rate_str, sizeof(rate_str), "%lim",
				    rate/1000/1000);
			else if (ROUNDKBPS(rate))
				snprintf(rate_str, sizeof(rate_str), "%lik",
				    rate/1000);
			else
				snprintf(rate_str, sizeof(rate_str), "%lu",
				    rate);

			if (size_bucket(ifnp->if_name, rate) == bucket)
				bucket_str[0] = '\0';
			else {
				if (ROUNDKBYTES(bucket))
					snprintf(bucket_str, sizeof(bucket_str),
					    " %lik", bucket/1024);
				else
					snprintf(bucket_str, sizeof(bucket_str),					    " %lu", bucket);
			}

			fprintf(output, " rate %s%s\n", rate_str, bucket_str);
		}

		/*
		 * print vlan tag, parent if available.  if a tag is set
		 * but there is no parent, discard.
		 */
		memset(&vreq, 0, sizeof(struct vlanreq));
		ifr.ifr_data = (caddr_t)&vreq;

		if (ioctl(ifs, SIOCGETVLAN, (caddr_t)&ifr) != -1) {
			if(vreq.vlr_tag && (vreq.vlr_parent[0] != '\0'))
				fprintf(output, " vlan %d %s\n", vreq.vlr_tag,
				    vreq.vlr_parent);
		}

		/*
		 * print shutdown if interface is not up
		 */
		if (!(flags & IFF_UP))
			fprintf(output, " shutdown\n");
        }
	close(ifs);
	if_freenameindex(ifn_list);

#if 0
	cfg_routes(SHOW_IP_CFG);
#endif

	return(0);
}

#if 0
/*
 * Here we can either SHOW_IP view routes in a regular view, SHOW_ARP view arp
 * table in a regular view, SHOW_IP_CFG static routes in a format for the
 * config file, SHOW_ARP_CFG static arps in a format for the config file
 */
void
kern_routes(FILE *output, int cmd);
{
	size_t needed;
	int af = AF_INET;
	int mib[6], rlen, seqno;
	char *buf = NULL, *next, *lim = NULL;
	struct rt_msghdr *rtm;
	struct sockaddr *sa;

	if (cmd != SHOW_IP && cmd != SHOW_ARP && cmd != SHOW_IP_CFG &&
	    cmd != SHOW_ARP_CFG) {
		printf ("%% cfg_routes: internal error");
		return (1);
	}

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		perror("% Unable to open routing socket");
		return;
	}

	shutdown(s, 0); /* Don't want to read back our messages */

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;		/* protocol */
	mib[3] = 0;		/* wildcard address family */
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;		/* no flags */
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		printf("%% route-sysctl-estimate\n");
		close(s);
		return;
	}
	if (needed) {
		if ((buf = malloc(needed)) == NULL) {
			printf("%% flushroutes: malloc\n");
			close(s);
			return;
		}
		if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
			printf("%% flushroutes: actual retrieval of routing table\n");
			free(buf);
			close(s);
			return;
		}
		lim = buf + needed;
	}
	if (verbose) {
		(void) printf("%% Examining routing table from sysctl\n");
		if (af)
			printf("%% (address family %d)\n", af); 
	}
	if (buf == NULL) {
		printf ("%% No routing table to flush\n");
		close(s);
		return;
	}
	seqno = 0;              /* ??? */
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if (verbose)
			print_rtmsg(rtm, rtm->rtm_msglen);
		if ((rtm->rtm_flags & (RTF_GATEWAY|RTF_STATIC|RTF_LLINFO)) == 0)
			continue;
		sa = (struct sockaddr *)(rtm + 1);
		if (af) {
			if (sa->sa_family != af)
				continue;
		}
		if (sa->sa_family == AF_KEY)
			continue;  /* Don't flush SPD */
		if (debugonly)
			continue;
/*
		rtm->rtm_type = RTM_DELETE;
		rtm->rtm_seq = seqno;
		rlen = write(s, next, rtm->rtm_msglen);
		if (rlen < (int)rtm->rtm_msglen) {
			(void) fprintf(stderr,
			    "route: write to routing socket: %s\n",
			    strerror(errno));
			(void) printf("%% flushroutes: got only %d for rlen\n",
			    rlen);
			break;
		}
*/
		seqno++;
		{
			struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
			(void) printf("%-20.20s ", routename_sa(sa));
/*rtm->rtm_flags & RTF_HOST ?
                            routename_sa(sa) : netname(sa));*/
			sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) +
			    (char *)sa);
			(void) printf("%-20.20s ", routename_sa(sa));
			(void) printf("deleted\n");
		}
	}
	free(buf);
	close(s);
}

#endif
