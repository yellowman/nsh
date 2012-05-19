/* $nsh: tunnel.c,v 1.8 2012/05/19 23:53:20 chris Exp $ */
/* From: $OpenBSD: /usr/src/sbin/ifconfig/ifconfig.c,v 1.64 2002/05/22 08:21:02 deraadt Exp $ */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netdb.h>

#include "externs.h"

int settunnel(int, char *, char *, char *, char *);
int deletetunnel(int, char *);

int
inttunnel(char *ifname, int ifs, int argc, char **argv)
{
	int set;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if (((set && argc !=2 && argc != 4) || (set && argc == 4 &&
	    !isprefix(argv[2], "rdomain"))) || (!set && argc > 4)) {
		printf("%% tunnel <src ip> <dest ip> [rdomain <domain>]\n");
		printf("%% no tunnel [src ip] [dest ip] [rdomain <domain>]\n");
		return(0);
	}

	if(set && argc == 2)
		settunnel(ifs, ifname, argv[0], argv[1], NULL);
	else if(set && argc == 4)
		settunnel(ifs, ifname, argv[0], argv[1], argv[3]);
	else
		deletetunnel(ifs, ifname);
	return(0);
}

int
settunnel(int s, char *ifname, char *src, char *dst, char *rdomain)
{
	const char *errmsg = NULL;
	struct addrinfo *srcres, *dstres;
	int ecode, rdomainid;
	struct if_laddrreq req;
	struct ifreq ifr;

	if ((ecode = getaddrinfo(src, NULL, NULL, &srcres)) != 0) {
		printf("%% unable to parse source address string: %s\n",
		     gai_strerror(ecode));
		return(0);
	}

	if ((ecode = getaddrinfo(dst, NULL, NULL, &dstres)) != 0) {
		printf("%% unable to parse destination address string: %s\n",
		     gai_strerror(ecode));
		return(0);
	}

	if (srcres->ai_addr->sa_family != dstres->ai_addr->sa_family) {
		printf(
		     "%% source and destination address families do not match");
		return(0);
	}

	if (srcres->ai_addrlen > sizeof(req.addr) ||
	    dstres->ai_addrlen > sizeof(req.dstaddr)) {
		printf("%% invalid sockaddr\n");
		goto end;
	}

	if (rdomain != NULL) {
		rdomainid = strtonum(rdomain, 0, RT_TABLEID_MAX, &errmsg);
		if (errmsg) {
			printf("%% invalid routing domain id %s: %s\n", rdomain, errmsg);
			goto end;
		}
		bzero(&ifr, sizeof(ifr));
		ifr.ifr_rdomainid = rdomainid;
		strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(s, SIOCSLIFPHYRTABLE, (caddr_t)&ifr) < 0) {	
			switch(errno) {
			case EINVAL:
				printf("%% tunnel rdomain %i not found\n", rdomainid);
				break;
			case ENOTTY:
				printf("%% cannot set tunnel rdomain on %s interface\n", ifname);
				break;
			default:
				printf("%% settunnel: SIOCSLIFPHYRTABLE: %s\n",
				    strerror(errno));
				break;
			}
			goto end;
		}
	}

	bzero(&req, sizeof(req));
	(void) strlcpy(req.iflr_name, ifname, sizeof(req.iflr_name));
	memcpy(&req.addr, srcres->ai_addr, srcres->ai_addrlen);
	memcpy(&req.dstaddr, dstres->ai_addr, dstres->ai_addrlen);
	if (ioctl(s, SIOCSLIFPHYADDR, &req) < 0) {
		if (errno == EINVAL)
			printf("%% tunnel cannot be used on %s interface\n",
			    ifname);
		else
			printf("%% settunnel: SIOCSLIFPHYADDR: %s\n",
			    strerror(errno));
	}

 end:
	freeaddrinfo(srcres);
	freeaddrinfo(dstres);
	return(1);
}

int
deletetunnel(int s, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(s, SIOCDIFPHYADDR, &ifr) < 0) {
		printf("%% deletetunnel: SIOCDIFPHYADDR: %s\n",
		    strerror(errno));
		return(0);
	}
	return(1);
}
