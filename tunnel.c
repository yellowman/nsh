/* From: $OpenBSD: /usr/src/sbin/ifconfig/ifconfig.c,v 1.64 2002/05/22 08:21:02 deraadt Exp $ */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <sys/errno.h>
#include <netdb.h>

#include "externs.h"

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

	if ((set && argc != 2) || (!set && argc > 2)) {
		printf("%% tunnel <src ip> <dest ip>\n");
		printf("%% no tunnel [src ip] [dest ip]\n");
		return(0);
	}

	if(set)
		settunnel(ifs, ifname, argv[0], argv[1]);
	else
		deletetunnel(ifs, ifname);
	return(0);
}

int
settunnel(int s, char *ifname, char *src, char *dst)
{
	struct addrinfo hints, *srcres, *dstres;
	int ecode;
	struct if_laddrreq req;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;	/* dummy */

	if ((ecode = getaddrinfo(src, NULL, &hints, &srcres)) != 0) {
		printf("%% unable to parsing source address string: %s\n",
		     gai_strerror(ecode));
		return(0);
	}

	if ((ecode = getaddrinfo(dst, NULL, &hints, &dstres)) != 0) {
		printf("%% unable to parsing destination address string: %s\n",
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

	memset(&req, 0, sizeof(req));
	(void) strlcpy(req.iflr_name, ifname, sizeof(req.iflr_name));
	memcpy(&req.addr, srcres->ai_addr, srcres->ai_addrlen);
	memcpy(&req.dstaddr, dstres->ai_addr, dstres->ai_addrlen);
	if (ioctl(s, SIOCSLIFPHYADDR, &req) < 0) {
		if (errno = EINVAL)
			printf("%% tunnel cannot be used on %s interface\n",
			    ifname);
		else
			perror("% settunnel: SIOCSLIFPHYADDR");
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

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(s, SIOCDIFPHYADDR, &ifr) < 0) {
		perror("% deletetunnel: SIOCDIFPHYADDR");
		return(0);
	}
	return(1);
}
