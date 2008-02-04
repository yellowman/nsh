/* $nsh $ */
/*
 * Copyright (c) 2004
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include "externs.h"

#define PFSYNC_MAXUPDATES 128

int
intsyncdev(char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	struct pfsyncreq preq;
	int set;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% syncdev <if>\n");
		printf("%% no syncdev [if]\n");
		return (0);
	}

	if (!MIN_ARG(ifname, "pfsync")) {
		printf("%% syncdev is only for pfsync devices\n");
		return 0;
	}

	bzero((char *) &preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t) & preq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCGETPFSYNC, (caddr_t) & ifr) == -1) {
		printf("%% intsyncdev: SIOCGETPFSYNC: %s\n", strerror(errno));
		return (0);
	}

	if (argv[0])
		if (!is_valid_ifname(argv[0])) {
			printf("%% Interface not found: %s\n", argv[0]);
			return (0);
		}

	if (set) {
		strlcpy(preq.pfsyncr_syncdev, argv[0],
			sizeof(preq.pfsyncr_syncdev));
		set_ifflag(ifs, ifname, IFF_UP);
	} else
		bzero((char *) &preq.pfsyncr_syncdev,
		      sizeof(preq.pfsyncr_syncdev));

	if (ioctl(ifs, SIOCSETPFSYNC, (caddr_t) & ifr) == -1) {
		if (errno == ENOBUFS)
			printf("%% Invalid synchronization interface: %s\n",
			    argv[0]);
		else
			printf("%% intsyncdev: SIOCSETPFSYNC: %s\n",
			    strerror(errno));
	}
	return (0);
}

int
intsyncpeer(char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	struct pfsyncreq preq;
	struct addrinfo hints, *peerres;
	int set, ecode;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if (!MIN_ARG(ifname, "pfsync")) {
		printf("%% syncpeer is only for pfsync devices\n");
		return 0;
	}

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% syncpeer <IPv4 peer address>\n");
		printf("%% no syncpeer [IPv4 peer address]\n");
		return (0);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	if ((ecode = getaddrinfo(argv[0], NULL, &hints, &peerres)) != 0) {
		printf("%% error in parsing address string: %s\n",
		    gai_strerror(ecode));
		return 0;
	}

	if (peerres->ai_addr->sa_family != AF_INET) {
		printf("%% only IPv4 addresses supported for syncpeer\n");
		freeaddrinfo(peerres);
		return 0;
	}
	if (set)
		preq.pfsyncr_syncpeer.s_addr = ((struct sockaddr_in *)
		    peerres->ai_addr)->sin_addr.s_addr;
	else
		preq.pfsyncr_syncpeer.s_addr = 0;

	if (ioctl(ifs, SIOCSETPFSYNC, (caddr_t)&ifr) == -1) {
		if (errno == ENXIO)
			printf("%% peer device (syncdev) not yet configured\n");
		else
			printf("%% intsyncpeer: SIOCSETPFSYNC: %s\n",
			    strerror(errno));
	}

	freeaddrinfo(peerres);

	return 0;
}

int
intmaxupd(char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	struct pfsyncreq preq;
	u_int32_t val;
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
		printf("%% maxupd <max pfsync updates>\n");
		printf("%% no maxupd [max pfsync updates]\n");
		return (0);
	}
	bzero((char *) &preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t) & preq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCGETPFSYNC, (caddr_t) & ifr) == -1) {
		printf("%% intmaxupd: SIOCGETPFSYNC: %s\n", strerror(errno));
		return (0);
	}
	if (set) {
		errno = 0;
		val = strtonum(argv[0], 0, INT_MAX, &errmsg);
		if (errmsg) {
			printf("%% maxupd value out of range %s: %s\n", argv[0],
			    errmsg);
			return (0);
		}
		preq.pfsyncr_maxupdates = (int)val;
	} else
		preq.pfsyncr_maxupdates = PFSYNC_MAXUPDATES;

	if (ioctl(ifs, SIOCSETPFSYNC, (caddr_t) & ifr) == -1) {
		if (errno == EINVAL)
			printf("%% maxupd value out of range\n");
		else
			printf("%% intmaxupd: SIOCSETPFSYNC: %s\n",
			    strerror(errno));
	}
	return (0);
}

int
conf_pfsync(FILE *output, int s, char *ifname)
{
	struct ifreq ifr;
	struct pfsyncreq preq;

	bzero((char *) &preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t) & preq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGETPFSYNC, (caddr_t) & ifr) == -1)
		return (0);

	if (preq.pfsyncr_syncdev[0] != '\0') {
		fprintf(output, " syncdev %s\n", preq.pfsyncr_syncdev);
		if (preq.pfsyncr_syncpeer.s_addr != INADDR_PFSYNC_GROUP)
			fprintf(output, " syncpeer %s", inet_ntoa(
			    preq.pfsyncr_syncpeer));
		if (preq.pfsyncr_maxupdates != PFSYNC_MAXUPDATES)
			fprintf(output, " maxupd %i\n",
			    preq.pfsyncr_maxupdates);
	}
	return (0);
}
