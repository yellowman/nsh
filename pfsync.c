/*
 * Copyright (c) 2004 Chris Cappuccio <chris@nmedia.net>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
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
#include <netinet/ip_ipsp.h>
#include <net/if_pfsync.h>
#include "externs.h"

#define PFSYNC_MAXUPDATES 128

int
intsyncdev(int argc, char **argv, ...)
{
	struct ifreq ifr;
	struct pfsyncreq preq;
	int set;
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
		printf("%% syncdev <if>\n");
		printf("%% no syncdev [if]\n");
		return (0);
	}

	if (!isprefix("pfsync", ifname)) {
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
intsyncpeer(int argc, char **argv, ...)
{
	struct ifreq ifr;
	struct pfsyncreq preq;
	struct addrinfo hints, *peerres;
	int set, ecode;
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

	if (!isprefix("pfsync", ifname)) {
		printf("%% syncpeer is only for pfsync devices\n");
		return 0;
	}

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% syncpeer <IPv4 peer address>\n");
		printf("%% no syncpeer [IPv4 peer address]\n");
		return (0);
	}

	bzero(&preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t) &preq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCGETPFSYNC, (caddr_t)&ifr) == -1) {
			printf("%% intsyncpeer: SIOCGETPFSYNC: %s\n",
			    strerror(errno));
		return 0;
	}

	if (set) {
		bzero(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;

		if ((ecode = getaddrinfo(argv[0], NULL, &hints, &peerres)) != 0)
		{
			printf("%% error in parsing address string: %s\n",
			    gai_strerror(ecode));
			return 0;
		}

		if (peerres->ai_addr->sa_family != AF_INET) {
			printf("%% only IPv4 allowed for syncpeer\n");
			freeaddrinfo(peerres);
			return 0;
		}
		preq.pfsyncr_syncpeer.s_addr = ((struct sockaddr_in *)
		    peerres->ai_addr)->sin_addr.s_addr;
	} else {
		preq.pfsyncr_syncpeer.s_addr = 0;
	}

	if (ioctl(ifs, SIOCSETPFSYNC, (caddr_t)&ifr) == -1) {
			printf("%% intsyncpeer: SIOCSETPFSYNC: %s\n",
			    strerror(errno));
	}

	if (set)
		freeaddrinfo(peerres);

	return 0;
}

int
intmaxupd(int argc, char **argv, ...)
{
	struct ifreq ifr;
	struct pfsyncreq preq;
	u_int32_t val;
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

	if ((!set && argc > 2) || (set && (argc < 1 || argc > 2)) ||
	    (set && argc == 2 && !isprefix(argv[1], "defer"))) {
		printf("%% maxupd <max pfsync updates> [defer]\n");
		printf("%% no maxupd [max pfsync updates] [defer]\n");
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
		if (argc == 2)
			preq.pfsyncr_defer = 1;
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

	/* syncdev must be first */
	if (preq.pfsyncr_syncdev[0] != '\0')
		fprintf(output, " syncdev %s\n", preq.pfsyncr_syncdev);
	/* syncpeer */
	if (preq.pfsyncr_syncpeer.s_addr != htonl(INADDR_PFSYNC_GROUP))
		fprintf(output, " syncpeer %s\n", inet_ntoa(
		    preq.pfsyncr_syncpeer));
	if (preq.pfsyncr_maxupdates != PFSYNC_MAXUPDATES || preq.pfsyncr_defer) {
		fprintf(output, " maxupd %i",
		    preq.pfsyncr_maxupdates);
		if (preq.pfsyncr_defer)
			fprintf(output, " defer");
		fprintf(output, "\n");
	}
	return (0);
}
