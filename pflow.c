/*
 * From: $OpenBSD: /usr/src/sbin/ifconfig/ifconfig.c,v 1.311 2015/12/10
 * 17:26:59 mmcc Exp $
 */

/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <sys/socket.h>
#include <sys/syslimits.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>
#include <net/if_pflow.h>

#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "externs.h"

int
pflow_addr(const char *val, struct sockaddr_storage *ss)
{
	struct addrinfo hints, *res0;
	int error, flag;
	char *cp, *ip, *port, buf[HOST_NAME_MAX + 1 + sizeof(":65535")];

	if (strlcpy(buf, val, sizeof(buf)) >= sizeof(buf)) {
		printf("%% pflow_addr: bad value: (%s)\n", val);
		return -1;
	}
	port = NULL;
	cp = buf;
	if (*cp == '[')
		flag = 1;
	else
		flag = 0;

	for (; *cp; ++cp) {
		if (*cp == ']' && *(cp + 1) == ':' && flag) {
			*cp = '\0';
			*(cp + 1) = '\0';
			port = cp + 2;
			break;
		}
		if (*cp == ']' && *(cp + 1) == '\0' && flag) {
			*cp = '\0';
			port = NULL;
			break;
		}
		if (*cp == ':' && !flag) {
			*cp = '\0';
			port = cp + 1;
			break;
		}
	}

	ip = buf;
	if (flag)
		ip++;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;	/* dummy */
	hints.ai_flags = AI_NUMERICHOST;

	if ((error = getaddrinfo(ip, port, &hints, &res0)) != 0) {
		printf("%% pflow_addr: error in address string: %s\n",
		       gai_strerror(error));
		return -1;
	}
	memcpy(ss, res0->ai_addr, res0->ai_addr->sa_len);
	freeaddrinfo(res0);
	return 0;
}

/*
 * An address as pflow_addr() reads it back, in result, PFLOW_ADDRSTRLEN
 * long: an IPv6 address in [], and ":port" if it has one.
 * Returns 1 if the address is not set.
 */
int
pflow_addrstr(struct sockaddr_storage *ss, char *result)
{
	char buf[NI_MAXHOST];
	in_port_t port;
	int error;

	switch (ss->ss_family) {
	case AF_INET:
		if (((struct sockaddr_in *)ss)->sin_addr.s_addr == INADDR_ANY)
			return 1;
		port = ((struct sockaddr_in *)ss)->sin_port;
		break;
	case AF_INET6:
		if (IN6_IS_ADDR_UNSPECIFIED(
		    &((struct sockaddr_in6 *)ss)->sin6_addr))
			return 1;
		port = ((struct sockaddr_in6 *)ss)->sin6_port;
		break;
	default:
		return 1;
	}
	error = getnameinfo((struct sockaddr *)ss, ss->ss_len, buf,
	    sizeof(buf), NULL, 0, NI_NUMERICHOST);
	if (error) {
		printf("%% pflow_addrstr: getnameinfo: %s\n",
		    gai_strerror(error));
		return 1;
	}
	snprintf(result, PFLOW_ADDRSTRLEN, ss->ss_family == AF_INET6 ?
	    "[%s]" : "%s", buf);
	if (port != 0)
		snprintf(result + strlen(result), PFLOW_ADDRSTRLEN -
		    strlen(result), ":%u", ntohs(port));
	return 0;
}

int
pflow_status(int type, int ifs, char *ifname, char *result)
{
	struct ifreq ifr;
	struct pflowreq preq;

	bzero(&ifr, sizeof(struct ifreq));
	bzero(&preq, sizeof(struct pflowreq));
	ifr.ifr_data = (caddr_t) & preq;
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGETPFLOW, (caddr_t) & ifr) == -1)
		return 1;

	if (type == PFLOW_SENDER)
		return pflow_addrstr(&preq.flowsrc, result);
	if (type == PFLOW_RECEIVER)
		return pflow_addrstr(&preq.flowdst, result);
	if (type == PFLOW_VERSION) {
		snprintf(result, PFLOW_ADDRSTRLEN, "%d", preq.version);
		return 0;
	}
	return 1;
}
