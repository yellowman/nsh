/* $nsh: route.c,v 1.7 2003/04/17 16:18:45 chris Exp $ */
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <net/route.h>
#include <arpa/inet.h>
#include "ip.h"
#include "externs.h"

int
route(int argc, char **argv)
{
	struct in_addr tmp;
	u_short cmd = 0;
	u_int32_t net;
	ip_t dest, gate;

	if (NO_ARG(argv[0])) {
		cmd = RTM_DELETE; 
		argc--;
		argv++;
	} else
		cmd = RTM_ADD;

	argc--;
	argv++;

	if (argc < 1 || argc > 2) {
		printf("%% route <destination>[/bits] <gateway>\n");
		printf("%% route <destination>[/netmask] <gateway>\n");
		printf("%% no route <destination>[/bits] [gateway]\n");
		printf("%% no route <destination>[/netmask] [gateway]\n");
		return(1);
	}

	memset(&gate, 0, sizeof(ip_t));
	memset(&dest, 0, sizeof(ip_t));

	dest = parse_ip(argv[0], ASSUME_NETMASK);
	if (dest.family == 0)
		/* bad arguments */
		return(1);

	if (argc > 1) {
		if (!(inet_aton(argv[1], &gate.addr.sin) &&
		    strchr(argv[1], '.'))) {
			printf("%% %s is not an IP address\n", argv[1]);
			return(1);
		}
	} else if (cmd == RTM_ADD) {
		printf("%% No gateway specified\n");
		return(1);
	}

	/*
	 * Detect if a user is adding a route with a non-network address.
	 */
	net = in4_netaddr(dest.addr.sin.s_addr,
	    (u_int32_t)htonl(0xffffffff << (32 - dest.bitlen)));

	if (ntohl(dest.addr.sin.s_addr) != net) {
		tmp.s_addr = htonl(net);
		printf("%% Inconsistent address and mask (%s/%i?)\n",
		    inet_ntoa(tmp), dest.bitlen);
		return(1);
	}

	/*
	 * Do the route...
	 */
	ip_route(&dest, &gate, cmd);
	return(0);
}

void show_route(char *arg)
{
	ip_t dest;

	memset(&dest, 0, sizeof(ip_t));

	dest = parse_ip(arg, NO_NETMASK);
	if (dest.family == 0)
		return;

	ip_route(&dest, NULL, RTM_GET);
	/*
	 * ip_route() calls rtmsg() which calls
	 * print_getmsg() on RTM_GET to show a route,
	 * so nothing else needs to happen here...
	 */

	return;
}

/*
 * A return value with ip_t.family == 0 means failure
 * (and fail message was displayed to user) otherwise argument was parsed
 * into ip_t
 *
 * 'int type' is used if the user does not specify a netmask in the argument.
 *
 * The type can be ASSUME_NETMASK in which case we assume a host netmask
 * (all ones) or NO_NETMASK in which case ip_t.bitlen = -1
 * 
 * If ip_route() sees that the destination ip_t.bitlen == -1, it does not
 * setup a netmask sockaddr in the routing message
 */
ip_t parse_ip(char *arg, int type)
{
	ip_t argip;
	struct in_addr mask;
	char *q, *s;

	memset(&argip, 0, sizeof(ip_t));

	/*
	 * We parse this argument first so that we can give out error
	 * messages in a sane order
	 */
	q = strchr(arg, '/');
	if (q)
		*q = '\0';
	if (!(inet_aton(arg, &argip.addr.sin) && strchr(arg, '.'))) {
		printf("%% %s is not an IP address\n", arg);
		return(argip);
	}
	if (q) {
		s = q + 1;
		if (inet_aton(s, &mask) && strchr(s, '.')) {
		    mask.s_addr = ntohl(mask.s_addr);
			argip.bitlen = mask.s_addr ? 33 - ffs(mask.s_addr) : 0;
		} else {
			if(strspn(s, "0123456789") == strlen(s)) {
				/* assume bits after slash */
				argip.bitlen = strtoul(s, 0, 0);
				if (argip.bitlen > 32) {
					printf("%% Invalid bit length\n");
					return(argip);
				}
			} else {
				printf("%% Invalid mask specified\n");
				return(argip);
			}
		}
	} else {
		/*
		 * If no netmask was specified, we assume the user refers to
		 * a host and not a network.  Or not, depending on type.
		 */
		switch (type) {
		case NO_NETMASK:
			argip.bitlen = -1;
			break;
		case ASSUME_NETMASK:
			argip.bitlen = 32;
			break;
		default:
			printf("%% parse_ip: Internal error\n");
			break;
		}
	}
	argip.family = AF_INET;
	return(argip);
}
