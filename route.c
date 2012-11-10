/*
 * Copyright (c) 2002 Chris Cappuccio <chris@nmedia.net>
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
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <net/route.h>
#include <arpa/inet.h>
#include "ip.h"
#include "externs.h"

#define ASSUME_NETMASK 1

int
route(int argc, char **argv)
{
	struct in_addr tmp;
	u_short cmd = 0;
	u_int32_t net;
	ip_t dest, gate;
	int flags = 0;

	if (NO_ARG(argv[0])) {
		cmd = RTM_DELETE; 
		argc--;
		argv++;
	} else
		cmd = RTM_ADD;

	argc--;
	argv++;

	if (argc < 1 || argc > 3) {
		printf("%% route <destination>[/bits] <gateway> [flags]\n");
		printf("%% route <destination>[/netmask] <gateway> [flags]\n");
		printf("%% no route <destination>[/bits] [gateway] [flags]\n");
		printf("%% no route <destination>[/netmask] [gateway] [flags]\n");
		return(1);
	}

	memset(&gate, 0, sizeof(ip_t));
	memset(&dest, 0, sizeof(ip_t));

	parse_ip_pfx(argv[0], ASSUME_NETMASK, &dest);
	if (dest.family == 0)
		/* bad arguments */
		return(1);

	if (argc > 1) {
		switch (dest.family) {
		case AF_INET:
			if (!inet_pton(AF_INET, argv[1], &gate.addr.in)) {
				printf("%% %s is not an IPv4 address\n", argv[1]);
				return(1);
			}
			gate.family = AF_INET;
			break;
		case AF_INET6:
			if (parse_ipv6(argv[1], &gate.addr.in6) != 0) {
				printf("%% %s is not an IPv6 address\n", argv[1]);
				return(1);
			}
			gate.family = AF_INET6;
			break;
		default:
			printf("%% unknown gateway address family %d\n", dest.family);
			return(1);
		}
		if (argc == 3) {
			if (isprefix(argv[2], "reject")) {
				flags = RTF_REJECT;
			} else {
				printf("%% unsupported flag\n");
				return(1);
			}
		}
	} else if (cmd == RTM_ADD) {
		printf("%% No gateway specified\n");
		return(1);
	}

	/*
	 * Detect if a user is adding a route with a non-network address.
	 */
	switch (dest.family) {
	case AF_INET:
		net = in4_netaddr(dest.addr.in.s_addr,
		    (u_int32_t)htonl(0xffffffff << (32 - dest.bitlen)));
		if (ntohl(dest.addr.in.s_addr) != net) {
			tmp.s_addr = htonl(net);
			printf("%% Inconsistent address and mask (%s/%i?)\n",
			    inet_ntoa(tmp), dest.bitlen);
			return(1);
		}
	case AF_INET6:
		/* XXX invent check */
		break;
	default:
		printf("%% unknown destination address family %d\n", dest.family);
		return(1);
	}

	flags |= RTF_UP | RTF_STATIC | RTF_MPATH;

	/*
	 * Do the route...
	 */
	if (argc > 1)
		ip_route(&dest, &gate, cmd, flags, cli_rtable);
	else
		ip_route(&dest, NULL, cmd, flags, cli_rtable);
	return(0);
}

void show_route(char *arg, int tableid)
{
	ip_t dest;

	memset(&dest, 0, sizeof(ip_t));

	parse_ip_pfx(arg, NO_NETMASK, &dest);
	if (dest.family == 0)
		return;

	ip_route(&dest, NULL, RTM_GET, RTF_UP, tableid);

	/*
	 * ip_route() calls rtmsg() which calls
	 * print_getmsg() on RTM_GET to show a route,
	 * so nothing else needs to happen here...
	 */

	return;
}

int parse_ipv6(char *arg, struct in6_addr *addr)
{
	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_socktype = SOCK_STREAM; 
	if ((error = getaddrinfo(arg, "0", &hints, &res)) != 0) {
		return error;
	}
	if (sizeof(struct sockaddr_in6) != res->ai_addrlen) {
		freeaddrinfo(res);
		return EAI_ADDRFAMILY;
	}
	if (res->ai_next) {
		/* not gonna happen with ai_flags = AI_NUMERICHOST */
		printf("%% parse_ipv6: %s resolved to multiple values\n", arg);
		freeaddrinfo(res);
		return EAI_OVERFLOW;
	}
	in6_clearscopeid((struct sockaddr_in6 *)res->ai_addr);
	memcpy(addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
	    sizeof(struct in6_addr));
	freeaddrinfo(res);

	return 0;
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
void parse_ip_pfx(char *arg, int type, ip_t *argip)
{
	struct in_addr mask;
	char *q, *s;

	q = strchr(arg, '/');
	if (q)
		*q = '\0';
	if (inet_pton(AF_INET, arg, &argip->addr.in)) {
		argip->family = AF_INET;
	} else if (parse_ipv6(arg, &argip->addr.in6) == 0) {
		argip->family = AF_INET6;
	} else {
		argip->family = 0;
		printf("%% %s is not an IPv4 or IPv6 address\n", arg);
		return;
	}
	if (q) {
		s = q + 1;
		if (argip->family == AF_INET && inet_pton(AF_INET, s, &mask)) {
			mask.s_addr = ntohl(mask.s_addr);
			argip->bitlen = mask.s_addr ? 33 - ffs(mask.s_addr) : 0;
		} else {
			if(strspn(s, "0123456789") == strlen(s)) {
				/* assume bits after slash */
				argip->bitlen = strtoul(s, 0, 0);
				if ((argip->family == AF_INET6 &&
				    argip->bitlen > 128) ||
				    (argip->family == AF_INET &&
				    argip->bitlen > 32)) {
					printf("%% Invalid bit length\n");
					argip->family = 0;
					return;
				}
			} else {
				printf("%% Invalid mask specified\n");
				argip->family = 0;
				return;
			}
		}
	} else {
		/*
		 * If no netmask was specified, we assume the user refers to
		 * a host and not a network.  Or not.
		 */
		switch (type) {
		case NO_NETMASK:
			argip->bitlen = -1;
			break;
		case ASSUME_NETMASK:
			argip->bitlen = argip->family == AF_INET ? 32 : 128;
			break;
		default:
			printf("%% parse_ip: Internal error\n");
			argip->family = 0;
			break;
		}
	}
	return;
}
