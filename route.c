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
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/route.h>
#include <arpa/inet.h>
#include "externs.h"
#include "ip.h"

int
route(int argc, char **argv)
{
	u_short cmd = 0, bits;
	ip_t dest, gate;
	struct in_addr mask;
	char *q, *s;

	if (strncasecmp(argv[0], "no", strlen("no")) == 0) {
		cmd = RTM_DELETE; 
		argc--;
		argv++;
	} else
		cmd = RTM_ADD;

	argc--;
	argv++;

	if (argc < 1 || argc > 2) {
		printf("%% [no] route destination[/bits] gateway\n");
		printf("%% [no] route destination[/netmask] gateway\n");
		printf("%% route flush\n");
		return(1);
	}

	if (strncasecmp(argv[0], "flush", strlen("flush")) == 0) {
		if (cmd == RTM_DELETE) {
			printf("%% Invalid command\n");
			return(1);
		} else {
			flushroutes(AF_INET);
			return(0);
		}
	}

	memset(&dest, 0, sizeof(ip_t));
	memset(&gate, 0, sizeof(ip_t));

	/*
	 * We parse this argument first so that we can give out error
	 * messages in a sane order
	 */
	q = strchr(argv[0], '/');
	if (q)
		*q = '\0';
	if (!(inet_aton(argv[0], &dest.addr.sin) && strchr(argv[0], '.'))) {
		printf("%% %s is not an IP address\n", argv[0]);
		return(1);
	}
	if (q) {
		s = q + 1;
		if (inet_aton(s, &mask) && strchr(s, '.')) {
			mask.s_addr = ntohl(mask.s_addr);
			bits = mask.s_addr ? 33 - ffs(mask.s_addr) : 0;
		} else {
			if(strspn(s, "0123456789") == strlen(s)) {
				/* assume bits after slash */
				bits = strtoul(s, 0, 0);
				if (bits > 32) {
					printf("%% Invalid bit length\n");
					return(1);
				}
			} else {
				printf("%% Invalid destination mask\n");
				return(1);
			}
		}
	} else {
		/*
		 * If no netmask was specified, we assume the user refers to
		 * a host and not a network.
		 */
		bits = 32;	
	}

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

	dest.bitlen = bits;
	dest.family = AF_INET;
	kernel_route(&dest, &gate, cmd);

	return 0;
}
