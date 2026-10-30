/*
 * Steal some useful routines from top
 *
 * Copyright (c) 1984, 1989, William LeFebvre, Rice University
 * Copyright (c) 1989, 1990, 1992, William LeFebvre, Northwestern University
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
 * IN NO EVENT SHALL THE AUTHOR OR HIS EMPLOYER BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ip.h"
#include "externs.h"

/*
 * string_index(string, array) - find string in array and return index
 */
int
string_index(char *string, char **array)
{
	int i = 0;

	while (*array != NULL) {
		if (strncmp(string, *array, strlen(string)) == 0)
			return (i);
		array++;
		i++;
	}
	return (-1);
}

/*
 * format_time(seconds) - format number of seconds into a suitable display
 * that will fit within 6 characters.  Note that this routine builds its
 * string in a static area.  If it needs to be called more than once without
 * overwriting previous data, then we will need to adopt a technique similar
 * to the one used for format_k.
 */

/*
 * Explanation: We want to keep the output within 6 characters.  For low
 * values we use the format mm:ss.  For values that exceed 999:59, we switch
 * to a format that displays hours and fractions:  hhh.tH.  For values that
 * exceed 999.9, we use hhhh.t and drop the "H" designator.  For values that
 * exceed 9999.9, we use "???".
 */

char *
format_time(time_t seconds)
{
	static char result[10];

	/* sanity protection */
	if (seconds < 0 || seconds > (99999l * 360l)) {
		strlcpy(result, "   ???", sizeof result);
	} else if (seconds >= (1000l * 60l)) {
		/* alternate (slow) method displaying hours and tenths */
		snprintf(result, sizeof(result), "%5.1fH",
		    (double) seconds / (double) (60l * 60l));

		/*
		 * It is possible that the snprintf took more than 6
		 * characters. If so, then the "H" appears as result[6].  If
		 * not, then there is a \0 in result[6].  Either way, it is
		 * safe to step on.
		 */
		result[6] = '\0';
	} else {
		/* standard method produces MMM:SS */
		/* we avoid printf as must as possible to make this quick */
		snprintf(result, sizeof(result), "%3d:%02d", (int)seconds / 60,
		    (int)seconds % 60);
	}
	return (result);
}

/*
 * format_k(amt) - format a kilobyte memory value, returning a string
 * suitable for display.  Returns a pointer to a static
 * area that changes each call.  "amt" is converted to a
 * string with a trailing "K".  If "amt" is 10000 or greater,
 * then it is formatted as megabytes (rounded) with a
 * trailing "M".
 */

/*
 * Compromise time.  We need to return a string, but we don't want the
 * caller to have to worry about freeing a dynamically allocated string.
 * Unfortunately, we can't just return a pointer to a static area as one
 * of the common uses of this function is in a large call to snprintf where
 * it might get invoked several times.  Our compromise is to maintain an
 * array of strings and cycle thru them with each invocation.  We make the
 * array large enough to handle the above mentioned case.  The constant
 * NUM_STRINGS defines the number of strings in this array:  we can tolerate
 * up to NUM_STRINGS calls before we start overwriting old information.
 * Keeping NUM_STRINGS a power of two will allow an intelligent optimizer
 * to convert the modulo operation into something quicker.  What a hack!
 */

#define NUM_STRINGS 8

char *
format_k(uint64_t amt)
{
	static char retarray[NUM_STRINGS][16];
	static int  idx = 0;
	char *ret, tag = 'K';

	ret = retarray[idx];
	idx = (idx + 1) % NUM_STRINGS;

	if (amt >= 10000) {
		amt /= 1024;
		tag = 'M';
		if (amt >= 10000) {
			amt /= 1024;
			tag = 'G';
		}
	}
	snprintf(ret, sizeof(retarray[0]), "%llu%c", amt, tag);
	return (ret);
}

/*
 * returns 1 if one valid, matching interface name is found
 * returns 0 for no valid or failure
 */
int
is_valid_ifname(char *ifname)
{
	struct if_nameindex *ifn_list, *ifnp;
	int count = 0;

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% is_valid_ifname: if_nameindex failed\n");
		return 0;
	}
	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		if (strcasecmp(ifname, ifnp->if_name) == 0)
			count++;
	}
	if_freenameindex(ifn_list);

	if (count == 1)
		return 1;
	else
		return 0;
}

int
getinetaddr(const char *host, struct in_addr *inap)
{
	struct hostent *hp;

	if (inet_aton(host, inap) == 1)
		return (0);
	if ((hp = gethostbyname(host)) == NULL) {
		printf("%% getinetaddr: %s: %s\n", host, hstrerror(h_errno));
		return (-1);
	}
	memcpy(inap, hp->h_addr, sizeof(*inap));
	return (0);
}

int
parse_host(const char *host, struct sockaddr_in6 *sin6)
{
	struct addrinfo hints, *res;
	int gai_error;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_flags = AI_NUMERICHOST;

	gai_error = getaddrinfo(host, NULL, &hints, &res);
	if (gai_error) {
		printf("%% %s: %s\n", host, gai_strerror(gai_error));
		return 1;
	}
	*sin6 = *(struct sockaddr_in6 *)res->ai_addr;
	freeaddrinfo(res);
	return 0;
}

void
in6_clearscopeid(struct sockaddr_in6 *sin6)
{
	if ((IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_INTFACELOCAL(&sin6->sin6_addr)) &&
	    *(u_int16_t *)&sin6->sin6_addr.s6_addr[2] == 0 &&
	    sin6->sin6_scope_id) {
		*(u_int16_t *)&sin6->sin6_addr.s6_addr[2] =
		    htons(sin6->sin6_scope_id & 0xffff);
		sin6->sin6_scope_id = 0;
	}
}

int
parse_ipv6(char *arg, struct in6_addr *addr)
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
void
parse_ip_pfx(char *arg, int type, ip_t *argip)
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
