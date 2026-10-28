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
#include <errno.h>
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
#include "settings.h"
#include "facts.h"
#include "showfacts.h"

#define ASSUME_NETMASK 1

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

void routeusage(void);
static int isword(const char *, int, const char *);

void
routeusage(void)
{
	printf("%% route <destination>[/bits] <gateway> [flags]\n");
	printf("%% route <destination>[/netmask] <gateway> [flags]\n");
	printf("%% no route <destination>[/bits] [gateway] [flags]\n");
	printf("%% no route <destination>[/netmask] [gateway] [flags]\n");
}

int
route(int argc, char **argv, ...)
{
	u_short cmd = 0;
	u_int32_t net;
	ip_t dest, gate;
	struct in_addr tmp;
	struct in6_addr tmp6;
	struct rt_metrics rt_metrics;
	char buf[INET6_ADDRSTRLEN];
	int i, ch, inits = 0, flags = RTF_STATIC | RTF_MPATH;

	static struct nopts routeflags[] = {
		{ "blackhole",	no_arg,		'b' },
		{ "cloning",	no_arg,		'c' },
		{ "expire",	req_arg,	'e' },
		{ "iface",	no_arg,		'i' },
		{ "llinfo",	no_arg,		'l' },
		{ "nompath",	no_arg,		'u' },
		{ "mtu",	req_arg,	'm' },
		{ "nostatic",	no_arg,		'n' },
		{ "proto1",	no_arg,		'1' },
		{ "proto2",	no_arg,		'2' },
		{ "reject",	no_arg,		'r' },
		{ NULL,		0,		0   }
	};

	if (NO_ARG(argv[0])) {
		cmd = RTM_DELETE; 
		argc--;
		argv++;
	} else
		cmd = RTM_ADD;

	argc--;
	argv++;

	if (argc < 1) {
		routeusage();
		return -1;
	}

	memset(&rt_metrics, 0, sizeof(rt_metrics));
	memset(&gate, 0, sizeof(ip_t));
	memset(&dest, 0, sizeof(ip_t));

	parse_ip_pfx(argv[0], ASSUME_NETMASK, &dest);
	if (dest.family == 0)
		/* bad arguments */
		return -1;

	argc--;
	argv++;

	if (argc >= 1) {
		switch (dest.family) {
		case AF_INET:
			if (!inet_pton(AF_INET, argv[0], &gate.addr.in)) {
				printf("%% %s is not an IPv4 address\n",
				    argv[0]);
				return -1;
			}
			gate.family = AF_INET;
			break;
		case AF_INET6:
			if (parse_ipv6(argv[0], &gate.addr.in6) != 0) {
				printf("%% %s is not an IPv6 address\n",
				    argv[0]);
				return -1;
			}
			gate.family = AF_INET6;
			break;
		default:
			printf("%% unknown gateway address family %d\n", dest.family);
			return -1;
		}

		flags |= RTF_GATEWAY;
		argc--;
		argv++;
	} else if (cmd == RTM_ADD) {
		printf("%% No gateway specified\n");
		return -1;
	}

	noptind = 0;
	if (argc >= 1) {
		long long relative_expire;

		/* parse flags */
		while ((ch = nopt(argc, argv, routeflags)) != -1) {
			switch (ch) {
			const char *errmsg = NULL;

			case 'b':	/* blackhole */
				flags |= RTF_BLACKHOLE;
				break;
			case 'c':	/* cloning */
				flags |= RTF_CLONING;
				break;
			case 'e':	/* expire */
				relative_expire = strtonum(
				    argv[noptind - 1], 0, INT_MAX, &errmsg);
				if (errmsg) {
					printf("%% Invalid expire %s: %s\n",
					    argv[noptind - 1], errmsg);
					return -1;
				}
				rt_metrics.rmx_expire = relative_expire ?
				    relative_expire + time(NULL) : 0;
				inits |= RTV_EXPIRE;
				break;
			case 'i':	/* iface */
				flags &= ~RTF_GATEWAY;
				break;
			case 'l':	/* llinfo */
				flags |= RTF_LLINFO;
				break;
			case 'u':	/* nompath */
				flags &= ~RTF_MPATH;
				break;
			case 'm':	/* mtu */
				rt_metrics.rmx_mtu = strtonum(
				    argv[noptind - 1], 64, 65536, &errmsg);
				if (errmsg) {
					printf("%% Invalid route mtu %s: %s\n",
					    argv[noptind - 1], errmsg);
					return -1;
				}
				inits |= RTV_MTU;
				break;
			case 'n':	/* nostatic */
				flags &= ~RTF_STATIC;
				break;
			case '1':	/* proto1 */
				flags |= RTF_PROTO1;
				break;
			case '2':	/* proto2 */
				flags |= RTF_PROTO2;
				break;
			case 'r':	/* reject */
				flags |= RTF_REJECT;
				break;
			default:
				printf("%% route: nopt table error\n");
				return -1;
			}
		}
	}

	if (argc - noptind != 0) {
		/* leftover salmon */
		printf("%% %s", nopterr);
		if (argv[noptind])
			printf(": %s", argv[noptind]);
		printf("\n");
		routeusage();
		return -1;
	}
	/*
	 * Detect if a user is adding a route with a non-network address.
	 */
	switch (dest.family) {
	case AF_INET:
		net = in4_netaddr(dest.addr.in.s_addr,
		    (u_int32_t)htonl(0xffffffffULL << (32 - dest.bitlen)));
		if (ntohl(dest.addr.in.s_addr) != net) {
			tmp.s_addr = htonl(net);
			printf("%% Inconsistent address and mask (%s/%i?)\n",
			    inet_ntoa(tmp), dest.bitlen);
			return -1;
		}
		break;
	case AF_INET6:
		tmp6 = dest.addr.in6;
		for (i = dest.bitlen; i < 128; i++)
			tmp6.s6_addr[i / 8] &= ~(0x80 >> (i % 8));
		if (memcmp(&tmp6, &dest.addr.in6, sizeof(tmp6)) != 0) {
			printf("%% Inconsistent address and mask (%s/%i?)\n",
			    inet_ntop(AF_INET6, &tmp6, buf, sizeof(buf)),
			    dest.bitlen);
			return -1;
		}
		break;
	default:
		printf("%% unknown destination address family %d\n", dest.family);
		return -1;
	}

	/*
	 * Adding blackhole or reject routes requires a gateway even if the
	 * "iface" parameter was specified. A gateway argument is required when
	 * adding routes so simply setting the GATEWAY flag here is sufficient.
	 */
	if (cmd == RTM_ADD && (flags & (RTF_BLACKHOLE|RTF_REJECT)))
		flags |= RTF_GATEWAY;

	if (candidate && cmd == RTM_ADD && rt_metrics.rmx_expire != 0) {
		printf("%% an expiring route is not saved in the"
		    " configuration\n");
		return -1;
	}

	flags |= RTF_UP;

	/*
	 * Do the route...
	 */
	if (ip_route(&dest, gate.family ? &gate : NULL, cmd, flags,
	    cli_rtable, rt_metrics, inits) != 0)
		return -1;
	return 0;
}

/*
 * A routing message in configure private: RTM_ADD or RTM_DELETE as
 * rtm_output() and rtable_insert() take it, on the routes the
 * candidate's lines describe, each the line conf_print_rtm() prints for
 * it.  Returns the message's length, or -1 with errno as the kernel
 * sets it.
 */
int
route_cand(struct rt_msghdr *rtm)
{
	struct sockaddr *sa, *dst = NULL, *gate = NULL, *mask = NULL;
	struct rtmsg m;
	char d[NI_MAXHOST + 5], g[NI_MAXHOST], *buf = NULL, *l, *key = NULL;
	char *cp;
	size_t len, n, found = 0;
	FILE *f;
	int i;

	cp = (char *)rtm + rtm->rtm_hdrlen;
	for (i = 1; i; i <<= 1)
		if (i & rtm->rtm_addrs) {
			sa = (struct sockaddr *)cp;
			if (i == RTA_DST)
				dst = sa;
			else if (i == RTA_GATEWAY)
				gate = sa;
			else if (i == RTA_NETMASK)
				mask = sa;
			ADVANCE(cp, sa);
		}
	if (dst == NULL || mask == NULL) {
		errno = EINVAL;
		return -1;
	}
	strlcpy(d, netname(dst, mask), sizeof(d));
	if (gate != NULL)
		strlcpy(g, routename(gate), sizeof(g));

	switch (rtm->rtm_type) {
	case RTM_ADD:
		if (gate == NULL) {
			errno = EINVAL;
			return -1;
		}
		/* refuse a duplicate, or a second route to d without MPATH */
		for (n = 0; (l = cand_line("route", n)) != NULL; n++)
			if (isword(l, 1, d) && (!(rtm->rtm_flags & RTF_MPATH) ||
			    isword(l, 2, g))) {
				errno = EEXIST;
				return -1;
			}
		/* the route as the kernel keeps it */
		memcpy(&m, rtm, rtm->rtm_msglen);
		m.m_rtm.rtm_flags |= RTF_UP;
		memset(&m.m_rtm.rtm_rmx, 0, sizeof(m.m_rtm.rtm_rmx));
		if (rtm->rtm_inits & RTV_MTU)
			m.m_rtm.rtm_rmx.rmx_mtu = rtm->rtm_rmx.rmx_mtu;
		if ((f = open_memstream(&buf, &len)) == NULL)
			return -1;
		conf_print_rtm(f, &m.m_rtm, "route ", dst->sa_family);
		if (fclose(f) == EOF || len == 0) {
			free(buf);
			errno = EINVAL;
			return -1;
		}
		buf[len - 1] = '\0';
		i = cand_setting(ST_ON, "%s", buf);
		free(buf);
		if (i == -1)
			return -1;
		break;
	case RTM_DELETE:
		/* without a gateway, only a route that is alone */
		for (n = 0; (l = cand_line("route", n)) != NULL; n++)
			if (isword(l, 1, d) &&
			    (gate == NULL || isword(l, 2, g)) && found++ == 0)
				key = l;
		if (found != 1) {
			errno = ESRCH;
			return -1;
		}
		if (cand_setting(ST_OFF, "%s", key) == -1)
			return -1;
		break;
	default:
		errno = EOPNOTSUPP;
		return -1;
	}
	return rtm->rtm_msglen;
}

/* Is word n of line, from 0, s? */
static int
isword(const char *line, int n, const char *s)
{
	size_t len;

	while (n-- > 0) {
		line += strcspn(line, " ");
		line += strspn(line, " ");
	}
	len = strcspn(line, " ");
	return len == strlen(s) && strncmp(line, s, len) == 0;
}

int
is_ip_addr(char *arg)
{
	ip_t argip;

	if (inet_pton(AF_INET, arg, &argip.addr.in))
		return 1;
	if (parse_ipv6(arg, &argip.addr.in6) == 0)
		return 1;
	return 0;
}

/* show route address: asked of nshd, and rendered here */
int
show_route(char *arg, int tableid)
{
	ip_t dest;

	memset(&dest, 0, sizeof(ip_t));
	parse_ip_pfx(arg, NO_NETMASK, &dest);
	if (dest.family == 0)
		return -1;
	return facts_show(stdout, "lookup %s %d", arg, tableid);
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
