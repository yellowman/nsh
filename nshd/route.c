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
#include "args.h"

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

/*
 * route: a destination with its prefix length, a gateway, and the
 * route's flags, expire and mtu, which route_parse() reads as route()
 * did
 */
#define RT_BLACKHOLE	0x001
#define RT_CLONING	0x002
#define RT_IFACE	0x004
#define RT_LLINFO	0x008
#define RT_NOMPATH	0x010
#define RT_NOSTATIC	0x020
#define RT_PROTO1	0x040
#define RT_PROTO2	0x080
#define RT_REJECT	0x100
const struct argkey route_keys[] = {
	{ "blackhole", RT_BLACKHOLE }, { "cloning", RT_CLONING },
	{ "iface", RT_IFACE }, { "llinfo", RT_LLINFO },
	{ "nompath", RT_NOMPATH }, { "nostatic", RT_NOSTATIC },
	{ "proto1", RT_PROTO1 }, { "proto2", RT_PROTO2 },
	{ "reject", RT_REJECT }, { NULL }
};
#define RT_DEST		0	/* and its prefix length, 1 */
#define RT_GATE		2
#define RT_FLAGS	3
#define RT_EXPIRE	4
#define RT_MTU		5

/* ip, as an address value in v */
static void
route_value(struct facts_value *v, ip_t *ip)
{
	if (ip->family == AF_INET)
		facts_address(v, FACT_INET, &ip->addr.in, 4, 0);
	else
		facts_address(v, FACT_INET6, &ip->addr.in6, 16, 0);
}

int
route_parse(const struct argcmd *c, int argc, char **argv,
    struct argvals *a)
{
	u_int32_t net;
	ip_t dest, gate;
	struct in_addr tmp;
	struct in6_addr tmp6;
	char buf[INET6_ADDRSTRLEN];
	long long bits = 0;
	int i, ch;

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

	if (argc < 1) {
		routeusage();
		return -1;
	}

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

		argc--;
		argv++;
	} else if (a->set) {
		printf("%% No gateway specified\n");
		return -1;
	}

	noptind = 0;
	if (argc >= 1) {
		/* parse flags */
		while ((ch = nopt(argc, argv, routeflags)) != -1) {
			switch (ch) {
			const char *errmsg = NULL;

			case 'b':	/* blackhole */
				bits |= RT_BLACKHOLE;
				break;
			case 'c':	/* cloning */
				bits |= RT_CLONING;
				break;
			case 'e':	/* expire */
				facts_i64(&a->v[RT_EXPIRE], strtonum(
				    argv[noptind - 1], 0, INT_MAX, &errmsg));
				if (errmsg) {
					printf("%% Invalid expire %s: %s\n",
					    argv[noptind - 1], errmsg);
					return -1;
				}
				break;
			case 'i':	/* iface */
				bits |= RT_IFACE;
				break;
			case 'l':	/* llinfo */
				bits |= RT_LLINFO;
				break;
			case 'u':	/* nompath */
				bits |= RT_NOMPATH;
				break;
			case 'm':	/* mtu */
				facts_i64(&a->v[RT_MTU], strtonum(
				    argv[noptind - 1], 64, 65536, &errmsg));
				if (errmsg) {
					printf("%% Invalid route mtu %s: %s\n",
					    argv[noptind - 1], errmsg);
					return -1;
				}
				break;
			case 'n':	/* nostatic */
				bits |= RT_NOSTATIC;
				break;
			case '1':	/* proto1 */
				bits |= RT_PROTO1;
				break;
			case '2':	/* proto2 */
				bits |= RT_PROTO2;
				break;
			case 'r':	/* reject */
				bits |= RT_REJECT;
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

	route_value(&a->v[RT_DEST], &dest);
	facts_i64(&a->v[RT_DEST + 1], dest.bitlen);
	if (gate.family != 0)
		route_value(&a->v[RT_GATE], &gate);
	if (bits != 0)
		facts_i64(&a->v[RT_FLAGS], bits);
	return 0;
}

/* the address in value v, as ip */
static void
route_ip(const struct facts_value *v, ip_t *ip)
{
	ip->family = v->v.a.family == FACT_INET ? AF_INET : AF_INET6;
	memcpy(&ip->addr, v->v.a.bytes, v->v.a.len);
}

int
route_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	u_short cmd = set ? RTM_ADD : RTM_DELETE;
	ip_t dest, gate;
	struct rt_metrics rt_metrics;
	long long bits = v[RT_FLAGS].type != FACT_NONE ? v[RT_FLAGS].v.i : 0;
	int inits = 0, flags = RTF_STATIC | RTF_MPATH;

	memset(&rt_metrics, 0, sizeof(rt_metrics));
	memset(&gate, 0, sizeof(ip_t));
	memset(&dest, 0, sizeof(ip_t));
	route_ip(&v[RT_DEST], &dest);
	dest.bitlen = v[RT_DEST + 1].v.i;
	if (v[RT_GATE].type != FACT_NONE) {
		route_ip(&v[RT_GATE], &gate);
		flags |= RTF_GATEWAY;
	}
	if (bits & RT_BLACKHOLE)
		flags |= RTF_BLACKHOLE;
	if (bits & RT_CLONING)
		flags |= RTF_CLONING;
	if (bits & RT_IFACE)
		flags &= ~RTF_GATEWAY;
	if (bits & RT_LLINFO)
		flags |= RTF_LLINFO;
	if (bits & RT_NOMPATH)
		flags &= ~RTF_MPATH;
	if (bits & RT_NOSTATIC)
		flags &= ~RTF_STATIC;
	if (bits & RT_PROTO1)
		flags |= RTF_PROTO1;
	if (bits & RT_PROTO2)
		flags |= RTF_PROTO2;
	if (bits & RT_REJECT)
		flags |= RTF_REJECT;
	if (v[RT_EXPIRE].type != FACT_NONE) {
		rt_metrics.rmx_expire = v[RT_EXPIRE].v.i ?
		    v[RT_EXPIRE].v.i + time(NULL) : 0;
		inits |= RTV_EXPIRE;
	}
	if (v[RT_MTU].type != FACT_NONE) {
		rt_metrics.rmx_mtu = v[RT_MTU].v.i;
		inits |= RTV_MTU;
	}

	/*
	 * Adding blackhole or reject routes requires a gateway even if the
	 * "iface" parameter was specified. A gateway argument is required when
	 * adding routes so simply setting the GATEWAY flag here is sufficient.
	 */
	if (cmd == RTM_ADD && (flags & (RTF_BLACKHOLE|RTF_REJECT)))
		flags |= RTF_GATEWAY;

	if (cand != NULL && cmd == RTM_ADD && rt_metrics.rmx_expire != 0) {
		printf("%% an expiring route is not saved in the"
		    " configuration\n");
		return -1;
	}

	flags |= RTF_UP;

	/*
	 * Do the route...
	 */
	if (ip_route(&dest, gate.family ? &gate : NULL, cmd, flags,
	    cli_rtable, rt_metrics, inits, cand) != 0)
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
route_cand(struct rt_msghdr *rtm, struct cand *cand)
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
		for (n = 0; (l = cand_line(cand, "route", n)) != NULL; n++)
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
		i = cand_setting(cand, ST_ON, "%s", buf);
		free(buf);
		if (i == -1)
			return -1;
		break;
	case RTM_DELETE:
		/* without a gateway, only a route that is alone */
		for (n = 0; (l = cand_line(cand, "route", n)) != NULL; n++)
			if (isword(l, 1, d) &&
			    (gate == NULL || isword(l, 2, g)) && found++ == 0)
				key = l;
		if (found != 1) {
			errno = ESRCH;
			return -1;
		}
		if (cand_setting(cand, ST_OFF, "%s", key) == -1)
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
