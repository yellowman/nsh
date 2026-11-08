/* From: $OpenBSD: /usr/src/sbin/ifconfig/ifconfig.c,v 1.295 2015/01/16 06:39:58 deraadt Exp $ */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if_types.h>
#include <net/if_bridge.h>
#include <netdb.h>

#include "externs.h"
#include "settings.h"

int settunnel(int, char *, char *, char *, char *);
int settunnelrdomain(int, char *, char *);
int settunnelttl(int, char *, char *);
int settunneldf(int, char *, int);
int settunnelecn(int, char *, int);
int setvnetid(int, char *, char *);
int delvnetid(int, char *);
int deletetunnel(int, char *);
void tunnelusage(int);
static int vnetid_arg(char *, int64_t *);
static int vnetid_range(char *, int64_t);
static int cand_vnetid(char *, int, char *);
static int tunnel_ttl(char *, char *);
static int tunnel_startttl(char *);
static int tunnel_rdomain(char *);
static int tunnel_addr(char *, char *, char *, char *, int *);
static int tunnel_arg(char *, char *, size_t, char **);
static int tunnel_mcast(char *);
static int endpoint_arg(char *, char *, struct sockaddr_storage *, char *);
static int cand_endpoint(char *, int);
static int cand_tunnel(char *, int, int, char *, char *, char *, char *,
    char *, int, int);

/* tunnel, and tunneladdr, a tunnel's source with no destination */
static char *tunnelcmds[] = { "tunnel", "tunneladdr", NULL };

/*
 * maxaddr and timeout: how many addresses bpe, nvgre and vxlan learn,
 * and for how many seconds. The kernel's etherbridge takes 1 to 4096
 * addresses and 8 to 3600 seconds, and starts with 100 and 240.
 */
static const struct cachec {
	char *name;
	u_long set, get;
	long long min, max, start;
} cachecs[] = {
	{ "maxaddr",	SIOCBRDGSCACHE,	SIOCBRDGGCACHE,	1,	4096,	100 },
	{ "timeout",	SIOCBRDGSTO,	SIOCBRDGGTO,	8,	3600,	240 },
	{ NULL,		0,		0,		0,	0,	0 }
};

/*
 * The vnetids each driver takes, as the kernel checks them. With
 * vnetflowid, gre, egre and mgre take 0 to FLOWID_MAX.
 */
static const struct vnetidr {
	char *name;
	long long min, max;
} vnetidrs[] = {
	{ "vlan",	1,	4094 },
	{ "svlan",	1,	4094 },
	{ "veb",	1,	4094 },
	{ "bpe",	0,	16777215 },
	{ "nvgre",	0,	16777215 },
	{ "vxlan",	0,	16777215 },
	{ "gre",	0,	4294967295LL },
	{ "egre",	0,	4294967295LL },
	{ "mgre",	0,	4294967295LL },
	{ "eoip",	0,	65535 },
	{ "erspan",	0,	1023 },
	{ NULL,		0,	0 }
};
#define FLOWID_MAX	16777215

static struct nopts tunnelopts[] = {
	{ "rdomain",	req_arg,	'r' },
	{ "ttl",	req_arg,	't' },
	{ "df",		no_arg,		'd' },
	{ "ecn",	no_arg,		'e' },
	{ NULL,		0,		0   },
};

int
intvnetid(int argc, char **argv, ...)
{
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

	if ((set && argc != 1) || (!set && argc > 1)) {
		printf("%% vnetid <vnetid>\n");
		printf("%% no vnetid [vnetid]\n");
		return -1;
        }
	if (candidate)
		return cand_vnetid(ifname, set, argv[0]);
	if (set)
		return setvnetid(ifs, ifname, argv[0]);
	return delvnetid(ifs, ifname);
}

/* vnetid in configure private */
static int
cand_vnetid(char *ifname, int set, char *vnetida)
{
	int64_t vnetid;

	if (!cand_takes(ifname, SIOCSVNETID)) {
		printf("%% vnetid not supported on %s\n", ifname);
		return -1;
	}
	if (!set) {
		if (!cand_takes(ifname, SIOCDVNETID)) {
			printf("%% The vnetid of %s cannot be removed\n",
			    ifname);
			return -1;
		}
		/* the kernel's vnetflowid goes with the vnetid */
		if (cand_takes(ifname, SIOCSVNETFLOWID) &&
		    cand_setting(ST_DEFAULT, "vnetflowid") == -1)
			return -1;
		/* a veb keeps a line that says it has none */
		return cand_setting(default_vnetid(ifname) != 0 ? ST_OFF :
		    ST_DEFAULT, "vnetid");
	}
	if (vnetid_arg(vnetida, &vnetid) == -1)
		return -1;
	if (vnetid == 0) {
		printf("%% The configuration does not keep vnetid 0\n");
		return -1;
	}
	if (vnetid_range(ifname, vnetid) == -1)
		return -1;
	return cand_setting(ST_ON, "vnetid %lld", vnetid);
}

/* Does ifname's driver take vnetid? 0, or -1 after saying why not */
static int
vnetid_range(char *ifname, int64_t vnetid)
{
	const struct vnetidr *v;
	long long max;

	for (v = vnetidrs; v->name != NULL; v++)
		if (isprefix(v->name, ifname))
			break;
	if (v->name == NULL)
		return 0;
	max = v->max;
	if (max > FLOWID_MAX && cand_line("vnetflowid", 0) != NULL)
		max = FLOWID_MAX;
	if (vnetid < v->min || vnetid > max) {
		printf("%% vnetid %lld out of range for %s: %lld to %lld\n",
		    vnetid, ifname, v->min, max);
		return -1;
	}
	return 0;
}

/*
 * Can the candidate's interface have vnetflowid? Only with a vnetid
 * from 0 to FLOWID_MAX: the kernel uses the rest of the key as the flow
 * ID. 0, or -1 after saying why not.
 */
int
cand_vnetflowid(void)
{
	const char *errmsg = NULL;
	char *l;

	if ((l = cand_line("vnetid", 0)) != NULL)
		strtonum(l + strlen("vnetid "), 0, FLOWID_MAX, &errmsg);
	if (l == NULL || errmsg != NULL) {
		printf("%% vnetflowid needs a vnetid from 0 to %d\n",
		    FLOWID_MAX);
		return -1;
	}
	return 0;
}

void
tunnelusage(int addr)
{
	if (addr) {
		printf("%% tunneladdr <src ip>[:port] [ttl <ttl>] [df]"
		    " [ecn]\n");
		printf("%% no tunneladdr [src ip] [ttl <ttl>] [df] [ecn]\n");
		return;
	}
	printf("%% tunnel <src ip>[:port] <dest ip> [ttl <ttl>] [df] [ecn]\n");
	printf("%% no tunnel [src ip] [dest ip] [ttl <ttl>] [df] [ecn]\n");
}

int
inttunnel(int argc, char **argv, ...)
{
	int set, addr, ch, df = 0, ecn = 0, r;
	char **c, *src = NULL, *rdomain = NULL, *ttl = NULL;
	char *srcport = NULL, *dstip = NULL, *dstport = NULL;
	char sbuf[NI_MAXHOST + sizeof(":65535")];
	char dbuf[NI_MAXHOST + sizeof(":65535")];
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

	c = (char **)genget(argv[0], tunnelcmds, sizeof(char *));
	if (c == 0 || Ambiguous(c)) {
		printf("%% Internal error - Invalid argument %s\n", argv[0]);
		return -1;
	}
	addr = c == &tunnelcmds[1];

	argc--;
	argv++;

	if (set && argc < (addr ? 1 : 2)) {
		tunnelusage(addr);
		return -1;
	}

	if (argc > 0 && tunnel_arg(argv[0], sbuf, sizeof(sbuf), &srcport)) {
		src = sbuf;
		argc--;
		argv++;
	}
	if (!addr && argc > 0 &&
	    tunnel_arg(argv[0], dbuf, sizeof(dbuf), &dstport)) {
		dstip = dbuf;
		argc--;
		argv++;
	}
	/* older versions of nsh wrote vxlan's port on the destination */
	if (dstport != NULL) {
		if (srcport != NULL) {
			printf("%% a tunnel has one port, on its source\n");
			return -1;
		}
		srcport = dstport;
	}
	if (srcport != NULL && !isprefix("vxlan", ifname)) {
		printf("%% only vxlan takes a port\n");
		return -1;
	}
	/* mgre's tunnel has no destination, and only vxlan's may have both */
	if (set && addr && !isprefix("mgre", ifname) &&
	    !isprefix("vxlan", ifname)) {
		printf("%% tunneladdr not supported on %s\n", ifname);
		return -1;
	}
	if (set && !addr && isprefix("mgre", ifname)) {
		printf("%% %s has no destination: use tunneladdr\n", ifname);
		return -1;
	}
	/*
	 * A source is one host. A destination is a multicast group on
	 * nvgre, either on vxlan, and one host on the others.
	 */
	if (set && src != NULL && tunnel_mcast(src) == 1) {
		printf("%% a tunnel's source cannot be a multicast group\n");
		return -1;
	}
	if (set && dstip != NULL && isprefix("nvgre", ifname) &&
	    tunnel_mcast(dstip) == 0) {
		printf("%% %s's destination must be a multicast group\n",
		    ifname);
		return -1;
	}
	if (set && dstip != NULL && !isprefix("nvgre", ifname) &&
	    !isprefix("vxlan", ifname) && tunnel_mcast(dstip) == 1) {
		printf("%% %s's destination cannot be a multicast group\n",
		    ifname);
		return -1;
	}

	noptind = 0;
	while ((ch = nopt(argc, argv, tunnelopts)) != -1)
		switch(ch) {
		case 'r':
			rdomain = argv[noptind - 1];
			break;
		case 't':
			ttl = argv[noptind - 1];
			break;
		case 'd':
			df = 1;
			break;
		case 'e':
			ecn = 1;
			break;
		}

	if (argc - noptind != 0) {
		/* leftover salmon */
		printf("%% %s", nopterr);
		if (argv[noptind])
			printf(": %s", argv[noptind]);
		printf("\n");
		tunnelusage(addr);
		return -1;
	}

	if (candidate)
		return cand_tunnel(ifname, set, addr, src, srcport, dstip,
		    rdomain, ttl, df, ecn);

	if (set) {
		/* without its addresses, the tunnel gets nothing else */
		if ((r = settunnel(ifs, ifname, src, srcport, dstip)) == -1)
			return -1;
		if (rdomain && settunnelrdomain(ifs, ifname, rdomain) == -1)
			r = -1;
		if (ttl && settunnelttl(ifs, ifname, ttl) == -1)
			r = -1;
		/* df and ecn are off unless the command gives them */
		if ((df || cand_takes(ifname, SIOCSLIFPHYDF)) &&
		    settunneldf(ifs, ifname, df) == -1)
			r = -1;
		if ((ecn || cand_takes(ifname, SIOCSLIFPHYECN)) &&
		    settunnelecn(ifs, ifname, ecn) == -1)
			r = -1;
	} else
		r = deletetunnel(ifs, ifname);
	return r;
}

/*
 * tunnel, or with addr tunneladdr, in configure private. The line has
 * the addresses as conf_tunnel() prints them, the source with vxlan's
 * port unless it is VXLAN_PORT, then the ttl, and ecn and df if they
 * are on. The kernel keeps the ttl a command leaves out, so it comes
 * from the candidate's tunnel or tunneladdr line, or for a new line, it
 * is the ttl the tunnel starts with. ecn and df are off unless the
 * command gives them. rdomain is the tunneldomain line. An interface
 * has one tunnel, so either line takes the other's place.
 */
static int
cand_tunnel(char *ifname, int set, int addr, char *src, char *srcport,
    char *dstip, char *rdomain, char *ttla, int df, int ecn)
{
	char s[NI_MAXHOST], d[NI_MAXHOST], line[1024], port[sizeof(":65535")];
	char ttls[sizeof(" ttl copy")], *l, *w, *p;
	const char *errmsg;
	int af, daf, sport, ttl = 0, rdomainid = 0, r;

	if (!cand_takes(ifname, set ? SIOCSLIFPHYADDR : SIOCDIFPHYADDR)) {
		printf("%% tunnel not supported on %s\n", ifname);
		return -1;
	}
	if (!set) {
		/* the kernel's tunnel goes, whichever line made it */
		if (cand_setting(ST_DEFAULT, "tunneladdr") == -1)
			return -1;
		return cand_setting(ST_DEFAULT, "tunnel");
	}
	if (src == NULL || (!addr && dstip == NULL)) {
		tunnelusage(addr);
		return -1;
	}
	if (rdomain != NULL) {
		if (!cand_takes(ifname, SIOCSLIFPHYRTABLE)) {
			printf("%% cannot set tunnel rdomain on %s interface\n",
			    ifname);
			return -1;
		}
		if ((rdomainid = tunnel_rdomain(rdomain)) == -1)
			return -1;
	}
	if (ttla != NULL) {
		if (!cand_takes(ifname, SIOCSLIFPHYTTL)) {
			printf("%% tunnel ttl not supported on %s\n", ifname);
			return -1;
		}
		if ((ttl = tunnel_ttl(ifname, ttla)) == 0)
			return -1;
	}
	if (df && !cand_takes(ifname, SIOCSLIFPHYDF)) {
		printf("%% tunnel df not supported on %s\n", ifname);
		return -1;
	}
	if (ecn && !cand_takes(ifname, SIOCSLIFPHYECN)) {
		printf("%% tunnel ecn not supported on %s\n", ifname);
		return -1;
	}
	if ((af = tunnel_addr("source", src, srcport, s, &sport)) == 0)
		return -1;
	if (!addr) {
		if ((daf = tunnel_addr("destination", dstip, NULL, d,
		    NULL)) == 0)
			return -1;
		if (af != daf) {
			printf("%% source and destination address families"
			    " do not match\n");
			return -1;
		}
	}

	if (ttl == 0 && ((l = cand_line("tunnel", 0)) != NULL ||
	    (l = cand_line("tunneladdr", 0)) != NULL)) {
		/* the ttl the kernel keeps */
		strlcpy(line, l, sizeof(line));
		for (w = strtok_r(line, " ", &p); w != NULL;
		    w = strtok_r(NULL, " ", &p))
			if (strcmp(w, "ttl") == 0 &&
			    (w = strtok_r(NULL, " ", &p)) != NULL)
				ttl = strcmp(w, "copy") == 0 ? -1 :
				    strtonum(w, 1, 0xff, &errmsg);
	}
	if (ttl == 0)
		ttl = tunnel_startttl(ifname);

	port[0] = ttls[0] = '\0';
	if (sport > 0 && sport != VXLAN_PORT)
		snprintf(port, sizeof(port), ":%d", sport);
	if (ttl == -1)
		strlcpy(ttls, " ttl copy", sizeof(ttls));
	else
		snprintf(ttls, sizeof(ttls), " ttl %d", ttl);
	if (cand_setting(ST_DEFAULT, addr ? "tunnel" : "tunneladdr") == -1)
		return -1;
	if (addr)
		r = cand_setting(ST_ON, "tunneladdr %s%s%s%s%s", s, port, ttls,
		    ecn ? " ecn" : "", df ? " df" : "");
	else
		r = cand_setting(ST_ON, "tunnel %s%s %s%s%s%s", s, port, d,
		    ttls, ecn ? " ecn" : "", df ? " df" : "");
	if (r == -1)
		return -1;
	if (rdomain == NULL)
		return 0;
	if (rdomainid != 0)
		return cand_setting(ST_ON, "tunneldomain %d", rdomainid);
	return cand_setting(ST_DEFAULT, "tunneldomain");
}

/*
 * A tunnel address as a command gives it, ip or ip:port, split into buf
 * (len bytes) and *port; an IPv6 address has no port. 1 if it is an
 * address, else 0.
 */
static int
tunnel_arg(char *arg, char *buf, size_t len, char **port)
{
	char *p;

	*port = NULL;
	if (strlcpy(buf, arg, len) >= len)
		return 0;
	if ((p = strchr(buf, ':')) != NULL && p == strrchr(buf, ':')) {
		*p++ = '\0';
		*port = p;
	}
	return is_ip_addr(buf);
}

/* Is address ip a multicast group? 1 if it is, 0 if not, -1 if no address */
static int
tunnel_mcast(char *ip)
{
	struct addrinfo *res;
	int mcast;

	if (numeric_addrinfo(ip, NULL, AF_UNSPEC, 0, &res) != 0)
		return -1;
	if (res->ai_family == AF_INET)
		mcast = IN_MULTICAST(ntohl(((struct sockaddr_in *)
		    res->ai_addr)->sin_addr.s_addr));
	else
		mcast = IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)
		    res->ai_addr)->sin6_addr);
	freeaddrinfo(res);
	return mcast != 0;
}

/*
 * A tunnel address as conf_tunnel() prints it, in buf (NI_MAXHOST), and
 * if portp, its port. Returns its family, or 0 after saying why not.
 */
static int
tunnel_addr(char *what, char *ip, char *port, char *buf, int *portp)
{
	struct addrinfo *res;
	int ecode, af;

	if ((ecode = numeric_addrinfo(ip, port, AF_UNSPEC, 0, &res)) != 0) {
		printf("%% unable to parse %s address string: %s\n", what,
		    gai_strerror(ecode));
		return 0;
	}
	af = res->ai_family;
	if (portp != NULL)
		*portp = ntohs(af == AF_INET6 ?
		    ((struct sockaddr_in6 *)res->ai_addr)->sin6_port :
		    ((struct sockaddr_in *)res->ai_addr)->sin_port);
	ecode = getnameinfo(res->ai_addr, res->ai_addrlen, buf, NI_MAXHOST,
	    NULL, 0, NI_NUMERICHOST);
	freeaddrinfo(res);
	if (ecode != 0) {
		printf("%% %s address %s: %s\n", what, ip, gai_strerror(ecode));
		return 0;
	}
	return af;
}

int
settunnel(int s, char *ifname, char *src, char *srcport, char *dstip)
{
	struct addrinfo *srcres, *dstres = NULL;
	int ecode, r = -1;
	struct if_laddrreq req;

	if ((ecode = numeric_addrinfo(src, srcport, AF_UNSPEC, 0,
	    &srcres)) != 0) {
		printf("%% unable to parse source address string: %s\n",
		     gai_strerror(ecode));
		return -1;
	}

	/* tunneladdr gives no destination */
	if (dstip != NULL &&
	    (ecode = numeric_addrinfo(dstip, NULL, AF_UNSPEC, 0,
	    &dstres)) != 0) {
		printf("%% unable to parse destination address string: %s\n",
		     gai_strerror(ecode));
		freeaddrinfo(srcres);
		return -1;
	}

	if (dstres != NULL &&
	    srcres->ai_addr->sa_family != dstres->ai_addr->sa_family) {
		printf(
		    "%% source and destination address families do not match\n");
		goto end;
	}

	if (srcres->ai_addrlen > sizeof(req.addr) ||
	    (dstres != NULL && dstres->ai_addrlen > sizeof(req.dstaddr))) {
		printf("%% invalid sockaddr\n");
		goto end;
	}

	bzero(&req, sizeof(req));
	(void) strlcpy(req.iflr_name, ifname, sizeof(req.iflr_name));
	memcpy(&req.addr, srcres->ai_addr, srcres->ai_addrlen);
	if (dstres != NULL)
		memcpy(&req.dstaddr, dstres->ai_addr, dstres->ai_addrlen);
	else {
		/* no destination, as the kernel gives it */
		req.dstaddr.ss_len = 2;
		req.dstaddr.ss_family = AF_UNSPEC;
	}
	if (ioctl_down(s, ifname, SIOCSLIFPHYADDR, &req) < 0) {
		if (errno == EINVAL)
			printf("%% tunnel cannot be used on %s interface\n",
			    ifname);
		else
			printf("%% settunnel: SIOCSLIFPHYADDR: %s\n",
			    strerror(errno));
	} else
		r = 0;

 end:
	freeaddrinfo(srcres);
	if (dstres != NULL)
		freeaddrinfo(dstres);
	return r;
}

/* maxaddr and timeout, on bpe, nvgre and vxlan */
int
intcache(int argc, char **argv, ...)
{
	const struct cachec *x;
	struct ifbrparam bp;
	const char *errmsg = NULL;
	long long val;
	va_list ap;
	char *ifname;
	int ifs, set;

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

	x = (const struct cachec *)genget(argv[0], (char **)cachecs,
	    sizeof(struct cachec));
	if (x == 0 || Ambiguous((void *)x)) {
		printf("%% Internal error - Invalid argument %s\n", argv[0]);
		return -1;
	}

	argc--;
	argv++;

	if ((set && argc != 1) || (!set && argc > 1)) {
		printf("%% %s <%lld-%lld>\n", x->name, x->min, x->max);
		printf("%% no %s [%lld-%lld]\n", x->name, x->min, x->max);
		return -1;
	}
	if (!cand_takes(ifname, x->set)) {
		printf("%% %s not supported on %s\n", x->name, ifname);
		return -1;
	}
	val = x->start;
	if (set) {
		val = strtonum(argv[0], x->min, x->max, &errmsg);
		if (errmsg) {
			printf("%% %s %s: %s\n", x->name, argv[0], errmsg);
			return -1;
		}
	}

	if (candidate) {
		/* conf_cache() leaves out what the kernel starts with */
		if (val == x->start)
			return cand_setting(ST_DEFAULT, "%s", x->name);
		return cand_setting(ST_ON, "%s %lld", x->name, val);
	}

	memset(&bp, 0, sizeof(bp));
	strlcpy(bp.ifbrp_name, ifname, sizeof(bp.ifbrp_name));
	if (x->set == SIOCBRDGSCACHE)
		bp.ifbrp_csize = val;
	else
		bp.ifbrp_ctime = val;
	if (ioctl(ifs, x->set, &bp) == -1) {
		printf("%% %s %lld: %s\n", x->name, val, strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * maxaddr and timeout, each unless it is what the kernel starts with,
 * then each endpoint
 */
void
conf_cache(FILE *output, int ifs, char *ifname)
{
	const struct cachec *x;
	struct ifbrparam bp;
	struct ifbaconf ifbac;
	struct ifbareq *ifba;
	struct sockaddr_dl *sdl;
	char *buf = NULL, *nb, ep[NI_MAXHOST];
	size_t i, len = 8192;
	long long val;

	for (x = cachecs; x->name != NULL; x++) {
		memset(&bp, 0, sizeof(bp));
		strlcpy(bp.ifbrp_name, ifname, sizeof(bp.ifbrp_name));
		if (ioctl(ifs, x->get, &bp) == -1)
			continue;
		val = x->get == SIOCBRDGGCACHE ? bp.ifbrp_csize :
		    bp.ifbrp_ctime;
		if (val != x->start)
			fprintf(output, " %s %lld\n", x->name, val);
	}

	/* the addresses learned, as many as the kernel has */
	for (;;) {
		if ((nb = realloc(buf, len)) == NULL) {
			printf("%% conf_cache: %s\n", strerror(errno));
			free(buf);
			return;
		}
		buf = nb;
		memset(&ifbac, 0, sizeof(ifbac));
		strlcpy(ifbac.ifbac_name, ifname, sizeof(ifbac.ifbac_name));
		ifbac.ifbac_len = len;
		ifbac.ifbac_buf = buf;
		if (ioctl(ifs, SIOCBRDGRTS, &ifbac) == -1) {
			free(buf);
			return;
		}
		if (ifbac.ifbac_len + sizeof(*ifba) < len)
			break;
		len *= 2;
	}
	/* the static ones are endpoint lines */
	for (i = 0; i < ifbac.ifbac_len / sizeof(*ifba); i++) {
		ifba = ifbac.ifbac_req + i;
		if (!(ifba->ifba_flags & IFBAF_STATIC))
			continue;
		if (ifba->ifba_dstsa.ss_family == AF_LINK) {
			/* bpe's: a backbone bridge's MAC address */
			sdl = (struct sockaddr_dl *)&ifba->ifba_dstsa;
			strlcpy(ep, ether_ntoa((struct ether_addr *)
			    LLADDR(sdl)), sizeof(ep));
		} else if (getnameinfo((struct sockaddr *)&ifba->ifba_dstsa,
		    ifba->ifba_dstsa.ss_len, ep, sizeof(ep), NULL, 0,
		    NI_NUMERICHOST) != 0)
			continue;
		fprintf(output, " endpoint %s", ether_ntoa(&ifba->ifba_dst));
		fprintf(output, " %s\n", ep);
	}
	free(buf);
}

/*
 * endpoint: a static entry of the addresses bpe, nvgre and vxlan learn,
 * the tunnel endpoint where a MAC address is. nvgre's and vxlan's are
 * hosts of the tunnel's family, and bpe's are the MAC addresses of
 * backbone bridges.
 */
int
intendpoint(int argc, char **argv, ...)
{
	struct ifbareq ifba;
	struct ether_addr *ea;
	char mac[sizeof("00:00:00:00:00:00")], ep[NI_MAXHOST];
	va_list ap;
	char *ifname;
	int ifs, set;

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

	if ((set && argc != 2) || (!set && (argc < 1 || argc > 2))) {
		printf("%% endpoint <mac address> <endpoint>\n");
		printf("%% no endpoint <mac address> [endpoint]\n");
		return -1;
	}
	if (!cand_takes(ifname, SIOCBRDGSADDR)) {
		printf("%% endpoint not supported on %s\n", ifname);
		return -1;
	}
	if ((ea = ether_aton(argv[0])) == NULL) {
		printf("%% Invalid MAC address %s\n", argv[0]);
		return -1;
	}
	strlcpy(mac, ether_ntoa(ea), sizeof(mac));
	memset(&ifba, 0, sizeof(ifba));
	strlcpy(ifba.ifba_name, ifname, sizeof(ifba.ifba_name));
	memcpy(&ifba.ifba_dst, ea, sizeof(ifba.ifba_dst));
	if (set && endpoint_arg(ifname, argv[1], &ifba.ifba_dstsa, ep) == -1)
		return -1;

	if (candidate) {
		if (!set)
			return cand_setting(ST_OFF, "endpoint %s", mac);
		if (cand_endpoint(ifname, ifba.ifba_dstsa.ss_family) == -1)
			return -1;
		return cand_setting(ST_ON, "endpoint %s %s", mac, ep);
	}

	ifba.ifba_flags = IFBAF_STATIC;
	if (ioctl(ifs, set ? SIOCBRDGSADDR : SIOCBRDGDADDR, &ifba) == -1) {
		printf("%% endpoint %s: %s\n", mac, strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * An endpoint as a command gives it: on bpe, a MAC address, else one
 * host's address. Fills in ss, and buf (NI_MAXHOST) as conf_cache()
 * prints it. -1 after saying why not.
 */
static int
endpoint_arg(char *ifname, char *arg, struct sockaddr_storage *ss, char *buf)
{
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	struct ether_addr *ea;
	struct addrinfo *res;

	memset(ss, 0, sizeof(*ss));
	if (isprefix("bpe", ifname)) {
		if ((ea = ether_aton(arg)) == NULL) {
			printf("%% Invalid MAC address %s\n", arg);
			return -1;
		}
		sdl->sdl_len = sizeof(*sdl);
		sdl->sdl_family = AF_LINK;
		sdl->sdl_type = IFT_ETHER;
		sdl->sdl_alen = ETHER_ADDR_LEN;
		memcpy(LLADDR(sdl), ea, ETHER_ADDR_LEN);
		strlcpy(buf, ether_ntoa(ea), NI_MAXHOST);
		return 0;
	}
	if (numeric_addrinfo(arg, NULL, AF_UNSPEC, 0, &res) != 0) {
		printf("%% endpoint %s is not an address\n", arg);
		return -1;
	}
	memcpy(ss, res->ai_addr, MIN(res->ai_addrlen, sizeof(*ss)));
	freeaddrinfo(res);
	if ((ss->ss_family == AF_INET &&
	    (sin->sin_addr.s_addr == INADDR_ANY ||
	    IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))) ||
	    (ss->ss_family == AF_INET6 &&
	    (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)))) {
		printf("%% endpoint %s is not one host\n", arg);
		return -1;
	}
	if (getnameinfo((struct sockaddr *)ss, ss->ss_len, buf, NI_MAXHOST,
	    NULL, 0, NI_NUMERICHOST) != 0) {
		printf("%% endpoint %s: getnameinfo failure\n", arg);
		return -1;
	}
	return 0;
}

/*
 * Does the candidate's tunnel take an endpoint of family af? nvgre's and
 * vxlan's tunnel must be of af, and vxlan's must have no destination, or
 * a multicast group as one. 0, or -1 after saying why not.
 */
static int
cand_endpoint(char *ifname, int af)
{
	char line[1024], sbuf[NI_MAXHOST + sizeof(":65535")], *l, *p, *port;
	char *src, *dst = NULL;
	struct addrinfo *res;
	int saf, mcast;

	if (af == AF_LINK)
		return 0;
	if ((l = cand_line("tunneladdr", 0)) == NULL &&
	    (l = cand_line("tunnel", 0)) == NULL) {
		printf("%% %s has no tunnel for an endpoint\n", ifname);
		return -1;
	}
	strlcpy(line, l, sizeof(line));
	if (strcmp(strtok_r(line, " ", &p), "tunnel") == 0) {
		src = strtok_r(NULL, " ", &p);
		dst = strtok_r(NULL, " ", &p);
	} else
		src = strtok_r(NULL, " ", &p);
	if (src == NULL || !tunnel_arg(src, sbuf, sizeof(sbuf), &port) ||
	    numeric_addrinfo(sbuf, NULL, AF_UNSPEC, 0, &res) != 0)
		return -1;
	saf = res->ai_family;
	freeaddrinfo(res);
	if (af != saf) {
		printf("%% endpoint and tunnel address families do not"
		    " match\n");
		return -1;
	}
	if (dst == NULL || !isprefix("vxlan", ifname))
		return 0;
	if ((mcast = tunnel_mcast(dst)) == -1)
		return -1;
	if (!mcast) {
		printf("%% %s has one destination: an endpoint needs"
		    " tunneladdr or a multicast destination\n", ifname);
		return -1;
	}
	return 0;
}

/* A tunnel's rdomain, or -1 after saying why not */
static int
tunnel_rdomain(char *rdomain)
{
	const char *errmsg = NULL;
	int rdomainid;

	rdomainid = strtonum(rdomain, 0, RT_TABLEID_MAX, &errmsg);
	if (errmsg) {
		printf("%% invalid routing domain id %s: %s\n", rdomain, errmsg);
		return -1;
	}
	/* SIOCSLIFPHYRTABLE needs the table (EINVAL) */
	if (!rtable_there(rdomainid))
		return -1;
	return rdomainid;
}

int
settunnelrdomain(int ifs, char *ifname, char *rdomain)
{
	int rdomainid;
	struct ifreq ifr;

	if (rdomain == NULL || (rdomainid = tunnel_rdomain(rdomain)) == -1)
		return -1;
	bzero(&ifr, sizeof(ifr));
	ifr.ifr_rdomainid = rdomainid;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl_down(ifs, ifname, SIOCSLIFPHYRTABLE, (caddr_t)&ifr) < 0) {
		switch(errno) {
		case EINVAL:
			printf("%% tunnel rdomain %i not initialized\n", rdomainid);
			break;
		case ENOTTY:
			printf("%% cannot set tunnel rdomain on %s interface\n", ifname);
			break;
		default:
			printf("%% settunnel: SIOCSLIFPHYRTABLE: %s\n",
			    strerror(errno));
			break;
		}
		return -1;
	}
	return 0;
}

/*
 * The ttl a new tunnel line gets: 1 for nvgre and vxlan, which send to
 * multicast groups, as the kernel starts them, and the kernel's default
 * IP ttl, IPDEFTTL, for the others
 */
static int
tunnel_startttl(char *ifname)
{
	if (isprefix("nvgre", ifname) || isprefix("vxlan", ifname))
		return 1;
	return IPDEFTTL;
}

/*
 * A tunnel's ttl, 1 to 255 as the kernel takes it, or -1 for copy, which
 * copies the ttl of the IP packets a gif, gre or mgre tunnel carries. 0
 * after saying why not: a tunnel of Ethernet frames has no ttl to copy.
 */
static int
tunnel_ttl(char *ifname, char *ttla)
{
	const char *errmsg = NULL;
	int ttl;

	if (strcmp(ttla, "copy") == 0) {
		if (cand_gettype(ifname) == IFT_ETHER) {
			printf("%% ttl copy not supported on %s\n", ifname);
			return 0;
		}
		return -1;
	}
	ttl = strtonum(ttla, 1, 0xff, &errmsg);
	if (errmsg) {
		printf("%% Invalid ttl %s: %s\n", ttla, errmsg);
		return 0;
	}
	return ttl;
}

int
settunnelttl(int ifs, char *ifname, char *ttla)
{
	int ttl;
	struct ifreq ifr;

	if (ttla == NULL || (ttl = tunnel_ttl(ifname, ttla)) == 0)
		return -1;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_ttl = ttl;
	if (ioctl(ifs, SIOCSLIFPHYTTL, (caddr_t)&ifr) < 0) {
		printf("%% settunnelttl: SIOCSLIFPHYTTL: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int
settunneldf(int ifs, char *ifname, int df)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_df = df;
	if (ioctl(ifs, SIOCSLIFPHYDF, (caddr_t)&ifr) == -1) {
		printf("%% settunneldf: SIOCSLIFPHYDF: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int
settunnelecn(int ifs, char *ifname, int ecn)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_metric = ecn;
	if (ioctl(ifs, SIOCSLIFPHYECN, (caddr_t)&ifr) == -1) {
		printf("%% settunnelecn: SIOCSLIFPHYECN: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* Parse a vnetid into *vnetid; -1 after saying why not */
static int
vnetid_arg(char *vnetida, int64_t *vnetid)
{
	const char *errmsg = NULL;

	*vnetid = strtonum(vnetida, 0, INT64_MAX, &errmsg);
	if (errmsg) {
		printf("%% vnetid %s out of range: %s\n", vnetida, errmsg);
		return -1;
	}
	return 0;
}

int
setvnetid(int ifs, char *ifname, char *vnetida)
{
	int64_t vnetid;
	struct ifreq ifr;

	if (vnetida == NULL || vnetid_arg(vnetida, &vnetid) == -1)
		return -1;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_vnetid = vnetid;
	if (ioctl_down(ifs, ifname, SIOCSVNETID, (caddr_t)&ifr) < 0) {
		if (errno == EINVAL) {
			printf("%% vnetid %lld out of range for %s\n",
			    vnetid, ifname);
		} else {
			printf("%% setvnetid SIOCSVNETID: %s\n",
			    strerror(errno));
		}
		return -1;
	}
	return 0;
}

int
delvnetid(int ifs, char *ifname)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl_down(ifs, ifname, SIOCDVNETID, &ifr) < 0) {
		printf("%% delvnetid SIOCDVNETID: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int
deletetunnel(int s, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl_down(s, ifname, SIOCDIFPHYADDR, &ifr) < 0) {
		printf("%% deletetunnel: SIOCDIFPHYADDR: %s\n",
		    strerror(errno));
		return -1;
	}
	return 0;
}

int
get_physrtable(int s, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGLIFPHYRTABLE, (caddr_t)&ifr) < 0)
		return 0;
        else
		return ifr.ifr_rdomainid;
}

int
get_physttl(int s, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGLIFPHYTTL, (caddr_t)&ifr) < 0)
		return 0;
	else
		return ifr.ifr_ttl;
}

int
get_physdf(int s, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGLIFPHYDF, (caddr_t)&ifr) < 0)
		return 0;
	else
		return ifr.ifr_df;
}

int
get_physecn(int s, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGLIFPHYECN, (caddr_t)&ifr) < 0)
		return 0;
	 else
		return ifr.ifr_metric;
}

int64_t
get_vnetid(int s, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGVNETID, (caddr_t)&ifr) < 0)
		return 0;
	else
		return ifr.ifr_vnetid;
}
