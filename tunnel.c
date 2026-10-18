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
#include <netdb.h>

#include "externs.h"
#include "settings.h"

int settunnel(int, char *, char *, char *, char *);
void settunnelrdomain(int, char *, char *);
void settunnelttl(int, char *, char *);
void settunneldf(int, char *, int);
void settunnelecn(int, char *, int);
void setvnetid(int, char *, char *);
void delvnetid(int, char *);
int deletetunnel(int, char *);
void tunnelusage(void);
static int vnetid_arg(char *, int64_t *);
static int cand_vnetid(char *, int, char *);
static int tunnel_ttl(char *);
static int tunnel_rdomain(char *);
static int tunnel_addr(char *, char *, char *, char *, int *);
static int cand_tunnel(char *, int, char *, char *, char *, char *, char *,
    int, int);

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
		return 0;
        }
	if (candidate)
		return cand_vnetid(ifname, set, argv[0]);
	if (set)
		setvnetid(ifs, ifname, argv[0]);
	else
		delvnetid(ifs, ifname);
	return (0);
}

/* vnetid in configure private */
static int
cand_vnetid(char *ifname, int set, char *vnetida)
{
	int64_t vnetid;

	if (!cand_takes(ifname, SIOCSVNETID)) {
		printf("%% vnetid not supported on %s\n", ifname);
		return 0;
	}
	if (!set) {
		if (!cand_takes(ifname, SIOCDVNETID)) {
			printf("%% The vnetid of %s cannot be removed\n",
			    ifname);
			return 0;
		}
		return cand_setting(ST_DEFAULT, "vnetid");
	}
	if (vnetid_arg(vnetida, &vnetid) == -1)
		return 0;
	if (vnetid == 0) {
		printf("%% The configuration does not keep vnetid 0\n");
		return 0;
	}
	if (vnetid < 0)
		return cand_setting(ST_ON, "vnetid any");
	return cand_setting(ST_ON, "vnetid %lld", vnetid);
}

void
tunnelusage(void)
{
	printf("%% tunnel <src ip> <dest ip> [ttl <ttl>] [df] [ecn]\n");
	printf("%% no tunnel [src ip] [dest ip] [ttl <ttl>] [df] [ecn]\n");
}

int
inttunnel(int argc, char **argv, ...)
{
	int set, ch, df = 0, ecn = 0;
	char *src = NULL, *dst = NULL, *rdomain = NULL, *ttl = NULL;
	char *dstip = NULL, *dstport = NULL;
	char buf[MAXHOSTNAMELEN+sizeof (":65535")];
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

	if (set && argc < 2) {
		tunnelusage();
		return 0;
	}

	if (argc > 0 && is_ip_addr(argv[0])) {
		src = argv[0];
		argc--;
		argv++;
	}
	if (argc > 0) {
		dst = argv[0];

		if (strchr(dst, ':') == NULL || strchr(dst, ':') !=
		    strrchr(dst, ':')) {
			/* no port or IPv6 */
			dstip = dst;
			dstport = NULL;
		} else {
			if (strlcpy(buf, dst, sizeof(buf)) >= sizeof(buf)) {
				printf("%% inttunnel: destination overflow\n");
				return 0;
			}
			dstport = strchr(buf, ':');
			*dstport++ = '\0';
			dstip = buf;
		}
		if (is_ip_addr(dstip)) {
			argc--;
			argv++;
		} else {
			dstip = NULL;
			dstport = NULL;
		}
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
		tunnelusage();
		return 0;
	}

	if (candidate)
		return cand_tunnel(ifname, set, src, dstip, dstport, rdomain,
		    ttl, df, ecn);

	if (set) {
		settunnel(ifs, ifname, src, dstip, dstport);
		if (rdomain)
			settunnelrdomain(ifs, ifname, rdomain);
		if (ttl)
			settunnelttl(ifs, ifname, ttl);
		if (df)
			settunneldf(ifs, ifname, 1);
		if (ecn)
			settunnelecn(ifs, ifname, 1);
	} else {
		deletetunnel(ifs, ifname);
		settunneldf(ifs, ifname, 0);
		settunnelecn(ifs, ifname, 0);
	}
	return 0;
}

/*
 * tunnel in configure private. The line has the addresses as
 * conf_tunnel() prints them, then ttl, ecn and df. The kernel keeps the
 * ttl, ecn and df a tunnel command leaves out, so they come from the
 * candidate's line. rdomain is the tunneldomain line.
 */
static int
cand_tunnel(char *ifname, int set, char *src, char *dstip, char *dstport,
    char *rdomain, char *ttla, int df, int ecn)
{
	char s[NI_MAXHOST], d[NI_MAXHOST], line[1024], port[sizeof(":65535")];
	char ttls[sizeof(" ttl 255")], *l, *w, *p;
	const char *errmsg;
	int af, daf, dport, ttl = 0, rdomainid = 0;

	if (!cand_takes(ifname, set ? SIOCSLIFPHYADDR : SIOCDIFPHYADDR)) {
		printf("%% tunnel not supported on %s\n", ifname);
		return 0;
	}
	if (!set)
		return cand_setting(ST_DEFAULT, "tunnel");
	if (src == NULL || dstip == NULL) {
		tunnelusage();
		return 0;
	}
	if (rdomain != NULL) {
		if (!cand_takes(ifname, SIOCSLIFPHYRTABLE)) {
			printf("%% cannot set tunnel rdomain on %s interface\n",
			    ifname);
			return 0;
		}
		if ((rdomainid = tunnel_rdomain(rdomain)) == -1)
			return 0;
	}
	if (ttla != NULL) {
		if (!cand_takes(ifname, SIOCSLIFPHYTTL)) {
			printf("%% tunnel ttl not supported on %s\n", ifname);
			return 0;
		}
		if ((ttl = tunnel_ttl(ttla)) == -1)
			return 0;
	}
	if (df && !cand_takes(ifname, SIOCSLIFPHYDF)) {
		printf("%% tunnel df not supported on %s\n", ifname);
		return 0;
	}
	if (ecn && !cand_takes(ifname, SIOCSLIFPHYECN)) {
		printf("%% tunnel ecn not supported on %s\n", ifname);
		return 0;
	}
	if ((af = tunnel_addr("source", src, NULL, s, NULL)) == 0 ||
	    (daf = tunnel_addr("destination", dstip, dstport, d, &dport)) == 0)
		return 0;
	if (af != daf) {
		printf("%% source and destination address families do not"
		    " match\n");
		return 0;
	}

	if ((l = cand_line("tunnel", 0)) != NULL) {
		/* tunnel src dst, then what the kernel keeps */
		strlcpy(line, l, sizeof(line));
		strtok_r(line, " ", &p);
		strtok_r(NULL, " ", &p);
		strtok_r(NULL, " ", &p);
		while ((w = strtok_r(NULL, " ", &p)) != NULL) {
			if (strcmp(w, "ttl") == 0) {
				w = strtok_r(NULL, " ", &p);
				if (ttl == 0 && w != NULL)
					ttl = strtonum(w, 1, 0xff, &errmsg);
			} else if (strcmp(w, "ecn") == 0)
				ecn = 1;
			else if (strcmp(w, "df") == 0)
				df = 1;
		}
	}

	port[0] = ttls[0] = '\0';
	if (dport > 0)
		snprintf(port, sizeof(port), ":%d", dport);
	if (ttl > 0)
		snprintf(ttls, sizeof(ttls), " ttl %d", ttl);
	cand_setting(ST_ON, "tunnel %s %s%s%s%s%s", s, d, port, ttls,
	    ecn ? " ecn" : "", df ? " df" : "");
	if (rdomain == NULL)
		return 0;
	if (rdomainid != 0)
		return cand_setting(ST_ON, "tunneldomain %d", rdomainid);
	return cand_setting(ST_DEFAULT, "tunneldomain");
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

	if ((ecode = getaddrinfo(ip, port, NULL, &res)) != 0) {
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
settunnel(int s, char *ifname, char *src, char *dstip, char *dstport)
{
	struct addrinfo *srcres, *dstres;
	int ecode;
	struct if_laddrreq req;

	if ((ecode = getaddrinfo(src, NULL, NULL, &srcres)) != 0) {
		printf("%% unable to parse source address string: %s\n",
		     gai_strerror(ecode));
		return 0;
	}

	if ((ecode = getaddrinfo(dstip, dstport, NULL, &dstres)) != 0) {
		printf("%% unable to parse destination address string: %s\n",
		     gai_strerror(ecode));
		freeaddrinfo(srcres);
		return 0;
	}

	if (srcres->ai_addr->sa_family != dstres->ai_addr->sa_family) {
		printf(
		    "%% source and destination address families do not match\n");
		goto end;
	}

	if (srcres->ai_addrlen > sizeof(req.addr) ||
	    dstres->ai_addrlen > sizeof(req.dstaddr)) {
		printf("%% invalid sockaddr\n");
		goto end;
	}

	bzero(&req, sizeof(req));
	(void) strlcpy(req.iflr_name, ifname, sizeof(req.iflr_name));
	memcpy(&req.addr, srcres->ai_addr, srcres->ai_addrlen);
	memcpy(&req.dstaddr, dstres->ai_addr, dstres->ai_addrlen);
	if (ioctl(s, SIOCSLIFPHYADDR, &req) < 0) {
		if (errno == EINVAL)
			printf("%% tunnel cannot be used on %s interface\n",
			    ifname);
		else
			printf("%% settunnel: SIOCSLIFPHYADDR: %s\n",
			    strerror(errno));
	}

 end:
	freeaddrinfo(srcres);
	freeaddrinfo(dstres);
	return 1;
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
	return rdomainid;
}

void
settunnelrdomain(int ifs, char *ifname, char *rdomain)
{
	int rdomainid;
	struct ifreq ifr;

	if (rdomain == NULL || (rdomainid = tunnel_rdomain(rdomain)) == -1)
		return;
	bzero(&ifr, sizeof(ifr));
	ifr.ifr_rdomainid = rdomainid;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSLIFPHYRTABLE, (caddr_t)&ifr) < 0) {
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
	}
}

/* A tunnel's ttl, 1 to 255 as the kernel takes it, or -1 */
static int
tunnel_ttl(char *ttla)
{
	const char *errmsg = NULL;
	int ttl;

	ttl = strtonum(ttla, 1, 0xff, &errmsg);
	if (errmsg) {
		printf("%% Invalid ttl %s: %s\n", ttla, errmsg);
		return -1;
	}
	return ttl;
}

void
settunnelttl(int ifs, char *ifname, char *ttla)
{
	int ttl;
	struct ifreq ifr;

	if (ttla == NULL || (ttl = tunnel_ttl(ttla)) == -1)
		return;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_ttl = ttl;
	if (ioctl(ifs, SIOCSLIFPHYTTL, (caddr_t)&ifr) < 0)
		printf("%% settunnelttl: SIOCSLIFPHYTTL: %s\n", strerror(errno));
}

void
settunneldf(int ifs, char *ifname, int df)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_df = df;
	if (ioctl(ifs, SIOCSLIFPHYDF, (caddr_t)&ifr) == -1)
		printf("%% settunneldf: SIOCSLIFPHYDF: %s\n", strerror(errno));
}

void
settunnelecn(int ifs, char *ifname, int ecn)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_metric = ecn;
	if (ioctl(ifs, SIOCSLIFPHYECN, (caddr_t)&ifr) == -1)
		printf("%% settunnelecn: SIOCSLIFPHYECN: %s\n", strerror(errno));
}

/* A vnetid into *vnetid, any as -1; -1 after saying why not */
static int
vnetid_arg(char *vnetida, int64_t *vnetid)
{
	const char *errmsg = NULL;

	if (isprefix("any", vnetida)) {
		*vnetid = -1;
		return 0;
	}
	*vnetid = strtonum(vnetida, 0, INT64_MAX, &errmsg);
	if (errmsg) {
		printf("%% vnetid %s out of range: %s\n", vnetida, errmsg);
		return -1;
	}
	return 0;
}

void
setvnetid(int ifs, char *ifname, char *vnetida)
{
	int64_t vnetid;
	struct ifreq ifr;

	if (vnetida == NULL || vnetid_arg(vnetida, &vnetid) == -1)
		return;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_vnetid = vnetid;
	if (ioctl(ifs, SIOCSVNETID, (caddr_t)&ifr) < 0) {
		if (errno == EINVAL) {
			printf("%% vnetid %lld out of range for %s\n",
			    vnetid, ifname);
		} else {
			printf("%% setvnetid SIOCSVNETID: %s\n",
			    strerror(errno));
		}
	}
}

void
delvnetid(int ifs, char *ifname)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCDVNETID, &ifr) < 0)
		printf("%% delvnetid SIOCDVNETID: %s\n", strerror(errno));
}

int
deletetunnel(int s, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(s, SIOCDIFPHYADDR, &ifr) < 0) {
		printf("%% deletetunnel: SIOCDIFPHYADDR: %s\n",
		    strerror(errno));
		return 0;
	}
	return 1;
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
