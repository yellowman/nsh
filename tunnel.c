/* From: $OpenBSD: /usr/src/sbin/ifconfig/ifconfig.c,v 1.295 2015/01/16 06:39:58 deraadt Exp $ */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/if_dl.h>

#include <netinet/in.h>

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "externs.h"

int settunnel(int, char *, char *, char *, char *);
void settunnelrdomain(int, char *, char *);
void settunnelttl(int, char *, char *);
void settunneldf(int, char *, int);
void settunnelecn(int, char *, int);
void setvnetid(int, char *, char *);
void delvnetid(int, char *);
int deletetunnel(int, char *);
void tunnelusage(void);

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
	if (set)
		setvnetid(ifs, ifname, argv[0]);
	else
		delvnetid(ifs, ifname);
	return (0);
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
		settunnelttl(ifs, ifname, "0");
		settunneldf(ifs, ifname, 0);
		settunnelecn(ifs, ifname, 0);
	}
	return 0;
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
		return 0;
	}

	if (srcres->ai_addr->sa_family != dstres->ai_addr->sa_family) {
		printf(
		    "%% source and destination address families do not match");
		return 0;
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

void
settunnelrdomain(int ifs, char *ifname, char *rdomain)
{
	int rdomainid;
	const char *errmsg = NULL;
	struct ifreq ifr;

	if (rdomain == NULL)
		return;

	rdomainid = strtonum(rdomain, 0, RT_TABLEID_MAX, &errmsg);
	if (errmsg) {
		printf("%% invalid routing domain id %s: %s\n", rdomain, errmsg);
	}
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

void
settunnelttl(int ifs, char *ifname, char *ttla)
{
	const char *errmsg = NULL;
	int ttl;
	struct ifreq ifr;

	if (ttla == NULL)
		return;

	ttl = strtonum(ttla, 0, 0xff, &errmsg);
	if (errmsg) {
		printf("%% settunnelttl %s: %s\n", ttla, errmsg);
		return;
	}

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

void
setvnetid(int ifs, char *ifname, char *vnetida)
{
	const char *errmsg = NULL;
	int64_t vnetid;
	struct ifreq ifr;

	if (vnetida == NULL)
		return;

	if (isprefix("any", vnetida)) {
		vnetid = -1;
	} else {
		vnetid = strtonum(vnetida, 0, INT64_MAX, &errmsg);
		if (errmsg) {
			printf("%% vnetid %s out of range: %s\n", vnetida,
			    errmsg);
			return;
		}
	}
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
