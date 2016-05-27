/* From: $OpenBSD: /usr/src/sbin/ifconfig/ifconfig.c,v 1.295 2015/01/16 06:39:58 deraadt Exp $ */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netdb.h>

#include "externs.h"

int settunnel(int, char *, char *, char *, char *);
void settunnelrdomain(int, char *, char *);
void settunnelttl(int, char *, char *);
void setvnetid(int, char *, char *);
int deletetunnel(int, char *);

static struct nopts tunnelopts[] = {
	{ "rdomain",	req_arg,	'r' },
	{ "ttl",	req_arg,	't' },
	{ NULL,		0,		0   },
};

int
intvnetid(char *ifname, int ifs, int argc, char **argv)
{
	int set;

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
                return(0);
        }
	if (set)
		setvnetid(ifs, ifname, argv[0]);
	else
		setvnetid(ifs, ifname, "0");
	return (0);
}

int
inttunnel(char *ifname, int ifs, int argc, char **argv)
{
	int set, ch;
	char *src = NULL, *dst = NULL, *rdomain = NULL, *ttl = NULL;
	char *dstip = NULL, *dstport = NULL;
	char buf[MAXHOSTNAMELEN+sizeof (":65535")];

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if (set && argc !=2 && argc != 4 && argc != 6) {
		printf("%% tunnel <src ip> <dest ip> [rdomain <domain>] [ttl <ttl>]\n");
		printf("%% no tunnel [src ip] [dest ip] [rdomain <domain>] [ttl <ttl>]\n");
		return(0);
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
				return(0);
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
		}

	if (set) {
		settunnel(ifs, ifname, src, dstip, dstport);
		if (rdomain)
			settunnelrdomain(ifs, ifname, rdomain);
		if (ttl)
			settunnelttl(ifs, ifname, ttl);
	} else {
		deletetunnel(ifs, ifname);
		settunnelrdomain(ifs, ifname, "0");
		settunnelttl(ifs, ifname, "0");
	}
	return(0);
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
		return(0);
	}

	if ((ecode = getaddrinfo(dstip, dstport, NULL, &dstres)) != 0) {
		printf("%% unable to parse destination address string: %s\n",
		     gai_strerror(ecode));
		return(0);
	}

	if (srcres->ai_addr->sa_family != dstres->ai_addr->sa_family) {
		printf(
		    "%% source and destination address families do not match");
		return(0);
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
	return(1);
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
setvnetid(int ifs, char *ifname, char *vnetida)
{
	const char *errmsg = NULL;
	int vnetid;
	struct ifreq ifr;

	if (vnetida == NULL)
		return;

	/* vxlan 2^24 is the upper limit user of vnetid as of OpenBSD 6.0 */
	vnetid = strtonum(vnetida, 0, 0xffffff, &errmsg);
	if (errmsg) {
		printf("%% vnetid %s out of range for %s: %s\n", vnetida,
		    ifname, errmsg);
		return;
	}
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_vnetid = vnetid;
	if (ioctl(ifs, SIOCSVNETID, (caddr_t)&ifr) < 0) {
		if (errno == EINVAL) {
			printf("%% vnetid %d out of range for %s\n",
			    vnetid, ifname);
		} else {
			printf("%% setvnetid SIOCSVNETID: %s\n",
			    strerror(errno));
		}
	}
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
		return(0);
	}
	return(1);
}

int get_physrtable(int s, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGLIFPHYRTABLE, (caddr_t)&ifr) < 0)
		return 0;
        else
		return ifr.ifr_rdomainid;
}

int get_physttl(int s, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGLIFPHYTTL, (caddr_t)&ifr) < 0)
		return 0;
	else
		return ifr.ifr_ttl;
}

int get_vnetid(int s, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGVNETID, (caddr_t)&ifr) < 0)
		return 0;
	else
		return ifr.ifr_vnetid;
}
