/*
 * Copyright (c) 2013 Chris Cappuccio <chris@nmedia.net>
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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/ppp_defs.h>
#include <net/if_sppp.h>
#include <net/if_pppoe.h>
#include "ip.h"
#include "stringlist.h"
#include "externs.h"
#include "settings.h"

#define TYPESZ 16

void authusage(void);
void peerusage(void);
void pppoeusage(void);
int pppoe_get_ifunit(char *);
void conf_sppp_mh(FILE *, struct sauthreq *, char *, char *);
static void sppp_line(char *, size_t, struct sauthreq *, char *, char *);
static int cand_sppp(char *, int, int, struct sauthreq *, char *);
static void pppoe_line(char *, size_t, struct pppoediscparms *);
static int pppoe_get(int, struct pppoediscparms *);
static int pppoe_set(int, struct pppoediscparms *);
static int pppoe_nodev(int, char *);
static int pppoe_cand(struct pppoediscparms *);
static int pppoe_isether(char *);

/* options for 'proto' */
static struct {
	char *name;
	u_short type;
} spppproto[] = {
	{ "pap",	PPP_PAP },
	{ "chap",	PPP_CHAP },
};

void
authusage(void)
{
	printf("%% auth proto <pap|chap> name <name> key <key>\n");
	printf("%% no auth\n");
}

void
peerusage(void)	
{
        printf("%% peer proto <pap|chap> name <name> key <key>" \
	    " [flag <callin|norechallenge>]\n");
        printf("%% no peer\n");
}

/* auth proto, auth name, auth key, peer proto, peer name, peer key, peer flag */
int
intsppp(int argc, char **argv, ...)
{
	struct sauthreq spa;
	struct ifreq ifr;
	int set, ch, i, cmd = 0;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	/* command options for 'auth' */
	static struct nopts authopts[] = {
		{ "proto",	req_arg,	'p' },
		{ "name",	req_arg,	'n' },
		{ "key",	req_arg,	'k' },
		{ NULL,		0,		0 }
	};

	/* command options for 'peer' */
	static struct nopts peeropts[] = {
		{ "proto",	req_arg,	'p' },
		{ "name",	req_arg,	'n' },
		{ "key",	req_arg,	'k' },
		{ "flag",	req_arg,	'f' },
		{ NULL,		0,		0 }
	};

	/* intsppp commands */
	struct intspppcmd {
		char *name;
		int cmd;
		void (*usage)();
		struct nopts *nopts;
	};
	struct intspppcmd intspppcmds[] = {
		{ "auth",	SPPPIOSMAUTH,	authusage,	authopts },
		{ "peer",	SPPPIOSHAUTH,	peerusage,	peeropts },
	};
	struct intspppcmd *isc = NULL;

	/* get rid of 'no' arg */
	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	/* point to right intspppcmd */
	for (i = 0; i < nitems(intspppcmds); i++) {
		if (isprefix(argv[0], intspppcmds[i].name))
			isc = &intspppcmds[i];
	}
	if (isc == NULL) {
		printf("%% intsppp: Internal error\n");
		return 0;
	}

	argc--;
	argv++;

	ifr.ifr_data = (caddr_t)&spa;

	/* setup spa */
	memset(&spa, 0, sizeof(spa));
	spa.cmd = isc->cmd;

	/* usage? */
	if (argc < 1 && set) {
		(*isc->usage)();
		return 0;
	}

	/* parse */
	noptind = 0;
	while ((ch = nopt(argc, argv, isc->nopts)) != -1)
		switch (ch) {
#define	__proto 1<<0
		case 'p':	/* proto */
			cmd |= __proto;
			for (i = 0; i < nitems(spppproto); i++) {
				if (isprefix(argv[noptind - 1],
				    spppproto[i].name))
					spa.proto = spppproto[i].type;
			}
			if (!spa.proto) {
				printf("%% Unknown proto: %s\n",
				    argv[noptind -1 ]);
				return 0;
			}
			break;
#define	__name	1<<1
		case 'n':	/* name */
			cmd |= __name;
			if (strlcpy(spa.name, argv[noptind - 1],
			    sizeof(spa.name)) >= sizeof(spa.name)) {
				printf("%% Name too long (> %zu): %s\n",
				    sizeof(spa.name), argv[noptind - 1]);
				return 0;
			}
			break;
#define	__key	1<<2
		case 'k':	/* key */
			cmd |= __key;
			if (strlcpy(spa.secret, argv[noptind - 1],
			    sizeof(spa.secret)) >= sizeof(spa.secret)) {
				printf("%% Key too long (> %zu): %s\n",
				    sizeof(spa.secret), argv[noptind - 1]);
				return 0;
			}
			break;
#define	__flag	1<<3
		case 'f':	/* flag */
			cmd |= __flag;
			if (isprefix(argv[noptind - 1], "callin")) {
				spa.flags |= AUTHFLAG_NOCALLOUT;
			} else if (isprefix(argv[noptind - 1],
			    "norechallenge")) {
				spa.flags |= AUTHFLAG_NORECHALLENGE;
			} else {
				printf("%% Unknown flag: %s\n",
			    argv[noptind - 1]);
				return 0;
			}
			break;
		default:
			printf("%% intsppp: nopt table error\n");
			return 0;
		}

	if (argc - noptind != 0) {
		/* leftover salmon */
		printf("%% %s", nopterr);
		if (argv[noptind])
			printf(": %s", argv[noptind]);
		printf("\n");
		(*isc->usage)();
		return 0;
	}

	/* sppp_set_params() takes proto 0 to remove all of it */
	if (set && !(cmd & __proto)) {
		(*isc->usage)();
		return 0;
	}

	if (argc < 1)
		cmd = __proto | __name | __key | __flag;

	if (!set) {
		spa.proto = 0;
		spa.flags = 0;
		memset(&spa.name, '\0', sizeof(spa.name));
		memset(&spa.secret, '\0', sizeof(spa.secret));
	}

	if (candidate)
		return cand_sppp(ifname, set, cmd & __key, &spa, isc->name);

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCSSPPPPARAMS, &ifr) == -1) {
		printf("%% intspppproto: SIOCSSPPPPARAMS: "
		    "SPPPIOS%sAUTH: %s\n",
		    isc->cmd == SPPPIOSMAUTH ? "M" : "H", strerror(errno));
		return 0;
	}
	if (cmd & __key) {
		char type[TYPESZ];

		snprintf(type, TYPESZ, "%skey", isc->name);
		db_delete_flag_x_ctl(type, ifname, cli_rtable);
		if (set) {
			db_insert_flag_x(type, ifname, cli_rtable, DB_X_ENABLE,
			    spa.secret);
		}
	}

	return 0;
}

/* conf_sppp()'s line for spa and the key the database has */
static void
sppp_line(char *buf, size_t len, struct sauthreq *spa, char *key, char *pfx)
{
	char *proto = NULL;
	int i;

	for (i = 0; i < nitems(spppproto); i++)
		if (spa->proto == spppproto[i].type)
			proto = spppproto[i].name;
	snprintf(buf, len, "%s%s%s%s%s%s%s%s%s", pfx,
	    proto ? " proto " : "", proto ? proto : "",
	    spa->name[0] ? " name " : "", (char *)spa->name,
	    key[0] ? " key " : "", key,
	    spa->flags & AUTHFLAG_NOCALLOUT ? " flag callin" : "",
	    spa->flags & AUTHFLAG_NORECHALLENGE ? " flag norechallenge" : "");
}

/*
 * auth and peer in configure private. sppp_set_params() keeps the
 * secret when given none, and intsppp() the key it stored.
 */
static int
cand_sppp(char *ifname, int set, int haskey, struct sauthreq *spa, char *pfx)
{
	char line[1024], key[AUTHMAXLEN], *l, *p, *w;

	if (!cand_takes(ifname, SIOCSSPPPPARAMS)) {
		printf("%% intspppproto: SIOCSSPPPPARAMS: SPPPIOS%sAUTH: %s\n",
		    spa->cmd == SPPPIOSMAUTH ? "M" : "H", strerror(ENOTTY));
		return 0;
	}
	if (!set)
		return cand_setting(ST_DEFAULT, "%s", pfx);
	key[0] = '\0';
	if (haskey)
		strlcpy(key, (char *)spa->secret, sizeof(key));
	else if ((l = cand_line(pfx, 0)) != NULL) {
		strlcpy(line, l, sizeof(line));
		p = line;
		strsep(&p, " ");
		while ((w = strsep(&p, " ")) != NULL && p != NULL)
			if (strcmp(w, "key") == 0)
				strlcpy(key, strsep(&p, " "), sizeof(key));
			else
				strsep(&p, " ");
	}
	sppp_line(line, sizeof(line), spa, key, pfx);
	return cand_setting(ST_ON, "%s", line);
}

void
pppoeusage(void)
{
	printf("%% pppoe ac <access-concentrator> dev <ifname> svc <service>\n");
	printf("%% no pppoe\n");
}

void
pppoe_ipcp(char *ifname, int ifs, int set)
{
	int unit, flags, up;
	struct ifaliasreq ip4req;
	ip_t in4dest, in4gate;
	char dest_str[16];
	struct sockaddr_in *sin;
	struct rt_metrics rt_metrics;

	memset(&ip4req, 0, sizeof(ip4req));
	memset(&in4dest, 0, sizeof(in4dest));
	memset(&in4gate, 0, sizeof(in4gate));
	memset(&rt_metrics, 0, sizeof(rt_metrics));

	in4dest.family = AF_INET;
	in4gate.family = AF_INET;

	unit = pppoe_get_ifunit(ifname);
	if (unit == -1)
		return;

	flags = get_ifflags(ifname, ifs);
	up = (flags & IFF_UP) ? 1 : 0;
	if (up) {
		flags &= ~IFF_UP;
		set_ifflags(ifname, ifs, flags);
	}
	
	/*
	 * Wildcard IPv4 addresses: 0.0.0.0/32 -> 0.0.0.$(unit + 1)
	 */

	/* IP address 0.0.0.0 */
	sin = (struct sockaddr_in *)&ip4req.ifra_addr;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	memset(&sin->sin_addr.s_addr, 0, sizeof(in_addr_t));

	/* Netmask 255.255.255.255 */
	sin = (struct sockaddr_in *)&ip4req.ifra_mask;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	memset(&sin->sin_addr.s_addr, 0xff, sizeof(in_addr_t));

	/* Destination address 0.0.0.$(unit + 1) */
	snprintf(dest_str, sizeof(dest_str), "0.0.0.%d", unit + 1);
	inet_pton(AF_INET, dest_str, &in4gate.addr.in);
	sin = (struct sockaddr_in *)&ip4req.ifra_dstaddr;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	memcpy(&sin->sin_addr.s_addr, &in4gate.addr.in.s_addr,
	    sizeof(in_addr_t));

	strlcpy(ip4req.ifra_name, ifname, sizeof(ip4req.ifra_name));
	if (ioctl(ifs, set ? SIOCAIFADDR : SIOCDIFADDR, &ip4req) < 0) {
		printf("%% pppoe_ipcp: SIOC%dIFADDR: %s\n",
		    set ? 'A' : 'D', strerror(errno));
	}

	/* Wildcard IPv4 default route: 0.0.0.$(unit + 1) */
	ip_route(&in4dest, &in4gate, set ? RTM_ADD : RTM_DELETE,
	    RTF_STATIC | RTF_MPATH | RTF_GATEWAY | RTF_UP,
	    cli_rtable, rt_metrics, 0);

	if (set || up)
		set_ifflags(ifname, ifs, flags | IFF_UP);
}

/* pppoe dev, pppoe svc, pppoe ac */
int
intpppoe(int argc, char **argv, ...)
{
	struct pppoediscparms parms;
	int set, ch, dev = 0;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	/* command options for 'auth' */
	static struct nopts authopts[] = {
		{ "ac",		req_arg,	'a' },
		{ "dev",	req_arg,	'd' },
		{ "svc",	req_arg,	's' },
		{ NULL,		0,		0 }
	};

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	/* setup spa */
	memset(&parms, 0, sizeof(parms));

	/* usage? */
 	if (argc < 1 && set) {
		pppoeusage();
		return 0;
	}

	strlcpy(parms.ifname, ifname, sizeof(parms.ifname));
	if (pppoe_get(ifs, &parms) == -1) {
		printf("%% intpppoe: PPPOEGETPARMS: %s\n",
		    strerror(errno));
		return 0;
	}

	/* parse */
	noptind = 0;
	while ((ch = nopt(argc, argv, authopts)) != -1)
		switch (ch) {
		case 'a':	/* ac */
			if (strlcpy(parms.ac_name, argv[noptind - 1],
			    sizeof(parms.ac_name)) >=
			    sizeof(parms.ac_name)) {
				printf("%% access concentrator name too"
				    " long (> %zu): %s\n",
				    sizeof(parms.ac_name),
				    argv[noptind - 1]);
				return 0;
			}
			break;
		case 'd':       /* dev */
			if (strlcpy(parms.eth_ifname, argv[noptind - 1],
			    sizeof(parms.eth_ifname)) >=
			    sizeof(parms.eth_ifname)) {
				printf("%% dev name too long (> %zu): %s\n",
				    sizeof(parms.eth_ifname),
				    argv[noptind - 1]);
				return 0;
			}
			break;
		case 's':	/* svc */
			if (strlcpy(parms.service_name,
			    argv[noptind - 1],
			    sizeof(parms.service_name)) >=
			    sizeof(parms.service_name)) {
				printf("%% service name too long (> %zu): %s\n",
				    sizeof(parms.service_name),
				    argv[noptind - 1]);
				return 0;
			}
			break;
		default:
			printf("%% intpppoe: nopt table error\n");
			return 0;
		}

	if (argc - noptind != 0) {
		/* leftover salmon */
		printf("%% %s", nopterr);
		if (argv[noptind])
			printf(": %s", argv[noptind]);
		printf("\n");
		pppoeusage();
		return 0;
	}

	/* PPPOESETPARMS drops the dev it had before refusing one */
	if (set && parms.eth_ifname[0] != '\0' &&
	    !pppoe_isether(parms.eth_ifname)) {
		printf("%% intpppoe: PPPOESETPARMS: %s\n", strerror(ENXIO));
		return 0;
	}

	if (!set) {
		dev = parms.eth_ifname[0] != '\0';
		memset(&parms.ac_name, 0, sizeof(parms.ac_name));
		memset(&parms.service_name, 0, sizeof(parms.service_name));
		memset(&parms.eth_ifname, 0, sizeof(parms.eth_ifname));
	}

	if (pppoe_set(ifs, &parms) == -1 ||
	    (!set && dev && pppoe_nodev(ifs, ifname) == -1))
		printf("%% intpppoe: PPPOESETPARMS: %s\n", strerror(errno));

	return (0);
}

/* conf_pppoe()'s line for parms */
static void
pppoe_line(char *buf, size_t len, struct pppoediscparms *parms)
{
	snprintf(buf, len, "pppoe%s%s%s%s%s%s",
	    parms->eth_ifname[0] ? " dev " : "", parms->eth_ifname,
	    parms->ac_name[0] ? " ac " : "", parms->ac_name,
	    parms->service_name[0] ? " svc " : "", parms->service_name);
}

/* PPPOEGETPARMS, or in configure private the candidate's pppoe line */
static int
pppoe_get(int ifs, struct pppoediscparms *parms)
{
	char line[1024], *l, *p, *w, *v;

	if (!candidate)
		return ioctl(ifs, PPPOEGETPARMS, parms);
	if (!cand_takes(parms->ifname, PPPOESETPARMS)) {
		errno = ENOTTY;
		return -1;
	}
	if ((l = cand_line("pppoe", 0)) == NULL)
		return 0;
	strlcpy(line, l, sizeof(line));
	p = line;
	strsep(&p, " ");
	while ((w = strsep(&p, " ")) != NULL && (v = strsep(&p, " ")) != NULL)
		if (strcmp(w, "dev") == 0)
			strlcpy(parms->eth_ifname, v, sizeof(parms->eth_ifname));
		else if (strcmp(w, "ac") == 0)
			strlcpy(parms->ac_name, v, sizeof(parms->ac_name));
		else if (strcmp(w, "svc") == 0)
			strlcpy(parms->service_name, v,
			    sizeof(parms->service_name));
	return 0;
}

/*
 * PPPOESETPARMS, or in configure private its change to the candidate.
 * It keeps the dev when given none, and drops it, and changes nothing
 * else, when given one that is no Ethernet interface (ENXIO).
 */
static int
pppoe_set(int ifs, struct pppoediscparms *parms)
{
	struct pppoediscparms cur;

	if (!candidate)
		return ioctl(ifs, PPPOESETPARMS, parms);
	memset(&cur, 0, sizeof(cur));
	strlcpy(cur.ifname, parms->ifname, sizeof(cur.ifname));
	if (pppoe_get(ifs, &cur) == -1)
		return -1;
	if (parms->eth_ifname[0] == '\0')
		strlcpy(parms->eth_ifname, cur.eth_ifname,
		    sizeof(parms->eth_ifname));
	else if (!pppoe_isether(parms->eth_ifname)) {
		memset(&cur.eth_ifname, 0, sizeof(cur.eth_ifname));
		pppoe_cand(&cur);
		errno = ENXIO;
		return -1;
	}
	return pppoe_cand(parms);
}

/* The candidate's pppoe line for parms, or none */
static int
pppoe_cand(struct pppoediscparms *parms)
{
	char line[1024];

	if (!(*parms->eth_ifname | *parms->ac_name | *parms->service_name))
		return cand_setting(ST_DEFAULT, "pppoe");
	pppoe_line(line, sizeof(line), parms);
	return cand_setting(ST_ON, "%s", line);
}

/*
 * Take away ifname's pppoe dev: PPPOESETPARMS drops it before it
 * refuses a dev that is no Ethernet interface, and no interface is "-"
 */
static int
pppoe_nodev(int ifs, char *ifname)
{
	struct pppoediscparms parms;

	memset(&parms, 0, sizeof(parms));
	strlcpy(parms.ifname, ifname, sizeof(parms.ifname));
	strlcpy(parms.eth_ifname, "-", sizeof(parms.eth_ifname));
	if (pppoe_set(ifs, &parms) == 0)
		errno = EINVAL;
	else if (errno == ENXIO)
		return 0;
	return -1;
}

/* Is name an Ethernet interface, as PPPOESETPARMS wants for a dev? */
static int
pppoe_isether(char *name)
{
	if (candidate)
		return cand_hasif(name) && cand_gettype(name) == IFT_ETHER;
	return get_ifdata(name, IFDATA_IFTYPE) == IFT_ETHER;
}

int
is_pppoe(char *ifname, int ifs)
{
	struct pppoediscparms parms;

	strlcpy(parms.ifname, ifname, sizeof(parms.ifname));
	if (ioctl(ifs, PPPOEGETPARMS, &parms))
		return 0;

	return 1;
}

int
pppoe_get_ipaddrmode(char *ifname)
{
	StringList *ipaddrmode;
	int ret = 0;

	ipaddrmode = sl_init();

	if (db_select_flag_x_ctl(ipaddrmode, "pppoeipaddrmode", ifname) < 0) {
		printf("%% database failure select flag x ctl\n");
		sl_free(ipaddrmode, 1);
		return 0;
	}

	if (ipaddrmode->sl_cur == 0) { /* ipaddrmode not yet initalized */
		db_insert_flag_x("pppoeipaddrmode", ifname, 0, 0, "ipcp");
		ret = NSH_PPPOE_IPADDR_IPCP;
	} else {
		if (strcmp(ipaddrmode->sl_str[0], "ipcp") == 0)
			ret = NSH_PPPOE_IPADDR_IPCP;
		else if (strcmp(ipaddrmode->sl_str[0], "static") == 0)
			ret = NSH_PPPOE_IPADDR_STATIC;
		else
			printf("%% invalid pppoe ipaddrmode %s \n",
			    ipaddrmode->sl_str[0]);
	}

	sl_free(ipaddrmode, 1);
	return ret;
}

int
pppoe_get_ifunit(char *ifname)
{
	long long unit;
	char *unitstr;
	const char *errstr;

	if (strncmp(ifname, "pppoe", 5) != 0)
		return -1;

	unitstr = ifname + 5;
	unit = strtonum(unitstr, 0, 254, &errstr);
	if (errstr) {
		printf("%% %s: interface unit is %s\n", ifname, errstr);
		return -1;
	}

	return (int)unit;
}

void
pppoe_conf_default_route(FILE *output, char *ifname, char *delim,
    char *netname, char *routename, char *flags)
{
	int ipaddrmode, unit;

	ipaddrmode = pppoe_get_ipaddrmode(ifname);
	if (ipaddrmode == NSH_PPPOE_IPADDR_STATIC) {
		fprintf(output, "%s%s ", delim, netname);
		fprintf(output, "%s%s\n", routename, flags);
		return;
	}

	if (ipaddrmode != NSH_PPPOE_IPADDR_IPCP)
		return;

	unit = pppoe_get_ifunit(ifname);
	if (unit == -1)
		return;

	fprintf(output, "%s0.0.0.0/0 0.0.0.%d%s\n", delim, unit + 1, flags);
}

void
conf_pppoe(FILE *output, int ifs, char *ifname)
{
	struct pppoediscparms parms;
	char line[1024];

	strlcpy(parms.ifname, ifname, sizeof(parms.ifname));
	if (ioctl(ifs, PPPOEGETPARMS, &parms))
		return;

	if (!(*parms.eth_ifname | *parms.ac_name | *parms.service_name))
		return;
	pppoe_line(line, sizeof(line), &parms);
	fprintf(output, " %s\n", line);
}

void
conf_sppp(FILE *output, int ifs, char *ifname)
{
	struct sauthreq spa;
	struct ifreq ifr;

	memset(&spa, 0, sizeof(spa));
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	ifr.ifr_data = (caddr_t)&spa;

	spa.cmd = SPPPIOGHAUTH;
	if (ioctl(ifs, SIOCGSPPPPARAMS, &ifr) == 0)
		conf_sppp_mh(output, &spa, ifname, "peer");

	memset(&spa, 0, sizeof(spa));

	spa.cmd = SPPPIOGMAUTH;
	if (ioctl(ifs, SIOCGSPPPPARAMS, &ifr) == 0)
		conf_sppp_mh(output, &spa, ifname, "auth");
}

void
conf_sppp_mh(FILE *output, struct sauthreq *spa, char *ifname, char *pfx)
{
	char type[TYPESZ], line[1024];
	StringList *req;

	if (!(spa->proto | spa->name[0] | (spa->flags &
	    AUTHFLAG_NOCALLOUT) | (spa->flags & AUTHFLAG_NORECHALLENGE)))
		return;

	snprintf(type, TYPESZ, "%skey", pfx);
	req = sl_init();
	sppp_line(line, sizeof(line), spa,
	    db_select_flag_x_ctl(req, type, ifname) >= 0 && req->sl_cur > 0 ?
	    req->sl_str[0] : "", pfx);
	sl_free(req, 1);
	fprintf(output, " %s\n", line);
}
