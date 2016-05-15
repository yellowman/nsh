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
#include <errno.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ppp_defs.h>
#include <net/if_sppp.h>
#include <net/if_pppoe.h>
#include "stringlist.h"
#include "externs.h"

#define TYPESZ 16

void authusage(void);
void peerusage(void);
void pppoeusage(void);
void conf_sppp_mh(FILE *, struct sauthreq *, char *, char *);

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
intsppp(char *ifname, int ifs, int argc, char **argv)
{
	struct sauthreq spa;
	struct ifreq ifr;
	int set, ch, i, cmd = 0;

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
		return(0);
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
		return(0);
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
				return(0);
			}
			break;
#define	__name	1<<1
		case 'n':	/* name */
			cmd |= __name;
			if (strlcpy(spa.name, argv[noptind - 1],
			    sizeof(spa.name)) >= sizeof(spa.name)) {
				printf("%% Name too long (> %lu): %s\n",
				    sizeof(spa.name), argv[noptind - 1]);
				return(0);
			}
			break;
#define	__key	1<<2
		case 'k':	/* key */
			cmd |= __key;
			if (strlcpy(spa.secret, argv[noptind - 1],
			    sizeof(spa.secret)) >= sizeof(spa.secret)) {
				printf("%% Key too long (> %lu): %s\n",
				    sizeof(spa.secret), argv[noptind - 1]);
				return(0);
			}
			break;
#define	__flag	1<<3
		case 'f':	/* flag */
			cmd |= __flag;
			if (isprefix(argv[noptind - 1], "callin")) {
				spa.flags = AUTHFLAG_NOCALLOUT;
			} else if (isprefix(argv[noptind - 1],
			    "norechallenge")) {
				spa.flags = AUTHFLAG_NORECHALLENGE;
			} else {
				printf("%% Unknown flag: %s",
			    argv[noptind - 1]);
				return(0);
			}
			break;
		default:
			printf("%% intsppp: nopt table error\n");
			return(0);
		}

	if (argc - noptind != 0) {
		/* leftover salmon */
		printf("%% %s", nopterr);
		if (argv[noptind])
			printf(": %s", argv[noptind]);
		printf("\n");
		(*isc->usage)();
		return(0);
	}

	if (argc < 1)
		cmd = __proto | __name | __key | __flag;

	if (!set) {
		spa.proto = 0;
		spa.flags = 0;
		memset(&spa.name, '\0', sizeof(spa.name));
		memset(&spa.secret, '\0', sizeof(spa.secret));
	}

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
#ifdef SIOCSIFGENERIC
	if (ioctl(ifs, SIOCSIFGENERIC, &ifr) == -1) {
		printf("%% intspppproto: SIOCSIFGENERIC: SPPPIOSxAUTH: %s\n",
#else
	if (ioctl(ifs, SIOCSSPPPPARAMS, &ifr) == -1) {
		printf("%% intspppproto: SIOCSSPPPPARAMS: SPPPIOSxAUTH: %s\n",
#endif
		    strerror(errno));
		return 0;
	}
	if (cmd & __key) {
		char type[TYPESZ];

		snprintf(type, TYPESZ, "%skey", isc->name);
		db_delete_flag_x_ctl(type, ifname);
		if (set) {
			db_insert_flag_x(type, ifname, 0, DB_X_ENABLE,
			    spa.secret);
		}
	}

	return 0;
}

void
pppoeusage(void)
{
	printf("%% pppoe ac <access-concentrator> dev <ifname> svc <service>\n");
	printf("%% no pppoe\n");
}


/* pppoe dev, pppoe svc, pppoe ac */
int
intpppoe(char *ifname, int ifs, int argc, char **argv)
{
	struct pppoediscparms parms;
	int set, ch;

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
		return(0);
	}

	strlcpy(parms.ifname, ifname, sizeof(parms.ifname));
	if (ioctl(ifs, PPPOEGETPARMS, &parms)) {
		printf("%% intpppoe: PPPOEGETPARMS: %s\n",
		    strerror(errno));
		return(0);
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
				    " long (> %lu): %s\n",
				    sizeof(parms.ac_name),
				    argv[noptind - 1]);
				return(0);
			}
			break;
		case 'd':       /* dev */
			if (strlcpy(parms.eth_ifname, argv[noptind - 1],
			    sizeof(parms.eth_ifname)) >=
			    sizeof(parms.eth_ifname)) {
				printf("%% dev name too long (> %lu): %s\n",
				    sizeof(parms.eth_ifname),
				    argv[noptind - 1]);
				return(0);
			}
			break;
		case 's':	/* svc */
			if (strlcpy(parms.service_name,
			    argv[noptind - 1],
			    sizeof(parms.service_name)) >=
			    sizeof(parms.service_name)) {
				printf("%% service name too long (> %lu): %s\n",
				    sizeof(parms.service_name),
				    argv[noptind - 1]);
				return(0);
			}
			break;
		default:
			printf("%% intpppoe: nopt table error\n");
			return(0);
		}

	if (argc - noptind != 0) {
		/* leftover salmon */
		printf("%% %s", nopterr);
		if (argv[noptind])
			printf(": %s", argv[noptind]);
		printf("\n");
		pppoeusage();
		return(0);
	}

	if (!set) {
		memset(&parms.ac_name, 0, sizeof(parms.ac_name));
		memset(&parms.service_name, 0, sizeof(parms.service_name));
		memset(&parms.eth_ifname, 0, sizeof(parms.eth_ifname));
	}

	if (ioctl(ifs, PPPOESETPARMS, &parms))
		printf("%% intpppoe: PPPOESETPARMS: %s\n", strerror(errno));

	return (0);
}

void
conf_pppoe(FILE *output, int ifs, char *ifname)
{
	struct pppoediscparms parms;

	strlcpy(parms.ifname, ifname, sizeof(parms.ifname));
	if (ioctl(ifs, PPPOEGETPARMS, &parms))
		return;

	if (!(*parms.eth_ifname | *parms.ac_name | *parms.service_name))
		return;
	fprintf(output, " pppoe");
	if (*parms.eth_ifname)
		fprintf(output, " dev %s", parms.eth_ifname);
	if (*parms.ac_name)
		fprintf(output, " ac %s", parms.ac_name);
	if (*parms.service_name)
		fprintf(output, " svc %s", parms.service_name);
	fprintf(output, "\n");
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
#ifdef SIOCGIFGENERIC
	if (ioctl(ifs, SIOCGIFGENERIC, &ifr) == 0)
#else
	if (ioctl(ifs, SIOCGSPPPPARAMS, &ifr) == 0)
#endif
		conf_sppp_mh(output, &spa, ifname, "peer");

	memset(&spa, 0, sizeof(spa));

	spa.cmd = SPPPIOGMAUTH;
#ifdef SIOCGIFGENERIC
	if (ioctl(ifs, SIOCGIFGENERIC, &ifr) == 0)
#else
	if (ioctl(ifs, SIOCGSPPPPARAMS, &ifr) == 0)
#endif
		conf_sppp_mh(output, &spa, ifname, "auth");
}

void
conf_sppp_mh(FILE *output, struct sauthreq *spa, char *ifname, char *pfx)
{
	int i;
	char type[TYPESZ];
	StringList *req;

	if (!(spa->proto | spa->name[0] | spa->secret[0] | (spa->flags &
	    AUTHFLAG_NOCALLOUT) | (spa->flags & AUTHFLAG_NORECHALLENGE)))
		return;
	fprintf(output, " %s", pfx);
	if (spa->proto)
		for (i = 0; i < nitems(spppproto); i++)
			if (spa->proto == spppproto[i].type)
				fprintf(output, " proto %s", spppproto[i].name);
	if (spa->name[0])
		fprintf(output, " name %s", spa->name);

	snprintf(type, TYPESZ, "%skey", pfx);
	req = sl_init();
	if (db_select_flag_x_ctl(req, type, ifname) >= 0) {
		if (req->sl_cur > 0)
			fprintf(output, " key %s", req->sl_str[0]);
	}
	sl_free(req, 1);

	if (spa->flags & AUTHFLAG_NOCALLOUT)
		fprintf(output, " flag callin");
	if (spa->flags & AUTHFLAG_NORECHALLENGE)
		fprintf(output, " flag norechallenge");
	fprintf(output, "\n");
}
