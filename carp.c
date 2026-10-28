/*
 * Copyright (c) 2004 Chris Cappuccio <chris@nmedia.net>
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
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_types.h>
#include <netinet/ip_carp.h>
#include <net/if.h>
#include <netdb.h>
#include <unistd.h>
#include "externs.h"
#include "settings.h"
#include "facts.h"
#include "showfacts.h"

static struct intc {
	char *name;
	char *descr;
	int type;
} intcs[] = {
	{ "advskew",	"skew",		CARP_ADVSKEW },
	{ "advbase",	"seconds",	CARP_ADVBASE },
	{ "vhid",	"id",		CARP_VHID },
	{ "carppeer",	"peer",		CARP_PEER },
	{ "balancing",	"balancing mode", CARP_BALANCING },
	{ 0,		0,		0 }
};

static const char *carp_bal_modes[] = { CARP_BAL_MODES };

static int carp_getvh(int, struct ifreq *);
static int carp_setvh(int, struct ifreq *);
static int cand_getvh(char *, struct carpreq *);
static int cand_setvh(int, char *, struct carpreq *);
static void sort_vhids(struct carpreq *);

/* Do SIOCGVH, or in configure private, read the candidate */
static int
carp_getvh(int ifs, struct ifreq *ifr)
{
	if (candidate)
		return cand_getvh(ifr->ifr_name, (struct carpreq *)ifr->ifr_data);
	return ioctl(ifs, SIOCGVH, (caddr_t)ifr);
}

/* Do SIOCSVH, or in configure private, change the candidate */
static int
carp_setvh(int ifs, struct ifreq *ifr)
{
	if (candidate)
		return cand_setvh(ifs, ifr->ifr_name,
		    (struct carpreq *)ifr->ifr_data);
	return ioctl(ifs, SIOCSVH, (caddr_t)ifr);
}

/*
 * SIOCGVH in configure private: fill creq from the candidate's lines, as
 * conf_carp() prints them, with the vhids in order as SIOCGVH has them
 */
static int
cand_getvh(char *ifname, struct carpreq *creq)
{
	char line[1024], *l, *w, *p;
	const char *errmsg;
	size_t n;
	int i;

	if (!cand_takes(ifname, SIOCSVH)) {
		errno = ENOTTY;
		return -1;
	}
	memset(creq, 0, sizeof(*creq));
	creq->carpr_advbase = CARP_DFLTINTV;
	creq->carpr_peer.s_addr = htonl(INADDR_CARP_GROUP);
	if ((l = cand_line("carpdev", 0)) != NULL)
		strlcpy(creq->carpr_carpdev, l + strlen("carpdev "),
		    sizeof(creq->carpr_carpdev));
	if ((l = cand_line("carppass", 0)) != NULL)
		strlcpy((char *)creq->carpr_key, l + strlen("carppass "),
		    sizeof(creq->carpr_key));
	if ((l = cand_line("advbase", 0)) != NULL)
		creq->carpr_advbase = strtonum(l + strlen("advbase "), 0, 255,
		    &errmsg);
	if ((l = cand_line("vhid", 0)) != NULL)
		creq->carpr_vhids[0] = strtonum(l + strlen("vhid "), 1, 255,
		    &errmsg);
	if ((l = cand_line("advskew", 0)) != NULL)
		creq->carpr_advskews[0] = strtonum(l + strlen("advskew "), 0,
		    254, &errmsg);
	for (n = 0, i = 0; i < CARP_MAXNODES &&
	    (l = cand_line("carpnode", n)) != NULL; n++, i++) {
		/* carpnode vhid advskew */
		strlcpy(line, l, sizeof(line));
		strtok_r(line, " ", &p);
		if ((w = strtok_r(NULL, " ", &p)) != NULL)
			creq->carpr_vhids[i] = strtonum(w, 1, 255, &errmsg);
		if ((w = strtok_r(NULL, " ", &p)) != NULL)
			creq->carpr_advskews[i] = strtonum(w, 0, 254, &errmsg);
	}
	sort_vhids(creq);
	if ((l = cand_line("carppeer", 0)) != NULL)
		inet_pton(AF_INET, l + strlen("carppeer "), &creq->carpr_peer);
	if ((l = cand_line("balancing", 0)) != NULL)
		for (i = 0; i <= CARP_BAL_MAXID; i++)
			if (strcmp(l + strlen("balancing "),
			    carp_bal_modes[i]) == 0)
				creq->carpr_balancing = i;
	return 0;
}

/* The vhids, and their advskews, in order, as carp_vhids_ioctl() keeps them */
static void
sort_vhids(struct carpreq *creq)
{
	u_int8_t v, a;
	int i, j;

	for (i = 1; i < CARP_MAXNODES && creq->carpr_vhids[i]; i++)
		for (j = i; j > 0 &&
		    creq->carpr_vhids[j - 1] > creq->carpr_vhids[j]; j--) {
			v = creq->carpr_vhids[j];
			a = creq->carpr_advskews[j];
			creq->carpr_vhids[j] = creq->carpr_vhids[j - 1];
			creq->carpr_advskews[j] = creq->carpr_advskews[j - 1];
			creq->carpr_vhids[j - 1] = v;
			creq->carpr_advskews[j - 1] = a;
		}
}

/*
 * SIOCSVH in configure private: what carpioctl(), carp_set_ifp() and
 * carp_vhids_ioctl() refuse is refused with their errno, and the lines
 * become what conf_carp() would print of the result
 */
static int
cand_setvh(int ifs, char *ifname, struct carpreq *r)
{
	struct carpreq cur;
	u_int8_t taken[256];
	char *l;
	size_t k;
	int i, n, v, many, tries, ret = 0;

	if (cand_getvh(ifname, &cur) == -1)
		return -1;
	if (r->carpr_carpdev[0] != '\0' &&
	    strcmp(r->carpr_carpdev, cur.carpr_carpdev) != 0) {
		if (!cand_hasif(r->carpr_carpdev) ||
		    cand_gettype(r->carpr_carpdev) != IFT_ETHER) {
			errno = EINVAL;
			return -1;
		}
		if (!(cand_getflags(r->carpr_carpdev, ifs) & IFF_MULTICAST)) {
			errno = EADDRNOTAVAIL;
			return -1;
		}
		strlcpy(cur.carpr_carpdev, r->carpr_carpdev,
		    sizeof(cur.carpr_carpdev));
	}
	if (r->carpr_vhids[0] != 0 &&
	    memcmp(r->carpr_vhids, cur.carpr_vhids, sizeof(cur.carpr_vhids))) {
		memset(taken, 0, sizeof(taken));
		for (n = 0; n < CARP_MAXNODES && r->carpr_vhids[n]; n++) {
			if (taken[r->carpr_vhids[n]] ||
			    r->carpr_advskews[n] >= 255) {
				errno = EINVAL;
				return -1;
			}
			taken[r->carpr_vhids[n]] = 1;
		}
		if (n <= 1)
			r->carpr_balancing = CARP_BAL_NONE;
		else if (r->carpr_balancing == CARP_BAL_NONE &&
		    cur.carpr_balancing == CARP_BAL_NONE)
			r->carpr_balancing = CARP_BAL_IP;
		memcpy(cur.carpr_vhids, r->carpr_vhids, sizeof(cur.carpr_vhids));
		memcpy(cur.carpr_advskews, r->carpr_advskews,
		    sizeof(cur.carpr_advskews));
		sort_vhids(&cur);
	} else
		for (i = 0; i < CARP_MAXNODES && cur.carpr_vhids[i]; i++)
			cur.carpr_advskews[i] = r->carpr_advskews[i];
	if (r->carpr_advbase > 255 || r->carpr_balancing > CARP_BAL_MAXID) {
		errno = EINVAL;
		return -1;
	}

	if (cur.carpr_carpdev[0] != '\0')
		ret |= cand_setting(ST_ON, "carpdev %s", cur.carpr_carpdev);
	if (r->carpr_key[0] != '\0')
		ret |= cand_setting(ST_ON, "carppass %.*s", CARP_KEY_LEN,
		    r->carpr_key);
	else
		ret |= cand_setting(ST_DEFAULT, "carppass");
	if (r->carpr_advbase >= 0 && r->carpr_advbase != CARP_DFLTINTV)
		ret |= cand_setting(ST_ON, "advbase %d", r->carpr_advbase);
	else if (r->carpr_advbase >= 0)
		ret |= cand_setting(ST_DEFAULT, "advbase");
	/*
	 * One vhid is a vhid line, more are carpnode lines. Remove each
	 * carpnode line whose vhid is not in the result.
	 */
	many = cur.carpr_vhids[1] != 0;
	for (k = 0, tries = 0; tries <= CARP_MAXNODES &&
	    (l = cand_line("carpnode", k)) != NULL; tries++) {
		v = atoi(l + strlen("carpnode "));
		for (i = 0; many && i < CARP_MAXNODES && cur.carpr_vhids[i] &&
		    cur.carpr_vhids[i] != v; i++)
			;
		if (many && i < CARP_MAXNODES && cur.carpr_vhids[i] == v)
			k++;
		else
			ret |= cand_setting(ST_DEFAULT, "carpnode %d", v);
	}
	if (!many && cur.carpr_vhids[0] != 0) {
		ret |= cand_setting(ST_ON, "vhid %d", cur.carpr_vhids[0]);
		if (cur.carpr_advskews[0] != 0)
			ret |= cand_setting(ST_ON, "advskew %d",
			    cur.carpr_advskews[0]);
		else
			ret |= cand_setting(ST_DEFAULT, "advskew");
	} else {
		ret |= cand_setting(ST_DEFAULT, "vhid");
		ret |= cand_setting(ST_DEFAULT, "advskew");
		for (i = 0; i < CARP_MAXNODES && cur.carpr_vhids[i]; i++)
			ret |= cand_setting(ST_ON, "carpnode %d %d",
			    cur.carpr_vhids[i], cur.carpr_advskews[i]);
	}
	if (r->carpr_peer.s_addr != 0 &&
	    r->carpr_peer.s_addr != htonl(INADDR_CARP_GROUP))
		ret |= cand_setting(ST_ON, "carppeer %s",
		    inet_ntoa(r->carpr_peer));
	else
		ret |= cand_setting(ST_DEFAULT, "carppeer");
	if (r->carpr_balancing != CARP_BAL_NONE)
		ret |= cand_setting(ST_ON, "balancing %s",
		    carp_bal_modes[r->carpr_balancing]);
	else
		ret |= cand_setting(ST_DEFAULT, "balancing");
	return ret;
}

int
intcarp(int argc, char **argv, ...)
{
	const char *errmsg = NULL;
	struct ifreq ifr;
	struct carpreq creq;
	int set, bal_mode = 0, val = 0;
	struct intc *x;
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

	x = (struct intc *) genget(argv[0], (char **)intcs,
	    sizeof(struct intc));

	if (x == 0) {
		printf("%% Internal error - Invalid argument %s\n", argv[0]);
		return -1;
	} else if (Ambiguous(x)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[0]);
		return -1;
	}

	argv++;
	argc--;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% %s <%s>\n", x->name, x->descr);
		printf("%% no %s [%s]\n", x->name, x->descr);
		return -1;
	}
	/* SIOCSVH keeps the vhids when the first is 0 */
	if (!set && x->type == CARP_VHID) {
		printf("%% The vhid of %s cannot be removed\n", ifname);
		return -1;
	}
	bzero(&ifr, sizeof(ifr));
	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (carp_getvh(ifs, &ifr) == -1) {
		printf("%% intcarp: SIOCGVH: %s\n", strerror(errno));
		return -1;
	}

	switch(x->type) {
	case CARP_ADVSKEW:
	case CARP_ADVBASE:
		if (set) {
			errno = 0;
			val = strtonum(argv[0], 0, 254, &errmsg);
			if (errmsg) {
				printf("%% %s value out of range: %s\n", x->name, errmsg);
				return -1;
			}
		}
		break;
	case CARP_VHID:
		if (set) {
			errno = 0;
			val = strtonum(argv[0], 1, 255, &errmsg);
			if (errmsg) {
				printf("%% %s value out of range: %s\n", x->name, errmsg);
				return -1;
			}
		}
		break;
	case CARP_BALANCING:
		if (set) {
			for (bal_mode = 0; bal_mode <= CARP_BAL_MAXID; bal_mode++)
				if (isprefix(argv[0], (char *)carp_bal_modes[bal_mode]))
					break;
			if (bal_mode > CARP_BAL_MAXID) {
				int i;

				printf("%% %s <", x->name);
				for (i = 0; i <= CARP_BAL_MAXID; i++)
					printf("%s%s", i == 0 ? "" : "|",
					    carp_bal_modes[i]);
				printf(">\n");
				printf("%% no %s\n", x->name);
				return -1;
			}
		}
		break;
	default:
		break;
	}

	switch(x->type) {
	case CARP_ADVSKEW:
		if (set)
			creq.carpr_advskews[0] = (int)val;
		else
			creq.carpr_advskews[0] = 0;
		break;
	case CARP_ADVBASE:
		if (set)
			creq.carpr_advbase = (int)val;
		else
			creq.carpr_advbase = CARP_DFLTINTV;
		break;
	case CARP_VHID:
		creq.carpr_vhids[0] = (int)val;
		break;
	case CARP_PEER:
		if(set) {
			struct addrinfo hints, *peerres;
			int ecode;

			bzero(&hints, sizeof(hints));
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_DGRAM;

			if ((ecode = getaddrinfo(argv[0], NULL, &hints, &peerres)) != 0) {
				printf("%% error in parsing address string: %s\n",
				    gai_strerror(ecode));
				return -1;
			}

			/* do we need this if hints.ai_family = AF_INET? */
			if (peerres->ai_addr->sa_family != AF_INET) {
				printf("%% only IPv4 addresses supported for the CARP peer\n");
				freeaddrinfo(peerres);
				return -1;
			}

			creq.carpr_peer.s_addr = ((struct sockaddr_in *)
			    peerres->ai_addr)->sin_addr.s_addr;
			freeaddrinfo(peerres);
		} else
			creq.carpr_peer.s_addr = htonl(INADDR_CARP_GROUP);
		break;
	case CARP_BALANCING:
		if(set)
			creq.carpr_balancing = bal_mode;
		else
			creq.carpr_balancing = 0;
	}

	if (carp_setvh(ifs, &ifr) == -1) {
		if (errno == EINVAL)
			printf("%% value out of range\n");
		else
			printf("%% intcarp: SIOCSVH: %s\n", strerror(errno));
		return -1;
	}
	return (0);
}

int
intcpass(int argc, char **argv, ...)
{
	struct ifreq ifr;
	struct carpreq creq;
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

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% pass <passphrase>\n");
		printf("%% no pass [passphrase]\n");
		return -1;
	}
	if (set && strlen(argv[0]) >= CARP_KEY_LEN) {
		printf("%% carppass is at most %d characters\n",
		    CARP_KEY_LEN - 1);
		return -1;
	}
	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (carp_getvh(ifs, &ifr) == -1) {
		printf("%% intpass: SIOCGVH: %s\n", strerror(errno));
		return -1;
	}
	if (set) {
		bzero(creq.carpr_key, CARP_KEY_LEN);
		strlcpy(creq.carpr_key, argv[0], CARP_KEY_LEN);
	} else {
		bzero((char *)&creq.carpr_key, sizeof(creq.carpr_key));
	}

	if (carp_setvh(ifs, &ifr) == -1) {
		printf("%% intcpass: SIOCSVH: %s\n", strerror(errno));
		return -1;
	}
	return (0);
}

int
intcnode(int argc, char **argv, ...)
{
	struct ifreq ifr;
	struct carpreq creq;
	const char *errmsg = NULL;
	int set, i, last;
	u_int vhid, advskew;
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

	/* "no carpnode" takes what carpnode does, and removes the vhid */
	if (argc < 1 || argc > 3) {
		printf("%% carpnode <vhid> [advskew] [state]\n");
		printf("%% no carpnode <vhid> [advskew] [state]\n");
		return -1;
	}
	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	errno = 0;
	vhid = strtonum(argv[0], 1, 255, &errmsg);
	if (errmsg) {
		printf("%% vhid value out of range: %s\n", errmsg);
		return -1;
	}
	if (argv[1]) {
		/* carp_vhids_ioctl() refuses 255 */
		advskew = strtonum(argv[1], 0, 254, &errmsg);
		if (errmsg) {
			printf("%% advskew value out of range: %s\n", errmsg);
			return -1;
		}
	} else {
		advskew = 0;
	}

	if (carp_getvh(ifs, &ifr) == -1) {
		printf("%% intcnode: SIOCGVH: %s\n", strerror(errno));
		return -1;
	}

	/* find last used vhid */
	for (last = 0; last < CARP_MAXNODES && creq.carpr_vhids[last]; last++) {
	}
	last--;

	/* find this vhid, or the next free one */
	for (i = 0; i < CARP_MAXNODES && creq.carpr_vhids[i]; i++)
		if (vhid == creq.carpr_vhids[i])
			break;
	if (set && i == CARP_MAXNODES) {
		printf("%% maximum carp nodes reached, unable to add more\n");
		return -1;
	}
	if (!set && (i == CARP_MAXNODES || !creq.carpr_vhids[i])) {
		printf("%% unable to delete vhid %u, does not exist on %s\n",
		    vhid, ifname);
		return -1;
	}

	if (set) {
		creq.carpr_vhids[i] = vhid;
		creq.carpr_advskews[i] = advskew;
	} else {
		if (last == i) {
			creq.carpr_vhids[i] = 0;
			creq.carpr_advskews[i] = 0;
		} else {
			/* Swap last vhid to erased one, to not create gap */
			creq.carpr_vhids[i] = creq.carpr_vhids[last];
			creq.carpr_advskews[i] = creq.carpr_advskews[last];
			creq.carpr_vhids[last] = 0;
			creq.carpr_advskews[last] = 0;
		}
	}

	if (carp_setvh(ifs, &ifr) == -1) {
		printf("%% intcnode: SIOCSVH: %s\n", strerror(errno));
		return -1;
	}
        return (0);
}

int
conf_carp(FILE *output, int s, char *ifname)
{
	struct ifreq ifr;
	struct carpreq creq;
	short i;

	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) &creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGVH, (caddr_t) & ifr) == -1)
		return (0);

	if (creq.carpr_carpdev[0] != '\0')
		fprintf(output, " carpdev %s\n", creq.carpr_carpdev);
	if (creq.carpr_key[0] != '\0')
		fprintf(output, " carppass %s\n", creq.carpr_key);
	if (creq.carpr_advbase != CARP_DFLTINTV)
		fprintf(output, " advbase %i\n", creq.carpr_advbase);
	if (creq.carpr_vhids[0] != 0)
	switch(creq.carpr_vhids[1]) {
	case 0:
		fprintf(output, " vhid %i\n", creq.carpr_vhids[0]);
		if (creq.carpr_advskews[0] != 0)
			fprintf(output, " advskew %i\n",
			    creq.carpr_advskews[0]);
		break;
	default:
		for (i = 0; i < CARP_MAXNODES && creq.carpr_vhids[i]; i++)
			fprintf(output, " carpnode %i %i\n",
			    creq.carpr_vhids[i], creq.carpr_advskews[i]);
		break;
	}
	if (creq.carpr_peer.s_addr != htonl(INADDR_CARP_GROUP))
		fprintf(output, " carppeer %s\n", inet_ntoa(creq.carpr_peer));
	if (creq.carpr_balancing != 0 && !(creq.carpr_balancing > CARP_BAL_MAXID))
		fprintf(output, " balancing %s\n", carp_bal_modes[creq.carpr_balancing]);

	return (0);
}

/* a carp interface's vhids, as facts */
static struct facts_field carp_fields[] = {
	[CARPV_VHID] =		{ "vhid",	FACT_U64 },
	[CARPV_STATE] =		{ "state",	FACT_U64 },
	[CARPV_ADVSKEW] =	{ "advskew",	FACT_U64 },
	[CARPV_IF] =		{ "interface",	FACT_STRING },
};
struct facts_kind kind_carp = { "carp-vhid", carp_fields, CARPV_NFIELDS };

/* names for the values of f, from a table of strings */
static void
carp_names(struct facts_field *f, const char **names, size_t n)
{
	struct facts_name	*fn;
	size_t			 i;

	if ((fn = calloc(n, sizeof(*fn))) == NULL)
		return;
	for (i = 0; i < n; i++) {
		fn[i].value = i;
		fn[i].name = names[i];
	}
	f->naming = FACT_VALUES;
	f->names = fn;
	f->nnames = n;
}

void
carp_balnames(struct facts_field *f)
{
	carp_names(f, carp_bal_modes, nitems(carp_bal_modes));
}

void
carp_facts_init(void)
{
	static const char *carp_states[] = { CARP_STATES };

	carp_names(&carp_fields[CARPV_STATE], carp_states,
	    nitems(carp_states));
}

/* ifname's vhids, and in ifv its balancing, peer, device and advbase */
void
carp_facts(struct facts_out *o, int s, char *ifname, struct facts_value *ifv)
{
	struct facts_value	 v[CARPV_NFIELDS];
	struct ifreq		 ifr;
	struct carpreq		 creq;
	static char		 carpdev[IFNAMSIZ];
	int			 i;

	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGVH, (caddr_t) & ifr) == -1)
		return;

	facts_u64(&ifv[IF_CARPBALANCING], creq.carpr_balancing);
	if (creq.carpr_peer.s_addr != htonl(INADDR_CARP_GROUP))
		facts_address(&ifv[IF_CARPPEER], FACT_INET,
		    &creq.carpr_peer, sizeof(creq.carpr_peer), 0);
	strlcpy(carpdev, creq.carpr_carpdev, sizeof(carpdev));
	facts_string(&ifv[IF_CARPDEV], carpdev);
	facts_u64(&ifv[IF_CARPADVBASE], creq.carpr_advbase);

	for (i = 0; i < CARP_MAXNODES && creq.carpr_vhids[i]; i++) {
		memset(v, 0, sizeof(v));
		facts_u64(&v[CARPV_VHID], creq.carpr_vhids[i]);
		facts_u64(&v[CARPV_STATE], creq.carpr_states[i]);
		facts_u64(&v[CARPV_ADVSKEW], creq.carpr_advskews[i]);
		facts_string(&v[CARPV_IF], ifname);
		facts_record(o, &kind_carp, v);
	}
}

/* carp, as carp_state() printed it */
void
carp_render(struct frecs *rs, struct frec *ifr, FILE *outfile)
{
	const char	*carp_states[] = { CARP_STATES };
	const char	*state = NULL, *carpdev;
	struct frec	*r, *first;
	struct in_addr	 peer;
	const struct facts_value *pv;
	uint64_t	 bal;
	int		 i, pntd = 0;

	if (!fhas(ifr, IF_CARPBALANCING))
		return;

	bal = fu(ifr, IF_CARPBALANCING, 0);
	if (bal <= CARP_BAL_MAXID) {
		fprintf(outfile, "  CARP balancing mode %s",
		    carp_bal_modes[bal]);
		pntd = 1;
	}

	if ((pv = FV(ifr, IF_CARPPEER, FACT_ADDRESS)) != NULL) {
		memcpy(&peer, pv->v.a.bytes, sizeof(peer));
		fprintf(outfile, " peer %s", inet_ntoa(peer));
		pntd = 1;
	}
	if (pntd)
		fputc('\n', outfile);

	if ((first = frec_next(rs, NULL, &kind_carp)) == NULL)
		return;
	carpdev = fs(ifr, IF_CARPDEV);
	if (carpdev == NULL || carpdev[0] == '\0')
		carpdev = "none";

	for (i = 0, r = first; r != NULL; i++,
	    r = frec_next(rs, r, &kind_carp)) {
		if (fu(r, CARPV_STATE, 0) <= CARP_MAXSTATE)
			state = carp_states[fu(r, CARPV_STATE, 0)];
		if (frec_next(rs, first, &kind_carp) == NULL) {
			fprintf(outfile, "  CARP state %s, "
			    "device %s vhid %u advbase %d advskew %u\n", state,
			    carpdev, (u_int)fu(r, CARPV_VHID, 0),
			    (int)fu(ifr, IF_CARPADVBASE, 0),
			    (u_int)fu(r, CARPV_ADVSKEW, 0));
		} else {
			if (i == 0) {
				fprintf(outfile,
				    "  CARP device %s advbase %d\n", carpdev,
				    (int)fu(ifr, IF_CARPADVBASE, 0));
			}
			fprintf(outfile, "  CARP state %s vhid %u advskew %u\n",
			    state, (u_int)fu(r, CARPV_VHID, 0),
			    (u_int)fu(r, CARPV_ADVSKEW, 0));
		}
	}
}

int
intcdev(int argc, char **argv, ...)
{
	struct ifreq ifr;
	struct carpreq creq;
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

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% carpdev <carpdev>\n");
		printf("%% no carpdev\n");
		return -1;
	}
	/* SIOCSVH keeps the carpdev when the name is empty */
	if (!set) {
		printf("%% The carpdev of %s cannot be removed\n", ifname);
		return -1;
	}

	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (carp_getvh(ifs, &ifr) == -1) {
		printf("%% intcdev: SIOCGVH: %s\n", strerror(errno));
		return -1;
	}
	if (set)
		strlcpy(creq.carpr_carpdev, argv[0], sizeof(creq.carpr_carpdev));
	else
		bzero((char *)&creq.carpr_carpdev, sizeof(creq.carpr_carpdev));

	if (carp_setvh(ifs, &ifr) == -1) {
		printf("%% intcdev: SIOCSVH: %s\n", strerror(errno));
		return -1;
	}

	return (0);
}

/* 
 * Change the carp demotion counter.
 * Return 1 if the counter was changed.
 * Return 0 if the counter was already at or beyond the desired "lock" value.
 * Return -1 on error.
 */
int
carplock(int lock)
{
	int ifs;
	struct ifgroupreq ifgr;

	bzero(&ifgr, sizeof(ifgr));
	strlcpy(ifgr.ifgr_name, "carp", sizeof(ifgr.ifgr_name));

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs == -1) {
		printf("%% carplock: socket: %s\n", strerror(errno));
		return -1;
	}

	if (ioctl(ifs, SIOCGIFGATTR, (caddr_t)&ifgr) == -1) {
		printf("%% carplock: SIOCGIFGATTR %s: %s\n",
		    ifgr.ifgr_name, strerror(errno));
		close(ifs);
		return -1;
	}

	if ((lock >= 0 && ifgr.ifgr_attrib.ifg_carp_demoted >= lock) ||
	    (lock < 0 && ifgr.ifgr_attrib.ifg_carp_demoted <= lock)) {
		close(ifs);
		return 0; /* already "locked" */
	}

	ifgr.ifgr_attrib.ifg_carp_demoted = lock;

	if (ioctl(ifs, SIOCSIFGATTR, (caddr_t)&ifgr) == -1) {
		printf("%% carplock: SIOCSIFGATTR: %s\n", strerror(errno));
		close(ifs);
		return -1;
	}
	close(ifs);

	return 1;
}
