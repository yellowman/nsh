/* From: $OpenBSD: brconfig.c,v 1.27 2003/09/26 03:29:59 deraadt Exp $ */

/*
 * Copyright (c) 1999, 2000 Jason L. Wright (jason@thought.net)
 * All rights reserved.
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
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_bridge.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <err.h>
#include <sysexits.h>
#include <stdlib.h>
#include <limits.h>
#include "externs.h"
#include "bridge.h"
#include "settings.h"
#include "kernel.h"
#include "facts.h"
#include "showfacts.h"

int	clr_ifflag(int, char *, short);
int 	bridge_ifsetflag(int, char *, char *, u_int32_t);
int 	bridge_ifclrflag(int, char *, char *, u_int32_t);
int 	bridge_addaddr(int, char *, char *, char *);
int 	bridge_deladdr(int, char *, char *);
int 	bridge_maxaddr(int, char *, u_int32_t);
int 	bridge_maxage(int, char *, u_int32_t);
int 	bridge_priority(int, char *, u_int32_t);
int 	bridge_fwddelay(int, char *, u_int32_t);
int 	bridge_hellotime(int, char *, u_int32_t);
int 	bridge_ifprio(int, char *, char *, int);
int 	bridge_ifcost(int, char *, char *, int);
int 	bridge_timeout(int, char *, int);
int 	bridge_flush(int, char *);
int 	bridge_flushall(int, char *);
int 	bridge_add(int, char *, char *);
int 	bridge_delete(int, char *, char *);
int 	bridge_addspan(int, char *, char *);
int 	bridge_delspan(int, char *, char *);
int 	bridge_rule(int, char *, int, char **, int);
int 	bridge_flushrule(int, char *, char *);
void 	bridge_badrule(int, char **, int, short);
void 	bridge_showrule(struct ifbrlreq *, char *, FILE *);
int 	bridge_confaddrs(int, char *, char *, FILE *);
int	bridge_protect(const char *, int, const char *, const char *);
int	bridge_unprotect(const char *, int, const char *);
void	brprotect_usage(void);
int	show_bridge(char *);
static int br_ioctl(int, u_long, void *);
static int br_portname(int, char *);
static int brvlan_parse(char *, u_int8_t *);
static int bridge_addrvlan(char *, struct ether_addr *, u_int16_t *);
static int bridge_confvaddrs(int, char *, char *, FILE *);
static void brvlan_print(FILE *, const u_int8_t *);

#define BRPORT_MEMBER 0
#define BRPORT_SPAN 1
#define BRPORT_BLOCKNONIP 2
#define BRPORT_DISCOVER 3
#define BRPORT_LEARN 4
#define BRPORT_STP 5
#define BRPORT_PVPTAGS 6

struct brc {
	char *name;
	int type;
};

struct brd {
	char *name;
	char *descr;
	int type;
};

static struct brc brps[] = {
	{ "member",	BRPORT_MEMBER },
	{ "span",	BRPORT_SPAN },
	{ "blocknonip",	BRPORT_BLOCKNONIP },
	{ "discover",	BRPORT_DISCOVER },
	{ "learning",	BRPORT_LEARN },
	{ "stp",	BRPORT_STP },
	{ "pvptags",	BRPORT_PVPTAGS },
	{ 0,		0 }
};

int
brport(int argc, char **argv, ...)
{
	int set, i, e = 0, r = 0;
	struct brc *x;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	x = (struct brc *) genget(argv[0], (char **)brps, sizeof(struct brc));
	if (x == 0) {
		printf("%% Internal error - Invalid argument %s\n", argv[0]);
		return -1;
	} else if (Ambiguous(x)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[0]);
		return -1;
	}

	argv++;
	argc--;

	if (argc == 0) {
		printf("%% %s <if> [if]...\n", x->name);
		printf("%% no %s <if> [if]...\n", x->name);
		return -1;
	}
	/* a veb's private VLANs */
	if (x->type == BRPORT_PVPTAGS && !cand_takes(ifname, SIOCBRDGADDPV)) {
		printf("%% %s not supported on %s\n", x->name, ifname);
		return -1;
	}

	for (i = 0; i < argc; i++) {
		if (!br_portname(ifs, argv[i])) {
			printf("%% Invalid interface name %s\n", argv[i]);
			r = -1;
			continue;
		}
		switch(x->type) {
		case BRPORT_MEMBER:
			if (set) {
				/* adding a member activates a bridge */
				if ((e = bridge_add(ifs, ifname, argv[i])) != 0)
					break;
				if (candidate)
					e = cand_upline(ifname, 1);
				else
					e = set_ifflag(ifs, ifname, IFF_UP);
			} else
				e = bridge_delete(ifs, ifname, argv[i]);
			break;
		case BRPORT_SPAN:
			if (set)
				e = bridge_addspan(ifs, ifname, argv[i]);
			else
				e = bridge_delspan(ifs, ifname, argv[i]);
			break;
		case BRPORT_BLOCKNONIP:
			if (set)
				e = bridge_ifsetflag(ifs, ifname, argv[i],
				    IFBIF_BLOCKNONIP);
			else
				e = bridge_ifclrflag(ifs, ifname, argv[i],
				    IFBIF_BLOCKNONIP);
			break;
		case BRPORT_DISCOVER:
			if (set)
				e = bridge_ifsetflag(ifs, ifname, argv[i],
				    IFBIF_DISCOVER);
			else
				e = bridge_ifclrflag(ifs, ifname, argv[i],
				    IFBIF_DISCOVER);
			break;
		case BRPORT_LEARN:
			if (set)
				e = bridge_ifsetflag(ifs, ifname, argv[i],
				    IFBIF_LEARNING);
			else
				e = bridge_ifclrflag(ifs, ifname, argv[i],
				    IFBIF_LEARNING);
			break;
		case BRPORT_STP:
			if (set)
				e = bridge_ifsetflag(ifs, ifname, argv[i],
				    IFBIF_STP);
			else
				e = bridge_ifclrflag(ifs, ifname, argv[i],
				    IFBIF_STP);
			break;
		case BRPORT_PVPTAGS:
			if (set)
				e = bridge_ifsetflag(ifs, ifname, argv[i],
				    IFBIF_PVLAN_PTAGS);
			else
				e = bridge_ifclrflag(ifs, ifname, argv[i],
				    IFBIF_PVLAN_PTAGS);
			break;
		}
		if (e != 0)
			r = -1;
	}

	return r;
}

#define BRVAL_MAXADDR 0
#define BRVAL_TIMEOUT 1
#define BRVAL_MAXAGE 2
#define BRVAL_FWDDELAY 3
#define BRVAL_HELLOTIME 4
#define BRVAL_PRIORITY 5

static struct brc brvs[] = {
	{ "maxaddr",	BRVAL_MAXADDR },
	{ "timeout",	BRVAL_TIMEOUT },
	{ "maxage",	BRVAL_MAXAGE },
	{ "fwddelay",	BRVAL_FWDDELAY },
	{ "hellotime",	BRVAL_HELLOTIME },
	{ "priority",	BRVAL_PRIORITY },
        { 0,            0 }
};

int
brval(int argc, char **argv, ...)
{
	int set, e = 0;
	u_int32_t val = 0;
	const char *errmsg = NULL;
	struct brc *x;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	x = (struct brc *) genget(argv[0], (char **)brvs, sizeof(struct brc));
	if (x == 0) {
		printf("%% Internal error - Invalid argument %s\n", argv[0]);
		return -1;
	} else if (Ambiguous(x)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[0]);
		return -1;
	}

	argv++;
	argc--;

	if ((set && argc != 1) || (!set && argc > 1)) {
		printf("%% %s <val>\n", x->name);
		printf("%% no %s [val]\n", x->name);
		return -1;
	}

	if (set) {
		errno = 0;
		val = strtonum(argv[0], 0, UINT32_MAX, &errmsg);
		if (errmsg) {
			printf("%% invalid %s argument %s: %s\n", x->name,
			    argv[0], errmsg);
			return -1;
		}
	}

	switch(x->type) {
	case BRVAL_MAXADDR:
		if (set)
			e = bridge_maxaddr(ifs, ifname, val);
		else
			e = bridge_maxaddr(ifs, ifname, DEFAULT_MAXADDR);
		break;
	case BRVAL_TIMEOUT:
		if (set)
			e = bridge_timeout(ifs, ifname, (int)val);
		else
			e = bridge_timeout(ifs, ifname, DEFAULT_TIMEOUT);
		break;
	case BRVAL_MAXAGE:
		if (val > 0xff) {
			printf("%% maxage too large\n");
			return -1;
		}
		if (set)
			e = bridge_maxage(ifs, ifname, val);
		else
			e = bridge_maxage(ifs, ifname, DEFAULT_MAXAGE);
		break;
	case BRVAL_FWDDELAY:
		if (val > 0xff) {
			printf("%% fwddelay too large\n");
			return -1;
		}
		if (set)
			e = bridge_fwddelay(ifs, ifname, val);
		else
			e = bridge_fwddelay(ifs, ifname, DEFAULT_FWDDELAY);
		break;
	case BRVAL_HELLOTIME:
		if (val > 0xff) {
			printf("%% hellotime too large\n");
			return -1;
		}
		if (set)
			e = bridge_hellotime(ifs, ifname, val);
		else
			e = bridge_hellotime(ifs, ifname, DEFAULT_HELLOTIME);
		break;
	case BRVAL_PRIORITY:
		if (val > 0xffff) {
			printf("%% priority too large\n");
			return -1;
		}
		if (set)
			e = bridge_priority(ifs, ifname, val);
		else
			e = bridge_priority(ifs, ifname, DEFAULT_PRIORITY);
		break;
	}

	return e == 0 ? 0 : -1;
}

int
brrule(int argc, char **argv, ...)
{
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		printf("%% all rules for a member must be applied in order\n");
		printf("%% use flush bridge-rules <bridge> <member>\n");
		printf("%% to erase all rules on interface <member>\n");
		return -1;
	}

	argv++;
	argc--;

	if (argc == 0) {
		printf("%% rule {block | pass} {in | out | in/out} on <member> [{src} mac] [{dst} mac]\n");
		return -1;
	}

	return bridge_rule(ifs, ifname, argc, argv, -1) == 0 ? 0 : -1;
}

int
brstatic(int argc, char **argv, ...)
{
	int set, e;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;
	argv++;
	argc--;

	if ((set && argc != 2) || ((!set && argc < 1) || (!set && argc > 2))) {
		printf("%% static <mac address>[@vlan] <member>\n");
		printf("%% no static <mac address>[@vlan] [member]\n");
		return -1;
	}
	/* a veb's addresses are each in a VLAN */
	if (strchr(argv[0], '@') != NULL &&
	    !cand_takes(ifname, SIOCBRDGSVADDR)) {
		printf("%% static with a VLAN not supported on %s\n", ifname);
		return -1;
	}

	if (argv[1] && !br_portname(ifs, argv[1]))
	{
		printf("%% invalid member: %s\n", argv[1]);
		return -1;
	}

	if (set)
		e = bridge_addaddr(ifs, ifname, argv[1], argv[0]);
	else
		e = bridge_deladdr(ifs, ifname, argv[0]);

	return e == 0 ? 0 : -1;
}

#define BRPRI_IFPRIORITY 0
#define BRPRI_IFCOST     1
static struct brd brds[] = {
	{ "ifpriority",		"priority",	BRPRI_IFPRIORITY },
	{ "ifcost",		"cost",		BRPRI_IFCOST },
	{ 0,			0,		0 }
};

int
brpri(int argc, char **argv, ...)
{
	int set, e = 0;
	long long val = 0;
	const char *errmsg = NULL;
	struct brd *x;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	x = (struct brd *) genget(argv[0], (char **)brds, sizeof(struct brd));
	if (x == 0) {
		printf("%% Internal error - Invalid argument %s\n", argv[0]);
		return -1;
	} else if (Ambiguous(x)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[0]);
		return -1;
	}

	argv++;
	argc--;

	/*
	 * the ifpriority value is ignored for 'no ifpriority' but
	 * we allow it anyways to retain compatibility with the
	 * set form of this command
	 */
	if ((set && argc != 2) || (!set && (argc < 1 || argc > 2))) {
		printf("%% %s <member> <%s>\n", x->name, x->descr);
		printf("%% no %s <member> [%s]\n", x->name, x->descr);
		return -1;
	}

	if (!br_portname(ifs, argv[0]))
	{
		printf("%% invalid member name: %s\n", argv[0]);
		return -1;
	}

	/* ifbr_priority is a byte; the kernel takes the cost as an int */
	if (set) {
		val = strtonum(argv[1], 0, x->type == BRPRI_IFPRIORITY ?
		    0xff : kern_bstp_max_path_cost, &errmsg);
		if (errmsg) {
			printf("%% invalid %s %s: %s\n", x->descr, argv[1],
			    errmsg);
			return -1;
		}
	}

	switch(x->type) {
	case BRPRI_IFPRIORITY:
		if (set)
			e = bridge_ifprio(ifs, ifname, argv[0], val);
		else
			e = bridge_ifprio(ifs, ifname, argv[0], DEFAULT_IFPRIORITY);
	break;
	case BRPRI_IFCOST:
		/* 0 has the kernel work the cost out from the speed again */
		e = bridge_ifcost(ifs, ifname, argv[0], val);
	break;
	}

	return e == 0 ? 0 : -1;
}

/*
 * flush wrappers here
 */
int
flush_bridgedyn(int argc, char **argv, ...)
{
	va_list ap;
	char *brdg;
	int ifs, e;

	va_start(ap, argv);
	brdg = va_arg(ap, char *);
	va_end (ap);

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% socket: %s\n", strerror(errno));
		return -1;
	}

	if (!bridge_learns(ifs, brdg)) {
		printf("%% %s is not a bridge\n", brdg);
		close(ifs);
		return -1;
	}

	e = bridge_flush(ifs, brdg);
	close(ifs);

	return e == 0 ? 0 : -1;
}

int
flush_bridgeall(int argc, char **argv, ...)
{
	va_list ap;
	char *brdg;
	int ifs, e;

	va_start(ap, argv);
	brdg = va_arg(ap, char *);
	va_end(ap);

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% socket: %s\n", strerror(errno));
		return -1;
	}

	if (!bridge_learns(ifs, brdg)) {
		printf("%% %s is not a bridge\n", brdg);
		close(ifs);
		return -1;
	}

	e = bridge_flushall(ifs, brdg);
	close(ifs);

	return e == 0 ? 0 : -1;
}

int
flush_bridgerule(int argc, char **argv, ...)
{
	va_list ap;
	char *brdg, *member;
	int ifs, e;

	va_start(ap, argv);
	brdg = va_arg(ap, char *);
	member = va_arg(ap, char *);
	va_end(ap);

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% socket: %s\n", strerror(errno));
		return -1;
	}

	if (!is_bridge(ifs, brdg)) {
		printf("%% %s is not a bridge\n", brdg);
		close(ifs);
		return -1;
	}
	if (!is_valid_ifname(member) || is_bridge(ifs, member)) {
		printf("%% %s is not a valid interface\n", member);
		close(ifs);
		return -1;
	}
	e = bridge_flushrule(ifs, brdg, member);
	close(ifs);

	return e == 0 ? 0 : -1;
}

/*
 * most of the following resembles the original brconfig.c
 */

int
bridge_ifsetflag(int s, char *brdg, char *ifsname, u_int32_t flag)
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifsname, sizeof(req.ifbr_ifsname));
	if (br_ioctl(s, SIOCBRDGGIFFLGS, (caddr_t)&req) < 0) {
		if (errno == ESRCH)
			printf("%% %s is not a member of %s\n", ifsname, brdg);
		else
			printf("%% cannot get flags for %s on %s: %s\n",
			    ifsname, brdg, strerror(errno));
		return (EX_IOERR);
	}

	req.ifbr_ifsflags |= flag;

	if (br_ioctl(s, SIOCBRDGSIFFLGS, (caddr_t)&req) < 0) {
		printf("%% cannot set flags for %s on %s: %s\n", ifsname, brdg,
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_ifclrflag(int s, char *brdg, char *ifsname, u_int32_t flag)
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifsname, sizeof(req.ifbr_ifsname));

	if (br_ioctl(s, SIOCBRDGGIFFLGS, (caddr_t)&req) < 0) {
		if (errno == ESRCH)
			printf("%% %s is not a member of %s\n", ifsname, brdg);
		else
			printf("%% cannot get flags for %s on %s: %s\n",
			    ifsname, brdg, strerror(errno));
		return (EX_IOERR);
	}

	req.ifbr_ifsflags &= ~flag;

	if (br_ioctl(s, SIOCBRDGSIFFLGS, (caddr_t)&req) < 0) {
		printf("%% cannot set flags for %s on %s: %s\n", ifsname, brdg,
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);
}

/*
 * like set_ifflags but only sets one flag
 */
int
set_ifflag(int s, char *brdg, short f)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, brdg, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		printf("%% cannot get flags for %s: %s\n", brdg,
		    strerror(errno));
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}

	ifr.ifr_flags |= f;

	if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
		printf("%% cannot set flags for %s: %s\n", brdg,
		    strerror(errno));
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}

	return (0);
}

int
clr_ifflag(int s, char *brdg, short f)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, brdg, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		printf("%% cannot get flags for %s: %s\n", brdg,
		    strerror(errno));
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}

	ifr.ifr_flags &= ~(f);

	if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
		printf("%% cannot set flags for %s: %s\n", brdg,
		    strerror(errno));
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}

	return (0);
}

int
bridge_flushall(int s, char *brdg)
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	req.ifbr_ifsflags = IFBF_FLUSHALL;
	if (ioctl(s, SIOCBRDGFLUSH, &req) < 0) {
		printf("%% cannot flush all: SIOCBRDGFLUSH: %s\n",
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_flush(int s, char *brdg)
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	req.ifbr_ifsflags = IFBF_FLUSHDYN;
	if (ioctl(s, SIOCBRDGFLUSH, &req) < 0) {
		printf("%% cannot flush: SIOCBRDGFLUSH: %s\n",
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);
}

long
bridge_cfg(int s, char *brdg, int type)
{
	struct ifbrparam ifbp;
	long val = 0;

	strlcpy(ifbp.ifbrp_name, brdg, sizeof(ifbp.ifbrp_name));

	switch (type) {
	case PRIORITY:
		if (ioctl(s, SIOCBRDGGPRI, (caddr_t)&ifbp)) {
			if (errno != ENOTTY)
				printf("%% bridge_cfg: SIOCBRDGGPRI: %s\n",
				    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_prio;
		break;

	case HELLOTIME:
		if (ioctl(s, SIOCBRDGGHT, (caddr_t)&ifbp)) {
			if (errno != ENOTTY)
				printf("%% bridge_cfg: SIOCBRDGGHT: %s\n",
			    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_hellotime;
		break;

	case FWDDELAY:
		if (ioctl(s, SIOCBRDGGFD, (caddr_t)&ifbp)) {
			if (errno != ENOTTY)
				printf("%% bridge_cfg: SIOCBRDGGFD: %s\n",
				    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_fwddelay;
		break;

	case MAXAGE:
		if (ioctl(s, SIOCBRDGGMA, (caddr_t)&ifbp)) {
			if (errno != ENOTTY)
				printf("%% bridge_cfg: SIOCBRDGGMA: %s\n",
				    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_maxage;
		break;

	case MAXADDR:
		if (ioctl(s, SIOCBRDGGCACHE, (caddr_t)&ifbp) < 0) {
			if (errno != ENOTTY)
				printf("%% bridge_cfg: SIOCBRDGGCACHE: %s\n",
				    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_csize;
		break;

	case TIMEOUT:
		if (ioctl(s, SIOCBRDGGTO, (caddr_t)&ifbp) < 0) {
			if (errno != ENOTTY)
				printf("%% bridge_cfg: SIOCBRDGGTO: %s\n",
				    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_ctime;
		break;
	}

	return (val);
}

/* The ports SIOCBRDGIFS lists for brdg, *n of them, or NULL */
static struct ifbreq *
bridge_ports(int s, char *brdg, size_t *n)
{
	struct ifbifconf bifc;
	u_int len = 8192;
	char *inbuf = NULL, *inb;

	while (1) {
		strlcpy(bifc.ifbic_name, brdg, sizeof(bifc.ifbic_name));
		bifc.ifbic_len = len;
		inb = realloc(inbuf, len);
		if (inb == NULL) {
			free(inbuf);
			printf("%% bridge_ports: malloc: %s\n", strerror(errno));
			return NULL;
		}
		bifc.ifbic_buf = inbuf = inb;
		if (ioctl(s, SIOCBRDGIFS, &bifc) < 0) {
			if (errno != ENOTTY)
				printf("%% bridge_ports: SIOCBRDGIFS: %s\n",
				    strerror(errno));
			free(inbuf);
			return NULL;
		}
		if (bifc.ifbic_len + sizeof(struct ifbreq) < len)
			break;
		len *= 2;
	}
	*n = bifc.ifbic_len / sizeof(struct ifbreq);
	return bifc.ifbic_req;
}

/*
 * hacked up bridge_list()
 *
 * bridge_member_search() and show_bridge() ask for MEMBER
 */
int
bridge_list(int s, char *brdg, char *delim, char *br_str, int str_len, int type)
{
	struct ifbreq *reqs, *reqp;
	size_t i, n;
	int identified = 0;
	char buf[256];

	if ((reqs = bridge_ports(s, brdg, &n)) == NULL)
		return 0;

	/* clear out br_str */
	br_str[0] = '\0';

	for (i = 0; i < n; i++) {
		reqp = &reqs[i];
		switch (type) {
		case MEMBER:
			if (reqp->ifbr_ifsname[0] != '\0' &&
			    !(reqp->ifbr_ifsflags & IFBIF_SPAN)) {
				snprintf(buf, sizeof(buf), "%s%s",
				    br_str[0] ? " " : "", reqp->ifbr_ifsname);
				strlcat(br_str, buf, str_len);
				identified++;
			}
			break;
		}
	}
	free(reqs);
	return (identified);
}

/*
 * Find a bridge, if any, which the given interface is a member of.
 * Return the interface index of the bridge, or 0 if not found.
 * A given interface can only be a member of one bridge at a time.
 */
int
bridge_member_search(int ifs, char *ifname)
{
	struct if_nameindex *ifn_list, *ifnp;
	int idx = 0;
	char buf[1024];
	char *p, *s;

	if (!is_valid_ifname(ifname) || is_bridge(ifs, ifname)) {
		printf("%% bridge_member_search: bad interface %s\n", ifname);
		return 0;
	}

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% bridge_member_search: if_nameindex failed\n");
		return 0;
	}

	/* Search all bridges. */
	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		if (!is_bridge(ifs, ifnp->if_name))
			continue;
		if (bridge_list(ifs, ifnp->if_name, NULL, buf, sizeof(buf),
		    MEMBER) == 0)
			continue;
		p = buf;
		while ((s = strsep(&p, " ")) != NULL) {
			if (strcmp(s, ifname) == 0) {
				idx = ifnp->if_index;
				goto found;
			}
		}
	}
found:
	if_freenameindex(ifn_list);
	return idx;
}

int
bridge_add(int s, char *brdg, char *ifn)
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	if (br_ioctl(s, SIOCBRDGADD, &req) < 0) {
		printf("%% cannot add member %s on %s: %s\n", ifn, brdg,
			strerror(errno));
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_delete(int s, char *brdg, char *ifn)
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, (char *)brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	if (br_ioctl(s, SIOCBRDGDEL, &req) < 0) {
		printf("%% unable to delete member: SIOCBRDGDEL: %s\n",
		    strerror(errno));
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_addspan(int s, char *brdg, char *ifn)
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	if (br_ioctl(s, SIOCBRDGADDS, &req) < 0) {
		printf("%% cannot add span %s on %s: %s\n", ifn, brdg,
		    strerror(errno));
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_delspan(int s, char *brdg, char *ifn)
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	if (br_ioctl(s, SIOCBRDGDELS, &req) < 0) {
		printf("%% cannot delete span %s on %s: %s\n", ifn, brdg,
		    strerror(errno));
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_timeout(int s, char *brdg, int val)
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_ctime = val;
	if (br_ioctl(s, SIOCBRDGSTO, (caddr_t)&bp) < 0) {
		printf("%% bridge_timeout: SIOCBRDGSTO: %s\n",
		   strerror(errno));
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_maxage(int s, char *brdg, u_int32_t val)
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_maxage = val;
	if (br_ioctl(s, SIOCBRDGSMA, (caddr_t)&bp) < 0) {
		printf("%% unable to set maxage: SIOCBRDGSMA: %s\n",
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);

}

int
bridge_priority(int s, char *brdg, u_int32_t val)
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_prio = val;
	if (br_ioctl(s, SIOCBRDGSPRI, (caddr_t)&bp) < 0) {
		printf("%% unable to set priority: SIOCBRDGSPRI: %s\n",
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_fwddelay(int s, char *brdg, u_int32_t val)
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_fwddelay = val;
	if (br_ioctl(s, SIOCBRDGSFD, (caddr_t)&bp) < 0) {
		printf("%% unable to set fwddelay: SIOCBRDGSFD: %s\n",
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);

}

int
bridge_hellotime(int s, char *brdg, u_int32_t val)
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_hellotime = val;
	if (br_ioctl(s, SIOCBRDGSHT, (caddr_t)&bp) < 0) {
		printf("%% unable to set hellotime: SIOCBRDGSHT: %s\n",
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);

}

int
bridge_maxaddr(int s, char *brdg, u_int32_t val)
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_csize = val;
	if (br_ioctl(s, SIOCBRDGSCACHE, (caddr_t)&bp) < 0) {
		printf("%% unable to set maxaddr: SIOCBRDGSCACHE: %s\n",
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_deladdr(int s, char *brdg, char *addr)
{
	struct ifbvareq ifbva;
	struct ifbareq ifba;
	struct ether_addr ea;
	u_int16_t vlan;
	int r;

	if (bridge_addrvlan(addr, &ea, &vlan) == -1)
		return (EX_USAGE);
	if (vlan != EVL_VLID_NULL) {
		memset(&ifbva, 0, sizeof(ifbva));
		strlcpy(ifbva.ifbva_name, brdg, sizeof(ifbva.ifbva_name));
		ifbva.ifbva_dst = ea;
		ifbva.ifbva_vid = vlan;
		r = br_ioctl(s, SIOCBRDGDVADDR, &ifbva);
	} else {
		memset(&ifba, 0, sizeof(ifba));
		strlcpy(ifba.ifba_name, brdg, sizeof(ifba.ifba_name));
		ifba.ifba_dst = ea;
		r = br_ioctl(s, SIOCBRDGDADDR, &ifba);
	}
	if (r < 0) {
		printf("%% unable to delete %s from %s\n", addr, brdg);
		return (EX_IOERR);
	}

	return (0);
}

int
bridge_ifprio(int s, char *brdg, char *ifname, int val)
{
	struct ifbreq breq;

	strlcpy(breq.ifbr_name, brdg, sizeof(breq.ifbr_name));
	strlcpy(breq.ifbr_ifsname, ifname, sizeof(breq.ifbr_ifsname));

	breq.ifbr_priority = val;

	if (br_ioctl(s, SIOCBRDGSIFPRIO, (caddr_t)&breq) < 0) {
		printf("%% bridge_ifprio: SIOCBRDGSIFPRIO: %s\n",
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_ifcost(int s, char *brdg, char *ifname, int val)
{
	struct ifbreq breq;

	strlcpy(breq.ifbr_name, brdg, sizeof(breq.ifbr_name));
	strlcpy(breq.ifbr_ifsname, ifname, sizeof(breq.ifbr_ifsname));

	breq.ifbr_path_cost = val;

	if (br_ioctl(s, SIOCBRDGSIFCOST, (caddr_t)&breq) < 0) {
		printf("%% bridge_ifcost: SIOCBRDGSIFCOST: %s\n",
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_addaddr(int s, char *brdg, char *ifname, char *addr)
{
	struct ifbvareq ifbva;
	struct ifbareq ifba;
	struct ether_addr ea;
	u_int16_t vlan;
	int r;

	if (bridge_addrvlan(addr, &ea, &vlan) == -1)
		return (EX_USAGE);
	/* a veb takes no endpoint, which ifba_dstsa would be */
	if (vlan != EVL_VLID_NULL) {
		memset(&ifbva, 0, sizeof(ifbva));
		strlcpy(ifbva.ifbva_name, brdg, sizeof(ifbva.ifbva_name));
		strlcpy(ifbva.ifbva_ifsname, ifname,
		    sizeof(ifbva.ifbva_ifsname));
		ifbva.ifbva_dst = ea;
		ifbva.ifbva_vid = vlan;
		ifbva.ifbva_flags = IFBAF_STATIC;
		r = br_ioctl(s, SIOCBRDGSVADDR, &ifbva);
	} else {
		memset(&ifba, 0, sizeof(ifba));
		strlcpy(ifba.ifba_name, brdg, sizeof(ifba.ifba_name));
		strlcpy(ifba.ifba_ifsname, ifname, sizeof(ifba.ifba_ifsname));
		ifba.ifba_dst = ea;
		ifba.ifba_flags = IFBAF_STATIC;
		r = br_ioctl(s, SIOCBRDGSADDR, &ifba);
	}
	if (r < 0) {
		char tmp[128];

		snprintf(tmp, sizeof(tmp), "%% unable to add %s to %s: %s\n",
		    addr, brdg, errno == ESRCH ? "no such member" :
		    strerror(errno));
		printf("%s", tmp);
		return (EX_IOERR);
	}

	return (0);
}

/*
 * A static line's address, "00:1b:21:0a:0b:01", or on a veb, with the
 * VLAN it is in, "00:1b:21:0a:0b:01@20", into ea and vlan, which is
 * EVL_VLID_NULL without one.  -1 after saying why not
 */
static int
bridge_addrvlan(char *addr, struct ether_addr *ea, u_int16_t *vlan)
{
	struct ether_addr *e;
	const char *errmsg = NULL;
	char buf[64], *v;

	strlcpy(buf, addr, sizeof(buf));
	*vlan = EVL_VLID_NULL;
	if ((v = strchr(buf, '@')) != NULL) {
		*v++ = '\0';
		*vlan = strtonum(v, EVL_VLID_MIN, EVL_VLID_MAX, &errmsg);
		if (errmsg) {
			printf("%% Invalid VLAN %s: %s\n", v, errmsg);
			return -1;
		}
	}
	if ((e = ether_aton(buf)) == NULL) {
		printf("%% Invalid address: %s\n", addr);
		return -1;
	}
	*ea = *e;
	return 0;
}

/* brdg's members; -1 if a record failed */
static int
bridge_members(struct facts_out *o, int s, char *brdg)
{
	struct facts_value v[BRM_NFIELDS];
	struct ifbreq *reqs;
	char buf[sizeof(reqs->ifbr_ifsname) + 1];
	size_t i, n;
	int r = 0;

	if ((reqs = bridge_ports(s, brdg, &n)) == NULL)
		return (0);
	for (i = 0; i < n && r != -1; i++) {
		memset(v, 0, sizeof(v));
		memcpy(buf, reqs[i].ifbr_ifsname,
		    sizeof(reqs[i].ifbr_ifsname));
		buf[sizeof(reqs[i].ifbr_ifsname)] = '\0';
		facts_string(&v[BRM_NAME], buf);
		facts_u64(&v[BRM_FLAGS], reqs[i].ifbr_ifsflags);
		facts_u64(&v[BRM_STATE], reqs[i].ifbr_state);
		facts_string(&v[BRM_IF], brdg);
		r = facts_record(o, &kind_bridgemember, v);
	}
	free(reqs);
	return (r);
}

/* brdg's members, and the addresses it learned */
void
bridge_facts(struct facts_out *o, int s, char *brdg)
{
	struct facts_value v[BRA_NFIELDS];
	struct ifbaconf ifbac;
	struct ifbareq *ifba;
	char buf[sizeof(ifba->ifba_ifsname) + 1], *inbuf = NULL, *inb;
	size_t i;
	u_int len = 8192;

	bridge_members(o, s, brdg);

	while (1) {
		ifbac.ifbac_len = len;
		inb = realloc(inbuf, len);
		if (inb == NULL) {
			free(inbuf);
			printf("%% bridge_addrs: malloc: %s\n",
			    strerror(errno));
			return;
		}
		ifbac.ifbac_buf = inbuf = inb;
		strlcpy(ifbac.ifbac_name, brdg, sizeof(ifbac.ifbac_name));
		if (ioctl(s, SIOCBRDGRTS, &ifbac) < 0) {
			if (errno != ENETDOWN)
				printf("%% bridge_addrs: SIOCBRDGRTS: %s\n",
				    strerror(errno));
			free(inbuf);
			return;
		}
		if (ifbac.ifbac_len + sizeof(*ifba) < len)
			break;
		len *= 2;
	}

	for (i = 0; i < ifbac.ifbac_len / sizeof(*ifba); i++) {
		ifba = ifbac.ifbac_req + i;
		memset(v, 0, sizeof(v));
		facts_address(&v[BRA_ADDRESS], FACT_LINK, &ifba->ifba_dst,
		    sizeof(ifba->ifba_dst), 0);
		memcpy(buf, ifba->ifba_ifsname, sizeof(ifba->ifba_ifsname));
		buf[sizeof(ifba->ifba_ifsname)] = '\0';
		facts_string(&v[BRA_MEMBER], buf);
		facts_u64(&v[BRA_AGE], ifba->ifba_age);
		facts_u64(&v[BRA_FLAGS], ifba->ifba_flags);
		facts_string(&v[BRA_IF], brdg);
		/* bpe's, nvgre's and vxlan's: the endpoint it is behind */
		facts_sockaddr(&v[BRA_ENDPOINT],
		    (struct sockaddr *)&ifba->ifba_dstsa);
		facts_record(o, &kind_bridgeaddr, v);
	}
	free(inbuf);
}

int
bridge_confaddrs(int s, char *brdg, char *delim, FILE *output)
{
	struct ifbaconf ifbac;
	struct ifbareq *ifba;
	char buf[sizeof(ifba->ifba_ifsname) + 1], *inbuf = NULL, *inb;
	u_int i, len = 8192;

	while (1) {
		ifbac.ifbac_len = len;
		inb = realloc(inbuf, len);
		if (inb == NULL) {
			free(inbuf);
			printf("%% bridge_confaddrs: malloc: %s\n",
				strerror(errno));
			return 0;
		}
		ifbac.ifbac_buf = inbuf = inb;
		strlcpy(ifbac.ifbac_name, brdg, sizeof(ifbac.ifbac_name));
		if (ioctl(s, SIOCBRDGRTS, &ifbac) < 0) {
			if ((errno != ENETDOWN) &&
			    (errno != ENOTTY))
				printf("%% bridge_confaddrs: SIOCBRDGRTS: %s\n",
				    strerror(errno));
			free(inbuf);
			return 0;
		}
		if (ifbac.ifbac_len + sizeof(*ifba) < len)
			break;
		len *= 2;
	}

	for (i = 0; i < ifbac.ifbac_len / sizeof(*ifba); i++) {
		ifba = ifbac.ifbac_req + i;
		strlcpy(buf, ifba->ifba_ifsname, sizeof(buf));
		if (ifba->ifba_flags & IFBAF_STATIC)
			fprintf(output, "%s%s %s\n", delim,
			    ether_ntoa(&ifba->ifba_dst), buf);
	}
	free(inbuf);
	return (0);
}

/* A veb's static addresses, as static lines have them, "mac@vlan member" */
static int
bridge_confvaddrs(int s, char *brdg, char *delim, FILE *output)
{
	struct ifbaconf ifbac;
	struct ifbvareq *ifbva;
	char buf[sizeof(ifbva->ifbva_ifsname) + 1], *inbuf = NULL, *inb;
	u_int i, len = 8192;

	while (1) {
		ifbac.ifbac_len = len;
		if ((inb = realloc(inbuf, len)) == NULL) {
			free(inbuf);
			printf("%% bridge_confvaddrs: malloc: %s\n",
			    strerror(errno));
			return 0;
		}
		ifbac.ifbac_buf = inbuf = inb;
		strlcpy(ifbac.ifbac_name, brdg, sizeof(ifbac.ifbac_name));
		if (ioctl(s, SIOCBRDGVRTS, &ifbac) < 0) {
			if (errno != ENETDOWN)
				printf("%% bridge_confvaddrs: SIOCBRDGVRTS: "
				    "%s\n", strerror(errno));
			free(inbuf);
			return 0;
		}
		if (ifbac.ifbac_len + sizeof(*ifbva) < len)
			break;
		len *= 2;
	}

	for (i = 0; i < ifbac.ifbac_len / sizeof(*ifbva); i++) {
		ifbva = ifbac.ifbac_vreq + i;
		strlcpy(buf, ifbva->ifbva_ifsname, sizeof(buf));
		if ((ifbva->ifbva_flags & IFBAF_TYPEMASK) == IFBAF_STATIC)
			fprintf(output, "%s%s@%u %s\n", delim,
			    ether_ntoa(&ifbva->ifbva_dst), ifbva->ifbva_vid,
			    buf);
	}
	free(inbuf);
	return (0);
}

/*
 * Is brdg a bridge, with members: bridge, veb or tpmr, which are
 * IFT_BRIDGE?  It has a bridge's mode, and is not a member.
 */
int
is_bridge(int s, char *brdg)
{
	struct ifreq ifr;
	struct if_data if_data;

	strlcpy(ifr.ifr_name, brdg, sizeof(ifr.ifr_name));

	ifr.ifr_data = (caddr_t)&if_data;
	if (ioctl(s, SIOCGIFDATA, (caddr_t)&ifr) < 0) {
		/* bail out */
		return 0;
	}
	return if_data.ifi_type == IFT_BRIDGE;
}

/*
 * Does brdg learn addresses, as a bridge does: a bridge, or bpe, nvgre
 * or vxlan, which answer SIOCBRDGRTS but are interfaces, with an
 * interface's mode?  Its learned addresses can be flushed.
 */
int
bridge_learns(int s, char *brdg)
{
	struct ifbaconf ifbac;

	if (is_bridge(s, brdg))
		return 1;

	/* ok, maybe still a bridge, let's ask for SIOCBRDGRTS */
	ifbac.ifbac_len = 0;
	strlcpy(ifbac.ifbac_name, brdg, sizeof(ifbac.ifbac_name));
	if (ioctl(s, SIOCBRDGRTS, (caddr_t)&ifbac) < 0) {
		if (errno == ENETDOWN) {
			/* oh, a bridge who happens to be unconfigured */
			return 1;
		}
		/* bridge ioctl failure, so, not a bridge */
		return 0;
	}

	/* apparently we had SIOCBRDGRTS success */
	return 1;
}

int
bridge_flushrule(int s, char *brdg, char *ifname)
{
	struct ifbrlreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifname, sizeof(req.ifbr_ifsname));
	if (ioctl(s, SIOCBRDGFRL, &req) < 0) {
		printf("%% unable to flush rules for %s: %s\n", ifname,
		    strerror(errno));
		return (EX_USAGE);
	}
	return (0);
}

int
bridge_rules(int s, char *brdg, char *ifname, char *delim, FILE *output)
{
	char *inbuf = NULL, *inb;
	struct ifbrlconf ifc;
	struct ifbrlreq *ifrp, ifreq;
	u_int i, len = 8192;

	while (1) {
		ifc.ifbrl_len = len;
		inb = realloc(inbuf, len);
		if (inb == NULL) {
			free(inbuf);
			printf("%% bridge_rules: malloc: %s\n",
			    strerror(errno));
			return 0;
		}
		ifc.ifbrl_buf = inbuf = inb;
		strlcpy(ifc.ifbrl_name, brdg, sizeof(ifc.ifbrl_name));
		strlcpy(ifc.ifbrl_ifsname, ifname, sizeof(ifc.ifbrl_ifsname));
		errno = 0;
		if (ioctl(s, SIOCBRDGGRL, &ifc) < 0) {
			if ((errno != ESRCH) && /* invalid interface name */
			    (errno != ENOTTY))	/* not a bridge */
				printf("%% bridge_rules: SIOCBRDGGRL: %s\n",
				    strerror(errno));
			free(inbuf);
			return 0;
		}
		if (ifc.ifbrl_len + sizeof(ifreq) < len)
			break;
		len *= 2;
	}
	for (i = 0; i < ifc.ifbrl_len; i += sizeof(ifreq)) {
		ifrp = (struct ifbrlreq *)((caddr_t)ifc.ifbrl_req + i);
		bridge_showrule(ifrp, delim, output);
	}
	free(inbuf);
	return (0);
}

void
bridge_showrule(struct ifbrlreq *r, char *delim, FILE *output)
{
	if (delim)
		fprintf(output, "%s", delim);
	else
		fprintf(output, "%s: ", r->ifbr_name);

	if (r->ifbr_action == BRL_ACTION_BLOCK)
		fprintf(output, "block ");
	else if (r->ifbr_action == BRL_ACTION_PASS)
		fprintf(output, "pass ");
	else
		/* this should not happen */
		fprintf(output, "[neither block nor pass?] ");

	if ((r->ifbr_flags & (BRL_FLAG_IN | BRL_FLAG_OUT)) ==
	    (BRL_FLAG_IN | BRL_FLAG_OUT))
		fprintf(output, "in/out ");
	else if (r->ifbr_flags & BRL_FLAG_IN)
		fprintf(output, "in ");
	else if (r->ifbr_flags & BRL_FLAG_OUT)
		fprintf(output, "out ");
	else
		/* this should not happen */
		fprintf(output, "[neither in nor out?] ");

	fprintf(output, "on %s", r->ifbr_ifsname);

	if (r->ifbr_flags & BRL_FLAG_SRCVALID)
		fprintf(output, " src %s", ether_ntoa(&r->ifbr_src));
	if (r->ifbr_flags & BRL_FLAG_DSTVALID)
		fprintf(output, " dst %s", ether_ntoa(&r->ifbr_dst));
	if (r->ifbr_tagname[0])
		fprintf(output, " tag %s", r->ifbr_tagname);

	fprintf(output, "\n");
}

/*
 * Parse a rule definition and send it upwards.
 *
 * Syntax:
 *	{block|pass} {in|out|in/out} on {ifs} [src {mac}] [dst {mac}]
 */
int
bridge_rule(int s, char *brdg, int targc, char **targv, int ln)
{
	char **argv = targv;
	int argc = targc;
	struct ifbrlreq rule;
	struct ether_addr *ea, *dea;
	short sec;

	if (argc == 0) {
		printf("%% Invalid rule\n");
		return (EX_USAGE);
	}
	rule.ifbr_tagname[0] = 0;
	rule.ifbr_flags = 0;
	rule.ifbr_action = 0;
	strlcpy(rule.ifbr_name, brdg, sizeof(rule.ifbr_name));

	sec = 1;
	if (strcmp(argv[0], "block") == 0)
		rule.ifbr_action = BRL_ACTION_BLOCK;
	else if (strcmp(argv[0], "pass") == 0)
		rule.ifbr_action = BRL_ACTION_PASS;
	else
		goto bad_rule;
	argc--;	argv++;

	sec++; /* 2 */
	if (argc == 0) {
		bridge_badrule(targc, targv, ln, sec);
		return (EX_USAGE);
	}
	if (strcmp(argv[0], "in") == 0)
		rule.ifbr_flags |= BRL_FLAG_IN;
	else if (strcmp(argv[0], "out") == 0)
		rule.ifbr_flags |= BRL_FLAG_OUT;
	else if (strcmp(argv[0], "in/out") == 0)
		rule.ifbr_flags |= BRL_FLAG_IN | BRL_FLAG_OUT;
	else
		goto bad_rule;
	argc--; argv++;

	sec++; /* 3 */
	if (argc == 0 || strcmp(argv[0], "on"))
		goto bad_rule;
	argc--; argv++;

	sec++; /* 4 */
	if (argc == 0 || !(candidate ? cand_hasif(argv[0]) :
	    is_valid_ifname(argv[0])))
		goto bad_rule;
	strlcpy(rule.ifbr_ifsname, argv[0], sizeof(rule.ifbr_ifsname));
	argc--; argv++;

	sec++; /* 5 */
	while (argc) {
		if (strcmp(argv[0], "dst") == 0) {
			if (rule.ifbr_flags & BRL_FLAG_DSTVALID)
				goto bad_rule;
			rule.ifbr_flags |= BRL_FLAG_DSTVALID;
			dea = &rule.ifbr_dst;
		} else if (strcmp(argv[0], "src") == 0) {
			if (rule.ifbr_flags & BRL_FLAG_SRCVALID)
				goto bad_rule;
			rule.ifbr_flags |= BRL_FLAG_SRCVALID;
			dea = &rule.ifbr_src;
		} else if (strcmp(argv[0], "tag") == 0) {
			if (argc < 2) {
				printf("%% missing tag name\n");
				goto bad_rule;
			}
			if (rule.ifbr_tagname[0]) {
				printf("%% tag already defined\n");
				goto bad_rule;
			}
			if (strlcpy(rule.ifbr_tagname, argv[1],
			    PF_TAG_NAME_SIZE) >= PF_TAG_NAME_SIZE) {
				printf("%% tag name too long\n");
				goto bad_rule;
			}
			dea = NULL;
		} else
			goto bad_rule;

		argc--; argv++;
		sec++;

		if (argc == 0)
			goto bad_rule;
		if (dea != NULL) {
			ea = ether_aton(argv[0]);
			if (ea == NULL) {
				printf("%% Invalid address: %s\n", argv[0]);
				return (EX_USAGE);
			}
			bcopy(ea, dea, sizeof(*dea));
 		}
		argc--; argv++;
		sec++;
	}

	if (br_ioctl(s, SIOCBRDGARL, &rule) < 0) {
		printf("%% unable to add rule: SIOCBRDGARL: %s\n",
		    strerror(errno));
		return (EX_IOERR);
	}
	return (0);

bad_rule:
	bridge_badrule(targc, targv, ln, sec);
	return (EX_USAGE);
}

#define MAXRULEWORDS 8

void
bridge_badrule(int argc, char **argv, int ln, short sec)
{
	int i;

	printf("%% Invalid rule: ");
	if (ln != -1)
		printf("%d: ", ln);
	for (i = 0; i < argc; i++) {
		printf("%s ", argv[i]);
	}
	printf(" (sec %i)\n", sec);
}

int
bridge_protect(const char *ifname, int sock, const char *ifsname,
    const char *val)
{
	struct ifbreq breq;
	unsigned long v;
	char *optlist, *str;
	const char *errstr;

	strlcpy(breq.ifbr_name, ifname, sizeof(breq.ifbr_name));
	strlcpy(breq.ifbr_ifsname, ifsname, sizeof(breq.ifbr_ifsname));
	breq.ifbr_protected = 0;

	/* We muck with the string, so copy it. */
	optlist = strdup(val);
	if (optlist == NULL)
		err(1, "strdup");

	str = strtok(optlist, ",");
	while (str != NULL) {
		v = strtonum(str, 1, 31, &errstr);
		if (errstr) {
			printf("%% protected domain %s is %s\n", str, errstr);
			free(optlist);
			return 1;
		}
		breq.ifbr_protected |= (1 << (v - 1));
		str = strtok(NULL, ",");
	}

	if (br_ioctl(sock, SIOCBRDGSIFPROT, (caddr_t)&breq) == -1) {
		printf("%% protect %s %s: %s\n", ifsname, val, strerror(errno));
		free(optlist);
		return 1;
	}

	free(optlist);
	return 0;
}

int
bridge_unprotect(const char *ifname, int sock, const char *ifsname)
{
	struct ifbreq breq;

	strlcpy(breq.ifbr_name, ifname, sizeof(breq.ifbr_name));
	strlcpy(breq.ifbr_ifsname, ifsname, sizeof(breq.ifbr_ifsname));

	breq.ifbr_protected = 0;

	if (br_ioctl(sock, SIOCBRDGSIFPROT, (caddr_t)&breq) == -1) {
		printf("%% no protect %s: %s\n", ifsname, strerror(errno));
		return 1;
	}

	return 0;
}

void
brprotect_usage(void)
{
	printf("%% protect <if> <domain-ids>\n");
	printf("%% no protect <if> [domain-ids]\n");
}

int
brprotect(int argc, char **argv, ...)
{
	int set, e;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
		if (argc != 2 && argc != 3) {
			brprotect_usage();
			return -1;
		}
	} else {
		set = 1;
		if (argc != 3) {
			brprotect_usage();
			return -1;
		}
	}

	if (!br_portname(ifs, argv[1])) {
		printf("%% Invalid interface name %s\n", argv[1]);
		return -1;
	}

	if (set)
		e = bridge_protect(ifname, ifs, argv[1], argv[2]);
	else
		e = bridge_unprotect(ifname, ifs, argv[1]);
	return e == 0 ? 0 : -1;
}

static struct brc brvls[] = {
	{ "untagged",	0 },
	{ "tagged",	1 },
	{ 0,		0 }
};

/*
 * On a veb, untagged sets the VLAN of the frames a member sends and
 * receives without a tag: a VLAN ID, passthrough, which hands them to
 * the system instead, none, which drops them, or default, the veb's
 * vnetid.  tagged adds the VLANs a member carries with a tag, and no
 * tagged removes them, or with no VLANs, all of them.  if_veb.c
 */
int
brvlan(int argc, char **argv, ...)
{
	struct ifbrvidmap vm;
	struct ifbreq breq;
	struct brc *x;
	const char *errmsg = NULL;
	va_list ap;
	char *ifname;
	int ifs, set, r;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	x = (struct brc *) genget(argv[0], (char **)brvls, sizeof(struct brc));
	if (x == 0 || Ambiguous(x)) {
		printf("%% Internal error - Invalid argument %s\n", argv[0]);
		return -1;
	}

	argv++;
	argc--;

	if ((set && argc != 2) || (!set && (argc < 1 || argc > 2))) {
		if (x->type == 0) {
			printf("%% untagged <member> <vlan|passthrough|none|"
			    "default>\n");
			printf("%% no untagged <member>\n");
		} else {
			printf("%% tagged <member> <vlans>\n");
			printf("%% no tagged <member> [vlans]\n");
		}
		return -1;
	}
	if (!cand_takes(ifname, SIOCBRDGSPVID)) {
		printf("%% %s not supported on %s\n", x->name, ifname);
		return -1;
	}
	if (!br_portname(ifs, argv[0])) {
		printf("%% invalid member name: %s\n", argv[0]);
		return -1;
	}

	if (x->type == 0) {
		memset(&breq, 0, sizeof(breq));
		strlcpy(breq.ifbr_name, ifname, sizeof(breq.ifbr_name));
		strlcpy(breq.ifbr_ifsname, argv[0], sizeof(breq.ifbr_ifsname));
		if (!set || strcmp(argv[1], "none") == 0)
			breq.ifbr_pvid = IFBR_PVID_NONE;
		else if (strcmp(argv[1], "passthrough") == 0)
			breq.ifbr_pvid = IFBR_PVID_DECLINE;
		else if (strcmp(argv[1], "default") == 0)
			breq.ifbr_pvid = EVL_VLID_NULL;
		else {
			breq.ifbr_pvid = strtonum(argv[1], EVL_VLID_MIN,
			    EVL_VLID_MAX, &errmsg);
			if (errmsg) {
				printf("%% invalid VLAN %s: %s\n", argv[1],
				    errmsg);
				return -1;
			}
		}
		r = br_ioctl(ifs, SIOCBRDGSPVID, &breq);
	} else {
		memset(&vm, 0, sizeof(vm));
		strlcpy(vm.ifbrvm_name, ifname, sizeof(vm.ifbrvm_name));
		strlcpy(vm.ifbrvm_ifsname, argv[0],
		    sizeof(vm.ifbrvm_ifsname));
		if (argc == 2 && brvlan_parse(argv[1], vm.ifbrvm_map) == -1)
			return -1;
		/* no tagged with no VLANs leaves none */
		vm.ifbrvm_op = set ? IFBRVM_OP_OR : argc == 2 ?
		    IFBRVM_OP_ANDNOT : IFBRVM_OP_SET;
		r = br_ioctl(ifs, SIOCBRDGSVMAP, &vm);
	}
	if (r < 0) {
		printf("%% %s %s: %s\n", x->name, argv[0],
		    errno == ESRCH ? "not a member" : strerror(errno));
		return -1;
	}
	return 0;
}

/* Parse VLANs, "10,20-30" or "all", into map, a bit each */
static int
brvlan_parse(char *vlans, u_int8_t *map)
{
	char *buf, *p, *w, *to;
	const char *errmsg = NULL;
	int from, last, v;

	if (strcmp(vlans, "all") == 0)
		vlans = "1-4094";
	if ((buf = strdup(vlans)) == NULL) {
		printf("%% brvlan_parse: %s\n", strerror(errno));
		return -1;
	}
	for (p = buf; (w = strsep(&p, ",")) != NULL && errmsg == NULL; ) {
		if ((to = strchr(w, '-')) != NULL)
			*to++ = '\0';
		from = strtonum(w, EVL_VLID_MIN, EVL_VLID_MAX, &errmsg);
		last = from;
		if (errmsg == NULL && to != NULL)
			last = strtonum(to, from, EVL_VLID_MAX, &errmsg);
		for (v = from; errmsg == NULL && v <= last; v++)
			map[v / 8] |= 1 << (v % 8);
	}
	free(buf);
	if (errmsg) {
		printf("%% invalid VLANs %s: %s\n", vlans, errmsg);
		return -1;
	}
	return 0;
}

/* Print map's VLANs as brvlan_parse() reads them, "10,20-30" */
static void
brvlan_print(FILE *output, const u_int8_t *map)
{
	int v, from, n = 0;

	for (v = EVL_VLID_MIN; v <= EVL_VLID_MAX; v++) {
		if (!(map[v / 8] & (1 << (v % 8))))
			continue;
		for (from = v; v < EVL_VLID_MAX &&
		    (map[(v + 1) / 8] & (1 << ((v + 1) % 8))); v++)
			;
		fprintf(output, n++ ? ",%d" : "%d", from);
		if (v > from)
			fprintf(output, "-%d", v);
	}
}

/*
 * For commit: if other is the untagged or tagged line of line's member,
 * write what takes the member out of the VLANs that line has and other
 * lacks, after in, to output, and return 1; else return 0.  A private
 * VLAN can go only once no member has it.
 */
int
brvlan_gone(FILE *output, const char *in, char *line, char *other)
{
	u_int8_t was[sizeof(((struct ifbrvidmap *)0)->ifbrvm_map)];
	u_int8_t now[sizeof(was)];
	char *v, *ov;
	size_t i, len, klen;
	int any = 0;

	/* "tagged em1 10,20-30", "untagged em1 5": the member, its VLANs */
	klen = strcspn(line, " ");
	if (strncmp(line, other, klen + 1) != 0)
		return 0;
	v = line + klen + 1;
	ov = other + klen + 1;
	len = strcspn(v, " ");
	if (strncmp(v, ov, len) != 0 || ov[len] != ' ' || v[len] != ' ')
		return 0;
	if (strncmp(line, "untagged ", 9) == 0) {
		if (isdigit((unsigned char)v[len + 1]))
			fprintf(output, "%sno untagged %.*s\n", in,
			    (int)len, v);
		return 1;
	}
	memset(was, 0, sizeof(was));
	memset(now, 0, sizeof(now));
	if (brvlan_parse(v + len + 1, was) == -1 ||
	    brvlan_parse(ov + len + 1, now) == -1)
		return 1;
	for (i = 0; i < sizeof(was); i++)
		any |= was[i] &= ~now[i];
	if (any) {
		fprintf(output, "%sno tagged %.*s ", in, (int)len, v);
		brvlan_print(output, was);
		fprintf(output, "\n");
	}
	return 1;
}

static struct brc brpvs[] = {
	{ "pvlan",		IFBRPV_T_PRIMARY },
	{ "pvlan-isolated",	IFBRPV_T_ISOLATED },
	{ "pvlan-community",	IFBRPV_T_COMMUNITY },
	{ 0,			0 }
};

/*
 * On a veb, pvlan makes a VLAN a private VLAN's primary VLAN, and
 * pvlan-isolated and pvlan-community add a secondary VLAN to it: its one
 * isolated VLAN, whose members reach only the primary VLAN's, and any
 * number of community VLANs, whose members reach each other's too.
 * if_veb.c
 */
int
brpvlan(int argc, char **argv, ...)
{
	struct ifbrpvlan pv;
	struct brc *x;
	const char *errmsg = NULL;
	va_list ap;
	char *ifname;
	int ifs, set;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	x = (struct brc *) genget(argv[0], (char **)brpvs, sizeof(struct brc));
	if (x == 0 || Ambiguous(x)) {
		printf("%% Internal error - Invalid argument %s\n", argv[0]);
		return -1;
	}

	argv++;
	argc--;

	if (argc != (x->type == IFBRPV_T_PRIMARY ? 1 : 2)) {
		if (x->type == IFBRPV_T_PRIMARY)
			printf("%% [no] pvlan <primary-vlan>\n");
		else
			printf("%% [no] %s <primary-vlan> <vlan>\n", x->name);
		return -1;
	}
	if (!cand_takes(ifname, SIOCBRDGADDPV)) {
		printf("%% %s not supported on %s\n", x->name, ifname);
		return -1;
	}

	memset(&pv, 0, sizeof(pv));
	strlcpy(pv.ifbrpv_name, ifname, sizeof(pv.ifbrpv_name));
	pv.ifbrpv_type = x->type;
	pv.ifbrpv_primary = strtonum(argv[0], EVL_VLID_MIN, EVL_VLID_MAX,
	    &errmsg);
	if (errmsg == NULL && argc == 2)
		pv.ifbrpv_secondary = strtonum(argv[1], EVL_VLID_MIN,
		    EVL_VLID_MAX, &errmsg);
	if (errmsg) {
		printf("%% invalid VLAN: %s\n", errmsg);
		return -1;
	}
	if (br_ioctl(ifs, set ? SIOCBRDGADDPV : SIOCBRDGDELPV, &pv) == 0)
		return 0;
	switch (errno) {
	case EBUSY:
		if (set)
			printf("%% %s: VLAN %s is a private VLAN already\n",
			    x->name, argv[argc - 1]);
		else if (x->type == IFBRPV_T_PRIMARY)
			printf("%% pvlan: %s has secondary VLANs\n", argv[0]);
		else
			printf("%% %s: a member has VLAN %s\n", x->name,
			    argv[1]);
		break;
	case ENETUNREACH:
		printf("%% %s: %s is no primary VLAN\n", x->name, argv[0]);
		break;
	case EADDRINUSE:
		printf("%% %s: a member has VLAN %s\n", x->name, argv[1]);
		break;
	case EADDRNOTAVAIL:
		printf("%% %s: %s has an isolated VLAN\n", x->name, argv[0]);
		break;
	case ESRCH:
		printf("%% %s: no such private VLAN\n", x->name);
		break;
	default:
		printf("%% %s: %s\n", x->name, strerror(errno));
	}
	return -1;
}

/*
 * A bridge as conf_brcfg() prints it.  In configure private, the bridge
 * ioctls nsh sends change the bridge the candidate's lines describe, as
 * the driver would change the bridge in the kernel (net/if_bridge.c,
 * bridgectl.c, bridgestp.c and if_veb.c).
 */
struct brport {
	char name[IFNAMSIZ];
	u_int32_t flags;	/* IFBIF_*, IFBIF_SPAN for a span port */
	u_int8_t prio;		/* with IFBIF_STP */
	u_int32_t cost;		/* with IFBIF_STP, if set by hand, or 0 */
	u_int32_t prot;		/* protected domains, a bit each */
	u_int16_t pvid;		/* veb's: untagged's VLAN, IFBR_PVID_* */
	u_int8_t tagged[sizeof(((struct ifbrvidmap *)0)->ifbrvm_map)];
};

/* A static address or a rule, as conf_brcfg() prints it after the keyword */
struct brline {
	char ifs[IFNAMSIZ];	/* the member it is for */
	char *text;
};

struct brcfg {
	long val[TIMEOUT + 1];	/* by PRIORITY to TIMEOUT, -1 for none */
	struct brport *ports;
	size_t nports;
	struct brline *statics, *rules;
	size_t nstatics, nrules;
	int vlans;		/* a veb's members have VLANs */
	u_int16_t dflt;		/* a new member's untagged VLAN: vnetid's */
	struct ifbrpvlan *pvlans;	/* a veb's private VLANs */
	size_t npvlans;
};

static const struct {
	char *name;
	long def;
} brvals[] = {		/* by PRIORITY to TIMEOUT */
	{ "priority",	DEFAULT_PRIORITY },
	{ "hellotime",	DEFAULT_HELLOTIME },
	{ "fwddelay",	DEFAULT_FWDDELAY },
	{ "maxage",	DEFAULT_MAXAGE },
	{ "maxaddr",	DEFAULT_MAXADDR },
	{ "timeout",	DEFAULT_TIMEOUT },
};

/* Port lists: members that have flag and lack without, or span ports */
static const struct {
	char *name;
	u_int32_t flag, without;
} brlists[] = {
	{ "member",	 0,			0 },
	{ "stp",	 IFBIF_STP,		0 },
	{ "span",	 IFBIF_SPAN,		0 },
	{ "no learning", 0,			IFBIF_LEARNING },
	{ "no discover", 0,			IFBIF_DISCOVER },
	{ "blocknonip",	 IFBIF_BLOCKNONIP,	0 },
	{ "pvptags",	 IFBIF_PVLAN_PTAGS,	0 },
};

/* A veb's private VLANs' lines, by IFBRPV_T_* */
static const char *brpvnames[] = { "pvlan", NULL, "pvlan-isolated",
    "pvlan-community" };

/* The lines for a member's STP priority, STP cost and protected domains */
static char *brper[] = { "ifpriority", "ifcost", "protect" };

/* And for a veb member's VLANs */
static char *brvper[] = { "untagged", "tagged" };

/* The candidate lines a struct brcfg makes */
static char *brnames[] = { "pvlan", "pvlan-isolated", "pvlan-community",
    "priority", "hellotime", "fwddelay", "maxage", "maxaddr", "timeout",
    "member", "stp", "span", "learning", "discover", "blocknonip",
    "pvptags", "untagged", "tagged", "ifpriority", "ifcost", "protect",
    "static", "rule" };

/* Is line a port list, whose command takes one port at a time? */
int
brport_list(char *line)
{
	size_t i, len;

	for (i = 0; i < nitems(brlists); i++) {
		len = strlen(brlists[i].name);
		if (strncmp(line, brlists[i].name, len) == 0 &&
		    line[len] == ' ')
			return 1;
	}
	return 0;
}

/* Is line a per-member line, whose first value is the member? */
int
brport_one(char *line)
{
	size_t i, len;

	for (i = 0; i < nitems(brper); i++) {
		len = strlen(brper[i]);
		if (strncmp(line, brper[i], len) == 0 && line[len] == ' ')
			return 1;
	}
	for (i = 0; i < nitems(brvper); i++) {
		len = strlen(brvper[i]);
		if (strncmp(line, brvper[i], len) == 0 && line[len] == ' ')
			return 1;
	}
	return 0;
}

/* By name: bridge(4) lists the newest member first, veb(4) last */
static int
brport_cmp(const void *a, const void *b)
{
	const struct brport *x = a, *y = b;

	return strcmp(x->name, y->name);
}

static void
brcfg_free(struct brcfg *b)
{
	size_t i;

	for (i = 0; i < b->nstatics; i++)
		free(b->statics[i].text);
	for (i = 0; i < b->nrules; i++)
		free(b->rules[i].text);
	free(b->statics);
	free(b->rules);
	free(b->ports);
	free(b->pvlans);
}

/* Add a private VLAN to b's */
static int
brcfg_pvlan(struct brcfg *b, u_int primary, u_int secondary, u_int type)
{
	struct ifbrpvlan *v;

	if ((v = reallocarray(b->pvlans, b->npvlans + 1, sizeof(*v))) == NULL)
		return -1;
	b->pvlans = v;
	v += b->npvlans++;
	memset(v, 0, sizeof(*v));
	v->ifbrpv_primary = primary;
	v->ifbrpv_secondary = secondary;
	v->ifbrpv_type = type;
	return 0;
}

/* The private VLAN with vlan as its primary, or with type, its secondary */
static struct ifbrpvlan *
brcfg_findpv(struct brcfg *b, u_int vlan, u_int type)
{
	size_t i;

	for (i = 0; i < b->npvlans; i++)
		if ((type == IFBRPV_T_PRIMARY ?
		    b->pvlans[i].ifbrpv_primary :
		    b->pvlans[i].ifbrpv_secondary) == vlan &&
		    b->pvlans[i].ifbrpv_type == type)
			return &b->pvlans[i];
	return NULL;
}

/* Is vlan a private VLAN's, primary or secondary?  sc_pvlans[] */
static int
brcfg_inpv(struct brcfg *b, u_int vlan)
{
	size_t i;

	for (i = 0; i < b->npvlans; i++)
		if ((b->pvlans[i].ifbrpv_type == IFBRPV_T_PRIMARY ?
		    b->pvlans[i].ifbrpv_primary :
		    b->pvlans[i].ifbrpv_secondary) == vlan)
			return 1;
	return 0;
}

/* The isolated VLAN of primary's private VLAN, or NULL */
static struct ifbrpvlan *
brcfg_isolated(struct brcfg *b, u_int primary)
{
	size_t i;

	for (i = 0; i < b->npvlans; i++)
		if (b->pvlans[i].ifbrpv_type == IFBRPV_T_ISOLATED &&
		    b->pvlans[i].ifbrpv_primary == primary)
			return &b->pvlans[i];
	return NULL;
}

/* Has a member of b vlan, untagged or tagged?  veb_vid_inuse() */
static int
brcfg_vlaninuse(struct brcfg *b, u_int vlan)
{
	size_t i;

	for (i = 0; i < b->nports; i++)
		if (!(b->ports[i].flags & IFBIF_SPAN) &&
		    (b->ports[i].pvid == vlan ||
		    (b->ports[i].tagged[vlan / 8] & (1 << (vlan % 8)))))
			return 1;
	return 0;
}

/* By type, then primary VLAN, then secondary, as conf_brcfg() prints */
static int
brpvlan_cmp(const void *a, const void *b)
{
	const struct ifbrpvlan *x = a, *y = b;

	if (x->ifbrpv_type != y->ifbrpv_type)
		return x->ifbrpv_type < y->ifbrpv_type ? -1 : 1;
	if (x->ifbrpv_primary != y->ifbrpv_primary)
		return x->ifbrpv_primary < y->ifbrpv_primary ? -1 : 1;
	return x->ifbrpv_secondary < y->ifbrpv_secondary ? -1 :
	    x->ifbrpv_secondary > y->ifbrpv_secondary;
}

/* The port called name or NULL; with add, a new one, or NULL if it exists */
static struct brport *
brcfg_port(struct brcfg *b, const char *name, int add)
{
	struct brport *p;
	size_t i;

	for (i = 0; i < b->nports; i++)
		if (strcmp(b->ports[i].name, name) == 0)
			return add ? NULL : &b->ports[i];
	if (!add || strlen(name) >= IFNAMSIZ ||
	    (p = reallocarray(b->ports, b->nports + 1, sizeof(*p))) == NULL)
		return NULL;
	b->ports = p;
	p = &b->ports[b->nports++];
	memset(p, 0, sizeof(*p));
	strlcpy(p->name, name, sizeof(p->name));
	return p;
}

/* The member called name, not a span port, or NULL */
static struct brport *
brcfg_member(struct brcfg *b, const char *name)
{
	struct brport *p = brcfg_port(b, name, 0);

	return p != NULL && !(p->flags & IFBIF_SPAN) ? p : NULL;
}

/*
 * Add a static address, or with rule a rule, from its line after the
 * keyword: "00:1b:21:0a:0b:01 em2", "block in on em0"
 */
static int
brcfg_line(struct brcfg *b, int rule, const char *text)
{
	struct brline **l = rule ? &b->rules : &b->statics, *v;
	size_t *n = rule ? &b->nrules : &b->nstatics, len;
	const char *ifs;

	if (rule) {
		if ((ifs = strstr(text, " on ")) != NULL)
			ifs += 4;
	} else if ((ifs = strchr(text, ' ')) != NULL)
		ifs++;
	if (ifs == NULL || (len = strcspn(ifs, " ")) == 0 || len >= IFNAMSIZ)
		return -1;
	if ((v = reallocarray(*l, *n + 1, sizeof(**l))) == NULL)
		return -1;
	*l = v;
	v += *n;
	memset(v->ifs, 0, sizeof(v->ifs));
	memcpy(v->ifs, ifs, len);
	if ((v->text = strdup(text)) == NULL)
		return -1;
	(*n)++;
	return 0;
}

static void
brcfg_delline(struct brline *l, size_t *n, size_t i)
{
	free(l[i].text);
	memmove(&l[i], &l[i + 1], (--*n - i) * sizeof(*l));
}

/* The index of the static entry for ea, or -1 */
static int
brcfg_static(struct brcfg *b, struct ether_addr *ea)
{
	char *mac = ether_ntoa(ea);
	size_t i, len = strlen(mac);

	for (i = 0; i < b->nstatics; i++)
		if (strncmp(b->statics[i].text, mac, len) == 0 &&
		    b->statics[i].text[len] == ' ')
			return i;
	return -1;
}

static int brcfg_findbif(struct brcfg *, char *, struct brport **);

/* The VLAN a veb keeps an address in: a secondary VLAN's primary's */
static u_int
brcfg_vp(struct brcfg *b, u_int vlan)
{
	size_t i;

	for (i = 0; i < b->npvlans; i++)
		if (b->pvlans[i].ifbrpv_type != IFBRPV_T_PRIMARY &&
		    b->pvlans[i].ifbrpv_secondary == vlan)
			return b->pvlans[i].ifbrpv_primary;
	return vlan;
}

/* The index of a veb's static entry for ea in vlan, by vlan's primary */
static int
brcfg_vstatic(struct brcfg *b, struct ether_addr *ea, u_int vlan)
{
	char *mac = ether_ntoa(ea), *v;
	size_t i, len = strlen(mac);

	for (i = 0; i < b->nstatics; i++) {
		v = b->statics[i].text + len;
		if (strncmp(b->statics[i].text, mac, len) == 0 &&
		    *v == '@' && brcfg_vp(b, strtoul(v + 1, NULL, 10)) ==
		    brcfg_vp(b, vlan))
			return i;
	}
	return -1;
}

/*
 * A veb's static entry for ea in vlan, or with none, member's untagged
 * VLAN: veb_add_addr(), veb_add_vid_addr() and etherbridge_add_addr()
 */
static int
brcfg_vaddr(struct brcfg *b, struct ether_addr *ea, u_int vlan, char *member)
{
	static const struct ether_addr any;
	struct brport *p;
	char text[64];
	int e;

	if ((e = brcfg_findbif(b, member, &p)) != 0)
		return e;
	if (vlan == EVL_VLID_NULL)
		vlan = p->pvid;
	if (vlan < EVL_VLID_MIN || vlan > EVL_VLID_MAX)
		return EADDRNOTAVAIL;
	if (ETHER_IS_MULTICAST(ea->ether_addr_octet) ||
	    memcmp(ea, &any, sizeof(*ea)) == 0)
		return EADDRNOTAVAIL;
	/* an address is in a VLAN once: the kernel does not replace it */
	if (brcfg_vstatic(b, ea, vlan) != -1)
		return EADDRINUSE;
	snprintf(text, sizeof(text), "%s@%u %s", ether_ntoa(ea), vlan, member);
	return brcfg_line(b, 0, text) == -1 ? ENOMEM : 0;
}

/* remove p and its static addresses and rules, as bridge_ifremove() does */
static void
brcfg_del(struct brcfg *b, struct brport *p)
{
	size_t i;

	for (i = b->nstatics; i-- > 0; )
		if (strcmp(b->statics[i].ifs, p->name) == 0)
			brcfg_delline(b->statics, &b->nstatics, i);
	for (i = b->nrules; i-- > 0; )
		if (strcmp(b->rules[i].ifs, p->name) == 0)
			brcfg_delline(b->rules, &b->nrules, i);
	i = p - b->ports;
	memmove(p, p + 1, (b->nports - i - 1) * sizeof(*p));
	b->nports--;
}

/* The bridge brdg in the kernel */
static int
brcfg_kernel(int s, char *brdg, struct brcfg *b)
{
	struct ifbrvidmap vm;
	struct ifbrpvlan pv;
	struct ifbreq *reqs;
	struct brport *p;
	u_int vp, vs;
	char *buf = NULL, *l, *t;
	size_t i, n, len;
	FILE *f;
	int ret = -1;

	memset(b, 0, sizeof(*b));
	b->vlans = cand_takes(brdg, SIOCBRDGSPVID);
	for (i = 0; i <= TIMEOUT; i++)
		b->val[i] = bridge_cfg(s, brdg, i);
	if ((reqs = bridge_ports(s, brdg, &n)) == NULL)
		n = 0;
	for (i = 0; i < n; i++) {
		if ((p = brcfg_port(b, reqs[i].ifbr_ifsname, 1)) == NULL)
			goto done;
		p->flags = reqs[i].ifbr_ifsflags;
		p->prio = reqs[i].ifbr_priority;
		if (reqs[i].ifbr_stpflags & kern_bstp_port_admcost)
			p->cost = reqs[i].ifbr_path_cost;
		p->prot = reqs[i].ifbr_protected;
		/* a veb's member's VLANs */
		if (!b->vlans || (p->flags & IFBIF_SPAN))
			continue;
		p->pvid = reqs[i].ifbr_pvid;
		memset(&vm, 0, sizeof(vm));
		strlcpy(vm.ifbrvm_name, brdg, sizeof(vm.ifbrvm_name));
		strlcpy(vm.ifbrvm_ifsname, p->name, sizeof(vm.ifbrvm_ifsname));
		if (ioctl(s, SIOCBRDGGVMAP, &vm) == 0)
			memcpy(p->tagged, vm.ifbrvm_map, sizeof(p->tagged));
	}

	/* a veb's private VLANs: each primary, with its isolated VLAN */
	for (vp = 0; b->vlans; ) {
		memset(&pv, 0, sizeof(pv));
		strlcpy(pv.ifbrpv_name, brdg, sizeof(pv.ifbrpv_name));
		pv.ifbrpv_primary = vp + 1;
		pv.ifbrpv_type = IFBRPV_T_PRIMARY;
		if (ioctl(s, SIOCBRDGNFINDPV, &pv) == -1)
			break;
		vp = pv.ifbrpv_primary;
		if (brcfg_pvlan(b, vp, 0, IFBRPV_T_PRIMARY) == -1 ||
		    (pv.ifbrpv_secondary != 0 && brcfg_pvlan(b, vp,
		    pv.ifbrpv_secondary, IFBRPV_T_ISOLATED) == -1))
			goto done;
		/* and its community VLANs */
		for (vs = 0; ; vs = pv.ifbrpv_secondary) {
			pv.ifbrpv_primary = vp;
			pv.ifbrpv_secondary = vs + 1;
			pv.ifbrpv_type = IFBRPV_T_COMMUNITY;
			if (ioctl(s, SIOCBRDGNFINDPV, &pv) == -1)
				break;
			if (brcfg_pvlan(b, vp, pv.ifbrpv_secondary,
			    IFBRPV_T_COMMUNITY) == -1)
				goto done;
		}
	}

	/* the static addresses, then the members' rules, as they print */
	if ((f = open_memstream(&buf, &len)) == NULL)
		goto done;
	if (b->vlans)
		bridge_confvaddrs(s, brdg, "s", f);
	else
		bridge_confaddrs(s, brdg, "s", f);
	for (i = 0; i < b->nports; i++)
		if (!(b->ports[i].flags & IFBIF_SPAN))
			bridge_rules(s, brdg, b->ports[i].name, "r", f);
	if (fclose(f) == EOF)
		goto done;
	for (t = buf; (l = strsep(&t, "\n")) != NULL; )
		if (*l != '\0' && brcfg_line(b, *l == 'r', l + 1) == -1)
			goto done;
	ret = 0;
done:
	free(reqs);
	free(buf);
	return ret;
}

/* The bridge brdg as the candidate's lines describe it */
static int
brcfg_cand(struct brcfg *b, char *brdg)
{
	struct brport *p;
	char line[1024], *l, *w, *ws;
	const char *e = NULL;
	size_t i, n, no;
	u_int v;

	memset(b, 0, sizeof(*b));
	/* a veb's new member takes its vnetid's VLAN, or none */
	if ((b->vlans = cand_takes(brdg, SIOCBRDGSPVID)) != 0) {
		b->dflt = default_vnetid(brdg);
		if ((l = cand_line("vnetid", 0)) != NULL &&
		    strncmp(l, "no ", 3) == 0)
			b->dflt = IFBR_PVID_NONE;
		else if (l != NULL)
			b->dflt = strtonum(l + strlen("vnetid "), EVL_VLID_MIN,
			    EVL_VLID_MAX, &e);
		if (e != NULL)
			goto bad;
	}
	for (i = 0; i <= TIMEOUT; i++)
		b->val[i] = (l = cand_line(brvals[i].name, 0)) == NULL ?
		    brvals[i].def :
		    strtol(l + strlen(brvals[i].name) + 1, NULL, 10);

	for (i = 0; i < nitems(brlists); i++) {
		/* "no learning" is a learning line */
		no = strncmp(brlists[i].name, "no ", 3) == 0 ? 3 : 0;
		if ((l = cand_line(brlists[i].name + no, 0)) == NULL)
			continue;
		strlcpy(line, l + strlen(brlists[i].name) + 1, sizeof(line));
		for (ws = line; (w = strsep(&ws, " ")) != NULL; ) {
			if (i == 0 || brlists[i].flag == IFBIF_SPAN) {
				if ((p = brcfg_port(b, w, 1)) == NULL)
					goto bad;
				p->flags = i == 0 ? IFBIF_LEARNING |
				    IFBIF_DISCOVER : IFBIF_SPAN;
				if (i == 0 && b->vlans)
					p->pvid = b->dflt;
			} else if ((p = brcfg_member(b, w)) == NULL)
				goto bad;
			if (brlists[i].flag == IFBIF_STP)
				p->prio = DEFAULT_IFPRIORITY;
			if (i != 0 && brlists[i].flag != IFBIF_SPAN)
				p->flags = (p->flags | brlists[i].flag) &
				    ~brlists[i].without;
		}
	}

	/* "ifpriority em0 64", "ifcost em0 2000", "protect em0 1,2" */
	for (i = 0; i < nitems(brper); i++)
		for (n = 0; (l = cand_line(brper[i], n)) != NULL; n++) {
			strlcpy(line, l + strlen(brper[i]) + 1, sizeof(line));
			ws = line;
			if ((p = brcfg_member(b, strsep(&ws, " "))) == NULL ||
			    ws == NULL || (i < 2 && !(p->flags & IFBIF_STP)))
				goto bad;
			if (i == 0)
				p->prio = strtonum(ws, 0, 0xff, &e);
			else if (i == 1)
				p->cost = strtonum(ws, 1,
				    kern_bstp_max_path_cost, &e);
			else
				while ((w = strsep(&ws, ",")) != NULL &&
				    (v = strtonum(w, 1, 31, &e)) != 0)
					p->prot |= 1 << (v - 1);
			if (e != NULL)
				goto bad;
		}
	/* "pvlan 100", "pvlan-isolated 100 101", "pvlan-community 100 102" */
	for (i = 0; i < nitems(brpvnames); i++)
		for (n = 0; brpvnames[i] != NULL &&
		    (l = cand_line((char *)brpvnames[i], n)) != NULL; n++) {
			strlcpy(line, l + strlen(brpvnames[i]) + 1,
			    sizeof(line));
			ws = line;
			v = strtonum(strsep(&ws, " "), EVL_VLID_MIN,
			    EVL_VLID_MAX, &e);
			if (e != NULL || (ws == NULL) != (i == 0) ||
			    brcfg_pvlan(b, v, ws == NULL ? 0 : strtonum(ws,
			    EVL_VLID_MIN, EVL_VLID_MAX, &e), i) == -1 ||
			    e != NULL)
				goto bad;
		}
	/* "untagged em0 5", "tagged em0 10,20-30" */
	for (n = 0; (l = cand_line("untagged", n)) != NULL; n++) {
		strlcpy(line, l + strlen("untagged "), sizeof(line));
		ws = line;
		if ((p = brcfg_member(b, strsep(&ws, " "))) == NULL ||
		    ws == NULL)
			goto bad;
		if (strcmp(ws, "none") == 0)
			p->pvid = IFBR_PVID_NONE;
		else if (strcmp(ws, "passthrough") == 0)
			p->pvid = IFBR_PVID_DECLINE;
		else
			p->pvid = strtonum(ws, EVL_VLID_MIN, EVL_VLID_MAX, &e);
		if (e != NULL)
			goto bad;
	}
	for (n = 0; (l = cand_line("tagged", n)) != NULL; n++) {
		strlcpy(line, l + strlen("tagged "), sizeof(line));
		ws = line;
		if ((p = brcfg_member(b, strsep(&ws, " "))) == NULL ||
		    ws == NULL || brvlan_parse(ws, p->tagged) == -1)
			goto bad;
	}
	for (n = 0; (l = cand_line("static", n)) != NULL; n++)
		if (brcfg_line(b, 0, l + strlen("static ")) == -1)
			goto bad;
	for (n = 0; (l = cand_line("rule", n)) != NULL; n++)
		if (brcfg_line(b, 1, l + strlen("rule ")) == -1)
			goto bad;
	return 0;
bad:
	printf("%% brcfg_cand: cannot read \"%s\"\n", l);
	return -1;
}

static void
brcfg_print(FILE *output, struct brcfg *b)
{
	struct brport *p;
	size_t i, j;
	int n, v;

	qsort(b->ports, b->nports, sizeof(*b->ports), brport_cmp);
	if (b->npvlans > 0)
		qsort(b->pvlans, b->npvlans, sizeof(*b->pvlans), brpvlan_cmp);
	for (j = 0; j < b->npvlans; j++) {
		fprintf(output, " %s %u", brpvnames[b->pvlans[j].ifbrpv_type],
		    b->pvlans[j].ifbrpv_primary);
		if (b->pvlans[j].ifbrpv_type != IFBRPV_T_PRIMARY)
			fprintf(output, " %u", b->pvlans[j].ifbrpv_secondary);
		fprintf(output, "\n");
	}
	for (i = 0; i <= TIMEOUT; i++)
		if (b->val[i] != -1 && b->val[i] != brvals[i].def)
			fprintf(output, " %s %ld\n", brvals[i].name, b->val[i]);
	for (i = 0; i < nitems(brlists); i++) {
		for (n = 0, j = 0; j < b->nports; j++) {
			p = &b->ports[j];
			if (((p->flags & IFBIF_SPAN) != 0) !=
			    (brlists[i].flag == IFBIF_SPAN) ||
			    (p->flags & brlists[i].flag) != brlists[i].flag ||
			    (p->flags & brlists[i].without) != 0)
				continue;
			if (n++ == 0)
				fprintf(output, " %s", brlists[i].name);
			fprintf(output, " %s", p->name);
		}
		if (n)
			fprintf(output, "\n");
	}
	/* a veb's members' VLANs */
	for (j = 0; b->vlans && j < b->nports; j++) {
		p = &b->ports[j];
		if (p->flags & IFBIF_SPAN)
			continue;
		if (p->pvid == IFBR_PVID_NONE)
			fprintf(output, " untagged %s none\n", p->name);
		else if (p->pvid == IFBR_PVID_DECLINE)
			fprintf(output, " untagged %s passthrough\n", p->name);
		else if (p->pvid != EVL_VLID_NULL)
			fprintf(output, " untagged %s %u\n", p->name, p->pvid);
	}
	for (j = 0; b->vlans && j < b->nports; j++) {
		p = &b->ports[j];
		for (i = 0; i < sizeof(p->tagged) && p->tagged[i] == 0; i++)
			;
		if (i == sizeof(p->tagged))
			continue;
		fprintf(output, " tagged %s ", p->name);
		brvlan_print(output, p->tagged);
		fprintf(output, "\n");
	}
	for (j = 0; j < b->nports; j++)
		if ((b->ports[j].flags & IFBIF_STP) &&
		    b->ports[j].prio != DEFAULT_IFPRIORITY)
			fprintf(output, " ifpriority %s %u\n", b->ports[j].name,
			    b->ports[j].prio);
	for (j = 0; j < b->nports; j++)
		if ((b->ports[j].flags & IFBIF_STP) && b->ports[j].cost != 0)
			fprintf(output, " ifcost %s %u\n", b->ports[j].name,
			    b->ports[j].cost);
	for (j = 0; j < b->nports; j++) {
		if (b->ports[j].prot == 0)
			continue;
		fprintf(output, " protect %s", b->ports[j].name);
		for (n = 0, v = 1; v < 32; v++)
			if (b->ports[j].prot & (1 << (v - 1)))
				fprintf(output, n++ ? ",%d" : " %d", v);
		fprintf(output, "\n");
	}
	for (j = 0; j < b->nstatics; j++)
		fprintf(output, " static %s\n", b->statics[j].text);
	for (j = 0; j < b->nrules; j++)
		fprintf(output, " rule %s\n", b->rules[j].text);
}

void
conf_brcfg(FILE *output, int ifs, char *ifname)
{
	struct brcfg b;

	if (brcfg_kernel(ifs, ifname, &b) == 0)
		brcfg_print(output, &b);
	brcfg_free(&b);
}

/* Adding name to the candidate's bridge brdg, as a span port with span */
static int
brcfg_add(struct brcfg *b, char *brdg, char *name, int span)
{
	struct brport *p;

	if (!cand_hasif(name))
		return ENOENT;
	if (cand_gettype(name) != IFT_ETHER)
		return EINVAL;
	if ((p = brcfg_port(b, name, 0)) != NULL)
		return (p->flags & IFBIF_SPAN) && !span ? EBUSY : EEXIST;
	if (cand_listowner(brdg, "member", name) != NULL)
		return EBUSY;
	if ((p = brcfg_port(b, name, 1)) == NULL)
		return ENOMEM;
	p->flags = span ? IFBIF_SPAN : IFBIF_LEARNING | IFBIF_DISCOVER;
	/* veb_add_port() */
	if (!span && b->vlans)
		p->pvid = b->dflt;
	return 0;
}

/* Set time i to secs, if from min to max ticks, as bstp_ioctl() checks */
static int
brcfg_time(struct brcfg *b, int i, int secs, int min, int max)
{
	if (secs * kern_bstp_tick_val < min || secs * kern_bstp_tick_val > max)
		return EINVAL;
	b->val[i] = secs;
	return 0;
}

/* find member name of the candidate's bridge, as bridge_findbif() does */
static int
brcfg_findbif(struct brcfg *b, char *name, struct brport **p)
{
	if (!cand_hasif(name))
		return ENOENT;
	return (*p = brcfg_member(b, name)) == NULL ? ESRCH : 0;
}

/* A rule, as the kernel keeps it: one for each direction */
static int
brcfg_rule(struct brcfg *b, struct ifbrlreq *req)
{
	static const u_int8_t ways[] = { BRL_FLAG_IN, BRL_FLAG_OUT };
	struct ifbrlreq r;
	char *buf = NULL;
	size_t i, len;
	FILE *f;
	int ret = 0;

	for (i = 0; i < nitems(ways) && ret == 0; i++) {
		if (!(req->ifbr_flags & ways[i]))
			continue;
		r = *req;
		r.ifbr_flags &= ~(BRL_FLAG_IN | BRL_FLAG_OUT);
		r.ifbr_flags |= ways[i];
		if ((f = open_memstream(&buf, &len)) == NULL)
			return ENOMEM;
		bridge_showrule(&r, "", f);
		if (fclose(f) == EOF || len == 0)
			ret = ENOMEM;
		else {
			buf[len - 1] = '\0';
			if (brcfg_line(b, 1, buf) == -1)
				ret = ENOMEM;
		}
		free(buf);
		buf = NULL;
	}
	return ret;
}

/*
 * A bridge ioctl in configure private: apply it to the bridge the
 * candidate's lines describe and answer as bridge_ioctl() would, then
 * write the resulting bridge back to the candidate's lines
 */
static int
cand_bridge(u_long cmd, void *data)
{
	char *brdg = data;	/* each request starts with the bridge's name */
	struct ifbreq *req = data;
	struct ifbrparam *bp = data;
	struct ifbareq *ba = data;
	struct ifbrlreq *rl = data;
	struct ifbrvidmap *vm = data;
	struct ifbrpvlan *pv = data, *v;
	struct ifbvareq *bva = data;
	struct brcfg b;
	struct brport *p;
	char *buf = NULL, text[64];
	size_t len;
	FILE *f;
	int e = 0, i;
	u_int16_t pvid;

	if (!cand_takes(brdg, cmd)) {
		errno = ENOTTY;
		return -1;
	}
	if (brcfg_cand(&b, brdg) == -1) {
		e = EINVAL;
		goto done;
	}
	switch (cmd) {
	case SIOCBRDGADD:
	case SIOCBRDGADDS:
		e = brcfg_add(&b, brdg, req->ifbr_ifsname,
		    cmd == SIOCBRDGADDS);
		/* a port's TCP large receive offload goes off */
		if (e == 0 && cand_ifsetting(req->ifbr_ifsname, ST_DEFAULT,
		    "tcplro") == -1)
			e = EINVAL;
		break;
	case SIOCBRDGDEL:
		if ((e = brcfg_findbif(&b, req->ifbr_ifsname, &p)) == 0)
			brcfg_del(&b, p);
		break;
	case SIOCBRDGDELS:
		if (!cand_hasif(req->ifbr_ifsname))
			e = ENOENT;
		else if ((p = brcfg_port(&b, req->ifbr_ifsname, 0)) == NULL ||
		    !(p->flags & IFBIF_SPAN))
			e = ESRCH;
		else
			brcfg_del(&b, p);
		break;
	case SIOCBRDGGIFFLGS:
		if ((e = brcfg_findbif(&b, req->ifbr_ifsname, &p)) == 0) {
			req->ifbr_ifsflags = p->flags;
			req->ifbr_protected = p->prot;
		}
		goto done;
	case SIOCBRDGSIFFLGS:
		if (req->ifbr_ifsflags & IFBIF_RO_MASK) {
			e = EINVAL;
			break;
		}
		if ((e = brcfg_findbif(&b, req->ifbr_ifsname, &p)) != 0)
			break;
		/* a driver with no spanning tree has no ioctls for it */
		if ((req->ifbr_ifsflags & IFBIF_STP) &&
		    !cand_takes(brdg, SIOCBRDGSIFPRIO)) {
			e = EINVAL;
			break;
		}
		/* bstp_add() */
		if ((req->ifbr_ifsflags & IFBIF_STP) &&
		    !(p->flags & IFBIF_STP)) {
			p->prio = DEFAULT_IFPRIORITY;
			p->cost = 0;
		}
		p->flags = req->ifbr_ifsflags;
		break;
	case SIOCBRDGSIFPROT:
		if ((e = brcfg_findbif(&b, req->ifbr_ifsname, &p)) == 0)
			p->prot = req->ifbr_protected;
		break;
	case SIOCBRDGSPVID:
		/* veb_port_set_pvid(): no VLAN is the veb's vnetid's */
		pvid = req->ifbr_pvid == EVL_VLID_NULL ? b.dflt :
		    req->ifbr_pvid;
		if (pvid != IFBR_PVID_NONE && pvid != IFBR_PVID_DECLINE &&
		    (pvid < EVL_VLID_MIN || pvid > EVL_VLID_MAX))
			e = EINVAL;
		else if ((e = brcfg_findbif(&b, req->ifbr_ifsname, &p)) != 0)
			break;
		/* a vport has a VLAN */
		else if ((pvid == IFBR_PVID_NONE ||
		    pvid == IFBR_PVID_DECLINE) && isprefix("vport", p->name))
			e = EOPNOTSUPP;
		else
			p->pvid = pvid;
		break;
	case SIOCBRDGADDPV:
	case SIOCBRDGDELPV:
		/* veb_add_pvlan(), veb_del_pvlan() */
		if (pv->ifbrpv_primary < EVL_VLID_MIN ||
		    pv->ifbrpv_primary > EVL_VLID_MAX ||
		    (pv->ifbrpv_type == IFBRPV_T_PRIMARY ?
		    pv->ifbrpv_secondary != 0 :
		    (pv->ifbrpv_type != IFBRPV_T_ISOLATED &&
		    pv->ifbrpv_type != IFBRPV_T_COMMUNITY) ||
		    pv->ifbrpv_secondary < EVL_VLID_MIN ||
		    pv->ifbrpv_secondary > EVL_VLID_MAX)) {
			e = EINVAL;
			break;
		}
		v = brcfg_findpv(&b, pv->ifbrpv_primary, IFBRPV_T_PRIMARY);
		if (cmd == SIOCBRDGDELPV) {
			if (v == NULL)
				e = ESRCH;
			else if (pv->ifbrpv_type != IFBRPV_T_PRIMARY &&
			    ((v = brcfg_findpv(&b, pv->ifbrpv_secondary,
			    pv->ifbrpv_type)) == NULL ||
			    v->ifbrpv_primary != pv->ifbrpv_primary))
				e = ESRCH;
			else if (pv->ifbrpv_type != IFBRPV_T_PRIMARY &&
			    brcfg_vlaninuse(&b, pv->ifbrpv_secondary))
				e = EBUSY;
			else if (pv->ifbrpv_type == IFBRPV_T_PRIMARY) {
				/* a primary goes once it has no secondary */
				for (i = 0; i < (int)b.npvlans; i++)
					if (b.pvlans[i].ifbrpv_type !=
					    IFBRPV_T_PRIMARY &&
					    b.pvlans[i].ifbrpv_primary ==
					    pv->ifbrpv_primary)
						e = EBUSY;
			}
			if (e == 0)
				memmove(v, v + 1, (b.npvlans-- -
				    (v - b.pvlans) - 1) * sizeof(*v));
			break;
		}
		/* a VLAN is one private VLAN's, primary or secondary */
		if (pv->ifbrpv_type == IFBRPV_T_PRIMARY ? brcfg_inpv(&b,
		    pv->ifbrpv_primary) : brcfg_inpv(&b, pv->ifbrpv_secondary))
			e = EBUSY;
		else if (pv->ifbrpv_type == IFBRPV_T_PRIMARY)
			;
		else if (v == NULL)
			e = ENETUNREACH;
		else if (brcfg_vlaninuse(&b, pv->ifbrpv_secondary))
			e = EADDRINUSE;
		else if (pv->ifbrpv_type == IFBRPV_T_ISOLATED &&
		    (v = brcfg_isolated(&b, pv->ifbrpv_primary)) != NULL)
			e = EADDRNOTAVAIL;
		if (e == 0 && brcfg_pvlan(&b, pv->ifbrpv_primary,
		    pv->ifbrpv_secondary, pv->ifbrpv_type) == -1)
			e = ENOMEM;
		break;
	case SIOCBRDGSVMAP:
		/* veb_set_vid_map(): VLANs 0 and 4095 are no tags */
		if (vm->ifbrvm_op > IFBRVM_OP_ANDNOT ||
		    (vm->ifbrvm_map[0] & 1) || (vm->ifbrvm_map[511] & 0x80)) {
			e = EINVAL;
			break;
		}
		if ((e = brcfg_findbif(&b, vm->ifbrvm_ifsname, &p)) != 0)
			break;
		for (i = 0; i < (int)sizeof(p->tagged); i++)
			if (vm->ifbrvm_op == IFBRVM_OP_SET)
				p->tagged[i] = vm->ifbrvm_map[i];
			else if (vm->ifbrvm_op == IFBRVM_OP_OR)
				p->tagged[i] |= vm->ifbrvm_map[i];
			else
				p->tagged[i] &= ~vm->ifbrvm_map[i];
		break;
	case SIOCBRDGSVADDR:
		/* veb_add_vid_addr() */
		if (bva->ifbva_vid != EVL_VLID_NULL &&
		    (bva->ifbva_vid < EVL_VLID_MIN ||
		    bva->ifbva_vid > EVL_VLID_MAX))
			e = EINVAL;
		else
			e = brcfg_vaddr(&b, &bva->ifbva_dst, bva->ifbva_vid,
			    bva->ifbva_ifsname);
		break;
	case SIOCBRDGDVADDR:
		/* veb_del_vid_addr() */
		if (bva->ifbva_vid < EVL_VLID_MIN ||
		    bva->ifbva_vid > EVL_VLID_MAX)
			e = EINVAL;
		else if ((i = brcfg_vstatic(&b, &bva->ifbva_dst,
		    bva->ifbva_vid)) == -1)
			e = ESRCH;
		else
			brcfg_delline(b.statics, &b.nstatics, i);
		break;
	case SIOCBRDGSADDR:
		/* a veb's address is in the member's untagged VLAN */
		if (b.vlans) {
			e = brcfg_vaddr(&b, &ba->ifba_dst, EVL_VLID_NULL,
			    ba->ifba_ifsname);
			break;
		}
		if ((e = brcfg_findbif(&b, ba->ifba_ifsname, &p)) != 0)
			break;
		if ((i = brcfg_static(&b, &ba->ifba_dst)) != -1)
			brcfg_delline(b.statics, &b.nstatics, i);
		snprintf(text, sizeof(text), "%s %s", ether_ntoa(&ba->ifba_dst),
		    ba->ifba_ifsname);
		if (brcfg_line(&b, 0, text) == -1)
			e = ENOMEM;
		break;
	case SIOCBRDGDADDR:
		/* a veb's address in its vnetid's VLAN: veb_del_addr() */
		if (b.vlans && (b.dflt == IFBR_PVID_NONE ||
		    (i = brcfg_vstatic(&b, &ba->ifba_dst, b.dflt)) == -1))
			e = ESRCH;
		else if (b.vlans)
			brcfg_delline(b.statics, &b.nstatics, i);
		else if ((i = brcfg_static(&b, &ba->ifba_dst)) == -1)
			e = ENOENT;
		else
			brcfg_delline(b.statics, &b.nstatics, i);
		break;
	case SIOCBRDGARL:
		if ((rl->ifbr_action != BRL_ACTION_BLOCK &&
		    rl->ifbr_action != BRL_ACTION_PASS) ||
		    !(rl->ifbr_flags & (BRL_FLAG_IN | BRL_FLAG_OUT)))
			e = EINVAL;
		else if ((e = brcfg_findbif(&b, rl->ifbr_ifsname, &p)) == 0)
			e = brcfg_rule(&b, rl);
		break;
	case SIOCBRDGSPRI:
		if (bp->ifbrp_prio > kern_bstp_max_priority)
			e = EINVAL;
		else
			b.val[PRIORITY] = bp->ifbrp_prio -
			    bp->ifbrp_prio % kern_bstp_priority_step;
		break;
	case SIOCBRDGSHT:
		/* bstp_create()'s protocol, which nsh never changes */
		if (kern_bstp_protover != kern_bstp_ht_protover)
			e = EPERM;
		else
			e = brcfg_time(&b, HELLOTIME, bp->ifbrp_hellotime,
			    kern_bstp_min_hello_time, kern_bstp_max_hello_time);
		break;
	case SIOCBRDGSFD:
		e = brcfg_time(&b, FWDDELAY, bp->ifbrp_fwddelay,
		    kern_bstp_min_fwd_delay, kern_bstp_max_fwd_delay);
		break;
	case SIOCBRDGSMA:
		e = brcfg_time(&b, MAXAGE, bp->ifbrp_maxage,
		    kern_bstp_min_max_age, kern_bstp_max_max_age);
		break;
	case SIOCBRDGSCACHE:
		b.val[MAXADDR] = bp->ifbrp_csize;
		break;
	case SIOCBRDGSTO:
		if (bp->ifbrp_ctime < 0)
			e = EINVAL;
		else
			b.val[TIMEOUT] = bp->ifbrp_ctime;
		break;
	case SIOCBRDGSIFPRIO:
	case SIOCBRDGSIFCOST:
		if ((e = brcfg_findbif(&b, req->ifbr_ifsname, &p)) != 0)
			break;
		if (!(p->flags & IFBIF_STP))
			e = EINVAL;
		else if (cmd == SIOCBRDGSIFCOST) {
			if (req->ifbr_path_cost > kern_bstp_max_path_cost)
				e = EINVAL;
			else	/* 0 has the kernel work it out from the speed */
				p->cost = req->ifbr_path_cost;
		} else if (req->ifbr_priority > kern_bstp_max_port_priority)
			e = EINVAL;
		else
			p->prio = req->ifbr_priority -
			    req->ifbr_priority % kern_bstp_port_priority_step;
		break;
	default:
		e = ENOTTY;
	}
	if (e != 0)
		goto done;
	if ((f = open_memstream(&buf, &len)) == NULL) {
		e = errno;
		goto done;
	}
	brcfg_print(f, &b);
	if (fclose(f) == EOF || cand_putlines(brnames, nitems(brnames),
	    buf) == -1)
		e = ENOMEM;
done:
	free(buf);
	brcfg_free(&b);
	if (e != 0) {
		errno = e;
		return -1;
	}
	return 0;
}

/* Send a bridge ioctl to the kernel, or in configure private, the candidate */
static int
br_ioctl(int s, u_long cmd, void *data)
{
	if (candidate)
		return cand_bridge(cmd, data);
	return ioctl(s, cmd, data);
}

/* Can name be a port of a bridge, as far as the kernel or candidate says? */
static int
br_portname(int ifs, char *name)
{
	if (candidate)
		return cand_hasif(name) && !cand_isbridge(name);
	return is_valid_ifname(name) && !is_bridge(ifs, name);
}

/* every bridge, or ifname, each after its members */
int
bridge_show_facts(struct facts_out *o, char *ifname)
{
	struct facts_value v[BR_NFIELDS];
	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr;
	char ifdescr[IFDESCRSIZE];
	int ifs, r = 0;

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% show_bridge: socket: %s\n", strerror(errno));
		return (-1);
	}

	if (ifname) {
		if (!is_valid_ifname(ifname) || !is_bridge(ifs, ifname)) {
			printf("%% interface %s is not a bridge\n", ifname);
			close(ifs);
			return (-1);
		}
	}

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% show_vlan: if_nameindex failed\n");
		close(ifs);
		return (-1);
	}

	for (ifnp = ifn_list; ifnp->if_name != NULL && r != -1; ifnp++) {
		if (ifname) {
			if (strcmp(ifname, ifnp->if_name) != 0)
				continue;
		} else if (!is_bridge(ifs, ifnp->if_name))
			continue;

		if (bridge_members(o, ifs, ifnp->if_name) == -1) {
			r = -1;
			break;
		}
		memset(v, 0, sizeof(v));
		facts_string(&v[BR_NAME], ifnp->if_name);
		facts_u64(&v[BR_FLAGS], get_ifflags(ifnp->if_name, ifs));

		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, ifnp->if_name, sizeof(ifr.ifr_name));
		memset(ifdescr, 0, sizeof(ifdescr));
		ifr.ifr_data = (caddr_t)&ifdescr;
		if (ioctl(ifs, SIOCGIFDESCR, &ifr) == 0 &&
		    ifr.ifr_data[0] != '\0')
			facts_string(&v[BR_DESCR], ifdescr);
		r = facts_record(o, &kind_bridge, v);

		if (ifname)
			break;
	}
	if_freenameindex(ifn_list);
	close(ifs);
	return (r);
}
