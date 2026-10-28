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
#include <errno.h>
#include <string.h>
#include <err.h>
#include <sysexits.h>
#include <stdlib.h>
#include <limits.h>
#include "externs.h"
#include "bridge.h"
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

char *stpstates[] = {
	"disabled",
	"listening",
	"learning",
	"forwarding",
	"blocking",
};

#define BRPORT_MEMBER 0
#define BRPORT_SPAN 1
#define BRPORT_BLOCKNONIP 2
#define BRPORT_DISCOVER 3
#define BRPORT_LEARN 4
#define BRPORT_STP 5

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
		printf("%% static <mac address> <member>\n");
		printf("%% no static <mac address> [member]\n");
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

	if (!is_bridge(ifs, brdg)) {
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

	if (!is_bridge(ifs, brdg)) {
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
	struct ifbareq ifba;
	struct ether_addr *ea;

	strlcpy(ifba.ifba_name, brdg, sizeof(ifba.ifba_name));
	ea = ether_aton(addr);
	if (ea == NULL) {
		printf("%% Invalid address: %s\n", addr);
		return (EX_USAGE);
	}
	bcopy(ea, &ifba.ifba_dst, sizeof(struct ether_addr));

	if (br_ioctl(s, SIOCBRDGDADDR, &ifba) < 0) {
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
	struct ifbareq ifba;
	struct ether_addr *ea;

	strlcpy(ifba.ifba_name, brdg, sizeof(ifba.ifba_name));
	strlcpy(ifba.ifba_ifsname, ifname, sizeof(ifba.ifba_ifsname));

	ea = ether_aton(addr);
	if (ea == NULL) {
		printf("%% Invalid address: %s\n", addr);
		return (EX_USAGE);
	}
	bcopy(ea, &ifba.ifba_dst, sizeof(struct ether_addr));
	ifba.ifba_flags = IFBAF_STATIC;

	if (br_ioctl(s, SIOCBRDGSADDR, &ifba) < 0) {
		char tmp[128];

		snprintf(tmp, sizeof(tmp), "%% unable to add %s to %s: %s\n",
		    addr, brdg, strerror(errno));
		printf("%s", tmp);
		return (EX_IOERR);
	}

	return (0);
}

/* a bridge's members, and the addresses it learned, as facts */
static struct facts_field bridgemember_fields[] = {
	[BRM_NAME] =		{ "name",	FACT_STRING },
	[BRM_FLAGS] =		{ "flags",	FACT_U64 },
	[BRM_STATE] =		{ "stp-state",	FACT_U64 },
	[BRM_IF] =		{ "interface",	FACT_STRING },
};
struct facts_kind kind_bridgemember = { "bridge-member", bridgemember_fields,
    BRM_NFIELDS };

static struct facts_field bridgeaddr_fields[] = {
	[BRA_ADDRESS] =		{ "address",	FACT_ADDRESS },
	[BRA_MEMBER] =		{ "member",	FACT_STRING },
	[BRA_AGE] =		{ "age",	FACT_U64 },
	[BRA_FLAGS] =		{ "flags",	FACT_U64 },
	[BRA_IF] =		{ "interface",	FACT_STRING },
};
struct facts_kind kind_bridgeaddr = { "bridge-address", bridgeaddr_fields,
    BRA_NFIELDS };

/* a bridge, after its members, as show bridge shows it */
static struct facts_field bridge_fields[] = {
	[BR_NAME] =		{ "name",		FACT_STRING },
	[BR_FLAGS] =		{ "flags",		FACT_U64 },
	[BR_DESCR] =		{ "description",	FACT_STRING },
};
struct facts_kind kind_bridge = { "bridge", bridge_fields, BR_NFIELDS };

void
bridge_facts_init(void)
{
	static struct facts_name	 states[nitems(stpstates)];
	size_t				 i;

	facts_bitnames(&bridgemember_fields[BRM_FLAGS], IFBIFBITS);
	for (i = 0; i < nitems(stpstates); i++) {
		states[i].value = i;
		states[i].name = stpstates[i];
	}
	bridgemember_fields[BRM_STATE].naming = FACT_VALUES;
	bridgemember_fields[BRM_STATE].names = states;
	bridgemember_fields[BRM_STATE].nnames = nitems(stpstates);
	facts_bitnames(&bridgeaddr_fields[BRA_FLAGS], IFBAFBITS);
	facts_bitnames(&bridge_fields[BR_FLAGS], ifnetflags);
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
		facts_record(o, &kind_bridgeaddr, v);
	}
	free(inbuf);
}

/* r's string i, or "" */
static const char *
bridge_s(struct frec *r, int i)
{
	const char	*s = fs(r, i);

	return (s != NULL ? s : "");
}

/* a bridge's STP members and learned addresses, as show_int() printed */
void
bridge_render(struct frecs *rs, FILE *outfile)
{
	const struct facts_value *a;
	struct ether_addr ea;
	struct frec *r;
	uint64_t state;
	int n;

	for (n = 0, r = NULL; (r = frec_next(rs, r, &kind_bridgemember)); )
		if (fu(r, BRM_FLAGS, 0) & IFBIF_STP)
			n++;
	if (n) {
		fprintf(outfile, "  STP member state%s:\n", n > 1 ?  "s" : "");
		for (r = NULL; (r = frec_next(rs, r, &kind_bridgemember)); ) {
			if (!(fu(r, BRM_FLAGS, 0) & IFBIF_STP))
				continue;
			state = fu(r, BRM_STATE, 0);
			if (state < nitems(stpstates))
				fprintf(outfile, "    %s: %s\n",
				    bridge_s(r, BRM_NAME), stpstates[state]);
			else
				fprintf(outfile, "    %s: %llu\n",
				    bridge_s(r, BRM_NAME),
				    (unsigned long long)state);
		}
	}

	if (frec_next(rs, NULL, &kind_bridgeaddr) != NULL) {
		fprintf(outfile, "  Learned addresses:\n");
		fprintf(outfile, "    address           member age\n");
	}
	for (r = NULL; (r = frec_next(rs, r, &kind_bridgeaddr)); ) {
		memset(&ea, 0, sizeof(ea));
		if ((a = FV(r, BRA_ADDRESS, FACT_ADDRESS)) != NULL &&
		    a->v.a.len == sizeof(ea))
			memcpy(&ea, a->v.a.bytes, sizeof(ea));
		fprintf(outfile, "    %s %-6s %u ", ether_ntoa(&ea),
		    bridge_s(r, BRA_MEMBER), (u_int)fu(r, BRA_AGE, 0));
		bprintf(outfile, fu(r, BRA_FLAGS, 0), IFBAFBITS);
		fputc('\n', outfile);
	}
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

/*
 * Check to make sure 'brdg' is really a bridge interface.
 */
int
is_bridge(int s, char *brdg)
{
	struct ifreq ifr;
	struct ifbaconf ifbac;
	struct if_data if_data;

	strlcpy(ifr.ifr_name, brdg, sizeof(ifr.ifr_name));

	ifr.ifr_data = (caddr_t)&if_data;
	if (ioctl(s, SIOCGIFDATA, (caddr_t)&ifr) < 0) {
		/* bail out */
		return 0;
	}
	if (if_data.ifi_type == IFT_BRIDGE) {
		/* surely a bridge! */
		return 1;
	}

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
};

/* The lines for a member's STP priority, STP cost and protected domains */
static char *brper[] = { "ifpriority", "ifcost", "protect" };

/* The candidate lines a struct brcfg makes */
static char *brnames[] = { "priority", "hellotime", "fwddelay", "maxage",
    "maxaddr", "timeout", "member", "stp", "span", "learning", "discover",
    "blocknonip", "ifpriority", "ifcost", "protect", "static", "rule" };

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
	struct ifbreq *reqs;
	struct brport *p;
	char *buf = NULL, *l, *t;
	size_t i, n, len;
	FILE *f;
	int ret = -1;

	memset(b, 0, sizeof(*b));
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
	}

	/* the static addresses, then the members' rules, as they print */
	if ((f = open_memstream(&buf, &len)) == NULL)
		goto done;
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

/* The bridge the candidate's lines describe */
static int
brcfg_cand(struct brcfg *b)
{
	struct brport *p;
	char line[1024], *l, *w, *ws;
	const char *e;
	size_t i, n, no;
	u_int v;

	memset(b, 0, sizeof(*b));
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
	struct brcfg b;
	struct brport *p;
	char *buf = NULL, text[64];
	size_t len;
	FILE *f;
	int e = 0, i;

	if (!cand_takes(brdg, cmd)) {
		errno = ENOTTY;
		return -1;
	}
	if (brcfg_cand(&b) == -1) {
		e = EINVAL;
		goto done;
	}
	switch (cmd) {
	case SIOCBRDGADD:
	case SIOCBRDGADDS:
		e = brcfg_add(&b, brdg, req->ifbr_ifsname,
		    cmd == SIOCBRDGADDS);
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
	case SIOCBRDGSADDR:
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
		if ((i = brcfg_static(&b, &ba->ifba_dst)) == -1)
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

/*
 * Bridge b and its members in rs, as show_bridge() printed them, and the
 * headers before the first
 */
void
bridge_show_render(struct frecs *rs, struct frec *b, int n)
{
	struct frec *r;
	const char *name;
	int totlen, len;
	char buf[1024], tmp[256], *p, *member;

	if (n == 0)
		puts("% Bridge    Status  Member Interfaces");

	/* as bridge_list() lists them */
	buf[0] = '\0';
	for (r = NULL; (r = frec_next(rs, r, &kind_bridgemember)); ) {
		if ((name = fs(r, BRM_NAME)) == NULL || name[0] == '\0' ||
		    (fu(r, BRM_FLAGS, 0) & IFBIF_SPAN))
			continue;
		snprintf(tmp, sizeof(tmp), "%s%s", buf[0] ? " " : "", name);
		strlcat(buf, tmp, sizeof(buf));
	}

	len = printf("  %-9s %-7s", bridge_s(b, BR_NAME),
	    (fu(b, BR_FLAGS, 0) & IFF_UP) ? "up" : "down");
	if (len < 0) {
		printf("\n%% show_bridge: printf failed: %s\n",
		    strerror(errno));
		return;
	}
	totlen = len;

	p = buf;
	while ((member = strsep(&p, " ")) != NULL) {
		if (totlen + strlen(member) >= 80) {
			printf("\n                   ");
			len = 19;
			totlen = len;
		}

		len = printf(" %s", member);
		if (len < 0) {
			printf("\n%% show_bridge: printf failed: %s\n",
			    strerror(errno));
			return;
		}
		totlen += len;
	}
	printf("\n");

	printf("            Description: %s\n", fs(b, BR_DESCR) != NULL ?
	    fs(b, BR_DESCR) : "-");
}

int
show_bridges(int argc, char **argv, ...)
{
	switch (argc) {
	case 2:
		return facts_show(stdout, "bridge");
	case 3:
		return facts_show(stdout, "bridge %s", argv[2]);
	}
	return 0;
}
