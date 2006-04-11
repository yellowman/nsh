/* $nsh: bridge.c,v 1.11 2006/04/11 12:29:01 pata Exp $ */
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
#include <stdlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
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

char *stpstates[] = {
	"disabled",
	"listening",
	"learning",
	"forwarding",
	"blocking",
};

/*
 * rather than muck up jason's nice routines too much, i create nsh
 * interface() wrappers here
 */
#define BRPORT_MEMBER 0
#define BRPORT_SPAN 1
#define BRPORT_BLOCKNONIP 2
#define BRPORT_DISCOVER 3
#define BRPORT_LEARN 4
#define BRPORT_STP 5
int
brport(char *ifname, int ifs, int argc, char **argv)
{
	int set, type, i;
	char *name;
 
	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	if (CMP_ARG(argv[0], "m")) {
		type = BRPORT_MEMBER;
		name = "member";
	} else if (CMP_ARG(argv[0], "sp")) {
		type = BRPORT_SPAN;
		name = "span";
	} else if (CMP_ARG(argv[0], "b")) {
		type = BRPORT_BLOCKNONIP;
		name = "blocknonip";
	} else if (CMP_ARG(argv[0], "d")) {
		type = BRPORT_DISCOVER;
		name = "discover";
	} else if (CMP_ARG(argv[0], "l")) {
		type = BRPORT_LEARN;
		name = "learning";
	} else if (CMP_ARG(argv[0], "st")) {
		type = BRPORT_STP;
		name = "stp";
	} else {
		printf("%% Internal error\n");
		return(1);
	}

	argv++;
	argc--;

	if (argc == 0) {
		printf("%% %s <if> [if]...\n", name);
		printf("%% no %s <if> [if]...\n", name);
		return(0);
	}

	for (i = 0; i < argc; i++) {
		if (!is_valid_ifname(argv[i]) ||
		    is_bridge(ifs, argv[i])) {
			printf("%% Invalid interface name %s\n", argv[i]);
			continue;
		}
		switch(type) {
		case BRPORT_MEMBER:
			if (set) {
				/* adding a member activates a bridge */
				set_ifflag(ifs, ifname, IFF_UP);
				bridge_add(ifs, ifname, argv[i]);
			} else
				bridge_delete(ifs, ifname, argv[i]);
			break;
		case BRPORT_SPAN:
			if (set)
				bridge_addspan(ifs, ifname, argv[i]);
			else
				bridge_delspan(ifs, ifname, argv[i]);
			break;
		case BRPORT_BLOCKNONIP:
			if (set)
				bridge_ifsetflag(ifs, ifname, argv[i],
				    IFBIF_BLOCKNONIP);
			else
				bridge_ifclrflag(ifs, ifname, argv[i],
				    IFBIF_BLOCKNONIP);
			break;
		case BRPORT_DISCOVER:
			if (set)
				bridge_ifsetflag(ifs, ifname, argv[i],
				    IFBIF_DISCOVER);
			else
				bridge_ifclrflag(ifs, ifname, argv[i],
				    IFBIF_DISCOVER);
			break;
		case BRPORT_LEARN:
			if (set)
				bridge_ifsetflag(ifs, ifname, argv[i],
				    IFBIF_LEARNING);
			else
				bridge_ifclrflag(ifs, ifname, argv[i],
				    IFBIF_LEARNING);
			break;
		case BRPORT_STP:
			if (set)
				bridge_ifsetflag(ifs, ifname, argv[i],
				    IFBIF_STP);
			else
				bridge_ifclrflag(ifs, ifname, argv[i],
				    IFBIF_STP);
			break;
		}
	}

	return(0);
}

#define BRVAL_MAXADDR 0
#define BRVAL_TIMEOUT 1
#define BRVAL_MAXAGE 2
#define BRVAL_FWDDELAY 3
#define BRVAL_HELLOTIME 4
#define BRVAL_PRIORITY 5
int
brval(char *ifname, int ifs, int argc, char **argv)
{
	int set, type;
	u_int32_t val;
	char *name;
	const char *errmsg = NULL;

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	if (CMP_ARG(argv[0], "maxad")) {
		type = BRVAL_MAXADDR;
		name = "maxaddr";
        } else if (CMP_ARG(argv[0], "t")) {
		type = BRVAL_TIMEOUT;
		name = "timeout";
	} else if (CMP_ARG(argv[0], "maxag")) {
		type = BRVAL_MAXAGE;
		name = "maxage";
	} else if (CMP_ARG(argv[0], "f")) {
		type = BRVAL_FWDDELAY;
		name = "fwddelay";
	} else if (CMP_ARG(argv[0], "h")) {
		type = BRVAL_HELLOTIME;
		name = "hellotime";
	} else if (CMP_ARG(argv[0], "p")) {
		type = BRVAL_PRIORITY;
		name = "priority";
	} else {
		printf("%% Internal error\n");
		return(1);
	}

	argv++;
	argc--;

	if ((set && argc != 1) || (!set && argc > 1)) {
		printf("%% %s <val>\n", name);
		printf("%% no %s [val]\n", name);
		return(0);
	}

	if (set) {
		errno = 0;
		val = strtonum(argv[0], 0, ULONG_MAX, &errmsg);
		if (errmsg) {
			printf("%% invalid %s argument %s: %s\n", name,
			    argv[0], errmsg);
			return(0);
		}
	}

	switch(type) {
	case BRVAL_MAXADDR:
		if (set)
			bridge_maxaddr(ifs, ifname, val);
		else
			bridge_maxaddr(ifs, ifname, DEFAULT_MAXADDR);
		break;
	case BRVAL_TIMEOUT:
		if (set)
			bridge_timeout(ifs, ifname, (int)val);
		else
			bridge_timeout(ifs, ifname, DEFAULT_TIMEOUT);
		break;
	case BRVAL_MAXAGE:
		if (val > 0xff) {
			printf("%% maxage too large\n");
			return(0);
		}
		if (set)
			bridge_maxage(ifs, ifname, val);
		else
			bridge_maxage(ifs, ifname, DEFAULT_MAXAGE);
		break;
	case BRVAL_FWDDELAY:
		if (val > 0xff) {
			printf("%% fwddelay too large\n");
			return(0);
		}
		if (set)
			bridge_fwddelay(ifs, ifname, val);
		else
			bridge_fwddelay(ifs, ifname, DEFAULT_FWDDELAY);
		break;
	case BRVAL_HELLOTIME:
		if (val > 0xff) {
			printf("%% hellotime too large\n");
			return(0);
		}
		if (set)
			bridge_hellotime(ifs, ifname, val);
		else
			bridge_hellotime(ifs, ifname, DEFAULT_HELLOTIME);
		break;
	case BRVAL_PRIORITY:
		if (val > 0xffff) {
			printf("%% priority too large\n");
			return(0);
		}
		if (set)
			bridge_priority(ifs, ifname, val);
		else
			bridge_priority(ifs, ifname, DEFAULT_PRIORITY);
		break;
	}

	return(0);
}

int
brrule(char *ifname, int ifs, int argc, char **argv)
{
	if (NO_ARG(argv[0])) {
		printf("%% all rules for a member must be applied in order\n");
		printf("%% use flush bridge-rules <bridge> <member>\n");
		printf("%% to erase all rules on interface <member>\n");
		return(0);
	}

	argv++;
	argc--;

	if (argc == 0) {
		printf("%% rule {block | pass} {in | out | in/out} on <member> [{src} mac] [{dst} mac]\n");
		return(0);
	}

	bridge_rule(ifs, ifname, argc, argv, -1);
	return(0);
}

int 
brstatic(char *ifname, int ifs, int argc, char **argv)
{
	int set;

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;
	argv++;
	argc--;

	if ((set && argc != 2) || ((!set && argc <1) || (!set && argc > 2))) {
		printf("%% static <mac address> <member>\n");
		printf("%% no static <mac address> [member]\n");
		return(0);
	}

	if (argv[1] && (!is_valid_ifname(argv[1]) || is_bridge(ifs, argv[1])))
	{
		printf("%% invalid member: %s\n", argv[1]);
		return(0);
	}

	if (set)
		bridge_addaddr(ifs, ifname, argv[1], argv[0]);
	else
		bridge_deladdr(ifs, ifname, argv[0]);

	return(0);
}

#define BRPRI_IFPRIORITY 0
#define BRPRI_IFCOST     1
int
brpri(char *ifname, int ifs, int argc, char **argv)   
{
	int set, val, type;
	char *name, *descr;
	const char *errmsg = NULL;
         
	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	if (CMP_ARG(argv[0], "ifp")) {
		type = BRPRI_IFPRIORITY;
		name = "ifpriority";
		descr = "priority";
	} else if (CMP_ARG(argv[0], "ifc")) {
		type = BRPRI_IFCOST;
		name = "ifcost";
		descr = "cost";
	} else {
		printf("%% Internal error\n");
		return(0);
	}

	argv++;
	argc--;

	/*
	 * the ifpriority value is ignored for 'no ifpriority' but
	 * we allow it anyways to retain compatibility with the 
	 * set form of this command
	 */
	if ((set && argc != 2) || (!set && (argc < 1 || argc > 2))) {
		printf("%% %s <member> <%s>\n", name, descr);
		printf("%% no %s <member> [%s]\n", name, descr);
		return(0);
	}

	if (!is_valid_ifname(argv[0]) || is_bridge(ifs, argv[0]))
	{
		printf("%% invalid member name: %s", argv[0]);
		return(0);
	}

	errno = 0;
	val = strtonum(argv[1], 0, 0xff, &errmsg);
	if (errmsg) {
		printf("%% invalid priority %s: %s\n", argv[1], errmsg);
		return (0);
        }

	switch(type) {
	case BRPRI_IFPRIORITY:
		if (set) {
			if (val > 0xff) {
				printf("%% %s exceeds limit\n",name);
				return(0);
			}
			bridge_ifprio(ifs, ifname, argv[0], val);
		} else {
			bridge_ifprio(ifs, ifname, argv[0], DEFAULT_IFPRIORITY);
		}	
	break;
	case BRPRI_IFCOST:
		if (set) {
			if (val > 65535) {
				printf("%% %s exceeds limit\n",name);
				return(0);
			}
			bridge_ifcost(ifs, ifname, argv[0], val);
		} else {
			bridge_ifcost(ifs, ifname, argv[0], DEFAULT_IFCOST);
		}
	break;
	}
	

	return(0);
}

/*
 * flush wrappers here
 */
int
flush_bridgedyn(char *brdg)
{
	int ifs;

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% socket: %s\n", strerror(errno));
		return(1);
	}

	if (!is_bridge(ifs, brdg)) {
		printf("%% %s is not a bridge\n", brdg);
		close(ifs);
		return(1);
	}

	bridge_flush(ifs, brdg);
	close(ifs);

	return(0);
}

int
flush_bridgeall(char *brdg)
{
	int ifs;

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% socket: %s\n", strerror(errno));
		return(1);
	}

	if (!is_bridge(ifs, brdg)) {
		printf("%% %s is not a bridge\n", brdg);
		close(ifs);
		return(1);
	}

	bridge_flushall(ifs, brdg);
	close(ifs);

	return(0);
}

int
flush_bridgerule(char *brdg, char *member)
{
	int ifs;

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% socket: %s\n", strerror(errno));
		return(1);
	}

	if (!is_bridge(ifs, brdg)) {
		printf("%% %s is not a bridge\n", brdg);
		close(ifs);
		return(1);
	}
	if (!is_valid_ifname(member) || is_bridge(ifs, member)) {
		printf("%% %s is not a valid interface\n", member);
		close(ifs);
		return(1);
	}
	bridge_flushrule(ifs, brdg, member);
	close(ifs);

	return(0);
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
	if (ioctl(s, SIOCBRDGGIFFLGS, (caddr_t)&req) < 0) {
		if (errno == ESRCH)
			printf("%% %s is not a member of %s\n", ifsname, brdg);
		else
			printf("%% cannot get flags for %s on %s: %s\n",
			    ifsname, brdg, strerror(errno));
		return (EX_IOERR);
	}

	req.ifbr_ifsflags |= flag;

	if (ioctl(s, SIOCBRDGSIFFLGS, (caddr_t)&req) < 0) {
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

	if (ioctl(s, SIOCBRDGGIFFLGS, (caddr_t)&req) < 0) {
		if (errno == ESRCH)
			printf("%% %s is not a member of %s\n", ifsname, brdg);
		else
			printf("%% cannot get flags for %s on %s: %s\n",
			    ifsname, brdg, strerror(errno));
		return (EX_IOERR);
	}

	req.ifbr_ifsflags &= ~flag;

	if (ioctl(s, SIOCBRDGSIFFLGS, (caddr_t)&req) < 0) {
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
	long val;

	strlcpy(ifbp.ifbrp_name, brdg, sizeof(ifbp.ifbrp_name));

	switch (type) {
	case PRIORITY:
		if (ioctl(s, SIOCBRDGGPRI, (caddr_t)&ifbp)) {
			printf("%% unable to get priority: SIOCBRDGGPRI: %s\n",
			    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_prio;
		break;

	case HELLOTIME:
		if (ioctl(s, SIOCBRDGGHT, (caddr_t)&ifbp)) {
			printf("%% unable to get hellotime: SIOCBRDGGHT: %s\n",
			    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_hellotime;
		break;

	case FWDDELAY:
		if (ioctl(s, SIOCBRDGGFD, (caddr_t)&ifbp)) {
			printf("%% unable to get fwddelay: SIOCBRDGGFD: %s\n",
			    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_fwddelay;
		break;

	case MAXAGE:
		if (ioctl(s, SIOCBRDGGMA, (caddr_t)&ifbp)) {
			printf("%% unable to get maxage: SIOCBRDGGMA: %s\n",
			    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_maxage;
		break;

	case MAXADDR:
		if (ioctl(s, SIOCBRDGGCACHE, (caddr_t)&ifbp) < 0) {
			printf("%% unable to get maxaddr: SIOCBRDGGCACHE: %s\n",
			    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_csize;
		break;

	case TIMEOUT:
		if (ioctl(s, SIOCBRDGGTO, (caddr_t)&ifbp) < 0) {
			printf("%% unable to get timeout: SIOCBRDGGTO: %s\n",
			    strerror(errno));
			return (-1);
		}
		val = ifbp.ifbrp_ctime;
		break;
	}

	return (val);
}

/*
 * hacked up bridge_list()
 *
 * conf() will ask us for a text list of interfaces filled into br_str
 *        except for ifpriority which will be filled in with "ifpriority"
 *	  as well since it returns multiple lines
 * show_int() will ask for SHOW_STPSTATE which has NULL br/str_len
 */
int
bridge_list(int s, char *brdg, char *delim, char *br_str, int str_len, int type)
{
	struct ifbreq *reqp;
	struct ifbifconf bifc;
	int i, len = 8192, identified = 0;
	char buf[256], *inbuf = NULL, *inb;

	while (1) {
		strlcpy(bifc.ifbic_name, brdg, sizeof(bifc.ifbic_name));
		bifc.ifbic_len = len;
		inb = realloc(inbuf, len);
		if (inb == NULL) {
			free(inbuf);
			printf("%% bridge_list: malloc: %s\n", strerror(errno));
			return(0);
		}
		bifc.ifbic_buf = inbuf = inb;
		if (ioctl(s, SIOCBRDGIFS, &bifc) < 0) {
			printf("%% unable to get interfaces: SIOCBRDGIFS: %s\n",
			    strerror(errno));
			free(inbuf);
			return(0);
		}
		if (bifc.ifbic_len + sizeof(*reqp) < len)
			break;
		len *= 2;
	}

	/* clear out br_str */
	br_str[0] = '\0';

	for (i = 0; i < bifc.ifbic_len / sizeof(*reqp); i++) {
		reqp = bifc.ifbic_req + i;
		switch (type) {
		case CONF_IFPRIORITY:
			if(reqp->ifbr_priority != DEFAULT_IFPRIORITY) {
			/* rework flow at some pointXXX */
				snprintf(buf, sizeof(buf),
				    "%sifpriority %s %u\n", delim,
				    reqp->ifbr_ifsname, reqp->ifbr_priority);
				strlcat(br_str, buf, str_len);
				identified++;
			}
			break;
		case CONF_IFCOST:
			if(reqp->ifbr_path_cost != DEFAULT_IFCOST) {
			/* rework flow at some pointXXX */
				snprintf(buf, sizeof(buf),
				    "%sifcost %s %u\n", delim,
				    reqp->ifbr_ifsname, reqp->ifbr_path_cost);
				strlcat(br_str, buf, str_len);
				identified++;
			}
			break;
		case SHOW_STPSTATE:
			if (reqp->ifbr_ifsflags & IFBIF_STP) {
				snprintf(buf, sizeof(buf),
				    "%s%s: %s\n", delim, reqp->ifbr_ifsname,
				    stpstates[reqp->ifbr_state]);
				strlcat(br_str, buf, str_len);
				identified++;
			}
			break;
		case MEMBER:
			if (reqp->ifbr_ifsname) {
				snprintf(buf, sizeof(buf), "%s ",
				    reqp->ifbr_ifsname);
				strlcat(br_str, buf, str_len);
				identified++;
			}
			break;
		case NOLEARNING:
			if (!(reqp->ifbr_ifsflags & IFBIF_LEARNING) &&
			    !(reqp->ifbr_ifsflags & IFBIF_SPAN)) {
				snprintf(buf, sizeof(buf), "%s ",
				    reqp->ifbr_ifsname);
				strlcat(br_str, buf, str_len);
				identified++;
			}
			break;
		case NODISCOVER:
			if (!(reqp->ifbr_ifsflags & IFBIF_DISCOVER) &&
			    !(reqp->ifbr_ifsflags & IFBIF_SPAN)) {
				snprintf(buf, sizeof(buf), "%s ",
				    reqp->ifbr_ifsname);
				strlcat(br_str, buf, str_len);
				identified++;
			}
			break;
		case BLOCKNONIP:
			if (reqp->ifbr_ifsflags & IFBIF_BLOCKNONIP) {
				snprintf(buf, sizeof(buf), "%s ",
				    reqp->ifbr_ifsname);
				strlcat(br_str, buf, str_len);
				identified++;
			}
			break;
		case STP:
			if (reqp->ifbr_ifsflags & IFBIF_STP) {
				snprintf(buf, sizeof(buf), "%s ",
				    reqp->ifbr_ifsname);
				strlcat(br_str, buf, str_len);
				identified++;
			}
			break;
		case SPAN:
			if (reqp->ifbr_ifsflags & IFBIF_SPAN) {
				snprintf(buf, sizeof(buf), "%s ",
				    reqp->ifbr_ifsname);
				strlcat(br_str, buf, str_len);
				identified++;
			}
			break;
		}
	}
	free(bifc.ifbic_buf);
	return (identified);
}

int
bridge_add(int s, char *brdg, char *ifn)
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	if (ioctl(s, SIOCBRDGADD, &req) < 0) {
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
	if (ioctl(s, SIOCBRDGDEL, &req) < 0) {
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
	if (ioctl(s, SIOCBRDGADDS, &req) < 0) {
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
	if (ioctl(s, SIOCBRDGDELS, &req) < 0) {
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
	if (ioctl(s, SIOCBRDGSTO, (caddr_t)&bp) < 0) {
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
	if (ioctl(s, SIOCBRDGSMA, (caddr_t)&bp) < 0) {
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
	if (ioctl(s, SIOCBRDGSPRI, (caddr_t)&bp) < 0) {
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
	if (ioctl(s, SIOCBRDGSFD, (caddr_t)&bp) < 0) {
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
	if (ioctl(s, SIOCBRDGSHT, (caddr_t)&bp) < 0) {
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
	if (ioctl(s, SIOCBRDGSCACHE, (caddr_t)&bp) < 0) {
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

	if (ioctl(s, SIOCBRDGDADDR, &ifba) < 0) {
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

	if (ioctl(s, SIOCBRDGSIFPRIO, (caddr_t)&breq) < 0) {
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

	if (ioctl(s, SIOCBRDGSIFCOST, (caddr_t)&breq) < 0) {
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

	if (ioctl(s, SIOCBRDGSADDR, &ifba) < 0) {
		char tmp[128];

		snprintf(tmp, sizeof(tmp), "%% unable to add %s to %s: %s\n",
		    addr, brdg, strerror(errno));
		printf("%s", tmp);
		return (EX_IOERR);
	}

	return (0);
}

int
bridge_addrs(int s, char *brdg, char *hdr_delim, char *body_delim)
{
	struct ifbaconf ifbac;
	struct ifbareq *ifba;
	char buf[sizeof(ifba->ifba_ifsname) + 1], *inbuf = NULL, *inb;
	int i, len = 8192;

	while (1) {
		ifbac.ifbac_len = len;
		inb = realloc(inbuf, len);
		if (inb == NULL) {
			free(inbuf);
			printf("%% bridge_addrs: malloc: %s\n",
			    strerror(errno));
			return(0);
		}
		ifbac.ifbac_buf = inbuf = inb;
		strlcpy(ifbac.ifbac_name, brdg, sizeof(ifbac.ifbac_name));
		if (ioctl(s, SIOCBRDGRTS, &ifbac) < 0) {
			if (errno != ENETDOWN)
				printf("%% bridge_addrs: SIOCBRDGRTS: %s\n",
				    strerror(errno));
			free(inbuf);
			return(0);
		}
		if (ifbac.ifbac_len + sizeof(*ifba) < len)
			break;
		len *= 2;
	}
	if (ifbac.ifbac_len / sizeof(*ifba)) {
		printf("%sLearned addresses:\n", hdr_delim);
		printf("%saddress           member age\n", body_delim);
	}

	for (i = 0; i < ifbac.ifbac_len / sizeof(*ifba); i++) {
		ifba = ifbac.ifbac_req + i;
		strlcpy(buf, ifba->ifba_ifsname, sizeof(buf));
		printf("%s%s %-6s %u ", body_delim, ether_ntoa(&ifba->ifba_dst),
		    buf, ifba->ifba_age);
		bprintf(stdout, ifba->ifba_flags, IFBAFBITS);
		printf("\n");
	}
	free(inbuf);
	return (0);
}

int
bridge_confaddrs(int s, char *brdg, char *delim, FILE *output)
{
	struct ifbaconf ifbac;
	struct ifbareq *ifba;
	char buf[sizeof(ifba->ifba_ifsname) + 1], *inbuf = NULL, *inb;
	int i, len = 8192;

	while (1) {
		ifbac.ifbac_len = len;
		inb = realloc(inbuf, len);
		if (inb == NULL) {
			free(inbuf);
			printf("%% bridge_confaddrs: malloc: %s\n",
				strerror(errno));
			return(0);
		}
		ifbac.ifbac_buf = inbuf = inb;
		strlcpy(ifbac.ifbac_name, brdg, sizeof(ifbac.ifbac_name));
		if (ioctl(s, SIOCBRDGRTS, &ifbac) < 0) {
			if (errno != ENETDOWN)
				printf("%% bridge_confaddrs: SIOCBRDGRTS: %s\n",
				    strerror(errno));
			free(inbuf);
			return(0);
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

	strlcpy(ifr.ifr_name, brdg, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0)
		return (0);

	ifbac.ifbac_len = 0;
	strlcpy(ifbac.ifbac_name, brdg, sizeof(ifbac.ifbac_name));
	if (ioctl(s, SIOCBRDGRTS, (caddr_t)&ifbac) < 0) {
		if (errno == ENETDOWN)
			return (1);
		return (0);
	}
	return (1);
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
	int len = 8192, i;

	while (1) {
		ifc.ifbrl_len = len;
		inb = realloc(inbuf, len);
		if (inb == NULL) {
			free(inbuf);
			printf("%% bridge_rules: malloc: %s\n",
			    strerror(errno));
			return(0);
		}
		ifc.ifbrl_buf = inbuf = inb;
		strlcpy(ifc.ifbrl_name, brdg, sizeof(ifc.ifbrl_name));
		strlcpy(ifc.ifbrl_ifsname, ifname, sizeof(ifc.ifbrl_ifsname));
		errno = 0;
		if (ioctl(s, SIOCBRDGGRL, &ifc) < 0) {
			if (errno != ESRCH) /* invalid interface name spec'd */
				printf("%% bridge_rules: SIOCBRDGGRL: %s\n",
				    strerror(errno));
			free(inbuf);
			return(0);
		}
		if (ifc.ifbrl_len + sizeof(ifreq) < len)
			break;
		len *= 2;
	}
	ifrp = ifc.ifbrl_req;
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
	if (argc == 0 || !is_valid_ifname(argv[0]))
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
			    PF_TAG_NAME_SIZE) > PF_TAG_NAME_SIZE) {
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
				return (0);
			}
			bcopy(ea, dea, sizeof(*dea));
 		}
		argc--; argv++;
		sec++;
	}

	if (ioctl(s, SIOCBRDGARL, &rule) < 0) {
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
