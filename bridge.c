/* From: $OpenBSD: /usr/src/sbin/brconfig/brconfig.c,v 1.17 2002/02/16 21:27:33 millert Exp $	*/

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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Jason L. Wright
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
#include <sys/errno.h>
#include <string.h>
#include <err.h>
#include <sysexits.h>
#include <stdlib.h>
#include <limits.h>
#include "externs.h"
#include "bridge.h"

int set_ifflag(int, char *, short);
int clr_ifflag(int, char *, short);
int bridge_ifsetflag(int, char *, char *, u_int32_t);
int bridge_ifclrflag(int, char *, char *, u_int32_t);
int bridge_list(int, char *, char *, char *, int, int);
long bridge_cfg(int, char *, int);
int bridge_addrs(int, char *, char *, char *);
int bridge_addaddr(int, char *, char *, char *);
int bridge_deladdr(int, char *, char *);
int bridge_maxaddr(int, char *, u_int32_t);
int bridge_maxage(int, char *, u_int32_t);
int bridge_priority(int, char *, u_int32_t);
int bridge_fwddelay(int, char *, u_int32_t);
int bridge_hellotime(int, char *, u_int32_t);
int bridge_ifprio(int, char *, char *, int);
int bridge_timeout(int, char *, u_int32_t);
int bridge_flush(int, char *);
int bridge_flushall(int, char *);
int bridge_add(int, char *, char *);
int bridge_delete(int, char *, char *);
int bridge_addspan(int, char *, char *);
int bridge_delspan(int, char *, char *);
int is_bridge(int, char *);
int bridge_rule(int, char *, int, char **, int);
int bridge_rules(int, char *, char *, char *, FILE *);
int bridge_flushrule(int, char *, char *);
void bridge_badrule(int, char **, int, short);
void bridge_showrule(struct ifbrlreq *, char *, FILE *);
int bridge_confaddrs(int, char *, char *, FILE *);

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
		name = "learn";
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
	int set, type, i;
	u_int32_t val;
	char *name, *endptr;

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
		val = strtoul(argv[0], &endptr, 0);
		if (argv[0][0] == '\0' || endptr[0] != '\0' ||
		    (errno == ERANGE && val == ULONG_MAX)) {
			printf("%% invalid %s argument: %s\n", name,
			    argv[0]);
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
			bridge_timeout(ifs, ifname, val);
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

	/*
	 * really, in the second example, the member is not necessary,
	 * but in order to retain the cisco-like 'no' <cmd>, we require it
	 */
	if (argc != 2) {
		printf("%% static <member> <mac address>\n");
		printf("%% no static <member> <mac address>\n");
		return(0);
	}

	if (!is_valid_ifname(argv[0]) || is_bridge(ifs, argv[0]))
	{
		printf("%% invalid member: %s\n", argv[0]);
		return(0);
	}

	if (set)
		bridge_addaddr(ifs, ifname, argv[0], argv[1]);
	else
		bridge_deladdr(ifs, ifname, argv[1]);

	return(0);
}

int
brpri(char *ifname, int ifs, int argc, char **argv)   
{
	int set, val;
	char *endptr;
         
	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;
	argv++;
	argc--;

	/*
	 * the ifpriority value is ignored for 'no ifpriority' but
	 * we allow it anyways to retain compatibility with the 
	 * set form of this command
	 */
	if ((set && argc != 2) || (!set && (argc < 1 || argc > 2))) {
		printf("%% ifpriority <member> <priority>\n");
		printf("%% no ifpriority <member> [priority]\n");
		return(0);
	}

	if (!is_valid_ifname(argv[0]) || is_bridge(ifs, argv[0]))
	{
		printf("%% invalid member name: %s", argv[0]);
		return(0);
	}

	errno = 0;
	val = strtoul(argv[1], &endptr, 0);
	if (argv[0][0] == '\0' || endptr[0] != '\0' ||
	    (errno == ERANGE && val == ULONG_MAX) || (val > 0xff)) {
		printf("%% invalid priority: %s\n", argv[1]);
		return (0);
        }

	if (set)
		bridge_ifprio(ifs, ifname, argv[0], val);
	else
		bridge_ifprio(ifs, ifname, argv[0], DEFAULT_IFPRIORITY);

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
		perror("% socket");
		return(0);
	}

	if (!is_bridge(ifs, brdg)) {
		printf("%% %s is not a bridge\n", brdg);
		close(ifs);
		return(0);
	}

	bridge_flush(ifs, brdg);
	close(ifs);

	return(1);
}

int
flush_bridgeall(char *brdg)
{
	int ifs;

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		perror("% socket");
		return(0);
	}

	if (!is_bridge(ifs, brdg)) {
		printf("%% %s is not a bridge\n", brdg);
		close(ifs);
		return(0);
	}

	bridge_flushall(ifs, brdg);
	close(ifs);

	return(1);
}

int
flush_bridgerule(char *brdg, char *member)
{
	int ifs;

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		perror("% socket");
		return(0);
	}

	if (!is_bridge(ifs, brdg)) {
		printf("%% %s is not a bridge\n", brdg);
		close(ifs);
		return(0);
	}
	if (!is_valid_ifname(member) || is_bridge(ifs, member)) {
		printf("%% %s is not a valid interface\n", member);
		close(ifs);
		return(0);
	}
	bridge_flushrule(ifs, brdg, member);
	close(ifs);

	return(1);
}

/*
 * most of the following resembles the original brconfig.c
 */

int
bridge_ifsetflag(s, brdg, ifsname, flag)
	int s;
	char *brdg;
	char *ifsname;
	u_int32_t flag;
{
	char tmp[128];
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifsname, sizeof(req.ifbr_ifsname));
	if (ioctl(s, SIOCBRDGGIFFLGS, (caddr_t)&req) < 0) {
		snprintf(tmp, sizeof(tmp), "%% cannot get flags for %s on %s",
		    ifsname, brdg);
		perror(tmp);
		return (EX_IOERR);
	}

	req.ifbr_ifsflags |= flag;

	if (ioctl(s, SIOCBRDGSIFFLGS, (caddr_t)&req) < 0) {
		snprintf(tmp, sizeof(tmp), "%% cannot set flags for %s on %s",
		    ifsname, brdg);
		perror(tmp);
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_ifclrflag(s, brdg, ifsname, flag)
	int s;
	char *brdg;
	char *ifsname;
	u_int32_t flag;
{
	char tmp[128];
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifsname, sizeof(req.ifbr_ifsname));

	if (ioctl(s, SIOCBRDGGIFFLGS, (caddr_t)&req) < 0) {
		snprintf(tmp, sizeof(tmp), "%% cannot get flags for %s on %s",
		    ifsname, brdg);
		perror(tmp);
		return (EX_IOERR);
	}

	req.ifbr_ifsflags &= ~flag;

	if (ioctl(s, SIOCBRDGSIFFLGS, (caddr_t)&req) < 0) {
		snprintf(tmp, sizeof(tmp), "%% cannot set flags for %s on %s",
		    ifsname, brdg);
		perror(tmp);
		return (EX_IOERR);
	}
	return (0);
}

/*
 * like set_ifflags but only sets one flag
 */
int
set_ifflag(s, brdg, f)
	int s;
	char *brdg;
	short f;
{
	struct ifreq ifr;
	char tmp[128];

	strlcpy(ifr.ifr_name, brdg, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		snprintf(tmp, sizeof(tmp), "%% cannot get flags for %s", brdg);
		perror(tmp);
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}

	ifr.ifr_flags |= f;

	if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
		snprintf(tmp, sizeof(tmp), "%% cannot set flags for %s", brdg);
		perror(tmp);
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}

	return (0);
}

int
clr_ifflag(s, brdg, f)
	int s;
	char *brdg;
	short f;
{
	struct ifreq ifr;
	char tmp[128];

	strlcpy(ifr.ifr_name, brdg, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		snprintf(tmp, sizeof(tmp), "%% cannot get flags for %s", brdg);
		perror(tmp);
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}

	ifr.ifr_flags &= ~(f);

	if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
		snprintf(tmp, sizeof(tmp), "%% cannot set flags for %s", brdg);
		perror(tmp);
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}

	return (0);
}

int
bridge_flushall(s, brdg)
	int s;
	char *brdg;
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	req.ifbr_ifsflags = IFBF_FLUSHALL;
	if (ioctl(s, SIOCBRDGFLUSH, &req) < 0) {
		perror("% cannot flush all: SIOCBRDGFLUSH");
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_flush(s, brdg)
	int s;
	char *brdg;
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	req.ifbr_ifsflags = IFBF_FLUSHDYN;
	if (ioctl(s, SIOCBRDGFLUSH, &req) < 0) {
		perror("% cannot flush: SIOCBRDGFLUSH");
		return (EX_IOERR);
	}
	return (0);
}

long
bridge_cfg(s, brdg, type)
	int s;
	char *brdg;
	int type;
{
	struct ifbrparam ifbp;
	long val;

	strlcpy(ifbp.ifbrp_name, brdg, sizeof(ifbp.ifbrp_name));

	switch (type) {
	case PRIORITY:
		if (ioctl(s, SIOCBRDGGPRI, (caddr_t)&ifbp)) {
			perror("% unable to get priority: SIOCBRDGGPRI");
			return (-1);
		}
		val = ifbp.ifbrp_prio;
		break;

	case HELLOTIME:
		if (ioctl(s, SIOCBRDGGHT, (caddr_t)&ifbp)) {
			perror("% unable to get hellotime: SIOCBRDGGHT");
			return (-1);
		}
		val = ifbp.ifbrp_hellotime;
		break;

	case FWDDELAY:
		if (ioctl(s, SIOCBRDGGFD, (caddr_t)&ifbp)) {
			perror("% unable to get fwddelay: SIOCBRDGGFD");
			return (-1);
		}
		val = ifbp.ifbrp_fwddelay;
		break;

	case MAXAGE:
		if (ioctl(s, SIOCBRDGGFD, (caddr_t)&ifbp)) {
			perror("% unable to get maxage: SIOCBRDGGFD");
			return (-1);
		}
		val = ifbp.ifbrp_maxage;
		break;

	case MAXADDR:
		if (ioctl(s, SIOCBRDGGCACHE, (caddr_t)&ifbp) < 0) {
			perror("% unable to get maxaddr: SIOCBRDGGCACHE");
			return (-1);
		}
		val = ifbp.ifbrp_csize;
		break;

	case TIMEOUT:
		if (ioctl(s, SIOCBRDGGTO, (caddr_t)&ifbp) < 0) {
			perror("% unable to get timeout: SIOCBRDGGTO");
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
bridge_list(s, brdg, delim, br_str, str_len, type)
	int s, type, str_len;
	char *brdg, *delim, *br_str;
{
	struct ifbreq *reqp;
	struct ifbifconf bifc;
	int i, len = 8192, identified = 0;
	char buf[256], *inbuf = NULL;

	while (1) {
		strlcpy(bifc.ifbic_name, brdg, sizeof(bifc.ifbic_name));
		bifc.ifbic_len = len;
		bifc.ifbic_buf = inbuf = realloc(inbuf, len);
		if (inbuf == NULL) {
			perror("% bridge_list: malloc");
			return(0);
		}
		if (ioctl(s, SIOCBRDGIFS, &bifc) < 0) {
			perror("% unable to get interfaces: SIOCBRDGIFS");
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
			/* conf() should test for DEFAULT_IFPRIORITY XXX */
				snprintf(buf, sizeof(buf),
				    "%sifpriority %s %u\n", delim,
				    reqp->ifbr_ifsname, reqp->ifbr_priority);
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
			if (reqp->ifbr_ifsflags ^ IFBIF_LEARNING &&
			    reqp->ifbr_ifsflags ^ IFBIF_SPAN) {
				snprintf(buf, sizeof(buf), "%s ",
				    reqp->ifbr_ifsname);
				strlcat(br_str, buf, str_len);
				identified++;
			}
			break;
		case NODISCOVER:
			if (reqp->ifbr_ifsflags ^ IFBIF_DISCOVER &&
			    reqp->ifbr_ifsflags ^ IFBIF_SPAN) {
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
bridge_add(s, brdg, ifn)
	int s;
	char *brdg;
	char *ifn;
{
	struct ifbreq req;
	char tmp[128];

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	if (ioctl(s, SIOCBRDGADD, &req) < 0) {
		snprintf(tmp, sizeof(tmp), "%% cannot add member %s on %s",
		    ifn, brdg);
		perror(tmp);
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_delete(s, brdg, ifn)
	int s;
	char *brdg;
	char *ifn;
{
	struct ifbreq req;

	strlcpy(req.ifbr_name, (char *)brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	if (ioctl(s, SIOCBRDGDEL, &req) < 0) {
		perror("% unable to delete member: SIOCBRDGDEL");
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_addspan(s, brdg, ifn)
	int s;
	char *brdg;
	char *ifn;
{
	struct ifbreq req;
	char tmp[128];

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	if (ioctl(s, SIOCBRDGADDS, &req) < 0) {
		snprintf(tmp, sizeof(tmp), "%% cannot add span %s on %s",
		    ifn, brdg);
		perror(tmp);
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_delspan(s, brdg, ifn)
	int s;
	char *brdg;
	char *ifn;
{
	struct ifbreq req;
	char tmp[128];

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	if (ioctl(s, SIOCBRDGDELS, &req) < 0) {
		snprintf(tmp, sizeof(tmp), "%% cannot delete span %s on %s",
		    ifn, brdg);
		perror(tmp);
		if (errno == EPERM)
			return (EX_NOPERM);
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_timeout(s, brdg, val)
	int s;
	char *brdg;
	u_int32_t val;
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_ctime = val;
	if (ioctl(s, SIOCBRDGSTO, (caddr_t)&bp) < 0) {
		perror("% bridge_timeout: SIOCBRDGSTO");
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_maxage(s, brdg, val)
	int s;
	char *brdg;
	u_int32_t val;
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_maxage = val;
	if (ioctl(s, SIOCBRDGSMA, (caddr_t)&bp) < 0) {
		perror("% unable to set maxage: SIOCBRDGSMA");
		return (EX_IOERR);
	}
	return (0);
	
}

int
bridge_priority(s, brdg, val)
	int s;
	char *brdg;
	u_int32_t val;
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_prio = val;
	if (ioctl(s, SIOCBRDGSPRI, (caddr_t)&bp) < 0) {
		perror("% unable to set priority: SIOCBRDGSPRI");
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_fwddelay(s, brdg, val)
	int s;
	char *brdg;
	u_int32_t val;
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_fwddelay = val;
	if (ioctl(s, SIOCBRDGSFD, (caddr_t)&bp) < 0) {
		perror("% unable to set fwddelay: SIOCBRDGSFD");
		return (EX_IOERR);
	}
	return (0);
	
}

int
bridge_hellotime(s, brdg, val)
	int s;
	char *brdg;
	u_int32_t val;
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_hellotime = val;
	if (ioctl(s, SIOCBRDGSHT, (caddr_t)&bp) < 0) {
		perror("% unable to set hellotime: SIOCBRDGSHT");
		return (EX_IOERR);
	}
	return (0);
	
}

int
bridge_maxaddr(s, brdg, val)
	int s;
	char *brdg;
	u_int32_t val;
{
	struct ifbrparam bp;

	strlcpy(bp.ifbrp_name, brdg, sizeof(bp.ifbrp_name));
	bp.ifbrp_csize = val;
	if (ioctl(s, SIOCBRDGSCACHE, (caddr_t)&bp) < 0) {
		perror("% unable to set maxaddr: SIOCBRDGSCACHE");
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_deladdr(s, brdg, addr)
	int s;
	char *brdg;
	char *addr;
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
bridge_ifprio(s, brdg, ifname, val)
	int s;
	char *brdg;
	char *ifname;
	int val;
{
	struct ifbreq breq;

	strlcpy(breq.ifbr_name, brdg, sizeof(breq.ifbr_name));
	strlcpy(breq.ifbr_ifsname, ifname, sizeof(breq.ifbr_ifsname));

	breq.ifbr_priority = val;

	if (ioctl(s, SIOCBRDGSIFPRIO, (caddr_t)&breq) < 0) {
		perror("% bridge_ifprio: SIOCBRDGSIFPRIO");
		return (EX_IOERR);
	}
	return (0);
}

int
bridge_addaddr(s, brdg, ifname, addr)
	int s;
	char *brdg;
	char *ifname, *addr;
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

		snprintf(tmp, sizeof(tmp), "%% unable to add %s to %s\n",
		    addr, brdg);
		perror(tmp);
		return (EX_IOERR);
	}

	return (0);
}

int
bridge_addrs(s, brdg, hdr_delim, body_delim)
	int s;
	char *brdg, *hdr_delim, *body_delim;
{
	struct ifbaconf ifbac;
	struct ifbareq *ifba;
	char *inbuf = NULL, buf[sizeof(ifba->ifba_ifsname) + 1];
	int i, len = 8192;

	while (1) {
		ifbac.ifbac_len = len;
		ifbac.ifbac_buf = inbuf = realloc(inbuf, len);
		strlcpy(ifbac.ifbac_name, brdg, sizeof(ifbac.ifbac_name));
		if (inbuf == NULL) {
			perror("% bridge_addrs: malloc");
			return(0);
		}
		if (ioctl(s, SIOCBRDGRTS, &ifbac) < 0) {
			if (errno != ENETDOWN)
				perror("% bridge_addrs: SIOCBRDGRTS");
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
bridge_confaddrs(s, brdg, delim, output)
	int s;
	char *brdg, *delim;
	FILE *output;
{
	struct ifbaconf ifbac;
	struct ifbareq *ifba;
	char *inbuf = NULL, buf[sizeof(ifba->ifba_ifsname) + 1];
	int i, len = 8192;

	while (1) {
		ifbac.ifbac_len = len;
		ifbac.ifbac_buf = inbuf = realloc(inbuf, len);
		strlcpy(ifbac.ifbac_name, brdg, sizeof(ifbac.ifbac_name));
		if (inbuf == NULL)
			perror("% bridge_confaddrs: malloc");
		if (ioctl(s, SIOCBRDGRTS, &ifbac) < 0) {
			if (errno != ENETDOWN)
				perror("% bridge_confaddrs: SIOCBRDGRTS");
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
			    buf, ether_ntoa(&ifba->ifba_dst));
	}
	free(inbuf);
	return (0);
}

/*
 * Check to make sure 'brdg' is really a bridge interface.
 */
int
is_bridge(s, brdg)
	int s;
	char *brdg;
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
bridge_flushrule(s, brdg, ifname)
	int s;
	char *brdg, *ifname;
{
	char tmp[128];
	struct ifbrlreq req;

	strlcpy(req.ifbr_name, brdg, sizeof(req.ifbr_name));
	strlcpy(req.ifbr_ifsname, ifname, sizeof(req.ifbr_ifsname));
	if (ioctl(s, SIOCBRDGFRL, &req) < 0) {
		snprintf(tmp, sizeof(tmp), "%% unable to flush rules for %s",
		    ifname);
		perror(tmp);
		return (EX_USAGE);
	}
	return (0);
}

int
bridge_rules(s, brdg, ifname, delim, output)
	int s;
	char *brdg;
	char *delim, *ifname;
	FILE *output;
{
	char *inbuf = NULL;
	struct ifbrlconf ifc;
	struct ifbrlreq *ifrp, ifreq;
	int len = 8192, i;

	while (1) {
		ifc.ifbrl_len = len;
		ifc.ifbrl_buf = inbuf = realloc(inbuf, len);
		strlcpy(ifc.ifbrl_name, brdg, sizeof(ifc.ifbrl_name));
		strlcpy(ifc.ifbrl_ifsname, ifname, sizeof(ifc.ifbrl_ifsname));
		if (inbuf == NULL) {
			perror("% bridge_rules: malloc");
			return(0);
		}
		errno = 0;
		if (ioctl(s, SIOCBRDGGRL, &ifc) < 0) {
			if (errno != ESRCH) /* invalid interface name spec'd */
				perror("% bridge_rules: SIOCBRDGGRL");
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
bridge_showrule(r, delim, output)
	struct ifbrlreq *r;
	char *delim;
	FILE *output;
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
		} else
			goto bad_rule;

		argc--; argv++;
		sec++;

		if (argc == 0)
			goto bad_rule;
		ea = ether_aton(argv[0]);
		if (ea == NULL) {
			printf("%% Invalid address: %s\n", argv[0]);
			return (EX_USAGE);
		}
		bcopy(ea, dea, sizeof(*dea));
		argc--; argv++;
		sec++;
	}

	if (ioctl(s, SIOCBRDGARL, &rule) < 0) {
		perror("% unable to add rule: SIOCBRDGARL");
		return (EX_IOERR);
	}
	return (0);

bad_rule:
	bridge_badrule(targc, targv, ln, sec);
	return (EX_USAGE);
}

#define MAXRULEWORDS 8

void
bridge_badrule(argc, argv, ln, sec)
	int argc, ln;
	short sec;
	char **argv;
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
