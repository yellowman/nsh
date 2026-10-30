/* From: $OpenBSD: ifconfig.c,v 1.174 2006/08/29 17:22:00 henning Exp $  */
/*
 * Copyright (c) 2006
 *      Manuel Pata.  All rights reserved.
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
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/limits.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/if_ether.h>
#include <net/if_trunk.h>
#include "externs.h"
#include "settings.h"
#include "facts.h"
#include "showfacts.h"

static struct trunk_protos tpr[] = TRUNK_PROTOS;

static int in_list(char *, char *);
static int cand_trunkport(char *, int, int, char **);
static int cand_trunkproto(char *, int);

/* Is word among the values of line, after its name? */
static int
in_list(char *line, char *word)
{
	char buf[1024], *w, *p;

	if (line == NULL)
		return 0;
	strlcpy(buf, line, sizeof(buf));
	strtok_r(buf, " ", &p);
	while ((w = strtok_r(NULL, " ", &p)) != NULL)
		if (strcmp(w, word) == 0)
			return 1;
	return 0;
}

/*
 * trunkport in configure private: the ports trunk_port_create() and
 * aggr_add_port() would refuse are refused, with inttrunkport()'s
 * messages, before any is added
 */
static int
cand_trunkport(char *ifname, int set, int argc, char **argv)
{
	char ports[1024], *l, *w, *p;
	int i, n = 0, aggr = strncmp(ifname, "aggr", strlen("aggr")) == 0;

	if (!cand_takes(ifname, SIOCSTRUNKPORT)) {
		printf("%% %s not trunk\n", ifname);
		return -1;
	}
	if ((l = cand_line("trunkport", 0)) != NULL) {
		strlcpy(ports, l, sizeof(ports));
		strtok_r(ports, " ", &p);
		while ((w = strtok_r(NULL, " ", &p)) != NULL)
			n++;
	}
	for (i = 0; i < argc; i++) {
		if (!set) {
			if (!in_list(cand_line("trunkport", 0), argv[i])) {
				printf("%% Port %s not part of %s\n", argv[i],
				    ifname);
				return -1;
			}
			continue;
		}
		if (!cand_hasif(argv[i]) || strcmp(argv[i], ifname) == 0) {
			printf("%% inttrunkport: SIOCSTRUNKPORT: %s\n",
			    strerror(EINVAL));
			return -1;
		}
		if (cand_gettype(argv[i]) != IFT_ETHER) {
			printf("%% inttrunkport: SIOCSTRUNKPORT: %s\n",
			    strerror(EPROTONOSUPPORT));
			return -1;
		}
		/* a port of any trunk, and for aggr of a bridge (EBUSY) */
		if (in_list(cand_line("trunkport", 0), argv[i]) ||
		    cand_listowner(ifname, "trunkport", argv[i]) != NULL ||
		    (aggr && cand_listowner(ifname, "member", argv[i]))) {
			printf("%% Failed (port %s already assigned to a trunk"
			    " group)\n", argv[i]);
			return -1;
		}
		if (++n > TRUNK_MAX_PORTS) {
			printf("%% inttrunkport: SIOCSTRUNKPORT: %s\n",
			    strerror(ENOSPC));
			return -1;
		}
	}
	argvtostring(argc, argv, ports, sizeof(ports));
	return cand_setting(set ? ST_ON : ST_OFF, "trunkport %s", ports);
}

/*
 * trunkproto in configure private. aggr takes only lacp
 * (EPROTONOSUPPORT), and conf_trunk() prints any other than the default.
 */
static int
cand_trunkproto(char *ifname, int proto)
{
	int i;

	if (!cand_takes(ifname, SIOCSTRUNK)) {
		printf("%% %s not trunk\n", ifname);
		return -1;
	}
	if (strncmp(ifname, "aggr", strlen("aggr")) == 0 &&
	    proto != TRUNK_PROTO_LACP) {
		printf("%% inttrunkproto: SIOCSTRUNK: %s\n",
		    strerror(EPROTONOSUPPORT));
		return -1;
	}
	if (proto == TRUNK_PROTO_DEFAULT)
		return cand_setting(ST_DEFAULT, "trunkproto");
	for (i = 0; tpr[i].tpr_proto != proto; i++)
		;
	return cand_setting(ST_ON, "trunkproto %s", tpr[i].tpr_name);
}

int
inttrunkport(int argc, char **argv, ...)
{
	struct trunk_reqport rp;
	int set, i, r = 0;
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

	if ((!set && argc < 1) || (set && argc < 1)) {
		printf("%% trunkport <ifname> [ifname ...]\n");
		printf("%% no trunkport <ifname> [ifname ...]\n");
		return -1;
	}

	if (candidate)
		return cand_trunkport(ifname, set, argc, argv);

	bzero(&rp, sizeof(rp));
	strlcpy(rp.rp_ifname, ifname, sizeof(rp.rp_ifname));

	for (i = 0; i < argc; i++) {
		if (set) {
			strlcpy(rp.rp_portname, argv[i],
			    sizeof(rp.rp_portname));
			if (ioctl(ifs, SIOCSTRUNKPORT, &rp) < 0) {
				switch(errno) {
				case ENOTTY:
					printf("%% %s not trunk\n",ifname);
					break;
				case EBUSY:
					printf("%% Failed (port %s already"
					    " assigned to a trunk group)\n",
					    argv[i]);
					break;
				case ENETDOWN:
					printf("%% Failed (port %s is "
					    "shutdown)\n", argv[i]);
					break;
				default:
					printf("%% inttrunkport:"
					    " SIOCSTRUNKPORT: %s\n",
				    strerror(errno));
				}
				r = -1;
			}
		} else {
			strlcpy(rp.rp_portname, argv[i],
			    sizeof(rp.rp_portname));
			if (ioctl(ifs, SIOCSTRUNKDELPORT, &rp) < 0) {
				switch(errno) {
				case ENOTTY:
					printf("%% %s not trunk\n",ifname);
					break;
				case ENOENT:
					printf("%% Port %s not part of %s\n",
					    argv[i], ifname);
					break;
				default:
					printf("%% inttrunkport:"
					    " SIOCSTRUNKDELPORT: %s\n",
				    strerror(errno));
				}
				return -1;
			}
		}
	}
	return r;
}

int
inttrunkproto(int argc, char **argv, ...)
{
	int i, set;
	struct trunk_reqall ra;
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
                printf("%% trunkproto <proto>\n");
                printf("%% no trunkproto\n");
		return -1;
        }

	bzero(&ra, sizeof(ra));
	strlcpy(ra.ra_ifname, ifname, sizeof(ra.ra_ifname));

	if (set) {
		for (i = 0; i < TRUNK_PROTO_MAX; ++i) {
			if (isprefix(argv[0], (char *)tpr[i].tpr_name)) {
				ra.ra_proto = tpr[i].tpr_proto;
				break;
			}
		}
		if (i == TRUNK_PROTO_MAX) {
			printf("%% trunkproto <");
			for (i = 0; i < TRUNK_PROTO_MAX; ++i)
				printf("%s%s", i == 0 ? "" : "|", tpr[i].tpr_name);
			printf(">\n");
			return -1;
		}
	} else
		ra.ra_proto = TRUNK_PROTO_DEFAULT;

	if (candidate)
		return cand_trunkproto(ifname, ra.ra_proto);

	if (ioctl(ifs, SIOCSTRUNK, &ra) != 0) {
		switch(errno) {
		case ENOTTY:
			printf("%% %s not trunk\n", ifname);
			break;
		default:
			printf("%% inttrunkproto: SIOCSTRUNK: %s\n", strerror(errno));
		}
		return -1;
	}

	return 0;
}

int
conf_trunk(FILE *output, int ifs, char *ifname)
{
	struct trunk_reqport rpbuf[TRUNK_MAX_PORTS];
        struct trunk_reqall ra;
        int i;

        bzero(&ra, sizeof(ra));
	for (i = 0; i < TRUNK_MAX_PORTS; i++)
		bzero(&rpbuf[i], sizeof(struct trunk_reqport));

        strlcpy(ra.ra_ifname, ifname, sizeof(ra.ra_ifname));
        ra.ra_size = sizeof(rpbuf);
	ra.ra_port = rpbuf;

        if (ioctl(ifs, SIOCGTRUNK, (caddr_t)&ra) == 0) {
		int pntd = 0;

		for (i = 0; i < nitems(tpr); i++)
			if (ra.ra_proto == tpr[i].tpr_proto)
				break;
		if (tpr[i].tpr_proto != TRUNK_PROTO_DEFAULT)
			fprintf(output," trunkproto %s\n", tpr[i].tpr_name);

                for (i = 0; i < ra.ra_ports; ++i)
			if(rpbuf[i].rp_portname[0] != '\0') {
				fprintf(output, " %s%s",
				    pntd ? "" : "trunkport ",
				    rpbuf[i].rp_portname);
				pntd = 1;
			}
		if (pntd) {
			fprintf(output, "\n");
		}
        } else return (1);

	return (0);
}

/* ifname's trunk ports, and in ifv its parent trunk and protocol */
void
trunk_facts(struct facts_out *o, int ifs, char *ifname, struct facts_value *ifv)
{
	struct facts_value v[TPORT_NFIELDS];
	struct trunk_reqport rp, rpbuf[TRUNK_MAX_PORTS];
	struct trunk_reqall ra;
	static char parent[IFNAMSIZ];
	int i;

	bzero(&ra, sizeof(ra));
	bzero(&rp, sizeof(rp));
	strlcpy(rp.rp_ifname, ifname, sizeof(rp.rp_ifname));
	strlcpy(rp.rp_portname, ifname, sizeof(rp.rp_portname));

	if (ioctl(ifs, SIOCGTRUNKPORT, (caddr_t)&rp) == 0) {
		strlcpy(parent, rp.rp_ifname, sizeof(parent));
		facts_string(&ifv[IF_TRUNKPARENT], parent);
		facts_u64(&ifv[IF_TRUNKFLAGS], rp.rp_flags);
	}

	for (i = 0; i < TRUNK_MAX_PORTS; i++)
		bzero(&rpbuf[i], sizeof(struct trunk_reqport));

	strlcpy(ra.ra_ifname, ifname, sizeof(ra.ra_ifname));
	ra.ra_size = sizeof(rpbuf);
	ra.ra_port = rpbuf;

	if (ioctl(ifs, SIOCGTRUNK, (caddr_t)&ra) == 0) {
		facts_u64(&ifv[IF_TRUNKPROTO], ra.ra_proto);
		for (i = 0; i < ra.ra_ports && i < TRUNK_MAX_PORTS; i++) {
			if (rpbuf[i].rp_portname[0] == '\0')
				continue;
			memset(v, 0, sizeof(v));
			facts_string(&v[TPORT_NAME], rpbuf[i].rp_portname);
			facts_u64(&v[TPORT_FLAGS], rpbuf[i].rp_flags);
			facts_string(&v[TPORT_IF], ifname);
			facts_record(o, &kind_trunkport, v);
		}
	}
}
