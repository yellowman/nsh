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
#include "args.h"
#include "showfacts.h"

static struct trunk_protos tpr[] = TRUNK_PROTOS;

static int in_list(char *, char *);
static int cand_trunkport(struct cand *, char *, int, int, char **);
static int cand_trunkproto(struct cand *, char *, int);

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
cand_trunkport(struct cand *cand, char *ifname, int set, int argc, char **argv)
{
	char ports[1024], *l, *w, *p;
	int i, busy, n = 0, aggr = strncmp(ifname, "aggr", strlen("aggr")) == 0;

	if (!cand_takes(ifname, SIOCSTRUNKPORT)) {
		printf("%% %s not trunk\n", ifname);
		return -1;
	}
	if ((l = cand_line(cand, "trunkport", 0)) != NULL) {
		strlcpy(ports, l, sizeof(ports));
		strtok_r(ports, " ", &p);
		while ((w = strtok_r(NULL, " ", &p)) != NULL)
			n++;
	}
	for (i = 0; i < argc; i++) {
		if (!set) {
			if (!in_list(cand_line(cand, "trunkport", 0),
			    argv[i])) {
				printf("%% Port %s not part of %s\n", argv[i],
				    ifname);
				return -1;
			}
			continue;
		}
		if (!cand_hasif(cand, argv[i]) ||
		    strcmp(argv[i], ifname) == 0) {
			printf("%% inttrunkport: SIOCSTRUNKPORT: %s\n",
			    strerror(EINVAL));
			return -1;
		}
		/* a port of any trunk, and for aggr of a bridge (EBUSY) */
		busy = in_list(cand_line(cand, "trunkport", 0), argv[i]) ||
		    cand_listowner(cand, ifname, "trunkport",
		        argv[i]) != NULL ||
		    (aggr && cand_listowner(cand, ifname, "member", argv[i]));
		/* trunk_port_create() checks the type after EBUSY */
		if ((aggr || !busy) &&
		    cand_gettype(cand, argv[i]) != IFT_ETHER) {
			printf("%% inttrunkport: SIOCSTRUNKPORT: %s\n",
			    strerror(EPROTONOSUPPORT));
			return -1;
		}
		if (busy) {
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
	return cand_setting(cand, set ? ST_ON : ST_OFF, "trunkport %s", ports);
}

/*
 * trunkproto in configure private: conf_trunk() prints any but the
 * driver's default, and aggr's only protocol, lacp, is its default
 */
static int
cand_trunkproto(struct cand *cand, char *ifname, int proto)
{
	int i;

	if (!cand_takes(ifname, SIOCSTRUNK)) {
		printf("%% %s not trunk\n", ifname);
		return -1;
	}
	if (proto == TRUNK_PROTO_DEFAULT || proto == TRUNK_PROTO_LACP)
		return cand_setting(cand, ST_DEFAULT, "trunkproto");
	for (i = 0; tpr[i].tpr_proto != proto; i++)
		;
	return cand_setting(cand, ST_ON, "trunkproto %s", tpr[i].tpr_name);
}

int
inttrunkport_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	struct trunk_reqport rp;
	char port[TRUNK_MAX_PORTS][IFNAMSIZ], *ports[TRUNK_MAX_PORTS];
	int i, n, r = 0;

	for (n = 0; n < TRUNK_MAX_PORTS && v[n].type != FACT_NONE; n++) {
		args_string(&v[n], port[n], sizeof(port[n]));
		ports[n] = port[n];
	}
	if (cand != NULL)
		return cand_trunkport(cand, ifname, set, n, ports);

	bzero(&rp, sizeof(rp));
	strlcpy(rp.rp_ifname, ifname, sizeof(rp.rp_ifname));

	for (i = 0; i < n; i++) {
		if (set) {
			strlcpy(rp.rp_portname, ports[i],
			    sizeof(rp.rp_portname));
			if (ioctl(ifs, SIOCSTRUNKPORT, &rp) < 0) {
				switch(errno) {
				case ENOTTY:
					printf("%% %s not trunk\n",ifname);
					break;
				case EBUSY:
					printf("%% Failed (port %s already"
					    " assigned to a trunk group)\n",
					    ports[i]);
					break;
				case ENETDOWN:
					printf("%% Failed (port %s is "
					    "shutdown)\n", ports[i]);
					break;
				default:
					printf("%% inttrunkport:"
					    " SIOCSTRUNKPORT: %s\n",
				    strerror(errno));
				}
				r = -1;
			}
		} else {
			strlcpy(rp.rp_portname, ports[i],
			    sizeof(rp.rp_portname));
			if (ioctl(ifs, SIOCSTRUNKDELPORT, &rp) < 0) {
				switch(errno) {
				case ENOTTY:
					printf("%% %s not trunk\n",ifname);
					break;
				case ENOENT:
					printf("%% Port %s not part of %s\n",
					    ports[i], ifname);
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
inttrunkproto_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	struct trunk_reqall ra;
	int aggr = strncmp(ifname, "aggr", strlen("aggr")) == 0;

	bzero(&ra, sizeof(ra));
	strlcpy(ra.ra_ifname, ifname, sizeof(ra.ra_ifname));
	if (set)
		ra.ra_proto = v[0].v.i;
	else
		ra.ra_proto = aggr ? TRUNK_PROTO_LACP : TRUNK_PROTO_DEFAULT;

	/*
	 * aggr takes only lacp, and trunk takes any other
	 * (EPROTONOSUPPORT: if_aggr.c, and if_trunk.c's trunk_protos[])
	 */
	if (cand_takes(ifname, SIOCSTRUNK) &&
	    (ra.ra_proto == TRUNK_PROTO_LACP) != aggr) {
		printf("%% %s takes %s\n", ifname, aggr ? "only lacp" :
		    "roundrobin, failover, loadbalance, broadcast or none");
		return -1;
	}

	if (cand != NULL)
		return cand_trunkproto(cand, ifname, ra.ra_proto);

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

/*
 * lacpmode and lacptimeout. Only aggr uses LACP: trunk refuses
 * SIOCSTRUNKOPTS (EPROTONOSUPPORT).
 */
int
intlacp_apply(const struct argcmd *c, int set,
    const struct facts_value *v, char *ifname, int ifs, struct cand *cand)
{
	struct trunk_opts to;
	const struct argkey *k;
	int opt, dflt, value;

	opt = c->code;
	dflt = opt == TRUNK_OPT_LACP_MODE;
	value = set ? v[0].v.i : dflt;
	if (strncmp(ifname, "aggr", strlen("aggr")) != 0) {
		printf("%% %s is not an aggr interface\n", ifname);
		return -1;
	}

	if (cand != NULL) {
		if (value == dflt)
			return cand_setting(cand, ST_DEFAULT, "%s", c->name);
		for (k = c->args[0].keys; k->value != value; k++)
			;
		return cand_setting(cand, ST_ON, "%s %s", c->name, k->word);
	}

	memset(&to, 0, sizeof(to));
	strlcpy(to.to_ifname, ifname, sizeof(to.to_ifname));
	to.to_proto = TRUNK_PROTO_LACP;
	to.to_opts = opt;
	if (opt == TRUNK_OPT_LACP_MODE)
		to.to_lacpopts.lacp_mode = value;
	else
		to.to_lacpopts.lacp_timeout = value;
	if (ioctl(ifs, SIOCSTRUNKOPTS, &to) == -1) {
		printf("%% %s: SIOCSTRUNKOPTS: %s\n", c->name,
		    strerror(errno));
		return -1;
	}
	return 0;
}

int
conf_trunk(FILE *output, int ifs, char *ifname)
{
	struct trunk_reqport rpbuf[TRUNK_MAX_PORTS];
	struct trunk_opts to;
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
		/* aggr has only lacp, its default */
		if (tpr[i].tpr_proto != TRUNK_PROTO_DEFAULT &&
		    tpr[i].tpr_proto != TRUNK_PROTO_LACP)
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

	/* aggr's LACP options, where they are not the defaults */
	memset(&to, 0, sizeof(to));
	strlcpy(to.to_ifname, ifname, sizeof(to.to_ifname));
	to.to_proto = TRUNK_PROTO_LACP;
	if (ioctl(ifs, SIOCGTRUNKOPTS, &to) == 0) {
		if (to.to_lacpopts.lacp_mode == 0)
			fprintf(output, " lacpmode passive\n");
		if (to.to_lacpopts.lacp_timeout == 1)
			fprintf(output, " lacptimeout fast\n");
	}

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
