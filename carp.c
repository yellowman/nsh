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
#include <string.h>
#include <errno.h>
#include <sys/limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_carp.h>
#include <net/if.h>
#include <netdb.h>
#include "externs.h"

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

int
intcarp(char *ifname, int ifs, int argc, char **argv)
{
	const char *errmsg = NULL;
	struct ifreq ifr;
	struct carpreq creq;
	int set, bal_mode = 0, val = 0;
	struct intc *x;

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
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[0]);
		return 0;
	}

	argv++;
	argc--;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% %s <%s>\n", x->name, x->descr);
		printf("%% no %s [%s]\n", x->name, x->descr);
		return (0);
	}
	bzero(&ifr, sizeof(ifr));
	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCGVH, (caddr_t) & ifr) == -1) {
		printf("%% intcarp: SIOCGVH: %s\n", strerror(errno));
		return (0);
	}

	switch(x->type) {
	case CARP_ADVSKEW:
	case CARP_ADVBASE:
		if (set) {
			errno = 0;
			val = strtonum(argv[0], 0, 254, &errmsg);
			if (errmsg) {
				printf("%% %s value out of range: %s\n", x->name, errmsg);
				return(0);
			}
		}
		break;
	case CARP_VHID:
		if (set) {
			errno = 0;
			val = strtonum(argv[0], 0, 255, &errmsg);
			if (errmsg) {
				printf("%% %s value out of range: %s\n", x->name, errmsg);
				return(0);
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
				return(0);
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
		if(set)
			creq.carpr_vhids[0] = (int)val;
		else
			creq.carpr_vhids[0] = -1;
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
				return(0);
			}

			/* do we need this if hints.ai_family = AF_INET? */
			if (peerres->ai_addr->sa_family != AF_INET) {
				printf("%% only IPv4 addresses supported for the CARP peer\n");
				return(0);
			}

			creq.carpr_peer.s_addr = ((struct sockaddr_in *)
			    peerres->ai_addr)->sin_addr.s_addr;
		} else
			creq.carpr_peer.s_addr = htonl(INADDR_CARP_GROUP);
		break;
	case CARP_BALANCING:
		if(set)
			creq.carpr_balancing = bal_mode;
		else
			creq.carpr_balancing = 0;
	}

	if (ioctl(ifs, SIOCSVH, (caddr_t) & ifr) == -1) {
		if (errno == EINVAL)
			printf("%% value out of range\n");
		else
			printf("%% intcarp: SIOCSVH: %s\n", strerror(errno));
	}
	return (0);
}

int
intcpass(char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	struct carpreq creq;
	int set;

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
		return (0);
	}
	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCGVH, (caddr_t) & ifr) == -1) {
		printf("%% intpass: SIOCGVH: %s\n", strerror(errno));
		return (0);
	}
	if (set) {
		bzero(creq.carpr_key, CARP_KEY_LEN);
		strlcpy(creq.carpr_key, argv[0], CARP_KEY_LEN);
	} else {
		bzero((char *)&creq.carpr_key, sizeof(creq.carpr_key));
	}

	if (ioctl(ifs, SIOCSVH, (caddr_t) & ifr) == -1)
		printf("%% intcpass: SIOCSVH: %s\n", strerror(errno));
	return (0);
}

int
intcnode(char *ifname, int ifs, int argc, char **argv)
{
	struct ifreq ifr;
	struct carpreq creq;
	const char *errmsg = NULL;
	int set, i, last;
	u_int vhid, advskew;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	if ((!set && argc != 1) || (set && argc > 3) || (set && argc < 1)) {
		printf("%% carpnode <vhid> [advskew] [state]\n");
		printf("%% no carpnode <vhid>\n");
		return (0);
	}
	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	errno = 0;
	vhid = strtonum(argv[0], 1, 255, &errmsg);
	if (errmsg) {
		printf("%% vhid value out of range: %s\n", errmsg);
		return(0);
	}
	if (argv[1]) {
		advskew = strtonum(argv[1], 0, 255, &errmsg);
		if (errmsg) {
			printf("%% advskew value out of range: %s\n", errmsg);
			return(0);
		}
	} else {
		advskew = 0;
	}
	
	if (ioctl(ifs, SIOCGVH, (caddr_t) & ifr) == -1) {
		printf("%% intcnode: SIOCGVH: %s\n", strerror(errno));
		return (0);
	}
	
	/* find last used vhid */
	for (last = 0; creq.carpr_vhids[last]; last++) {
	}
	last--;

	/* find next free vhid */
	for (i = 0; creq.carpr_vhids[i]; i++) {
		if (vhid == creq.carpr_vhids[i])
			break;
		if (set && ((i + 1) == CARP_MAXNODES)) {
			printf("%% maximum carp nodes reached, unable to add "
			    "more\n");
			return(0);
		}
	}
	if (!set && !creq.carpr_vhids[i]) {
		printf("%% unable to delete vhid %u, does not exist on %s\n",
		    vhid, ifname);
		return(0);
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

	if (ioctl(ifs, SIOCSVH, (caddr_t) & ifr) == -1)
		printf("%% intcnode: SIOCSVH: %s\n", strerror(errno));
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
		for (i = 0; creq.carpr_vhids[i]; i++)
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

int
carp_state(int s, char *ifname)
{
	struct ifreq ifr;
	struct carpreq creq;
	const char *carp_states[] = { CARP_STATES };
	const char *state = NULL;
	int i, pntd = 0;

	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGVH, (caddr_t) & ifr) == -1)
		return (0);

	if (creq.carpr_balancing <= CARP_BAL_MAXID) {
		printf("  CARP balancing mode %s", carp_bal_modes[creq.carpr_balancing]);
		pntd = 1;
	}

	if (creq.carpr_peer.s_addr != htonl(INADDR_CARP_GROUP)) {
		printf(" peer %s", inet_ntoa(creq.carpr_peer));
		pntd = 1;
	}
	if (pntd)
		printf("\n");

	if (creq.carpr_vhids[0] == 0)
		return(0);

	for (i = 0; creq.carpr_vhids[i]; i++) {
		if (creq.carpr_states[i] <= CARP_MAXSTATE)
			state = carp_states[creq.carpr_states[i]];
		if (creq.carpr_vhids[1] == 0) {
			printf("  CARP state %s, device %s vhid %u advbase %d "
		 	    "advskew %u\n", state,
			    creq.carpr_carpdev[0] != '\0' ?
			    creq.carpr_carpdev : "none", creq.carpr_vhids[0],
			    creq.carpr_advbase, creq.carpr_advskews[0]);
		} else {
			if (i == 0) {
				printf("  CARP device %s advbase %d\n",
				    creq.carpr_carpdev[0] != '\0' ?
				    creq.carpr_carpdev : "none",
				    creq.carpr_advbase);
			}
			printf("  CARP state %s vhid %u advskew %u\n", state,
			    creq.carpr_vhids[i], creq.carpr_advskews[i]);
		}
	}
			
	return(0);
}
