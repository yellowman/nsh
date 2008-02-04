/* $nsh $ */
/*
 * Copyright (c) 2004
 *      Chris Cappuccio.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/limits.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip_carp.h>
#include <net/if.h>
#include "externs.h"

static struct intc {
	char *name;
	char *descr;
	int type;
} intcs[] = {
	{ "advskew",	"skew",		CARP_ADVSKEW },
	{ "advbase",	"seconds",	CARP_ADVBASE },
	{ "vhid",	"id",		CARP_VHID },
	{ 0,		0,		0 }
};

int
intcarp(char *ifname, int ifs, int argc, char **argv)
{
	const char *errmsg = NULL;
	struct ifreq ifr;
	struct carpreq creq;
	int set;
	u_int32_t val = 0;
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
	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCGVH, (caddr_t) & ifr) == -1) {
		printf("%% intcarp: SIOCGVH: %s\n", strerror(errno));
		return (0);
	}

	if (set) {
		errno = 0;
		val = strtonum(argv[0], 0, INT_MAX, &errmsg);
		if (errmsg) {
			printf("%% %s value out of range: %s\n", x->name, errmsg);
			return(0);
		}
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
	if (set)
		strlcpy(creq.carpr_key, argv[0], CARP_KEY_LEN);
	else
		bzero((char *)&creq.carpr_key, sizeof(creq.carpr_key));

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
	vhid = strtonum(argv[0], 0, 255, &errmsg);
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

	if (creq.carpr_vhids[0] == 0)
		return (0);

	if (creq.carpr_carpdev[0] != '\0')
		fprintf(output, " carpdev %s\n", creq.carpr_carpdev);
	if (creq.carpr_key[0] != '\0')
		fprintf(output, " cpass %s\n", creq.carpr_key);
	if (creq.carpr_advbase != CARP_DFLTINTV)
		fprintf(output, " advbase %i\n", creq.carpr_advbase);
	if (creq.carpr_vhids[1] == 0) {
		fprintf(output, " vhid %i\n", creq.carpr_vhids[0]);
		if (creq.carpr_advskews[0] != 0)
			fprintf(output, " advskew %i\n",
			    creq.carpr_advskews[0]);
	} else {
		for (i = 0; creq.carpr_vhids[i]; i++) {
			fprintf(output, " carpnode %i %i\n",
			    creq.carpr_vhids[i], creq.carpr_advskews[i]);
		}
	}
			
	return (0);
}

const char *
carp_state(int s, char *ifname)
{
	struct ifreq ifr;
	struct carpreq creq;
	const char *carp_states[] = { CARP_STATES };
	const char *state = NULL;

	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGVH, (caddr_t) & ifr) == -1)
		return (NULL);

	/*
	 * XXX carp_state and its callers need to be extended to handle
	 * interfaces with multiple vhids
	 */
	if (creq.carpr_vhids[0] > 0) {
		if (creq.carpr_state > CARP_MAXSTATE) {
			errno = EINVAL;
			return(NULL);
		} else {
			state = carp_states[creq.carpr_state];
		}
	}	
	return(state);
}

int
intcdev(char *ifname, int ifs, int argc, char **argv) 
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
		printf("%% carpdev <carpdev>\n");
		printf("%% no carpdev\n");
		return (0);
	}

	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(ifs, SIOCGVH, (caddr_t) & ifr) == -1) {
		printf("%% intcdev: SIOCGVH: %s\n", strerror(errno));
		return (0);
	}
	if (set)
		strlcpy(creq.carpr_carpdev, argv[0], sizeof(creq.carpr_carpdev));
	else
		bzero((char *)&creq.carpr_carpdev, sizeof(creq.carpr_carpdev));

	if (ioctl(ifs, SIOCSVH, (caddr_t) & ifr) == -1)
		printf("%% intcdev: SIOCSVH: %s\n", strerror(errno));

	return (0);
}

