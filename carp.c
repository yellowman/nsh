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

int
intcarp(char *ifname, int ifs, int argc, char **argv)
{
	char *name, *descr;
	const char *errmsg = NULL;
	struct ifreq ifr;
	struct carpreq creq;
	int type, set;
	u_int32_t val;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	if (CMP_ARG(argv[0], "advs")) {
		type = CARP_ADVSKEW;
		name = "advskew";
		descr = "skew";
	} else if (CMP_ARG(argv[0], "advb")) {
		type = CARP_ADVBASE;
		name = "advbase";
		descr = "seconds";
	} else if (CMP_ARG(argv[0], "v")) {
		type = CARP_VHID;
		name = "vhid";
		descr = "id";
	} else {
		printf("%% Internal error\n");
		return(1);
	}

	argv++;
	argc--;

	if ((!set && argc > 1) || (set && argc != 1)) {
		printf("%% %s <%s>\n", name, descr);
		printf("%% no %s [%s]\n", name, descr);
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
			printf("%% %s value out of range: %s\n", name, errmsg);
			return(0);
		}
	}

	switch(type) {
	case CARP_ADVSKEW:
		if (set)
			creq.carpr_advskew = (int)val;
		else
			creq.carpr_advskew = 0;
		break;
	case CARP_ADVBASE:
		if (set)
			creq.carpr_advbase = (int)val;
		else
			creq.carpr_advbase = CARP_DFLTINTV;
		break;
	case CARP_VHID:
		if(set)
			creq.carpr_vhid = (int)val;
		else
			creq.carpr_vhid = -1;
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
conf_carp(FILE *output, int s, char *ifname)
{
	struct ifreq ifr;
	struct carpreq creq;

	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGVH, (caddr_t) & ifr) == -1)
		return (0);

	if (creq.carpr_carpdev[0] != '\0')
		fprintf(output, " carpdev %s\n", creq.carpr_carpdev);
	if (creq.carpr_key[0] != '\0')
		fprintf(output, " cpass %s\n", creq.carpr_key);
	if (creq.carpr_vhid != -1)
		fprintf(output, " vhid %i\n", creq.carpr_vhid);
	if (creq.carpr_advbase != CARP_DFLTINTV)
		fprintf(output, " advbase %i\n", creq.carpr_advbase);
	if (creq.carpr_advskew != 0)
		fprintf(output, " advskew %i\n", creq.carpr_advskew);
	return (0);
}

const char *
carp_state(int s, char *ifname)
{
	struct ifreq ifr;
	struct carpreq creq;
	const char *carp_states[] = { CARP_STATES };
	const char *state;

	bzero((char *) &creq, sizeof(struct carpreq));
	ifr.ifr_data = (caddr_t) & creq;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGVH, (caddr_t) & ifr) == -1)
		return (NULL);

	if (creq.carpr_vhid > 0) {
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

