/* $nsh: rate.c,v 1.13 2003/04/14 08:44:20 chris Exp $ */
/* From: $OpenBSD: /usr/src/usr.sbin/altq/tbrconfig/tbrconfig.c,v 1.3 2002/02/15 03:31:16 deraadt Exp $ */

/*
 * Copyright (C) 2000
 *	Sony Computer Science Laboratories Inc.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/pfvar.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/*
#include <altq/altq.h>
*/

#include "externs.h"

#define	ALTQ_DEVICE	"/dev/pf"

u_long atobps(const char *s);
u_long atobytes(const char *s);
u_long get_tbr(char *ifname, int);
u_int size_bucket(char *ifname, u_int rate);
u_int autosize_bucket(char *ifname, u_int rate);
static int get_clockfreq(void);
int list_rates(void);

int 
intrate(char *ifname, int ifs, int argc, char **argv)
{
	struct pfioc_altq ioc;
	u_int baudrate = 0, rate = 0, depth = 0;
	int fd, delete = 0;

	if (NO_ARG(argv[0])) {
		delete = 1;

		/* bye bye 'no' */
		argc--;
		argv++;
	}

	/* bye bye 'rate' */
	argc--;
	argv++;

	memset(&ioc, 0, sizeof(ioc));

	if ((delete && argc > 1) || (!delete && (argc < 1 || argc > 2))) {
		printf("%% rate <tokenrate> [bucketsize]\n");
		printf("%% no rate [tokenrate]\n");
		return(0);
	}

	strlcpy(ioc.altq.ifname, ifname, IFNAMSIZ);
	if (argc)
		rate = (u_int)atobps(argv[0]);
	if (argc > 1) {
		if (CMP_ARG(argv[1], "auto"))
			depth = autosize_bucket(ioc.altq.ifname, rate);
		else {
			depth = (u_int)atobytes(argv[1]);
			if (depth < 1) {
				printf("%% Invalid bucket size argument\n");
				depth = autosize_bucket(ioc.altq.ifname, rate);
			}
		}
	}

	if (delete || rate > 0) {
		/* set token bucket regulator */
		if (delete)
			rate = 0;
		else if (depth == 0)
			depth = size_bucket(ioc.altq.ifname, rate);

		if (!delete)
			baudrate = get_ifdata(ioc.altq.ifname, IFDATA_BAUDRATE);

		if (baudrate > 0) {
			if (rate > baudrate) {
				printf("%% Rate set to interface max\n");
				rate = baudrate;
			}
		} else {
			if (verbose)
				printf("%% Failed to determine interface line rate\n");
		}
		
		ioc.altq.ifbandwidth = rate;
		ioc.altq.tbrsize = depth;

		if ((fd = open(ALTQ_DEVICE, O_RDWR)) < 0) {
			printf("%% rate: can't open altq device: %s\n",
			    strerror(errno));
			return(1);
		}

		if (ioctl(fd, DIOCSTARTALTQ) < 0) {
			if (errno != EEXIST) {
				printf("%% rate: DIOCSTARTALTQ for interface"
				    " %s: %s\n",
				    ioc.altq.ifname, strerror(errno));
				close(fd);
				return(0);
			}
		}

		if (ioctl(fd, DIOCBEGINALTQS, &ioc.ticket) < 0) {
				printf("%% rate: DIOCBEGINALTAS: %s\n",
				    strerror(errno));
			close(fd);
			return(0);
		}

		if (ioctl(fd, DIOCADDALTQ, &ioc) < 0) {
			if (errno == ENODEV)
				printf("%% This interface does not support"
				    " rate limiting\n");
			else
				printf("%% rate: DIOCADDALTQ: %s\n",
				    strerror(errno));
			close(fd);
			return(0);
		}

		if (ioctl(fd, DIOCCOMMITALTQS, &ioc.ticket) < 0) {
				printf("%% rate: DIOCCOMMITALTQS: %s\n",
				    strerror(errno));
			close(fd);
			return(0);
		}

		close(fd);

		if (delete) {
			printf("%% Deleted token bucket regulator on %s\n",
			       ifname);
			return (0);
		}
	} else {
		printf("%% Invalid rate argument\n");
	}

	return (0);
}

u_long
get_tbr(char *ifname, int type)
{
	struct pfioc_altq ioc;
	u_long value = 0;
	int fd;

	if ((fd = open(ALTQ_DEVICE, O_RDONLY)) < 0) {
		printf("%% get_rate: can't open altq device: %s\n",
		    strerror(errno));
		return(0);
	}

	strlcpy(ioc.altq.ifname, ifname, IFNAMSIZ); 
	if (ioctl(fd, DIOCGETALTQ, &ioc) == 0) {
		if (type == TBR_RATE)
			value = ioc.altq.ifbandwidth;
		else if (type == TBR_BUCKET)
			value = ioc.altq.tbrsize;
		else if (type == ALTQ_TICKET)
			value = ioc.ticket;
	}

	close(fd);

	return value;
}

u_long
atobps(const char *s)
{
	double bandwidth;
	char *cp;
			
	bandwidth = strtod(s, &cp);
	if (cp != NULL) {
		if (*cp == 'K' || *cp == 'k')
			bandwidth *= 1000;
		else if (*cp == 'M' || *cp == 'm')
			bandwidth *= 1000000;
		else if (*cp == 'G' || *cp == 'g')
			bandwidth *= 1000000000;
	}
	if (bandwidth < 0)
		bandwidth = 0;
	return ((u_long)bandwidth);
}

u_long
atobytes(const char *s)
{
	double bytes;
	char *cp;
			
	bytes = strtod(s, &cp);
	if (cp != NULL) {
		if (*cp == 'K' || *cp == 'k')
			bytes *= 1024;
		else if (*cp == 'M' || *cp == 'm')
			bytes *= 1024 * 1024;
		else if (*cp == 'G' || *cp == 'g')
			bytes *= 1024 * 1024 * 1024;
	}
	if (bytes < 0)
		bytes = 0;
	return ((u_long)bytes);
}

/*
 * use heuristics to determine the bucket size
 */
u_int
size_bucket(char *ifname, u_int rate)
{
	u_int size, mtu;

	mtu = get_ifdata(ifname, IFDATA_MTU);
	if (mtu > DEFAULT_MTU)
		mtu = DEFAULT_MTU; /* assume that the path mtu is still 1500 */

	if (rate <= 1*1000*1000)
		size = 1;
	else if (rate <= 10*1000*1000)
		size = 4;
	else if (rate <= 200*1000*1000)
		size = 8;
	else
		size = 24;

	size = size * mtu;
	return (size);
}

/*
 * compute the bucket size to be required to fill the rate
 * even when the rate is controlled only by the kernel timer.
 */
u_int
autosize_bucket(char *ifname, u_int rate)
{
	u_int size, freq, mtu;

	mtu = get_ifdata(ifname, IFDATA_MTU);
	freq = get_clockfreq();
	size = rate / 8 / freq;
	if (size < mtu)
		size = mtu;
	return (size);
}

static int
get_clockfreq(void)
{
	struct clockinfo clkinfo;
	int mib[2];
	size_t len;

	clkinfo.hz = 100; /* default Hz */

	mib[0] = CTL_KERN;
	mib[1] = KERN_CLOCKRATE;
	len = sizeof(struct clockinfo);
	if (sysctl(mib, 2, &clkinfo, &len, NULL, 0) == -1)
		printf("%% get_clockfreq: can't get clockrate via sysctl!"
		    " using %dHz\n",
		    clkinfo.hz);
	return (clkinfo.hz);
}

