/* $nsh: version.c,v 1.6 2003/02/18 09:29:46 chris Exp $ */
/*
 * Copyright (c) 2002
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
#include <ctype.h>
#include <tzfile.h>
#include <errno.h>
#include <string.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/errno.h>
#include "externs.h"

int
version(void)
{
	char cpubuf[1024];
	char kernver[1024];
	struct timeval tv, boottime;
	struct utsname un;
	size_t len;
	time_t c;
	u_long physmem;
	int mib[2], pntd, weeks, days, hours, mins;

	mib[0] = CTL_HW;
	mib[1] = HW_PHYSMEM;
	len = sizeof(physmem);
	if (sysctl(mib, 2, &physmem, &len, NULL, 0) == -1) {
		printf("%% HW_PHYSMEM: %s\n", strerror(errno));
		return(1);
	}
	mib[0] = CTL_HW;
	mib[1] = HW_MODEL;
	len = sizeof(cpubuf);
	if (sysctl(mib, 2, &cpubuf, &len, NULL, 0) == -1) {
		printf("%% HW_MODEL: %s\n", strerror(errno));
		return(1);
	}
	mib[0] = CTL_KERN;
	mib[1] = KERN_BOOTTIME;
	len = sizeof(boottime);
	if (sysctl(mib, 2, &boottime, &len, NULL, 0) == -1) {
		printf("%% KERN_BOOTTIME: %s\n", strerror(errno));
		return(1);
	}
	mib[0] = CTL_KERN;
	mib[1] = KERN_VERSION;
	len = sizeof(kernver);
	if (sysctl(mib, 2, &kernver, &len, NULL, 0) == -1) {
		printf("%% KERN_VERSION: %s\n", strerror(errno));
		return(1);
	}
	if (uname(&un)) {
		printf("%% uname: %s\n", strerror(errno));
		return(1);
	}
	gettimeofday(&tv, (struct timezone *)0);
	c = difftime(tv.tv_sec, boottime.tv_sec);

	printf("%% NSH v%s\n", vers);
	printf("Compiled %s by %s@%s\n", compiled, compiledby, compilehost);
	printf("uptime: ");
	pntd = 0;
#define SECSPERWEEK (SECSPERDAY * DAYSPERWEEK)
	weeks = c / SECSPERWEEK;
	c %= SECSPERWEEK;
	days = c / SECSPERDAY;
	c %= SECSPERDAY;
	hours = c / SECSPERHOUR;
	c %= SECSPERHOUR;
	mins = c / SECSPERMIN;
	c %= SECSPERMIN;
	if (weeks) {
		printf("%d week%s", weeks, weeks == 1 ? "" : "s");
		pntd = 1;
	}
	if (days) {
		printf("%s%d day%s", pntd ? ", " : "", days,
		    days == 1 ? "" : "s");
		pntd = 1;
	}
	if (hours) {
		printf("%s%d hour%s", pntd ? ", " : "", hours,
		    hours == 1 ? "" : "s");
		pntd = 1;
	}
	if (mins) {
		printf("%s%d minute%s", pntd ? ", " : "", mins,
		    mins == 1 ? "" : "s");
		pntd = 1;
	}
	if (!pntd)
		printf("%d second%s", c, c == 1 ? "" : "s");
	printf("\n");
	printf("kernel: %s/%s version %s\n", un.sysname, un.machine,
	    un.release);
	printf("cpu: %s\n", cpubuf);
	printf("memory: %luK\n", physmem / 1024);
	printf("compiled on: %s\n", compiledon);
	printf("running on: %s", kernver);
	return(0);
}

