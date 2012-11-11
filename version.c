/*
 * Copyright (c) 2002 Chris Cappuccio <chris@nmedia.net>
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
#include <ctype.h>
#include <tzfile.h>
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netmpls/mpls.h>
#include "externs.h"

int
version(int argc, char **argv)
{
	char cpubuf[1024];
	char kernver[1024];
	struct timeval tv, boottime;
	struct utsname un;
	size_t len;
	time_t c;
	uint64_t physmem;
	int mib[5], ipdrops, mplsdrops, pntd, weeks, days, hours, mins;

	mib[0] = CTL_HW;
	mib[1] = HW_PHYSMEM64;
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
	mib[0] = CTL_NET;
	mib[1] = PF_INET;
	mib[2] = IPPROTO_IP;
	mib[3] = IPCTL_IFQUEUE;
	mib[4] = IFQCTL_DROPS;
	len = sizeof(ipdrops);
	if (sysctl(mib, 5, &ipdrops, &len, NULL, 0) == -1) {
		printf("%% IFQ_DROPS: %s\n", strerror(errno));
		return(1);
	}
	mib[0] = CTL_NET;
	mib[1] = PF_MPLS;
	mib[2] = MPLSCTL_IFQUEUE;
	mib[3] = IFQCTL_DROPS;
	len = sizeof(mplsdrops);
	if (sysctl(mib, 4, &mplsdrops, &len, NULL, 0) == -1) {
		printf("%% MPLS_IFQCTL_DROPS: %s\n", strerror(errno));
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
	printf("system: %s/%s version %s\n", un.sysname, un.machine,
	    un.release);
	printf("cpu: %s\n", cpubuf);
	printf("memory: %sB\n", format_k(physmem / 1024));
	printf("kernel: %s", kernver);
	printf("IFQ drops: ip %d mpls %d\n", ipdrops, mplsdrops);
	return(0);
}

