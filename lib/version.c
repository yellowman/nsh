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
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include "externs.h"
#include "facts.h"
#include "showfacts.h"

/* the nsh build and the system it runs on, as facts */
static struct facts_field version_fields[] = {
	[VER_NSH] =		{ "nsh-version",	FACT_STRING },
	[VER_COMPILED] =	{ "compiled",		FACT_STRING },
	[VER_COMPILEDBY] =	{ "compiled-by",	FACT_STRING },
	[VER_COMPILEHOST] =	{ "compile-host",	FACT_STRING },
	[VER_BOOTTIME] =	{ "boot-time",		FACT_TIME },
	[VER_SYSNAME] =		{ "system",		FACT_STRING },
	[VER_MACHINE] =		{ "machine",		FACT_STRING },
	[VER_RELEASE] =		{ "release",		FACT_STRING },
	[VER_CPU] =		{ "cpu",		FACT_STRING },
	[VER_MEMORY] =		{ "memory",		FACT_U64 },
	[VER_KERNEL] =		{ "kernel",		FACT_STRING },
};
struct facts_kind kind_version = { "version", version_fields,
    VER_NFIELDS };

int
version(int argc, char **argv, ...)
{
	return facts_show(stdout, "version");
}

int
version_facts(struct facts_out *o)
{
	struct facts_value v[VER_NFIELDS];
	char cpubuf[1024];
	char kernver[1024];
	struct timeval boottime;
	struct utsname un;
	size_t len;
	uint64_t physmem;
	int mib[2];

	mib[0] = CTL_HW;
	mib[1] = HW_PHYSMEM64;
	len = sizeof(physmem);
	if (sysctl(mib, 2, &physmem, &len, NULL, 0) == -1) {
		printf("%% HW_PHYSMEM: %s\n", strerror(errno));
		return -1;
	}
	mib[0] = CTL_HW;
	mib[1] = HW_MODEL;
	len = sizeof(cpubuf);
	if (sysctl(mib, 2, &cpubuf, &len, NULL, 0) == -1) {
		printf("%% HW_MODEL: %s\n", strerror(errno));
		return -1;
	}
	mib[0] = CTL_KERN;
	mib[1] = KERN_BOOTTIME;
	len = sizeof(boottime);
	if (sysctl(mib, 2, &boottime, &len, NULL, 0) == -1) {
		printf("%% KERN_BOOTTIME: %s\n", strerror(errno));
		return -1;
	}
	mib[0] = CTL_KERN;
	mib[1] = KERN_VERSION;
	len = sizeof(kernver);
	if (sysctl(mib, 2, &kernver, &len, NULL, 0) == -1) {
		printf("%% KERN_VERSION: %s\n", strerror(errno));
		return -1;
	}
	if (uname(&un)) {
		printf("%% uname: %s\n", strerror(errno));
		return -1;
	}

	memset(v, 0, sizeof(v));
	facts_string(&v[VER_NSH], vers);
	facts_string(&v[VER_COMPILED], compiled);
	facts_string(&v[VER_COMPILEDBY], compiledby);
	facts_string(&v[VER_COMPILEHOST], compilehost);
	facts_time(&v[VER_BOOTTIME], boottime.tv_sec, boottime.tv_usec * 1000);
	facts_string(&v[VER_SYSNAME], un.sysname);
	facts_string(&v[VER_MACHINE], un.machine);
	facts_string(&v[VER_RELEASE], un.release);
	facts_string(&v[VER_CPU], cpubuf);
	facts_u64(&v[VER_MEMORY], physmem);
	facts_string(&v[VER_KERNEL], kernver);
	return facts_record(o, &kind_version, v);
}

/* r's string i, or "" */
static const char *
ver_s(struct frec *r, int i)
{
	const char *s = fs(r, i);

	return s != NULL ? s : "";
}

void
version_render(struct frec *r)
{
	const struct facts_value *b;
	struct timeval tv;
	time_t c;
	int pntd, weeks, days, hours, mins;

	b = FV(r, VER_BOOTTIME, FACT_TIME);
	gettimeofday(&tv, (struct timezone *)0);
	c = difftime(tv.tv_sec, b != NULL ? b->v.t.sec : 0);

	printf("%% NSH v%s\n", ver_s(r, VER_NSH));
	printf("Compiled %s by %s@%s\n", ver_s(r, VER_COMPILED),
	    ver_s(r, VER_COMPILEDBY), ver_s(r, VER_COMPILEHOST));
	printf("uptime: ");
	pntd = 0;
	weeks = c / (7 * 24 * 60 * 60);
	c %= (7 * 24 * 60 * 60);
	days = c / (24 * 60 * 60);
	c %= (24 * 60 * 60);
	hours = c / (60 * 60);
	c %= (60 * 60);
	mins = c / 60;
	c %= 60;
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
		printf("%d second%s", (int)c, c == 1 ? "" : "s");
	printf("\n");
	printf("system: %s/%s version %s\n", ver_s(r, VER_SYSNAME),
	    ver_s(r, VER_MACHINE), ver_s(r, VER_RELEASE));
	printf("cpu: %s\n", ver_s(r, VER_CPU));
	printf("memory: %sB\n", format_k(fu(r, VER_MEMORY, 0) / 1024));
	printf("kernel: %s", ver_s(r, VER_KERNEL));
}
