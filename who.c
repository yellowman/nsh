/* $nsh: who.c,v 1.1 2007/12/27 22:19:39 chris Exp $ */
/*
 * Copyright (c) 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Michael Fischbein.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <paths.h>
#include <pwd.h>
#include <utmp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "externs.h"

void  output(struct utmp *);
void  output_labels(void);

int
who(int argc, char **argv)
{
	FILE *utmp;
	struct utmp who;
	int count = 0;

	if (argc > 1) {
		printf("%% Too many arguments\n");
		return(0);
	}

	if ((utmp = fopen(_PATH_UTMP, "r")) == NULL) {
		printf("%% who: fopen %s: %s\n",_PATH_UTMP,strerror(errno));
		return(0);
	}

#define HOST_WIDTH 40
#define NAME_WIDTH 8

	output_labels();

	while (fread((char *)&who, sizeof(who), 1, utmp) == 1) {
		if (*who.ut_name && *who.ut_line) {
			output(&who);
			count++;
		}
	}
	(void) printf ("%% users=%d\n", count);

	return(0);
}

void
output_labels(void)
{
	(void)printf("%-*.*s ", NAME_WIDTH, UT_NAMESIZE, "User");

	(void)printf("%-*.*s ", UT_LINESIZE, UT_LINESIZE, "Line");
	(void)printf("When         ");

	(void)printf("Idle    %.*s", HOST_WIDTH, "From");

	(void)putchar('\n');
}

void
output(struct utmp *up)
{
	char line[sizeof(_PATH_DEV) + sizeof (up->ut_line)];
	static time_t now = 0;
	time_t idle = 0;

	if (now == 0)
		time(&now);
	
	memset(line, 0, sizeof line);
	strlcpy(line, _PATH_DEV, sizeof line);
	strlcat(line, up->ut_line, sizeof line);

	(void)printf("%-*.*s ", NAME_WIDTH, UT_NAMESIZE, up->ut_name);

	(void)printf("%-*.*s ", UT_LINESIZE, UT_LINESIZE, up->ut_line);
	(void)printf("%.12s ", ctime(&up->ut_time) + 4);

	if (idle < 60) 
		(void)printf("00:00 ");
	else if (idle < (24 * 60 * 60))
		(void)printf("%02d:%02d ", 
			     (idle / (60 * 60)),
			     (idle % (60 * 60)) / 60);
	else
		(void)printf(" old  ");
	
	if (*up->ut_host)
		printf("  %.*s", HOST_WIDTH, up->ut_host);
	(void)putchar('\n');
}
