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
#include <sys/queue.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <utmp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "externs.h"
#include "facts.h"
#include "showfacts.h"

int utmpfd = -1;	/* nshd's show opens it before it chroots */

int
users_facts(struct facts_out *o)
{
	struct facts_value v[LOGIN_NFIELDS];
	struct utmp who;
	char name[UT_NAMESIZE + 1], line[UT_LINESIZE + 1];
	char host[UT_HOSTSIZE + 1];
	off_t off;
	int fd, r = 0;

	if ((fd = utmpfd) == -1 && (fd = open(_PATH_UTMP, O_RDONLY)) == -1) {
		printf("%% who: fopen %s: %s\n",_PATH_UTMP,strerror(errno));
		return -1;
	}

	for (off = 0; r != -1 && pread(fd, &who, sizeof(who), off) ==
	    sizeof(who); off += sizeof(who)) {
		if (*who.ut_name && *who.ut_line) {
			memset(v, 0, sizeof(v));
			snprintf(name, sizeof(name), "%.*s", UT_NAMESIZE,
			    who.ut_name);
			snprintf(line, sizeof(line), "%.*s", UT_LINESIZE,
			    who.ut_line);
			snprintf(host, sizeof(host), "%.*s", UT_HOSTSIZE,
			    who.ut_host);
			facts_string(&v[LOGIN_USER], name);
			facts_string(&v[LOGIN_LINE], line);
			facts_time(&v[LOGIN_TIME], who.ut_time, 0);
			facts_string(&v[LOGIN_HOST], host);
			r = facts_record(o, &kind_login, v);
		}
	}

	if (fd != utmpfd)
		close(fd);
	return r;
}
