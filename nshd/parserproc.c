/*
 * Copyright (c) 2026 Chris Cappuccio <chris@nmedia.net>
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

/*
 * The parser reads text for system, so that system need not. system
 * runs a new one for each check (systemproc.c's JOB_PARSE): this program
 * again, with -P, which becomes NSHD_PARSE_USER in a chroot(2) and
 * pledges only stdio before it reads anything. Its standard input holds
 * the request, struct nshd_parse, and the text after it. What it prints
 * on its standard output, system passes on to the session. It exits 0
 * if what it checked may run, 1 if not, and 2 if it could not check. It
 * keeps nothing: the next check is another process.
 *
 * It checks what a session without admin commits, against the running
 * configuration (ctl.c's and passwd.c's admin checks): a commit's
 * script, before system begins the commit, and a daemon's rules, before
 * system runs their test.
 */

#include <sys/types.h>
#include <sys/queue.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "externs.h"

static int	parser_read(void *, size_t);

/* d and v as child_start() takes them: nsh's externs.h has a verbose */
__dead void
parserproc(int d, int v)
{
	struct nshd_parse	 p;
	struct script		 sc;
	char			*before = NULL, *text = NULL;
	int			 i, r;

	log_init(d, LOG_DAEMON);
	log_setverbose(v);
	log_procinit("parser");
	setproctitle("parser");
	privdrop(PROC_PARSER);
	if (pledge("stdio", NULL) == -1)
		fatal("pledge");

	if (parser_read(&p, sizeof(p)) == -1 ||
	    p.beforelen > NSHD_PART || p.len > NSHD_PART ||
	    p.apply.nclears < 0 || p.apply.nclears > NSHD_CLEARS ||
	    (before = malloc(p.beforelen + 1)) == NULL ||
	    (text = malloc(p.len + 1)) == NULL ||
	    parser_read(before, p.beforelen) == -1 ||
	    parser_read(text, p.len) == -1) {
		printf("%% nshd: the parser could not read what to check\n");
		fflush(stdout);
		_exit(2);
	}
	before[p.beforelen] = text[p.len] = '\0';
	p.daemon[sizeof(p.daemon) - 1] = '\0';
	/* the script, as the commit's job would run it */
	memset(&sc, 0, sizeof(sc));
	sc.edits = text;
	sc.elen = p.len;
	for (i = 0; i < p.apply.nclears; i++)
		strlcpy(sc.clears[i].name, p.apply.clears[i].name,
		    sizeof(sc.clears[i].name));
	sc.nclears = p.apply.nclears;

	admin_begin(1, before, p.beforelen);
	switch (p.kind) {
	case NSHD_PARSE_SCRIPT:
		r = edits_admin(&sc) == 0 ? 0 : 1;
		break;
	case NSHD_PARSE_RULES:
		r = admin_test(p.daemon, text, p.len) == 0 ? 0 : 1;
		break;
	default:
		printf("%% nshd: the parser has no check %d\n", p.kind);
		r = 2;
	}
	fflush(stdout);
	_exit(r);
}

/* len bytes of standard input into buf: 0, or -1 if it ended first */
static int
parser_read(void *buf, size_t len)
{
	size_t	 got = 0;
	ssize_t	 n;

	while (got < len) {
		if ((n = read(STDIN_FILENO, (char *)buf + got,
		    len - got)) == -1 && errno == EINTR)
			continue;
		if (n <= 0)
			return (-1);
		got += n;
	}
	return (0);
}
