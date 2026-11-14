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
 * Stand-ins for what nsh's main.c, loop.c and client.c define; nshd
 * builds none of them
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdio.h>
#include "editing.h"
#include "stringlist.h"
#include "externs.h"
#include "facts.h"
#include "showfacts.h"

char *vers = NSH_VERSION_STR;
int bridge, verbose, cli_rtable;
int config_mode;
pid_t pid;

char *cursor_pos;

/* nshd shows no manual */
struct ghs mantab[] = {
	{ NULL, NULL, NULL, NULL, 0 }
};

/* nshd does not ask itself, and is not a session of its own */
int
nshd_facts(int rw, char *words, struct facts_in *in)
{
	return -1;
}

int
nshd_op(const char *text, int rtable, struct facts_in *in)
{
	return 1;
}

void
nshd_why(void)
{
}

/* configure here is config's own, never nshd's session */
int nshd_config, nshd_rtable;

/* system runs what nsh's code names, as root; config runs none */
int
nshd_runs(const char *cmd)
{
	return 1;
}

