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

/* What nsh's main.c has for nsh's code, and nshd does not use */

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
int bridge, verbose, priv, privexec, cli_rtable;
int editing, interactive_mode, config_mode;
pid_t pid;

History *histi, *histc;
HistEvent ev;
EditLine *elc, *eli, *elp;
char *cursor_pos;

struct hashtable *nsh_env;
volatile sig_atomic_t caught_sigwinch;

/* nshd shows no manual */
struct ghs mantab[] = {
	{ NULL, NULL, NULL, NULL, 0 }
};

void
intr(void)
{
}

/* nshd does not ask itself */
int
nshd_show(char *words)
{
	return -1;
}

int
nshd_facts(int rw, char *words, struct facts_in *in)
{
	return -1;
}
