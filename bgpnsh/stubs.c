/*
 * Copyright (c) 2023 Stefan Sperling <stsp@openbsd.org>
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

/* These functions are stubbed out in bgpnsh but required for linking. */

#include "../stringlist.h"

int kf_names(int, StringList *);
int prot1_run(char *, char *, int, char **, char **);
int cmdargs(char *, char **);
int nshd_runs(const char *);
int nshd_execs(void);

int candidate;		/* bgpnsh has no configure private */
int cand_rtable;
int in_config;		/* nor is it nshd's config */
int nshd_config;	/* nor configure in nshd */
int nshd_rtable;

/* bgpnsh completes no names of interfaces, groups, bridges or rtables */
int
kf_names(int kind, StringList *sl)
{
	return -1;
}

/* bgpnsh runs a daemon's show itself, as its user: it has no nshd */
int
prot1_run(char *prot, char *sub, int argc, char **argv, char **args)
{
	return cmdargs(args[0], args) == 0 ? 0 : -1;
}

/* bgpnsh has no nshd: it runs every program as its user */
int
nshd_runs(const char *cmd)
{
	return 1;
}

int
nshd_execs(void)
{
	return 1;
}
