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
 * Sessions, each running with its own state: session_enter() puts a
 * session's globals in place, and session_leave() keeps them and puts
 * back the process's, as they were before any session, so nothing of
 * one session is seen by another. nshd's config runs configure private
 * for its sessions through the rest, a request at a time.
 */
#include <sys/param.h>	/* MAXHOSTNAMELEN */
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "externs.h"
#include "commands.h"
#include "ctl.h"
#include "conftree.h"
#include "session.h"

int in_config;		/* nshd's config: no kernel, file or program its own */

extern struct sglobal candidate_sglobals[], commands_sglobals[];
extern struct sglobal ctl_sglobals[], if_sglobals[];

/* main.c's, makeargv.c's, prompt.c's and bgpcommands.c's */
static struct sglobal session_sglobals[] = {
	SGLOBAL(priv), SGLOBAL(cli_rtable), SGLOBAL(config_mode),
	SGLOBAL(bridge), SGLOBAL(verbose),
	SGLOBAL(line), SGLOBAL(saveline), SGLOBAL(margc), SGLOBAL(margv),
	SGLOBAL(cursor_argc), SGLOBAL(cursor_argo),
	SGLOBAL(prompt), SGLOBAL(saved_prompt),
	SGLOBAL(bgpd_socket_path),
	{ NULL }
};

static struct sglobal *sglobals[] = {
	session_sglobals, candidate_sglobals, commands_sglobals,
	ctl_sglobals, if_sglobals
};

struct session_state {
	unsigned char	*mem;	/* each global's bytes, in sglobals' order */
};

/* the globals as the process had them before the first session */
static unsigned char *fresh;
static size_t total;

/* The globals into mem if out, else mem into the globals */
static void
copy(unsigned char *mem, int out)
{
	struct sglobal *g;
	size_t i;

	for (i = 0; i < nitems(sglobals); i++)
		for (g = sglobals[i]; g->name != NULL; g++) {
			if (out)
				memcpy(mem, g->addr, g->size);
			else
				memcpy(g->addr, mem, g->size);
			mem += g->size;
		}
}

/* A new session, as the process was before the first: NULL, errno set */
struct session_state *
session_new(void)
{
	struct session_state *s;
	const struct sglobal *g;
	size_t i;

	if (fresh == NULL) {
		for (i = 0; (g = session_global(i)) != NULL; i++)
			total += g->size;
		if ((fresh = malloc(total)) == NULL)
			return NULL;
		copy(fresh, 1);
	}
	if ((s = calloc(1, sizeof(*s))) == NULL)
		return NULL;
	if ((s->mem = malloc(total)) == NULL) {
		free(s);
		return NULL;
	}
	memcpy(s->mem, fresh, total);
	return s;
}

/* Drop s, and what its candidate and rules file hold */
void
session_free(struct session_state *s)
{
	if (s == NULL)
		return;
	session_enter(s);
	cand_end();
	ctl_rules_done();
	session_leave(s);
	free(s->mem);
	free(s);
}

void
session_enter(struct session_state *s)
{
	copy(s->mem, 0);
}

void
session_leave(struct session_state *s)
{
	copy(s->mem, 1);
	copy(fresh, 0);
}

/*
 * The running configuration, text as system's snapshot has it, which
 * running_tree() gives from now on: -1 if it could not be read, said why
 */
int
session_running(char *text, size_t len)
{
	struct cnode *t;
	FILE *f;

	if ((f = fmemopen(len > 0 ? text : "\n", len > 0 ? len : 1,
	    "r")) == NULL) {
		printf("%% session_running: %s\n", strerror(errno));
		return -1;
	}
	t = conftree_fread(f, "the running configuration", conf_mode,
	    conf_ordered);
	fclose(f);
	if (t == NULL)
		return -1;
	running_set(t);
	return 0;
}

/* configure private, in s, privileged: as a handler returns */
int
session_configure(struct session_state *s)
{
	int r;

	session_enter(s);
	priv = 1;
	if ((r = cand_begin()) == 0)
		config_mode = 1;
	session_leave(s);
	return r;
}

/* A line of configure private's, in s, as cmdline() runs it */
int
session_line(struct session_state *s, char *line)
{
	int r;

	session_enter(s);
	r = cmdline(line);
	session_leave(s);
	return r;
}

/* Leave configure private, in s, from any mode */
int
session_exit(struct session_state *s)
{
	int r = 0;

	session_enter(s);
	if (config_mode)
		r = cmdexit();
	session_leave(s);
	return r;
}

/*
 * s's mode: whether in configure private, the rtable its lines are for,
 * and the interface whose mode it is in, or "", and whether a bridge
 */
void
session_mode(struct session_state *s, int *private, int *rtable,
    char *ifn, size_t len, int *isbridge)
{
	session_enter(s);
	*private = config_mode && candidate;
	*rtable = cand_rtable;
	strlcpy(ifn, ifname, len);
	*isbridge = bridge;
	session_leave(s);
}

/* show candidate-config, in s, to stdout */
int
session_candidate(struct session_state *s)
{
	int r;

	session_enter(s);
	r = cand_write(stdout);
	session_leave(s);
	return r;
}

/* The nth global a session keeps, or NULL */
const struct sglobal *
session_global(size_t n)
{
	struct sglobal *g;
	size_t i;

	for (i = 0; i < nitems(sglobals); i++)
		for (g = sglobals[i]; g->name != NULL; g++)
			if (n-- == 0)
				return g;
	return NULL;
}
