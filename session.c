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
 * for its sessions through the rest, a request at a time, and plans
 * their commits, which system runs.
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

#if PLAN_CLEARS != MAXCLEARS
#error "PLAN_CLEARS is not MAXCLEARS"
#endif

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

static int plan_text(struct plan *, int, struct cnode *);
static int plan_script(struct plan *, struct cnode *, struct cnode *);

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

	if ((t = conftree_mem(text, len, "the running configuration",
	    conf_mode, conf_ordered)) == NULL)
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

/*
 * A commit of s's candidate, into *pp, checked, as commit check says it
 * when checking, which plans nothing: as a handler returns, -1 when the
 * candidate may not become the running configuration or no plan could
 * be made, said why
 */
int
session_plan(struct session_state *s, int checking, struct plan **pp)
{
	struct plan *p;
	struct cnode *t;
	int r = -1;

	*pp = NULL;
	if ((p = calloc(1, sizeof(*p))) == NULL) {
		printf("%% session_plan: %s\n", strerror(errno));
		return -1;
	}
	session_enter(s);
	if ((t = cand_tree()) == NULL)
		goto done;
	if ((p->want = conftree_copy(t)) == NULL) {
		printf("%% session_plan: %s\n", strerror(errno));
		goto done;
	}
	if ((p->was = running_tree()) == NULL ||
	    commit_checks(p->was, p->want, checking) == -1)
		goto done;
	if (!checking) {
		p->same = conftree_compare(NULL, p->was, p->want) == 0;
		if (!p->same && (plan_text(p, PLAN_BEFORE, p->was) == -1 ||
		    plan_text(p, PLAN_WANT, p->want) == -1 ||
		    plan_script(p, p->was, p->want) == -1))
			goto done;
		*pp = p;
		p = NULL;
	}
	r = 0;
done:
	session_leave(s);
	plan_free(p);
	return r;
}

/*
 * Does the running configuration, the last snapshot's, read as p's
 * candidate, and no line of the script failed? 0 if so; else what did
 * not take is said, and p's script is the one back to how it was: 1, or
 * -1 if it could not be made, said why
 */
int
session_verify(struct plan *p, int failed)
{
	struct cnode *now;
	int r = -1;

	if ((now = running_tree()) == NULL)
		return -1;
	if (!failed && commit_took(now, p->want)) {
		conftree_free(now);
		return 0;
	}
	commit_untaken(now, p->want, failed);
	conftree_free(now);
	/* differ() took from now: the script is from all of it */
	if ((now = running_tree()) != NULL &&
	    plan_script(p, now, p->was) == 0)
		r = 1;
	conftree_free(now);
	return r;
}

/*
 * Whether the running configuration, the last snapshot's, is as it was
 * before p ran: 0 if so, said
 */
int
session_verify_back(struct plan *p)
{
	struct cnode *back;
	int r;

	if ((back = running_tree()) == NULL)
		return -1;
	r = commit_back(back, p->was);
	conftree_free(back);
	return r;
}

void
plan_free(struct plan *p)
{
	int i;

	if (p == NULL)
		return;
	for (i = 0; i < PLAN_PARTS; i++)
		free(p->text[i]);
	conftree_free(p->was);
	conftree_free(p->want);
	free(p);
}

/* The tree t, as text, as p's part */
static int
plan_text(struct plan *p, int part, struct cnode *t)
{
	FILE *f;
	int r;

	if ((f = open_memstream(&p->text[part], &p->len[part])) == NULL) {
		printf("%% session_plan: %s\n", strerror(errno));
		return -1;
	}
	r = conftree_write(f, t);
	if (fclose(f) == EOF)
		r = -1;
	if (r == -1)
		printf("%% session_plan: %s\n", strerror(errno));
	return r;
}

/* The script that makes from read as to, as p's */
static int
plan_script(struct plan *p, struct cnode *from, struct cnode *to)
{
	struct script sc;
	int i;

	free(p->text[PLAN_SCRIPT]);
	p->text[PLAN_SCRIPT] = NULL;
	p->len[PLAN_SCRIPT] = 0;
	if (script_make(from, to, &sc) == -1)
		return -1;
	p->text[PLAN_SCRIPT] = sc.text;
	p->len[PLAN_SCRIPT] = sc.len;
	for (i = 0; i < sc.nclears; i++) {
		strlcpy(p->clears[i].name, sc.clears[i].name,
		    sizeof(p->clears[i].name));
		p->clears[i].rtable = sc.clears[i].rtable;
		p->clears[i].keep = sc.clears[i].keep;
	}
	p->nclears = sc.nclears;
	return 0;
}

/* A new candidate for s, from the running configuration */
int
session_renew(struct session_state *s)
{
	int r;

	session_enter(s);
	cand_end();
	r = cand_begin();
	session_leave(s);
	return r;
}

/*
 * rollback n, in s: the candidate starts over as text, configuration n
 * as it was saved, or as the running configuration if n is 0
 */
int
session_rollback(struct session_state *s, char *text, size_t len, int n)
{
	struct cnode *base = NULL;
	char what[32];
	int r;

	snprintf(what, sizeof(what), "rollback %d", n);
	if (n > 0 && (base = conftree_mem(text, len, what, conf_mode,
	    conf_ordered)) == NULL)
		return -1;
	session_enter(s);
	r = cand_restart(base, n);
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
