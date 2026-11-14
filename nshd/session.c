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
 * Sessions, each with its own state: a struct cand, its candidate and
 * its mode, which nshd's config passes to what runs the session's
 * request. So no session sees another's state, except a candidate that
 * sessions share. config uses this file to run configure private, and
 * configure, whose sessions share one candidate, a request at a time,
 * and plans their commits, which system runs.
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
#include "facts.h"
#include "session.h"

#if PLAN_CLEARS != MAXCLEARS
#error "PLAN_CLEARS is not MAXCLEARS"
#endif

static int plan_text(struct plan *, int, struct cnode *);
static int plan_script(struct plan *, struct cnode *, struct cnode *);

/* A new session, outside configure, or NULL with errno set */
struct cand *
session_new(void)
{
	struct cand *s;

	if ((s = calloc(1, sizeof(*s))) == NULL)
		return NULL;
	if ((s->own = cand_new()) == NULL) {
		free(s);
		return NULL;
	}
	s->cur = s->own;
	return s;
}

/* Free s, and its candidate if it is its own */
void
session_free(struct cand *s)
{
	if (s == NULL)
		return;
	if (cand_attached(s))
		cand_detach(s);
	cand_end(s);
	free(s->own);
	free(s);
}

/*
 * The running configuration that running_tree() gives from now on: text,
 * as system's snapshot has it. -1 if it could not be read, after saying
 * why
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

/*
 * configure private in s, or with sh, configure, on sh, the candidate
 * that sessions share: as a handler returns
 */
int
session_configure(struct cand *s, struct cand_state *sh)
{
	if (sh != NULL && !s->on)
		cand_attach(s, sh);
	return cand_begin(s);
}

/* A configuration line, in s, as cmdline() runs it */
int
session_line(struct cand *s, char *line)
{
	return cmdline(line, s);
}

/*
 * A daemon's rules in rtable, in s's candidate: printed, or with set,
 * replaced by the lines of text, as ctl_cand_rules() does
 */
int
session_rules(struct cand *s, char *daemon, int rtable, int set,
    char *text, size_t len)
{
	return ctl_cand_rules(daemon, rtable, set, text, len, s);
}

/*
 * Send nsh's command tables to o as facts, for a client that completes
 * lines itself.  Each row of cmdtab (table 0), Intlist (1), Bridgelist
 * (2) and of every table a row points to becomes one record.  Tables are
 * numbered in the order they are found.  A record holds the row's name,
 * help, completion hints, the number of the table under it, in the
 * first three tables nocmd, and how the row runs outside configure and
 * in it, where row_runs() says.  Some tables do not start with the fields
 * of struct ghs, as their row size shows; their rows get only a name and
 * help, because completion does not look further into them.
 */
static const struct facts_field rowfields[] = {
	{ "table",	FACT_U64 },
	{ "name",	FACT_STRING },
	{ "help",	FACT_STRING },
	{ "complete",	FACT_STRING },
	{ "sub",	FACT_U64 },
	{ "nocmd",	FACT_U64 },
	{ "out",	FACT_U64 },
	{ "conf",	FACT_U64 },
};
static const struct facts_kind kind_row = { "row", rowfields,
	nitems(rowfields) };

int
cmplt_facts(struct facts_out *o)
{
	struct facts_value v[nitems(rowfields)];
	struct { char **rows; size_t stlen; } *t, *nt;
	struct ghs *g;
	char **c;
	size_t i, j, n = 3, max = 16;
	int r = 0, out, conf;

	if ((t = calloc(max, sizeof(*t))) == NULL)
		return -1;
	t[0].rows = (char **)cmdtab;
	t[0].stlen = sizeof(Command);
	t[1].rows = (char **)Intlist;
	t[2].rows = (char **)Bridgelist;
	t[1].stlen = t[2].stlen = sizeof(struct intlist);
	for (i = 0; i < n && r == 0; i++)
		for (c = t[i].rows; *c != NULL && r == 0;
		    c = (char **)((char *)c + t[i].stlen)) {
			g = (struct ghs *)c;
			memset(v, 0, sizeof(v));
			facts_u64(&v[0], i);
			facts_string(&v[1], g->name);
			if (g->help != NULL)
				facts_string(&v[2], g->help);
			if (i == 0)
				facts_u64(&v[5], ((Command *)c)->nocmd);
			else if (i < 3)
				facts_u64(&v[5], ((struct intlist *)c)->nocmd);
			row_runs(t[i].rows, t[i].stlen, (char *)c, &out, &conf);
			if (out != 0)
				facts_u64(&v[6], out);
			if (conf != 0)
				facts_u64(&v[7], conf);
			if (t[i].stlen != sizeof(struct ghs) &&
			    t[i].stlen != sizeof(Menu) &&
			    t[i].stlen != sizeof(Command) &&
			    t[i].stlen != sizeof(struct intlist)) {
				r = facts_record(o, &kind_row, v);
				continue;
			}
			facts_string(&v[3], g->complete);
			if (g->table != NULL) {
				for (j = 0; j < n && t[j].rows != g->table; j++)
					;
				if (j == n && n == max) {
					if ((nt = reallocarray(t, max * 2,
					    sizeof(*t))) == NULL) {
						r = -1;
						break;
					}
					t = nt;
					max *= 2;
				}
				if (j == n) {
					t[n].rows = g->table;
					t[n++].stlen = g->stlen;
				}
				facts_u64(&v[4], j);
			}
			r = facts_record(o, &kind_row, v);
		}
	free(t);
	return r;
}

/* Leave configure, in s, from any of its modes */
int
session_exit(struct cand *s)
{
	return cmdexit(s);
}

/*
 * s's mode: whether in configure, private or not, the rtable its lines
 * are for, the interface whose mode it is in, or "", and whether that
 * is a bridge
 */
void
session_mode(struct cand *s, int *in, int *rtable,
    char *ifn, size_t len, int *isbridge)
{
	*in = s->on;
	*rtable = s->rtable;
	strlcpy(ifn, s->ifname, len);
	*isbridge = s->bridge;
}

/*
 * show diff-config, in s, to stdout: how its candidate differs from the
 * running configuration, nothing if it does not
 */
int
session_diff(struct cand *s)
{
	struct cnode *old, *new;
	char *buf = NULL;
	size_t len = 0;
	FILE *f;
	int n = -1;

	if (!s->on) {
		printf("%% Not in configure\n");
		goto done;
	}
	if ((f = open_memstream(&buf, &len)) == NULL) {
		printf("%% session_diff: %s\n", strerror(errno));
		goto done;
	}
	if ((old = running_tree()) != NULL && (new = cand_tree(s)) != NULL)
		n = conftree_compare(f, old, new);
	conftree_free(old);
	if (fclose(f) == EOF) {
		printf("%% session_diff: %s\n", strerror(errno));
		n = -1;
	}
	if (n > 0)
		printf("--- running-config\n+++ candidate-config\n%s", buf);
done:
	free(buf);
	return n == -1 ? -1 : 0;
}

/* show candidate-config, in s, to stdout */
int
session_candidate(struct cand *s)
{
	return cand_write(s, stdout);
}

/*
 * Check s's candidate as commit check does and, unless checking, plan
 * its commit into *pp: as a handler returns, -1 when the candidate may
 * not become the running configuration or no plan could be made, after
 * saying why. Daemons' tests of rules are the plan's, which system
 * runs, and the verdict waits on them; with them, a plan is made when
 * checking too. A commit confirmed records the running configuration
 * and the candidate even if they are the same. A commit is refused once
 * if another commit has since changed what its candidate changes
 * (cand_conflicts())
 */
int
session_plan(struct cand *s, int checking, int confirmed,
    struct plan **pp)
{
	struct plan *p;
	struct cnode *t;
	int n, r = -1;

	*pp = NULL;
	if ((p = calloc(1, sizeof(*p))) == NULL) {
		printf("%% session_plan: %s\n", strerror(errno));
		return -1;
	}
	if ((t = cand_tree(s)) == NULL)
		goto done;
	if ((p->want = conftree_copy(t)) == NULL) {
		printf("%% session_plan: %s\n", strerror(errno));
		goto done;
	}
	if ((p->was = running_tree()) == NULL)
		goto done;
	if (!checking && (n = cand_conflicts(s, p->was, 1)) != 0) {
		if (n > 0)
			printf("%% Commit refused: %d statement%s changed by "
			    "another commit. Commit again to keep this "
			    "candidate's changes over %s\n", n,
			    n == 1 ? "" : "s", n == 1 ? "it" : "them");
		goto done;
	}
	p->bad = commit_problems(p->was, p->want);
	p->ntests = commit_deferred(&p->tests);
	p->checking = checking;
	p->same = conftree_compare(NULL, p->was, p->want) == 0;
	/* lines that are not configuration have no edits: a problem */
	if ((!p->same || confirmed) && plan_script(p, p->was, p->want) == -1)
		p->bad++;
	if (p->ntests == 0 && commit_verdict(p->bad, checking) == -1)
		goto done;
	if (!checking && (!p->same || confirmed) &&
	    (plan_text(p, PLAN_BEFORE, p->was) == -1 ||
	    plan_text(p, PLAN_WANT, p->want) == -1))
		goto done;
	if (!checking || p->ntests > 0) {
		*pp = p;
		p = NULL;
	}
	r = 0;
done:
	plan_free(p);
	return r;
}

/* p's nth test, if failed, refused its rules: say so */
void
session_tested(struct plan *p, int n, int failed)
{
	if (failed)
		commit_refused_by(p->tests[n].label, p->tests[n].name);
}

/* Whether p changes login users or classes */
int
session_logins(struct plan *p)
{
	return logins_differ(p->want, p->was);
}

/*
 * The boot's plan: the running configuration, the last snapshot's, made
 * to read as text, the saved configuration, as far as it succeeds. What
 * check finds is printed, and the daemons' tests of rules are the
 * plan's, but neither keeps it from running: -1 if it could not be
 * made, after saying why
 */
int
session_boot_plan(char *text, size_t len, struct plan **pp)
{
	struct plan *p;

	*pp = NULL;
	if ((p = calloc(1, sizeof(*p))) == NULL) {
		printf("%% session_boot_plan: %s\n", strerror(errno));
		return -1;
	}
	if ((p->want = conftree_mem(text, len, "the saved configuration",
	    conf_mode, conf_ordered)) == NULL ||
	    (p->was = running_tree()) == NULL) {
		plan_free(p);
		return -1;
	}
	p->bad = commit_problems(p->was, p->want);
	p->ntests = commit_deferred(&p->tests);
	p->same = conftree_compare(NULL, p->was, p->want) == 0;
	p->boot = 1;
	if (!p->same && plan_script(p, p->was, p->want) == -1) {
		plan_free(p);
		return -1;
	}
	*pp = p;
	return 0;
}

void
plan_free(struct plan *p)
{
	int i;

	if (p == NULL)
		return;
	for (i = 0; i < PLAN_PARTS; i++)
		free(p->text[i]);
	for (i = 0; i < p->ntests; i++) {
		free(p->tests[i].label);
		free(p->tests[i].text);
	}
	free(p->tests);
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

/* The edits of the script that makes from read as to, as p's */
static int
plan_script(struct plan *p, struct cnode *from, struct cnode *to)
{
	struct script sc;
	int i;

	free(p->text[PLAN_EDITS]);
	p->text[PLAN_EDITS] = NULL;
	p->len[PLAN_EDITS] = 0;
	if (script_make(from, to, &sc, p->boot) == -1)
		return -1;
	free(sc.text);
	p->text[PLAN_EDITS] = sc.edits;
	p->len[PLAN_EDITS] = sc.elen;
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
session_renew(struct cand *s)
{
	cand_end(s);
	return cand_begin(s);
}

/*
 * text, nsh -c's configuration, as s's candidate in place of what it
 * was, as rollback N takes a saved one; an empty one changes nothing.
 * -1 if it could not, after saying why, else 0
 */
int
session_load(struct cand *s, char *text, size_t len)
{
	struct cnode *t;

	if (len == 0)
		return 0;
	if ((t = conftree_mem(text, len, "the configuration loaded",
	    conf_mode, conf_ordered)) == NULL)
		return -1;
	return cand_restart(s, t, -1);
}

/* Whether s's candidate differs from how it began */
int
session_changed(struct cand *s)
{
	return cand_changed(s);
}

/*
 * rollback n, in s: the candidate starts over as text, configuration n
 * as it was saved, or as the running configuration if n is 0
 */
int
session_rollback(struct cand *s, char *text, size_t len, int n)
{
	struct cnode *base = NULL;
	char what[32];

	snprintf(what, sizeof(what), "rollback %d", n);
	if (n > 0 && (base = conftree_mem(text, len, what, conf_mode,
	    conf_ordered)) == NULL)
		return -1;
	return cand_restart(s, base, n);
}
