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
 * one session is seen by another, but a candidate that sessions share. nshd's
 * config runs configure private, and configure, whose candidate its
 * sessions share, through the rest, a request at a time, and plans
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
#include "facts.h"
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
	struct cand_shared *shared;	/* the candidate it shares, or NULL */
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

/* Drop s, and what its candidate, if its own, and rules file hold */
void
session_free(struct session_state *s)
{
	if (s == NULL)
		return;
	session_enter(s);
	if (cand_sharing)
		cand_detach();
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
	if (s->shared != NULL)
		cand_share(s->shared, 1);
}

/* s's globals kept, the shared candidate left as s left it, if it shares */
void
session_leave(struct session_state *s)
{
	if (s->shared != NULL && cand_sharing)
		cand_share(s->shared, 0);
	else
		s->shared = NULL;
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

/*
 * configure private, in s, privileged, or with sh, configure, whose
 * candidate sessions share: as a handler returns
 */
int
session_configure(struct session_state *s, struct cand_shared *sh)
{
	int r;

	session_enter(s);
	if (sh != NULL && !candidate) {
		s->shared = sh;
		cand_share(sh, 1);
		cand_sharing = 1;
	}
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

/*
 * A daemon's rules in rtable, in s's candidate: printed, or with set,
 * made the lines of text, as ctl_cand_rules() does
 */
int
session_rules(struct session_state *s, char *daemon, int rtable, int set,
    char *text, size_t len)
{
	int r;

	session_enter(s);
	r = ctl_cand_rules(daemon, rtable, set, text, len);
	session_leave(s);
	return r;
}

/*
 * Send nsh's command tables to o as facts, for a client that completes
 * lines itself.  Each row of cmdtab (table 0), Intlist (1), Bridgelist
 * (2) and of every table a row points to becomes one record.  Tables are
 * numbered in the order they are found.  A record holds the row's name,
 * help, completion hints, the number of the table under it and, in the
 * first three tables, nocmd.  Some tables do not start with the fields
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
	int r = 0;

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
 * s's mode: whether in configure, private or not, the rtable its lines
 * are for, and the interface whose mode it is in, or "", and whether a
 * bridge
 */
void
session_mode(struct session_state *s, int *in, int *rtable,
    char *ifn, size_t len, int *isbridge)
{
	session_enter(s);
	*in = config_mode && candidate;
	*rtable = cand_rtable;
	strlcpy(ifn, ifname, len);
	*isbridge = bridge;
	session_leave(s);
}

/*
 * show diff-config, in s, to stdout: how its candidate differs from the
 * running configuration, nothing if it does not
 */
int
session_diff(struct session_state *s)
{
	struct cnode *old, *new;
	char *buf = NULL;
	size_t len = 0;
	FILE *f;
	int n = -1;

	session_enter(s);
	if (!candidate) {
		printf("%% Not in configure private\n");
		goto done;
	}
	if ((f = open_memstream(&buf, &len)) == NULL) {
		printf("%% session_diff: %s\n", strerror(errno));
		goto done;
	}
	if ((old = running_tree()) != NULL && (new = cand_tree()) != NULL)
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
	session_leave(s);
	return n == -1 ? -1 : 0;
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
 * be made, said why. Daemons' tests of rules are the plan's, and the
 * verdict waits on them (session_verdict()); with them, a plan is made
 * when checking too. A commit confirmed records what runs and what is
 * wanted even if they are the same. A commit is refused once if another
 * commit changed what its candidate changes since (cand_conflicts())
 */
int
session_plan(struct session_state *s, int checking, int confirmed,
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
	session_enter(s);
	if ((t = cand_tree()) == NULL)
		goto done;
	if ((p->want = conftree_copy(t)) == NULL) {
		printf("%% session_plan: %s\n", strerror(errno));
		goto done;
	}
	if ((p->was = running_tree()) == NULL)
		goto done;
	if (!checking && (n = cand_conflicts(p->was, 1)) != 0) {
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
	session_leave(s);
	plan_free(p);
	return r;
}

/* p's nth test refused its rules, if failed, a problem said */
void
session_tested(struct plan *p, int n, int failed)
{
	if (failed)
		p->bad += commit_refused_by(p->tests[n].label,
		    p->tests[n].name);
}

/* The verdict on p, its tests run, as commit_checks() says it */
int
session_verdict(struct plan *p)
{
	return commit_verdict(p->bad, p->checking);
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

/*
 * The boot's plan, as nsh -i's commit_boot() makes it: the running
 * configuration, the last snapshot's, made to read as text, the saved
 * configuration, all of it that takes. What check finds is said, and
 * the daemons' tests of rules are the plan's, but neither keeps it from
 * running: -1 if it could not be made, said why
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

/*
 * Does the running configuration, the last snapshot's, read as the
 * boot's, and no line of its script failed? 0 if so, else 1, what
 * differs said, or -1 if it could not be read
 */
int
session_boot_verify(struct plan *p, int failed)
{
	struct cnode *now;
	int r;

	if ((now = running_tree()) == NULL)
		return -1;
	r = commit_booted(now, p->want) == -1 || failed;
	conftree_free(now);
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
 * text, nsh -c's configuration, as s's candidate in place of what it
 * was, as rollback N takes a saved one; an empty one changes nothing:
 * -1 if it could not, said why, else 0
 */
int
session_load(struct session_state *s, char *text, size_t len)
{
	struct cnode *t;
	int r;

	if (len == 0)
		return 0;
	if ((t = conftree_mem(text, len, "the configuration loaded",
	    conf_mode, conf_ordered)) == NULL)
		return -1;
	session_enter(s);
	r = cand_restart(t, -1);
	session_leave(s);
	return r;
}

/* Whether s's candidate differs from how it began */
int
session_changed(struct session_state *s)
{
	int r;

	session_enter(s);
	r = cand_changed();
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
