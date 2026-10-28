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
 * Completion in session: nsh's own complete_line() (complete.c), run on
 * nsh's command tables as nshd sends them.  session asks for the tables
 * once and keeps them, and asks for the names of interfaces, groups,
 * bridges and routing tables on each completion.  This file also
 * defines the globals of nsh's that complete.c reads.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#include <event.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "nshd.h"
#include "facts.h"
#include "nshdeck.h"
#include "editing.h"
#include "stringlist.h"
#include "externs.h"
#include "kfacts.h"

#define DECK_ROWS	512	/* most rows in cmdtab, Intlist or Bridgelist */
#define DECK_TABLES	1024	/* most tables */

/* nsh's tables, filled from what nshd sends */
Command		 cmdtab[DECK_ROWS];
size_t		 cmdtab_nitems;
struct intlist	 Intlist[DECK_ROWS];
struct intlist	 Bridgelist[DECK_ROWS];
size_t		 Intlist_nitems;
size_t		 Bridgelist_nitems;
struct intlist	*whichlist;
int		 bridge;
char		*cursor_pos;		/* read by makeargv() */

static int		 built;		/* the tables are built */
static StringList	**names;	/* names for kf_names(), or NULL */

/* the records nshd sends, as session.c and configproc.c define them */
static const struct facts_field rowfields[] = {
	{ "table",	FACT_U64 },
	{ "name",	FACT_STRING },
	{ "help",	FACT_STRING },
	{ "complete",	FACT_STRING },
	{ "sub",	FACT_U64 },
	{ "nocmd",	FACT_U64 },
};
static const struct facts_kind kind_row = { "row", rowfields,
	sizeof(rowfields) / sizeof(rowfields[0]) };
static const struct facts_field namefields[] = {
	{ "of",		FACT_STRING },
	{ "name",	FACT_STRING },
};
static const struct facts_kind kind_name = { "name", namefields,
	sizeof(namefields) / sizeof(namefields[0]) };
static const char	*of[] = { "interface", "group", "bridge", "rtable" };

/* the rows and names nshd sent for a completion */
struct deck_cmplt {
	struct row {
		uint64_t	 table;
		char		*name;
		char		*help;
		char		*complete;
		int64_t		 sub;		/* the table under it, or -1 */
		int		 nocmd;
	}		*rows;
	size_t		 nrows;
	StringList	*names[4];		/* KF_* */
};

struct deck_cmplt *
deck_cmplt_new(void)
{
	struct deck_cmplt	*c;
	int			 i;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		fatal("%s", __func__);
	for (i = 0; i < 4; i++)
		if ((c->names[i] = sl_init()) == NULL)
			fatal("%s", __func__);
	return (c);
}

void
deck_cmplt_free(struct deck_cmplt *c)
{
	size_t	i;

	if (c == NULL)
		return;
	for (i = 0; i < c->nrows; i++) {
		free(c->rows[i].name);
		free(c->rows[i].help);
		free(c->rows[i].complete);
	}
	free(c->rows);
	for (i = 0; i < 4; i++)
		sl_free(c->names[i], 1);
	free(c);
}

/* Return a copy of the string v, or NULL if v is absent. */
static char *
copy(const struct facts_value *v)
{
	char	*s;

	if (v == NULL)
		return (NULL);
	if ((s = facts_strdup(v)) == NULL)
		fatal("%s", __func__);
	return (s);
}

/* Keep a row or a name nshd sent, in the deck_cmplt arg. */
void
deck_cmplt_record(void *arg, const struct facts_template *t,
    const struct facts_value *v)
{
	struct deck_cmplt		*c = arg;
	struct row			*r;
	const struct facts_value	*f;
	int				 idx[6], i;

	if (strcmp(t->kind, kind_row.name) == 0) {
		facts_bind(t, &kind_row, idx);
		if ((r = reallocarray(c->rows, c->nrows + 1,
		    sizeof(*r))) == NULL)
			fatal("%s", __func__);
		c->rows = r;
		r = &c->rows[c->nrows++];
		memset(r, 0, sizeof(*r));
		f = facts_get(v, idx, 0, FACT_U64);
		r->table = f != NULL ? f->v.u : DECK_TABLES;
		r->name = copy(facts_get(v, idx, 1, FACT_STRING));
		r->help = copy(facts_get(v, idx, 2, FACT_STRING));
		r->complete = copy(facts_get(v, idx, 3, FACT_STRING));
		f = facts_get(v, idx, 4, FACT_U64);
		r->sub = f != NULL ? (int64_t)f->v.u : -1;
		f = facts_get(v, idx, 5, FACT_U64);
		r->nocmd = f != NULL && f->v.u != 0;
	} else if (strcmp(t->kind, kind_name.name) == 0) {
		facts_bind(t, &kind_name, idx);
		if ((f = facts_get(v, idx, 0, FACT_STRING)) == NULL)
			return;
		for (i = 0; i < 4; i++)
			if (strlen(of[i]) == f->v.str.len &&
			    memcmp(of[i], f->v.str.s, f->v.str.len) == 0)
				break;
		if (i < 4 && (f = facts_get(v, idx, 1, FACT_STRING)) != NULL)
			sl_add(c->names[i], copy(f));
	}
}

int
deck_tables_ready(void)
{
	return (built);
}

/*
 * Build nsh's tables from c's rows, unless they are built already.  The
 * rows keep the order they came in, and each table ends with a row of
 * zeros, as nsh's do.  The strings move from c into the tables.  Return
 * 0, or -1 if the rows do not form tables.
 */
int
deck_tables(struct deck_cmplt *c)
{
	struct ghs	**subs, *g;
	size_t		 ntables = 3, *n, i, t;
	char		**table;
	int		 stlen;

	if (built)
		return (0);
	for (i = 0; i < c->nrows; i++) {
		if (c->rows[i].table >= DECK_TABLES ||
		    c->rows[i].sub >= DECK_TABLES || c->rows[i].name == NULL)
			return (-1);
		if (c->rows[i].table >= ntables)
			ntables = c->rows[i].table + 1;
		if (c->rows[i].sub >= (int64_t)ntables)
			ntables = c->rows[i].sub + 1;
	}
	if ((n = calloc(ntables, sizeof(*n))) == NULL ||
	    (subs = calloc(ntables, sizeof(*subs))) == NULL)
		fatal("%s", __func__);
	for (i = 0; i < c->nrows; i++)
		n[c->rows[i].table]++;
	if (n[0] >= DECK_ROWS || n[1] >= DECK_ROWS || n[2] >= DECK_ROWS) {
		free(n);
		free(subs);
		return (-1);
	}
	for (t = 3; t < ntables; t++)
		if ((subs[t] = calloc(n[t] + 1, sizeof(struct ghs))) == NULL)
			fatal("%s", __func__);
	cmdtab_nitems = n[0] + 1;
	Intlist_nitems = n[1] + 1;
	Bridgelist_nitems = n[2] + 1;
	memset(n, 0, ntables * sizeof(*n));
	for (i = 0; i < c->nrows; i++) {
		t = c->rows[i].table;
		if (t == 0)
			g = (struct ghs *)&cmdtab[n[t]++];
		else if (t < 3)
			g = (struct ghs *)&(t == 1 ? Intlist :
			    Bridgelist)[n[t]++];
		else
			g = &subs[t][n[t]++];
		table = NULL;
		stlen = 0;
		if (c->rows[i].sub == 0) {
			table = (char **)cmdtab;
			stlen = sizeof(Command);
		} else if (c->rows[i].sub == 1 || c->rows[i].sub == 2) {
			table = (char **)(c->rows[i].sub == 1 ? Intlist :
			    Bridgelist);
			stlen = sizeof(struct intlist);
		} else if (c->rows[i].sub > 2) {
			table = (char **)subs[c->rows[i].sub];
			stlen = sizeof(struct ghs);
		}
		/* the tables own the strings now */
		g->name = c->rows[i].name;
		g->help = c->rows[i].help;
		g->complete = c->rows[i].complete != NULL ?
		    c->rows[i].complete : strdup("");
		if (g->complete == NULL)
			fatal("%s", __func__);
		g->table = table;
		g->stlen = stlen;
		if (t == 0)
			cmdtab[n[t] - 1].nocmd = c->rows[i].nocmd;
		else if (t < 3)
			(t == 1 ? Intlist : Bridgelist)[n[t] - 1].nocmd =
			    c->rows[i].nocmd;
		c->rows[i].name = c->rows[i].help = NULL;
		c->rows[i].complete = NULL;
	}
	free(n);
	free(subs);
	built = 1;
	return (0);
}

/*
 * Complete text at its end, in the mode ctx gives, with c's names, as
 * Tab does in nsh; with help, list every choice instead.  Pass each
 * result to found: text to insert (insert 1), or a choice and its help,
 * if it has one.
 */
void
deck_complete(struct deck_cmplt *c, const char *text, int help,
    const struct nshd_context *ctx,
    void (*found)(void *, int, const char *, const char *), void *arg)
{
	char		 word[CMPLT_WORD] = "", *w;
	struct cmplt	 cp;
	size_t		 len = strlen(text);
	int		 i;

	names = c->names;
	cmplt_remote = 1;
	bridge = ctx->bridge;
	whichlist = bridge ? Bridgelist : Intlist;
	if (ctx->ifname[0] != '\0')
		complete_line(text, len, len, word, (char **)whichlist,
		    sizeof(struct intlist), help, &cp);
	else
		complete_line(text, len, len, word, (char **)cmdtab,
		    sizeof(Command), help, &cp);
	names = NULL;
	if (cp.insert[0] != '\0')
		found(arg, 1, cp.insert, NULL);
	for (i = 0; i < (int)cp.words->sl_cur; i++) {
		/* a word starting with '^' is shown as it is, without the '^' */
		w = cp.words->sl_str[i];
		found(arg, 0, w[0] == '^' ? w + 1 : w, cp.helps != NULL &&
		    cp.helps->sl_str[i][0] != '\0' ? cp.helps->sl_str[i] :
		    NULL);
	}
	cmplt_free(&cp);
}

/* kf_names() for complete.c: the names nshd sent for this completion */
int
kf_names(int kind, StringList *sl)
{
	char	*s;
	size_t	 i;

	if (names == NULL || kind < 0 || kind >= 4)
		return (-1);
	for (i = 0; i < names[kind]->sl_cur; i++) {
		if ((s = strdup(names[kind]->sl_str[i])) == NULL)
			return (-1);
		sl_add(sl, s);
	}
	return (0);
}
