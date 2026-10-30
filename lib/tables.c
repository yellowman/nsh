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
 * nsh's command tables as nshd sends them, for a client that completes
 * lines itself with nsh's complete_line() (complete.c): nsh, and
 * nshdeck's session.  The client asks nshd for the tables once and
 * keeps them, with how each row runs (row_runs()), and asks for the
 * names of interfaces, groups, bridges and routing tables on each
 * completion.
 * This file also defines the globals of nsh's that complete.c reads.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "facts.h"
#include "editing.h"
#include "stringlist.h"
#include "externs.h"
#include "kfacts.h"
#include "tables.h"

#define TABLE_ROWS	512	/* most rows in cmdtab, Intlist or Bridgelist */
#define TABLES		1024	/* most tables */

/* nsh's tables, filled from what nshd sends */
Command		 cmdtab[TABLE_ROWS];
size_t		 cmdtab_nitems;
struct intlist	 Intlist[TABLE_ROWS];
struct intlist	 Bridgelist[TABLE_ROWS];
size_t		 Intlist_nitems;
size_t		 Bridgelist_nitems;
struct intlist	*whichlist;
int		 bridge;
char		*cursor_pos;		/* read by makeargv() */

static int		 built;		/* the tables are built */

/* how each row of each table built runs, as nshd sent it */
static struct runs {
	char		**table;
	size_t		 stlen;
	size_t		 nrows;
	int		*out;
	int		*conf;
}			*runs;
static size_t		 nruns;

/* the records nshd sends, as session.c and configproc.c define them */
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
	sizeof(rowfields) / sizeof(rowfields[0]) };
static const struct facts_field namefields[] = {
	{ "of",		FACT_STRING },
	{ "name",	FACT_STRING },
};
static const struct facts_kind kind_name = { "name", namefields,
	sizeof(namefields) / sizeof(namefields[0]) };
static const char	*of[] = { "interface", "group", "bridge", "rtable" };

/* the rows and names nshd sent for a completion */
struct rows {
	struct row {
		uint64_t	 table;
		char		*name;
		char		*help;
		char		*complete;
		int64_t		 sub;		/* the table under it, or -1 */
		int		 nocmd;
		int		 out;		/* RUN_*, outside configure */
		int		 conf;		/* RUN_*, in configure */
	}		*rows;
	size_t		 nrows;
	StringList	*names[4];		/* KF_* */
};

struct rows *
rows_new(void)
{
	struct rows	*c;
	int		 i;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		err(1, "%s", __func__);
	for (i = 0; i < 4; i++)
		if ((c->names[i] = sl_init()) == NULL)
			err(1, "%s", __func__);
	return (c);
}

void
rows_free(struct rows *c)
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
		err(1, "%s", __func__);
	return (s);
}

/* Keep a row or a name nshd sent, in the rows arg. */
void
rows_record(void *arg, const struct facts_template *t,
    const struct facts_value *v)
{
	struct rows			*c = arg;
	struct row			*r;
	const struct facts_value	*f;
	int				 idx[8], i;

	if (strcmp(t->kind, kind_row.name) == 0) {
		facts_bind(t, &kind_row, idx);
		if ((r = reallocarray(c->rows, c->nrows + 1,
		    sizeof(*r))) == NULL)
			err(1, "%s", __func__);
		c->rows = r;
		r = &c->rows[c->nrows++];
		memset(r, 0, sizeof(*r));
		f = facts_get(v, idx, 0, FACT_U64);
		r->table = f != NULL ? f->v.u : TABLES;
		r->name = copy(facts_get(v, idx, 1, FACT_STRING));
		r->help = copy(facts_get(v, idx, 2, FACT_STRING));
		r->complete = copy(facts_get(v, idx, 3, FACT_STRING));
		f = facts_get(v, idx, 4, FACT_U64);
		r->sub = f != NULL ? (int64_t)f->v.u : -1;
		f = facts_get(v, idx, 5, FACT_U64);
		r->nocmd = f != NULL && f->v.u != 0;
		f = facts_get(v, idx, 6, FACT_U64);
		r->out = f != NULL && f->v.u <= RUN_UNSUPPORTED ? f->v.u : 0;
		f = facts_get(v, idx, 7, FACT_U64);
		r->conf = f != NULL && f->v.u <= RUN_UNSUPPORTED ? f->v.u : 0;
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
tables_ready(void)
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
tables_build(struct rows *c)
{
	struct ghs	**subs, *g;
	size_t		 ntables = 3, *n, i, t;
	char		**table;
	int		 stlen;

	if (built)
		return (0);
	for (i = 0; i < c->nrows; i++) {
		if (c->rows[i].table >= TABLES ||
		    c->rows[i].sub >= TABLES || c->rows[i].name == NULL)
			return (-1);
		if (c->rows[i].table >= ntables)
			ntables = c->rows[i].table + 1;
		if (c->rows[i].sub >= (int64_t)ntables)
			ntables = c->rows[i].sub + 1;
	}
	if ((n = calloc(ntables, sizeof(*n))) == NULL ||
	    (subs = calloc(ntables, sizeof(*subs))) == NULL)
		err(1, "%s", __func__);
	for (i = 0; i < c->nrows; i++)
		n[c->rows[i].table]++;
	if (n[0] >= TABLE_ROWS || n[1] >= TABLE_ROWS || n[2] >= TABLE_ROWS) {
		free(n);
		free(subs);
		return (-1);
	}
	for (t = 3; t < ntables; t++)
		if ((subs[t] = calloc(n[t] + 1, sizeof(struct ghs))) == NULL)
			err(1, "%s", __func__);
	if ((runs = calloc(ntables, sizeof(*runs))) == NULL)
		err(1, "%s", __func__);
	for (t = 0; t < ntables; t++) {
		if (t == 0) {
			runs[t].table = (char **)cmdtab;
			runs[t].stlen = sizeof(Command);
		} else if (t < 3) {
			runs[t].table = (char **)(t == 1 ? Intlist :
			    Bridgelist);
			runs[t].stlen = sizeof(struct intlist);
		} else {
			runs[t].table = (char **)subs[t];
			runs[t].stlen = sizeof(struct ghs);
		}
		runs[t].nrows = n[t];
		if ((runs[t].out = calloc(n[t] + 1, sizeof(int))) == NULL ||
		    (runs[t].conf = calloc(n[t] + 1, sizeof(int))) == NULL)
			err(1, "%s", __func__);
	}
	nruns = ntables;
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
			err(1, "%s", __func__);
		g->table = table;
		g->stlen = stlen;
		if (t == 0) {
			cmdtab[n[t] - 1].nocmd = c->rows[i].nocmd;
			cmdtab[n[t] - 1].needconfig =
			    c->rows[i].out == RUN_CONFIGURE;
		} else if (t < 3)
			(t == 1 ? Intlist : Bridgelist)[n[t] - 1].nocmd =
			    c->rows[i].nocmd;
		runs[t].out[n[t] - 1] = c->rows[i].out;
		runs[t].conf[n[t] - 1] = c->rows[i].conf;
		c->rows[i].name = c->rows[i].help = NULL;
		c->rows[i].complete = NULL;
	}
	free(n);
	free(subs);
	built = 1;
	return (0);
}

/*
 * How row, of table, whose rows are stlen bytes, runs outside configure
 * (*out) and in configure (*conf), as nshd sent it: RUN_*, or 0 where
 * the row of the command above it says how it runs
 */
void
row_runs(char **table, int stlen, char *row, int *out, int *conf)
{
	size_t	t, i;

	*out = *conf = 0;
	for (t = 0; t < nruns; t++) {
		if (runs[t].table != table)
			continue;
		i = (row - (char *)table) / runs[t].stlen;
		if (i < runs[t].nrows) {
			*out = runs[t].out[i];
			*conf = runs[t].conf[i];
		}
		return;
	}
}

/*
 * Complete text at its end, as Tab does in nsh: in an interface's mode
 * if inif, a bridge's if isbridge too.  With help, list every choice
 * instead.  Pass each result to found: text to insert (insert 1), or a
 * choice and its help, if it has one.
 */
void
tables_complete(const char *text, int help, int inif, int isbridge,
    void (*found)(void *, int, const char *, const char *), void *arg)
{
	char		 word[CMPLT_WORD] = "", *w;
	struct cmplt	 cp;
	size_t		 len = strlen(text);
	int		 i;

	cmplt_remote = 1;
	bridge = isbridge;
	whichlist = bridge ? Bridgelist : Intlist;
	if (inif)
		complete_line(text, len, len, word, (char **)whichlist,
		    sizeof(struct intlist), help, &cp);
	else
		complete_line(text, len, len, word, (char **)cmdtab,
		    sizeof(Command), help, &cp);
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

/*
 * Add to sl copies of c's names of kind (KF_* in kfacts.h), as
 * kf_names() does: 0, or -1
 */
int
rows_names(struct rows *c, int kind, StringList *sl)
{
	char	*s;
	size_t	 i;

	if (kind < 0 || kind >= 4)
		return (-1);
	for (i = 0; i < c->names[kind]->sl_cur; i++) {
		if ((s = strdup(c->names[kind]->sl_str[i])) == NULL)
			return (-1);
		sl_add(sl, s);
	}
	return (0);
}
