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
 * A configuration file as a tree of lines, and the differences between
 * two of them.
 *
 * The tree follows the grammar cmdrc() reads:
 *
 *  * A line in column 0 is a statement.  A '!' in column 0 ends its
 *    block, a '#' in column 0 is a comment, and blank lines are skipped.
 *  * The indented lines after a CT_LINES statement are its children,
 *    with one space of indentation removed.
 *  * Under a CT_NESTED statement, a line indented by one space is a
 *    statement of its own, and the lines indented by two spaces after
 *    it are its children, with two spaces removed.  " !" is skipped.
 *  * An indented line with no block to belong to is skipped, with a
 *    warning, as cmdrc() skips it.
 *
 * The children of an ordered statement (a daemon's rules) are compared
 * as a sequence.  All other children are compared as a set, so the
 * order of the lines in an interface block, or of the statements in
 * the file, makes no difference.  Lines are compared as text: two
 * spellings of one command, such as with extra spaces, are different.
 *
 * The differences are printed like the body of a unified diff: a '-'
 * or '+' in front of a line that only the old or the new tree has, and
 * a ' ' in front of the statements that contain them.  Without the
 * first column, each line reads as it does in the file.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conftree.h"

struct cnode {
	char *text;		/* the line without its indentation */
	int ordered;		/* the children are a sequence, not a set */
	struct cnode **kids;	/* the indented lines under it */
	size_t nkids;
};

#define CT_MAXDEPTH	2	/* statement, nested statement */

/* the LCS table for an ordered block, in cells */
#ifndef CT_LCSMAX
#define CT_LCSMAX	(4 * 1024 * 1024)
#endif

#define NOMATCH		((size_t)-1)

struct cmpctx {
	FILE *out;
	struct cnode *heads[CT_MAXDEPTH];	/* the blocks being compared */
	int nheads;
	int nprinted;		/* how many of heads[] are printed */
	int ndiff;
};

struct ckey {
	struct cnode *n;
	size_t i;
};

static struct cnode *cnode_add(struct cnode *, char *, int);
static int blank(char *);
static int match(struct cnode *, struct cnode *, size_t *, size_t *);
static int ckeycmp(const void *, const void *);
static int compare_block(struct cmpctx *, struct cnode *, struct cnode *);
static int compare_set(struct cmpctx *, struct cnode *, struct cnode *);
static int compare_seq(struct cmpctx *, struct cnode *, struct cnode *);
static void emit(struct cmpctx *, char, struct cnode *);
static void emit_tree(struct cmpctx *, char, int, struct cnode *);

/*
 * Read the configuration file at path. mode(statement) says what the
 * statement does with the indented lines after it, ordered(statement)
 * says whether they are a sequence.
 */
struct cnode *
conftree_read(char *path, int (*mode)(char *), int (*ordered)(char *))
{
	FILE *f;
	struct cnode *root, *top = NULL, *stmt = NULL;
	int topmode = CT_LEAF;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	unsigned int lnum = 0;

	if ((f = fopen(path, "r")) == NULL) {
		printf("%% %s: %s\n", path, strerror(errno));
		return NULL;
	}
	if ((root = calloc(1, sizeof(*root))) == NULL)
		goto fail;

	while ((linelen = getline(&line, &linesize, f)) != -1) {
		lnum++;
		if (linelen > 0 && line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';

		if (line[0] == '#')
			continue;
		if (line[0] == '!') {
			top = stmt = NULL;
			continue;
		}
		if (line[0] != ' ') {
			if (blank(line))
				continue;
			if ((top = cnode_add(root, line, ordered(line))) == NULL)
				goto fail;
			topmode = mode(line);
			stmt = NULL;
			continue;
		}

		/* an indented line */
		if (top == NULL || topmode == CT_LEAF) {
			if (!blank(line))
				printf("%% %s: line %u: indented line without"
				    " a block, skipped\n", path, lnum);
			continue;
		}
		if (topmode == CT_LINES) {
			/* in a set, a blank line does nothing */
			if (!top->ordered && blank(line))
				continue;
			if (cnode_add(top, line + 1, 0) == NULL)
				goto fail;
			continue;
		}
		if (line[1] != ' ') {
			if (line[1] == '!' || blank(line))
				continue;
			stmt = cnode_add(top, line + 1, ordered(line + 1));
			if (stmt == NULL)
				goto fail;
			continue;
		}
		if (stmt == NULL) {
			if (!blank(line))
				printf("%% %s: line %u: indented line without"
				    " a block, skipped\n", path, lnum);
			continue;
		}
		if (!stmt->ordered && blank(line))
			continue;
		if (cnode_add(stmt, line + 2, 0) == NULL)
			goto fail;
	}
	if (ferror(f)) {
		printf("%% %s: %s\n", path, strerror(errno));
		conftree_free(root);
		root = NULL;
	}
	free(line);
	fclose(f);
	return root;

fail:
	printf("%% conftree_read: %s\n", strerror(errno));
	conftree_free(root);
	free(line);
	fclose(f);
	return NULL;
}

void
conftree_free(struct cnode *n)
{
	size_t i;

	if (n == NULL)
		return;
	for (i = 0; i < n->nkids; i++)
		conftree_free(n->kids[i]);
	free(n->kids);
	free(n->text);
	free(n);
}

/*
 * Print the differences between the trees old and new to out. Returns
 * how many lines or blocks were removed or added, or -1 on failure.
 */
int
conftree_compare(FILE *out, struct cnode *old, struct cnode *new)
{
	struct cmpctx c;

	memset(&c, 0, sizeof(c));
	c.out = out;
	if (compare_set(&c, old, new) == -1)
		return -1;
	return c.ndiff;
}

static struct cnode *
cnode_add(struct cnode *parent, char *text, int ordered)
{
	struct cnode *n, **kids;

	kids = reallocarray(parent->kids, parent->nkids + 1, sizeof(*kids));
	if (kids == NULL)
		return NULL;
	parent->kids = kids;
	if ((n = calloc(1, sizeof(*n))) == NULL)
		return NULL;
	if ((n->text = strdup(text)) == NULL) {
		free(n);
		return NULL;
	}
	n->ordered = ordered;
	parent->kids[parent->nkids++] = n;
	return n;
}

static int
blank(char *s)
{
	for (; *s != '\0'; s++)
		if (*s != ' ' && *s != '\t')
			return 0;
	return 1;
}

/* Compare the children of a and b, two statements with the same text */
static int
compare_block(struct cmpctx *c, struct cnode *a, struct cnode *b)
{
	int ret;

	if (a->nkids == 0 && b->nkids == 0)
		return 0;
	if (c->nheads == CT_MAXDEPTH) {
		printf("%% conftree_compare: nested too deep\n");
		return -1;
	}
	c->heads[c->nheads++] = b;
	if (b->ordered)
		ret = compare_seq(c, a, b);
	else
		ret = compare_set(c, a, b);
	c->nheads--;
	if (c->nprinted > c->nheads)
		c->nprinted = c->nheads;
	return ret;
}

/*
 * Compare the children of a and b as sets. A line only a has is
 * printed after the nearest line before it that both have, so that
 * a changed line reads as its old and new versions next to each other.
 */
static int
compare_set(struct cmpctx *c, struct cnode *a, struct cnode *b)
{
	size_t *ma, *mb, i, j;
	int ret = -1;

	ma = calloc(a->nkids + 1, sizeof(*ma));
	mb = calloc(b->nkids + 1, sizeof(*mb));
	if (ma == NULL || mb == NULL) {
		printf("%% conftree_compare: %s\n", strerror(errno));
		goto done;
	}
	if (match(a, b, ma, mb) == -1)
		goto done;

	for (i = 0; i < a->nkids && ma[i] == NOMATCH; i++)
		emit(c, '-', a->kids[i]);
	for (j = 0; j < b->nkids; j++) {
		if (mb[j] == NOMATCH) {
			emit(c, '+', b->kids[j]);
			continue;
		}
		if (compare_block(c, a->kids[mb[j]], b->kids[j]) == -1)
			goto done;
		for (i = mb[j] + 1; i < a->nkids && ma[i] == NOMATCH; i++)
			emit(c, '-', a->kids[i]);
	}
	ret = 0;
done:
	free(ma);
	free(mb);
	return ret;
}

/*
 * Pair the children of a and b with the same text, the k-th copy of a
 * line in a with the k-th copy in b. ma[i] is the index in b of the
 * pair of a's child i, or NOMATCH; mb is the same for b.
 */
static int
match(struct cnode *a, struct cnode *b, size_t *ma, size_t *mb)
{
	struct ckey *ka, *kb;
	size_t i, j;
	int r, ret = -1;

	ka = calloc(a->nkids + 1, sizeof(*ka));
	kb = calloc(b->nkids + 1, sizeof(*kb));
	if (ka == NULL || kb == NULL) {
		printf("%% conftree_compare: %s\n", strerror(errno));
		goto done;
	}
	for (i = 0; i < a->nkids; i++) {
		ka[i].n = a->kids[i];
		ka[i].i = i;
		ma[i] = NOMATCH;
	}
	for (j = 0; j < b->nkids; j++) {
		kb[j].n = b->kids[j];
		kb[j].i = j;
		mb[j] = NOMATCH;
	}
	qsort(ka, a->nkids, sizeof(*ka), ckeycmp);
	qsort(kb, b->nkids, sizeof(*kb), ckeycmp);

	i = j = 0;
	while (i < a->nkids && j < b->nkids) {
		r = strcmp(ka[i].n->text, kb[j].n->text);
		if (r < 0)
			i++;
		else if (r > 0)
			j++;
		else {
			ma[ka[i].i] = kb[j].i;
			mb[kb[j].i] = ka[i].i;
			i++;
			j++;
		}
	}
	ret = 0;
done:
	free(ka);
	free(kb);
	return ret;
}

/* by text, then by position, so copies of a line stay in order */
static int
ckeycmp(const void *x, const void *y)
{
	const struct ckey *a = x, *b = y;
	int r;

	if ((r = strcmp(a->n->text, b->n->text)) != 0)
		return r;
	return (a->i > b->i) - (a->i < b->i);
}

/*
 * Compare the children of a and b as sequences, with as few lines
 * removed and added as possible (a longest common subsequence).  The
 * lines both start and end with are skipped first. If what is left is
 * too big for the table, all of it is printed as removed and added:
 * still correct, though not the shortest.
 */
static int
compare_seq(struct cmpctx *c, struct cnode *a, struct cnode *b)
{
	struct cnode **x = a->kids, **y = b->kids;
	size_t n = a->nkids, m = b->nkids, w, i, j;
	unsigned int *l = NULL, del, ins;

	while (n > 0 && m > 0 && strcmp(x[0]->text, y[0]->text) == 0) {
		x++;
		y++;
		n--;
		m--;
	}
	while (n > 0 && m > 0 &&
	    strcmp(x[n - 1]->text, y[m - 1]->text) == 0) {
		n--;
		m--;
	}

	/* l[i * w + j] is the LCS of x[i..n) and y[j..m) */
	w = m + 1;
	if (n > 0 && m > 0 && n + 1 <= CT_LCSMAX / w) {
		if ((l = calloc((n + 1) * w, sizeof(*l))) == NULL) {
			printf("%% conftree_compare: %s\n", strerror(errno));
			return -1;
		}
		for (i = n; i-- > 0; ) {
			for (j = m; j-- > 0; ) {
				if (strcmp(x[i]->text, y[j]->text) == 0) {
					l[i * w + j] = l[(i + 1) * w + j + 1] + 1;
					continue;
				}
				del = l[(i + 1) * w + j];
				ins = l[i * w + j + 1];
				l[i * w + j] = del >= ins ? del : ins;
			}
		}
	}

	i = j = 0;
	while (l != NULL && i < n && j < m) {
		if (strcmp(x[i]->text, y[j]->text) == 0) {
			i++;
			j++;
		} else if (l[(i + 1) * w + j] >= l[i * w + j + 1])
			emit(c, '-', x[i++]);
		else
			emit(c, '+', y[j++]);
	}
	while (i < n)
		emit(c, '-', x[i++]);
	while (j < m)
		emit(c, '+', y[j++]);
	free(l);
	return 0;
}

/* Print n and its children, after the statements that contain them */
static void
emit(struct cmpctx *c, char mark, struct cnode *n)
{
	for (; c->nprinted < c->nheads; c->nprinted++)
		fprintf(c->out, " %*s%s\n", c->nprinted, "",
		    c->heads[c->nprinted]->text);
	emit_tree(c, mark, c->nheads, n);
	c->ndiff++;
}

static void
emit_tree(struct cmpctx *c, char mark, int depth, struct cnode *n)
{
	size_t i;

	fprintf(c->out, "%c%*s%s\n", mark, depth, "", n->text);
	for (i = 0; i < n->nkids; i++)
		emit_tree(c, mark, depth + 1, n->kids[i]);
}
