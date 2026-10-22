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
 *
 * conftree_edit() changes a tree as one configuration command would,
 * and a journal records the edits so that they can be made again on a
 * newer copy of the running configuration. conftree_write() prints a
 * tree in the form conftree_read() reads.
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

struct cedit {
	int op;
	char *block;		/* NULL for the top level */
	char *line;
	int keylen;
};

struct cjournal {
	struct cedit *edits;
	size_t nedits;
};

static struct cnode *cnode_add(struct cnode *, char *, int);
static int blank(char *);
static int storable(char *);
static int storable_stmt(char *);
static int match(struct cnode *, struct cnode *, size_t *, size_t *);
static int ckeycmp(const void *, const void *);
static int compare_block(struct cmpctx *, struct cnode *, struct cnode *);
static int compare_set(struct cmpctx *, struct cnode *, struct cnode *);
static int compare_seq(struct cmpctx *, struct cnode *, struct cnode *);
static void emit(struct cmpctx *, char, struct cnode *);
static void emit_tree(struct cmpctx *, char, int, struct cnode *);
static struct cnode *find_kid(struct cnode *, char *);
static struct cnode *find_stmt(struct cnode *, char *, int, int);
static void remove_kid(struct cnode *, size_t);
static int set_text(struct cnode *, char *);
static char *skipno(char *);
static int samename(char *, char *);
static int samekey(char *, char *, int);
static int hasword(char *, char *, size_t);
static int list_add(struct cnode *, char *);
static int list_del(struct cnode *, size_t, char *);
static void write_node(FILE *, int, struct cnode *);

/*
 * Read the configuration file at path. mode(statement) says what the
 * statement does with the indented lines after it, ordered(statement)
 * says whether they are a sequence.
 */
struct cnode *
conftree_read(char *path, int (*mode)(char *), int (*ordered)(char *))
{
	struct cnode *t;
	FILE *f;

	if ((f = fopen(path, "r")) == NULL) {
		printf("%% %s: %s\n", path, strerror(errno));
		return NULL;
	}
	t = conftree_fread(f, path, mode, ordered);
	fclose(f);
	return t;
}

/* conftree_read() of len bytes of text, which path names in what it says */
struct cnode *
conftree_mem(char *text, size_t len, char *path, int (*mode)(char *),
    int (*ordered)(char *))
{
	struct cnode *t;
	FILE *f;

	/* fmemopen() takes no empty buffer */
	if ((f = fmemopen(len > 0 ? text : "\n", len > 0 ? len : 1,
	    "r")) == NULL) {
		printf("%% %s: %s\n", path, strerror(errno));
		return NULL;
	}
	t = conftree_fread(f, path, mode, ordered);
	fclose(f);
	return t;
}

/* conftree_read() of f, which path names in what it says */
struct cnode *
conftree_fread(FILE *f, char *path, int (*mode)(char *),
    int (*ordered)(char *))
{
	struct cnode *root, *top = NULL, *stmt = NULL;
	int topmode = CT_LEAF;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	unsigned int lnum = 0;

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
	return root;

fail:
	printf("%% conftree_read: %s\n", strerror(errno));
	conftree_free(root);
	free(line);
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

/* A copy of the tree n, or NULL */
struct cnode *
conftree_copy(struct cnode *n)
{
	struct cnode *c;
	size_t i;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		return NULL;
	c->ordered = n->ordered;
	if ((n->text != NULL && (c->text = strdup(n->text)) == NULL) ||
	    (n->nkids > 0 &&
	    (c->kids = calloc(n->nkids, sizeof(*c->kids))) == NULL)) {
		conftree_free(c);
		return NULL;
	}
	for (i = 0; i < n->nkids; i++) {
		if ((c->kids[i] = conftree_copy(n->kids[i])) == NULL) {
			conftree_free(c);
			return NULL;
		}
		c->nkids++;
	}
	return c;
}

/*
 * Print the differences between the trees old and new to out, or with
 * out NULL only count them. Returns how many lines or blocks were
 * removed or added, or -1 on failure.
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

/*
 * Can conftree_read() read s back as the line it is (not blank, not
 * indented, not a comment or a '!', and one line?)
 */
static int
storable(char *s)
{
	return !blank(s) && s[0] != ' ' && s[0] != '!' && s[0] != '#' &&
	    strchr(s, '\n') == NULL;
}

/* Can s be a block as conftree_edit() takes it? */
static int
storable_stmt(char *s)
{
	size_t len;

	for (;;) {
		len = strcspn(s, "\n");
		if (s[0] == ' ' || s[0] == '!' || s[0] == '#' ||
		    strspn(s, " \t") >= len)
			return 0;
		if (s[len] == '\0')
			return 1;
		s += len + 1;
	}
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
		if (c->out != NULL)
			fprintf(c->out, " %*s%s\n", c->nprinted, "",
			    c->heads[c->nprinted]->text);
	emit_tree(c, mark, c->nheads, n);
	c->ndiff++;
}

static void
emit_tree(struct cmpctx *c, char mark, int depth, struct cnode *n)
{
	size_t i;

	if (c->out != NULL)
		fprintf(c->out, "%c%*s%s\n", mark, depth, "", n->text);
	for (i = 0; i < n->nkids; i++)
		emit_tree(c, mark, depth + 1, n->kids[i]);
}

/*
 * Change the tree as one configuration command would.  block is the
 * statement the line belongs under, or NULL for the top level: a
 * top-level statement, or a statement under one, named by the two
 * joined by a newline. For CE_BLOCK and CE_NOBLOCK, line is the
 * statement itself, and CE_RENAME makes the top-level statement block
 * read line, unless there is already a statement that does. CE_SEQ
 * adds line after the lines of block, an ordered statement made if it
 * is not there, even if it has the line already; line is a line of a
 * daemon's file, which may be blank or start with a space, '!' or '#'.
 * A line set or added under a block that is not there creates the block.
 * block must be a statement that takes indented lines.  The name of a
 * line is its first word, after a "no"; CE_SET and CE_UNSET match lines
 * by their key, the first keylen words, as samekey() compares them.
 * Returns CE_CHANGED, CE_NOOP, or -1 on failure, including a line the
 * file could not hold.
 */
int
conftree_edit(struct cnode *root, int op, char *block, char *line, int keylen)
{
	struct cnode *p = root, *n;
	size_t i;
	int ret = CE_NOOP;

	if (op == CE_SEQ ? block == NULL || strchr(line, '\n') != NULL :
	    !storable(line)) {
		printf("%% conftree_edit: not a configuration line: \"%s\"\n",
		    line);
		return -1;
	}
	if (block != NULL && !storable_stmt(block)) {
		printf("%% conftree_edit: not a configuration line: \"%s\"\n",
		    block);
		return -1;
	}

	switch (op) {
	case CE_BLOCK:
		if (block != NULL && (p = find_stmt(root, block, 1, 0)) == NULL)
			return -1;
		if (find_kid(p, line) != NULL)
			return CE_NOOP;
		return cnode_add(p, line, 0) == NULL ? -1 : CE_CHANGED;
	case CE_NOBLOCK:
		if (block != NULL && (p = find_stmt(root, block, 0, 0)) == NULL)
			return CE_NOOP;
		for (i = p->nkids; i-- > 0; ) {
			if (strcmp(p->kids[i]->text, line) == 0) {
				remove_kid(p, i);
				ret = CE_CHANGED;
			}
		}
		return ret;
	case CE_RENAME:
		if (block == NULL || (p = find_kid(root, block)) == NULL ||
		    find_kid(root, line) != NULL)
			return CE_NOOP;
		return set_text(p, line) == -1 ? -1 : CE_CHANGED;
	case CE_SEQ:
		if ((p = find_stmt(root, block, 1, 1)) == NULL)
			return -1;
		return cnode_add(p, line, 0) == NULL ? -1 : CE_CHANGED;
	}

	if (block != NULL && (p = find_stmt(root, block, 0, 0)) == NULL) {
		if (op != CE_SET && op != CE_ADD && op != CE_LISTADD)
			return CE_NOOP;
		if ((p = find_stmt(root, block, 1, 0)) == NULL)
			return -1;
		ret = CE_CHANGED;
	}

	switch (op) {
	case CE_SET:
		n = NULL;
		for (i = 0; i < p->nkids; i++) {
			if (!samekey(p->kids[i]->text, line, keylen))
				continue;
			if (n == NULL) {
				n = p->kids[i];
				if (strcmp(n->text, line) != 0) {
					if (set_text(n, line) == -1)
						return -1;
					ret = CE_CHANGED;
				}
			} else {
				remove_kid(p, i--);
				ret = CE_CHANGED;
			}
		}
		if (n == NULL) {
			if (cnode_add(p, line, 0) == NULL)
				return -1;
			ret = CE_CHANGED;
		}
		return ret;
	case CE_UNSET:
		for (i = p->nkids; i-- > 0; ) {
			if (samekey(p->kids[i]->text, line, keylen)) {
				remove_kid(p, i);
				ret = CE_CHANGED;
			}
		}
		return ret;
	case CE_ADD:
		if (find_kid(p, line) != NULL)
			return ret;
		return cnode_add(p, line, 0) == NULL ? -1 : CE_CHANGED;
	case CE_DEL:
		for (i = p->nkids; i-- > 0; ) {
			if (strcmp(p->kids[i]->text, line) == 0) {
				remove_kid(p, i);
				ret = CE_CHANGED;
			}
		}
		return ret;
	case CE_LISTADD:
		for (i = 0; i < p->nkids; i++)
			if (samename(p->kids[i]->text, line))
				break;
		if (i == p->nkids) {
			/*
			 * Start the line with its name and add the values to
			 * it, so each is there once; with none, there is no
			 * line.
			 */
			if ((n = cnode_add(p, line, 0)) == NULL)
				return -1;
			n->text[strcspn(n->text, " ")] = '\0';
			switch (list_add(n, line)) {
			case CE_CHANGED:
				return CE_CHANGED;
			case -1:
				remove_kid(p, i);
				return -1;
			}
			remove_kid(p, i);
			return ret;
		}
		switch (list_add(p->kids[i], line)) {
		case -1:
			return -1;
		case CE_CHANGED:
			ret = CE_CHANGED;
		}
		return ret;
	case CE_LISTDEL:
		for (i = 0; i < p->nkids; i++)
			if (samename(p->kids[i]->text, line))
				return list_del(p, i, line);
		return ret;
	}
	printf("%% conftree_edit: unknown edit %d\n", op);
	return -1;
}

/* Is there a statement line, as conftree_edit() takes a block? */
int
conftree_has(struct cnode *root, char *line)
{
	return find_stmt(root, line, 0, 0) != NULL;
}

/* The n'th top-level statement, from 0, or NULL if there are not that many */
char *
conftree_stmt(struct cnode *root, size_t n)
{
	return n < root->nkids ? root->kids[n]->text : NULL;
}

/*
 * The n'th line named name, or of any name if name is NULL, from 0, in
 * block, as conftree_edit() takes it, or at the top level if block is
 * NULL, or NULL if there are not that many
 */
char *
conftree_line(struct cnode *root, char *block, char *name, size_t n)
{
	struct cnode *p;
	size_t i;

	if ((p = block == NULL ? root : find_stmt(root, block, 0, 0)) == NULL)
		return NULL;
	for (i = 0; i < p->nkids; i++)
		if ((name == NULL || samename(p->kids[i]->text, name)) &&
		    n-- == 0)
			return p->kids[i]->text;
	return NULL;
}

/*
 * Has block, as conftree_line() takes it, a line with line's key, its
 * first keylen words, as samekey() compares them?
 */
int
conftree_haskey(struct cnode *root, char *block, char *line, int keylen)
{
	struct cnode *p;
	size_t i;

	if ((p = block == NULL ? root : find_stmt(root, block, 0, 0)) == NULL)
		return 0;
	for (i = 0; i < p->nkids; i++)
		if (samekey(p->kids[i]->text, line, keylen))
			return 1;
	return 0;
}

/*
 * Print the tree as a configuration file: each statement with its
 * lines indented below it and a '!' after them.
 */
int
conftree_write(FILE *out, struct cnode *root)
{
	size_t i;

	for (i = 0; i < root->nkids; i++)
		write_node(out, 0, root->kids[i]);
	return ferror(out) ? -1 : 0;
}

/*
 * The top-level statements stmt names, written as conftree_write()
 * writes them: stmt itself if whole, else each line of stmt's name, as
 * conftree_edit() names lines
 */
int
conftree_write_stmt(FILE *out, struct cnode *root, char *stmt, int whole)
{
	size_t i;

	for (i = 0; i < root->nkids; i++)
		if (whole ? strcmp(root->kids[i]->text, stmt) == 0 :
		    samename(root->kids[i]->text, stmt))
			write_node(out, 0, root->kids[i]);
	return ferror(out) ? -1 : 0;
}

struct cjournal *
cjournal_new(void)
{
	return calloc(1, sizeof(struct cjournal));
}

/* Record an edit, to make it again later with cjournal_replay() */
int
cjournal_add(struct cjournal *j, int op, char *block, char *line, int keylen)
{
	struct cedit *e;

	e = reallocarray(j->edits, j->nedits + 1, sizeof(*e));
	if (e == NULL)
		return -1;
	j->edits = e;
	e = &j->edits[j->nedits];
	e->op = op;
	e->keylen = keylen;
	e->block = NULL;
	if (block != NULL && (e->block = strdup(block)) == NULL)
		return -1;
	if ((e->line = strdup(line)) == NULL) {
		free(e->block);
		return -1;
	}
	j->nedits++;
	return 0;
}

size_t
cjournal_len(struct cjournal *j)
{
	return j->nedits;
}

/* The nth edit, as cjournal_add() took it */
void
cjournal_get(struct cjournal *j, size_t n, int *op, char **block,
    char **line, int *keylen)
{
	*op = j->edits[n].op;
	*block = j->edits[n].block;
	*line = j->edits[n].line;
	*keylen = j->edits[n].keylen;
}

/*
 * Make the recorded edits on root, in order. On a newer copy of the
 * running configuration, this keeps what changed there and puts each
 * recorded edit on top of it.
 */
int
cjournal_replay(struct cjournal *j, struct cnode *root)
{
	size_t i;

	for (i = 0; i < j->nedits; i++)
		if (conftree_edit(root, j->edits[i].op, j->edits[i].block,
		    j->edits[i].line, j->edits[i].keylen) == -1)
			return -1;
	return 0;
}

void
cjournal_free(struct cjournal *j)
{
	size_t i;

	if (j == NULL)
		return;
	for (i = 0; i < j->nedits; i++) {
		free(j->edits[i].block);
		free(j->edits[i].line);
	}
	free(j->edits);
	free(j);
}

static struct cnode *
find_kid(struct cnode *p, char *text)
{
	size_t i;

	for (i = 0; i < p->nkids; i++)
		if (strcmp(p->kids[i]->text, text) == 0)
			return p->kids[i];
	return NULL;
}

/*
 * The statement name names, as conftree_edit() takes a block, or NULL;
 * with make, it and any it is under are made if they are not there,
 * it ordered if ordered is not 0
 */
static struct cnode *
find_stmt(struct cnode *p, char *name, int make, int ordered)
{
	struct cnode *n;
	size_t len, i;
	char *s;

	for (;;) {
		len = strcspn(name, "\n");
		for (i = 0; i < p->nkids; i++)
			if (strncmp(p->kids[i]->text, name, len) == 0 &&
			    p->kids[i]->text[len] == '\0')
				break;
		if (i < p->nkids)
			n = p->kids[i];
		else {
			if (!make || (s = strndup(name, len)) == NULL)
				return NULL;
			n = cnode_add(p, s, name[len] == '\0' && ordered);
			free(s);
			if (n == NULL)
				return NULL;
		}
		if (name[len] == '\0')
			return n;
		p = n;
		name += len + 1;
	}
}

static void
remove_kid(struct cnode *p, size_t i)
{
	conftree_free(p->kids[i]);
	memmove(&p->kids[i], &p->kids[i + 1],
	    (p->nkids - i - 1) * sizeof(*p->kids));
	p->nkids--;
}

static int
set_text(struct cnode *n, char *text)
{
	char *t;

	if ((t = strdup(text)) == NULL)
		return -1;
	free(n->text);
	n->text = t;
	return 0;
}

/* "no mtu 1400" -> "mtu 1400" */
static char *
skipno(char *s)
{
	return strncmp(s, "no ", 3) == 0 ? s + 3 : s;
}

/* Do two lines have the same name: their first word, after "no"? */
static int
samename(char *a, char *b)
{
	return samekey(a, b, 1);
}

/*
 * Do two lines have the same key, the same first k words after "no"?
 * With CK_ADDR in k, the last word is an address and its "/prefixlen"
 * is not part of the key, so "inet 192.0.2.1/24" and "inet 192.0.2.1/25"
 * have the same key, 2 | CK_ADDR.
 */
static int
samekey(char *a, char *b, int k)
{
	size_t la, lb;
	int n = k & ~CK_ADDR;

	a = skipno(a);
	b = skipno(b);
	for (;;) {
		if (n == 1 && (k & CK_ADDR)) {
			la = strcspn(a, " /");
			lb = strcspn(b, " /");
		} else {
			la = strcspn(a, " ");
			lb = strcspn(b, " ");
		}
		if (la != lb || strncmp(a, b, la) != 0)
			return 0;
		if (--n <= 0)
			return 1;
		a += la;
		b += lb;
		if (*a == '\0' || *b == '\0')	/* shorter than the key */
			return *a == *b;
		a++;
		b++;
	}
}

/* Is w, len bytes long, one of the words after the first in text? */
static int
hasword(char *text, char *w, size_t len)
{
	size_t l;

	text += strcspn(text, " ");
	while (*text == ' ') {
		text++;
		l = strcspn(text, " ");
		if (l == len && strncmp(text, w, len) == 0)
			return 1;
		text += l;
	}
	return 0;
}

/* Add the values in line (the words after its name) to n's line */
static int
list_add(struct cnode *n, char *line)
{
	char *v, *t;
	size_t l, len;
	int ret = CE_NOOP;

	v = line + strcspn(line, " ");
	while (*v == ' ') {
		v++;
		l = strcspn(v, " ");
		if (l > 0 && !hasword(n->text, v, l)) {
			len = strlen(n->text);
			if ((t = realloc(n->text, len + l + 2)) == NULL)
				return -1;
			t[len] = ' ';
			memcpy(t + len + 1, v, l);
			t[len + l + 1] = '\0';
			n->text = t;
			ret = CE_CHANGED;
		}
		v += l;
	}
	return ret;
}

/*
 * Remove the values in line from p's line i, and the line if no value
 * is left. A line with no values removes the whole line.
 */
static int
list_del(struct cnode *p, size_t i, char *line)
{
	struct cnode *n = p->kids[i];
	char *t, *w, *end;
	size_t l, len;
	int ret = CE_NOOP;

	if (line[strcspn(line, " ")] == '\0') {
		remove_kid(p, i);
		return CE_CHANGED;
	}
	len = strlen(n->text);
	if ((t = malloc(len + 1)) == NULL)
		return -1;
	l = strcspn(n->text, " ");
	memcpy(t, n->text, l);
	end = t + l;
	for (w = n->text + l; *w == ' '; w += l) {
		w++;
		l = strcspn(w, " ");
		if (l > 0 && hasword(line, w, l)) {
			ret = CE_CHANGED;
			continue;
		}
		*end++ = ' ';
		memcpy(end, w, l);
		end += l;
	}
	*end = '\0';
	if (ret == CE_NOOP) {
		free(t);
		return ret;
	}
	if (strchr(t, ' ') == NULL) {
		free(t);
		remove_kid(p, i);
		return CE_CHANGED;
	}
	free(n->text);
	n->text = t;
	return ret;
}

static void
write_node(FILE *out, int depth, struct cnode *n)
{
	size_t i;

	fprintf(out, "%*s%s\n", depth, "", n->text);
	for (i = 0; i < n->nkids; i++)
		write_node(out, depth + 1, n->kids[i]);
	if (n->nkids > 0)
		fprintf(out, "%*s!\n", depth, "");
}
