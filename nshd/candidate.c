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
 * configure private: a candidate configuration for this session.
 *
 * In configure private, commands change a copy of the configuration
 * instead of the kernel.  The copy starts as the running configuration,
 * read into a conftree, and every change the session makes to it is
 * recorded in a journal.  Showing the candidate replays the journal on
 * a fresh copy of the running configuration, so what other sessions
 * changed since shows through, with this session's changes on top.
 * Each nsh session is its own process, so its candidate is private.
 *
 * rollback N starts the copy over as configuration N, as it was saved
 * (ROLLBACK), and then nothing other sessions change shows through.
 *
 * Each top-level statement the journal changes is kept as it was before
 * the journal first changed it.  A commit is refused if another commit
 * changed one since (cand_conflicts()); committing again keeps this
 * session's changes over the other's.
 *
 * A candidate is a struct cand_state.  nshd's config has one for each
 * session, and one that the sessions of configure share.  A session's
 * struct cand points at its own and at the one its lines edit, and
 * config passes it to what runs the session's request, down to the
 * functions here.  A session attached to the shared one leaves it to
 * the others when it leaves configure (cand_detach()).  While another
 * session holds it, nshd's config sets cand_held, and no edit or
 * rollback changes it.
 *
 * A command's table row (cand) says how it takes part.  A CAND_EDIT
 * command's apply function is passed the candidate, and calls
 * cand_setting() where it would have changed the kernel; passed none,
 * it changes the kernel.  A CAND_RUN command runs as it always does,
 * and any other command is refused until its handler is converted.
 * cand_setting() says what the command did to a setting; the settings
 * table (settings.c) turns that into the edit.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "stringlist.h"
#include "externs.h"
#include "ctl.h"
#include "commands.h"
#include "conftree.h"
#include "settings.h"
#include "kernel.h"
#include "kfacts.h"
#include "session.h"

int cand_rtable;			/* rtable for rtable settings, or 0 */
const char *cand_held;			/* why it may not change now, or NULL */

/* a top-level statement the journal changes, as it was before the change */
struct cand_was {
	char	*top;		/* the statement, or its lines' name */
	int	 whole;		/* top is a statement, not a line name */
	char	*image;		/* as conftree_write_stmt() wrote it */
};

/*
 * A candidate: a session's own, or the one that sessions share. A
 * session's struct cand (session.h) points at its own and at the one its
 * lines edit
 */
struct cand_state {
	struct cnode	*tree;		/* the session's view of it */
	struct cnode	*base;		/* what rollback N loaded, or NULL */
	struct cjournal	*journal;	/* the changes made to it */
	struct cand_was	*was;
	size_t		 nwas;
	unsigned int	 nedits;	/* number of edits and rollbacks */
};

/* what a session keeps of this file (session.c) */
struct sglobal candidate_sglobals[] = {
	SGLOBAL(cand_rtable),
	{ NULL }
};

static int cand_record(struct cand *, char *, struct sedit *);
static int cand_remember(struct cand *, char *, struct sedit *);
static char *cand_image(struct cnode *, char *, int);
static void cand_forget(struct cand *);
static int cand_rtblock(struct cand *, char *, size_t, int);
static char *cand_rtcur(struct cand *, char *, size_t);
static int cand_set(struct cand *, int, int, char *, char *);
static void cand_block(char *, size_t, char *, int);
static int cand_vsetting(struct cand *, char *, int, int,
    const char *, va_list);
static const struct kcloner *cand_cloner(char *);
static size_t cloner_namelen(char *);

/*
 * configure private: start a candidate from the running configuration,
 * or take the shared one as it is, if it has begun
 */
int
cand_begin(struct cand *cand)
{
	if (cand->on)
		return 0;
	if (cand->cur->journal == NULL) {
		if ((cand->cur->tree = running_tree()) == NULL)
			return -1;
		if ((cand->cur->journal = cjournal_new()) == NULL) {
			printf("%% cand_begin: %s\n", strerror(errno));
			conftree_free(cand->cur->tree);
			cand->cur->tree = NULL;
			return -1;
		}
	} else if (cand->cur->tree == NULL && cand_tree(cand) == NULL)
		return -1;
	cand->on = 1;
	cand_rtable = 0;
	return 0;
}

/* A new candidate, not begun, or NULL with errno set */
struct cand_state *
cand_new(void)
{
	return calloc(1, sizeof(struct cand_state));
}

/* Attach cand's session to the shared candidate sh */
void
cand_attach(struct cand *cand, struct cand_state *sh)
{
	cand->cur = sh;
}

/* Is cand's session attached to a shared candidate? */
int
cand_attached(struct cand *cand)
{
	return cand->cur != cand->own;
}

/* Leave the shared candidate, as it is, to the sessions that share it */
void
cand_detach(struct cand *cand)
{
	cand->cur = cand->own;
	cand->on = 0;
	cand_rtable = 0;
}

/* Free all that c holds: it is a candidate not begun again */
static void
cand_drop(struct cand_state *c)
{
	size_t i;

	conftree_free(c->tree);
	conftree_free(c->base);
	cjournal_free(c->journal);
	for (i = 0; i < c->nwas; i++) {
		free(c->was[i].top);
		free(c->was[i].image);
	}
	free(c->was);
	memset(c, 0, sizeof(*c));
}

/*
 * The shared candidate sh starts again from the running configuration.
 * -1 if it could not, after saying why, with sh as it was
 */
int
cand_shared_renew(struct cand_state *sh)
{
	struct cnode *t;
	struct cjournal *j;

	if ((t = running_tree()) == NULL)
		return -1;
	if ((j = cjournal_new()) == NULL) {
		printf("%% cand_shared_renew: %s\n", strerror(errno));
		conftree_free(t);
		return -1;
	}
	cand_drop(sh);
	sh->tree = t;
	sh->journal = j;
	return 0;
}

/* Has the shared candidate sh changed? */
int
cand_shared_changed(struct cand_state *sh)
{
	return sh->journal != NULL &&
	    (cjournal_len(sh->journal) > 0 || sh->base != NULL);
}

/* The number of edits and rollbacks made to sh since it began */
unsigned int
cand_shared_edits(struct cand_state *sh)
{
	return sh->nedits;
}

/*
 * The shared candidate sh, written to f as cand_shared_read() reads it:
 * what rollback N loaded, if it did, as "base LENGTH" and its text; each
 * edit of its journal as "edit OP KEYLEN BLOCKLENGTH LINELENGTH", its
 * block (BLOCKLENGTH -1 for none) and its line; and each statement as it
 * was before an edit first changed it, as "was WHOLE TOPLENGTH
 * IMAGELENGTH", its name and its text. -1 if it could not be written
 */
int
cand_shared_write(struct cand_state *sh, FILE *f)
{
	char *buf = NULL, *block, *line;
	size_t len = 0, i;
	FILE *m;
	int op, keylen, r;

	if (sh->base != NULL) {
		if ((m = open_memstream(&buf, &len)) == NULL)
			return -1;
		r = conftree_write(m, sh->base);
		if (fclose(m) == EOF || r == -1 ||
		    fprintf(f, "base %zu\n", len) < 0 ||
		    fwrite(buf, 1, len, f) != len) {
			free(buf);
			return -1;
		}
		free(buf);
	}
	for (i = 0; sh->journal != NULL && i < cjournal_len(sh->journal);
	    i++) {
		cjournal_get(sh->journal, i, &op, &block, &line, &keylen);
		if (fprintf(f, "edit %d %d %zd %zu\n%s%s", op, keylen,
		    block == NULL ? -1 : (ssize_t)strlen(block), strlen(line),
		    block == NULL ? "" : block, line) < 0)
			return -1;
	}
	for (i = 0; i < sh->nwas; i++)
		if (fprintf(f, "was %d %zu %zu\n%s%s", sh->was[i].whole,
		    strlen(sh->was[i].top), strlen(sh->was[i].image),
		    sh->was[i].top, sh->was[i].image) < 0)
			return -1;
	return 0;
}

/* the len bytes at *p, before end, as a new string, or NULL */
static char *
cand_field(char **p, char *end, size_t len)
{
	char *s;

	if (len > (size_t)(end - *p) || memchr(*p, '\0', len) != NULL)
		return NULL;
	if ((s = strndup(*p, len)) == NULL)
		return NULL;
	*p += len;
	return s;
}

/*
 * The shared candidate sh, which no session has begun, read from the len
 * bytes of text that cand_shared_write() wrote.  -1 on error, after
 * saying why, with sh as it was
 */
int
cand_shared_read(struct cand_state *sh, char *text, size_t len)
{
	struct cnode *base = NULL;
	struct cjournal *j;
	struct cand_was *was = NULL, *w;
	char head[64], canon[64], *p = text, *end = text + len, *nl;
	char *block, *line, *top, *image;
	size_t nwas = 0, n, ll, tl, il, i;
	ssize_t bl;
	int op, keylen, whole;

	if ((j = cjournal_new()) == NULL) {
		printf("%% cand_shared_read: %s\n", strerror(errno));
		return -1;
	}
	while (p < end) {
		if ((nl = memchr(p, '\n', end - p)) == NULL ||
		    (size_t)(nl - p) >= sizeof(head))
			goto bad;
		memcpy(head, p, nl - p);
		head[nl - p] = '\0';
		p = nl + 1;
		block = line = top = image = NULL;
		if (sscanf(head, "base %zu", &n) == 1) {
			snprintf(canon, sizeof(canon), "base %zu", n);
			if (strcmp(canon, head) != 0 || base != NULL ||
			    cjournal_len(j) > 0 || n > (size_t)(end - p) ||
			    (base = conftree_mem(p, n, "the shared candidate",
			    conf_mode, conf_ordered)) == NULL)
				goto bad;
			p += n;
		} else if (sscanf(head, "edit %d %d %zd %zu", &op, &keylen,
		    &bl, &ll) == 4) {
			snprintf(canon, sizeof(canon), "edit %d %d %zd %zu", op,
			    keylen, bl, ll);
			if (strcmp(canon, head) != 0 || op < CE_SET ||
			    op > CE_SEQ || bl < -1 || keylen < 0 ||
			    (size_t)keylen > ll ||
			    (bl >= 0 && (block = cand_field(&p, end, bl)) ==
			    NULL) || (line = cand_field(&p, end, ll)) == NULL ||
			    cjournal_add(j, op, block, line, keylen) == -1) {
				free(block);
				free(line);
				goto bad;
			}
			free(block);
			free(line);
		} else if (sscanf(head, "was %d %zu %zu", &whole, &tl,
		    &il) == 3) {
			snprintf(canon, sizeof(canon), "was %d %zu %zu", whole,
			    tl, il);
			if (strcmp(canon, head) != 0 ||
			    (whole != 0 && whole != 1) ||
			    (top = cand_field(&p, end, tl)) == NULL ||
			    (image = cand_field(&p, end, il)) == NULL ||
			    (w = reallocarray(was, nwas + 1,
			    sizeof(*was))) == NULL) {
				free(top);
				free(image);
				goto bad;
			}
			was = w;
			was[nwas].top = top;
			was[nwas].whole = whole;
			was[nwas++].image = image;
		} else
			goto bad;
	}
	cand_drop(sh);
	sh->base = base;
	sh->journal = j;
	sh->was = was;
	sh->nwas = nwas;
	return 0;
 bad:
	printf("%% The shared candidate kept is not one\n");
	conftree_free(base);
	cjournal_free(j);
	for (i = 0; i < nwas; i++) {
		free(was[i].top);
		free(was[i].image);
	}
	free(was);
	return -1;
}

/* Leave configure private, dropping the candidate. */
void
cand_end(struct cand *cand)
{
	cand_drop(cand->cur);
	cand->on = 0;
	cand_rtable = 0;
}

/* Has this session changed its candidate? */
int
cand_changed(struct cand *cand)
{
	return cand->on &&
	    (cjournal_len(cand->cur->journal) > 0 || cand->cur->base != NULL);
}

/*
 * A command in configure private: put the setting that line names into
 * state (ST_*), as the command would have in the kernel. In interface
 * or bridge mode the line goes into that interface's block.  line is
 * canonical, as conf() prints it, without "no". 0, or -1 after
 * saying why if it could not, as a handler returns.
 */
int
cand_setting(struct cand *cand, int state, const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = cand_vsetting(cand, ifname, bridge, state, fmt, ap);
	va_end(ap);
	return r;
}

/* cand_setting() for another interface, in the block the candidate has */
int
cand_ifsetting(struct cand *cand, char *name, int state, const char *fmt, ...)
{
	char head[sizeof("interface ") + IFNAMSIZ];
	va_list ap;
	int r;

	cand_block(head, sizeof(head), name, 1);
	va_start(ap, fmt);
	r = cand_vsetting(cand, name, conftree_has(cand->cur->tree, head),
	    state, fmt, ap);
	va_end(ap);
	return r;
}

/*
 * The n'th line named name, from 0, in the candidate's block for the
 * current interface, or NULL.  Outside an interface, the line is looked
 * for in the current rtable's block if name is an rtable setting, else
 * at the top level
 */
char *
cand_line(struct cand *cand, char *name, size_t n)
{
	char block[sizeof("interface ") + IFNAMSIZ], rtblock[96];

	if (ifname[0] == '\0') {
		if (cand_rtable != 0 && setting_has(CTX_RTABLE, name) &&
		    cand_rtblock(cand, rtblock, sizeof(rtblock),
		    cand_rtable) == 0)
			return conftree_line(cand->cur->tree, rtblock, name, n);
		return conftree_line(cand->cur->tree, NULL, name, n);
	}
	cand_block(block, sizeof(block), ifname, bridge);
	return conftree_line(cand->cur->tree, block, name, n);
}

/* cand_line() for another interface */
char *
cand_ifline(struct cand *cand, char *ifn, char *name, size_t n)
{
	char block[sizeof("interface ") + IFNAMSIZ];

	cand_block(block, sizeof(block), ifn, 1);
	if (!conftree_has(cand->cur->tree, block))
		cand_block(block, sizeof(block), ifn, 0);
	return conftree_line(cand->cur->tree, block, name, n);
}

/* The name of the n'th interface, from 0, in the candidate, or NULL */
char *
cand_ifname(struct cand *cand, size_t n)
{
	char *s;
	size_t i;

	for (i = 0; (s = conftree_stmt(cand->cur->tree, i)) != NULL; i++)
		if (strncmp(s, "interface ", strlen("interface ")) == 0 &&
		    n-- == 0)
			return s + strlen("interface ");
	return NULL;
}

/*
 * Replace the current interface's lines named in names[] with the lines
 * in buf, which a conf() printer wrote.  Each line in buf replaces the
 * lines with its key, and lines that buf does not have are removed.  A
 * line with "no" turns its setting off.  buf is changed.
 */
int
cand_putlines(struct cand *cand, char **names, size_t nnames, char *buf)
{
	char **lines = NULL, **gone = NULL, **v, *l, *p;
	size_t i, j, n, nlines = 0, ngone = 0;
	int ret = -1;

	for (p = buf; (l = strsep(&p, "\n")) != NULL; ) {
		if (*l != ' ')
			continue;
		if ((v = reallocarray(lines, nlines + 1,
		    sizeof(*lines))) == NULL)
			goto done;
		lines = v;
		lines[nlines++] = l + 1;
	}

	for (i = 0; i < nlines; i++)
		if (strncmp(lines[i], "no ", 3) == 0)
			cand_setting(cand, ST_OFF, "%s", lines[i] + 3);
		else
			cand_setting(cand, ST_ON, "%s", lines[i]);
	for (i = 0; i < nnames; i++)
		for (n = 0; (l = cand_line(cand, names[i], n)) != NULL; n++) {
			for (j = 0; j < nlines && strcmp(lines[j], l) != 0; j++)
				;
			if (j < nlines)
				continue;
			if ((v = reallocarray(gone, ngone + 1,
			    sizeof(*gone))) == NULL)
				goto done;
			gone = v;
			if ((gone[ngone] = strdup(l)) == NULL)
				goto done;
			ngone++;
		}
	for (i = 0; i < ngone; i++)
		cand_setting(cand, ST_DEFAULT, "%s",
		    strncmp(gone[i], "no ", 3) == 0 ? gone[i] + 3 : gone[i]);
	ret = 0;
done:
	for (i = 0; i < ngone; i++)
		free(gone[i]);
	free(gone);
	free(lines);
	return ret;
}

/*
 * The state of the setting name for the current interface: its line,
 * its line with "no", or no line (ST_*)
 */
int
cand_state(struct cand *cand, char *name)
{
	char *l;

	if ((l = cand_line(cand, name, 0)) == NULL)
		return ST_DEFAULT;
	return strncmp(l, "no ", 3) == 0 ? ST_OFF : ST_ON;
}

/*
 * The if_flags of an interface: the kernel's, or for one only the
 * candidate has, what its cloner's create function sets
 */
int
cand_getflags(char *name, int ifs)
{
	const struct kcloner *kc;

	if (kf_index(name) != 0)
		return kf_flags(name, ifs);
	return (kc = cand_cloner(name)) != NULL ? kc->flags : 0;
}

/* The if_type of an interface, from the kernel or its cloner */
int
cand_gettype(struct cand *cand, char *name)
{
	const struct kcloner *kc;

	if (kf_index(name) != 0) {
		/*
		 * A trunk port is IFT_IEEE8023ADLAG while it is in its trunk,
		 * and IFT_ETHER again once it leaves. Commit takes ports out
		 * of trunks before it adds them anywhere.
		 */
		if (kf_type(name) == IFT_IEEE8023ADLAG &&
		    cand_listowner(cand, name, "trunkport", name) == NULL)
			return IFT_ETHER;
		return kf_type(name);
	}
	return (kc = cand_cloner(name)) != NULL ? kc->type : 0;
}

/*
 * Does the kernel take the driver ioctl cmd for name? Only the drivers of
 * cloned interfaces take the ioctls kernel.c lists; any other answers
 * ENOTTY.
 */
int
cand_takes(char *name, u_long cmd)
{
	const struct kcloner *kc;
	const u_long *p;

	if ((kc = cand_cloner(name)) == NULL)
		return 0;
	for (p = kc->ioctls; *p != 0; p++)
		if (*p == cmd)
			return 1;
	return 0;
}

/* Has the candidate an interface or bridge block for name? */
int
cand_hasif(struct cand *cand, char *name)
{
	char head[sizeof("interface ") + IFNAMSIZ];

	if (strlen(name) >= IFNAMSIZ)
		return 0;
	snprintf(head, sizeof(head), "interface %s", name);
	if (conftree_has(cand->cur->tree, head))
		return 1;
	snprintf(head, sizeof(head), "bridge %s", name);
	return conftree_has(cand->cur->tree, head);
}

/*
 * The interface, other than name, whose candidate block has a line
 * called list with value among the words after its name, or NULL
 */
char *
cand_listowner(struct cand *cand, char *name, char *list, char *value)
{
	static char owner[IFNAMSIZ];
	char line[1024], *s, *ifn, *l, *w, *p;
	size_t i, n;

	for (i = 0; (s = conftree_stmt(cand->cur->tree, i)) != NULL; i++) {
		if (strncmp(s, "interface ", strlen("interface ")) == 0)
			ifn = s + strlen("interface ");
		else if (strncmp(s, "bridge ", strlen("bridge ")) == 0)
			ifn = s + strlen("bridge ");
		else
			continue;
		if (strcmp(ifn, name) == 0)
			continue;
		for (n = 0; (l = conftree_line(cand->cur->tree, s, list,
		    n)) != NULL; n++) {
			strlcpy(line, l, sizeof(line));
			strtok_r(line, " ", &p);
			while ((w = strtok_r(NULL, " ", &p)) != NULL)
				if (strcmp(w, value) == 0) {
					strlcpy(owner, ifn, sizeof(owner));
					return owner;
				}
		}
	}
	return NULL;
}

/* The n'th line, from 0, of a daemon's rules stmt, or NULL */
char *
cand_rule(struct cand *cand, char *stmt, size_t n)
{
	char rt[96], block[160];

	if (cand_rtcur(cand, rt, sizeof(rt)) == NULL)
		return conftree_line(cand->cur->tree, stmt, NULL, n);
	snprintf(block, sizeof(block), "%s\n%s", rt, stmt);
	return conftree_line(cand->cur->tree, block, NULL, n);
}

/*
 * Make the n lines in lines, in that order, the lines of a daemon's
 * rules stmt, an ordered statement; if n is 0, stmt is removed
 */
int
cand_setrules(struct cand *cand, char *stmt, char **lines, size_t n)
{
	struct sedit e;
	char rtbuf[96], block[160], *rt, *l;
	size_t i;

	if ((rt = cand_rtcur(cand, rtbuf, sizeof(rtbuf))) != NULL)
		snprintf(block, sizeof(block), "%s\n%s", rt, stmt);
	else
		strlcpy(block, stmt, sizeof(block));
	for (i = 0; i < n && (l = cand_rule(cand, stmt, i)) != NULL &&
	    strcmp(l, lines[i]) == 0; i++)
		;
	if (i == n && cand_rule(cand, stmt, n) == NULL &&
	    (n > 0 || !conftree_has(cand->cur->tree, block)))
		return 0;
	for (i = 0; i < n; i++)
		if (strlen(lines[i]) >= sizeof(e.line)) {
			printf("%% %s: line %zu is too long\n", stmt, i + 1);
			return -1;
		}
	e.keylen = 1;
	e.strict = 0;
	e.op = CE_NOBLOCK;
	strlcpy(e.line, stmt, sizeof(e.line));
	if (cand_record(cand, rt, &e) == -1)
		return -1;
	e.op = CE_SEQ;
	for (i = 0; i < n; i++) {
		strlcpy(e.line, lines[i], sizeof(e.line));
		if (cand_record(cand, block, &e) == -1)
			return -1;
	}
	return 0;
}

/*
 * rtable in configure private: with set, the rtable settings that
 * follow go into table's block, which is made if the candidate has none
 * and named name if name is not NULL.  Without set, the block is
 * removed.  Table 0's settings are at the top level.
 */
int
cand_rtable_set(struct cand *cand, int set, int table, char *name)
{
	char block[96], line[96];
	struct sedit e;
	int has;

	has = cand_rtblock(cand, block, sizeof(block), table) == 0;
	if (!set) {
		if (table == 0) {
			printf("%% cannot remove rtable %d\n", table);
			return -1;
		}
		if (!has) {
			printf("%% rtable %d is not in the candidate\n", table);
			return -1;
		}
		if (cand_set(cand, CTX_TOP, ST_OFF, NULL, block) == -1)
			return -1;
		cand_rtable = 0;
		return 0;
	}
	if (table != 0) {
		if (name != NULL && name[0] != '\0')
			snprintf(line, sizeof(line), "rtable %d %s", table,
			    name);
		else
			snprintf(line, sizeof(line), "rtable %d", table);
		if (!has) {
			if (cand_set(cand, CTX_TOP, ST_ON, NULL, line) == -1)
				return -1;
		} else if (name != NULL && strcmp(block, line) != 0) {
			/* renamed, with its lines */
			e.op = CE_RENAME;
			e.keylen = 1;
			e.strict = 0;
			strlcpy(e.line, line, sizeof(e.line));
			if (cand_record(cand, block, &e) == -1)
				return -1;
		}
	}
	cand_rtable = table;
	return 0;
}

/* The candidate's block for rtable table, in buf, or -1 if it has none */
static int
cand_rtblock(struct cand *cand, char *buf, size_t len, int table)
{
	char key[32], *s;
	size_t i;
	int n;

	n = snprintf(key, sizeof(key), "rtable %d", table);
	for (i = 0; (s = conftree_stmt(cand->cur->tree, i)) != NULL; i++)
		if (strncmp(s, key, n) == 0 && (s[n] == '\0' || s[n] == ' ')) {
			strlcpy(buf, s, len);
			return 0;
		}
	return -1;
}

/*
 * 1 if routing table id is there, or in configure private if it will be
 * once the candidate is committed. A table the kernel has stays, as the
 * kernel never destroys one. Else 0, after saying what makes one.
 */
int
rtable_there(int id, struct cand *cand)
{
	if (id == 0 || kf_rtable(id) ||
	    (cand != NULL && conftree_makes_rtable(cand->cur->tree, id)))
		return 1;
	printf("%% There is no rtable %d: an interface in rdomain %d, or a"
	    " route in rtable %d, makes it\n", id, id, id);
	return 0;
}

/* Has the candidate a block for rtable table? Table 0's is the top level */
int
cand_hasrtable(struct cand *cand, int table)
{
	char block[96];

	return table == 0 ||
	    cand_rtblock(cand, block, sizeof(block), table) == 0;
}

/* The current rtable's block, in buf, or NULL if there is none */
static char *
cand_rtcur(struct cand *cand, char *buf, size_t len)
{
	if (cand_rtable == 0 || cand_rtblock(cand, buf, len, cand_rtable) == -1)
		return NULL;
	return buf;
}

/* Is name a pppoe(4) interface? */
int
cand_ispppoe(char *name)
{
	const struct kcloner *kc;

	return (kc = cand_cloner(name)) != NULL &&
	    strcmp(kc->name, "pppoe") == 0;
}

/*
 * Is name a bridge in the candidate: a bridge block, or else no
 * interface block and a cloner that makes bridges?
 */
int
cand_isbridge(struct cand *cand, char *name)
{
	char head[sizeof("interface ") + IFNAMSIZ];
	const struct kcloner *kc;

	snprintf(head, sizeof(head), "bridge %s", name);
	if (conftree_has(cand->cur->tree, head))
		return 1;
	snprintf(head, sizeof(head), "interface %s", name);
	return !conftree_has(cand->cur->tree, head) &&
	    (kc = cand_cloner(name)) != NULL && kc->bridge;
}

/*
 * interface or bridge <name> in configure private: find or start the
 * interface's block in the candidate, or remove it with "no".  Sets
 * *isbridge to whether it takes the Bridgelist commands.  Returns 0 to
 * go on into interface mode, 1 when there is nothing more to do, and
 * -1 when it could not, after saying why.
 */
int
cand_interface(struct cand *cand, int set, char *name, int *isbridge)
{
	char head[sizeof("interface ") + IFNAMSIZ];
	int new;

	*isbridge = cand_isbridge(cand, name);
	snprintf(head, sizeof(head), "%s %s",
	    *isbridge ? "bridge" : "interface", name);

	if (!set) {
		if (!conftree_has(cand->cur->tree, head)) {
			printf("%% interface %s not found\n", name);
			return -1;
		}
		if (!cand_cloneable(name)) {
			printf("%% interface %s cannot be removed\n", name);
			return -1;
		}
		return cand_set(cand, CTX_TOP, ST_OFF, NULL,
		    head) == -1 ? -1 : 1;
	}
	if ((new = !conftree_has(cand->cur->tree, head)) && !kf_valid(name) &&
	    !cand_cloneable(name)) {
		printf("%% interface %s not found\n", name);
		return -1;
	}
	if (cand_set(cand, CTX_TOP, ST_ON, NULL, head) == -1)
		return -1;
	/* a new veb has vnetid 1, as the kernel makes it */
	if (new && default_vnetid(name) != 0 &&
	    cand_ifsetting(cand, name, ST_ON, "vnetid %lld",
	    default_vnetid(name)) == -1)
		return -1;
	return 0;
}

/*
 * The candidate as it stands: the journal replayed on a fresh copy of
 * the running configuration, or of what rollback N loaded.  It becomes
 * the session's view, so the caller must not free it.
 */
struct cnode *
cand_tree(struct cand *cand)
{
	struct cnode *t;

	if (cand->cur->base == NULL)
		t = running_tree();
	else if ((t = conftree_copy(cand->cur->base)) == NULL)
		printf("%% cand_tree: %s\n", strerror(errno));
	if (t == NULL)
		return NULL;
	if (cjournal_replay(cand->cur->journal, t) == -1) {
		printf("%% cand_tree: %s\n", strerror(errno));
		conftree_free(t);
		return NULL;
	}
	conftree_free(cand->cur->tree);
	cand->cur->tree = t;
	return cand->cur->tree;
}

/* The candidate, written to f: -1 on error, after saying why */
int
cand_write(struct cand *cand, FILE *f)
{
	struct cnode *t;

	if (!cand->on) {
		printf("%% Not in configure\n");
		return -1;
	}
	if ((t = cand_tree(cand)) == NULL)
		return -1;
	if (conftree_write(f, t) == -1 || fflush(f) == EOF) {
		printf("%% cand_write: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * The candidate starts over as base, which it keeps: saved configuration
 * n, or with n -1 a loaded one, for which nothing is printed; or as the
 * running configuration if base is NULL.  -1 if it could not, after
 * saying why
 */
int
cand_restart(struct cand *cand, struct cnode *base, int n)
{
	struct cnode *t;
	struct cjournal *j;

	if (cand_held != NULL) {
		printf("%% %s\n", cand_held);
		conftree_free(base);
		return -1;
	}
	if (base == NULL)
		t = running_tree();
	else if ((t = conftree_copy(base)) == NULL)
		printf("%% cand_rollback: %s\n", strerror(errno));
	if (t == NULL) {
		conftree_free(base);
		return -1;
	}
	if ((j = cjournal_new()) == NULL) {
		printf("%% cand_rollback: %s\n", strerror(errno));
		conftree_free(t);
		conftree_free(base);
		return -1;
	}
	conftree_free(cand->cur->tree);
	conftree_free(cand->cur->base);
	cjournal_free(cand->cur->journal);
	cand_forget(cand);
	cand->cur->tree = t;
	cand->cur->base = base;
	cand->cur->journal = j;
	cand->cur->nedits++;
	if (n == 0)
		printf("%% Candidate reset to the running configuration\n");
	else if (n > 0)
		printf("%% Candidate loaded from rollback %d\n", n);
	return 0;
}

/* The head of an interface's block: bridge or interface, and its name */
static void
cand_block(char *buf, size_t len, char *name, int isbridge)
{
	snprintf(buf, len, "%s %s", isbridge ? "bridge" : "interface", name);
}

/*
 * Put the setting fmt names into state, in name's block, a bridge block
 * if isbridge.  If name is empty, it goes at the top level, or in the
 * current rtable's block if it is an rtable setting
 */
static int
cand_vsetting(struct cand *cand, char *name, int isbridge, int state,
    const char *fmt, va_list ap)
{
	char line[1024], block[sizeof("interface ") + IFNAMSIZ], rtblock[96];
	int n;

	n = vsnprintf(line, sizeof(line), fmt, ap);
	if (n < 0 || (size_t)n >= sizeof(line)) {
		printf("%% Configuration line too long\n");
		return -1;
	}
	if (name[0] == '\0') {
		if (cand_rtable != 0 && setting_has(CTX_RTABLE, line) &&
		    cand_rtblock(cand, rtblock, sizeof(rtblock),
		    cand_rtable) == 0)
			return cand_set(cand, CTX_RTABLE, state, rtblock, line);
		return cand_set(cand, CTX_TOP, state, NULL, line);
	}
	cand_block(block, sizeof(block), name, isbridge);
	return cand_set(cand, isbridge ? CTX_BRIDGE : CTX_IF, state,
	    block, line);
}

/*
 * Put line's setting in context ctx into state, in block or at the top level
 */
static int
cand_set(struct cand *cand, int ctx, int state, char *block, char *line)
{
	struct sedit e;

	if (setting_edit(ctx, state, line, &e) == -1) {
		printf("%% cand_set: no setting for \"%s\"\n", line);
		return -1;
	}
	return cand_record(cand, block, &e);
}

/*
 * Make an edit on the session's view and record it if it changed
 * anything. A strict edit that changes nothing says so, and fails.
 */
static int
cand_record(struct cand *cand, char *block, struct sedit *e)
{
	int r;

	if (cand_held != NULL) {
		printf("%% %s\n", cand_held);
		return -1;
	}
	if (cand_remember(cand, block, e) == -1)
		return -1;
	errno = 0;
	if ((r = conftree_edit(cand->cur->tree, e->op, block, e->line,
	    e->keylen)) == -1) {
		/* conftree_edit() prints why, except when memory ran out */
		if (errno == ENOMEM)
			printf("%% cand_record: %s\n", strerror(errno));
		return -1;
	}
	if (r == CE_NOOP && e->strict) {
		printf("%% %s: not in the candidate\n", e->line);
		return -1;
	}
	if (r == CE_CHANGED && cjournal_add(cand->cur->journal, e->op, block,
	    e->line, e->keylen) == -1) {
		printf("%% cand_record: %s\n", strerror(errno));
		return -1;
	}
	if (r == CE_CHANGED)
		cand->cur->nedits++;
	return 0;
}

/*
 * Before an edit first changes a top-level statement, keep a copy of it,
 * except after rollback N.  -1 if it could not be kept, after saying why
 */
static int
cand_remember(struct cand *cand, char *block, struct sedit *e)
{
	struct cand_was *w;
	char top[1024], *p = e->line;
	int whole = 1;
	size_t i;

	if (cand->cur->base != NULL)
		return 0;
	if (block != NULL)
		p = block;
	else if (e->op != CE_BLOCK && e->op != CE_NOBLOCK) {
		/* the lines of its name, as conftree_edit() names lines */
		if (strncmp(p, "no ", 3) == 0)
			p += 3;
		whole = 0;
	}
	strlcpy(top, p, sizeof(top));
	top[strcspn(top, whole ? "\n" : " ")] = '\0';
	for (i = 0; i < cand->cur->nwas; i++)
		if (cand->cur->was[i].whole == whole &&
		    strcmp(cand->cur->was[i].top, top) == 0)
			return 0;
	if ((w = reallocarray(cand->cur->was, cand->cur->nwas + 1,
	    sizeof(*w))) == NULL) {
		printf("%% cand_remember: %s\n", strerror(errno));
		return -1;
	}
	cand->cur->was = w;
	w = &cand->cur->was[cand->cur->nwas];
	w->whole = whole;
	if ((w->top = strdup(top)) == NULL) {
		printf("%% cand_remember: %s\n", strerror(errno));
		return -1;
	}
	if ((w->image = cand_image(cand->cur->tree, top, whole)) == NULL) {
		free(w->top);
		return -1;
	}
	cand->cur->nwas++;
	return 0;
}

/* The text t has for top, whole or its lines, or NULL after saying why */
static char *
cand_image(struct cnode *t, char *top, int whole)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *f;
	int r;

	if ((f = open_memstream(&buf, &len)) == NULL) {
		printf("%% cand_image: %s\n", strerror(errno));
		return NULL;
	}
	r = conftree_write_stmt(f, t, top, whole);
	if (fclose(f) == EOF || r == -1) {
		printf("%% cand_image: %s\n", strerror(errno));
		free(buf);
		return NULL;
	}
	return buf;
}

/*
 * Report each statement the candidate changes that the running
 * configuration, now, has changed since.  Returns how many, or -1 after
 * saying why.  With rebase, what each was becomes what it is now, so the
 * next commit keeps the candidate's changes over it
 */
int
cand_conflicts(struct cand *cand, struct cnode *now, int rebase)
{
	char *image;
	size_t i;
	int n = 0;

	for (i = 0; i < cand->cur->nwas; i++) {
		if ((image = cand_image(now, cand->cur->was[i].top,
		    cand->cur->was[i].whole)) == NULL)
			return -1;
		if (strcmp(image, cand->cur->was[i].image) == 0) {
			free(image);
			continue;
		}
		printf("%% %s: another commit changed it after this "
		    "candidate did\n", cand->cur->was[i].top);
		n++;
		if (rebase) {
			free(cand->cur->was[i].image);
			cand->cur->was[i].image = image;
		} else
			free(image);
	}
	return n;
}

/* Free the saved copies of statements (cand->cur->was) */
static void
cand_forget(struct cand *cand)
{
	size_t i;

	for (i = 0; i < cand->cur->nwas; i++) {
		free(cand->cur->was[i].top);
		free(cand->cur->was[i].image);
	}
	free(cand->cur->was);
	cand->cur->was = NULL;
	cand->cur->nwas = 0;
}

/* The kernel's cloner for an interface called name, or NULL */
static const struct kcloner *
cand_cloner(char *name)
{
	const struct kcloner *kc;
	size_t l;

	if ((l = cloner_namelen(name)) == 0)
		return NULL;
	for (kc = kcloners; kc->name != NULL; kc++)
		if (strlen(kc->name) == l && strncmp(kc->name, name, l) == 0)
			return kc;
	return NULL;
}

/*
 * How much of name is a cloner's name, if the rest is a unit number as
 * if_clone_lookup() takes it: decimal, at most INT_MAX, and no leading
 * zero. 0 if name is not a cloned interface's name.
 */
static size_t
cloner_namelen(char *name)
{
	size_t l = strcspn(name, "0123456789"), n = strlen(name);
	const char *errstr;

	if (l == 0 || l == n || n >= IFNAMSIZ || (name[l] == '0' && n - l > 1))
		return 0;
	strtonum(name + l, 0, INT_MAX, &errstr);
	return errstr == NULL ? l : 0;
}

/* Could the running kernel create an interface called name? */
int
cand_cloneable(char *name)
{
	size_t l;

	return (l = cloner_namelen(name)) != 0 && kf_cloner(name, l);
}
