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
 * the journal first changed it, so a commit that finds another commit
 * changed it since is refused (cand_conflicts()); committing again keeps
 * this session's changes over the other's.
 *
 * nshd's configure is a candidate sessions share, struct cand_shared,
 * which a session takes as its own while it runs (session.c), and
 * leaves to the others when it leaves configure (cand_detach()). While
 * another session holds it, nshd's config sets cand_held, and no edit
 * or rollback changes it.
 *
 * A command takes part only as its table row says (cand): a CAND_EDIT
 * handler checks 'candidate' and calls cand_setting() where it would
 * have changed the kernel, a CAND_RUN command runs as it always does,
 * and any other command is refused until its handler is converted.
 * cand_setting() says what the command did to a setting; the settings
 * table (settings.c) turns that into the edit.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

int candidate;				/* configure private is on */
int cand_rtable;			/* the rtable its lines are for */
int cand_sharing;			/* the candidate is a shared one */
const char *cand_held;			/* why it may not change now, or NULL */

static struct cnode *cand;		/* this session's view of it */
static struct cjournal *cand_journal;	/* the changes it made */
static struct cnode *cand_base;		/* what rollback N loaded, or NULL */
static unsigned int cand_nedits;	/* the edits that changed it */

/* a top-level statement the journal changes, as it was before it did */
struct cand_was {
	char	*top;		/* the statement, or its lines' name */
	int	 whole;		/* the statement, else the lines of that name */
	char	*image;		/* as conftree_write_stmt() wrote it */
};
static struct cand_was *cand_was;
static size_t cand_nwas;

/* what a session keeps of this file (session.c) */
struct sglobal candidate_sglobals[] = {
	SGLOBAL(candidate), SGLOBAL(cand_rtable), SGLOBAL(cand),
	SGLOBAL(cand_journal), SGLOBAL(cand_base), SGLOBAL(cand_was),
	SGLOBAL(cand_nwas), SGLOBAL(cand_nedits), SGLOBAL(cand_sharing),
	{ NULL }
};

/* a candidate sessions share, as each takes it as its own */
struct cand_shared {
	struct cnode	*cand, *base;
	struct cjournal	*journal;
	struct cand_was	*was;
	size_t		 nwas;
	unsigned int	 nedits;
};

static int cand_record(char *, struct sedit *);
static int cand_remember(char *, struct sedit *);
static char *cand_image(struct cnode *, char *, int);
static void cand_forget(void);
static int cand_rtblock(char *, size_t, int);
static char *cand_rtcur(char *, size_t);
static int cand_set(int, int, char *, char *);
static void cand_block(char *, size_t, char *, int);
static int cand_vsetting(char *, int, int, const char *, va_list);
static const struct kcloner *cand_cloner(char *);
static size_t cloner_namelen(char *);

/*
 * configure private: start a candidate from the running configuration,
 * or take the shared one as it is, if it has begun
 */
int
cand_begin(void)
{
	if (candidate)
		return 0;
	if (cand_journal == NULL) {
		if ((cand = running_tree()) == NULL)
			return -1;
		if ((cand_journal = cjournal_new()) == NULL) {
			printf("%% cand_begin: %s\n", strerror(errno));
			conftree_free(cand);
			cand = NULL;
			return -1;
		}
	} else if (cand == NULL && cand_tree() == NULL)
		return -1;
	candidate = 1;
	cand_rtable = 0;
	return 0;
}

/* A candidate for sessions to share, not begun: NULL, errno set */
struct cand_shared *
cand_shared_new(void)
{
	return calloc(1, sizeof(struct cand_shared));
}

/* The shared candidate sh in as this session's if in, else out to sh */
void
cand_share(struct cand_shared *sh, int in)
{
	if (in) {
		cand = sh->cand;
		cand_base = sh->base;
		cand_journal = sh->journal;
		cand_was = sh->was;
		cand_nwas = sh->nwas;
		cand_nedits = sh->nedits;
	} else {
		sh->cand = cand;
		sh->base = cand_base;
		sh->journal = cand_journal;
		sh->was = cand_was;
		sh->nwas = cand_nwas;
		sh->nedits = cand_nedits;
	}
}

/* Leave the shared candidate, as it is, to the sessions that share it */
void
cand_detach(void)
{
	cand = NULL;
	cand_base = NULL;
	cand_journal = NULL;
	cand_was = NULL;
	cand_nwas = 0;
	cand_nedits = 0;
	candidate = 0;
	cand_rtable = 0;
	cand_sharing = 0;
}

/*
 * The shared candidate sh starts again from the running configuration:
 * -1, said why, and sh as it was, if it could not
 */
int
cand_shared_renew(struct cand_shared *sh)
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
	cand_share(sh, 1);
	cand_end();
	cand = t;
	cand_journal = j;
	cand_share(sh, 0);
	cand_detach();
	return 0;
}

/* Has the shared candidate sh changed? */
int
cand_shared_changed(struct cand_shared *sh)
{
	return sh->journal != NULL &&
	    (cjournal_len(sh->journal) > 0 || sh->base != NULL);
}

/* The edits that changed sh, since it began, counted */
unsigned int
cand_shared_edits(struct cand_shared *sh)
{
	return sh->nedits;
}

/*
 * The shared candidate sh, to f, as cand_shared_read() reads it: what
 * rollback N loaded, if it did, as "base LENGTH" and its text, each
 * edit of its journal as "edit OP KEYLEN BLOCKLENGTH LINELENGTH" and
 * its block, or -1 for none, and line, and each statement as it was
 * before an edit first changed it as "was WHOLE TOPLENGTH IMAGELENGTH"
 * and its name and text. -1 if it could not be written
 */
int
cand_shared_write(struct cand_shared *sh, FILE *f)
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

/* len bytes of text at *p, before end, as a string: NULL if not */
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
 * The shared candidate sh, which no session has begun, as
 * cand_shared_write() wrote it in the len bytes of text: -1, said why,
 * and sh as it was, if they are not one
 */
int
cand_shared_read(struct cand_shared *sh, char *text, size_t len)
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
	cand_share(sh, 1);
	cand_end();
	cand_base = base;
	cand_journal = j;
	cand_was = was;
	cand_nwas = nwas;
	cand_share(sh, 0);
	cand_detach();
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
cand_end(void)
{
	conftree_free(cand);
	conftree_free(cand_base);
	cjournal_free(cand_journal);
	cand_forget();
	cand = NULL;
	cand_base = NULL;
	cand_journal = NULL;
	cand_nedits = 0;
	candidate = 0;
	cand_rtable = 0;
}

/* Has this session changed its candidate? */
int
cand_changed(void)
{
	return candidate &&
	    (cjournal_len(cand_journal) > 0 || cand_base != NULL);
}

/*
 * A command in configure private: put the setting that line names into
 * state (ST_*), as the command would have in the kernel. In interface
 * or bridge mode the line goes into that interface's block.  line is
 * canonical, as conf() prints it, without "no". -1 if it could not,
 * said why, else 0, as a handler returns.
 */
int
cand_setting(int state, const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = cand_vsetting(ifname, bridge, state, fmt, ap);
	va_end(ap);
	return r;
}

/* cand_setting() for another interface, in the block the candidate has */
int
cand_ifsetting(char *name, int state, const char *fmt, ...)
{
	char head[sizeof("interface ") + IFNAMSIZ];
	va_list ap;
	int r;

	cand_block(head, sizeof(head), name, 1);
	va_start(ap, fmt);
	r = cand_vsetting(name, conftree_has(cand, head), state, fmt, ap);
	va_end(ap);
	return r;
}

/*
 * The n'th line named name, from 0, in the candidate's block for the
 * current interface, or at the top level outside one, or in the current
 * rtable's block if it is a line of an rtable's, or NULL
 */
char *
cand_line(char *name, size_t n)
{
	char block[sizeof("interface ") + IFNAMSIZ], rtblock[96];

	if (ifname[0] == '\0') {
		if (cand_rtable != 0 && setting_has(CTX_RTABLE, name) &&
		    cand_rtblock(rtblock, sizeof(rtblock), cand_rtable) == 0)
			return conftree_line(cand, rtblock, name, n);
		return conftree_line(cand, NULL, name, n);
	}
	cand_block(block, sizeof(block), ifname, bridge);
	return conftree_line(cand, block, name, n);
}

/* cand_line() for another interface */
char *
cand_ifline(char *ifn, char *name, size_t n)
{
	char block[sizeof("interface ") + IFNAMSIZ];

	cand_block(block, sizeof(block), ifn, 1);
	if (!conftree_has(cand, block))
		cand_block(block, sizeof(block), ifn, 0);
	return conftree_line(cand, block, name, n);
}

/*
 * Make the current interface's lines called one of names[] the lines in
 * buf, which a conf() printer wrote: each in place of the lines of its
 * key, and none it did not write.  A line with "no" turns its setting
 * off.  buf is changed.
 */
int
cand_putlines(char **names, size_t nnames, char *buf)
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
			cand_setting(ST_OFF, "%s", lines[i] + 3);
		else
			cand_setting(ST_ON, "%s", lines[i]);
	for (i = 0; i < nnames; i++)
		for (n = 0; (l = cand_line(names[i], n)) != NULL; n++) {
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
		cand_setting(ST_DEFAULT, "%s", strncmp(gone[i], "no ", 3) == 0 ?
		    gone[i] + 3 : gone[i]);
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
cand_state(char *name)
{
	char *l;

	if ((l = cand_line(name, 0)) == NULL)
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
cand_gettype(char *name)
{
	const struct kcloner *kc;

	if (kf_index(name) != 0)
		return kf_type(name);
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
cand_hasif(char *name)
{
	char head[sizeof("interface ") + IFNAMSIZ];

	if (strlen(name) >= IFNAMSIZ)
		return 0;
	snprintf(head, sizeof(head), "interface %s", name);
	if (conftree_has(cand, head))
		return 1;
	snprintf(head, sizeof(head), "bridge %s", name);
	return conftree_has(cand, head);
}

/*
 * The interface, other than name, whose candidate block has a line
 * called list with value among the words after its name, or NULL
 */
char *
cand_listowner(char *name, char *list, char *value)
{
	static char owner[IFNAMSIZ];
	char line[1024], *s, *ifn, *l, *w, *p;
	size_t i, n;

	for (i = 0; (s = conftree_stmt(cand, i)) != NULL; i++) {
		if (strncmp(s, "interface ", strlen("interface ")) == 0)
			ifn = s + strlen("interface ");
		else if (strncmp(s, "bridge ", strlen("bridge ")) == 0)
			ifn = s + strlen("bridge ");
		else
			continue;
		if (strcmp(ifn, name) == 0)
			continue;
		for (n = 0; (l = conftree_line(cand, s, list, n)) != NULL;
		    n++) {
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
cand_rule(char *stmt, size_t n)
{
	char rt[96], block[160];

	if (cand_rtcur(rt, sizeof(rt)) == NULL)
		return conftree_line(cand, stmt, NULL, n);
	snprintf(block, sizeof(block), "%s\n%s", rt, stmt);
	return conftree_line(cand, block, NULL, n);
}

/*
 * Make the n lines in lines the lines of a daemon's rules stmt, an
 * ordered statement, in order; with none, stmt goes
 */
int
cand_setrules(char *stmt, char **lines, size_t n)
{
	struct sedit e;
	char rtbuf[96], block[160], *rt, *l;
	size_t i;

	if ((rt = cand_rtcur(rtbuf, sizeof(rtbuf))) != NULL)
		snprintf(block, sizeof(block), "%s\n%s", rt, stmt);
	else
		strlcpy(block, stmt, sizeof(block));
	for (i = 0; i < n && (l = cand_rule(stmt, i)) != NULL &&
	    strcmp(l, lines[i]) == 0; i++)
		;
	if (i == n && cand_rule(stmt, n) == NULL &&
	    (n > 0 || !conftree_has(cand, block)))
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
	if (cand_record(rt, &e) == -1)
		return -1;
	e.op = CE_SEQ;
	for (i = 0; i < n; i++) {
		strlcpy(e.line, lines[i], sizeof(e.line));
		if (cand_record(block, &e) == -1)
			return -1;
	}
	return 0;
}

/*
 * rtable in configure private: with set, the lines of an rtable's that
 * follow are table's, in its block, called name if name is not NULL,
 * which is made if the candidate has none; without, the block goes.
 * Table 0's are the top level's.
 */
int
cand_rtable_set(int set, int table, char *name)
{
	char block[96], line[96];
	struct sedit e;
	int has;

	has = cand_rtblock(block, sizeof(block), table) == 0;
	if (!set) {
		if (table == 0) {
			printf("%% cannot remove rtable %d\n", table);
			return -1;
		}
		if (!has) {
			printf("%% rtable %d is not in the candidate\n", table);
			return -1;
		}
		if (cand_set(CTX_TOP, ST_OFF, NULL, block) == -1)
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
			if (cand_set(CTX_TOP, ST_ON, NULL, line) == -1)
				return -1;
		} else if (name != NULL && strcmp(block, line) != 0) {
			/* renamed, with its lines */
			e.op = CE_RENAME;
			e.keylen = 1;
			e.strict = 0;
			strlcpy(e.line, line, sizeof(e.line));
			if (cand_record(block, &e) == -1)
				return -1;
		}
	}
	cand_rtable = table;
	return 0;
}

/* The candidate's block for rtable table, in buf, or -1 if it has none */
static int
cand_rtblock(char *buf, size_t len, int table)
{
	char key[32], *s;
	size_t i;
	int n;

	n = snprintf(key, sizeof(key), "rtable %d", table);
	for (i = 0; (s = conftree_stmt(cand, i)) != NULL; i++)
		if (strncmp(s, key, n) == 0 && (s[n] == '\0' || s[n] == ' ')) {
			strlcpy(buf, s, len);
			return 0;
		}
	return -1;
}

/* The current rtable's block, in buf, or NULL for table 0 */
static char *
cand_rtcur(char *buf, size_t len)
{
	if (cand_rtable == 0 || cand_rtblock(buf, len, cand_rtable) == -1)
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
cand_isbridge(char *name)
{
	char head[sizeof("interface ") + IFNAMSIZ];
	const struct kcloner *kc;

	snprintf(head, sizeof(head), "bridge %s", name);
	if (conftree_has(cand, head))
		return 1;
	snprintf(head, sizeof(head), "interface %s", name);
	return !conftree_has(cand, head) &&
	    (kc = cand_cloner(name)) != NULL && kc->bridge;
}

/*
 * interface or bridge <name> in configure private: find or start the
 * interface's block in the candidate, or remove it with "no".  Sets
 * *isbridge to whether it takes the Bridgelist commands.  Returns 0 to
 * go on into interface mode, 1 when there is nothing more to do, and
 * -1 when it could not, said why.
 */
int
cand_interface(int set, char *name, int *isbridge)
{
	char head[sizeof("interface ") + IFNAMSIZ];

	*isbridge = cand_isbridge(name);
	snprintf(head, sizeof(head), "%s %s",
	    *isbridge ? "bridge" : "interface", name);

	if (!set) {
		if (!conftree_has(cand, head)) {
			printf("%% interface %s not found\n", name);
			return -1;
		}
		if (!cand_cloneable(name)) {
			printf("%% interface %s cannot be removed\n", name);
			return -1;
		}
		return cand_set(CTX_TOP, ST_OFF, NULL, head) == -1 ? -1 : 1;
	}
	if (!conftree_has(cand, head) && !kf_valid(name) &&
	    !cand_cloneable(name)) {
		printf("%% interface %s not found\n", name);
		return -1;
	}
	return cand_set(CTX_TOP, ST_ON, NULL, head) == -1 ? -1 : 0;
}

/*
 * The candidate as it stands: the journal replayed on a fresh copy of
 * the running configuration, or of what rollback N loaded.  It becomes
 * the session's view, so the caller must not free it.
 */
struct cnode *
cand_tree(void)
{
	struct cnode *t;

	if (cand_base == NULL)
		t = running_tree();
	else if ((t = conftree_copy(cand_base)) == NULL)
		printf("%% cand_tree: %s\n", strerror(errno));
	if (t == NULL)
		return NULL;
	if (cjournal_replay(cand_journal, t) == -1) {
		printf("%% cand_tree: %s\n", strerror(errno));
		conftree_free(t);
		return NULL;
	}
	conftree_free(cand);
	cand = t;
	return cand;
}

/* The candidate, written to f: -1 if it could not be, said why */
int
cand_write(FILE *f)
{
	struct cnode *t;

	if (!candidate) {
		printf("%% Not in configure private\n");
		return -1;
	}
	if ((t = cand_tree()) == NULL)
		return -1;
	if (conftree_write(f, t) == -1 || fflush(f) == EOF) {
		printf("%% cand_write: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* show candidate-config */
int
pr_cand_conf(int argc, char **argv, ...)
{
	char path[PATH_MAX];
	FILE *f;
	int fd, ret = 0;

	/* configure private, nshd's */
	if (nshd_config)
		return nshd_cshow("candidate-config");
	if (!candidate) {
		printf("%% Not in configure private\n");
		return -1;
	}
	strlcpy(path, "/tmp/nshrc.cand.XXXXXXXX", sizeof(path));
	if ((fd = mkstemp(path)) == -1) {
		printf("%% mkstemp %s: %s\n", path, strerror(errno));
		return -1;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		printf("%% fdopen %s: %s\n", path, strerror(errno));
		unlink(path);
		close(fd);
		return -1;
	}
	if (cand_write(f) == -1 || !more(path))
		ret = -1;
	unlink(path);
	fclose(f);
	return ret;
}

/*
 * rollback [N]: drop this session's changes to the candidate, which is
 * the running configuration again, or configuration N as it was saved
 */
int
cand_rollback(int argc, char **argv, ...)
{
	char path[PATH_MAX];
	struct cnode *base = NULL;
	const char *errstr;
	int n = 0;

	if (!candidate && !nshd_config) {
		printf("%% rollback requires configure private\n");
		return -1;
	}
	if (argc > 2) {
		printf("%% rollback [0-%d]\n", ROLLBACKS - 1);
		return -1;
	}
	if (argc == 2) {
		n = strtonum(argv[1], 0, ROLLBACKS - 1, &errstr);
		if (errstr != NULL) {
			printf("%% rollback %s is %s\n", argv[1], errstr);
			return -1;
		}
	}
	/* configure private, nshd's */
	if (nshd_config)
		return nshd_rollback(n);
	if (n > 0) {
		snprintf(path, sizeof(path), ROLLBACK, n);
		if (access(path, R_OK) == -1) {
			printf("%% rollback %d: %s\n", n, strerror(errno));
			return -1;
		}
		if ((base = conftree_read(path, conf_mode, conf_ordered)) ==
		    NULL)
			return -1;
	}
	return cand_restart(base, n);
}

/*
 * The candidate starts over as base, which it keeps: configuration n as
 * it was saved, or with n -1 one loaded, which says nothing; or as the
 * running configuration if NULL: -1 if it could not, said why
 */
int
cand_restart(struct cnode *base, int n)
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
	conftree_free(cand);
	conftree_free(cand_base);
	cjournal_free(cand_journal);
	cand_forget();
	cand = t;
	cand_base = base;
	cand_journal = j;
	cand_nedits++;
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
 * if isbridge, or at the top level if name is empty
 */
static int
cand_vsetting(char *name, int isbridge, int state, const char *fmt,
    va_list ap)
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
		    cand_rtblock(rtblock, sizeof(rtblock), cand_rtable) == 0)
			return cand_set(CTX_RTABLE, state, rtblock, line);
		return cand_set(CTX_TOP, state, NULL, line);
	}
	cand_block(block, sizeof(block), name, isbridge);
	return cand_set(isbridge ? CTX_BRIDGE : CTX_IF, state, block, line);
}

/*
 * Put line's setting in context ctx into state, in block or at the top level
 */
static int
cand_set(int ctx, int state, char *block, char *line)
{
	struct sedit e;

	if (setting_edit(ctx, state, line, &e) == -1) {
		printf("%% cand_set: no setting for \"%s\"\n", line);
		return -1;
	}
	return cand_record(block, &e);
}

/*
 * Make an edit on the session's view and record it if it changed
 * anything. A strict edit that changes nothing says so, and fails.
 */
static int
cand_record(char *block, struct sedit *e)
{
	int r;

	if (cand_held != NULL) {
		printf("%% %s\n", cand_held);
		return -1;
	}
	if (cand_remember(block, e) == -1)
		return -1;
	errno = 0;
	if ((r = conftree_edit(cand, e->op, block, e->line, e->keylen)) ==
	    -1) {
		/* conftree_edit() says why, but when memory ran out */
		if (errno == ENOMEM)
			printf("%% cand_record: %s\n", strerror(errno));
		return -1;
	}
	if (r == CE_NOOP && e->strict) {
		printf("%% %s: not in the candidate\n", e->line);
		return -1;
	}
	if (r == CE_CHANGED && cjournal_add(cand_journal, e->op, block,
	    e->line, e->keylen) == -1) {
		printf("%% cand_record: %s\n", strerror(errno));
		return -1;
	}
	if (r == CE_CHANGED)
		cand_nedits++;
	return 0;
}

/*
 * Before an edit first changes a top-level statement, what it was, but
 * on a rollback N's configuration: -1, said why, if it could not be
 * kept
 */
static int
cand_remember(char *block, struct sedit *e)
{
	struct cand_was *w;
	char top[1024], *p = e->line;
	int whole = 1;
	size_t i;

	if (cand_base != NULL)
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
	for (i = 0; i < cand_nwas; i++)
		if (cand_was[i].whole == whole &&
		    strcmp(cand_was[i].top, top) == 0)
			return 0;
	if ((w = reallocarray(cand_was, cand_nwas + 1, sizeof(*w))) == NULL) {
		printf("%% cand_remember: %s\n", strerror(errno));
		return -1;
	}
	cand_was = w;
	w = &cand_was[cand_nwas];
	w->whole = whole;
	if ((w->top = strdup(top)) == NULL) {
		printf("%% cand_remember: %s\n", strerror(errno));
		return -1;
	}
	if ((w->image = cand_image(cand, top, whole)) == NULL) {
		free(w->top);
		return -1;
	}
	cand_nwas++;
	return 0;
}

/* What t has of top, whole or its lines, as text: NULL, said why, if not */
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
 * The statements the candidate changes that the running configuration,
 * now, has changed since, each said: how many, or -1, said why. With
 * rebase, what each was becomes what it is now, so the next commit
 * keeps the candidate's changes over it
 */
int
cand_conflicts(struct cnode *now, int rebase)
{
	char *image;
	size_t i;
	int n = 0;

	for (i = 0; i < cand_nwas; i++) {
		if ((image = cand_image(now, cand_was[i].top,
		    cand_was[i].whole)) == NULL)
			return -1;
		if (strcmp(image, cand_was[i].image) == 0) {
			free(image);
			continue;
		}
		printf("%% %s: another commit changed it after this "
		    "candidate did\n", cand_was[i].top);
		n++;
		if (rebase) {
			free(cand_was[i].image);
			cand_was[i].image = image;
		} else
			free(image);
	}
	return n;
}

/* No statement's before */
static void
cand_forget(void)
{
	size_t i;

	for (i = 0; i < cand_nwas; i++) {
		free(cand_was[i].top);
		free(cand_was[i].image);
	}
	free(cand_was);
	cand_was = NULL;
	cand_nwas = 0;
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
