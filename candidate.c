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
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/if.h>
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

int candidate;				/* configure private is on */

static struct cnode *cand;		/* this session's view of it */
static struct cjournal *cand_journal;	/* the changes it made */

static int cand_record(char *, struct sedit *);
static int cand_set(int, int, char *, char *);
static void cand_block(char *, size_t, char *, int);
static int cand_vsetting(char *, int, int, const char *, va_list);
static const struct kcloner *cand_cloner(char *);
static size_t cloner_namelen(char *);
static int cand_cloneable(char *);

/* configure private: start a candidate from the running configuration */
int
cand_begin(void)
{
	if (candidate)
		return 0;
	if ((cand = running_tree()) == NULL)
		return -1;
	if ((cand_journal = cjournal_new()) == NULL) {
		printf("%% cand_begin: %s\n", strerror(errno));
		conftree_free(cand);
		cand = NULL;
		return -1;
	}
	candidate = 1;
	return 0;
}

/* Leave configure private, dropping the candidate. */
void
cand_end(void)
{
	conftree_free(cand);
	cjournal_free(cand_journal);
	cand = NULL;
	cand_journal = NULL;
	candidate = 0;
}

/* Has this session changed its candidate? */
int
cand_changed(void)
{
	return candidate && cjournal_len(cand_journal) > 0;
}

/*
 * A command in configure private: put the setting that line names into
 * state (ST_*), as the command would have in the kernel. In interface
 * or bridge mode the line goes into that interface's block.  line is
 * canonical, as conf() prints it, without "no".
 */
int
cand_setting(int state, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	cand_vsetting(ifname, bridge, state, fmt, ap);
	va_end(ap);
	return 0;
}

/* cand_setting() for another interface, in the block the candidate has */
int
cand_ifsetting(char *name, int state, const char *fmt, ...)
{
	char head[sizeof("interface ") + IFNAMSIZ];
	va_list ap;

	cand_block(head, sizeof(head), name, 1);
	va_start(ap, fmt);
	cand_vsetting(name, conftree_has(cand, head), state, fmt, ap);
	va_end(ap);
	return 0;
}

/*
 * The n'th line named name, from 0, in the candidate's block for the
 * current interface, or NULL
 */
char *
cand_line(char *name, size_t n)
{
	char block[sizeof("interface ") + IFNAMSIZ];

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

	if (if_nametoindex(name) != 0)
		return get_ifflags(name, ifs);
	return (kc = cand_cloner(name)) != NULL ? kc->flags : 0;
}

/* The if_type of an interface, from the kernel or its cloner */
int
cand_gettype(char *name)
{
	const struct kcloner *kc;

	if (if_nametoindex(name) != 0)
		return get_ifdata(name, IFDATA_IFTYPE);
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
 * go on into interface mode, 1 when there is nothing more to do.
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
			return 1;
		}
		if (!cand_cloneable(name)) {
			printf("%% interface %s cannot be removed\n", name);
			return 1;
		}
		cand_set(CTX_TOP, ST_OFF, NULL, head);
		return 1;
	}
	if (!conftree_has(cand, head) && !is_valid_ifname(name) &&
	    !cand_cloneable(name)) {
		printf("%% interface %s not found\n", name);
		return 1;
	}
	cand_set(CTX_TOP, ST_ON, NULL, head);
	return 0;
}

/*
 * The candidate as it stands: the journal replayed on a fresh copy of
 * the running configuration.  It becomes the session's view, so the
 * caller must not free it.
 */
struct cnode *
cand_tree(void)
{
	struct cnode *t;

	if ((t = running_tree()) == NULL)
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

/* show candidate-config */
int
pr_cand_conf(int argc, char **argv, ...)
{
	char path[PATH_MAX];
	struct cnode *t;
	FILE *f;
	int fd;

	if (!candidate) {
		printf("%% Not in configure private\n");
		return 0;
	}
	if ((t = cand_tree()) == NULL)
		return 0;
	strlcpy(path, "/tmp/nshrc.cand.XXXXXXXX", sizeof(path));
	if ((fd = mkstemp(path)) == -1) {
		printf("%% mkstemp %s: %s\n", path, strerror(errno));
		return 0;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		printf("%% fdopen %s: %s\n", path, strerror(errno));
		unlink(path);
		close(fd);
		return 0;
	}
	if (conftree_write(f, t) == -1 || fflush(f) == EOF)
		printf("%% %s: %s\n", path, strerror(errno));
	else
		more(path);
	unlink(path);
	fclose(f);
	return 0;
}

/* rollback [0]: drop this session's changes to the candidate */
int
cand_rollback(int argc, char **argv, ...)
{
	struct cnode *t;
	struct cjournal *j;

	if (!candidate) {
		printf("%% rollback requires configure private\n");
		return 0;
	}
	if (argc > 2 || (argc == 2 && strcmp(argv[1], "0") != 0)) {
		printf("%% rollback [0]\n");
		return 0;
	}
	if ((t = running_tree()) == NULL)
		return 0;
	if ((j = cjournal_new()) == NULL) {
		printf("%% cand_rollback: %s\n", strerror(errno));
		conftree_free(t);
		return 0;
	}
	conftree_free(cand);
	cjournal_free(cand_journal);
	cand = t;
	cand_journal = j;
	printf("%% Candidate reset to the running configuration\n");
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
	char line[1024], block[sizeof("interface ") + IFNAMSIZ];
	int n;

	n = vsnprintf(line, sizeof(line), fmt, ap);
	if (n < 0 || (size_t)n >= sizeof(line)) {
		printf("%% Configuration line too long\n");
		return 0;
	}
	if (name[0] == '\0')
		return cand_set(CTX_TOP, state, NULL, line);
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
 * anything. A strict edit that changes nothing says so.
 */
static int
cand_record(char *block, struct sedit *e)
{
	int r;

	if ((r = conftree_edit(cand, e->op, block, e->line, e->keylen)) == -1)
		return -1;
	if (r == CE_NOOP && e->strict) {
		printf("%% %s: not in the candidate\n", e->line);
		return 0;
	}
	if (r == CE_CHANGED && cjournal_add(cand_journal, e->op, block,
	    e->line, e->keylen) == -1) {
		printf("%% cand_record: %s\n", strerror(errno));
		return -1;
	}
	return 0;
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
static int
cand_cloneable(char *name)
{
	struct if_clonereq ifcr;
	char *buf = NULL, *cp;
	size_t l;
	int s, i, ret = 0;

	if ((l = cloner_namelen(name)) == 0)
		return 0;
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return 0;
	memset(&ifcr, 0, sizeof(ifcr));
	if (ioctl(s, SIOCIFGCLONERS, &ifcr) == -1)
		goto done;
	if ((buf = calloc(ifcr.ifcr_total, IFNAMSIZ)) == NULL)
		goto done;
	ifcr.ifcr_count = ifcr.ifcr_total;
	ifcr.ifcr_buffer = buf;
	if (ioctl(s, SIOCIFGCLONERS, &ifcr) == -1)
		goto done;
	if (ifcr.ifcr_count > ifcr.ifcr_total)
		ifcr.ifcr_count = ifcr.ifcr_total;
	for (cp = buf, i = 0; i < ifcr.ifcr_count; i++, cp += IFNAMSIZ) {
		if (strnlen(cp, IFNAMSIZ) == l && strncmp(name, cp, l) == 0) {
			ret = 1;
			break;
		}
	}
done:
	free(buf);
	close(s);
	return ret;
}
