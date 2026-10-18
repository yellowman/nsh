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
#include "commands.h"
#include "conftree.h"
#include "settings.h"

int candidate;				/* configure private is on */

static struct cnode *cand;		/* this session's view of it */
static struct cjournal *cand_journal;	/* the changes it made */

static int cand_record(int, char *, char *);
static int cand_set(int, int, char *, char *);
static int cand_bridgelike(char *);
static int cand_cloneable(char *);

/*
 * Interfaces that is_bridge() calls bridges, which conf() prints as
 * "bridge <name>" and which take the Bridgelist commands.  A new one
 * is not in the kernel yet to ask, so its cloner's name says.  From the
 * kernel: if_type IFT_BRIDGE in if_bridge.c, if_veb.c and if_tpmr.c,
 * and a SIOCBRDGRTS handler in if_bpe.c, if_gre.c (nvgre) and
 * if_vxlan.c.
 */
static const char *bridgelike[] = {
	"bridge", "veb", "tpmr", "bpe", "nvgre", "vxlan",
};

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
	char line[1024], block[sizeof("interface ") + IFNAMSIZ];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(line)) {
		printf("%% Configuration line too long\n");
		return 0;
	}
	if (ifname[0] == '\0') {
		cand_set(CTX_TOP, state, NULL, line);
		return 0;
	}
	snprintf(block, sizeof(block), "%s %s",
	    bridge ? "bridge" : "interface", ifname);
	cand_set(bridge ? CTX_BRIDGE : CTX_IF, state, block, line);
	return 0;
}

/* Does the candidate's block for the current interface have a line named name? */
int
cand_named(char *name)
{
	char block[sizeof("interface ") + IFNAMSIZ];

	snprintf(block, sizeof(block), "%s %s",
	    bridge ? "bridge" : "interface", ifname);
	return conftree_named(cand, block, name);
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

	snprintf(head, sizeof(head), "bridge %s", name);
	if (conftree_has(cand, head))
		*isbridge = 1;
	else {
		snprintf(head, sizeof(head), "interface %s", name);
		*isbridge = !conftree_has(cand, head) && cand_bridgelike(name);
	}
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

/*
 * Put line's setting in context ctx into state, in block or at the top level
 */
static int
cand_set(int ctx, int state, char *block, char *line)
{
	char edit[1024];
	int op;

	if ((op = setting_edit(ctx, state, line, edit, sizeof(edit))) == -1) {
		printf("%% cand_set: no setting for \"%s\"\n", line);
		return -1;
	}
	return cand_record(op, block, edit);
}

/*
 * Make an edit on the session's view and record it if it changed
 * anything. Removing a line or value that is not there says so.
 */
static int
cand_record(int op, char *block, char *line)
{
	int r;

	if ((r = conftree_edit(cand, op, block, line)) == -1)
		return -1;
	if (r == CE_NOOP && (op == CE_DEL || op == CE_LISTDEL ||
	    op == CE_NOBLOCK)) {
		printf("%% %s: not in the candidate\n", line);
		return 0;
	}
	if (r == CE_CHANGED &&
	    cjournal_add(cand_journal, op, block, line) == -1) {
		printf("%% cand_record: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int
cand_bridgelike(char *name)
{
	size_t i, l;

	for (i = 0; i < nitems(bridgelike); i++) {
		l = strlen(bridgelike[i]);
		if (strncmp(name, bridgelike[i], l) == 0 &&
		    name[l] >= '0' && name[l] <= '9')
			return 1;
	}
	return 0;
}

/*
 * Could the kernel create an interface called name: is it a cloner's
 * name (SIOCIFGCLONERS) followed by a unit number?
 */
static int
cand_cloneable(char *name)
{
	struct if_clonereq ifcr;
	char *buf = NULL, *cp;
	size_t l;
	int s, i, ret = 0;

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
		l = strnlen(cp, IFNAMSIZ);
		if (strncmp(name, cp, l) == 0 && name[l] != '\0' &&
		    strspn(name + l, "0123456789") == strlen(name + l)) {
			ret = 1;
			break;
		}
	}
done:
	free(buf);
	close(s);
	return ret;
}
