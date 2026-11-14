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
 * commit: make the candidate the running configuration, and save it.
 *
 * What differs between the running configuration and the candidate
 * becomes a script, lines as conf() prints them. First it removes
 * lines, in the reverse of the order conf() prints them, then it adds
 * lines, in that order, whatever order an interface's or a bridge's
 * lines were typed in (setting_rank()):
 *
 *  * a line is removed with its "no" form, and "no x" with x, unless the
 *    candidate sets the same setting another way, with its own line;
 *  * a list loses the values the candidate's line does not have;
 *  * an interface's addresses are added again after a new rdomain,
 *    which removed them, and its dhcrelay6, which still runs in the
 *    old rdomain's routing table; its endpoints after a new tunnel,
 *    tunneladdr, tunneldomain, vnetid or parent, which removed them,
 *    and its WEP and WPA lines after a new nwid, which turned them off;
 *  * a cloned interface is removed whole, and a physical one line by
 *    line;
 *  * a daemon's state is removed with its disable, and its rules by
 *    removing the rules file;
 *  * a block's new lines are added under it, and a list's new values;
 *  * a daemon's rules are added whole, and what conf() prints after
 *    them, its reload or install, when they are new or it starts.
 *
 * script_make() makes the script from the two trees alone, and its
 * edits from the script: each line becomes a record, with its words,
 * that names its command only by its place among the commands a
 * configuration has (conf_cmd(), ctl_act()). script_run() runs the
 * edits, so one process may make what another runs, and the code that
 * runs them reads no command's name: it runs the command at an edit's
 * place. A record that names no such place, or is where it does not
 * belong, stops all of them before any runs.
 *
 * Then the running configuration must read as the candidate does, but
 * for a physical interface the candidate has no block for, which keeps
 * what its hardware has. If it does not, a script that restores the
 * configuration as it was undoes the commit, and the differences are
 * shown.
 *
 * The last ROLLBACKS saved configurations are kept, for rollback N and
 * show rollback. Each records who saved it and the comment they gave,
 * on a line of its own that conftree_read() skips, and its generation
 * on the next. system keeps what those lines say: the parser reads them
 * as nshd starts (rollback_heads()), and system keeps those it writes.
 *
 * commit check shows what it can find in advance that would keep the
 * candidate from being the running configuration: an interface a
 * line names that is not there, one in two trunks or bridges, a bridge
 * option for one not its member, an address twice in one rdomain, a
 * vlan or carp id twice on one interface, a daemon in an rtable nothing
 * makes, and daemon rules their test refuses. commit refuses a
 * candidate with any of them.
 *
 * nshd's boot applies the saved configuration to the running one as
 * commit applies the candidate, and keeps every line that succeeds;
 * nothing is undone (session_boot_plan()).
 *
 * commit confirmed does all that but save; unless a commit confirms it
 * first, at the deadline nshd's system rolls the running configuration
 * back to how it was before the first unconfirmed commit, as it undoes
 * a commit that did not take (commit_undo()).
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "externs.h"
#include "ctl.h"
#include "conftree.h"
#include "settings.h"
#include "kfacts.h"
#include "session.h"
#include "facts.h"
#include "args.h"


struct commit {
	FILE *f;			/* the script's lines */
	struct cnode *from, *to;	/* the configurations it goes between */
	struct script *s;
};

/* each kept configuration's head lines, as system keeps them */
static struct rollback_head heads[ROLLBACKS];

/* A buffer for a block's lines, whose head waits on them */
struct sub {
	FILE *save;
	char *buf;
	size_t len;
};

/* A line, ranked by where conf() prints it within its block */
struct ranked {
	char *line;
	int rank;
	size_t i;
};

/* What each interface claims that only one may: a port, an address */
struct claims {
	struct {
		char *what;
		char who[IFNAMSIZ];
	} *v;
	size_t n;
};

/*
 * A script's edits. Each record is this header followed by len bytes:
 * for a line, its words after the command and any "no", each ending in
 * a NUL; for a line whose command parses its arguments (an argcmd in
 * its row, args.h), the parsed values instead, as a facts template and
 * record; for a daemon's rules, their lines, each ending in a newline.
 */
struct edit {
	uint8_t		kind;		/* EDIT_* */
	uint8_t		no;		/* 1 if the line starts with "no" */
	uint8_t		typed;		/* 1 if the bytes are parsed values */
	uint16_t	row;		/* command row, or daemon index */
	int32_t		act;		/* what the daemon does (ctl_act()) */
	uint32_t	len;
};
#define EDIT_TOP	1	/* a top-level statement, CTX_TOP's */
#define EDIT_IF		2	/* a line of an interface's block, CTX_IF's */
#define EDIT_BRIDGE	3	/* a line of a bridge's block, CTX_BRIDGE's */
#define EDIT_END	4	/* a block's end */
#define EDIT_RULES	5	/* a daemon's rules */
#define EDIT_DAEMON	6	/* a daemon's state, or what follows its rules */

/* in nshd's config, the rule tests check() saves for the system process */
static struct plan_test *deferred;
static int ndeferred;

/* An interface's lines that name other interfaces: the word, or 0 for all */
static const struct {
	char *name;
	int word;
} ifrefs[] = {
	{ "parent", 1 }, { "carpdev", 1 }, { "syncdev", 1 }, { "patch", 1 },
	{ "pppoe dev", 1 }, { "trunkport", 0 },
};

static int check(struct cnode *, struct cnode *);
static int edits_make(struct script *, int);
static int edits_line(FILE *, int, char *, int *, int *, char *);
static int edit_put(FILE *, struct edit *, char *, size_t);
static int edits_check(char *, size_t);
static int edit_args(FILE *, struct edit *, const struct argcmd *, int,
    char **);
static int edit_typed(const struct argcmd *, struct edit *, char *, int,
    int, char *);
static int edits_apply(char *, size_t);
static int check_if(struct cnode *, char *, char *, struct claims *);
static int check_ports(struct cnode *, char *, char *, char *,
    struct claims *);
static int check_ids(struct cnode *, char *, char *, struct claims *);
static int check_rtable(struct cnode *, char *);
static int check_rules(struct cnode *, struct cnode *, char *);
static int rules_test(char *, char **, size_t, char *);
static int ifthere(struct cnode *, char *);
static int inwords(char *, char *);
static char *claim(struct claims *, char *, char *);
static int problem(const char *, ...);
static int removals(struct commit *, char *, char *, int, const char *);
static int additions(struct commit *, char *, char *, int, const char *);
static int unset(struct commit *, char *, int, int, const char *, char *);
static void set(struct commit *, char *, int, int, char *);
static int islist(int, char *);
static char *listline(struct cnode *, char *, char *);
static char *listvalues(char *);
static void values(FILE *, const char *, char *, char *, int);
static int renewed(struct commit *, char *, char *, char *);
static int differ(FILE *, struct cnode *, struct cnode *);
static int ranked(struct cnode *, char *, struct ranked **, size_t *);
static int byrank(const void *, const void *);
static char *counterpart(struct cnode *, char *, char *);
static char *under(char *, char *);
static int has(struct cnode *, char *, char *);
static int samelines(struct cnode *, char *, struct cnode *, char *);
static int sameline(struct cnode *, char *, struct cnode *, char *, char *);
static int address(char *);
static int relay6(char *);
static int endpoint(char *);
static int wifikey(char *);
static int context(char *);
static int rtableid(char *);
static int ifblock(char *, char *, size_t);
static int clear(struct commit *, char *, int, int);
static int samefile(const char *);
static char *file_text(const char *, size_t *);
static int copyfile(const char *, char *, char *);
static int syncdir(const char *);
static int sub_begin(struct commit *, struct sub *);
static void sub_end(struct commit *, struct sub *, const char *, char *,
    int);

/* The problems check() finds with want, each reported, and how many */
int
commit_problems(struct cnode *was, struct cnode *want)
{
	return check(was, want);
}

/* The verdict on bad problems: said unless none and not checking */
int
commit_verdict(int bad, int checking)
{
	if (bad == 0 && !checking)
		return 0;
	if (bad == 0)
		printf("%% Configuration check succeeds\n");
	else
		printf("%% %s: %d problem%s\n", checking ?
		    "Configuration check fails" : "Commit refused",
		    bad, bad == 1 ? "" : "s");
	return bad == 0 ? 0 : -1;
}

/* Does the running configuration, now, read as want? */
int
commit_took(struct cnode *now, struct cnode *want)
{
	return differ(NULL, now, want) == 0;
}

/* Report a failed commit, and how now differs from want */
void
commit_untaken(struct cnode *now, struct cnode *want, int failed)
{
	if (failed)
		printf("%% Commit failed: a line it ran failed\n");
	else
		printf("%% Commit failed: the running configuration differs "
		    "from the candidate\n");
	differ(stdout, now, want);
}

/* Report whether back, the rolled-back configuration, matches was: 0 if so */
int
commit_back(struct cnode *back, struct cnode *was)
{
	if (differ(NULL, back, was) == 0) {
		printf("%% The running configuration reverted back\n");
		return 0;
	}
	printf("%% The running configuration differs from how it was\n");
	differ(stdout, back, was);
	return -1;
}

/*
 * Does the running configuration, now, read as the saved one, want, as
 * nshd's boot makes it? 0 if so, else -1 after printing what differs
 */
int
commit_booted(struct cnode *now, struct cnode *want)
{
	if (differ(NULL, now, want) == 0)
		return 0;
	printf("%% The running configuration differs from the saved "
	    "configuration\n");
	differ(stdout, now, want);
	return -1;
}

/*
 * After a commit's script ran, failed if a line of it failed: 0 if the
 * running configuration, text now, reads as want's text and no line
 * failed; else 1, after saying what did not take; or -1, after saying
 * why, if either could not be read. With boot, as nshd's boot judges it
 */
int
commit_verify(char *text, size_t len, char *want, size_t wantlen,
    int failed, int boot)
{
	struct cnode *w, *now = NULL;
	int ret = -1;

	if ((w = conftree_mem(want, wantlen, "the configuration wanted",
	    conf_mode, conf_ordered)) != NULL &&
	    (now = conftree_mem(text, len, "the running configuration",
	    conf_mode, conf_ordered)) != NULL) {
		if (boot)
			ret = commit_booted(now, w) == -1 || failed;
		else if (!failed && commit_took(now, w))
			ret = 0;
		else {
			commit_untaken(now, w, failed);
			ret = 1;
		}
	}
	conftree_free(now);
	conftree_free(w);
	return ret;
}

/*
 * The script, into s, that makes the running configuration, text now,
 * read as want's text: a commit's, the undo of one that did not take,
 * or the rollback of an unconfirmed one. -1 if it could not be made,
 * after saying why, else 0
 */
int
commit_plan(char *text, size_t len, char *want, size_t wantlen,
    struct script *s)
{
	struct cnode *w, *now = NULL;
	int ret = -1;

	if ((w = conftree_mem(want, wantlen, "the configuration wanted",
	    conf_mode, conf_ordered)) != NULL &&
	    (now = conftree_mem(text, len, "the running configuration",
	    conf_mode, conf_ordered)) != NULL)
		ret = script_make(now, w, s, 0);
	conftree_free(now);
	conftree_free(w);
	return ret;
}

/*
 * Once that script ran: whether the running configuration, text after,
 * reads as was's text again. Whether it does decides, not how the
 * script went: 0 if so, after saying so; else -1, after saying how it
 * differs or why it could not be read
 */
int
commit_undone(char *text, size_t len, char *was, size_t waslen)
{
	struct cnode *w, *after = NULL;
	int ret = -1;

	if ((w = conftree_mem(was, waslen, "the configuration before",
	    conf_mode, conf_ordered)) != NULL &&
	    (after = conftree_mem(text, len, "the running configuration",
	    conf_mode, conf_ordered)) != NULL)
		ret = commit_back(after, w);
	conftree_free(after);
	conftree_free(w);
	return ret;
}

/*
 * Does configuration text now read as text want, as commit_took() reads
 * them? 1 if it does, 0 if not, -1 if either could not be read, after
 * saying why
 */
int
commit_reads(char *now, size_t nowlen, char *want, size_t wantlen)
{
	struct cnode *n, *w = NULL;
	int ret = -1;

	if ((n = conftree_mem(now, nowlen, "a configuration", conf_mode,
	    conf_ordered)) != NULL && (w = conftree_mem(want, wantlen,
	    "a configuration", conf_mode, conf_ordered)) != NULL)
		ret = commit_took(n, w);
	conftree_free(n);
	conftree_free(w);
	return ret;
}

/* Whether a login statement of a, a class or a user, is not in b */
static int
logins_in(struct cnode *a, struct cnode *b)
{
	char	*s;
	size_t	 i;

	for (i = 0; (s = conftree_stmt(a, i)) != NULL; i++)
		if (strncmp(s, "login ", 6) == 0 && !conftree_has(b, s))
			return 1;
	return 0;
}

/* Whether a and b have different login users or classes */
int
logins_differ(struct cnode *a, struct cnode *b)
{
	return logins_in(a, b) || logins_in(b, a);
}

/*
 * Do configuration texts a and b have different login users or classes?
 * 1 if so, 0 if not, -1 if either could not be read, after saying why
 */
int
commit_logins(char *a, size_t alen, char *b, size_t blen)
{
	struct cnode *x, *y = NULL;
	int ret = -1;

	if ((x = conftree_mem(a, alen, "a configuration", conf_mode,
	    conf_ordered)) != NULL && (y = conftree_mem(b, blen,
	    "a configuration", conf_mode, conf_ordered)) != NULL)
		ret = logins_differ(x, y);
	conftree_free(x);
	conftree_free(y);
	return ret;
}

/*
 * What would keep want from replacing was, the running configuration,
 * that can be found in advance: each problem shown, and how many
 */
static int
check(struct cnode *was, struct cnode *want)
{
	struct claims c = { NULL, 0 };
	char *s, name[IFNAMSIZ];
	size_t i;
	int bad = 0;

	bad += check_rules(was, want, NULL);
	for (i = 0; (s = conftree_stmt(want, i)) != NULL; i++)
		if (ifblock(s, name, sizeof(name)))
			bad += check_if(want, s, name, &c);
		else if (strncmp(s, "rtable ", 7) == 0)
			bad += check_rtable(want, s) + check_rules(was, want, s);
	for (i = 0; i < c.n; i++)
		free(c.v[i].what);
	free(c.v);
	return bad;
}

/* An interface's block, block, for interface name */
static int
check_if(struct cnode *want, char *block, char *name, struct claims *c)
{
	char *l, *v, *last, *word, *who, what[128], rd[32], buf[1024];
	size_t i, n, len;
	int bad = 0, w;

	for (n = 0; (l = conftree_line(want, block, NULL, n)) != NULL; n++) {
		for (i = 0; i < nitems(ifrefs); i++) {
			len = strlen(ifrefs[i].name);
			if (strncmp(l, ifrefs[i].name, len) == 0 &&
			    l[len] == ' ')
				break;
		}
		if (i == nitems(ifrefs)) {
			if (brport_list(l) || brport_one(l))
				bad += check_ports(want, block, name, l, c);
			continue;
		}
		/* the interfaces it names */
		strlcpy(buf, l + len, sizeof(buf));
		for (w = 1, word = strtok_r(buf, " ", &last); word != NULL;
		    word = strtok_r(NULL, " ", &last), w++) {
			if (ifrefs[i].word != 0 && w != ifrefs[i].word)
				continue;
			if (!ifthere(want, word))
				bad += problem("%s: %s %s is no interface",
				    block, ifrefs[i].name, word);
			snprintf(what, sizeof(what), "trunkport %s", word);
			if (strcmp(ifrefs[i].name, "trunkport") == 0 &&
			    (who = claim(c, what, name)) != NULL)
				bad += problem("%s: trunkport %s is %s's too",
				    block, word, who);
		}
	}

	/* an address, once in an rdomain */
	if ((v = conftree_line(want, block, "rdomain", 0)) != NULL)
		strlcpy(rd, v + strlen("rdomain "), sizeof(rd));
	else
		strlcpy(rd, "0", sizeof(rd));
	for (n = 0; (l = conftree_line(want, block, "inet", n)) != NULL; n++) {
		strlcpy(buf, l + strlen("inet"), sizeof(buf));
		/* an address, not dhcp or autoconf */
		if ((word = strtok_r(buf, " ", &last)) == NULL ||
		    strchr(word, '/') == NULL)
			continue;
		word[strcspn(word, "/")] = '\0';
		snprintf(what, sizeof(what), "inet %s rdomain %s", word, rd);
		if ((who = claim(c, what, name)) != NULL)
			bad += problem("%s: inet %s is %s's too, in rdomain %s",
			    block, word, who, rd);
	}
	return bad + check_ids(want, block, name, c);
}

/* A bridge's line, l, that names its ports */
static int
check_ports(struct cnode *want, char *block, char *name, char *l,
    struct claims *c)
{
	char *p, *who, *m, *word, *last, what[128], list[32], buf[1024];
	int bad = 0;

	/* its name, which may be "no learning", and then its ports */
	p = l + (strncmp(l, "no ", 3) == 0 ? 3 : 0);
	snprintf(list, sizeof(list), "%.*s", (int)(strcspn(p, " ") +
	    (p - l)), l);
	m = conftree_line(want, block, "member", 0);
	strlcpy(buf, l + strlen(list), sizeof(buf));
	for (word = strtok_r(buf, " ", &last); word != NULL;
	    word = brport_one(l) ? NULL : strtok_r(NULL, " ", &last)) {
		if (!ifthere(want, word))
			bad += problem("%s: %s %s is no interface", block,
			    list, word);
		if (strcmp(list, "member") == 0) {
			snprintf(what, sizeof(what), "member %s", word);
			if ((who = claim(c, what, name)) != NULL)
				bad += problem("%s: member %s is %s's too",
				    block, word, who);
		} else if (strcmp(list, "span") != 0 &&
		    (m == NULL || !inwords(m + strlen("member"), word)))
			bad += problem("%s: %s %s is no member", block, list,
			    word);
	}
	return bad;
}

/* A vlan's id, once on its parent, and carp's, once on its carpdev */
static int
check_ids(struct cnode *want, char *block, char *name, struct claims *c)
{
	char *dev, *l, *who, what[128];
	size_t n;
	int bad = 0, id;

	if ((strncmp(name, "vlan", 4) == 0 || strncmp(name, "svlan", 5) == 0) &&
	    (dev = conftree_line(want, block, "parent", 0)) != NULL &&
	    (l = conftree_line(want, block, "vnetid", 0)) != NULL &&
	    sscanf(l, "vnetid %d", &id) == 1) {
		snprintf(what, sizeof(what), "vnetid %d %s", id, dev);
		if ((who = claim(c, what, name)) != NULL)
			bad += problem("%s: vnetid %d on %s is %s's too", block,
			    id, dev + strlen("parent "), who);
	}
	if ((dev = conftree_line(want, block, "carpdev", 0)) == NULL)
		return bad;
	for (n = 0; (l = conftree_line(want, block, NULL, n)) != NULL; n++) {
		if (sscanf(l, "vhid %d", &id) != 1 &&
		    sscanf(l, "carpnode %d", &id) != 1)
			continue;
		snprintf(what, sizeof(what), "vhid %d %s", id, dev);
		if ((who = claim(c, what, name)) != NULL)
			bad += problem("%s: vhid %d on %s is %s's too", block,
			    id, dev + strlen("carpdev "), who);
	}
	return bad;
}

/*
 * An rtable's block: a daemon runs in it only if its table is there,
 * or something makes it, a route in it or an interface in its rdomain
 */
static int
check_rtable(struct cnode *want, char *block)
{
	char *l, name[32];
	size_t n;
	int id = rtableid(block);

	if (kf_rtable(id) || conftree_makes_rtable(want, id))
		return 0;
	for (n = 0; (l = conftree_line(want, block, NULL, n)) != NULL; n++)
		if (ctl_line(l, name, sizeof(name)) == CTL_STATE)
			return problem("%s: %s, but nothing makes table %d: a "
			    "route in it, or an interface in rdomain %d", block,
			    l, id, id);
	return 0;
}

/* Test new or changed daemon rules under block, or at the top level */
static int
check_rules(struct cnode *was, struct cnode *want, char *block)
{
	char **lines = NULL, **nl, *l, *k, *f, *fp = NULL, *tp, name[32];
	char label[512];
	size_t i, j;
	int bad = 0;

	f = block == NULL ? NULL : counterpart(was, NULL, block);
	for (i = 0; (l = conftree_line(want, block, NULL, i)) != NULL; i++) {
		if (ctl_line(l, name, sizeof(name)) != CTL_RULES)
			continue;
		if ((tp = under(block, l)) == NULL)
			break;
		free(fp);
		fp = NULL;
		if ((block == NULL || f != NULL) &&
		    (fp = under(f, l)) != NULL &&
		    samelines(was, fp, want, tp)) {
			free(tp);
			continue;
		}
		for (j = 0; (k = conftree_line(want, tp, NULL, j)) != NULL;
		    j++) {
			if ((nl = reallocarray(lines, j + 1,
			    sizeof(*lines))) == NULL)
				break;
			lines = nl;
			lines[j] = k;
		}
		snprintf(label, sizeof(label), "%s%s%s", block != NULL ?
		    block : "", block != NULL ? ", " : "", l);
		if (j > 0 && rules_test(name, lines, j, label) == -1)
			bad += commit_refused_by(label, name);
		free(tp);
	}
	free(fp);
	free(lines);
	return bad;
}

/*
 * Keep daemon name's rules, its n lines, which label names, for its
 * test: nshd's config runs no test, and system gets them from
 * commit_deferred(). -1 if they could not be kept, else 0
 */
static int
rules_test(char *name, char **lines, size_t n, char *label)
{
	struct plan_test *t, *nt;
	FILE *f;
	size_t i;

	if (!ctl_rules_args(name, NULL, NULL, 0, NULL))
		return 0;
	if ((nt = reallocarray(deferred, ndeferred + 1,
	    sizeof(*deferred))) == NULL) {
		printf("%% commit: %s\n", strerror(errno));
		return -1;
	}
	deferred = nt;
	t = &deferred[ndeferred];
	memset(t, 0, sizeof(*t));
	strlcpy(t->name, name, sizeof(t->name));
	if ((t->label = strdup(label)) == NULL ||
	    (f = open_memstream(&t->text, &t->len)) == NULL) {
		printf("%% commit: %s\n", strerror(errno));
		free(t->label);
		return -1;
	}
	for (i = 0; i < n; i++)
		fprintf(f, "%s\n", lines[i]);
	if (fclose(f) == EOF) {
		printf("%% commit: %s\n", strerror(errno));
		free(t->label);
		free(t->text);
		return -1;
	}
	ndeferred++;
	return 0;
}

/* The tests rules_test() kept for system, given to the caller in *tp */
int
commit_deferred(struct plan_test **tp)
{
	int n = ndeferred;

	*tp = deferred;
	deferred = NULL;
	ndeferred = 0;
	return n;
}

/* Report that name's test refuses the rules label names, as one problem */
int
commit_refused_by(char *label, char *name)
{
	return problem("%s: %s's test refuses them", label, name);
}

/* Is name an interface the candidate has, or hardware that is there? */
static int
ifthere(struct cnode *want, char *name)
{
	char head[sizeof("interface ") + IFNAMSIZ];

	if (strlen(name) >= IFNAMSIZ)
		return 0;
	snprintf(head, sizeof(head), "interface %s", name);
	if (has(want, NULL, head))
		return 1;
	snprintf(head, sizeof(head), "bridge %s", name);
	if (has(want, NULL, head))
		return 1;
	/* what a commit would not destroy */
	return !cand_cloneable(name) && kf_valid(name);
}

/* Is w one of the words of list? */
static int
inwords(char *list, char *w)
{
	size_t len = strlen(w), l;

	for (; *(list += strspn(list, " ")) != '\0'; list += l) {
		l = strcspn(list, " ");
		if (l == len && strncmp(list, w, len) == 0)
			return 1;
	}
	return 0;
}

/*
 * Claim what for who: the interface that claimed it before, if not who,
 * or NULL
 */
static char *
claim(struct claims *c, char *what, char *who)
{
	void *v;
	size_t i;

	for (i = 0; i < c->n; i++)
		if (strcmp(c->v[i].what, what) == 0)
			return strcmp(c->v[i].who, who) == 0 ? NULL :
			    c->v[i].who;
	if ((v = reallocarray(c->v, c->n + 1, sizeof(*c->v))) == NULL)
		return NULL;
	c->v = v;
	if ((c->v[c->n].what = strdup(what)) == NULL)
		return NULL;
	strlcpy(c->v[c->n++].who, who, sizeof(c->v[0].who));
	return NULL;
}

/* A problem: shown, and counted as one */
static int
problem(const char *fmt, ...)
{
	va_list ap;

	printf("%% ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	return 1;
}

/*
 * The script that makes from read as to, into s, from the trees alone,
 * and its edits; -1 if it could not be made, after saying why. A line
 * that is not configuration has no edit: with skip, as at boot, it is
 * reported and left out, else no edits are made
 */
int
script_make(struct cnode *from, struct cnode *to, struct script *s, int skip)
{
	struct commit c;
	int ret = -1;

	memset(s, 0, sizeof(*s));
	c.from = from;
	c.to = to;
	c.s = s;
	if ((c.f = open_memstream(&s->text, &s->len)) == NULL) {
		printf("%% commit: %s\n", strerror(errno));
		return -1;
	}
	if (removals(&c, NULL, NULL, 1, "") != -1 &&
	    additions(&c, NULL, NULL, 1, "") != -1)
		ret = 0;
	if (fclose(c.f) == EOF && ret == 0) {
		printf("%% commit: %s\n", strerror(errno));
		ret = -1;
	}
	if (ret == 0)
		ret = edits_make(s, skip);
	if (ret == -1)
		script_free(s);
	return ret;
}

/*
 * Run s's edits: -1 if they could not run and none did, after saying
 * why; 1 if one failed or rules could not be cleared; else 0
 */
int
script_run(struct script *s)
{
	int i, rt, failed, cleared = 0;

	if (edits_check(s->edits, s->elen) == -1)
		return -1;
	/* from table 0, as nshrc at boot, whatever the session's table */
	if ((rt = cli_rtable) != 0) {
		if (nsh_setrtable(0) != 0)
			return -1;
		cli_rtable = 0;
	}
	/* empty rules before the script starts a daemon on them */
	for (i = 0; i < s->nclears; i++)
		if (s->clears[i].keep && ctl_rules_clear(s->clears[i].name,
		    s->clears[i].rtable, 1) == -1)
			cleared = -1;
	failed = edits_apply(s->edits, s->elen);
	/* remove rules once the script has stopped the daemon */
	for (i = 0; i < s->nclears; i++)
		if (!s->clears[i].keep && ctl_rules_clear(s->clears[i].name,
		    s->clears[i].rtable, 0) == -1)
			cleared = -1;
	if (cli_rtable != rt && nsh_setrtable(rt) == 0)
		cli_rtable = rt;
	return failed || cleared == -1;
}

void
script_free(struct script *s)
{
	free(s->text);
	s->text = NULL;
	s->len = 0;
	free(s->edits);
	s->edits = NULL;
	s->elen = 0;
}

/*
 * s's edits, from its lines (script_make()). A line becomes a record
 * with its words and its command's place among the commands a
 * configuration has, found as nsh reads the line. A daemon's rules block
 * becomes one record, and a block's "!" its end. A line that names no
 * such command is reported; with skip it is left out, else -1 once all
 * are reported. 0 if made
 */
static int
edits_make(struct script *s, int skip)
{
	struct edit e;
	FILE *f, *rf = NULL;
	char *t, *p, *l, *rules = NULL, head[1024] = "";
	size_t rlen = 0;
	int block = 0, rd = -1, in, k, bad = 0, r = -1;

	s->edits = NULL;
	s->elen = 0;
	if ((f = open_memstream(&s->edits, &s->elen)) == NULL) {
		printf("%% commit: %s\n", strerror(errno));
		return -1;
	}
	if ((t = p = strndup(s->text != NULL ? s->text : "", s->len)) ==
	    NULL) {
		printf("%% commit: %s\n", strerror(errno));
		goto done;
	}
	while ((l = strsep(&p, "\n")) != NULL && (p != NULL || *l != '\0')) {
		/* how far in a statement is: one, in an rtable's block */
		in = block == CF_RTABLE;
		/* a daemon's rules: one further in, to a "!" as far in */
		if (rd != -1) {
			if (strncmp(l, "  ", in) == 0 && strcmp(l + in, "!") == 0) {
				memset(&e, 0, sizeof(e));
				e.kind = EDIT_RULES;
				e.row = rd;
				rd = -1;
				if (fclose(rf) == EOF ||
				    edit_put(f, &e, rules, rlen) == -1) {
					rf = NULL;
					goto done;
				}
				rf = NULL;
				free(rules);
				rules = NULL;
			} else if (strncmp(l, "  ", in + 1) == 0)
				fprintf(rf, "%s\n", l + in + 1);
			else
				break;
			continue;
		}
		if (strcmp(l, "!") == 0) {
			memset(&e, 0, sizeof(e));
			e.kind = EDIT_END;
			if (block != 0 && edit_put(f, &e, NULL, 0) == -1)
				goto done;
			block = 0;
			continue;
		}
		if (l[0] != ' ' && block != 0) {
			printf("%% %s: a block without its end\n", head);
			goto done;
		}
		if (l[0] != ' ')
			k = edits_line(f, CTX_TOP, l, &block, &rd, head);
		else if (block == CF_IF || block == CF_BRIDGE)
			k = edits_line(f, block == CF_IF ? CTX_IF : CTX_BRIDGE,
			    l, &block, &rd, head);
		else if (block == CF_RTABLE && l[1] != ' ')
			k = strcmp(l, " !") == 0 ? 0 :
			    edits_line(f, CTX_TOP, l + 1, &block, &rd, head);
		else {
			printf("%% %s is not configuration\n", l + strspn(l, " "));
			k = -1;
		}
		if (k == -1)
			bad++;
		if (rd != -1 && (rf = open_memstream(&rules, &rlen)) == NULL) {
			printf("%% commit: %s\n", strerror(errno));
			goto done;
		}
	}
	/* rules cut off by the end of the script, or by a less indented line */
	if (rd != -1) {
		printf("%% %s%s%s rules without their end\n",
		    block == CF_RTABLE ? head : "", block == CF_RTABLE ? ": " : "",
		    ctl_daemons[rd].name);
		goto done;
	}
	if (bad > 0 && skip)
		printf("%% Left out %d line%s that %s not configuration\n",
		    bad, bad == 1 ? "" : "s", bad == 1 ? "is" : "are");
	if (bad == 0 || skip)
		r = 0;
done:
	if (rf != NULL)
		fclose(rf);
	free(rules);
	free(t);
	if (fclose(f) == EOF && r == 0) {
		printf("%% commit: %s\n", strerror(errno));
		r = -1;
	}
	if (r == -1) {
		free(s->edits);
		s->edits = NULL;
		s->elen = 0;
	}
	return r;
}

/*
 * Line l of a script, in ctx, as an edit to f: a statement at the top
 * level or in an rtable's block (*block CF_RTABLE), or a line of head's
 * block. A statement that begins a block sets *block to its kind and
 * head to l; a daemon's rules statement writes no edit and sets *rd to
 * the daemon. 0, or -1 after saying why
 */
static int
edits_line(FILE *f, int ctx, char *l, int *block, int *rd, char *head)
{
	const struct argcmd *c = NULL;
	struct argcmd cmd;
	struct edit e;
	char *t, *w[NARGS], *daemon;
	int n, i, d, row, act;

	memset(&e, 0, sizeof(e));
	if ((t = strdup(l)) == NULL) {
		printf("%% commit: %s\n", strerror(errno));
		return -1;
	}
	if ((n = argsplit(t, w, nitems(w))) == 0) {
		free(t);
		return 0;
	}
	e.no = n > 0 && NO_ARG(w[0]);
	i = e.no;
	if (n <= i)
		goto refused;
	row = conf_find(ctx, w[i], &daemon);
	if (row == -2) {
		/* a daemon's rules, or what a configuration has it do */
		d = ctl_daemon(daemon);
		if (e.no || n != i + 2 || d == -1)
			goto refused;
		if (isprefix(w[i + 1], "rules")) {
			*rd = d;
			free(t);
			return 0;
		}
		if ((act = ctl_act(d, w[i + 1])) == -1)
			goto refused;
		e.kind = EDIT_DAEMON;
		e.row = d;
		e.act = act;
		free(t);
		return edit_put(f, &e, NULL, 0);
	}
	if (row == -1)
		goto refused;
	c = conf_cmd(ctx, row, &cmd);
	if (ctx == CTX_TOP && ((e.no && (c->flags & CF_NO) == 0) ||
	    (*block == CF_RTABLE && (c->flags & (CF_IF | CF_BRIDGE |
	    CF_RTABLE)) != 0)))
		goto refused;
	e.kind = ctx == CTX_TOP ? EDIT_TOP : ctx == CTX_IF ? EDIT_IF :
	    EDIT_BRIDGE;
	e.row = row;
	if (edit_args(f, &e, c, n, w) == -1) {
		free(t);
		return -1;
	}
	if (ctx == CTX_TOP && !e.no && (c->flags & (CF_IF | CF_BRIDGE |
	    CF_RTABLE)) != 0) {
		*block = c->flags & (CF_IF | CF_BRIDGE | CF_RTABLE);
		strlcpy(head, l, 1024);
	}
	free(t);
	return 0;
refused:
	l += strspn(l, " ");
	if (ctx == CTX_TOP && *block != CF_RTABLE)
		printf("%% %s is not configuration\n", l);
	else
		printf("%% %s: %s is not configuration\n", head, l);
	free(t);
	return -1;
}

/* e, written to f, then len bytes of text */
static int
edit_put(FILE *f, struct edit *e, char *text, size_t len)
{
	if (len > UINT32_MAX - sizeof(*e)) {
		printf("%% commit: an edit too long\n");
		return -1;
	}
	e->len = len;
	if (fwrite(e, sizeof(*e), 1, f) != 1)
		goto fail;
	if (text != NULL && len > 0 && fwrite(text, len, 1, f) != 1)
		goto fail;
	return 0;
fail:
	printf("%% commit: %s\n", strerror(errno));
	return -1;
}

/* facts output callback: write the encoded units to f */
static void
edit_emit(void *f, const void *p, size_t len)
{
	fwrite(p, len, 1, f);
}

/* where edit_args_one() writes, and the edit it writes */
struct edit_dest {
	FILE		*f;
	struct edit	*e;
};

/* Write one record of a's parsed values v as an edit */
static int
edit_args_one(const struct argcmd *a, struct argvals *v, void *arg)
{
	struct edit_dest	*d = arg;
	struct facts_field	 fl[ARGS_MAX];
	struct facts_kind	 k;
	struct facts_out	 o;
	FILE			*m;
	char			*buf = NULL;
	size_t			 len = 0;
	int			 r = -1;

	if ((m = open_memstream(&buf, &len)) == NULL) {
		printf("%% commit: %s\n", strerror(errno));
		return -1;
	}
	args_kind(a, &k, fl);
	facts_out_init(&o, edit_emit, m);
	if (facts_record(&o, &k, v->v) == -1)
		printf("%% commit: %s: its values do not fit\n", a->name);
	else
		r = 0;
	if (fclose(m) == EOF && r == 0) {
		printf("%% commit: %s\n", strerror(errno));
		r = -1;
	}
	d->e->typed = 1;
	d->e->no = !v->set;
	if (r == 0)
		r = edit_put(d->f, d->e, buf, len);
	free(buf);
	return r;
}

/*
 * Parse line w (n words) with a's arguments and write it to f as edit
 * e, carrying the parsed values. A list longer than one record holds
 * goes as several edits (args_each()). Returns 0, or -1 after printing
 * an error.
 */
static int
edit_args(FILE *f, struct edit *e, const struct argcmd *a, int n, char **w)
{
	struct edit_dest	 d = { f, e };

	return args_each(a, n, w, edit_args_one, &d) == -1 ? -1 : 0;
}

/* state for edit_record(): check a typed edit, and maybe run it */
struct edit_values {
	const struct argcmd	*c;
	int			 ctx, row, set, run, n, r;
	char			*name;
};

static void
edit_record(void *arg, const struct facts_template *t,
    const struct facts_value *v)
{
	struct edit_values	*x = arg;

	x->n++;
	if (args_check(x->c, x->set, t, v) == -1)
		x->r = -1;
	else if (x->run) {
		x->r = conf_run_values(x->ctx, x->row, x->set, v, x->name);
		/* a block's head: the interface its lines are for */
		if (x->ctx == CTX_TOP && x->set &&
		    (x->c->flags & (CF_IF | CF_BRIDGE)))
			args_string(&v[0], x->name, IFNAMSIZ);
	}
}

/*
 * Check the values of typed edit e (len bytes at p) against the
 * arguments of c, the command at e's row of ctx, with args_check(). If
 * run is set, also run the command with them on name. Returns 0, or -1
 * if the values are invalid or the command failed.
 */
static int
edit_typed(const struct argcmd *c, struct edit *e, char *p, int ctx,
    int run, char *name)
{
	struct facts_in		 in;
	struct edit_values	 x = { c, ctx, e->row, !e->no, run, 0, 0,
				    name };

	facts_in_init(&in, edit_record, &x);
	if (facts_read(&in, p, e->len) == -1)
		x.r = -1;
	facts_in_free(&in);
	return x.n == 1 ? x.r : -1;
}

/*
 * Check that buf (len bytes) holds edits that may run. Each record must
 * be complete, of a known kind, and name a command a configuration can
 * have, in the block where it belongs, or a daemon action a
 * configuration can have, with its rules complete. A line carries its
 * parsed values. Returns 0 if so, else -1 after printing why.
 */
static int
edits_check(char *buf, size_t len)
{
	const struct argcmd *c;
	struct argcmd cmd;
	struct edit e;
	char *p;
	size_t off;
	int block = 0, ctx;

	for (off = 0; off < len; off += sizeof(e) + e.len) {
		if (len - off < sizeof(e)) {
			printf("%% edits: a record cut short\n");
			return -1;
		}
		memcpy(&e, buf + off, sizeof(e));
		p = buf + off + sizeof(e);
		if (e.len > len - off - sizeof(e)) {
			printf("%% edits: a record cut short\n");
			return -1;
		}
		if (e.no > 1 || (e.typed && e.kind != EDIT_TOP &&
		    e.kind != EDIT_IF && e.kind != EDIT_BRIDGE))
			goto bad;
		switch (e.kind) {
		case EDIT_TOP:
			if ((c = conf_cmd(CTX_TOP, e.row, &cmd)) == NULL ||
			    (block != 0 && (block != CF_RTABLE ||
			    (c->flags & (CF_IF | CF_BRIDGE | CF_RTABLE)))) ||
			    (e.no && (c->flags & CF_NO) == 0) || e.typed != 1 ||
			    edit_typed(c, &e, p, CTX_TOP, 0, NULL) == -1)
				goto bad;
			if (!e.no && (c->flags & (CF_IF | CF_BRIDGE |
			    CF_RTABLE)))
				block = c->flags & (CF_IF | CF_BRIDGE |
				    CF_RTABLE);
			break;
		case EDIT_IF:
		case EDIT_BRIDGE:
			ctx = e.kind == EDIT_IF ? CTX_IF : CTX_BRIDGE;
			if (block != (e.kind == EDIT_IF ? CF_IF : CF_BRIDGE) ||
			    (c = conf_cmd(ctx, e.row, &cmd)) == NULL ||
			    e.typed != 1 ||
			    edit_typed(c, &e, p, ctx, 0, NULL) == -1)
				goto bad;
			break;
		case EDIT_END:
			if (block == 0 || e.len != 0)
				goto bad;
			block = 0;
			break;
		case EDIT_RULES:
			if ((block != 0 && block != CF_RTABLE) ||
			    !ctl_takes(e.row, CTL_ACT_RULES) ||
			    memchr(p, '\0', e.len) != NULL)
				goto bad;
			break;
		case EDIT_DAEMON:
			if ((block != 0 && block != CF_RTABLE) ||
			    !ctl_takes(e.row, e.act) || e.len != 0)
				goto bad;
			break;
		default:
			goto bad;
		}
	}
	return 0;
bad:
	printf("%% edits: the record at byte %zu is not one that may "
	    "run\n", off);
	return -1;
}

/* an rtable's head's record: its table */
static void
edit_rtable(void *arg, const struct facts_template *t,
    const struct facts_value *v)
{
	*(int *)arg = v[0].v.i;
}

/* what edit_login() checks: a login line, set or not, and the verdict */
struct edit_admin {
	int	 set, r;
};

/* a login line's record: may a session without admin run it? */
static void
edit_login(void *arg, const struct facts_template *t,
    const struct facts_value *v)
{
	struct edit_admin	*x = arg;

	if (login_admin(x->set, v) == -1)
		x->r = -1;
}

/*
 * The parser's check of s, as script_run() would run it, in the commit
 * of a session without admin, against the running configuration before
 * it (admin_begin()): a login line, a daemon's rules and a clear of them
 * may change nothing that needs admin. 0 if the script may run, else -1
 * after saying why
 */
int
edits_admin(struct script *s)
{
	const struct argcmd *c;
	struct argcmd cmd;
	struct facts_in in;
	struct edit_admin x;
	struct edit e;
	char *p;
	size_t off;
	int i, rt = 0, r = 0;

	if (edits_check(s->edits, s->elen) == -1)
		return -1;
	for (i = 0; i < s->nclears; i++)
		if (admin_cleared(s->clears[i].name) == -1)
			r = -1;
	for (off = 0; off < s->elen; off += sizeof(e) + e.len) {
		memcpy(&e, s->edits + off, sizeof(e));
		p = s->edits + off + sizeof(e);
		switch (e.kind) {
		case EDIT_TOP:
			c = conf_cmd(CTX_TOP, e.row, &cmd);
			/* an rtable's block, whose rules are that rtable's */
			if ((c->flags & CF_RTABLE) && !e.no) {
				facts_in_init(&in, edit_rtable, &rt);
				facts_read(&in, p, e.len);
				facts_in_free(&in);
			}
			if (strcmp(c->name, "login") != 0)
				break;
			x.set = !e.no;
			x.r = 0;
			facts_in_init(&in, edit_login, &x);
			facts_read(&in, p, e.len);
			facts_in_free(&in);
			if (x.r == -1)
				r = -1;
			break;
		case EDIT_END:
			rt = 0;
			break;
		case EDIT_RULES:
			if (admin_rules(e.row, rt, p, e.len) == -1)
				r = -1;
			break;
		}
	}
	return r;
}

/*
 * Run buf's len bytes of edits (edits_check()): run the command at the
 * place each record names, with its words, write a daemon's rules, or
 * do a daemon action. 1 if one failed, else 0
 */
static int
edits_apply(char *buf, size_t len)
{
	struct argcmd cmd;
	struct edit e;
	char *p, name[IFNAMSIZ] = "";
	size_t off;
	int ctx, rt = cli_rtable, failed = 0, r = 0;

	conf_reading(1);
	for (off = 0; off < len; off += sizeof(e) + e.len) {
		memcpy(&e, buf + off, sizeof(e));
		p = buf + off + sizeof(e);
		switch (e.kind) {
		case EDIT_TOP:
		case EDIT_IF:
		case EDIT_BRIDGE:
			ctx = e.kind == EDIT_TOP ? CTX_TOP : e.kind == EDIT_IF ?
			    CTX_IF : CTX_BRIDGE;
			r = edit_typed(conf_cmd(ctx, e.row, &cmd), &e, p, ctx,
			    1, name);
			break;
		case EDIT_END:
			conf_block_end(rt);
			r = 0;
			break;
		case EDIT_RULES:
			r = ctl_setrules(e.row, p, e.len);
			break;
		case EDIT_DAEMON:
			r = ctl_do(e.row, e.act);
			break;
		}
		if (r == -1)
			failed = 1;
		conf_settle();
	}
	conf_reading(0);
	return failed;
}

/*
 * What is removed from under fblock, in the reverse of conf()'s order.
 * The candidate has the block as tblock, if there.
 */
static int
removals(struct commit *c, char *fblock, char *tblock, int there,
    const char *in)
{
	struct ranked *r;
	struct sub s;
	char *l, *t, *fp = NULL, *tp = NULL, *k, name[IFNAMSIZ];
	size_t n, i, j;
	int ret = -1;

	if (ranked(c->from, fblock, &r, &n) == -1)
		return -1;
	for (i = n; i-- > 0; ) {
		l = r[i].line;
		t = there ? counterpart(c->to, tblock, l) : NULL;
		free(fp);
		free(tp);
		tp = NULL;
		if ((fp = under(fblock, l)) == NULL ||
		    (t != NULL && (tp = under(tblock, t)) == NULL))
			goto done;

		if (conf_ordered(l)) {
			/* a daemon's rules: changed ones are added whole */
			if (t == NULL && clear(c, l, rtableid(fblock), 0) == -1)
				goto done;
		} else if (fblock == NULL && strncmp(l, "rtable ", 7) == 0) {
			if (sub_begin(c, &s) == -1)
				goto done;
			if (removals(c, fp, tp, t != NULL, " ") == -1) {
				sub_end(c, &s, in, l, 0);
				goto done;
			}
			sub_end(c, &s, in, l, 0);
			if (t == NULL)
				fprintf(c->f, "no rtable %d\n", rtableid(fp));
		} else if (fblock == NULL && t == NULL &&
		    ifblock(l, name, sizeof(name)) && cand_cloneable(name))
			fprintf(c->f, "no %s\n", l);
		else if (conftree_line(c->from, fp, NULL, 0) != NULL) {
			/* a block's lines are removed, in reverse */
			if (sub_begin(c, &s) == -1)
				goto done;
			for (j = 0; (k = conftree_line(c->from, fp, NULL, j)) !=
			    NULL; j++)
				;
			while (j-- > 0) {
				k = conftree_line(c->from, fp, NULL, j);
				if (t == NULL || !has(c->to, tp, k))
					unset(c, tp, t != NULL, context(fp),
					    " ", k);
			}
			sub_end(c, &s, in, l, 0);
		} else if (fblock == NULL && ifblock(l, name, sizeof(name)))
			/* an interface with no lines: nothing to remove */
			;
		else if (t == NULL && unset(c, tblock, there,
		    context(fblock), in, l) == -1)
			goto done;
	}
	ret = 0;
done:
	free(fp);
	free(tp);
	free(r);
	return ret;
}

/*
 * What is added under tblock, in conf()'s order. The running
 * configuration has the block as fblock, if there.
 */
static int
additions(struct commit *c, char *fblock, char *tblock, int there,
    const char *in)
{
	struct ranked *r, *kr;
	struct sub s;
	char *l, *f, *fp = NULL, *tp = NULL, *k, name[IFNAMSIZ], dname[32];
	size_t n, i, j, kn;
	int moved, flushed, rekeyed, ret = -1;

	if (ranked(c->to, tblock, &r, &n) == -1)
		return -1;
	for (i = 0; i < n; i++) {
		l = r[i].line;
		f = there ? counterpart(c->from, fblock, l) : NULL;
		free(fp);
		free(tp);
		fp = NULL;
		if ((tp = under(tblock, l)) == NULL ||
		    (f != NULL && (fp = under(fblock, f)) == NULL))
			goto done;

		if (conf_ordered(l)) {
			if (f != NULL && samelines(c->from, fp, c->to, tp))
				continue;
			if (conftree_line(c->to, tp, NULL, 0) == NULL) {
				if (clear(c, l, rtableid(tblock), 1) == -1)
					goto done;
			} else {
				fprintf(c->f, "%s%s\n", in, l);
				for (j = 0; (k = conftree_line(c->to, tp, NULL,
				    j)) != NULL; j++)
					fprintf(c->f, "%s %s\n", in, k);
				fprintf(c->f, "%s!\n", in);
			}
		} else if (tblock == NULL && strncmp(l, "rtable ", 7) == 0) {
			if (sub_begin(c, &s) == -1)
				goto done;
			if (additions(c, fp, tp, f != NULL, " ") == -1) {
				sub_end(c, &s, in, l, 0);
				goto done;
			}
			/* a new or renamed rtable is added, lines or not */
			sub_end(c, &s, in, l, f == NULL || strcmp(f, l) != 0);
		} else if (conftree_line(c->to, tp, NULL, 0) != NULL ||
		    (tblock == NULL && ifblock(l, name, sizeof(name)))) {
			if (sub_begin(c, &s) == -1)
				goto done;
			/*
			 * a new rdomain removed the addresses, and left
			 * dhcrelay6 in the old routing table, so add them
			 */
			moved = f != NULL && context(tp) == CTX_IF &&
			    !sameline(c->from, fp, c->to, tp, "rdomain");
			/*
			 * a new tunnel, tunneldomain, vnetid or parent removed
			 * the endpoints, so add them
			 */
			flushed = f != NULL && context(tp) == CTX_IF &&
			    (!sameline(c->from, fp, c->to, tp, "tunnel") ||
			    !sameline(c->from, fp, c->to, tp, "tunneladdr") ||
			    !sameline(c->from, fp, c->to, tp, "tunneldomain") ||
			    !sameline(c->from, fp, c->to, tp, "vnetid") ||
			    !sameline(c->from, fp, c->to, tp, "parent"));
			/* a new nwid turned WEP and WPA off, so add them */
			rekeyed = f != NULL && context(tp) == CTX_IF &&
			    !sameline(c->from, fp, c->to, tp, "nwid");
			/* in the order conf() prints them */
			if (ranked(c->to, tp, &kr, &kn) == -1) {
				sub_end(c, &s, in, l, 0);
				goto done;
			}
			for (j = 0; j < kn; j++) {
				k = kr[j].line;
				if (f == NULL || !has(c->from, fp, k) ||
				    (moved && (address(k) || relay6(k))) ||
				    (flushed && endpoint(k)) ||
				    (rekeyed && wifikey(k)))
					set(c, fp, f != NULL, context(tp), k);
			}
			free(kr);
			sub_end(c, &s, in, l, f == NULL);
		} else if (ctl_line(l, dname, sizeof(dname)) == CTL_FOLLOW) {
			/* if new (as in a new rtable), or if renewed() */
			if (f == NULL || renewed(c, fblock, tblock, dname))
				fprintf(c->f, "%s%s\n", in, l);
		} else if (f == NULL)
			fprintf(c->f, "%s%s\n", in, l);
	}
	ret = 0;
done:
	free(fp);
	free(tp);
	free(r);
	return ret;
}

/*
 * What removes line, under the block the candidate has as tblock if
 * there, in context ctx. Nothing if the candidate sets the same
 * setting another way, as its own line will.
 */
static int
unset(struct commit *c, char *tblock, int there, int ctx, const char *in,
    char *line)
{
	struct sedit e;
	char name[32], other[32], *base, *l;
	size_t n;

	switch (ctl_line(line, name, sizeof(name))) {
	case CTL_RULES:
	case CTL_FOLLOW:
		return 0;
	case CTL_STATE:
		/* a daemon's state, unless the candidate has its own */
		for (n = 0; there &&
		    (l = conftree_line(c->to, tblock, NULL, n)) != NULL; n++)
			if (ctl_line(l, other, sizeof(other)) == CTL_STATE &&
			    strcmp(other, name) == 0)
				return 0;
		if (strcmp(line + strlen(name), " disable") != 0)
			fprintf(c->f, "%s%s disable\n", in, name);
		return 0;
	}
	base = strncmp(line, "no ", 3) == 0 ? line + 3 : line;
	/*
	 * a veb member's VLANs that the candidate's lines lack go first,
	 * so that a private VLAN can go
	 */
	if (there && ctx == CTX_BRIDGE && (strncmp(base, "tagged ", 7) == 0 ||
	    strncmp(base, "untagged ", 9) == 0))
		for (n = 0; (l = conftree_line(c->to, tblock, base, n)) !=
		    NULL; n++)
			if (brvlan_gone(c->f, in, base, l))
				return 0;
	if (there && ctx != -1) {
		/* a list keeps the values the candidate's line has */
		if (islist(ctx, line) &&
		    (l = listline(c->to, tblock, line)) != NULL) {
			values(c->f, in, line, l, 1);
			return 0;
		}
		if (setting_edit(ctx, ST_ON, base, &e) == 0 &&
		    e.op == CE_SET &&
		    conftree_haskey(c->to, tblock, base, e.keylen))
			return 0;
	}
	fprintf(c->f, "%s%s%s\n", in, base == line ? "no " : "", base);
	return 0;
}

/*
 * What adds line, under the block the running configuration has as
 * fblock if there, in context ctx: line, or the values of a list its
 * line lacks
 */
static void
set(struct commit *c, char *fblock, int there, int ctx, char *line)
{
	char *l;

	if (there && ctx != -1 && islist(ctx, line) &&
	    (l = listline(c->from, fblock, line)) != NULL)
		values(c->f, " ", line, l, 0);
	else
		fprintf(c->f, " %s\n", line);
}

/* Is line a list, whose values its command takes one by one? */
static int
islist(int ctx, char *line)
{
	struct sedit e;

	if (ctx == CTX_BRIDGE && brport_list(line))
		return 1;
	return strncmp(line, "no ", 3) != 0 &&
	    setting_edit(ctx, ST_ON, line, &e) == 0 && e.op == CE_LISTADD;
}

/* The list line under block in t with the same name and "no" as line */
static char *
listline(struct cnode *t, char *block, char *line)
{
	char *l;
	size_t n;
	int no = strncmp(line, "no ", 3) == 0;

	for (n = 0; (l = conftree_line(t, block, line, n)) != NULL; n++)
		if ((strncmp(l, "no ", 3) == 0) == no)
			return l;
	return NULL;
}

/* Where a list line's values start, after any "no" and its name */
static char *
listvalues(char *line)
{
	if (strncmp(line, "no ", 3) == 0)
		line += 3;
	return line + strcspn(line, " ");
}

/*
 * The values of list line that list other lacks, under line's name, or
 * with gone, under the name that removes them: line's name with "no"
 * added, or with its "no" removed. Nothing if there are none.
 */
static void
values(FILE *f, const char *in, char *line, char *other, int gone)
{
	char *v = listvalues(line), *p, *q;
	size_t len, olen;
	int n = 0, no = strncmp(line, "no ", 3) == 0;

	for (p = v; *(p += strspn(p, " ")) != '\0'; p += len) {
		len = strcspn(p, " ");
		for (q = listvalues(other); *(q += strspn(q, " ")) != '\0';
		    q += olen) {
			olen = strcspn(q, " ");
			if (olen == len && strncmp(p, q, len) == 0)
				break;
		}
		if (*q != '\0')
			continue;
		if (n++ > 0)
			;
		else if (gone && no)
			fprintf(f, "%s%.*s", in, (int)(v - line - 3), line + 3);
		else
			fprintf(f, "%s%s%.*s", in, gone ? "no " : "",
			    (int)(v - line), line);
		fprintf(f, " %.*s", (int)len, p);
	}
	if (n > 0)
		fprintf(f, "\n");
}

/*
 * Does daemon name load its rules under tblock again: are they new, or
 * does it start? The running configuration has the block as fblock.
 */
static int
renewed(struct commit *c, char *fblock, char *tblock, char *name)
{
	char *l, *fp, *tp, other[32];
	size_t n;
	int kind, ret = 0;

	for (n = 0; ret == 0 &&
	    (l = conftree_line(c->to, tblock, NULL, n)) != NULL; n++) {
		kind = ctl_line(l, other, sizeof(other));
		if (kind == 0 || strcmp(other, name) != 0)
			continue;
		if (kind == CTL_STATE)
			ret = strcmp(l + strlen(name), " disable") != 0 &&
			    !has(c->from, fblock, l);
		else if (kind == CTL_RULES) {
			if ((fp = under(fblock, l)) == NULL)
				return 1;
			if ((tp = under(tblock, l)) == NULL) {
				free(fp);
				return 1;
			}
			ret = !samelines(c->from, fp, c->to, tp);
			free(fp);
			free(tp);
		}
	}
	return ret;
}

/*
 * How the running configuration, now, differs from want: printed to out,
 * or only counted with out NULL. A physical interface that want has no
 * block for keeps what its hardware has, so it is taken out of now.
 */
static int
differ(FILE *out, struct cnode *now, struct cnode *want)
{
	char *s, stmt[64], name[IFNAMSIZ];
	size_t n = 0;

	while ((s = conftree_stmt(now, n)) != NULL) {
		if (ifblock(s, name, sizeof(name)) && !conftree_has(want, s) &&
		    !cand_cloneable(name)) {
			strlcpy(stmt, s, sizeof(stmt));
			conftree_edit(now, CE_NOBLOCK, NULL, stmt, 0);
			continue;
		}
		n++;
	}
	return conftree_compare(out, now, want);
}

/* The lines under block in t, in the order conf() prints them */
static int
ranked(struct cnode *t, char *block, struct ranked **rp, size_t *np)
{
	struct ranked *r = NULL, *nr;
	char *l, name[32];
	size_t n;
	int rank, kind;

	for (n = 0; (l = conftree_line(t, block, NULL, n)) != NULL; n++) {
		if ((nr = reallocarray(r, n + 1, sizeof(*r))) == NULL) {
			printf("%% commit: %s\n", strerror(errno));
			free(r);
			return -1;
		}
		r = nr;
		if (block == NULL)
			rank = conf_rank(l);
		else if (context(block) == CTX_RTABLE)
			rank = conf_rank_rtable(l);
		else if (context(block) == CTX_IF ||
		    context(block) == CTX_BRIDGE)
			rank = setting_rank(context(block), l);
		else
			rank = 0;
		/* a daemon's rules, then its state, then its reload */
		kind = ctl_line(l, name, sizeof(name));
		r[n].line = l;
		r[n].rank = rank * 4 + (kind == CTL_RULES ? 0 :
		    kind == CTL_FOLLOW ? 2 : 1);
		r[n].i = n;
	}
	if (n > 0)
		qsort(r, n, sizeof(*r), byrank);
	*rp = r;
	*np = n;
	return 0;
}

static int
byrank(const void *x, const void *y)
{
	const struct ranked *a = x, *b = y;

	if (a->rank != b->rank)
		return a->rank < b->rank ? -1 : 1;
	return (a->i > b->i) - (a->i < b->i);
}

/*
 * The line under block in t that stands for line: line itself, or an
 * rtable of the same number under another name
 */
static char *
counterpart(struct cnode *t, char *block, char *line)
{
	char *l;
	size_t n;
	int id, other;

	if (has(t, block, line))
		return line;
	if (block != NULL || sscanf(line, "rtable %d", &id) != 1)
		return NULL;
	for (n = 0; (l = conftree_stmt(t, n)) != NULL; n++)
		if (sscanf(l, "rtable %d", &other) == 1 && other == id)
			return l;
	return NULL;
}

/* block and line joined, as conftree_has() takes a line under a block */
static char *
under(char *block, char *line)
{
	char *p;

	if (block == NULL)
		p = strdup(line);
	else if (asprintf(&p, "%s\n%s", block, line) == -1)
		p = NULL;
	if (p == NULL)
		printf("%% commit: %s\n", strerror(errno));
	return p;
}

/* Has t line under block? */
static int
has(struct cnode *t, char *block, char *line)
{
	char *p;
	int ret;

	if ((p = under(block, line)) == NULL)
		return 0;
	ret = conftree_has(t, p);
	free(p);
	return ret;
}

/* Are the lines under a's block pa the lines under b's pb, in order? */
static int
samelines(struct cnode *a, char *pa, struct cnode *b, char *pb)
{
	char *x, *y;
	size_t n;

	for (n = 0; ; n++) {
		x = conftree_line(a, pa, NULL, n);
		y = conftree_line(b, pb, NULL, n);
		if (x == NULL || y == NULL)
			return x == y;
		if (strcmp(x, y) != 0)
			return 0;
	}
}

/* Have a's block pa and b's pb the same line named name, or none? */
static int
sameline(struct cnode *a, char *pa, struct cnode *b, char *pb, char *name)
{
	char *x = conftree_line(a, pa, name, 0);
	char *y = conftree_line(b, pb, name, 0);

	if (x == NULL || y == NULL)
		return x == y;
	return strcmp(x, y) == 0;
}

/* Is line an interface's address, of either family? */
static int
address(char *line)
{
	return strncmp(line, "inet ", 5) == 0;
}

/* Is line an interface's dhcrelay6, which runs in its rdomain? */
static int
relay6(char *line)
{
	return strncmp(line, "dhcrelay6 ", 10) == 0;
}

/* Is line an interface's endpoint? */
static int
endpoint(char *line)
{
	return strncmp(line, "endpoint ", 9) == 0;
}

/* Is line an interface's WEP or WPA line, which a new nwid turns off? */
static int
wifikey(char *line)
{
	size_t len;

	if (strncmp(line, "no ", 3) == 0)
		line += 3;
	len = strcspn(line, " ");
	return (len == 5 && strncmp(line, "nwkey", len) == 0) ||
	    (len >= 3 && strncmp(line, "wpa", 3) == 0);
}

/* The settings table's context for the lines under block, or -1 */
static int
context(char *block)
{
	if (block == NULL)
		return CTX_TOP;
	if (strncmp(block, "interface ", 10) == 0)
		return CTX_IF;
	if (strncmp(block, "bridge ", 7) == 0)
		return CTX_BRIDGE;
	if (strncmp(block, "rtable ", 7) == 0 && strchr(block, '\n') == NULL)
		return CTX_RTABLE;
	return -1;
}

/* The rtable a block is in */
static int
rtableid(char *block)
{
	int id;

	if (block == NULL || sscanf(block, "rtable %d", &id) != 1)
		return 0;
	return id;
}

/* Is line an interface's block, and which interface? */
static int
ifblock(char *line, char *name, size_t len)
{
	char fmt[32];

	snprintf(fmt, sizeof(fmt), "%%*s %%%zus", len - 1);
	return (strncmp(line, "interface ", 10) == 0 ||
	    strncmp(line, "bridge ", 7) == 0) && sscanf(line, fmt, name) == 1;
}

/* Daemon rules script_run() clears: to no file, or with keep, an empty one */
static int
clear(struct commit *c, char *stmt, int rtable, int keep)
{
	char name[32];

	if (ctl_line(stmt, name, sizeof(name)) != CTL_RULES)
		return 0;
	if (c->s->nclears == MAXCLEARS) {
		printf("%% commit: too many daemon rules to clear\n");
		return -1;
	}
	strlcpy(c->s->clears[c->s->nclears].name, name,
	    sizeof(c->s->clears[c->s->nclears].name));
	c->s->clears[c->s->nclears].rtable = rtable;
	c->s->clears[c->s->nclears++].keep = keep;
	return 0;
}

/*
 * Keep the configuration just saved, in file, as rollback 0, with who
 * saved it, their comment if not empty, and its generation, one more
 * than rollback 0's. Each older rollback N becomes N + 1, and the oldest
 * is dropped. Nothing is done if rollback 0 is the same. -1 if it could
 * not, after saying why
 */
int
rollback_keep(const char *file, const char *who, const char *comment)
{
	struct rollback_head h;
	char from[PATH_MAX], to[PATH_MAX], head[96 + COMMENTMAX], *p;
	int i;

	if (samefile(file))
		return 0;
	memset(&h, 0, sizeof(h));
	h.gen = heads[0].gen + 1;
	if (mkdir(NSHDB, 0700) == -1 && errno != EEXIST) {
		printf("%% mkdir %s: %s\n", NSHDB, strerror(errno));
		return -1;
	}
	for (i = ROLLBACKS - 1; i > 0; i--) {
		snprintf(from, sizeof(from), ROLLBACK, i - 1);
		snprintf(to, sizeof(to), ROLLBACK, i);
		if (rename(from, to) == 0) {
			heads[i] = heads[i - 1];
			continue;
		}
		/* the oldest stays if there is none to take its place */
		if (i < ROLLBACKS - 1)
			memset(&heads[i], 0, sizeof(heads[i]));
		if (errno != ENOENT) {
			printf("%% rename %s: %s\n", from, strerror(errno));
			return -1;
		}
	}
	memset(&heads[0], 0, sizeof(heads[0]));
	/* the head on one line, with no control characters */
	snprintf(head, sizeof(head) - 1, "%s%s%s%s", ROLLBACK_HEAD, who,
	    comment[0] != '\0' ? ": " : "", comment);
	for (p = head; *p != '\0'; p++)
		if (iscntrl((unsigned char)*p))
			*p = ' ';
	/* as the parser would read it */
	h.saved = 1;
	p = head + strlen(ROLLBACK_HEAD);
	strlcpy(h.who, p, sizeof(h.who));
	h.who[strcspn(h.who, ":")] = '\0';
	if ((p = strchr(p, ':')) != NULL)
		strlcpy(h.why, p + 1 + strspn(p + 1, " "), sizeof(h.why));
	snprintf(head + strlen(head), sizeof(head) - strlen(head),
	    "\n%s%llu\n", ROLLBACK_GEN, (unsigned long long)h.gen);
	h.len = strlen(head);
	snprintf(to, sizeof(to), ROLLBACK, 0);
	if (copyfile(file, to, head) == -1)
		return -1;
	heads[0] = h;
	return 0;
}

/*
 * The first ROLLBACK_SLOT bytes of each configuration kept, for the
 * parser, each in a slot of slots, ROLLBACKS of them, or none
 */
void
rollback_slots(char *slots)
{
	char path[PATH_MAX];
	FILE *f;
	int i;

	memset(slots, 0, ROLLBACKS * ROLLBACK_SLOT);
	for (i = 0; i < ROLLBACKS; i++) {
		snprintf(path, sizeof(path), ROLLBACK, i);
		if ((f = fopen(path, "r")) == NULL)
			continue;
		fread(slots + i * ROLLBACK_SLOT, 1, ROLLBACK_SLOT, f);
		fclose(f);
	}
}

/*
 * The parser's reading of the head lines in slots (rollback_slots())
 * into h, ROLLBACKS of them: who saved each and their comment, as its
 * first line says, its generation, as the next says, and their length
 */
void
rollback_heads(char *slots, struct rollback_head *h)
{
	char *p, *end, *nl, *why;
	const char *errstr;
	int i;

	memset(h, 0, ROLLBACKS * sizeof(*h));
	for (i = 0; i < ROLLBACKS; i++) {
		p = slots + i * ROLLBACK_SLOT;
		end = p + ROLLBACK_SLOT;
		if (strncmp(p, ROLLBACK_HEAD, strlen(ROLLBACK_HEAD)) != 0 ||
		    (nl = memchr(p, '\n', end - p)) == NULL)
			continue;
		*nl = '\0';
		h[i].saved = 1;
		h[i].len = nl - p + 1;
		why = p + strlen(ROLLBACK_HEAD);
		strlcpy(h[i].who, strsep(&why, ":"), sizeof(h[i].who));
		if (why != NULL)
			strlcpy(h[i].why, why + strspn(why, " "),
			    sizeof(h[i].why));
		p = nl + 1;
		if ((size_t)(end - p) < strlen(ROLLBACK_GEN) ||
		    strncmp(p, ROLLBACK_GEN, strlen(ROLLBACK_GEN)) != 0 ||
		    (nl = memchr(p, '\n', end - p)) == NULL)
			continue;
		*nl = '\0';
		h[i].len += nl - p + 1;
		h[i].gen = strtonum(p + strlen(ROLLBACK_GEN), 1, LLONG_MAX,
		    &errstr);
	}
}

/* h, the parser's reading of the head lines, kept: -1 if it is not one */
int
rollback_heads_kept(struct rollback_head *h)
{
	int i;

	for (i = 0; i < ROLLBACKS; i++)
		if (h[i].len > ROLLBACK_SLOT ||
		    (h[i].saved != 0 && h[i].saved != 1) ||
		    memchr(h[i].who, '\0', sizeof(h[i].who)) == NULL ||
		    memchr(h[i].why, '\0', sizeof(h[i].why)) == NULL)
			return -1;
	memcpy(heads, h, sizeof(heads));
	return 0;
}

/*
 * nshd's save: the running configuration, as conf() writes it, written
 * to SAVED, readable by root alone, whole and on disk, or not at all: 1
 * if it was, else 0 after saying why
 */
int
saved_write(void)
{
	char tmp[] = SAVED ".XXXXXXXXXX";
	FILE *f;
	int fd, ok;

	if (mkdir(NSHDB, 0700) == -1 && errno != EEXIST) {
		printf("%% mkdir %s: %s\n", NSHDB, strerror(errno));
		return 0;
	}
	if ((fd = mkstemp(tmp)) == -1) {
		printf("%% %s: %s\n", tmp, strerror(errno));
		return 0;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		printf("%% %s: %s\n", tmp, strerror(errno));
		close(fd);
		unlink(tmp);
		return 0;
	}
	conf(f);
	ok = fflush(f) != EOF && fsync(fd) == 0;
	if (fclose(f) == EOF)
		ok = 0;
	if (!ok || rename(tmp, SAVED) == -1) {
		printf("%% Unable to save configuration: %s\n",
		    strerror(errno));
		unlink(tmp);
		return 0;
	}
	if (syncdir(NSHDB) == -1)
		return 0;
	printf("%% Saving configuration\n");
	return 1;
}

/*
 * The first time nshd boots, with no SAVED, make it from nsh's own
 * NSHRC, as saved_write() makes one, so nothing in NSHRC is lost: -1 if
 * it could not be, after saying why
 */
int
saved_first(void)
{
	char tmp[] = SAVED ".XXXXXXXXXX", buf[BUFSIZ];
	FILE *in, *out;
	size_t n;
	int fd, ok;

	if (access(SAVED, F_OK) == 0)
		return 0;
	if (errno != ENOENT) {
		printf("%% %s: %s\n", SAVED, strerror(errno));
		return -1;
	}
	if ((in = fopen(NSHRC, "r")) == NULL) {
		if (errno == ENOENT)
			return 0;
		printf("%% %s: %s\n", NSHRC, strerror(errno));
		return -1;
	}
	if ((mkdir(NSHDB, 0700) == -1 && errno != EEXIST) ||
	    (fd = mkstemp(tmp)) == -1) {
		printf("%% %s: %s\n", tmp, strerror(errno));
		fclose(in);
		return -1;
	}
	if ((out = fdopen(fd, "w")) == NULL) {
		printf("%% %s: %s\n", tmp, strerror(errno));
		close(fd);
		unlink(tmp);
		fclose(in);
		return -1;
	}
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
		if (fwrite(buf, 1, n, out) != n)
			break;
	ok = !ferror(in) && fflush(out) != EOF && fsync(fd) == 0;
	fclose(in);
	if (fclose(out) == EOF)
		ok = 0;
	if (!ok || rename(tmp, SAVED) == -1) {
		printf("%% %s: %s\n", SAVED, strerror(errno));
		unlink(tmp);
		return -1;
	}
	if (syncdir(NSHDB) == -1)
		return -1;
	printf("%% %s taken as the saved configuration\n", NSHRC);
	return 0;
}

/* nshd's saved configuration, SAVED, to out: -1 if none, after saying why */
int
saved_text(FILE *out)
{
	char line[BUFSIZ];
	FILE *f;

	if ((f = fopen(SAVED, "r")) == NULL) {
		if (errno == ENOENT)
			printf("%% No saved configuration\n");
		else
			printf("%% %s: %s\n", SAVED, strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f) != NULL)
		fputs(line, out);
	fclose(f);
	return 0;
}

/*
 * show diff-config outside configure, as nshd's system shows it: how the
 * running configuration differs from SAVED, or from an empty one if there
 * is none, printed block by block to stdout by the parser, with each
 * password hash hidden if hide. 1 if they differ, 0 if not, -1 if either
 * cannot be read, after saying why
 */
int
saved_diff(int hide)
{
	char *saved, *now = NULL;
	size_t slen, nlen = 0;
	FILE *f;
	int r = -1;

	if ((saved = saved_read(&slen)) == NULL)
		return -1;
	if ((f = open_memstream(&now, &nlen)) == NULL) {
		printf("%% saved_diff: %s\n", strerror(errno));
		free(saved);
		return -1;
	}
	conf(f);
	if (fclose(f) == EOF)
		printf("%% saved_diff: %s\n", strerror(errno));
	else
		r = parser_diff(saved, slen, now, nlen,
		    "--- startup-config\n+++ running-config\n", hide);
	free(saved);
	free(now);
	return r;
}

/*
 * How b, blen bytes of configuration text, differs from a: block by
 * block, after head, printed, with each password hash hidden if hide,
 * or nothing if quiet. 1 if they differ, 0 if not, -1 if either cannot
 * be read, after saying why
 */
int
commit_diff(char *a, size_t alen, char *b, size_t blen, char *head,
    int hide, int quiet)
{
	struct cnode *x, *y = NULL;
	char *buf = NULL;
	size_t len = 0;
	FILE *out;
	int n = -1;

	if ((x = conftree_mem(a, alen, "a configuration", conf_mode,
	    conf_ordered)) == NULL ||
	    (y = conftree_mem(b, blen, "a configuration", conf_mode,
	    conf_ordered)) == NULL ||
	    (n = conftree_compare(NULL, x, y)) <= 0 || quiet)
		goto done;
	/* buffered whole, to hide the hashes */
	if ((out = open_memstream(&buf, &len)) == NULL) {
		printf("%% commit_diff: %s\n", strerror(errno));
		n = -1;
		goto done;
	}
	fputs(head, out);
	n = conftree_compare(out, x, y);
	if (fclose(out) == EOF) {
		printf("%% commit_diff: %s\n", strerror(errno));
		n = -1;
	} else
		fwrite(buf, 1, hide ? login_hide(buf, len) : len, stdout);
	free(buf);
 done:
	conftree_free(x);
	conftree_free(y);
	return n == -1 ? -1 : n > 0;
}

/*
 * The saved configuration's text, SAVED's, or an empty one if none, and
 * its length in *len; or NULL after saying why
 */
char *
saved_read(size_t *len)
{
	char *empty;

	if (access(SAVED, R_OK) == -1 && errno == ENOENT) {
		*len = 0;
		if ((empty = strdup("")) == NULL)
			printf("%% %s: %s\n", SAVED, strerror(errno));
		return empty;
	}
	return file_text(SAVED, len);
}

/* file's text, its length in *len: NULL if it cannot be read, saying why */
static char *
file_text(const char *file, size_t *len)
{
	char buf[BUFSIZ], *text = NULL;
	FILE *f, *m;
	size_t n;
	int ok;

	*len = 0;
	if ((f = fopen(file, "r")) == NULL) {
		printf("%% %s: %s\n", file, strerror(errno));
		return NULL;
	}
	if ((m = open_memstream(&text, len)) == NULL) {
		printf("%% %s: %s\n", file, strerror(errno));
		fclose(f);
		return NULL;
	}
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
		if (fwrite(buf, 1, n, m) != n)
			break;
	ok = !ferror(f) && !ferror(m);
	fclose(f);
	if (fclose(m) == EOF)
		ok = 0;
	if (!ok) {
		printf("%% %s: %s\n", file, strerror(errno));
		free(text);
		return NULL;
	}
	return text;
}

/* dir's entries, synced to disk: -1 if not, after saying why */
static int
syncdir(const char *dir)
{
	int fd, r;

	if ((fd = open(dir, O_RDONLY | O_DIRECTORY)) == -1) {
		printf("%% %s: %s\n", dir, strerror(errno));
		return -1;
	}
	if ((r = fsync(fd)) == -1)
		printf("%% %s: %s\n", dir, strerror(errno));
	close(fd);
	return r;
}

/* Does file a hold the same as rollback 0, after its head lines? */
static int
samefile(const char *a)
{
	char x[BUFSIZ], y[BUFSIZ];
	FILE *fa, *fb;
	size_t n;
	int same = 0;

	if ((fa = fopen(a, "r")) == NULL)
		return 0;
	snprintf(y, sizeof(y), ROLLBACK, 0);
	if ((fb = fopen(y, "r")) == NULL) {
		fclose(fa);
		return 0;
	}
	if (fseek(fb, heads[0].len, SEEK_SET) == -1)
		goto done;
	do {
		n = fread(x, 1, sizeof(x), fa);
		if (fread(y, 1, sizeof(y), fb) != n || memcmp(x, y, n) != 0)
			goto done;
	} while (n == sizeof(x));
	same = !ferror(fa) && !ferror(fb);
done:
	fclose(fa);
	fclose(fb);
	return same;
}

/* Copy file from to to, after head, made 0600, or none of it; -1 if not */
static int
copyfile(const char *from, char *to, char *head)
{
	char buf[BUFSIZ];
	FILE *in, *out;
	size_t n;
	int fd, ret = -1;

	if ((in = fopen(from, "r")) == NULL) {
		printf("%% %s: %s\n", from, strerror(errno));
		return -1;
	}
	if ((fd = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0600)) == -1) {
		printf("%% %s: %s\n", to, strerror(errno));
		fclose(in);
		return -1;
	}
	if ((out = fdopen(fd, "w")) == NULL) {
		printf("%% %s: %s\n", to, strerror(errno));
		close(fd);
		goto done;
	}
	fputs(head, out);
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
		if (fwrite(buf, 1, n, out) != n)
			break;
	if (ferror(in))
		printf("%% %s: %s\n", from, strerror(errno));
	else if (ferror(out))
		printf("%% %s: %s\n", to, strerror(errno));
	else
		ret = 0;
	if (fclose(out) == EOF && ret == 0) {
		printf("%% %s: %s\n", to, strerror(errno));
		ret = -1;
	}
done:
	if (ret == -1)
		unlink(to);
	fclose(in);
	return ret;
}

/* Configuration n as it was saved, to out: -1 on error, after saying why */
int
rollback_text(int n, FILE *out)
{
	char path[PATH_MAX], line[BUFSIZ];
	FILE *f;

	snprintf(path, sizeof(path), ROLLBACK, n);
	if ((f = fopen(path, "r")) == NULL) {
		printf("%% rollback %d: %s\n", n, strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f) != NULL)
		fputs(line, out);
	fclose(f);
	return 0;
}

/*
 * What configuration n changed from the one saved before it, n + 1, as
 * texts for the parser to compare: 1 with both, 0 if n + 1 is not kept,
 * after saying so, or -1 if either cannot be read, after saying why
 */
int
rollback_texts(int n, char **old, size_t *oldlen, char **new,
    size_t *newlen)
{
	char a[PATH_MAX], b[PATH_MAX];

	*old = *new = NULL;
	snprintf(b, sizeof(b), ROLLBACK, n);
	snprintf(a, sizeof(a), ROLLBACK, n + 1);
	if (access(b, R_OK) == -1) {
		printf("%% rollback %d: %s\n", n, strerror(errno));
		return -1;
	}
	if (access(a, R_OK) == -1 && errno == ENOENT) {
		printf("%% No configuration saved before rollback %d is kept\n",
		    n);
		return 0;
	}
	if ((*old = file_text(a, oldlen)) == NULL ||
	    (*new = file_text(b, newlen)) == NULL) {
		free(*old);
		*old = NULL;
		return -1;
	}
	return 1;
}

/*
 * When each configuration kept was saved, its generation, who saved it
 * and why, to out
 */
void
rollback_list(FILE *out)
{
	char path[PATH_MAX], when[64], gen[40];
	struct rollback_head *h;
	struct stat sb;
	int i;

	for (i = 0; i < ROLLBACKS; i++) {
		snprintf(path, sizeof(path), ROLLBACK, i);
		if (stat(path, &sb) == -1)
			continue;
		strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S %Z",
		    localtime(&sb.st_mtime));
		/* one saved without a head line says only when */
		h = &heads[i];
		gen[0] = '\0';
		if (h->gen > 0)
			snprintf(gen, sizeof(gen), "generation %llu  ",
			    (unsigned long long)h->gen);
		fprintf(out, "%2d  %s%s%s%s%s%s\n", i, gen, when,
		    h->saved ? "  " : "", h->who, h->why[0] != '\0' ? "  " : "",
		    h->why);
	}
}

/* Write to a buffer, for a block whose head waits on its lines */
static int
sub_begin(struct commit *c, struct sub *s)
{
	s->buf = NULL;
	s->len = 0;
	s->save = c->f;
	if ((c->f = open_memstream(&s->buf, &s->len)) == NULL) {
		c->f = s->save;
		printf("%% commit: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* The block: its head, its lines and a '!', if it has lines or always */
static void
sub_end(struct commit *c, struct sub *s, const char *in, char *head,
    int always)
{
	fclose(c->f);
	c->f = s->save;
	if (s->len > 0 || always)
		fprintf(c->f, "%s%s\n%s%s!\n", in, head,
		    s->buf != NULL ? s->buf : "", in);
	free(s->buf);
}
