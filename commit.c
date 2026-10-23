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
 * becomes a script in the form cmdrc() reads, and cmdrc() runs it
 * through the commands that run nshrc at boot. First what goes, in
 * the reverse of the order conf() prints it, then what comes, in that
 * order:
 *
 *  * a line goes as its no, or "no x" as x, unless the candidate sets
 *    the same setting another way, which its own line does;
 *  * a list goes as the values the candidate's line has not;
 *  * an interface's addresses come again after a new rdomain, which
 *    took them away;
 *  * a cloned interface goes whole, and a physical one line by line;
 *  * a daemon's state goes as its disable, and its rules as no file;
 *  * a block's new lines come under it, and a list's new values;
 *  * a daemon's rules come whole, and what conf() prints after them,
 *    its reload or install, comes when they are new or it starts.
 *
 * script_make() makes the script from the two trees alone, and
 * script_run() runs it, so one process may make what another runs.
 *
 * Then the running configuration must read as the candidate does, but
 * for a physical interface the candidate has no block for, which keeps
 * what its hardware has. If it does not, a script back to the
 * configuration as it was undoes the commit, and what did not take is
 * shown.
 *
 * Each configuration saved is kept, the last ROLLBACKS of them, for
 * rollback N and show rollback, with who saved it and the comment they
 * gave, on a line of its own that cmdrc() and conftree_read() skip.
 *
 * commit check shows what would keep the candidate from being the
 * running configuration that it can see before then: an interface a
 * line names that is not there, one in two trunks or bridges, a bridge
 * option for one not its member, an address twice in one rdomain, a
 * vlan or carp id twice on one interface, a daemon in an rtable nothing
 * makes, and daemon rules their test refuses. commit refuses a
 * candidate with any of them.
 *
 * nsh -i makes the running configuration its file as commit does the
 * candidate, all of it that takes; nothing is undone (commit_boot()).
 *
 * commit confirmed does all that but save, and a process waits; unless
 * a commit confirms it first, at the deadline the running configuration
 * goes back to how it was before the first commit not confirmed
 * (commit_expire()). What it goes back to and when are in CONFIRM, as
 * the configuration itself is not saved until confirmed.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "externs.h"
#include "ctl.h"
#include "conftree.h"
#include "settings.h"
#include "kfacts.h"
#include "session.h"

#define CONFIRMMIN	10	/* commit confirmed's minutes, if not given */
#define CONFIRMMAX	1440

struct commit {
	FILE *f;			/* the script's lines */
	struct cnode *from, *to;	/* the configurations it goes between */
	struct script *s;
};

/* A buffer for a block's lines, whose head waits on them */
struct sub {
	FILE *save;
	char *buf;
	size_t len;
};

/* A line, where conf() prints it among its block's */
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

/* in nshd's config, the tests of rules check() keeps for system */
static struct plan_test *deferred;
static int ndeferred;

/* An interface's lines that name other interfaces: the word, or 0 all */
static const struct {
	char *name;
	int word;
} ifrefs[] = {
	{ "parent", 1 }, { "carpdev", 1 }, { "syncdev", 1 }, { "patch", 1 },
	{ "pppoe dev", 1 }, { "trunkport", 0 },
};

static int take(struct cnode *, struct cnode *);
static int check(struct cnode *, struct cnode *);
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
static int apply(struct cnode *, struct cnode *);
static int waiter(time_t);
static int unconfirm(struct cnode *, time_t);
static struct cnode *unconfirmed(void);
static time_t deadline(void);
static void confirmed(void);
static void report(const char *);
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
static int context(char *);
static int rtableid(char *);
static int ifblock(char *, char *, size_t);
static int clear(struct commit *, char *, int, int);
static const char *committer(void);
static int samefile(const char *, char *);
static int copyfile(const char *, char *, char *);
static int syncdir(const char *);
static int sub_begin(struct commit *, struct sub *);
static void sub_end(struct commit *, struct sub *, const char *, char *,
    int);

/*
 * commit [confirmed [minutes]] [comment text]: in configure private,
 * make the candidate the running configuration, all of it or none, then
 * save the running configuration; or with confirmed, do not save it,
 * and roll it back unless a commit confirms it in time. Elsewhere, nshd
 * saves it. The comment is kept with what is saved.
 */
int
commit(int argc, char **argv, ...)
{
	struct cnode *want, *was, *now, *back = NULL;
	char comment[COMMENTMAX] = "";
	const char *errstr;
	time_t when = 0;
	int minutes = 0, checking = 0, bad, ret = -1, i, j, said = 1;

	/* comment, at least "com" of it, and the words after it */
	for (i = 1; i < argc && (strlen(argv[i]) < 3 ||
	    !isprefix(argv[i], "comment")); i++)
		;
	if (i < argc) {
		said = i + 1 < argc;
		for (j = i + 1; j < argc; j++)
			if ((j > i + 1 && strlcat(comment, " ",
			    sizeof(comment)) >= sizeof(comment)) ||
			    strlcat(comment, argv[j], sizeof(comment)) >=
			    sizeof(comment)) {
				printf("%% comment is longer than %d\n",
				    COMMENTMAX - 1);
				return -1;
			}
		argc = i;
	}
	if (argc > 1) {
		checking = isprefix(argv[1], "check") != 0;
		/* c alone could be either */
		if (checking == (isprefix(argv[1], "confirmed") != 0) ||
		    (checking && argc > 2))
			argc = 4;
	}
	if (argc > 3 || !said) {
		printf("%% commit [check | confirmed [minutes]] "
		    "[comment text]\n");
		return -1;
	}
	if (comment[0] != '\0' && argc > 1) {
		printf("%% commit %s saves nothing to comment\n",
		    checking ? "check" : "confirmed");
		return -1;
	}
	if (argc > 1 && !checking) {
		minutes = CONFIRMMIN;
		if (argc == 3 && (minutes = strtonum(argv[2], 1, CONFIRMMAX,
		    &errstr)) == 0) {
			printf("%% minutes %s is %s\n", argv[2], errstr);
			return -1;
		}
	}
	/* configure's, nshd's; outside it, what runs, which nshd saves */
	if (nshd_config || !candidate)
		return nshd_commit(checking, minutes, comment);
	/* one not confirmed in time goes back first */
	commit_expire();
	if ((want = cand_tree()) == NULL)
		return -1;
	if ((was = running_tree()) == NULL)
		return -1;
	if ((bad = commit_checks(was, want, checking)) == -1 || checking) {
		ret = bad;
		goto done;
	}
	if (minutes > 0) {
		/* back to before the first commit not confirmed */
		if ((back = unconfirmed()) == NULL &&
		    (back = conftree_copy(was)) == NULL) {
			printf("%% commit: %s\n", strerror(errno));
			goto done;
		}
		when = time(NULL) + minutes * 60;
		if (waiter(when) == -1)
			goto done;
	}
	if (conftree_compare(NULL, was, want) != 0 && take(was, want) == -1)
		goto done;
	/* taken: what fails after is said, and the candidate starts again */
	ret = 0;
	if (minutes > 0) {
		if (unconfirm(back, when) == -1) {
			printf("%% Nothing can roll this commit back: undone\n");
			if ((now = running_tree()) != NULL)
				apply(now, was);
			conftree_free(now);
			ret = -1;
			goto done;
		}
		printf("%% Commit within %d minute%s to keep this, or it is "
		    "rolled back\n", minutes, minutes == 1 ? "" : "s");
	} else {
		confirmed();
		if (conf_save())
			rollback_keep(SAVED, committer(), comment);
		else
			ret = -1;
	}
	/* a new candidate, from the new running configuration */
	cand_end();
	if (cand_begin() == -1)
		ret = -1;
done:
	conftree_free(back);
	conftree_free(was);
	return ret;
}

/*
 * check() of want against was, as commit says it: 0 if want may become
 * the running configuration, else -1; with checking, said either way
 */
int
commit_checks(struct cnode *was, struct cnode *want, int checking)
{
	return commit_verdict(check(was, want), checking);
}

/* The problems check() finds with want, each said, and how many */
int
commit_problems(struct cnode *was, struct cnode *want)
{
	return check(was, want);
}

/* The verdict on bad problems, said as commit_checks() says it */
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

/* What did not take, now against want, and failed if a line failed */
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

/* Whether the way back, back, is how it was, was: 0 if so, said */
int
commit_back(struct cnode *back, struct cnode *was)
{
	if (differ(NULL, back, was) == 0) {
		printf("%% The running configuration is as it was\n");
		return 0;
	}
	printf("%% The running configuration differs from how it was\n");
	differ(stdout, back, was);
	return -1;
}

/*
 * Does the running configuration, now, read as the saved one, want, as
 * nshd's boot makes it? 0 if so, else -1, what differs said
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
 * Does configuration text now read as text want, as commit_took() reads
 * them? 1 if it does, 0 if not, -1 if either could not be read, said why
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

/*
 * A commit not confirmed goes back, as nshd's system takes it back: the
 * running configuration made to read as back's text, as commit_expire()
 * makes it. 0 if it does, else -1, said why
 */
int
commit_recover(char *back, size_t backlen)
{
	struct cnode *b, *now = NULL, *after = NULL;
	int ret = -1;

	if ((b = conftree_mem(back, backlen, "the configuration before",
	    conf_mode, conf_ordered)) == NULL)
		return -1;
	if ((now = running_tree()) != NULL &&
	    (conftree_compare(NULL, now, b) == 0 || apply(now, b) != -1) &&
	    (after = running_tree()) != NULL) {
		if (commit_took(after, b)) {
			printf("%% Commit not confirmed: rolled back\n");
			ret = 0;
		} else {
			printf("%% Commit not confirmed: rolled back, but the "
			    "running configuration differs from how it was\n");
			differ(stdout, after, b);
		}
	}
	conftree_free(after);
	conftree_free(now);
	conftree_free(b);
	return ret;
}

/*
 * What would keep want from becoming the running configuration, was,
 * that can be seen before it does: each problem shown, and how many
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

	/* its name, "no learning" one of them, and then its ports */
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
	char *l, *s, *v, name[32], rd[32];
	size_t i, n;
	int id = rtableid(block);

	if (kf_rtable(id) || conftree_line(want, block, "route", 0) != NULL)
		return 0;
	snprintf(rd, sizeof(rd), "rdomain %d", id);
	for (i = 0; (s = conftree_stmt(want, i)) != NULL; i++)
		if ((v = conftree_line(want, s, "rdomain", 0)) != NULL &&
		    strcmp(v, rd) == 0)
			return 0;
	for (n = 0; (l = conftree_line(want, block, NULL, n)) != NULL; n++)
		if (ctl_line(l, name, sizeof(name)) == CTL_STATE)
			return problem("%s: %s, but nothing makes table %d: a "
			    "route in it, or an interface in rdomain %d", block,
			    l, id, id);
	return 0;
}

/* Daemon rules under block, or the top level, new or changed: tested */
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
 * Test daemon name's rules, its n lines, which label names: -1 if the
 * test refuses them, else 0. nshd's config runs no test: it keeps them
 * for system, as commit_deferred() gives them
 */
static int
rules_test(char *name, char **lines, size_t n, char *label)
{
	struct plan_test *t, *nt;
	FILE *f;
	size_t i;

	if (!in_config)
		return ctl_rules_test(name, lines, n);
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

/* The tests rules_test() kept for system, into *tp, now the caller's */
int
commit_deferred(struct plan_test **tp)
{
	int n = ndeferred;

	*tp = deferred;
	deferred = NULL;
	ndeferred = 0;
	return n;
}

/* A daemon's test refuses its rules, which label names: a problem */
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
 * The interface that claimed what before, if not who, or NULL, and
 * then what is who's
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
 * Make the running configuration, was, read as want, or undo that; -1
 * if it does not read as want
 */
static int
take(struct cnode *was, struct cnode *want)
{
	struct cnode *now = NULL, *back = NULL;
	int ret = -1, failed;

	if ((failed = apply(was, want)) == -1 ||
	    (now = running_tree()) == NULL)
		goto done;
	if (!failed && commit_took(now, want)) {
		ret = 0;
		goto done;
	}
	commit_untaken(now, want, failed);
	conftree_free(now);
	if ((now = running_tree()) == NULL || apply(now, was) == -1 ||
	    (back = running_tree()) == NULL)
		goto done;
	commit_back(back, was);
done:
	conftree_free(back);
	conftree_free(now);
	return ret;
}

/*
 * nsh -i: make the running configuration the one in path, as commit
 * makes it the candidate, but never undone: what check finds is shown,
 * all that takes stays, and what did not take is shown. Returns 1 if
 * a line failed or the running configuration then differs from it,
 * else 0.
 */
int
commit_boot(char *path)
{
	struct cnode *want, *was = NULL, *now = NULL;
	int ret = 1, failed = 0;

	if ((want = conftree_read(path, conf_mode, conf_ordered)) == NULL)
		return 1;
	if ((was = running_tree()) == NULL)
		goto done;
	/* shown, but a system starts with what takes */
	check(was, want);
	if (conftree_compare(NULL, was, want) != 0 &&
	    (failed = apply(was, want)) == -1)
		goto done;
	if ((now = running_tree()) == NULL)
		goto done;
	if (differ(NULL, now, want) == 0)
		ret = failed;
	else {
		printf("%% The running configuration differs from %s\n", path);
		differ(stdout, now, want);
		syslog(LOG_WARNING, "the running configuration differs from %s",
		    path);
	}
done:
	conftree_free(now);
	conftree_free(was);
	conftree_free(want);
	return ret;
}

/*
 * A commit not confirmed by its deadline goes back: the running
 * configuration is made the one before the first commit not confirmed.
 * Returns 1 if one went back, else 0.
 */
int
commit_expire(void)
{
	struct cnode *back, *now = NULL, *after = NULL;
	time_t when;

	if ((when = deadline()) == 0 || time(NULL) < when ||
	    (back = unconfirmed()) == NULL)
		return 0;
	if ((now = running_tree()) != NULL &&
	    (conftree_compare(NULL, now, back) == 0 ||
	    apply(now, back) != -1) &&
	    (after = running_tree()) != NULL &&
	    differ(NULL, after, back) == 0)
		report("Commit not confirmed: rolled back");
	else {
		report("Commit not confirmed: rolled back, but the running "
		    "configuration differs from how it was");
		if (after != NULL)
			differ(stdout, after, back);
	}
	/* unless another commit confirmed has come since */
	if (deadline() == when && unlink(CONFIRM) == -1)
		printf("%% unlink %s: %s\n", CONFIRM, strerror(errno));
	conftree_free(after);
	conftree_free(now);
	conftree_free(back);
	return 1;
}

/*
 * A process of its own, apart from the session, to wait for when and
 * then roll back a commit not confirmed: -1 if there cannot be one
 */
static int
waiter(time_t when)
{
	time_t left;
	pid_t pid;
	int fd, status;

	fflush(stdout);
	switch (pid = fork()) {
	case -1:
		printf("%% commit confirmed: fork: %s\n", strerror(errno));
		return -1;
	case 0:
		break;
	default:
		if (waitpid(pid, &status, 0) == -1 || !WIFEXITED(status) ||
		    WEXITSTATUS(status) != 0) {
			printf("%% commit confirmed: no process to wait\n");
			return -1;
		}
		return 0;
	}
	/* its child, so init and not the session waits for it */
	switch (fork()) {
	case -1:
		_exit(1);
	case 0:
		break;
	default:
		_exit(0);
	}
	setsid();
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	if ((fd = open(_PATH_DEVNULL, O_RDWR)) != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	}
	while ((left = when - time(NULL)) > 0)
		sleep(left > INT_MAX ? INT_MAX : left);
	commit_expire();
	_exit(0);
}

/* Roll back to back at when, unless confirmed: CONFIRM, or -1 */
static int
unconfirm(struct cnode *back, time_t when)
{
	char path[PATH_MAX];
	FILE *f;
	int fd;

	snprintf(path, sizeof(path), "%s.new", CONFIRM);
	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600)) == -1) {
		printf("%% %s: %s\n", path, strerror(errno));
		return -1;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		printf("%% %s: %s\n", path, strerror(errno));
		close(fd);
		unlink(path);
		return -1;
	}
	fprintf(f, "# deadline %lld\n", (long long)when);
	if (conftree_write(f, back) == -1 || fclose(f) == EOF ||
	    rename(path, CONFIRM) == -1) {
		printf("%% %s: %s\n", path, strerror(errno));
		unlink(path);
		return -1;
	}
	return 0;
}

/* What a commit not confirmed goes back to, or NULL if there is none */
static struct cnode *
unconfirmed(void)
{
	if (access(CONFIRM, F_OK) == -1)
		return NULL;
	return conftree_read(CONFIRM, conf_mode, conf_ordered);
}

/* When a commit not confirmed goes back, or 0 if there is none */
static time_t
deadline(void)
{
	long long when;
	FILE *f;

	if ((f = fopen(CONFIRM, "r")) == NULL)
		return 0;
	if (fscanf(f, "# deadline %lld", &when) != 1)
		when = 0;
	fclose(f);
	return when;
}

/* The commit not confirmed is: nothing rolls it back */
static void
confirmed(void)
{
	if (unlink(CONFIRM) == 0)
		printf("%% Commit confirmed\n");
	else if (errno != ENOENT)
		printf("%% unlink %s: %s\n", CONFIRM, strerror(errno));
}

/* What a rollback did, to the session if there is one, and the log */
static void
report(const char *msg)
{
	printf("%% %s\n", msg);
	syslog(LOG_WARNING, "%s", msg);
}

/*
 * Make the running configuration, from, read as to: -1 if the script
 * could not run, 1 if a line of it failed, else 0
 */
static int
apply(struct cnode *from, struct cnode *to)
{
	struct script s;
	int ret;

	if (script_make(from, to, &s) == -1)
		return -1;
	ret = script_run(&s);
	script_free(&s);
	return ret;
}

/*
 * The script that makes from read as to, into s, from the trees alone;
 * -1 if it could not be made, said why
 */
int
script_make(struct cnode *from, struct cnode *to, struct script *s)
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
	if (ret == -1)
		script_free(s);
	return ret;
}

/*
 * Run s, as cmdrc() runs nshrc at boot: -1 if it could not run, 1 if a
 * line of it failed, else 0
 */
int
script_run(struct script *s)
{
	char path[] = "/tmp/nshcommit.XXXXXXXX";
	FILE *f;
	int fd, i, save, rt, failed, ret = -1;

	if ((fd = mkstemp(path)) == -1) {
		printf("%% mkstemp %s: %s\n", path, strerror(errno));
		return -1;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		printf("%% commit: %s\n", strerror(errno));
		close(fd);
		goto done;
	}
	if (s->len > 0 && fwrite(s->text, s->len, 1, f) != 1) {
		printf("%% %s: %s\n", path, strerror(errno));
		fclose(f);
		goto done;
	}
	if (fclose(f) == EOF) {
		printf("%% %s: %s\n", path, strerror(errno));
		goto done;
	}

	/* from table 0, as nshrc at boot, whatever the session's table */
	if ((rt = cli_rtable) != 0) {
		if (nsh_setrtable(0) != 0)
			goto done;
		cli_rtable = 0;
	}
	/* empty rules before the script starts a daemon on them */
	for (i = 0; i < s->nclears; i++)
		if (s->clears[i].keep)
			ctl_rules_clear(s->clears[i].name, s->clears[i].rtable,
			    1);
	save = candidate;
	candidate = 0;
	failed = cmdrc(path) == -1;
	candidate = save;
	/* and none once it stopped the daemon */
	for (i = 0; i < s->nclears; i++)
		if (!s->clears[i].keep)
			ctl_rules_clear(s->clears[i].name, s->clears[i].rtable,
			    0);
	if (cli_rtable != rt && nsh_setrtable(rt) == 0)
		cli_rtable = rt;
	ret = failed;
done:
	unlink(path);
	return ret;
}

void
script_free(struct script *s)
{
	free(s->text);
	s->text = NULL;
	s->len = 0;
}

/*
 * What goes from under fblock, in the reverse of conf()'s order. The
 * candidate has the block as tblock, if there.
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
			/* a daemon's rules: changed, they come whole */
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
			/* a block's lines go, in reverse */
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
			/* a physical interface stays, with nothing on it */
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
 * What comes under tblock, in conf()'s order. The running
 * configuration has the block as fblock, if there.
 */
static int
additions(struct commit *c, char *fblock, char *tblock, int there,
    const char *in)
{
	struct ranked *r;
	struct sub s;
	char *l, *f, *fp = NULL, *tp = NULL, *k, name[IFNAMSIZ], dname[32];
	size_t n, i, j;
	int moved, ret = -1;

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
			/* a new or renamed rtable comes, lines or not */
			sub_end(c, &s, in, l, f == NULL || strcmp(f, l) != 0);
		} else if (conftree_line(c->to, tp, NULL, 0) != NULL ||
		    (tblock == NULL && ifblock(l, name, sizeof(name)))) {
			if (sub_begin(c, &s) == -1)
				goto done;
			/* a new rdomain took the addresses, so they come again */
			moved = f != NULL && context(tp) == CTX_IF &&
			    !sameline(c->from, fp, c->to, tp, "rdomain");
			for (j = 0; (k = conftree_line(c->to, tp, NULL, j)) !=
			    NULL; j++)
				if (f == NULL || !has(c->from, fp, k) ||
				    (moved && address(k)))
					set(c, fp, f != NULL, context(tp), k);
			sub_end(c, &s, in, l, f == NULL);
		} else if (ctl_line(l, dname, sizeof(dname)) == CTL_FOLLOW) {
			/* new, as everything in a new rtable is, or taken again */
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
 * What takes away line, under the block the candidate has as tblock if
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
 * What brings line in, under the block the running configuration has
 * as fblock if there, in context ctx: line, or the values of a list
 * its line lacks
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

/* The list line under block in t with list line's name, and its no */
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

/* Where a list line's values start, after its no and its name */
static char *
listvalues(char *line)
{
	if (strncmp(line, "no ", 3) == 0)
		line += 3;
	return line + strcspn(line, " ");
}

/*
 * The values of list line that list other has not, under line's name,
 * or with gone, under the name that takes them away: its no, or itself
 * without its no. Nothing if there are none.
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
 * Does daemon name take its rules again, the candidate's under tblock:
 * are they new, or does it start? The running configuration has the
 * block as fblock.
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

/* Daemon rules no script writes: none, or with keep, an empty file */
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

/* Who commits: the session's login name, or else the user's */
static const char *
committer(void)
{
	struct passwd *pw;
	char *l;

	if ((l = getlogin()) != NULL)
		return l;
	return (pw = getpwuid(getuid())) != NULL ? pw->pw_name : "?";
}

/*
 * Keep the configuration just saved, in file, as rollback 0, with who
 * saved it and their comment, if not empty; each kept before it one
 * further on, and the oldest no more; unless rollback 0 is the same. -1
 * if it could not, said why
 */
int
rollback_keep(const char *file, const char *who, const char *comment)
{
	char from[PATH_MAX], to[PATH_MAX], head[64 + COMMENTMAX], *p;
	int i;

	snprintf(to, sizeof(to), ROLLBACK, 0);
	if (samefile(file, to))
		return 0;
	if (mkdir(NSHDB, 0700) == -1 && errno != EEXIST) {
		printf("%% mkdir %s: %s\n", NSHDB, strerror(errno));
		return -1;
	}
	for (i = ROLLBACKS - 1; i > 0; i--) {
		snprintf(from, sizeof(from), ROLLBACK, i - 1);
		snprintf(to, sizeof(to), ROLLBACK, i);
		if (rename(from, to) == -1 && errno != ENOENT) {
			printf("%% rename %s: %s\n", from, strerror(errno));
			return -1;
		}
	}
	/* one line, of words alone */
	snprintf(head, sizeof(head) - 1, "%s%s%s%s", ROLLBACK_HEAD, who,
	    comment[0] != '\0' ? ": " : "", comment);
	for (p = head; *p != '\0'; p++)
		if (iscntrl((unsigned char)*p))
			*p = ' ';
	strlcat(head, "\n", sizeof(head));
	snprintf(to, sizeof(to), ROLLBACK, 0);
	return copyfile(file, to, head);
}

/*
 * nshd's save: the running configuration, as conf() writes it, made
 * SAVED, root's alone, whole and on disk, or not at all: 1 if it was,
 * else 0, said why
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
 * The first time nshd boots, with no SAVED, nsh's own NSHRC made it, as
 * saved_write() makes one, so nothing in it is lost: -1 if it could not
 * be, said why
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

/* nshd's saved configuration, SAVED, to out: -1 if none, said why */
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
 * show diff-config outside configure, as nshd's system shows it: the
 * saved configuration, SAVED, or none, against what runs, block by
 * block, to stdout, if they differ: 1 if they do, 0 if not, -1 if either
 * cannot be read, said why
 */
int
saved_diff(void)
{
	struct cnode *saved, *now = NULL;
	int n = -1;

	if (access(SAVED, R_OK) == -1 && errno == ENOENT)
		saved = conftree_read("/dev/null", conf_mode, conf_ordered);
	else
		saved = conftree_read(SAVED, conf_mode, conf_ordered);
	if (saved != NULL && (now = running_tree()) != NULL &&
	    (n = conftree_compare(NULL, saved, now)) > 0) {
		printf("--- startup-config\n+++ running-config\n");
		n = conftree_compare(stdout, saved, now);
	}
	conftree_free(saved);
	conftree_free(now);
	return n == -1 ? -1 : n > 0;
}

/* dir's entries, as they now are, kept: -1, said, if not */
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

/* Do the files a and b hold the same, but for b's line of who saved it? */
static int
samefile(const char *a, char *b)
{
	char x[BUFSIZ], y[BUFSIZ];
	FILE *fa, *fb;
	size_t n;
	int same = 0;

	if ((fa = fopen(a, "r")) == NULL)
		return 0;
	if ((fb = fopen(b, "r")) == NULL) {
		fclose(fa);
		return 0;
	}
	if (fgets(y, sizeof(y), fb) == NULL ||
	    strncmp(y, ROLLBACK_HEAD, strlen(ROLLBACK_HEAD)) != 0)
		rewind(fb);
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

/*
 * show rollback [N]: when each configuration kept was saved, who saved
 * it and their comment, or configuration N
 */
int
pr_rollback(int argc, char **argv, ...)
{
	char words[sizeof("rollback 99")];
	const char *errstr;
	int n;

	if (argc == 3) {
		n = strtonum(argv[2], 0, ROLLBACKS - 1, &errstr);
		if (errstr != NULL) {
			printf("%% rollback %s is %s\n", argv[2], errstr);
			return -1;
		}
	}
	/* nshd's */
	if (argc == 3)
		snprintf(words, sizeof(words), "rollback %d", n);
	else
		strlcpy(words, "rollback", sizeof(words));
	return nshd_show(words) ? 0 : -1;
}

/* Configuration n as it was saved, to out: -1 if it could not be, said why */
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

/* When each configuration kept was saved, who saved it and why, to out */
void
rollback_list(FILE *out)
{
	char path[PATH_MAX], when[64], line[BUFSIZ], *who, *why;
	struct stat sb;
	FILE *f;
	int i;

	for (i = 0; i < ROLLBACKS; i++) {
		snprintf(path, sizeof(path), ROLLBACK, i);
		if (stat(path, &sb) == -1)
			continue;
		strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S %Z",
		    localtime(&sb.st_mtime));
		/* one saved before who saved it was kept says when alone */
		who = why = NULL;
		if ((f = fopen(path, "r")) != NULL) {
			if (fgets(line, sizeof(line), f) != NULL &&
			    strncmp(line, ROLLBACK_HEAD,
			    strlen(ROLLBACK_HEAD)) == 0) {
				line[strcspn(line, "\n")] = '\0';
				why = line + strlen(ROLLBACK_HEAD);
				who = strsep(&why, ":");
				if (why != NULL)
					why += strspn(why, " ");
			}
			fclose(f);
		}
		fprintf(out, "%2d  %s%s%s%s%s\n", i, when, who ? "  " : "",
		    who ? who : "", why ? "  " : "", why ? why : "");
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
