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
 * Then the running configuration must read as the candidate does, but
 * for a physical interface the candidate has no block for, which keeps
 * what its hardware has. If it does not, a script back to the
 * configuration as it was undoes the commit, and what did not take is
 * shown.
 *
 * Each configuration saved is kept, the last ROLLBACKS of them, for
 * rollback N and show rollback.
 *
 * commit confirmed does all that but save, and a process waits; unless
 * a commit confirms it first, at the deadline the running configuration
 * goes back to how it was before the first commit not confirmed
 * (commit_expire()). What it goes back to and when are in CONFIRM, as
 * the configuration itself is not saved until confirmed.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
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

#define MAXCLEARS	64
#define CONFIRMMIN	10	/* commit confirmed's minutes, if not given */
#define CONFIRMMAX	1440

struct commit {
	FILE *f;			/* the script */
	struct cnode *from, *to;	/* the configurations it goes between */
	struct {
		char name[32];
		int rtable;
		int keep;
	} clears[MAXCLEARS];		/* daemon rules no script can write */
	int nclears;
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

static int take(struct cnode *, struct cnode *);
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
static void history(void);
static int samefile(char *, char *);
static int copyfile(char *, char *);
static int sub_begin(struct commit *, struct sub *);
static void sub_end(struct commit *, struct sub *, const char *, char *,
    int);

/*
 * commit [confirmed [minutes]]: in configure private, make the
 * candidate the running configuration, all of it or none, then save the
 * running configuration; or with confirmed, do not save it, and roll it
 * back unless a commit confirms it in time. Elsewhere, save it.
 */
int
commit(int argc, char **argv, ...)
{
	struct cnode *want, *was, *now, *back = NULL;
	const char *errstr;
	time_t when = 0;
	int minutes = 0;

	if (argc > 3 || (argc > 1 && !isprefix(argv[1], "confirmed"))) {
		printf("%% commit [confirmed [minutes]]\n");
		return 0;
	}
	if (argc > 1) {
		minutes = CONFIRMMIN;
		if (argc == 3 && (minutes = strtonum(argv[2], 1, CONFIRMMAX,
		    &errstr)) == 0) {
			printf("%% minutes %s is %s\n", argv[2], errstr);
			return 0;
		}
		if (!candidate) {
			printf("%% commit confirmed requires configure "
			    "private\n");
			return 0;
		}
	}
	/* one not confirmed in time goes back first */
	commit_expire();
	if (!candidate) {
		if (conf_save()) {
			confirmed();
			history();
		}
		return 0;
	}
	if ((want = cand_tree()) == NULL)
		return 0;
	if ((was = running_tree()) == NULL)
		return 0;
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
	if (minutes > 0) {
		if (unconfirm(back, when) == -1) {
			printf("%% Nothing can roll this commit back: undone\n");
			if ((now = running_tree()) != NULL)
				apply(now, was);
			conftree_free(now);
			goto done;
		}
		printf("%% Commit within %d minute%s to keep this, or it is "
		    "rolled back\n", minutes, minutes == 1 ? "" : "s");
	} else {
		confirmed();
		if (conf_save())
			history();
	}
	/* a new candidate, from the new running configuration */
	cand_end();
	cand_begin();
done:
	conftree_free(back);
	conftree_free(was);
	return 0;
}

/*
 * Make the running configuration, was, read as want, or undo that; -1
 * if it does not read as want
 */
static int
take(struct cnode *was, struct cnode *want)
{
	struct cnode *now = NULL, *back = NULL;
	int ret = -1;

	if (apply(was, want) == -1 || (now = running_tree()) == NULL)
		goto done;
	if (differ(NULL, now, want) == 0) {
		ret = 0;
		goto done;
	}
	printf("%% Commit failed: the running configuration differs from "
	    "the candidate\n");
	differ(stdout, now, want);
	conftree_free(now);
	if ((now = running_tree()) == NULL || apply(now, was) == -1 ||
	    (back = running_tree()) == NULL)
		goto done;
	if (differ(NULL, back, was) == 0)
		printf("%% The running configuration is as it was\n");
	else {
		printf("%% The running configuration differs from how it "
		    "was\n");
		differ(stdout, back, was);
	}
done:
	conftree_free(back);
	conftree_free(now);
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
	    apply(now, back) == 0) &&
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

/* Make the running configuration, from, read as to */
static int
apply(struct cnode *from, struct cnode *to)
{
	struct commit *c;
	char path[] = "/tmp/nshcommit.XXXXXXXX";
	int fd, i, save, rt, ret = -1;

	if ((c = calloc(1, sizeof(*c))) == NULL) {
		printf("%% commit: %s\n", strerror(errno));
		return -1;
	}
	c->from = from;
	c->to = to;
	if ((fd = mkstemp(path)) == -1) {
		printf("%% mkstemp %s: %s\n", path, strerror(errno));
		free(c);
		return -1;
	}
	if ((c->f = fdopen(fd, "w")) == NULL) {
		printf("%% commit: %s\n", strerror(errno));
		close(fd);
		goto done;
	}
	if (removals(c, NULL, NULL, 1, "") == -1 ||
	    additions(c, NULL, NULL, 1, "") == -1) {
		fclose(c->f);
		goto done;
	}
	if (fclose(c->f) == EOF) {
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
	for (i = 0; i < c->nclears; i++)
		if (c->clears[i].keep)
			ctl_rules_clear(c->clears[i].name, c->clears[i].rtable,
			    1);
	save = candidate;
	candidate = 0;
	cmdrc(path);
	candidate = save;
	/* and none once it stopped the daemon */
	for (i = 0; i < c->nclears; i++)
		if (!c->clears[i].keep)
			ctl_rules_clear(c->clears[i].name, c->clears[i].rtable,
			    0);
	if (cli_rtable != rt && nsh_setrtable(rt) == 0)
		cli_rtable = rt;
	ret = 0;
done:
	unlink(path);
	free(c);
	return ret;
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
		} else if (t == NULL && unset(c, tblock, there,
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
	if (c->nclears == MAXCLEARS) {
		printf("%% commit: too many daemon rules to clear\n");
		return -1;
	}
	strlcpy(c->clears[c->nclears].name, name,
	    sizeof(c->clears[c->nclears].name));
	c->clears[c->nclears].rtable = rtable;
	c->clears[c->nclears++].keep = keep;
	return 0;
}

/*
 * Keep the configuration just saved as rollback 0, each kept before it
 * one further on, and the oldest no more; unless rollback 0 is the same
 */
static void
history(void)
{
	char from[PATH_MAX], to[PATH_MAX];
	int i;

	snprintf(to, sizeof(to), ROLLBACK, 0);
	if (samefile(NSHRC_TEMP, to))
		return;
	if (mkdir(NSHDB, 0700) == -1 && errno != EEXIST) {
		printf("%% mkdir %s: %s\n", NSHDB, strerror(errno));
		return;
	}
	for (i = ROLLBACKS - 1; i > 0; i--) {
		snprintf(from, sizeof(from), ROLLBACK, i - 1);
		snprintf(to, sizeof(to), ROLLBACK, i);
		if (rename(from, to) == -1 && errno != ENOENT) {
			printf("%% rename %s: %s\n", from, strerror(errno));
			return;
		}
	}
	snprintf(to, sizeof(to), ROLLBACK, 0);
	copyfile(NSHRC_TEMP, to);
}

/* Do the files a and b hold the same? */
static int
samefile(char *a, char *b)
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

/* Copy file from to to, made 0600, or none of it; -1 if it cannot */
static int
copyfile(char *from, char *to)
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
 * show rollback [N]: when each configuration kept was saved, or
 * configuration N
 */
int
pr_rollback(int argc, char **argv, ...)
{
	char path[PATH_MAX], when[64], line[BUFSIZ];
	struct stat sb;
	const char *errstr;
	va_list ap;
	FILE *out, *f;
	int i, n;

	va_start(ap, argv);
	out = va_arg(ap, FILE *);
	va_end(ap);

	if (priv != 1) {
		printf("%% Privilege required\n");
		return 0;
	}
	if (argc == 3) {
		n = strtonum(argv[2], 0, ROLLBACKS - 1, &errstr);
		if (errstr != NULL) {
			printf("%% rollback %s is %s\n", argv[2], errstr);
			return 0;
		}
		snprintf(path, sizeof(path), ROLLBACK, n);
		if ((f = fopen(path, "r")) == NULL) {
			printf("%% rollback %d: %s\n", n, strerror(errno));
			return 0;
		}
		while (fgets(line, sizeof(line), f) != NULL)
			fputs(line, out);
		fclose(f);
		return 0;
	}
	for (i = 0; i < ROLLBACKS; i++) {
		snprintf(path, sizeof(path), ROLLBACK, i);
		if (stat(path, &sb) == -1)
			continue;
		strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S %Z",
		    localtime(&sb.st_mtime));
		fprintf(out, "%2d  %s\n", i, when);
	}
	return 0;
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
