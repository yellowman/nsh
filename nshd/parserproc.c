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
 * The parser reads configuration text for system, so that system need
 * not. system runs a new one for each reading, in a job, or from a
 * job's child: this program again, with -P, which becomes
 * NSHD_PARSE_USER in a chroot(2) and pledges only stdio before it reads
 * anything. Its standard input holds the request, struct nshd_parse,
 * and the texts after it. What it prints on its standard output goes
 * to the session, or to the log; what it answers, it writes to
 * descriptor 3. It exits 0 or 1, as the kind says, or 2 if it could not
 * read. It keeps nothing: the next reading is another process.
 *
 * It reads whether one configuration reads as another, the login lines
 * one holds, the script that makes one read as another, the boot's
 * plan, and how two differ. And it checks what a session without admin
 * commits, against the running configuration (ctl.c's and passwd.c's
 * admin checks). As nshd starts, it reads the head lines of the records
 * system keeps.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "externs.h"
#include "facts.h"
#include "kfacts.h"
#include "session.h"

#define PARSE_FD	3	/* the parser's answer */

static int	parser_read(void *, size_t);
static int	parser_write(const void *, size_t);
static int	parse_begin(struct nshd_parse *, char **);
static int	parse_back(struct nshd_parse *, char **);
static int	parse_plan(struct nshd_parse *, char **);
static int	parse_boot(struct nshd_parse *, char **);
static int	parse_facts(char *, size_t);
static int	parse_records(struct nshd_parse *, char **);
static void	parse_commit(char *, size_t, struct nshd_records *);
static void	parse_confirm(char *, size_t, struct nshd_records *);
static void	parse_bootrecord(char *, struct nshd_records *);
static void	parse_clears(struct nshd_apply *, struct script *);

static char	 parser_path[PATH_MAX];	/* this program, as system ran it */
static int	 parser_debug, parser_verbose;

/* d and v as child_start() takes them: nsh's externs.h has a verbose */
__dead void
parserproc(int d, int v)
{
	struct nshd_parse	 p;
	char			*t[NSHD_PARSE_TEXTS];
	int			 i, r;

	log_init(d, LOG_DAEMON);
	log_setverbose(v);
	log_procinit("parser");
	setproctitle("parser");
	privdrop(PROC_PARSER);
	if (pledge("stdio", NULL) == -1)
		fatal("pledge");

	memset(t, 0, sizeof(t));
	if (parser_read(&p, sizeof(p)) == -1 ||
	    p.apply.nclears < 0 || p.apply.nclears > NSHD_CLEARS)
		goto unread;
	for (i = 0; i < NSHD_PARSE_TEXTS; i++) {
		if (p.len[i] > NSHD_PART ||
		    (t[i] = malloc(p.len[i] + 1)) == NULL ||
		    parser_read(t[i], p.len[i]) == -1)
			goto unread;
		t[i][p.len[i]] = '\0';
	}
	p.daemon[sizeof(p.daemon) - 1] = '\0';

	switch (p.kind) {
	case NSHD_PARSE_RULES:
		admin_begin(1, t[0], p.len[0]);
		r = admin_test(p.daemon, t[1], p.len[1]) == 0 ? 0 : 1;
		break;
	case NSHD_PARSE_BEGIN:
		r = parse_begin(&p, t);
		break;
	case NSHD_PARSE_BACK:
		r = parse_back(&p, t);
		break;
	case NSHD_PARSE_VERIFY:
		r = commit_verify(t[0], p.len[0], t[1], p.len[1],
		    (p.flags & NSHD_PARSE_FAILED) != 0,
		    (p.flags & NSHD_PARSE_BOOTS) != 0);
		break;
	case NSHD_PARSE_PLAN:
		r = parse_plan(&p, t);
		break;
	case NSHD_PARSE_UNDONE:
		r = commit_undone(t[0], p.len[0], t[1], p.len[1]);
		break;
	case NSHD_PARSE_BOOT:
		r = parse_boot(&p, t);
		break;
	case NSHD_PARSE_DIFF:
		r = commit_diff(t[0], p.len[0], t[1], p.len[1], t[2],
		    (p.flags & NSHD_PARSE_HIDE) != 0,
		    (p.flags & NSHD_PARSE_QUIET) != 0);
		break;
	case NSHD_PARSE_RECORDS:
		r = parse_records(&p, t);
		break;
	default:
		printf("%% nshd: the parser reads no kind %d\n", p.kind);
		r = -1;
	}
	fflush(stdout);
	_exit(r == -1 ? 2 : r);
 unread:
	printf("%% nshd: the parser could not read what to read\n");
	fflush(stdout);
	_exit(2);
}

/*
 * BEGIN: whether now reads as what the commit is based on, whether it
 * changes login users or classes, how a record's configurations read,
 * and, with NSHD_PARSE_ADMIN, whether its script may run. Then the
 * login lines it wants, for system to see who would lose a permission
 */
static int
parse_begin(struct nshd_parse *p, char **t)
{
	struct nshd_began	 b;
	struct login_line	*l = NULL;
	struct script		 sc;
	int			 r = -1;

	memset(&b, 0, sizeof(b));
	b.admin = 1;
	if ((b.based = commit_reads(t[0], p->len[0], t[1], p->len[1])) == -1 ||
	    (b.logins = commit_logins(t[0], p->len[0], t[2],
	    p->len[2])) == -1)
		return -1;
	if ((p->flags & NSHD_PARSE_RECORD) &&
	    ((b.none = commit_reads(t[0], p->len[0], t[3], p->len[3])) == -1 ||
	    (b.wanted = commit_reads(t[0], p->len[0], t[4], p->len[4])) == -1 ||
	    (b.back = commit_reads(t[3], p->len[3], t[2], p->len[2])) == -1))
		return -1;
	/* what is refused already, the parser need not check */
	if (b.based && (p->flags & NSHD_PARSE_ADMIN)) {
		memset(&sc, 0, sizeof(sc));
		sc.edits = t[5];
		sc.elen = p->len[5];
		parse_clears(&p->apply, &sc);
		admin_begin(1, t[0], p->len[0]);
		b.admin = edits_admin(&sc) == 0;
	}
	/* those it wants, which login_perms_by() reads */
	if (b.logins && login_lines(t[2], p->len[2], NSHD_LOGINS, &l,
	    &b.nlogins) == -1)
		return -1;
	if (parser_write(&b, sizeof(b)) == 0 &&
	    parser_write(l, b.nlogins * sizeof(*l)) == 0)
		r = 0;
	free(l);
	return r;
}

/* BACK: whether now reads as the rollback's configuration */
static int
parse_back(struct nshd_parse *p, char **t)
{
	struct nshd_back	 b;

	if ((b.there = commit_reads(t[0], p->len[0], t[1], p->len[1])) == -1 ||
	    (b.logins = commit_logins(t[0], p->len[0], t[1],
	    p->len[1])) == -1)
		return -1;
	return parser_write(&b, sizeof(b));
}

/* PLAN: the script that makes now read as what is wanted */
static int
parse_plan(struct nshd_parse *p, char **t)
{
	struct nshd_apply	 a;
	struct script		 sc;
	int			 r = -1, i;

	if (parse_facts(t[2], p->len[2]) == -1 ||
	    commit_plan(t[0], p->len[0], t[1], p->len[1], &sc) == -1)
		return -1;
	memset(&a, 0, sizeof(a));
	for (i = 0; i < sc.nclears; i++) {
		strlcpy(a.clears[i].name, sc.clears[i].name,
		    sizeof(a.clears[i].name));
		a.clears[i].rtable = sc.clears[i].rtable;
		a.clears[i].keep = sc.clears[i].keep;
	}
	a.nclears = sc.nclears;
	if (parser_write(&a, sizeof(a)) == 0 &&
	    parser_write(sc.edits, sc.elen) == 0)
		r = 0;
	script_free(&sc);
	return r;
}

/*
 * BOOT: the boot's plan, from the saved configuration and what runs. What
 * its checks find is printed
 */
static int
parse_boot(struct nshd_parse *p, char **t)
{
	struct nshd_bootplan	 b;
	struct nshd_boottest	 bt;
	struct plan		*pl;
	int			 i, r = -1;

	if (parse_facts(t[2], p->len[2]) == -1 ||
	    session_boot_plan(t[0], p->len[0], t[1], p->len[1], &pl) == -1)
		return -1;
	memset(&b, 0, sizeof(b));
	b.same = pl->same;
	b.ntests = pl->ntests;
	b.elen = pl->len[PLAN_EDITS];
	plan_clears(pl, &b.apply);
	if (parser_write(&b, sizeof(b)) == -1)
		goto done;
	for (i = 0; i < pl->ntests; i++) {
		memset(&bt, 0, sizeof(bt));
		strlcpy(bt.name, pl->tests[i].name, sizeof(bt.name));
		strlcpy(bt.label, pl->tests[i].label, sizeof(bt.label));
		bt.len = pl->tests[i].len;
		if (parser_write(&bt, sizeof(bt)) == -1 ||
		    parser_write(pl->tests[i].text, bt.len) == -1)
			goto done;
	}
	if (parser_write(pl->text[PLAN_EDITS], b.elen) == 0)
		r = 0;
 done:
	plan_free(pl);
	return r;
}

/* the kernel's facts, len bytes, as a snapshot sends them, for checks */
static int
parse_facts(char *buf, size_t len)
{
	struct facts_in	 in;
	struct kfacts	*k;

	if ((k = calloc(1, sizeof(*k))) == NULL) {
		printf("%% nshd: the parser: %s\n", strerror(errno));
		return -1;
	}
	facts_in_init(&in, kfacts_record, k);
	if (facts_read(&in, buf, len) == -1 || k->failed) {
		printf("%% nshd: the parser could not read the kernel's "
		    "facts\n");
		facts_in_free(&in);
		kfacts_free(k);
		return -1;
	}
	facts_in_free(&in);
	kfacts_set(k);
	return 0;
}

/* a's clears, into s */
static void
parse_clears(struct nshd_apply *a, struct script *s)
{
	int	 i;

	for (i = 0; i < a->nclears; i++) {
		a->clears[i].name[sizeof(a->clears[i].name) - 1] = '\0';
		strlcpy(s->clears[i].name, a->clears[i].name,
		    sizeof(s->clears[i].name));
		s->clears[i].rtable = a->clears[i].rtable;
		s->clears[i].keep = a->clears[i].keep;
	}
	s->nclears = a->nclears;
}

/*
 * The head lines of the records system keeps, as system writes them
 * (systemproc.c's record_write() and boot_write(), confirm.c's
 * confirm_write()): t[0] the commit record's first bytes, t[1] the
 * confirm record's and t[2] the boot record's, each there as p's flags
 * say. struct nshd_records, the numbers as each line says them: system
 * judges whether they are a record's
 */
static int
parse_records(struct nshd_parse *p, char **t)
{
	struct nshd_records	 r;

	memset(&r, 0, sizeof(r));
	if (p->flags & NSHD_PARSE_HAS_COMMIT)
		parse_commit(t[0], p->len[0], &r);
	if (p->flags & NSHD_PARSE_HAS_CONFIRM)
		parse_confirm(t[1], p->len[1], &r);
	if (p->flags & NSHD_PARSE_HAS_BOOT)
		parse_bootrecord(t[2], &r);
	return (parser_write(&r, sizeof(r)));
}

/* STATE UID WHEN BEFORELEN WANTLEN, the commit record's, in text */
static void
parse_commit(char *text, size_t len, struct nshd_records *r)
{
	static const char	*states[] = NSHD_RECORD_STATES;
	char			 state[16], *nl;
	unsigned int		 uid;
	long long		 when;
	size_t			 before, want, i;

	if ((nl = memchr(text, '\n', len)) == NULL)
		return;
	*nl = '\0';
	if (sscanf(text, "%15s %u %lld %zu %zu", state, &uid, &when, &before,
	    &want) != 5)
		return;
	for (i = 1; i < sizeof(states) / sizeof(states[0]); i++)
		if (strcmp(state, states[i]) == 0)
			r->commit = i;
	r->uid = uid;
	r->when = when;
	r->beforelen = before;
	r->wantlen = want;
	r->commithead = nl - text + 1;
}

/*
 * STATE ID DEADLINE ATTEMPTS DEMOTED LENGTH, the confirm record's, in
 * text, exactly as NSHD_CONFIRM_FORMAT writes it
 */
static void
parse_confirm(char *text, size_t len, struct nshd_records *r)
{
	static const char	*states[] = NSHD_CONFIRM_STATES;
	char			 state[16], canon[128], *nl;
	unsigned long long	 id;
	long long		 deadline;
	size_t			 back, i;
	int			 attempts, demoted;

	if ((nl = memchr(text, '\n', len)) == NULL)
		return;
	*nl = '\0';
	if (sscanf(text, "%15s %llx %lld %d %d %zu", state, &id, &deadline,
	    &attempts, &demoted, &back) != 6)
		return;
	snprintf(canon, sizeof(canon), NSHD_CONFIRM_FORMAT, state, id,
	    deadline, attempts, demoted, back);
	if (strcmp(canon, text) != 0)
		return;
	for (i = 1; i < sizeof(states) / sizeof(states[0]); i++)
		if (strcmp(state, states[i]) == 0)
			r->confirm = i;
	r->id = id;
	r->deadline = deadline;
	r->attempts = attempts;
	r->demoted = demoted;
	r->backlen = back;
	r->confirmhead = nl - text + 1;
}

/* STATE BOOTTIME DEMOTED, the boot record's, in text */
static void
parse_bootrecord(char *text, struct nshd_records *r)
{
	static const char	*states[] = NSHD_BOOT_STATES;
	char			 state[16];
	long long		 when;
	size_t			 i;
	int			 demoted;

	if (sscanf(text, "%15s %lld %d", state, &when, &demoted) != 3)
		return;
	for (i = 1; i < sizeof(states) / sizeof(states[0]); i++)
		if (strcmp(state, states[i]) == 0)
			r->boot = i;
	r->boottime = when;
	r->bootdemoted = demoted;
}

/* len bytes of standard input into buf: 0, or -1 if it ended first */
static int
parser_read(void *buf, size_t len)
{
	size_t	 got = 0;
	ssize_t	 n;

	while (got < len) {
		if ((n = read(STDIN_FILENO, (char *)buf + got,
		    len - got)) == -1 && errno == EINTR)
			continue;
		if (n <= 0)
			return (-1);
		got += n;
	}
	return (0);
}

/* len bytes of buf, the answer, to descriptor 3: 0, or -1 */
static int
parser_write(const void *buf, size_t len)
{
	size_t	 done = 0;
	ssize_t	 n;

	while (done < len) {
		if ((n = write(PARSE_FD, (const char *)buf + done,
		    len - done)) == -1 && errno == EINTR)
			continue;
		if (n <= 0) {
			printf("%% nshd: the parser's answer: %s\n",
			    strerror(errno));
			return (-1);
		}
		done += n;
	}
	return (0);
}

/*
 * The rest is system's, and its children's: how they run the parser
 */

/* where this program is, and system's -d and -v, for the parser */
void
parser_init(int d, int v)
{
	if (getexecpath(parser_path, sizeof(parser_path)) == -1)
		fatal("getexecpath");
	parser_debug = d;
	parser_verbose = v;
}

/*
 * Become the parser for p, its texts as t gives them, with their
 * lengths in p: a file no other process has, as its standard input,
 * and answer, a file too, as descriptor 3. What it prints goes where
 * this process prints
 */
__dead void
parser_exec(struct nshd_parse *p, char **t, int answer)
{
	char	 path[] = "/tmp/nshparse.XXXXXXXXXX", *argv[5];
	int	 fd, i, argc = 0;

	if ((fd = mkstemp(path)) == -1 || unlink(path) == -1 ||
	    write(fd, p, sizeof(*p)) != sizeof(*p))
		goto fail;
	for (i = 0; i < NSHD_PARSE_TEXTS; i++)
		if (p->len[i] > 0 && write(fd, t[i], p->len[i]) !=
		    (ssize_t)p->len[i])
			goto fail;
	if (lseek(fd, 0, SEEK_SET) == -1 || dup2(fd, STDIN_FILENO) == -1 ||
	    dup2(answer, PARSE_FD) == -1)
		goto fail;
	closefrom(PARSE_FD + 1);
	argv[argc++] = parser_path;
	argv[argc++] = "-P";
	if (parser_debug)
		argv[argc++] = "-d";
	if (parser_verbose)
		argv[argc++] = "-v";
	argv[argc] = NULL;
	fflush(stdout);
	execv(parser_path, argv);
 fail:
	printf("%% nshd: the parser: %s\n", strerror(errno));
	fflush(stdout);
	_exit(2);
}

/*
 * The answer in fd, a file, up to max bytes, into *ap and its length
 * into *lenp: 0, or -1 after saying why
 */
int
parser_answer(int fd, size_t max, char **ap, size_t *lenp)
{
	char	*a = NULL;
	size_t	 len = 0;
	off_t	 end;
	ssize_t	 n;

	*ap = NULL;
	*lenp = 0;
	if ((end = lseek(fd, 0, SEEK_END)) == -1 ||
	    lseek(fd, 0, SEEK_SET) == -1)
		goto bad;
	if ((size_t)end > max) {
		printf("%% nshd: the parser answered past %zu bytes\n", max);
		return (-1);
	}
	if ((a = malloc(end + 1)) == NULL)
		goto bad;
	while (len < (size_t)end) {
		if ((n = read(fd, a + len, end - len)) == -1 && errno == EINTR)
			continue;
		if (n <= 0)
			goto bad;
		len += n;
	}
	*ap = a;
	*lenp = len;
	return (0);
 bad:
	printf("%% nshd: the parser's answer: %s\n", strerror(errno));
	free(a);
	return (-1);
}

/*
 * In a child of system's: the parser for p, its texts as t gives them,
 * and its answer, up to max bytes, into *ap, unless ap is NULL. How it
 * ended: 0 or 1, or -1 after saying why
 */
int
parser_call(struct nshd_parse *p, char **t, size_t max, char **ap,
    size_t *lenp)
{
	char	 path[] = "/tmp/nshanswer.XXXXXXXXXX";
	pid_t	 forked;
	int	 fd, status;

	if ((fd = mkstemp(path)) == -1 || unlink(path) == -1) {
		printf("%% nshd: the parser's answer: %s\n", strerror(errno));
		return (-1);
	}
	fflush(stdout);
	switch (forked = fork()) {
	case -1:
		printf("%% nshd: fork: %s\n", strerror(errno));
		close(fd);
		return (-1);
	case 0:
		parser_exec(p, t, fd);
	}
	while (waitpid(forked, &status, 0) == -1)
		if (errno != EINTR) {
			printf("%% nshd: waitpid: %s\n", strerror(errno));
			close(fd);
			return (-1);
		}
	if (!WIFEXITED(status) || WEXITSTATUS(status) > 1 ||
	    (ap != NULL && parser_answer(fd, max, ap, lenp) == -1)) {
		close(fd);
		return (-1);
	}
	close(fd);
	return (WEXITSTATUS(status));
}

/*
 * In a child of system's: how b, blen bytes, differs from a, block by
 * block, after head, printed, with each password hash hidden if hide: 1
 * if they differ, 0 if not, or -1 after saying why
 */
int
parser_diff(char *a, size_t alen, char *b, size_t blen, char *head,
    int hide)
{
	struct nshd_parse	 p;
	char			*t[NSHD_PARSE_TEXTS] = { a, b, head };

	memset(&p, 0, sizeof(p));
	p.kind = NSHD_PARSE_DIFF;
	p.flags = hide ? NSHD_PARSE_HIDE : 0;
	p.len[0] = alen;
	p.len[1] = blen;
	p.len[2] = strlen(head);
	return (parser_call(&p, t, 0, NULL, NULL));
}
