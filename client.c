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
 * nsh as a client of nshd(8). nsh holds a session of nshd's, on its
 * read-write socket, which root and the group nshadmin may use; nshd
 * gives the session the permissions of its user's login class, and
 * refuses what they do not allow. nsh opens the session as it starts,
 * and again when a command needs it after it was lost. An interrupt
 * while nshd answers closes it, and so does nshd exiting. nsh's other
 * connections to nshd, such as shows of what only nshd's system reads,
 * are sessions of their own, with the same permissions. Where nshd does
 * not run, or the user may not use its socket, nsh is not privileged.
 * nsh checks the permissions a program needs itself (nshd_runs()), and
 * runs none for anyone but root without nshd's answer.
 *
 * configure private, configure and configure exclusive run in that
 * session. Commands that edit the candidate or leave a mode go to nshd
 * as lines, and nsh takes the mode nshd gives back for its prompt, its
 * completion and the lines after (cmdline_nshd()). A daemon's edit
 * asks nshd for its rules, edits them here, as the user, and sends them
 * back whole.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "stringlist.h"
#include "externs.h"
#include "facts.h"
#include "showfacts.h"
#include "nshd/nshd.h"

#if NSHD_CPRIVATE != NSHD_PRIVATE || NSHD_CSHARED != NSHD_SHARED || \
    NSHD_CEXCLUSIVE != NSHD_EXCLUSIVE || NSHD_CTERMINAL != NSHD_TERMINAL
#error "externs.h's configures are not nshd.h's"
#endif

static volatile sig_atomic_t	nshd_intr;	/* ^C, while nshd answers */

int		nshd_config;	/* the configure nshd has, or 0 */
int		nshd_rtable;	/* and the rtable its lines are for */

/* nsh's session, or -1 */
static int		sfd = -1;
static struct imsgbuf	sib;

static int	nshd_next(struct imsgbuf *, struct imsg *, const sigset_t *);
static int	nshd_open(char *, struct imsgbuf *, int32_t *);
static int	nshd_has(int, int);
static int	nshd_ask(int, uint32_t, const void *, size_t, struct facts_in *,
		    int32_t *);
static void	nshd_sigint(int);
static int	nshd_request(uint32_t, const void *, size_t, FILE *);
static void	nshd_context(struct nshd_context *);
static void	nshd_close(void);

/*
 * The next message, read as it comes; -1 if nshd is gone. If waiting is
 * not NULL, wait with that signal mask, and return -1 too if SIGINT ends
 * the wait.
 */
static int
nshd_next(struct imsgbuf *ib, struct imsg *imsg, const sigset_t *waiting)
{
	struct pollfd	 pfd;
	int		 n;

	for (;;) {
		if ((n = imsgbuf_get(ib, imsg)) != 0)
			return (n == 1 ? 0 : -1);
		if (waiting != NULL) {
			pfd.fd = ib->fd;
			pfd.events = POLLIN;
			if (ppoll(&pfd, 1, NULL, waiting) == -1) {
				if (errno == EINTR && !nshd_intr)
					continue;
				return (-1);
			}
		}
		if (imsgbuf_read(ib) != 1)
			return (-1);
	}
}

static void
nshd_sigint(int sig)
{
	nshd_intr = 1;
}

/*
 * A session on nshd's socket at path, with its permissions in *perms if
 * perms is not NULL: its descriptor, or -1 with errno set, EPROTO if
 * nshd answered something else.
 */
static int
nshd_open(char *path, struct imsgbuf *ib, int32_t *perms)
{
	struct sockaddr_un	 sun;
	struct nshd_hello	 hello;
	struct nshd_session	 s;
	struct imsg		 imsg;
	int			 fd, saved;

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
		return (-1);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		close(fd);
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1 ||
	    imsgbuf_init(ib, fd) == -1) {
		saved = errno;
		close(fd);
		errno = saved;
		return (-1);
	}

	hello.version = NSHD_VERSION;
	if (imsg_compose(ib, IMSG_CTL_HELLO, 0, 0, -1, &hello,
	    sizeof(hello)) == -1 || imsgbuf_flush(ib) == -1 ||
	    nshd_next(ib, &imsg, NULL) == -1) {
		imsgbuf_clear(ib);
		close(fd);
		errno = EPROTO;
		return (-1);
	}
	if (imsg_get_type(&imsg) != IMSG_CTL_HELLO ||
	    imsg_get_data(&imsg, &s, sizeof(s)) == -1 ||
	    s.version != NSHD_VERSION) {
		imsg_free(&imsg);
		imsgbuf_clear(ib);
		close(fd);
		errno = EPROTO;
		return (-1);
	}
	imsg_free(&imsg);
	if (perms != NULL)
		*perms = s.perms;
	return (fd);
}

/* Why nshd_open() failed */
void
nshd_why(void)
{
	if (errno == ENOENT || errno == ECONNREFUSED)
		printf("%% nshd is not running here\n");
	else if (errno == EACCES)
		printf("%% nshd: only root and the group %s may use it\n",
		    NSHD_GROUP);
	else if (errno == EPROTO)
		printf("%% nshd: not a version nsh speaks\n");
	else
		printf("%% nshd: %s\n", strerror(errno));
}

/*
 * Does the user's login class have the permission need?  1 if it does,
 * or the user is root, else 0, after saying why if why is set
 */
static int
nshd_has(int need, int why)
{
	struct imsgbuf	 ib;
	int32_t		 perms;
	int		 fd;

	if (getuid() == 0)
		return (1);
	if ((fd = nshd_open(NSHD_SOCKET, &ib, &perms)) == -1) {
		if (why)
			nshd_why();
		return (0);
	}
	imsgbuf_clear(&ib);
	close(fd);
	if (perms != -1 && (perms & need) != 0)
		return (1);
	if (why)
		printf("%% Not allowed: your login class does not have the %s "
		    "permission\n", need == NSHD_EXEC ? "exec" : "operate");
	return (0);
}

/*
 * May nsh run the program cmd, as the user's login class says: ping and
 * traceroute need operate, clear nothing, and any other exec. root may
 * run any. 1 if it may, else 0 after saying why
 */
int
nshd_runs(const char *cmd)
{
	static const struct {
		const char	*path;
		int		 need;
	} progs[] = {
		{ PING,		NSHD_OPERATE },
		{ PING6,	NSHD_OPERATE },
		{ TRACERT,	NSHD_OPERATE },
		{ TRACERT6,	NSHD_OPERATE },
		{ CLEAR,	0 },
	};
	size_t		 i;
	int		 need = NSHD_EXEC;

	for (i = 0; i < nitems(progs); i++)
		if (strcmp(cmd, progs[i].path) == 0)
			need = progs[i].need;
	if (need == 0)
		return (1);
	return (nshd_has(need, 1));
}

/*
 * May the user run programs, as the line editor's vi-histedit runs vi?
 * Prints nothing
 */
int
nshd_execs(void)
{
	return (nshd_has(NSHD_EXEC, 0));
}

/*
 * show words, as nshd answers them on its read-write socket, paged: 1 if
 * the show was answered, else 0 after saying why
 */
int
nshd_show(char *words)
{
	struct nshd_show	 show;
	struct nshd_result	 r = { 0 };
	struct imsgbuf		 ib;
	struct imsg		 imsg;
	struct ibuf		 b;
	char			 path[] = "/tmp/nshd.XXXXXXXXXX";
	FILE			*f = NULL;
	int			 fd, out = -1, done = 0, ret = 0;

	if ((fd = nshd_open(NSHD_SOCKET, &ib, NULL)) == -1) {
		nshd_why();
		return (0);
	}

	memset(&show, 0, sizeof(show));
	if (strlcpy(show.words, words, sizeof(show.words)) >=
	    sizeof(show.words)) {
		printf("%% show %s: too long\n", words);
		goto done;
	}
	if ((out = mkstemp(path)) == -1) {
		printf("%% %s: %s\n", path, strerror(errno));
		goto done;
	}
	if ((f = fdopen(out, "w")) == NULL) {
		printf("%% %s: %s\n", path, strerror(errno));
		close(out);
		goto done;
	}

	if (imsg_compose(&ib, IMSG_CTL_SHOW, 0, 0, -1, &show,
	    sizeof(show)) == -1 || imsgbuf_flush(&ib) == -1) {
		printf("%% nshd: %s\n", strerror(errno));
		goto done;
	}
	while (!done) {
		if (nshd_next(&ib, &imsg, NULL) == -1) {
			printf("%% nshd: gone before it answered\n");
			goto done;
		}
		switch (imsg_get_type(&imsg)) {
		case IMSG_CTL_OUTPUT:
			if (imsg_get_ibuf(&imsg, &b) == -1 ||
			    fwrite(ibuf_data(&b), 1, ibuf_size(&b), f) !=
			    ibuf_size(&b)) {
				printf("%% %s: %s\n", path, strerror(errno));
				imsg_free(&imsg);
				goto done;
			}
			break;
		case IMSG_CTL_RESULT:
			if (imsg_get_data(&imsg, &r, sizeof(r)) == -1) {
				printf("%% nshd: a result nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			done = 1;
			break;
		default:
			printf("%% nshd: a message nsh does not know\n");
			imsg_free(&imsg);
			goto done;
		}
		imsg_free(&imsg);
	}

	if (fclose(f) == EOF) {
		f = NULL;
		printf("%% %s: %s\n", path, strerror(errno));
		goto done;
	}
	f = NULL;
	more(path);
	ret = r.status == 0;
done:
	if (f != NULL)
		fclose(f);
	if (out != -1)
		unlink(path);
	imsgbuf_clear(&ib);
	close(fd);
	return (ret);
}

/*
 * A request of type, with len bytes of data, on a connection of its
 * own, to nshd's read-write socket if rw, else to its read-only one.
 * Facts are read into in and text printed as they come, and how it
 * ended goes in *status, or 1 if it was not answered, as when ^C ends
 * it; ^C closes the connection, so nshd stops what it runs. A watch nshd
 * takes goes on after its answer, each log's text printed as it comes,
 * until ^C or nshd says the log ended. -1 if nsh could not connect to
 * nshd, else 0.
 */
static int
nshd_ask(int rw, uint32_t type, const void *data, size_t len,
    struct facts_in *in, int32_t *status)
{
	struct nshd_result	 r = { 1 };
	struct nshd_notice	 nt;
	struct imsgbuf		 ib;
	struct imsg		 imsg;
	struct ibuf		 b;
	struct sigaction	 sa, osa;
	sigset_t		 block, saved, waiting;
	int			 fd, done = 0;

	*status = 1;
	if ((fd = nshd_open(rw ? NSHD_SOCKET : NSHD_RO_SOCKET, &ib,
	    NULL)) == -1) {
		if (errno != EPROTO)
			return (-1);
		printf("%% nshd: not a version nsh speaks\n");
		return (0);
	}

	/* ^C is taken only while waiting for nshd, so none is missed */
	sigemptyset(&block);
	sigaddset(&block, SIGINT);
	sigprocmask(SIG_BLOCK, &block, &saved);
	waiting = saved;
	sigdelset(&waiting, SIGINT);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = nshd_sigint;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, &osa);
	nshd_intr = 0;

	if (imsg_compose(&ib, type, 0, 0, -1, data, len) == -1 ||
	    imsgbuf_flush(&ib) == -1) {
		printf("%% nshd: %s\n", strerror(errno));
		goto done;
	}
	while (!done) {
		if (nshd_next(&ib, &imsg, &waiting) == -1) {
			if (nshd_intr)
				putchar('\n');
			else
				printf("%% nshd: gone before it answered\n");
			goto done;
		}
		switch (imsg_get_type(&imsg)) {
		case IMSG_CTL_OUTPUT:
			if (imsg_get_ibuf(&imsg, &b) == -1) {
				printf("%% nshd: output nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			fwrite(ibuf_data(&b), 1, ibuf_size(&b), stdout);
			break;
		case IMSG_CTL_FACTS:
			if (in == NULL || imsg_get_ibuf(&imsg, &b) == -1 ||
			    facts_read(in, ibuf_data(&b), ibuf_size(&b)) ==
			    -1) {
				printf("%% nshd: facts nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			break;
		case IMSG_CTL_RESULT:
			if (imsg_get_data(&imsg, &r, sizeof(r)) == -1) {
				printf("%% nshd: a result nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			*status = r.status;
			/* an accepted watch continues */
			done = type != IMSG_CTL_WATCH || r.status != 0;
			break;
		case IMSG_CTL_NOTICE:
			if (imsg_get_ibuf(&imsg, &b) == -1 ||
			    ibuf_get(&b, &nt, sizeof(nt)) == -1) {
				printf("%% nshd: a notice nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			if (nt.kind == NSHD_NOTICE_LOG) {
				fwrite(ibuf_data(&b), 1, ibuf_size(&b), stdout);
				fflush(stdout);
			} else if (nt.kind == NSHD_NOTICE_LOGEND)
				done = 1;
			break;
		default:
			printf("%% nshd: a message nsh does not know\n");
			imsg_free(&imsg);
			goto done;
		}
		imsg_free(&imsg);
	}
done:
	imsgbuf_clear(&ib);
	close(fd);
	/* a ^C pending now ends nothing */
	sigprocmask(SIG_SETMASK, &saved, NULL);
	sigaction(SIGINT, &osa, NULL);
	return (0);
}

/*
 * show words, as nshd answers them through nshd_ask(): on the read-write
 * socket, where its system answers, if rw, else on the read-only socket,
 * where its show processes do. -1 if nsh could not connect to nshd,
 * else 1 if the show was answered and 0 if not.
 */
int
nshd_facts(int rw, char *words, struct facts_in *in)
{
	struct nshd_show	 show;
	int32_t			 status;

	memset(&show, 0, sizeof(show));
	if (strlcpy(show.words, words, sizeof(show.words)) >=
	    sizeof(show.words)) {
		printf("%% show %s: too long\n", words);
		return (0);
	}
	if (nshd_ask(rw, IMSG_CTL_SHOW, &show, sizeof(show), in,
	    &status) == -1)
		return (-1);
	return (status == 0);
}

/*
 * show log name: the log nshd's system follows, printed from its last
 * lines as it comes, until ^C, through nshd_ask()
 */
int
show_log(int argc, char **argv, ...)
{
	static const struct {
		const char	*name;
		int32_t		 log;
	} logs[] = {
		{ "daemon",	NSHD_WATCH_DAEMON },
		{ "messages",	NSHD_WATCH_MESSAGES },
		{ "authlog",	NSHD_WATCH_AUTHLOG },
		{ "pflog",	NSHD_WATCH_PFLOG },
	};
	struct nshd_watch	 w = { 0 };
	int32_t			 status;
	size_t			 i;

	for (i = 0; i < sizeof(logs) / sizeof(logs[0]); i++)
		if (strcmp(argv[2], logs[i].name) == 0)
			w.what = logs[i].log;
	if (w.what == 0) {
		printf("%% show log: daemon, messages, authlog or pflog\n");
		return (-1);
	}
	printf("%% Following %s, until ^C\n", argv[2]);
	if (nshd_ask(1, IMSG_CTL_WATCH, &w, sizeof(w), NULL, &status) ==
	    -1) {
		nshd_why();
		return (-1);
	}
	return (status == 0 ? 0 : -1);
}

/*
 * The operation text, in rtable, which nshd's system runs through
 * nshd_ask(), with facts read into in: its status, or 1 if it was not
 * answered, after saying why
 */
int
nshd_op(const char *text, int rtable, struct facts_in *in)
{
	struct nshd_op	 op;
	int32_t		 status;

	memset(&op, 0, sizeof(op));
	op.rtable = rtable;
	if (strlcpy(op.line, text, sizeof(op.line)) >= sizeof(op.line)) {
		printf("%% Input exceeds permitted length\n");
		return (1);
	}
	if (nshd_ask(1, IMSG_CTL_OP, &op, sizeof(op), in, &status) == -1) {
		nshd_why();
		return (1);
	}
	return (status);
}

/*
 * nsh's session, opened if it is not: 1 if nsh has one, and so is
 * privileged, else 0, after saying why unless quiet
 */
int
nshd_priv(int quiet)
{
	if (sfd != -1)
		return (1);
	if ((sfd = nshd_open(NSHD_SOCKET, &sib, NULL)) == -1) {
		if (!quiet)
			nshd_why();
		return (0);
	}
	priv = 1;
	return (1);
}

/* enter configure mode how in nsh's session; returns as a handler does */
int
nshd_configure(int how)
{
	struct nshd_configure	 cf;

	cf.mode = how;
	return (nshd_request(IMSG_CTL_CONFIGURE, &cf, sizeof(cf), NULL));
}

/* A configuration line, sent to nshd in the session's mode */
int
nshd_line(char *text)
{
	struct nshd_line	 l;

	memset(&l, 0, sizeof(l));
	if (strlcpy(l.line, text, sizeof(l.line)) >= sizeof(l.line)) {
		printf("%% Input exceeds permitted length\n");
		return (-1);
	}
	return (nshd_request(IMSG_CTL_LINE, &l, sizeof(l), NULL));
}

/* Leave configure, from any of its modes */
int
nshd_exit(void)
{
	return (nshd_request(IMSG_CTL_EXIT, NULL, 0, NULL));
}

/* commit, commit check, or commit confirmed for minutes, with the comment */
int
nshd_commit(int check, int minutes, char *comment)
{
	struct nshd_commit	 c;

	memset(&c, 0, sizeof(c));
	c.check = check;
	c.minutes = minutes;
	strlcpy(c.comment, comment, sizeof(c.comment));
	return (nshd_request(IMSG_CTL_COMMIT, &c, sizeof(c), NULL));
}

/*
 * nsh -c: path's configuration, which nshd loads into a candidate of its
 * own, in place of the running configuration, and commits; as a handler
 * returns
 */
int
nshd_load(const char *path)
{
	struct nshd_load	 l;
	FILE			*f;
	int			 r;

	if ((f = fopen(path, "r")) == NULL) {
		printf("%% Unable to open %s: %s\n", path, strerror(errno));
		return (-1);
	}
	memset(&l, 0, sizeof(l));
	snprintf(l.comment, sizeof(l.comment), "nsh -c %s", path);
	do {
		l.len = fread(l.text, 1, sizeof(l.text), f);
		if (ferror(f)) {
			printf("%% %s: %s\n", path, strerror(errno));
			r = -1;
			break;
		}
		l.last = feof(f) != 0;
		r = nshd_request(IMSG_CTL_LOAD, &l, sizeof(l), NULL);
	} while (r == 0 && !l.last);
	fclose(f);
	return (r);
}

/* rollback n */
int
nshd_rollback(int n)
{
	struct nshd_rollback	 rb;

	rb.n = n;
	return (nshd_request(IMSG_CTL_ROLLBACK, &rb, sizeof(rb), NULL));
}

/* the name of the session's configure mode */
const char *
nshd_cname(void)
{
	return (nshd_config == NSHD_PRIVATE ? "configure private" :
	    nshd_config == NSHD_EXCLUSIVE ? "configure exclusive" :
	    nshd_config == NSHD_TERMINAL ? "configure terminal" :
	    "configure");
}

/* show words in configure, candidate-config or diff-config, paged */
int
nshd_cshow(char *words)
{
	struct nshd_show	 show;
	char			 path[] = "/tmp/nshd.XXXXXXXXXX";
	FILE			*f;
	int			 fd, r;

	if ((fd = mkstemp(path)) == -1 || (f = fdopen(fd, "w")) == NULL) {
		printf("%% %s: %s\n", path, strerror(errno));
		if (fd != -1) {
			unlink(path);
			close(fd);
		}
		return (-1);
	}
	memset(&show, 0, sizeof(show));
	strlcpy(show.words, words, sizeof(show.words));
	r = nshd_request(IMSG_CTL_SHOW, &show, sizeof(show), f);
	if (fclose(f) == EOF)
		printf("%% %s: %s\n", path, strerror(errno));
	else if (sfd != -1)	/* unless the session was lost */
		more(path);
	unlink(path);
	return (r);
}

/*
 * daemon's rules for rtable in the session's candidate, read into path;
 * or, with set, path's text sent as the new rules, a part at a time. As
 * a handler returns
 */
int
nshd_rules(char *daemon, int rtable, int set, char *path)
{
	struct nshd_rules	 rl;
	FILE			*f;
	int			 c, r;

	if ((f = fopen(path, set ? "r" : "w+")) == NULL) {
		printf("%% %s: %s\n", path, strerror(errno));
		return (-1);
	}
	memset(&rl, 0, sizeof(rl));
	rl.set = set;
	rl.rtable = rtable;
	strlcpy(rl.daemon, daemon, sizeof(rl.daemon));
	if (!set) {
		rl.last = 1;
		/* what nshd said, not rules, if it failed */
		if ((r = nshd_request(IMSG_CTL_RULES, &rl, sizeof(rl), f)) ==
		    -1 && fseek(f, 0, SEEK_SET) == 0)
			while ((c = getc(f)) != EOF)
				putchar(c);
	} else
		do {
			rl.len = fread(rl.text, 1, sizeof(rl.text), f);
			if (ferror(f)) {
				printf("%% %s: %s\n", path, strerror(errno));
				r = -1;
				break;
			}
			rl.last = feof(f) != 0;
			r = nshd_request(IMSG_CTL_RULES, &rl, sizeof(rl), NULL);
		} while (r == 0 && !rl.last);
	if (fclose(f) == EOF) {
		printf("%% %s: %s\n", path, strerror(errno));
		r = -1;
	}
	return (r);
}

/*
 * A request of type, with len bytes of data, on nsh's session, opened if
 * it is not: what nshd prints goes to out or stdout, nsh takes the mode
 * nshd gives, and it returns as a handler does. ^C closes the session,
 * while nshd finishes what it was asked.
 */
static int
nshd_request(uint32_t type, const void *data, size_t len, FILE *out)
{
	struct nshd_context	 c;
	struct nshd_result	 r = { -1 };
	struct imsg		 imsg;
	struct ibuf		 b;
	struct sigaction	 sa, osa, opipe;
	sigset_t		 block, saved, waiting;
	FILE			*f = out != NULL ? out : stdout;
	int			 done = 0, gone = 1;

	if (!nshd_priv(0))
		return (-1);

	/* ^C is taken only while waiting for nshd, so none is missed */
	sigemptyset(&block);
	sigaddset(&block, SIGINT);
	sigprocmask(SIG_BLOCK, &block, &saved);
	waiting = saved;
	sigdelset(&waiting, SIGINT);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = nshd_sigint;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, &osa);
	/* report a lost session instead of dying of SIGPIPE */
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, &opipe);
	nshd_intr = 0;

	if (imsg_compose(&sib, type, 0, 0, -1, data, len) == -1 ||
	    imsgbuf_flush(&sib) == -1) {
		if (errno == EPIPE)
			printf("%% nshd: the session is gone; asking again "
			    "opens another\n");
		else
			printf("%% nshd: %s\n", strerror(errno));
		goto done;
	}
	while (!done) {
		if (nshd_next(&sib, &imsg, &waiting) == -1) {
			if (nshd_intr)
				printf("\n%% Interrupted: every mode is left, "
				    "and nshd finishes what it was asked\n");
			else
				printf("%% nshd: gone before it answered\n");
			goto done;
		}
		switch (imsg_get_type(&imsg)) {
		case IMSG_CTL_OUTPUT:
			if (imsg_get_ibuf(&imsg, &b) == -1) {
				printf("%% nshd: output nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			fwrite(ibuf_data(&b), 1, ibuf_size(&b), f);
			break;
		case IMSG_CTL_CONTEXT:
			if (imsg_get_data(&imsg, &c, sizeof(c)) == -1 ||
			    memchr(c.ifname, '\0', sizeof(c.ifname)) == NULL) {
				printf("%% nshd: a mode nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			nshd_context(&c);
			break;
		case IMSG_CTL_RESULT:
			if (imsg_get_data(&imsg, &r, sizeof(r)) == -1) {
				printf("%% nshd: a result nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			done = 1;
			break;
		default:
			printf("%% nshd: a message nsh does not know\n");
			imsg_free(&imsg);
			goto done;
		}
		imsg_free(&imsg);
	}
	gone = 0;
done:
	/* a session nshd closed, or one nsh cannot follow */
	if (gone)
		nshd_close();
	/* a ^C pending now ends nothing */
	sigprocmask(SIG_SETMASK, &saved, NULL);
	sigaction(SIGINT, &osa, NULL);
	sigaction(SIGPIPE, &opipe, NULL);
	return (gone || r.status != 0 ? -1 : 0);
}

/* Set nsh's mode to the session's, as nshd gives it */
static void
nshd_context(struct nshd_context *c)
{
	nshd_config = c->mode >= NSHD_PRIVATE && c->mode <= NSHD_TERMINAL ?
	    c->mode : 0;
	nshd_rtable = nshd_config ? c->rtable : 0;
	nshd_mode(nshd_config != 0, c->ifname, c->bridge);
}

/* nsh's session gone, and every mode with it */
static void
nshd_close(void)
{
	if (sfd == -1)
		return;
	nshd_config = 0;
	nshd_rtable = 0;
	nshd_mode(0, "", 0);
	imsgbuf_clear(&sib);
	close(sfd);
	sfd = -1;
	priv = 0;
}
