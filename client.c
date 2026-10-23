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
 * nsh as a client of nshd(8). Privileged mode is a session of nshd's,
 * on its read-write socket, which root or the group nshadmin may use:
 * enable opens it, and nshd takes the enable secret, if there is one,
 * and gives a token, which nsh's other connections there give, as shows
 * do of what only nshd's system reads. Privileged mode ends with the
 * session: disable closes it, and so does an interrupt while nshd
 * answers on it, or nshd going. Where nshd does not run, nsh is not
 * privileged.
 *
 * configure private, configure and configure exclusive are that
 * session's: what edits the candidate, and leaving a mode, go to nshd
 * as lines, and the mode nshd gives back is nsh's, for its prompt, its
 * completion and the lines after (cmdline_nshd()).
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

/* the session privileged mode is, or -1, and its token */
static int		sfd = -1;
static struct imsgbuf	sib;
static uint8_t		token[NSHD_TOKEN];
static int32_t		sstatus;	/* how its last request ended */

static int	nshd_next(struct imsgbuf *, struct imsg *, const sigset_t *);
static int	nshd_open(char *, struct imsgbuf *);
static void	nshd_why(void);
static int	nshd_borrow(struct imsgbuf *, const sigset_t *);
static int	nshd_ask(int, uint32_t, const void *, size_t, struct facts_in *,
		    int32_t *);
static void	nshd_sigint(int);
static int	nshd_request(uint32_t, const void *, size_t, int);
static void	nshd_context(struct nshd_context *);
static void	nshd_close(void);

/*
 * The next message, read as it comes; -1 if nshd is gone. With
 * waiting, the signal mask to wait with, -1 too if SIGINT ends a wait.
 */
static int
nshd_next(struct imsgbuf *ib, struct imsg *imsg, const sigset_t *waiting)
{
	struct pollfd	 pfd;
	ssize_t		 n;

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
 * A session on nshd's socket at path: its descriptor, or -1, with
 * EPROTO for an nshd that said something else.
 */
static int
nshd_open(char *path, struct imsgbuf *ib)
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
	return (fd);
}

/* Why nshd_open() could not */
static void
nshd_why(void)
{
	if (errno == ENOENT || errno == ECONNREFUSED)
		printf("%% nshd is not running here\n");
	else if (errno == EACCES)
		printf("%% nshd: privileged mode is root's, and the group "
		    "%s's\n", NSHD_GROUP);
	else if (errno == EPROTO)
		printf("%% nshd: not a version nsh speaks\n");
	else
		printf("%% nshd: %s\n", strerror(errno));
}

/*
 * A connection to nshd's read-write socket enabled, by the token of
 * privileged mode's session: 0, or -1, said why. With waiting, as
 * nshd_next() waits.
 */
static int
nshd_borrow(struct imsgbuf *ib, const sigset_t *waiting)
{
	struct nshd_enable	 e;
	struct nshd_result	 r;
	struct imsg		 imsg;
	struct ibuf		 b;

	memset(&e, 0, sizeof(e));
	e.how = NSHD_BY_TOKEN;
	memcpy(e.token, token, sizeof(e.token));
	if (imsg_compose(ib, IMSG_CTL_ENABLE, 0, 0, -1, &e,
	    sizeof(e)) == -1 || imsgbuf_flush(ib) == -1) {
		explicit_bzero(&e, sizeof(e));
		printf("%% nshd: %s\n", strerror(errno));
		return (-1);
	}
	explicit_bzero(&e, sizeof(e));
	for (;;) {
		if (nshd_next(ib, &imsg, waiting) == -1) {
			if (nshd_intr)
				putchar('\n');
			else
				printf("%% nshd: gone before it answered\n");
			return (-1);
		}
		switch (imsg_get_type(&imsg)) {
		case IMSG_CTL_OUTPUT:
			if (imsg_get_ibuf(&imsg, &b) == -1) {
				printf("%% nshd: output nsh cannot read\n");
				imsg_free(&imsg);
				return (-1);
			}
			fwrite(ibuf_data(&b), 1, ibuf_size(&b), stdout);
			break;
		case IMSG_CTL_RESULT:
			if (imsg_get_data(&imsg, &r, sizeof(r)) == -1) {
				printf("%% nshd: a result nsh cannot read\n");
				imsg_free(&imsg);
				return (-1);
			}
			imsg_free(&imsg);
			return (r.status == 0 ? 0 : -1);
		default:
			printf("%% nshd: a message nsh does not know\n");
			imsg_free(&imsg);
			return (-1);
		}
		imsg_free(&imsg);
	}
}

/*
 * show words, as nshd answers them, paged, in privileged mode: 1 if the
 * show was answered, else 0, said why
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

	if (sfd == -1) {
		printf("%% Privilege required\n");
		return (0);
	}
	if ((fd = nshd_open(NSHD_SOCKET, &ib)) == -1) {
		nshd_why();
		return (0);
	}
	if (nshd_borrow(&ib, NULL) == -1)
		goto done;

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
 * A request of type, with len bytes of data, on a connection of its own,
 * to nshd's read-write socket if rw, enabled by privileged mode's token,
 * else to its read-only one: facts read into in as they come, and text
 * printed, and how it ended, *status, or 1 if it was not answered, as
 * when ^C ends it, which closes the connection, so nshd stops what it
 * runs. -1 if there is no nshd to ask, or none this user may, else 0.
 */
static int
nshd_ask(int rw, uint32_t type, const void *data, size_t len,
    struct facts_in *in, int32_t *status)
{
	struct nshd_result	 r = { 1 };
	struct imsgbuf		 ib;
	struct imsg		 imsg;
	struct ibuf		 b;
	struct sigaction	 sa, osa;
	sigset_t		 block, saved, waiting;
	int			 fd, done = 0;

	*status = 1;
	if (rw && sfd == -1)
		return (-1);
	if ((fd = nshd_open(rw ? NSHD_SOCKET : NSHD_RO_SOCKET, &ib)) == -1) {
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

	if (rw && nshd_borrow(&ib, &waiting) == -1)
		goto done;
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
			if (imsg_get_ibuf(&imsg, &b) == -1 ||
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
			done = 1;
			break;
		default:
			printf("%% nshd: a message nsh does not know\n");
			imsg_free(&imsg);
			goto done;
		}
		imsg_free(&imsg);
	}
	*status = r.status;
done:
	imsgbuf_clear(&ib);
	close(fd);
	/* a ^C pending now ends nothing */
	sigprocmask(SIG_SETMASK, &saved, NULL);
	sigaction(SIGINT, &osa, NULL);
	return (0);
}

/*
 * show words, as nshd answers them, on the read-write socket if rw, its
 * system's, in privileged mode, else as its show processes do, as
 * nshd_ask() asks: -1 if there is no nshd to ask, or none this user
 * may, else 1 if the show was answered and 0 if not.
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
 * The operation text, in privileged mode, in rtable, which nshd's system
 * runs, as nshd_ask() asks: facts read into in, and how it ended, its
 * status, or 1 if it was not, said why
 */
int
nshd_op(const char *text, int rtable, struct facts_in *in)
{
	struct nshd_op	 op;
	int32_t		 status;

	if (sfd == -1) {
		printf("%% Privilege required\n");
		return (1);
	}
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
 * enable: privileged mode's session opened, and enabled by the secret,
 * which is asked for if nshd takes one; as a handler returns
 */
int
nshd_enable(void)
{
	struct nshd_enable	 e;
	char			*p;
	int			 r;

	if (priv)
		return (0);
	nshd_close();
	if ((sfd = nshd_open(NSHD_SOCKET, &sib)) == -1) {
		nshd_why();
		return (-1);
	}
	memset(&e, 0, sizeof(e));
	e.how = NSHD_BY_SECRET;
	if ((r = nshd_request(IMSG_CTL_ENABLE, &e, sizeof(e), 0)) == -1 &&
	    sfd != -1 && sstatus == NSHD_NEEDSECRET) {
		p = getpass("Privileged Mode Secret:");
		if (p == NULL || *p == '\0')
			printf("%% Secret incorrect\n");
		else {
			/* bcrypt reads 72 bytes of it, at most */
			strlcpy(e.secret, p, sizeof(e.secret));
			r = nshd_request(IMSG_CTL_ENABLE, &e, sizeof(e), 0);
		}
		if (p != NULL)
			explicit_bzero(p, strlen(p));
		explicit_bzero(&e, sizeof(e));
	}
	if (r == -1) {
		nshd_close();
		return (-1);
	}
	priv = 1;
	return (0);
}

/* disable: privileged mode's session closed, and every mode left */
void
nshd_disable(void)
{
	nshd_close();
}

/* configure, of how, in privileged mode's session; as a handler returns */
int
nshd_configure(int how)
{
	struct nshd_configure	 cf;

	cf.mode = how;
	return (nshd_request(IMSG_CTL_CONFIGURE, &cf, sizeof(cf), 0));
}

/* A line of configure private's, in the session's mode */
int
nshd_line(char *text)
{
	struct nshd_line	 l;

	memset(&l, 0, sizeof(l));
	if (strlcpy(l.line, text, sizeof(l.line)) >= sizeof(l.line)) {
		printf("%% Input exceeds permitted length\n");
		return (-1);
	}
	return (nshd_request(IMSG_CTL_LINE, &l, sizeof(l), 0));
}

/* Leave configure private, and the session, from any mode */
int
nshd_exit(void)
{
	return (nshd_request(IMSG_CTL_EXIT, NULL, 0, 0));
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
	return (nshd_request(IMSG_CTL_COMMIT, &c, sizeof(c), 0));
}

/* rollback n */
int
nshd_rollback(int n)
{
	struct nshd_rollback	 rb;

	rb.n = n;
	return (nshd_request(IMSG_CTL_ROLLBACK, &rb, sizeof(rb), 0));
}

/* configure, as the session has it, by name */
const char *
nshd_cname(void)
{
	return (nshd_config == NSHD_PRIVATE ? "configure private" :
	    nshd_config == NSHD_EXCLUSIVE ? "configure exclusive" :
	    nshd_config == NSHD_TERMINAL ? "configure terminal" :
	    "configure");
}

/* show words of a configure's, candidate-config or diff-config, paged */
int
nshd_cshow(char *words)
{
	struct nshd_show	 show;

	memset(&show, 0, sizeof(show));
	strlcpy(show.words, words, sizeof(show.words));
	return (nshd_request(IMSG_CTL_SHOW, &show, sizeof(show), 1));
}

/*
 * type, with len bytes of data, on the session: what nshd prints, to
 * stdout or paged, and the mode and token it gives taken, and how it
 * ended, sstatus; as a handler returns. ^C closes the session, as nshd
 * finishes what it was asked.
 */
static int
nshd_request(uint32_t type, const void *data, size_t len, int paged)
{
	struct nshd_context	 c;
	struct nshd_token	 t;
	struct nshd_result	 r = { -1 };
	struct imsg		 imsg;
	struct ibuf		 b;
	struct sigaction	 sa, osa;
	sigset_t		 block, saved, waiting;
	char			 path[] = "/tmp/nshd.XXXXXXXXXX";
	FILE			*f = stdout;
	int			 fd, done = 0, gone = 1;

	sstatus = -1;
	if (sfd == -1) {
		printf("%% Privilege required\n");
		return (-1);
	}
	if (paged) {
		if ((fd = mkstemp(path)) == -1 ||
		    (f = fdopen(fd, "w")) == NULL) {
			printf("%% %s: %s\n", path, strerror(errno));
			if (fd != -1) {
				unlink(path);
				close(fd);
			}
			return (-1);
		}
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

	if (imsg_compose(&sib, type, 0, 0, -1, data, len) == -1 ||
	    imsgbuf_flush(&sib) == -1) {
		printf("%% nshd: %s\n", strerror(errno));
		goto done;
	}
	while (!done) {
		if (nshd_next(&sib, &imsg, &waiting) == -1) {
			if (nshd_intr)
				printf("\n%% Interrupted: %s, and nshd "
				    "finishes what it was asked\n", priv ?
				    "privileged mode is left" : "not enabled");
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
		case IMSG_CTL_TOKEN:
			if (imsg_get_data(&imsg, &t, sizeof(t)) == -1) {
				printf("%% nshd: a token nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			memcpy(token, t.token, sizeof(token));
			explicit_bzero(&t, sizeof(t));
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
	sstatus = r.status;
done:
	if (paged) {
		if (fclose(f) == EOF)
			printf("%% %s: %s\n", path, strerror(errno));
		else if (!gone)
			more(path);
		unlink(path);
	}
	/* a session nshd closed, or one nsh cannot follow */
	if (gone)
		nshd_close();
	/* a ^C pending now ends nothing */
	sigprocmask(SIG_SETMASK, &saved, NULL);
	sigaction(SIGINT, &osa, NULL);
	return (gone || r.status != 0 ? -1 : 0);
}

/* The session's mode, as nshd gives it, nsh's */
static void
nshd_context(struct nshd_context *c)
{
	nshd_config = c->mode >= NSHD_PRIVATE && c->mode <= NSHD_TERMINAL ?
	    c->mode : 0;
	nshd_rtable = nshd_config ? c->rtable : 0;
	nshd_mode(nshd_config != 0, c->ifname, c->bridge);
}

/* The session gone, and privileged mode and every mode with it */
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
	explicit_bzero(token, sizeof(token));
	priv = 0;
}
