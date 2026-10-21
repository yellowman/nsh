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
 * nsh as a client of nshd(8), where nshd runs. Who may connect to its
 * read-write socket, root or the group nshadmin, has what an enabled
 * nsh has there.
 *
 * configure private, where nshd runs, is a session of its: what edits
 * the candidate, and leaving a mode, go to nshd as lines, and the mode
 * nshd gives back is nsh's, for its prompt, its completion and the
 * lines after (cmdline_nshd()).
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

static volatile sig_atomic_t	nshd_intr;	/* ^C, while nshd answers */

int		nshd_private;	/* configure private, in nshd */
int		nshd_rtable;	/* and the rtable its lines are for */

/* the session configure private is, or -1 */
static int		sfd = -1;
static struct imsgbuf	sib;

static int	nshd_next(struct imsgbuf *, struct imsg *, const sigset_t *);
static int	nshd_open(char *, struct imsgbuf *);
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

/*
 * show words, as nshd answers them, paged: -1 if there is no nshd to
 * ask, else 1 if the show was answered and 0 if not.
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

	if ((fd = nshd_open(NSHD_SOCKET, &ib)) == -1) {
		if (errno != EPROTO)
			return (-1);
		printf("%% nshd: not a version nsh speaks\n");
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
 * show words, as nshd answers them, on the read-write socket if rw, its
 * system's, else as its show processes do: facts read into in as they
 * come, and text printed. -1 if there is no nshd to ask, or none this
 * user may, else 1 if the show was answered and 0 if not, as when ^C
 * ends it, which closes the session, so nshd stops what it runs.
 */
int
nshd_facts(int rw, char *words, struct facts_in *in)
{
	struct nshd_show	 show;
	struct nshd_result	 r = { 0 };
	struct imsgbuf		 ib;
	struct imsg		 imsg;
	struct ibuf		 b;
	struct sigaction	 sa, osa;
	sigset_t		 block, saved, waiting;
	int			 fd, done = 0, ret = 0;

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

	memset(&show, 0, sizeof(show));
	if (strlcpy(show.words, words, sizeof(show.words)) >=
	    sizeof(show.words)) {
		printf("%% show %s: too long\n", words);
		goto done;
	}
	if (imsg_compose(&ib, IMSG_CTL_SHOW, 0, 0, -1, &show,
	    sizeof(show)) == -1 || imsgbuf_flush(&ib) == -1) {
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
	ret = r.status == 0;
done:
	imsgbuf_clear(&ib);
	close(fd);
	/* a ^C pending now ends nothing */
	sigprocmask(SIG_SETMASK, &saved, NULL);
	sigaction(SIGINT, &osa, NULL);
	return (ret);
}

/*
 * configure private, a session of nshd's: as a handler returns, or
 * NSHD_ABSENT if no nshd runs here
 */
int
nshd_configure(void)
{
	struct nshd_configure	 cf;

	if ((sfd = nshd_open(NSHD_SOCKET, &sib)) == -1) {
		if (errno == ENOENT || errno == ECONNREFUSED)
			return (NSHD_ABSENT);
		printf("%% nshd: %s\n", errno == EPROTO ?
		    "not a version nsh speaks" : strerror(errno));
		return (-1);
	}
	cf.mode = NSHD_PRIVATE;
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

/* commit, or commit check, with the comment */
int
nshd_commit(int check, char *comment)
{
	struct nshd_commit	 c;

	memset(&c, 0, sizeof(c));
	c.check = check;
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

/* show words of configure private's, candidate-config or diff-config, paged */
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
 * stdout or paged, and the mode it gives taken; as a handler returns.
 * ^C leaves configure private, as nshd finishes what it was asked.
 */
static int
nshd_request(uint32_t type, const void *data, size_t len, int paged)
{
	struct nshd_context	 c;
	struct nshd_result	 r = { -1 };
	struct imsg		 imsg;
	struct ibuf		 b;
	struct sigaction	 sa, osa;
	sigset_t		 block, saved, waiting;
	char			 path[] = "/tmp/nshd.XXXXXXXXXX";
	FILE			*f = stdout;
	int			 fd, done = 0, gone = 1;

	if (sfd == -1) {
		printf("%% nshd: not in configure private\n");
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
				printf("\n%% Interrupted: configure private "
				    "is left, and nshd finishes what it was "
				    "asked\n");
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
	if (paged) {
		if (fclose(f) == EOF)
			printf("%% %s: %s\n", path, strerror(errno));
		else if (!gone)
			more(path);
		unlink(path);
	}
	/* a session nshd closed, or that did not reach configure private */
	if (gone || !nshd_private)
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
	nshd_private = c->mode == NSHD_PRIVATE;
	nshd_rtable = c->rtable;
	nshd_mode(nshd_private, c->ifname, c->bridge);
}

/* The session gone, and configure private with it */
static void
nshd_close(void)
{
	if (sfd == -1)
		return;
	if (nshd_private) {
		nshd_private = 0;
		nshd_mode(0, "", 0);
	}
	nshd_rtable = 0;
	imsgbuf_clear(&sib);
	close(sfd);
	sfd = -1;
}
