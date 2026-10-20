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
 * kernel: root, and nsh's own code, which reads and changes the kernel.
 * It answers config, through relay, one request at a time, in order:
 * the running configuration as text, and the shows only root may make
 * as facts, with what nsh's code prints as it makes them, as messages.
 * A show's answer is made whole, as it is small, its units as many to a
 * message as fit.
 *
 * But a show of text, what a program prints or the leases, may be long,
 * or go on until it is stopped: a child of kernel's prints it, and
 * kernel streams it as messages, as many as KERN_WINDOW before the
 * client has read them, while it answers other requests. A stream ends
 * when its child's output does and its child is reaped, or when config
 * says its session is gone, or config starts again, which kill the
 * child; or when kernel ends.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/wait.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <paths.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "stringlist.h"
#include "externs.h"
#include "facts.h"
#include "showfacts.h"

#define KERN_BATCH	256	/* records made before what is printed is sent */
#define KERN_STREAMS	16	/* streams at once, at most */
#define KERN_WINDOW	16	/* messages a stream sends its client unread */

/* a show's text, which a child prints, as messages to its client */
struct stream {
	TAILQ_ENTRY(stream)	 entry;
	uint32_t		 id;		/* the request */
	pid_t			 pid;		/* the child, or 0, reaped */
	int			 fd;		/* its output, or -1 at its end */
	int			 window;	/* messages it may still send */
	int			 stopped;
	struct event		 ev;
	struct facts_out	 o;
};

static struct imsgev	*iev_relay;
static uint8_t		 units[FACTS_UNIT];	/* not yet sent */
static size_t		 nunits;
static TAILQ_HEAD(, stream) streams = TAILQ_HEAD_INITIALIZER(streams);
static int		 nstreams;

static void	kern_dispatch_relay(int, short, void *);
static void	kern_snapshot(uint32_t);
static void	kern_show(uint32_t, char *);
static void	kern_end(uint32_t, int32_t, const char *, ...)
		    __attribute__((__format__ (printf, 3, 4)));
static void	kern_emit(void *, const void *, size_t);
static void	kern_flush(uint32_t);
static void	kern_stream(uint32_t, struct facts_answer *);
static __dead void kern_child(int, struct facts_answer *);
static void	kern_stream_read(int, short, void *);
static void	kern_stream_more(uint32_t);
static void	kern_stream_stop(struct stream *);
static void	kern_stream_done(struct stream *);
static void	kern_sigchld(int, short, void *);
static __dead void kern_exit(void);

void
kernproc(int debug, int v)
{
	static struct event	 ev_sigchld;

	child_start("kernel", debug, v);
	capture_stdout();

	/* nsh's code here is nsh's as root */
	priv = 1;
	facts_from = FACTS_KERNEL;
	db_create();

	if ((iev_relay = imsgev_new(3, kern_dispatch_relay, 0)) == NULL)
		fatal(NULL);
	signal_set(&ev_sigchld, SIGCHLD, kern_sigchld, NULL);
	signal_add(&ev_sigchld, NULL);
	event_dispatch();
	kern_exit();
}

/* config's requests, through relay */
static void
kern_dispatch_relay(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_show	 show;
	struct stream		*s, *next;
	ssize_t			 n;

	if (imsgev_io(iev, event) == -1)
		kern_exit();

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		switch (imsg_get_type(&imsg)) {
		case IMSG_STARTUP:
			break;
		case IMSG_RESTART:
			/* config, kernel's one peer: what it asked is lost */
			TAILQ_FOREACH_SAFE(s, &streams, entry, next)
				kern_stream_stop(s);
			break;
		case IMSG_KRN_SNAPSHOT:
			kern_snapshot(imsg_get_id(&imsg));
			break;
		case IMSG_KRN_SHOW:
			if (imsg_get_data(&imsg, &show, sizeof(show)) == -1 ||
			    memchr(show.words, '\0', sizeof(show.words)) ==
			    NULL)
				fatalx("%s: bad IMSG_KRN_SHOW", __func__);
			kern_show(imsg_get_id(&imsg), show.words);
			break;
		case IMSG_KRN_READ:
			kern_stream_more(imsg_get_id(&imsg));
			break;
		case IMSG_KRN_STOP:
			TAILQ_FOREACH(s, &streams, entry)
				if (s->id == imsg_get_id(&imsg)) {
					kern_stream_stop(s);
					break;
				}
			break;
		default:
			log_debug("%s: unexpected imsg %u", __func__,
			    imsg_get_type(&imsg));
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* the running configuration, as conf() writes it, then how it went */
static void
kern_snapshot(uint32_t id)
{
	struct nshd_result	 r = { 0 };
	FILE			*f;
	char			*buf = NULL;
	size_t			 len = 0;

	if ((f = open_memstream(&buf, &len)) == NULL) {
		log_warn("%s: open_memstream", __func__);
		r.status = -1;
	} else {
		conf(f);
		printed(NULL);
		if (fclose(f) == EOF) {
			log_warn("%s: fclose", __func__);
			r.status = -1;
		} else if (imsg_text(iev_relay, IMSG_KRN_TEXT, id, buf,
		    len) == -1)
			fatal("%s", __func__);
	}
	free(buf);
	if (imsg_compose_event(iev_relay, IMSG_KRN_END, id, 0, -1, &r,
	    sizeof(r)) == -1)
		fatal("%s", __func__);
}

/* the facts words ask, all of them, then how it went; or a stream */
static void
kern_show(uint32_t id, char *words)
{
	struct facts_answer	*a;
	struct facts_out	 o;
	int			 more = 1;

	printed(NULL);
	if ((a = facts_answer(words)) == NULL) {
		kern_end(id, 1, "%% show %s: not answered by nshd\n", words);
		return;
	}
	if (facts_streams(a)) {
		kern_stream(id, a);
		facts_answer_free(a);
		return;
	}
	facts_out_init(&o, kern_emit, &id);
	while (more == 1) {
		more = facts_more(a, &o, KERN_BATCH);
		if (printed(&o) == -1)
			more = -1;
	}
	facts_answer_free(a);
	kern_flush(id);
	kern_end(id, more != 0, NULL);
}

/* to config: a line of text, if fmt, and how request id ended */
static void
kern_end(uint32_t id, int32_t status, const char *fmt, ...)
{
	struct nshd_result	 r;
	va_list			 ap;
	char			*s;
	int			 len;

	if (fmt != NULL) {
		va_start(ap, fmt);
		len = vasprintf(&s, fmt, ap);
		va_end(ap);
		if (len == -1 ||
		    imsg_text(iev_relay, IMSG_KRN_TEXT, id, s, len) == -1)
			fatal("%s", __func__);
		free(s);
	}
	r.status = status;
	if (imsg_compose_event(iev_relay, IMSG_KRN_END, id, 0, -1, &r,
	    sizeof(r)) == -1)
		fatal("%s", __func__);
}

/* a unit of facts, for request *arg, kept until a message is full */
static void
kern_emit(void *arg, const void *buf, size_t len)
{
	uint32_t	*id = arg;

	if (nunits + len > sizeof(units))
		kern_flush(*id);
	memcpy(units + nunits, buf, len);
	nunits += len;
}

/* the units kept, to config, as one message */
static void
kern_flush(uint32_t id)
{
	if (nunits == 0)
		return;
	if (imsg_compose_event(iev_relay, IMSG_KRN_FACTS, id, 0, -1, units,
	    nunits) == -1)
		fatal("%s", __func__);
	nunits = 0;
}

/* a's text, which a child prints, streamed to request id's client */
static void
kern_stream(uint32_t id, struct facts_answer *a)
{
	struct stream	*s;
	int		 fds[2];

	if (nstreams == KERN_STREAMS) {
		kern_end(id, 1, "%% nshd: %d shows already stream\n",
		    KERN_STREAMS);
		return;
	}
	if (pipe2(fds, O_CLOEXEC) == -1) {
		kern_end(id, 1, "%% nshd: pipe: %s\n", strerror(errno));
		return;
	}
	if ((s = calloc(1, sizeof(*s))) == NULL)
		fatal(NULL);
	switch (s->pid = fork()) {
	case -1:
		kern_end(id, 1, "%% nshd: fork: %s\n", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		free(s);
		return;
	case 0:
		kern_child(fds[1], a);
	}
	close(fds[1]);
	s->id = id;
	s->fd = fds[0];
	s->window = KERN_WINDOW;
	facts_out_init(&s->o, kern_emit, &s->id);
	event_set(&s->ev, s->fd, EV_READ | EV_PERSIST, kern_stream_read, s);
	event_add(&s->ev, NULL);
	TAILQ_INSERT_TAIL(&streams, s, entry);
	nstreams++;
}

/* the child: a's text, to fd, with nothing else of kernel's */
static __dead void
kern_child(int fd, struct facts_answer *a)
{
	int	 null;

	/* as a program expects them, and as kernel's are not */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	if (dup2(fd, STDOUT_FILENO) == -1 || dup2(fd, STDERR_FILENO) == -1 ||
	    (null = open(_PATH_DEVNULL, O_RDONLY)) == -1 ||
	    dup2(null, STDIN_FILENO) == -1)
		_exit(127);
	closefrom(STDERR_FILENO + 1);
	facts_stream(a, 1);
	fflush(stdout);
	_exit(0);
}

/* what a stream's child printed, as a message to its client */
static void
kern_stream_read(int fd, short event, void *arg)
{
	struct stream	*s = arg;
	char		 buf[NSHD_TEXT];
	ssize_t		 n;

	if ((n = read(s->fd, buf, sizeof(buf))) == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		log_warn("%s: read", __func__);
	}
	if (n > 0 && facts_text(&s->o, buf, n) == -1) {
		log_warnx("%s: a message of %zd bytes", __func__, n);
		n = -1;
	}
	kern_flush(s->id);
	if (n == -1)
		kern_stream_stop(s);
	else if (n == 0) {
		event_del(&s->ev);
		close(s->fd);
		s->fd = -1;
		kern_stream_done(s);
	} else if (--s->window == 0)
		event_del(&s->ev);
}

/* request id's client read all it was sent: its stream may send more */
static void
kern_stream_more(uint32_t id)
{
	struct stream	*s;

	TAILQ_FOREACH(s, &streams, entry)
		if (s->id == id) {
			if (s->window == 0 && s->fd != -1)
				event_add(&s->ev, NULL);
			s->window = KERN_WINDOW;
			break;
		}
}

/* s, its child killed: it ends once the child is reaped */
static void
kern_stream_stop(struct stream *s)
{
	s->stopped = 1;
	if (s->pid != 0)
		kill(s->pid, SIGKILL);
	if (s->fd != -1) {
		event_del(&s->ev);
		close(s->fd);
		s->fd = -1;
	}
	kern_stream_done(s);
}

/* s, if its output has ended and its child is reaped: how it went */
static void
kern_stream_done(struct stream *s)
{
	if (s->fd != -1 || s->pid != 0)
		return;
	kern_end(s->id, s->stopped, NULL);
	TAILQ_REMOVE(&streams, s, entry);
	nstreams--;
	free(s);
}

/* the streams' children that are gone; no other child is reaped */
static void
kern_sigchld(int sig, short event, void *arg)
{
	struct stream	*s, *next;

	TAILQ_FOREACH_SAFE(s, &streams, entry, next)
		if (s->pid != 0 && waitpid(s->pid, NULL, WNOHANG) == s->pid) {
			s->pid = 0;
			kern_stream_done(s);
		}
}

/* kernel ends, and with it what its streams' children print */
static __dead void
kern_exit(void)
{
	struct stream	*s;

	TAILQ_FOREACH(s, &streams, entry)
		if (s->pid != 0)
			kill(s->pid, SIGKILL);
	exit(0);
}
