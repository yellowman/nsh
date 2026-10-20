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
 * relay: the one way between nshd's children, so no message a child
 * writes reaches root but config's requests to kernel. parent gives
 * relay each child's pipe; once it has them all, relay sends each child
 * IMSG_STARTUP, and from then on forwards each message a child sends to
 * the child that routes[] names for its sender and type, unaltered,
 * reading nothing but the header. A child that sends what routes[] does
 * not name, or what imsg cannot read, or whose pipe closes, is reported
 * to parent. parent kills it, and gives relay the pipe of the one it
 * starts in its place, or says it stays down; relay tells its peers
 * (IMSG_RESTART), so they forget what it held, and tells a child it
 * starts which of its peers are down.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <event.h>
#include <imsg.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"

static struct peer {
	enum nshd_proc	 proc;
	int		 instance;
	char		*name;
	struct imsgev	*iev;
	uint32_t	 generation;
	int		 down;
} peers[NCHILD] = {
	/* SHOWS of them */
	{ PROC_SHOW,	 0, "show0" },
	{ PROC_SHOW,	 1, "show1" },
	{ PROC_SHOW,	 2, "show2" },
	{ PROC_SHOW,	 3, "show3" },
	{ PROC_FRONTEND, 0, "frontend" },
	{ PROC_CONFIG,	 0, "config" },
	{ PROC_KERNEL,	 0, "kernel" },
	{ PROC_ARCHIVE,	 0, "archive" },
};

/* all that may pass between the children: who sends what to whom */
static const struct route {
	enum nshd_proc	 from;
	uint32_t	 type;
	enum nshd_proc	 to;
} routes[] = {
	{ PROC_FRONTEND, IMSG_CTL_HELLO,	PROC_CONFIG },
	{ PROC_FRONTEND, IMSG_CTL_SHOW,		PROC_CONFIG },
	{ PROC_FRONTEND, IMSG_CTL_CLOSE,	PROC_CONFIG },
	{ PROC_CONFIG,	 IMSG_CTL_HELLO,	PROC_FRONTEND },
	{ PROC_CONFIG,	 IMSG_CTL_OUTPUT,	PROC_FRONTEND },
	{ PROC_CONFIG,	 IMSG_CTL_RESULT,	PROC_FRONTEND },
	{ PROC_CONFIG,	 IMSG_CTL_FACTS,	PROC_FRONTEND },
	{ PROC_CONFIG,	 IMSG_KRN_SNAPSHOT,	PROC_KERNEL },
	{ PROC_CONFIG,	 IMSG_KRN_SHOW,		PROC_KERNEL },
	{ PROC_KERNEL,	 IMSG_KRN_TEXT,		PROC_CONFIG },
	{ PROC_KERNEL,	 IMSG_KRN_FACTS,	PROC_CONFIG },
	{ PROC_KERNEL,	 IMSG_KRN_END,		PROC_CONFIG },
};

static struct imsgev	*iev_parent;
static int		 started;	/* every child has been told */

static void		 relay_dispatch_parent(int, short, void *);
static void		 relay_dispatch(int, short, void *);
static void		 relay_broken(struct peer *, const char *, ...)
			    __attribute__((__format__ (printf, 2, 3)));
static void		 relay_detach(struct peer *);
static void		 relay_start(struct peer *);
static void		 relay_tell(struct peer *);
static int		 joined(struct peer *, struct peer *);
static struct peer	*peer(enum nshd_proc, int);

void
relay(int debug, int verbose)
{
	child_start("relay", debug, verbose);
	privdrop();
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	/* the one pipe that passes descriptors: parent's, to here */
	if ((iev_parent = imsgev_new(3, relay_dispatch_parent, 1)) == NULL)
		fatal(NULL);
	event_dispatch();
	exit(0);
}

static struct peer *
peer(enum nshd_proc proc, int instance)
{
	int	 i;

	for (i = 0; i < NCHILD; i++)
		if (peers[i].proc == proc && peers[i].instance == instance)
			return (&peers[i]);
	return (NULL);
}

/* whether a route joins a and b */
static int
joined(struct peer *a, struct peer *b)
{
	size_t	 i;

	for (i = 0; i < sizeof(routes) / sizeof(routes[0]); i++)
		if ((routes[i].from == a->proc && routes[i].to == b->proc) ||
		    (routes[i].from == b->proc && routes[i].to == a->proc))
			return (1);
	return (0);
}

/* each child's pipe, or that it stays down, from parent */
static void
relay_dispatch_parent(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_child	 ch;
	struct peer		*p;
	ssize_t			 n;
	int			 i, cfd = -1;

	if (imsgev_io(iev, event) == -1)
		exit(0);

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		switch (imsg_get_type(&imsg)) {
		case IMSG_PIPE:
		case IMSG_DOWN:
			/* one gone wrong was reported, and let go, first */
			if (imsg_get_data(&imsg, &ch, sizeof(ch)) == -1 ||
			    (p = peer(ch.proc, ch.instance)) == NULL ||
			    p->iev != NULL ||
			    (imsg_get_type(&imsg) == IMSG_PIPE &&
			    (cfd = imsg_get_fd(&imsg)) == -1))
				fatalx("%s: bad imsg %u", __func__,
				    imsg_get_type(&imsg));
			p->generation = ch.generation;
			p->down = imsg_get_type(&imsg) == IMSG_DOWN;
			/* a child's pipe passes no descriptors */
			if (!p->down && (p->iev = imsgev_new(cfd,
			    relay_dispatch, 0)) == NULL)
				fatal(NULL);
			if (started) {
				if (!p->down)
					relay_start(p);
				relay_tell(p);
				break;
			}
			for (i = 0; i < NCHILD; i++)
				if (peers[i].iev == NULL && !peers[i].down)
					break;
			if (i < NCHILD)
				break;
			/* every pipe is here: the children may talk */
			started = 1;
			for (i = 0; i < NCHILD; i++)
				if (!peers[i].down)
					relay_start(&peers[i]);
			break;
		default:
			fatalx("%s: unexpected imsg %u", __func__,
			    imsg_get_type(&imsg));
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* p, told its generation, and which of its peers are down */
static void
relay_start(struct peer *p)
{
	struct nshd_startup	 st;
	struct nshd_restart	 r;
	int			 i;

	st.generation = p->generation;
	if (imsg_compose_event(p->iev, IMSG_STARTUP, 0, 0, -1, &st,
	    sizeof(st)) == -1)
		fatal("%s: startup", p->name);
	for (i = 0; i < NCHILD; i++) {
		if (!peers[i].down || !joined(p, &peers[i]))
			continue;
		r.proc = peers[i].proc;
		r.down = 1;
		if (imsg_compose_event(p->iev, IMSG_RESTART, 0, 0, -1, &r,
		    sizeof(r)) == -1)
			fatal("%s: a peer down", p->name);
	}
}

/* p's peers, told it started again, or is down */
static void
relay_tell(struct peer *p)
{
	struct nshd_restart	 r;
	int			 i;

	r.proc = p->proc;
	r.down = p->down;
	for (i = 0; i < NCHILD; i++)
		if (&peers[i] != p && peers[i].iev != NULL &&
		    joined(p, &peers[i]) &&
		    imsg_compose_event(peers[i].iev, IMSG_RESTART, 0, 0, -1,
		    &r, sizeof(r)) == -1)
			fatal("%s", __func__);
}

static void
relay_detach(struct peer *p)
{
	event_del(&p->iev->ev);
	imsgbuf_clear(&p->iev->ibuf);
	close(p->iev->ibuf.fd);
	free(p->iev);
	p->iev = NULL;
}

/* what a child sends, to the child routes[] names, unaltered */
static void
relay_dispatch(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct peer	*from = NULL, *to;
	struct imsg	 imsg;
	uint32_t	 type;
	ssize_t		 n;
	size_t		 i;

	for (i = 0; i < NCHILD; i++)
		if (peers[i].iev == iev)
			from = &peers[i];
	if (from == NULL)
		fatalx("%s: from no child", __func__);

	if (imsgev_io(iev, event) == -1) {
		relay_broken(from, "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			relay_broken(from, "sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		type = imsg_get_type(&imsg);
		to = NULL;
		for (i = 0; i < sizeof(routes) / sizeof(routes[0]); i++)
			if (routes[i].from == from->proc &&
			    routes[i].type == type)
				to = peer(routes[i].to, 0);
		if (to == NULL) {
			imsg_free(&imsg);
			relay_broken(from, "sent imsg %u, which it may not",
			    type);
			return;
		}
		/* gone, its peers not yet told: these crossed */
		if (to->iev == NULL)
			log_debug("%s is gone: imsg %u from %s dropped",
			    to->name, type, from->name);
		else if (imsg_forward(&to->iev->ibuf, &imsg) == -1)
			fatal("imsg_forward");
		else
			imsg_event_add(to->iev);
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* a child gone wrong: no more from it, and parent told */
static void
relay_broken(struct peer *p, const char *fmt, ...)
{
	struct nshd_child	 ch;
	va_list			 ap;
	char			*why;

	va_start(ap, fmt);
	if (vasprintf(&why, fmt, ap) == -1)
		fatal("%s", __func__);
	va_end(ap);
	log_warnx("%s %s", p->name, why);
	free(why);

	relay_detach(p);
	ch.proc = p->proc;
	ch.instance = p->instance;
	ch.generation = p->generation;
	if (imsg_compose_event(iev_parent, IMSG_BROKEN, 0, 0, -1, &ch,
	    sizeof(ch)) == -1)
		fatal("%s", __func__);
}
