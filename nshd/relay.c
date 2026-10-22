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
 * relay: the children's lives, and nothing else; their requests go on
 * pipes of their own, from peer to peer. parent gives relay each
 * child's pipe; once it has them all, relay sends each child
 * IMSG_STARTUP, and each child started again its own. A child may send
 * relay only that a peer of its own went wrong (IMSG_BROKEN), which
 * relay tells parent. A child that sends anything else, or what imsg
 * cannot read, or whose pipe closes, is reported to parent. parent
 * kills the one reported, and gives relay the pipe of the one it starts
 * in its place, or says it stays down.
 *
 * Started with -b, relay tells each child at its start that the boot
 * is not done, until config says it is (IMSG_BOOTED), which relay tells
 * parent; then it tells frontend and each show to take clients
 * (IMSG_LISTEN), and each started after that the boot is done.
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
	{ PROC_SYSTEM,	 0, "system" },
	{ PROC_ARCHIVE,	 0, "archive" },
};

static struct imsgev	*iev_parent;
static int		 started;	/* every child has been told */
static int		 booting;	/* the boot is not done */

static void		 relay_dispatch_parent(int, short, void *);
static void		 relay_dispatch(int, short, void *);
static void		 relay_broken(struct peer *, const char *, ...)
			    __attribute__((__format__ (printf, 2, 3)));
static void		 relay_detach(struct peer *);
static void		 relay_start(struct peer *);
static void		 relay_booted(struct imsg *);
static struct peer	*peer(enum nshd_proc, int);

void
relay(int debug, int verbose, int boot)
{
	booting = boot;
	child_start("relay", debug, verbose);
	privdrop(PROC_RELAY);
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
			if (imsg_get_data(&imsg, &ch, sizeof(ch)) == -1 ||
			    (p = peer(ch.proc, ch.instance)) == NULL ||
			    (imsg_get_type(&imsg) == IMSG_PIPE &&
			    (cfd = imsg_get_fd(&imsg)) == -1))
				fatalx("%s: bad imsg %u", __func__,
				    imsg_get_type(&imsg));
			/* one a peer said went wrong, which parent killed */
			if (p->iev != NULL)
				relay_detach(p);
			p->generation = ch.generation;
			p->down = imsg_get_type(&imsg) == IMSG_DOWN;
			/* a child's pipe passes no descriptors */
			if (!p->down && (p->iev = imsgev_new(cfd,
			    relay_dispatch, 0)) == NULL)
				fatal(NULL);
			if (started) {
				if (!p->down)
					relay_start(p);
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

/* p, told its generation, whether the boot is done, and that it may start */
static void
relay_start(struct peer *p)
{
	struct nshd_startup	 st;

	st.generation = p->generation;
	st.boot = booting;
	if (imsg_compose_event(p->iev, IMSG_STARTUP, 0, 0, -1, &st,
	    sizeof(st)) == -1)
		fatal("%s: startup", p->name);
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

/* a peer of its own a child says went wrong, to parent */
static void
relay_dispatch(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct peer		*from = NULL;
	struct imsg		 imsg;
	struct nshd_child	 ch;
	uint32_t		 type;
	ssize_t			 n;
	size_t			 i;

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
		/* config's word that the boot is done, once */
		if (type == IMSG_BOOTED && from->proc == PROC_CONFIG &&
		    booting && imsg_get_len(&imsg) == sizeof(struct nshd_result)) {
			relay_booted(&imsg);
			imsg_free(&imsg);
			continue;
		}
		if (type != IMSG_BROKEN ||
		    imsg_get_data(&imsg, &ch, sizeof(ch)) == -1 ||
		    ch.instance != 0 || !joined(from->proc, ch.proc)) {
			imsg_free(&imsg);
			relay_broken(from, "sent imsg %u, which it may not",
			    type);
			return;
		}
		imsg_free(&imsg);
		if (imsg_compose_event(iev_parent, IMSG_BROKEN, 0, 0, -1, &ch,
		    sizeof(ch)) == -1)
			fatal("%s", __func__);
	}
	imsg_event_add(iev);
}

/* the boot done: parent told how, and frontend and the shows to listen */
static void
relay_booted(struct imsg *imsg)
{
	struct nshd_result	 res;
	int			 i;

	if (imsg_get_data(imsg, &res, sizeof(res)) == -1)
		fatal("%s", __func__);
	booting = 0;
	if (imsg_compose_event(iev_parent, IMSG_BOOTED, 0, 0, -1, &res,
	    sizeof(res)) == -1)
		fatal("%s", __func__);
	for (i = 0; i < NCHILD; i++)
		if ((peers[i].proc == PROC_FRONTEND ||
		    peers[i].proc == PROC_SHOW) && peers[i].iev != NULL &&
		    imsg_compose_event(peers[i].iev, IMSG_LISTEN, 0, 0, -1,
		    NULL, 0) == -1)
			fatal("%s: listen", peers[i].name);
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
