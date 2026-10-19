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
 * to parent.
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
	char		*name;
	struct imsgev	*iev;
} peers[NCHILD] = {
	{ PROC_SHOW,	 "show" },
	{ PROC_FRONTEND, "frontend" },
	{ PROC_CONFIG,	 "config" },
	{ PROC_KERNEL,	 "kernel" },
	{ PROC_ARCHIVE,	 "archive" },
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
	{ PROC_CONFIG,	 IMSG_KRN_SNAPSHOT,	PROC_KERNEL },
	{ PROC_KERNEL,	 IMSG_KRN_TEXT,		PROC_CONFIG },
	{ PROC_KERNEL,	 IMSG_KRN_END,		PROC_CONFIG },
};

static struct imsgev	*iev_parent;

static void		 relay_dispatch_parent(int, short, void *);
static void		 relay_dispatch(int, short, void *);
static void		 relay_broken(struct peer *, const char *, ...)
			    __attribute__((__format__ (printf, 2, 3)));
static struct peer	*peer(enum nshd_proc);

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
peer(enum nshd_proc proc)
{
	int	 i;

	for (i = 0; i < NCHILD; i++)
		if (peers[i].proc == proc)
			return (&peers[i]);
	return (NULL);
}

/* each child's pipe, from parent */
static void
relay_dispatch_parent(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_child	 ch;
	struct peer		*p;
	ssize_t			 n;
	int			 i, cfd;

	if (imsgev_io(iev, event) == -1)
		exit(0);

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		switch (imsg_get_type(&imsg)) {
		case IMSG_PIPE:
			if (imsg_get_data(&imsg, &ch, sizeof(ch)) == -1 ||
			    (p = peer(ch.proc)) == NULL || p->iev != NULL ||
			    (cfd = imsg_get_fd(&imsg)) == -1)
				fatalx("%s: bad IMSG_PIPE", __func__);
			/* a child's pipe passes no descriptors */
			if ((p->iev = imsgev_new(cfd, relay_dispatch, 0)) ==
			    NULL)
				fatal(NULL);
			for (i = 0; i < NCHILD; i++)
				if (peers[i].iev == NULL)
					break;
			if (i < NCHILD)
				break;
			/* every pipe is here: the children may talk */
			for (i = 0; i < NCHILD; i++)
				if (imsg_compose_event(peers[i].iev,
				    IMSG_STARTUP, 0, 0, -1, NULL, 0) == -1)
					fatal("%s: startup", peers[i].name);
			break;
		default:
			fatalx("%s: unexpected imsg %u", __func__,
			    imsg_get_type(&imsg));
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
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
				to = peer(routes[i].to);
		if (to == NULL) {
			imsg_free(&imsg);
			relay_broken(from, "sent imsg %u, which it may not",
			    type);
			return;
		}
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

	event_del(&p->iev->ev);
	imsgbuf_clear(&p->iev->ibuf);
	close(p->iev->ibuf.fd);
	free(p->iev);
	p->iev = NULL;

	ch.proc = p->proc;
	if (imsg_compose_event(iev_parent, IMSG_BROKEN, 0, 0, -1, &ch,
	    sizeof(ch)) == -1)
		fatal("%s", __func__);
}
