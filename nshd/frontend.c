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
 * frontend: the read-write socket. Each client is a session; what it
 * sends goes to config, through relay, under the session's id, and what
 * config answers for that id goes back to it. frontend checks only that
 * a message is one a client may send, and is whole; it reads no
 * configuration.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <event.h>
#include <imsg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "control.h"

static struct imsgev	*iev_relay;

static void	frontend_dispatch_relay(int, short, void *);
static int	frontend_client(struct ctl_conn *, struct imsg *);
static void	frontend_gone(struct ctl_conn *);

void
frontend(int debug, int verbose)
{
	child_start("frontend", debug, verbose);
	privdrop();
	if (pledge("stdio unix", NULL) == -1)
		fatal("pledge");

	if ((iev_relay = imsgev_new(3, frontend_dispatch_relay, 0)) == NULL)
		fatal(NULL);
	event_dispatch();
	exit(0);
}

static void
frontend_dispatch_relay(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct ctl_conn	*c;
	struct imsg	 imsg;
	struct ibuf	 b;
	ssize_t		 n;

	if (imsgev_io(iev, event) == -1)
		exit(0);

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		switch (imsg_get_type(&imsg)) {
		/* its socket is fd 4, from parent */
		case IMSG_STARTUP:
			if (control_listen(4, frontend_client, frontend_gone) == -1)
				fatalx("cannot listen on %s", NSHD_SOCKET);
			break;
		/* config's answers, to the session each names, if there */
		case IMSG_CTL_HELLO:
		case IMSG_CTL_RESULT:
			/* the request's end */
			if ((c = control_connbyid(imsg_get_id(&imsg))) != NULL)
				c->pending = 0;
			/* FALLTHROUGH */
		case IMSG_CTL_OUTPUT:
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			control_reply(imsg_get_id(&imsg), imsg_get_type(&imsg),
			    ibuf_data(&b), ibuf_size(&b));
			break;
		default:
			log_debug("%s: unexpected imsg %u", __func__,
			    imsg_get_type(&imsg));
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/*
 * What a client sends, to config as its session's; -1 closes it. A
 * client asks one thing at a time, and waits for its answer.
 */
static int
frontend_client(struct ctl_conn *c, struct imsg *imsg)
{
	struct nshd_peer	 peer;
	struct nshd_show	 show;

	if (c->pending)
		return (-1);
	c->pending = 1;
	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_HELLO:
		if (imsg_get_data(imsg, &peer.hello, sizeof(peer.hello)) == -1)
			return (-1);
		peer.uid = c->uid;
		peer.gid = c->gid;
		if (imsg_compose_event(iev_relay, IMSG_CTL_HELLO, c->id, 0,
		    -1, &peer, sizeof(peer)) == -1)
			fatal("%s", __func__);
		return (0);
	case IMSG_CTL_SHOW:
		if (imsg_get_data(imsg, &show, sizeof(show)) == -1 ||
		    memchr(show.words, '\0', sizeof(show.words)) == NULL)
			return (-1);
		if (imsg_compose_event(iev_relay, IMSG_CTL_SHOW, c->id, 0,
		    -1, &show, sizeof(show)) == -1)
			fatal("%s", __func__);
		return (0);
	default:
		return (-1);
	}
}

static void
frontend_gone(struct ctl_conn *c)
{
	if (imsg_compose_event(iev_relay, IMSG_CTL_CLOSE, c->id, 0, -1,
	    NULL, 0) == -1)
		fatal("%s", __func__);
}
