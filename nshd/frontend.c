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
 * sends goes to config, on their pipe, under the session's id, and what
 * config answers for that id goes back to it, and config learns each
 * time the client has read all of it. frontend checks only that a
 * message is one a client may send, or config, and is whole; it reads
 * no configuration.
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

/* a client's request, as config takes it */
union frontend_request {
	struct nshd_show	 show;
	struct nshd_configure	 cf;
	struct nshd_line	 line;
	struct nshd_commit	 commit;
	struct nshd_rollback	 rollback;
	struct nshd_enable	 enable;
};

static void	frontend_dispatch_relay(int, short, void *);
static void	frontend_listen(void);
static void	frontend_dispatch_config(int, short, void *);
static void	frontend_forget_config(void);
static int	frontend_client(struct ctl_conn *, struct imsg *);
static void	frontend_gone(struct ctl_conn *);
static int	frontend_written(struct ctl_conn *);
static int	frontend_answer(struct ctl_conn *, struct imsg *);
static ssize_t	frontend_whole(struct imsg *, union frontend_request *);

static struct link	 config = {
	PROC_CONFIG, frontend_dispatch_config, frontend_forget_config
};

void
frontend(int debug, int verbose)
{
	child_start("frontend", debug, verbose);
	privdrop(PROC_FRONTEND);
	if (pledge("stdio unix recvfd", NULL) == -1)
		fatal("pledge");

	if ((iev_relay = imsgev_new(3, frontend_dispatch_relay, 0)) == NULL)
		fatal(NULL);
	links_init(&config, 1, iev_relay, NULL);
	event_dispatch();
	exit(0);
}

/*
 * relay's word that frontend may start, and take clients, at once, or
 * once the boot is done
 */
static void
frontend_dispatch_relay(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_startup	 st;
	ssize_t			 n;

	if (imsgev_io(iev, event) == -1)
		exit(0);

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		if (imsg_get_type(&imsg) == IMSG_STARTUP &&
		    imsg_get_data(&imsg, &st, sizeof(st)) == 0) {
			if (!st.boot)
				frontend_listen();
		} else if (imsg_get_type(&imsg) == IMSG_LISTEN)
			frontend_listen();
		else
			fatalx("relay sent imsg %u, which it may not",
			    imsg_get_type(&imsg));
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* clients taken, on its socket, fd 5, from parent */
static void
frontend_listen(void)
{
	if (control_listen(5, frontend_client, frontend_gone,
	    frontend_written) == -1)
		fatalx("cannot listen on %s", NSHD_SOCKET);
}

/* config's answers, to the session each names, if there */
static void
frontend_dispatch_config(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct ctl_conn		*c;
	struct imsg		 imsg;
	struct ibuf		 b;
	uint32_t		 type;
	ssize_t			 n;

	if (imsgev_io(iev, event) == -1) {
		link_broken(&config, "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			link_broken(&config, "sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		switch (type = imsg_get_type(&imsg)) {
		case IMSG_CTL_HELLO:
		case IMSG_CTL_RESULT:
			/* the request's end */
			if ((c = control_connbyid(imsg_get_id(&imsg))) != NULL)
				c->pending = 0;
			/* FALLTHROUGH */
		case IMSG_CTL_OUTPUT:
		case IMSG_CTL_FACTS:
		case IMSG_CTL_CONTEXT:
		case IMSG_CTL_TOKEN:
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			if (control_reply(imsg_get_id(&imsg), type,
			    ibuf_data(&b), ibuf_size(&b)) == -1)
				control_drop(imsg_get_id(&imsg));
			break;
		default:
			imsg_free(&imsg);
			link_broken(&config, "sent imsg %u, which it may not",
			    type);
			return;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* config started again, or is down: it forgot every session */
static void
frontend_forget_config(void)
{
	control_close_all();
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
	union frontend_request	 r;
	ssize_t			 len;

	if (c->pending)
		return (-1);
	c->pending = 1;
	if (config.down)
		return (frontend_answer(c, imsg));
	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_HELLO:
		if (imsg_get_data(imsg, &peer.hello, sizeof(peer.hello)) == -1)
			return (-1);
		peer.uid = c->uid;
		peer.gid = c->gid;
		if (link_compose(&config, IMSG_CTL_HELLO, c->id, &peer,
		    sizeof(peer)) == -1)
			fatal("%s", __func__);
		return (0);
	case IMSG_CTL_SHOW:
		if (imsg_get_data(imsg, &show, sizeof(show)) == -1 ||
		    memchr(show.words, '\0', sizeof(show.words)) == NULL)
			return (-1);
		if (link_compose(&config, IMSG_CTL_SHOW, c->id, &show,
		    sizeof(show)) == -1)
			fatal("%s", __func__);
		return (0);
	case IMSG_CTL_CONFIGURE:
	case IMSG_CTL_LINE:
	case IMSG_CTL_EXIT:
	case IMSG_CTL_COMMIT:
	case IMSG_CTL_ROLLBACK:
	case IMSG_CTL_ENABLE:
		if ((len = frontend_whole(imsg, &r)) == -1)
			return (-1);
		if (link_compose(&config, imsg_get_type(imsg), c->id,
		    len > 0 ? &r : NULL, len) == -1)
			fatal("%s", __func__);
		return (0);
	default:
		return (-1);
	}
}

static void
frontend_gone(struct ctl_conn *c)
{
	if (link_compose(&config, IMSG_CTL_CLOSE, c->id, NULL, 0) == -1)
		fatal("%s", __func__);
}

/* the client has read all it was sent, so system may stream it more */
static int
frontend_written(struct ctl_conn *c)
{
	if (imsgbuf_queuelen(&c->iev.ibuf) == 0 &&
	    link_compose(&config, IMSG_CTL_READ, c->id, NULL, 0) == -1)
		fatal("%s", __func__);
	return (0);
}

/* with config down, what it would have answered, as far as it can */
static int
frontend_answer(struct ctl_conn *c, struct imsg *imsg)
{
	struct nshd_hello	 hello;
	struct nshd_session	 s;
	struct nshd_result	 r;
	union frontend_request	 req;
	const char		*down = "% nshd: config is down\n";

	c->pending = 0;
	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_HELLO:
		if (imsg_get_data(imsg, &hello, sizeof(hello)) == -1)
			return (-1);
		s.version = NSHD_VERSION;
		s.id = c->id;
		s.priv = 0;
		return (control_reply(c->id, IMSG_CTL_HELLO, &s, sizeof(s)));
	case IMSG_CTL_SHOW:
	case IMSG_CTL_CONFIGURE:
	case IMSG_CTL_LINE:
	case IMSG_CTL_EXIT:
	case IMSG_CTL_COMMIT:
	case IMSG_CTL_ROLLBACK:
	case IMSG_CTL_ENABLE:
		if (frontend_whole(imsg, &req) == -1)
			return (-1);
		r.status = 1;
		if (control_reply(c->id, IMSG_CTL_OUTPUT, down,
		    strlen(down)) == -1)
			return (-1);
		return (control_reply(c->id, IMSG_CTL_RESULT, &r, sizeof(r)));
	default:
		return (-1);
	}
}

/*
 * A client's request but hello, into r, if it is whole, as config takes
 * it: its length, or -1
 */
static ssize_t
frontend_whole(struct imsg *imsg, union frontend_request *r)
{
	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_SHOW:
		if (imsg_get_data(imsg, &r->show, sizeof(r->show)) == -1 ||
		    memchr(r->show.words, '\0', sizeof(r->show.words)) == NULL)
			return (-1);
		return (sizeof(r->show));
	case IMSG_CTL_CONFIGURE:
		if (imsg_get_data(imsg, &r->cf, sizeof(r->cf)) == -1)
			return (-1);
		return (sizeof(r->cf));
	case IMSG_CTL_LINE:
		if (imsg_get_data(imsg, &r->line, sizeof(r->line)) == -1 ||
		    memchr(r->line.line, '\0', sizeof(r->line.line)) == NULL)
			return (-1);
		return (sizeof(r->line));
	case IMSG_CTL_EXIT:
		return (imsg_get_len(imsg) == 0 ? 0 : -1);
	case IMSG_CTL_COMMIT:
		if (imsg_get_data(imsg, &r->commit, sizeof(r->commit)) == -1 ||
		    memchr(r->commit.comment, '\0',
		    sizeof(r->commit.comment)) == NULL)
			return (-1);
		return (sizeof(r->commit));
	case IMSG_CTL_ROLLBACK:
		if (imsg_get_data(imsg, &r->rollback,
		    sizeof(r->rollback)) == -1)
			return (-1);
		return (sizeof(r->rollback));
	case IMSG_CTL_ENABLE:
		if (imsg_get_data(imsg, &r->enable, sizeof(r->enable)) == -1 ||
		    memchr(r->enable.secret, '\0',
		    sizeof(r->enable.secret)) == NULL)
			return (-1);
		return (sizeof(r->enable));
	}
	return (-1);
}
