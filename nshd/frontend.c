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
 * config answers for that id goes back to it, with the notices config
 * sends unasked, and config learns each time the client has read all
 * of it. frontend checks only that a message is one a client may send,
 * or config, and is whole; it reads no configuration.
 *
 * And it tells system, on their pipe, whose each request is, and whether
 * the session is the web configurator's, a client of NSHD_WEB_USER's
 * uid, before config hears of it: each request that may begin a commit,
 * a line, a commit or a load's part, or that system checks itself, an
 * operation, a login, a terminal or a watch; and when config answers
 * it, and when a session goes. system begins config's commits only for
 * a request not answered, so a config a client compromised cannot say
 * whose they are.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "control.h"

static struct imsgev	*iev_parent;
static uid_t		 web_uid;	/* NSHD_WEB_USER's, */
static int		 web_user;	/* if there is one */

/* a client's request, as config takes it */
union frontend_request {
	struct nshd_show	 show;
	struct nshd_configure	 cf;
	struct nshd_line	 line;
	struct nshd_commit	 commit;
	struct nshd_rollback	 rollback;
	struct nshd_op		 op;
	struct nshd_load	 load;
	struct nshd_login	 login;
	struct nshd_watch	 watch;
	struct nshd_terminal	 terminal;
};

static void	frontend_dispatch_parent(int, short, void *);
static void	frontend_listen(void);
static void	frontend_dispatch_config(int, short, void *);
static void	frontend_dispatch_system(int, short, void *);
static void	frontend_asked(struct ctl_conn *, uint32_t);
static int	frontend_client(struct ctl_conn *, struct imsg *);
static void	frontend_gone(struct ctl_conn *);
static int	frontend_written(struct ctl_conn *);
static ssize_t	frontend_whole(struct imsg *, union frontend_request *);

static struct link	 links[] = {
#define CONFIG		0
	{ PROC_CONFIG,	 frontend_dispatch_config },
#define SYSTEM		1
	{ PROC_SYSTEM,	 frontend_dispatch_system },
};

void
frontend(int debug, int verbose)
{
	struct passwd	*pw;

	child_start("frontend", debug, verbose);
	if ((pw = getpwnam(NSHD_WEB_USER)) != NULL) {
		web_uid = pw->pw_uid;
		web_user = 1;
	}
	privdrop(PROC_FRONTEND);
	if (pledge("stdio unix recvfd", NULL) == -1)
		fatal("pledge");

	if ((iev_parent = imsgev_new(3, frontend_dispatch_parent, 0)) == NULL)
		fatal(NULL);
	links_init(links, sizeof(links) / sizeof(links[0]));
	/* its peers' pipes are here; a terminal's pty comes from config */
	imsgbuf_allow_fdpass(&links[CONFIG].iev->ibuf);
	if (pledge("stdio unix recvfd sendfd", NULL) == -1)
		fatal("pledge");
	event_dispatch();
	exit(0);
}

/*
 * parent's word that frontend may start, and take clients, at once, or
 * once the boot is done
 */
static void
frontend_dispatch_parent(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_startup	 st;
	int			 n;

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
			fatalx("parent sent imsg %u, which it may not",
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
	int			 n, pty;

	if (imsgev_io(iev, event) == -1) {
		link_broken(&links[CONFIG], "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			link_broken(&links[CONFIG], "sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		switch (type = imsg_get_type(&imsg)) {
		case IMSG_CTL_HELLO:
		case IMSG_CTL_RESULT:
			/* the request's end */
			if ((c = control_connbyid(imsg_get_id(&imsg))) !=
			    NULL) {
				c->pending = 0;
				if (c->asked) {
					c->asked = 0;
					frontend_asked(c, IMSG_FRONT_ANSWERED);
				}
			}
			/* FALLTHROUGH */
		case IMSG_CTL_OUTPUT:
		case IMSG_CTL_FACTS:
		case IMSG_CTL_CONTEXT:
		case IMSG_CTL_NOTICE:
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			if (control_reply(imsg_get_id(&imsg), type,
			    ibuf_data(&b), ibuf_size(&b)) == -1)
				control_drop(imsg_get_id(&imsg));
			break;
		case IMSG_CTL_TERMINAL:
			/* a terminal's pty, before the request's end */
			if ((pty = imsg_get_fd(&imsg)) == -1 ||
			    imsg_get_len(&imsg) != 0) {
				imsg_free(&imsg);
				link_broken(&links[CONFIG], "sent a terminal "
				    "not whole");
				return;
			}
			if (control_pass(imsg_get_id(&imsg), type, pty) == -1)
				control_drop(imsg_get_id(&imsg));
			break;
		default:
			imsg_free(&imsg);
			link_broken(&links[CONFIG], "sent imsg %u, which it may not",
			    type);
			return;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* system sends frontend nothing */
static void
frontend_dispatch_system(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	uint32_t		 type;
	int			 n;

	if (imsgev_io(iev, event) == -1) {
		link_broken(&links[SYSTEM], "closed its pipe");
		return;
	}
	if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
		link_broken(&links[SYSTEM], "sent what imsg cannot read");
		return;
	}
	if (n > 0) {
		type = imsg_get_type(&imsg);
		imsg_free(&imsg);
		link_broken(&links[SYSTEM], "sent imsg %u, which it may not",
		    type);
		return;
	}
	imsg_event_add(iev);
}

/*
 * to system: the session's request that may begin a commit, its answer,
 * or the session gone
 */
static void
frontend_asked(struct ctl_conn *c, uint32_t type)
{
	struct nshd_asked	 a;

	memset(&a, 0, sizeof(a));
	a.session = c->id;
	a.uid = c->uid;
	a.web = web_user && c->uid == web_uid;
	if (link_compose(&links[SYSTEM], type, 0, &a, sizeof(a)) == -1)
		fatal("%s", __func__);
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
	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_HELLO:
		if (imsg_get_data(imsg, &peer.hello, sizeof(peer.hello)) == -1)
			return (-1);
		peer.uid = c->uid;
		peer.gid = c->gid;
		peer.web = web_user && c->uid == web_uid;
		if (link_compose(&links[CONFIG], IMSG_CTL_HELLO, c->id, &peer,
		    sizeof(peer)) == -1)
			fatal("%s", __func__);
		return (0);
	case IMSG_CTL_SHOW:
		if (imsg_get_data(imsg, &show, sizeof(show)) == -1 ||
		    memchr(show.words, '\0', sizeof(show.words)) == NULL)
			return (-1);
		if (link_compose(&links[CONFIG], IMSG_CTL_SHOW, c->id, &show,
		    sizeof(show)) == -1)
			fatal("%s", __func__);
		return (0);
	case IMSG_CTL_COMMANDS:
	case IMSG_CTL_NAMES:
		/* completion's tables and names: these carry no data */
		if (imsg_get_len(imsg) != 0)
			return (-1);
		if (link_compose(&links[CONFIG], imsg_get_type(imsg), c->id,
		    NULL, 0) == -1)
			fatal("%s", __func__);
		return (0);
	case IMSG_CTL_LOGIN:
	case IMSG_CTL_TERMINAL:
		/* the web configurator's alone */
		if (!web_user || c->uid != web_uid)
			return (-1);
		/* FALLTHROUGH */
	case IMSG_CTL_CONFIGURE:
	case IMSG_CTL_LINE:
	case IMSG_CTL_EXIT:
	case IMSG_CTL_COMMIT:
	case IMSG_CTL_ROLLBACK:
	case IMSG_CTL_OP:
	case IMSG_CTL_LOAD:
	case IMSG_CTL_WATCH:
		if ((len = frontend_whole(imsg, &r)) == -1)
			return (-1);
		/* system first, so it knows of what config may begin */
		if (imsg_get_type(imsg) == IMSG_CTL_LINE ||
		    imsg_get_type(imsg) == IMSG_CTL_COMMIT ||
		    imsg_get_type(imsg) == IMSG_CTL_OP ||
		    imsg_get_type(imsg) == IMSG_CTL_LOAD ||
		    imsg_get_type(imsg) == IMSG_CTL_LOGIN ||
		    imsg_get_type(imsg) == IMSG_CTL_TERMINAL ||
		    imsg_get_type(imsg) == IMSG_CTL_WATCH) {
			c->asked = 1;
			frontend_asked(c, IMSG_FRONT_ASKED);
		}
		if (link_compose(&links[CONFIG], imsg_get_type(imsg), c->id,
		    len > 0 ? &r : NULL, len) == -1)
			fatal("%s", __func__);
		explicit_bzero(&r, sizeof(r));
		return (0);
	default:
		return (-1);
	}
}

static void
frontend_gone(struct ctl_conn *c)
{
	frontend_asked(c, IMSG_FRONT_GONE);
	if (link_compose(&links[CONFIG], IMSG_CTL_CLOSE, c->id, NULL, 0) ==
	    -1)
		fatal("%s", __func__);
}

/* the client has read all it was sent, so system may stream it more */
static int
frontend_written(struct ctl_conn *c)
{
	if (imsgbuf_queuelen(&c->iev.ibuf) == 0 &&
	    link_compose(&links[CONFIG], IMSG_CTL_READ, c->id, NULL, 0) == -1)
		fatal("%s", __func__);
	return (0);
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
	case IMSG_CTL_OP:
		if (imsg_get_data(imsg, &r->op, sizeof(r->op)) == -1 ||
		    memchr(r->op.line, '\0', sizeof(r->op.line)) == NULL)
			return (-1);
		return (sizeof(r->op));
	case IMSG_CTL_LOAD:
		if (imsg_get_data(imsg, &r->load, sizeof(r->load)) == -1 ||
		    (r->load.last != 0 && r->load.last != 1) ||
		    r->load.len < 0 || r->load.len > NSHD_TEXT ||
		    memchr(r->load.comment, '\0',
		    sizeof(r->load.comment)) == NULL)
			return (-1);
		return (sizeof(r->load));
	case IMSG_CTL_LOGIN:
		if (imsg_get_data(imsg, &r->login, sizeof(r->login)) == -1 ||
		    memchr(r->login.name, '\0', sizeof(r->login.name)) == NULL ||
		    memchr(r->login.password, '\0',
		    sizeof(r->login.password)) == NULL)
			return (-1);
		return (sizeof(r->login));
	case IMSG_CTL_WATCH:
		if (imsg_get_data(imsg, &r->watch, sizeof(r->watch)) == -1)
			return (-1);
		return (sizeof(r->watch));
	case IMSG_CTL_TERMINAL:
		if (imsg_get_data(imsg, &r->terminal,
		    sizeof(r->terminal)) == -1 ||
		    r->terminal.rows < 1 || r->terminal.rows > NSHD_TERMSIZE ||
		    r->terminal.cols < 1 || r->terminal.cols > NSHD_TERMSIZE)
			return (-1);
		return (sizeof(r->terminal));
	}
	return (-1);
}
