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
 * show: the read-only socket, answered here and nowhere else, with what
 * anyone may see. SHOWS of these share it. Each has no peer, so
 * nothing a client sends here reaches the processes that change
 * anything.
 *
 * A show of state answers with facts, made a batch at a time, as the
 * client reads them, by nsh's own code. What that code prints, as it
 * always has, goes to an unlinked file on fd 1, and from there to the
 * client, as messages.
 *
 * show is not pledged: no promise has the ioctls show interface asks,
 * for tunnels, carp, wg, trunk, umb, 802.11, bridges and more. It runs
 * as _nshshow, chrooted, with no peer, and keeps utmp open from before.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmp.h>

#include "log.h"
#include "nshd.h"
#include "control.h"
#include "facts.h"
#include "showfacts.h"

#define SHOW_LOW	32	/* messages a client has unread, when more are made */
#define SHOW_BATCH	256	/* records made at a time, about */

/* an answer of facts, as its client reads it */
struct answer {
	struct facts_answer	*a;
	struct facts_out	 o;
	struct ctl_conn		*c;
	int			 failed;
};

static struct imsgev	*iev_parent;

static void	show_dispatch_parent(int, short, void *);
static void	show_listen(void);
static int	show_client(struct ctl_conn *, struct imsg *);
static int	show_answer(uint32_t, int32_t, const char *);
static int	show_facts(struct ctl_conn *, char *);
static int	show_more(struct ctl_conn *);
static int	show_result(struct ctl_conn *, int32_t);
static void	show_gone(struct ctl_conn *);
static void	show_emit(void *, const void *, size_t);

void
showproc(int debug, int verbose, int instance)
{
	static char	 name[16];

	snprintf(name, sizeof(name), "show%d", instance);
	child_start(name, debug, verbose);
	capture_stdout();
	facts_from = FACTS_SHOW;
	if ((utmpfd = open(_PATH_UTMP, O_RDONLY)) == -1)
		log_warn("%s", _PATH_UTMP);
	privdrop(PROC_SHOW);

	if ((iev_parent = imsgev_new(3, show_dispatch_parent, 0)) == NULL)
		fatal(NULL);
	event_dispatch();
	exit(0);
}

static void
show_dispatch_parent(int fd, short event, void *arg)
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
		switch (imsg_get_type(&imsg)) {
		/* clients taken at once, or once the boot is done */
		case IMSG_STARTUP:
			if (imsg_get_data(&imsg, &st, sizeof(st)) == -1)
				fatalx("parent sent a startup show cannot read");
			if (!st.boot)
				show_listen();
			break;
		case IMSG_LISTEN:
			show_listen();
			break;
		default:
			log_debug("%s: unexpected imsg %u", __func__,
			    imsg_get_type(&imsg));
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* clients taken, on its socket, fd 4, from parent */
static void
show_listen(void)
{
	if (control_listen(4, show_client, show_gone, show_more) == -1)
		fatalx("cannot listen on %s", NSHD_RO_SOCKET);
}

/* a client's request, answered; -1 closes it */
static int
show_client(struct ctl_conn *c, struct imsg *imsg)
{
	struct nshd_hello	 hello;
	struct nshd_session	 s;
	struct nshd_show	 show;

	/* one request at a time */
	if (c->arg != NULL)
		return (-1);
	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_HELLO:
		if (imsg_get_data(imsg, &hello, sizeof(hello)) == -1)
			return (-1);
		s.version = NSHD_VERSION;
		s.id = c->id;
		/* shows of what anyone may see, whoever asks */
		s.perms = NSHD_VIEW;
		return (control_reply(c->id, IMSG_CTL_HELLO, &s, sizeof(s)));
	case IMSG_CTL_SHOW:
		if (imsg_get_data(imsg, &show, sizeof(show)) == -1 ||
		    memchr(show.words, '\0', sizeof(show.words)) == NULL)
			return (-1);
		return (show_facts(c, show.words));
	default:
		return (-1);
	}
}

/* to client id, text and then the result status */
static int
show_answer(uint32_t id, int32_t status, const char *text)
{
	struct nshd_result	 r;

	r.status = status;
	if (control_reply(id, IMSG_CTL_OUTPUT, text, strlen(text)) == -1)
		return (-1);
	return (control_reply(id, IMSG_CTL_RESULT, &r, sizeof(r)));
}

/* the facts words ask, begun; or that nshd does not answer them */
static int
show_facts(struct ctl_conn *c, char *words)
{
	struct answer		*an;
	char			*out;
	int			 ret;

	if ((an = calloc(1, sizeof(*an))) == NULL)
		fatal("%s", __func__);
	if ((an->a = facts_answer(words)) == NULL) {
		free(an);
		if (asprintf(&out, "%% show %s: not answered by nshd\n",
		    words) == -1)
			fatal("%s", __func__);
		ret = show_answer(c->id, NSHD_ELSEWHERE, out);
		free(out);
		return (ret);
	}
	an->c = c;
	facts_out_init(&an->o, show_emit, an);
	c->arg = an;
	return (show_more(c));
}

/*
 * More of c's answer, while c has read most of what it was sent, and
 * its result once it is all made; -1 closes c
 */
static int
show_more(struct ctl_conn *c)
{
	struct answer		*an = c->arg;
	int			 more = 1;

	if (an == NULL)
		return (0);
	while (more == 1 && imsgbuf_queuelen(&c->iev.ibuf) < SHOW_LOW) {
		more = facts_more(an->a, &an->o, SHOW_BATCH);
		if (printed(&an->o) == -1)
			an->failed = 1;
		if (an->failed)
			return (-1);
	}
	if (more == 1)
		return (0);
	show_gone(c);
	return (show_result(c, more == 0 ? 0 : 1));
}

/* the end of an answer of facts, after however much c has unread */
static int
show_result(struct ctl_conn *c, int32_t status)
{
	struct nshd_result	 r;

	r.status = status;
	return (imsg_compose_event(&c->iev, IMSG_CTL_RESULT, 0, 0, -1, &r,
	    sizeof(r)) == -1 ? -1 : 0);
}

static void
show_gone(struct ctl_conn *c)
{
	struct answer	*an = c->arg;

	if (an == NULL)
		return;
	facts_answer_free(an->a);
	free(an);
	c->arg = NULL;
}

/* a unit, to the client; however much it has unread, as it is a batch */
static void
show_emit(void *arg, const void *buf, size_t len)
{
	struct answer	*an = arg;

	if (imsg_compose_event(&an->c->iev, IMSG_CTL_FACTS, 0, 0, -1, buf,
	    len) == -1)
		an->failed = 1;
}
