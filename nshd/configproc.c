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
 * config: the sessions, from frontend, and what they ask of kernel,
 * each on its own pipe. Each request to kernel has an id of its own,
 * with config's generation in its top bits, so an answer meant for a
 * config before this one is known for what it is; kernel's answers for
 * it go to the session that asked, if that session is still there, its
 * facts passed on unread. kernel learns when a session's client has
 * read all it was sent, and when the session is gone, so it stops what
 * it streams the session. When frontend starts again, every session is
 * gone; when kernel does, what it was asked is lost. A peer that sends
 * what it may not, or sends it wrong, is reported, as it went wrong.
 */

#include <sys/types.h>
#include <sys/queue.h>

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

struct session {
	TAILQ_ENTRY(session)	 entry;
	uint32_t		 id;
	uid_t			 uid;
	gid_t			 gid;
};

/* a request kernel has not finished, and the session that asked it */
struct request {
	TAILQ_ENTRY(request)	 entry;
	uint32_t		 id;
	uint32_t		 session;
};

static TAILQ_HEAD(, session)	sessions = TAILQ_HEAD_INITIALIZER(sessions);
static TAILQ_HEAD(, request)	requests = TAILQ_HEAD_INITIALIZER(requests);
static uint32_t			request_id;

#define REQUEST_GEN_SHIFT	24	/* generation above, count below */
#define REQUEST_COUNT		((1U << REQUEST_GEN_SHIFT) - 1)

static struct imsgev	*iev_relay;

static void		 config_dispatch_relay(int, short, void *);
static void		 config_dispatch_frontend(int, short, void *);
static void		 config_dispatch_kernel(int, short, void *);
static void		 config_forget_frontend(void);
static void		 config_forget_kernel(void);
static void		 config_show(uint32_t, struct nshd_show *);
static void		 config_answer(uint32_t, int32_t, const char *, ...)
			    __attribute__((__format__ (printf, 3, 4)));
static void		 config_tell(uint32_t, uint32_t);
static struct session	*session_find(uint32_t);
static struct request	*request_find(uint32_t);

static struct link	 links[] = {
#define FRONTEND	0
	{ PROC_FRONTEND, config_dispatch_frontend, config_forget_frontend },
#define KERNEL		1
	{ PROC_KERNEL,	 config_dispatch_kernel,   config_forget_kernel },
};

void
configproc(int debug, int verbose)
{
	child_start("config", debug, verbose);
	privdrop(PROC_CONFIG);
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	if ((iev_relay = imsgev_new(3, config_dispatch_relay, 0)) == NULL)
		fatal(NULL);
	links_init(links, sizeof(links) / sizeof(links[0]), iev_relay);
	event_dispatch();
	exit(0);
}

/* relay's word of config's generation */
static void
config_dispatch_relay(int fd, short event, void *arg)
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
		if (imsg_get_type(&imsg) != IMSG_STARTUP ||
		    imsg_get_data(&imsg, &st, sizeof(st)) == -1)
			fatalx("relay sent imsg %u, which it may not",
			    imsg_get_type(&imsg));
		request_id = st.generation << REQUEST_GEN_SHIFT;
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* frontend's requests, each for a session */
static void
config_dispatch_frontend(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct link		*l = &links[FRONTEND];
	struct imsg		 imsg;
	struct nshd_peer	 peer;
	struct nshd_session	 s;
	struct nshd_show	 show;
	struct session		*sp;
	uint32_t		 id, type;
	ssize_t			 n;

	if (imsgev_io(iev, event) == -1) {
		link_broken(l, "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			link_broken(l, "sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		id = imsg_get_id(&imsg);
		switch (type = imsg_get_type(&imsg)) {
		case IMSG_CTL_HELLO:
			if (imsg_get_data(&imsg, &peer, sizeof(peer)) == -1)
				goto bad;
			if ((sp = session_find(id)) == NULL) {
				if ((sp = calloc(1, sizeof(*sp))) == NULL)
					fatal(NULL);
				sp->id = id;
				sp->uid = peer.uid;
				sp->gid = peer.gid;
				TAILQ_INSERT_TAIL(&sessions, sp, entry);
			}
			/* the socket's group already decided it */
			s.version = NSHD_VERSION;
			s.id = id;
			s.priv = 1;
			if (link_compose(l, IMSG_CTL_HELLO, id, &s,
			    sizeof(s)) == -1)
				fatal("%s", __func__);
			break;
		case IMSG_CTL_SHOW:
			if (imsg_get_data(&imsg, &show, sizeof(show)) == -1 ||
			    memchr(show.words, '\0', sizeof(show.words)) ==
			    NULL)
				goto bad;
			config_show(id, &show);
			break;
		case IMSG_CTL_CLOSE:
			if ((sp = session_find(id)) != NULL) {
				TAILQ_REMOVE(&sessions, sp, entry);
				free(sp);
			}
			config_tell(id, IMSG_KRN_STOP);
			break;
		case IMSG_CTL_READ:
			config_tell(id, IMSG_KRN_READ);
			break;
		default:
			goto bad;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
	return;
 bad:
	imsg_free(&imsg);
	link_broken(l, "sent imsg %u, which it may not, or not whole", type);
}

/* kernel's answers, each for a request */
static void
config_dispatch_kernel(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct link		*l = &links[KERNEL];
	struct imsg		 imsg;
	struct ibuf		 b;
	struct nshd_result	 res;
	struct request		*r;
	uint32_t		 type;
	ssize_t			 n;

	if (imsgev_io(iev, event) == -1) {
		link_broken(l, "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			link_broken(l, "sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		r = request_find(imsg_get_id(&imsg));
		switch (type = imsg_get_type(&imsg)) {
		case IMSG_KRN_TEXT:
		case IMSG_KRN_FACTS:
			/* for a config before this one, or a request failed */
			if (r == NULL)
				break;
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			if (session_find(r->session) != NULL &&
			    link_compose(&links[FRONTEND],
			    type == IMSG_KRN_TEXT ? IMSG_CTL_OUTPUT :
			    IMSG_CTL_FACTS, r->session, ibuf_data(&b),
			    ibuf_size(&b)) == -1)
				fatal("%s", __func__);
			break;
		case IMSG_KRN_END:
			if (imsg_get_data(&imsg, &res, sizeof(res)) == -1)
				goto bad;
			if (r == NULL)
				break;
			if (session_find(r->session) != NULL)
				config_answer(r->session, res.status, NULL);
			TAILQ_REMOVE(&requests, r, entry);
			free(r);
			break;
		default:
			goto bad;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
	return;
 bad:
	imsg_free(&imsg);
	link_broken(l, "sent imsg %u, which it may not, or not whole", type);
}

static void
config_show(uint32_t session, struct nshd_show *show)
{
	struct request	*r;

	if (session_find(session) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if (links[KERNEL].down) {
		config_answer(session, 1, "%% nshd: kernel is down\n");
		return;
	}
	if ((request_id & REQUEST_COUNT) == REQUEST_COUNT) {
		config_answer(session, 1, "%% nshd: request ids exhausted\n");
		return;
	}
	if ((r = calloc(1, sizeof(*r))) == NULL)
		fatal(NULL);
	r->id = ++request_id;
	r->session = session;
	TAILQ_INSERT_TAIL(&requests, r, entry);
	/* kernel answers the rest with facts, or says it does not */
	if ((strcmp(show->words, "running-config") == 0 ?
	    link_compose(&links[KERNEL], IMSG_KRN_SNAPSHOT, r->id, NULL, 0) :
	    link_compose(&links[KERNEL], IMSG_KRN_SHOW, r->id, show,
	    sizeof(*show))) == -1)
		fatal("%s", __func__);
}

/* to session, a line of output if fmt, and the result status */
static void
config_answer(uint32_t session, int32_t status, const char *fmt, ...)
{
	struct nshd_result	 r;
	va_list			 ap;
	char			*s;
	int			 len;

	if (fmt != NULL) {
		va_start(ap, fmt);
		len = vasprintf(&s, fmt, ap);
		va_end(ap);
		if (len == -1)
			fatal("%s", __func__);
		if (imsg_text(links[FRONTEND].iev, IMSG_CTL_OUTPUT, session,
		    s, len) == -1)
			fatal("%s", __func__);
		free(s);
	}
	r.status = status;
	if (link_compose(&links[FRONTEND], IMSG_CTL_RESULT, session, &r,
	    sizeof(r)) == -1)
		fatal("%s", __func__);
}

/* frontend started again, or is down: its sessions are gone */
static void
config_forget_frontend(void)
{
	struct session	*sp;
	struct request	*r;

	while ((sp = TAILQ_FIRST(&sessions)) != NULL) {
		config_tell(sp->id, IMSG_KRN_STOP);
		TAILQ_REMOVE(&sessions, sp, entry);
		free(sp);
	}
	/* no session again has 0, and a new one may have the id */
	TAILQ_FOREACH(r, &requests, entry)
		r->session = 0;
}

/* kernel started again, or is down: what it was asked is lost */
static void
config_forget_kernel(void)
{
	struct request	*r;

	while ((r = TAILQ_FIRST(&requests)) != NULL) {
		if (session_find(r->session) != NULL)
			config_answer(r->session, 1, links[KERNEL].down ?
			    "%% nshd: kernel is down\n" :
			    "%% nshd: kernel started again, and its answer is "
			    "lost\n");
		TAILQ_REMOVE(&requests, r, entry);
		free(r);
	}
}

/* to kernel: type, for each request of session not finished */
static void
config_tell(uint32_t session, uint32_t type)
{
	struct request	*r;

	TAILQ_FOREACH(r, &requests, entry)
		if (r->session == session && link_compose(&links[KERNEL],
		    type, r->id, NULL, 0) == -1)
			fatal("%s", __func__);
}

static struct session *
session_find(uint32_t id)
{
	struct session	*sp;

	TAILQ_FOREACH(sp, &sessions, entry)
		if (sp->id == id)
			break;
	return (sp);
}

static struct request *
request_find(uint32_t id)
{
	struct request	*r;

	TAILQ_FOREACH(r, &requests, entry)
		if (r->id == id)
			break;
	return (r);
}
