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
 * config: the sessions, and what they ask of kernel, all through relay.
 * Each request to kernel has an id of its own; kernel's answers for it
 * go to the session that asked, if that session is still there.
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

static struct imsgev	*iev_relay;

static void		 config_dispatch_relay(int, short, void *);
static void		 config_show(uint32_t, struct nshd_show *);
static void		 config_answer(uint32_t, int32_t, const char *, ...)
			    __attribute__((__format__ (printf, 3, 4)));
static struct session	*session_find(uint32_t);
static struct request	*request_find(uint32_t);

void
configproc(int debug, int verbose)
{
	child_start("config", debug, verbose);
	privdrop();
	if (pledge("stdio", NULL) == -1)
		fatal("pledge");

	if ((iev_relay = imsgev_new(3, config_dispatch_relay, 0)) == NULL)
		fatal(NULL);
	event_dispatch();
	exit(0);
}

/* frontend's requests and kernel's answers, through relay */
static void
config_dispatch_relay(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct ibuf		 b;
	struct nshd_peer	 peer;
	struct nshd_session	 s;
	struct nshd_show	 show;
	struct nshd_result	 res;
	struct session		*sp;
	struct request		*r;
	uint32_t		 id;
	ssize_t			 n;

	if (imsgev_io(iev, event) == -1)
		exit(0);

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		id = imsg_get_id(&imsg);
		switch (imsg_get_type(&imsg)) {
		case IMSG_STARTUP:
			break;
		case IMSG_CTL_HELLO:
			if (imsg_get_data(&imsg, &peer, sizeof(peer)) == -1)
				fatalx("%s: bad IMSG_CTL_HELLO", __func__);
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
			if (imsg_compose_event(iev_relay, IMSG_CTL_HELLO, id, 0,
			    -1, &s, sizeof(s)) == -1)
				fatal("%s", __func__);
			break;
		case IMSG_CTL_SHOW:
			if (imsg_get_data(&imsg, &show, sizeof(show)) == -1 ||
			    memchr(show.words, '\0', sizeof(show.words)) ==
			    NULL)
				fatalx("%s: bad IMSG_CTL_SHOW", __func__);
			config_show(id, &show);
			break;
		case IMSG_CTL_CLOSE:
			if ((sp = session_find(id)) != NULL) {
				TAILQ_REMOVE(&sessions, sp, entry);
				free(sp);
			}
			break;
		case IMSG_KRN_TEXT:
			if ((r = request_find(id)) == NULL ||
			    imsg_get_ibuf(&imsg, &b) == -1)
				fatalx("%s: bad IMSG_KRN_TEXT", __func__);
			if (session_find(r->session) != NULL &&
			    imsg_compose_event(iev_relay, IMSG_CTL_OUTPUT,
			    r->session, 0, -1, ibuf_data(&b), ibuf_size(&b)) ==
			    -1)
				fatal("%s", __func__);
			break;
		case IMSG_KRN_END:
			if ((r = request_find(id)) == NULL ||
			    imsg_get_data(&imsg, &res, sizeof(res)) == -1)
				fatalx("%s: bad IMSG_KRN_END", __func__);
			if (session_find(r->session) != NULL)
				config_answer(r->session, res.status, NULL);
			TAILQ_REMOVE(&requests, r, entry);
			free(r);
			break;
		default:
			log_debug("%s: unexpected imsg %u", __func__,
			    imsg_get_type(&imsg));
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

static void
config_show(uint32_t session, struct nshd_show *show)
{
	struct request	*r;

	if (session_find(session) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if (strcmp(show->words, "running-config") != 0) {
		config_answer(session, 1, "%% show %s: not answered by nshd\n",
		    show->words);
		return;
	}
	if (request_id == UINT32_MAX) {
		config_answer(session, 1, "%% nshd: request ids exhausted\n");
		return;
	}
	if ((r = calloc(1, sizeof(*r))) == NULL)
		fatal(NULL);
	r->id = ++request_id;
	r->session = session;
	TAILQ_INSERT_TAIL(&requests, r, entry);
	if (imsg_compose_event(iev_relay, IMSG_KRN_SNAPSHOT, r->id, 0, -1,
	    NULL, 0) == -1)
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
		if (imsg_text(iev_relay, IMSG_CTL_OUTPUT, session, s,
		    len) == -1)
			fatal("%s", __func__);
		free(s);
	}
	r.status = status;
	if (imsg_compose_event(iev_relay, IMSG_CTL_RESULT, session, 0, -1,
	    &r, sizeof(r)) == -1)
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
