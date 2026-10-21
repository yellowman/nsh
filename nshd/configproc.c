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
 * config: the sessions, from frontend, and what they ask of system,
 * each on its own pipe. Each request to system has an id of its own,
 * with config's generation in its top bits, so an answer meant for a
 * config before this one is known for what it is; system's answers for
 * it go to the session that asked, if that session is still there, its
 * facts passed on unread. system learns when a session's client has
 * read all it was sent, and when the session is gone, so it stops what
 * it streams the session. When frontend starts again, every session is
 * gone; when system does, what it was asked is lost. A peer that sends
 * what it may not, or sends it wrong, is reported, as it went wrong.
 *
 * A session in configure private has nsh's state of its own (session.c),
 * and config runs its lines through nsh's code in candidate mode, which
 * reads no kernel, no file and no program here: the running
 * configuration and what the lines read of the kernel are a snapshot's,
 * system's, taken when a session enters configure private or shows its
 * candidate, and kept for every session until the next.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

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
#include "facts.h"
#include "kfacts.h"
#include "session.h"

#define SNAPSHOT_TEXT	(16 * 1024 * 1024)	/* a snapshot's, at most */

/* what a session waits on a snapshot for */
enum { WAIT_NONE, WAIT_CONFIGURE, WAIT_CANDIDATE };

struct session {
	TAILQ_ENTRY(session)	 entry;
	uint32_t		 id;
	uid_t			 uid;
	gid_t			 gid;
	struct session_state	*st;	/* nsh's, once in configure */
	int			 waits;
};

/* a request system has not finished, and the session that asked it */
struct request {
	TAILQ_ENTRY(request)	 entry;
	uint32_t		 id;
	uint32_t		 session;	/* or 0, a snapshot config keeps */
};

/* the snapshot sessions wait on, as it comes */
struct snapshot {
	uint32_t		 id;
	char			*text;
	size_t			 len;
	struct kfacts		*kf;
	struct facts_in		 in;
	int			 bad;
};

static TAILQ_HEAD(, session)	sessions = TAILQ_HEAD_INITIALIZER(sessions);
static TAILQ_HEAD(, request)	requests = TAILQ_HEAD_INITIALIZER(requests);
static uint32_t			request_id;
static struct snapshot		*snap;
static struct kfacts		*kf_now;	/* the last snapshot's */

#define REQUEST_GEN_SHIFT	24	/* generation above, count below */
#define REQUEST_COUNT		((1U << REQUEST_GEN_SHIFT) - 1)

static struct imsgev	*iev_relay;

static void		 config_dispatch_relay(int, short, void *);
static void		 config_dispatch_frontend(int, short, void *);
static void		 config_dispatch_system(int, short, void *);
static void		 config_forget_frontend(void);
static void		 config_forget_system(void);
static void		 config_show(uint32_t, struct nshd_show *);
static void		 config_configure(uint32_t, struct nshd_configure *);
static void		 config_line(uint32_t, struct nshd_line *);
static void		 config_exit(uint32_t);
static void		 config_wait(struct session *, int);
static void		 config_snapshot(struct request *, uint32_t,
			    struct ibuf *);
static void		 config_snapshot_done(int32_t);
static void		 config_snapshot_lost(const char *);
static void		 config_ran(struct session *, int, int);
static void		 config_answer(uint32_t, int32_t, const char *, ...)
			    __attribute__((__format__ (printf, 3, 4)));
static void		 config_tell(uint32_t, uint32_t);
static struct request	*config_request(uint32_t);
static void		 session_gone(struct session *);
static struct session	*session_find(uint32_t);
static struct request	*request_find(uint32_t);

static struct link	 links[] = {
#define FRONTEND	0
	{ PROC_FRONTEND, config_dispatch_frontend, config_forget_frontend },
#define SYSTEM		1
	{ PROC_SYSTEM,	 config_dispatch_system,   config_forget_system },
};

void
configproc(int debug, int verbose)
{
	child_start("config", debug, verbose);
	capture_stdout();
	privdrop(PROC_CONFIG);
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	/* nsh's code here asks no kernel, opens no file, runs no program */
	in_config = 1;

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
	struct nshd_configure	 cf;
	struct nshd_line	 line;
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
		case IMSG_CTL_CONFIGURE:
			if (imsg_get_data(&imsg, &cf, sizeof(cf)) == -1)
				goto bad;
			config_configure(id, &cf);
			break;
		case IMSG_CTL_LINE:
			if (imsg_get_data(&imsg, &line, sizeof(line)) == -1 ||
			    memchr(line.line, '\0', sizeof(line.line)) == NULL)
				goto bad;
			config_line(id, &line);
			break;
		case IMSG_CTL_EXIT:
			if (imsg_get_len(&imsg) != 0)
				goto bad;
			config_exit(id);
			break;
		case IMSG_CTL_CLOSE:
			if ((sp = session_find(id)) != NULL)
				session_gone(sp);
			config_tell(id, IMSG_SYS_STOP);
			break;
		case IMSG_CTL_READ:
			config_tell(id, IMSG_SYS_READ);
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

/* system's answers, each for a request */
static void
config_dispatch_system(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct link		*l = &links[SYSTEM];
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
		case IMSG_SYS_TEXT:
		case IMSG_SYS_FACTS:
			/* for a config before this one, or a request failed */
			if (r == NULL)
				break;
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			if (snap != NULL && r->id == snap->id) {
				config_snapshot(r, type, &b);
				break;
			}
			if (session_find(r->session) != NULL &&
			    link_compose(&links[FRONTEND],
			    type == IMSG_SYS_TEXT ? IMSG_CTL_OUTPUT :
			    IMSG_CTL_FACTS, r->session, ibuf_data(&b),
			    ibuf_size(&b)) == -1)
				fatal("%s", __func__);
			break;
		case IMSG_SYS_END:
			if (imsg_get_data(&imsg, &res, sizeof(res)) == -1)
				goto bad;
			if (r == NULL)
				break;
			TAILQ_REMOVE(&requests, r, entry);
			if (snap != NULL && r->id == snap->id)
				config_snapshot_done(res.status);
			else if (session_find(r->session) != NULL)
				config_answer(r->session, res.status, NULL);
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
	struct nshd_snapshot	 ns = { 0 };
	struct session		*sp;
	struct request		*r;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if (strcmp(show->words, "candidate-config") == 0) {
		if (sp->st == NULL) {
			config_answer(session, 1,
			    "%% Not in configure private\n");
			return;
		}
		config_wait(sp, WAIT_CANDIDATE);
		return;
	}
	if (links[SYSTEM].down) {
		config_answer(session, 1, "%% nshd: system is down\n");
		return;
	}
	if ((r = config_request(session)) == NULL)
		return;
	/* system answers the rest with facts, or says it does not */
	if ((strcmp(show->words, "running-config") == 0 ?
	    link_compose(&links[SYSTEM], IMSG_SYS_SNAPSHOT, r->id, &ns,
	    sizeof(ns)) :
	    link_compose(&links[SYSTEM], IMSG_SYS_SHOW, r->id, show,
	    sizeof(*show))) == -1)
		fatal("%s", __func__);
}

/* configure private: the session's candidate, once a snapshot is in */
static void
config_configure(uint32_t session, struct nshd_configure *cf)
{
	struct session	*sp;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if (cf->mode != NSHD_PRIVATE) {
		config_answer(session, 1,
		    "%% nshd: configure private, and no other, for now\n");
		return;
	}
	if (sp->st == NULL && (sp->st = session_new()) == NULL)
		fatal("%s", __func__);
	config_wait(sp, WAIT_CONFIGURE);
}

/* a line, in the session's mode, as nsh runs it */
static void
config_line(uint32_t session, struct nshd_line *line)
{
	struct session	*sp;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if (sp->st == NULL) {
		config_answer(session, 1,
		    "%% nshd: configure private first\n");
		return;
	}
	config_ran(sp, session_line(sp->st, line->line), 1);
}

/* leave configure private, from any of its modes */
static void
config_exit(uint32_t session)
{
	struct session	*sp;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	config_ran(sp, sp->st == NULL ? 0 : session_exit(sp->st), 1);
}

/*
 * sp waits on a snapshot for what, which runs when it is in; a snapshot
 * system already makes will do
 */
static void
config_wait(struct session *sp, int what)
{
	struct nshd_snapshot	 ns = { 1 };
	struct request		*r;

	if (links[SYSTEM].down) {
		config_answer(sp->id, 1, "%% nshd: system is down\n");
		return;
	}
	sp->waits = what;
	if (snap != NULL)
		return;
	if ((r = config_request(0)) == NULL) {
		sp->waits = WAIT_NONE;
		return;
	}
	if ((snap = calloc(1, sizeof(*snap))) == NULL ||
	    (snap->kf = calloc(1, sizeof(*snap->kf))) == NULL)
		fatal("%s", __func__);
	snap->id = r->id;
	facts_in_init(&snap->in, kfacts_record, snap->kf);
	if (link_compose(&links[SYSTEM], IMSG_SYS_SNAPSHOT, r->id, &ns,
	    sizeof(ns)) == -1)
		fatal("%s", __func__);
}

/* a snapshot's text or facts, kept as they come */
static void
config_snapshot(struct request *r, uint32_t type, struct ibuf *b)
{
	char	*p;

	if (snap->bad)
		return;
	if (type == IMSG_SYS_FACTS) {
		if (facts_read(&snap->in, ibuf_data(b), ibuf_size(b)) == -1)
			snap->bad = 1;
		return;
	}
	if (ibuf_size(b) > SNAPSHOT_TEXT - snap->len) {
		snap->bad = 1;
		return;
	}
	if ((p = realloc(snap->text, snap->len + ibuf_size(b))) == NULL)
		fatal("%s", __func__);
	snap->text = p;
	memcpy(snap->text + snap->len, ibuf_data(b), ibuf_size(b));
	snap->len += ibuf_size(b);
}

/* the snapshot is in, or not: what each session waits on it for runs */
static void
config_snapshot_done(int32_t status)
{
	struct session	*sp;
	struct snapshot	*s = snap;
	int		 r, mode;

	snap = NULL;
	facts_in_free(&s->in);
	if (status != 0 || s->bad || s->kf->failed ||
	    session_running(s->text, s->len) == -1) {
		printed_text(NULL, 0, 0);
		kfacts_free(s->kf);
		free(s->text);
		free(s);
		config_snapshot_lost("% nshd: the running configuration "
		    "could not be read\n");
		return;
	}
	kfacts_set(s->kf);
	kfacts_free(kf_now);
	kf_now = s->kf;
	free(s->text);
	free(s);
	TAILQ_FOREACH(sp, &sessions, entry) {
		switch (sp->waits) {
		case WAIT_CONFIGURE:
			r = session_configure(sp->st);
			mode = 1;
			break;
		case WAIT_CANDIDATE:
			r = session_candidate(sp->st);
			mode = 0;
			break;
		default:
			continue;
		}
		sp->waits = WAIT_NONE;
		config_ran(sp, r, mode);
	}
}

/* the snapshot sessions waited on is lost, as msg says */
static void
config_snapshot_lost(const char *msg)
{
	struct session	*sp;

	TAILQ_FOREACH(sp, &sessions, entry)
		if (sp->waits != WAIT_NONE) {
			sp->waits = WAIT_NONE;
			config_answer(sp->id, 1, "%s", msg);
		}
}

/*
 * What nsh's code printed for sp, with mode its mode, and r, as a
 * handler returns it: 0, or -1 when it failed
 */
static void
config_ran(struct session *sp, int r, int mode)
{
	struct nshd_context	 c;
	int			 private, rtable, bridge;

	memset(&c, 0, sizeof(c));
	if (sp->st != NULL) {
		session_mode(sp->st, &private, &rtable, c.ifname,
		    sizeof(c.ifname), &bridge);
		c.mode = private ? NSHD_PRIVATE : 0;
		c.rtable = rtable;
		c.bridge = bridge;
	}
	if (printed_text(links[FRONTEND].iev, IMSG_CTL_OUTPUT, sp->id) == -1)
		r = -1;
	if (mode && link_compose(&links[FRONTEND], IMSG_CTL_CONTEXT, sp->id,
	    &c, sizeof(c)) == -1)
		fatal("%s", __func__);
	config_answer(sp->id, r == -1 ? -1 : 0, NULL);
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
		config_tell(sp->id, IMSG_SYS_STOP);
		session_gone(sp);
	}
	/* no session again has 0, and a new one may have the id */
	TAILQ_FOREACH(r, &requests, entry)
		r->session = 0;
}

/* system started again, or is down: what it was asked is lost */
static void
config_forget_system(void)
{
	struct request	*r;
	const char	*lost = links[SYSTEM].down ?
	    "% nshd: system is down\n" :
	    "% nshd: system started again, and its answer is lost\n";

	while ((r = TAILQ_FIRST(&requests)) != NULL) {
		if (r->session != 0 && session_find(r->session) != NULL)
			config_answer(r->session, 1, "%s", lost);
		TAILQ_REMOVE(&requests, r, entry);
		free(r);
	}
	if (snap != NULL) {
		facts_in_free(&snap->in);
		kfacts_free(snap->kf);
		free(snap->text);
		free(snap);
		snap = NULL;
		config_snapshot_lost(lost);
	}
}

/* to system: type, for each request of session not finished */
static void
config_tell(uint32_t session, uint32_t type)
{
	struct request	*r;

	TAILQ_FOREACH(r, &requests, entry)
		if (r->session == session && link_compose(&links[SYSTEM],
		    type, r->id, NULL, 0) == -1)
			fatal("%s", __func__);
}

/*
 * A request of session's, or config's own if 0, with an id of its own;
 * NULL, said, when the ids are exhausted
 */
static struct request *
config_request(uint32_t session)
{
	struct request	*r;

	if ((request_id & REQUEST_COUNT) == REQUEST_COUNT) {
		if (session != 0)
			config_answer(session, 1,
			    "%% nshd: request ids exhausted\n");
		else
			config_snapshot_lost("% nshd: request ids exhausted\n");
		return (NULL);
	}
	if ((r = calloc(1, sizeof(*r))) == NULL)
		fatal(NULL);
	r->id = ++request_id;
	r->session = session;
	TAILQ_INSERT_TAIL(&requests, r, entry);
	return (r);
}

/* sp is gone, and the candidate it had */
static void
session_gone(struct session *sp)
{
	TAILQ_REMOVE(&sessions, sp, entry);
	session_free(sp->st);
	free(sp);
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
