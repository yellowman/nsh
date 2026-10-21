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
 *
 * A commit is one at a time, of all sessions': config plans it from a
 * snapshot, system tests the daemons' rules it changes (TEST), then
 * records it (BEGIN), runs its script (APPLY) and, if a snapshot after
 * reads as the candidate, saves what runs (SAVE); if not, it runs the
 * script back, and the record goes (RECORD). It runs to its end if its
 * session goes. commit check stops after the tests.
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

#define IDS_GONE	"% nshd: request ids exhausted\n"

#if NSHD_CLEARS != PLAN_CLEARS
#error "NSHD_CLEARS is not PLAN_CLEARS"
#endif

/* what a session waits on a snapshot for */
enum { WAIT_NONE, WAIT_CONFIGURE, WAIT_CANDIDATE, WAIT_RESET };

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
	int			 kind;
	int			 n;		/* rollback n's */
	char			*text;		/* and its text, as it comes */
	size_t			 len;
	int			 bad;		/* past NSHD_PART */
};

/* what a request's end does: answer the session, or what follows */
enum { REQ_ANSWER, REQ_COMMIT, REQ_ROLLBACK };

/* the commit, and what it waits on */
enum {
	COMMIT_PLAN,		/* a snapshot, to plan from */
	COMMIT_TEST,		/* a daemon's test of its rules */
	COMMIT_BEGIN,		/* the record made */
	COMMIT_APPLY,		/* the script run */
	COMMIT_VERIFY,		/* a snapshot, to verify */
	COMMIT_SAVE,		/* what runs saved */
	COMMIT_UNDO,		/* the script back run */
	COMMIT_BACK,		/* a snapshot, to verify that */
	COMMIT_RECORD		/* the record gone */
};

struct commit {
	uint32_t		 session;	/* or 0, gone */
	uid_t			 uid;
	int			 step;
	int			 waits;		/* on a snapshot */
	int			 check;		/* commit check */
	int			 test;		/* the plan's test running */
	int			 failed;	/* a line of the script failed */
	char			 comment[NSHD_COMMENT];
	struct plan		*plan;
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
static struct commit		*commit;	/* the one running, or NULL */

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
static void		 config_commit(uint32_t, struct nshd_commit *);
static void		 config_rollback(uint32_t, struct nshd_rollback *);
static void		 config_rolled(struct request *, int32_t);
static struct session	*config_private(uint32_t);
static void		 config_wait(struct session *, int);
static void		 snapshot_take(void);
static void		 config_snapshot(struct request *, uint32_t,
			    struct ibuf *);
static void		 config_snapshot_done(int32_t);
static void		 config_snapshot_lost(const char *);
static void		 config_ran(struct session *, int, int);
static void		 config_answer(uint32_t, int32_t, const char *, ...)
			    __attribute__((__format__ (printf, 3, 4)));
static void		 config_tell(uint32_t, uint32_t);
static struct request	*config_request(uint32_t, int);
static void		 commit_wait(int);
static void		 commit_snapshot(void);
static void		 commit_ended(int32_t);
static void		 commit_test(int);
static void		 commit_go(void);
static int		 commit_part(int32_t, const char *, size_t);
static void		 commit_apply(int);
static void		 commit_save(void);
static void		 commit_request(int, uint32_t, const void *, size_t);
static void		 commit_end(int, const char *);
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
	struct nshd_commit	 cm;
	struct nshd_rollback	 rb;
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
		case IMSG_CTL_COMMIT:
			if (imsg_get_data(&imsg, &cm, sizeof(cm)) == -1 ||
			    memchr(cm.comment, '\0', sizeof(cm.comment)) == NULL)
				goto bad;
			config_commit(id, &cm);
			break;
		case IMSG_CTL_ROLLBACK:
			if (imsg_get_data(&imsg, &rb, sizeof(rb)) == -1)
				goto bad;
			config_rollback(id, &rb);
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
	char			*p;

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
			if (r->kind == REQ_ROLLBACK) {
				if (type != IMSG_SYS_TEXT)
					goto bad;
				if (ibuf_size(&b) > NSHD_PART - r->len) {
					r->bad = 1;
					break;
				}
				if ((p = realloc(r->text, r->len +
				    ibuf_size(&b))) == NULL)
					fatal("%s", __func__);
				r->text = p;
				memcpy(r->text + r->len, ibuf_data(&b),
				    ibuf_size(&b));
				r->len += ibuf_size(&b);
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
			else if (r->kind == REQ_COMMIT) {
				if (commit != NULL)
					commit_ended(res.status);
			} else if (r->kind == REQ_ROLLBACK)
				config_rolled(r, res.status);
			else if (session_find(r->session) != NULL)
				config_answer(r->session, res.status, NULL);
			free(r->text);
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
	struct nshd_rollback	 rb = { -1 };
	struct session		*sp;
	struct request		*r;
	const char		*errstr;
	uint32_t		 type = IMSG_SYS_SHOW;
	const void		*data = show;
	size_t			 len = sizeof(*show);

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
	if (strcmp(show->words, "running-config") == 0) {
		type = IMSG_SYS_SNAPSHOT;
		data = &ns;
		len = sizeof(ns);
	} else if (strcmp(show->words, "rollback") == 0) {
		type = IMSG_SYS_ROLLBACK_LIST;
		data = NULL;
		len = 0;
	} else if (strncmp(show->words, "rollback ", 9) == 0) {
		rb.n = strtonum(show->words + 9, 0, NSHD_ROLLBACKS - 1,
		    &errstr);
		if (errstr != NULL) {
			config_answer(session, 1, "%% rollback %s is %s\n",
			    show->words + 9, errstr);
			return;
		}
		type = IMSG_SYS_ROLLBACK_READ;
		data = &rb;
		len = sizeof(rb);
	}
	if ((r = config_request(session, REQ_ANSWER)) == NULL) {
		config_answer(session, 1, "%s", IDS_GONE);
		return;
	}
	/* system answers the rest with facts, or says it does not */
	if (link_compose(&links[SYSTEM], type, r->id, data, len) == -1)
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

/* commit, or commit check, of the session's candidate */
static void
config_commit(uint32_t session, struct nshd_commit *c)
{
	struct session	*sp;

	if ((sp = config_private(session)) == NULL)
		return;
	if (commit != NULL) {
		config_answer(session, 1, "%% Commit refused: uid %u commits "
		    "now\n", (unsigned int)commit->uid);
		return;
	}
	if ((commit = calloc(1, sizeof(*commit))) == NULL)
		fatal(NULL);
	commit->session = session;
	commit->uid = sp->uid;
	commit->check = c->check;
	strlcpy(commit->comment, c->comment, sizeof(commit->comment));
	commit_wait(COMMIT_PLAN);
}

/*
 * rollback n: the session's candidate starts over as configuration n
 * as it was saved, which system reads, or as what runs if n is 0
 */
static void
config_rollback(uint32_t session, struct nshd_rollback *rb)
{
	struct session	*sp;
	struct request	*r;

	if ((sp = config_private(session)) == NULL)
		return;
	if (rb->n < 0 || rb->n >= NSHD_ROLLBACKS) {
		config_answer(session, 1, "%% rollback [0-%d]\n",
		    NSHD_ROLLBACKS - 1);
		return;
	}
	if (rb->n == 0) {
		config_wait(sp, WAIT_RESET);
		return;
	}
	if (links[SYSTEM].down) {
		config_answer(session, 1, "%% nshd: system is down\n");
		return;
	}
	if ((r = config_request(session, REQ_ROLLBACK)) == NULL) {
		config_answer(session, 1, "%s", IDS_GONE);
		return;
	}
	r->n = rb->n;
	if (link_compose(&links[SYSTEM], IMSG_SYS_ROLLBACK_READ, r->id, rb,
	    sizeof(*rb)) == -1)
		fatal("%s", __func__);
}

/* rollback n's text is in, or why not */
static void
config_rolled(struct request *r, int32_t status)
{
	struct session	*sp;

	if ((sp = session_find(r->session)) == NULL)
		return;
	if (status == 0 && r->bad) {
		config_answer(sp->id, 1, "%% nshd: rollback %d is past %d "
		    "bytes\n", r->n, NSHD_PART);
		return;
	}
	if (status != 0) {
		if (imsg_text(links[FRONTEND].iev, IMSG_CTL_OUTPUT, sp->id,
		    r->text, r->len) == -1)
			fatal("%s", __func__);
		config_answer(sp->id, 1, NULL);
		return;
	}
	config_ran(sp, session_rollback(sp->st, r->text, r->len, r->n), 1);
}

/* session's, if in configure private; or NULL, said why */
static struct session *
config_private(uint32_t session)
{
	struct session	*sp;
	char		 ifn[NSHD_IFNAME];
	int		 private = 0, rtable, bridge;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return (NULL);
	}
	if (sp->st != NULL)
		session_mode(sp->st, &private, &rtable, ifn, sizeof(ifn),
		    &bridge);
	if (!private) {
		config_answer(session, 1,
		    "%% nshd: configure private first\n");
		return (NULL);
	}
	return (sp);
}

/* sp waits on a snapshot for what, which runs when it is in */
static void
config_wait(struct session *sp, int what)
{
	sp->waits = what;
	snapshot_take();
}

/*
 * A snapshot, for the sessions and the commit that wait on it, unless
 * system makes one already, which will do; if none can be, they are told
 */
static void
snapshot_take(void)
{
	struct nshd_snapshot	 ns = { 1 };
	struct request		*r;

	if (snap != NULL)
		return;
	if (links[SYSTEM].down) {
		config_snapshot_lost("% nshd: system is down\n");
		return;
	}
	if ((r = config_request(0, REQ_ANSWER)) == NULL) {
		config_snapshot_lost(IDS_GONE);
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
		case WAIT_RESET:
			r = session_rollback(sp->st, NULL, 0, 0);
			mode = 1;
			break;
		default:
			continue;
		}
		sp->waits = WAIT_NONE;
		config_ran(sp, r, mode);
	}
	if (commit != NULL && commit->waits)
		commit_snapshot();
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
	if (commit != NULL && commit->waits)
		commit_end(-1, msg);
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

/* the commit waits on a snapshot, at step */
static void
commit_wait(int step)
{
	commit->step = step;
	commit->waits = 1;
	snapshot_take();
}

/* the snapshot the commit waited on is in: its next step */
static void
commit_snapshot(void)
{
	struct session		*sp;
	int			 r;

	commit->waits = 0;
	switch (commit->step) {
	case COMMIT_PLAN:
		if ((sp = session_find(commit->session)) == NULL ||
		    session_plan(sp->st, commit->check, &commit->plan) == -1)
			commit_end(-1, NULL);
		else if (commit->plan == NULL)
			commit_end(0, NULL);
		else if (commit->plan->ntests > 0)
			commit_test(0);
		else
			commit_go();
		break;
	case COMMIT_VERIFY:
		if ((r = session_verify(commit->plan, commit->failed)) == 0)
			commit_save();
		else if (r == 1)
			commit_apply(COMMIT_UNDO);
		else
			commit_end(-1, NULL);
		break;
	case COMMIT_BACK:
		/* if not, the record says it did not finish */
		if (session_verify_back(commit->plan) == 0)
			commit_request(COMMIT_RECORD, IMSG_SYS_RECORD, NULL,
			    0);
		else
			commit_end(-1, NULL);
		break;
	}
}

/* system ended the commit's request: its next step */
static void
commit_ended(int32_t status)
{
	struct session	*sp;
	int		 r;

	switch (commit->step) {
	case COMMIT_TEST:
		session_tested(commit->plan, commit->test, status != 0);
		if (commit->test + 1 < commit->plan->ntests)
			commit_test(commit->test + 1);
		else if (session_verdict(commit->plan) == -1)
			commit_end(-1, NULL);
		else if (commit->check)
			commit_end(0, NULL);
		else
			commit_go();
		break;
	case COMMIT_BEGIN:
		if (status != 0)
			commit_end(-1, NULL);
		else
			commit_apply(COMMIT_APPLY);
		break;
	case COMMIT_APPLY:
		commit->failed = status != 0;
		commit_wait(COMMIT_VERIFY);
		break;
	case COMMIT_UNDO:
		commit_wait(COMMIT_BACK);
		break;
	case COMMIT_SAVE:
		/* taken: the candidate starts again, saved or not */
		r = status == 0 ? 0 : -1;
		if ((sp = session_find(commit->session)) != NULL &&
		    session_renew(sp->st) == -1)
			r = -1;
		commit_end(r, NULL);
		break;
	case COMMIT_RECORD:
		commit_end(-1, NULL);
		break;
	}
}

/* the plan's nth test of a daemon's rules, which system runs */
static void
commit_test(int n)
{
	struct plan_test	*t = &commit->plan->tests[n];
	struct nshd_test	 nt;

	commit->test = n;
	memset(&nt, 0, sizeof(nt));
	strlcpy(nt.name, t->name, sizeof(nt.name));
	if (commit_part(NSHD_SCRIPT, t->text, t->len) == -1)
		return;
	commit_request(COMMIT_TEST, IMSG_SYS_TEST, &nt, sizeof(nt));
}

/* the plan checked: what runs saved, if it is the candidate, or begun */
static void
commit_go(void)
{
	struct plan		*p = commit->plan;
	struct nshd_begin	 b;

	if (p->same) {
		commit_save();
		return;
	}
	if (commit_part(NSHD_BEFORE, p->text[PLAN_BEFORE],
	    p->len[PLAN_BEFORE]) == -1 || commit_part(NSHD_WANT,
	    p->text[PLAN_WANT], p->len[PLAN_WANT]) == -1)
		return;
	b.uid = commit->uid;
	commit_request(COMMIT_BEGIN, IMSG_SYS_BEGIN, &b, sizeof(b));
}

/* a part of the commit's, to system, as chunks: -1 if too long, said */
static int
commit_part(int32_t part, const char *text, size_t len)
{
	struct nshd_chunk	 c = { part };
	char			 buf[sizeof(c) + NSHD_TEXT];
	size_t			 n;

	if (len > NSHD_PART) {
		commit_end(-1, "% Commit refused: the configuration is past "
		    "what nshd takes\n");
		return (-1);
	}
	memcpy(buf, &c, sizeof(c));
	while (len > 0) {
		n = len < NSHD_TEXT ? len : NSHD_TEXT;
		memcpy(buf + sizeof(c), text, n);
		if (link_compose(&links[SYSTEM], IMSG_SYS_SCRIPT, 0, buf,
		    sizeof(c) + n) == -1)
			fatal("%s", __func__);
		text += n;
		len -= n;
	}
	return (0);
}

/* the plan's script, run by system, at step */
static void
commit_apply(int step)
{
	struct nshd_apply	 a;
	struct plan		*p = commit->plan;
	int			 i;

	memset(&a, 0, sizeof(a));
	a.nclears = p->nclears;
	for (i = 0; i < p->nclears; i++) {
		strlcpy(a.clears[i].name, p->clears[i].name,
		    sizeof(a.clears[i].name));
		a.clears[i].rtable = p->clears[i].rtable;
		a.clears[i].keep = p->clears[i].keep;
	}
	if (commit_part(NSHD_SCRIPT, p->text[PLAN_SCRIPT],
	    p->len[PLAN_SCRIPT]) == -1)
		return;
	commit_request(step, IMSG_SYS_APPLY, &a, sizeof(a));
}

/* what runs, saved by system, with who commits and their comment */
static void
commit_save(void)
{
	struct nshd_save	 sv;

	memset(&sv, 0, sizeof(sv));
	sv.uid = commit->uid;
	strlcpy(sv.comment, commit->comment, sizeof(sv.comment));
	commit_request(COMMIT_SAVE, IMSG_SYS_SAVE, &sv, sizeof(sv));
}

/*
 * A request of the commit's, to system, whose end it waits on at step,
 * after what nsh's code printed for it
 */
static void
commit_request(int step, uint32_t type, const void *data, size_t len)
{
	struct request	*r;

	printed_text(session_find(commit->session) != NULL ?
	    links[FRONTEND].iev : NULL, IMSG_CTL_OUTPUT, commit->session);
	if (links[SYSTEM].down) {
		commit_end(-1, "% nshd: system is down\n");
		return;
	}
	if ((r = config_request(commit->session, REQ_COMMIT)) == NULL) {
		commit_end(-1, IDS_GONE);
		return;
	}
	commit->step = step;
	if (link_compose(&links[SYSTEM], type, r->id, data, len) == -1)
		fatal("%s", __func__);
}

/*
 * The commit ends, r as a handler returns it, or with msg said after
 * what nsh's code printed for it
 */
static void
commit_end(int r, const char *msg)
{
	struct commit	*c = commit;
	struct session	*sp;

	commit = NULL;
	if ((sp = session_find(c->session)) == NULL)
		printed_text(NULL, 0, 0);
	else if (msg != NULL) {
		printed_text(links[FRONTEND].iev, IMSG_CTL_OUTPUT, sp->id);
		config_answer(sp->id, 1, "%s", msg);
	} else
		config_ran(sp, r, 1);
	plan_free(c->plan);
	free(c);
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
	if (commit != NULL)
		commit->session = 0;
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
		if (r->kind != REQ_COMMIT && r->session != 0 &&
		    session_find(r->session) != NULL)
			config_answer(r->session, 1, "%s", lost);
		TAILQ_REMOVE(&requests, r, entry);
		free(r->text);
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
	if (commit != NULL)
		commit_end(-1, lost);
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
 * A request of session's, or config's own if 0, of kind, with an id of
 * its own; NULL when the ids are exhausted
 */
static struct request *
config_request(uint32_t session, int kind)
{
	struct request	*r;

	if ((request_id & REQUEST_COUNT) == REQUEST_COUNT)
		return (NULL);
	if ((r = calloc(1, sizeof(*r))) == NULL)
		fatal(NULL);
	r->id = ++request_id;
	r->session = session;
	r->kind = kind;
	TAILQ_INSERT_TAIL(&requests, r, entry);
	return (r);
}

/* sp is gone, and the candidate it had; a commit of its runs on */
static void
session_gone(struct session *sp)
{
	if (commit != NULL && commit->session == sp->id)
		commit->session = 0;
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
