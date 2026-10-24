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
 * session: the web users logged in, each with a connection of nshd's,
 * which parent makes, and a token, which the user's cookie carries.
 * session reads what front sends as a stranger's: each message whole,
 * each string with its NUL, each number in its range.
 *
 * A login asks parent for a connection, says hello, and logs in, as
 * nshd's system checks; then hello again, for the permissions the
 * user's class gives, and the user's token, 32 random bytes in hex.
 * Each request of a user's goes to nshd on that user's connection, one
 * at a time, the rest waiting; nshd's answer comes back as JSON, which
 * session writes and never reads: the records of a show as it comes,
 * then what nshd printed, and how it ended. While front has not written
 * DECK_WINDOW messages of an answer, session stops reading nshd's. A
 * show nshd's system says it does not answer is asked again of nshd's
 * shows, as nsh asks them, on a connection of its own, which parent
 * makes, and which closes when it is answered.
 *
 * A user's event streams have nshd watch commits, interfaces and routes,
 * and the logs any of them follows, and each notice nshd sends goes to each
 * stream as an event, a log's only to those that follow it. A user with
 * no stream and nothing asked for DECK_IDLE seconds is logged out, as a
 * logout does, which closes the connection: nshd forgets the login, and
 * the candidate, with it. If nshd closes it, the user is logged out.
 *
 * session completes lines itself, in the user's mode, with nsh's code
 * (tables.c), as nsh's Tab does.  It asks nshd for nsh's command tables
 * once, and for the names of interfaces, groups, bridges and routing
 * tables on each completion.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "facts.h"
#include "nshdeck.h"

#define DECK_QUEUE	16		/* a user's requests waiting, at most */
#define DECK_OUTPUT	(1024 * 1024)	/* what nshd printed, kept, at most */
#define DECK_CHUNK	8192		/* JSON sent front at once, about */
#define DECK_FAILS	32		/* failed logins remembered, by user */
#define DECK_QUIET	10		/* seconds between a user's logged fails */

/* a literal, to JSON j */
#define J(j, s)		j_raw((j), (s), sizeof(s) - 1)

/* JSON, as it is written, until it is sent */
struct jbuf {
	char			*p;
	size_t			 len;
	size_t			 size;		/* p's */
};

/* how far a user's login is */
enum { U_CONNECT, U_HELLO, U_LOGIN, U_WHO, U_READY };

/* how far a show asked of nshd's shows is, or that it was */
enum { RO_NONE, RO_CONNECT, RO_HELLO, RO_SHOW, RO_DONE };

/* a request of a user's, waiting or answered, or session's own watch */
struct pending {
	TAILQ_ENTRY(pending)	 entry;
	uint32_t		 id;		/* front's, or 0: a watch */
	int			 gone;		/* front's client is gone */
	struct deck_request	 r;
};

/* an event stream of a user's */
struct stream {
	TAILQ_ENTRY(stream)	 entry;
	uint32_t		 id;
	int			 logs;		/* NSHD_WATCH_* it follows */
};

struct user {
	TAILQ_ENTRY(user)	 entry;
	char			 token[DECK_TOKEN + 1];
	char			 name[NSHD_NAME];
	int			 state;
	int			 perms;
	uint32_t		 connect;	/* the id parent connects for */
	struct deck_pipe	 nshd;
	int			 hasnshd;
	struct deck_pipe	 ro;		/* to nshd's shows, for cur */
	int			 toro;		/* RO_* */
	TAILQ_HEAD(, pending)	 queue;
	int			 nqueue;
	struct pending		*cur;		/* nshd answers it */
	int			 sent;		/* messages front has not written */
	int			 headed;	/* its head sent */
	int			 nrecords;
	struct facts_in		 in;
	struct jbuf		 j;		/* its answer's, to send front */
	char			*out;		/* what nshd printed */
	size_t			 outlen;
	struct nshd_context	 ctx;
	int			 hasctx;
	struct deck_cmplt	*cmplt;		/* what a completion has read */
	int			 naming;	/* its names were asked for */
	TAILQ_HEAD(, stream)	 streams;
	int			 watch;		/* what nshd was asked to watch */
	int			 watching;	/* a watch waits */
	time_t			 used;
};

static TAILQ_HEAD(, user)	 users = TAILQ_HEAD_INITIALIZER(users);
static int			 nusers;
static struct deck_pipe		 toparent, tofront;
static struct event		 ev_idle;
static struct {
	char			 name[NSHD_NAME];
	time_t			 when;
} fails[DECK_FAILS];

static void	 sessions_parent(int, short, void *);
static void	 sessions_front(int, short, void *);
static void	 sessions_nshd(int, short, void *);
static void	 sessions_ro(int, short, void *);
static void	 sessions_idle(int, short, void *);
static void	 request(uint32_t, struct deck_request *);
static void	 login(uint32_t, struct deck_request *);
static void	 connected(uint32_t, int, int);
static void	 logged(struct user *, int32_t);
static void	 next(struct user *);
static void	 ask(struct user *, uint32_t, const void *, size_t);
static void	 answered(struct user *, int32_t);
static void	 kept(struct user *, const void *, size_t);
static int	 facts(struct user *, struct deck_pipe *, struct imsg *);
static void	 unshown(struct user *, const char *);
static void	 ro_close(struct user *);
static struct deck_pipe *answering(struct user *);
static void	 noticed(struct user *, struct ibuf *);
static void	 rewatch(struct user *);
static void	 gone(uint32_t);
static void	 logout(struct user *, const char *);
static void	 record(void *, const struct facts_template *,
		    const struct facts_value *);
static void	 completed(void *, int, const char *, const char *);
static void	 head(uint32_t, int, int, const char *, int);
static void	 reply(uint32_t, int, const char *, ...)
		    __attribute__((__format__ (printf, 3, 4)));
static void	 j_raw(struct jbuf *, const char *, size_t);
static void	 j_str(struct jbuf *, const char *, size_t);
static void	 j_fmt(struct jbuf *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));
static void	 j_who(struct jbuf *, struct user *);
static int	 j_flush(struct jbuf *, uint32_t);
static void	 j_answer(struct user *);
static void	 failed(const char *);
static struct user *user_token(const char *);
static void	 user_free(struct user *);

__dead void
sessions(int debug, int verbose)
{
	deck_child("session", debug, verbose);
	deck_drop(DECK_USER);
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	if (pipe_init(&toparent, 3, sessions_parent, 1) == -1 ||
	    pipe_init(&tofront, 4, sessions_front, 0) == -1)
		fatal(NULL);
	evtimer_set(&ev_idle, sessions_idle, NULL);
	sessions_idle(0, 0, NULL);
	event_dispatch();
	exit(0);
}

/* parent's connections to nshd, each for the login that asked */
static void
sessions_parent(int fd, short event, void *arg)
{
	struct imsg	 imsg;
	int32_t		 serrno;
	int		 n;

	if (pipe_io(&toparent, event) == -1)
		exit(0);
	for (;;) {
		if ((n = imsgbuf_get(&toparent.ibuf, &imsg)) == -1)
			fatalx("parent sent what imsg cannot read");
		if (n == 0)
			break;
		if (imsg_get_type(&imsg) != DECK_CONNECTED ||
		    imsg_get_data(&imsg, &serrno, sizeof(serrno)) == -1)
			fatalx("parent sent imsg %u, which it may not",
			    imsg_get_type(&imsg));
		connected(imsg_get_id(&imsg), imsg_get_fd(&imsg), serrno);
		imsg_free(&imsg);
	}
	pipe_event(&toparent);
}

/* front's requests, and what front says of their clients */
static void
sessions_front(int fd, short event, void *arg)
{
	struct deck_request	 r;
	struct deck_pipe	*from;
	struct imsg		 imsg;
	struct user		*u;
	uint32_t		 id;
	int			 n;

	if (pipe_io(&tofront, event) == -1)
		exit(0);
	for (;;) {
		if ((n = imsgbuf_get(&tofront.ibuf, &imsg)) == -1)
			fatalx("front sent what imsg cannot read");
		if (n == 0)
			break;
		id = imsg_get_id(&imsg);
		switch (imsg_get_type(&imsg)) {
		case DECK_REQUEST:
			/* n: rollback's, an rtable or a configure */
			if (imsg_get_data(&imsg, &r, sizeof(r)) == -1 ||
			    r.kind < DECK_LOGIN || r.kind > DECK_EVENTS ||
			    memchr(r.token, '\0', sizeof(r.token)) == NULL ||
			    memchr(r.text, '\0', sizeof(r.text)) == NULL ||
			    memchr(r.password, '\0', sizeof(r.password)) ==
			    NULL ||
			    memchr(r.comment, '\0', sizeof(r.comment)) ==
			    NULL || r.n < 0 || r.n > 255 ||
			    r.minutes < 0 || r.minutes > NSHD_CONFIRMMAX ||
			    (r.check != 0 && r.check != 1) ||
			    (r.logs & ~NSHD_WATCH_LOGS) != 0)
				fatalx("front sent a request not whole");
			request(id, &r);
			explicit_bzero(&r, sizeof(r));
			break;
		case DECK_READ:
			/* an answer front has written: nshd's read again */
			TAILQ_FOREACH(u, &users, entry)
				if (u->cur != NULL && u->cur->id == id &&
				    (from = answering(u)) != NULL) {
					u->sent = 0;
					from->paused = 0;
					pipe_event(from);
				}
			break;
		case DECK_GONE:
			gone(id);
			break;
		default:
			fatalx("front sent imsg %u, which it may not",
			    imsg_get_type(&imsg));
		}
		imsg_free(&imsg);
	}
	pipe_event(&tofront);
}

/* a request, of a user's, by the token, or a login */
static void
request(uint32_t id, struct deck_request *r)
{
	struct jbuf	 j = { NULL, 0, 0 };
	struct user	*u;
	struct pending	*p;
	struct stream	*s;

	if (r->kind == DECK_LOGIN) {
		login(id, r);
		return;
	}
	if ((u = user_token(r->token)) == NULL) {
		reply(id, 401, "{\"error\":\"not logged in\"}");
		return;
	}
	u->used = time(NULL);
	switch (r->kind) {
	case DECK_LOGOUT:
		head(id, 200, 0, NULL, 1);
		reply(id, 0, "{\"ok\":true}");
		logout(u, NULL);
		return;
	case DECK_WHOAMI:
		head(id, 200, 0, NULL, 0);
		j_who(&j, u);
		j_flush(&j, id);
		pipe_compose(&tofront, DECK_END, id, -1, NULL, 0);
		return;
	case DECK_EVENTS:
		if ((s = calloc(1, sizeof(*s))) == NULL)
			fatal(NULL);
		s->id = id;
		s->logs = r->logs;
		TAILQ_INSERT_TAIL(&u->streams, s, entry);
		head(id, 200, 1, NULL, 0);
		rewatch(u);
		return;
	}
	if (u->nqueue == DECK_QUEUE) {
		reply(id, 503, "{\"error\":\"too many requests waiting\"}");
		return;
	}
	if ((p = calloc(1, sizeof(*p))) == NULL)
		fatal(NULL);
	p->id = id;
	p->r = *r;
	TAILQ_INSERT_TAIL(&u->queue, p, entry);
	u->nqueue++;
	next(u);
}

/* a login: a user, of no token yet, whose connection parent makes */
static void
login(uint32_t id, struct deck_request *r)
{
	struct user	*u;
	struct pending	*p;
	int32_t		 ro = 0;

	if (nusers == DECK_SESSIONS) {
		reply(id, 503, "{\"error\":\"too many logged in\"}");
		return;
	}
	if ((u = calloc(1, sizeof(*u))) == NULL ||
	    (p = calloc(1, sizeof(*p))) == NULL)
		fatal(NULL);
	TAILQ_INIT(&u->queue);
	TAILQ_INIT(&u->streams);
	strlcpy(u->name, r->text, sizeof(u->name));
	u->state = U_CONNECT;
	u->connect = id;
	u->used = time(NULL);
	p->id = id;
	p->r = *r;
	u->cur = p;
	TAILQ_INSERT_TAIL(&users, u, entry);
	nusers++;
	pipe_compose(&toparent, DECK_CONNECT, id, -1, &ro, sizeof(ro));
}

/*
 * parent's connection for login id, or for show id, to nshd's shows, or
 * why there is none
 */
static void
connected(uint32_t id, int fd, int serrno)
{
	struct nshd_hello	 h = { NSHD_VERSION };
	struct user		*u;

	TAILQ_FOREACH(u, &users, entry)
		if ((u->state == U_CONNECT || u->toro == RO_CONNECT) &&
		    u->connect == id)
			break;
	if (u == NULL) {
		if (fd != -1)
			close(fd);
		return;
	}
	if (u->toro == RO_CONNECT && fd == -1) {
		log_warnx("nshd's shows: %s", strerror(serrno));
		unshown(u, "nshd's shows do not answer");
		return;
	}
	if (u->toro == RO_CONNECT) {
		if (pipe_init(&u->ro, fd, sessions_ro, 0) == -1)
			fatal(NULL);
		u->toro = RO_HELLO;
		pipe_compose(&u->ro, IMSG_CTL_HELLO, 0, -1, &h, sizeof(h));
		return;
	}
	if (fd == -1) {
		log_warnx("nshd: %s", strerror(serrno));
		reply(id, 503, "{\"error\":\"nshd does not answer\"}");
		user_free(u);
		return;
	}
	if (pipe_init(&u->nshd, fd, sessions_nshd, 0) == -1)
		fatal(NULL);
	u->hasnshd = 1;
	u->state = U_HELLO;
	pipe_compose(&u->nshd, IMSG_CTL_HELLO, 0, -1, &h, sizeof(h));
}

/* what nshd sends a user: answers, and notices */
static void
sessions_nshd(int fd, short event, void *arg)
{
	struct user		*u, *v;
	struct nshd_session	 s;
	struct nshd_result	 res;
	struct nshd_login	 lg;
	struct nshd_hello	 h = { NSHD_VERSION };
	struct imsg		 imsg;
	struct ibuf		 b;
	int			 n;

	u = NULL;
	TAILQ_FOREACH(v, &users, entry)
		if (&v->nshd == arg)
			u = v;
	if (u == NULL)
		fatalx("%s: from no user", __func__);
	if (pipe_io(&u->nshd, event) == -1) {
		logout(u, "nshd closed the session");
		return;
	}
	for (;;) {
		if ((n = imsgbuf_get(&u->nshd.ibuf, &imsg)) == -1) {
			logout(u, "nshd sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		switch (imsg_get_type(&imsg)) {
		case IMSG_CTL_HELLO:
			if (imsg_get_data(&imsg, &s, sizeof(s)) == -1 ||
			    s.version != NSHD_VERSION ||
			    (u->state != U_HELLO && u->state != U_WHO)) {
				imsg_free(&imsg);
				logout(u, "nshd's hello is not one nshdeck "
				    "knows");
				return;
			}
			if (u->state == U_WHO) {
				u->perms = s.perms;
				logged(u, 0);
				break;
			}
			/* then the login, as system checks it */
			memset(&lg, 0, sizeof(lg));
			strlcpy(lg.name, u->cur->r.text, sizeof(lg.name));
			strlcpy(lg.password, u->cur->r.password,
			    sizeof(lg.password));
			explicit_bzero(u->cur->r.password,
			    sizeof(u->cur->r.password));
			pipe_compose(&u->nshd, IMSG_CTL_LOGIN, 0, -1, &lg,
			    sizeof(lg));
			explicit_bzero(&lg, sizeof(lg));
			u->state = U_LOGIN;
			break;
		case IMSG_CTL_OUTPUT:
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			kept(u, ibuf_data(&b), ibuf_size(&b));
			break;
		case IMSG_CTL_FACTS:
			if (facts(u, &u->nshd, &imsg) == -1) {
				imsg_free(&imsg);
				logout(u, "nshd sent facts nshdeck cannot "
				    "read");
				return;
			}
			break;
		case IMSG_CTL_CONTEXT:
			if (imsg_get_data(&imsg, &u->ctx,
			    sizeof(u->ctx)) == -1 || memchr(u->ctx.ifname,
			    '\0', sizeof(u->ctx.ifname)) == NULL) {
				imsg_free(&imsg);
				logout(u, "nshd sent a context not whole");
				return;
			}
			u->hasctx = 1;
			break;
		case IMSG_CTL_RESULT:
			if (imsg_get_data(&imsg, &res, sizeof(res)) == -1) {
				imsg_free(&imsg);
				logout(u, "nshd sent a result not whole");
				return;
			}
			if (u->state == U_LOGIN) {
				if (res.status != 0) {
					imsg_free(&imsg);
					logged(u, res.status);
					return;
				}
				u->state = U_WHO;
				pipe_compose(&u->nshd, IMSG_CTL_HELLO, 0, -1,
				    &h, sizeof(h));
				break;
			}
			answered(u, res.status);
			break;
		case IMSG_CTL_NOTICE:
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			noticed(u, &b);
			break;
		default:
			imsg_free(&imsg);
			logout(u, "nshd sent what nshdeck does not know");
			return;
		}
		imsg_free(&imsg);
	}
	pipe_event(&u->nshd);
}

/* what nshd's shows send for u's show: hello, then its answer */
static void
sessions_ro(int fd, short event, void *arg)
{
	struct user		*u, *v;
	struct nshd_session	 s;
	struct nshd_show	 sh;
	struct nshd_result	 res;
	struct imsg		 imsg;
	struct ibuf		 b;
	int			 n;

	u = NULL;
	TAILQ_FOREACH(v, &users, entry)
		if (&v->ro == arg)
			u = v;
	if (u == NULL)
		fatalx("%s: from no user", __func__);
	if (pipe_io(&u->ro, event) == -1) {
		unshown(u, "nshd's shows closed the connection");
		return;
	}
	for (;;) {
		if ((n = imsgbuf_get(&u->ro.ibuf, &imsg)) == -1) {
			unshown(u, "nshd's shows sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		/* hello, then the show's answer, and nothing else */
		if ((imsg_get_type(&imsg) == IMSG_CTL_HELLO) !=
		    (u->toro == RO_HELLO)) {
			imsg_free(&imsg);
			unshown(u, "nshd's shows sent what nshdeck did not "
			    "ask");
			return;
		}
		switch (imsg_get_type(&imsg)) {
		case IMSG_CTL_HELLO:
			if (imsg_get_data(&imsg, &s, sizeof(s)) == -1 ||
			    s.version != NSHD_VERSION) {
				imsg_free(&imsg);
				unshown(u, "nshd's shows' hello is not one "
				    "nshdeck knows");
				return;
			}
			memset(&sh, 0, sizeof(sh));
			strlcpy(sh.words, u->cur->r.text, sizeof(sh.words));
			pipe_compose(&u->ro, IMSG_CTL_SHOW, 0, -1, &sh,
			    sizeof(sh));
			u->toro = RO_SHOW;
			break;
		case IMSG_CTL_OUTPUT:
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			kept(u, ibuf_data(&b), ibuf_size(&b));
			break;
		case IMSG_CTL_FACTS:
			if (facts(u, &u->ro, &imsg) == -1) {
				imsg_free(&imsg);
				unshown(u, "nshd's shows sent facts nshdeck "
				    "cannot read");
				return;
			}
			break;
		case IMSG_CTL_RESULT:
			if (imsg_get_data(&imsg, &res, sizeof(res)) == -1) {
				imsg_free(&imsg);
				unshown(u, "nshd's shows sent a result not "
				    "whole");
				return;
			}
			imsg_free(&imsg);
			ro_close(u);
			answered(u, res.status);
			return;
		default:
			imsg_free(&imsg);
			unshown(u, "nshd's shows sent what nshdeck does not "
			    "know");
			return;
		}
		imsg_free(&imsg);
	}
	pipe_event(&u->ro);
}

/*
 * u's login, as nshd answered it: u ready, with its token, or gone; a
 * failure logged, but not more than one a user each DECK_QUIET seconds
 */
static void
logged(struct user *u, int32_t status)
{
	struct jbuf	 j = { NULL, 0, 0 };
	unsigned char	 rnd[DECK_TOKEN / 2];
	uint32_t	 id = u->cur->id;
	size_t		 i;

	if (status != 0) {
		failed(u->name);
		reply(id, 401, "{\"error\":\"Login incorrect\"}");
		user_free(u);
		return;
	}
	arc4random_buf(rnd, sizeof(rnd));
	for (i = 0; i < sizeof(rnd); i++)
		snprintf(u->token + 2 * i, 3, "%02x", rnd[i]);
	explicit_bzero(rnd, sizeof(rnd));
	u->state = U_READY;
	head(id, 200, 0, u->token, 0);
	j_who(&j, u);
	j_flush(&j, id);
	pipe_compose(&tofront, DECK_END, id, -1, NULL, 0);
	free(u->cur);
	u->cur = NULL;
	free(u->out);
	u->out = NULL;
	u->outlen = 0;
	log_info("%s logged in", u->name);
	next(u);
}

/* a failed login of name's, logged, unless one was just now */
static void
failed(const char *name)
{
	time_t	 now = time(NULL);
	size_t	 i, old = 0;

	for (i = 0; i < DECK_FAILS; i++) {
		if (strcmp(fails[i].name, name) == 0) {
			if (now - fails[i].when < DECK_QUIET)
				return;
			break;
		}
		if (fails[i].when < fails[old].when)
			old = i;
	}
	if (i == DECK_FAILS)
		i = old;
	strlcpy(fails[i].name, name, sizeof(fails[i].name));
	fails[i].when = now;
	log_warnx("login failed for %s", name);
}

/* the next of u's requests, to nshd, if none is asked */
static void
next(struct user *u)
{
	struct nshd_show	 sh;
	struct nshd_configure	 cf;
	struct nshd_line	 ln;
	struct nshd_commit	 cm;
	struct nshd_rollback	 rb;
	struct nshd_op		 op;
	struct nshd_watch	 w;
	struct pending		*p;

	if (u->cur != NULL || u->state != U_READY ||
	    (p = TAILQ_FIRST(&u->queue)) == NULL)
		return;
	TAILQ_REMOVE(&u->queue, p, entry);
	u->nqueue--;
	u->cur = p;
	u->headed = u->nrecords = u->hasctx = u->sent = 0;
	if (p->r.kind == DECK_COMPLETE) {
		u->cmplt = deck_cmplt_new();
		facts_in_init(&u->in, deck_cmplt_record, u->cmplt);
	} else
		facts_in_init(&u->in, record, u);
	switch (p->r.kind) {
	case DECK_SHOW:
	case DECK_CONFIG:
		memset(&sh, 0, sizeof(sh));
		strlcpy(sh.words, p->r.text, sizeof(sh.words));
		ask(u, IMSG_CTL_SHOW, &sh, sizeof(sh));
		break;
	case DECK_CONFIGURE:
		memset(&cf, 0, sizeof(cf));
		cf.mode = p->r.n;
		ask(u, IMSG_CTL_CONFIGURE, &cf, sizeof(cf));
		break;
	case DECK_LINE:
		memset(&ln, 0, sizeof(ln));
		strlcpy(ln.line, p->r.text, sizeof(ln.line));
		ask(u, IMSG_CTL_LINE, &ln, sizeof(ln));
		break;
	case DECK_EXIT:
		ask(u, IMSG_CTL_EXIT, NULL, 0);
		break;
	case DECK_COMMIT:
		memset(&cm, 0, sizeof(cm));
		cm.check = p->r.check;
		cm.minutes = p->r.minutes;
		strlcpy(cm.comment, p->r.comment, sizeof(cm.comment));
		ask(u, IMSG_CTL_COMMIT, &cm, sizeof(cm));
		break;
	case DECK_ROLLBACK:
		memset(&rb, 0, sizeof(rb));
		rb.n = p->r.n;
		ask(u, IMSG_CTL_ROLLBACK, &rb, sizeof(rb));
		break;
	case DECK_OP:
		memset(&op, 0, sizeof(op));
		op.rtable = p->r.n;
		strlcpy(op.line, p->r.text, sizeof(op.line));
		ask(u, IMSG_CTL_OP, &op, sizeof(op));
		break;
	case DECK_COMPLETE:
		/* the tables if we have none, else the names */
		u->naming = deck_tables_ready();
		ask(u, u->naming ? IMSG_CTL_NAMES : IMSG_CTL_COMMANDS, NULL, 0);
		break;
	default:
		/* session's own: the watch its streams want */
		memset(&w, 0, sizeof(w));
		w.what = p->r.logs;
		ask(u, IMSG_CTL_WATCH, &w, sizeof(w));
		break;
	}
}

static void
ask(struct user *u, uint32_t type, const void *data, size_t len)
{
	pipe_compose(&u->nshd, type, 0, -1, data, len);
}

/*
 * u's request ended, as status says: the rest of its answer, what nshd
 * printed and how it ended; or for a watch, a refusal its streams hear
 */
static void
answered(struct user *u, int32_t status)
{
	struct jbuf	 j = { NULL, 0, 0 };
	struct pending	*p = u->cur;
	struct stream	*s;
	const char	*why;
	int32_t		 ro = 1;

	if (p == NULL)
		return;
	u->nshd.paused = 0;
	if (p->r.kind == DECK_COMPLETE && !u->naming && status == 0 &&
	    !p->gone) {
		/* the tables are here: build them, then ask for the names */
		facts_in_free(&u->in);
		facts_in_init(&u->in, deck_cmplt_record, u->cmplt);
		if (deck_tables(u->cmplt) == 0) {
			u->naming = 1;
			ask(u, IMSG_CTL_NAMES, NULL, 0);
			return;
		}
		why = "% nshdeck cannot use the command tables nshd sent\n";
		kept(u, why, strlen(why));
		status = 1;
	}
	if (p->id != 0 && !p->gone && p->r.kind == DECK_SHOW &&
	    status == NSHD_ELSEWHERE && u->toro == RO_NONE) {
		/* not the system's to answer: nshd's shows', as nsh asks */
		free(u->out);
		u->out = NULL;
		u->outlen = 0;
		u->toro = RO_CONNECT;
		u->connect = p->id;
		pipe_compose(&toparent, DECK_CONNECT, p->id, -1, &ro,
		    sizeof(ro));
		return;
	}
	if (p->id == 0) {
		u->watching = 0;
		if (status != 0)
			TAILQ_FOREACH(s, &u->streams, entry) {
				J(&j, "event: refused\ndata: {\"text\":");
				j_str(&j, u->out, u->outlen);
				J(&j, "}\n\n");
				j_flush(&j, s->id);
			}
	} else if (!p->gone) {
		j_answer(u);
		if (p->r.kind == DECK_COMPLETE && status == 0)
			deck_complete(u->cmplt, p->r.text, p->r.n, &u->ctx,
			    completed, u);
		J(&u->j, "],\"output\":");
		j_str(&u->j, u->out, u->outlen);
		if (u->hasctx) {
			j_fmt(&u->j, ",\"context\":{\"mode\":%d,"
			    "\"rtable\":%d,\"bridge\":%d,\"interface\":",
			    u->ctx.mode, u->ctx.rtable, u->ctx.bridge);
			j_str(&u->j, u->ctx.ifname, strlen(u->ctx.ifname));
			J(&u->j, "}");
		}
		j_fmt(&u->j, ",\"status\":%d,\"ok\":%s}\n", status,
		    status == 0 ? "true" : "false");
		j_flush(&u->j, p->id);
		pipe_compose(&tofront, DECK_END, p->id, -1, NULL, 0);
	}
	facts_in_free(&u->in);
	deck_cmplt_free(u->cmplt);
	u->cmplt = NULL;
	free(u->j.p);
	memset(&u->j, 0, sizeof(u->j));
	free(u->out);
	u->out = NULL;
	u->outlen = 0;
	free(p);
	u->cur = NULL;
	u->toro = RO_NONE;
	rewatch(u);
	next(u);
}

/* what nshd printed for u's request, kept, but past DECK_OUTPUT bytes */
static void
kept(struct user *u, const void *data, size_t len)
{
	char	*q;

	if (u->outlen + len > DECK_OUTPUT)
		return;
	if ((q = realloc(u->out, u->outlen + len)) == NULL)
		fatal(NULL);
	u->out = q;
	memcpy(u->out + u->outlen, data, len);
	u->outlen += len;
}

/*
 * facts from, for u's request, as JSON to front, from not read while
 * front has not written DECK_WINDOW messages: -1 if they cannot be read
 */
static int
facts(struct user *u, struct deck_pipe *from, struct imsg *imsg)
{
	struct ibuf	 b;

	if (imsg_get_ibuf(imsg, &b) == -1)
		fatal("%s", __func__);
	if (u->cur == NULL || u->cur->gone || u->state != U_READY)
		return (0);
	j_answer(u);
	if (facts_read(&u->in, ibuf_data(&b), ibuf_size(&b)) == -1)
		return (-1);
	if (u->j.len >= DECK_CHUNK &&
	    (u->sent += j_flush(&u->j, u->cur->id)) >= DECK_WINDOW)
		from->paused = 1;
	return (0);
}

/* u's show, which nshd's shows did not answer: ended, as why says */
static void
unshown(struct user *u, const char *why)
{
	log_warnx("%s: %s", u->name, why);
	ro_close(u);
	kept(u, "% ", 2);
	kept(u, why, strlen(why));
	kept(u, "\n", 1);
	answered(u, 1);
}

/* u's connection to nshd's shows, closed if it was made */
static void
ro_close(struct user *u)
{
	if (u->toro == RO_HELLO || u->toro == RO_SHOW)
		pipe_close(&u->ro);
	u->toro = RO_DONE;
}

/* what answers u's request: its connection, or nshd's shows', or none */
static struct deck_pipe *
answering(struct user *u)
{
	if (u->toro == RO_HELLO || u->toro == RO_SHOW)
		return (&u->ro);
	if (u->toro == RO_NONE && u->hasnshd)
		return (&u->nshd);
	return (NULL);
}

/* a notice nshd sent u, as an event, to each stream that wants it */
static void
noticed(struct user *u, struct ibuf *b)
{
	static const char	*kinds[] = { "", "commit", "confirmed",
				    "applied", "back", "lock", "unlock",
				    "links", "routes", "log", "logend" };
	static const char	*logs[] = { "daemon", "messages", "authlog",
				    "pflog" };
	struct nshd_notice	 nt;
	struct stream		*s;
	struct jbuf		 j = { NULL, 0, 0 };
	size_t			 i;
	int			 log = 0;

	if (ibuf_get(b, &nt, sizeof(nt)) == -1 || nt.kind < 1 ||
	    nt.kind >= (int)(sizeof(kinds) / sizeof(kinds[0])))
		return;
	if (nt.kind == NSHD_NOTICE_LOG || nt.kind == NSHD_NOTICE_LOGEND)
		log = nt.n;
	TAILQ_FOREACH(s, &u->streams, entry) {
		if (log != 0 && (s->logs & log) == 0)
			continue;
		j_fmt(&j, "event: %s\ndata: {\"kind\":\"%s\"",
		    nt.kind == NSHD_NOTICE_LOG ? "log" : "notice",
		    kinds[nt.kind]);
		if (log != 0) {
			for (i = 0; i < sizeof(logs) / sizeof(logs[0]); i++)
				if (log == (NSHD_WATCH_DAEMON << i))
					j_fmt(&j, ",\"log\":\"%s\"", logs[i]);
		} else
			j_fmt(&j, ",\"uid\":%u,\"n\":%d", nt.uid, nt.n);
		J(&j, ",\"text\":");
		j_str(&j, ibuf_data(b), ibuf_size(b));
		J(&j, "}\n\n");
		j_flush(&j, s->id);
	}
}

/*
 * What u's streams want nshd to watch, asked, once nothing else is: all
 * but logs while any stream is open, and the logs any of them follows
 */
static void
rewatch(struct user *u)
{
	struct stream	*s;
	struct pending	*p;
	int		 want = 0;

	TAILQ_FOREACH(s, &u->streams, entry)
		want |= NSHD_WATCH_COMMITS | NSHD_WATCH_ROUTING | s->logs;
	if (want == u->watch || u->watching || u->state != U_READY)
		return;
	if ((p = calloc(1, sizeof(*p))) == NULL)
		fatal(NULL);
	p->r.logs = want;
	u->watch = want;
	u->watching = 1;
	TAILQ_INSERT_HEAD(&u->queue, p, entry);
	u->nqueue++;
	next(u);
}

/* front's client for id is gone: its request, waiting or answered */
static void
gone(uint32_t id)
{
	struct deck_pipe	*from;
	struct user		*u;
	struct pending		*p;
	struct stream		*s;

	TAILQ_FOREACH(u, &users, entry) {
		if (u->cur != NULL && u->cur->id == id) {
			u->cur->gone = 1;
			/* front sends no more READ for it */
			if ((from = answering(u)) != NULL) {
				from->paused = 0;
				pipe_event(from);
			}
		}
		TAILQ_FOREACH(p, &u->queue, entry)
			if (p->id == id) {
				TAILQ_REMOVE(&u->queue, p, entry);
				u->nqueue--;
				free(p);
				break;
			}
		TAILQ_FOREACH(s, &u->streams, entry)
			if (s->id == id) {
				TAILQ_REMOVE(&u->streams, s, entry);
				free(s);
				rewatch(u);
				break;
			}
	}
}

/*
 * u logged out, its connection closed, and its requests and streams
 * ended: with why, logged, if nshd ended it
 */
static void
logout(struct user *u, const char *why)
{
	if (why != NULL)
		log_warnx("%s: %s", u->name, why);
	else
		log_info("%s logged out", u->name);
	user_free(u);
}

/* each user unused for DECK_IDLE seconds, logged out */
static void
sessions_idle(int fd, short event, void *arg)
{
	struct timeval	 tv = { 60, 0 };
	struct user	*u, *next;
	time_t		 now = time(NULL);

	TAILQ_FOREACH_SAFE(u, &users, entry, next)
		if (u->state == U_READY && TAILQ_EMPTY(&u->streams) &&
		    u->cur == NULL && now - u->used > DECK_IDLE) {
			log_info("%s: unused, logged out", u->name);
			user_free(u);
		}
	evtimer_add(&ev_idle, &tv);
}

/* a record, as JSON, its fields by their names, absent ones left out */
static void
record(void *arg, const struct facts_template *t, const struct facts_value *v)
{
	struct user			*u = arg;
	struct jbuf			*j = &u->j;
	const struct facts_tfield	*f;
	char				 a[INET6_ADDRSTRLEN];
	size_t				 i, k;
	int				 first;

	if (u->nrecords++ > 0)
		J(j, ",");
	J(j, "{\"kind\":");
	j_str(j, t->kind, strlen(t->kind));
	for (i = 0; i < t->nfields; i++) {
		f = &t->fields[i];
		if (v[i].type == FACT_NONE)
			continue;
		J(j, ",");
		j_str(j, f->name, strlen(f->name));
		J(j, ":");
		switch (v[i].type) {
		case FACT_U64:
			if (f->naming == FACT_BITS) {
				J(j, "[");
				for (k = 0, first = 1; k < f->nnames; k++)
					if (v[i].v.u & f->names[k].value) {
						if (!first)
							J(j, ",");
						j_str(j, f->names[k].name,
						    strlen(f->names[k].name));
						first = 0;
					}
				J(j, "]");
				break;
			}
			if (f->naming == FACT_VALUES) {
				for (k = 0; k < f->nnames; k++)
					if (v[i].v.u == f->names[k].value)
						break;
				if (k < f->nnames) {
					j_str(j, f->names[k].name,
					    strlen(f->names[k].name));
					break;
				}
			}
			j_fmt(j, "%llu", (unsigned long long)v[i].v.u);
			break;
		case FACT_I64:
			j_fmt(j, "%lld", (long long)v[i].v.i);
			break;
		case FACT_STRING:
			j_str(j, v[i].v.str.s, v[i].v.str.len);
			break;
		case FACT_TIME:
			j_fmt(j, "%lld.%09u", (long long)v[i].v.t.sec,
			    (unsigned int)v[i].v.t.nsec);
			break;
		case FACT_ADDRESS:
			a[0] = '\0';
			if (v[i].v.a.family == FACT_INET && v[i].v.a.len == 4)
				inet_ntop(AF_INET, v[i].v.a.bytes, a,
				    sizeof(a));
			else if (v[i].v.a.family == FACT_INET6 &&
			    v[i].v.a.len == 16)
				inet_ntop(AF_INET6, v[i].v.a.bytes, a,
				    sizeof(a));
			else
				for (k = 0; k < v[i].v.a.len &&
				    k * 3 + 3 <= sizeof(a); k++)
					snprintf(a + k * 3, sizeof(a) - k * 3,
					    "%s%02x", k ? ":" : "",
					    v[i].v.a.bytes[k]);
			j_str(j, a, strlen(a));
			break;
		default:
			J(j, "null");
		}
	}
	J(j, "}");
}

/* Write one thing completion found as a record: an insert or a choice. */
static void
completed(void *arg, int insert, const char *s, const char *help)
{
	struct user	*u = arg;

	if (u->nrecords++ > 0)
		J(&u->j, ",");
	if (insert)
		J(&u->j, "{\"kind\":\"insert\",\"text\":");
	else
		J(&u->j, "{\"kind\":\"choice\",\"word\":");
	j_str(&u->j, s, strlen(s));
	if (help != NULL) {
		J(&u->j, ",\"help\":");
		j_str(&u->j, help, strlen(help));
	}
	J(&u->j, "}");
}

/* an answer's head, to front */
static void
head(uint32_t id, int status, int events, const char *token, int clear)
{
	struct deck_head	 h;

	memset(&h, 0, sizeof(h));
	h.status = status;
	h.events = events;
	h.clear = clear;
	if (token != NULL)
		strlcpy(h.cookie, token, sizeof(h.cookie));
	pipe_compose(&tofront, DECK_HEAD, id, -1, &h, sizeof(h));
	explicit_bzero(&h, sizeof(h));
}

/* a whole answer, of status, with its head unless status is 0 */
static void
reply(uint32_t id, int status, const char *fmt, ...)
{
	va_list	 ap;
	char	*s;
	int	 len;

	if (status != 0)
		head(id, status, 0, NULL, 0);
	va_start(ap, fmt);
	if ((len = vasprintf(&s, fmt, ap)) == -1)
		fatal("%s", __func__);
	va_end(ap);
	pipe_compose(&tofront, DECK_BODY, id, -1, s, len);
	pipe_compose(&tofront, DECK_BODY, id, -1, "\n", 1);
	free(s);
	pipe_compose(&tofront, DECK_END, id, -1, NULL, 0);
}

/* len bytes of s, as they are, to j */
static void
j_raw(struct jbuf *j, const char *s, size_t len)
{
	char	*p;
	size_t	 size;

	if (j->len + len > j->size) {
		for (size = j->size ? j->size : DECK_CHUNK;
		    size < j->len + len; size *= 2)
			;
		if ((p = realloc(j->p, size)) == NULL)
			fatal(NULL);
		j->p = p;
		j->size = size;
	}
	memcpy(j->p + j->len, s, len);
	j->len += len;
}

/*
 * len bytes of s, as a JSON string: quotes, backslashes and control
 * characters escaped, and each byte that does not begin a whole
 * sequence of UTF-8 as U+FFFD
 */
static void
j_str(struct jbuf *j, const char *s, size_t len)
{
	const unsigned char	*p = (const unsigned char *)s;
	char			 e[8];
	size_t			 i, n, k;

	J(j, "\"");
	for (i = 0; i < len; i += n) {
		n = 1;
		if (p[i] == '"' || p[i] == '\\') {
			e[0] = '\\';
			e[1] = p[i];
			j_raw(j, e, 2);
			continue;
		}
		if (p[i] < 0x20 || p[i] == 0x7f) {
			snprintf(e, sizeof(e), "\\u%04x", p[i]);
			j_raw(j, e, 6);
			continue;
		}
		if (p[i] < 0x80) {
			j_raw(j, (const char *)p + i, 1);
			continue;
		}
		/* the sequence's length, by its first byte, or 0 */
		n = p[i] >= 0xf5 ? 0 : p[i] >= 0xf0 ? 4 : p[i] >= 0xe0 ? 3 :
		    p[i] >= 0xc2 ? 2 : 0;
		for (k = 1; n > 0 && k < n; k++)
			if (i + k >= len || (p[i + k] & 0xc0) != 0x80)
				n = 0;
		/* not overlong, nor a surrogate, nor past U+10FFFF */
		if ((n == 3 && ((p[i] == 0xe0 && p[i + 1] < 0xa0) ||
		    (p[i] == 0xed && p[i + 1] >= 0xa0))) ||
		    (n == 4 && ((p[i] == 0xf0 && p[i + 1] < 0x90) ||
		    (p[i] == 0xf4 && p[i + 1] >= 0x90))))
			n = 0;
		if (n == 0) {
			J(j, "\\ufffd");
			n = 1;
		} else
			j_raw(j, (const char *)p + i, n);
	}
	J(j, "\"");
}

static void
j_fmt(struct jbuf *j, const char *fmt, ...)
{
	va_list	 ap;
	char	*s;
	int	 len;

	va_start(ap, fmt);
	if ((len = vasprintf(&s, fmt, ap)) == -1)
		fatal("%s", __func__);
	va_end(ap);
	j_raw(j, s, len);
	free(s);
}

/* who u is, and the names of its class's permissions */
static void
j_who(struct jbuf *j, struct user *u)
{
	static const char	*names[] = { "view", "operate", "configure",
				    "admin", "exec" };
	size_t			 i;
	int			 first = 1;

	J(j, "{\"user\":");
	j_str(j, u->name, strlen(u->name));
	J(j, ",\"perms\":[");
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		if (u->perms > 0 && (u->perms & (1 << i))) {
			if (!first)
				J(j, ",");
			j_str(j, names[i], strlen(names[i]));
			first = 0;
		}
	J(j, "]}\n");
}

/* u's answer, begun, if it is not: its head, and its records' start */
static void
j_answer(struct user *u)
{
	if (u->headed)
		return;
	head(u->cur->id, 200, 0, NULL, 0);
	u->headed = 1;
	J(&u->j, "{\"records\":[");
}

/* j, to front, for id, in messages that fit, and emptied: how many */
static int
j_flush(struct jbuf *j, uint32_t id)
{
	size_t	 off, n;
	int	 sent = 0;

	for (off = 0; off < j->len; off += n, sent++) {
		n = j->len - off > DECK_CHUNK ? DECK_CHUNK : j->len - off;
		pipe_compose(&tofront, DECK_BODY, id, -1, j->p + off, n);
	}
	free(j->p);
	memset(j, 0, sizeof(*j));
	return (sent);
}

/* the user whose token this is, logged in, or NULL */
static struct user *
user_token(const char *token)
{
	struct user	*u;

	if (strlen(token) != DECK_TOKEN)
		return (NULL);
	TAILQ_FOREACH(u, &users, entry)
		if (u->state == U_READY &&
		    timingsafe_bcmp(u->token, token, DECK_TOKEN) == 0)
			return (u);
	return (NULL);
}

/*
 * u, and its connection, gone: what it was asked ends, unanswered by
 * nshd, and its streams end
 */
static void
user_free(struct user *u)
{
	struct pending	*p;
	struct stream	*s;

	if (u->cur != NULL) {
		/* an answer begun ends as JSON still */
		if (u->cur->id != 0 && !u->cur->gone && u->headed) {
			J(&u->j, "],\"error\":\"nshd ended the session\","
			    "\"ok\":false}\n");
			j_flush(&u->j, u->cur->id);
			pipe_compose(&tofront, DECK_END, u->cur->id, -1, NULL, 0);
		} else if (u->cur->id != 0 && !u->cur->gone)
			reply(u->cur->id, 503, "{\"error\":\"nshd ended the "
			    "session\"}");
		explicit_bzero(u->cur, sizeof(*u->cur));
		free(u->cur);
	}
	while ((p = TAILQ_FIRST(&u->queue)) != NULL) {
		TAILQ_REMOVE(&u->queue, p, entry);
		if (p->id != 0)
			reply(p->id, 503, "{\"error\":\"logged out\"}");
		free(p);
	}
	while ((s = TAILQ_FIRST(&u->streams)) != NULL) {
		TAILQ_REMOVE(&u->streams, s, entry);
		pipe_compose(&tofront, DECK_END, s->id, -1, NULL, 0);
		free(s);
	}
	if (u->hasnshd)
		pipe_close(&u->nshd);
	ro_close(u);
	facts_in_free(&u->in);
	deck_cmplt_free(u->cmplt);
	free(u->j.p);
	free(u->out);
	TAILQ_REMOVE(&users, u, entry);
	nusers--;
	explicit_bzero(u, sizeof(*u));
	free(u);
}
