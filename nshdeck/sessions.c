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
 * session: the web users logged in, each with a connection to nshd,
 * which parent makes, and a token, which the user's cookie carries.
 * session does not trust what front sends: it checks that each message
 * is whole, each string ends with a NUL, and each number is in its
 * range.
 *
 * For a login, session asks parent for a connection, sends nshd a hello,
 * and logs in; nshd's system process checks the login. Then session
 * sends a second hello to learn the permissions of the user's class,
 * and gives the user a token of 32 random bytes in hex. Each request of
 * a user's goes to nshd on that user's connection, one at a time, the
 * rest waiting. session writes the answer as JSON, and never parses
 * JSON: the records of a show as they come, then what nshd printed, and
 * how it ended. While front has DECK_WINDOW messages of an answer not
 * yet written, session stops reading from nshd. When nshd's system
 * process says it does not answer a show, session asks nshd's shows
 * process instead, as nsh does, on a separate connection that parent
 * makes and that closes after the answer. A daemon's rules go to nshd
 * in parts, as nsh sends them, and are set with the last.
 *
 * Failed logins are counted for each user name and for each client
 * address, the one httpd passes; an IPv6 address is counted by its /64.
 * After DECK_TRIES failures in a row, logins for that name or from that
 * address are refused, without asking nshd, for one second, and each
 * further failure doubles the wait, up to DECK_WAIT seconds. While nshd
 * checks a login, another for the same name or from the same address is
 * refused, so each failure is counted before the next login. A
 * successful login resets the count for its name. A count with no
 * failure for DECK_FORGET seconds starts over. Failed and refused
 * logins are logged at most once every DECK_QUIET seconds for each name
 * and address, and each log line says how many were not logged.
 *
 * A user's event streams have nshd watch commits, interfaces and routes,
 * and the logs any of them follows. Each notice nshd sends goes to each
 * stream as an event, but a log's notices go only to the streams that
 * follow it. A user with no stream and no request for DECK_IDLE seconds
 * is logged out, as by a logout request. That closes the connection, so
 * nshd forgets the login and the user's candidate. If nshd closes the
 * connection, the user is logged out.
 *
 * session completes lines itself, in the user's mode, with nsh's code
 * (tables.c), as nsh's Tab does.  It asks nshd for nsh's command tables
 * once, and for the names of interfaces, groups, bridges and routing
 * tables on each completion.
 *
 * A user's terminal is nsh on a pty, which nshd starts as the user and
 * passes back on the user's connection. Its own stream carries what nsh
 * writes, in base64, as it comes, but no more than DECK_WINDOW messages
 * front has not written, so none is dropped; what the user types goes
 * to nsh as nsh takes it. The terminal, and nsh with it, ends when its
 * stream does, when nsh does, or when the user logs out.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <resolv.h>
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
#include "stringlist.h"
#include "kfacts.h"
#include "tables.h"

#define DECK_QUEUE	16		/* a user's requests waiting, at most */
#define DECK_OUTPUT	(1024 * 1024)	/* what nshd printed, kept, at most */
#define DECK_CHUNK	8192		/* JSON bytes per message to front */
#define DECK_FAILS	512		/* names and addresses counted */
#define DECK_QUIET	10		/* seconds between log lines, at least */
#define DECK_TRIES	5		/* failed logins in a row before a wait */
#define DECK_WAIT	60		/* longest wait, in seconds */
#define DECK_FORGET	(15 * 60)	/* idle seconds before a count resets */
#define DECK_PTY	3072		/* maximum nsh output read at once, */
					/* which is 4096 bytes in base64 */
#define DECK_TYPED	(64 * 1024)	/* what was typed to a terminal, */
					/* not yet written to it, at most */

/* a literal, to JSON j */
#define J(j, s)		j_raw((j), (s), sizeof(s) - 1)

/* JSON, as it is written, until it is sent */
struct jbuf {
	char			*p;
	size_t			 len;
	size_t			 size;		/* allocated size of p */
};

/* how far a user's login is */
enum { U_CONNECT, U_HELLO, U_LOGIN, U_WHO, U_READY };

/* how far a show asked of nshd's shows is; RO_DONE once it ended */
enum { RO_NONE, RO_CONNECT, RO_HELLO, RO_SHOW, RO_DONE };

/* a request of a user's, waiting or answered, or session's own watch */
struct pending {
	TAILQ_ENTRY(pending)	 entry;
	uint32_t		 id;		/* front's id; 0 for a watch */
	int			 gone;		/* front's client is gone */
	struct deck_request	 r;
	char			*text;		/* setrules' rules */
	size_t			 textlen;
	size_t			 textoff;	/* bytes sent to nshd */
};

/* an event stream of a user's */
struct stream {
	TAILQ_ENTRY(stream)	 entry;
	uint32_t		 id;
	int			 logs;		/* NSHD_WATCH_* it follows */
};

/* how far a terminal is: asked of nshd, or running */
enum { TS_ASKED, TS_RUNS };

/* a terminal of a user's, and its stream */
struct terminal {
	TAILQ_ENTRY(terminal)	 entry;
	uint32_t		 id;		/* id of its stream */
	int			 n;		/* the page's name for it */
	int			 state;
	int			 pty;		/* or -1 */
	struct event		 ev;
	short			 events;
	int			 sent;		/* messages front has not written */
	char			*typed;		/* not yet written to nsh */
	size_t			 typedlen;
};

struct user {
	TAILQ_ENTRY(user)	 entry;
	char			 token[DECK_TOKEN + 1];
	char			 name[NSHD_NAME];
	char			 addr[DECK_ADDR];	/* from httpd */
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
	struct jbuf		 j;		/* answer JSON for front */
	char			*out;		/* what nshd printed */
	size_t			 outlen;
	int			 lost;		/* some was not kept */
	struct nshd_context	 ctx;
	int			 hasctx;
	struct rows		*cmplt;		/* what a completion has read */
	int			 naming;	/* its names were asked for */
	TAILQ_HEAD(, stream)	 streams;
	TAILQ_HEAD(, terminal)	 terms;
	int			 nterms;
	int			 watch;		/* what nshd was asked to watch */
	int			 watching;	/* a watch waits */
	time_t			 used;
};

static TAILQ_HEAD(, user)	 users = TAILQ_HEAD_INITIALIZER(users);
static int			 nusers;
static struct deck_pipe		 toparent, tofront;
static struct {
	uint32_t		 id;
	char			*p;
	size_t			 len;
} incoming;			/* rules for the next setrules request */
static struct event		 ev_idle;
static struct rows		*completing;	/* what kf_names() reads */
/* what a count is for, and how a login ended */
enum { FAIL_NAME = 1, FAIL_ADDR };
enum { EV_FAILED, EV_REFUSED, EV_SUCCEEDED };

static struct fail {
	int			 kind;		/* FAIL_*, or 0: none */
	char			 key[DECK_ADDR];	/* its name or address */
	int64_t			 last;		/* the last failure, in ms */
	int64_t			 until;		/* refused until, in ms */
	int64_t			 logged;	/* last logged, in ms */
	unsigned int		 row;		/* failed in a row */
	unsigned int		 failed;	/* failed, not logged */
	unsigned int		 refused;	/* refused, not logged */
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
static void	 rules(struct user *);
static void	 answered(struct user *, int32_t);
static void	 kept(struct user *, const void *, size_t);
static int	 facts(struct user *, struct deck_pipe *, struct imsg *);
static void	 unshown(struct user *, const char *);
static void	 ro_close(struct user *);
static struct deck_pipe *answering(struct user *);
static void	 noticed(struct user *, struct ibuf *);
static void	 rewatch(struct user *);
static void	 terminal(uint32_t, struct user *);
static struct terminal *term_find(uint32_t, struct user **);
static void	 term_started(struct user *, uint32_t, int32_t);
static void	 term_io(int, short, void *);
static void	 term_event(struct terminal *);
static void	 term_end(struct user *, struct terminal *, const char *);
static void	 typed(uint32_t, struct user *, struct deck_request *);
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
static void	 failed(const char *, const char *);
static void	 fail_key(const char *, char *, size_t);
static struct fail *fail_find(int, const char *);
static struct fail *fail_add(int, const char *, struct fail *, int64_t);
static void	 fail_log(int, struct fail *[2], const char *, const char *,
		    int64_t);
static int64_t	 msnow(void);
static struct user *user_token(const char *);
static void	 user_free(struct user *);

__dead void
sessions(int debug, int verbose)
{
	deck_child("session", debug, verbose);
	deck_drop(DECK_USER);
	if (pledge("stdio recvfd tty", NULL) == -1)
		fatal("pledge");

	if (pipe_init(&toparent, 3, sessions_parent, 1) == -1 ||
	    pipe_init(&tofront, 4, sessions_front, 0) == -1)
		fatal(NULL);
	evtimer_set(&ev_idle, sessions_idle, NULL);
	sessions_idle(0, 0, NULL);
	event_dispatch();
	exit(0);
}

/* parent's connections to nshd, each for the request that asked */
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
	struct terminal		*t;
	struct imsg		 imsg;
	struct ibuf		 b;
	struct user		*u;
	char			*q;
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
			/* every use of n fits in 0 to 255 */
			if (imsg_get_data(&imsg, &r, sizeof(r)) == -1 ||
			    r.kind < DECK_LOGIN || r.kind > DECK_SETRULES ||
			    (incoming.len > 0 && (incoming.id != id ||
			    r.kind != DECK_SETRULES)) ||
			    memchr(r.token, '\0', sizeof(r.token)) == NULL ||
			    memchr(r.addr, '\0', sizeof(r.addr)) == NULL ||
			    memchr(r.text, '\0', sizeof(r.text)) == NULL ||
			    memchr(r.password, '\0', sizeof(r.password)) ==
			    NULL ||
			    memchr(r.comment, '\0', sizeof(r.comment)) ==
			    NULL || memchr(r.daemon, '\0', sizeof(r.daemon)) ==
			    NULL || r.n < 0 || r.n > 255 ||
			    r.minutes < 0 || r.minutes > NSHD_CONFIRMMAX ||
			    (r.check != 0 && r.check != 1) ||
			    (r.logs & ~NSHD_WATCH_LOGS) != 0 ||
			    r.rows < 0 || r.rows > NSHD_TERMSIZE ||
			    r.cols < 0 || r.cols > NSHD_TERMSIZE)
				fatalx("front sent a request not whole");
			request(id, &r);
			explicit_bzero(&r, sizeof(r));
			free(incoming.p);
			memset(&incoming, 0, sizeof(incoming));
			break;
		case DECK_TEXT:
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			if ((incoming.len > 0 && incoming.id != id) ||
			    ibuf_size(&b) == 0 ||
			    ibuf_size(&b) > NSHD_RULES - incoming.len ||
			    memchr(ibuf_data(&b), '\0', ibuf_size(&b)) != NULL)
				fatalx("front sent rules not a request's");
			if ((q = realloc(incoming.p, incoming.len +
			    ibuf_size(&b))) == NULL)
				fatal(NULL);
			memcpy(q + incoming.len, ibuf_data(&b), ibuf_size(&b));
			incoming.p = q;
			incoming.len += ibuf_size(&b);
			incoming.id = id;
			break;
		case DECK_READ:
			/* an answer front has written: read nshd again */
			TAILQ_FOREACH(u, &users, entry)
				if (u->cur != NULL && u->cur->id == id &&
				    (from = answering(u)) != NULL) {
					u->sent = 0;
					from->paused = 0;
					pipe_event(from);
				}
			/* or a terminal's stream: read nsh again */
			if ((t = term_find(id, &u)) != NULL) {
				t->sent = 0;
				term_event(t);
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

/* a login, or a request of the user the token names */
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
	case DECK_TERMINAL:
		if (u->nterms == DECK_TERMINALS) {
			reply(id, 503, "{\"error\":\"too many terminals\"}");
			return;
		}
		if (u->nqueue == DECK_QUEUE)
			break;
		terminal(id, u);
		break;
	case DECK_TYPE:
		typed(id, u, r);
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
	if (r->kind == DECK_SETRULES) {
		p->text = incoming.p;
		p->textlen = incoming.len;
		memset(&incoming, 0, sizeof(incoming));
	}
	TAILQ_INSERT_TAIL(&u->queue, p, entry);
	u->nqueue++;
	next(u);
}

/* a login: a user with no token yet, whose connection parent makes */
static void
login(uint32_t id, struct deck_request *r)
{
	struct user	*u, *v;
	struct pending	*p;
	struct fail	*f[2];
	const char	*addr = r->addr[0] != '\0' ? r->addr : "?";
	char		 key[DECK_ADDR], vkey[DECK_ADDR], name[NSHD_NAME];
	int64_t		 now = msnow(), wait = 0;
	int32_t		 ro = 0;
	size_t		 i;

	fail_key(addr, key, sizeof(key));
	f[0] = fail_find(FAIL_NAME, r->text);
	f[1] = fail_find(FAIL_ADDR, key);
	for (i = 0; i < 2; i++)
		if (f[i] != NULL && f[i]->until - now > wait)
			wait = f[i]->until - now;
	if (wait > 0) {
		fail_log(EV_REFUSED, f, r->text, addr, now);
		wait = (wait + 999) / 1000;
		reply(id, 429, "{\"error\":\"too many failed logins, wait "
		    "%lld s\",\"wait\":%lld}", (long long)wait, (long long)wait);
		return;
	}
	/* one login at a time for a name, and for an address */
	strlcpy(name, r->text, sizeof(name));
	TAILQ_FOREACH(v, &users, entry) {
		if (v->state == U_READY)
			continue;
		fail_key(v->addr, vkey, sizeof(vkey));
		if (strcmp(v->name, name) == 0 || strcmp(vkey, key) == 0) {
			fail_log(EV_REFUSED, f, r->text, addr, now);
			reply(id, 429, "{\"error\":\"another login for this "
			    "name or address is being checked, try again\","
			    "\"wait\":1}");
			return;
		}
	}
	if (nusers == DECK_SESSIONS) {
		reply(id, 503, "{\"error\":\"too many logged in\"}");
		return;
	}
	if ((u = calloc(1, sizeof(*u))) == NULL ||
	    (p = calloc(1, sizeof(*p))) == NULL)
		fatal(NULL);
	TAILQ_INIT(&u->queue);
	TAILQ_INIT(&u->streams);
	TAILQ_INIT(&u->terms);
	strlcpy(u->name, r->text, sizeof(u->name));
	strlcpy(u->addr, addr, sizeof(u->addr));
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
	if (pipe_init(&u->nshd, fd, sessions_nshd, 1) == -1)
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
	struct terminal		*t;
	struct nshd_session	 s;
	struct nshd_result	 res;
	struct nshd_login	 lg;
	struct nshd_hello	 h = { NSHD_VERSION };
	struct imsg		 imsg;
	struct ibuf		 b;
	int			 n, pty;

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
		case IMSG_CTL_TERMINAL:
			/* a terminal's pty, before its result */
			if ((pty = imsg_get_fd(&imsg)) == -1 ||
			    u->cur == NULL || u->cur->r.kind != DECK_TERMINAL) {
				if (pty != -1)
					close(pty);
				imsg_free(&imsg);
				logout(u, "nshd sent a terminal not asked for");
				return;
			}
			/* its stream may be gone; nsh ends as it closes */
			if ((t = term_find(u->cur->id, &v)) == NULL ||
			    t->pty != -1)
				close(pty);
			else
				t->pty = pty;
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
 * nshd's answer to u's login. On success, give u its token and reset
 * the failure count for its name. On failure, count it for the name
 * and the address, answer 401, and free u.
 */
static void
logged(struct user *u, int32_t status)
{
	struct jbuf	 j = { NULL, 0, 0 };
	struct fail	*f[2];
	char		 key[DECK_ADDR];
	unsigned char	 rnd[DECK_TOKEN / 2];
	uint32_t	 id = u->cur->id;
	size_t		 i;

	if (status != 0) {
		failed(u->name, u->addr);
		reply(id, 401, "{\"error\":\"Login incorrect\"}");
		user_free(u);
		return;
	}
	arc4random_buf(rnd, sizeof(rnd));
	for (i = 0; i < sizeof(rnd); i++)
		snprintf(u->token + 2 * i, 3, "%02x", rnd[i]);
	explicit_bzero(rnd, sizeof(rnd));
	fail_key(u->addr, key, sizeof(key));
	f[0] = fail_find(FAIL_NAME, u->name);
	f[1] = fail_find(FAIL_ADDR, key);
	if (f[0] != NULL) {
		if (f[0]->failed > 0 || f[0]->refused > 0)
			fail_log(EV_SUCCEEDED, f, u->name, u->addr, msnow());
		memset(f[0], 0, sizeof(*f[0]));
	}
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

/*
 * Count a failed login for name from addr. Once either has DECK_TRIES
 * failures in a row, each failure makes it wait longer. Log the failure
 * unless both logged a line in the last DECK_QUIET seconds.
 */
static void
failed(const char *name, const char *addr)
{
	struct fail	*f[2];
	char		 key[DECK_ADDR];
	int64_t		 now = msnow(), wait;
	size_t		 i, k;

	fail_key(addr, key, sizeof(key));
	f[0] = fail_add(FAIL_NAME, name, NULL, now);
	f[1] = fail_add(FAIL_ADDR, key, f[0], now);
	for (k = 0; k < 2; k++) {
		if (now - f[k]->last >= DECK_FORGET * 1000)
			f[k]->row = 0;
		f[k]->last = now;
		f[k]->row++;
		wait = 0;
		if (f[k]->row >= DECK_TRIES)
			for (wait = 1, i = DECK_TRIES; i < f[k]->row &&
			    wait < DECK_WAIT; i++)
				wait *= 2;
		if (wait > DECK_WAIT)
			wait = DECK_WAIT;
		f[k]->until = now + wait * 1000;
	}
	fail_log(EV_FAILED, f, name, addr, now);
}

/*
 * The key that failures from addr are counted under: for an IPv6
 * address, its /64, since one host may hold all of it; else addr.
 */
static void
fail_key(const char *addr, char *key, size_t len)
{
	struct in6_addr	 in6;
	char		 a[DECK_ADDR], *p;

	strlcpy(a, addr, sizeof(a));
	if ((p = strchr(a, '%')) != NULL)
		*p = '\0';
	if (inet_pton(AF_INET6, a, &in6) == 1 &&
	    !IN6_IS_ADDR_V4MAPPED(&in6)) {
		memset(&in6.s6_addr[8], 0, 8);
		inet_ntop(AF_INET6, &in6, a, sizeof(a));
		snprintf(key, len, "%s/64", a);
	} else
		strlcpy(key, addr, len);
}

/* the count of kind for key, or NULL if there is none */
static struct fail *
fail_find(int kind, const char *key)
{
	size_t	 i;

	for (i = 0; i < DECK_FAILS; i++)
		if (fails[i].kind == kind && strcmp(fails[i].key, key) == 0)
			return (&fails[i]);
	return (NULL);
}

/*
 * The count of kind for key, made if there is none. A new count takes
 * the place of the one whose wait ended longest ago, but never keep's.
 */
static struct fail *
fail_add(int kind, const char *key, struct fail *keep, int64_t now)
{
	struct fail	*f;
	size_t		 i;

	if ((f = fail_find(kind, key)) != NULL)
		return (f);
	for (i = 0; i < DECK_FAILS; i++)
		if (&fails[i] != keep && (f == NULL ||
		    fails[i].until < f->until))
			f = &fails[i];
	memset(f, 0, sizeof(*f));
	f->kind = kind;
	strlcpy(f->key, key, sizeof(f->key));
	f->logged = now - DECK_QUIET * 1000;
	return (f);
}

/*
 * Log a login for name from addr that failed, was refused or succeeded,
 * as ev says. f holds the counts for the name and the address; either
 * may be NULL. Each line says how many were not logged before it. If
 * both counts logged a line in the last DECK_QUIET seconds, count the
 * login instead of logging it. A success is always logged.
 */
static void
fail_log(int ev, struct fail *f[2], const char *name, const char *addr,
    int64_t now)
{
	static const char	*verb[] = { "failed", "refused", "succeeded" };
	char			 line[512];
	size_t			 i, len;
	int			 due = ev == EV_SUCCEEDED;

	for (i = 0; i < 2; i++)
		if (f[i] != NULL && now - f[i]->logged >= DECK_QUIET * 1000)
			due = 1;
	for (i = 0; !due && i < 2; i++) {
		if (f[i] == NULL)
			continue;
		if (ev == EV_FAILED)
			f[i]->failed++;
		else
			f[i]->refused++;
	}
	if (!due)
		return;
	snprintf(line, sizeof(line), "login %s for %s from %s", verb[ev],
	    name, addr);
	for (i = 0; i < 2; i++) {
		if (f[i] == NULL)
			continue;
		len = strlen(line);
		snprintf(line + len, sizeof(line) - len, "; %s: %u in a row",
		    f[i]->key, f[i]->row);
		if (f[i]->failed > 0 || f[i]->refused > 0) {
			len = strlen(line);
			snprintf(line + len, sizeof(line) - len, ", not logged "
			    "%u failed and %u refused", f[i]->failed,
			    f[i]->refused);
		}
		f[i]->failed = f[i]->refused = 0;
		f[i]->logged = now;
	}
	log_warnx("%s", line);
}

/* the monotonic clock, in ms */
static int64_t
msnow(void)
{
	struct timespec	 ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* u's next request, to nshd, unless one is waiting for an answer */
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
	struct nshd_terminal	 tm;
	struct pending		*p;

	if (u->cur != NULL || u->state != U_READY ||
	    (p = TAILQ_FIRST(&u->queue)) == NULL)
		return;
	TAILQ_REMOVE(&u->queue, p, entry);
	u->nqueue--;
	u->cur = p;
	u->headed = u->nrecords = u->hasctx = u->sent = u->lost = 0;
	if (p->r.kind == DECK_COMPLETE) {
		u->cmplt = rows_new();
		facts_in_init(&u->in, rows_record, u->cmplt);
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
		u->naming = tables_ready();
		ask(u, u->naming ? IMSG_CTL_NAMES : IMSG_CTL_COMMANDS, NULL, 0);
		break;
	case DECK_TERMINAL:
		memset(&tm, 0, sizeof(tm));
		tm.rows = p->r.rows > 0 ? p->r.rows : 24;
		tm.cols = p->r.cols > 0 ? p->r.cols : 80;
		ask(u, IMSG_CTL_TERMINAL, &tm, sizeof(tm));
		break;
	case DECK_RULES:
	case DECK_SETRULES:
		rules(u);
		break;
	default:
		/* session's own request: the watch its streams want */
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

/* u's rules request to nshd: the rules asked for, or the next part */
static void
rules(struct user *u)
{
	struct nshd_rules	 rl;
	struct pending		*p = u->cur;
	size_t			 n;

	memset(&rl, 0, sizeof(rl));
	rl.set = p->r.kind == DECK_SETRULES;
	rl.rtable = p->r.n;
	strlcpy(rl.daemon, p->r.daemon, sizeof(rl.daemon));
	if ((n = p->textlen - p->textoff) > sizeof(rl.text))
		n = sizeof(rl.text);
	if (n > 0)
		memcpy(rl.text, p->text + p->textoff, n);
	rl.len = n;
	p->textoff += n;
	rl.last = p->textoff == p->textlen;
	ask(u, IMSG_CTL_RULES, &rl, sizeof(rl));
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
	if (p->r.kind == DECK_SETRULES && status == 0 &&
	    p->textoff < p->textlen) {
		rules(u);
		return;
	}
	if (p->r.kind == DECK_RULES && u->lost) {
		/* rules cut short are not the rules */
		u->outlen = 0;
		why = "% nshdeck: the rules are longer than it keeps\n";
		kept(u, why, strlen(why));
		status = 1;
	}
	if (p->r.kind == DECK_COMPLETE && !u->naming && status == 0 &&
	    !p->gone) {
		/* the tables are here: build them, then ask for the names */
		facts_in_free(&u->in);
		facts_in_init(&u->in, rows_record, u->cmplt);
		if (tables_build(u->cmplt) == 0) {
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
		/* not the system's to answer: ask nshd's shows, as nsh does */
		free(u->out);
		u->out = NULL;
		u->outlen = 0;
		u->toro = RO_CONNECT;
		u->connect = p->id;
		pipe_compose(&toparent, DECK_CONNECT, p->id, -1, &ro,
		    sizeof(ro));
		return;
	}
	if (p->r.kind == DECK_TERMINAL)
		term_started(u, p->id, status);
	else if (p->id == 0) {
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
		if (p->r.kind == DECK_COMPLETE && status == 0) {
			completing = u->cmplt;
			tables_complete(p->r.text, p->r.n,
			    u->ctx.ifname[0] != '\0', u->ctx.bridge,
			    completed, u);
			completing = NULL;
		}
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
	rows_free(u->cmplt);
	u->cmplt = NULL;
	free(u->j.p);
	memset(&u->j, 0, sizeof(u->j));
	free(u->out);
	u->out = NULL;
	u->outlen = 0;
	free(p->text);
	free(p);
	u->cur = NULL;
	u->toro = RO_NONE;
	rewatch(u);
	next(u);
}

/* what nshd printed for u's request, kept up to DECK_OUTPUT bytes */
static void
kept(struct user *u, const void *data, size_t len)
{
	char	*q;

	if (u->outlen + len > DECK_OUTPUT) {
		u->lost = 1;
		return;
	}
	if ((q = realloc(u->out, u->outlen + len)) == NULL)
		fatal(NULL);
	u->out = q;
	memcpy(u->out + u->outlen, data, len);
	u->outlen += len;
}

/*
 * facts from from, for u's request, as JSON to front, from paused once
 * front has DECK_WINDOW messages not yet written: -1 if they cannot be
 * read
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

/* the pipe that answers u's request: to nshd, to nshd's shows, or NULL */
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
 * What u's streams want nshd to watch, if that changed, asked ahead of
 * u's other requests: commits and routes while any stream is open, and
 * the logs any of them follows
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

/*
 * A terminal of u's, for stream id, and its stream begun; the caller
 * asks nshd for it
 */
static void
terminal(uint32_t id, struct user *u)
{
	struct terminal	*t, *o;
	int		 n;

	if ((t = calloc(1, sizeof(*t))) == NULL)
		fatal(NULL);
	/* the lowest number none of u's terminals has */
	for (n = 1; n <= DECK_TERMINALS; n++) {
		TAILQ_FOREACH(o, &u->terms, entry)
			if (o->n == n)
				break;
		if (o == NULL)
			break;
	}
	t->id = id;
	t->n = n;
	t->state = TS_ASKED;
	t->pty = -1;
	TAILQ_INSERT_TAIL(&u->terms, t, entry);
	u->nterms++;
	head(id, 200, 1, NULL, 0);
}

/* the terminal with stream id, and its user, or NULL */
static struct terminal *
term_find(uint32_t id, struct user **up)
{
	struct terminal	*t;
	struct user	*u;

	TAILQ_FOREACH(u, &users, entry)
		TAILQ_FOREACH(t, &u->terms, entry)
			if (t->id == id) {
				*up = u;
				return (t);
			}
	return (NULL);
}

/*
 * nshd's answer to the terminal of stream id: if status is 0, its pty,
 * which came before, is read and written; else the terminal ends, with
 * the reason nshd printed
 */
static void
term_started(struct user *u, uint32_t id, int32_t status)
{
	struct terminal	*t;
	struct user	*v;
	struct jbuf	 j = { NULL, 0, 0 };
	char		*why;

	if ((t = term_find(id, &v)) == NULL || v != u)
		return;
	if (status != 0 || t->pty == -1) {
		if ((why = status != 0 && u->outlen > 0 ?
		    strndup(u->out, u->outlen) :
		    strdup("nshd gave no terminal")) == NULL)
			fatal(NULL);
		term_end(u, t, why);
		free(why);
		return;
	}
	if (fcntl(t->pty, F_SETFL, O_NONBLOCK) == -1)
		fatal("fcntl");
	t->state = TS_RUNS;
	j_fmt(&j, "event: terminal\ndata: {\"n\":%d}\n\n", t->n);
	j_flush(&j, t->id);
	term_event(t);
}

/*
 * What nsh writes, read and sent to the terminal's stream as an event
 * in base64, and what was typed, written to nsh. When nsh ends, so does
 * the terminal
 */
static void
term_io(int fd, short event, void *arg)
{
	struct terminal	*t = arg;
	struct user	*u;
	unsigned char	 buf[DECK_PTY];
	char		 b64[DECK_PTY / 3 * 4 + 1];
	struct jbuf	 j = { NULL, 0, 0 };
	ssize_t		 n;

	if (term_find(t->id, &u) != t)
		fatalx("%s: no such terminal", __func__);
	t->events = 0;
	if (event & EV_WRITE) {
		if ((n = write(t->pty, t->typed, t->typedlen)) == -1 &&
		    errno != EAGAIN && errno != EINTR) {
			term_end(u, t, "nsh ended");
			return;
		}
		if (n > 0) {
			memmove(t->typed, t->typed + n, t->typedlen - n);
			t->typedlen -= n;
		}
	}
	if (event & EV_READ) {
		/* nsh gone, its side of the pty with it */
		if ((n = read(t->pty, buf, sizeof(buf))) == 0 ||
		    (n == -1 && errno != EAGAIN && errno != EINTR)) {
			term_end(u, t, "nsh ended");
			return;
		}
		if (n > 0) {
			if (b64_ntop(buf, n, b64, sizeof(b64)) == -1)
				fatalx("%s: b64_ntop", __func__);
			J(&j, "event: out\ndata: ");
			j_raw(&j, b64, strlen(b64));
			J(&j, "\n\n");
			t->sent += j_flush(&j, t->id);
		}
	}
	term_event(t);
}

/* t's pty read while front may take more, and written while t has some */
static void
term_event(struct terminal *t)
{
	short	 events = 0;

	if (t->state != TS_RUNS)
		return;
	if (t->sent < DECK_WINDOW)
		events |= EV_READ;
	if (t->typedlen > 0)
		events |= EV_WRITE;
	if (t->events != 0)
		event_del(&t->ev);
	t->events = events;
	if (events == 0)
		return;
	event_set(&t->ev, t->pty, events, term_io, t);
	event_add(&t->ev, NULL);
}

/*
 * t ended, as why says, and its stream with it; and its pty closed, so
 * nsh ends
 */
static void
term_end(struct user *u, struct terminal *t, const char *why)
{
	struct jbuf	 j = { NULL, 0, 0 };

	if (why != NULL) {
		J(&j, "event: end\ndata: {\"text\":");
		j_str(&j, why, strlen(why));
		J(&j, "}\n\n");
		j_flush(&j, t->id);
		pipe_compose(&tofront, DECK_END, t->id, -1, NULL, 0);
	}
	if (t->events != 0)
		event_del(&t->ev);
	if (t->pty != -1)
		close(t->pty);
	TAILQ_REMOVE(&u->terms, t, entry);
	u->nterms--;
	if (t->typed != NULL)
		explicit_bzero(t->typed, t->typedlen);
	free(t->typed);
	explicit_bzero(t, sizeof(*t));
	free(t);
}

/*
 * What u typed in its terminal r names, to write to nsh; and its new
 * size, if r has one
 */
static void
typed(uint32_t id, struct user *u, struct deck_request *r)
{
	struct terminal	*t;
	struct winsize	 ws;
	size_t		 len = strlen(r->text);
	char		*p;

	TAILQ_FOREACH(t, &u->terms, entry)
		if (t->n == r->n && t->state == TS_RUNS)
			break;
	if (t == NULL) {
		reply(id, 404, "{\"error\":\"no such terminal\"}");
		return;
	}
	if (t->typedlen + len > DECK_TYPED) {
		reply(id, 503, "{\"error\":\"nsh has not taken what was "
		    "typed\"}");
		return;
	}
	if (len > 0) {
		if ((p = realloc(t->typed, t->typedlen + len)) == NULL)
			fatal(NULL);
		t->typed = p;
		memcpy(t->typed + t->typedlen, r->text, len);
		t->typedlen += len;
	}
	if (r->rows > 0 && r->cols > 0) {
		memset(&ws, 0, sizeof(ws));
		ws.ws_row = r->rows;
		ws.ws_col = r->cols;
		if (ioctl(t->pty, TIOCSWINSZ, &ws) == -1)
			log_warn("%s: TIOCSWINSZ", u->name);
	}
	term_event(t);
	head(id, 200, 0, NULL, 0);
	reply(id, 0, "{\"ok\":true}");
}

/* front's client for id is gone: its request, waiting or answered */
static void
gone(uint32_t id)
{
	struct deck_pipe	*from;
	struct user		*u;
	struct pending		*p;
	struct stream		*s;
	struct terminal		*t;

	/* a terminal's stream: nsh ends with it */
	if ((t = term_find(id, &u)) != NULL)
		term_end(u, t, NULL);
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
				free(p->text);
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
 * ended; if nshd ended it, why is logged
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
		    TAILQ_EMPTY(&u->terms) && u->cur == NULL &&
		    now - u->used > DECK_IDLE) {
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

/* kf_names() for complete.c: the names nshd sent for this completion */
int
kf_names(int kind, StringList *sl)
{
	if (completing == NULL)
		return (-1);
	return (rows_names(completing, kind, sl));
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

/* u's answer begun, if it is not: its head, and the start of its records */
static void
j_answer(struct user *u)
{
	if (u->headed)
		return;
	head(u->cur->id, 200, 0, NULL, 0);
	u->headed = 1;
	J(&u->j, "{\"records\":[");
}

/* j sent to front for id, in messages that fit, and emptied; their number */
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

	/* a terminal's request ends with the terminal */
	if (u->cur != NULL && u->cur->r.kind == DECK_TERMINAL)
		u->cur->gone = 1;
	TAILQ_FOREACH(p, &u->queue, entry)
		if (p->r.kind == DECK_TERMINAL)
			p->id = 0;
	while (!TAILQ_EMPTY(&u->terms))
		term_end(u, TAILQ_FIRST(&u->terms), "logged out");
	if (u->cur != NULL) {
		/* an answer begun still ends as valid JSON */
		if (u->cur->id != 0 && !u->cur->gone && u->headed) {
			J(&u->j, "],\"error\":\"nshd ended the session\","
			    "\"ok\":false}\n");
			j_flush(&u->j, u->cur->id);
			pipe_compose(&tofront, DECK_END, u->cur->id, -1, NULL, 0);
		} else if (u->cur->id != 0 && !u->cur->gone)
			reply(u->cur->id, 503, "{\"error\":\"nshd ended the "
			    "session\"}");
		free(u->cur->text);
		explicit_bzero(u->cur, sizeof(*u->cur));
		free(u->cur);
	}
	while ((p = TAILQ_FIRST(&u->queue)) != NULL) {
		TAILQ_REMOVE(&u->queue, p, entry);
		if (p->id != 0)
			reply(p->id, 503, "{\"error\":\"logged out\"}");
		free(p->text);
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
	rows_free(u->cmplt);
	free(u->j.p);
	free(u->out);
	TAILQ_REMOVE(&users, u, entry);
	nusers--;
	explicit_bzero(u, sizeof(*u));
	free(u);
}
