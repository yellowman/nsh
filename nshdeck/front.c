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
 * front: httpd's FastCGI connections, on the socket parent bound, fd 5.
 * Each connection is one request: front reads its records, then its
 * parameters, then its body, each under a limit of its own, and
 * believes nothing httpd's parameters say about the client, as any
 * process of DECK_GROUP's can write to the socket. It takes the
 * request's endpoint, the last part of its path; its fields, from the
 * query of a GET or the form body of a POST, each named, once, with a
 * bound; and the cookie's token. A request must say it is the page's,
 * by an X-Nshdeck header, which a page of another site cannot send
 * without asking first; except a stream, events or a terminal's, which
 * the browser's EventSource asks for, and which cannot send it. The
 * request goes to session as one message, zeroed first; session's
 * answer comes back to the connection as FastCGI
 * records, and the connection closes. front sends session nothing of
 * an answer's until the client has written what it was sent, when it
 * says so (DECK_READ), so a slow client holds up only its own answer.
 *
 * An event stream stays open, a comment written to it each
 * DECK_KEEPALIVE seconds so httpd does not time it out. Its events wait
 * in front until the client has written what it was sent, then go to it
 * together, and session hears so, as it does of an answer; past
 * DECK_UNREAD bytes waiting, the oldest go, and the client is sent a
 * dropped event in their place, so it knows to ask again for what it
 * shows. A terminal's stream never comes to that: session sends it
 * only DECK_WINDOW messages front has not written. front takes no more
 * than DECK_CONNS connections, and a request that does not arrive whole
 * within DECK_ARRIVE seconds is closed.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <errno.h>
#include <event.h>
#include <stddef.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "nshdeck.h"

#define DECK_CONNS	128		/* connections at once, at most */
#define DECK_ARRIVE	30		/* seconds a request may take to come */
#define DECK_KEEPALIVE	30		/* seconds between a stream's comments */
#define DECK_UNREAD	(1024 * 1024)	/* a stream's events waiting, at most */
#define DROPPED		"event: dropped\ndata: {}\n\n"
#define PARAMS_MAX	16384		/* a request's parameters, at most */
#define BODY_MAX	8192		/* a request's body, at most */

#define FCGI_HEADER	8
#define FCGI_CONTENT	65535
#define FCGI_RECORD	(FCGI_HEADER + FCGI_CONTENT + 255)
#define FCGI_VERSION_1	1
#define FCGI_BEGIN	1
#define FCGI_ABORT	2
#define FCGI_END	3
#define FCGI_PARAMS	4
#define FCGI_STDIN	5
#define FCGI_STDOUT	6
#define FCGI_RESPONDER	1

/* what a connection waits for */
enum { C_BEGIN, C_PARAMS, C_STDIN, C_ANSWER, C_DONE };

struct conn {
	TAILQ_ENTRY(conn)	 entry;
	uint32_t		 id;		/* session's for it */
	int			 fd;
	int			 state;
	int			 asked;		/* session has the request */
	int			 events;	/* an event stream */
	uint16_t		 rid;		/* httpd's id for the request */
	struct event		 ev;
	struct event		 tm;		/* arrival, or the next comment */
	unsigned char		 in[FCGI_RECORD];	/* a record, as it comes */
	size_t			 inlen;
	char			 params[PARAMS_MAX];
	size_t			 paramslen;
	char			 body[BODY_MAX + 1];
	size_t			 bodylen;
	char			*out;		/* to write */
	size_t			 outlen;
	size_t			 outoff;
	char			*pend;		/* a stream's events, waiting */
	size_t			 pendlen;
	int			 dropped;	/* some went since the last sent */
};

/* the parameters front reads, of a request's */
struct params {
	char	method[8];
	char	uri[256];
	char	query[BODY_MAX + 1];
	char	ctype[128];
	char	clen[16];
	char	cookie[1024];
	char	xdeck[8];
};

/* what each endpoint is, and the fields it takes */
#define F_USER		0x001
#define F_PASSWORD	0x002
#define F_WORDS		0x004
#define F_WHAT		0x008
#define F_N		0x010
#define F_MODE		0x020
#define F_LINE		0x040
#define F_RTABLE	0x080
#define F_CHECK		0x100
#define F_MINUTES	0x200
#define F_COMMENT	0x400
#define F_LOGS		0x800
#define F_HELP		0x1000
#define F_KEYS		0x2000
#define F_ROWS		0x4000
#define F_COLS		0x8000
#define F_TERMINAL	0x10000
static const struct endpoint {
	const char	*name;
	int		 kind;
	int		 post;
	int		 fields;
} endpoints[] = {
	{ "login",	DECK_LOGIN,	1, F_USER | F_PASSWORD },
	{ "logout",	DECK_LOGOUT,	1, 0 },
	{ "whoami",	DECK_WHOAMI,	0, 0 },
	{ "show",	DECK_SHOW,	0, F_WORDS },
	{ "config",	DECK_CONFIG,	0, F_WHAT | F_N },
	{ "configure",	DECK_CONFIGURE,	1, F_MODE },
	{ "line",	DECK_LINE,	1, F_LINE },
	{ "exit",	DECK_EXIT,	1, 0 },
	{ "commit",	DECK_COMMIT,	1, F_CHECK | F_MINUTES | F_COMMENT },
	{ "rollback",	DECK_ROLLBACK,	1, F_N },
	{ "op",		DECK_OP,	1, F_LINE | F_RTABLE },
	{ "complete",	DECK_COMPLETE,	0, F_LINE | F_HELP },
	{ "terminal",	DECK_TERMINAL,	0, F_ROWS | F_COLS },
	{ "type",	DECK_TYPE,	1, F_TERMINAL | F_KEYS | F_ROWS |
	    F_COLS },
	{ "events",	DECK_EVENTS,	0, F_LOGS },
};

static TAILQ_HEAD(, conn)	 conns = TAILQ_HEAD_INITIALIZER(conns);
static int			 nconns;
static uint32_t			 conn_id;
static struct event		 ev_accept, ev_pause;
static struct deck_pipe		 parent, session;

static void	 front_parent(int, short, void *);
static void	 front_session(int, short, void *);
static void	 front_accept(int, short, void *);
static void	 front_io(int, short, void *);
static void	 front_timer(int, short, void *);
static int	 front_record(struct conn *, int, const unsigned char *,
		    size_t);
static int	 front_params(struct conn *, struct params *);
static int	 front_request(struct conn *);
static int	 front_fields(const char *, int, struct deck_request *);
static int	 front_field(int, const char *, struct deck_request *);
static int	 front_token(const char *, char *);
static int	 decode(char *, size_t, const char *, size_t);
static void	 front_error(struct conn *, int, const char *);
static void	 front_head(struct conn *, struct deck_head *);
static void	 front_stdout(struct conn *, const void *, size_t);
static void	 front_event(struct conn *, const char *, size_t);
static void	 front_events(struct conn *, int);
static void	 front_end(struct conn *);
static void	 front_out(struct conn *, const void *, size_t);
static void	 front_close(struct conn *);
static void	 front_wait(struct conn *);
static struct conn *conn_find(uint32_t);

__dead void
front(int debug, int verbose)
{
	deck_child("front", debug, verbose);
	deck_drop(DECK_FRONT);
	if (pledge("stdio unix", NULL) == -1)
		fatal("pledge");

	if (pipe_init(&parent, 3, front_parent, 0) == -1 ||
	    pipe_init(&session, 4, front_session, 0) == -1)
		fatal(NULL);
	if (listen(5, 16) == -1)
		fatal("listen");
	event_set(&ev_accept, 5, EV_READ | EV_PERSIST, front_accept, NULL);
	event_add(&ev_accept, NULL);
	evtimer_set(&ev_pause, front_accept, NULL);
	event_dispatch();
	exit(0);
}

/* parent sends front nothing: its pipe closed, front ends */
static void
front_parent(int fd, short event, void *arg)
{
	if (pipe_io(&parent, event) == -1)
		exit(0);
	fatalx("parent sent what it may not");
}

/* session's answers, each to the connection it names, if still there */
static void
front_session(int fd, short event, void *arg)
{
	struct deck_head	 h;
	struct imsg		 imsg;
	struct ibuf		 b;
	struct conn		*c;
	int			 n;

	if (pipe_io(&session, event) == -1)
		fatalx("session closed its pipe");
	for (;;) {
		if ((n = imsgbuf_get(&session.ibuf, &imsg)) == -1)
			fatalx("session sent what imsg cannot read");
		if (n == 0)
			break;
		c = conn_find(imsg_get_id(&imsg));
		switch (imsg_get_type(&imsg)) {
		case DECK_HEAD:
			if (imsg_get_data(&imsg, &h, sizeof(h)) == -1 ||
			    memchr(h.cookie, '\0', sizeof(h.cookie)) == NULL)
				fatalx("session sent a head not whole");
			if (c != NULL)
				front_head(c, &h);
			break;
		case DECK_BODY:
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			if (c != NULL && c->events)
				front_event(c, ibuf_data(&b), ibuf_size(&b));
			else if (c != NULL)
				front_stdout(c, ibuf_data(&b), ibuf_size(&b));
			break;
		case DECK_END:
			if (c != NULL)
				front_end(c);
			break;
		default:
			fatalx("session sent imsg %u, which it may not",
			    imsg_get_type(&imsg));
		}
		imsg_free(&imsg);
	}
	pipe_event(&session);
}

static void
front_accept(int fd, short event, void *arg)
{
	struct timeval	 pause = { 1, 0 }, arrive = { DECK_ARRIVE, 0 };
	struct conn	*c;
	int		 s;

	if (event & EV_TIMEOUT) {
		event_add(&ev_accept, NULL);
		return;
	}
	if ((s = accept4(5, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK)) ==
	    -1) {
		/* out of descriptors: wait, or libevent loops here */
		if (errno == ENFILE || errno == EMFILE) {
			event_del(&ev_accept);
			evtimer_add(&ev_pause, &pause);
		} else if (errno != EWOULDBLOCK && errno != EINTR &&
		    errno != ECONNABORTED)
			log_warn("accept4");
		return;
	}
	if (conn_id == UINT32_MAX || (c = calloc(1, sizeof(*c))) == NULL) {
		log_warnx("%s: no room for a connection", __func__);
		close(s);
		return;
	}
	c->id = ++conn_id;
	c->fd = s;
	c->state = C_BEGIN;
	event_set(&c->ev, s, EV_READ, front_io, c);
	event_add(&c->ev, NULL);
	evtimer_set(&c->tm, front_timer, c);
	evtimer_add(&c->tm, &arrive);
	TAILQ_INSERT_TAIL(&conns, c, entry);
	/* the rest wait in the backlog */
	if (++nconns == DECK_CONNS)
		event_del(&ev_accept);
}

/* the request's time, gone; or a stream's comment, due */
static void
front_timer(int fd, short event, void *arg)
{
	struct timeval	 tv = { DECK_KEEPALIVE, 0 };
	struct conn	*c = arg;

	if (!c->events) {
		front_close(c);
		return;
	}
	front_event(c, ":\n\n", 3);
	evtimer_add(&c->tm, &tv);
}

/* what c's client sent, read, and what it was sent, written */
static void
front_io(int fd, short event, void *arg)
{
	struct conn	*c = arg;
	unsigned char	*p;
	ssize_t		 n;
	size_t		 clen, need;

	if (event & EV_WRITE) {
		if ((n = write(c->fd, c->out + c->outoff, c->outlen -
		    c->outoff)) == -1 && errno != EAGAIN && errno != EINTR) {
			front_close(c);
			return;
		}
		if (n > 0)
			c->outoff += n;
		if (c->outoff == c->outlen) {
			c->outoff = c->outlen = 0;
			if (c->state == C_DONE) {
				front_close(c);
				return;
			}
			/* session may send more of the answer */
			if (c->events)
				front_events(c, 0);
			if (c->asked && c->outoff == c->outlen)
				pipe_compose(&session, DECK_READ, c->id, -1,
				    NULL, 0);
		}
	}
	if (event & EV_READ) {
		n = read(c->fd, c->in + c->inlen, sizeof(c->in) - c->inlen);
		if (n == 0 || (n == -1 && errno != EAGAIN && errno != EINTR)) {
			front_close(c);
			return;
		}
		if (n > 0)
			c->inlen += n;
		/* each whole record */
		while (c->inlen >= FCGI_HEADER) {
			p = c->in;
			clen = (p[4] << 8) | p[5];
			need = FCGI_HEADER + clen + p[6];
			if (c->inlen < need)
				break;
			if (p[0] != FCGI_VERSION_1 ||
			    front_record(c, p[1], p + FCGI_HEADER, clen) ==
			    -1) {
				front_close(c);
				return;
			}
			memmove(c->in, c->in + need, c->inlen - need);
			c->inlen -= need;
		}
	}
	front_wait(c);
}

/*
 * One record of type, with its content: -1 if it is wrong, which
 * closes the connection
 */
static int
front_record(struct conn *c, int type, const unsigned char *data,
    size_t len)
{
	/* once the request is in, what httpd sends is not read */
	if (c->state >= C_ANSWER)
		return (type == FCGI_ABORT ? -1 : 0);
	switch (type) {
	case FCGI_BEGIN:
		if (c->state != C_BEGIN || len != 8 ||
		    ((data[0] << 8) | data[1]) != FCGI_RESPONDER)
			return (-1);
		c->rid = (c->in[2] << 8) | c->in[3];
		c->state = C_PARAMS;
		return (0);
	case FCGI_PARAMS:
		if (c->state != C_PARAMS ||
		    ((c->in[2] << 8) | c->in[3]) != c->rid)
			return (-1);
		if (len == 0) {
			c->state = C_STDIN;
			return (0);
		}
		if (len > sizeof(c->params) - c->paramslen) {
			front_error(c, 431, "too many parameters");
			return (0);
		}
		memcpy(c->params + c->paramslen, data, len);
		c->paramslen += len;
		return (0);
	case FCGI_STDIN:
		if (c->state != C_STDIN ||
		    ((c->in[2] << 8) | c->in[3]) != c->rid)
			return (-1);
		if (len == 0)
			return (front_request(c));
		if (len > BODY_MAX - c->bodylen) {
			front_error(c, 413, "body too long");
			return (0);
		}
		memcpy(c->body + c->bodylen, data, len);
		c->bodylen += len;
		return (0);
	default:
		/* an abort too: the connection goes */
		return (-1);
	}
}

/* the request, whole, to session, or answered with why it is not one */
static int
front_request(struct conn *c)
{
	const struct endpoint	*e = NULL;
	struct deck_request	 r;
	struct params		 p;
	const char		*errstr, *name;
	size_t			 i;
	long long		 clen;

	c->state = C_ANSWER;
	evtimer_del(&c->tm);
	if (front_params(c, &p) == -1) {
		front_error(c, 400, "parameters front cannot read");
		return (0);
	}
	name = (name = strrchr(p.uri, '/')) != NULL ? name + 1 : p.uri;
	for (i = 0; i < sizeof(endpoints) / sizeof(endpoints[0]); i++)
		if (strcmp(name, endpoints[i].name) == 0)
			e = &endpoints[i];
	if (e == NULL) {
		front_error(c, 404, "no such request");
		return (0);
	}
	if (strcmp(p.method, e->post ? "POST" : "GET") != 0) {
		front_error(c, 405, e->post ? "POST it" : "GET it");
		return (0);
	}
	/* a page of another site cannot set this without asking */
	if (e->kind != DECK_EVENTS && e->kind != DECK_TERMINAL &&
	    strcmp(p.xdeck, "1") != 0) {
		front_error(c, 403, "not the page's");
		return (0);
	}
	clen = strtonum(p.clen[0] == '\0' ? "0" : p.clen, 0, BODY_MAX,
	    &errstr);
	if (errstr != NULL || (size_t)clen != c->bodylen) {
		front_error(c, 400, "a body not as long as it says");
		return (0);
	}
	c->body[c->bodylen] = '\0';
	if (e->post && c->bodylen > 0 && strncmp(p.ctype,
	    "application/x-www-form-urlencoded", 33) != 0) {
		front_error(c, 415, "a form, please");
		return (0);
	}
	memset(&r, 0, sizeof(r));
	r.kind = e->kind;
	if (front_token(p.cookie, r.token) == -1 ||
	    front_fields(e->post ? c->body : p.query, e->fields, &r) == -1) {
		explicit_bzero(&r, sizeof(r));
		explicit_bzero(c->body, sizeof(c->body));
		front_error(c, 400, "fields front cannot take");
		return (0);
	}
	explicit_bzero(c->body, sizeof(c->body));
	c->asked = 1;
	pipe_compose(&session, DECK_REQUEST, c->id, -1, &r, sizeof(r));
	explicit_bzero(&r, sizeof(r));
	return (0);
}

/*
 * The parameters front reads, out of c's, each its length and its
 * bytes as FastCGI says: -1 if one is not whole or past its bound
 */
static int
front_params(struct conn *c, struct params *p)
{
	static const struct {
		const char	*name;
		size_t		 off;
		size_t		 size;
	} want[] = {
#define P(n, f)	{ n, offsetof(struct params, f), sizeof(((struct params *)0)->f) }
		P("REQUEST_METHOD", method),
		P("DOCUMENT_URI", uri),
		P("QUERY_STRING", query),
		P("CONTENT_TYPE", ctype),
		P("CONTENT_LENGTH", clen),
		P("HTTP_COOKIE", cookie),
		P("HTTP_X_NSHDECK", xdeck),
#undef P
	};
	const unsigned char	*s = (unsigned char *)c->params;
	size_t			 left = c->paramslen, len[2], i, k;

	memset(p, 0, sizeof(*p));
	while (left > 0) {
		for (k = 0; k < 2; k++) {
			if (left < 1)
				return (-1);
			if (s[0] & 0x80) {
				if (left < 4)
					return (-1);
				len[k] = ((size_t)(s[0] & 0x7f) << 24) |
				    (s[1] << 16) | (s[2] << 8) | s[3];
				s += 4;
				left -= 4;
			} else {
				len[k] = s[0];
				s++;
				left--;
			}
		}
		if (len[0] > left || len[1] > left - len[0])
			return (-1);
		for (i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
			if (strlen(want[i].name) != len[0] ||
			    memcmp(want[i].name, s, len[0]) != 0)
				continue;
			if (len[1] >= want[i].size ||
			    memchr(s + len[0], '\0', len[1]) != NULL)
				return (-1);
			memcpy((char *)p + want[i].off, s + len[0], len[1]);
		}
		s += len[0] + len[1];
		left -= len[0] + len[1];
	}
	return (0);
}

/*
 * The fields of form, key=value pairs joined by &, each that fields
 * names, once, into r: -1 if one is not, is twice, or is not right
 */
static int
front_fields(const char *form, int fields, struct deck_request *r)
{
	static const struct {
		const char	*name;
		int		 field;
	} names[] = {
		{ "user", F_USER }, { "password", F_PASSWORD },
		{ "words", F_WORDS }, { "what", F_WHAT }, { "n", F_N },
		{ "mode", F_MODE }, { "line", F_LINE }, { "rtable", F_RTABLE },
		{ "check", F_CHECK }, { "minutes", F_MINUTES },
		{ "comment", F_COMMENT }, { "logs", F_LOGS },
		{ "help", F_HELP }, { "keys", F_KEYS }, { "rows", F_ROWS },
		{ "cols", F_COLS }, { "terminal", F_TERMINAL },
	};
	char		 key[16], value[NSHD_LINE];
	const char	*p, *eq, *end;
	size_t		 i;
	int		 seen = 0, f;

	for (p = form; *p != '\0'; p = *end == '&' ? end + 1 : end) {
		end = p + strcspn(p, "&");
		if ((eq = memchr(p, '=', end - p)) == NULL ||
		    decode(key, sizeof(key), p, eq - p) == -1 ||
		    decode(value, sizeof(value), eq + 1, end - eq - 1) == -1)
			return (-1);
		for (i = 0, f = 0; i < sizeof(names) / sizeof(names[0]); i++)
			if (strcmp(key, names[i].name) == 0)
				f = names[i].field;
		if ((f & fields) == 0 || (f & seen) != 0 ||
		    front_field(f, value, r) == -1) {
			explicit_bzero(value, sizeof(value));
			return (-1);
		}
		seen |= f;
		explicit_bzero(value, sizeof(value));
	}
	/* a configuration's what, if none was named */
	if ((fields & F_WHAT) && (seen & F_WHAT) == 0)
		strlcpy(r->text, "running-config", sizeof(r->text));
	/* n is rollback's, and changes', which needs it: what n changed */
	if ((fields & F_WHAT) && strcmp(r->text, "changes") == 0) {
		if ((seen & F_N) == 0)
			return (-1);
		snprintf(r->text, sizeof(r->text), "rollback %d diff", r->n);
	} else if ((fields & F_WHAT) && (seen & F_N)) {
		if (strcmp(r->text, "rollback") != 0)
			return (-1);
		snprintf(r->text, sizeof(r->text), "rollback %d", r->n);
	}
	return (0);
}

/* field f's value, into r: -1 if it is not one f takes */
static int
front_field(int f, const char *v, struct deck_request *r)
{
	static const char	*whats[] = { "running", "startup",
				    "candidate", "diff", "rollback", "changes" };
	static const char	*modes[] = { "private", "shared",
				    "exclusive", "terminal" };
	static const char	*logs[] = { "daemon", "messages", "authlog",
				    "pflog" };
	char			 buf[64], *s, *t;
	const char		*errstr;
	size_t			 i;

	switch (f) {
	case F_USER:
		/* what a login name may be, and no leading '-' */
		if (v[0] == '\0' || v[0] == '-' || strlen(v) >= NSHD_NAME ||
		    strspn(v, "abcdefghijklmnopqrstuvwxyz"
		    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != strlen(v))
			return (-1);
		strlcpy(r->text, v, sizeof(r->text));
		return (0);
	case F_PASSWORD:
		return (strlcpy(r->password, v, sizeof(r->password)) >=
		    sizeof(r->password) ? -1 : 0);
	case F_WORDS:
		return (strlcpy(r->text, v, NSHD_WORDS) >= NSHD_WORDS ? -1 : 0);
	case F_LINE:
	case F_KEYS:
		return (strlcpy(r->text, v, sizeof(r->text)) >=
		    sizeof(r->text) ? -1 : 0);
	case F_COMMENT:
		return (strlcpy(r->comment, v, sizeof(r->comment)) >=
		    sizeof(r->comment) ? -1 : 0);
	case F_WHAT:
		for (i = 0; i < sizeof(whats) / sizeof(whats[0]); i++)
			if (strcmp(v, whats[i]) == 0) {
				snprintf(r->text, sizeof(r->text), "%s%s",
				    whats[i], i >= 4 ? "" : "-config");
				return (0);
			}
		return (-1);
	case F_MODE:
		for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
			if (strcmp(v, modes[i]) == 0) {
				r->n = i + 1;
				return (0);
			}
		return (-1);
	case F_N:
		r->n = strtonum(v, 0, NSHD_ROLLBACKS - 1, &errstr);
		return (errstr == NULL ? 0 : -1);
	case F_RTABLE:
		r->n = strtonum(v, 0, 255, &errstr);
		return (errstr == NULL ? 0 : -1);
	case F_CHECK:
		r->check = strtonum(v, 0, 1, &errstr);
		return (errstr == NULL ? 0 : -1);
	case F_HELP:
		r->n = strtonum(v, 0, 1, &errstr);
		return (errstr == NULL ? 0 : -1);
	case F_TERMINAL:
		r->n = strtonum(v, 1, DECK_TERMINALS, &errstr);
		return (errstr == NULL ? 0 : -1);
	case F_ROWS:
		r->rows = strtonum(v, 1, NSHD_TERMSIZE, &errstr);
		return (errstr == NULL ? 0 : -1);
	case F_COLS:
		r->cols = strtonum(v, 1, NSHD_TERMSIZE, &errstr);
		return (errstr == NULL ? 0 : -1);
	case F_MINUTES:
		r->minutes = strtonum(v, 0, NSHD_CONFIRMMAX, &errstr);
		return (errstr == NULL ? 0 : -1);
	case F_LOGS:
		/* names, joined by commas */
		if (strlcpy(buf, v, sizeof(buf)) >= sizeof(buf))
			return (-1);
		for (s = buf; (t = strsep(&s, ",")) != NULL;) {
			for (i = 0; i < sizeof(logs) / sizeof(logs[0]); i++)
				if (strcmp(t, logs[i]) == 0)
					break;
			if (i == sizeof(logs) / sizeof(logs[0]))
				return (-1);
			r->logs |= NSHD_WATCH_DAEMON << i;
		}
		return (0);
	}
	return (-1);
}

/*
 * The token of the cookie nshdeck=, of DECK_TOKEN hex digits, into
 * token, or "" if there is none: -1 if there is one, not right
 */
static int
front_token(const char *cookies, char *token)
{
	const char	*p = cookies;
	size_t		 len;

	while (*p != '\0') {
		p += strspn(p, " ");
		len = strcspn(p, ";");
		if (strncmp(p, "nshdeck=", 8) == 0) {
			if (len != 8 + DECK_TOKEN ||
			    strspn(p + 8, "0123456789abcdef") < DECK_TOKEN)
				return (-1);
			memcpy(token, p + 8, DECK_TOKEN);
			token[DECK_TOKEN] = '\0';
			return (0);
		}
		p += len;
		if (*p == ';')
			p++;
	}
	return (0);
}

/* the value of hex digit c, or -1 */
static int
hexval(int c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

/*
 * s, len bytes of a form's, decoded into buf of size: '+' as a space,
 * %XX as its byte: -1 if it does not fit, or holds a NUL
 */
static int
decode(char *buf, size_t size, const char *s, size_t len)
{
	size_t	 i, n = 0;
	int	 hi, lo;

	for (i = 0; i < len; i++) {
		if (n + 1 >= size)
			return (-1);
		if (s[i] == '+')
			buf[n++] = ' ';
		else if (s[i] != '%')
			buf[n++] = s[i];
		else {
			if (i + 2 >= len || (hi = hexval(s[i + 1])) == -1 ||
			    (lo = hexval(s[i + 2])) == -1 ||
			    (hi == 0 && lo == 0))
				return (-1);
			buf[n++] = hi << 4 | lo;
			i += 2;
		}
	}
	buf[n] = '\0';
	return (0);
}

/* c answered by front itself: status, and why, as JSON */
static void
front_error(struct conn *c, int status, const char *why)
{
	struct deck_head	 h;
	char			 body[128];
	int			 len;

	memset(&h, 0, sizeof(h));
	h.status = status;
	front_head(c, &h);
	len = snprintf(body, sizeof(body), "{\"error\":\"%s\"}\n", why);
	front_stdout(c, body, len);
	c->asked = 0;
	front_end(c);
}

/* an answer's head, as FastCGI's first STDOUT */
static void
front_head(struct conn *c, struct deck_head *h)
{
	static const struct {
		int		 status;
		const char	*reason;
	} reasons[] = {
		{ 200, "OK" }, { 400, "Bad Request" },
		{ 401, "Unauthorized" }, { 403, "Forbidden" },
		{ 404, "Not Found" }, { 405, "Method Not Allowed" },
		{ 413, "Payload Too Large" },
		{ 415, "Unsupported Media Type" },
		{ 431, "Request Header Fields Too Large" },
		{ 503, "Service Unavailable" },
	};
	struct timeval	 keepalive = { DECK_KEEPALIVE, 0 };
	const char	*reason = "Error";
	char		 buf[1024];
	size_t		 i;
	int		 len;

	for (i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++)
		if (reasons[i].status == h->status)
			reason = reasons[i].reason;
	len = snprintf(buf, sizeof(buf), "Status: %d %s\r\n"
	    "Content-Type: %s\r\n"
	    "Cache-Control: no-store\r\n"
	    "X-Content-Type-Options: nosniff\r\n"
	    "Content-Security-Policy: default-src 'none'\r\n"
	    "%s%s%s"
	    "\r\n", h->status, reason,
	    h->events ? "text/event-stream" : "application/json",
	    h->cookie[0] != '\0' ? "Set-Cookie: nshdeck=" : "",
	    h->cookie[0] != '\0' ? h->cookie : "",
	    h->cookie[0] != '\0' ? "; Path=/; HttpOnly; Secure; "
	    "SameSite=Strict\r\n" : h->clear ? "Set-Cookie: nshdeck=; "
	    "Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict\r\n" : "");
	front_stdout(c, buf, len);
	if (h->events) {
		c->events = 1;
		evtimer_add(&c->tm, &keepalive);
	}
}

/* data, as STDOUT records */
static void
front_stdout(struct conn *c, const void *data, size_t len)
{
	unsigned char	 h[FCGI_HEADER];
	const char	*p = data;
	size_t		 n;

	if (c->state == C_DONE)
		return;
	do {
		n = len > FCGI_CONTENT ? FCGI_CONTENT : len;
		h[0] = FCGI_VERSION_1;
		h[1] = FCGI_STDOUT;
		h[2] = c->rid >> 8;
		h[3] = c->rid & 0xff;
		h[4] = n >> 8;
		h[5] = n & 0xff;
		h[6] = h[7] = 0;
		front_out(c, h, sizeof(h));
		front_out(c, p, n);
		p += n;
		len -= n;
	} while (len > 0);
	front_wait(c);
}

/*
 * len bytes of a stream's events, kept, the oldest whole ones dropped
 * while more than DECK_UNREAD bytes wait, and sent if c has written all
 * it was sent. Each event ends "\n\n", which no other part of one has
 */
static void
front_event(struct conn *c, const char *data, size_t len)
{
	char	*p;
	size_t	 i;

	if ((p = realloc(c->pend, c->pendlen + len)) == NULL)
		fatal("%s", __func__);
	c->pend = p;
	memcpy(c->pend + c->pendlen, data, len);
	c->pendlen += len;
	while (c->pendlen > DECK_UNREAD) {
		for (i = 1; i < c->pendlen; i++)
			if (c->pend[i - 1] == '\n' && c->pend[i] == '\n')
				break;
		if (i == c->pendlen)
			break;
		/* a comment is not an event: none is missed */
		if (c->pend[0] != ':')
			c->dropped = 1;
		memmove(c->pend, c->pend + i + 1, c->pendlen - i - 1);
		c->pendlen -= i + 1;
	}
	front_events(c, 0);
}

/*
 * A stream's whole events, to write, after a dropped event if some
 * went: once c has written all it was sent, or now
 */
static void
front_events(struct conn *c, int now)
{
	size_t	 n;

	if (!now && c->outoff < c->outlen)
		return;
	for (n = c->pendlen; n >= 2; n--)
		if (c->pend[n - 2] == '\n' && c->pend[n - 1] == '\n')
			break;
	if (n < 2)
		return;
	if (c->dropped)
		front_stdout(c, DROPPED, sizeof(DROPPED) - 1);
	c->dropped = 0;
	front_stdout(c, c->pend, n);
	memmove(c->pend, c->pend + n, c->pendlen - n);
	c->pendlen -= n;
}

/* the answer's end: an empty STDOUT and END_REQUEST, then c closes */
static void
front_end(struct conn *c)
{
	unsigned char	 end[FCGI_HEADER + 8];

	if (c->state == C_DONE)
		return;
	if (c->events)
		front_events(c, 1);
	front_stdout(c, "", 0);
	memset(end, 0, sizeof(end));
	end[0] = FCGI_VERSION_1;
	end[1] = FCGI_END;
	end[2] = c->rid >> 8;
	end[3] = c->rid & 0xff;
	end[5] = 8;
	front_out(c, end, sizeof(end));
	c->state = C_DONE;
	c->asked = 0;
	front_wait(c);
}

/* len bytes of data, to write to c's client */
static void
front_out(struct conn *c, const void *data, size_t len)
{
	char	*p;

	if (c->outoff > 0 && c->outoff == c->outlen)
		c->outoff = c->outlen = 0;
	if ((p = realloc(c->out, c->outlen + len)) == NULL)
		fatal("%s", __func__);
	c->out = p;
	memcpy(c->out + c->outlen, data, len);
	c->outlen += len;
}

/* c's events: read, and written while it has something to write */
static void
front_wait(struct conn *c)
{
	event_del(&c->ev);
	event_set(&c->ev, c->fd, EV_READ | (c->outlen > c->outoff ?
	    EV_WRITE : 0), front_io, c);
	event_add(&c->ev, NULL);
}

/* c closed, and session told, if it has c's request still */
static void
front_close(struct conn *c)
{
	if (c->asked)
		pipe_compose(&session, DECK_GONE, c->id, -1, NULL, 0);
	event_del(&c->ev);
	evtimer_del(&c->tm);
	close(c->fd);
	free(c->out);
	free(c->pend);
	TAILQ_REMOVE(&conns, c, entry);
	explicit_bzero(c, sizeof(*c));
	free(c);
	if (nconns-- == DECK_CONNS)
		event_add(&ev_accept, NULL);
}

static struct conn *
conn_find(uint32_t id)
{
	struct conn	*c;

	TAILQ_FOREACH(c, &conns, entry)
		if (c->id == id)
			return (c);
	return (NULL);
}
