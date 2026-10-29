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
 * Messages between nshdeck's processes. Include this file after
 * <event.h>, <imsg.h> and nshd.h.
 */

#ifndef NSHDECK_H
#define NSHDECK_H

#define DECK_USER	"_nshweb"	/* parent, once started, and session */
#define DECK_FRONT	"_nshdeck"	/* front */
#define DECK_GROUP	"www"		/* httpd's group; it uses the socket */
#define DECK_SOCKET	"/var/www/run/nshdeck.sock"

#define DECK_TOKEN	64		/* a session's token, in hex */
#define DECK_ADDR	64		/* a client's address, from httpd */
#define DECK_SESSIONS	64		/* web users logged in, at most */
#define DECK_IDLE	(30 * 60)	/* seconds a session lasts unused */
#define DECK_WINDOW	16		/* an answer's messages front has */
					/* not written, at most */
#define DECK_TERMINALS	4		/* a user's terminals, at most */

/* what a request asks */
enum deck_kind {
	DECK_LOGIN = 1,
	DECK_LOGOUT,
	DECK_WHOAMI,
	DECK_SHOW,
	DECK_CONFIG,
	DECK_CONFIGURE,
	DECK_LINE,
	DECK_EXIT,
	DECK_COMMIT,
	DECK_ROLLBACK,
	DECK_OP,
	DECK_COMPLETE,
	DECK_TERMINAL,
	DECK_TYPE,
	DECK_EVENTS,
	DECK_RULES,
	DECK_SETRULES
};

/*
 * front to session: a request, as front read it, zeroed first, each
 * string with its NUL
 */
struct deck_request {
	int32_t		kind;
	char		token[DECK_TOKEN + 1];	/* cookie's token, or "" */
	char		addr[DECK_ADDR];	/* the client's address from */
						/* httpd, or "" */
	char		text[NSHD_LINE];	/* a user's name, a show's */
						/* words, a line, an */
						/* operation, a configuration, */
						/* keys typed in a terminal */
	char		password[NSHD_PASSWORD];
	char		comment[NSHD_COMMENT];
	char		daemon[NSHD_DAEMON];	/* whose rules */
	int32_t		n;		/* rollback's n, an operation's */
					/* or rules' rtable, configure */
					/* mode, 1 for a completion's */
					/* help, or a terminal's number */
	int32_t		minutes;	/* minutes for commit confirmed */
	int32_t		check;		/* commit check */
	int32_t		logs;		/* the logs events follow, as */
					/* NSHD_WATCH_* */
	int32_t		rows;		/* a terminal's size, or 0 */
	int32_t		cols;
};

/* session to front: how an answer begins */
struct deck_head {
	int32_t		status;		/* HTTP status */
	int32_t		events;		/* text/event-stream, not JSON */
	char		cookie[DECK_TOKEN + 1];	/* to set, or "" */
	int32_t		clear;		/* the cookie cleared */
};

enum deck_imsg {
	DECK_NONE,
	DECK_REQUEST,	/* front to session: deck_request */
	DECK_HEAD,	/* session to front: deck_head */
	DECK_BODY,	/* session to front: what follows the head */
	DECK_END,	/* session to front: the answer ends */
	DECK_READ,	/* front to session: front wrote all it was sent */
	DECK_GONE,	/* front to session: the client is gone */
	DECK_CONNECT,	/* session to parent: a connection to nshd, please, */
			/* to its shows if the int32_t is 1 */
	DECK_CONNECTED,	/* parent to session: the fd, or -1 and errno */
	DECK_TEXT	/* front to session: a part of a request's rules, */
			/* before it */
};

/* a pipe to a peer, read and written by its handler */
struct deck_pipe {
	struct imsgbuf	 ibuf;
	struct event	 ev;
	void		(*handler)(int, short, void *);
	short		 events;
	int		 paused;	/* not read: its peer waits */
};

/* nshdeck.c */
void		 deck_child(const char *, int, int);
void		 deck_drop(const char *);
int		 pipe_init(struct deck_pipe *, int,
		    void (*)(int, short, void *), int);
void		 pipe_event(struct deck_pipe *);
void		 pipe_close(struct deck_pipe *);
int		 pipe_io(struct deck_pipe *, short);
void		 pipe_compose(struct deck_pipe *, uint32_t, uint32_t, int,
		    const void *, size_t);

/* each process but parent */
__dead void	 front(int, int);
__dead void	 sessions(int, int);

#endif /* NSHDECK_H */
