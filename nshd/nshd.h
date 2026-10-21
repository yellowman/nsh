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
 * nshd's messages, with its clients, which include this after
 * <event.h> and <imsg.h>, and between its processes.
 */

#ifndef NSHD_H
#define NSHD_H

#define NSHD_GROUP	"nshadmin"	/* who may use the read-write socket */
#define NSHD_CHECK_USER	"_nshcheck"	/* system's helpers, but root's */
#define NSHD_SOCKET	"/var/run/nshd.sock"	/* 0660, group nshadmin */
#define NSHD_RO_SOCKET	"/var/run/nshd.ro.sock"	/* 0666 */

#define NSHD_VERSION	1	/* of what a client and nshd say */
#define NSHD_TEXT	8192	/* text in one message, at most */
#define NSHD_WORDS	256	/* a show's words, at most */
#define NSHD_LINE	1024	/* a line of configuration, with its NUL */
#define NSHD_IFNAME	16	/* an interface's name, IFNAMSIZ */

/* a client's first message */
struct nshd_hello {
	uint32_t	version;
};

/* nshd's answer: its version, the session, and whether it may change */
struct nshd_session {
	uint32_t	version;
	uint32_t	id;
	int32_t		priv;
};

/* what to show, as the show command names it */
struct nshd_show {
	char		words[NSHD_WORDS];
};

/* how a request ended: 0, or not */
struct nshd_result {
	int32_t		status;
};

/* which configure: private, for now the only one */
struct nshd_configure {
	int32_t		mode;
};
#define NSHD_PRIVATE	1

/* a line of configuration, in the session's mode */
struct nshd_line {
	char		line[NSHD_LINE];
};

/* a session's mode, after what may change it */
struct nshd_context {
	int32_t		mode;		/* 0, or NSHD_PRIVATE */
	int32_t		rtable;		/* the rtable its lines are for */
	int32_t		bridge;		/* the interface is a bridge */
	char		ifname[NSHD_IFNAME];	/* whose mode, or "" */
};

/* config to system: the running configuration, and with facts, kfacts.h's */
struct nshd_snapshot {
	int32_t		facts;
};

/*
 * parent to relay: a child's pipe, or that it is down; parent to a
 * child: a peer's pipe, or that it is down; a child to relay, and relay
 * to parent: a peer gone wrong. Each start of a child is a generation
 * of it, and instance tells the shows apart
 */
struct nshd_child {
	int32_t			proc;
	int32_t			instance;
	uint32_t		generation;
};

/* relay to a child, at each start: its generation */
struct nshd_startup {
	uint32_t		generation;
};

/* a client's hello, with who it is, from frontend to config */
struct nshd_peer {
	struct nshd_hello	hello;
	uint32_t		uid;
	uint32_t		gid;
};

enum nshd_proc {
	PROC_PARENT,
	PROC_RELAY,
	PROC_SHOW,
	PROC_FRONTEND,
	PROC_CONFIG,
	PROC_SYSTEM,
	PROC_ARCHIVE
};

#define SHOWS		4	/* shows, which share the read-only socket */
#define NCHILD		(4 + SHOWS)	/* the processes relay joins */

enum nshd_imsg {
	IMSG_NONE,

	/* with clients, on either socket */
	IMSG_CTL_HELLO,		/* nshd_hello; nshd_session back */
	IMSG_CTL_SHOW,		/* nshd_show; output or facts, then a result */
	IMSG_CTL_OUTPUT,	/* text */
	IMSG_CTL_RESULT,	/* nshd_result */
	IMSG_CTL_FACTS,		/* units of facts, as facts.h has them */

	/* between nshd's processes */
	IMSG_CTL_CLOSE,		/* frontend to config: a session is gone */
	IMSG_PIPE,		/* parent to relay: nshd_child, and its pipe */
	IMSG_DOWN,		/* parent to relay: nshd_child stays down */
	IMSG_BROKEN,		/* to relay, and parent: nshd_child gone wrong */
	IMSG_STARTUP,		/* relay to a child: nshd_startup */
	IMSG_PEER,		/* parent to a child: nshd_child, its pipe or none */
	IMSG_SYS_SNAPSHOT,	/* config to system: the running configuration */
	IMSG_SYS_TEXT,		/* system to config: text */
	IMSG_SYS_END,		/* system to config: nshd_result */
	IMSG_SYS_SHOW,		/* config to system: nshd_show, facts back */
	IMSG_SYS_FACTS,		/* system to config: units of facts */
	IMSG_CTL_READ,		/* frontend to config: a client read all */
	IMSG_SYS_READ,		/* config to system: a request's client did */
	IMSG_SYS_STOP,		/* config to system: a request's session is gone */

	/* with clients, on the read-write socket */
	IMSG_CTL_CONFIGURE,	/* nshd_configure; a context, then a result */
	IMSG_CTL_LINE,		/* nshd_line; output, a context, a result */
	IMSG_CTL_EXIT,		/* leave configure; a context, then a result */
	IMSG_CTL_CONTEXT	/* nshd_context */
};

struct imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	struct event	 ev;
	short		 events;
};

/* a child's peer, and the pipe between them, from parent */
struct link {
	enum nshd_proc	 proc;
	void		(*handler)(int, short, void *);
	void		(*forget)(void);	/* all the peer held */
	struct imsgev	*iev;		/* or NULL: gone, or down */
	struct imsgev	*wrong;		/* gone wrong: held, unread */
	uint32_t	 generation;
	int		 down;
};

/* nshd.c */
void		 imsg_event_add(struct imsgev *);
int		 imsg_compose_event(struct imsgev *, uint32_t, uint32_t, pid_t,
		    int, const void *, size_t);
struct imsgev	*imsgev_new(int, void (*)(int, short, void *), int);
int		 imsgev_io(struct imsgev *, short);
int		 imsg_text(struct imsgev *, uint32_t, uint32_t, const char *,
		    size_t);
struct facts_out;
void		 capture_stdout(void);
int		 printed(struct facts_out *);
int		 printed_text(struct imsgev *, uint32_t, uint32_t);
void		 child_start(const char *, int, int);
void		 privdrop(enum nshd_proc);
int		 joined(enum nshd_proc, enum nshd_proc);
void		 links_init(struct link *, size_t, struct imsgev *);
int		 link_compose(struct link *, uint32_t, uint32_t, const void *,
		    size_t);
void		 link_broken(struct link *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));

/* each process but parent */
__dead void	 relay(int, int);
__dead void	 showproc(int, int, int);
__dead void	 frontend(int, int);
__dead void	 configproc(int, int);
__dead void	 systemproc(int, int);
__dead void	 archive(int, int);

#endif /* NSHD_H */
