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
 * <event.h> and <imsg.h>, and between its processes, through relay.
 */

#ifndef NSHD_H
#define NSHD_H

#define NSHD_GROUP	"nshadmin"	/* who may use the read-write socket */
#define NSHD_SOCKET	"/var/run/nshd.sock"	/* 0660, group nshadmin */
#define NSHD_RO_SOCKET	"/var/run/nshd.ro.sock"	/* 0666 */

#define NSHD_VERSION	1	/* of what a client and nshd say */
#define NSHD_TEXT	8192	/* text in one message, at most */
#define NSHD_WORDS	256	/* a show's words, at most */

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

/*
 * parent to relay: a child's pipe, or that it is down; relay to parent:
 * a child gone wrong. Each start of a child is a generation of it, and
 * instance tells the shows apart
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

/* relay to a child: one of its peers started again, or is down */
struct nshd_restart {
	int32_t			proc;
	int32_t			down;
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
	PROC_KERNEL,
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
	IMSG_BROKEN,		/* relay to parent: nshd_child gone wrong */
	IMSG_STARTUP,		/* relay to a child: nshd_startup */
	IMSG_RESTART,		/* relay to a child: nshd_restart */
	IMSG_KRN_SNAPSHOT,	/* config to kernel: the running configuration */
	IMSG_KRN_TEXT,		/* kernel to config: text */
	IMSG_KRN_END,		/* kernel to config: nshd_result */
	IMSG_KRN_SHOW,		/* config to kernel: nshd_show, facts back */
	IMSG_KRN_FACTS,		/* kernel to config: units of facts */
	IMSG_CTL_READ,		/* frontend to config: a client read all */
	IMSG_KRN_READ,		/* config to kernel: a request's client did */
	IMSG_KRN_STOP		/* config to kernel: a request's session is gone */
};

struct imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	struct event	 ev;
	short		 events;
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
void		 child_start(const char *, int, int);
void		 privdrop(enum nshd_proc);

/* each process but parent */
__dead void	 relay(int, int);
__dead void	 showproc(int, int, int);
__dead void	 frontend(int, int);
__dead void	 configproc(int, int);
__dead void	 kernproc(int, int);
__dead void	 archive(int, int);

#endif /* NSHD_H */
