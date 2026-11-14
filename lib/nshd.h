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
 * Messages between nshd and its clients.
 */

#ifndef NSHD_H
#define NSHD_H

#define NSHD_GROUP	"nshadmin"	/* who may use the read-write socket */
#define NSHD_SOCKET	"/var/run/nshd.sock"	/* 0660, group nshadmin */
#define NSHD_RO_SOCKET	"/var/run/nshd.ro.sock"	/* 0666 */

#define NSHD_VERSION	10	/* protocol version of clients and nshd */
#define NSHD_TEXT	8192	/* text in one message, at most */
#define NSHD_WORDS	256	/* a show's words, at most */
#define NSHD_LINE	1024	/* a line of configuration, with its NUL */
#define NSHD_IFNAME	16	/* an interface's name, IFNAMSIZ */
#define NSHD_COMMENT	256	/* a commit's comment, with its NUL */
#define NSHD_ROLLBACKS	50	/* configurations kept, ROLLBACKS */
#define NSHD_CONFIRMMAX	1440	/* commit confirmed's minutes, CONFIRMMAX */
#define NSHD_DAEMON	16	/* a daemon's name, with its NUL */
#define NSHD_RULES	(1024 * 1024)	/* a daemon's rules, at most */

/* the permissions a session's login class gives it */
#define NSHD_VIEW	0x1	/* every show */
#define NSHD_OPERATE	0x2	/* operations: clear, reboot, daemon actions */
#define NSHD_CONFIGURE	0x4	/* configure private and terminal, commit */
#define NSHD_ADMIN	0x8	/* configure and configure exclusive, and */
				/* the password hashes */
#define NSHD_EXEC	0x10	/* running programs; nsh checks this */

/* a client's first message */
struct nshd_hello {
	uint32_t	version;
};

/* nshd's answer: its version, the session, and its permissions */
struct nshd_session {
	uint32_t	version;
	uint32_t	id;
	int32_t		perms;
};

/* what to show, as the show command names it */
struct nshd_show {
	char		words[NSHD_WORDS];
};

/* how a request ended: 0 on success */
struct nshd_result {
	int32_t		status;
};

/* a show's status, from the process that does not answer it */
#define NSHD_ELSEWHERE	2

/*
 * an operation, in nsh's words, which config parses; system runs it as
 * root in the client's rtable and streams what it prints, and its status
 * is how it ended
 */
struct nshd_op {
	int32_t		rtable;
	char		line[NSHD_LINE];
};

/* nsh -c's configuration, a part at a time, committed after the last */
struct nshd_load {
	int32_t		last;
	int32_t		len;		/* of text */
	char		comment[NSHD_COMMENT];
	char		text[NSHD_TEXT];
};

/*
 * A daemon's rules in the session's candidate, in an rtable: asked for,
 * or set a part at a time, as the daemon's edit sets them
 */
struct nshd_rules {
	int32_t		set;		/* 1 to set, 0 to request */
	int32_t		last;
	int32_t		rtable;
	int32_t		len;		/* of text */
	char		daemon[NSHD_DAEMON];
	char		text[NSHD_TEXT];
};

/* which configure */
struct nshd_configure {
	int32_t		mode;
};
#define NSHD_PRIVATE	1	/* a candidate of the session's own */
#define NSHD_SHARED	2	/* the candidate sessions share */
#define NSHD_EXCLUSIVE	3	/* that, and no other session changes it */
#define NSHD_TERMINAL	4	/* its own, each line committed, not saved */

/* a line of configuration, in the session's mode */
struct nshd_line {
	char		line[NSHD_LINE];
};

/* A stage: lines of text, one to a line, to run in an interface's mode */
struct nshd_stage {
	int32_t		bridge;		/* 1 if the interface is a bridge */
	char		ifname[NSHD_IFNAME];
	int32_t		len;		/* of text */
	char		text[NSHD_TEXT];
};

/* how a line of a stage went: 0 if it succeeded */
struct nshd_staged {
	int32_t		status;
	char		line[NSHD_LINE];
};

/* the session's mode, sent after a request that may change it */
struct nshd_context {
	int32_t		mode;		/* 0, or which configure */
	int32_t		rtable;		/* the rtable its lines are for */
	int32_t		bridge;		/* the interface is a bridge */
	char		ifname[NSHD_IFNAME];	/* interface, or "" if none */
};

/* the web configurator's session logs in as name, a login user */
#define NSHD_NAME	32
#define NSHD_PASSWORD	128
struct nshd_login {
	char		name[NSHD_NAME];
	char		password[NSHD_PASSWORD];
};

/* a web login's terminal: nsh, as the login's user, on a pty this size */
#define NSHD_TERMSIZE	1000	/* its rows or columns, at most */
struct nshd_terminal {
	int32_t		rows;
	int32_t		cols;
};

/*
 * commit of the session's candidate; check asks for commit check, and
 * minutes for commit confirmed
 */
struct nshd_commit {
	int32_t		check;
	int32_t		minutes;
	char		comment[NSHD_COMMENT];
};

/*
 * What a session watches, each a bit: a watch takes the place of the one
 * before, and 0 watches nothing. nshd then sends the session notices,
 * unasked, between the answers to what it asks
 */
struct nshd_watch {
	int32_t		what;
};
#define NSHD_WATCH_COMMITS	0x1	/* commits and configure exclusive */
#define NSHD_WATCH_ROUTING	0x2	/* interfaces, addresses and routes */
#define NSHD_WATCH_DAEMON	0x4	/* /var/log/daemon, followed */
#define NSHD_WATCH_MESSAGES	0x8	/* /var/log/messages */
#define NSHD_WATCH_AUTHLOG	0x10	/* /var/log/authlog, with admin */
#define NSHD_WATCH_PFLOG	0x20	/* pf's logged packets, as tcpdump */
#define NSHD_WATCH_LOGS		0x3c
#define NSHD_WATCH_ALL		0x3f

/* a notice, then its text, if it has one, of NSHD_TEXT at most */
struct nshd_notice {
	int32_t		kind;
	uint32_t	uid;		/* the user it is about, if any */
	int32_t		n;		/* as the kind says */
};
#define NSHD_NOTICE_COMMIT	1	/* uid's commit saved; its comment */
#define NSHD_NOTICE_CONFIRMED	2	/* uid's unconfirmed commit: rolled */
					/* back in n minutes unless saved */
#define NSHD_NOTICE_APPLIED	3	/* uid's line of configure terminal */
					/* committed, not saved; the line */
#define NSHD_NOTICE_BACK	4	/* unconfirmed commit rolled back; */
					/* n is 1 if the rollback failed */
#define NSHD_NOTICE_LOCK	5	/* uid has configure exclusive */
#define NSHD_NOTICE_UNLOCK	6	/* uid left configure exclusive */
#define NSHD_NOTICE_LINKS	7	/* interfaces or addresses changed */
#define NSHD_NOTICE_ROUTES	8	/* routes in rtable n changed, or */
					/* in every rtable if n is -1 */
#define NSHD_NOTICE_LOG		9	/* text read from log n, where n is */
					/* the log's watch bit */
#define NSHD_NOTICE_LOGEND	10	/* the log n is no longer followed */

/* rollback n, or show rollback n */
struct nshd_rollback {
	int32_t		n;
};

/*
 * The messages of a client and nshd. They share one numbering with the
 * messages between nshd's processes (nshd/internal.h), and no two have
 * the same number
 */
enum nshd_imsg {
	/* on either socket */
	IMSG_CTL_HELLO = 1,	/* nshd_hello; nshd_session back */
	IMSG_CTL_SHOW = 2,	/* nshd_show; output or facts, then a result */
	IMSG_CTL_OUTPUT = 3,	/* text */
	IMSG_CTL_RESULT = 4,	/* nshd_result */
	IMSG_CTL_FACTS = 5,	/* units of facts, as facts.h has them */

	/* on the read-write socket */
	IMSG_CTL_CONFIGURE = 15, /* nshd_configure; a context, then a result */
	IMSG_CTL_LINE = 16,	/* nshd_line; output, a context, a result */
	IMSG_CTL_EXIT = 17,	/* leave configure; a context, then a result */
	IMSG_CTL_CONTEXT = 18,	/* nshd_context */
	IMSG_CTL_COMMIT = 19,	/* nshd_commit; output, a context, a result */
	IMSG_CTL_ROLLBACK = 20,	/* nshd_rollback; output, a context, a result */
	IMSG_CTL_OP = 38,	/* nshd_op: what it prints, a result */
	IMSG_CTL_LOAD = 40,	/* nshd_load: a result; the last, as commit */
	IMSG_CTL_LOGIN = 41,	/* nshd_login: as HELLO's answer, or a result */
	IMSG_CTL_WATCH = 43,	/* nshd_watch: a result */
	IMSG_CTL_NOTICE = 44,	/* nshd_notice, and text: unasked */
	IMSG_CTL_COMMANDS = 49,	/* nsh's command tables, as facts */
	IMSG_CTL_NAMES = 50,	/* names for completion, as facts */
	IMSG_CTL_TERMINAL = 51,	/* nshd_terminal; the pty, then a result */
	IMSG_CTL_RULES = 53,	/* nshd_rules: the rules asked for, a result */

	/* a stage, as one request */
	IMSG_CTL_STAGE = 56,	/* nshd_stage; output and STAGED, each line */
	IMSG_CTL_STAGED = 57	/* nshd_staged, after the line's output */
};

#endif /* NSHD_H */
