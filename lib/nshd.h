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
 * Messages between nshd and its clients, and between nshd's processes.
 * Clients include this file after <event.h> and <imsg.h>.
 */

#ifndef NSHD_H
#define NSHD_H

#define NSHD_GROUP	"nshadmin"	/* who may use the read-write socket */
#define NSHD_CHECK_USER	"_nshcheck"	/* system's non-root helpers */
#define NSHD_WEB_USER	"_nshweb"	/* the web configurator's sessions */
#define NSHD_SOCKET	"/var/run/nshd.sock"	/* 0660, group nshadmin */
#define NSHD_RO_SOCKET	"/var/run/nshd.ro.sock"	/* 0666 */

#define NSHD_VERSION	5	/* protocol version of clients and nshd */
#define NSHD_TEXT	8192	/* text in one message, at most */
#define NSHD_WORDS	256	/* a show's words, at most */
#define NSHD_LINE	1024	/* a line of configuration, with its NUL */
#define NSHD_IFNAME	16	/* an interface's name, IFNAMSIZ */
#define NSHD_COMMENT	256	/* a commit's comment, with its NUL */
#define NSHD_ROLLBACKS	50	/* configurations kept, ROLLBACKS */
#define NSHD_CLEARS	64	/* daemons' rules a script empties, MAXCLEARS */
#define NSHD_PART	(16 * 1024 * 1024)	/* a commit's part, at most */
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
 * an operation, in nsh's words; system runs it as root in the client's
 * rtable and streams what it prints, and its status is how it ended
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

/* the session's mode, sent after a request that may change it */
struct nshd_context {
	int32_t		mode;		/* 0, or which configure */
	int32_t		rtable;		/* the rtable its lines are for */
	int32_t		bridge;		/* the interface is a bridge */
	char		ifname[NSHD_IFNAME];	/* interface, or "" if none */
};

/* config to system: running configuration; kernel facts if facts is set */
struct nshd_snapshot {
	int32_t		facts;
};

/*
 * config to system: ask a uid's permissions, NSHD_*; a session of the
 * web configurator's has none until it logs in
 */
struct nshd_perms {
	uint32_t	uid;
	int32_t		web;
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

/* config to system: which part the text after this belongs to */
struct nshd_chunk {
	int32_t		part;
};
#define NSHD_SCRIPT	0	/* the edits APPLY runs, or the rules TEST tests */
#define NSHD_BEFORE	1	/* for BEGIN: the running configuration */
#define NSHD_WANT	2	/* for BEGIN: the candidate */
#define NSHD_PARTS	3

/*
 * frontend to system: a new session's client, with its socket; or a
 * session's request that may begin a commit (a line, a commit or a part
 * of a load), an operation, a login, a terminal or a watch
 */
struct nshd_asked {
	uint32_t	session;
};

/*
 * config to system: the session a request is for, as frontend reported
 * it; or session 0, for the boot
 */
struct nshd_whose {
	uint32_t	session;
};

/* config to system: follow a log, named by its watch bit, for a session */
struct nshd_follow {
	struct nshd_whose whose;
	int32_t		log;
};

/* config to system: an operation, and the session that asked it */
struct nshd_sysop {
	struct nshd_whose whose;
	struct nshd_op	 op;
};

/* config to system: a login, and the session that asked it */
struct nshd_syslogin {
	struct nshd_whose whose;
	struct nshd_login login;
};

/* config to system: a terminal, and the session that asked it */
struct nshd_systerm {
	struct nshd_whose	whose;
	struct nshd_terminal	size;
};

/* system to config: the user a web session logged in as */
struct nshd_logged {
	uint32_t	uid;
};

/* config to system: begin a session's commit; minutes for commit confirmed */
struct nshd_begin {
	struct nshd_whose whose;
	int32_t		minutes;
	int32_t		unsaved;	/* for configure terminal: not saved */
};

/* config to system: how the begun commit ended */
struct nshd_record {
	int32_t		how;
};
#define NSHD_BACK	0	/* rolled back to how it was */
#define NSHD_KEPT	1	/* unconfirmed, applied until its deadline */
#define NSHD_LEFT	2	/* the records left as they are */
#define NSHD_APPLIED	3	/* configure terminal: applied, not saved */

/* config to system: run the script, and empty these daemons' rules */
struct nshd_apply {
	int32_t		nclears;
	struct {
		char	name[32];
		int32_t	rtable;
		int32_t	keep;	/* empty before the script, else remove after */
	}		clears[NSHD_CLEARS];
};

/* config to system: save the running configuration, with the comment */
struct nshd_save {
	struct nshd_whose whose;
	char		comment[NSHD_COMMENT];
};

/* config to system: test daemon name's rules, sent as the script part */
struct nshd_test {
	struct nshd_whose whose;
	char		name[32];
};

/* parent to a child: a peer's pipe; instance tells the shows apart */
struct nshd_child {
	int32_t			proc;
	int32_t			instance;
};

/*
 * parent to a child, once it may start: whether the boot is not done;
 * until it is, frontend and the shows wait for LISTEN
 */
struct nshd_startup {
	int32_t			boot;
};

/* system's answer to SYS_BOOT: 0 to boot, or 1 if it could not record it */
#define NSHD_DONE	2	/* not booting, or this host boot is done */

/* a client's hello, with who it is, from frontend to config */
struct nshd_peer {
	struct nshd_hello	hello;
	uint32_t		uid;
	uint32_t		gid;
	int32_t			web;	/* the client is NSHD_WEB_USER */
};

enum nshd_proc {
	PROC_PARENT,
	PROC_SHOW,
	PROC_FRONTEND,
	PROC_CONFIG,
	PROC_SYSTEM,
	PROC_ARCHIVE
};

#define SHOWS		4	/* shows, which share the read-only socket */

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
	IMSG_STARTUP,		/* parent to a child: nshd_startup */
	IMSG_PEER,		/* parent to a child: nshd_child, its pipe */
	IMSG_SYS_SNAPSHOT,	/* config to system: the running configuration */
	IMSG_SYS_TEXT,		/* system to config: text */
	IMSG_SYS_END,		/* system to config: nshd_result */
	IMSG_SYS_SHOW,		/* config to system: nshd_show, facts back */
	IMSG_SYS_FACTS,		/* system to config: units of facts */
	IMSG_CTL_READ,		/* frontend to config: client read all output */
	IMSG_SYS_READ,		/* config to system: CTL_READ, per request */
	IMSG_SYS_STOP,		/* config to system: stop a request */

	/* with clients, on the read-write socket */
	IMSG_CTL_CONFIGURE,	/* nshd_configure; a context, then a result */
	IMSG_CTL_LINE,		/* nshd_line; output, a context, a result */
	IMSG_CTL_EXIT,		/* leave configure; a context, then a result */
	IMSG_CTL_CONTEXT,	/* nshd_context */
	IMSG_CTL_COMMIT,	/* nshd_commit; output, a context, a result */
	IMSG_CTL_ROLLBACK,	/* nshd_rollback; output, a context, a result */

	/* config to system, for commits: each is answered as SYS_SHOW is */
	IMSG_SYS_SCRIPT,	/* nshd_chunk, and text; no answer */
	IMSG_SYS_BEGIN,		/* nshd_begin: make the commit record */
	IMSG_SYS_APPLY,		/* nshd_apply: run the script, report status */
	IMSG_SYS_SAVE,		/* nshd_save: save, and remove the record */
	IMSG_SYS_RECORD,	/* nshd_record: how the commit ended */
	IMSG_SYS_ROLLBACK_READ,	/* nshd_rollback: configuration n */
	IMSG_SYS_ROLLBACK_LIST,	/* show rollback's list */
	IMSG_SYS_ROLLBACK_DIFF,	/* nshd_rollback: what configuration n changed */
	IMSG_SYS_TEST,		/* nshd_test: run the test, report status */

	/* config and archive: the shared candidate, as text */
	IMSG_ARC_TEXT,		/* its text, in either direction */
	IMSG_ARC_KEEP,		/* config: nshd_keep; keep the text sent */
	IMSG_ARC_KEPT,		/* archive: nshd_keep, and if it was kept */
	IMSG_ARC_LOAD,		/* config: what was kept, as text, then LOADED */
	IMSG_ARC_LOADED,	/* archive: nshd_result */

	/* config to system, answered as SYS_SHOW is */
	IMSG_SYS_SAVED,		/* the saved configuration, as text */
	IMSG_SYS_BOOT,		/* begin the boot, or report it done */
	IMSG_SYS_BOOTED,	/* nshd_result: how the boot went */

	/* the end of the boot, and what follows it */
	IMSG_BOOTED,		/* config to parent: nshd_result of the boot */
	IMSG_LISTEN,		/* parent to frontend and each show: take clients */

	/* with clients, on the read-write socket, and config to system */
	IMSG_SYS_PERMS,		/* nshd_perms: result is the permissions */
	IMSG_CTL_OP,		/* nshd_op: what it prints, a result */
	IMSG_SYS_OP,		/* nshd_sysop: a stream, a result */
	IMSG_CTL_LOAD,		/* nshd_load: a result; the last, as commit */
	IMSG_CTL_LOGIN,		/* nshd_login (web configurator): a result */
	IMSG_SYS_LOGIN,		/* nshd_syslogin: the permissions, as the result */

	/* frontend to system: which sessions have unanswered requests */
	IMSG_FRONT_ASKED,	/* nshd_asked: a session sent a request */
	IMSG_FRONT_ANSWERED,	/* nshd_asked: config answered it */
	IMSG_FRONT_GONE,	/* nshd_asked: its session is gone */

	/* with clients, on the read-write socket, and system to config */
	IMSG_CTL_WATCH,		/* nshd_watch: a result */
	IMSG_CTL_NOTICE,	/* nshd_notice, and text: unasked */
	IMSG_SYS_NOTICE,	/* nshd_notice from system; unrequested */
	IMSG_SYS_FOLLOW,	/* nshd_follow: FOLLOWING, then text */
	IMSG_SYS_FOLLOWING,	/* system to config: the log is followed */
	IMSG_SYS_LOGGED,	/* nshd_logged: before a login's result */
	IMSG_CTL_COMMANDS,	/* nsh's command tables, as facts */
	IMSG_CTL_NAMES,		/* names for completion, as facts */
	IMSG_CTL_TERMINAL,	/* nshd_terminal; the pty, then a result */
	IMSG_SYS_TERMINAL,	/* nshd_systerm; the pty, then SYS_END */
	IMSG_CTL_RULES,		/* nshd_rules: the rules asked for, a result */

	/* frontend to system: who a session is, as system reads it */
	IMSG_FRONT_SESSION	/* nshd_asked, and the client's socket */
};

struct imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	struct event	 ev;
	short		 events;
};

/* config and archive: the sequence number of a KEEP, and its status */
struct nshd_keep {
	uint32_t	seq;
	int32_t		status;
};
#define NSHD_KEEPMAX	(16 * 1024 * 1024)	/* what archive keeps, at most */

/* a child's peer, and the pipe between them, from parent */
struct link {
	enum nshd_proc	 proc;
	void		(*handler)(int, short, void *);
	void		(*ready)(void);	/* or NULL: run once all pipes are in */
	struct imsgev	*iev;
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
int		 printed_text(struct imsgev *, uint32_t, uint32_t, int);
size_t		 login_hide(char *, size_t);	/* passwd.c's */
void		 printed_log(void);
void		 log_text(const char *, size_t);
void		 child_start(const char *, int, int);
void		 privdrop(enum nshd_proc);
int		 proc_user(enum nshd_proc, uid_t *, gid_t *);
int		 joined(enum nshd_proc, enum nshd_proc);
void		 links_init(struct link *, size_t);
int		 link_compose(struct link *, uint32_t, uint32_t, const void *,
		    size_t);
void		 link_broken(struct link *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));

/* confirm.c: the record of an unconfirmed commit */
enum { CONFIRM_NONE, CONFIRM_WAITING, CONFIRM_FAILED };
struct confirm {
	int		 state;
	uint64_t	 id;
	time_t		 deadline;	/* wall-clock time of the rollback */
	int		 attempts;	/* rollback attempts begun */
	int		 demoted;	/* carp demoted, for it */
	char		*back;		/* the rollback configuration */
	size_t		 backlen;
};
int		 confirm_read(struct confirm *, int);
int		 confirm_write(struct confirm *);
int		 confirm_clear(void);
void		 confirm_free(struct confirm *);

/* each process but parent */
__dead void	 showproc(int, int, int);
__dead void	 frontend(int, int);
__dead void	 configproc(int, int);
__dead void	 systemproc(int, int);
__dead void	 archive(int, int);

#endif /* NSHD_H */
