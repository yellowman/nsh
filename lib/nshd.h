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
#define NSHD_PARSE_USER	"_nshparse"	/* the parser, which reads for system */
#define NSHD_WEB_USER	"_nshweb"	/* the web configurator's sessions */
#define NSHD_SOCKET	"/var/run/nshd.sock"	/* 0660, group nshadmin */
#define NSHD_RO_SOCKET	"/var/run/nshd.ro.sock"	/* 0666 */

#define NSHD_VERSION	8	/* protocol version of clients and nshd */
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

/* config to system: running configuration; kernel facts if facts is set */
struct nshd_snapshot {
	int32_t		facts;
};

/*
 * config to system: ask a session's permissions, NSHD_*. system answers
 * for the uid of the session's client, which it reads from the client's
 * socket. A session of the web configurator's has none until it logs
 * in.
 */
struct nshd_perms {
	uint32_t	session;
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
#define NSHD_SCRIPT	0	/* the edits BEGIN runs */
#define NSHD_BEFORE	1	/* BEGIN: the config the commit is based on */
#define NSHD_WANT	2	/* BEGIN's: the configuration wanted */
#define NSHD_TEST	3	/* TEST's: the rules it tests */
#define NSHD_PARTS	4

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

/*
 * config to system: an operation, as its row of ops[] and the values of
 * the row's arguments, a facts record; and the session that asked it
 */
struct nshd_sysop {
	struct nshd_whose whose;
	int32_t		rtable;
	int32_t		row;		/* in ops[] */
	int32_t		set;		/* 0 for "no" */
	char		ifname[NSHD_IFNAME];	/* an interface's operation's */
	uint32_t	len;		/* of values */
	char		values[2 * NSHD_LINE];
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

/* a commit's script empties these daemons' rules */
struct nshd_apply {
	int32_t		nclears;
	struct {
		char	name[32];
		int32_t	rtable;
		int32_t	keep;	/* empty before the script, else remove after */
	}		clears[NSHD_CLEARS];
};

/*
 * config to system: run a session's commit, which system records,
 * applies and ends. minutes is for commit confirmed, unsaved for
 * configure terminal, and comment is saved with the commit. The parts
 * carry the commit's script, the configuration it is based on and the
 * configuration wanted. For commit check (checking), or if config
 * found problems (bad of them), system only runs the commit's tests
 * and reports the verdict
 */
struct nshd_begin {
	struct nshd_whose whose;
	int32_t		checking;
	int32_t		bad;
	int32_t		minutes;
	int32_t		unsaved;
	char		comment[NSHD_COMMENT];
	struct nshd_apply apply;
};
/*
 * system to the parser, on its standard input: what to read, then its
 * texts, len[0] bytes, then len[1] and on (parserproc.c). What the
 * parser finds it prints; what it answers it writes to descriptor 3.
 * Its exit status is 0, 1 as each kind says, or 2 if it could not read
 */
#define NSHD_PARSE_TEXTS 6
struct nshd_parse {
	int32_t		kind;		/* NSHD_PARSE_* */
	int32_t		flags;
	uint32_t	len[NSHD_PARSE_TEXTS];
	char		daemon[32];	/* the rules' daemon */
	struct nshd_apply apply;	/* the script's clears */
};
/*
 * the kinds, each with its texts: "now" is what runs, as conf() prints
 * it; "facts" are the kernel's, as a snapshot sends them
 */
#define NSHD_PARSE_RULES 2	/* now, a test's rules: 1 if a session
				   without admin may not test them */
#define NSHD_PARSE_BEGIN 3	/* now, what the commit is based on, what
				   it wants, the record's before and want,
				   and with NSHD_PARSE_ADMIN its script:
				   struct nshd_began */
#define NSHD_PARSE_BACK	4	/* now, a rollback's configuration: struct
				   nshd_back */
#define NSHD_PARSE_VERIFY 5	/* now, what a script wanted: 1 if what
				   runs is not it */
#define NSHD_PARSE_PLAN	6	/* now, what is wanted, facts: struct
				   nshd_apply, then the edits */
#define NSHD_PARSE_UNDONE 7	/* now, what an undo wanted: 1 if what
				   runs is not it */
#define NSHD_PARSE_BOOT	8	/* the saved configuration, now, facts:
				   struct nshd_bootplan */
#define NSHD_PARSE_DIFF	9	/* a, b, a head: 1 if b differs from a */

#define NSHD_PARSE_ADMIN 0x1	/* BEGIN: check the script's admin lines */
#define NSHD_PARSE_FAILED 0x2	/* VERIFY: a line of the script failed */
#define NSHD_PARSE_BOOTS 0x4	/* VERIFY: as the boot judges it */
#define NSHD_PARSE_HIDE	0x8	/* DIFF: each password hash hidden */
#define NSHD_PARSE_QUIET 0x10	/* DIFF: only whether they differ */
#define NSHD_PARSE_RECORD 0x20	/* BEGIN: there is a commit record */

#define NSHD_LOGINS	1024		/* login lines, at most */

/* BEGIN's answer, then nlogins of struct login_line, what it wants */
struct nshd_began {
	int32_t		based;		/* now reads as what it is based on */
	int32_t		logins;		/* it changes login users or classes */
	int32_t		none;		/* now reads as the record's before */
	int32_t		wanted;		/* now reads as the record's want */
	int32_t		back;		/* the record's before reads as what
					   it wants */
	int32_t		admin;		/* its script may run */
	uint32_t	nlogins;
};

/* BACK's answer */
struct nshd_back {
	int32_t		there;		/* now reads as the configuration */
	int32_t		logins;		/* they differ in login users or
					   classes */
};

/*
 * BOOT's answer: the plan, its clears, then ntests of struct
 * nshd_boottest, each with its len bytes of rules, then elen of edits
 */
struct nshd_bootplan {
	int32_t		same;		/* now reads as the saved one */
	uint32_t	ntests;
	uint32_t	elen;
	struct nshd_apply apply;
};
struct nshd_boottest {
	char		name[32];	/* the daemon */
	char		label[512];	/* the line, and its block */
	uint32_t	len;
};
#define NSHD_TESTS	1024		/* a boot's tests, at most */

/* how a commit ended: BEGIN's answer, once BEGUN said it was begun */
#define NSHD_SAVED	0	/* the candidate runs, saved */
#define NSHD_KEPT	1	/* the candidate runs until its deadline */
#define NSHD_LEFT	2	/* neither it nor what ran before runs */
#define NSHD_APPLIED	3	/* configure terminal: it runs, not saved */
#define NSHD_UNDONE	4	/* it did not take; what ran before runs */
#define NSHD_UNSAVED	5	/* the candidate runs, but the save failed */

/* config to system: save the running configuration, with the comment */
struct nshd_save {
	struct nshd_whose whose;
	char		comment[NSHD_COMMENT];
};

/* config to system: test daemon name's rules, sent as the test part */
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
 * parent to a child, once it may start: whether nshd boots, which system
 * does; until it is done, the shows wait for LISTEN
 */
struct nshd_startup {
	int32_t			boot;
};

/*
 * parent to config and system: a new session, with the pipe to its
 * frontend; to config, with the uid and gid of its client, which parent
 * read from the client's socket
 */
struct nshd_newsession {
	uint32_t		session;
	uint32_t		uid;
	uint32_t		gid;
};

/* config or system to parent: whether it took a new session */
struct nshd_taken {
	uint32_t		session;
	int32_t			status;		/* 0 if it did */
};

enum nshd_proc {
	PROC_PARENT,
	PROC_SHOW,
	PROC_FRONTEND,
	PROC_CONFIG,
	PROC_SYSTEM,
	PROC_ARCHIVE,
	PROC_PARSER
};

#define SHOWS		4	/* shows, which share the read-only socket */
#define NSHD_SESSIONS	64	/* sessions on the read-write socket, at most */

/*
 * REVOKING's: 1, as login users or classes are about to change, and the
 * n sessions that would lose a permission or their login, each with the
 * permissions it would have, which config lowers its own to, or -1 for
 * no login, which config ends; or 0, once they have changed
 */
struct nshd_revoking {
	int32_t		on;
	uint32_t	n;
	uint32_t	sessions[NSHD_SESSIONS];
	int32_t		perms[NSHD_SESSIONS];
};

enum nshd_imsg {
	/* with clients, on either socket */
	IMSG_CTL_HELLO = 1,	/* nshd_hello; nshd_session back */
	IMSG_CTL_SHOW,		/* nshd_show; output or facts, then a result */
	IMSG_CTL_OUTPUT,	/* text */
	IMSG_CTL_RESULT,	/* nshd_result */
	IMSG_CTL_FACTS,		/* units of facts, as facts.h has them */

	/* between nshd's processes */
	IMSG_SESSION,		/* parent to config: nshd_newsession, a pipe */
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
	IMSG_SYS_BEGIN,		/* nshd_begin: a commit; how it ended */
	IMSG_SYS_SAVE,		/* nshd_save: save, and remove the record */
	IMSG_SYS_BEGUN,		/* system to config: BEGIN's commit is begun */
	IMSG_SYS_GO,		/* config to system: REVOKING is done */
	IMSG_SYS_ROLLBACK_READ,	/* nshd_rollback: configuration n */
	IMSG_SYS_ROLLBACK_LIST,	/* show rollback's list */
	IMSG_SYS_ROLLBACK_DIFF,	/* nshd_rollback: what configuration n changed */
	IMSG_SYS_TEST,		/* nshd_test; back, nshd_result: how it went */

	/* config and archive: the shared candidate, as text */
	IMSG_ARC_TEXT,		/* its text, in either direction */
	IMSG_ARC_KEEP,		/* config: nshd_keep; keep the text sent */
	IMSG_ARC_KEPT,		/* archive: nshd_keep, and if it was kept */
	IMSG_ARC_LOAD,		/* config: what was kept, as text, then LOADED */
	IMSG_ARC_LOADED,	/* archive: nshd_result */

	/* config to system, answered as SYS_SHOW is */
	IMSG_SYS_SAVED,		/* the saved configuration, as text */

	/* the end of the boot, and what follows it */
	IMSG_BOOTED,		/* system to parent: nshd_result of the boot */
	IMSG_LISTEN,		/* parent to each show: take clients */

	/* with clients, on the read-write socket, and config to system */
	IMSG_SYS_PERMS,		/* nshd_perms: result is the permissions */
	IMSG_CTL_OP,		/* nshd_op: what it prints, a result */
	IMSG_SYS_OP,		/* nshd_sysop: a stream, a result */
	IMSG_CTL_LOAD,		/* nshd_load: a result; the last, as commit */
	IMSG_CTL_LOGIN,		/* nshd_login: as HELLO's answer, or a result */
	IMSG_SYS_LOGIN,		/* nshd_syslogin: the permissions, as the result */

	IMSG_SESSION_TAKEN,	/* config or system to parent: nshd_taken */

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

	/* parent to system: who a new session is, as system reads it */
	IMSG_SESSION_CLIENT,	/* nshd_newsession, and the client's socket */

	/*
	 * a session ends: system to parent, then parent to config; parent
	 * to system, as its frontend ends
	 */
	IMSG_SESSION_GONE,	/* the session is the imsg's id */

	/* a stage, as one request */
	IMSG_CTL_STAGE,		/* nshd_stage; output and STAGED, each line */
	IMSG_CTL_STAGED,	/* nshd_staged, after the line's output */

	/*
	 * system to config: login users or classes are about to change, by
	 * a commit or a rollback; config lowers the permissions of the
	 * sessions that would lose one, ends those that would lose their
	 * login, and says so (GO)
	 */
	IMSG_SYS_REVOKING,	/* nshd_revoking */

	/*
	 * system to parent: config is gone, or has gone wrong, and is to
	 * end; parent to system, once it has: config and every session
	 * have ended
	 */
	IMSG_CONFIG_END
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
/*
 * Facts for one reader, not yet sent: as many of a struct facts_out's
 * units as fit one message (units_emit()), which send() takes with arg.
 * units_flush() has send() take those kept
 */
struct units {
	void		(*send)(void *, const void *, size_t);
	void		*arg;
	size_t		 len;
	uint8_t		 buf[16000];	/* FACTS_UNIT */
};
void		 units_emit(void *, const void *, size_t);
void		 units_flush(struct units *);
void		 child_start(const char *, int, int);
void		 privdrop(enum nshd_proc);
int		 proc_user(enum nshd_proc, uid_t *, gid_t *);
void		 links_init(struct link *, size_t);
int		 link_compose(struct link *, uint32_t, uint32_t, const void *,
		    size_t);
void		 link_broken(struct link *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));
struct plan;
void		 plan_clears(struct plan *, struct nshd_apply *);

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
__dead void	 parserproc(int, int);

/* system's, and its children's, to run the parser (parserproc.c) */
void		 parser_init(int, int);
__dead void	 parser_exec(struct nshd_parse *, char **, int);
int		 parser_answer(int, size_t, char **, size_t *);
int		 parser_call(struct nshd_parse *, char **, size_t, char **,
		    size_t *);

#endif /* NSHD_H */
