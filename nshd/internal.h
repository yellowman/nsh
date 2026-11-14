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
 * Messages between nshd's processes, and what the processes share.
 * They include this file after <event.h>, <imsg.h> and nshd.h.
 */

#ifndef INTERNAL_H
#define INTERNAL_H

#define NSHD_CHECK_USER	"_nshcheck"	/* system's non-root helpers */
#define NSHD_PARSE_USER	"_nshparse"	/* the parser, which reads for system */
#define NSHD_WEB_USER	"_nshweb"	/* the web configurator's sessions */

#define NSHD_CLEARS	64	/* daemons' rules a script empties, MAXCLEARS */
#define NSHD_PART	(16 * 1024 * 1024)	/* a commit's part, at most */

/*
 * config to system: a show that system answers, as config parsed its
 * words (facts_answer_pack()): what it asks, and the values it asks
 * with, where its kind has them
 */
#define NSHD_SHOWARGS	6	/* a program's words, at most */
struct nshd_sysshow {
	int32_t		type;		/* enum answer_type */
	int32_t		af;		/* ip: a family, or AF_UNSPEC */
	int32_t		stats;		/* statistics: the group's place */
	int32_t		table;		/* a program: its routing table, */
	int32_t		prot, sub;	/* the show's places (prot1_at()), */
	int32_t		nargs;		/* and its words */
	char		args[NSHD_SHOWARGS][NSHD_WORDS];
	char		name[NSHD_IFNAME];	/* autoconf: one interface */
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

/* config to system: which part the text after this belongs to */
struct nshd_chunk {
	int32_t		part;
};
#define NSHD_SCRIPT	0	/* a script's edits: the parser's, not sent */
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
 * configure terminal, and comment is saved with the commit. If sent,
 * the parts carry the configuration it is based on and the
 * configuration wanted, and the parser makes its script from what runs
 * (NSHD_PARSE_BEGIN). For commit check (checking), or if config found
 * problems (bad of them), system only runs the commit's tests, counts
 * a script that cannot be made as a problem, and reports the verdict
 */
struct nshd_begin {
	struct nshd_whose whose;
	int32_t		checking;
	int32_t		bad;
	int32_t		sent;
	int32_t		minutes;
	int32_t		unsaved;
	char		comment[NSHD_COMMENT];
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
};
/*
 * the kinds, each with its texts: "now" is what runs, as conf() prints
 * it; "facts" are the kernel's, as a snapshot sends them
 */
#define NSHD_PARSE_RULES 2	/* now, a test's rules: 1 if a session
				   without admin may not test them */
#define NSHD_PARSE_BEGIN 3	/* now, what the commit is based on, what
				   it wants, the record's before and want,
				   facts: struct nshd_began, with the
				   script that makes now read as what it
				   wants */
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
#define NSHD_PARSE_RECORDS 10	/* the first bytes of the commit, confirm
				   and boot records, each there as the
				   flags say, and of each configuration
				   kept (rollback_slots()), and NSHLOGIN's
				   text: struct nshd_records, then
				   ROLLBACKS of struct rollback_head, then
				   a count of struct login_rec and each,
				   or -1 if too many */
#define NSHD_PARSE_LOGINS 11	/* NSHLOGIN's text, if the flags say it
				   is there: the count and each, as
				   RECORDS answers them */

#define NSHD_PARSE_ADMIN 0x1	/* BEGIN: check the script's admin lines */
#define NSHD_PARSE_FAILED 0x2	/* VERIFY: a line of the script failed */
#define NSHD_PARSE_BOOTS 0x4	/* VERIFY: as the boot judges it */
#define NSHD_PARSE_HIDE	0x8	/* DIFF: each password hash hidden */
#define NSHD_PARSE_QUIET 0x10	/* DIFF: only whether they differ */
#define NSHD_PARSE_RECORD 0x20	/* BEGIN: there is a commit record */
#define NSHD_PARSE_HAS_COMMIT 0x40	/* RECORDS: the commit record */
#define NSHD_PARSE_HAS_CONFIRM 0x80	/* RECORDS: the confirm record */
#define NSHD_PARSE_HAS_BOOT 0x100	/* RECORDS: the boot record */
#define NSHD_PARSE_HAS_LOGINS 0x200	/* RECORDS, LOGINS: NSHLOGIN */

#define NSHD_LOGINS	1024		/* login lines, at most */

/*
 * BEGIN's answer, then nlogins of struct login_line, what it wants, then
 * its script: struct nshd_apply and elen bytes of edits
 */
struct nshd_began {
	int32_t		based;		/* now reads as what it is based on */
	int32_t		logins;		/* it changes login users or classes */
	int32_t		none;		/* now reads as the record's before */
	int32_t		wanted;		/* now reads as the record's want */
	int32_t		back;		/* the record's before reads as what
					   it wants */
	int32_t		planned;	/* its script could be made */
	int32_t		admin;		/* its script may run */
	uint32_t	nlogins;
	uint32_t	elen;
};

/*
 * The records' head lines, as system writes them: each one's state, as
 * the index of its name, then the commit record's uid, time and the
 * lengths of its parts; the confirm record's id, deadline, attempts,
 * whether carp is demoted for it and its configuration's length; and
 * the boot record's boot time and whether carp is demoted for it
 */
#define NSHD_RECORD_STATES	{ "none", "applying", "unsaved" }
#define NSHD_CONFIRM_STATES	{ "none", "waiting", "failed" }
#define NSHD_CONFIRM_FORMAT	"%s %016llx %lld %d %d %zu"
#define NSHD_BOOT_STATES	{ "none", "runs", "failed", "done" }

/*
 * RECORDS' answer: what each record's head line says, as the parser
 * read it, and the line's length, with its newline. A state of 0 is
 * a head line that is not one, or a record not there
 */
struct nshd_records {
	int32_t		commit;
	uint32_t	uid;
	int64_t		when;
	uint64_t	beforelen, wantlen;
	uint64_t	commithead;
	int32_t		confirm;
	int32_t		attempts;
	int32_t		demoted;
	uint64_t	id;
	int64_t		deadline;
	uint64_t	backlen;
	uint64_t	confirmhead;
	int32_t		boot;
	int32_t		bootdemoted;
	int64_t		boottime;
};

/* BACK's answer, then nlogins of struct login_line, the configuration's */
struct nshd_back {
	int32_t		there;		/* now reads as the configuration */
	int32_t		logins;		/* they differ in login users or
					   classes */
	uint32_t	nlogins;
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

/*
 * system to config: a new session, with the pipe to its frontend, and
 * the uid of its client, which system read from the client's socket
 */
struct nshd_newsession {
	uint32_t		session;
	uint32_t		uid;
};

/*
 * A session's frontend to config: the lines of a request, as the
 * frontend read them (cmdline_edits()), a part at a time, which config
 * runs after the last. The parts' bytes hold each line as struct
 * nshd_edline and then its edits. A LINE has one line. A STAGE has the
 * line that enters ifname's mode, then its own; a line of its text that
 * the frontend refused has no edits, and says so. In configure
 * terminal, label is the line as typed: config sends it in the notice
 * of the line's commit, and reads nothing of it
 */
#define NSHD_EDITS	(1024 * 1024)	/* a request's lines, at most */
struct nshd_edits {
	int32_t		last;
	int32_t		stage;		/* 1 for a STAGE's lines */
	char		ifname[NSHD_IFNAME];	/* the stage's interface */
	char		label[NSHD_LINE];
	int32_t		len;		/* of bytes */
	char		bytes[NSHD_TEXT];
};
struct nshd_edline {
	int32_t		refused;	/* 1 if the frontend refused it */
	uint32_t	len;		/* of its edits, which follow */
};

enum nshd_proc {
	PROC_PARENT,
	PROC_SHOW,
	PROC_FRONTEND,
	PROC_CONFIG,
	PROC_SYSTEM,
	PROC_JOURNAL,
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

/*
 * The messages between nshd's processes. They share one numbering with
 * the messages of a client and nshd (nshd.h), and no two have the same
 * number
 */
enum nshd_procmsg {
	/*
	 * a session's pipe to its frontend: parent to system, the session
	 * the imsg's id; then system to config, with nshd_newsession
	 */
	IMSG_SESSION = 6,
	/* config to system: the running configuration */
	IMSG_SYS_SNAPSHOT = 7,
	IMSG_SYS_TEXT = 8,	/* system to config: text */
	IMSG_SYS_END = 9,	/* system to config: nshd_result */
	IMSG_SYS_SHOW = 10,	/* config to system: nshd_sysshow, facts back */
	IMSG_SYS_FACTS = 11,	/* system to config: units of facts */
	IMSG_CTL_READ = 12,	/* frontend to config: client read all output */
	IMSG_SYS_READ = 13,	/* config to system: CTL_READ, per request */
	IMSG_SYS_STOP = 14,	/* config to system: stop a request */

	/* config to system, for commits: each is answered as SYS_SHOW is */
	IMSG_SYS_SCRIPT = 21,	/* nshd_chunk, and text; no answer */
	IMSG_SYS_BEGIN = 22,	/* nshd_begin: a commit; how it ended */
	IMSG_SYS_SAVE = 23,	/* nshd_save: save, and remove the record */
	IMSG_SYS_BEGUN = 24,	/* system to config: BEGIN's commit is begun */
	IMSG_SYS_GO = 25,	/* config to system: REVOKING is done */
	IMSG_SYS_ROLLBACK_READ = 26,	/* nshd_rollback: configuration n */
	IMSG_SYS_ROLLBACK_LIST = 27,	/* show rollback's list */
	/* nshd_rollback: what configuration n changed */
	IMSG_SYS_ROLLBACK_DIFF = 28,
	IMSG_SYS_TEST = 29,	/* nshd_test; back, nshd_result: how it went */

	/* config and journal: the shared candidate, as text */
	IMSG_STORE_TEXT = 30,	/* its text, in either direction */
	IMSG_STORE_KEEP = 31,	/* config: nshd_keep; keep the text sent */
	IMSG_STORE_KEPT = 32,	/* journal: nshd_keep, and if it was kept */
	IMSG_STORE_LOAD = 33,	/* config: what was kept, text, then LOADED */
	IMSG_STORE_LOADED = 34,	/* journal: nshd_result */

	/* config to system, answered as SYS_SHOW is */
	IMSG_SYS_SAVED = 35,	/* the saved configuration, as text */

	/*
	 * system to parent, once: it has started, and with -b, the
	 * nshd_result of the boot
	 */
	IMSG_STARTED = 36,

	/* config to system, and system to config */
	IMSG_SYS_PERMS = 37,	/* nshd_perms: result is the permissions */
	IMSG_SYS_OP = 39,	/* nshd_sysop: a stream, a result */
	/* nshd_syslogin: the permissions, as the result */
	IMSG_SYS_LOGIN = 42,
	IMSG_SYS_NOTICE = 45,	/* nshd_notice from system; unrequested */
	IMSG_SYS_FOLLOW = 46,	/* nshd_follow: FOLLOWING, then text */
	IMSG_SYS_FOLLOWING = 47, /* system to config: the log is followed */
	IMSG_SYS_LOGGED = 48,	/* nshd_logged: before a login's result */
	IMSG_SYS_TERMINAL = 52,	/* nshd_systerm; the pty, then SYS_END */

	/*
	 * parent to system, before SESSION: the client's socket of the
	 * session the imsg's id names, where system reads who it is
	 */
	IMSG_SESSION_CLIENT = 54,

	/*
	 * a session ends: system to config and to parent; parent to
	 * system, as its frontend ends
	 */
	IMSG_SESSION_GONE = 55,	/* the session is the imsg's id */

	/*
	 * system to config: login users or classes are about to change, by
	 * a commit or a rollback; config lowers the permissions of the
	 * sessions that would lose one, ends those that would lose their
	 * login, and says so (GO)
	 */
	IMSG_SYS_REVOKING = 58,	/* nshd_revoking */

	/*
	 * system to parent: config is gone, or has gone wrong, and is to
	 * end; parent to system, once it has: config and every session
	 * have ended
	 */
	IMSG_CONFIG_END = 59,

	/*
	 * frontend to config: nshd_edits, the lines of a LINE or a STAGE;
	 * after the last part, config answers as it answers that request
	 */
	IMSG_FRONT_EDITS = 60
};

struct imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	struct event	 ev;
	short		 events;
};

/* config and journal: the sequence number of a KEEP, and its status */
struct nshd_keep {
	uint32_t	seq;
	int32_t		status;
};
#define NSHD_KEEPMAX	(16 * 1024 * 1024)	/* most journal keeps */

/* a child's peer, and the pipe between them, there as the child starts */
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
void		 links_init(struct link *, size_t, int);
void		 parent_watch(void);
int		 link_compose(struct link *, uint32_t, uint32_t, const void *,
		    size_t);
void		 link_broken(struct link *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));
struct plan;
void		 plan_clears(struct plan *, struct nshd_apply *);

/* confirm.c: the record of an unconfirmed commit */
#define CONFIRM_RECORD	NSHDB "/confirm"
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
void		 confirm_kept(struct confirm *, size_t, int);
int		 confirm_read(struct confirm *, int);
int		 confirm_write(struct confirm *);
int		 confirm_clear(void);
void		 confirm_free(struct confirm *);

/* each process but parent */
__dead void	 showproc(int, int, int);
__dead void	 frontend(int, int);
__dead void	 configproc(int, int);
__dead void	 systemproc(int, int, int);
__dead void	 journal(int, int);
__dead void	 parserproc(int, int);

/* system's, and its children's, to run the parser (parserproc.c) */
void		 parser_init(int, int);
__dead void	 parser_exec(struct nshd_parse *, char **, int);
int		 parser_answer(int, size_t, char **, size_t *);
int		 parser_call(struct nshd_parse *, char **, size_t, char **,
		    size_t *);

#endif /* INTERNAL_H */
