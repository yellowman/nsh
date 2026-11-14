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
 * The system process runs as root and uses nsh's own code to read and
 * change kernel state. It answers config's requests on their pipe, one
 * at a time and in order. It sends the running configuration as text;
 * the kernel state that configure private reads, as facts; the shows
 * that only root may run, as facts, with any text nsh's code prints
 * while running them; and the permissions of a uid's login class, which
 * config gives to that uid's session. A show's answer is small, so
 * system builds it whole and packs as many units into each message as
 * fit.
 *
 * A show of text, such as a program's output or the DHCP leases, may be
 * long, or may continue until it is stopped. A child of system prints
 * it, and system streams it to the client as messages, with at most
 * SYS_WINDOW messages the client has not read, while it answers other
 * requests. A stream ends when its child's output ends and the child is
 * reaped; when config reports that its session is gone, which kills the
 * child; or when system exits. A request that waits for a job to end, and
 * that config stops, ends without beginning. If config sends a request it
 * may not send, or a malformed one, system exits, and so does nshd.
 *
 * A log that a session watches is also a stream, and it continues until
 * config stops it. system opens a log file as root, reads it as
 * NSHD_CHECK_USER starting from its last lines, and follows the new
 * file when newsyslog rotates it. The pf log comes from tcpdump on
 * pflog0, which system starts as root, because tcpdump drops root
 * itself. A log needs the view permission, and authlog also needs
 * admin; system checks these itself, as it does for an operation. No
 * request names a path.
 *
 * system runs in a session of its own, which parent kills when system
 * exits. It sets the environment, umask and cwd that rc gives, so the
 * programs it runs get none of these from whoever started nshd. Each
 * stream's child leads its own process group, which is killed when the
 * stream stops. The kind of stream decides which user the child runs
 * as. A show's program runs as NSHD_CHECK_USER, except the programs
 * listed in root_programs, which keep root. dhcpd's leases file is
 * opened as root and copied as NSHD_CHECK_USER. A show comes as the
 * values config parsed from its words: its kind, and for a program,
 * its places in nsh's table, its routing table and the words for its
 * arguments. The program comes from the table; no request names a
 * path.
 *
 * An operation, which a privileged session requests, comes as its row of
 * ops[] and the values config parsed for the row's arguments. system
 * checks them with args_check(), and refuses values the row does not
 * take. A stream's child runs the operation as root, in the client's
 * rtable, with nsh's own code, op_run(), and exits with the operation's
 * status.
 *
 * config sends a commit's requests in order. First come the parts that
 * BEGIN and TEST use, sent in chunks. Each TEST runs a daemon's test of
 * its rules, in a job, and then tells config how it went. The TESTs come
 * before the BEGIN they are for, with its request id, and BEGIN waits
 * for them, as config's requests wait while a job runs. A commit that a
 * test refused is not begun, nor is one that BEGIN asks only to test, as
 * commit check does, nor one with problems config found. system then
 * says the verdict, which counts those problems and the tests that
 * refused the commit, and BEGIN's answer is 0 if it passes. Otherwise
 * BEGIN runs the commit to its end. It writes the commit record and
 * tells config that the commit is begun (BEGUN). If the commit changes
 * login users or classes, system has config lower the permissions of
 * each session that would lose one, end each that would lose its login
 * (REVOKING), and take no new one, and waits until config says it has
 * (GO). Then system runs the script, and checks that what runs is then
 * the configuration wanted. If it is not, system undoes the script,
 * back to the running configuration it read at BEGIN, and removes the
 * record. If it is, system saves the running configuration and removes
 * the record. An unconfirmed commit is kept until its deadline instead,
 * and a configure terminal commit is kept without being saved; their
 * records go too. BEGIN's answer is how the commit ended. BEGIN refuses
 * such a configure terminal commit while an unconfirmed commit exists,
 * because rolling back the unconfirmed commit would roll it back too.
 * Outside a commit, SAVE saves the running configuration.
 *
 * system reads no configuration text itself. The parser does
 * (parserproc.c): a new one for each reading, run in a job of its own
 * or from a job's child. It reads whether what runs is what a commit is
 * based on, and how a record's configurations read; which login lines a
 * commit changes, and to what; whether a script verifies; the script
 * that undoes a commit or rolls one back; the boot's plan; and how two
 * configurations differ. system checks what the parser answers before
 * it uses it, as it checks config's script: its edits before any runs.
 *
 * An apply, an undo, a save, a test and the parser's reading each run
 * as a job: a child of system in its own process group, whose output is
 * sent as it arrives.
 * If a job runs past its time limit, its group gets SIGTERM, then
 * SIGKILL after a grace period, and the job fails. A test runs as
 * NSHD_CHECK_USER, with
 * its rules staged in a directory of its own. The daemons listed in
 * root_tests are exceptions: their tests keep root, and their rules are
 * root's. SAVE writes the running configuration to SAVED, whole and on
 * disk, and keeps it as rollback 0, one generation after the previous
 * rollback 0, unless it is the same as that one. While a job runs,
 * config's requests wait for it, except reports that a stream's client
 * read its messages, requests to stop a stream, and requests for a new
 * session's permissions.
 *
 * When config goes, or breaks a rule, or has not ended the sessions
 * system named GO_SECS seconds after system asked it to, system takes no
 * more of its requests and ends those that have not begun: the requests
 * that wait, streams, logins, and the tests of a commit not begun. What
 * it began goes on to its end, within each job's time limit: a commit,
 * with its undo or save, a rollback of an unconfirmed commit, or the
 * boot. A commit whose script waits for config to lower or end sessions
 * does not run, and ends as one undone. system asks parent to end config,
 * and a rollback that waits so runs once parent says that config and
 * every session have ended. It begins no rollback then, and logs what the
 * jobs print. Then system exits, and parent ends nshd. A commit kept
 * until its deadline leaves its unconfirmed commit record, which the
 * next system takes over.
 *
 * The commit record, in NSHDB, outlives the commit that wrote it, and a
 * commit that does not finish leaves it behind. Its state is applying
 * if the commit neither saved nor rolled back, or unsaved if the commit
 * applied but the save failed. The next commit compares an applying
 * record with the running configuration and reports what the earlier
 * commit left. An unsaved record refuses the next commit, unless that
 * commit only saves the running configuration, or rolls back to the
 * configuration before the earlier commit.
 *
 * A commit with a confirmation deadline sends its minutes with BEGIN,
 * and BEGIN then also writes an unconfirmed commit record (confirm.c).
 * Its rollback configuration is what ran before the first unconfirmed
 * commit. A commit kept until its deadline leaves that record in place;
 * one undone restores the record that existed before BEGIN; one whose
 * undo failed leaves both records. A successful save confirms the
 * commit by removing its record.
 *
 * The deadline is the given number of minutes after BEGIN, and is reset
 * to that many minutes once the commit is kept. After the
 * deadline, system rolls the commit back, but not while a begun commit
 * has not ended or a job runs, because that commit's undo could restore
 * what the rollback removed. system demotes carp, records the attempt,
 * and starts a JOB_RECOVER job, which makes the running configuration
 * match the rollback configuration; then it promotes carp again. A
 * rollback that changes login users or classes first waits for config
 * to take no new session, as such a commit's script does, but ends
 * none. If the job fails or cannot start, system's timer tries again
 * CONFIRM_RETRY seconds later, up to CONFIRM_ATTEMPTS attempts in all;
 * then the record is marked failed, and carp stays demoted. If the
 * record cannot be read or removed, the timer tries again too, and that
 * is not an attempt.
 * If the running configuration already matches
 * the rollback configuration, as after a reboot or a commit that never
 * ran, system only removes the record. When system starts, it takes
 * over an unconfirmed commit that a previous system process left, and
 * rolls it back at its deadline. BEGIN is refused if the running
 * configuration is not the one the commit was planned from, as when an
 * unconfirmed commit was rolled back in the meantime.
 *
 * system starts alone: parent starts config, and takes clients, once
 * system says it has started (STARTED). By then system has read its
 * records, a rollback due as it starts has ended, and, where parent
 * started it with -b, the boot is over. Until then there is no session,
 * so such a rollback waits for no one. The boot
 * begins once no job runs, so that a rollback of an unconfirmed commit
 * that runs as system starts ends first; no rollback begins while the
 * boot runs. The first time, system copies nsh's own NSHRC to the saved
 * configuration. It then writes the boot record, in NSHDB, which names
 * the host boot it is for by kern.boottime and says the boot is
 * running; then it demotes carp and records that too. A system process
 * restarted during the boot finds the record and does not demote carp
 * again. If this host boot is already done, the boot does not run
 * again. Otherwise system plans the boot from the
 * saved configuration and what runs, runs its tests and then its
 * script, each in a job, and the script says whether the running
 * configuration is then the saved configuration. If it is, the record
 * says the boot is done, carp is promoted if it was demoted for the
 * boot, and any unconfirmed commit record is removed. If not, the
 * record says the boot failed, and carp stays demoted until a commit
 * saves. Either way system has then started, and tells parent how the
 * boot went.
 *
 * Each commit belongs to a session, and system learns whose it is from
 * the session's client. parent passes system each client's socket when
 * the client connects, and system asks the kernel who is at the other
 * end of the socket, and whether that is the web configurator. config
 * names the session of each request it sends for a client, and system
 * refuses the request unless that session's client is still connected.
 * The session is gone when system finds that its client has closed its
 * connection, which system checks each second, or when parent says its
 * frontend has ended. When system finds the client gone, it tells
 * parent, which kills the session's frontend if it still runs and tells
 * config to drop the session too. BEGIN, TEST and SAVE name the
 * session. The commit record stores the uid of BEGIN's session; from
 * then on the commit runs to its end, with no request from config. A
 * TEST for no session belongs to the boot, and is refused unless the
 * boot is running. system trusts config to
 * name the session a request came from: a compromised config could act
 * in the name of any connected client, but only as that client's login
 * class allows.
 *
 * system checks the permissions of the login class of that request's
 * uid itself, as config does. An operation needs operate; BEGIN, TEST
 * and SAVE need configure. A commit
 * by a session without admin may not change settings that need admin:
 * system keeps the running configuration when BEGIN accepts the commit,
 * and before it records the commit, a parser checks the script against
 * it (system_parse(), parserproc.c). system reads none of that text
 * itself. Login classes and users, root's crontab, and the
 * rules of inetd, ifstated and sshd need admin. So does a line in
 * smtpd's rules with mda, proc, a pipe, a table or a macro; in snmpd's
 * with a trap handle or a macro; in pf's with file or load; and in any
 * daemon's with include. Each of these runs a command as root, reads a
 * file as root, or decides who may log in. A TEST for such a session is
 * refused those lines too: a parser judges them against the running
 * configuration before the test runs.
 *
 * A web configurator session has no permissions until it logs in, and
 * only such a session may log in. system checks the user's password
 * itself (passwd.c's login_auth()), for a user that a login user line
 * names, never root. It keeps the uid the session logged in as until
 * the session is gone. The session then has the
 * permissions of that user's login class, and its commits are that
 * user's.
 *
 * A web session's terminal is nsh, which system starts on a pty as the
 * logged-in user, as login(1) would. system sends the pty to config,
 * which passes it on to the session. nsh exits when its pty is closed.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <imsg.h>
#include <login_cap.h>
#include <paths.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

#include "log.h"
#include "nshd.h"
#include "stringlist.h"
#include "externs.h"
#include "ctl.h"
#include "facts.h"
#include "args.h"
#include "kfacts.h"
#include "showfacts.h"
#include "answer.h"
#include "session.h"

#define SYS_PATH	"/sbin:/bin:/usr/sbin:/usr/bin"	/* rc's */
#define SYS_BATCH	256	/* records made before what is printed is sent */
#define SYS_STREAMS	16	/* streams at once, at most */
#define SYS_WINDOW	16	/* messages a stream sends its client unread */
#define SYS_TERMINALS	64	/* web logins' terminals at once, at most */
#define SYS_AUTHS	4	/* web logins checked at once, at most */
#define AUTH_SECS	30	/* a web login's check, at most */
#define GO_SECS		10	/* config's GO, for the job that waits */
#define AUTH_GRACE	2	/* after SIGTERM, before SIGKILL */
/* reply to a refused web login; only nshd's log says why */
#define LOGIN_INCORRECT	"% Login incorrect\n"
/* descriptors kept free of sessions: streams, logins, commits, files */
#define SYS_RESERVE	(SYS_STREAMS + SYS_AUTHS + 16)
#define CLIENT_LOOK	1	/* seconds between looks at the clients */

/*
 * kinds of stream, besides a show's (FACTS_*): an operation's output, a
 * log file, or a log file followed again after it was rotated; and an
 * operation's output for a session that may not see password hashes,
 * with any hash it prints removed
 */
#define SYS_OPERATION	3
#define SYS_LOG		4
#define SYS_LOG_AGAIN	5
#define SYS_OPERATION_HIDDEN 6
#define LOG_TAIL	2048	/* a log's last bytes, printed first */
#define LOG_TURNED	4	/* child's exit status: the log was rotated */
#define LOG_WAIT	10	/* half seconds to wait for a rotated log */
#define COMMIT_RECORD	NSHDB "/commit"
#define RECORD_HEAD	128	/* the record's first line, at most */
#define BOOT_RECORD	NSHDB "/boot"

#if NSHD_CLEARS != MAXCLEARS || NSHD_ROLLBACKS != ROLLBACKS
#error "nshd.h's sizes are not nsh's"
#endif

/*
 * A job: an apply, a save, a test, a recover, an undo or the parser's
 * check, and how long it may run, then the grace between SIGTERM and
 * SIGKILL. These are not measured; each should be measured on OpenBSD
 * with a full table
 */
#define JOB_APPLY	0
#define JOB_SAVE	1
#define JOB_TEST	2
#define JOB_RECOVER	3
#define JOB_UNDO	4
#define JOB_PARSE	5
static const struct {
	const char	*what;
	int		 secs;
	int		 grace;
} jobs[] = {
	{ "apply",	900,	10 },	/* a script that starts every daemon */
	{ "save",	300,	10 },	/* conf(), and the save script */
	{ "test",	120,	5 },	/* a validation: bgpd -n on a full table */
	{ "recover",	900,	10 },	/* rollback of an unconfirmed commit */
	{ "undo",	900,	10 },	/* rollback of a commit not taken */
	{ "check",	60,	5 },	/* the parser's, of a full configuration */
};

/* rollback attempts for an unconfirmed commit, and seconds between them */
#define CONFIRM_ATTEMPTS 3
#define CONFIRM_RETRY	5

/*
 * The daemons whose test keeps root, each an exception: each reads, as
 * root, what its rules name. relayd and ldapd their keys, npppd its
 * secrets, sasyncd its shared key, and sshd its host keys
 */
static const char *root_tests[] = {
	"relay", "ldap", "nppp", "sasync", "sshd"
};

/*
 * The programs a show runs that keep root, each an exception: a
 * daemon's control socket is 0660 root:wheel, smtpd answers its shows
 * only to euid 0, /dev/pf is 0600 and PF_KEY needs root. Any other runs
 * as NSHD_CHECK_USER
 */
static const char *root_programs[] = {
	BGPCTL, DVMRPCTL, EIGRPCTL, IKECTL, LDAPCTL, LDPCTL, OSPF6CTL,
	OSPFCTL, RELAYCTL, RIPCTL, SMTPCTL, PFCTL, IPSECCTL, LLDP,
	TCPDUMP		/* opens bpf as root, then drops it itself */
};

/* the logs a session may watch, each by its watch's bit */
static const struct {
	int		 log;
	char		*path;		/* a file, or NULL for the pf log */
} logs[] = {
	{ NSHD_WATCH_DAEMON,	DAEMON_LOG },
	{ NSHD_WATCH_MESSAGES,	MESSAGES_LOG },
	{ NSHD_WATCH_AUTHLOG,	AUTH_LOG },
	{ NSHD_WATCH_PFLOG,	NULL },
};

/* a stream: text a child prints, sent to its client as messages */
struct stream {
	TAILQ_ENTRY(stream)	 entry;
	uint32_t		 id;		/* the request */
	pid_t			 pid;		/* the child, or 0 if reaped */
	int			 fd;		/* its output, or -1 at its end */
	int			 window;	/* messages it may still send */
	int			 stopped;
	int			 op;		/* an operation (either kind) */
	char			*log;		/* log file followed, or NULL */
	int			 text;		/* text, not facts: a log's */
	int			 status;	/* how its child ended */
	struct event		 ev;
	struct facts_out	 o;
};

/* the job running, which a child of system's runs, and what it takes */
/*
 * The commit begun, from BEGIN until it ends (system_ended()): whose it
 * is, how BEGIN asked it to end, and, for commit confirmed, its minutes
 * and the unconfirmed commit record it replaced
 */
struct begun {
	struct nshd_begin	 bg;		/* BEGIN, as config sent it */
	uid_t			 uid;		/* its user's */
	int			 admin;		/* its login class has admin */
	int			 unsaved;	/* configure terminal's */
	char			 comment[NSHD_COMMENT];	/* its save's */
	struct nshd_apply	 apply;		/* its script's clears */
	char			*before;	/* running config at BEGIN */
	size_t			 beforelen;
	struct record		*rec;		/* the commit record then */
	struct nshd_began	 ans;		/* the parser's reading of it */
	struct login_line	*logins;	/* those it wants, if it */
	uint32_t		 nlogins;	/* changes them */
	int			 minutes;	/* commit confirmed's, else 0 */
	struct confirm		 prev;		/* the record before, if so */
};

struct job {
	uint32_t		 id;		/* the request */
	int			 kind;
	pid_t			 pid;		/* the child, or 0 if reaped */
	pid_t			 pgid;
	int			 status;	/* how it ended, once reaped */
	int			 fd;		/* its output, or -1 at its end */
	int			 killed;	/* the signal its group got last */
	int			 waits;		/* to start (system_go()) */
	struct event		 ev, tm;
	struct nshd_apply	*apply;
	struct nshd_parse	 parse;		/* the parser's reading */
	char			*text[NSHD_PARSE_TEXTS];	/* its texts, */
	char			*keep[NSHD_PARSE_TEXTS];	/* those it frees */
	int			 answer;	/* its answer's file, or -1 */
	int			 after;		/* LOGINS: the job ended, */
	int32_t			 after_status;	/* and how */
	struct confirm		 cf;		/* what a rollback's reads */
	char			*back;		/* rollback configuration */
	size_t			 backlen;
	char			*want;		/* what an apply wants */
	size_t			 wantlen;
	char			 who[64];	/* a save's user and comment */
	char			 comment[NSHD_COMMENT];
	char			*args[NOPTFILL];	/* a test's */
	int			 root;
	char			 dir[PATH_MAX];	/* its rules, removed after */
	char			 path[PATH_MAX];
};

/* a request of config's, which waits while a job runs */
struct queued {
	TAILQ_ENTRY(queued)	 entry;
	uint32_t		 type;
	uint32_t		 id;
	size_t			 len;
	unsigned char		 data[];
};

/* the commit record: its state, who made it when, and the parts BEGIN took */
enum { RECORD_NONE, RECORD_APPLYING, RECORD_UNSAVED };
static const char *states[] = NSHD_RECORD_STATES;
struct record {
	int			 state;
	uid_t			 uid;
	time_t			 when;
	char			*before, *want;
	size_t			 beforelen, wantlen;
	char			*buf;		/* what was read, or NULL */
};

/*
 * A session, from parent: its client, as system reads it from the
 * client's socket: the uid the kernel says it is, if it is the web
 * configurator's, and the socket, kept to see whether it is still there.
 * A web configurator's session also has the uid it logged in as, once
 * it logs in
 */
struct client {
	TAILQ_ENTRY(client)	 entry;
	uint32_t		 session;
	uid_t			 uid;
	int			 web;
	int			 fd;
	int			 logged;	/* it logged in */
	uid_t			 login;		/* as this uid */
};

/* what a web login's check sends back */
struct auth_result {
	int32_t			 uid;		/* a uid, or -1 */
	char			 why[96];	/* if uid is -1, the reason */
};

/*
 * A web login being checked, in a child of its own (system_login()). It
 * counts until its child is reaped and its pipe is read to its end,
 * even once it is answered
 */
struct attempt {
	TAILQ_ENTRY(attempt)	 entry;
	uint32_t		 id;		/* its request */
	uint32_t		 session;
	char			 name[NSHD_NAME];	/* the user's */
	pid_t			 pid;		/* its child's, 0 once reaped */
	pid_t			 pgid;		/* the child's process group */
	int			 status;	/* the child's, once reaped */
	int			 fd;		/* its result; -1 at its end */
	struct auth_result	 res;		/* the result */
	size_t			 got;		/* bytes of it read */
	int			 answered;
	int			 killed;	/* its group's last signal */
	struct event		 ev;
	struct event		 tm;		/* its time, then the grace */
};

/* the boot record: the boot of the host it is for, how it went, carp */
enum { BOOT_NONE, BOOT_RUNS, BOOT_FAILED, BOOT_DONE };
static const char *boot_states[] = NSHD_BOOT_STATES;
struct boot {
	int			 state;
	long long		 when;		/* kern.boottime */
	int			 demoted;	/* carp demoted, for it */
};

static struct imsgev	*iev_parent;
static void	system_units(void *, const void *, size_t);
/* facts for a request, kept until its message is full or it flushes */
static struct units	 units = { system_units };
static TAILQ_HEAD(, stream) streams = TAILQ_HEAD_INITIALIZER(streams);
static int		 nstreams;
static uid_t		 check_uid;	/* NSHD_CHECK_USER's */
static uid_t		 web_uid;	/* NSHD_WEB_USER's, */
static int		 web_user;	/* if there is one */
static gid_t		 check_gid;
static struct job	*job;
static pid_t		 terminals[SYS_TERMINALS];	/* nsh's pid, or 0 */
static TAILQ_HEAD(, queued) queue = TAILQ_HEAD_INITIALIZER(queue);
static char		*parts[NSHD_PARTS];	/* sent in chunks, until used */
static size_t		 partlen[NSHD_PARTS];
static struct begun	*begun;		/* the commit begun, or NULL */
static uint32_t		 test_refused;	/* the request a test refused, */
static int		 test_refusals;	/* and how many of its tests did */
static int		 revoking;	/* login lines change: logins refused */
static int		 booting;	/* the boot runs, or waits for a job */
static int		 started;	/* parent was told, and starts config */
static struct plan	*boot_plan;	/* the boot's, once it is made */
static int		 boot_test;	/* the next of its tests */
static int		 boot_unrecorded; /* its record could not be made */
static struct nshd_apply boot_apply;	/* its script's clears */
static TAILQ_HEAD(, attempt) attempts = TAILQ_HEAD_INITIALIZER(attempts);
static TAILQ_HEAD(, client) clients = TAILQ_HEAD_INITIALIZER(clients);
static struct event	 confirm_tm;	/* the deadline, or the next attempt */
static struct event	 look_tm;	/* the next look at the clients */
static time_t		 confirm_next;	/* earliest next rollback attempt */

/*
 * The commit and boot records as system last wrote them, or as the
 * parser read their head lines as nshd started (records_read()), and
 * the commit record's head line's length; or why one could not be read,
 * EFTYPE if it is not a record. system reads only the commit record's
 * parts again
 */
static struct record	 kept;
static size_t		 kept_head;
static int		 kept_error;
static struct boot	 kept_boot;
static int		 kept_boot_error;
/* their first bytes as read, or why not */
static char		 heads[3][RECORD_HEAD + 1];
static int		 errors[3];
/* and those of each configuration kept */
static char		 slots[ROLLBACKS * ROLLBACK_SLOT];
/* NSHLOGIN's error, if it could not be read */
static int		 logins_error;
/* a job changed NSHLOGIN, perhaps, and it could not be read again */
static int		 logins_lost;

static void	system_dispatch_parent(int, short, void *);
static void	system_dispatch_config(int, short, void *);
static int	client_socket(uint32_t, int);
static void	client_drop(struct client *);
static void	client_look(int, short, void *);
static struct client *client_find(uint32_t);
static struct client *client_whose(struct nshd_whose *);
static int	client_there(struct client *);
static int	system_whom(struct client *, uid_t *);
static int	system_perms(uint32_t);
static void	system_login(uint32_t, struct nshd_syslogin *);
static pid_t	system_fork(void);
static __dead void system_auth_child(int, struct nshd_syslogin *);
static void	system_auth_read(int, short, void *);
static void	system_auth_late(int, short, void *);
static void	system_auth_stop(struct attempt *, const char *);
static void	system_auth_reap(struct attempt *);
static void	system_auth_done(struct attempt *);
static void	system_auth_answer(struct attempt *);
static void	system_refused(uint32_t, const char *, const char *, ...)
		    __attribute__((__format__ (printf, 3, 4)));
static void	system_terminal(uint32_t, struct nshd_systerm *);
static __dead void system_term_child(int, struct passwd *);
static int	system_whole(uint32_t, const void *, size_t);
static int	apply_whole(struct nshd_apply *);
static int	system_request(uint32_t, uint32_t, const void *, size_t);
static void	system_queue(uint32_t, uint32_t, const void *, size_t);
static int	system_unqueue(uint32_t);
static void	system_drain(void);
static void	config_gone(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)));
static void	system_drained(void);
static int	system_said(uint32_t);
static void	system_tell(uint32_t, uint32_t, const void *, size_t);
static void	system_snapshot(uint32_t, int);
static void	system_show(uint32_t, struct nshd_sysshow *);
static void	system_op(uint32_t, struct nshd_sysop *);
static int	system_may(int, int, const char *);
static void	system_end(uint32_t, int32_t, const char *, ...)
		    __attribute__((__format__ (printf, 3, 4)));
static int	system_stream(uint32_t, int, char **, int);
static int	system_stream_child(struct stream *, int, char **, int);
static void	system_follow(uint32_t, struct nshd_follow *);
static int	system_tail(int, const char *);
static __dead void system_child(int, int, char **, int);
static int	system_root(const char *);
static void	system_drop(void);
static void	system_stream_read(int, short, void *);
static void	system_stream_more(uint32_t);
static void	system_stream_stop(struct stream *);
static void	system_stream_done(struct stream *);
static void	system_sigchld(int, short, void *);
static int	system_chunk(const unsigned char *, size_t);
static void	system_part_free(int);
static void	system_parts_free(void);
static void	system_begin(uint32_t, struct nshd_begin *);
static void	system_script(uint32_t, struct nshd_apply *, int);
static void	system_go(uint32_t);
static void	system_took(uint32_t);
static void	system_finish(uint32_t, int);
static void	system_save(uint32_t, struct nshd_save *);
static int	system_saved(int);
static void	system_ended(void);
static int	system_unconfirm(void);
static int	system_boot(void);
static void	boot_start(void);
static void	boot_next(void);
static void	boot_end(int);
static void	system_started(int32_t);
static int	system_booted(int);
static void	boot_saved(void);
static int	boot_read(struct boot *);
static int	boot_write(struct boot *);
static long long boot_time(void);
static int	system_arm(int);
static void	system_unarm(void);
static void	system_kept(void);
static void	system_confirm(int, short, void *);
static void	system_recover(struct confirm *);
static void	system_recovering(struct confirm *, int, int);
static void	system_attempted(int);
static void	confirm_retry(void);
static void	system_taken(struct confirm *, const char *);
static void	system_failed(struct confirm *);
static void	system_went(int);
static void	system_revoking(uint32_t, int, struct login_line *,
		    uint32_t);
static char	*system_running(size_t *);
static char	*child_running(size_t *);
static char	*system_facts(size_t *);
static void	system_facts_emit(void *, const void *, size_t);
static int	system_verify(char *, size_t, int, int);
static int	system_undo(char *, size_t);
static void	system_clears(struct nshd_apply *, struct script *);
static void	system_rollback(uint32_t, int, int);
static void	system_listed(uint32_t, int);
static void	system_health(int);
static void	system_test(uint32_t, struct nshd_whose *, char *);
static void	system_tested(uint32_t, int32_t);
static void	system_test_run(uint32_t, char *);
static void	system_begin_checked(uint32_t, int);
static struct job *system_parse_job(uint32_t, int);
static void	system_parse_text(struct job *, int, char *, size_t);
static void	system_parse(struct job *);
static void	system_parsed(struct job *, int32_t);
static int	system_began(struct job *);
static void	boot_parsed(struct job *, int32_t);
static int	boot_planned(struct job *);
static void	system_printed(uint32_t, int32_t);
static struct job *system_job_new(uint32_t, int);
static void	system_job(struct job *);
static __dead void system_job_child(int, struct job *);
static void	system_job_free(struct job *);
static void	system_job_read(int, short, void *);
static void	system_job_late(int, short, void *);
static void	system_job_wait(struct job *);
static void	system_go_late(int, short, void *);
static void	system_job_done(void);
static void	system_job_end(struct job *, int32_t);
static void	records_start(void);
static void	records_read(struct job *, int32_t);
static char	*file_read(int, size_t, size_t *);
static int	logins_answered(struct job *);
static void	logins_reread(struct job *, int32_t);
static void	logins_read(struct job *, int32_t);
static int	record_read(struct record *);
static int	record_write(struct record *);
static int	record_clear(void);
static void	record_free(struct record *);
static const char *record_by(struct record *);
static void	user_name(uid_t, char *, size_t);
static int	db_sync(void);
static __dead void system_exit(void);

static struct link	 links[] = {
#define CONFIG		0
	{ PROC_CONFIG,	 system_dispatch_config },
};

void
systemproc(int debug, int v, int boot)
{
	extern char		**environ;
	static char		*empty[] = { NULL };
	static struct event	 ev_sigchld;
	struct passwd		*pw;

	child_start("system", debug, v);
	if (setsid() == -1)
		fatal("setsid");
	/* the parser is this program again (parser_exec()) */
	parser_init(debug, v);
	/* rc's environment, umask and cwd, whoever started nshd */
	environ = empty;
	if (setenv("PATH", SYS_PATH, 1) == -1 || setenv("HOME", "/", 1) == -1)
		fatal("setenv");
	umask(022);
	if (chdir("/") == -1)
		fatal("chdir /");
	if ((pw = getpwnam(NSHD_WEB_USER)) != NULL) {
		web_uid = pw->pw_uid;
		web_user = 1;
	}
	if ((pw = getpwnam(NSHD_CHECK_USER)) == NULL)
		fatalx("unknown user %s", NSHD_CHECK_USER);
	check_uid = pw->pw_uid;
	check_gid = pw->pw_gid;
	capture_stdout();

	facts_from = FACTS_SYSTEM;
	db_create();

	/* each session's pipe and its client's socket come from parent */
	if ((iev_parent = imsgev_new(3, system_dispatch_parent, 1)) == NULL)
		fatal(NULL);
	evtimer_set(&confirm_tm, system_confirm, NULL);
	evtimer_set(&look_tm, client_look, NULL);
	client_look(-1, 0, NULL);
	links_init(links, sizeof(links) / sizeof(links[0]));
	/* terminal ptys go to config */
	imsgbuf_allow_fdpass(&links[CONFIG].iev->ibuf);
	/* before any child: one that ends unwatched is never reaped */
	signal_set(&ev_sigchld, SIGCHLD, system_sigchld, NULL);
	signal_add(&ev_sigchld, NULL);
	/* the records an earlier nshd left, then a commit not confirmed */
	records_start();
	/* the boot waits for a rollback that runs */
	booting = boot;
	if (booting && job == NULL)
		boot_start();
	if (!booting && job == NULL)
		system_started(0);
	event_dispatch();
	system_exit();
}

/*
 * parent's word of each new session, with its client's socket; of each
 * session whose frontend has ended; and, once config is gone, that
 * config and every session have ended, which starts a rollback that
 * waits for that
 */
static void
system_dispatch_parent(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_newsession	 ns;
	struct nshd_taken	 t;
	struct client		*cl;
	uint32_t		 type;
	int			 n, sfd;

	if (imsgev_io(iev, event) == -1)
		system_exit();

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		type = imsg_get_type(&imsg);
		if (type == IMSG_CONFIG_END && imsg_get_len(&imsg) == 0 &&
		    links[CONFIG].iev == NULL) {
			imsg_free(&imsg);
			system_go(0);
			/* system exits if the rollback could not start */
			system_drained();
			continue;
		}
		if (type == IMSG_SESSION_GONE && imsg_get_len(&imsg) == 0) {
			if ((cl = client_find(imsg_get_id(&imsg))) != NULL)
				client_drop(cl);
			imsg_free(&imsg);
			continue;
		}
		if (type == IMSG_SESSION_CLIENT &&
		    imsg_get_data(&imsg, &ns, sizeof(ns)) == 0 &&
		    (sfd = imsg_get_fd(&imsg)) != -1) {
			imsg_free(&imsg);
			memset(&t, 0, sizeof(t));
			t.session = ns.session;
			t.status = client_socket(ns.session, sfd);
			if (imsg_compose_event(iev, IMSG_SESSION_TAKEN, 0, 0,
			    -1, &t, sizeof(t)) == -1)
				fatal("%s", __func__);
			continue;
		}
		log_warnx("parent sent imsg %u, which it may not",
		    imsg_get_type(&imsg));
		system_exit();
	}
	imsg_event_add(iev);
}

/* a's clears, each named whole: -1 if not */
static int
apply_whole(struct nshd_apply *a)
{
	int	 i;

	if (a->nclears < 0 || a->nclears > NSHD_CLEARS)
		return (-1);
	for (i = 0; i < a->nclears; i++)
		if (memchr(a->clears[i].name, '\0',
		    sizeof(a->clears[i].name)) == NULL)
			return (-1);
	return (0);
}

/* config's requests, in order; most wait while a job runs */
static void
system_dispatch_config(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct ibuf		 b;
	const void		*data;
	size_t			 len;
	uint32_t		 type, id;
	int			 n;
	int			 r = 0;

	if (imsgev_io(iev, event) == -1) {
		config_gone("closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			config_gone("sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		type = imsg_get_type(&imsg);
		id = imsg_get_id(&imsg);
		data = NULL;
		len = 0;
		/* an imsg with no data has no ibuf */
		if (imsg_get_len(&imsg) > 0) {
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			data = ibuf_data(&b);
			len = ibuf_size(&b);
		}
		if (system_whole(type, data, len) == -1) {
			imsg_free(&imsg);
			config_gone("sent imsg %u, which it may not, or not "
			    "whole", type);
			return;
		}
		/*
		 * what a stream's client read, stopping a stream, a new
		 * session's permissions, a login, and GO for the job that
		 * waits do not wait
		 */
		if (type == IMSG_SYS_READ || type == IMSG_SYS_STOP ||
		    type == IMSG_SYS_PERMS || type == IMSG_SYS_LOGIN ||
		    type == IMSG_SYS_GO ||
		    (job == NULL && TAILQ_EMPTY(&queue)))
			r = system_request(type, id, data, len);
		else
			system_queue(type, id, data, len);
		/* a login's password is kept nowhere */
		if (type == IMSG_SYS_LOGIN && data != NULL)
			explicit_bzero(ibuf_data(&b), ibuf_size(&b));
		imsg_free(&imsg);
		if (r == -1) {
			config_gone("sent a part past %d bytes", NSHD_PART);
			return;
		}
	}
	imsg_event_add(iev);
}

/*
 * The client's socket, fd, of a new session from parent, with the uid
 * getpeereid() reports: 0 if system takes the session, else 1, and the
 * session is gone. It is not taken if keeping its socket would leave
 * fewer than SYS_RESERVE descriptors free
 */
static int
client_socket(uint32_t session, int fd)
{
	struct client	*cl;
	uid_t		 uid;
	gid_t		 gid;

	if (session == 0 || client_find(session) != NULL) {
		close(fd);
		return (1);
	}
	if (getdtablesize() - getdtablecount() < SYS_RESERVE) {
		log_warnx("%s: session %u: too many clients", __func__,
		    session);
		close(fd);
		return (1);
	}
	if (getpeereid(fd, &uid, &gid) == -1) {
		log_warn("%s: session %u: getpeereid", __func__, session);
		close(fd);
		return (1);
	}
	if ((cl = calloc(1, sizeof(*cl))) == NULL)
		fatal(NULL);
	cl->session = session;
	cl->uid = uid;
	cl->web = web_user && uid == web_uid;
	cl->fd = fd;
	TAILQ_INSERT_TAIL(&clients, cl, entry);
	return (0);
}

/*
 * cl's session gone: its client's socket closed, and its login
 * forgotten. parent ends its frontend, and has config drop it too
 */
static void
client_drop(struct client *cl)
{
	struct attempt	*a;

	if (imsg_compose_event(iev_parent, IMSG_SESSION_GONE, cl->session, 0,
	    -1, NULL, 0) == -1)
		fatal("%s", __func__);
	/* a login it began is not checked on */
	TAILQ_FOREACH(a, &attempts, entry)
		if (a->session == cl->session) {
			system_auth_stop(a, "its session ended");
			break;
		}
	TAILQ_REMOVE(&clients, cl, entry);
	close(cl->fd);
	free(cl);
}

/*
 * Each CLIENT_LOOK seconds, a session whose client has closed its
 * connection ends, though its frontend may still be there
 */
static void
client_look(int fd, short event, void *arg)
{
	struct timeval	 tv = { CLIENT_LOOK, 0 };
	struct client	*cl, *next;

	TAILQ_FOREACH_SAFE(cl, &clients, entry, next)
		if (!client_there(cl)) {
			log_debug("session %u: its client is gone",
			    cl->session);
			client_drop(cl);
		}
	evtimer_add(&look_tm, &tv);
}

static struct client *
client_find(uint32_t session)
{
	struct client	*cl;

	TAILQ_FOREACH(cl, &clients, entry)
		if (cl->session == session)
			return (cl);
	return (NULL);
}

/*
 * The client of the session w names, if it is still connected; else
 * NULL
 */
static struct client *
client_whose(struct nshd_whose *w)
{
	struct client	*cl;

	if ((cl = client_find(w->session)) == NULL || !client_there(cl))
		return (NULL);
	return (cl);
}

/*
 * Is the client still connected? Its socket says, whatever frontend
 * has read of it
 */
static int
client_there(struct client *cl)
{
	struct pollfd	 pfd;

	pfd.fd = cl->fd;
	pfd.events = POLLIN;
	return (poll(&pfd, 1, 0) != -1 &&
	    (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) == 0);
}

/*
 * The login class permissions of cl's session, and its uid in *uid if
 * uid is not NULL. A session of the web configurator's has those of the
 * user it logged in as, or none before
 */
static int
system_whom(struct client *cl, uid_t *uid)
{
	if (uid != NULL)
		*uid = cl->uid;
	if (!cl->web)
		return (login_perms(cl->uid));
	if (!cl->logged)
		return (0);
	if (uid != NULL)
		*uid = cl->login;
	return (login_perms(cl->login));
}

/*
 * The login class permissions of a session, for the uid of its client.
 * system has the client's socket before the session's frontend starts,
 * so before config hears the client's hello. A session whose client is
 * gone, or not known, has none. A session of the web configurator's has
 * none until it logs in
 */
static int
system_perms(uint32_t session)
{
	struct client	*cl;

	if ((cl = client_find(session)) == NULL || !client_there(cl) ||
	    cl->web)
		return (0);
	return (login_perms(cl->uid));
}

/* Is a request one config may send, and whole? 0 if so, else -1 */
static int
system_whole(uint32_t type, const void *data, size_t len)
{
	struct nshd_begin	 bg;
	struct nshd_sysshow	 show;
	struct nshd_chunk	 c;
	struct nshd_save	 sv;
	struct nshd_rollback	 rb;
	struct nshd_test	 t;
	struct nshd_sysop	 so;
	struct nshd_syslogin	 sl;
	struct nshd_systerm	 st;
	struct nshd_follow	 f;
	int			 i, r;

	switch (type) {
	case IMSG_SYS_READ:
	case IMSG_SYS_STOP:
	case IMSG_SYS_GO:
		return (0);
	case IMSG_SYS_OP:
		if (len != sizeof(so))
			return (-1);
		memcpy(&so, data, len);
		/* an interface's operation names one, and no other does */
		return (so.row < 0 || (size_t)so.row >= nops ||
		    (so.set != 0 && so.set != 1) || so.len > sizeof(so.values) ||
		    memchr(so.ifname, '\0', sizeof(so.ifname)) == NULL ||
		    ((ops[so.row].flags & CF_INIF) != 0) !=
		    (so.ifname[0] != '\0') ? -1 : 0);
	case IMSG_SYS_ROLLBACK_LIST:
	case IMSG_SYS_SAVED:
		return (len == 0 ? 0 : -1);
	case IMSG_SYS_PERMS:
		return (len == sizeof(struct nshd_perms) ? 0 : -1);
	case IMSG_SYS_FOLLOW:
		if (len != sizeof(f))
			return (-1);
		memcpy(&f, data, len);
		for (i = 0; i < (int)(sizeof(logs) / sizeof(logs[0])); i++)
			if (f.log == logs[i].log)
				return (0);
		return (-1);
	case IMSG_SYS_LOGIN:
		if (len != sizeof(sl))
			return (-1);
		memcpy(&sl, data, len);
		r = memchr(sl.login.name, '\0', sizeof(sl.login.name)) == NULL ||
		    memchr(sl.login.password, '\0',
		    sizeof(sl.login.password)) == NULL ? -1 : 0;
		explicit_bzero(&sl, sizeof(sl));
		return (r);
	case IMSG_SYS_TERMINAL:
		if (len != sizeof(st))
			return (-1);
		memcpy(&st, data, len);
		return (st.size.rows < 1 || st.size.rows > NSHD_TERMSIZE ||
		    st.size.cols < 1 || st.size.cols > NSHD_TERMSIZE ? -1 : 0);
	case IMSG_SYS_SNAPSHOT:
		return (len == sizeof(struct nshd_snapshot) ? 0 : -1);
	case IMSG_SYS_BEGIN:
		if (len != sizeof(bg))
			return (-1);
		memcpy(&bg, data, len);
		return ((bg.checking != 0 && bg.checking != 1) || bg.bad < 0 ||
		    bg.minutes < 0 || bg.minutes > NSHD_CONFIRMMAX ||
		    (bg.unsaved != 0 && (bg.unsaved != 1 || bg.minutes != 0)) ||
		    memchr(bg.comment, '\0', sizeof(bg.comment)) == NULL ?
		    -1 : apply_whole(&bg.apply));
	case IMSG_SYS_SHOW:
		if (len != sizeof(show))
			return (-1);
		memcpy(&show, data, len);
		if (show.nargs < 0 || show.nargs > NSHD_SHOWARGS)
			return (-1);
		for (i = 0; i < NSHD_SHOWARGS; i++)
			if (memchr(show.args[i], '\0', sizeof(show.args[i])) ==
			    NULL)
				return (-1);
		return (memchr(show.name, '\0', sizeof(show.name)) == NULL ?
		    -1 : 0);
	case IMSG_SYS_SCRIPT:
		if (len < sizeof(c) || len - sizeof(c) > NSHD_TEXT)
			return (-1);
		memcpy(&c, data, sizeof(c));
		return (c.part < 0 || c.part >= NSHD_PARTS ? -1 : 0);
	case IMSG_SYS_SAVE:
		if (len != sizeof(sv))
			return (-1);
		memcpy(&sv, data, len);
		return (memchr(sv.comment, '\0', sizeof(sv.comment)) ==
		    NULL ? -1 : 0);
	case IMSG_SYS_ROLLBACK_READ:
	case IMSG_SYS_ROLLBACK_DIFF:
		if (len != sizeof(rb))
			return (-1);
		memcpy(&rb, data, len);
		return (rb.n < 0 || rb.n >= NSHD_ROLLBACKS ? -1 : 0);
	case IMSG_SYS_TEST:
		if (len != sizeof(t))
			return (-1);
		memcpy(&t, data, len);
		return (memchr(t.name, '\0', sizeof(t.name)) == NULL ? -1 : 0);
	}
	return (-1);
}

/* run a whole request: -1 if config sent a part past NSHD_PART */
static int
system_request(uint32_t type, uint32_t id, const void *data, size_t len)
{
	struct nshd_snapshot	 snap;
	struct nshd_perms	 pm;
	struct nshd_syslogin	 sl;
	struct nshd_sysshow	 show;
	struct nshd_begin	 bg;
	struct nshd_save	 sv;
	struct nshd_rollback	 rb;
	struct nshd_test	 t;
	struct nshd_sysop	 so;
	struct nshd_follow	 f;
	struct nshd_systerm	 st;
	struct stream		*s;
	struct attempt		*at;

	switch (type) {
	case IMSG_SYS_SNAPSHOT:
		memcpy(&snap, data, sizeof(snap));
		system_snapshot(id, snap.facts);
		break;
	case IMSG_SYS_SHOW:
		memcpy(&show, data, sizeof(show));
		system_show(id, &show);
		break;
	case IMSG_SYS_READ:
		system_stream_more(id);
		break;
	case IMSG_SYS_GO:
		system_go(id);
		break;
	case IMSG_SYS_STOP:
		if (system_unqueue(id))
			break;
		TAILQ_FOREACH(s, &streams, entry)
			if (s->id == id) {
				system_stream_stop(s);
				break;
			}
		TAILQ_FOREACH(at, &attempts, entry)
			if (at->id == id) {
				system_auth_stop(at, "config stopped it");
				break;
			}
		break;
	case IMSG_SYS_SCRIPT:
		return (system_chunk(data, len));
	case IMSG_SYS_BEGIN:
		memcpy(&bg, data, sizeof(bg));
		system_begin(id, &bg);
		break;
	case IMSG_SYS_SAVE:
		memcpy(&sv, data, sizeof(sv));
		system_save(id, &sv);
		break;
	case IMSG_SYS_ROLLBACK_READ:
	case IMSG_SYS_ROLLBACK_DIFF:
		memcpy(&rb, data, sizeof(rb));
		system_rollback(id, rb.n, type == IMSG_SYS_ROLLBACK_DIFF);
		break;
	case IMSG_SYS_ROLLBACK_LIST:
		system_rollback(id, -1, 0);
		break;
	case IMSG_SYS_SAVED:
		system_rollback(id, -2, 0);
		break;
	case IMSG_SYS_PERMS:
		memcpy(&pm, data, sizeof(pm));
		system_end(id, system_perms(pm.session), NULL);
		break;
	case IMSG_SYS_LOGIN:
		memcpy(&sl, data, sizeof(sl));
		system_login(id, &sl);
		explicit_bzero(&sl, sizeof(sl));
		break;
	case IMSG_SYS_TERMINAL:
		memcpy(&st, data, sizeof(st));
		system_terminal(id, &st);
		break;
	case IMSG_SYS_OP:
		memcpy(&so, data, sizeof(so));
		system_op(id, &so);
		break;
	case IMSG_SYS_FOLLOW:
		memcpy(&f, data, sizeof(f));
		system_follow(id, &f);
		break;
	case IMSG_SYS_TEST:
		memcpy(&t, data, sizeof(t));
		system_test(id, &t.whose, t.name);
		break;
	}
	return (0);
}

/* a request that waits for the job running, and those before it */
static void
system_queue(uint32_t type, uint32_t id, const void *data, size_t len)
{
	struct queued	*q;

	if ((q = malloc(sizeof(*q) + len)) == NULL)
		fatal(NULL);
	q->type = type;
	q->id = id;
	q->len = len;
	if (len > 0)
		memcpy(q->data, data, len);
	TAILQ_INSERT_TAIL(&queue, q, entry);
}

/*
 * A request that waits, and has not begun, ends now, as config stopped
 * it: 1 if one did, else 0
 */
static int
system_unqueue(uint32_t id)
{
	struct queued	*q, *next;
	int		 found = 0;

	TAILQ_FOREACH_SAFE(q, &queue, entry, next)
		if (q->id == id) {
			TAILQ_REMOVE(&queue, q, entry);
			free(q);
			found = 1;
		}
	if (found)
		system_end(id, 1, NULL);
	return (found);
}

/* the requests that waited, in order, until one starts a job */
static void
system_drain(void)
{
	struct queued	*q;
	int		 r;

	while (job == NULL && (q = TAILQ_FIRST(&queue)) != NULL) {
		TAILQ_REMOVE(&queue, q, entry);
		r = system_request(q->type, q->id, q->data, q->len);
		free(q);
		if (r == -1) {
			config_gone("sent a part past %d bytes", NSHD_PART);
			return;
		}
	}
}

/*
 * config is gone, or broke a rule, as fmt says, and system takes no more
 * of its requests. It ends what it has not begun: the requests that
 * wait, streams, logins, and a test of a commit that is not begun. What
 * it has begun goes on to its end, within the time each job has: a
 * commit, with its undo or its save, a rollback of an unconfirmed
 * commit, or the boot. What these print is logged. Then system exits
 * (system_drained()). A commit whose script waits for config to end
 * sessions does not run, and ends as one undone. system asks
 * parent to end config: a config that is silent may still run. A
 * rollback that waits so waits on, until parent says that config and
 * every session have ended (system_dispatch_parent())
 */
static void
config_gone(const char *fmt, ...)
{
	struct imsgev	*iev = links[CONFIG].iev;
	struct job	*j;
	struct queued	*q;
	struct stream	*s;
	struct attempt	*a;
	va_list		 ap;
	char		*why;

	va_start(ap, fmt);
	if (vasprintf(&why, fmt, ap) == -1)
		fatal("%s", __func__);
	va_end(ap);
	log_warnx("config %s: system finishes what it began", why);
	free(why);
	event_del(&iev->ev);
	close(iev->ibuf.fd);
	imsgbuf_clear(&iev->ibuf);
	free(iev);
	links[CONFIG].iev = NULL;
	while ((q = TAILQ_FIRST(&queue)) != NULL) {
		TAILQ_REMOVE(&queue, q, entry);
		free(q);
	}
	TAILQ_FOREACH(s, &streams, entry)
		if (s->pid != 0)
			killpg(s->pid, SIGKILL);
	TAILQ_FOREACH(a, &attempts, entry)
		killpg(a->pgid, SIGKILL);
	if (job != NULL && (job->kind == JOB_TEST || job->kind == JOB_PARSE) &&
	    job->id != 0)
		killpg(job->pgid, SIGKILL);
	if (job != NULL && job->waits && job->kind == JOB_RECOVER)
		evtimer_del(&job->tm);
	else if (job != NULL && job->waits) {
		j = job;
		job = NULL;
		evtimer_del(&j->tm);
		printf("%% The commit did not run: config ended while it "
		    "waited\n");
		system_parts_free();
		system_finish(j->id, NSHD_UNDONE);
		system_job_free(j);
	}
	if (imsg_compose_event(iev_parent, IMSG_CONFIG_END, 0, 0, -1, NULL,
	    0) == -1)
		fatal("%s", __func__);
	system_drained();
}

/*
 * once config is gone, system exits when no job runs: what it began, a
 * commit, a rollback or the boot, runs in a job until it ends
 */
static void
system_drained(void)
{
	if (links[CONFIG].iev == NULL && job == NULL)
		system_exit();
}

/*
 * what nsh's code printed for request id, to config, or to the log once
 * config is gone; -1 if it could not be sent
 */
static int
system_said(uint32_t id)
{
	if (links[CONFIG].iev == NULL) {
		printed_log();
		return (0);
	}
	return (printed_text(links[CONFIG].iev, IMSG_SYS_TEXT, id, 0));
}

/*
 * To config, of request id, or of none, 0: how it goes, how it ended, or
 * a notice. Once config is gone, nothing is sent, as what system began
 * finishes without it (config_gone())
 */
static void
system_tell(uint32_t type, uint32_t id, const void *data, size_t len)
{
	if (links[CONFIG].iev != NULL &&
	    link_compose(&links[CONFIG], type, id, data, len) == -1)
		fatal("%s", __func__);
}

/*
 * the running configuration, as conf() writes it, and if facts is set,
 * what configure private reads of the kernel; then how it went
 */
static void
system_snapshot(uint32_t id, int facts)
{
	struct nshd_result	 r = { 0 };
	struct facts_out	 o;
	struct kfacts		*k;
	FILE			*f;
	char			*buf = NULL;
	size_t			 len = 0;

	if ((f = open_memstream(&buf, &len)) == NULL) {
		log_warn("%s: open_memstream", __func__);
		r.status = -1;
	} else {
		conf(f);
		printed(NULL);
		if (fclose(f) == EOF) {
			log_warn("%s: fclose", __func__);
			r.status = -1;
		} else if (imsg_text(links[CONFIG].iev, IMSG_SYS_TEXT, id, buf,
		    len) == -1)
			fatal("%s", __func__);
	}
	free(buf);
	if (r.status == 0 && facts) {
		if ((k = kfacts_scan()) == NULL) {
			log_warn("%s: kfacts_scan", __func__);
			r.status = -1;
		} else {
			units.arg = &id;
			facts_out_init(&o, units_emit, &units);
			if (kfacts_emit(&o, k) == -1)
				r.status = -1;
			units_flush(&units);
			kfacts_free(k);
		}
	}
	if (link_compose(&links[CONFIG], IMSG_SYS_END, id, &r, sizeof(r)) == -1)
		fatal("%s", __func__);
}

/* all the facts a show's values ask for, then how it went; or a stream */
static void
system_show(uint32_t id, struct nshd_sysshow *ss)
{
	struct collection	*a;
	struct facts_out	 o;
	char			**argv;
	int			 more = 1, op, table;

	printed(NULL);
	if ((a = facts_answer_take(ss)) == NULL) {
		system_end(id, 1, "%% nshd: a show system does not "
		    "answer\n");
		return;
	}
	units.arg = &id;
	facts_out_init(&o, units_emit, &units);
	if ((op = facts_streams(a, &argv, &table)) != 0) {
		/* -1: words cannot fill the program's arguments; send why */
		if (op == -1) {
			printed(&o);
			units_flush(&units);
			system_end(id, 1, NULL);
		} else
			system_stream(id, op, argv, table);
		facts_answer_end(a);
		return;
	}
	while (more == 1) {
		more = facts_more(a, &o, SYS_BATCH);
		if (printed(&o) == -1)
			more = -1;
	}
	facts_answer_end(a);
	units_flush(&units);
	system_end(id, more != 0, NULL);
}

/* an operation's values, for system_op() and its stream's child */
struct op_values {
	struct nshd_sysop	*so;
	int			 ok;
	struct facts_value	 v[ARGS_MAX];
};
static struct op_values	*op_next;	/* the operation a child runs */

/* a record of an operation's values, kept if its row takes them */
static void
op_record(void *arg, const struct facts_template *t,
    const struct facts_value *v)
{
	struct op_values	*x = arg;

	if (args_check(&ops[x->so->row], x->so->set, t, v) == 0) {
		memcpy(x->v, v, t->nfields * sizeof(*v));
		x->ok = 1;
	}
}

/*
 * An operation, run by a stream's child if its row takes its values, or
 * refused, saying why
 */
static void
system_op(uint32_t id, struct nshd_sysop *so)
{
	struct client	*cl;
	struct facts_in	 in;
	struct op_values x;
	int		 perms;

	printed(NULL);
	if ((cl = client_whose(&so->whose)) == NULL) {
		system_end(id, 1, "%% nshd: this operation's client is "
		    "gone\n");
		return;
	}
	perms = system_whom(cl, NULL);
	if (!system_may(perms, LOGIN_OPERATE, "operate")) {
		system_printed(id, 1);
		return;
	}
	memset(&x, 0, sizeof(x));
	x.so = so;
	facts_in_init(&in, op_record, &x);
	if (facts_read(&in, so->values, so->len) == -1)
		x.ok = 0;
	facts_in_free(&in);
	if (!x.ok) {
		system_end(id, 1, "%% nshd: %s: values it does not take\n",
		    ops[so->row].name);
		return;
	}
	op_next = &x;
	system_stream(id, (perms & LOGIN_ADMIN) != 0 ? SYS_OPERATION :
	    SYS_OPERATION_HIDDEN, NULL, so->rtable);
	op_next = NULL;
}

/*
 * A log, followed as a stream for a session whose class may read it:
 * FOLLOWING once it begins, then its text until it is stopped; or
 * refused, saying why
 */
static void
system_follow(uint32_t id, struct nshd_follow *f)
{
	char		*argv[] = { TCPDUMP, "-l", "-n", "-e", "-ttt", "-i",
			    "pflog0", NULL };
	struct client	*cl;
	size_t		 i;
	int		 perms, r;

	printed(NULL);
	if ((cl = client_whose(&f->whose)) == NULL) {
		system_end(id, 1, "%% nshd: this watch's client is gone\n");
		return;
	}
	perms = system_whom(cl, NULL);
	if (!system_may(perms, LOGIN_VIEW, "view") ||
	    (f->log == NSHD_WATCH_AUTHLOG &&
	    !system_may(perms, LOGIN_ADMIN, "admin"))) {
		system_printed(id, 1);
		return;
	}
	for (i = 0; logs[i].log != f->log; i++)
		;
	if (logs[i].path != NULL) {
		argv[0] = logs[i].path;
		argv[1] = NULL;
		r = system_stream(id, SYS_LOG, argv, 0);
	} else
		r = system_stream(id, FACTS_PROGRAM, argv, 0);
	if (r == 0 && link_compose(&links[CONFIG], IMSG_SYS_FOLLOWING, id,
	    NULL, 0) == -1)
		fatal("%s", __func__);
}

/* Does perms have need? 1 if so, else 0, after saying name is missing */
static int
system_may(int perms, int need, const char *name)
{
	if (perms & need)
		return (1);
	printf("%% Not allowed: your login class does not have the %s "
	    "permission\n", name);
	return (0);
}

/*
 * Log in the web configurator's session as a user named by a login user
 * line, never root, if the password is right (login_auth()). The
 * session then acts as that user, and config takes the user's uid as
 * the session's. The answer is the user's login class permissions, or
 * -1 with "Login incorrect", and nshd's log says why. BSD auth may run
 * slow programs, so the check runs in its own child for at most
 * AUTH_SECS seconds, and is answered when it ends
 * (system_auth_answer()). At most SYS_AUTHS checks run at once, one per
 * session. While login users or classes are changing, logins are
 * refused, because the session would get its permissions from the old
 * login lines; checks already running are stopped (system_revoking()).
 */
static void
system_login(uint32_t id, struct nshd_syslogin *sl)
{
	struct timeval		 tv = { AUTH_SECS, 0 };
	struct client		*cl;
	struct attempt		*a;
	int			 fds[2], n = 0;

	printed(NULL);
	if ((cl = client_whose(&sl->whose)) == NULL) {
		system_refused(id, sl->login.name, "its session ended");
		return;
	}
	if (!cl->web) {
		system_refused(id, sl->login.name, "its session's uid is "
		    "not %s's, as nshd looked it up when it started",
		    NSHD_WEB_USER);
		return;
	}
	if (revoking) {
		system_refused(id, sl->login.name, "login users or classes "
		    "are changing");
		return;
	}
	TAILQ_FOREACH(a, &attempts, entry) {
		if (a->session == sl->whose.session) {
			system_refused(id, sl->login.name, "its session's "
			    "last login is still being checked");
			return;
		}
		n++;
	}
	if (n >= SYS_AUTHS) {
		system_refused(id, sl->login.name, "%d logins are being "
		    "checked", SYS_AUTHS);
		return;
	}
	if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) == -1) {
		system_refused(id, sl->login.name, "pipe: %s",
		    strerror(errno));
		return;
	}
	if ((a = calloc(1, sizeof(*a))) == NULL)
		fatal(NULL);
	switch (a->pid = system_fork()) {
	case -1:
		system_refused(id, sl->login.name, "fork: %s",
		    strerror(errno));
		close(fds[0]);
		close(fds[1]);
		free(a);
		return;
	case 0:
		close(fds[0]);
		system_auth_child(fds[1], sl);
	}
	/* as the child does, so neither waits on the other */
	setpgid(a->pid, a->pid);
	close(fds[1]);
	a->pgid = a->pid;
	a->id = id;
	a->session = sl->whose.session;
	strlcpy(a->name, sl->login.name, sizeof(a->name));
	a->fd = fds[0];
	a->res.uid = -1;
	TAILQ_INSERT_TAIL(&attempts, a, entry);
	event_set(&a->ev, a->fd, EV_READ | EV_PERSIST, system_auth_read, a);
	event_add(&a->ev, NULL);
	evtimer_set(&a->tm, system_auth_late, a);
	evtimer_add(&a->tm, &tv);
}

/*
 * fork(), with every signal blocked in the child. Until the child puts
 * back the default handlers, it has system's, which pass a signal on to
 * system's event loop: a SIGTERM sent to the child, such as the one that
 * stops a login's check, would end system. So each child unblocks
 * signals once it has put back the default handlers
 */
static pid_t
system_fork(void)
{
	sigset_t	 all, was;
	pid_t		 forked;

	sigfillset(&all);
	sigprocmask(SIG_BLOCK, &all, &was);
	if ((forked = fork()) != 0)
		sigprocmask(SIG_SETMASK, &was, NULL);
	return (forked);
}

/*
 * The child that checks a web login (login_auth()), in its own process
 * group, keeping nothing of system's but fd, the pipe for its result:
 * the uid, or -1 and the reason. BSD auth's programs inherit neither fd
 * nor system's signal mask or handlers.
 */
static __dead void
system_auth_child(int fd, struct nshd_syslogin *sl)
{
	struct auth_result	 res;
	sigset_t		 none;
	const char		*why = NULL;
	int			 null;

	setpgid(0, 0);
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
	/* the result's pipe is 3; what login_auth() prints goes nowhere */
	if ((fd != 3 && dup2(fd, 3) == -1) ||
	    fcntl(3, F_SETFD, FD_CLOEXEC) == -1)
		_exit(1);
	closefrom(4);
	if ((null = open(_PATH_DEVNULL, O_RDWR)) == -1 ||
	    dup2(null, STDIN_FILENO) == -1 || dup2(null, STDOUT_FILENO) == -1)
		_exit(1);
	close(null);
	memset(&res, 0, sizeof(res));
	res.uid = login_auth(sl->login.name, sl->login.password, &why);
	explicit_bzero(sl, sizeof(*sl));
	if (why != NULL)
		strlcpy(res.why, why, sizeof(res.why));
	if (write(3, &res, sizeof(res)) != sizeof(res))
		_exit(1);
	_exit(0);
}

/* the attempt's result, as its child writes it, then the pipe's end */
static void
system_auth_read(int fd, short event, void *arg)
{
	struct attempt	*a = arg;
	char		 buf[sizeof(a->res) + 1];
	ssize_t		 n;

	if ((n = read(a->fd, buf, sizeof(buf))) == -1 &&
	    (errno == EINTR || errno == EAGAIN))
		return;
	if (n > 0 && a->got + n <= sizeof(a->res)) {
		memcpy((char *)&a->res + a->got, buf, n);
		a->got += n;
		return;
	}
	/* its end, an error, or more than a result: no more is read */
	if (n > 0)
		system_auth_stop(a, "its check sent more than a result");
	event_del(&a->ev);
	close(a->fd);
	a->fd = -1;
	system_auth_reap(a);
	system_auth_done(a);
}

/*
 * The attempt past its time: it fails, whatever its child says later,
 * and its group is sent SIGTERM, then SIGKILL a grace later
 */
static void
system_auth_late(int fd, short event, void *arg)
{
	struct attempt	*a = arg;

	if (!a->killed) {
		system_auth_stop(a, "its check took too long");
		return;
	}
	/* the child may be gone, and a program it started not */
	killpg(a->pgid, SIGKILL);
	a->killed = SIGKILL;
	if (a->fd != -1) {
		event_del(&a->ev);
		close(a->fd);
		a->fd = -1;
	}
	system_auth_reap(a);
	system_auth_done(a);
}

/*
 * Refuse the attempt now for why, unless it was answered already, and
 * send its process group SIGTERM, then SIGKILL after a grace period.
 * It still counts toward SYS_AUTHS until then, and until its child is
 * reaped.
 */
static void
system_auth_stop(struct attempt *a, const char *why)
{
	struct timeval	 tv = { AUTH_GRACE, 0 };

	if (!a->answered) {
		a->answered = 1;
		system_refused(a->id, a->name, "%s", why);
	}
	if (a->killed)
		return;
	a->killed = SIGTERM;
	killpg(a->pgid, SIGTERM);
	evtimer_del(&a->tm);
	evtimer_add(&a->tm, &tv);
}

/*
 * The attempt's child, reaped once its pipe is read to its end, and once
 * its group has had SIGKILL if it had SIGTERM. Until it is reaped, no
 * other process can have its pid, so no other group can have the
 * group's id, and the SIGKILL reaches only what the child started
 */
static void
system_auth_reap(struct attempt *a)
{
	if (a->pid == 0 || a->fd != -1 || a->killed == SIGTERM)
		return;
	if (waitpid(a->pid, &a->status, WNOHANG) == a->pid)
		a->pid = 0;
}

/* once its child is reaped and its pipe read to its end */
static void
system_auth_done(struct attempt *a)
{
	if (a->pid != 0 || a->fd != -1)
		return;
	if (!a->answered)
		system_auth_answer(a);
	evtimer_del(&a->tm);
	TAILQ_REMOVE(&attempts, a, entry);
	free(a);
}

/*
 * A login succeeds only if its child wrote a whole result, a uid, and
 * exited 0, and if then its session's client is still there and the
 * user may still log in as that uid. Its permissions are those of the
 * user's class now
 */
static void
system_auth_answer(struct attempt *a)
{
	struct nshd_logged	 lg;
	struct client		*cl;

	a->answered = 1;
	if (a->got != sizeof(a->res) || !WIFEXITED(a->status) ||
	    WEXITSTATUS(a->status) != 0 ||
	    memchr(a->res.why, '\0', sizeof(a->res.why)) == NULL) {
		system_refused(a->id, a->name, "its check did not finish");
		return;
	}
	if (a->res.uid <= 0) {
		system_refused(a->id, a->name, "%s", a->res.why);
		return;
	}
	if ((cl = client_find(a->session)) == NULL || !client_there(cl) ||
	    !cl->web) {
		system_refused(a->id, a->name, "its session ended");
		return;
	}
	if (!login_may(a->name, a->res.uid)) {
		system_refused(a->id, a->name, "its login user line or "
		    "account changed as it was checked");
		return;
	}
	cl->logged = 1;
	cl->login = a->res.uid;
	lg.uid = a->res.uid;
	system_tell(IMSG_SYS_LOGGED, a->id, &lg, sizeof(lg));
	system_end(a->id, login_perms(a->res.uid), NULL);
}

/*
 * Refuse web login request id for name: log why, and tell the session
 * only "Login incorrect".
 */
static void
system_refused(uint32_t id, const char *name, const char *fmt, ...)
{
	va_list	 ap;
	char	 why[128];

	va_start(ap, fmt);
	vsnprintf(why, sizeof(why), fmt, ap);
	va_end(ap);
	log_warnx("web login of %s refused: %s", name, why);
	system_end(id, -1, "%s", LOGIN_INCORRECT);
}

/*
 * A terminal for a web login session: nsh as the login's user, on a pty
 * of the size asked, which goes to config before the answer; or -1,
 * saying why
 */
static void
system_terminal(uint32_t id, struct nshd_systerm *st)
{
	struct winsize	 ws;
	struct passwd	*pw;
	struct client	*cl;
	pid_t		 nsh;
	int		 i, pty, tty;

	if ((cl = client_whose(&st->whose)) == NULL || !cl->web) {
		system_end(id, -1, "%% nshd: only a web login has a "
		    "terminal\n");
		return;
	}
	if (!cl->logged) {
		system_end(id, -1, "%% nshd: log in first\n");
		return;
	}
	for (i = 0; i < SYS_TERMINALS && terminals[i] != 0; i++)
		;
	if (i == SYS_TERMINALS) {
		system_end(id, -1, "%% nshd: %d terminals already\n",
		    SYS_TERMINALS);
		return;
	}
	if ((pw = getpwuid(cl->login)) == NULL) {
		system_end(id, -1, "%% nshd: no user %u\n", cl->login);
		return;
	}
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = st->size.rows;
	ws.ws_col = st->size.cols;
	if (openpty(&pty, &tty, NULL, NULL, &ws) == -1) {
		system_end(id, -1, "%% nshd: openpty: %s\n", strerror(errno));
		return;
	}
	/* no child started later holds them */
	if (fcntl(pty, F_SETFD, FD_CLOEXEC) == -1 ||
	    fcntl(tty, F_SETFD, FD_CLOEXEC) == -1)
		fatal("%s: fcntl", __func__);
	if ((nsh = system_fork()) == -1) {
		system_end(id, -1, "%% nshd: fork: %s\n", strerror(errno));
		close(pty);
		close(tty);
		return;
	}
	if (nsh == 0)
		system_term_child(tty, pw);
	close(tty);
	terminals[i] = nsh;
	if (imsg_compose_event(links[CONFIG].iev, IMSG_SYS_TERMINAL, id, 0,
	    pty, NULL, 0) == -1)
		fatal("%s", __func__);
	system_end(id, 0, NULL);
}

/* nsh, as pw's user, on tty, as login(1) starts a shell */
static __dead void
system_term_child(int tty, struct passwd *pw)
{
	extern char	**environ;
	static char	*empty[] = { NULL };
	char		*argv[] = { "-nsh", NULL };
	sigset_t	 none;

	/* restore the default signal handling, which a program expects */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
	if (login_tty(tty) == -1)
		_exit(1);
	closefrom(STDERR_FILENO + 1);
	environ = empty;
	if (setenv("HOME", pw->pw_dir, 1) == -1 ||
	    setenv("SHELL", NSH_SHELL, 1) == -1 ||
	    setenv("USER", pw->pw_name, 1) == -1 ||
	    setenv("LOGNAME", pw->pw_name, 1) == -1 ||
	    setenv("TERM", "xterm", 1) == -1 ||
	    setusercontext(NULL, pw, pw->pw_uid, LOGIN_SETALL) == -1)
		_exit(1);
	if (chdir(pw->pw_dir) == -1 && chdir("/") == -1)
		_exit(1);
	execv(NSH_SHELL, argv);
	_exit(1);
}

/* to config: a line of text, if fmt, and how request id ended */
static void
system_end(uint32_t id, int32_t status, const char *fmt, ...)
{
	struct nshd_result	 r;
	va_list			 ap;
	char			*s;
	int			 len;

	if (fmt != NULL) {
		va_start(ap, fmt);
		len = vasprintf(&s, fmt, ap);
		va_end(ap);
		if (len == -1 ||
		    imsg_text(links[CONFIG].iev, IMSG_SYS_TEXT, id, s, len) == -1)
			fatal("%s", __func__);
		free(s);
	}
	r.status = status;
	system_tell(IMSG_SYS_END, id, &r, sizeof(r));
}

/* facts units for request *arg, to config, as one message */
static void
system_units(void *arg, const void *buf, size_t len)
{
	uint32_t	*id = arg;

	if (link_compose(&links[CONFIG], IMSG_SYS_FACTS, *id, buf, len) == -1)
		fatal("%s", __func__);
}

/*
 * op's text, which a child prints, streamed to request id's client: 0,
 * or -1, after saying why, if it could not begin
 */
static int
system_stream(uint32_t id, int op, char **argv, int table)
{
	struct stream	*s;

	if (nstreams == SYS_STREAMS) {
		system_end(id, 1, "%% nshd: %d shows already stream\n",
		    SYS_STREAMS);
		return (-1);
	}
	if ((s = calloc(1, sizeof(*s))) == NULL)
		fatal(NULL);
	s->id = id;
	s->op = op == SYS_OPERATION || op == SYS_OPERATION_HIDDEN;
	s->text = op == SYS_LOG || (op == FACTS_PROGRAM &&
	    strcmp(argv[0], TCPDUMP) == 0);
	if (op == SYS_LOG)
		s->log = argv[0];
	s->window = SYS_WINDOW;
	facts_out_init(&s->o, units_emit, &units);
	if (system_stream_child(s, op, argv, table) == -1) {
		free(s);
		return (-1);
	}
	TAILQ_INSERT_TAIL(&streams, s, entry);
	nstreams++;
	return (0);
}

/* s's child, which prints op's text: 0, or -1 after saying why */
static int
system_stream_child(struct stream *s, int op, char **argv, int table)
{
	int	 fds[2];

	if (pipe2(fds, O_CLOEXEC) == -1) {
		system_end(s->id, 1, "%% nshd: pipe: %s\n", strerror(errno));
		return (-1);
	}
	switch (s->pid = system_fork()) {
	case -1:
		system_end(s->id, 1, "%% nshd: fork: %s\n", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		return (-1);
	case 0:
		system_child(fds[1], op, argv, table);
	}
	/* as the child does, so neither waits on the other */
	setpgid(s->pid, s->pid);
	close(fds[1]);
	s->fd = fds[0];
	event_set(&s->ev, s->fd, EV_READ | EV_PERSIST, system_stream_read, s);
	if (s->window > 0)
		event_add(&s->ev, NULL);
	return (0);
}

/* the child: op's text, to fd, with nothing else of system's */
static __dead void
system_child(int fd, int op, char **argv, int table)
{
	char	 buf[8192];
	size_t	 n;
	FILE	*f;
	sigset_t none;
	int	 null, r, lfd, tries;

	setpgid(0, 0);
	/* restore the default signal handling, which a program expects */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
	if (dup2(fd, STDOUT_FILENO) == -1 || dup2(fd, STDERR_FILENO) == -1 ||
	    (null = open(_PATH_DEVNULL, O_RDONLY)) == -1 ||
	    dup2(null, STDIN_FILENO) == -1)
		_exit(127);
	closefrom(STDERR_FILENO + 1);
	switch (op) {
	case FACTS_PROGRAM:
		if (nsh_setrtable(table) != 0)
			break;
		if (!system_root(argv[0]))
			system_drop();
		execv(argv[0], argv);
		printf("%% exec '%s' failed: %s\n", argv[0], strerror(errno));
		break;
	case SYS_OPERATION:
	case SYS_OPERATION_HIDDEN:
		if (nsh_setrtable(table) != 0) {
			fflush(stdout);
			_exit(1);
		}
		cli_rtable = table;
		r = op_run(op_next->so->row, op_next->so->set, op_next->v,
		    op_next->so->ifname, op == SYS_OPERATION_HIDDEN);
		fflush(stdout);
		_exit(r == -1 ? 1 : r);
	case FACTS_LEASES:
		/* dhcpd's leases file, mode 0640 */
		if ((f = fopen(DHCPLEASES, "r")) == NULL) {
			if (errno == ENOENT)
				printf("%% File %s not found\n", DHCPLEASES);
			else
				printf("%% more: fopen(%s): %s\n", DHCPLEASES,
				    strerror(errno));
			break;
		}
		system_drop();
		while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
			fwrite(buf, 1, n, stdout);
		fclose(f);
		break;
	case SYS_LOG:
	case SYS_LOG_AGAIN:
		/* open as root, read as NSHD_CHECK_USER; wait for a new log */
		for (tries = 0; (lfd = open(argv[0], O_RDONLY)) == -1 &&
		    errno == ENOENT && op == SYS_LOG_AGAIN && tries < LOG_WAIT;
		    tries++)
			nanosleep(&(struct timespec){ 0, 500000000 }, NULL);
		if (lfd == -1) {
			printf("%% %s: %s\n", argv[0], strerror(errno));
			break;
		}
		system_drop();
		r = system_tail(lfd, argv[0]);
		fflush(stdout);
		_exit(r);
	}
	fflush(stdout);
	_exit(0);
}

/*
 * fd, the log at path: its last lines, then each as it comes, until path
 * names another file, as newsyslog leaves it; then LOG_TURNED, once the
 * rest of fd is read; or 1 if fd cannot be read or the output written
 */
static int
system_tail(int fd, const char *path)
{
	struct timespec	 nap = { 0, 500000000 };
	struct stat	 st, now;
	char		 buf[8192], *p;
	off_t		 off;
	ssize_t		 n;
	int		 skip, turned = 0;

	if (fstat(fd, &st) == -1)
		return (1);
	off = st.st_size > LOG_TAIL ? st.st_size - LOG_TAIL : 0;
	if (lseek(fd, off, SEEK_SET) == -1)
		return (1);
	/* from the first whole line */
	skip = off > 0;
	for (;;) {
		while ((n = read(fd, buf, sizeof(buf))) > 0) {
			p = buf;
			if (skip) {
				if ((p = memchr(buf, '\n', n)) == NULL)
					continue;
				p++;
				skip = 0;
			}
			if (fwrite(p, 1, buf + n - p, stdout) !=
			    (size_t)(buf + n - p) || fflush(stdout) == EOF)
				return (1);
		}
		if (n == -1)
			return (1);
		if (turned)
			return (LOG_TURNED);
		if (stat(path, &now) == -1 || now.st_dev != st.st_dev ||
		    now.st_ino != st.st_ino)
			turned = 1;
		else if (fstat(fd, &now) == 0 &&
		    now.st_size < lseek(fd, 0, SEEK_CUR))
			/* truncated in place: read it from its start */
			lseek(fd, 0, SEEK_SET);
		else
			nanosleep(&nap, NULL);
	}
}

/* whether program keeps root, an exception root_programs names */
static int
system_root(const char *program)
{
	size_t	 i;

	for (i = 0; i < sizeof(root_programs) / sizeof(root_programs[0]); i++)
		if (strcmp(program, root_programs[i]) == 0)
			return (1);
	return (0);
}

/* make a child NSHD_CHECK_USER, once it holds what it needed root for */
static void
system_drop(void)
{
	if (setgroups(1, &check_gid) == -1 ||
	    setresgid(check_gid, check_gid, check_gid) == -1 ||
	    setresuid(check_uid, check_uid, check_uid) == -1)
		_exit(127);
}

/* what a stream's child printed, as a message to its client */
static void
system_stream_read(int fd, short event, void *arg)
{
	struct stream	*s = arg;
	char		 buf[NSHD_TEXT];
	ssize_t		 n;

	if ((n = read(s->fd, buf, sizeof(buf))) == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		log_warn("%s: read", __func__);
	}
	units.arg = &s->id;
	if (n > 0 && s->text) {
		if (imsg_text(links[CONFIG].iev, IMSG_SYS_TEXT, s->id, buf,
		    n) == -1)
			fatal("%s", __func__);
	} else if (n > 0 && facts_text(&s->o, buf, n) == -1) {
		log_warnx("%s: a message of %zd bytes", __func__, n);
		n = -1;
	}
	units_flush(&units);
	if (n == -1)
		system_stream_stop(s);
	else if (n == 0) {
		event_del(&s->ev);
		close(s->fd);
		s->fd = -1;
		system_stream_done(s);
	} else if (--s->window == 0)
		event_del(&s->ev);
}

/* request id's client read all it was sent: its stream may send more */
static void
system_stream_more(uint32_t id)
{
	struct stream	*s;

	TAILQ_FOREACH(s, &streams, entry)
		if (s->id == id) {
			if (s->window == 0 && s->fd != -1)
				event_add(&s->ev, NULL);
			s->window = SYS_WINDOW;
			break;
		}
}

/*
 * stop s, and kill the process group its child leads: it ends once the
 * child is reaped
 */
static void
system_stream_stop(struct stream *s)
{
	s->stopped = 1;
	if (s->pid != 0)
		killpg(s->pid, SIGKILL);
	if (s->fd != -1) {
		event_del(&s->ev);
		close(s->fd);
		s->fd = -1;
	}
	system_stream_done(s);
}

/* end s, with how it went, once its output ends and its child is reaped */
static void
system_stream_done(struct stream *s)
{
	char	*argv[2];

	if (s->fd != -1 || s->pid != 0)
		return;
	/* a log newsyslog rotated: follow the new file */
	if (s->log != NULL && !s->stopped && WIFEXITED(s->status) &&
	    WEXITSTATUS(s->status) == LOG_TURNED) {
		argv[0] = s->log;
		argv[1] = NULL;
		if (system_stream_child(s, SYS_LOG_AGAIN, argv, 0) == 0)
			return;
		/* it said why, and ended the request */
		TAILQ_REMOVE(&streams, s, entry);
		nstreams--;
		free(s);
		return;
	}
	/* an operation's status is how its child ended */
	system_end(s->id, s->stopped ? 1 : !s->op ? 0 :
	    WIFEXITED(s->status) ? WEXITSTATUS(s->status) : 1, NULL);
	TAILQ_REMOVE(&streams, s, entry);
	nstreams--;
	free(s);
}

/*
 * reap the exited children of streams, the job, terminals and logins'
 * checks; no others
 */
static void
system_sigchld(int sig, short event, void *arg)
{
	struct stream	*s, *next;
	struct attempt	*a, *anext;
	int		 i;

	TAILQ_FOREACH_SAFE(s, &streams, entry, next)
		if (s->pid != 0 &&
		    waitpid(s->pid, &s->status, WNOHANG) == s->pid) {
			s->pid = 0;
			system_stream_done(s);
		}
	if (job != NULL && job->pid != 0 &&
	    waitpid(job->pid, &job->status, WNOHANG) == job->pid) {
		job->pid = 0;
		system_job_done();
	}
	for (i = 0; i < SYS_TERMINALS; i++)
		if (terminals[i] != 0 &&
		    waitpid(terminals[i], NULL, WNOHANG) == terminals[i])
			terminals[i] = 0;
	TAILQ_FOREACH_SAFE(a, &attempts, entry, anext) {
		system_auth_reap(a);
		system_auth_done(a);
	}
}

/* text of a part the next BEGIN, APPLY or TEST takes: -1 if past NSHD_PART */
static int
system_chunk(const unsigned char *data, size_t len)
{
	struct nshd_chunk	 c;
	char			*p;

	memcpy(&c, data, sizeof(c));
	data += sizeof(c);
	len -= sizeof(c);
	if (len > NSHD_PART - partlen[c.part])
		return (-1);
	if (len == 0)
		return (0);
	if ((p = realloc(parts[c.part], partlen[c.part] + len)) == NULL)
		fatal(NULL);
	memcpy(p + partlen[c.part], data, len);
	parts[c.part] = p;
	partlen[c.part] += len;
	return (0);
}

static void
system_part_free(int n)
{
	free(parts[n]);
	parts[n] = NULL;
	partlen[n] = 0;
}

static void
system_parts_free(void)
{
	int	 i;

	for (i = 0; i < NSHD_PARTS; i++)
		system_part_free(i);
}

/*
 * A commit begins, from the running configuration to the wanted one in
 * the parts sent: the record is made, unless one that a commit left
 * refuses it. config is told it is begun, and its script runs; then it
 * ends as BEGIN asked (system_job_end()). The answer is how it ended.
 * The commit's tests have run before this (system_test()). If one
 * refused, or BEGIN asks for only the tests, the answer is 0 and the
 * commit is not begun
 */
static void
system_begin(uint32_t id, struct nshd_begin *bg)
{
	struct confirm	 cf;
	struct client	*cl;
	struct begun	*b;
	struct job	*j;
	char		*runs;
	size_t		 len;
	int		 perms;

	/* not begun: the verdict counts the tests that refused it too */
	if (bg->checking || bg->bad > 0 || test_refused == id) {
		system_parts_free();
		system_printed(id, commit_verdict(bg->bad +
		    (test_refused == id ? test_refusals : 0), bg->checking));
		return;
	}
	if ((b = begun = calloc(1, sizeof(*b))) == NULL)
		fatal(NULL);
	b->bg = *bg;
	if ((cl = client_whose(&bg->whose)) == NULL) {
		printf("%% Commit refused: its client is gone\n");
		goto done;
	}
	perms = system_whom(cl, &b->uid);
	if (!system_may(perms, LOGIN_CONFIGURE, "configure"))
		goto done;
	b->admin = (perms & LOGIN_ADMIN) != 0;
	/* an unsaved commit would be rolled back with an unconfirmed one */
	if (bg->unsaved) {
		if (confirm_read(&cf, 0) == -1) {
			printf("%% nshd: the record of a commit not confirmed: "
			    "%s\n", strerror(errno));
			goto done;
		}
		if (cf.state != CONFIRM_NONE) {
			printf("%% Commit refused: a commit confirmed is not "
			    "confirmed. Commit to confirm it first\n");
			goto done;
		}
	}
	/* the running configuration, which the commit must be planned from */
	if ((runs = system_running(&len)) == NULL)
		goto done;
	/*
	 * Keep the running configuration as read here. The records store
	 * it, an undo or rollback restores it, and the parser reads the
	 * commit against it.
	 */
	b->before = runs;
	b->beforelen = len;
	if ((b->rec = calloc(1, sizeof(*b->rec))) == NULL)
		fatal(NULL);
	if (record_read(b->rec) == -1)
		goto done;
	/* the parser reads them, and a script of a session without admin */
	j = system_parse_job(id, NSHD_PARSE_BEGIN);
	j->parse.apply = bg->apply;
	system_parse_text(j, 0, b->before, b->beforelen);
	system_parse_text(j, 1, parts[NSHD_BEFORE], partlen[NSHD_BEFORE]);
	system_parse_text(j, 2, parts[NSHD_WANT], partlen[NSHD_WANT]);
	if (b->rec->state != RECORD_NONE) {
		j->parse.flags |= NSHD_PARSE_RECORD;
		system_parse_text(j, 3, b->rec->before, b->rec->beforelen);
		system_parse_text(j, 4, b->rec->want, b->rec->wantlen);
	}
	if (!b->admin) {
		j->parse.flags |= NSHD_PARSE_ADMIN;
		system_parse_text(j, 5, parts[NSHD_SCRIPT],
		    partlen[NSHD_SCRIPT]);
	}
	system_parse(j);
	return;
 done:
	system_ended();
	system_parts_free();
	system_printed(id, 1);
}

/*
 * The commit begun for request id, once the parser has read it: ok if
 * it may run. It is recorded, and runs as BEGIN asked
 */
static void
system_begin_checked(uint32_t id, int ok)
{
	struct record	 now, *rec;
	struct begun	*b = begun;
	struct nshd_begin *bg = &b->bg;
	int		 wrote = 0, status = 1;

	rec = b->rec;
	if (!ok)
		goto done;
	/* the parser ran in a job, while the client could go */
	if (client_whose(&bg->whose) == NULL) {
		printf("%% Commit refused: its client is gone\n");
		goto done;
	}
	if (rec->state == RECORD_APPLYING) {
		/* report what it left, judged by the running configuration */
		if (b->ans.none) {
			printf("%% The commit %s did not finish, and changed "
			    "nothing\n", record_by(rec));
		} else {
			printf("%% The commit %s did not finish: what runs is "
			    "%s, and is not saved\n", record_by(rec),
			    b->ans.wanted ? "what it wanted" : "neither what "
			    "it wanted nor what was");
			rec->state = RECORD_UNSAVED;
			if (record_write(rec) == -1)
				goto done;
		}
	}
	if (rec->state == RECORD_UNSAVED) {
		/* allowed only if it rolls back to before that commit */
		if (!b->ans.back) {
			printf("%% Commit refused: what the commit %s changed is "
			    "not saved. Commit with no changes to save it, or "
			    "commit the configuration before it\n",
			    record_by(rec));
			goto done;
		}
	} else {
		now.state = RECORD_APPLYING;
		now.uid = b->uid;
		now.when = time(NULL);
		now.before = b->before;
		now.beforelen = b->beforelen;
		now.want = parts[NSHD_WANT];
		now.wantlen = partlen[NSHD_WANT];
		if (record_write(&now) == -1)
			goto done;
		wrote = 1;
	}
	if (bg->minutes > 0 && system_arm(bg->minutes) == -1) {
		if (wrote)
			record_clear();
		goto done;
	}
	b->unsaved = bg->unsaved;
	strlcpy(b->comment, bg->comment, sizeof(b->comment));
	status = 0;
 done:
	if (status != 0) {
		system_ended();
		system_parts_free();
		system_printed(id, status);
		return;
	}
	system_said(id);
	if (link_compose(&links[CONFIG], IMSG_SYS_BEGUN, id, NULL, 0) == -1)
		fatal("%s", __func__);
	b->apply = bg->apply;
	/* one that changes login users or classes waits for config */
	system_script(id, &b->apply, b->ans.logins);
}

/*
 * Write the unconfirmed commit record for the commit begun, with its
 * deadline minutes from now. Its rollback configuration is what ran
 * before the first unconfirmed commit that still waits, or else before
 * this one. Keep the previous record, to restore if this commit is
 * rolled back. Returns -1 on error, after printing why.
 */
static int
system_arm(int minutes)
{
	struct confirm		 cf;

	if (confirm_read(&begun->prev, 1) == -1) {
		printf("%% nshd: the record of a commit not confirmed: %s\n",
		    strerror(errno));
		return (-1);
	}
	cf = begun->prev;
	if (cf.state != CONFIRM_WAITING) {
		cf.back = begun->before;
		cf.backlen = begun->beforelen;
	}
	cf.state = CONFIRM_WAITING;
	cf.attempts = 0;
	do
		arc4random_buf(&cf.id, sizeof(cf.id));
	while (cf.id == 0);
	cf.deadline = time(NULL) + minutes * 60;
	if (confirm_write(&cf) == -1) {
		printf("%% nshd: the record of a commit not confirmed: %s\n",
		    strerror(errno));
		return (-1);
	}
	begun->minutes = minutes;
	return (0);
}

/* put back the unconfirmed commit record as it was before BEGIN */
static void
system_unarm(void)
{
	if ((begun->prev.state == CONFIRM_NONE ? confirm_clear() :
	    confirm_write(&begun->prev)) == -1)
		printf("%% nshd: the record of a commit not confirmed: %s\n",
		    strerror(errno));
}

/* the commit confirmed kept: its minutes from now, not from its BEGIN */
static void
system_kept(void)
{
	struct confirm	 cf;

	if (confirm_read(&cf, 1) == -1 || cf.state != CONFIRM_WAITING) {
		confirm_free(&cf);
		return;
	}
	cf.deadline = time(NULL) + begun->minutes * 60;
	if (confirm_write(&cf) == -1)
		printf("%% nshd: the record of a commit not confirmed: %s\n",
		    strerror(errno));
	confirm_free(&cf);
}

/*
 * Roll back the unconfirmed commit once its deadline or next attempt is
 * due, unless a commit is begun or a job is running, in which case this
 * function runs again when that commit or job ends. Before then, set the
 * timer for when it is due. If the record cannot be read, try again
 * CONFIRM_RETRY seconds later, and log the error only once. Do not try
 * again if the file is not a record at all, since reading it again will
 * not help.
 */
static void
system_confirm(int fd, short event, void *arg)
{
	static int	 unread;
	struct confirm	 cf;
	struct timeval	 tv = { 0, 0 };
	time_t		 now = time(NULL), due;
	int		 serrno;

	evtimer_del(&confirm_tm);
	if (job != NULL && job->kind == JOB_RECOVER)
		return;
	if (confirm_read(&cf, 1) == -1) {
		serrno = errno;
		if (serrno != unread)
			logit(LOG_CRIT, "the record of a commit not "
			    "confirmed: %s", strerror(serrno));
		unread = serrno;
		if (serrno != EFTYPE)
			confirm_retry();
		return;
	}
	unread = 0;
	due = cf.deadline > confirm_next ? cf.deadline : confirm_next;
	if (cf.state == CONFIRM_WAITING && now < due) {
		tv.tv_sec = due - now;
		evtimer_add(&confirm_tm, &tv);
	} else if (cf.state == CONFIRM_WAITING && begun == NULL && job == NULL)
		system_recover(&cf);
	confirm_free(&cf);
}

/*
 * Roll back the commit cf describes: first the parser reads what runs
 * against cf's rollback configuration, in a job, which takes cf's
 * (system_recovering())
 */
static void
system_recover(struct confirm *cf)
{
	struct job	*j;
	char		*runs;
	size_t		 len;

	if ((runs = system_running(&len)) == NULL) {
		system_recovering(cf, -1, 1);
		return;
	}
	j = system_parse_job(0, NSHD_PARSE_BACK);
	j->cf = *cf;
	cf->back = NULL;
	j->keep[0] = runs;
	system_parse_text(j, 0, runs, len);
	system_parse_text(j, 1, j->cf.back, j->cf.backlen);
	system_parse(j);
}

/*
 * The rollback cf describes, as the parser read it: r 1 if what runs is
 * cf's rollback configuration, 0 if not, or -1 if it could not say;
 * logins 0 if they do not differ in login users or classes. If it is,
 * as when the previous system process stopped after its last attempt
 * succeeded, only clear the record. If every attempt is used, mark the
 * rollback failed. Otherwise demote carp unless that was done already,
 * record the attempt, and start a job that applies the rollback
 * configuration.
 */
static void
system_recovering(struct confirm *cf, int r, int logins)
{
	struct job	*j;

	if (r == 1) {
		system_taken(cf, "what runs is what it goes back to");
		return;
	}
	if (cf->attempts >= CONFIRM_ATTEMPTS) {
		system_failed(cf);
		return;
	}
	if (!cf->demoted && carplock(128) == 1)
		cf->demoted = 1;
	cf->attempts++;
	if (confirm_write(cf) == -1)
		logit(LOG_CRIT, "the record of a commit not confirmed: %s",
		    strerror(errno));
	printed_log();
	/* the job keeps the rollback configuration */
	j = system_job_new(0, JOB_RECOVER);
	j->back = cf->back;
	j->backlen = cf->backlen;
	cf->back = NULL;
	/*
	 * one that changes login users or classes, or may, waits for config
	 * to take no new session, if config is there; it ends none. As
	 * nshd starts, config is not there yet, and no session is
	 */
	if (logins == 0 || links[CONFIG].iev == NULL || !started) {
		system_job(j);
		return;
	}
	system_job_wait(j);
	system_revoking(0, 1, NULL, 0);
}

/*
 * An attempt to roll back the unconfirmed commit ended, or its job could
 * not start. If it succeeded, remove the record. If not, try again
 * CONFIRM_RETRY seconds later, or mark the record failed if no attempts
 * are left. If the record cannot be read, try again later too, unless
 * the file is not a record at all.
 */
static void
system_attempted(int ok)
{
	struct confirm	 cf;
	int		 serrno;

	if (revoking)
		system_revoking(0, 0, NULL, 0);
	if (confirm_read(&cf, 1) == -1) {
		serrno = errno;
		logit(LOG_CRIT, "the record of a commit not confirmed: %s",
		    strerror(serrno));
		if (serrno != EFTYPE)
			confirm_retry();
		return;
	}
	if (cf.state != CONFIRM_WAITING) {
		confirm_free(&cf);
		return;
	}
	if (ok)
		system_taken(&cf, "rolled back");
	else if (cf.attempts < CONFIRM_ATTEMPTS) {
		log_warnx("commit not confirmed: attempt %d of %d to roll "
		    "back failed", cf.attempts, CONFIRM_ATTEMPTS);
		confirm_retry();
	} else
		system_failed(&cf);
	confirm_free(&cf);
}

/*
 * Try the rollback again CONFIRM_RETRY seconds from now: set the time of
 * the next attempt, and the timer that runs system_confirm() then. Only
 * the timer starts the attempt, never this function.
 */
static void
confirm_retry(void)
{
	struct timeval	 tv = { CONFIRM_RETRY, 0 };

	confirm_next = time(NULL) + CONFIRM_RETRY;
	evtimer_add(&confirm_tm, &tv);
}

/*
 * cf was rolled back, as how says: remove its record and carp demotion.
 * If the record cannot be removed, try again later.
 */
static void
system_taken(struct confirm *cf, const char *how)
{
	if (confirm_clear() == -1) {
		logit(LOG_CRIT, "the record of a commit not confirmed: %s",
		    strerror(errno));
		confirm_retry();
		return;
	}
	if (cf->demoted)
		carplock(-128);
	log_warnx("commit not confirmed: %s", how);
	printed_log();
	system_went(0);
}

/* to config, for the sessions that watch: the rollback worked, or not */
static void
system_went(int failed)
{
	struct nshd_notice	 nt;

	memset(&nt, 0, sizeof(nt));
	nt.kind = NSHD_NOTICE_BACK;
	nt.n = failed;
	system_tell(IMSG_SYS_NOTICE, 0, &nt, sizeof(nt));
}

/*
 * To config, with on: login users or classes are about to change to
 * after's n, as the parser read them, by request id's commit, or by a
 * rollback, 0. config lowers the permissions of each session that would
 * lose one, as its permissions now and those after differ, to those
 * after, ends each that would lose its login, takes no new one, and says
 * so (system_go()). A session not logged in has none to lose, so each
 * login being checked is stopped, refused, and none begins until the
 * change ends (system_login()). Or, without on, they have changed
 */
static void
system_revoking(uint32_t id, int on, struct login_line *after, uint32_t n)
{
	struct nshd_revoking	 rv;
	struct client		*cl;
	struct attempt		*a;
	uid_t			 uid;
	int			 now, then;

	memset(&rv, 0, sizeof(rv));
	revoking = rv.on = on;
	if (on)
		TAILQ_FOREACH(a, &attempts, entry)
			system_auth_stop(a, "login users or classes are "
			    "changing");
	/*
	 * a rollback, id 0, ends no session: it takes back a commit, and
	 * system's own checks read the class as it is then
	 */
	TAILQ_FOREACH(cl, &clients, entry) {
		if (!on || id == 0 || rv.n == NSHD_SESSIONS)
			break;
		/* a web session not logged in has no login to lose */
		if (cl->web && !cl->logged)
			continue;
		now = system_whom(cl, &uid);
		then = login_perms_by(uid, cl->web, after, n);
		if (then == -1 || (now & ~then) != 0) {
			rv.sessions[rv.n] = cl->session;
			rv.perms[rv.n++] = then;
		}
	}
	system_tell(IMSG_SYS_REVOKING, id, &rv, sizeof(rv));
}

/* cf not rolled back, and its attempts done: carp stays demoted */
static void
system_failed(struct confirm *cf)
{
	cf->state = CONFIRM_FAILED;
	if (confirm_write(cf) == -1)
		logit(LOG_CRIT, "the record of a commit not confirmed: %s",
		    strerror(errno));
	logit(LOG_CRIT, "commit not confirmed: not rolled back after %d "
	    "attempts%s", CONFIRM_ATTEMPTS, cf->demoted ?
	    ", carp stays demoted" : "");
	system_went(1);
}

/* the running configuration, as conf() writes it, or NULL after saying why */
static char *
system_running(size_t *len)
{
	FILE	*f;
	char	*buf = NULL;

	*len = 0;
	if ((f = open_memstream(&buf, len)) == NULL) {
		printf("%% nshd: the running configuration: %s\n",
		    strerror(errno));
		return (NULL);
	}
	conf(f);
	printed(NULL);
	if (fclose(f) == EOF) {
		printf("%% nshd: the running configuration: %s\n",
		    strerror(errno));
		free(buf);
		return (NULL);
	}
	return (buf);
}

/*
 * In a job's child: the running configuration, as conf() writes it, or
 * NULL after saying why
 */
static char *
child_running(size_t *len)
{
	FILE	*f;
	char	*buf = NULL;

	*len = 0;
	if ((f = open_memstream(&buf, len)) == NULL) {
		printf("%% nshd: the running configuration: %s\n",
		    strerror(errno));
		return (NULL);
	}
	conf(f);
	if (fclose(f) == EOF) {
		printf("%% nshd: the running configuration: %s\n",
		    strerror(errno));
		free(buf);
		return (NULL);
	}
	return (buf);
}

/*
 * The kernel's facts that a plan's checks read, as a snapshot sends
 * them, for the parser; or NULL after saying why
 */
static char *
system_facts(size_t *len)
{
	struct facts_out	 o;
	struct kfacts		*k;
	FILE			*f;
	char			*buf = NULL;
	int			 r;

	*len = 0;
	if ((k = kfacts_scan()) == NULL) {
		printf("%% nshd: the kernel's facts: %s\n", strerror(errno));
		return (NULL);
	}
	if ((f = open_memstream(&buf, len)) == NULL) {
		printf("%% nshd: the kernel's facts: %s\n", strerror(errno));
		kfacts_free(k);
		return (NULL);
	}
	facts_out_init(&o, system_facts_emit, f);
	r = kfacts_emit(&o, k);
	kfacts_free(k);
	if (fclose(f) == EOF || r == -1) {
		printf("%% nshd: the kernel's facts could not be written\n");
		free(buf);
		return (NULL);
	}
	return (buf);
}

static void
system_facts_emit(void *arg, const void *buf, size_t len)
{
	fwrite(buf, 1, len, arg);
}

/*
 * In an apply's job, once its script ran, failed if a line of it
 * failed: whether what runs is want's text, as the parser reads it, as
 * the boot judges it if boot. 0 if so, 1 if not, after the parser says
 * what did not take, or -1 after saying why it could not say
 */
static int
system_verify(char *want, size_t wantlen, int failed, int boot)
{
	struct nshd_parse	 p;
	char			*t[NSHD_PARSE_TEXTS] = { NULL }, *now;
	size_t			 len;
	int			 r;

	if ((now = child_running(&len)) == NULL)
		return (-1);
	memset(&p, 0, sizeof(p));
	p.kind = NSHD_PARSE_VERIFY;
	p.flags = (failed ? NSHD_PARSE_FAILED : 0) |
	    (boot ? NSHD_PARSE_BOOTS : 0);
	t[0] = now;
	p.len[0] = len;
	t[1] = want;
	p.len[1] = wantlen;
	r = parser_call(&p, t, 0, NULL, NULL);
	free(now);
	return (r);
}

/*
 * In an undo's or a rollback's job: make the running configuration read
 * as was's text again, by the script the parser makes from what runs.
 * Whether it does, as the parser reads it, decides, not how the script
 * went: 0 if so, 1 if not, or -1 after saying why it could not say
 */
static int
system_undo(char *was, size_t waslen)
{
	struct nshd_parse	 p;
	struct nshd_apply	 a;
	struct script		 sc;
	char			*t[NSHD_PARSE_TEXTS] = { NULL };
	char			*ans = NULL, *now, *facts = NULL;
	size_t			 len, flen, alen;
	int			 r = -1;

	if ((now = child_running(&len)) == NULL ||
	    (facts = system_facts(&flen)) == NULL)
		goto done;
	memset(&p, 0, sizeof(p));
	p.kind = NSHD_PARSE_PLAN;
	t[0] = now;
	p.len[0] = len;
	t[1] = was;
	p.len[1] = waslen;
	t[2] = facts;
	p.len[2] = flen;
	if (parser_call(&p, t, sizeof(a) + 2 * NSHD_PART, &ans, &alen) != 0)
		goto done;
	if (alen < sizeof(a)) {
		printf("%% nshd: the parser's plan is cut short\n");
		goto done;
	}
	memcpy(&a, ans, sizeof(a));
	if (apply_whole(&a) == -1) {
		printf("%% nshd: the parser's plan clears what none may\n");
		goto done;
	}
	memset(&sc, 0, sizeof(sc));
	sc.edits = ans + sizeof(a);
	sc.elen = alen - sizeof(a);
	system_clears(&a, &sc);
	/* script_run() checks the edits before any runs */
	script_run(&sc);
	free(now);
	if ((now = child_running(&len)) == NULL)
		goto done;
	p.kind = NSHD_PARSE_UNDONE;
	t[0] = now;
	p.len[0] = len;
	t[2] = NULL;
	p.len[2] = 0;
	r = parser_call(&p, t, 0, NULL, NULL);
 done:
	free(ans);
	free(now);
	free(facts);
	return (r);
}

/* a's clears, which apply_whole() checked, into s */
static void
system_clears(struct nshd_apply *a, struct script *s)
{
	int	 i;

	for (i = 0; i < a->nclears; i++) {
		strlcpy(s->clears[i].name, a->clears[i].name,
		    sizeof(s->clears[i].name));
		s->clears[i].rtable = a->clears[i].rtable;
		s->clears[i].keep = a->clears[i].keep;
	}
	s->nclears = a->nclears;
}

/*
 * Start a job that runs the commit's script, then checks that the
 * running configuration is the one wanted. If it is not, an undo job
 * restores the configuration read at BEGIN (system_job_end()). If
 * revoke is set, the commit changes login users or classes, and the job
 * waits until config has lowered the permissions of the sessions that
 * lose some (system_go()).
 */
static void
system_script(uint32_t id, struct nshd_apply *a, int revoke)
{
	struct job	*j;

	j = system_job_new(id, JOB_APPLY);
	j->apply = a;
	j->want = parts[NSHD_WANT];
	j->wantlen = partlen[NSHD_WANT];
	parts[NSHD_WANT] = NULL;
	system_part_free(NSHD_BEFORE);
	if (revoke) {
		system_job_wait(j);
		system_revoking(id, 1, begun->logins, begun->nlogins);
		return;
	}
	system_job(j);
	system_parts_free();
}

/*
 * The job that waits, a commit's script or a rollback, starts: config
 * has lowered the permissions of the sessions that would lose one, and
 * system has stopped the requests of those that ended already
 */
static void
system_go(uint32_t id)
{
	struct job	*j = job;
	int		 apply;

	if (j == NULL || !j->waits || j->id != id)
		return;
	job = NULL;
	j->waits = 0;
	evtimer_del(&j->tm);
	apply = j->kind == JOB_APPLY;
	system_job(j);
	/* the script's part is the child's now */
	if (apply)
		system_parts_free();
}

/* the running configuration, saved by uid with a comment, in a job */
static void
system_save(uint32_t id, struct nshd_save *sv)
{
	struct client	*cl;
	struct job	*j;
	uid_t		 uid;
	int		 perms;

	if ((cl = client_whose(&sv->whose)) == NULL) {
		printf("%% Commit refused: its client is gone\n");
		system_printed(id, 1);
		return;
	}
	perms = system_whom(cl, &uid);
	if (!system_may(perms, LOGIN_CONFIGURE, "configure")) {
		system_printed(id, 1);
		return;
	}
	j = system_job_new(id, JOB_SAVE);
	user_name(uid, j->who, sizeof(j->who));
	strlcpy(j->comment, sv->comment, sizeof(j->comment));
	system_job(j);
}

/*
 * Remove the unconfirmed commit record, or a file there that is not a
 * record, and promote carp if it was demoted for that commit. Returns 1
 * if a file was removed, 0 if there was none, or -1, after saying why,
 * if it could not be read or removed.
 */
static int
system_unconfirm(void)
{
	struct confirm	 cf;
	int		 r;

	if ((r = confirm_read(&cf, 0)) == -1 && errno != EFTYPE) {
		printf("%% nshd: the record of a commit not confirmed: %s\n",
		    strerror(errno));
		return (-1);
	}
	if (r == -1 || cf.state != CONFIRM_NONE) {
		if (confirm_clear() == -1) {
			printf("%% nshd: the record of a commit not confirmed: "
			    "%s\n", strerror(errno));
			return (-1);
		}
		if (r == 0 && cf.demoted)
			carplock(-128);
		return (1);
	}
	return (0);
}

/*
 * daemon name's test of its rules, the part sent, staged in a directory
 * of their own, in a job. It is the commit's or the boot's of request
 * id, and runs before its BEGIN or APPLY, which waits while a job runs.
 * For a session without admin, the parser checks the rules first
 */
static void
system_test(uint32_t id, struct nshd_whose *whose, char *name)
{
	struct client	*cl = NULL;
	struct job	*j;
	char		*runs;
	size_t		 len;
	int		 perms = LOGIN_ALL;

	if (whose->session == 0 ? !booting :
	    (cl = client_whose(whose)) == NULL) {
		printf("%% Commit refused: its client is gone\n");
		system_part_free(NSHD_TEST);
		system_tested(id, 1);
		return;
	}
	if (cl != NULL)
		perms = system_whom(cl, NULL);
	if (!system_may(perms, LOGIN_CONFIGURE, "configure")) {
		system_part_free(NSHD_TEST);
		system_tested(id, 1);
		return;
	}
	if (perms & LOGIN_ADMIN) {
		system_test_run(id, name);
		return;
	}
	/* the parser checks them against what runs as the check begins */
	j = system_parse_job(id, NSHD_PARSE_RULES);
	strlcpy(j->parse.daemon, name, sizeof(j->parse.daemon));
	if ((runs = system_running(&len)) == NULL) {
		system_job_end(j, -1);
		return;
	}
	j->keep[0] = runs;
	system_parse_text(j, 0, runs, len);
	system_parse_text(j, 1, parts[NSHD_TEST], partlen[NSHD_TEST]);
	system_parse(j);
}

/* daemon name's test, for request id, in a job, the rules checked */
static void
system_test_run(uint32_t id, char *name)
{
	struct job	*j;
	size_t		 i;
	int		 fd;

	if (!ctl_rules_args(name, NULL, NULL, 0, NULL)) {
		printf("%% nshd: %s's rules have no test\n", name);
		system_part_free(NSHD_TEST);
		system_tested(id, 1);
		return;
	}
	j = system_job_new(id, JOB_TEST);
	for (i = 0; i < sizeof(root_tests) / sizeof(root_tests[0]); i++)
		if (strcmp(name, root_tests[i]) == 0)
			j->root = 1;
	strlcpy(j->dir, "/tmp/nshtest.XXXXXXXXXX", sizeof(j->dir));
	if (mkdtemp(j->dir) == NULL) {
		printf("%% nshd: mkdtemp %s: %s\n", j->dir, strerror(errno));
		j->dir[0] = '\0';
		goto fail;
	}
	ctl_rules_args(name, j->dir, j->path, sizeof(j->path), j->args);
	if ((fd = open(j->path, O_WRONLY | O_CREAT | O_EXCL, 0600)) == -1) {
		printf("%% nshd: %s: %s\n", j->path, strerror(errno));
		j->path[0] = '\0';
		goto fail;
	}
	if ((!j->root && (fchown(fd, check_uid, check_gid) == -1 ||
	    chown(j->dir, check_uid, check_gid) == -1)) ||
	    (partlen[NSHD_TEST] > 0 && write(fd, parts[NSHD_TEST],
	    partlen[NSHD_TEST]) != (ssize_t)partlen[NSHD_TEST])) {
		printf("%% nshd: %s: %s\n", j->path, strerror(errno));
		close(fd);
		goto fail;
	}
	close(fd);
	system_job(j);
	system_part_free(NSHD_TEST);
	return;
 fail:
	system_job_free(j);
	system_part_free(NSHD_TEST);
	system_tested(id, -1);
}

/*
 * request id's test ended as status says, which config is told; one that
 * did not pass refuses the commit
 */
static void
system_tested(uint32_t id, int32_t status)
{
	struct nshd_result	 r;

	if (id == 0 && boot_plan != NULL) {
		session_tested(boot_plan, boot_test++, status != 0);
		printed_log();
		boot_next();
		return;
	}
	if (status != 0) {
		if (test_refused != id)
			test_refusals = 0;
		test_refused = id;
		test_refusals++;
	}
	system_said(id);
	r.status = status;
	system_tell(IMSG_SYS_TEST, id, &r, sizeof(r));
}

/*
 * After a save. If it succeeded, clear the commit record and confirm a
 * commit that waits for confirmation. If it failed, mark a commit that
 * was applying as applied but not saved; a commit that waits for
 * confirmation keeps its record, and is still rolled back at its
 * deadline. Returns -1 if the save succeeded but the commit that waits
 * could not be confirmed, else 0.
 */
static int
system_saved(int ok)
{
	struct record	 rec;
	int		 r;

	if (ok) {
		record_clear();
		boot_saved();
		if ((r = system_unconfirm()) == 1)
			printf("%% Commit confirmed\n");
		else if (r == -1) {
			printf("%% Saved, but the commit that waits for "
			    "confirmation is not confirmed\n");
			return (-1);
		}
	} else if (record_read(&rec) == 0) {
		if (rec.state == RECORD_APPLYING) {
			rec.state = RECORD_UNSAVED;
			record_write(&rec);
		}
		record_free(&rec);
	}
	return (0);
}

/*
 * End the commit begun, and free it. If it changed login users or
 * classes, config takes sessions again
 */
static void
system_ended(void)
{
	if (revoking)
		system_revoking(0, 0, NULL, 0);
	confirm_free(&begun->prev);
	free(begun->before);
	if (begun->rec != NULL)
		record_free(begun->rec);
	free(begun->rec);
	free(begun->logins);
	free(begun);
	begun = NULL;
}

/*
 * The commit begun took: what runs is the candidate. It ends as BEGIN
 * asked: kept until its deadline, left applied for configure terminal,
 * or saved, in a job (system_job_end())
 */
static void
system_took(uint32_t id)
{
	struct job	*j;

	if (begun->minutes > 0)
		system_finish(id, NSHD_KEPT);
	else if (begun->unsaved)
		system_finish(id, NSHD_APPLIED);
	else {
		j = system_job_new(id, JOB_SAVE);
		user_name(begun->uid, j->who, sizeof(j->who));
		strlcpy(j->comment, begun->comment, sizeof(j->comment));
		system_job(j);
	}
}

/*
 * The commit begun ended as how says, which is its answer. A commit kept
 * until its deadline, applied and not saved, or undone removes its
 * record, but an unsaved one from an earlier commit stays; if the record
 * cannot be read or removed, the answer is -1. A commit whose undo
 * failed leaves both records. A commit kept has its deadline from now,
 * and one undone puts back the unconfirmed commit record that BEGIN
 * replaced. A commit saved has had its records seen to already
 * (system_saved())
 */
static void
system_finish(uint32_t id, int how)
{
	struct record	 rec;
	int		 answer = how;

	if (how == NSHD_KEPT || how == NSHD_APPLIED || how == NSHD_UNDONE) {
		if (record_read(&rec) == -1 ||
		    (rec.state == RECORD_APPLYING && record_clear() == -1))
			answer = -1;
		record_free(&rec);
	}
	if (begun->minutes > 0 && how == NSHD_UNDONE)
		system_unarm();
	else if (begun->minutes > 0 && how == NSHD_KEPT)
		system_kept();
	system_ended();
	system_said(id);
	system_end(id, answer, NULL);
}

/*
 * The boot's record: the first time, nsh's own NSHRC taken as the saved
 * configuration; then the boot record made, and carp demoted for it,
 * unless a system before this did. 0 to boot, 1 if this boot of the
 * host is done already, or -1 if the record could not be made
 */
static int
system_boot(void)
{
	struct boot	 b;

	saved_first();
	if (boot_read(&b) == -1)
		return (-1);
	if (b.state == BOOT_DONE)
		return (1);
	if (b.state == BOOT_NONE) {
		b.state = BOOT_RUNS;
		b.when = boot_time();
		/* recorded first: carp demoted without a record stays so */
		if (boot_write(&b) == -1)
			return (-1);
		if (carplock(128) == 1) {
			b.demoted = 1;
			boot_write(&b);
		}
	}
	return (0);
}

/*
 * The boot, once parent says nshd boots and no job runs. Its record is
 * made; if it cannot be, the boot runs all the same, and is reported as
 * failed. The parser plans it, in a job, from the saved configuration,
 * what runs and the kernel's facts, and says what checks find
 * (boot_parsed()). Then its tests run, each in a job of its own, and
 * then its script, in a job (boot_next()). What checks and tests find
 * does not stop it. What nsh's code and the jobs print is logged
 */
static void
boot_start(void)
{
	struct job	*j;
	FILE		*f;
	char		*saved = NULL, *runs = NULL, *facts = NULL;
	size_t		 len = 0, rlen, flen;
	int		 r;

	if ((r = system_boot()) == 1) {
		booting = 0;
		return;
	}
	boot_unrecorded = r == -1;
	if ((f = open_memstream(&saved, &len)) == NULL)
		fatal("%s", __func__);
	r = saved_text(f);
	if (fclose(f) == EOF)
		fatal("%s", __func__);
	/* logged now: reading what runs drops what was said */
	printed_log();
	if (r != 0 || (runs = system_running(&rlen)) == NULL ||
	    (facts = system_facts(&flen)) == NULL) {
		free(saved);
		free(runs);
		boot_end(0);
		return;
	}
	j = system_parse_job(0, NSHD_PARSE_BOOT);
	j->keep[0] = saved;
	j->keep[1] = runs;
	j->keep[2] = facts;
	system_parse_text(j, 0, saved, len);
	system_parse_text(j, 1, runs, rlen);
	system_parse_text(j, 2, facts, flen);
	system_parse(j);
}

/*
 * The boot's plan, j's answer, as status says: it runs, unless what runs
 * is the saved configuration already, or the parser could not plan it
 */
static void
boot_parsed(struct job *j, int32_t status)
{
	if (status != 0 || boot_planned(j) == -1) {
		boot_end(0);
		return;
	}
	if (boot_plan->same) {
		boot_end(1);
		return;
	}
	printed_log();
	system_parts_free();
	parts[NSHD_WANT] = j->keep[0];
	partlen[NSHD_WANT] = j->parse.len[0];
	j->keep[0] = NULL;
	boot_next();
}

/*
 * The parser's answer to BOOT, j's, as the boot's plan: 0, or -1 after
 * saying why it is not one
 */
static int
boot_planned(struct job *j)
{
	struct nshd_bootplan	 b;
	struct nshd_boottest	 bt;
	struct plan		*p;
	struct plan_test	*t;
	char			*a, *at;
	size_t			 len, left;
	uint32_t		 i;
	int			 k;

	if (parser_answer(j->answer, sizeof(b) + 3 * (size_t)NSHD_PART,
	    &a, &len) == -1)
		return (-1);
	if ((p = calloc(1, sizeof(*p))) == NULL)
		fatal(NULL);
	if (len < sizeof(b))
		goto bad;
	memcpy(&b, a, sizeof(b));
	if (apply_whole(&b.apply) == -1 || b.ntests > NSHD_TESTS)
		goto bad;
	if ((p->tests = calloc(b.ntests + 1, sizeof(*p->tests))) == NULL)
		fatal(NULL);
	at = a + sizeof(b);
	left = len - sizeof(b);
	for (i = 0; i < b.ntests; i++) {
		if (left < sizeof(bt))
			goto bad;
		memcpy(&bt, at, sizeof(bt));
		at += sizeof(bt);
		left -= sizeof(bt);
		if (bt.len > left)
			goto bad;
		t = &p->tests[p->ntests++];
		bt.name[sizeof(bt.name) - 1] = '\0';
		bt.label[sizeof(bt.label) - 1] = '\0';
		strlcpy(t->name, bt.name, sizeof(t->name));
		if ((t->label = strdup(bt.label)) == NULL ||
		    (t->text = malloc(bt.len + 1)) == NULL)
			fatal(NULL);
		memcpy(t->text, at, bt.len);
		t->len = bt.len;
		at += bt.len;
		left -= bt.len;
	}
	if (left != b.elen)
		goto bad;
	if ((p->text[PLAN_EDITS] = malloc(b.elen + 1)) == NULL)
		fatal(NULL);
	memcpy(p->text[PLAN_EDITS], at, b.elen);
	p->len[PLAN_EDITS] = b.elen;
	for (k = 0; k < b.apply.nclears; k++) {
		strlcpy(p->clears[k].name, b.apply.clears[k].name,
		    sizeof(p->clears[k].name));
		p->clears[k].rtable = b.apply.clears[k].rtable;
		p->clears[k].keep = b.apply.clears[k].keep;
	}
	p->nclears = b.apply.nclears;
	p->same = b.same != 0;
	p->boot = 1;
	free(a);
	boot_plan = p;
	return (0);
 bad:
	printf("%% nshd: the parser's answer to BOOT is not a plan\n");
	plan_free(p);
	free(a);
	return (-1);
}

/* the boot's next test, in a job, or once its tests have run, its script */
static void
boot_next(void)
{
	struct plan_test	*t;
	struct nshd_whose	 w;
	struct plan		*p = boot_plan;

	if (boot_test < p->ntests) {
		t = &p->tests[boot_test];
		memset(&w, 0, sizeof(w));
		parts[NSHD_TEST] = t->text;
		partlen[NSHD_TEST] = t->len;
		t->text = NULL;
		system_test(0, &w, t->name);
		return;
	}
	plan_clears(p, &boot_apply);
	parts[NSHD_SCRIPT] = p->text[PLAN_EDITS];
	partlen[NSHD_SCRIPT] = p->len[PLAN_EDITS];
	p->text[PLAN_EDITS] = NULL;
	/* no session runs during the boot, so none can lose a permission */
	system_script(0, &boot_apply, 0);
}

/*
 * The boot ended, ok if what runs is the saved configuration: its record
 * says how (system_booted()), and parent is told, 0 if it went well. A
 * boot whose record could not be made leaves the record as it is, and
 * is told as failed
 */
static void
boot_end(int ok)
{
	plan_free(boot_plan);
	boot_plan = NULL;
	booting = 0;
	if (boot_unrecorded)
		system_started(1);
	else
		system_started(system_booted(ok) == 0 && ok ? 0 : 1);
}

/*
 * system has started: its records are read, no job runs, and with -b
 * the boot is over, status 0 if it went well. parent is told, once,
 * and then starts config and takes clients; until then there is no
 * session
 */
static void
system_started(int32_t status)
{
	struct nshd_result	 res;

	if (started)
		return;
	started = 1;
	printed_log();
	res.status = status;
	if (imsg_compose_event(iev_parent, IMSG_STARTED, 0, 0, -1, &res,
	    sizeof(res)) == -1)
		fatal("%s", __func__);
}

/*
 * The boot ran; ok is set if the running configuration is the saved
 * configuration. If so, mark the boot done, promote carp if it was
 * demoted for the boot, and remove any unconfirmed commit record, since
 * the configuration it would roll back to is running. If not, mark the
 * boot failed; carp stays demoted until a commit saves. 0 if the record
 * says so, else 1
 */
static int
system_booted(int ok)
{
	struct boot	 b;
	int		 demoted, status = 1;

	if (boot_read(&b) == -1)
		goto done;
	if (b.state != BOOT_RUNS && b.state != BOOT_FAILED) {
		printf("%% nshd: no boot runs\n");
		goto done;
	}
	demoted = b.demoted;
	if (ok) {
		b.state = BOOT_DONE;
		b.demoted = 0;
	} else
		b.state = BOOT_FAILED;
	if (boot_write(&b) == -1)
		goto done;
	if (ok && demoted)
		carplock(-128);
	if (ok && system_unconfirm() == 1) {
		printf("%% nshd: the commit not confirmed went with the boot\n");
		system_confirm(-1, 0, NULL);
	}
	status = 0;
 done:
	return (status);
}

/* after a save: a failed boot done, carp promoted if the boot demoted it */
static void
boot_saved(void)
{
	struct boot	 b;
	int		 demoted;

	if (boot_read(&b) == -1 || b.state != BOOT_FAILED)
		return;
	demoted = b.demoted;
	b.state = BOOT_DONE;
	b.demoted = 0;
	if (boot_write(&b) == 0 && demoted)
		carplock(-128);
}

/*
 * configuration n as it was saved, or with diff, what it changed, as
 * the parser says, or with n -1, the list of them, once the parser has
 * said whether what runs is saved (system_listed()), or with -2, the
 * saved configuration
 */
static void
system_rollback(uint32_t id, int n, int diff)
{
	struct job	*j;
	char		*buf = NULL, *old, *new, *head;
	size_t		 len = 0, oldlen, newlen;
	FILE		*f;
	int		 r = 0;

	if (n == -1 || diff) {
		j = system_parse_job(id, NSHD_PARSE_DIFF);
		if (n == -1) {
			j->parse.flags = NSHD_PARSE_QUIET;
			old = NULL;
			if ((new = system_running(&newlen)) == NULL ||
			    (old = saved_read(&oldlen)) == NULL) {
				free(new);
				system_job_free(j);
				system_listed(id, -1);
				return;
			}
			head = NULL;
		} else {
			if ((r = rollback_texts(n, &old, &oldlen, &new,
			    &newlen)) != 1) {
				system_job_free(j);
				system_printed(id, r == -1);
				return;
			}
			if (asprintf(&head, "--- rollback %d\n+++ rollback "
			    "%d\n", n + 1, n) == -1)
				fatal("%s", __func__);
		}
		j->keep[0] = old;
		j->keep[1] = new;
		j->keep[2] = head;
		system_parse_text(j, 0, old, oldlen);
		system_parse_text(j, 1, new, newlen);
		system_parse_text(j, 2, head, head != NULL ? strlen(head) : 0);
		system_parse(j);
		return;
	}
	if ((f = open_memstream(&buf, &len)) == NULL)
		fatal("%s", __func__);
	if (n == -2)
		r = saved_text(f);
	else
		r = rollback_text(n, f);
	if (fclose(f) == EOF)
		fatal("%s", __func__);
	/* first what nsh's code printed, then the text */
	if (system_said(id) == -1)
		r = -1;
	if (imsg_text(links[CONFIG].iev, IMSG_SYS_TEXT, id, buf, len) == -1)
		fatal("%s", __func__);
	free(buf);
	system_end(id, r != 0, NULL);
}

/*
 * The list of rollbacks, for request id, once the parser has said
 * whether what runs differs from the saved configuration: differs 1 if
 * so, or 0, or -1 if it could not say
 */
static void
system_listed(uint32_t id, int differs)
{
	char	*buf = NULL;
	size_t	 len = 0;
	FILE	*f;

	if ((f = open_memstream(&buf, &len)) == NULL)
		fatal("%s", __func__);
	system_health(differs);
	rollback_list(f);
	if (fclose(f) == EOF)
		fatal("%s", __func__);
	/* first what nsh's code printed, then the text */
	system_said(id);
	if (imsg_text(links[CONFIG].iev, IMSG_SYS_TEXT, id, buf, len) == -1)
		fatal("%s", __func__);
	free(buf);
	system_end(id, 0, NULL);
}

/*
 * What is wrong with the running configuration, said before the list of
 * rollbacks: that it is not the saved configuration, if differs, a
 * commit that did not finish or is not saved, a boot that failed, a
 * commit that was not confirmed and could not be rolled back, and a
 * commit record that cannot be read
 */
static void
system_health(int differs)
{
	struct record	 rec;
	struct boot	 b;
	struct confirm	 cf;

	if (differs == 1)
		printf("%% What runs is not the saved configuration\n");
	if (begun == NULL && record_read(&rec) == 0) {
		if (rec.state == RECORD_APPLYING)
			printf("%% The commit %s did not finish\n",
			    record_by(&rec));
		else if (rec.state == RECORD_UNSAVED)
			printf("%% What the commit %s changed is not saved\n",
			    record_by(&rec));
		record_free(&rec);
	}
	if (boot_read(&b) == 0 && b.state == BOOT_FAILED)
		printf("%% The boot failed%s\n", b.demoted ? ", and carp is "
		    "demoted until a commit saves" : "");
	if (confirm_read(&cf, 0) == -1)
		printf("%% The record of a commit not confirmed cannot be "
		    "read: %s\n", strerror(errno));
	else if (cf.state == CONFIRM_FAILED)
		printf("%% A commit not confirmed was not rolled back%s\n",
		    cf.demoted ? ", and carp is demoted until a commit saves" :
		    "");
}

/*
 * A reading of the parser's for request id, kind as nshd.h says, to be
 * given its texts (system_parse_text()), then started (system_parse())
 */
static struct job *
system_parse_job(uint32_t id, int kind)
{
	struct job	*j;

	j = system_job_new(id, JOB_PARSE);
	j->parse.kind = kind;
	return (j);
}

/* j's text i, len bytes, which must last until j starts */
static void
system_parse_text(struct job *j, int i, char *text, size_t len)
{
	j->text[i] = text;
	j->parse.len[i] = len;
}

/*
 * j, the parser's reading, in a job: the parser is the job's child
 * (parser_exec()), its answer in a file that only it and system have.
 * What it prints goes to the session, or is logged; system_parsed()
 * takes its answer
 */
static void
system_parse(struct job *j)
{
	char	 path[] = "/tmp/nshanswer.XXXXXXXXXX";

	if ((j->answer = mkstemp(path)) == -1 || unlink(path) == -1) {
		printf("%% nshd: the parser's answer: %s\n", strerror(errno));
		system_job_end(j, -1);
		return;
	}
	system_job(j);
}

/*
 * j, the parser's reading, ended as status says: 0 or 1, as its kind
 * says, or -1 if it could not read. What waits on it goes on
 */
static void
system_parsed(struct job *j, int32_t status)
{
	struct nshd_back	 b;
	char			*a = NULL;
	size_t			 len;
	int			 there = -1, logins = 1;

	switch (j->parse.kind) {
	case NSHD_PARSE_RULES:
		if (status == 0)
			system_test_run(j->id, j->parse.daemon);
		else {
			system_part_free(NSHD_TEST);
			system_tested(j->id, 1);
		}
		break;
	case NSHD_PARSE_BEGIN:
		system_begin_checked(j->id, status == 0 &&
		    system_began(j) == 0);
		break;
	case NSHD_PARSE_BACK:
		if (status == 0 && parser_answer(j->answer, sizeof(b), &a,
		    &len) == 0 && len == sizeof(b)) {
			memcpy(&b, a, sizeof(b));
			there = b.there != 0;
			logins = b.logins != 0;
		}
		free(a);
		printed_log();
		system_recovering(&j->cf, there, logins);
		confirm_free(&j->cf);
		break;
	case NSHD_PARSE_BOOT:
		boot_parsed(j, status);
		break;
	case NSHD_PARSE_DIFF:
		if (j->parse.flags & NSHD_PARSE_QUIET)
			system_listed(j->id, status);
		else
			system_printed(j->id, status == -1);
		break;
	case NSHD_PARSE_RECORDS:
		records_read(j, status);
		break;
	case NSHD_PARSE_LOGINS:
		logins_read(j, status);
		break;
	}
}

/*
 * The parser's answer to BEGIN, j's, for the commit begun: 0 if it may
 * go on, else -1 after saying why, if the parser did not
 */
static int
system_began(struct job *j)
{
	struct nshd_began	*ans = &begun->ans;
	struct login_line	*l;
	char			*a;
	size_t			 len, n;

	if (parser_answer(j->answer, sizeof(*ans) + NSHD_LOGINS * sizeof(*l),
	    &a, &len) == -1)
		return (-1);
	if (len < sizeof(*ans))
		goto bad;
	memcpy(ans, a, sizeof(*ans));
	if (ans->nlogins > NSHD_LOGINS || len - sizeof(*ans) !=
	    ans->nlogins * sizeof(*l))
		goto bad;
	if ((l = begun->logins = calloc(ans->nlogins + 1, sizeof(*l))) == NULL)
		fatal(NULL);
	memcpy(l, a + sizeof(*ans), ans->nlogins * sizeof(*l));
	for (n = 0; n < ans->nlogins; n++) {
		l[n].name[sizeof(l[n].name) - 1] = '\0';
		l[n].class[sizeof(l[n].class) - 1] = '\0';
	}
	begun->nlogins = ans->nlogins;
	free(a);
	if (!ans->based) {
		printf("%% Commit refused: what runs changed after the commit "
		    "was planned. Commit again\n");
		return (-1);
	}
	/* the parser said why */
	return (ans->admin ? 0 : -1);
 bad:
	printf("%% nshd: the parser's answer to BEGIN is not one\n");
	free(a);
	return (-1);
}

/* what nsh's code printed, to config, then how request id ended */
static void
system_printed(uint32_t id, int32_t status)
{
	if (system_said(id) == -1 && status == 0)
		status = 1;
	system_end(id, status, NULL);
}

/* a job of kind, for request id, to fill, then start */
static struct job *
system_job_new(uint32_t id, int kind)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		fatal(NULL);
	j->id = id;
	j->kind = kind;
	j->fd = -1;
	j->answer = -1;
	return (j);
}

/* start j, in a child of system's, as the running job */
static void
system_job(struct job *j)
{
	struct timeval	 tv = { jobs[j->kind].secs, 0 };
	char		 path[] = "/tmp/nshanswer.XXXXXXXXXX";
	int		 fds[2];

	fflush(stdout);
	/* a script's job answers NSHLOGIN's lines, as it leaves them */
	if ((j->kind == JOB_APPLY || j->kind == JOB_UNDO ||
	    j->kind == JOB_RECOVER) && ((j->answer = mkstemp(path)) == -1 ||
	    unlink(path) == -1)) {
		printf("%% nshd: %s: %s\n", path, strerror(errno));
		goto fail;
	}
	if (pipe2(fds, O_CLOEXEC) == -1) {
		printf("%% nshd: pipe: %s\n", strerror(errno));
		goto fail;
	}
	switch (j->pid = system_fork()) {
	case -1:
		printf("%% nshd: fork: %s\n", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		goto fail;
	case 0:
		system_job_child(fds[1], j);
	}
	/* as the child does, so neither waits on the other */
	setpgid(j->pid, j->pid);
	close(fds[1]);
	j->pgid = j->pid;
	j->fd = fds[0];
	job = j;
	event_set(&job->ev, job->fd, EV_READ | EV_PERSIST, system_job_read,
	    NULL);
	event_add(&job->ev, NULL);
	evtimer_set(&job->tm, system_job_late, NULL);
	evtimer_add(&job->tm, &tv);
	return;
 fail:
	system_job_end(j, -1);
}

/* the job's child: what it prints, to fd, with nothing else of system's */
static __dead void
system_job_child(int fd, struct job *j)
{
	struct script	 sc;
	sigset_t	 none;
	int		 null, r;

	setpgid(0, 0);
	/* the default signal handling nsh's code and its programs expect */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
	if (dup2(fd, STDOUT_FILENO) == -1 || dup2(fd, STDERR_FILENO) == -1 ||
	    (null = open(_PATH_DEVNULL, O_RDONLY)) == -1 ||
	    dup2(null, STDIN_FILENO) == -1)
		_exit(2);
	/*
	 * the parser's answer, which it writes to descriptor 3, or a
	 * script's, which no program it runs has
	 */
	if (j->answer != -1) {
		if (dup2(j->answer, STDERR_FILENO + 1) == -1 ||
		    (j->kind != JOB_PARSE && fcntl(STDERR_FILENO + 1,
		    F_SETFD, FD_CLOEXEC) == -1))
			_exit(2);
		j->answer = STDERR_FILENO + 1;
		closefrom(STDERR_FILENO + 2);
	} else
		closefrom(STDERR_FILENO + 1);
	switch (j->kind) {
	case JOB_APPLY:
		memset(&sc, 0, sizeof(sc));
		sc.edits = parts[NSHD_SCRIPT];
		sc.elen = partlen[NSHD_SCRIPT];
		system_clears(j->apply, &sc);
		/* -1, it could not run; 1, a line of it failed */
		r = script_run(&sc);
		/* then whether what runs is what was wanted; the boot's too */
		r = system_verify(j->want, j->wantlen, r != 0, begun == NULL);
		break;
	case JOB_UNDO:
		r = system_undo(begun->before, begun->beforelen) == 0 ? 0 : 1;
		break;
	case JOB_SAVE:
		/* then system keeps it, as it keeps their heads */
		r = !saved_write();
		break;
	case JOB_RECOVER:
		/* a rollback is an undo, to the rollback configuration */
		r = system_undo(j->back, j->backlen) == 0 ? 0 : 1;
		if (r == 0)
			printf("%% Commit not confirmed: rolled back\n");
		break;
	case JOB_PARSE:
		parser_exec(&j->parse, j->text, j->answer);
	default:
		if (!j->root)
			system_drop();
		execv(j->args[0], j->args);
		printf("%% exec '%s' failed: %s\n", j->args[0],
		    strerror(errno));
		r = -1;
		break;
	}
	if (j->answer != -1 && login_answer(j->answer) == -1)
		r = -1;
	fflush(stdout);
	_exit(r == -1 ? 2 : r);
}

/* what the job's child printed, to config as it comes; a recover's is logged */
static void
system_job_read(int fd, short event, void *arg)
{
	char	 buf[NSHD_TEXT];
	ssize_t	 n;

	if ((n = read(job->fd, buf, sizeof(buf))) == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		log_warn("%s: read", __func__);
	}
	if (n > 0) {
		/* a job of no request's, or once config is gone */
		if (job->id == 0 || links[CONFIG].iev == NULL)
			log_text(buf, n);
		else if (imsg_text(links[CONFIG].iev, IMSG_SYS_TEXT, job->id, buf,
		    n) == -1)
			fatal("%s", __func__);
		return;
	}
	event_del(&job->ev);
	close(job->fd);
	job->fd = -1;
	system_job_done();
}

/*
 * j, a commit's script or a rollback, is the job, but does not start
 * until config has lowered the permissions of the sessions that would
 * lose one (system_go()). Requests wait for it meanwhile. A config that
 * has not said so in GO_SECS seconds has failed
 */
static void
system_job_wait(struct job *j)
{
	struct timeval	 tv = { GO_SECS, 0 };

	j->waits = 1;
	job = j;
	evtimer_set(&j->tm, system_go_late, NULL);
	evtimer_add(&j->tm, &tv);
}

/* config has not said GO in time: it has failed */
static void
system_go_late(int fd, short event, void *arg)
{
	config_gone("did not lower or end its sessions in %d seconds", GO_SECS);
}

/*
 * The job past its time: its group is sent SIGTERM, then SIGKILL a grace
 * later, and its output is no longer waited for
 */
static void
system_job_late(int fd, short event, void *arg)
{
	struct timeval	 tv = { jobs[job->kind].grace, 0 };

	if (job->killed == 0) {
		job->killed = SIGTERM;
		killpg(job->pgid, SIGTERM);
		evtimer_add(&job->tm, &tv);
		return;
	}
	job->killed = SIGKILL;
	killpg(job->pgid, SIGKILL);
	if (job->fd != -1) {
		event_del(&job->ev);
		close(job->fd);
		job->fd = -1;
	}
	system_job_done();
}

/*
 * The job, once its output has ended and its child is reaped: how it
 * went, 0, 1 if a line of the script failed, or -1; then what waited
 */
static void
system_job_done(void)
{
	struct job	*j = job;
	int32_t		 status = -1;

	if (j->fd != -1 || j->pid != 0)
		return;
	evtimer_del(&j->tm);
	job = NULL;
	if (j->killed)
		printf("%% nshd: the %s ran past %d seconds, and is killed\n",
		    jobs[j->kind].what, jobs[j->kind].secs);
	else if (WIFEXITED(j->status) && WEXITSTATUS(j->status) <= 1)
		status = WEXITSTATUS(j->status);
	system_job_end(j, status);
	/* the boot that waited on a rollback */
	if (booting && boot_plan == NULL && job == NULL)
		boot_start();
	if (!booting && job == NULL)
		system_started(0);
	/*
	 * first roll back an unconfirmed commit that is due; once config
	 * is gone, system only finishes what it began
	 */
	if (links[CONFIG].iev != NULL)
		system_confirm(-1, 0, NULL);
	system_drain();
	system_drained();
}

/*
 * j ended, or could not start, as status says: 0, 1 if a line of a
 * script failed or what runs is not what was wanted, or -1. A commit's
 * apply that took ends the commit as BEGIN asked; one that did not is
 * undone in a job of its own. The commit's undo or save ends it too
 */
static void
system_job_end(struct job *j, int32_t status)
{
	struct job	*u;

	if (j->kind == JOB_SAVE && status == 0)
		rollback_keep(SAVED, j->who, j->comment);
	if (j->answer != -1 && j->kind != JOB_PARSE &&
	    logins_answered(j) == -1) {
		/* NSHLOGIN is read again before anything goes on */
		logins_reread(j, status);
		system_job_free(j);
		return;
	}
	if (j->kind == JOB_RECOVER) {
		printed_log();
		system_attempted(status == 0 && !logins_lost);
	} else if (j->kind == JOB_APPLY && begun != NULL && status != 0) {
		/* what was printed goes to config before the undo's */
		system_said(j->id);
		u = system_job_new(j->id, JOB_UNDO);
		system_job(u);
	} else if (j->kind == JOB_APPLY && begun != NULL)
		system_took(j->id);
	else if (j->kind == JOB_UNDO)
		/* with NSHLOGIN unread, what runs is not known */
		system_finish(j->id, status == 0 && !logins_lost ?
		    NSHD_UNDONE : NSHD_LEFT);
	else if (j->kind == JOB_SAVE && begun != NULL)
		system_finish(j->id, system_saved(status == 0) == 0 &&
		    status == 0 ? NSHD_SAVED : NSHD_UNSAVED);
	else if (j->kind == JOB_TEST)
		system_tested(j->id, status);
	else if (j->kind == JOB_PARSE)
		system_parsed(j, status);
	else if (j->kind == JOB_APPLY)
		boot_end(status == 0 && !logins_lost);
	else {
		if (j->kind == JOB_SAVE && system_saved(status == 0) == -1)
			status = -1;
		system_printed(j->id, status);
	}
	system_job_free(j);
}

/* free j, and remove its test's rules */
static void
system_job_free(struct job *j)
{
	int	 i;

	if (j->path[0] != '\0')
		unlink(j->path);
	if (j->dir[0] != '\0')
		rmdir(j->dir);
	if (j->answer != -1)
		close(j->answer);
	for (i = 0; i < NSHD_PARSE_TEXTS; i++)
		free(j->keep[i]);
	free(j->want);
	free(j->back);
	free(j);
}

/*
 * The first bytes of the commit, confirm and boot records an earlier
 * nshd left, and of each configuration kept, which the parser reads in
 * a job, as nshd starts. Requests but a session's permissions and a
 * login wait for it, and so does the boot
 */
static void
records_start(void)
{
	static const char	*paths[] = { COMMIT_RECORD, CONFIRM_RECORD,
				    BOOT_RECORD };
	static const int	 there[] = { NSHD_PARSE_HAS_COMMIT,
				    NSHD_PARSE_HAS_CONFIRM,
				    NSHD_PARSE_HAS_BOOT };
	/* the boot record's whole, and less than the others' heads */
	static const size_t	 most[] = { RECORD_HEAD, RECORD_HEAD, 63 };
	struct job		*j;
	ssize_t			 n;
	size_t			 got;
	int			 fd, i;

	j = system_parse_job(0, NSHD_PARSE_RECORDS);
	for (i = 0; i < 3; i++) {
		if ((fd = open(paths[i], O_RDONLY)) == -1) {
			if (errno != ENOENT)
				errors[i] = errno;
			continue;
		}
		j->parse.flags |= there[i];
		for (got = 0; got < most[i]; got += n)
			if ((n = read(fd, heads[i] + got,
			    most[i] - got)) <= 0) {
				if (n == -1 && errno == EINTR) {
					n = 0;
					continue;
				}
				/* the others' is not a record */
				if (n == -1 && i == 1)
					errors[i] = errno;
				break;
			}
		close(fd);
		system_parse_text(j, i, heads[i], got);
	}
	rollback_slots(slots);
	system_parse_text(j, 3, slots, sizeof(slots));
	/* and NSHLOGIN, whole */
	if ((fd = open(NSHLOGIN, O_RDONLY)) == -1) {
		if (errno != ENOENT)
			logins_error = errno;
	} else {
		if ((j->keep[4] = file_read(fd, NSHD_PART, &got)) == NULL)
			logins_error = errno;
		else {
			j->parse.flags |= NSHD_PARSE_HAS_LOGINS;
			system_parse_text(j, 4, j->keep[4], got);
		}
		close(fd);
	}
	system_parse(j);
}

/* fd's text, at most max bytes, and how long: NULL, errno set, if not */
static char *
file_read(int fd, size_t max, size_t *len)
{
	char	*text;
	ssize_t	 n;
	size_t	 got;

	if ((text = malloc(max + 1)) == NULL)
		fatal(NULL);
	for (got = 0; got <= max; got += n)
		if ((n = read(fd, text + got, max + 1 - got)) <= 0) {
			if (n == -1 && errno == EINTR) {
				n = 0;
				continue;
			}
			if (n == 0)
				break;
			free(text);
			return (NULL);
		}
	if (got > max) {
		free(text);
		errno = EFBIG;
		return (NULL);
	}
	*len = got;
	return (text);
}

/*
 * The parser read the records' head lines, and the configurations', as
 * status says: system keeps what each says, as it does what it writes.
 * Then a commit not confirmed is due
 */
static void
records_read(struct job *j, int32_t status)
{
	struct nshd_records	 r;
	struct rollback_head	 h[ROLLBACKS];
	struct confirm		 cf;
	char			*a = NULL;
	size_t			 len, at = sizeof(r) + sizeof(h);
	int32_t			 n = -1;

	memset(&r, 0, sizeof(r));
	if (status != 0 || parser_answer(j->answer, at + sizeof(n) +
	    LOGIN_LINES * sizeof(struct login_rec), &a, &len) == -1 ||
	    len < at + sizeof(n)) {
		printf("%% nshd: the parser did not read the records\n");
		/* each one there is not read */
		if ((j->parse.flags & NSHD_PARSE_HAS_COMMIT) && !errors[0])
			errors[0] = EIO;
		if ((j->parse.flags & NSHD_PARSE_HAS_CONFIRM) && !errors[1])
			errors[1] = EIO;
		if ((j->parse.flags & NSHD_PARSE_HAS_BOOT) && !errors[2])
			errors[2] = EIO;
		if ((j->parse.flags & NSHD_PARSE_HAS_LOGINS) && !logins_error)
			logins_error = EIO;
	} else {
		memcpy(&r, a, sizeof(r));
		memcpy(h, a + sizeof(r), sizeof(h));
		/* one configuration kept without its head lines is none */
		if (rollback_heads_kept(h) == -1)
			printf("%% nshd: the parser's reading of the "
			    "configurations kept is not one\n");
		memcpy(&n, a + at, sizeof(n));
		at += sizeof(n);
	}
	/* NSHLOGIN's lines, or none, or lines that could not be read */
	if (logins_error != 0)
		n = -1;
	else if (!(j->parse.flags & NSHD_PARSE_HAS_LOGINS))
		n = 0;
	if ((n > 0 && len != at + n * sizeof(struct login_rec)) ||
	    login_kept(n > 0 ? (struct login_rec *)(a + at) : NULL, n) == -1) {
		printf("%% nshd: the parser's reading of %s is not one\n",
		    NSHLOGIN);
		login_kept(NULL, -1);
	}
	free(a);
	printed_log();

	memset(&kept, 0, sizeof(kept));
	kept_error = errors[0];
	if (kept_error == 0 && (j->parse.flags & NSHD_PARSE_HAS_COMMIT)) {
		/* the parts' lengths are checked as they are read */
		if ((r.commit != RECORD_APPLYING &&
		    r.commit != RECORD_UNSAVED) || r.beforelen > NSHD_PART ||
		    r.wantlen > NSHD_PART)
			kept_error = EFTYPE;
		else {
			kept.state = r.commit;
			kept.uid = r.uid;
			kept.when = r.when;
			kept.beforelen = r.beforelen;
			kept.wantlen = r.wantlen;
			kept_head = r.commithead;
		}
	}

	memset(&cf, 0, sizeof(cf));
	if (errors[1] == 0 && (j->parse.flags & NSHD_PARSE_HAS_CONFIRM)) {
		if ((r.confirm != CONFIRM_WAITING &&
		    r.confirm != CONFIRM_FAILED) || r.id == 0 ||
		    r.deadline <= 0 || r.attempts < 0 ||
		    (r.demoted != 0 && r.demoted != 1) ||
		    r.backlen > NSHD_PART)
			errors[1] = EFTYPE;
		else {
			cf.state = r.confirm;
			cf.id = r.id;
			cf.deadline = r.deadline;
			cf.attempts = r.attempts;
			cf.demoted = r.demoted;
			cf.backlen = r.backlen;
		}
	}
	confirm_kept(&cf, r.confirmhead, errors[1]);

	memset(&kept_boot, 0, sizeof(kept_boot));
	kept_boot_error = errors[2];
	if (kept_boot_error == 0 && (j->parse.flags & NSHD_PARSE_HAS_BOOT)) {
		if (r.boot < BOOT_RUNS || r.boot > BOOT_DONE ||
		    (r.bootdemoted != 0 && r.bootdemoted != 1))
			kept_boot_error = EFTYPE;
		else {
			kept_boot.state = r.boot;
			kept_boot.when = r.boottime;
			kept_boot.demoted = r.bootdemoted;
		}
	}
	system_confirm(-1, 0, NULL);
}

/*
 * NSHLOGIN's lines as j, a script's job, left them, which system keeps.
 * -1 if the job ended before it said: it may have changed the file
 */
static int
logins_answered(struct job *j)
{
	char	*a;
	size_t	 len;
	int32_t	 n;

	if (parser_answer(j->answer, sizeof(n) + LOGIN_LINES *
	    sizeof(struct login_rec), &a, &len) == -1 || len == 0) {
		free(a);
		return (-1);
	}
	if (len < sizeof(n))
		n = -2;
	else
		memcpy(&n, a, sizeof(n));
	if ((n > 0 && len != sizeof(n) + n * sizeof(struct login_rec)) ||
	    login_kept((struct login_rec *)(a + sizeof(n)), n) == -1) {
		printf("%% nshd: the lines of %s the job left are not lines\n",
		    NSHLOGIN);
		login_kept(NULL, -1);
	}
	free(a);
	logins_lost = 0;
	return (0);
}

/*
 * j, a script's job, ended as status says and did not say how it left
 * NSHLOGIN. system's lines are not the file's until the parser has read
 * it again, in a job; then j's end goes on (logins_read())
 */
static void
logins_reread(struct job *j, int32_t status)
{
	struct job	*r;
	size_t		 got;
	int		 fd;

	login_kept(NULL, -1);
	logins_lost = 1;
	r = system_parse_job(j->id, NSHD_PARSE_LOGINS);
	r->after = j->kind;
	r->after_status = status;
	if ((fd = open(NSHLOGIN, O_RDONLY)) == -1) {
		/* with no file there are no lines */
		if (errno == ENOENT)
			logins_lost = 0;
	} else {
		if ((r->keep[0] = file_read(fd, NSHD_PART, &got)) != NULL) {
			r->parse.flags |= NSHD_PARSE_HAS_LOGINS;
			system_parse_text(r, 0, r->keep[0], got);
			logins_lost = 0;
		}
		close(fd);
	}
	system_parse(r);
}

/*
 * The parser's reading of NSHLOGIN, j's, after a job that did not say
 * how it left it; that job's end goes on, as one that answered
 */
static void
logins_read(struct job *j, int32_t status)
{
	struct job	*f;
	char		*a = NULL;
	size_t		 len = 0;
	int32_t		 n = -1;

	if (!logins_lost && status == 0 && parser_answer(j->answer,
	    sizeof(n) + LOGIN_LINES * sizeof(struct login_rec), &a,
	    &len) != -1 && len >= sizeof(n))
		memcpy(&n, a, sizeof(n));
	if (n < 0 || (n > 0 && len != sizeof(n) + n *
	    sizeof(struct login_rec)) || login_kept(n > 0 ?
	    (struct login_rec *)(a + sizeof(n)) : NULL, n) == -1) {
		printf("%% nshd: %s could not be read again\n", NSHLOGIN);
		login_kept(NULL, -1);
		logins_lost = 1;
	}
	free(a);
	f = system_job_new(j->id, j->after);
	system_job_end(f, j->after_status);
}

/*
 * The commit record into rec, RECORD_NONE if none, its parts read again:
 * -1, saying why, if not
 */
static int
record_read(struct record *rec)
{
	struct stat	 sb;
	ssize_t		 n;
	size_t		 got, len;
	int		 fd;

	memset(rec, 0, sizeof(*rec));
	if (kept_error == EFTYPE) {
		printf("%% nshd: %s is not a commit record\n", COMMIT_RECORD);
		return (-1);
	}
	if (kept_error != 0) {
		printf("%% nshd: %s: %s\n", COMMIT_RECORD,
		    strerror(kept_error));
		return (-1);
	}
	if (kept.state == RECORD_NONE)
		return (0);
	if ((fd = open(COMMIT_RECORD, O_RDONLY)) == -1 ||
	    fstat(fd, &sb) == -1) {
		printf("%% nshd: %s: %s\n", COMMIT_RECORD, strerror(errno));
		if (fd != -1)
			close(fd);
		return (-1);
	}
	/* the parts after the head line, as system wrote them */
	len = kept.beforelen + kept.wantlen;
	if (sb.st_size != (off_t)(kept_head + len))
		goto bad;
	if ((rec->buf = malloc(len + 1)) == NULL)
		fatal(NULL);
	for (got = 0; got < len; got += n)
		if ((n = pread(fd, rec->buf + got, len - got,
		    kept_head + got)) <= 0) {
			if (n == -1 && errno == EINTR) {
				n = 0;
				continue;
			}
			goto bad;
		}
	close(fd);
	rec->buf[len] = '\0';
	rec->state = kept.state;
	rec->uid = kept.uid;
	rec->when = kept.when;
	rec->beforelen = kept.beforelen;
	rec->wantlen = kept.wantlen;
	rec->before = rec->buf;
	rec->want = rec->before + rec->beforelen;
	return (0);
 bad:
	close(fd);
	printf("%% nshd: %s is not a commit record\n", COMMIT_RECORD);
	record_free(rec);
	return (-1);
}

/* rec as the commit record, whole or not at all: -1, saying why, if not */
static int
record_write(struct record *rec)
{
	char	 tmp[] = COMMIT_RECORD ".XXXXXXXXXX";
	FILE	*f;
	int	 fd, head, r = 0;

	if (mkdir(NSHDB, 0700) == -1 && errno != EEXIST) {
		printf("%% nshd: mkdir %s: %s\n", NSHDB, strerror(errno));
		return (-1);
	}
	if ((fd = mkstemp(tmp)) == -1) {
		printf("%% nshd: %s: %s\n", tmp, strerror(errno));
		return (-1);
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		printf("%% nshd: %s: %s\n", tmp, strerror(errno));
		close(fd);
		unlink(tmp);
		return (-1);
	}
	if ((head = fprintf(f, "%s %u %lld %zu %zu\n", states[rec->state],
	    (unsigned int)rec->uid, (long long)rec->when, rec->beforelen,
	    rec->wantlen)) < 0)
		r = -1;
	if (rec->beforelen > 0)
		fwrite(rec->before, 1, rec->beforelen, f);
	if (rec->wantlen > 0)
		fwrite(rec->want, 1, rec->wantlen, f);
	if (fflush(f) == EOF || fsync(fd) == -1)
		r = -1;
	if (fclose(f) == EOF)
		r = -1;
	if (r == -1 || rename(tmp, COMMIT_RECORD) == -1) {
		printf("%% nshd: %s: %s\n", tmp, strerror(errno));
		unlink(tmp);
		return (-1);
	}
	kept = *rec;
	kept.buf = kept.before = kept.want = NULL;
	kept_head = head;
	kept_error = 0;
	return (db_sync());
}

/* no commit record: -1, saying why, if it could not be removed */
static int
record_clear(void)
{
	int	 r;

	if ((r = unlink(COMMIT_RECORD)) == -1 && errno != ENOENT) {
		printf("%% nshd: %s: %s\n", COMMIT_RECORD, strerror(errno));
		return (-1);
	}
	memset(&kept, 0, sizeof(kept));
	kept_error = 0;
	return (r == -1 ? 0 : db_sync());
}

static void
record_free(struct record *rec)
{
	free(rec->buf);
	rec->buf = NULL;
}

/*
 * The boot record, as b: none if there is none, if it is one of another
 * boot of the host, whose demotion went with it, or if it is not one,
 * saying so; -1, saying why, if it could not be opened
 */
static int
boot_read(struct boot *b)
{
	memset(b, 0, sizeof(*b));
	if (kept_boot_error != 0 && kept_boot_error != EFTYPE) {
		printf("%% nshd: %s: %s\n", BOOT_RECORD,
		    strerror(kept_boot_error));
		return (-1);
	}
	if (kept_boot_error == EFTYPE)
		printf("%% nshd: %s is not a boot record\n", BOOT_RECORD);
	else if (kept_boot.state != BOOT_NONE &&
	    kept_boot.when == boot_time())
		*b = kept_boot;
	return (0);
}

/* b as the boot record, whole or not at all: -1, saying why, if not */
static int
boot_write(struct boot *b)
{
	char	 tmp[] = BOOT_RECORD ".XXXXXXXXXX", rec[64];
	int	 fd, len;

	if (mkdir(NSHDB, 0700) == -1 && errno != EEXIST) {
		printf("%% nshd: mkdir %s: %s\n", NSHDB, strerror(errno));
		return (-1);
	}
	if ((fd = mkstemp(tmp)) == -1) {
		printf("%% nshd: %s: %s\n", tmp, strerror(errno));
		return (-1);
	}
	len = snprintf(rec, sizeof(rec), "%s %lld %d\n",
	    boot_states[b->state], b->when, b->demoted);
	if (write(fd, rec, len) != len || fsync(fd) == -1) {
		printf("%% nshd: %s: %s\n", tmp, strerror(errno));
		close(fd);
		unlink(tmp);
		return (-1);
	}
	if (close(fd) == -1 || rename(tmp, BOOT_RECORD) == -1) {
		printf("%% nshd: %s: %s\n", tmp, strerror(errno));
		unlink(tmp);
		return (-1);
	}
	kept_boot = *b;
	kept_boot_error = 0;
	return (db_sync());
}

/* when the host booted, kern.boottime, which tells its boots apart */
static long long
boot_time(void)
{
	int		 mib[2] = { CTL_KERN, KERN_BOOTTIME };
	struct timeval	 tv;
	size_t		 len = sizeof(tv);

	if (sysctl(mib, 2, &tv, &len, NULL, 0) == -1) {
		printf("%% nshd: kern.boottime: %s\n", strerror(errno));
		return (0);
	}
	return (tv.tv_sec);
}

/* who made rec and when, as "by NAME at WHEN" */
static const char *
record_by(struct record *rec)
{
	static char	 by[sizeof("by  at ") + 128];
	char		 who[64], when[64];

	user_name(rec->uid, who, sizeof(who));
	strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S %Z",
	    localtime(&rec->when));
	snprintf(by, sizeof(by), "by %s at %s", who, when);
	return (by);
}

/* uid's name, or its number */
static void
user_name(uid_t uid, char *buf, size_t len)
{
	struct passwd	*pw;

	if ((pw = getpwuid(uid)) != NULL)
		strlcpy(buf, pw->pw_name, len);
	else
		snprintf(buf, len, "uid %u", (unsigned int)uid);
}

/* sync NSHDB's entries to disk: -1, after saying why, on failure */
static int
db_sync(void)
{
	int	 fd, r;

	if ((fd = open(NSHDB, O_RDONLY | O_DIRECTORY)) == -1) {
		printf("%% nshd: %s: %s\n", NSHDB, strerror(errno));
		return (-1);
	}
	if ((r = fsync(fd)) == -1)
		printf("%% nshd: %s: %s\n", NSHDB, strerror(errno));
	close(fd);
	return (r);
}

/*
 * system ends, and with it what its streams' children, its logins'
 * checks and its job run
 */
static __dead void
system_exit(void)
{
	struct stream	*s;
	struct attempt	*a;

	TAILQ_FOREACH(s, &streams, entry)
		if (s->pid != 0)
			killpg(s->pid, SIGKILL);
	TAILQ_FOREACH(a, &attempts, entry)
		killpg(a->pgid, SIGKILL);
	if (job != NULL && job->pid != 0)
		killpg(job->pgid, SIGKILL);
	exit(0);
}
