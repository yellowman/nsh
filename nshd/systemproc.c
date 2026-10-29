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
 * child; or when system exits. If config sends a request it may not
 * send, or a malformed one, system exits, and so does nshd.
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
 * opened as root and copied as NSHD_CHECK_USER. The program and its
 * arguments come from nsh's table for the show's words; no request
 * names a path.
 *
 * An operation, which a privileged session requests, is given as nsh's
 * words for it. op_allowed() accepts or refuses the words, and prints
 * why it refuses. A stream's child runs the operation as root, in the
 * client's rtable, with nsh's own code, op_run(), and exits with the
 * operation's status.
 *
 * config sends a commit's requests in order. First come the parts that
 * BEGIN, APPLY and TEST use, sent in chunks. BEGIN writes the commit record,
 * APPLY runs the script, and SAVE saves the running configuration and
 * removes the commit record. RECORD reports how the commit ended: rolled
 * back to how it was, an unconfirmed commit kept until its deadline, or
 * a configure terminal commit applied and kept without being saved.
 * BEGIN refuses such a configure terminal commit while an unconfirmed
 * commit exists, because rolling back the unconfirmed commit would roll
 * it back too. TEST, which runs a daemon's test of its rules, comes
 * before BEGIN.
 *
 * An apply, a save and a test each run as a job: a child of system in
 * its own process group, whose output is sent as it arrives. If a job
 * runs past its time limit, its group gets SIGTERM, then SIGKILL after a
 * grace period, and the job fails. A test runs as NSHD_CHECK_USER, with
 * its rules staged in a directory of its own. The daemons listed in
 * root_tests are exceptions: their tests keep root, and their rules are
 * root's. SAVE writes the running configuration to SAVED, whole and on
 * disk, and keeps it as rollback 0, one generation after the previous
 * rollback 0, unless it is the same as that one. While a job runs,
 * config's requests wait for it, except reports that a stream's client
 * read its messages, requests to stop a stream, and requests for a new
 * session's permissions.
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
 * commit. RECORD with NSHD_KEPT leaves that record in place; with
 * NSHD_BACK it restores the record that existed before BEGIN; with
 * NSHD_LEFT the commit ended neither way, and both records stay. A
 * successful SAVE confirms the commit by removing its record.
 *
 * The deadline is the given number of minutes after BEGIN, and is reset
 * to that many minutes after RECORD reports the commit kept. After the
 * deadline, system rolls the commit back, but not while a begun commit
 * has not ended or a job runs, because that commit's undo could restore
 * what the rollback removed. system demotes carp, records the attempt,
 * and starts a JOB_RECOVER job, which makes the running configuration
 * match the rollback configuration; then it promotes carp again. If the
 * job fails, system tries again CONFIRM_RETRY seconds later, up to
 * CONFIRM_ATTEMPTS attempts in all; then the record is marked failed,
 * and carp stays demoted. If the running configuration already matches
 * the rollback configuration, as after a reboot or a commit that never
 * ran, system only removes the record. When system starts, it takes
 * over an unconfirmed commit that a previous system process left, and
 * rolls it back at its deadline. BEGIN is refused if the running
 * configuration is not the one the commit was planned from, as when an
 * unconfirmed commit was rolled back in the meantime.
 *
 * The boot, which config runs when nshd starts with -b, begins with
 * BOOT. The first time, system copies nsh's own NSHRC to the saved
 * configuration. It then writes the boot record, in NSHDB, which names
 * the host boot it is for by kern.boottime and says the boot is
 * running; then it demotes carp and records that too. A system process
 * restarted during the boot finds the record and does not demote carp
 * again. If this host boot is already done, system reports that, and
 * the boot does not run again. config then requests the saved
 * configuration (SAVED) and a snapshot, runs the tests, runs the script
 * (APPLY), and requests another snapshot. Then BOOTED reports whether
 * the running configuration is the saved configuration. If it is, the
 * record says the boot is done, carp is promoted if it was demoted for
 * the boot, and any unconfirmed commit record is removed. If not, the
 * record says the boot failed, and carp stays demoted until a commit
 * saves.
 *
 * Each commit belongs to a session, and system learns whose it is from
 * the session's client. frontend passes system each client's socket when
 * the client connects, and system asks the kernel who is at the other
 * end, and whether that is the web configurator. frontend reports to
 * system, on their pipe, each request that may begin a commit (a line,
 * a commit or part of a load) before config receives it; it also
 * reports when config answers it and when a session is gone. system
 * accepts such a report only while the client is still connected, as
 * the socket shows. BEGIN and TEST, and SAVE outside a commit, name the
 * session, and are refused unless the session has a request not yet
 * answered, or had one when the session went away. BEGIN uses up that
 * request, and the commit record stores its uid. TEST for no session
 * and APPLY outside a commit belong to the boot, and are refused unless
 * the boot is running. BOOT is answered as already done once parent
 * says nshd is not booting, or once BOOTED has been received. So a
 * config process that a client has compromised can begin a commit only
 * for a request that a client made, and cannot choose whose commit it
 * is; and a compromised frontend cannot choose who a client is.
 *
 * system checks the permissions of the login class of that request's
 * uid itself, as config does. An operation, which frontend also
 * reports, needs operate; BEGIN, TEST and SAVE need configure. A commit
 * by a session without admin may not change settings that need admin:
 * system keeps the running configuration when BEGIN accepts the commit,
 * and the commit's script checks its changes against it (ctl.c's
 * admin_begin()). Login classes and users, root's crontab, and the
 * rules of inetd, ifstated and sshd need admin. So does a line in
 * smtpd's rules with mda, proc, a pipe, a table or a macro; in snmpd's
 * with a trap handle or a macro; in pf's with file or load; and in any
 * daemon's with include. Each of these runs a command as root, reads a
 * file as root, or decides who may log in. A TEST for such a session is
 * refused those lines too, judged against the running configuration.
 *
 * A web configurator session has no permissions until it logs in, and
 * only such a session may log in. system checks the user's password
 * itself (passwd.c's login_auth()), for a user that a login user line
 * names, never root. It keeps the uid the session logged in as until
 * frontend reports that the session is gone. The session then has the
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
#include "kfacts.h"
#include "showfacts.h"
#include "answer.h"

#define SYS_PATH	"/sbin:/bin:/usr/sbin:/usr/bin"	/* rc's */
#define SYS_BATCH	256	/* records made before what is printed is sent */
#define SYS_STREAMS	16	/* streams at once, at most */
#define SYS_WINDOW	16	/* messages a stream sends its client unread */
#define SYS_OPWORDS	32	/* an operation's words, at most */
#define SYS_TERMINALS	64	/* web logins' terminals at once, at most */
/* descriptors kept free of clients' sockets: streams, commits, files */
#define SYS_RESERVE	(SYS_STREAMS + 16)

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
 * A job: an apply, a save, a test or a recover, and how long it may run,
 * then the grace between SIGTERM and SIGKILL. These are not measured;
 * each should be measured on OpenBSD with a full table
 */
#define JOB_APPLY	0
#define JOB_SAVE	1
#define JOB_TEST	2
#define JOB_RECOVER	3
static const struct {
	const char	*what;
	int		 secs;
	int		 grace;
} jobs[] = {
	{ "apply",	900,	10 },	/* a script that starts every daemon */
	{ "save",	300,	10 },	/* conf(), and the save script */
	{ "test",	120,	5 },	/* a validation: bgpd -n on a full table */
	{ "recover",	900,	10 },	/* rollback of an unconfirmed commit */
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
	OSPFCTL, RELAYCTL, RIPCTL, SMTPCTL, PFCTL, IPSECCTL,
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
struct job {
	uint32_t		 id;		/* the request */
	int			 kind;
	pid_t			 pid;		/* the child, or 0 if reaped */
	pid_t			 pgid;
	int			 status;	/* how it ended, once reaped */
	int			 fd;		/* its output, or -1 at its end */
	int			 killed;	/* the signal its group got last */
	struct event		 ev, tm;
	struct nshd_apply	*apply;
	char			*back;		/* rollback configuration */
	size_t			 backlen;
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
static const char *states[] = { "none", "applying", "unsaved" };
struct record {
	int			 state;
	uid_t			 uid;
	time_t			 when;
	char			*before, *want;
	size_t			 beforelen, wantlen;
	char			*buf;		/* what was read, or NULL */
};

/*
 * What frontend told system: a session's request, not yet answered,
 * with who the session's client is. Once the session is gone, it is
 * kept for a commit it asked, ASKED_GONE of them at most
 */
struct asked {
	TAILQ_ENTRY(asked)	 entry;
	uint32_t		 session;
	uid_t			 uid;
	int			 web;
	int			 gone;
};
#define ASKED_GONE	64

/*
 * A session's client, as system reads it from the client's socket, which
 * frontend passes it: the uid the kernel says it is, if it is the web
 * configurator's, and the socket, kept to see whether it is still there
 */
struct client {
	TAILQ_ENTRY(client)	 entry;
	uint32_t		 session;
	uid_t			 uid;
	int			 web;
	int			 fd;
};

/* a session of the web configurator's, and the uid it logged in as */
struct login {
	TAILQ_ENTRY(login)	 entry;
	uint32_t		 session;
	uid_t			 uid;
};

/* the boot record: the boot of the host it is for, how it went, carp */
enum { BOOT_NONE, BOOT_RUNS, BOOT_FAILED, BOOT_DONE };
static const char *boot_states[] = { "none", "runs", "failed", "done" };
struct boot {
	int			 state;
	long long		 when;		/* kern.boottime */
	int			 demoted;	/* carp demoted, for it */
};

static struct imsgev	*iev_parent;
static uint8_t		 units[FACTS_UNIT];	/* not yet sent */
static size_t		 nunits;
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
/* a commit confirmed begun: the unconfirmed commit record before it */
static struct confirm	 confirm_prev;
static int		 confirm_begun;
static int		 confirm_minutes;
static int		 committing;	/* a commit is begun and not ended */
static uid_t		 commit_uid;	/* its uid */
static int		 commit_web;	/* it is the web configurator's */
static int		 commit_admin;	/* its login class has admin */
static char		*commit_before;	/* if not, what ran before it */
static size_t		 commit_beforelen;
static int		 booting;	/* from BOOT until BOOTED */
static int		 boot_over;	/* not booting, or BOOTED came */
static TAILQ_HEAD(, asked) askeds = TAILQ_HEAD_INITIALIZER(askeds);
static TAILQ_HEAD(, login) logins = TAILQ_HEAD_INITIALIZER(logins);
static TAILQ_HEAD(, client) clients = TAILQ_HEAD_INITIALIZER(clients);
static int		 nagone;	/* askeds of sessions that are gone */
static struct event	 confirm_tm;	/* the deadline, or the next attempt */
static time_t		 confirm_next;	/* earliest next rollback attempt */

static void	system_dispatch_parent(int, short, void *);
static void	system_dispatch_config(int, short, void *);
static void	system_dispatch_frontend(int, short, void *);
static struct asked *asked_find(uint32_t);
static struct asked *asked_whose(struct nshd_whose *);
static void	asked_free(struct asked *);
static void	asked_trim(void);
static void	client_new(uint32_t, int);
static struct client *client_find(uint32_t);
static int	client_there(struct client *);
static struct login *login_find(uint32_t);
static int	system_whom(struct asked *, uid_t *);
static void	system_login(uint32_t, struct nshd_syslogin *);
static void	system_terminal(uint32_t, struct nshd_systerm *);
static __dead void system_term_child(int, struct passwd *);
static int	system_whole(uint32_t, const void *, size_t);
static int	system_request(uint32_t, uint32_t, const void *, size_t);
static void	system_queue(uint32_t, uint32_t, const void *, size_t);
static void	system_drain(void);
static void	system_snapshot(uint32_t, int);
static void	system_show(uint32_t, char *);
static void	system_op(uint32_t, struct nshd_sysop *);
static int	system_may(int, int, const char *);
static void	system_end(uint32_t, int32_t, const char *, ...)
		    __attribute__((__format__ (printf, 3, 4)));
static void	system_emit(void *, const void *, size_t);
static void	system_flush(uint32_t);
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
static void	system_parts_free(void);
static void	system_begin(uint32_t, struct nshd_begin *);
static void	system_apply(uint32_t, struct nshd_apply *);
static void	system_save(uint32_t, struct nshd_save *);
static int	system_saved(int);
static void	system_ended(void);
static int	system_unconfirm(void);
static void	system_back(uint32_t, int);
static void	system_boot(uint32_t);
static void	system_booted(uint32_t, int);
static void	boot_saved(void);
static int	boot_read(struct boot *);
static int	boot_write(struct boot *);
static long long boot_time(void);
static int	system_arm(int);
static void	system_unarm(void);
static void	system_kept(void);
static void	system_confirm(int, short, void *);
static void	system_recover(struct confirm *);
static void	system_attempted(int);
static void	system_taken(struct confirm *, const char *);
static void	system_failed(struct confirm *);
static void	system_went(int);
static char	*system_running(size_t *);
static void	system_rollback(uint32_t, int, int);
static void	system_health(void);
static void	system_test(uint32_t, struct nshd_whose *, char *);
static int	system_admin_test(char *);
static void	system_printed(uint32_t, int32_t);
static struct job *system_job_new(uint32_t, int);
static void	system_job(struct job *);
static __dead void system_job_child(int, struct job *);
static void	system_job_free(struct job *);
static void	system_job_read(int, short, void *);
static void	system_job_late(int, short, void *);
static void	system_job_done(void);
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
#define FRONTEND	1
	{ PROC_FRONTEND, system_dispatch_frontend },
};

void
systemproc(int debug, int v)
{
	extern char		**environ;
	static char		*empty[] = { NULL };
	static struct event	 ev_sigchld;
	struct passwd		*pw;

	child_start("system", debug, v);
	if (setsid() == -1)
		fatal("setsid");
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

	/* nsh's code runs here privileged, as it does for root */
	priv = 1;
	facts_from = FACTS_SYSTEM;
	db_create();

	if ((iev_parent = imsgev_new(3, system_dispatch_parent, 0)) == NULL)
		fatal(NULL);
	evtimer_set(&confirm_tm, system_confirm, NULL);
	links_init(links, sizeof(links) / sizeof(links[0]));
	/* terminal ptys go to config; clients' sockets come from frontend */
	imsgbuf_allow_fdpass(&links[CONFIG].iev->ibuf);
	imsgbuf_allow_fdpass(&links[FRONTEND].iev->ibuf);
	/* before any child: one that ends unwatched is never reaped */
	signal_set(&ev_sigchld, SIGCHLD, system_sigchld, NULL);
	signal_add(&ev_sigchld, NULL);
	/* an unconfirmed commit that an earlier nshd left */
	system_confirm(-1, 0, NULL);
	event_dispatch();
	system_exit();
}

/* parent's word that system may start, and whether nshd boots */
static void
system_dispatch_parent(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_startup	 st;
	int			 n;

	if (imsgev_io(iev, event) == -1)
		system_exit();

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		if (imsg_get_type(&imsg) != IMSG_STARTUP ||
		    imsg_get_data(&imsg, &st, sizeof(st)) == -1) {
			log_warnx("parent sent imsg %u, which it may not",
			    imsg_get_type(&imsg));
			system_exit();
		}
		boot_over = !st.boot;
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
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
		link_broken(&links[CONFIG], "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			link_broken(&links[CONFIG], "sent what imsg cannot read");
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
			link_broken(&links[CONFIG], "sent imsg %u, which it may not, "
			    "or not whole", type);
			return;
		}
		/*
		 * what a stream's client read, stopping a stream, and a new
		 * session's permissions do not wait
		 */
		if (type == IMSG_SYS_READ || type == IMSG_SYS_STOP ||
		    type == IMSG_SYS_PERMS ||
		    (job == NULL && TAILQ_EMPTY(&queue)))
			r = system_request(type, id, data, len);
		else
			system_queue(type, id, data, len);
		imsg_free(&imsg);
		if (r == -1) {
			link_broken(&links[CONFIG], "sent a part past %d bytes",
			    NSHD_PART);
			return;
		}
	}
	imsg_event_add(iev);
}

/*
 * frontend's word of the requests sessions make, and each client's
 * socket
 */
static void
system_dispatch_frontend(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_asked	 a;
	struct asked		*k;
	struct client		*cl;
	struct login		*l;
	uint32_t		 type;
	int			 n;

	if (imsgev_io(iev, event) == -1) {
		link_broken(&links[FRONTEND], "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			link_broken(&links[FRONTEND],
			    "sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		type = imsg_get_type(&imsg);
		if ((type != IMSG_FRONT_SESSION && type != IMSG_FRONT_ASKED &&
		    type != IMSG_FRONT_ANSWERED && type != IMSG_FRONT_GONE) ||
		    imsg_get_data(&imsg, &a, sizeof(a)) == -1) {
			imsg_free(&imsg);
			link_broken(&links[FRONTEND], "sent imsg %u, which it "
			    "may not, or not whole", type);
			return;
		}
		if (type == IMSG_FRONT_SESSION)
			client_new(a.session, imsg_get_fd(&imsg));
		imsg_free(&imsg);
		k = asked_find(a.session);
		cl = client_find(a.session);
		if (type == IMSG_FRONT_ASKED) {
			if (k != NULL)
				asked_free(k);
			/* a request of a client gone, or not known, is refused */
			if (cl == NULL || !client_there(cl))
				continue;
			if ((k = calloc(1, sizeof(*k))) == NULL)
				fatal(NULL);
			k->session = a.session;
			k->uid = cl->uid;
			k->web = cl->web;
			TAILQ_INSERT_TAIL(&askeds, k, entry);
		} else if (k != NULL && type == IMSG_FRONT_ANSWERED)
			asked_free(k);
		else if (type == IMSG_FRONT_GONE) {
			if (cl != NULL) {
				TAILQ_REMOVE(&clients, cl, entry);
				close(cl->fd);
				free(cl);
			}
			if ((l = login_find(a.session)) != NULL) {
				TAILQ_REMOVE(&logins, l, entry);
				free(l);
			}
			if (k != NULL && !k->gone) {
				k->gone = 1;
				nagone++;
				asked_trim();
			}
		}
	}
	imsg_event_add(iev);
}

static struct asked *
asked_find(uint32_t session)
{
	struct asked	*k;

	TAILQ_FOREACH(k, &askeds, entry)
		if (k->session == session)
			return (k);
	return (NULL);
}

/*
 * The request of the session w names, which frontend told system of
 * before config heard of it, or NULL. What frontend sent is read first,
 * as system may not have read it yet
 */
static struct asked *
asked_whose(struct nshd_whose *w)
{
	struct pollfd	 pfd;

	if (w->session == 0)
		return (NULL);
	pfd.fd = links[FRONTEND].iev->ibuf.fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 0) == 1)
		system_dispatch_frontend(pfd.fd, EV_READ, links[FRONTEND].iev);
	return (asked_find(w->session));
}

static void
asked_free(struct asked *k)
{
	if (k->gone)
		nagone--;
	TAILQ_REMOVE(&askeds, k, entry);
	free(k);
}

/*
 * Record a session's client from its socket, fd, with the uid
 * getpeereid() reports. The session gets no client, and its requests are
 * refused, if fd is -1 because system had no descriptor free for it, if
 * keeping fd would leave fewer than SYS_RESERVE descriptors free, or if
 * fd is not a client's socket.
 */
static void
client_new(uint32_t session, int fd)
{
	struct client	*cl;
	gid_t		 gid;

	if (client_find(session) != NULL)
		link_broken(&links[FRONTEND], "passed session %u's client "
		    "twice", session);
	if (fd == -1) {
		log_warnx("%s: session %u: no socket", __func__, session);
		return;
	}
	if (getdtablesize() - getdtablecount() < SYS_RESERVE) {
		log_warnx("%s: session %u: too many clients", __func__,
		    session);
		close(fd);
		return;
	}
	if ((cl = calloc(1, sizeof(*cl))) == NULL)
		fatal(NULL);
	if (getpeereid(fd, &cl->uid, &gid) == -1) {
		log_warn("%s: session %u: getpeereid", __func__, session);
		close(fd);
		free(cl);
		return;
	}
	cl->session = session;
	cl->web = web_user && cl->uid == web_uid;
	cl->fd = fd;
	TAILQ_INSERT_TAIL(&clients, cl, entry);
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

/* the login of a web configurator session, or NULL */
static struct login *
login_find(uint32_t session)
{
	struct login	*l;

	TAILQ_FOREACH(l, &logins, entry)
		if (l->session == session)
			return (l);
	return (NULL);
}

/*
 * The login class permissions of k's request, and its uid in *uid if
 * uid is not NULL. A session of the web configurator's has those of the
 * user it logged in as, or none before
 */
static int
system_whom(struct asked *k, uid_t *uid)
{
	struct login	*l;

	if (uid != NULL)
		*uid = k->uid;
	if (!k->web)
		return (login_perms(k->uid));
	if ((l = login_find(k->session)) == NULL)
		return (0);
	if (uid != NULL)
		*uid = l->uid;
	return (login_perms(l->uid));
}

/* forget the oldest requests of sessions gone, past ASKED_GONE */
static void
asked_trim(void)
{
	struct asked	*k, *next;

	TAILQ_FOREACH_SAFE(k, &askeds, entry, next) {
		if (nagone <= ASKED_GONE)
			break;
		if (k->gone)
			asked_free(k);
	}
}

/* Is a request one config may send, and whole? 0 if so, else -1 */
static int
system_whole(uint32_t type, const void *data, size_t len)
{
	struct nshd_begin	 bg;
	struct nshd_record	 rc;
	struct nshd_show	 show;
	struct nshd_chunk	 c;
	struct nshd_apply	 a;
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
		return (0);
	case IMSG_SYS_OP:
		if (len != sizeof(so))
			return (-1);
		memcpy(&so, data, len);
		return (memchr(so.op.line, '\0', sizeof(so.op.line)) == NULL ?
		    -1 : 0);
	case IMSG_SYS_ROLLBACK_LIST:
	case IMSG_SYS_SAVED:
	case IMSG_SYS_BOOT:
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
	case IMSG_SYS_BOOTED:
		return (len == sizeof(struct nshd_result) ? 0 : -1);
	case IMSG_SYS_RECORD:
		if (len != sizeof(rc))
			return (-1);
		memcpy(&rc, data, len);
		return (rc.how != NSHD_BACK && rc.how != NSHD_KEPT &&
		    rc.how != NSHD_LEFT && rc.how != NSHD_APPLIED ? -1 : 0);
	case IMSG_SYS_SNAPSHOT:
		return (len == sizeof(struct nshd_snapshot) ? 0 : -1);
	case IMSG_SYS_BEGIN:
		if (len != sizeof(bg))
			return (-1);
		memcpy(&bg, data, len);
		return (bg.minutes < 0 || bg.minutes > NSHD_CONFIRMMAX ||
		    (bg.unsaved != 0 && (bg.unsaved != 1 || bg.minutes != 0)) ?
		    -1 : 0);
	case IMSG_SYS_SHOW:
		if (len != sizeof(show))
			return (-1);
		memcpy(&show, data, len);
		return (memchr(show.words, '\0', sizeof(show.words)) ==
		    NULL ? -1 : 0);
	case IMSG_SYS_SCRIPT:
		if (len < sizeof(c) || len - sizeof(c) > NSHD_TEXT)
			return (-1);
		memcpy(&c, data, sizeof(c));
		return (c.part < 0 || c.part >= NSHD_PARTS ? -1 : 0);
	case IMSG_SYS_APPLY:
		if (len != sizeof(a))
			return (-1);
		memcpy(&a, data, len);
		if (a.nclears < 0 || a.nclears > NSHD_CLEARS)
			return (-1);
		for (i = 0; i < a.nclears; i++)
			if (memchr(a.clears[i].name, '\0',
			    sizeof(a.clears[i].name)) == NULL)
				return (-1);
		return (0);
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
	struct nshd_show	 show;
	struct nshd_begin	 bg;
	struct nshd_record	 rc;
	struct nshd_apply	 a;
	struct nshd_save	 sv;
	struct nshd_rollback	 rb;
	struct nshd_test	 t;
	struct nshd_result	 res;
	struct nshd_sysop	 so;
	struct nshd_follow	 f;
	struct nshd_systerm	 st;
	struct stream		*s;

	switch (type) {
	case IMSG_SYS_SNAPSHOT:
		memcpy(&snap, data, sizeof(snap));
		system_snapshot(id, snap.facts);
		break;
	case IMSG_SYS_SHOW:
		memcpy(&show, data, sizeof(show));
		system_show(id, show.words);
		break;
	case IMSG_SYS_READ:
		system_stream_more(id);
		break;
	case IMSG_SYS_STOP:
		TAILQ_FOREACH(s, &streams, entry)
			if (s->id == id) {
				system_stream_stop(s);
				break;
			}
		break;
	case IMSG_SYS_SCRIPT:
		return (system_chunk(data, len));
	case IMSG_SYS_BEGIN:
		memcpy(&bg, data, sizeof(bg));
		system_begin(id, &bg);
		break;
	case IMSG_SYS_APPLY:
		memcpy(&a, data, sizeof(a));
		system_apply(id, &a);
		break;
	case IMSG_SYS_SAVE:
		memcpy(&sv, data, sizeof(sv));
		system_save(id, &sv);
		break;
	case IMSG_SYS_RECORD:
		memcpy(&rc, data, sizeof(rc));
		system_back(id, rc.how);
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
	case IMSG_SYS_BOOT:
		system_boot(id);
		break;
	case IMSG_SYS_BOOTED:
		memcpy(&res, data, sizeof(res));
		system_booted(id, res.status == 0);
		break;
	case IMSG_SYS_PERMS:
		memcpy(&pm, data, sizeof(pm));
		/* the web configurator has none until it logs in */
		system_end(id, pm.web ? 0 : login_perms(pm.uid), NULL);
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
			link_broken(&links[CONFIG], "sent a part past %d bytes",
			    NSHD_PART);
			return;
		}
	}
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
			facts_out_init(&o, system_emit, &id);
			if (kfacts_emit(&o, k) == -1)
				r.status = -1;
			system_flush(id);
			kfacts_free(k);
		}
	}
	if (link_compose(&links[CONFIG], IMSG_SYS_END, id, &r, sizeof(r)) == -1)
		fatal("%s", __func__);
}

/* all the facts words ask for, then how it went; or a stream */
static void
system_show(uint32_t id, char *words)
{
	struct collection	*a;
	struct facts_out	 o;
	char			**argv;
	int			 more = 1, op, table;

	printed(NULL);
	if ((a = facts_answer_begin(words)) == NULL) {
		system_end(id, NSHD_ELSEWHERE,
		    "%% show %s: not answered by nshd\n", words);
		return;
	}
	facts_out_init(&o, system_emit, &id);
	if ((op = facts_streams(a, &argv, &table)) != 0) {
		/* -1: words cannot fill the program's arguments; send why */
		if (op == -1) {
			printed(&o);
			system_flush(id);
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
	system_flush(id);
	system_end(id, more != 0, NULL);
}

/*
 * An operation, run by a stream's child if op_allowed() takes its words,
 * or refused, saying why
 */
static void
system_op(uint32_t id, struct nshd_sysop *so)
{
	struct asked	*k;
	char		*argv[SYS_OPWORDS + 1], *p = so->op.line;
	int		 argc = 0, perms;

	printed(NULL);
	if ((k = asked_whose(&so->whose)) == NULL) {
		system_end(id, 1, "%% nshd: frontend told system of no request "
		    "this operation is for\n");
		return;
	}
	perms = system_whom(k, NULL);
	asked_free(k);
	if (!system_may(perms, LOGIN_OPERATE, "operate")) {
		system_printed(id, 1);
		return;
	}
	while (argc < SYS_OPWORDS &&
	    (argv[argc] = strsep(&p, " \t")) != NULL)
		if (*argv[argc] != '\0')
			argc++;
	if (p != NULL) {
		system_end(id, 1, "%% nshd: an operation of more than %d "
		    "words\n", SYS_OPWORDS);
		return;
	}
	argv[argc] = NULL;
	if (argc == 0 || !op_allowed(argc, argv)) {
		system_printed(id, 1);
		return;
	}
	system_stream(id, (perms & LOGIN_ADMIN) != 0 ? SYS_OPERATION :
	    SYS_OPERATION_HIDDEN, argv, so->op.rtable);
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
	struct asked	*k;
	size_t		 i;
	int		 perms, r;

	printed(NULL);
	if ((k = asked_whose(&f->whose)) == NULL) {
		system_end(id, 1, "%% nshd: frontend told system of no request "
		    "this log is for\n");
		return;
	}
	/* the request is kept: a watch may follow several logs */
	perms = system_whom(k, NULL);
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
 * The web configurator's session logs in as a user a login user line
 * names, never root, if the password is the user's (login_auth()); the
 * session then acts as that user, and config takes the user's uid as the
 * session's. The answer is the permissions of the user's login class,
 * or -1, saying why
 */
static void
system_login(uint32_t id, struct nshd_syslogin *sl)
{
	struct nshd_logged	 lg;
	struct asked		*k;
	struct login		*l;
	int			 uid;

	printed(NULL);
	if ((k = asked_whose(&sl->whose)) == NULL || !k->web) {
		system_end(id, -1, "%% nshd: only the web configurator logs "
		    "in\n");
		return;
	}
	asked_free(k);
	if ((uid = login_auth(sl->login.name, sl->login.password)) == -1) {
		system_printed(id, -1);
		return;
	}
	if ((l = login_find(sl->whose.session)) == NULL) {
		if ((l = calloc(1, sizeof(*l))) == NULL)
			fatal(NULL);
		l->session = sl->whose.session;
		TAILQ_INSERT_TAIL(&logins, l, entry);
	}
	l->uid = uid;
	lg.uid = uid;
	if (link_compose(&links[CONFIG], IMSG_SYS_LOGGED, id, &lg,
	    sizeof(lg)) == -1)
		fatal("%s", __func__);
	system_end(id, login_perms(uid), NULL);
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
	struct asked	*k;
	struct login	*l;
	pid_t		 nsh;
	int		 i, pty, tty;

	if ((k = asked_whose(&st->whose)) == NULL || !k->web) {
		system_end(id, -1, "%% nshd: only a web login has a "
		    "terminal\n");
		return;
	}
	asked_free(k);
	if ((l = login_find(st->whose.session)) == NULL) {
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
	if ((pw = getpwuid(l->uid)) == NULL) {
		system_end(id, -1, "%% nshd: no user %u\n", l->uid);
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
	if ((nsh = fork()) == -1) {
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
	if (link_compose(&links[CONFIG], IMSG_SYS_END, id, &r, sizeof(r)) == -1)
		fatal("%s", __func__);
}

/* a unit of facts, for request *arg, kept until a message is full */
static void
system_emit(void *arg, const void *buf, size_t len)
{
	uint32_t	*id = arg;

	if (nunits + len > sizeof(units))
		system_flush(*id);
	memcpy(units + nunits, buf, len);
	nunits += len;
}

/* the units kept, to config, as one message */
static void
system_flush(uint32_t id)
{
	if (nunits == 0)
		return;
	if (link_compose(&links[CONFIG], IMSG_SYS_FACTS, id, units, nunits) == -1)
		fatal("%s", __func__);
	nunits = 0;
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
	facts_out_init(&s->o, system_emit, &s->id);
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
	switch (s->pid = fork()) {
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
	int	 null, argc, r, lfd, tries;

	setpgid(0, 0);
	/* restore the default signal handling, which a program expects */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
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
		for (argc = 0; argv[argc] != NULL; argc++)
			;
		r = op_run(argc, argv, op == SYS_OPERATION_HIDDEN);
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
	if (n > 0 && s->text) {
		if (imsg_text(links[CONFIG].iev, IMSG_SYS_TEXT, s->id, buf,
		    n) == -1)
			fatal("%s", __func__);
	} else if (n > 0 && facts_text(&s->o, buf, n) == -1) {
		log_warnx("%s: a message of %zd bytes", __func__, n);
		n = -1;
	}
	system_flush(s->id);
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

/* reap the exited children of streams, the job and terminals; no others */
static void
system_sigchld(int sig, short event, void *arg)
{
	struct stream	*s, *next;
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
system_parts_free(void)
{
	int	 i;

	for (i = 0; i < NSHD_PARTS; i++) {
		free(parts[i]);
		parts[i] = NULL;
		partlen[i] = 0;
	}
}

/*
 * A commit begins, from the running configuration to the wanted one in
 * the parts sent: the record is made, unless one that a commit left
 * refuses it
 */
static void
system_begin(uint32_t id, struct nshd_begin *bg)
{
	struct record	 rec, now;
	struct confirm	 cf;
	struct asked	*k;
	char		*runs;
	size_t		 len;
	int		 r, perms, wrote = 0, status = 1;

	memset(&rec, 0, sizeof(rec));
	if ((k = asked_whose(&bg->whose)) == NULL) {
		printf("%% Commit refused: frontend told system of no request "
		    "it is for\n");
		goto done;
	}
	perms = system_whom(k, &commit_uid);
	commit_web = k->web;
	asked_free(k);
	if (!system_may(perms, LOGIN_CONFIGURE, "configure"))
		goto done;
	commit_admin = (perms & LOGIN_ADMIN) != 0;
	if (record_read(&rec) == -1)
		goto done;
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
	r = commit_reads(runs, len, parts[NSHD_BEFORE], partlen[NSHD_BEFORE]);
	/* without admin, keep the running configuration for the script */
	free(commit_before);
	commit_before = NULL;
	if (r == 1 && !commit_admin) {
		commit_before = runs;
		commit_beforelen = len;
	} else
		free(runs);
	if (r == -1)
		goto done;
	if (r == 0) {
		printf("%% Commit refused: what runs changed after the commit "
		    "was planned. Commit again\n");
		goto done;
	}
	if (rec.state == RECORD_APPLYING) {
		/* report what it left, judged by the running configuration */
		if ((r = commit_reads(parts[NSHD_BEFORE],
		    partlen[NSHD_BEFORE], rec.before, rec.beforelen)) == -1)
			goto done;
		if (r) {
			printf("%% The commit %s did not finish, and changed "
			    "nothing\n", record_by(&rec));
		} else {
			if ((r = commit_reads(parts[NSHD_BEFORE],
			    partlen[NSHD_BEFORE], rec.want, rec.wantlen)) == -1)
				goto done;
			printf("%% The commit %s did not finish: what runs is "
			    "%s, and is not saved\n", record_by(&rec), r ?
			    "what it wanted" : "neither what it wanted nor "
			    "what was");
			rec.state = RECORD_UNSAVED;
			if (record_write(&rec) == -1)
				goto done;
		}
	}
	if (rec.state == RECORD_UNSAVED) {
		/* allowed only if it rolls back to before that commit */
		if ((r = commit_reads(rec.before, rec.beforelen,
		    parts[NSHD_WANT], partlen[NSHD_WANT])) == -1)
			goto done;
		if (!r) {
			printf("%% Commit refused: what the commit %s changed is "
			    "not saved. Commit with no changes to save it, or "
			    "commit the configuration before it\n",
			    record_by(&rec));
			goto done;
		}
	} else {
		now.state = RECORD_APPLYING;
		now.uid = commit_uid;
		now.when = time(NULL);
		now.before = parts[NSHD_BEFORE];
		now.beforelen = partlen[NSHD_BEFORE];
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
	committing = 1;
	status = 0;
 done:
	record_free(&rec);
	system_parts_free();
	system_printed(id, status);
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

	confirm_free(&confirm_prev);
	confirm_begun = 0;
	if (confirm_read(&confirm_prev, 1) == -1) {
		printf("%% nshd: the record of a commit not confirmed: %s\n",
		    strerror(errno));
		return (-1);
	}
	cf = confirm_prev;
	if (cf.state != CONFIRM_WAITING) {
		cf.back = parts[NSHD_BEFORE];
		cf.backlen = partlen[NSHD_BEFORE];
	}
	cf.state = CONFIRM_WAITING;
	cf.attempts = 0;
	do
		arc4random_buf(&cf.id, sizeof(cf.id));
	while (cf.id == 0);
	cf.deadline = time(NULL) + minutes * 60;
	confirm_minutes = minutes;
	if (confirm_write(&cf) == -1) {
		printf("%% nshd: the record of a commit not confirmed: %s\n",
		    strerror(errno));
		confirm_free(&confirm_prev);
		return (-1);
	}
	confirm_begun = 1;
	return (0);
}

/* put back the unconfirmed commit record as it was before BEGIN */
static void
system_unarm(void)
{
	if ((confirm_prev.state == CONFIRM_NONE ? confirm_clear() :
	    confirm_write(&confirm_prev)) == -1)
		printf("%% nshd: the record of a commit not confirmed: %s\n",
		    strerror(errno));
	confirm_free(&confirm_prev);
	confirm_begun = 0;
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
	cf.deadline = time(NULL) + confirm_minutes * 60;
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
		if (serrno != EFTYPE) {
			tv.tv_sec = CONFIRM_RETRY;
			evtimer_add(&confirm_tm, &tv);
		}
		return;
	}
	unread = 0;
	due = cf.deadline > confirm_next ? cf.deadline : confirm_next;
	if (cf.state == CONFIRM_WAITING && now < due) {
		tv.tv_sec = due - now;
		evtimer_add(&confirm_tm, &tv);
	} else if (cf.state == CONFIRM_WAITING && !committing && job == NULL)
		system_recover(&cf);
	confirm_free(&cf);
}

/*
 * Roll back the commit cf describes. If the running configuration
 * already matches cf's rollback configuration, as when the previous
 * system process stopped after its last attempt succeeded, only clear
 * the record. If every attempt is used, mark the rollback failed.
 * Otherwise demote carp unless that was done already, record the
 * attempt, and start a job that applies the rollback configuration.
 */
static void
system_recover(struct confirm *cf)
{
	struct job	*j;
	char		*runs;
	size_t		 len;
	int		 r = -1;

	if ((runs = system_running(&len)) != NULL)
		r = commit_reads(runs, len, cf->back, cf->backlen);
	free(runs);
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
	j = system_job_new(0, JOB_RECOVER);
	j->back = cf->back;
	j->backlen = cf->backlen;
	system_job(j);
}

/*
 * An attempt to roll back the unconfirmed commit ended. If it succeeded,
 * remove the record. If not, try again CONFIRM_RETRY seconds later, or
 * mark the record failed if no attempts are left.
 */
static void
system_attempted(int ok)
{
	struct confirm	 cf;

	if (confirm_read(&cf, 1) == -1) {
		logit(LOG_CRIT, "the record of a commit not confirmed: %s",
		    strerror(errno));
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
		confirm_next = time(NULL) + CONFIRM_RETRY;
	} else
		system_failed(&cf);
	confirm_free(&cf);
}

/* cf was rolled back, as how says: remove its record and carp demotion */
static void
system_taken(struct confirm *cf, const char *how)
{
	if (confirm_clear() == -1) {
		logit(LOG_CRIT, "the record of a commit not confirmed: %s",
		    strerror(errno));
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
	if (links[CONFIG].iev != NULL && link_compose(&links[CONFIG],
	    IMSG_SYS_NOTICE, 0, &nt, sizeof(nt)) == -1)
		fatal("%s", __func__);
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

/* the script, the part sent, in a job */
static void
system_apply(uint32_t id, struct nshd_apply *a)
{
	struct job	*j;

	if (!committing && !booting) {
		printf("%% nshd: no commit is begun\n");
		system_printed(id, 1);
		system_parts_free();
		return;
	}
	j = system_job_new(id, JOB_APPLY);
	j->apply = a;
	system_job(j);
	system_parts_free();
}

/* the running configuration, saved by uid with a comment, in a job */
static void
system_save(uint32_t id, struct nshd_save *sv)
{
	struct asked	*k;
	struct job	*j;
	uid_t		 uid;
	int		 perms;

	/* the commit's uid, or for a commit with no changes, the request's */
	if (committing)
		uid = commit_uid;
	else if ((k = asked_whose(&sv->whose)) == NULL) {
		printf("%% Commit refused: frontend told system of no request "
		    "it is for\n");
		system_printed(id, 1);
		return;
	} else {
		perms = system_whom(k, &uid);
		asked_free(k);
		if (!system_may(perms, LOGIN_CONFIGURE, "configure")) {
			system_printed(id, 1);
			return;
		}
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
 * of their own, in a job
 */
static void
system_test(uint32_t id, struct nshd_whose *whose, char *name)
{
	struct asked	*k = NULL;
	struct job	*j;
	size_t		 i;
	int		 fd, perms = LOGIN_ALL;

	if (whose->session == 0 ? !booting : (k = asked_whose(whose)) == NULL) {
		printf("%% Commit refused: frontend told system of no request "
		    "it is for\n");
		system_printed(id, 1);
		system_parts_free();
		return;
	}
	if (k != NULL)
		perms = system_whom(k, NULL);
	if (!system_may(perms, LOGIN_CONFIGURE, "configure") ||
	    ((perms & LOGIN_ADMIN) == 0 && system_admin_test(name) == -1)) {
		system_printed(id, 1);
		system_parts_free();
		return;
	}
	if (!ctl_rules_args(name, NULL, NULL, 0, NULL)) {
		printf("%% nshd: %s's rules have no test\n", name);
		system_printed(id, 1);
		system_parts_free();
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
	    (partlen[NSHD_SCRIPT] > 0 && write(fd, parts[NSHD_SCRIPT],
	    partlen[NSHD_SCRIPT]) != (ssize_t)partlen[NSHD_SCRIPT])) {
		printf("%% nshd: %s: %s\n", j->path, strerror(errno));
		close(fd);
		goto fail;
	}
	close(fd);
	system_job(j);
	system_parts_free();
	return;
 fail:
	system_printed(id, -1);
	system_job_free(j);
	system_parts_free();
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

	system_ended();
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

/* End the commit begun, and free what ran before it */
static void
system_ended(void)
{
	committing = 0;
	free(commit_before);
	commit_before = NULL;
	commit_beforelen = 0;
}

/*
 * The commit begun ended as how says: NSHD_BACK, rolled back to how it
 * was; NSHD_KEPT, a commit confirmed kept until its deadline; or
 * NSHD_APPLIED, configure terminal's commit applied, not saved. Then the
 * record it made goes, but an unsaved one from an earlier commit stays.
 * With NSHD_LEFT the commit ended neither way, and the records stay
 */
static void
system_back(uint32_t id, int how)
{
	struct record	 rec;
	int		 status = 1;

	if (how == NSHD_LEFT)
		status = 0;
	else if (record_read(&rec) == 0) {
		if (rec.state != RECORD_APPLYING || record_clear() == 0)
			status = 0;
		record_free(&rec);
	}
	/* a commit confirmed kept until its deadline, or rolled back */
	if (confirm_begun && how == NSHD_BACK)
		system_unarm();
	else if (confirm_begun && how == NSHD_KEPT)
		system_kept();
	confirm_free(&confirm_prev);
	confirm_begun = 0;
	system_ended();
	system_printed(id, status);
	system_confirm(-1, 0, NULL);
}

/*
 * The boot: the first time, nsh's own NSHRC taken as the saved
 * configuration; then the boot record made, and carp demoted for it,
 * unless a system before this did. The answer 0, to boot, NSHD_DONE if
 * nshd is not booting or this boot of the host is done already, else 1
 */
static void
system_boot(uint32_t id)
{
	struct boot	 b;
	int		 status = 1;

	/* a boot, except while nshd boots, is config's word alone */
	if (boot_over) {
		status = NSHD_DONE;
		goto done;
	}
	saved_first();
	if (boot_read(&b) == -1)
		goto done;
	if (b.state == BOOT_DONE) {
		status = NSHD_DONE;
		goto done;
	}
	if (b.state == BOOT_NONE) {
		b.state = BOOT_RUNS;
		b.when = boot_time();
		/* recorded first: carp demoted without a record stays so */
		if (boot_write(&b) == -1)
			goto done;
		if (carplock(128) == 1) {
			b.demoted = 1;
			boot_write(&b);
		}
	}
	status = 0;
 done:
	/* unrecorded, it runs all the same */
	booting = status != NSHD_DONE;
	system_printed(id, status);
}

/*
 * The boot ran; ok is set if the running configuration is the saved
 * configuration. If so, mark the boot done, promote carp if it was
 * demoted for the boot, and remove any unconfirmed commit record, since
 * the configuration it would roll back to is running. If not, mark the
 * boot failed; carp stays demoted until a commit saves.
 */
static void
system_booted(uint32_t id, int ok)
{
	struct boot	 b;
	int		 demoted, status = 1;

	booting = 0;
	boot_over = 1;
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
	system_printed(id, status);
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
 * configuration n as it was saved, or with diff, what it changed, or
 * with n -1, the list of them, or with -2, the saved configuration
 */
static void
system_rollback(uint32_t id, int n, int diff)
{
	char	*buf = NULL;
	size_t	 len = 0;
	FILE	*f;
	int	 r = 0;

	if ((f = open_memstream(&buf, &len)) == NULL)
		fatal("%s", __func__);
	if (n == -1) {
		system_health();
		rollback_list(f);
	}
	else if (n == -2)
		r = saved_text(f);
	else if (diff)
		r = rollback_diff(n, f);
	else
		r = rollback_text(n, f);
	if (fclose(f) == EOF)
		fatal("%s", __func__);
	/* first what nsh's code printed, then the text */
	if (printed_text(links[CONFIG].iev, IMSG_SYS_TEXT, id, 0) == -1)
		r = -1;
	if (imsg_text(links[CONFIG].iev, IMSG_SYS_TEXT, id, buf, len) == -1)
		fatal("%s", __func__);
	free(buf);
	system_end(id, r != 0, NULL);
}

/*
 * What is wrong with the running configuration, said before the list of
 * rollbacks: that it is not the saved configuration, a commit that did
 * not finish or is not saved, a boot that failed, a commit that was not
 * confirmed and could not be rolled back, and a commit record that
 * cannot be read
 */
static void
system_health(void)
{
	struct record	 rec;
	struct boot	 b;
	struct confirm	 cf;

	if (saved_differs() == 1)
		printf("%% What runs is not the saved configuration\n");
	if (!committing && record_read(&rec) == 0) {
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
 * A test of daemon name's rules, the part sent, for a session without
 * admin: -1, after saying why, if it has a line that needs admin and did
 * not run
 */
static int
system_admin_test(char *name)
{
	char	*runs;
	size_t	 len;
	int	 r;

	if ((runs = system_running(&len)) == NULL)
		return (-1);
	admin_begin(1, runs, len);
	r = admin_test(name, parts[NSHD_SCRIPT], partlen[NSHD_SCRIPT]);
	admin_end();
	free(runs);
	return (r);
}

/* what nsh's code printed, to config, then how request id ended */
static void
system_printed(uint32_t id, int32_t status)
{
	if (printed_text(links[CONFIG].iev, IMSG_SYS_TEXT, id, 0) == -1 &&
	    status == 0)
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
	return (j);
}

/* start j, in a child of system's, as the running job */
static void
system_job(struct job *j)
{
	struct timeval	 tv = { jobs[j->kind].secs, 0 };
	int		 fds[2];

	fflush(stdout);
	if (pipe2(fds, O_CLOEXEC) == -1) {
		printf("%% nshd: pipe: %s\n", strerror(errno));
		goto fail;
	}
	switch (j->pid = fork()) {
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
	if (j->kind == JOB_RECOVER) {
		printed_log();
		system_attempted(0);
	} else
		system_printed(j->id, -1);
	system_job_free(j);
}

/* the job's child: what it prints, to fd, with nothing else of system's */
static __dead void
system_job_child(int fd, struct job *j)
{
	struct script	 sc;
	int		 i, null, r;

	setpgid(0, 0);
	/* the default signal handling nsh's code and its programs expect */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	if (dup2(fd, STDOUT_FILENO) == -1 || dup2(fd, STDERR_FILENO) == -1 ||
	    (null = open(_PATH_DEVNULL, O_RDONLY)) == -1 ||
	    dup2(null, STDIN_FILENO) == -1)
		_exit(2);
	closefrom(STDERR_FILENO + 1);
	switch (j->kind) {
	case JOB_APPLY:
		memset(&sc, 0, sizeof(sc));
		sc.edits = parts[NSHD_SCRIPT];
		sc.elen = partlen[NSHD_SCRIPT];
		for (i = 0; i < j->apply->nclears; i++) {
			strlcpy(sc.clears[i].name, j->apply->clears[i].name,
			    sizeof(sc.clears[i].name));
			sc.clears[i].rtable = j->apply->clears[i].rtable;
			sc.clears[i].keep = j->apply->clears[i].keep;
		}
		sc.nclears = j->apply->nclears;
		/* without admin, what needs admin stays as it was running */
		admin_begin(committing && !commit_admin, commit_before,
		    commit_beforelen);
		/* -1, it could not run; 1, a line of it failed */
		r = script_run(&sc);
		break;
	case JOB_SAVE:
		if ((r = saved_write()))
			rollback_keep(SAVED, j->who, j->comment);
		r = !r;
		break;
	case JOB_RECOVER:
		r = commit_recover(j->back, j->backlen) == 0 ? 0 : 1;
		break;
	default:
		if (!j->root)
			system_drop();
		execv(j->args[0], j->args);
		printf("%% exec '%s' failed: %s\n", j->args[0],
		    strerror(errno));
		r = -1;
		break;
	}
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
		if (job->kind == JOB_RECOVER)
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
	if (j->kind == JOB_RECOVER) {
		printed_log();
		system_attempted(status == 0);
	} else {
		if (j->kind == JOB_SAVE && system_saved(status == 0) == -1)
			status = -1;
		system_printed(j->id, status);
	}
	system_job_free(j);
	/* first roll back an unconfirmed commit that is due */
	system_confirm(-1, 0, NULL);
	system_drain();
}

/* free j, and remove its test's rules */
static void
system_job_free(struct job *j)
{
	if (j->path[0] != '\0')
		unlink(j->path);
	if (j->dir[0] != '\0')
		rmdir(j->dir);
	free(j);
}

/* the commit record into rec, RECORD_NONE if none: -1, saying why, if not */
static int
record_read(struct record *rec)
{
	struct stat	 sb;
	char		 state[16], *nl;
	unsigned int	 uid;
	long long	 when;
	ssize_t		 n;
	size_t		 got, head;
	int		 fd, i;

	memset(rec, 0, sizeof(*rec));
	if ((fd = open(COMMIT_RECORD, O_RDONLY)) == -1) {
		if (errno == ENOENT)
			return (0);
		printf("%% nshd: %s: %s\n", COMMIT_RECORD, strerror(errno));
		return (-1);
	}
	if (fstat(fd, &sb) == -1) {
		printf("%% nshd: %s: %s\n", COMMIT_RECORD, strerror(errno));
		close(fd);
		return (-1);
	}
	if (sb.st_size > RECORD_HEAD + 2 * (off_t)NSHD_PART)
		goto bad;
	if ((rec->buf = malloc(sb.st_size + 1)) == NULL)
		fatal(NULL);
	for (got = 0; got < (size_t)sb.st_size; got += n)
		if ((n = read(fd, rec->buf + got, sb.st_size - got)) <= 0) {
			if (n == -1 && errno == EINTR) {
				n = 0;
				continue;
			}
			goto bad;
		}
	close(fd);
	fd = -1;
	rec->buf[got] = '\0';
	if ((nl = memchr(rec->buf, '\n', got < RECORD_HEAD ? got :
	    RECORD_HEAD)) == NULL)
		goto bad;
	*nl = '\0';
	head = nl - rec->buf + 1;
	if (sscanf(rec->buf, "%15s %u %lld %zu %zu", state, &uid, &when,
	    &rec->beforelen, &rec->wantlen) != 5 ||
	    rec->beforelen > NSHD_PART || rec->wantlen > NSHD_PART ||
	    head + rec->beforelen + rec->wantlen != got)
		goto bad;
	for (i = RECORD_APPLYING; i <= RECORD_UNSAVED; i++)
		if (strcmp(state, states[i]) == 0)
			rec->state = i;
	if (rec->state == RECORD_NONE)
		goto bad;
	rec->uid = uid;
	rec->when = when;
	rec->before = rec->buf + head;
	rec->want = rec->before + rec->beforelen;
	return (0);
 bad:
	if (fd != -1)
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
	int	 fd, r = 0;

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
	fprintf(f, "%s %u %lld %zu %zu\n", states[rec->state],
	    (unsigned int)rec->uid, (long long)rec->when, rec->beforelen,
	    rec->wantlen);
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
	return (db_sync());
}

/* no commit record: -1, saying why, if it could not be removed */
static int
record_clear(void)
{
	if (unlink(COMMIT_RECORD) == 0)
		return (db_sync());
	if (errno == ENOENT)
		return (0);
	printf("%% nshd: %s: %s\n", COMMIT_RECORD, strerror(errno));
	return (-1);
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
	char	 buf[64], state[16];
	ssize_t	 n;
	int	 fd, i;

	memset(b, 0, sizeof(*b));
	if ((fd = open(BOOT_RECORD, O_RDONLY)) == -1) {
		if (errno == ENOENT)
			return (0);
		printf("%% nshd: %s: %s\n", BOOT_RECORD, strerror(errno));
		return (-1);
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	buf[n > 0 ? n : 0] = '\0';
	if (sscanf(buf, "%15s %lld %d", state, &b->when, &b->demoted) == 3 &&
	    (b->demoted == 0 || b->demoted == 1))
		for (i = BOOT_RUNS; i <= BOOT_DONE; i++)
			if (strcmp(state, boot_states[i]) == 0)
				b->state = i;
	if (b->state == BOOT_NONE)
		printf("%% nshd: %s is not a boot record\n", BOOT_RECORD);
	if (b->state == BOOT_NONE || b->when != boot_time())
		memset(b, 0, sizeof(*b));
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

/* system ends, and with it what its streams' children and its job run */
static __dead void
system_exit(void)
{
	struct stream	*s;

	TAILQ_FOREACH(s, &streams, entry)
		if (s->pid != 0)
			killpg(s->pid, SIGKILL);
	if (job != NULL && job->pid != 0)
		killpg(job->pgid, SIGKILL);
	exit(0);
}
