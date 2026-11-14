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
 * config: the sessions, and what they ask of system. Each session comes
 * from parent, with its number, the uid and gid of its client, and a pipe
 * to its frontend; config knows the session by that pipe alone. Each
 * request to system has an id of its own; system's answers for it go to
 * the session that asked, if that session is still there, its facts
 * passed on unread. system learns, for each request it has sent output
 * for, when the session's client has read it all, so it may stream more;
 * and when the session is gone, so it stops streaming to it. A frontend
 * that closes its pipe, sends what it may not, or sends it wrong, ends
 * its session, and so does one whose session has FRONT_REQUESTS requests
 * unfinished and asks another. So system has at most that many of each
 * session's requests at once, and one step of a commit. Another peer
 * that sends what it may not, or sends it wrong, ends config, and nshd
 * with it.
 *
 * A session in configure has nsh's state of its own (session.c), and
 * config runs its lines through nsh's code in candidate mode, which here
 * asks no kernel, opens no file and runs no program. The running
 * configuration and what the lines read of the kernel come from a
 * snapshot system takes when a session enters configure or shows its
 * candidate, kept for every session until the next.
 *
 * configure private's candidate is the session's own; configure's is one
 * the sessions in configure share, and a commit of it commits what each
 * changed. configure exclusive is configure while no other session may
 * change the shared candidate or commit. While another session has it,
 * every mode but configure private is refused; configure exclusive is
 * also refused while another user's changes to the shared candidate are
 * not committed. Leaving configure exclusive discards what was not
 * committed. A commit of the shared candidate holds it, while it runs,
 * from the others' changes.
 *
 * A session has the permissions of its user's login class, which config
 * asks system for at the session's hello, by the session; system answers
 * for the uid of the session's client. Until they are in, the session may
 * only say hello, log in and go. A
 * show, a watch, the tables and names for completion, and a terminal need
 * view; an operation needs operate; configure private, configure
 * terminal, a commit, a rollback, a load and a daemon's rules need
 * configure. configure and configure exclusive need admin, as their
 * candidate is everyone's. exec is nsh's to check, as it runs a program:
 * config only tells it at hello. A session without admin sees no password
 * hash: config takes each out of the configuration it sends such a
 * session. system checks and runs an operation a session may ask, and
 * config passes it on. A session of the web configurator's has no
 * permissions until it logs in, as system checks it; then it has the
 * class of the user it logged in as. Its terminal, which system starts,
 * comes back as a pty, which config passes on.
 *
 * archive keeps the shared candidate, and who changed it, past config's
 * end. config sends it each time it changes, and answers the session that
 * changed it once archive says whether it kept it. A config that starts
 * takes what archive kept before a session enters configure. If the
 * candidate cannot be sent, or archive does not keep it, the session is
 * told.
 *
 * Commits run one at a time, for all sessions: config plans a commit from
 * a snapshot, then sends the whole commit (BEGIN), with the tests of the
 * daemons' rules it changes (TEST). system runs the tests first, and
 * says how each went. Then it runs the commit to its end: it records
 * it, says it is begun (BEGUN), runs its script and checks that what
 * runs is then the candidate. If it is, system saves the running
 * configuration; if not, it undoes the script. Before the script of a
 * commit that changes login users or classes, as before a rollback that
 * does, config lowers the permissions of the sessions that system says
 * would lose one, ends those that would lose their login (REVOKING),
 * and says so (GO). BEGIN's answer is how the commit ended, and config
 * then takes a snapshot, for the candidate to start again from. Once
 * system has begun a commit, it runs to its end if its session goes;
 * system does not begin it once the session's client has gone, nor once
 * a test refuses it. For commit check, and for a commit with problems
 * already, system only runs the tests, and says the verdict. commit
 * confirmed passes its minutes to BEGIN, so system also keeps an
 * unconfirmed commit record, and runs its script even if it is empty;
 * then, if what runs is the candidate, the commit's record goes, and the
 * running configuration stays until the deadline, not saved. A commit
 * that saves confirms it. A commit outside configure only saves the running
 * configuration (SAVE), as one that changes nothing does; check and
 * confirmed are configure's.
 *
 * configure terminal gives the session its own candidate, reset to the
 * running configuration from a new snapshot before each line. A line that
 * changes the candidate is committed but not saved, as BEGIN says, and
 * the commit record goes once what runs is the candidate. The line is
 * answered when its commit ends, and the candidate is then the running
 * configuration again. commit there saves the running configuration;
 * rollback has nothing to roll back.
 *
 * A daemon's rules come to a session in configure a part at a time, and
 * become its candidate's rules, in the rtable asked for, as the daemon's
 * edit makes them; the session may ask for them too. configure terminal
 * takes none.
 *
 * A client that completes lines itself, as nsh's Tab does, asks config
 * for two things, sent as facts: nsh's command tables, and the names of
 * interfaces, groups, bridges and routing tables.  The names come from
 * the last snapshot; if there is none yet, config takes one first.
 *
 * nsh -c's configuration comes a part at a time, each answered, outside
 * configure. After the last, on a new snapshot, it becomes the session's
 * own candidate, in place of the running configuration, and is committed,
 * all of it or none; then the candidate goes.
 *
 * A session may watch commits, configure exclusive, and interfaces,
 * addresses and routes, and config sends it a notice, unasked, as each
 * changes: a commit saved, confirmed or applied, as it ends; an
 * unconfirmed commit rolled back, as system says; configure exclusive
 * taken or left; and interfaces or addresses changed, and the rtables
 * whose routes did, which config reads from the routing socket parent
 * opened for it, fd 5, and says once a second at most. It may watch logs
 * too: system follows each, as a stream, whose text config sends as
 * notices until the watch drops the log or the stream ends, which config
 * says. A watch is answered once system has followed each log it adds, or
 * refused to.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "facts.h"
#include "args.h"
#include "stringlist.h"
#include "kfacts.h"
#include "session.h"

#define SNAPSHOT_TEXT	(16 * 1024 * 1024)	/* most text in a snapshot */

#define REQ_REFUSED	"% nshd: cannot take another request now\n"

#if NSHD_CLEARS != PLAN_CLEARS
#error "NSHD_CLEARS is not PLAN_CLEARS"
#endif

/* what a session waits on a snapshot for */
enum { WAIT_NONE, WAIT_CONFIGURE, WAIT_CANDIDATE, WAIT_DIFF, WAIT_RESET,
    WAIT_TERMINAL, WAIT_LOAD, WAIT_NAMES };

struct session {
	TAILQ_ENTRY(session)	 entry;
	uint32_t		 id;
	uid_t			 uid;
	gid_t			 gid;
	struct cand		*st;	/* nsh's state, once in configure */
	int			 want;	/* the configure it asked for */
	int			 how;	/* the configure it is in, or 0 */
	int			 waits;
	char			 line[NSHD_LINE];	/* configure terminal's */
	char			*load;	/* nsh -c's text, as it comes */
	size_t			 loadlen;
	char			 loaded[NSHD_COMMENT];	/* its comment */
	char			*rules;	/* a daemon's rules, as they come */
	size_t			 ruleslen;
	char			 rulesof[NSHD_DAEMON];	/* the daemon, or "" */
	int			 rulesrt;	/* their rtable */
	uint32_t		 keep;	/* the KEEP its answer waits for */
	struct nshd_context	 held;	/* that answer: its context, */
	int			 heldmode;	/* whether to send it, */
	int			 heldr;		/* and how it ended */
	int			 perms;		/* NSHD_*, -1 until known */
	int			 watch;		/* NSHD_WATCH_* */
	int			 starting;	/* log follows not yet begun */
	int			 watchr;	/* the watch's result status */
};

/*
 * A session's frontend: the pipe parent gave config for it, and who its
 * client is, as parent read it
 */
struct front {
	TAILQ_ENTRY(front)	 entry;
	uint32_t		 session;
	uid_t			 uid;
	gid_t			 gid;
	int			 dropped;	/* to go, as front_sweep() runs */
	struct imsgev		*iev;
};
#define FRONT_QUEUE	4096	/* messages to all frontends, unwritten */
#define FRONT_REQUESTS	16	/* a session's requests unfinished, at most */
/* all sessions' requests unfinished, at most, whether or not they are gone */
#define ALL_REQUESTS	(NSHD_SESSIONS * FRONT_REQUESTS)

/* a request system has not finished, and the session that asked it */
struct request {
	TAILQ_ENTRY(request)	 entry;
	uint32_t		 id;
	uint32_t		 session;	/* or 0 if no session made it */
	int			 kind;
	int			 n;		/* rollback n, or the log bit */
	char			*text;		/* its text, as it comes */
	size_t			 len;
	int			 bad;		/* past NSHD_PART */
	int			 started;	/* system began the follow */
	int			 stopped;	/* config stopped the follow */
	int			 unread;	/* output since its last READ */
};

/* kinds of request, by what config does when one ends */
enum { REQ_ANSWER, REQ_COMMIT, REQ_ROLLBACK, REQ_PERMS, REQ_TEXT, REQ_LOGIN,
    REQ_FOLLOW };

/* the commit's steps, by what it waits on */
enum {
	COMMIT_PLAN,		/* a snapshot, to plan from */
	COMMIT_BEGIN,		/* how system ended the commit */
	COMMIT_RAN,		/* a snapshot of what runs then */
	COMMIT_SAVE		/* the running configuration, to save */
};

struct commit {
	uint32_t		 session;	/* or 0 if gone */
	struct nshd_whose	 whose;		/* as system knows it */
	uid_t			 uid;
	int			 step;
	int			 waits;		/* on a snapshot */
	int			 check;		/* commit check */
	int			 test;		/* the plan's tests run */
	int			 ran;		/* how BEGIN ended */
	int			 minutes;	/* for commit confirmed, or 0 */
	int			 save;		/* outside configure: a save */
	int			 terminal;	/* configure terminal's line, */
	int			 line;		/* and how the line ended */
	int			 load;		/* nsh -c's configuration */
	int			 begun;		/* system said BEGUN */
	int			 logins;	/* changes login lines */
	int			 shared;	/* of the shared candidate */
	char			 comment[NSHD_COMMENT];
	struct plan		*plan;
};

/* the snapshot sessions wait on, as it comes */
struct snapshot {
	uint32_t		 id;
	char			*text;
	size_t			 len;
	struct kfacts		*kf;
	struct facts_in		 in;
	int			 bad;
};

static TAILQ_HEAD(, session)	sessions = TAILQ_HEAD_INITIALIZER(sessions);
static TAILQ_HEAD(, request)	requests = TAILQ_HEAD_INITIALIZER(requests);
static uint32_t			request_id;
static struct snapshot		*snap;
static struct kfacts		*kf_now;	/* facts of the last snapshot */
static struct commit		*commit;	/* the one running, or NULL */
static int			 revoking;	/* login lines change */
static struct cand_state	*shared;	/* configure's candidate */
static struct session		*exclusive;	/* in configure exclusive */
static uid_t			*editors;	/* who changed shared since */
static size_t			 neditors;
static unsigned int		 shared_edits;	/* its edits before a request */
static char			 held[64];	/* why a candidate is held */
static uint32_t			 keep_sent;	/* last KEEP sent to archive */
static uint32_t			 keep_done;	/* last KEEP archive answered */
static int			 keep_loaded;	/* archive's text was loaded */
static char			*loading;	/* that text, as it comes */
static size_t			 loading_len;
static int			 loading_past;	/* too big, or archive failed */
static struct event		 rt_ev;		/* the routing socket, */
static struct event		 rt_tm;		/* a timer for its notices, */
static int			 rt_links;	/* and what it saw change */
static int			 rt_all;
static uint8_t			 rt_tables[RT_TABLEID_MAX + 1];

static struct imsgev	*iev_parent;
static TAILQ_HEAD(, front)	 fronts = TAILQ_HEAD_INITIALIZER(fronts);
static struct event		 front_tm;	/* runs front_sweep() */

static void		 config_dispatch_parent(int, short, void *);
static void		 config_dispatch_front(int, short, void *);
static void		 front_new(struct nshd_newsession *, int);
static struct front	*front_find(uint32_t);
static struct imsgev	*front_iev(uint32_t);
static int		 front_compose(uint32_t, uint32_t, const void *,
			    size_t);
static int		 front_text(uint32_t, const char *, size_t);
static int		 front_printed(uint32_t);
static int		 front_fd(uint32_t, uint32_t, int);
static void		 front_check(void);
static void		 front_sweep(int, short, void *);
static void		 front_drop(struct front *);
static void		 front_revoke(struct nshd_revoking *);
static void		 config_dispatch_system(int, short, void *);
static void		 config_dispatch_archive(int, short, void *);
static void		 config_ready_archive(void);
static void		 config_show(uint32_t, struct nshd_show *);
static void		 config_configure(uint32_t, struct nshd_configure *);
static void		 config_line(uint32_t, struct nshd_line *);
static void		 config_stage(uint32_t, struct nshd_stage *);
static int		 config_staged(struct session *, const char *);
static int		 config_staging(struct session *, const char *);
static void		 config_exit(uint32_t);
static void		 config_commit(uint32_t, struct nshd_commit *);
static void		 config_rollback(uint32_t, struct nshd_rollback *);
static void		 config_rolled(struct request *, int32_t);
static void		 config_hello(uint32_t);
static void		 config_hello_answer(struct session *);
static void		 config_perms(struct request *, int32_t);
static void		 config_login(uint32_t, struct nshd_login *);
static void		 config_logged(struct request *, int32_t);
static void		 config_pty(uint32_t, struct nshd_terminal *);
static void		 config_text(struct request *, int32_t);
static int		 config_hides(struct session *);
static int		 config_may(uint32_t, uint32_t);
static void		 config_op(uint32_t, struct nshd_op *);
static void		 config_watch(uint32_t, struct nshd_watch *);
static void		 config_commands(uint32_t);
static void		 config_names(uint32_t);
static void		 config_named(struct session *);
static void		 config_units(void *, const void *, size_t);
static void		 config_notice(int, int, uid_t, int, const char *);
static void		 config_notice_to(uint32_t, int, uid_t, int,
			    const char *, size_t);
static struct request	*config_followed(struct session *, int);
static void		 config_follow_end(struct request *, int32_t);
static void		 config_route(int, short, void *);
static void		 config_routed(int, short, void *);
static struct session	*config_private(uint32_t);
static int		 config_in(struct session *);
static int		 config_terminal(struct session *);
static void		 config_load(uint32_t, struct nshd_load *);
static void		 config_rules(uint32_t, struct nshd_rules *);
static void		 rules_drop(struct session *);
static int		 config_loaded(struct session *);
static int		 config_enter(struct session *);
static void		 config_left(struct session *);
static void		 shared_hold(struct session *);
static void		 shared_done(struct session *);
static size_t		 editors_say(uid_t, const char *);
static uint32_t		 shared_keep(void);
static int		 shared_send(uint32_t);
static void		 shared_kept(uint32_t, const char *);
static void		 shared_load(void);
static void		 config_wait(struct session *, int);
static void		 snapshot_take(void);
static void		 config_snapshot(struct request *, uint32_t,
			    struct ibuf *);
static void		 config_snapshot_done(int32_t);
static void		 config_snapshot_lost(const char *);
static void		 config_ran(struct session *, int, int);
static void		 config_reply(struct session *, struct nshd_context *,
			    int, int);
static void		 config_answer(uint32_t, int32_t, const char *, ...)
			    __attribute__((__format__ (printf, 3, 4)));
static void		 config_tell(uint32_t, uint32_t);
static void		 config_read(uint32_t);
static struct request	*config_request(uint32_t, int);
static void		 commit_wait(int);
static void		 commit_snapshot(void);
static void		 commit_ended(int32_t);
static void		 commit_go(void);
static int		 commit_part(int32_t, const char *, size_t);
static void		 commit_saved(int);
static void		 commit_save(void);
static void		 commit_new(struct session *);
static void		 commit_request(int, uint32_t, const void *, size_t);
static void		 commit_tests(uint32_t);
static void		 commit_end(int, const char *);
static int		 commit_renew(void);
static void		 session_gone(struct session *);
static struct session	*session_find(uint32_t);
static struct request	*request_find(uint32_t);
static void		 request_free(struct request *);

static struct link	 links[] = {
#define SYSTEM		0
	{ PROC_SYSTEM,	 config_dispatch_system },
#define ARCHIVE		1
	{ PROC_ARCHIVE,	 config_dispatch_archive, config_ready_archive },
};

void
configproc(int debug, int verbose)
{
	child_start("config", debug, verbose);
	capture_stdout();
	privdrop(PROC_CONFIG);
	/* a later pledge cannot add a promise */
	if (pledge("stdio recvfd sendfd", NULL) == -1)
		fatal("pledge");

	/* nsh's code here asks no kernel, opens no file, runs no program */
	in_config = 1;
	if ((shared = cand_new()) == NULL)
		fatal(NULL);

	/* each session's pipe to its frontend comes from parent */
	if ((iev_parent = imsgev_new(3, config_dispatch_parent, 1)) == NULL)
		fatal(NULL);
	links_init(links, sizeof(links) / sizeof(links[0]));
	/* its peers' pipes are here; a terminal's pty passes through */
	imsgbuf_allow_fdpass(&links[SYSTEM].iev->ibuf);
	evtimer_set(&front_tm, front_sweep, NULL);
	event_set(&rt_ev, 5, EV_READ | EV_PERSIST, config_route, NULL);
	event_add(&rt_ev, NULL);
	evtimer_set(&rt_tm, config_routed, NULL);
	event_dispatch();
	exit(0);
}

/*
 * parent's word that config may start; each new session, with its pipe
 * to its frontend; and that a session ends
 */
static void
config_dispatch_parent(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_startup	 st;
	struct nshd_newsession	 ns;
	struct front		*f;
	int			 n, pfd;

	if (imsgev_io(iev, event) == -1)
		exit(0);

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		if (imsg_get_type(&imsg) == IMSG_SESSION &&
		    imsg_get_data(&imsg, &ns, sizeof(ns)) == 0 &&
		    (pfd = imsg_get_fd(&imsg)) != -1) {
			front_new(&ns, pfd);
			imsg_free(&imsg);
			continue;
		}
		if (imsg_get_type(&imsg) == IMSG_SESSION_GONE &&
		    imsg_get_len(&imsg) == 0) {
			if ((f = front_find(imsg_get_id(&imsg))) != NULL)
				front_drop(f);
			imsg_free(&imsg);
			continue;
		}
		if (imsg_get_type(&imsg) != IMSG_STARTUP ||
		    imsg_get_data(&imsg, &st, sizeof(st)) == -1)
			fatalx("parent sent imsg %u, which it may not",
			    imsg_get_type(&imsg));
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/*
 * A new session from parent, and fd, the pipe to its frontend: parent is
 * told whether config took it. While login users or classes change,
 * config refuses it (front_revoke())
 */
static void
front_new(struct nshd_newsession *ns, int fd)
{
	struct nshd_taken	 t;
	struct front		*f;

	memset(&t, 0, sizeof(t));
	t.session = ns->session;
	if (ns->session == 0 || front_find(ns->session) != NULL || revoking ||
	    (f = calloc(1, sizeof(*f))) == NULL) {
		close(fd);
		t.status = 1;
	} else if ((f->iev = imsgev_new(fd, config_dispatch_front, 1)) ==
	    NULL) {	/* a terminal's pty passes on to the frontend */
		close(fd);
		free(f);
		t.status = 1;
	} else {
		f->session = ns->session;
		f->uid = ns->uid;
		f->gid = ns->gid;
		TAILQ_INSERT_TAIL(&fronts, f, entry);
	}
	if (imsg_compose_event(iev_parent, IMSG_SESSION_TAKEN, 0, 0, -1, &t,
	    sizeof(t)) == -1)
		fatal("%s", __func__);
}

static struct front *
front_find(uint32_t session)
{
	struct front	*f;

	TAILQ_FOREACH(f, &fronts, entry)
		if (f->session == session)
			return (f);
	return (NULL);
}

/*
 * The pipe to session's frontend, or NULL if the session is gone, or is
 * to go: what is sent there is dropped. A session's output goes only
 * through front_compose(), front_text(), front_printed() and front_fd(),
 * which take the session, not the pipe, and which alone call this
 */
static struct imsgev *
front_iev(uint32_t session)
{
	struct front	*f;

	front_check();
	if ((f = front_find(session)) == NULL || f->dropped)
		return (NULL);
	return (f->iev);
}

/* a message to session's frontend, as link_compose() sends one */
static int
front_compose(uint32_t session, uint32_t type, const void *data,
    size_t len)
{
	struct imsgev	*iev;

	if ((iev = front_iev(session)) == NULL)
		return (0);
	return (imsg_compose_event(iev, type, session, 0, -1, data, len));
}

/* text to session's frontend, as output, in as many messages as it takes */
static int
front_text(uint32_t session, const char *text, size_t len)
{
	return (imsg_text(front_iev(session), IMSG_CTL_OUTPUT, session, text,
	    len));
}

/*
 * What nsh's code printed, to session's frontend, with each password
 * hash taken out if the session sees none; dropped if the session is gone
 */
static int
front_printed(uint32_t session)
{
	struct session	*sp = session_find(session);

	return (printed_text(sp == NULL ? NULL : front_iev(session),
	    IMSG_CTL_OUTPUT, session, config_hides(sp)));
}

/* fd, as a message of type, to session's frontend; closed if it is gone */
static int
front_fd(uint32_t session, uint32_t type, int fd)
{
	struct imsgev	*iev;

	if ((iev = front_iev(session)) == NULL) {
		close(fd);
		return (0);
	}
	return (imsg_compose_event(iev, type, session, 0, fd, NULL, 0));
}

/*
 * If config holds more than FRONT_QUEUE messages for the frontends, not
 * yet written, the session whose frontend has most of them goes, once
 * config is back in its event loop. A frontend that does not read cannot
 * make config hold more than that, and one answer more
 */
static void
front_check(void)
{
	struct front	*f, *most = NULL;
	struct timeval	 now = { 0, 0 };
	uint32_t	 all = 0, n;

	TAILQ_FOREACH(f, &fronts, entry) {
		if (f->dropped)
			continue;
		n = imsgbuf_queuelen(&f->iev->ibuf);
		all += n;
		if (most == NULL || n > imsgbuf_queuelen(&most->iev->ibuf))
			most = f;
	}
	if (all <= FRONT_QUEUE)
		return;
	log_warnx("session %u: its frontend reads too little", most->session);
	most->dropped = 1;
	evtimer_add(&front_tm, &now);
}

/* the sessions whose frontends front_check() found read too little go */
static void
front_sweep(int fd, short event, void *arg)
{
	struct front	*f, *next;

	TAILQ_FOREACH_SAFE(f, &fronts, entry, next)
		if (f->dropped)
			front_drop(f);
}

/*
 * f's session goes: system stops what it streams to it, and f's pipe is
 * closed, so its frontend ends
 */
static void
front_drop(struct front *f)
{
	struct session	*sp;

	if ((sp = session_find(f->session)) != NULL)
		session_gone(sp);
	config_tell(f->session, IMSG_SYS_STOP);
	TAILQ_REMOVE(&fronts, f, entry);
	event_del(&f->iev->ev);
	imsgbuf_clear(&f->iev->ibuf);
	close(f->iev->ibuf.fd);
	free(f->iev);
	free(f);
}

/*
 * Login users or classes are about to change, by a commit's script or a
 * rollback (REVOKING): system names each session that would lose a
 * permission, with those it would have, and config lowers its own to
 * them, so none goes on with permissions its class may no longer have;
 * one it gains it has once it connects again. A session that would lose
 * its login, or whose permissions are not in yet, ends: its frontend's
 * pipe is closed, so nothing more reaches it, and a commit it began runs
 * on. No session is taken until the change is done
 */
static void
front_revoke(struct nshd_revoking *rv)
{
	struct front	*f;
	struct session	*sp;
	uint32_t	 i;

	for (i = 0; i < rv->n; i++) {
		sp = session_find(rv->sessions[i]);
		if (rv->perms[i] != -1 && sp != NULL && sp->perms != -1) {
			log_info("session %u: its permissions lowered as login "
			    "users or classes change", sp->id);
			sp->perms &= rv->perms[i];
		} else if ((f = front_find(rv->sessions[i])) != NULL) {
			log_info("session %u ends: it would lose its login as "
			    "login users or classes change", f->session);
			front_drop(f);
		}
	}
}

/*
 * A frontend's requests, for its session: the session is the pipe's, as
 * parent gave it, whatever the frontend sends
 */
static void
config_dispatch_front(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct front		*f;
	struct imsg		 imsg;
	struct nshd_hello	 hello;
	struct nshd_show	 show;
	struct nshd_configure	 cf;
	struct nshd_line	 line;
	struct nshd_stage	 sg;
	struct nshd_commit	 cm;
	struct nshd_rollback	 rb;
	struct nshd_op		 op;
	struct nshd_load	 ld;
	struct nshd_rules	 rl;
	struct nshd_login	 lg;
	struct nshd_watch	 w;
	struct nshd_terminal	 tm;
	uint32_t		 id, type;
	int			 n;

	TAILQ_FOREACH(f, &fronts, entry)
		if (f->iev == iev)
			break;
	if (f == NULL)
		fatalx("%s: from no session", __func__);
	if (f->dropped)
		return;
	if (imsgev_io(iev, event) == -1) {
		front_drop(f);
		return;
	}

	id = f->session;
	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			log_warnx("session %u: its frontend sent what imsg "
			    "cannot read", id);
			front_drop(f);
			return;
		}
		if (n == 0)
			break;
		if (!config_may(id, type = imsg_get_type(&imsg))) {
			imsg_free(&imsg);
			continue;
		}
		switch (type) {
		case IMSG_CTL_HELLO:
			if (imsg_get_data(&imsg, &hello, sizeof(hello)) == -1)
				goto bad;
			config_hello(id);
			break;
		case IMSG_CTL_SHOW:
			if (imsg_get_data(&imsg, &show, sizeof(show)) == -1 ||
			    memchr(show.words, '\0', sizeof(show.words)) ==
			    NULL)
				goto bad;
			config_show(id, &show);
			break;
		case IMSG_CTL_CONFIGURE:
			if (imsg_get_data(&imsg, &cf, sizeof(cf)) == -1)
				goto bad;
			config_configure(id, &cf);
			break;
		case IMSG_CTL_LINE:
			if (imsg_get_data(&imsg, &line, sizeof(line)) == -1 ||
			    memchr(line.line, '\0', sizeof(line.line)) == NULL)
				goto bad;
			config_line(id, &line);
			break;
		case IMSG_CTL_STAGE:
			if (imsg_get_data(&imsg, &sg, sizeof(sg)) == -1 ||
			    (sg.bridge != 0 && sg.bridge != 1) ||
			    sg.ifname[0] == '\0' || memchr(sg.ifname, '\0',
			    sizeof(sg.ifname)) == NULL ||
			    sg.len < 0 || sg.len > NSHD_TEXT ||
			    memchr(sg.text, '\0', sg.len) != NULL)
				goto bad;
			config_stage(id, &sg);
			break;
		case IMSG_CTL_EXIT:
			if (imsg_get_len(&imsg) != 0)
				goto bad;
			config_exit(id);
			break;
		case IMSG_CTL_COMMIT:
			if (imsg_get_data(&imsg, &cm, sizeof(cm)) == -1 ||
			    memchr(cm.comment, '\0', sizeof(cm.comment)) == NULL)
				goto bad;
			config_commit(id, &cm);
			break;
		case IMSG_CTL_ROLLBACK:
			if (imsg_get_data(&imsg, &rb, sizeof(rb)) == -1)
				goto bad;
			config_rollback(id, &rb);
			break;
		case IMSG_CTL_OP:
			if (imsg_get_data(&imsg, &op, sizeof(op)) == -1 ||
			    memchr(op.line, '\0', sizeof(op.line)) == NULL)
				goto bad;
			config_op(id, &op);
			break;
		case IMSG_CTL_LOAD:
			if (imsg_get_data(&imsg, &ld, sizeof(ld)) == -1 ||
			    (ld.last != 0 && ld.last != 1) || ld.len < 0 ||
			    ld.len > NSHD_TEXT || memchr(ld.comment, '\0',
			    sizeof(ld.comment)) == NULL)
				goto bad;
			config_load(id, &ld);
			break;
		case IMSG_CTL_RULES:
			if (imsg_get_data(&imsg, &rl, sizeof(rl)) == -1 ||
			    (rl.set != 0 && rl.set != 1) ||
			    (rl.last != 0 && rl.last != 1) || rl.len < 0 ||
			    rl.len > NSHD_TEXT || memchr(rl.daemon, '\0',
			    sizeof(rl.daemon)) == NULL)
				goto bad;
			config_rules(id, &rl);
			break;
		case IMSG_CTL_LOGIN:
			if (imsg_get_data(&imsg, &lg, sizeof(lg)) == -1 ||
			    memchr(lg.name, '\0', sizeof(lg.name)) == NULL ||
			    memchr(lg.password, '\0', sizeof(lg.password)) ==
			    NULL)
				goto bad;
			config_login(id, &lg);
			explicit_bzero(&lg, sizeof(lg));
			break;
		case IMSG_CTL_WATCH:
			if (imsg_get_data(&imsg, &w, sizeof(w)) == -1)
				goto bad;
			config_watch(id, &w);
			break;
		case IMSG_CTL_TERMINAL:
			if (imsg_get_data(&imsg, &tm, sizeof(tm)) == -1 ||
			    tm.rows < 1 || tm.rows > NSHD_TERMSIZE ||
			    tm.cols < 1 || tm.cols > NSHD_TERMSIZE)
				goto bad;
			config_pty(id, &tm);
			break;
		case IMSG_CTL_COMMANDS:
		case IMSG_CTL_NAMES:
			if (imsg_get_len(&imsg) != 0)
				goto bad;
			if (type == IMSG_CTL_COMMANDS)
				config_commands(id);
			else
				config_names(id);
			break;
		case IMSG_CTL_READ:
			config_read(id);
			break;
		default:
			goto bad;
		}
		imsg_free(&imsg);
		/* a request may have made config drop the session */
		if (f->dropped)
			return;
	}
	imsg_event_add(iev);
	return;
 bad:
	imsg_free(&imsg);
	log_warnx("session %u: its frontend sent imsg %u, which it may not, "
	    "or not whole", id, type);
	front_drop(f);
}

/* system's answers, each for a request */
static void
config_dispatch_system(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct link		*l = &links[SYSTEM];
	struct imsg		 imsg;
	struct ibuf		 b;
	struct nshd_result	 res;
	struct nshd_notice	 nt;
	struct nshd_logged	 lg;
	struct nshd_revoking	 rv;
	struct request		*r;
	struct session		*sp;
	uint32_t		 type;
	int			 n, pty;
	char			*p;

	if (imsgev_io(iev, event) == -1) {
		link_broken(l, "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			link_broken(l, "sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		r = request_find(imsg_get_id(&imsg));
		switch (type = imsg_get_type(&imsg)) {
		case IMSG_SYS_TEXT:
		case IMSG_SYS_FACTS:
			/* a request config no longer knows of: ignore it */
			if (r == NULL)
				break;
			r->unread = 1;
			if (imsg_get_ibuf(&imsg, &b) == -1)
				fatal("%s", __func__);
			if (snap != NULL && r->id == snap->id) {
				config_snapshot(r, type, &b);
				break;
			}
			/* a log, as it comes, or why it is not followed */
			if (r->kind == REQ_FOLLOW) {
				if (type != IMSG_SYS_TEXT)
					goto bad;
				if (r->stopped || session_find(r->session) ==
				    NULL)
					break;
				if (r->started)
					config_notice_to(r->session,
					    NSHD_NOTICE_LOG, 0, r->n,
					    ibuf_data(&b), ibuf_size(&b));
				else if (front_compose(r->session,
				    IMSG_CTL_OUTPUT, ibuf_data(&b),
				    ibuf_size(&b)) == -1)
					fatal("%s", __func__);
				break;
			}
			if (r->kind == REQ_ROLLBACK || r->kind == REQ_TEXT) {
				if (type != IMSG_SYS_TEXT)
					goto bad;
				if (ibuf_size(&b) > NSHD_PART - r->len) {
					r->bad = 1;
					break;
				}
				if ((p = realloc(r->text, r->len +
				    ibuf_size(&b))) == NULL)
					fatal("%s", __func__);
				r->text = p;
				memcpy(r->text + r->len, ibuf_data(&b),
				    ibuf_size(&b));
				r->len += ibuf_size(&b);
				break;
			}
			if (session_find(r->session) != NULL &&
			    front_compose(r->session,
			    type == IMSG_SYS_TEXT ? IMSG_CTL_OUTPUT :
			    IMSG_CTL_FACTS, ibuf_data(&b),
			    ibuf_size(&b)) == -1)
				fatal("%s", __func__);
			break;
		case IMSG_SYS_END:
			if (imsg_get_data(&imsg, &res, sizeof(res)) == -1)
				goto bad;
			if (r == NULL)
				break;
			TAILQ_REMOVE(&requests, r, entry);
			if (snap != NULL && r->id == snap->id)
				config_snapshot_done(res.status);
			else if (r->kind == REQ_COMMIT) {
				if (commit != NULL)
					commit_ended(res.status);
			} else if (r->kind == REQ_ROLLBACK)
				config_rolled(r, res.status);
			else if (r->kind == REQ_PERMS)
				config_perms(r, res.status);
			else if (r->kind == REQ_LOGIN)
				config_logged(r, res.status);
			else if (r->kind == REQ_TEXT)
				config_text(r, res.status);
			else if (r->kind == REQ_FOLLOW)
				config_follow_end(r, res.status);
			else if (session_find(r->session) != NULL)
				config_answer(r->session, res.status, NULL);
			request_free(r);
			break;
		case IMSG_SYS_NOTICE:
			/* an unconfirmed commit rolled back, or failed to */
			if (imsg_get_data(&imsg, &nt, sizeof(nt)) == -1 ||
			    nt.kind != NSHD_NOTICE_BACK ||
			    (nt.n != 0 && nt.n != 1))
				goto bad;
			config_notice(NSHD_WATCH_COMMITS, NSHD_NOTICE_BACK, 0,
			    nt.n, NULL);
			break;
		case IMSG_SYS_REVOKING:
			/*
			 * login users or classes are about to change, by a
			 * commit or a rollback: config lowers the permissions
			 * of the sessions that would lose one, or ends them,
			 * and then tells system (GO), after the stops of the
			 * requests of those that end (front_drop()); or they
			 * have changed
			 */
			if (imsg_get_data(&imsg, &rv, sizeof(rv)) == -1 ||
			    (rv.on != 0 && rv.on != 1) ||
			    rv.n > NSHD_SESSIONS)
				goto bad;
			revoking = rv.on;
			if (revoking) {
				front_revoke(&rv);
				if (link_compose(&links[SYSTEM], IMSG_SYS_GO,
				    imsg_get_id(&imsg), NULL, 0) == -1)
					fatal("%s", __func__);
			}
			break;
		case IMSG_SYS_LOGGED:
			/* whom a web session logged in as: it is that uid */
			if (imsg_get_data(&imsg, &lg, sizeof(lg)) == -1 ||
			    r == NULL || r->kind != REQ_LOGIN)
				goto bad;
			if ((sp = session_find(r->session)) != NULL)
				sp->uid = lg.uid;
			break;
		case IMSG_SYS_TEST:
			/* how a test of the commit's went, before it begins */
			if (imsg_get_data(&imsg, &res, sizeof(res)) == -1 ||
			    r == NULL || r->kind != REQ_COMMIT ||
			    commit == NULL || commit->plan == NULL ||
			    commit->test >= commit->plan->ntests)
				goto bad;
			session_tested(commit->plan, commit->test++,
			    res.status != 0);
			front_printed(commit->session);
			break;
		case IMSG_SYS_BEGUN:
			/* the commit is begun: BEGIN's answer is how it ends */
			if (imsg_get_len(&imsg) != 0 || r == NULL ||
			    r->kind != REQ_COMMIT || commit == NULL)
				goto bad;
			commit->begun = 1;
			break;
		case IMSG_SYS_TERMINAL:
			/* a terminal's pty, before its request's end */
			if ((pty = imsg_get_fd(&imsg)) == -1 ||
			    imsg_get_len(&imsg) != 0)
				goto bad;
			if (r == NULL || session_find(r->session) == NULL)
				close(pty);
			else if (front_fd(r->session, IMSG_CTL_TERMINAL,
			    pty) == -1)
				fatal("%s", __func__);
			break;
		case IMSG_SYS_FOLLOWING:
			/* a follow begun, once */
			if (imsg_get_len(&imsg) != 0 || r == NULL ||
			    r->kind != REQ_FOLLOW || r->started)
				goto bad;
			r->started = 1;
			if ((sp = session_find(r->session)) != NULL &&
			    --sp->starting == 0)
				config_answer(sp->id, sp->watchr, NULL);
			break;
		default:
			goto bad;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
	return;
 bad:
	imsg_free(&imsg);
	link_broken(l, "sent imsg %u, which it may not, or not whole", type);
}

static void
config_show(uint32_t session, struct nshd_show *show)
{
	struct nshd_snapshot	 ns = { 0 };
	struct nshd_rollback	 rb = { -1 };
	struct session		*sp;
	struct request		*r;
	const char		*errstr;
	char			 num[16], *p;
	uint32_t		 type = IMSG_SYS_SHOW;
	const void		*data = show;
	size_t			 len = sizeof(*show);
	int			 kind = REQ_ANSWER;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if (strcmp(show->words, "candidate-config") == 0 ||
	    strcmp(show->words, "diff-config") == 0) {
		if (sp->st == NULL) {
			config_answer(session, 1, "%% Not in configure\n");
			return;
		}
		config_wait(sp, show->words[0] == 'c' ? WAIT_CANDIDATE :
		    WAIT_DIFF);
		return;
	}
	if (strcmp(show->words, "running-config") == 0) {
		type = IMSG_SYS_SNAPSHOT;
		data = &ns;
		len = sizeof(ns);
		kind = REQ_TEXT;
	} else if (strcmp(show->words, "startup-config") == 0) {
		type = IMSG_SYS_SAVED;
		data = NULL;
		len = 0;
		kind = REQ_TEXT;
	} else if (strcmp(show->words, "rollback") == 0) {
		type = IMSG_SYS_ROLLBACK_LIST;
		data = NULL;
		len = 0;
	} else if (strncmp(show->words, "rollback ", 9) == 0) {
		/* rollback N, or rollback N diff, what N changed */
		strlcpy(num, show->words + 9, sizeof(num));
		type = IMSG_SYS_ROLLBACK_READ;
		if ((p = strchr(num, ' ')) != NULL && strcmp(p, " diff") == 0) {
			*p = '\0';
			type = IMSG_SYS_ROLLBACK_DIFF;
		}
		rb.n = strtonum(num, 0, NSHD_ROLLBACKS - 1, &errstr);
		if (errstr != NULL) {
			config_answer(session, 1, "%% rollback %s is %s\n",
			    show->words + 9, errstr);
			return;
		}
		data = &rb;
		len = sizeof(rb);
		kind = REQ_TEXT;
	}
	/* the whole text is collected only to take its hashes out */
	if (kind == REQ_TEXT && !config_hides(sp))
		kind = REQ_ANSWER;
	if ((r = config_request(session, kind)) == NULL) {
		config_answer(session, 1, "%s", REQ_REFUSED);
		return;
	}
	/* system answers the rest with facts, or says it does not */
	if (link_compose(&links[SYSTEM], type, r->id, data, len) == -1)
		fatal("%s", __func__);
}

/* enter configure in the mode asked for, once a snapshot is in */
static void
config_configure(uint32_t session, struct nshd_configure *cf)
{
	static const char	*names[] = { "", " private", "", " exclusive",
				    " terminal" };
	struct session		*sp;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if (cf->mode != NSHD_PRIVATE && cf->mode != NSHD_SHARED &&
	    cf->mode != NSHD_EXCLUSIVE && cf->mode != NSHD_TERMINAL) {
		config_answer(session, 1,
		    "%% nshd: configure, private, exclusive or terminal\n");
		return;
	}
	/* their candidate is everyone's */
	if ((cf->mode == NSHD_SHARED || cf->mode == NSHD_EXCLUSIVE) &&
	    (sp->perms & NSHD_ADMIN) == 0) {
		config_answer(session, 1, "%% Not allowed: configure%s needs "
		    "the admin permission; configure private does not\n",
		    names[cf->mode]);
		return;
	}
	if (sp->how != 0 && sp->how != cf->mode) {
		config_answer(session, 1, "%% In configure%s; exit it first\n",
		    names[sp->how]);
		return;
	}
	if (sp->st == NULL && (sp->st = session_new()) == NULL)
		fatal("%s", __func__);
	sp->want = cf->mode;
	config_wait(sp, WAIT_CONFIGURE);
}

/* a line, in the session's mode, as nsh runs it */
static void
config_line(uint32_t session, struct nshd_line *line)
{
	struct session	*sp;
	int		 r;

	if ((sp = config_private(session)) == NULL)
		return;
	/* in configure terminal, run it once a snapshot is in */
	if (sp->how == NSHD_TERMINAL) {
		strlcpy(sp->line, line->line, sizeof(sp->line));
		config_wait(sp, WAIT_TERMINAL);
		return;
	}
	shared_hold(sp);
	r = session_line(sp->st, line->line);
	shared_done(sp);
	config_ran(sp, r, 1);
}

/*
 * A stage, into the session's candidate: the lines of its text, run in
 * the mode of the interface or bridge it names until one fails, then
 * out of that mode. A line may leave the mode itself; then no more
 * lines run, nor the exit, and the stage fails if any line was left.
 * Each line's output is followed by STAGED, which says how it went. The
 * stage changes the shared candidate as one edit, and is answered as a
 * line is
 */
static void
config_stage(uint32_t session, struct nshd_stage *sg)
{
	struct session	*sp;
	char		 head[NSHD_LINE], text[NSHD_TEXT + 1], *line, *next;
	int		 r;

	if ((sp = config_private(session)) == NULL)
		return;
	if (sp->how == NSHD_TERMINAL) {
		config_answer(session, 1, "%% configure terminal has no "
		    "candidate to stage into; each line is committed\n");
		return;
	}
	snprintf(head, sizeof(head), "%s %s", sg->bridge ? "bridge" :
	    "interface", sg->ifname);
	memcpy(text, sg->text, sg->len);
	text[sg->len] = '\0';
	shared_hold(sp);
	if ((r = config_staged(sp, head)) == 0) {
		for (line = text; r == 0 && line != NULL &&
		    config_staging(sp, sg->ifname); line = next) {
			if ((next = strchr(line, '\n')) != NULL)
				*next++ = '\0';
			if (*line != '\0')
				r = config_staged(sp, line);
		}
		if (config_staging(sp, sg->ifname)) {
			if (config_staged(sp, "exit") == -1)
				r = -1;
		} else if (line != NULL)
			r = -1;
	}
	shared_done(sp);
	config_ran(sp, r, 1);
}

/* a line of a stage, run in the session's mode: its output, then STAGED */
static int
config_staged(struct session *sp, const char *line)
{
	struct nshd_staged	 sd;
	char			 buf[NSHD_LINE];
	int			 r = -1;

	memset(&sd, 0, sizeof(sd));
	strlcpy(sd.line, line, sizeof(sd.line));
	if (strlcpy(buf, line, sizeof(buf)) >= sizeof(buf))
		printf("%% nshd: a line is longer than %d bytes\n",
		    NSHD_LINE - 1);
	else
		r = session_line(sp->st, buf);
	if (front_printed(sp->id) == -1)
		r = -1;
	sd.status = r == -1 ? -1 : 0;
	if (front_compose(sp->id, IMSG_CTL_STAGED, &sd, sizeof(sd)) == -1)
		fatal("%s", __func__);
	return (sd.status);
}

/* whether the session is in the mode of interface ifname */
static int
config_staging(struct session *sp, const char *ifname)
{
	char	 ifn[NSHD_IFNAME];
	int	 in, rtable, bridge;

	session_mode(sp->st, &in, &rtable, ifn, sizeof(ifn), &bridge);
	return (strcmp(ifn, ifname) == 0);
}

/* leave configure, from any of its modes, if in it */
static void
config_exit(uint32_t session)
{
	struct session	*sp;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	config_ran(sp, sp->how == 0 ? 0 : session_exit(sp->st), 1);
}

/*
 * commit, or commit check, of the session's candidate; or outside
 * configure, a save of the running configuration
 */
static void
config_commit(uint32_t session, struct nshd_commit *c)
{
	struct session	*sp;
	int		 save;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	/* a save in configure terminal too, as its lines are committed */
	if ((save = !config_in(sp) || sp->how == NSHD_TERMINAL) &&
	    (c->check || c->minutes != 0)) {
		config_answer(session, 1, "%% commit %s requires a "
		    "candidate: configure, private or exclusive\n",
		    c->check ? "check" : "confirmed");
		return;
	}
	if (commit != NULL) {
		config_answer(session, 1, "%% Commit refused: uid %u commits "
		    "now\n", (unsigned int)commit->uid);
		return;
	}
	if (exclusive != NULL && exclusive != sp) {
		config_answer(session, 1, "%% Commit refused: uid %u has "
		    "configure exclusive\n", (unsigned int)exclusive->uid);
		return;
	}
	if (c->minutes < 0 || c->minutes > NSHD_CONFIRMMAX ||
	    (c->minutes > 0 && (c->check || c->comment[0] != '\0'))) {
		config_answer(session, 1, "%% commit confirmed takes 1 to %d "
		    "minutes, and no check or comment\n", NSHD_CONFIRMMAX);
		return;
	}
	commit_new(sp);
	commit->check = c->check;
	commit->minutes = c->minutes;
	commit->save = save;
	commit->shared = !save && sp->how != NSHD_PRIVATE;
	strlcpy(commit->comment, c->comment, sizeof(commit->comment));
	if (save)
		commit_save();
	else
		commit_wait(COMMIT_PLAN);
}

/*
 * rollback n: the session's candidate starts over as saved configuration
 * n, which system reads, or as the running configuration if n is 0
 */
static void
config_rollback(uint32_t session, struct nshd_rollback *rb)
{
	struct session	*sp;
	struct request	*r;

	if ((sp = config_private(session)) == NULL)
		return;
	if (sp->how == NSHD_TERMINAL) {
		config_answer(session, 1, "%% configure terminal has no "
		    "candidate to roll back; each line is committed\n");
		return;
	}
	if (rb->n < 0 || rb->n >= NSHD_ROLLBACKS) {
		config_answer(session, 1, "%% rollback [0-%d]\n",
		    NSHD_ROLLBACKS - 1);
		return;
	}
	if (rb->n == 0) {
		config_wait(sp, WAIT_RESET);
		return;
	}
	if ((r = config_request(session, REQ_ROLLBACK)) == NULL) {
		config_answer(session, 1, "%s", REQ_REFUSED);
		return;
	}
	r->n = rb->n;
	if (link_compose(&links[SYSTEM], IMSG_SYS_ROLLBACK_READ, r->id, rb,
	    sizeof(*rb)) == -1)
		fatal("%s", __func__);
}

/* rollback n's text is in, or why not */
static void
config_rolled(struct request *r, int32_t status)
{
	struct session	*sp;
	int		 n;

	if ((sp = session_find(r->session)) == NULL)
		return;
	if (status == 0 && r->bad) {
		config_answer(sp->id, 1, "%% nshd: rollback %d is past %d "
		    "bytes\n", r->n, NSHD_PART);
		return;
	}
	if (status != 0) {
		if (front_text(sp->id, r->text, r->len) == -1)
			fatal("%s", __func__);
		config_answer(sp->id, 1, NULL);
		return;
	}
	shared_hold(sp);
	n = session_rollback(sp->st, r->text, r->len, r->n);
	shared_done(sp);
	config_ran(sp, n, 1);
}

/*
 * hello: the session, made once, with the uid and gid parent read from
 * its client's socket, and its permissions asked of system
 */
static void
config_hello(uint32_t session)
{
	struct nshd_perms	 p;
	struct session		*sp;
	struct request		*r;
	struct front		*f;

	if ((sp = session_find(session)) != NULL) {
		config_hello_answer(sp);
		return;
	}
	if ((f = front_find(session)) == NULL)
		return;
	if ((sp = calloc(1, sizeof(*sp))) == NULL)
		fatal(NULL);
	sp->id = session;
	sp->uid = f->uid;
	sp->gid = f->gid;
	sp->perms = -1;
	TAILQ_INSERT_TAIL(&sessions, sp, entry);
	if ((r = config_request(session, REQ_PERMS)) == NULL) {
		sp->perms = 0;
		config_hello_answer(sp);
		return;
	}
	memset(&p, 0, sizeof(p));
	p.session = session;
	if (link_compose(&links[SYSTEM], IMSG_SYS_PERMS, r->id, &p,
	    sizeof(p)) == -1)
		fatal("%s", __func__);
}

static void
config_hello_answer(struct session *sp)
{
	struct nshd_session	 s;

	s.version = NSHD_VERSION;
	s.id = sp->id;
	s.perms = sp->perms;
	if (front_compose(sp->id, IMSG_CTL_HELLO, &s,
	    sizeof(s)) == -1)
		fatal("%s", __func__);
}

/* system's answer: the session's permissions, or none if it had none */
static void
config_perms(struct request *r, int32_t status)
{
	struct session	*sp;

	if ((sp = session_find(r->session)) == NULL)
		return;
	sp->perms = status > 0 ? status & (NSHD_VIEW | NSHD_OPERATE |
	    NSHD_CONFIGURE | NSHD_ADMIN | NSHD_EXEC) : 0;
	config_hello_answer(sp);
}

/* the web configurator's session logs in, as system checks it */
static void
config_login(uint32_t session, struct nshd_login *lg)
{
	struct nshd_syslogin	 sl;
	struct request		*r;

	if (session_find(session) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if ((r = config_request(session, REQ_LOGIN)) == NULL) {
		config_answer(session, 1, "%s", REQ_REFUSED);
		return;
	}
	memset(&sl, 0, sizeof(sl));
	sl.whose.session = session;
	sl.login = *lg;
	if (link_compose(&links[SYSTEM], IMSG_SYS_LOGIN, r->id, &sl,
	    sizeof(sl)) == -1)
		fatal("%s", __func__);
	explicit_bzero(&sl, sizeof(sl));
}

/*
 * system's answer: the permissions of the user the session logged in as,
 * or -1 if it did not, which leaves the session as it was. A login that
 * succeeds is answered as a hello is, with the session's permissions
 */
static void
config_logged(struct request *r, int32_t status)
{
	struct session	*sp;

	if ((sp = session_find(r->session)) == NULL)
		return;
	if (status < 0) {
		config_answer(sp->id, 1, NULL);
		return;
	}
	sp->perms = status;
	config_hello_answer(sp);
}

/* a terminal for the session's web login, as system starts it */
static void
config_pty(uint32_t session, struct nshd_terminal *tm)
{
	struct nshd_systerm	 st;
	struct request		*r;

	if (session_find(session) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if ((r = config_request(session, REQ_ANSWER)) == NULL) {
		config_answer(session, 1, "%s", REQ_REFUSED);
		return;
	}
	memset(&st, 0, sizeof(st));
	st.whose.session = session;
	st.size = *tm;
	if (link_compose(&links[SYSTEM], IMSG_SYS_TERMINAL, r->id, &st,
	    sizeof(st)) == -1)
		fatal("%s", __func__);
}

/*
 * The configuration's text system gave, for a session without admin,
 * with each password hash taken out, and how it went
 */
static void
config_text(struct request *r, int32_t status)
{
	if (session_find(r->session) == NULL)
		return;
	if (r->bad) {
		config_answer(r->session, 1, "%% nshd: past %d bytes\n",
		    NSHD_PART);
		return;
	}
	r->len = login_hide(r->text, r->len);
	if (front_text(r->session, r->text, r->len) == -1)
		fatal("%s", __func__);
	config_answer(r->session, status, NULL);
}

/* Does sp see no password hash? */
static int
config_hides(struct session *sp)
{
	return (sp != NULL && (sp->perms & NSHD_ADMIN) == 0);
}

/*
 * Whether session may ask type: hello, exit, read and login always; else
 * what its permissions allow, once they are in, and in configure shared
 * or exclusive, admin. A request before hello passes, for its handler to
 * refuse
 */
static int
config_may(uint32_t session, uint32_t type)
{
	struct session	*sp;
	const char	*name = "configure";
	int		 need = NSHD_CONFIGURE;

	if (type == IMSG_CTL_HELLO || type == IMSG_CTL_EXIT ||
	    type == IMSG_CTL_READ || type == IMSG_CTL_LOGIN ||
	    (sp = session_find(session)) == NULL)
		return (1);
	if (type == IMSG_CTL_SHOW || type == IMSG_CTL_WATCH ||
	    type == IMSG_CTL_COMMANDS || type == IMSG_CTL_NAMES ||
	    type == IMSG_CTL_TERMINAL) {
		need = NSHD_VIEW;
		name = "view";
	} else if (type == IMSG_CTL_OP) {
		need = NSHD_OPERATE;
		name = "operate";
	}
	if (sp->perms == -1 || (sp->perms & need) == 0) {
		config_answer(session, 1, "%% Not allowed: your login class "
		    "does not have the %s permission\n", name);
		return (0);
	}
	/* the shared candidate is admin's, and a session can lose admin */
	if ((sp->how == NSHD_SHARED || sp->how == NSHD_EXCLUSIVE) &&
	    need == NSHD_CONFIGURE && (sp->perms & NSHD_ADMIN) == 0) {
		config_answer(session, 1, "%% Not allowed: your login class no "
		    "longer has the admin permission the shared candidate "
		    "needs; exit configure\n");
		return (0);
	}
	return (1);
}

/* Send nsh's command tables to the session as facts, then a result. */
static void
config_commands(uint32_t session)
{
	struct session		*sp;
	struct units		 u = { config_units };
	struct facts_out	 o;
	int			 r;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	u.arg = sp;
	facts_out_init(&o, units_emit, &u);
	r = cmplt_facts(&o);
	units_flush(&u);
	if (r == -1)
		config_answer(sp->id, 1, "%% nshd: the command tables "
		    "could not be sent\n");
	else
		config_answer(sp->id, 0, NULL);
}

/* Send the names for completion, once there is a snapshot to read. */
static void
config_names(uint32_t session)
{
	struct session	*sp;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if (kf_now == NULL)
		config_wait(sp, WAIT_NAMES);
	else
		config_named(sp);
}

/* a name record: what kind of thing it names, and the name */
static const struct facts_field namefields[] = {
	{ "of",		FACT_STRING },
	{ "name",	FACT_STRING },
};
static const struct facts_kind kind_name = { "name", namefields,
	sizeof(namefields) / sizeof(namefields[0]) };

/* Send the snapshot's names to sp as facts, then a result. */
static void
config_named(struct session *sp)
{
	static char		*of[] = { "interface", "group", "bridge",
				    "rtable" };
	struct facts_value	 v[sizeof(namefields) / sizeof(namefields[0])];
	struct units		 u = { config_units, sp };
	struct facts_out	 o;
	StringList		*sl;
	size_t			 i, j;
	int			 r = 0;

	facts_out_init(&o, units_emit, &u);
	for (i = 0; i < sizeof(of) / sizeof(of[0]) && r == 0; i++) {
		if ((sl = sl_init()) == NULL)
			fatal("%s", __func__);
		if (kf_names(i, sl) == -1)
			r = -1;
		for (j = 0; j < sl->sl_cur && r == 0; j++) {
			memset(v, 0, sizeof(v));
			facts_string(&v[0], of[i]);
			facts_string(&v[1], sl->sl_str[j]);
			r = facts_record(&o, &kind_name, v);
		}
		sl_free(sl, 1);
	}
	units_flush(&u);
	if (r == -1)
		config_answer(sp->id, 1, "%% nshd: the names could not be "
		    "sent\n");
	else
		config_answer(sp->id, 0, NULL);
}

/* facts units for the session arg, as one message */
static void
config_units(void *arg, const void *buf, size_t len)
{
	struct session	*sp = arg;

	if (front_compose(sp->id, IMSG_CTL_FACTS, buf, len) == -1)
		fatal("%s", __func__);
}

/*
 * an operation, as nsh's words for it, which config parses into a row of
 * ops[] and its values (op_parse()): system checks the values, runs the
 * row and streams what it prints
 */
static void
config_op(uint32_t session, struct nshd_op *op)
{
	struct nshd_sysop	 so;
	struct argvals		 a;
	struct request		*r;
	char			*w[NSHD_LINE / 2], *p = op->line;
	ssize_t			 len = -1;
	int			 n = 0, row = -1;

	if (session_find(session) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	memset(&so, 0, sizeof(so));
	while (n < (int)(sizeof(w) / sizeof(w[0])) &&
	    (w[n] = strsep(&p, " \t")) != NULL)
		if (*w[n] != '\0')
			n++;
	if (n == 0 || p != NULL)
		printf("%% nshd: an operation of no words, or too many\n");
	else if ((row = op_parse(n, w, &a, so.ifname, sizeof(so.ifname))) !=
	    -1)
		len = args_record(&ops[row], &a, so.values,
		    sizeof(so.values));
	if (len == -1) {
		front_printed(session);
		config_answer(session, 1, NULL);
		return;
	}
	if ((r = config_request(session, REQ_ANSWER)) == NULL) {
		config_answer(session, 1, "%s", REQ_REFUSED);
		return;
	}
	so.whose.session = session;
	so.rtable = op->rtable;
	so.row = row;
	so.set = a.set;
	so.len = len;
	if (link_compose(&links[SYSTEM], IMSG_SYS_OP, r->id, &so,
	    sizeof(so)) == -1)
		fatal("%s", __func__);
}

/*
 * What the session watches, from now on. system follows each log it
 * adds, or refuses to, before the watch is answered; each it drops is
 * stopped
 */
static void
config_watch(uint32_t session, struct nshd_watch *w)
{
	struct nshd_follow	 f;
	struct session		*sp;
	struct request		*r;
	int			 log;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if ((w->what & ~NSHD_WATCH_ALL) != 0) {
		config_answer(session, 1, "%% nshd: no such watch: %#x\n",
		    w->what & ~NSHD_WATCH_ALL);
		return;
	}
	sp->watchr = 0;
	for (log = NSHD_WATCH_DAEMON; log & NSHD_WATCH_LOGS; log <<= 1) {
		r = config_followed(sp, log);
		if (r != NULL && (w->what & log) == 0) {
			r->stopped = 1;
			if (link_compose(&links[SYSTEM], IMSG_SYS_STOP, r->id,
			    NULL, 0) == -1)
				fatal("%s", __func__);
		} else if (r == NULL && (w->what & log) != 0) {
			if ((r = config_request(session, REQ_FOLLOW)) ==
			    NULL) {
				if (front_text(session, REQ_REFUSED,
				    strlen(REQ_REFUSED)) == -1)
					fatal("%s", __func__);
				sp->watchr = 1;
				continue;
			}
			r->n = log;
			memset(&f, 0, sizeof(f));
			f.whose.session = session;
			f.log = log;
			if (link_compose(&links[SYSTEM], IMSG_SYS_FOLLOW, r->id,
			    &f, sizeof(f)) == -1)
				fatal("%s", __func__);
			sp->starting++;
		}
	}
	sp->watch = w->what;
	if (sp->starting == 0)
		config_answer(session, sp->watchr, NULL);
}

/* the follow of log, for sp, not stopped, or NULL */
static struct request *
config_followed(struct session *sp, int log)
{
	struct request	*r;

	TAILQ_FOREACH(r, &requests, entry)
		if (r->session == sp->id && r->kind == REQ_FOLLOW &&
		    r->n == log && !r->stopped)
			return (r);
	return (NULL);
}

/*
 * A follow ended: if system refused it before it began, the watch's
 * answer says so, and if a later watch dropped it before it began, the
 * watch is answered all the same; if it ended later, and the watch did
 * not drop it, a notice says so
 */
static void
config_follow_end(struct request *r, int32_t status)
{
	struct session	*sp;

	if ((sp = session_find(r->session)) == NULL)
		return;
	if (r->started) {
		if (!r->stopped)
			config_notice_to(sp->id, NSHD_NOTICE_LOGEND, 0, r->n,
			    NULL, 0);
		return;
	}
	/* refused, or stopped before system began it */
	if (!r->stopped)
		sp->watchr = 1;
	if (--sp->starting == 0)
		config_answer(sp->id, sp->watchr, NULL);
}

/*
 * A notice of kind, about uid and n, with text, if not NULL, to each
 * session that watches what. A session that sees no password hash gets
 * the text with each taken out, as a configure terminal line may hold one
 */
static void
config_notice(int what, int kind, uid_t uid, int n, const char *text)
{
	struct session		*sp;
	char			 hidden[NSHD_COMMENT];
	size_t			 len, hlen = 0;

	len = text == NULL ? 0 : strnlen(text, NSHD_COMMENT - 1);
	if (text != NULL) {
		memcpy(hidden, text, len);
		hlen = login_hide(hidden, len);
	}
	TAILQ_FOREACH(sp, &sessions, entry)
		if ((sp->watch & what) != 0)
			config_notice_to(sp->id, kind, uid, n,
			    config_hides(sp) ? hidden : text,
			    config_hides(sp) ? hlen : len);
}

/* a notice of kind, about uid and n, with len of text, to session */
static void
config_notice_to(uint32_t session, int kind, uid_t uid, int n,
    const char *text, size_t len)
{
	struct nshd_notice	 nt;
	char			 buf[sizeof(nt) + NSHD_TEXT];

	memset(&nt, 0, sizeof(nt));
	nt.kind = kind;
	nt.uid = uid;
	nt.n = n;
	memcpy(buf, &nt, sizeof(nt));
	if (len > NSHD_TEXT)
		len = NSHD_TEXT;
	if (len > 0)
		memcpy(buf + sizeof(nt), text, len);
	if (front_compose(session, IMSG_CTL_NOTICE, buf,
	    sizeof(nt) + len) == -1)
		fatal("%s", __func__);
}

/*
 * What the routing socket says changed, kept until the next second's
 * notices: interfaces and addresses, and each rtable's routes, or every
 * rtable's, if the kernel had more than the socket could take
 */
static void
config_route(int fd, short event, void *arg)
{
	struct rt_msghdr	 rtm;
	struct timeval		 tv = { 1, 0 };
	char			 buf[2048];
	ssize_t			 n;

	for (;;) {
		if ((n = read(fd, buf, sizeof(buf))) == -1) {
			if (errno == EAGAIN || errno == EINTR)
				break;
			if (errno != ENOBUFS)
				fatal("%s: read", __func__);
			rt_links = rt_all = 1;
			continue;
		}
		if (n == 0)
			break;
		/* the header every kind of message begins with */
		if (n < (ssize_t)offsetof(struct rt_msghdr, rtm_tableid) +
		    (ssize_t)sizeof(rtm.rtm_tableid))
			continue;
		memset(&rtm, 0, sizeof(rtm));
		memcpy(&rtm, buf, (size_t)n < sizeof(rtm) ? (size_t)n :
		    sizeof(rtm));
		if (rtm.rtm_version != RTM_VERSION)
			continue;
		switch (rtm.rtm_type) {
		case RTM_IFINFO:
		case RTM_IFANNOUNCE:
		case RTM_NEWADDR:
		case RTM_DELADDR:
		case RTM_CHGADDRATTR:
			rt_links = 1;
			break;
		case RTM_ADD:
		case RTM_DELETE:
		case RTM_CHANGE:
			if (rtm.rtm_tableid <= RT_TABLEID_MAX)
				rt_tables[rtm.rtm_tableid] = 1;
			break;
		default:
			continue;
		}
	}
	if ((rt_links || rt_all || memchr(rt_tables, 1,
	    sizeof(rt_tables)) != NULL) && !evtimer_pending(&rt_tm, NULL))
		evtimer_add(&rt_tm, &tv);
}

/* the notices of what changed in the last second */
static void
config_routed(int fd, short event, void *arg)
{
	int	 i;

	if (rt_links)
		config_notice(NSHD_WATCH_ROUTING, NSHD_NOTICE_LINKS, 0, 0,
		    NULL);
	if (rt_all)
		config_notice(NSHD_WATCH_ROUTING, NSHD_NOTICE_ROUTES, 0, -1,
		    NULL);
	else
		for (i = 0; i <= RT_TABLEID_MAX; i++)
			if (rt_tables[i])
				config_notice(NSHD_WATCH_ROUTING,
				    NSHD_NOTICE_ROUTES, 0, i, NULL);
	rt_links = rt_all = 0;
	memset(rt_tables, 0, sizeof(rt_tables));
}

/* the session, if in configure; or NULL, after saying why */
static struct session *
config_private(uint32_t session)
{
	struct session	*sp;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return (NULL);
	}
	if (!config_in(sp)) {
		config_answer(session, 1, "%% nshd: configure first\n");
		return (NULL);
	}
	return (sp);
}

/*
 * configure terminal's line, run on a candidate reset to the running
 * configuration. If the line changes the candidate, it is committed, not
 * saved, and answered once the commit ends. 1 if it is committed, else as
 * a handler returns
 */
static int
config_terminal(struct session *sp)
{
	int	 r;

	if (commit != NULL) {
		printf("%% Refused: uid %u commits now\n",
		    (unsigned int)commit->uid);
		return (-1);
	}
	if (exclusive != NULL) {
		printf("%% Refused: uid %u has configure exclusive\n",
		    (unsigned int)exclusive->uid);
		return (-1);
	}
	if (session_renew(sp->st) == -1)
		return (-1);
	r = session_line(sp->st, sp->line);
	if (!session_changed(sp->st))
		return (r);
	commit_new(sp);
	commit->terminal = 1;
	commit->line = r;
	/* what its notice says */
	strlcpy(commit->comment, sp->line, sizeof(commit->comment));
	/* planned from the snapshot the line ran on */
	commit->step = COMMIT_PLAN;
	commit->waits = 1;
	return (1);
}

/*
 * a part of nsh -c's configuration, kept and answered; after the last,
 * once a snapshot is in, the configuration is loaded and committed
 */
static void
config_load(uint32_t session, struct nshd_load *l)
{
	struct session	*sp;
	char		*p;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if (config_in(sp)) {
		config_answer(session, 1, "%% nshd: a configuration is loaded "
		    "outside configure\n");
		return;
	}
	if ((size_t)l->len > NSHD_PART - sp->loadlen) {
		free(sp->load);
		sp->load = NULL;
		sp->loadlen = 0;
		config_answer(session, 1, "%% nshd: a configuration past %d "
		    "bytes\n", NSHD_PART);
		return;
	}
	if (l->len > 0) {
		if ((p = realloc(sp->load, sp->loadlen + l->len)) == NULL)
			fatal("%s", __func__);
		memcpy(p + sp->loadlen, l->text, l->len);
		sp->load = p;
		sp->loadlen += l->len;
	}
	if (!l->last) {
		config_answer(session, 0, NULL);
		return;
	}
	strlcpy(sp->loaded, l->comment, sizeof(sp->loaded));
	config_wait(sp, WAIT_LOAD);
}

/*
 * A daemon's rules in the session's candidate, in an rtable: printed when
 * asked for; or kept and answered a part at a time, and set with the last
 * part, as the daemon's edit sets them
 */
static void
config_rules(uint32_t session, struct nshd_rules *rl)
{
	struct session	*sp;
	char		*p;
	int		 r;

	if ((sp = config_private(session)) == NULL)
		return;
	if (sp->how == NSHD_TERMINAL) {
		rules_drop(sp);
		config_answer(session, 1, "%% configure terminal sets no "
		    "daemon's rules; configure private does\n");
		return;
	}
	if (rl->set) {
		if (sp->rulesof[0] == '\0') {
			strlcpy(sp->rulesof, rl->daemon, sizeof(sp->rulesof));
			sp->rulesrt = rl->rtable;
		}
		if (strcmp(sp->rulesof, rl->daemon) != 0 ||
		    sp->rulesrt != rl->rtable) {
			rules_drop(sp);
			config_answer(session, 1, "%% nshd: a part of other "
			    "rules came before the last of these\n");
			return;
		}
		if ((size_t)rl->len > NSHD_RULES - sp->ruleslen ||
		    memchr(rl->text, '\0', rl->len) != NULL) {
			rules_drop(sp);
			config_answer(session, 1, "%% nshd: a daemon's rules "
			    "are text, at most %d bytes\n", NSHD_RULES);
			return;
		}
		if (rl->len > 0) {
			if ((p = realloc(sp->rules, sp->ruleslen + rl->len)) ==
			    NULL)
				fatal("%s", __func__);
			memcpy(p + sp->ruleslen, rl->text, rl->len);
			sp->rules = p;
			sp->ruleslen += rl->len;
		}
		if (!rl->last) {
			config_answer(session, 0, NULL);
			return;
		}
	}
	shared_hold(sp);
	r = session_rules(sp->st, rl->daemon, rl->rtable, rl->set, sp->rules,
	    sp->ruleslen);
	shared_done(sp);
	rules_drop(sp);
	config_ran(sp, r, 0);
}

/* the parts of a daemon's rules the session sent, dropped */
static void
rules_drop(struct session *sp)
{
	free(sp->rules);
	sp->rules = NULL;
	sp->ruleslen = 0;
	sp->rulesof[0] = '\0';
}

/*
 * nsh -c's configuration, as a candidate of its own in place of the
 * running configuration. If it differs, it is committed, all of it or
 * none, and answered once the commit ends. 1 if it is committed, else as
 * a handler returns
 */
static int
config_loaded(struct session *sp)
{
	int	 r = -1;

	if (commit != NULL)
		printf("%% Refused: uid %u commits now\n",
		    (unsigned int)commit->uid);
	else if (exclusive != NULL)
		printf("%% Refused: uid %u has configure exclusive\n",
		    (unsigned int)exclusive->uid);
	else {
		if (sp->st == NULL && (sp->st = session_new()) == NULL)
			fatal("%s", __func__);
		if ((r = session_configure(sp->st, NULL)) == 0 &&
		    (r = session_load(sp->st, sp->load, sp->loadlen)) == 0 &&
		    session_changed(sp->st)) {
			commit_new(sp);
			commit->load = 1;
			strlcpy(commit->comment, sp->loaded,
			    sizeof(commit->comment));
			/* planned from the snapshot it was loaded on */
			commit->step = COMMIT_PLAN;
			commit->waits = 1;
			r = 1;
		} else if (r == -1)
			printf("%% Nothing is committed\n");
	}
	free(sp->load);
	sp->load = NULL;
	sp->loadlen = 0;
	if (r != 1) {
		session_free(sp->st);
		sp->st = NULL;
	}
	return (r);
}

/* whether sp is in configure */
static int
config_in(struct session *sp)
{
	char	ifn[NSHD_IFNAME];
	int	in = 0, rtable, bridge;

	if (sp->st != NULL)
		session_mode(sp->st, &in, &rtable, ifn, sizeof(ifn), &bridge);
	return (in);
}

/*
 * sp into the configure it asked for, if it may: each but configure
 * private is refused while another has configure exclusive, and configure
 * exclusive while another user's changes to the shared candidate are not
 * committed. As a handler returns
 */
static int
config_enter(struct session *sp)
{
	int	 r;

	if (sp->want != NSHD_PRIVATE && exclusive != NULL &&
	    exclusive != sp) {
		printf("%% Configure refused: uid %u has configure "
		    "exclusive\n", (unsigned int)exclusive->uid);
		return (-1);
	}
	if (sp->want == NSHD_EXCLUSIVE && editors_say(sp->uid,
	    "Configure exclusive refused: changes to the shared candidate "
	    "not committed") > 0)
		return (-1);
	r = session_configure(sp->st, sp->want == NSHD_PRIVATE ||
	    sp->want == NSHD_TERMINAL ? NULL : shared);
	if (r == 0) {
		sp->how = sp->want;
		if (sp->how == NSHD_EXCLUSIVE) {
			exclusive = sp;
			config_notice(NSHD_WATCH_COMMITS, NSHD_NOTICE_LOCK,
			    sp->uid, 0, NULL);
		}
	}
	return (r);
}

/*
 * sp left configure: if it had configure exclusive, the shared
 * candidate's uncommitted changes are discarded
 */
static void
config_left(struct session *sp)
{
	int	 how = sp->how;

	sp->how = 0;
	rules_drop(sp);
	if (how != NSHD_EXCLUSIVE)
		return;
	exclusive = NULL;
	config_notice(NSHD_WATCH_COMMITS, NSHD_NOTICE_UNLOCK, sp->uid, 0,
	    NULL);
	if (!cand_shared_changed(shared) || cand_shared_renew(shared) == -1)
		return;
	neditors = 0;
	printf("%% Uncommitted changes discarded\n");
	sp->keep = shared_keep();
}

/*
 * Before sp runs what may change its candidate: if that is the shared
 * one, and another session holds it, nsh's code changes nothing
 */
static void
shared_hold(struct session *sp)
{
	if (sp->how != NSHD_SHARED && sp->how != NSHD_EXCLUSIVE)
		return;
	if (exclusive != NULL && exclusive != sp)
		snprintf(held, sizeof(held), "Refused: uid %u has configure "
		    "exclusive", (unsigned int)exclusive->uid);
	else if (commit != NULL && commit->shared)
		snprintf(held, sizeof(held), "Refused: uid %u commits the "
		    "shared candidate", (unsigned int)commit->uid);
	else {
		shared_edits = cand_shared_edits(shared);
		return;
	}
	sp->st->held = held;
}

/*
 * After: if sp changed the shared candidate, sp's user is added to who
 * did, and the candidate is kept before sp is answered
 */
static void
shared_done(struct session *sp)
{
	uid_t	*e;
	size_t	 i;

	if (sp->st != NULL && sp->st->held != NULL) {
		sp->st->held = NULL;
		return;
	}
	if ((sp->how != NSHD_SHARED && sp->how != NSHD_EXCLUSIVE) ||
	    cand_shared_edits(shared) == shared_edits)
		return;
	if (!cand_shared_changed(shared))
		neditors = 0;
	else {
		for (i = 0; i < neditors && editors[i] != sp->uid; i++)
			;
		if (i == neditors) {
			if ((e = reallocarray(editors, neditors + 1,
			    sizeof(*e))) == NULL)
				fatal(NULL);
			editors = e;
			editors[neditors++] = sp->uid;
		}
	}
	sp->keep = shared_keep();
}

/*
 * Say what, followed by the users other than uid who changed the shared
 * candidate, if there are any; returns how many
 */
static size_t
editors_say(uid_t uid, const char *what)
{
	size_t	 i, n = 0;

	for (i = 0; i < neditors; i++) {
		if (editors[i] == uid)
			continue;
		if (n++ == 0)
			printf("%% %s, by", what);
		else
			printf(",");
		printf(" uid %u", (unsigned int)editors[i]);
	}
	if (n > 0)
		printf("\n");
	return (n);
}

/*
 * The shared candidate changed: send it, and who changed it, to archive
 * to keep. Returns its KEEP's number, or 0 after saying why it could not
 * be sent
 */
static uint32_t
shared_keep(void)
{
	uint32_t	 seq = keep_sent + 1;

	if (seq == 0)
		seq = 1;
	if (shared_send(seq) == -1) {
		printf("%% nshd: the shared candidate could not be kept\n");
		return (0);
	}
	keep_sent = seq;
	return (seq);
}

/*
 * Send archive the shared candidate to keep as KEEP seq, after a line of
 * "editors" and the uid of each user who changed it. Returns -1, and logs
 * why, if it could not be sent
 */
static int
shared_send(uint32_t seq)
{
	struct nshd_keep	 k = { seq, 0 };
	FILE			*f;
	char			*buf = NULL;
	size_t			 len = 0, i, n;
	int			 r;

	if ((f = open_memstream(&buf, &len)) == NULL) {
		log_warn("%s", __func__);
		return (-1);
	}
	r = fprintf(f, "editors") < 0 ? -1 : 0;
	for (i = 0; i < neditors && r == 0; i++)
		if (fprintf(f, " %u", (unsigned int)editors[i]) < 0)
			r = -1;
	if (r == 0 && (fprintf(f, "\n") < 0 ||
	    cand_shared_write(shared, f) == -1))
		r = -1;
	if (fclose(f) == EOF || r == -1 || len > NSHD_KEEPMAX) {
		log_warnx("%s: the shared candidate could not be written",
		    __func__);
		free(buf);
		return (-1);
	}
	for (i = 0; i < len; i += n) {
		n = len - i < NSHD_TEXT ? len - i : NSHD_TEXT;
		if (link_compose(&links[ARCHIVE], IMSG_ARC_TEXT, 0, buf + i,
		    n) == -1)
			fatal("%s", __func__);
	}
	free(buf);
	if (link_compose(&links[ARCHIVE], IMSG_ARC_KEEP, 0, &k,
	    sizeof(k)) == -1)
		fatal("%s", __func__);
	return (0);
}

/*
 * archive answered each KEEP up to seq, with warn if it did not keep
 * them: each session that waited on one is answered, after warn
 */
static void
shared_kept(uint32_t seq, const char *warn)
{
	struct session	*sp;

	keep_done = seq;
	TAILQ_FOREACH(sp, &sessions, entry) {
		if (sp->keep == 0 || (int32_t)(sp->keep - seq) > 0)
			continue;
		sp->keep = 0;
		if (warn != NULL && front_text(sp->id, warn,
		    strlen(warn)) == -1)
			fatal("%s", __func__);
		config_reply(sp, &sp->held, sp->heldr, sp->heldmode);
	}
}

/*
 * What archive kept, taken as the shared candidate and who changed it,
 * if it is one; then the sessions that wait may enter configure
 */
static void
shared_load(void)
{
	struct session	*sp;
	uid_t		*e;
	char		*nl, *p, *q;
	unsigned long	 u;

	keep_loaded = 1;
	if (loading_len > 0 && !loading_past) {
		if ((nl = memchr(loading, '\n', loading_len)) == NULL ||
		    strncmp(loading, "editors", 7) != 0)
			goto bad;
		*nl = '\0';
		for (p = loading + 7; *p != '\0'; p = q) {
			if (*p++ != ' ' || *p < '0' || *p > '9')
				goto bad;
			errno = 0;
			u = strtoul(p, &q, 10);
			if (errno != 0 || (uid_t)u != u || (*q != ' ' &&
			    *q != '\0') || (*p == '0' && q - p > 1))
				goto bad;
			if ((e = reallocarray(editors, neditors + 1,
			    sizeof(*e))) == NULL)
				fatal(NULL);
			editors = e;
			editors[neditors++] = u;
		}
		if (cand_shared_read(shared, nl + 1,
		    loading_len - (nl + 1 - loading)) == -1)
			goto bad;
	}
	goto done;
 bad:
	log_warnx("what archive kept is not a shared candidate");
	neditors = 0;
 done:
	/* discard what nsh's code printed, such as why the text was bad */
	printed_text(NULL, 0, 0, 0);
	free(loading);
	loading = NULL;
	loading_len = 0;
	loading_past = 0;
	TAILQ_FOREACH(sp, &sessions, entry)
		if (sp->waits == WAIT_CONFIGURE) {
			snapshot_take();
			break;
		}
}

/* sp waits on a snapshot for what, which runs when it is in */
static void
config_wait(struct session *sp, int what)
{
	sp->waits = what;
	snapshot_take();
}

/*
 * A snapshot, for the sessions and the commit that wait on it, unless
 * system makes one already, which will do; if none can be, they are told
 */
static void
snapshot_take(void)
{
	struct nshd_snapshot	 ns = { 1 };
	struct request		*r;

	if (snap != NULL)
		return;
	if ((r = config_request(0, REQ_ANSWER)) == NULL) {
		config_snapshot_lost(REQ_REFUSED);
		return;
	}
	if ((snap = calloc(1, sizeof(*snap))) == NULL ||
	    (snap->kf = calloc(1, sizeof(*snap->kf))) == NULL)
		fatal("%s", __func__);
	snap->id = r->id;
	facts_in_init(&snap->in, kfacts_record, snap->kf);
	if (link_compose(&links[SYSTEM], IMSG_SYS_SNAPSHOT, r->id, &ns,
	    sizeof(ns)) == -1)
		fatal("%s", __func__);
}

/* a snapshot's text or facts, kept as they come */
static void
config_snapshot(struct request *r, uint32_t type, struct ibuf *b)
{
	char	*p;

	if (snap->bad)
		return;
	if (type == IMSG_SYS_FACTS) {
		if (facts_read(&snap->in, ibuf_data(b), ibuf_size(b)) == -1)
			snap->bad = 1;
		return;
	}
	if (ibuf_size(b) > SNAPSHOT_TEXT - snap->len) {
		snap->bad = 1;
		return;
	}
	if ((p = realloc(snap->text, snap->len + ibuf_size(b))) == NULL)
		fatal("%s", __func__);
	snap->text = p;
	memcpy(snap->text + snap->len, ibuf_data(b), ibuf_size(b));
	snap->len += ibuf_size(b);
}

/* the snapshot is in, or not: run what each session waits on it for */
static void
config_snapshot_done(int32_t status)
{
	struct session	*sp;
	struct snapshot	*s = snap;
	int		 r, mode;

	snap = NULL;
	facts_in_free(&s->in);
	if (status != 0 || s->bad || s->kf->failed ||
	    session_running(s->text, s->len) == -1) {
		printed_text(NULL, 0, 0, 0);
		kfacts_free(s->kf);
		free(s->text);
		free(s);
		config_snapshot_lost("% nshd: the running configuration "
		    "could not be read\n");
		return;
	}
	kfacts_set(s->kf);
	kfacts_free(kf_now);
	kf_now = s->kf;
	free(s->text);
	free(s);
	TAILQ_FOREACH(sp, &sessions, entry) {
		switch (sp->waits) {
		case WAIT_CONFIGURE:
			/* the shared candidate, once what archive kept is in */
			if (sp->want != NSHD_PRIVATE && !keep_loaded)
				continue;
			r = config_enter(sp);
			mode = 1;
			break;
		case WAIT_CANDIDATE:
			r = session_candidate(sp->st);
			mode = 0;
			break;
		case WAIT_DIFF:
			r = session_diff(sp->st);
			mode = 0;
			break;
		case WAIT_RESET:
			shared_hold(sp);
			r = session_rollback(sp->st, NULL, 0, 0);
			shared_done(sp);
			mode = 1;
			break;
		case WAIT_TERMINAL:
			/* if a commit started, answer when it ends */
			if ((r = config_terminal(sp)) == 1) {
				sp->waits = WAIT_NONE;
				continue;
			}
			mode = 1;
			break;
		case WAIT_LOAD:
			if ((r = config_loaded(sp)) == 1) {
				sp->waits = WAIT_NONE;
				continue;
			}
			mode = 1;
			break;
		case WAIT_NAMES:
			sp->waits = WAIT_NONE;
			config_named(sp);
			continue;
		default:
			continue;
		}
		sp->waits = WAIT_NONE;
		config_ran(sp, r, mode);
	}
	if (commit != NULL && commit->waits)
		commit_snapshot();
}

/* the snapshot sessions waited on is lost, as msg says */
static void
config_snapshot_lost(const char *msg)
{
	struct session	*sp;

	TAILQ_FOREACH(sp, &sessions, entry)
		if (sp->waits != WAIT_NONE) {
			sp->waits = WAIT_NONE;
			config_answer(sp->id, 1, "%s", msg);
		}
	if (commit != NULL && commit->waits)
		commit_end(-1, msg);
}

/*
 * What nsh's code printed for sp, its context if mode is set, and r, as a
 * handler returns it: 0, or -1 when it failed
 */
static void
config_ran(struct session *sp, int r, int mode)
{
	struct nshd_context	 c;
	int			 in, rtable, bridge;

	memset(&c, 0, sizeof(c));
	if (sp->st != NULL) {
		session_mode(sp->st, &in, &rtable, c.ifname,
		    sizeof(c.ifname), &bridge);
		if (!in && sp->how != 0)
			config_left(sp);
		c.mode = in ? sp->how : 0;
		c.rtable = rtable;
		c.bridge = bridge;
	}
	if (front_printed(sp->id) == -1)
		r = -1;
	/* a change to the shared candidate is answered once it is kept */
	if (sp->keep != 0 && (int32_t)(sp->keep - keep_done) > 0) {
		sp->held = c;
		sp->heldmode = mode;
		sp->heldr = r;
		return;
	}
	sp->keep = 0;
	config_reply(sp, &c, r, mode);
}

/* sp's answer: its context c, if mode, and r, as a handler returns it */
static void
config_reply(struct session *sp, struct nshd_context *c, int r, int mode)
{
	if (mode && front_compose(sp->id, IMSG_CTL_CONTEXT, c,
	    sizeof(*c)) == -1)
		fatal("%s", __func__);
	config_answer(sp->id, r == -1 ? -1 : 0, NULL);
}

/* the commit waits on a snapshot, at step */
static void
commit_wait(int step)
{
	commit->step = step;
	commit->waits = 1;
	snapshot_take();
}

/* the snapshot the commit waited on is in: its next step */
static void
commit_snapshot(void)
{
	struct session		*sp;

	commit->waits = 0;
	switch (commit->step) {
	case COMMIT_PLAN:
		if ((sp = session_find(commit->session)) == NULL ||
		    session_plan(sp->st, commit->check, commit->minutes > 0,
		    &commit->plan) == -1)
			commit_end(-1, NULL);
		else if (commit->plan == NULL)
			commit_end(0, NULL);
		else
			commit_go();
		break;
	case COMMIT_RAN:
		/* how system ended the commit */
		if (commit->ran == NSHD_SAVED || commit->ran == NSHD_UNSAVED)
			commit_saved(commit->ran == NSHD_SAVED);
		else if (commit->ran == NSHD_KEPT) {
			config_notice(NSHD_WATCH_COMMITS,
			    NSHD_NOTICE_CONFIRMED, commit->uid,
			    commit->minutes, NULL);
			printf("%% Commit within %d minute%s to keep this, or "
			    "it is rolled back\n", commit->minutes,
			    commit->minutes == 1 ? "" : "s");
			commit_end(commit_renew(), NULL);
		} else if (commit->ran == NSHD_APPLIED) {
			config_notice(NSHD_WATCH_COMMITS, NSHD_NOTICE_APPLIED,
			    commit->uid, 0, commit->comment);
			commit_end(0, NULL);
		} else
			commit_end(-1, NULL);
		break;
	}
}

/* system ended the commit's request: its next step */
static void
commit_ended(int32_t status)
{
	switch (commit->step) {
	case COMMIT_BEGIN:
		/*
		 * One not begun was refused, or only tested, and system said
		 * the verdict; one begun has its candidate start from the
		 * snapshot
		 */
		if (!commit->begun)
			commit_end(status == 0 ? 0 : -1, NULL);
		else {
			commit->ran = status;
			commit_wait(COMMIT_RAN);
		}
		break;
	case COMMIT_SAVE:
		commit_saved(status == 0);
		break;
	}
}

/*
 * The plan checked. For commit check, and for a commit with problems
 * already, system only runs the tests. Otherwise, save if nothing
 * changes, else begin the commit
 */
static void
commit_go(void)
{
	struct plan		*p = commit->plan;
	struct nshd_begin	 b;
	struct session		*sp;

	/*
	 * A commit is begun only while its session is there, as its
	 * permissions are the session's
	 */
	if ((sp = session_find(commit->session)) == NULL) {
		commit_end(-1, NULL);
		return;
	}
	memset(&b, 0, sizeof(b));
	b.whose = commit->whose;
	b.checking = p->checking;
	b.bad = p->bad;
	if (p->checking || p->bad > 0) {
		commit_request(COMMIT_BEGIN, IMSG_SYS_BEGIN, &b, sizeof(b));
		return;
	}
	if (p->same && commit->minutes == 0) {
		if (commit->terminal)
			commit_end(0, NULL);
		else
			commit_save();
		return;
	}
	/*
	 * Before its script, a commit that changes login users or classes
	 * lowers the permissions of the sessions that would lose one
	 * (front_revoke()).
	 * system refuses the change from a session without admin as the
	 * script runs, so refuse it now, before system has any part of it,
	 * or such a session could lower others'
	 */
	commit->logins = session_logins(p);
	if (commit->logins && (sp->perms & NSHD_ADMIN) == 0) {
		commit_end(-1, "% Commit refused: changing login classes and "
		    "users needs the admin permission\n");
		return;
	}
	if (commit_part(NSHD_SCRIPT, p->text[PLAN_EDITS],
	    p->len[PLAN_EDITS]) == -1 || commit_part(NSHD_BEFORE,
	    p->text[PLAN_BEFORE], p->len[PLAN_BEFORE]) == -1 ||
	    commit_part(NSHD_WANT, p->text[PLAN_WANT],
	    p->len[PLAN_WANT]) == -1)
		return;
	b.minutes = commit->minutes;
	b.unsaved = commit->terminal;
	strlcpy(b.comment, commit->comment, sizeof(b.comment));
	plan_clears(commit->plan, &b.apply);
	commit_request(COMMIT_BEGIN, IMSG_SYS_BEGIN, &b, sizeof(b));
}

/* a commit part, to system in chunks; -1 if too long, and the commit ends */
static int
commit_part(int32_t part, const char *text, size_t len)
{
	struct nshd_chunk	 c = { part };
	char			 buf[sizeof(c) + NSHD_TEXT];
	size_t			 n;

	if (len > NSHD_PART) {
		commit_end(-1, "% Commit refused: the configuration is past "
		    "what nshd takes\n");
		return (-1);
	}
	memcpy(buf, &c, sizeof(c));
	while (len > 0) {
		n = len < NSHD_TEXT ? len : NSHD_TEXT;
		memcpy(buf + sizeof(c), text, n);
		if (link_compose(&links[SYSTEM], IMSG_SYS_SCRIPT, 0, buf,
		    sizeof(c) + n) == -1)
			fatal("%s", __func__);
		text += n;
		len -= n;
	}
	return (0);
}

/* the running configuration, saved by system with the commit's comment */
static void
commit_save(void)
{
	struct nshd_save	 sv;

	memset(&sv, 0, sizeof(sv));
	sv.whose = commit->whose;
	strlcpy(sv.comment, commit->comment, sizeof(sv.comment));
	commit_request(COMMIT_SAVE, IMSG_SYS_SAVE, &sv, sizeof(sv));
}

/*
 * The commit saved the running configuration, if ok: its candidate
 * starts again either way
 */
static void
commit_saved(int ok)
{
	int	 r = ok ? 0 : -1;

	if (ok)
		config_notice(NSHD_WATCH_COMMITS, NSHD_NOTICE_COMMIT,
		    commit->uid, 0, commit->comment);
	if (!commit->save && !commit->load && commit_renew() == -1)
		r = -1;
	commit_end(r, NULL);
}

/*
 * The commit of session sp, which system begins only while the request
 * frontend told it of is not answered
 */
static void
commit_new(struct session *sp)
{
	if ((commit = calloc(1, sizeof(*commit))) == NULL)
		fatal(NULL);
	commit->session = sp->id;
	commit->uid = sp->uid;
	commit->whose.session = sp->id;
}

/*
 * A request for the commit, sent to system after what nsh's code printed
 * for it; the commit waits at step for it to end
 */
static void
commit_request(int step, uint32_t type, const void *data, size_t len)
{
	struct request	*r;

	front_printed(commit->session);
	if ((r = config_request(commit->session, REQ_COMMIT)) == NULL) {
		commit_end(-1, REQ_REFUSED);
		return;
	}
	commit->step = step;
	/* BEGIN runs the plan's tests first */
	if (type == IMSG_SYS_BEGIN)
		commit_tests(r->id);
	if (link_compose(&links[SYSTEM], type, r->id, data, len) == -1)
		fatal("%s", __func__);
}

/*
 * The plan's tests of daemons' rules, for request id, each its rules
 * and TEST, which system runs in turn. Rules are at most NSHD_RULES
 * bytes, so each fits in a part
 */
static void
commit_tests(uint32_t id)
{
	struct plan_test	*t;
	struct nshd_test	 nt;
	int			 i;

	for (i = 0; i < commit->plan->ntests; i++) {
		t = &commit->plan->tests[i];
		memset(&nt, 0, sizeof(nt));
		nt.whose = commit->whose;
		strlcpy(nt.name, t->name, sizeof(nt.name));
		commit_part(NSHD_TEST, t->text, t->len);
		if (link_compose(&links[SYSTEM], IMSG_SYS_TEST, id, &nt,
		    sizeof(nt)) == -1)
			fatal("%s", __func__);
	}
}

/*
 * The commit ends, with r as a handler returns it, or with msg, said
 * after what nsh's code printed for it
 */
static void
commit_end(int r, const char *msg)
{
	struct commit		*c = commit;
	struct session		*sp;

	commit = NULL;
	sp = session_find(c->session);
	/* configure terminal's candidate is the running configuration again */
	if (c->terminal && sp != NULL && session_renew(sp->st) == -1)
		r = -1;
	if (c->terminal && c->line == -1)
		r = -1;
	/* nsh -c's candidate goes with it */
	if (c->load && sp != NULL) {
		session_free(sp->st);
		sp->st = NULL;
	}
	if (sp == NULL)
		printed_text(NULL, 0, 0, 0);
	else if (msg != NULL) {
		front_printed(sp->id);
		config_answer(sp->id, 1, "%s", msg);
	} else
		config_ran(sp, r, 1);
	plan_free(c->plan);
	free(c);
}

/* the commit's candidate starts again: -1, after saying why, if not */
static int
commit_renew(void)
{
	struct session	*sp;

	if (commit->shared) {
		if (cand_shared_renew(shared) == -1)
			return (-1);
		neditors = 0;
		if ((sp = session_find(commit->session)) != NULL)
			sp->keep = shared_keep();
		else
			shared_keep();
		return (0);
	}
	if ((sp = session_find(commit->session)) != NULL)
		return (session_renew(sp->st));
	return (0);
}

/* to session, a line of output if fmt, and the result status */
static void
config_answer(uint32_t session, int32_t status, const char *fmt, ...)
{
	struct nshd_result	 r;
	va_list			 ap;
	char			*s;
	int			 len;

	if (fmt != NULL) {
		va_start(ap, fmt);
		len = vasprintf(&s, fmt, ap);
		va_end(ap);
		if (len == -1)
			fatal("%s", __func__);
		if (front_text(session, s, len) == -1)
			fatal("%s", __func__);
		free(s);
	}
	r.status = status;
	if (front_compose(session, IMSG_CTL_RESULT, &r,
	    sizeof(r)) == -1)
		fatal("%s", __func__);
}

/* archive's answers: what it kept, for config to take, or whether it kept */
static void
config_dispatch_archive(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct link		*l = &links[ARCHIVE];
	struct imsg		 imsg;
	struct ibuf		 b;
	struct nshd_keep	 k;
	struct nshd_result	 res;
	uint32_t		 type;
	int			 n;
	char			*p;

	if (imsgev_io(iev, event) == -1) {
		link_broken(l, "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			link_broken(l, "sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		switch (type = imsg_get_type(&imsg)) {
		case IMSG_ARC_TEXT:
			if (keep_loaded || imsg_get_ibuf(&imsg, &b) == -1)
				goto bad;
			if (ibuf_size(&b) > NSHD_KEEPMAX - loading_len) {
				loading_past = 1;
				break;
			}
			if ((p = realloc(loading, loading_len +
			    ibuf_size(&b))) == NULL)
				fatal("%s", __func__);
			loading = p;
			memcpy(loading + loading_len, ibuf_data(&b),
			    ibuf_size(&b));
			loading_len += ibuf_size(&b);
			break;
		case IMSG_ARC_LOADED:
			if (keep_loaded ||
			    imsg_get_data(&imsg, &res, sizeof(res)) == -1)
				goto bad;
			if (res.status != 0)
				loading_past = 1;
			shared_load();
			break;
		case IMSG_ARC_KEPT:
			if (imsg_get_data(&imsg, &k, sizeof(k)) == -1 ||
			    (int32_t)(k.seq - keep_done) <= 0 ||
			    (int32_t)(k.seq - keep_sent) > 0)
				goto bad;
			shared_kept(k.seq, k.status == 0 ? NULL :
			    "% nshd: archive did not keep the shared candidate\n");
			break;
		default:
			goto bad;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
	return;
 bad:
	imsg_free(&imsg);
	link_broken(l, "sent imsg %u, which it may not, or not whole", type);
}

/* archive's pipe is here: ask for what it kept */
static void
config_ready_archive(void)
{
	if (link_compose(&links[ARCHIVE], IMSG_ARC_LOAD, 0, NULL, 0) == -1)
		fatal("%s", __func__);
}

/*
 * to system: type, for each request of session not finished, but a
 * commit's: once system has begun a commit, it runs to its end
 */
static void
config_tell(uint32_t session, uint32_t type)
{
	struct request	*r;

	TAILQ_FOREACH(r, &requests, entry)
		if (r->session == session && r->kind != REQ_COMMIT &&
		    link_compose(&links[SYSTEM], type, r->id, NULL, 0) == -1)
			fatal("%s", __func__);
}

/*
 * to system: READ, for each request of session that system has sent
 * output for since the last, so a frontend's READs cannot multiply
 */
static void
config_read(uint32_t session)
{
	struct request	*r;

	TAILQ_FOREACH(r, &requests, entry)
		if (r->session == session && r->unread) {
			r->unread = 0;
			if (link_compose(&links[SYSTEM], IMSG_SYS_READ, r->id,
			    NULL, 0) == -1)
				fatal("%s", __func__);
		}
}

/*
 * A request of kind for session, or for config itself if 0, with an id of
 * its own; NULL when the ids are exhausted, when the session has
 * FRONT_REQUESTS requests unfinished, or when all sessions have
 * ALL_REQUESTS. A request counts until system ends it, even once its
 * session is gone, so a new session does not make room for more. A
 * client asks one request at a time, and watches four logs at most, so a
 * frontend that asks FRONT_REQUESTS speaks for no client, and its session
 * goes. A commit's steps are config's, so they are neither counted nor
 * refused. A session's permissions are not refused either: a session asks
 * them once, at its hello, and system answers at once
 */
static struct request *
config_request(uint32_t session, int kind)
{
	static int	 full;
	struct request	*r;
	struct front	*f;
	struct timeval	 now = { 0, 0 };
	int		 n = 0, all = 0;

	if (request_id == UINT32_MAX)
		return (NULL);
	if (session != 0 && kind != REQ_COMMIT && kind != REQ_PERMS) {
		TAILQ_FOREACH(r, &requests, entry)
			if (r->session != 0 && r->kind != REQ_COMMIT) {
				all++;
				if (r->session == session)
					n++;
			}
		if (n >= FRONT_REQUESTS) {
			if ((f = front_find(session)) != NULL && !f->dropped) {
				log_warnx("session %u: its frontend asks too "
				    "much at once", session);
				f->dropped = 1;
				evtimer_add(&front_tm, &now);
			}
			return (NULL);
		}
		if (all >= ALL_REQUESTS) {
			if (!full)
				log_warnx("%d requests unfinished: others "
				    "refused until system ends some", all);
			full = 1;
			return (NULL);
		}
		full = 0;
	}
	if ((r = calloc(1, sizeof(*r))) == NULL)
		fatal(NULL);
	r->id = ++request_id;
	r->session = session;
	r->kind = kind;
	TAILQ_INSERT_TAIL(&requests, r, entry);
	return (r);
}

/*
 * sp is gone, with the candidate it had and, if it had configure
 * exclusive, its uncommitted changes; a commit it began runs on
 */
static void
session_gone(struct session *sp)
{
	if (sp->how != 0) {
		config_left(sp);
		printed_text(NULL, 0, 0, 0);
	}
	if (commit != NULL && commit->session == sp->id)
		commit->session = 0;
	TAILQ_REMOVE(&sessions, sp, entry);
	session_free(sp->st);
	free(sp->load);
	free(sp->rules);
	free(sp);
}

static struct session *
session_find(uint32_t id)
{
	struct session	*sp;

	TAILQ_FOREACH(sp, &sessions, entry)
		if (sp->id == id)
			break;
	return (sp);
}

static struct request *
request_find(uint32_t id)
{
	struct request	*r;

	TAILQ_FOREACH(r, &requests, entry)
		if (r->id == id)
			break;
	return (r);
}

/* free r, already taken from requests */
static void
request_free(struct request *r)
{
	free(r->text);
	free(r);
}
