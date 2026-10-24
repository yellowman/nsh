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
 * config: the sessions, from frontend, and what they ask of system,
 * each on its own pipe. Each request to system has an id of its own;
 * system's answers for it go to the session that asked, if that
 * session is still there, its facts passed on unread. system learns
 * when a session's client has read all it was sent, and when the
 * session is gone, so it stops what it streams the session. A peer that
 * sends what it may not, or sends it wrong, ends config, and nshd with
 * it.
 *
 * A session in configure has nsh's state of its own (session.c), and
 * config runs its lines through nsh's code in candidate mode, which
 * reads no kernel, no file and no program here: the running
 * configuration and what the lines read of the kernel are a snapshot's,
 * system's, taken when a session enters configure or shows its
 * candidate, and kept for every session until the next.
 *
 * configure private's candidate is the session's own; configure's is
 * one the sessions in configure share, and a commit of it commits what
 * each changed. configure exclusive is configure, while no other
 * session changes or commits a candidate, and it is refused while
 * another has it, or while another's changes to the shared candidate
 * are not committed. Leaving configure exclusive discards what was not
 * committed. A commit of the shared candidate holds it, while it runs,
 * from the others' changes.
 *
 * A session has the permissions of its user's login class, which config
 * asks system for at the session's hello, by the uid frontend gives;
 * until they are in, the session may only say hello and go. A show
 * and the tables and names for completion need view; an operation
 * needs operate; configure private, configure terminal, a commit, a
 * rollback and a load need configure. configure and configure
 * exclusive need admin, as their candidate is everyone's. exec is nsh's
 * to check, as it runs a program: config only tells it at hello.
 * A session without admin sees no password hash: config takes each
 * out of what it sends such a session of the configuration.
 * An operation a session may ask, system checks and runs, and config
 * passes on. A session of the web configurator's has no permissions
 * until it logs in, as system checks it; then it has the class of the
 * user it logged in as, without admin.
 *
 * archive keeps the shared candidate, and who changed it, past config's
 * end: config sends it each time it changes, and answers the session
 * that changed it once archive says it kept it, or that it did not; a
 * config that starts takes what archive kept before a session enters
 * configure. If archive is down, a change is said not to be kept.
 *
 * A commit is one at a time, of all sessions': config plans it from a
 * snapshot, system tests the daemons' rules it changes (TEST), then
 * records it (BEGIN), runs its script (APPLY) and, if a snapshot after
 * reads as the candidate, saves what runs (SAVE); if not, it runs the
 * script back, and the record goes (RECORD). It runs to its end if its
 * session goes. commit check stops after the tests. commit confirmed
 * begins with its minutes, which has system keep the record of a commit
 * not confirmed, and runs its script even if it is empty; then, if a
 * snapshot reads as the candidate, the commit's record goes, and what
 * runs is kept until the deadline, not saved. A commit that saves
 * confirms it. A commit outside configure only saves what runs, as one
 * that changes nothing does; check and confirmed are configure's.
 *
 * configure terminal is a candidate of the session's own, as what runs
 * on a snapshot taken for each line: a line that changes it is
 * committed, and not saved, the commit's record gone once a snapshot
 * after reads as the candidate (RECORD, as applied), and answered once
 * its commit ends, after which the candidate is what runs again. commit
 * there saves what runs; rollback has nothing to roll back.
 *
 * A client that completes lines itself, as nsh's Tab does, asks config
 * for two things, sent as facts: nsh's command tables, and the names of
 * interfaces, groups, bridges and routing tables.  The names come from
 * the last snapshot; if there is none yet, config takes one first.
 *
 * nsh -c's configuration comes a part at a time, each answered, outside
 * configure. After the last, on a snapshot, it becomes the candidate of
 * a session of its own, in place of what runs, which is committed, all
 * of it or none; then the candidate goes.
 *
 * A session may watch commits, configure exclusive, and interfaces,
 * addresses and routes, and config sends it a notice, unasked, as each
 * changes: a commit saved, confirmed or applied, as it ends; a commit
 * not confirmed gone back, as system says; configure exclusive taken or
 * left; and, from the routing socket parent opened for it, fd 5,
 * interfaces or addresses changed, and the rtables whose routes did,
 * each said once a second at most. It may watch logs too: system
 * follows each, as a stream, whose text config sends as notices until
 * the watch drops the log or the stream ends, which config says. A
 * watch is answered once system has followed each log it adds, or
 * refused to.
 *
 * Told at its start that the boot is not done, config boots, as nsh -i
 * does, once there is a pipe to system: system says whether this boot
 * of the host's is done already (BOOT), and if not, gives the saved
 * configuration, which a commit of no session's makes what runs, all
 * of it that takes, as nothing it checks or tests refuses it; then
 * system records how it went (BOOTED), and parent is told. What nsh's
 * code and system print for it is logged. If system could not record
 * the boot, it runs, and did not go well.
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
#include "stringlist.h"
#include "kfacts.h"
#include "session.h"

#define SNAPSHOT_TEXT	(16 * 1024 * 1024)	/* a snapshot's, at most */

#define IDS_GONE	"% nshd: request ids exhausted\n"

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
	int			 web;	/* the web configurator's */
	struct session_state	*st;	/* nsh's, once in configure */
	int			 want;	/* the configure it asked for */
	int			 how;	/* the configure it is in, or 0 */
	int			 waits;
	char			 line[NSHD_LINE];	/* configure terminal's */
	char			*load;	/* nsh -c's, as it comes */
	size_t			 loadlen;
	char			 loaded[NSHD_COMMENT];	/* its comment */
	uint32_t		 keep;	/* the keeping its answer waits on */
	struct nshd_context	 held;	/* that answer: its context, */
	int			 heldmode;	/* if it gives one, */
	int			 heldr;		/* and how it ended */
	int			 perms;		/* NSHD_*, -1 until known */
	int			 watch;		/* NSHD_WATCH_* */
	int			 starting;	/* the follows its watch waits */
	int			 watchr;	/* on, and how they went */
};

/* a request system has not finished, and the session that asked it */
struct request {
	TAILQ_ENTRY(request)	 entry;
	uint32_t		 id;
	uint32_t		 session;	/* or 0, a snapshot config keeps */
	int			 kind;
	int			 n;		/* rollback n's */
	char			*text;		/* and its text, as it comes */
	size_t			 len;
	int			 bad;		/* past NSHD_PART */
	int			 started;	/* a follow system said it began */
	int			 stopped;	/* and one config stopped */
};

/* what a request's end does: answer the session, or what follows */
enum { REQ_ANSWER, REQ_COMMIT, REQ_ROLLBACK, REQ_PERMS, REQ_TEXT, REQ_LOGIN,
    REQ_FOLLOW };

/* the commit, and what it waits on */
enum {
	COMMIT_PLAN,		/* a snapshot, to plan from */
	COMMIT_TEST,		/* a daemon's test of its rules */
	COMMIT_BEGIN,		/* the record made */
	COMMIT_APPLY,		/* the script run */
	COMMIT_VERIFY,		/* a snapshot, to verify */
	COMMIT_SAVE,		/* what runs saved */
	COMMIT_UNDO,		/* the script back run */
	COMMIT_BACK,		/* a snapshot, to verify that */
	COMMIT_RECORD,		/* the record gone, kept or back */
	BOOT_BEGIN,		/* the boot begun, or done already */
	BOOT_SAVED,		/* the saved configuration, to boot to */
	BOOT_END		/* how the boot went, recorded */
};

struct commit {
	uint32_t		 session;	/* or 0, gone */
	struct nshd_whose	 whose;		/* as system knows it */
	uid_t			 uid;
	int			 step;
	int			 waits;		/* on a snapshot */
	int			 check;		/* commit check */
	int			 test;		/* the plan's test running */
	int			 failed;	/* a line of the script failed */
	int			 minutes;	/* commit confirmed's, or 0 */
	int			 save;		/* outside configure: a save */
	int			 terminal;	/* configure terminal's line, */
	int			 line;		/* and how the line ended */
	int			 load;		/* nsh -c's */
	int			 how;		/* it ended, NSHD_BACK or KEPT */
	int			 begun;		/* and not ended, to system */
	int			 shared;	/* of the shared candidate */
	int			 boot;		/* the boot's */
	int			 unrecorded;	/* and system could not record it */
	int			 ok;		/* and it went well */
	char			*saved;		/* what it boots to, as it comes */
	size_t			 savedlen;
	int			 savedbad;	/* past NSHD_PART */
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
static struct kfacts		*kf_now;	/* the last snapshot's */
static struct commit		*commit;	/* the one running, or NULL */
static struct cand_shared	*shared;	/* configure's candidate */
static struct session		*exclusive;	/* in configure exclusive */
static uid_t			*editors;	/* who changed shared since */
static size_t			 neditors;
static unsigned int		 shared_edits;	/* its edits, before a request */
static char			 held[64];	/* cand_held's, if it is */
static uint32_t			 keep_sent;	/* shared, sent archive */
static uint32_t			 keep_done;	/* the last kept, or not */
static int			 keep_loaded;	/* what archive kept, taken */
static char			*loading;	/* that, as it comes */
static size_t			 loading_len;
static int			 loading_past;	/* past NSHD_KEEPMAX */
static struct event		 rt_ev;		/* the routing socket, */
static struct event		 rt_tm;		/* its notices' second, */
static int			 rt_links;	/* and what it saw change */
static int			 rt_all;
static uint8_t			 rt_tables[RT_TABLEID_MAX + 1];
static uint8_t			 units[FACTS_UNIT];	/* facts to send */
static size_t			 nunits;		/* bytes in units */

static struct imsgev	*iev_parent;

static void		 config_dispatch_parent(int, short, void *);
static void		 config_dispatch_frontend(int, short, void *);
static void		 config_dispatch_system(int, short, void *);
static void		 config_dispatch_archive(int, short, void *);
static void		 config_ready_archive(void);
static void		 config_show(uint32_t, struct nshd_show *);
static void		 config_configure(uint32_t, struct nshd_configure *);
static void		 config_line(uint32_t, struct nshd_line *);
static void		 config_exit(uint32_t);
static void		 config_commit(uint32_t, struct nshd_commit *);
static void		 config_rollback(uint32_t, struct nshd_rollback *);
static void		 config_rolled(struct request *, int32_t);
static void		 config_hello(uint32_t, struct nshd_peer *);
static void		 config_hello_answer(struct session *);
static void		 config_perms(struct request *, int32_t);
static void		 config_login(uint32_t, struct nshd_login *);
static void		 config_logged(struct request *, int32_t);
static void		 config_text(struct request *, int32_t);
static int		 config_hides(struct session *);
static int		 config_may(uint32_t, uint32_t);
static void		 config_op(uint32_t, struct nshd_op *);
static void		 config_watch(uint32_t, struct nshd_watch *);
static void		 config_commands(uint32_t);
static void		 config_names(uint32_t);
static void		 config_named(struct session *);
static void		 config_emit(void *, const void *, size_t);
static void		 config_flush(struct session *);
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
static struct request	*config_request(uint32_t, int);
static void		 commit_wait(int);
static void		 commit_snapshot(void);
static void		 commit_ended(int32_t);
static void		 commit_test(int);
static void		 commit_go(void);
static int		 commit_part(int32_t, const char *, size_t);
static void		 commit_apply(int);
static void		 commit_save(void);
static void		 commit_record(int);
static void		 commit_new(struct session *);
static void		 commit_request(int, uint32_t, const void *, size_t);
static void		 commit_end(int, const char *);
static int		 commit_renew(void);
static void		 boot_start(void);
static void		 boot_text(struct ibuf *);
static void		 boot_plan(void);
static void		 boot_ran(int);
static void		 boot_drop(void);
static void		 boot_end(int32_t);
static void		 session_gone(struct session *);
static struct session	*session_find(uint32_t);
static struct request	*request_find(uint32_t);
static void		 request_free(struct request *);

static struct link	 links[] = {
#define FRONTEND	0
	{ PROC_FRONTEND, config_dispatch_frontend },
#define SYSTEM		1
	{ PROC_SYSTEM,	 config_dispatch_system },
#define ARCHIVE		2
	{ PROC_ARCHIVE,	 config_dispatch_archive, config_ready_archive },
};

void
configproc(int debug, int verbose)
{
	child_start("config", debug, verbose);
	capture_stdout();
	privdrop(PROC_CONFIG);
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	/* nsh's code here asks no kernel, opens no file, runs no program */
	in_config = 1;
	if ((shared = cand_shared_new()) == NULL)
		fatal(NULL);

	if ((iev_parent = imsgev_new(3, config_dispatch_parent, 0)) == NULL)
		fatal(NULL);
	links_init(links, sizeof(links) / sizeof(links[0]));
	/* its peers' pipes are here, and no descriptor comes after them */
	if (pledge("stdio", NULL) == -1)
		fatal("pledge");
	event_set(&rt_ev, 5, EV_READ | EV_PERSIST, config_route, NULL);
	event_add(&rt_ev, NULL);
	evtimer_set(&rt_tm, config_routed, NULL);
	event_dispatch();
	exit(0);
}

/* parent's word that config may start, and whether to boot */
static void
config_dispatch_parent(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_startup	 st;
	int			 n;

	if (imsgev_io(iev, event) == -1)
		exit(0);

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		if (imsg_get_type(&imsg) != IMSG_STARTUP ||
		    imsg_get_data(&imsg, &st, sizeof(st)) == -1)
			fatalx("parent sent imsg %u, which it may not",
			    imsg_get_type(&imsg));
		if (st.boot)
			boot_start();
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* frontend's requests, each for a session */
static void
config_dispatch_frontend(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct link		*l = &links[FRONTEND];
	struct imsg		 imsg;
	struct nshd_peer	 peer;
	struct nshd_show	 show;
	struct nshd_configure	 cf;
	struct nshd_line	 line;
	struct nshd_commit	 cm;
	struct nshd_rollback	 rb;
	struct nshd_op		 op;
	struct nshd_load	 ld;
	struct nshd_login	 lg;
	struct nshd_watch	 w;
	struct session		*sp;
	uint32_t		 id, type;
	int			 n;

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
		id = imsg_get_id(&imsg);
		if (!config_may(id, type = imsg_get_type(&imsg))) {
			imsg_free(&imsg);
			continue;
		}
		switch (type) {
		case IMSG_CTL_HELLO:
			if (imsg_get_data(&imsg, &peer, sizeof(peer)) == -1)
				goto bad;
			config_hello(id, &peer);
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
		case IMSG_CTL_COMMANDS:
		case IMSG_CTL_NAMES:
			if (imsg_get_len(&imsg) != 0)
				goto bad;
			if (type == IMSG_CTL_COMMANDS)
				config_commands(id);
			else
				config_names(id);
			break;
		case IMSG_CTL_CLOSE:
			if ((sp = session_find(id)) != NULL)
				session_gone(sp);
			config_tell(id, IMSG_SYS_STOP);
			break;
		case IMSG_CTL_READ:
			config_tell(id, IMSG_SYS_READ);
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
	struct request		*r;
	struct session		*sp;
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
		r = request_find(imsg_get_id(&imsg));
		switch (type = imsg_get_type(&imsg)) {
		case IMSG_SYS_TEXT:
		case IMSG_SYS_FACTS:
			/* for a config before this one, or a request failed */
			if (r == NULL)
				break;
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
				else if (link_compose(&links[FRONTEND],
				    IMSG_CTL_OUTPUT, r->session, ibuf_data(&b),
				    ibuf_size(&b)) == -1)
					fatal("%s", __func__);
				break;
			}
			if (r->kind == REQ_COMMIT && commit != NULL &&
			    commit->boot) {
				if (type == IMSG_SYS_TEXT)
					boot_text(&b);
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
			    link_compose(&links[FRONTEND],
			    type == IMSG_SYS_TEXT ? IMSG_CTL_OUTPUT :
			    IMSG_CTL_FACTS, r->session, ibuf_data(&b),
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
			/* a commit not confirmed gone back, or not */
			if (imsg_get_data(&imsg, &nt, sizeof(nt)) == -1 ||
			    nt.kind != NSHD_NOTICE_BACK ||
			    (nt.n != 0 && nt.n != 1))
				goto bad;
			config_notice(NSHD_WATCH_COMMITS, NSHD_NOTICE_BACK, 0,
			    nt.n, NULL);
			break;
		case IMSG_SYS_LOGGED:
			/* whom a web session logged in as: it is that uid */
			if (imsg_get_data(&imsg, &lg, sizeof(lg)) == -1 ||
			    r == NULL || r->kind != REQ_LOGIN)
				goto bad;
			if ((sp = session_find(r->session)) != NULL)
				sp->uid = lg.uid;
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
		rb.n = strtonum(show->words + 9, 0, NSHD_ROLLBACKS - 1,
		    &errstr);
		if (errstr != NULL) {
			config_answer(session, 1, "%% rollback %s is %s\n",
			    show->words + 9, errstr);
			return;
		}
		type = IMSG_SYS_ROLLBACK_READ;
		data = &rb;
		len = sizeof(rb);
		kind = REQ_TEXT;
	}
	/* a configuration's text is had whole, to take its hashes out */
	if (kind == REQ_TEXT && !config_hides(sp))
		kind = REQ_ANSWER;
	if ((r = config_request(session, kind)) == NULL) {
		config_answer(session, 1, "%s", IDS_GONE);
		return;
	}
	/* system answers the rest with facts, or says it does not */
	if (link_compose(&links[SYSTEM], type, r->id, data, len) == -1)
		fatal("%s", __func__);
}

/* configure, of its mode: the session's candidate, once a snapshot is in */
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
	/* configure terminal's, once a snapshot is in */
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
 * configure, what runs saved
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
	/* configure terminal's too, whose lines are committed already */
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
 * rollback n: the session's candidate starts over as configuration n
 * as it was saved, which system reads, or as what runs if n is 0
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
		config_answer(session, 1, "%s", IDS_GONE);
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
		if (imsg_text(links[FRONTEND].iev, IMSG_CTL_OUTPUT, sp->id,
		    r->text, r->len) == -1)
			fatal("%s", __func__);
		config_answer(sp->id, 1, NULL);
		return;
	}
	shared_hold(sp);
	n = session_rollback(sp->st, r->text, r->len, r->n);
	shared_done(sp);
	config_ran(sp, n, 1);
}

/* hello: the session, made once, and its permissions asked of system */
static void
config_hello(uint32_t session, struct nshd_peer *peer)
{
	struct nshd_perms	 p;
	struct session		*sp;
	struct request		*r;

	if ((sp = session_find(session)) != NULL) {
		config_hello_answer(sp);
		return;
	}
	if ((sp = calloc(1, sizeof(*sp))) == NULL)
		fatal(NULL);
	sp->id = session;
	sp->uid = peer->uid;
	sp->gid = peer->gid;
	sp->web = peer->web;
	sp->perms = -1;
	TAILQ_INSERT_TAIL(&sessions, sp, entry);
	if ((r = config_request(session, REQ_PERMS)) == NULL) {
		sp->perms = 0;
		config_hello_answer(sp);
		return;
	}
	memset(&p, 0, sizeof(p));
	p.uid = peer->uid;
	p.web = peer->web;
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
	if (link_compose(&links[FRONTEND], IMSG_CTL_HELLO, sp->id, &s,
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
		config_answer(session, 1, "%s", IDS_GONE);
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
 * system's answer: the permissions of the user the session logged in
 * as, or, if it did not, -1, and the session as it was
 */
static void
config_logged(struct request *r, int32_t status)
{
	struct session	*sp;

	if ((sp = session_find(r->session)) == NULL)
		return;
	if (status >= 0)
		sp->perms = status;
	config_answer(sp->id, status >= 0 ? 0 : 1, NULL);
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
	if (imsg_text(links[FRONTEND].iev, IMSG_CTL_OUTPUT, r->session,
	    r->text, r->len) == -1)
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
 * Whether session may ask type: hello and going, always; else what its
 * permissions allow, once they are in. One with no hello, its handler
 * says
 */
static int
config_may(uint32_t session, uint32_t type)
{
	struct session	*sp;
	const char	*name = "configure";
	int		 need = NSHD_CONFIGURE;

	if (type == IMSG_CTL_HELLO || type == IMSG_CTL_CLOSE ||
	    type == IMSG_CTL_READ || type == IMSG_CTL_LOGIN ||
	    (sp = session_find(session)) == NULL)
		return (1);
	if (type == IMSG_CTL_SHOW || type == IMSG_CTL_WATCH ||
	    type == IMSG_CTL_COMMANDS || type == IMSG_CTL_NAMES) {
		need = NSHD_VIEW;
		name = "view";
	} else if (type == IMSG_CTL_OP) {
		need = NSHD_OPERATE;
		name = "operate";
	}
	if (sp->perms != -1 && (sp->perms & need) != 0)
		return (1);
	config_answer(session, 1, "%% Not allowed: your login class does not "
	    "have the %s permission\n", name);
	return (0);
}

/* Send nsh's command tables to the session as facts, then a result. */
static void
config_commands(uint32_t session)
{
	struct session		*sp;
	struct facts_out	 o;
	int			 r;

	if ((sp = session_find(session)) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	facts_out_init(&o, config_emit, sp);
	r = cmplt_facts(&o);
	config_flush(sp);
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
	struct facts_out	 o;
	StringList		*sl;
	size_t			 i, j;
	int			 r = 0;

	facts_out_init(&o, config_emit, sp);
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
	config_flush(sp);
	if (r == -1)
		config_answer(sp->id, 1, "%% nshd: the names could not be "
		    "sent\n");
	else
		config_answer(sp->id, 0, NULL);
}

/*
 * Queue a unit of facts for the session arg.  Send the queue first if
 * the unit would not fit.
 */
static void
config_emit(void *arg, const void *buf, size_t len)
{
	if (nunits + len > sizeof(units))
		config_flush(arg);
	memcpy(units + nunits, buf, len);
	nunits += len;
}

/* Send the queued units to sp as one message. */
static void
config_flush(struct session *sp)
{
	if (nunits == 0)
		return;
	if (link_compose(&links[FRONTEND], IMSG_CTL_FACTS, sp->id, units,
	    nunits) == -1)
		fatal("%s", __func__);
	nunits = 0;
}

/* an operation, which system checks, runs and streams */
static void
config_op(uint32_t session, struct nshd_op *op)
{
	struct nshd_sysop	 so;
	struct request		*r;

	if (session_find(session) == NULL) {
		config_answer(session, 1, "%% nshd: hello first\n");
		return;
	}
	if ((r = config_request(session, REQ_ANSWER)) == NULL) {
		config_answer(session, 1, "%s", IDS_GONE);
		return;
	}
	memset(&so, 0, sizeof(so));
	so.whose.session = session;
	so.op = *op;
	if (link_compose(&links[SYSTEM], IMSG_SYS_OP, r->id, &so,
	    sizeof(so)) == -1)
		fatal("%s", __func__);
}

/*
 * What the session watches, from now on. Each log it adds system
 * follows, or refuses to, before the watch is answered; each it drops
 * is stopped
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
				if (imsg_text(links[FRONTEND].iev,
				    IMSG_CTL_OUTPUT, session, IDS_GONE,
				    strlen(IDS_GONE)) == -1)
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
 * A follow ended: refused, before it began, which the watch's answer
 * says; or, unless the watch dropped it, ended, which a notice says
 */
static void
config_follow_end(struct request *r, int32_t status)
{
	struct session	*sp;

	if ((sp = session_find(r->session)) == NULL || r->stopped)
		return;
	if (r->started) {
		config_notice_to(sp->id, NSHD_NOTICE_LOGEND, 0, r->n, NULL, 0);
		return;
	}
	sp->watchr = 1;
	if (--sp->starting == 0)
		config_answer(sp->id, sp->watchr, NULL);
}

/*
 * A notice of kind, about uid and n, with text, if not NULL, to each
 * session that watches what
 */
static void
config_notice(int what, int kind, uid_t uid, int n, const char *text)
{
	struct session		*sp;

	TAILQ_FOREACH(sp, &sessions, entry)
		if ((sp->watch & what) != 0)
			config_notice_to(sp->id, kind, uid, n, text,
			    text == NULL ? 0 : strnlen(text, NSHD_COMMENT - 1));
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
	if (link_compose(&links[FRONTEND], IMSG_CTL_NOTICE, session, buf,
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

/* session's, if in configure; or NULL, said why */
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
 * configure terminal's line, on a candidate as what runs now: committed,
 * not saved, if it changed it, and answered once the commit ends; 1 if
 * it is committed, else as a handler returns
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
 * nsh -c's configuration, a part, kept, answered; the last, once a
 * snapshot is in, loaded and committed
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
 * nsh -c's configuration, as a candidate of its own in place of what
 * runs: committed, if it differs, all of it or none, and answered once
 * the commit ends; 1 if it is committed, else as a handler returns
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
 * sp into the configure it asked for, if it may: configure and configure
 * exclusive are refused while another has configure exclusive, and
 * configure exclusive while another's changes to the shared candidate
 * are not committed. As a handler returns
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
 * sp left configure: if it had configure exclusive, what the shared
 * candidate has not committed is discarded
 */
static void
config_left(struct session *sp)
{
	int	 how = sp->how;

	sp->how = 0;
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
	cand_held = held;
}

/*
 * After: if sp changed the shared candidate, sp among who did, and it
 * kept before sp is answered
 */
static void
shared_done(struct session *sp)
{
	uid_t	*e;
	size_t	 i;

	if (cand_held != NULL) {
		cand_held = NULL;
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
 * what, by the users but uid who changed the shared candidate, said if
 * there are any: how many
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
 * The shared candidate changed: it, and who changed it, to archive to
 * keep, the next keeping, which is its number, or 0 if archive is down
 * or it could not be sent, said
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
 * The shared candidate as it is, and who changed it, as "editors" and a
 * uid for each, to archive, to keep as keeping seq: -1, logged, if it
 * could not be sent
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
 * The shared candidate's keepings to seq are done, with warn, if they
 * were not kept: the sessions that waited on them answered
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
		if (warn != NULL && imsg_text(links[FRONTEND].iev,
		    IMSG_CTL_OUTPUT, sp->id, warn, strlen(warn)) == -1)
			fatal("%s", __func__);
		config_reply(sp, &sp->held, sp->heldr, sp->heldmode);
	}
}

/*
 * What archive kept, taken as the shared candidate and who changed it,
 * if it is one; then the sessions that wait to enter configure may
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
	/* nsh's code may have said why, to no session */
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
		config_snapshot_lost(IDS_GONE);
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

/* the snapshot is in, or not: what each session waits on it for runs */
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
			/* the shared candidate, once what archive kept is */
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
			/* or answered once its commit ends */
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
 * What nsh's code printed for sp, with mode its mode, and r, as a
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
	if (printed_text(links[FRONTEND].iev, IMSG_CTL_OUTPUT, sp->id,
	    config_hides(sp)) == -1)
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
	if (mode && link_compose(&links[FRONTEND], IMSG_CTL_CONTEXT, sp->id,
	    c, sizeof(*c)) == -1)
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
	int			 r;

	commit->waits = 0;
	switch (commit->step) {
	case COMMIT_PLAN:
		if (commit->boot)
			boot_plan();
		else if ((sp = session_find(commit->session)) == NULL ||
		    session_plan(sp->st, commit->check, commit->minutes > 0,
		    &commit->plan) == -1)
			commit_end(-1, NULL);
		else if (commit->plan == NULL)
			commit_end(0, NULL);
		else if (commit->plan->ntests > 0)
			commit_test(0);
		else
			commit_go();
		break;
	case COMMIT_VERIFY:
		if (commit->boot)
			boot_ran(session_boot_verify(commit->plan,
			    commit->failed) == 0);
		else if ((r = session_verify(commit->plan,
		    commit->failed)) == 0) {
			if (commit->minutes > 0)
				commit_record(NSHD_KEPT);
			else if (commit->terminal)
				commit_record(NSHD_APPLIED);
			else
				commit_save();
		} else if (r == 1)
			commit_apply(COMMIT_UNDO);
		else
			commit_end(-1, NULL);
		break;
	case COMMIT_BACK:
		/* if not, the record says it did not finish */
		if (session_verify_back(commit->plan) == 0)
			commit_record(NSHD_BACK);
		else
			commit_end(-1, NULL);
		break;
	}
}

/* system ended the commit's request: its next step */
static void
commit_ended(int32_t status)
{
	int		 r;

	switch (commit->step) {
	case BOOT_BEGIN:
		/* if it could not be recorded, it runs */
		if (status == NSHD_DONE)
			boot_end(0);
		else {
			commit->unrecorded = status != 0;
			commit_request(BOOT_SAVED, IMSG_SYS_SAVED, NULL, 0);
		}
		break;
	case BOOT_SAVED:
		if (status != 0) {
			/* what it got is why */
			log_text(commit->saved, commit->savedlen);
			boot_ran(0);
		} else if (commit->savedbad) {
			log_warnx("the saved configuration is past %d bytes",
			    NSHD_PART);
			boot_ran(0);
		} else
			commit_wait(COMMIT_PLAN);
		break;
	case BOOT_END:
		boot_end(commit->ok && status == 0 ? 0 : 1);
		break;
	case COMMIT_TEST:
		session_tested(commit->plan, commit->test, status != 0);
		if (commit->test + 1 < commit->plan->ntests)
			commit_test(commit->test + 1);
		else if (commit->boot)
			commit_apply(COMMIT_APPLY);
		else if (session_verdict(commit->plan) == -1)
			commit_end(-1, NULL);
		else if (commit->check)
			commit_end(0, NULL);
		else
			commit_go();
		break;
	case COMMIT_BEGIN:
		if (status != 0)
			commit_end(-1, NULL);
		else {
			commit->begun = 1;
			commit_apply(COMMIT_APPLY);
		}
		break;
	case COMMIT_APPLY:
		commit->failed = status != 0;
		commit_wait(COMMIT_VERIFY);
		break;
	case COMMIT_UNDO:
		commit_wait(COMMIT_BACK);
		break;
	case COMMIT_SAVE:
		/* taken: the candidate starts again, saved or not */
		r = status == 0 ? 0 : -1;
		if (r == 0)
			config_notice(NSHD_WATCH_COMMITS, NSHD_NOTICE_COMMIT,
			    commit->uid, 0, commit->comment);
		if (!commit->save && !commit->load && commit_renew() == -1)
			r = -1;
		commit_end(r, NULL);
		break;
	case COMMIT_RECORD:
		if (commit->how == NSHD_APPLIED) {
			if (status == 0)
				config_notice(NSHD_WATCH_COMMITS,
				    NSHD_NOTICE_APPLIED, commit->uid, 0,
				    commit->comment);
			commit_end(status == 0 ? 0 : -1, NULL);
			break;
		}
		if (commit->how != NSHD_KEPT || status != 0) {
			commit_end(-1, NULL);
			break;
		}
		config_notice(NSHD_WATCH_COMMITS, NSHD_NOTICE_CONFIRMED,
		    commit->uid, commit->minutes, NULL);
		printf("%% Commit within %d minute%s to keep this, or it is "
		    "rolled back\n", commit->minutes,
		    commit->minutes == 1 ? "" : "s");
		commit_end(commit_renew(), NULL);
		break;
	}
}

/* the plan's nth test of a daemon's rules, which system runs */
static void
commit_test(int n)
{
	struct plan_test	*t = &commit->plan->tests[n];
	struct nshd_test	 nt;

	commit->test = n;
	memset(&nt, 0, sizeof(nt));
	nt.whose = commit->whose;
	strlcpy(nt.name, t->name, sizeof(nt.name));
	if (commit_part(NSHD_SCRIPT, t->text, t->len) == -1)
		return;
	commit_request(COMMIT_TEST, IMSG_SYS_TEST, &nt, sizeof(nt));
}

/* the plan checked: what runs saved, if it is the candidate, or begun */
static void
commit_go(void)
{
	struct plan		*p = commit->plan;
	struct nshd_begin	 b;

	if (p->same && commit->minutes == 0) {
		if (commit->terminal)
			commit_end(0, NULL);
		else
			commit_save();
		return;
	}
	if (commit_part(NSHD_BEFORE, p->text[PLAN_BEFORE],
	    p->len[PLAN_BEFORE]) == -1 || commit_part(NSHD_WANT,
	    p->text[PLAN_WANT], p->len[PLAN_WANT]) == -1)
		return;
	memset(&b, 0, sizeof(b));
	b.whose = commit->whose;
	b.minutes = commit->minutes;
	b.unsaved = commit->terminal;
	commit_request(COMMIT_BEGIN, IMSG_SYS_BEGIN, &b, sizeof(b));
}

/* a part of the commit's, to system, as chunks: -1 if too long, said */
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

/* the plan's script, run by system, at step */
static void
commit_apply(int step)
{
	struct nshd_apply	 a;
	struct plan		*p = commit->plan;
	int			 i;

	memset(&a, 0, sizeof(a));
	a.nclears = p->nclears;
	for (i = 0; i < p->nclears; i++) {
		strlcpy(a.clears[i].name, p->clears[i].name,
		    sizeof(a.clears[i].name));
		a.clears[i].rtable = p->clears[i].rtable;
		a.clears[i].keep = p->clears[i].keep;
	}
	if (commit_part(NSHD_SCRIPT, p->text[PLAN_SCRIPT],
	    p->len[PLAN_SCRIPT]) == -1)
		return;
	commit_request(step, IMSG_SYS_APPLY, &a, sizeof(a));
}

/* what runs, saved by system, with who commits and their comment */
static void
commit_save(void)
{
	struct nshd_save	 sv;

	memset(&sv, 0, sizeof(sv));
	commit->begun = 0;
	sv.whose = commit->whose;
	strlcpy(sv.comment, commit->comment, sizeof(sv.comment));
	commit_request(COMMIT_SAVE, IMSG_SYS_SAVE, &sv, sizeof(sv));
}

/* the record of the commit begun gone, as it ended, how */
static void
commit_record(int how)
{
	struct nshd_record	 rc;

	rc.how = how;
	commit->how = how;
	commit->begun = 0;
	commit_request(COMMIT_RECORD, IMSG_SYS_RECORD, &rc, sizeof(rc));
}

/*
 * The commit, of session sp's, which system begins only while the
 * request frontend told it of is not answered
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
 * A request of the commit's, to system, whose end it waits on at step,
 * after what nsh's code printed for it
 */
static void
commit_request(int step, uint32_t type, const void *data, size_t len)
{
	struct session	*sp = session_find(commit->session);
	struct request	*r;

	if (commit->boot)
		printed_log();
	else
		printed_text(sp != NULL ? links[FRONTEND].iev : NULL,
		    IMSG_CTL_OUTPUT, commit->session, config_hides(sp));
	if ((r = config_request(commit->session, REQ_COMMIT)) == NULL) {
		commit_end(-1, IDS_GONE);
		return;
	}
	commit->step = step;
	if (link_compose(&links[SYSTEM], type, r->id, data, len) == -1)
		fatal("%s", __func__);
}

/*
 * The commit ends, r as a handler returns it, or with msg said after
 * what nsh's code printed for it
 */
static void
commit_end(int r, const char *msg)
{
	struct commit		*c = commit;
	struct nshd_record	 rc = { NSHD_LEFT };
	struct session		*sp;

	/* the boot's did not go well, and it ends once that is recorded */
	if (c->boot) {
		if (msg != NULL)
			log_text(msg, strlen(msg));
		if (c->step == BOOT_END)
			boot_end(1);
		else
			boot_ran(0);
		return;
	}
	commit = NULL;
	/* system told a commit begun ended, if it did not say so itself */
	if (c->begun && link_compose(&links[SYSTEM], IMSG_SYS_RECORD, 0, &rc,
	    sizeof(rc)) == -1)
		fatal("%s", __func__);
	sp = session_find(c->session);
	/* configure terminal's candidate is what runs again */
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
		printed_text(links[FRONTEND].iev, IMSG_CTL_OUTPUT, sp->id,
		    config_hides(sp));
		config_answer(sp->id, 1, "%s", msg);
	} else
		config_ran(sp, r, 1);
	plan_free(c->plan);
	free(c);
}

/* the commit's candidate starts again: -1, said why, if it could not */
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

/* the boot, a commit of no session's, begun */
static void
boot_start(void)
{
	if ((commit = calloc(1, sizeof(*commit))) == NULL)
		fatal(NULL);
	commit->boot = 1;
	commit_request(BOOT_BEGIN, IMSG_SYS_BOOT, NULL, 0);
}

/* system's text for the boot: the saved configuration, or logged */
static void
boot_text(struct ibuf *b)
{
	char	*p;

	if (commit->step != BOOT_SAVED) {
		log_text(ibuf_data(b), ibuf_size(b));
		return;
	}
	if (ibuf_size(b) > NSHD_PART - commit->savedlen) {
		commit->savedbad = 1;
		return;
	}
	if ((p = realloc(commit->saved, commit->savedlen +
	    ibuf_size(b))) == NULL)
		fatal("%s", __func__);
	commit->saved = p;
	memcpy(commit->saved + commit->savedlen, ibuf_data(b), ibuf_size(b));
	commit->savedlen += ibuf_size(b);
}

/* the boot's plan, from the snapshot: what is not the saved, applied */
static void
boot_plan(void)
{
	struct plan	*p;

	if (session_boot_plan(commit->saved, commit->savedlen,
	    &commit->plan) == -1)
		boot_ran(0);
	else if ((p = commit->plan)->same)
		boot_ran(1);
	else if (p->ntests > 0)
		commit_test(0);
	else
		commit_apply(COMMIT_APPLY);
}

/* the boot ran, ok if it went well: system records how */
static void
boot_ran(int ok)
{
	struct nshd_result	res;

	if (commit->unrecorded) {
		boot_end(1);
		return;
	}
	/* first, as a request that cannot be made ends the boot */
	commit->step = BOOT_END;
	commit->ok = ok;
	res.status = !ok;
	commit_request(BOOT_END, IMSG_SYS_BOOTED, &res, sizeof(res));
}

/* the boot's commit, if any, gone, and what nsh's code printed logged */
static void
boot_drop(void)
{
	if (commit != NULL) {
		plan_free(commit->plan);
		free(commit->saved);
		free(commit);
		commit = NULL;
	}
	printed_log();
}

/* the boot done, 0 if it went well: parent told */
static void
boot_end(int32_t status)
{
	struct nshd_result	res;

	boot_drop();
	res.status = status;
	if (imsg_compose_event(iev_parent, IMSG_BOOTED, 0, 0, -1, &res,
	    sizeof(res)) == -1)
		fatal("%s", __func__);
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
		if (imsg_text(links[FRONTEND].iev, IMSG_CTL_OUTPUT, session,
		    s, len) == -1)
			fatal("%s", __func__);
		free(s);
	}
	r.status = status;
	if (link_compose(&links[FRONTEND], IMSG_CTL_RESULT, session, &r,
	    sizeof(r)) == -1)
		fatal("%s", __func__);
}

/* archive's answers: what it kept, for config to take, or that it kept */
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

/* archive's pipe here: what it kept, asked for */
static void
config_ready_archive(void)
{
	if (link_compose(&links[ARCHIVE], IMSG_ARC_LOAD, 0, NULL, 0) == -1)
		fatal("%s", __func__);
}

/* to system: type, for each request of session not finished */
static void
config_tell(uint32_t session, uint32_t type)
{
	struct request	*r;

	TAILQ_FOREACH(r, &requests, entry)
		if (r->session == session && link_compose(&links[SYSTEM],
		    type, r->id, NULL, 0) == -1)
			fatal("%s", __func__);
}

/*
 * A request of session's, or config's own if 0, of kind, with an id of
 * its own; NULL when the ids are exhausted
 */
static struct request *
config_request(uint32_t session, int kind)
{
	struct request	*r;

	if (request_id == UINT32_MAX)
		return (NULL);
	if ((r = calloc(1, sizeof(*r))) == NULL)
		fatal(NULL);
	r->id = ++request_id;
	r->session = session;
	r->kind = kind;
	TAILQ_INSERT_TAIL(&requests, r, entry);
	return (r);
}

/*
 * sp is gone, and the candidate it had, or, from configure exclusive,
 * what it did not commit; a commit of its runs on
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

/* r, taken from requests, freed */
static void
request_free(struct request *r)
{
	free(r->text);
	free(r);
}
