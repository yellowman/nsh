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
 * system: root, and nsh's own code, which reads and changes the kernel.
 * It answers config, on their pipe, one request at a time, in order:
 * the running configuration as text, and what configure private reads
 * of the kernel as facts, and the shows only root may make as facts,
 * with what nsh's code prints as it makes them, as messages.
 * A show's answer is made whole, as it is small, its units as many to a
 * message as fit.
 *
 * But a show of text, what a program prints or the leases, may be long,
 * or go on until it is stopped: a child of system's prints it, and
 * system streams it as messages, as many as SYS_WINDOW before the
 * client has read them, while it answers other requests. A stream ends
 * when its child's output does and its child is reaped, or when config
 * says its session is gone, or config starts again, which kill the
 * child; or when system ends. config sending what it may not, or
 * sending it wrong, is reported, as it went wrong.
 *
 * system is a session of its own, which parent clears when system goes,
 * and each stream's child leads a process group of its own, which is
 * killed when the stream stops. What a child runs is an operation, and
 * the operation says who the child is: a show's program runs as
 * NSHD_CHECK_USER, but for the programs root_programs names, each an
 * exception that keeps root; dhcpd's leases are opened as root and
 * copied as NSHD_CHECK_USER. The program, and its arguments, are nsh's
 * table's for the show's words; no request names a path.
 *
 * A commit's requests come from config in order: the parts BEGIN and
 * APPLY take, as chunks, then BEGIN, which makes the commit record,
 * APPLY, which runs the script, SAVE, which saves what runs and takes
 * the record away, and RECORD, when the commit went back to how it was.
 * An apply and a save each run in a child of system's, a job, in a
 * process group of its own, its output sent as it comes; past its time
 * the group is sent SIGTERM, and a grace later SIGKILL, and it fails.
 * While a job runs, config's requests wait for it, but what a stream's
 * client read and a session gone.
 *
 * The record, in NSHDB, outlives the commit that made it, which leaves
 * it if it does not finish: applying, if it did not save or go back, or
 * applied and not saved, if the save failed. The next commit says what
 * one applying left, by what runs now; one not saved refuses it, but
 * saving what runs, or going back to how it was before that commit.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <grp.h>
#include <imsg.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "stringlist.h"
#include "externs.h"
#include "ctl.h"
#include "facts.h"
#include "kfacts.h"
#include "showfacts.h"

#define SYS_BATCH	256	/* records made before what is printed is sent */
#define SYS_STREAMS	16	/* streams at once, at most */
#define SYS_WINDOW	16	/* messages a stream sends its client unread */
#define COMMIT_RECORD	NSHDB "/commit"
#define RECORD_HEAD	128	/* the record's first line, at most */

#if NSHD_CLEARS != MAXCLEARS || NSHD_ROLLBACKS != ROLLBACKS
#error "nshd.h's sizes are not nsh's"
#endif

/*
 * A job: an apply or a save, and how long it may run, then the grace
 * between SIGTERM and SIGKILL. Each to measure on OpenBSD, on a full
 * table: these are not measured
 */
#define JOB_APPLY	0
#define JOB_SAVE	1
static const struct {
	const char	*what;
	int		 secs;
	int		 grace;
} jobs[] = {
	{ "apply",	900,	10 },	/* a script that starts every daemon */
	{ "save",	300,	10 },	/* conf(), and the save script */
};

/*
 * The programs a show runs that keep root, each an exception: a
 * daemon's control socket is 0660 root:wheel, smtpd answers its shows
 * only to euid 0, /dev/pf is 0600 and PF_KEY root's. Any other runs as
 * NSHD_CHECK_USER
 */
static const char *root_programs[] = {
	BGPCTL, DVMRPCTL, EIGRPCTL, IKECTL, LDAPCTL, LDPCTL, OSPF6CTL,
	OSPFCTL, RELAYCTL, RIPCTL, SMTPCTL, PFCTL, IPSECCTL
};

/* a show's text, which a child prints, as messages to its client */
struct stream {
	TAILQ_ENTRY(stream)	 entry;
	uint32_t		 id;		/* the request */
	pid_t			 pid;		/* the child, or 0, reaped */
	int			 fd;		/* its output, or -1 at its end */
	int			 window;	/* messages it may still send */
	int			 stopped;
	struct event		 ev;
	struct facts_out	 o;
};

/* the job running, which a child of system's runs */
struct job {
	uint32_t		 id;		/* the request */
	int			 kind;
	pid_t			 pid;		/* the child, or 0, reaped */
	pid_t			 pgid;
	int			 status;	/* how it ended, once reaped */
	int			 fd;		/* its output, or -1 at its end */
	int			 killed;	/* the signal its group got last */
	struct event		 ev, tm;
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

static struct imsgev	*iev_relay;
static uint8_t		 units[FACTS_UNIT];	/* not yet sent */
static size_t		 nunits;
static TAILQ_HEAD(, stream) streams = TAILQ_HEAD_INITIALIZER(streams);
static int		 nstreams;
static uid_t		 check_uid;	/* NSHD_CHECK_USER's */
static gid_t		 check_gid;
static struct job	*job;
static TAILQ_HEAD(, queued) queue = TAILQ_HEAD_INITIALIZER(queue);
static char		*parts[NSHD_PARTS];	/* chunks, until taken */
static size_t		 partlen[NSHD_PARTS];

static void	system_dispatch_relay(int, short, void *);
static void	system_dispatch_config(int, short, void *);
static void	system_forget_config(void);
static int	system_whole(uint32_t, const void *, size_t);
static int	system_request(uint32_t, uint32_t, const void *, size_t);
static void	system_queue(uint32_t, uint32_t, const void *, size_t);
static void	system_drain(void);
static void	system_snapshot(uint32_t, int);
static void	system_show(uint32_t, char *);
static void	system_end(uint32_t, int32_t, const char *, ...)
		    __attribute__((__format__ (printf, 3, 4)));
static void	system_emit(void *, const void *, size_t);
static void	system_flush(uint32_t);
static void	system_stream(uint32_t, int, char **, int);
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
static void	system_begin(uint32_t, uid_t);
static void	system_apply(uint32_t, struct nshd_apply *);
static void	system_save(uint32_t, struct nshd_save *);
static void	system_saved(int);
static void	system_back(uint32_t);
static void	system_rollback(uint32_t, int);
static void	system_printed(uint32_t, int32_t);
static void	system_job(uint32_t, int, struct nshd_apply *, const char *,
		    const char *);
static __dead void system_job_child(int, int, struct nshd_apply *,
		    const char *, const char *);
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

static struct link	 config = {
	PROC_CONFIG, system_dispatch_config, system_forget_config
};

void
systemproc(int debug, int v)
{
	static struct event	 ev_sigchld;
	struct passwd		*pw;

	child_start("system", debug, v);
	if (setsid() == -1)
		fatal("setsid");
	if ((pw = getpwnam(NSHD_CHECK_USER)) == NULL)
		fatalx("unknown user %s", NSHD_CHECK_USER);
	check_uid = pw->pw_uid;
	check_gid = pw->pw_gid;
	capture_stdout();

	/* nsh's code here is nsh's as root */
	priv = 1;
	facts_from = FACTS_SYSTEM;
	db_create();

	if ((iev_relay = imsgev_new(3, system_dispatch_relay, 0)) == NULL)
		fatal(NULL);
	links_init(&config, 1, iev_relay);
	signal_set(&ev_sigchld, SIGCHLD, system_sigchld, NULL);
	signal_add(&ev_sigchld, NULL);
	event_dispatch();
	system_exit();
}

/* relay's word that system may start */
static void
system_dispatch_relay(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	ssize_t			 n;

	if (imsgev_io(iev, event) == -1)
		system_exit();

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		if (imsg_get_type(&imsg) != IMSG_STARTUP) {
			log_warnx("relay sent imsg %u, which it may not",
			    imsg_get_type(&imsg));
			system_exit();
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* config's requests, in order, but that they wait while a job runs */
static void
system_dispatch_config(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct ibuf		 b;
	const void		*data;
	size_t			 len;
	uint32_t		 type, id;
	ssize_t			 n;
	int			 r = 0;

	if (imsgev_io(iev, event) == -1) {
		link_broken(&config, "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1) {
			link_broken(&config, "sent what imsg cannot read");
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
			link_broken(&config, "sent imsg %u, which it may not, "
			    "or not whole", type);
			return;
		}
		/* what a stream's client read, and a session gone, wait not */
		if (type == IMSG_SYS_READ || type == IMSG_SYS_STOP ||
		    (job == NULL && TAILQ_EMPTY(&queue)))
			r = system_request(type, id, data, len);
		else
			system_queue(type, id, data, len);
		imsg_free(&imsg);
		if (r == -1) {
			link_broken(&config, "sent a part past %d bytes",
			    NSHD_PART);
			return;
		}
	}
	imsg_event_add(iev);
}

/* Is a request one config may send, and whole? 0 if so, else -1 */
static int
system_whole(uint32_t type, const void *data, size_t len)
{
	struct nshd_show	 show;
	struct nshd_chunk	 c;
	struct nshd_apply	 a;
	struct nshd_save	 sv;
	struct nshd_rollback	 rb;
	int			 i;

	switch (type) {
	case IMSG_SYS_READ:
	case IMSG_SYS_STOP:
		return (0);
	case IMSG_SYS_RECORD:
	case IMSG_SYS_ROLLBACK_LIST:
		return (len == 0 ? 0 : -1);
	case IMSG_SYS_SNAPSHOT:
		return (len == sizeof(struct nshd_snapshot) ? 0 : -1);
	case IMSG_SYS_BEGIN:
		return (len == sizeof(struct nshd_begin) ? 0 : -1);
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
		if (len != sizeof(rb))
			return (-1);
		memcpy(&rb, data, len);
		return (rb.n < 0 || rb.n >= NSHD_ROLLBACKS ? -1 : 0);
	}
	return (-1);
}

/* a whole request, run: -1 if config sent a part past NSHD_PART */
static int
system_request(uint32_t type, uint32_t id, const void *data, size_t len)
{
	struct nshd_snapshot	 snap;
	struct nshd_show	 show;
	struct nshd_begin	 bg;
	struct nshd_apply	 a;
	struct nshd_save	 sv;
	struct nshd_rollback	 rb;
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
		system_begin(id, bg.uid);
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
		system_back(id);
		break;
	case IMSG_SYS_ROLLBACK_READ:
		memcpy(&rb, data, sizeof(rb));
		system_rollback(id, rb.n);
		break;
	case IMSG_SYS_ROLLBACK_LIST:
		system_rollback(id, -1);
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
			link_broken(&config, "sent a part past %d bytes",
			    NSHD_PART);
			return;
		}
	}
}

/*
 * config started again, or is down: what it asked is lost, but a job,
 * which runs to its end, as stopping an apply part way is worse
 */
static void
system_forget_config(void)
{
	struct stream	*s, *next;
	struct queued	*q;

	TAILQ_FOREACH_SAFE(s, &streams, entry, next)
		system_stream_stop(s);
	while ((q = TAILQ_FIRST(&queue)) != NULL) {
		TAILQ_REMOVE(&queue, q, entry);
		free(q);
	}
	system_parts_free();
}

/*
 * the running configuration, as conf() writes it, with facts what
 * configure private reads of the kernel, then how it went
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
		} else if (imsg_text(config.iev, IMSG_SYS_TEXT, id, buf,
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
	if (link_compose(&config, IMSG_SYS_END, id, &r, sizeof(r)) == -1)
		fatal("%s", __func__);
}

/* the facts words ask, all of them, then how it went; or a stream */
static void
system_show(uint32_t id, char *words)
{
	struct facts_answer	*a;
	struct facts_out	 o;
	char			**argv;
	int			 more = 1, op, table;

	printed(NULL);
	if ((a = facts_answer(words)) == NULL) {
		system_end(id, 1, "%% show %s: not answered by nshd\n", words);
		return;
	}
	facts_out_init(&o, system_emit, &id);
	if ((op = facts_streams(a, &argv, &table)) != 0) {
		/* -1: the words do not fill the program's, said why */
		if (op == -1) {
			printed(&o);
			system_flush(id);
			system_end(id, 1, NULL);
		} else
			system_stream(id, op, argv, table);
		facts_answer_free(a);
		return;
	}
	while (more == 1) {
		more = facts_more(a, &o, SYS_BATCH);
		if (printed(&o) == -1)
			more = -1;
	}
	facts_answer_free(a);
	system_flush(id);
	system_end(id, more != 0, NULL);
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
		    imsg_text(config.iev, IMSG_SYS_TEXT, id, s, len) == -1)
			fatal("%s", __func__);
		free(s);
	}
	r.status = status;
	if (link_compose(&config, IMSG_SYS_END, id, &r, sizeof(r)) == -1)
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
	if (link_compose(&config, IMSG_SYS_FACTS, id, units, nunits) == -1)
		fatal("%s", __func__);
	nunits = 0;
}

/* op's text, which a child prints, streamed to request id's client */
static void
system_stream(uint32_t id, int op, char **argv, int table)
{
	struct stream	*s;
	int		 fds[2];

	if (nstreams == SYS_STREAMS) {
		system_end(id, 1, "%% nshd: %d shows already stream\n",
		    SYS_STREAMS);
		return;
	}
	if (pipe2(fds, O_CLOEXEC) == -1) {
		system_end(id, 1, "%% nshd: pipe: %s\n", strerror(errno));
		return;
	}
	if ((s = calloc(1, sizeof(*s))) == NULL)
		fatal(NULL);
	switch (s->pid = fork()) {
	case -1:
		system_end(id, 1, "%% nshd: fork: %s\n", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		free(s);
		return;
	case 0:
		system_child(fds[1], op, argv, table);
	}
	/* as the child does, so neither waits on the other */
	setpgid(s->pid, s->pid);
	close(fds[1]);
	s->id = id;
	s->fd = fds[0];
	s->window = SYS_WINDOW;
	facts_out_init(&s->o, system_emit, &s->id);
	event_set(&s->ev, s->fd, EV_READ | EV_PERSIST, system_stream_read, s);
	event_add(&s->ev, NULL);
	TAILQ_INSERT_TAIL(&streams, s, entry);
	nstreams++;
}

/* the child: op's text, to fd, with nothing else of system's */
static __dead void
system_child(int fd, int op, char **argv, int table)
{
	char	 buf[8192];
	size_t	 n;
	FILE	*f;
	int	 null;

	setpgid(0, 0);
	/* as a program expects them, and as system's are not */
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
	case FACTS_LEASES:
		/* dhcpd's, 0640 */
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
	}
	fflush(stdout);
	_exit(0);
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

/* a stream's child, once it holds what it needed root for */
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
	if (n > 0 && facts_text(&s->o, buf, n) == -1) {
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
 * s, and the process group its child leads, killed: it ends once the
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

/* s, if its output has ended and its child is reaped: how it went */
static void
system_stream_done(struct stream *s)
{
	if (s->fd != -1 || s->pid != 0)
		return;
	system_end(s->id, s->stopped, NULL);
	TAILQ_REMOVE(&streams, s, entry);
	nstreams--;
	free(s);
}

/* the streams' children and the job's that are gone; no other is reaped */
static void
system_sigchld(int sig, short event, void *arg)
{
	struct stream	*s, *next;

	TAILQ_FOREACH_SAFE(s, &streams, entry, next)
		if (s->pid != 0 && waitpid(s->pid, NULL, WNOHANG) == s->pid) {
			s->pid = 0;
			system_stream_done(s);
		}
	if (job != NULL && job->pid != 0 &&
	    waitpid(job->pid, &job->status, WNOHANG) == job->pid) {
		job->pid = 0;
		system_job_done();
	}
}

/* text of a part the next BEGIN or APPLY takes: -1 if past NSHD_PART */
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
 * A commit begins, uid's, from what runs to what is wanted, the parts
 * sent: the record made, unless one a commit left refuses it
 */
static void
system_begin(uint32_t id, uid_t uid)
{
	struct record	 rec, now;
	int		 r, status = 1;

	if (record_read(&rec) == -1)
		goto done;
	if (rec.state == RECORD_APPLYING) {
		/* what it left, by what runs */
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
		/* the commit goes back to how it was before that one */
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
		now.uid = uid;
		now.when = time(NULL);
		now.before = parts[NSHD_BEFORE];
		now.beforelen = partlen[NSHD_BEFORE];
		now.want = parts[NSHD_WANT];
		now.wantlen = partlen[NSHD_WANT];
		if (record_write(&now) == -1)
			goto done;
	}
	status = 0;
 done:
	record_free(&rec);
	system_parts_free();
	system_printed(id, status);
}

/* the script, the part sent, in a job */
static void
system_apply(uint32_t id, struct nshd_apply *a)
{
	system_job(id, JOB_APPLY, a, NULL, NULL);
	system_parts_free();
}

/* what runs, saved by uid with a comment, in a job */
static void
system_save(uint32_t id, struct nshd_save *sv)
{
	char	 who[64];

	user_name(sv->uid, who, sizeof(who));
	system_job(id, JOB_SAVE, NULL, who, sv->comment);
}

/*
 * After a save: the record gone, or if it failed, a commit applying
 * applied and not saved
 */
static void
system_saved(int ok)
{
	struct record	 rec;

	if (ok)
		record_clear();
	else if (record_read(&rec) == 0) {
		if (rec.state == RECORD_APPLYING) {
			rec.state = RECORD_UNSAVED;
			record_write(&rec);
		}
		record_free(&rec);
	}
}

/*
 * The commit went back to how it was: the record it made gone, but one
 * not saved, which it went back from, kept
 */
static void
system_back(uint32_t id)
{
	struct record	 rec;
	int		 status = 1;

	if (record_read(&rec) == 0) {
		if (rec.state != RECORD_APPLYING || record_clear() == 0)
			status = 0;
		record_free(&rec);
	}
	system_printed(id, status);
}

/* configuration n as it was saved, or with n -1, the list of them */
static void
system_rollback(uint32_t id, int n)
{
	char	*buf = NULL;
	size_t	 len = 0;
	FILE	*f;
	int	 r = 0;

	if ((f = open_memstream(&buf, &len)) == NULL)
		fatal("%s", __func__);
	if (n == -1)
		rollback_list(f);
	else
		r = rollback_text(n, f);
	if (fclose(f) == EOF)
		fatal("%s", __func__);
	/* why it could not, then it */
	if (printed_text(config.iev, IMSG_SYS_TEXT, id) == -1)
		r = -1;
	if (imsg_text(config.iev, IMSG_SYS_TEXT, id, buf, len) == -1)
		fatal("%s", __func__);
	free(buf);
	system_end(id, r != 0, NULL);
}

/* what nsh's code printed, to config, then how request id ended */
static void
system_printed(uint32_t id, int32_t status)
{
	if (printed_text(config.iev, IMSG_SYS_TEXT, id) == -1 && status == 0)
		status = 1;
	system_end(id, status, NULL);
}

/* a job of kind, for request id: an apply of a, or a save by who */
static void
system_job(uint32_t id, int kind, struct nshd_apply *a, const char *who,
    const char *comment)
{
	struct timeval	 tv = { jobs[kind].secs, 0 };
	int		 fds[2];
	pid_t		 jp;

	fflush(stdout);
	if (pipe2(fds, O_CLOEXEC) == -1) {
		printf("%% nshd: pipe: %s\n", strerror(errno));
		system_printed(id, -1);
		return;
	}
	switch (jp = fork()) {
	case -1:
		printf("%% nshd: fork: %s\n", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		system_printed(id, -1);
		return;
	case 0:
		system_job_child(fds[1], kind, a, who, comment);
	}
	/* as the child does, so neither waits on the other */
	setpgid(jp, jp);
	close(fds[1]);
	if ((job = calloc(1, sizeof(*job))) == NULL)
		fatal(NULL);
	job->id = id;
	job->kind = kind;
	job->pid = job->pgid = jp;
	job->fd = fds[0];
	event_set(&job->ev, job->fd, EV_READ | EV_PERSIST, system_job_read,
	    NULL);
	event_add(&job->ev, NULL);
	evtimer_set(&job->tm, system_job_late, NULL);
	evtimer_add(&job->tm, &tv);
}

/* the job's child: what it prints, to fd, with nothing else of system's */
static __dead void
system_job_child(int fd, int kind, struct nshd_apply *a, const char *who,
    const char *comment)
{
	struct script	 sc;
	int		 i, null, r;

	setpgid(0, 0);
	/* as nsh's code, and the programs it runs, expect them */
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
	if (kind == JOB_APPLY) {
		memset(&sc, 0, sizeof(sc));
		sc.text = parts[NSHD_SCRIPT];
		sc.len = partlen[NSHD_SCRIPT];
		for (i = 0; i < a->nclears; i++) {
			strlcpy(sc.clears[i].name, a->clears[i].name,
			    sizeof(sc.clears[i].name));
			sc.clears[i].rtable = a->clears[i].rtable;
			sc.clears[i].keep = a->clears[i].keep;
		}
		sc.nclears = a->nclears;
		/* -1, it could not run; 1, a line of it failed */
		r = script_run(&sc);
		fflush(stdout);
		_exit(r == -1 ? 2 : r);
	}
	r = conf_save();
	if (r)
		rollback_keep(who, comment);
	fflush(stdout);
	_exit(r ? 0 : 1);
}

/* what the job's child printed, to config as it comes */
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
		if (imsg_text(config.iev, IMSG_SYS_TEXT, job->id, buf, n) ==
		    -1)
			fatal("%s", __func__);
		return;
	}
	event_del(&job->ev);
	close(job->fd);
	job->fd = -1;
	system_job_done();
}

/*
 * The job past its time: its group sent SIGTERM, then a grace later
 * SIGKILL, and what it prints no longer waited for
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
	if (j->kind == JOB_SAVE)
		system_saved(status == 0);
	system_printed(j->id, status);
	free(j);
	system_drain();
}

/* the commit record into rec, state RECORD_NONE if none: -1, said, if not */
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

/* rec as the commit record, whole or not at all: -1, said, if not */
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

/* no commit record: -1, said, if it could not be taken away */
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

/* NSHDB's entries, as they now are, kept: -1, said, if not */
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
