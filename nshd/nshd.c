/*
 * Copyright (c) 2026 Chris Cappuccio <chris@nmedia.net>
 * Copyright (c) 2018 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
 * nshd: the configuration, and the only thing that changes the kernel.
 *
 * parent binds the two sockets and starts relay and the children, each
 * this program again with a flag for its part:
 *
 *	relay (-R)	_nshrelay, chroot: the children's lives
 *	show (-Sn)	_nshshow, chroot: the read-only socket, SHOWS of
 *			them, n from 0, so one long answer holds up no other
 *	frontend (-F)	_nshfront, chroot: the read-write socket, sessions
 *	config (-C)	_nshconf, chroot: sessions' state, what to ask kernel
 *	kernel (-K)	root: reads and changes the kernel
 *	archive (-A)	_nsharc, chroot: the configurations saved
 *
 * Each user is a role's alone, so no child may signal another of
 * another role, or reach its files; the group nshadmin may use the
 * read-write socket.
 *
 * Two children that talk, frontend and config, config and kernel, do so
 * on a pipe of their own, which parent makes, so each knows who sent
 * what it reads. Each child has a pipe to relay, as fd 3, which tells
 * it when it may start, and to which it tells a peer gone wrong; one
 * with peers has a pipe from parent, as fd 4, which gives it each
 * peer's pipe, or says the peer is down, with the peer's generation,
 * before it starts and each time the peer starts again; frontend and
 * each show have their socket after these, and no other child has it.
 * parent gives relay each child's pipe, and from then on reads only
 * what relay sends it, on a pipe that passes it no descriptor. relay
 * passes no descriptor to a child, and carries no request.
 *
 * nshd stays up for all that depends on it. A child that relay says went
 * wrong, its pipe closed or a rule broken, relay's or a peer's, is
 * killed and started again, and its peers given new pipes. One that
 * fails RESTARTS times in RESTART_SECS stays down: its peers answer for
 * it, and if it is frontend, or the last show, parent closes the socket,
 * which no process then holds, so clients are refused. If relay goes
 * wrong, every child goes with it, and all start again; if relay fails
 * RESTARTS times in RESTART_SECS, nshd ends.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <grp.h>
#include <imsg.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "control.h"
#include "facts.h"
#include "showfacts.h"

#define RESTARTS	5	/* failures in RESTART_SECS, and one stays down */
#define RESTART_SECS	60

static struct child {
	enum nshd_proc	 proc;
	int		 instance;
	char		*name;
	char		*flag;
	char		*user;		/* chrooted to its home, or root */
	pid_t		 pid;
	uint32_t	 generation;
	unsigned int	 nfails;
	time_t		 fails[RESTARTS];	/* the last ones, monotonic */
	int		 down;
	struct imsgbuf	 out;		/* its peers' pipes, from parent */
	struct event	 outev;
	int		 hasout;
} children[] = {
	{ PROC_RELAY,	 0, "relay",	"-R",	"_nshrelay" },
	/* SHOWS of them */
	{ PROC_SHOW,	 0, "show0",	"-S0",	"_nshshow" },
	{ PROC_SHOW,	 1, "show1",	"-S1",	"_nshshow" },
	{ PROC_SHOW,	 2, "show2",	"-S2",	"_nshshow" },
	{ PROC_SHOW,	 3, "show3",	"-S3",	"_nshshow" },
	{ PROC_FRONTEND, 0, "frontend",	"-F",	"_nshfront" },
	{ PROC_CONFIG,	 0, "config",	"-C",	"_nshconf" },
	{ PROC_KERNEL,	 0, "kernel",	"-K",	NULL },
	{ PROC_ARCHIVE,	 0, "archive",	"-A",	"_nsharc" },
};
#define NPROC	(sizeof(children) / sizeof(children[0]))

/* the children that talk, each two on a pipe of their own */
static const struct pair {
	enum nshd_proc	 a, b;
} pairs[] = {
	{ PROC_FRONTEND, PROC_CONFIG },
	{ PROC_CONFIG,	 PROC_KERNEL },
};
#define NPAIRS	(sizeof(pairs) / sizeof(pairs[0]))

static void		 parent_sig_handler(int, short, void *);
static void		 parent_dispatch(int, short, void *);
static void		 spawn_all(void);
static void		 spawn(struct child *);
static void		 start(struct child *, int);
static pid_t		 start_child(struct child *, int, int, int);
static int		 talks(enum nshd_proc);
static void		 pair_peers(struct child *);
static void		 pair(struct child *, struct child *);
static void		 tell(struct child *, struct child *, int);
static int		 out_open(struct child *);
static void		 out_close(struct child *);
static void		 out_write(int, short, void *);
static void		 restart(struct child *, const char *);
static int		 failed(struct child *);
static struct child	*child(enum nshd_proc, int);
static int		 shows_down(void);
static void		 users(void);
static __dead void	 parent_shutdown(int, const char *);
static __dead void	 usage(void);

static char		*argv0;
static int		 opt_debug, opt_verbose, rwfd, rofd;
static struct imsgev	*iev_relay;	/* to relay, with descriptors */
static struct imsgbuf	 relay_in;	/* from relay, without */

static __dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dv]\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct event		 ev_sigint, ev_sigterm, ev_sighup, ev_sigchld;
	struct group		*gr;
	const char		*errstr;
	int			 c, role = PROC_PARENT, instance = 0;

	argv0 = argv[0] != NULL ? argv[0] : "nshd";

	while ((c = getopt(argc, argv, "ACdFKRS:v")) != -1) {
		switch (c) {
		case 'A':
			role = PROC_ARCHIVE;
			break;
		case 'C':
			role = PROC_CONFIG;
			break;
		case 'd':
			opt_debug = 1;
			break;
		case 'F':
			role = PROC_FRONTEND;
			break;
		case 'K':
			role = PROC_KERNEL;
			break;
		case 'R':
			role = PROC_RELAY;
			break;
		case 'S':
			role = PROC_SHOW;
			instance = strtonum(optarg, 0, SHOWS - 1, &errstr);
			if (errstr != NULL)
				usage();
			break;
		case 'v':
			opt_verbose++;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	if (argc > 0)
		usage();

	switch (role) {
	case PROC_RELAY:
		relay(opt_debug, opt_verbose);
	case PROC_SHOW:
		showproc(opt_debug, opt_verbose, instance);
	case PROC_FRONTEND:
		frontend(opt_debug, opt_verbose);
	case PROC_CONFIG:
		configproc(opt_debug, opt_verbose);
	case PROC_KERNEL:
		kernproc(opt_debug, opt_verbose);
	case PROC_ARCHIVE:
		archive(opt_debug, opt_verbose);
	case PROC_PARENT:
		break;
	}

	if (geteuid())
		errx(1, "need root privileges");
	users();
	if ((gr = getgrnam(NSHD_GROUP)) == NULL)
		errx(1, "unknown group %s", NSHD_GROUP);
	/* what children start from, once daemon() has left the directory */
	if (strchr(argv0, '/') != NULL && (argv0 = realpath(argv0, NULL)) ==
	    NULL)
		err(1, "realpath");

	log_init(opt_debug, LOG_DAEMON);
	log_setverbose(opt_verbose);

	if (!opt_debug && daemon(0, 0) == -1)
		err(1, "daemon");

	/* kept, and never read, for each frontend and show started */
	if ((rwfd = control_init(NSHD_SOCKET, 0660, gr->gr_gid)) == -1)
		fatalx("cannot open %s", NSHD_SOCKET);
	if ((rofd = control_init(NSHD_RO_SOCKET, 0666, gr->gr_gid)) == -1)
		fatalx("cannot open %s", NSHD_RO_SOCKET);

	log_procinit("parent");
	setproctitle("parent");

	event_init();

	signal_set(&ev_sigint, SIGINT, parent_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, parent_sig_handler, NULL);
	signal_set(&ev_sighup, SIGHUP, parent_sig_handler, NULL);
	signal_set(&ev_sigchld, SIGCHLD, parent_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sighup, NULL);
	signal_add(&ev_sigchld, NULL);
	signal(SIGPIPE, SIG_IGN);

	spawn_all();

	if (pledge("stdio sendfd proc exec", NULL) == -1)
		fatal("pledge");

	event_dispatch();
	parent_shutdown(1, "event loop exit");
}

static struct child *
child(enum nshd_proc proc, int instance)
{
	size_t	 i;

	for (i = 0; i < NPROC; i++)
		if (children[i].proc == proc &&
		    children[i].instance == instance)
			return (&children[i]);
	return (NULL);
}

/* whether every show is down */
static int
shows_down(void)
{
	size_t	 i;

	for (i = 0; i < NPROC; i++)
		if (children[i].proc == PROC_SHOW && !children[i].down)
			return (0);
	return (1);
}

/* each child's user, which is not root, nor any other role's uid */
static void
users(void)
{
	struct passwd	*pw;
	uid_t		 uid[NPROC];
	size_t		 i, j;

	for (i = 0; i < NPROC; i++) {
		if (children[i].user == NULL)
			continue;
		if ((pw = getpwnam(children[i].user)) == NULL)
			errx(1, "unknown user %s", children[i].user);
		if ((uid[i] = pw->pw_uid) == 0)
			errx(1, "%s is root", children[i].user);
		for (j = 0; j < i; j++)
			if (children[j].user != NULL && uid[j] == uid[i] &&
			    strcmp(children[j].user, children[i].user) != 0)
				errx(1, "%s and %s are one uid",
				    children[j].user, children[i].user);
	}
}

/*
 * relay, and its pipe, written with descriptors and read without; then
 * each child that is not down, with the pipes to its peers
 */
static void
spawn_all(void)
{
	struct nshd_child	 ch;
	struct child		*r = child(PROC_RELAY, 0);
	size_t			 i;
	int			 sp[2], out[NPROC];

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, sp) == -1)
		fatal("socketpair");
	r->pid = start_child(r, sp[1], -1, -1);
	if ((iev_relay = imsgev_new(sp[0], parent_dispatch, 1)) == NULL ||
	    imsgbuf_init(&relay_in, sp[0]) == -1)
		fatal(NULL);

	for (i = 0; i < NPROC; i++) {
		out[i] = -1;
		if (children[i].proc == PROC_RELAY || children[i].down)
			continue;
		children[i].generation++;
		out[i] = out_open(&children[i]);
	}
	for (i = 0; i < NPAIRS; i++)
		pair(child(pairs[i].a, 0), child(pairs[i].b, 0));

	for (i = 0; i < NPROC; i++) {
		if (children[i].proc == PROC_RELAY)
			continue;
		if (!children[i].down) {
			start(&children[i], out[i]);
			continue;
		}
		ch.proc = children[i].proc;
		ch.instance = children[i].instance;
		ch.generation = children[i].generation;
		if (imsg_compose_event(iev_relay, IMSG_DOWN, 0, 0, -1, &ch,
		    sizeof(ch)) == -1)
			fatal("%s: down", children[i].name);
	}
}

/* c started again, with new pipes to its peers, each told of it */
static void
spawn(struct child *c)
{
	int	 out;

	c->generation++;
	out = out_open(c);
	pair_peers(c);
	start(c, out);
}

/* c, with its pipe to relay, relay the other end, and out from parent */
static void
start(struct child *c, int out)
{
	struct nshd_child	 ch;
	int			 sp[2], fd = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, sp) == -1)
		fatal("socketpair");
	if (c->proc == PROC_FRONTEND)
		fd = rwfd;
	else if (c->proc == PROC_SHOW)
		fd = rofd;
	/* its peers' pipes there before it starts */
	if (c->hasout && imsgbuf_flush(&c->out) == -1)
		fatal("%s: its peers' pipes", c->name);
	c->pid = start_child(c, sp[1], out, fd);
	ch.proc = c->proc;
	ch.instance = c->instance;
	ch.generation = c->generation;
	if (imsg_compose_event(iev_relay, IMSG_PIPE, 0, 0, sp[0], &ch,
	    sizeof(ch)) == -1)
		fatal("%s: its pipe", c->name);
}

/*
 * c, with pipefd as fd 3, then outfd and sockfd as the next, each if
 * not -1
 */
static pid_t
start_child(struct child *c, int pipefd, int outfd, int sockfd)
{
	char	*argv[6];
	int	 fds[3] = { pipefd, outfd, sockfd };
	int	 argc = 0, i, n = 3;
	pid_t	 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(pipefd);
		if (outfd != -1)
			close(outfd);
		return (pid);
	}

	/* above 5 first, so none lands on another's place */
	for (i = 0; i < 3; i++)
		if (fds[i] != -1 &&
		    (fds[i] = fcntl(fds[i], F_DUPFD_CLOEXEC, 6)) == -1)
			fatal("%s: its descriptors", c->name);
	for (i = 0; i < 3; i++)
		if (fds[i] != -1 && dup2(fds[i], n++) == -1)
			fatal("%s: its descriptors", c->name);

	argv[argc++] = argv0;
	argv[argc++] = c->flag;
	if (opt_debug)
		argv[argc++] = "-d";
	if (opt_verbose)
		argv[argc++] = "-v";
	argv[argc++] = NULL;

	execvp(argv0, argv);
	fatal("execvp");
}

/* whether p talks to any other child */
static int
talks(enum nshd_proc p)
{
	size_t	 i;

	for (i = 0; i < NPAIRS; i++)
		if (pairs[i].a == p || pairs[i].b == p)
			return (1);
	return (0);
}

/* whether a and b talk */
int
joined(enum nshd_proc a, enum nshd_proc b)
{
	size_t	 i;

	for (i = 0; i < NPAIRS; i++)
		if ((pairs[i].a == a && pairs[i].b == b) ||
		    (pairs[i].a == b && pairs[i].b == a))
			return (1);
	return (0);
}

/* c and each of its peers paired */
static void
pair_peers(struct child *c)
{
	size_t	 i;

	for (i = 0; i < NPAIRS; i++)
		if (pairs[i].a == c->proc)
			pair(c, child(pairs[i].b, 0));
		else if (pairs[i].b == c->proc)
			pair(c, child(pairs[i].a, 0));
}

/*
 * a pipe between a and b, each given its end; or, if one is down, the
 * other told so
 */
static void
pair(struct child *a, struct child *b)
{
	int	 sp[2];

	if (a->down || b->down) {
		if (!a->down)
			tell(a, b, -1);
		else if (!b->down)
			tell(b, a, -1);
		return;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, sp) == -1)
		fatal("socketpair");
	tell(a, b, sp[0]);
	tell(b, a, sp[1]);
}

/* to c, the pipe fd to its peer p, of p's generation, or -1: p is down */
static void
tell(struct child *c, struct child *p, int fd)
{
	struct nshd_child	 ch;

	ch.proc = p->proc;
	ch.instance = p->instance;
	ch.generation = p->generation;
	if (imsg_compose(&c->out, IMSG_PEER, 0, 0, fd, &ch, sizeof(ch)) ==
	    -1)
		fatal("%s: %s's pipe", c->name, p->name);
	event_add(&c->outev, NULL);
}

/*
 * the pipe from parent to c, if it has peers, which parent writes and
 * never reads: c's end of it, or -1
 */
static int
out_open(struct child *c)
{
	int	 sp[2];

	if (!talks(c->proc))
		return (-1);
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, sp) == -1)
		fatal("socketpair");
	if (imsgbuf_init(&c->out, sp[0]) == -1)
		fatal(NULL);
	imsgbuf_allow_fdpass(&c->out);
	event_set(&c->outev, sp[0], EV_WRITE, out_write, c);
	c->hasout = 1;
	return (sp[1]);
}

static void
out_close(struct child *c)
{
	if (!c->hasout)
		return;
	event_del(&c->outev);
	imsgbuf_clear(&c->out);
	close(c->out.fd);
	c->hasout = 0;
}

/* what parent told c, once its pipe may be written */
static void
out_write(int fd, short event, void *arg)
{
	struct child	*c = arg;

	/* c is gone, which relay tells, and what it was told with it */
	if (imsgbuf_write(&c->out) == -1) {
		imsgbuf_clear(&c->out);
		return;
	}
	if (imsgbuf_queuelen(&c->out) > 0)
		event_add(&c->outev, NULL);
}

/* whether c, failing now, has failed RESTARTS times in RESTART_SECS */
static int
failed(struct child *c)
{
	struct timespec	 ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		fatal("clock_gettime");
	c->fails[c->nfails++ % RESTARTS] = ts.tv_sec;
	/* the oldest of the last RESTARTS */
	return (c->nfails >= RESTARTS &&
	    ts.tv_sec - c->fails[c->nfails % RESTARTS] < RESTART_SECS);
}

/*
 * c, gone wrong: killed if it is not gone already, and started again,
 * unless it has failed RESTARTS times in RESTART_SECS; relay with every
 * child, as each child's life is told on relay's pipes
 */
static void
restart(struct child *c, const char *why)
{
	struct nshd_child	 ch;
	size_t			 i;
	int			 down;

	log_warnx("%s %s", c->name, why);
	down = failed(c);
	if (down)
		log_warnx("%s failed %d times in %d seconds, and stays down",
		    c->name, RESTARTS, RESTART_SECS);

	if (c->proc == PROC_RELAY) {
		for (i = 0; i < NPROC; i++) {
			if (children[i].pid > 0)
				kill(children[i].pid, SIGKILL);
			children[i].pid = -1;	/* reaped on SIGCHLD */
			out_close(&children[i]);
		}
		event_del(&iev_relay->ev);
		imsgbuf_clear(&iev_relay->ibuf);
		imsgbuf_clear(&relay_in);
		close(iev_relay->ibuf.fd);
		free(iev_relay);
		iev_relay = NULL;
		if (down)
			parent_shutdown(1, "no child talks without relay");
		spawn_all();
		return;
	}

	if (c->pid > 0)
		kill(c->pid, SIGKILL);
	c->pid = -1;
	out_close(c);
	if (!down) {
		spawn(c);
		return;
	}
	c->down = 1;
	/* its peers, told so */
	pair_peers(c);
	/* refused, rather than left waiting for no one */
	if (c->proc == PROC_FRONTEND) {
		close(rwfd);
		rwfd = -1;
	} else if (c->proc == PROC_SHOW && shows_down()) {
		close(rofd);
		rofd = -1;
	}
	ch.proc = c->proc;
	ch.instance = c->instance;
	ch.generation = c->generation;
	if (imsg_compose_event(iev_relay, IMSG_DOWN, 0, 0, -1, &ch,
	    sizeof(ch)) == -1)
		fatal("%s: down", c->name);
}

static void
parent_sig_handler(int sig, short event, void *arg)
{
	char	 why[32];
	int	 status, serrno = errno;
	size_t	 i;
	pid_t	 pid;

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		parent_shutdown(0, "terminating on signal");
	case SIGHUP:
		break;
	case SIGCHLD:
		while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
			for (i = 0; i < NPROC; i++) {
				if (pid != children[i].pid)
					continue;
				children[i].pid = -1;
				if (WIFSIGNALED(status))
					snprintf(why, sizeof(why),
					    "killed by signal %d",
					    WTERMSIG(status));
				else
					snprintf(why, sizeof(why), "exited %d",
					    WEXITSTATUS(status));
				/*
				 * relay says when a child went wrong: every
				 * child goes when relay does, and that is
				 * relay's failure
				 */
				if (children[i].proc == PROC_RELAY)
					restart(&children[i], why);
				else
					log_warnx("%s %s", children[i].name,
					    why);
			}
		break;
	}
	errno = serrno;
}

/* relay's word, which is all parent reads */
static void
parent_dispatch(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_child	 ch;
	struct child		*c;
	char			 why[64];
	ssize_t			 n;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(&relay_in)) == -1 || n == 0) {
			restart(child(PROC_RELAY, 0), "closed its pipe");
			return;
		}
	}
	if ((event & EV_WRITE) && imsgbuf_write(&iev->ibuf) == -1) {
		restart(child(PROC_RELAY, 0), "closed its pipe");
		return;
	}

	for (;;) {
		if ((n = imsgbuf_get(&relay_in, &imsg)) == -1) {
			restart(child(PROC_RELAY, 0),
			    "sent what imsg cannot read");
			return;
		}
		if (n == 0)
			break;
		if (imsg_get_type(&imsg) != IMSG_BROKEN ||
		    imsg_get_data(&imsg, &ch, sizeof(ch)) == -1 ||
		    (c = child(ch.proc, ch.instance)) == NULL ||
		    c->proc == PROC_RELAY) {
			snprintf(why, sizeof(why),
			    "sent imsg %u, which it may not",
			    imsg_get_type(&imsg));
			imsg_free(&imsg);
			restart(child(PROC_RELAY, 0), why);
			return;
		}
		imsg_free(&imsg);
		/* not one started since, nor one down already */
		if (ch.generation == c->generation && !c->down)
			restart(c, "went wrong, relay says");
	}
	imsg_event_add(iev);
}

static __dead void
parent_shutdown(int status, const char *why)
{
	size_t	 i;

	log_info("%s", why);
	for (i = 0; i < NPROC; i++)
		if (children[i].pid > 0)
			kill(children[i].pid, SIGTERM);
	exit(status);
}

static void
child_sig_handler(int sig, short event, void *arg)
{
	event_loopexit(NULL);
}

/* a child's logs and name, and the signals that end it */
void
child_start(const char *name, int debug, int verbose)
{
	static struct event	 ev_sigint, ev_sigterm;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);
	log_procinit(name);
	setproctitle("%s", name);

	event_init();
	signal_set(&ev_sigint, SIGINT, child_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, child_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
}

/* chroot to proc's user's home and become its user */
void
privdrop(enum nshd_proc proc)
{
	struct passwd	*pw;
	const char	*user = child(proc, 0)->user;

	if ((pw = getpwnam(user)) == NULL)
		fatalx("unknown user %s", user);
	if (chroot(pw->pw_dir) == -1)
		fatal("chroot %s", pw->pw_dir);
	if (chdir("/") == -1)
		fatal("chdir /");
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("cannot drop privileges");
}

static struct link	*links;
static size_t		 nlinks;
static struct imsgev	*links_relay;

static void		 links_dispatch(int, short, void *);
static void		 link_take(struct imsg *);
static void		 link_close(struct link *);

/*
 * A child's n peers, in l, each with its pipe from parent, on fd 4, or
 * none if it is down: those parent wrote before the child started are
 * taken first, so its first requests have a peer to go to. A peer gone
 * wrong is told relay
 */
void
links_init(struct link *l, size_t n, struct imsgev *relay)
{
	struct pollfd	 pfd;
	struct imsgev	*iev;
	struct imsg	 imsg;
	size_t		 have = 0;
	ssize_t		 r;

	links = l;
	nlinks = n;
	links_relay = relay;
	if ((iev = imsgev_new(4, links_dispatch, 1)) == NULL)
		fatal(NULL);
	while (have < n) {
		if ((r = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("%s", __func__);
		if (r > 0) {
			link_take(&imsg);
			imsg_free(&imsg);
			have++;
			continue;
		}
		pfd.fd = 4;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, -1) == -1)
			fatal("%s: poll", __func__);
		if ((r = imsgbuf_read(&iev->ibuf)) == -1)
			fatal("%s", __func__);
		if (r == 0)
			fatalx("%s: parent's pipe closed", __func__);
	}
}

/* parent's word of a peer; once parent is gone, relay ends the child */
static void
links_dispatch(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct imsg	 imsg;
	ssize_t		 n;

	if (imsgev_io(iev, event) == -1) {
		event_del(&iev->ev);
		return;
	}
	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("%s", __func__);
		if (n == 0)
			break;
		link_take(&imsg);
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/*
 * a peer's pipe, of the generation it started with, in place of the one
 * before, or that it is down: what it held is forgotten first, as it is
 * not the peer that held it
 */
static void
link_take(struct imsg *imsg)
{
	struct nshd_child	 ch;
	struct link		*l = NULL;
	size_t			 i;
	int			 fd;

	if (imsg_get_type(imsg) == IMSG_PEER &&
	    imsg_get_data(imsg, &ch, sizeof(ch)) == 0)
		for (i = 0; i < nlinks; i++)
			if ((int)links[i].proc == ch.proc)
				l = &links[i];
	if (l == NULL || ch.generation < l->generation)
		fatalx("%s: bad imsg %u", __func__, imsg_get_type(imsg));
	fd = imsg_get_fd(imsg);
	link_close(l);
	l->generation = ch.generation;
	l->down = fd == -1;
	l->forget();
	if (fd != -1 && (l->iev = imsgev_new(fd, l->handler, 0)) == NULL)
		fatal(NULL);
}

static void
link_close(struct link *l)
{
	struct imsgev	**iev[] = { &l->iev, &l->wrong };
	size_t		  i;

	for (i = 0; i < 2; i++) {
		if (*iev[i] == NULL)
			continue;
		event_del(&(*iev[i])->ev);
		imsgbuf_clear(&(*iev[i])->ibuf);
		close((*iev[i])->ibuf.fd);
		free(*iev[i]);
		*iev[i] = NULL;
	}
}

/* to l's peer, if there is a pipe to it: what crosses its going is lost */
int
link_compose(struct link *l, uint32_t type, uint32_t id, const void *data,
    size_t len)
{
	if (l->iev == NULL)
		return (0);
	return (imsg_compose_event(l->iev, type, id, 0, -1, data, len));
}

/*
 * l's peer gone wrong: nothing more read from it or written to it, and
 * relay told, which tells parent, which starts it again. Its pipe stays
 * open until then, so it does not see this child go and say so
 */
void
link_broken(struct link *l, const char *fmt, ...)
{
	struct nshd_child	 ch;
	va_list			 ap;
	char			*why;

	va_start(ap, fmt);
	if (vasprintf(&why, fmt, ap) == -1)
		fatal("%s", __func__);
	va_end(ap);
	log_warnx("%s %s", child(l->proc, 0)->name, why);
	free(why);

	if (l->iev != NULL && l->wrong == NULL) {
		event_del(&l->iev->ev);
		l->wrong = l->iev;
	} else
		link_close(l);
	l->iev = NULL;
	ch.proc = l->proc;
	ch.instance = 0;
	ch.generation = l->generation;
	if (imsg_compose_event(links_relay, IMSG_BROKEN, 0, 0, -1, &ch,
	    sizeof(ch)) == -1)
		fatal("%s", __func__);
}

/* a channel on fd, read and written by handler */
struct imsgev *
imsgev_new(int fd, void (*handler)(int, short, void *), int fdpass)
{
	struct imsgev	*iev;

	if ((iev = calloc(1, sizeof(*iev))) == NULL)
		return (NULL);
	if (imsgbuf_init(&iev->ibuf, fd) == -1) {
		free(iev);
		return (NULL);
	}
	if (fdpass)
		imsgbuf_allow_fdpass(&iev->ibuf);
	iev->handler = handler;
	iev->events = EV_READ;
	event_set(&iev->ev, fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
	return (iev);
}

/*
 * iev's reads and writes for event; -1 if its peer is gone, or sent
 * what imsg cannot read
 */
int
imsgev_io(struct imsgev *iev, short event)
{
	ssize_t	 n;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(&iev->ibuf)) == -1) {
			log_warn("imsgbuf_read");
			return (-1);
		}
		if (n == 0)
			return (-1);
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(&iev->ibuf) == -1) {
			if (errno != EPIPE)
				log_warn("imsgbuf_write");
			return (-1);
		}
	}
	return (0);
}

/* stdout, from now on, to an unlinked file, which printed() reads */
void
capture_stdout(void)
{
	char	 path[] = "/tmp/nshd.out.XXXXXXXXXX";
	int	 fd;

	if ((fd = mkstemp(path)) == -1 || unlink(path) == -1 ||
	    dup2(fd, STDOUT_FILENO) == -1)
		fatal("%s", path);
	close(fd);
}

/*
 * What nsh's code printed since, as messages in o, or forgotten if o is
 * NULL; -1 if a message could not be made, or what was printed could
 * not all be kept
 */
int
printed(struct facts_out *o)
{
	char	 buf[1024];
	off_t	 off = 0;
	ssize_t	 n;
	int	 r = 0;

	if (fflush(stdout) == EOF) {
		log_warn("%s: stdout", __func__);
		r = -1;
	}
	clearerr(stdout);
	while (o != NULL &&
	    (n = pread(STDOUT_FILENO, buf, sizeof(buf) - 1, off)) > 0) {
		buf[n] = '\0';
		off += n;
		if (facts_message(o, "%s", buf) == -1)
			r = -1;
	}
	if (ftruncate(STDOUT_FILENO, 0) == -1 ||
	    lseek(STDOUT_FILENO, 0, SEEK_SET) == -1)
		fatal("%s", __func__);
	return (r);
}

/*
 * text as messages of type, NSHD_TEXT bytes at most each; on no pipe,
 * lost, as link_compose() loses it
 */
int
imsg_text(struct imsgev *iev, uint32_t type, uint32_t id, const char *text,
    size_t len)
{
	size_t	 n;

	while (iev != NULL && len > 0) {
		n = len < NSHD_TEXT ? len : NSHD_TEXT;
		if (imsg_compose_event(iev, type, id, 0, -1, text, n) == -1)
			return (-1);
		text += n;
		len -= n;
	}
	return (0);
}

void
imsg_event_add(struct imsgev *iev)
{
	iev->events = EV_READ;
	if (imsgbuf_queuelen(&iev->ibuf) > 0)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}

int
imsg_compose_event(struct imsgev *iev, uint32_t type, uint32_t peerid,
    pid_t pid, int fd, const void *data, size_t datalen)
{
	int	 r;

	if ((r = imsg_compose(&iev->ibuf, type, peerid, pid, fd, data,
	    datalen)) == -1)
		return (-1);
	imsg_event_add(iev);
	return (r);
}
