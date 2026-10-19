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
 *	relay (-R)	_nshd, chroot: every message between the others
 *	show (-Sn)	_nshd, chroot: the read-only socket, SHOWS of
 *			them, n from 0, so one long answer holds up no other
 *	frontend (-F)	_nshd, chroot: the read-write socket, sessions
 *	config (-C)	_nshd, chroot: sessions' state, what to ask kernel
 *	kernel (-K)	root: reads and changes the kernel
 *	archive (-A)	_nshd, chroot: the configurations saved
 *
 * Each child has one imsg pipe, to relay, as fd 3, a show as much as any
 * other, though relay forwards nothing from a show; frontend and each
 * show have their socket as fd 4, and no other child has it. parent
 * gives relay each child's pipe, and from then on reads only what relay
 * sends it, on a pipe that passes it no descriptor.
 *
 * nshd stays up for all that depends on it. A child that relay says went
 * wrong, its pipe closed or a rule broken, is killed and started again,
 * and relay tells its peers. One that fails RESTARTS times in
 * RESTART_SECS stays down: its peers answer for it, and if it is
 * frontend, or the last show, parent closes the socket, which no process
 * then holds, so clients are refused. If relay goes wrong, every child
 * goes with it, and all start again; if relay fails RESTARTS times in
 * RESTART_SECS, nshd ends.
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
#include <pwd.h>
#include <signal.h>
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

#define RESTARTS	5	/* failures in RESTART_SECS, and one stays down */
#define RESTART_SECS	60

static struct child {
	enum nshd_proc	 proc;
	int		 instance;
	char		*name;
	char		*flag;
	pid_t		 pid;
	uint32_t	 generation;
	unsigned int	 nfails;
	time_t		 fails[RESTARTS];	/* the last ones, monotonic */
	int		 down;
} children[] = {
	{ PROC_RELAY,	 0, "relay",	"-R" },
	/* SHOWS of them */
	{ PROC_SHOW,	 0, "show0",	"-S0" },
	{ PROC_SHOW,	 1, "show1",	"-S1" },
	{ PROC_SHOW,	 2, "show2",	"-S2" },
	{ PROC_SHOW,	 3, "show3",	"-S3" },
	{ PROC_FRONTEND, 0, "frontend",	"-F" },
	{ PROC_CONFIG,	 0, "config",	"-C" },
	{ PROC_KERNEL,	 0, "kernel",	"-K" },
	{ PROC_ARCHIVE,	 0, "archive",	"-A" },
};
#define NPROC	(sizeof(children) / sizeof(children[0]))

static void		 parent_sig_handler(int, short, void *);
static void		 parent_dispatch(int, short, void *);
static void		 spawn_all(void);
static void		 spawn(struct child *);
static pid_t		 start_child(struct child *, int, int);
static void		 restart(struct child *, const char *);
static int		 failed(struct child *);
static struct child	*child(enum nshd_proc, int);
static int		 shows_down(void);
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
	if (getpwnam(NSHD_USER) == NULL)
		errx(1, "unknown user %s", NSHD_USER);
	if ((gr = getgrnam(NSHD_USER)) == NULL)
		errx(1, "unknown group %s", NSHD_USER);
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

/*
 * relay, and its pipe, written with descriptors and read without; then
 * each child that is not down
 */
static void
spawn_all(void)
{
	struct nshd_child	 ch;
	struct child		*r = child(PROC_RELAY, 0);
	size_t			 i;
	int			 sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, sp) == -1)
		fatal("socketpair");
	r->pid = start_child(r, sp[1], -1);
	if ((iev_relay = imsgev_new(sp[0], parent_dispatch, 1)) == NULL ||
	    imsgbuf_init(&relay_in, sp[0]) == -1)
		fatal(NULL);

	for (i = 0; i < NPROC; i++) {
		if (children[i].proc == PROC_RELAY)
			continue;
		if (!children[i].down) {
			spawn(&children[i]);
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

/* c, with its pipe to relay, and relay the other end */
static void
spawn(struct child *c)
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
	c->pid = start_child(c, sp[1], fd);
	ch.proc = c->proc;
	ch.instance = c->instance;
	ch.generation = ++c->generation;
	if (imsg_compose_event(iev_relay, IMSG_PIPE, 0, 0, sp[0], &ch,
	    sizeof(ch)) == -1)
		fatal("%s: its pipe", c->name);
}

/* c, with pipefd as fd 3 and sockfd, if not -1, as fd 4 */
static pid_t
start_child(struct child *c, int pipefd, int sockfd)
{
	char	*argv[6];
	int	 argc = 0;
	pid_t	 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(pipefd);
		return (pid);
	}

	/* above 4 first, so neither lands on the other's place */
	if ((pipefd = fcntl(pipefd, F_DUPFD_CLOEXEC, 5)) == -1 ||
	    (sockfd != -1 && (sockfd = fcntl(sockfd, F_DUPFD_CLOEXEC,
	    5)) == -1) ||
	    dup2(pipefd, 3) == -1 ||
	    (sockfd != -1 && dup2(sockfd, 4) == -1))
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
 * child, as no child talks without it
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
	if (!down) {
		spawn(c);
		return;
	}
	c->down = 1;
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

/* chroot to _nshd's home and become _nshd */
void
privdrop(void)
{
	struct passwd	*pw;

	if ((pw = getpwnam(NSHD_USER)) == NULL)
		fatalx("unknown user %s", NSHD_USER);
	if (chroot(pw->pw_dir) == -1)
		fatal("chroot %s", pw->pw_dir);
	if (chdir("/") == -1)
		fatal("chdir /");
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("cannot drop privileges");
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

/* text as messages of type, NSHD_TEXT bytes at most each */
int
imsg_text(struct imsgev *iev, uint32_t type, uint32_t id, const char *text,
    size_t len)
{
	size_t	 n;

	while (len > 0) {
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
