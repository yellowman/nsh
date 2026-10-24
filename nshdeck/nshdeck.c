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
 * nshdeck: nshd's web configurator, a FastCGI daemon behind httpd(8).
 *
 * parent, started as root, binds the socket httpd connects to, and
 * starts the children, each this program again, by the path
 * getexecpath(3) gives, with a flag for its part:
 *
 *	front (-F)	DECK_FRONT, chroot: httpd's connections, all of what
 *			they send read and checked, each request passed to
 *			session as a typed message
 *	session (-S)	DECK_USER, chroot: a connection of nshd's for each
 *			web user logged in, known by its cookie's token,
 *			and each answer, as JSON
 *
 * Each child has a pipe to parent as fd 3, front and session a pipe to
 * each other as fd 4, and front the socket as fd 5; none is passed
 * later. Then parent becomes DECK_USER, with that user's groups, so
 * nshd's read-write socket takes it, and does one thing: when session
 * asks, it connects to nshd, which takes a client of DECK_USER's uid
 * for the web configurator's, or to nshd's read-only socket, for a show
 * only nshd's shows answer, and passes the connection on. A child
 * that ends, or that sends parent anything else, ends nshdeck, as each
 * child ends once its pipe to parent closes; nothing is started again.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <grp.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "nshdeck.h"

static struct child {
	const char	*name;
	char		*flag;
	pid_t		 pid;
	struct deck_pipe p;		/* its pipe to parent */
} children[] = {
	{ "front",	"-F" },
	{ "session",	"-S" },
};
#define FRONT		0
#define SESSION		1
#define NCHILDREN	(sizeof(children) / sizeof(children[0]))

static void	 parent_sig(int, short, void *);
static void	 parent_dispatch(int, short, void *);
static void	 parent_connect(uint32_t, int32_t);
static void	 users(void);
static int	 deck_socket(const char *, gid_t);
static pid_t	 start_child(struct child *, int, int, int);
static __dead void usage(void);

static char	 execpath[PATH_MAX];	/* this program, which children run */
static int	 opt_debug, opt_verbose;

static __dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dv] [-s socket]\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct event	 ev_sigint, ev_sigterm, ev_sigchld;
	struct passwd	*pw;
	struct group	*gr;
	const char	*path = DECK_SOCKET;
	size_t		 i;
	int		 c, role = 0, sock, sp[2], peer[2];

	while ((c = getopt(argc, argv, "dFSs:v")) != -1) {
		switch (c) {
		case 'd':
			opt_debug = 1;
			break;
		case 'F':
		case 'S':
			role = c;
			break;
		case 's':
			path = optarg;
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

	if (role == 'F')
		front(opt_debug, opt_verbose);
	if (role == 'S')
		sessions(opt_debug, opt_verbose);

	if (geteuid())
		errx(1, "need root privileges");
	users();
	if ((gr = getgrnam(DECK_GROUP)) == NULL)
		errx(1, "unknown group %s", DECK_GROUP);
	if (getexecpath(execpath, sizeof(execpath)) == -1)
		err(1, "getexecpath");

	log_init(opt_debug, LOG_DAEMON);
	log_setverbose(opt_verbose);
	if (!opt_debug && daemon(0, 0) == -1)
		err(1, "daemon");

	if ((sock = deck_socket(path, gr->gr_gid)) == -1)
		fatalx("cannot open %s", path);
	log_procinit("parent");
	setproctitle("parent");

	event_init();
	signal_set(&ev_sigint, SIGINT, parent_sig, NULL);
	signal_set(&ev_sigterm, SIGTERM, parent_sig, NULL);
	signal_set(&ev_sigchld, SIGCHLD, parent_sig, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sigchld, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* front's and session's pipe, then each child's to parent */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, peer) == -1)
		fatal("socketpair");
	for (i = 0; i < NCHILDREN; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC |
		    SOCK_NONBLOCK, PF_UNSPEC, sp) == -1)
			fatal("socketpair");
		children[i].pid = start_child(&children[i], sp[1], peer[i],
		    i == FRONT ? sock : -1);
		close(sp[1]);
		if (pipe_init(&children[i].p, sp[0], parent_dispatch,
		    i == SESSION) == -1)
			fatal(NULL);
	}
	close(peer[0]);
	close(peer[1]);
	close(sock);

	/* DECK_USER, with its groups, which nshd's socket takes */
	if ((pw = getpwnam(DECK_USER)) == NULL)
		fatalx("unknown user %s", DECK_USER);
	if (initgroups(pw->pw_name, pw->pw_gid) == -1 ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatal("cannot drop privileges");
	if (unveil(NSHD_SOCKET, "rw") == -1 ||
	    unveil(NSHD_RO_SOCKET, "rw") == -1 || unveil(NULL, NULL) == -1)
		fatal("unveil");
	if (pledge("stdio unix sendfd", NULL) == -1)
		fatal("pledge");

	event_dispatch();
	exit(1);
}

/* the children's users, each its own, and neither root */
static void
users(void)
{
	struct passwd	*pw;
	uid_t		 deck, front;

	if ((pw = getpwnam(DECK_USER)) == NULL)
		errx(1, "unknown user %s", DECK_USER);
	deck = pw->pw_uid;
	if ((pw = getpwnam(DECK_FRONT)) == NULL)
		errx(1, "unknown user %s", DECK_FRONT);
	front = pw->pw_uid;
	if (deck == 0 || front == 0)
		errx(1, "%s is root", deck == 0 ? DECK_USER : DECK_FRONT);
	if (deck == front)
		errx(1, "%s and %s are one uid", DECK_USER, DECK_FRONT);
}

/* the socket at path, root's and gid's, 0660: its descriptor, or -1 */
static int
deck_socket(const char *path, gid_t gid)
{
	struct sockaddr_un	 sun;
	mode_t			 old;
	int			 fd;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		log_warnx("%s: too long", path);
		return (-1);
	}
	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    0)) == -1) {
		log_warn("socket");
		return (-1);
	}
	if (unlink(path) == -1 && errno != ENOENT) {
		log_warn("unlink %s", path);
		close(fd);
		return (-1);
	}
	/* no one may connect before it has its owner and mode */
	old = umask(S_IRWXG | S_IRWXO);
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_warn("bind %s", path);
		umask(old);
		close(fd);
		return (-1);
	}
	umask(old);
	if (chown(path, 0, gid) == -1 || chmod(path, 0660) == -1) {
		log_warn("%s", path);
		unlink(path);
		close(fd);
		return (-1);
	}
	return (fd);
}

/* c, with pipefd as fd 3, peerfd as 4, and sockfd, if not -1, as 5 */
static pid_t
start_child(struct child *c, int pipefd, int peerfd, int sockfd)
{
	char	*argv[5];
	int	 fds[3] = { pipefd, peerfd, sockfd };
	int	 argc = 0, i;
	pid_t	 pid;

	switch (pid = fork()) {
	case -1:
		fatal("fork");
	case 0:
		break;
	default:
		return (pid);
	}
	/* above 5 first, so none lands on another's place */
	for (i = 0; i < 3; i++)
		if (fds[i] != -1 &&
		    (fds[i] = fcntl(fds[i], F_DUPFD_CLOEXEC, 6)) == -1)
			fatal("%s: its descriptors", c->name);
	for (i = 0; i < 3; i++)
		if (fds[i] != -1 && dup2(fds[i], 3 + i) == -1)
			fatal("%s: its descriptors", c->name);
	argv[argc++] = execpath;
	argv[argc++] = c->flag;
	if (opt_debug)
		argv[argc++] = "-d";
	if (opt_verbose)
		argv[argc++] = "-v";
	argv[argc] = NULL;
	execv(execpath, argv);
	fatal("execv");
}

static void
parent_sig(int sig, short event, void *arg)
{
	int	 status;
	pid_t	 pid;
	size_t	 i;

	if (sig != SIGCHLD)
		exit(0);
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
		for (i = 0; i < NCHILDREN; i++)
			if (pid == children[i].pid)
				fatalx("%s ended: nshdeck ends with it",
				    children[i].name);
}

/*
 * A child's word: session's asking for a connection to nshd, and no
 * other. Anything else, or a pipe closed, ends nshdeck
 */
static void
parent_dispatch(int fd, short event, void *arg)
{
	struct child	*c = NULL;
	struct imsg	 imsg;
	size_t		 i;
	int32_t		 ro;
	int		 n;

	for (i = 0; i < NCHILDREN; i++)
		if (&children[i].p == arg)
			c = &children[i];
	if (c == NULL)
		fatalx("%s: from no child", __func__);
	if (pipe_io(&c->p, event) == -1)
		fatalx("%s closed its pipe", c->name);
	for (;;) {
		if ((n = imsgbuf_get(&c->p.ibuf, &imsg)) == -1)
			fatalx("%s sent what imsg cannot read", c->name);
		if (n == 0)
			break;
		if (c != &children[SESSION] ||
		    imsg_get_type(&imsg) != DECK_CONNECT ||
		    imsg_get_data(&imsg, &ro, sizeof(ro)) == -1 ||
		    (ro != 0 && ro != 1))
			fatalx("%s sent imsg %u, which it may not", c->name,
			    imsg_get_type(&imsg));
		parent_connect(imsg_get_id(&imsg), ro);
		imsg_free(&imsg);
	}
	pipe_event(&c->p);
}

/*
 * to session, for id: a connection to nshd, to its shows if ro, or why
 * there is none
 */
static void
parent_connect(uint32_t id, int32_t ro)
{
	struct sockaddr_un	 sun;
	int32_t			 serrno = 0;
	int			 fd;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, ro ? NSHD_RO_SOCKET : NSHD_SOCKET,
	    sizeof(sun.sun_path));
	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
		serrno = errno;
	else if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		serrno = errno;
		close(fd);
		fd = -1;
	}
	pipe_compose(&children[SESSION].p, DECK_CONNECTED, id, fd, &serrno,
	    sizeof(serrno));
}

static void
child_sig(int sig, short event, void *arg)
{
	event_loopexit(NULL);
}

/* a child's logs and name, and the signals that end it */
void
deck_child(const char *name, int debug, int verbose)
{
	static struct event	 ev_sigint, ev_sigterm;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);
	log_procinit(name);
	setproctitle("%s", name);
	event_init();
	signal_set(&ev_sigint, SIGINT, child_sig, NULL);
	signal_set(&ev_sigterm, SIGTERM, child_sig, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
}

/* chroot to user's home, and become user */
void
deck_drop(const char *user)
{
	struct passwd	*pw;

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

/* p, on fd, read and written by handler, passing descriptors if fdpass */
int
pipe_init(struct deck_pipe *p, int fd, void (*handler)(int, short, void *),
    int fdpass)
{
	if (imsgbuf_init(&p->ibuf, fd) == -1)
		return (-1);
	if (fdpass)
		imsgbuf_allow_fdpass(&p->ibuf);
	p->handler = handler;
	p->events = 0;
	p->paused = 0;
	pipe_event(p);
	return (0);
}

/* p read, unless paused, and written while it has something to write */
void
pipe_event(struct deck_pipe *p)
{
	short	 events = p->paused ? 0 : EV_READ;

	if (imsgbuf_queuelen(&p->ibuf) > 0)
		events |= EV_WRITE;
	if (p->events != 0)
		event_del(&p->ev);
	p->events = events;
	if (events == 0)
		return;
	event_set(&p->ev, p->ibuf.fd, events, p->handler, p);
	event_add(&p->ev, NULL);
}

/* what event says p may do, done: -1 if p is closed, or broken */
int
pipe_io(struct deck_pipe *p, short event)
{
	int	 n;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(&p->ibuf)) == -1 || n == 0)
			return (-1);
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(&p->ibuf) == -1)
			return (-1);
	}
	return (0);
}

/* p, and its descriptor, closed */
void
pipe_close(struct deck_pipe *p)
{
	if (p->events != 0)
		event_del(&p->ev);
	p->events = 0;
	imsgbuf_clear(&p->ibuf);
	close(p->ibuf.fd);
}

/* to p's peer: type, for id, with fd, if not -1, and data */
void
pipe_compose(struct deck_pipe *p, uint32_t type, uint32_t id, int fd,
    const void *data, size_t len)
{
	if (imsg_compose(&p->ibuf, type, id, 0, fd, data, len) == -1)
		fatal("%s", __func__);
	pipe_event(p);
}
