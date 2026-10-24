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
 * parent binds the two sockets and starts the children, each this
 * program again, by the path getexecpath(3) gives, with a flag for its
 * part:
 *
 *	show (-Sn)	_nshshow, chroot: the read-only socket, SHOWS of
 *			them, n from 0, so one long answer holds up no other
 *	frontend (-F)	_nshfront, chroot: the read-write socket, sessions
 *	config (-C)	_nshconf, chroot: sessions' state, what to ask system
 *	system (-Y)	root, a session of its own: reads and changes the
 *			kernel, the daemons and the saved configuration
 *	archive (-A)	_nsharc, chroot: what config keeps past its end
 *
 * Each user is a role's alone, so no child may signal another of
 * another role, or reach its files; the group nshadmin may use the
 * read-write socket. system's helpers that need not be root run as
 * NSHD_CHECK_USER, whose uid is theirs alone too.
 *
 * Two children that talk, frontend and config, config and system,
 * config and archive, and frontend and system, do so on a pipe of their
 * own, which parent makes, so each knows who sent what it reads. Each
 * child has a pipe to parent, as fd 3, which tells it when it may
 * start; one with peers has a pipe from parent, as fd 4, which gives it
 * each peer's pipe before it starts, and is closed then; frontend and
 * each show have their socket after these, and no other child has it,
 * and config a routing socket, which tells it what the kernel changes.
 * No pipe is made or passed once the children start. parent reads, of
 * what children send, config's word that the boot is done, and nothing
 * else.
 *
 * A child that ends, or that breaks a rule, ends nshd: its peers find
 * their pipes to it closed and end too, and parent ends the rest, and
 * system's helpers with them, as they run beyond system. Nothing is
 * started again. A commit not confirmed whose nshd ends goes back when
 * nshd starts again, and system finds its record.
 *
 * With -b, as rc starts it, nshd boots: config has system make the
 * running configuration the saved one, while frontend and the shows
 * hold their sockets, and parent tells them to take clients once config
 * says the boot is done. rc waits for it: the process rc started exits
 * then, 0 if the boot went well, else 1, as it does if nshd ends before.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/signal.h>
#include <sys/proc.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <grp.h>
#include <imsg.h>
#include <limits.h>
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
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "control.h"
#include "facts.h"
#include "showfacts.h"

#define CLEAR_TRIES	200	/* system's helpers killed, 10 ms apart */

static struct child {
	enum nshd_proc	 proc;
	int		 instance;
	char		*name;
	char		*flag;
	char		*user;		/* chrooted to its home, or root */
	pid_t		 pid;
	struct imsgev	*iev;		/* its pipe to parent, fd 3 */
	struct imsgbuf	 out;		/* its peers' pipes, fd 4 */
	int		 hasout;
} children[] = {
	/* SHOWS of them */
	{ PROC_SHOW,	 0, "show0",	"-S0",	"_nshshow" },
	{ PROC_SHOW,	 1, "show1",	"-S1",	"_nshshow" },
	{ PROC_SHOW,	 2, "show2",	"-S2",	"_nshshow" },
	{ PROC_SHOW,	 3, "show3",	"-S3",	"_nshshow" },
	{ PROC_FRONTEND, 0, "frontend",	"-F",	"_nshfront" },
	{ PROC_CONFIG,	 0, "config",	"-C",	"_nshconf" },
	{ PROC_SYSTEM,	 0, "system",	"-Y",	NULL },
	{ PROC_ARCHIVE,	 0, "archive",	"-A",	"_nsharc" },
};
#define NPROC	(sizeof(children) / sizeof(children[0]))

/* the children that talk, each two on a pipe of their own */
static const struct pair {
	enum nshd_proc	 a, b;
} pairs[] = {
	{ PROC_FRONTEND, PROC_CONFIG },
	{ PROC_CONFIG,	 PROC_SYSTEM },
	{ PROC_CONFIG,	 PROC_ARCHIVE },
	{ PROC_FRONTEND, PROC_SYSTEM },
};
#define NPAIRS	(sizeof(pairs) / sizeof(pairs[0]))

static void		 parent_sig_handler(int, short, void *);
static void		 parent_dispatch(int, short, void *);
static void		 spawn_all(void);
static void		 start(struct child *, int);
static pid_t		 start_child(struct child *, int, int, int);
static int		 talks(enum nshd_proc);
static void		 pair(struct child *, struct child *);
static void		 tell(struct child *, struct child *, int);
static int		 out_open(struct child *);
static __dead void	 ended(struct child *, const char *, ...)
			    __attribute__((__format__ (printf, 2, 3)));
static int		 system_clear(struct child *);
static struct kinfo_proc *procs(int, int, size_t *);
static const char	*how(int);
static struct child	*child(enum nshd_proc, int);
static void		 users(void);
static void		 daemon_boot(void);
static void		 booted(int32_t);
static __dead void	 parent_shutdown(int, const char *);
static __dead void	 usage(void);

static char		 execpath[PATH_MAX];	/* this program, which children run */
static int		 opt_debug, opt_verbose, rwfd, rofd, rtfd;
static int		 booting;	/* -b, until config says it is done */
static int		 boot_fd = -1;	/* to the process rc started, or -1 */
static uid_t		 check_uid;	/* NSHD_CHECK_USER's */

static __dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-bdv]\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct event		 ev_sigint, ev_sigterm, ev_sighup, ev_sigchld;
	struct group		*gr;
	const char		*errstr;
	int			 c, role = PROC_PARENT, instance = 0;

	while ((c = getopt(argc, argv, "AbCdFS:vY")) != -1) {
		switch (c) {
		case 'A':
			role = PROC_ARCHIVE;
			break;
		case 'b':
			booting = 1;
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
		case 'S':
			role = PROC_SHOW;
			instance = strtonum(optarg, 0, SHOWS - 1, &errstr);
			if (errstr != NULL)
				usage();
			break;
		case 'v':
			opt_verbose++;
			break;
		case 'Y':
			role = PROC_SYSTEM;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	if (argc > 0)
		usage();

	switch (role) {
	case PROC_SHOW:
		showproc(opt_debug, opt_verbose, instance);
	case PROC_FRONTEND:
		frontend(opt_debug, opt_verbose);
	case PROC_CONFIG:
		configproc(opt_debug, opt_verbose);
	case PROC_SYSTEM:
		systemproc(opt_debug, opt_verbose);
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
	if (getexecpath(execpath, sizeof(execpath)) == -1)
		err(1, "getexecpath");

	log_init(opt_debug, LOG_DAEMON);
	log_setverbose(opt_verbose);

	if (!opt_debug && booting)
		daemon_boot();
	else if (!opt_debug && daemon(0, 0) == -1)
		err(1, "daemon");

	/* frontend's and the shows', once they start */
	if ((rwfd = control_init(NSHD_SOCKET, 0660, gr->gr_gid)) == -1)
		fatalx("cannot open %s", NSHD_SOCKET);
	if ((rofd = control_init(NSHD_RO_SOCKET, 0666, gr->gr_gid)) == -1)
		fatalx("cannot open %s", NSHD_RO_SOCKET);
	/* config's */
	if ((rtfd = control_route()) == -1)
		fatal("routing socket");

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
	close(rwfd);
	close(rofd);
	close(rtfd);

	/* what ends system's helpers, as nshd ends */
	if (pledge("stdio proc ps", NULL) == -1)
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

/*
 * each child's user, and system's helpers', which is not root, nor any
 * other role's uid
 */
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
	if ((pw = getpwnam(NSHD_CHECK_USER)) == NULL)
		errx(1, "unknown user %s", NSHD_CHECK_USER);
	if ((check_uid = pw->pw_uid) == 0)
		errx(1, "%s is root", NSHD_CHECK_USER);
	for (i = 0; i < NPROC; i++)
		if (children[i].user != NULL && uid[i] == check_uid)
			errx(1, "%s and %s are one uid", children[i].user,
			    NSHD_CHECK_USER);
	/* the web configurator's, if there is one, which is no role's */
	if ((pw = getpwnam(NSHD_WEB_USER)) == NULL)
		return;
	if (pw->pw_uid == 0)
		errx(1, "%s is root", NSHD_WEB_USER);
	if (pw->pw_uid == check_uid)
		errx(1, "%s and %s are one uid", NSHD_WEB_USER,
		    NSHD_CHECK_USER);
	for (i = 0; i < NPROC; i++)
		if (children[i].user != NULL && uid[i] == pw->pw_uid)
			errx(1, "%s and %s are one uid", children[i].user,
			    NSHD_WEB_USER);
}

/*
 * each child, with its pipe to parent, and the pipes to its peers there
 * before it starts; then each told it may
 */
static void
spawn_all(void)
{
	struct nshd_startup	 st;
	size_t			 i;
	int			 out[NPROC];

	for (i = 0; i < NPROC; i++)
		out[i] = out_open(&children[i]);
	for (i = 0; i < NPAIRS; i++)
		pair(child(pairs[i].a, 0), child(pairs[i].b, 0));
	for (i = 0; i < NPROC; i++)
		start(&children[i], out[i]);

	memset(&st, 0, sizeof(st));
	st.boot = booting;
	for (i = 0; i < NPROC; i++)
		if (imsg_compose_event(children[i].iev, IMSG_STARTUP, 0, 0,
		    -1, &st, sizeof(st)) == -1)
			fatal("%s: startup", children[i].name);
}

/* c, with its pipe to parent, and its peers' pipes, given and closed */
static void
start(struct child *c, int out)
{
	int	 sp[2], fd = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, sp) == -1)
		fatal("socketpair");
	if (c->proc == PROC_FRONTEND)
		fd = rwfd;
	else if (c->proc == PROC_SHOW)
		fd = rofd;
	else if (c->proc == PROC_CONFIG)
		fd = rtfd;
	if (c->hasout) {
		if (imsgbuf_flush(&c->out) == -1)
			fatal("%s: its peers' pipes", c->name);
		imsgbuf_clear(&c->out);
		close(c->out.fd);
		c->hasout = 0;
	}
	c->pid = start_child(c, sp[1], out, fd);
	if ((c->iev = imsgev_new(sp[0], parent_dispatch, 0)) == NULL)
		fatal(NULL);
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

	argv[argc++] = execpath;
	argv[argc++] = c->flag;
	if (opt_debug)
		argv[argc++] = "-d";
	if (opt_verbose)
		argv[argc++] = "-v";
	argv[argc++] = NULL;

	execv(execpath, argv);
	fatal("execv");
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

/* a pipe between a and b, each given its end */
static void
pair(struct child *a, struct child *b)
{
	int	 sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, sp) == -1)
		fatal("socketpair");
	tell(a, b, sp[0]);
	tell(b, a, sp[1]);
}

/* to c, the pipe fd to its peer p */
static void
tell(struct child *c, struct child *p, int fd)
{
	struct nshd_child	 ch;

	memset(&ch, 0, sizeof(ch));
	ch.proc = p->proc;
	ch.instance = p->instance;
	if (imsg_compose(&c->out, IMSG_PEER, 0, 0, fd, &ch, sizeof(ch)) ==
	    -1)
		fatal("%s: %s's pipe", c->name, p->name);
}

/* the pipe from parent to c, if it has peers: c's end of it, or -1 */
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
	c->hasout = 1;
	return (sp[1]);
}

/* c ended, or broke a rule, as why says: nshd ends with it */
static __dead void
ended(struct child *c, const char *fmt, ...)
{
	va_list	 ap;
	char	*why;

	va_start(ap, fmt);
	if (vasprintf(&why, fmt, ap) == -1)
		fatal("%s", __func__);
	va_end(ap);
	log_warnx("%s %s", c->name, why);
	free(why);
	parent_shutdown(1, "nshd ends with it");
}

/*
 * system gone, or to go, and its helpers with it: each process of its
 * session, which system made as it started, and of NSHD_CHECK_USER's,
 * killed until none is left. system is reaped last, so its session is
 * no other's while its helpers are found by it. -1, said, if one
 * outlives CLEAR_TRIES
 */
static int
system_clear(struct child *k)
{
	struct kinfo_proc	*kp;
	uint64_t		 sess = 0, own = 0;
	size_t			 n, i;
	int			 tries, left, status;

	if (k->pid <= 0)
		return (0);
	if ((kp = procs(KERN_PROC_PID, k->pid, &n)) != NULL && n == 1)
		sess = kp->p_sess;
	free(kp);
	if ((kp = procs(KERN_PROC_PID, getpid(), &n)) != NULL && n == 1)
		own = kp->p_sess;
	free(kp);
	/* not yet a session of its own, so no helper either */
	if (sess == own)
		sess = 0;
	kill(k->pid, SIGKILL);

	for (tries = 0;; tries++) {
		if ((kp = procs(KERN_PROC_ALL, 0, &n)) == NULL) {
			logit(LOG_CRIT, "system's helpers: sysctl: %s",
			    strerror(errno));
			return (-1);
		}
		for (i = 0, left = 0; i < n; i++)
			if ((kp[i].p_psflags & PS_ZOMBIE) == 0 &&
			    ((sess != 0 && kp[i].p_sess == sess) ||
			    kp[i].p_ruid == check_uid)) {
				kill(kp[i].p_pid, SIGKILL);
				left++;
			}
		free(kp);
		if (left == 0)
			break;
		if (tries == CLEAR_TRIES) {
			logit(LOG_CRIT, "%d of system's helpers outlive "
			    "SIGKILL", left);
			return (-1);
		}
		nanosleep(&(struct timespec){ 0, 10000000 }, NULL);
	}
	if (waitpid(k->pid, &status, 0) == k->pid)
		log_warnx("%s %s", k->name, how(status));
	k->pid = -1;
	return (0);
}

/* the processes op and arg name, as kern.proc has them, or NULL */
static struct kinfo_proc *
procs(int op, int arg, size_t *n)
{
	struct kinfo_proc	*kp;
	int			 mib[6] = { CTL_KERN, KERN_PROC, op, arg,
				    sizeof(*kp), 0 };
	size_t			 len;

	for (;;) {
		if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1)
			return (NULL);
		/* and room for some started since */
		len += 16 * sizeof(*kp);
		mib[5] = len / sizeof(*kp);
		if ((kp = malloc(len)) == NULL)
			return (NULL);
		if (sysctl(mib, 6, kp, &len, NULL, 0) == 0)
			break;
		free(kp);
		if (errno != ENOMEM)
			return (NULL);
	}
	*n = len / sizeof(*kp);
	return (kp);
}

/* how a child ended, by its status */
static const char *
how(int status)
{
	static char	 why[32];

	if (WIFSIGNALED(status))
		snprintf(why, sizeof(why), "killed by signal %d",
		    WTERMSIG(status));
	else
		snprintf(why, sizeof(why), "exited %d", WEXITSTATUS(status));
	return (why);
}

static void
parent_sig_handler(int sig, short event, void *arg)
{
	int		 status, serrno = errno;
	size_t		 i;
	pid_t		 pid;

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		parent_shutdown(0, "terminating on signal");
	case SIGHUP:
		break;
	case SIGCHLD:
		/* but system, a session of its own: system_clear() reaps it */
		while ((pid = waitpid(0, &status, WNOHANG)) > 0)
			for (i = 0; i < NPROC; i++)
				if (pid == children[i].pid) {
					children[i].pid = -1;
					ended(&children[i], "%s", how(status));
				}
		break;
	}
	errno = serrno;
}

/*
 * c's word on its pipe to parent: config's that the boot is done, once,
 * and no other. Anything else, or the pipe closed, ends nshd
 */
static void
parent_dispatch(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_result	 res;
	struct child		*c = NULL;
	size_t			 i;
	int			 n;

	for (i = 0; i < NPROC; i++)
		if (children[i].iev == iev)
			c = &children[i];
	if (c == NULL)
		fatalx("%s: from no child", __func__);
	if (imsgev_io(iev, event) == -1)
		ended(c, "closed its pipe");

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			ended(c, "sent what imsg cannot read");
		if (n == 0)
			break;
		if (imsg_get_type(&imsg) != IMSG_BOOTED ||
		    c->proc != PROC_CONFIG || !booting ||
		    imsg_get_data(&imsg, &res, sizeof(res)) == -1)
			ended(c, "sent imsg %u, which it may not",
			    imsg_get_type(&imsg));
		imsg_free(&imsg);
		booted(res.status);
	}
	imsg_event_add(iev);
}

/*
 * daemon(3), but for the process rc started, which waits, on a pipe,
 * until the boot is done, and exits 0 if it went well, else 1, as it
 * does if nshd ends before
 */
static void
daemon_boot(void)
{
	char	 c;
	ssize_t	 n;
	int	 p[2], fd;

	if (pipe2(p, O_CLOEXEC) == -1)
		err(1, "pipe2");
	switch (fork()) {
	case -1:
		err(1, "fork");
	case 0:
		break;
	default:
		close(p[1]);
		while ((n = read(p[0], &c, 1)) == -1 && errno == EINTR)
			;
		_exit(n != 1 || c != '0');
	}
	close(p[0]);
	boot_fd = p[1];
	if (setsid() == -1)
		err(1, "setsid");
	if (chdir("/") == -1)
		err(1, "chdir");
	if ((fd = open(_PATH_DEVNULL, O_RDWR)) == -1)
		err(1, "%s", _PATH_DEVNULL);
	if (dup2(fd, STDIN_FILENO) == -1 || dup2(fd, STDOUT_FILENO) == -1 ||
	    dup2(fd, STDERR_FILENO) == -1)
		err(1, "dup2");
	if (fd > STDERR_FILENO)
		close(fd);
}

/*
 * the boot done, as status says it went: rc told, and frontend and the
 * shows to take clients
 */
static void
booted(int32_t status)
{
	size_t	 i;
	char	 c = status == 0 ? '0' : '1';

	booting = 0;
	for (i = 0; i < NPROC; i++)
		if ((children[i].proc == PROC_FRONTEND ||
		    children[i].proc == PROC_SHOW) &&
		    imsg_compose_event(children[i].iev, IMSG_LISTEN, 0, 0, -1,
		    NULL, 0) == -1)
			fatal("%s: listen", children[i].name);
	if (status == 0)
		log_info("booted");
	else
		log_warnx("booted, but the running configuration is not the "
		    "saved one");
	if (boot_fd != -1) {
		if (write(boot_fd, &c, 1) != 1)
			log_warn("%s", __func__);
		close(boot_fd);
		boot_fd = -1;
	}
}

/*
 * nshd ends: every child killed. SIGKILL, because a child that has gone
 * wrong may ignore SIGTERM, or be stopped, and must not outlive nshd
 */
static __dead void
parent_shutdown(int status, const char *why)
{
	size_t	 i;

	log_info("%s", why);
	for (i = 0; i < NPROC; i++)
		if (children[i].pid > 0 && children[i].proc != PROC_SYSTEM)
			kill(children[i].pid, SIGKILL);
	system_clear(child(PROC_SYSTEM, 0));
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

/* proc's user, its uid and gid: -1 if there is none */
int
proc_user(enum nshd_proc proc, uid_t *uid, gid_t *gid)
{
	struct passwd	*pw;

	if ((pw = getpwnam(child(proc, 0)->user)) == NULL)
		return (-1);
	*uid = pw->pw_uid;
	*gid = pw->pw_gid;
	return (0);
}

static struct link	*links;
static size_t		 nlinks;

static void		 link_take(struct imsg *);

/*
 * A child's n peers, in l, each with its pipe from parent, on fd 4, all
 * of them written before the child started: fd 4 is closed once they
 * are taken, and then each link's ready() is called
 */
void
links_init(struct link *l, size_t n)
{
	struct pollfd	 pfd;
	struct imsgbuf	 ibuf;
	struct imsg	 imsg;
	size_t		 have = 0;
	int		 r;

	links = l;
	nlinks = n;
	if (imsgbuf_init(&ibuf, 4) == -1)
		fatal(NULL);
	imsgbuf_allow_fdpass(&ibuf);
	while (have < n) {
		if ((r = imsgbuf_get(&ibuf, &imsg)) == -1)
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
		if ((r = imsgbuf_read(&ibuf)) == -1)
			fatal("%s", __func__);
		if (r == 0)
			fatalx("%s: parent's pipe closed", __func__);
	}
	imsgbuf_clear(&ibuf);
	close(4);
	for (have = 0; have < n; have++)
		if (l[have].ready != NULL)
			l[have].ready();
}

/* a peer's pipe, once */
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
	if (l == NULL || l->iev != NULL || (fd = imsg_get_fd(imsg)) == -1)
		fatalx("%s: bad imsg %u", __func__, imsg_get_type(imsg));
	if ((l->iev = imsgev_new(fd, l->handler, 0)) == NULL)
		fatal(NULL);
}

/* to l's peer */
int
link_compose(struct link *l, uint32_t type, uint32_t id, const void *data,
    size_t len)
{
	return (imsg_compose_event(l->iev, type, id, 0, -1, data, len));
}

/* l's peer gone wrong: this child ends, and nshd with it */
void
link_broken(struct link *l, const char *fmt, ...)
{
	va_list	 ap;
	char	*why;

	va_start(ap, fmt);
	if (vasprintf(&why, fmt, ap) == -1)
		fatal("%s", __func__);
	va_end(ap);
	fatalx("%s %s", child(l->proc, 0)->name, why);
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
	int	 n;

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
 * What nsh's code printed since, as text messages of type for id on
 * iev, as imsg_text() sends them, and with hide, with each password hash
 * taken out (login_hide()); -1 if a message could not be made, or what
 * was printed could not all be kept
 */
int
printed_text(struct imsgev *iev, uint32_t type, uint32_t id, int hide)
{
	char	 buf[NSHD_TEXT], *all = NULL, *p;
	size_t	 len = 0;
	off_t	 off = 0;
	ssize_t	 n;
	int	 r = 0;

	if (fflush(stdout) == EOF) {
		log_warn("%s: stdout", __func__);
		r = -1;
	}
	clearerr(stdout);
	while ((n = pread(STDOUT_FILENO, buf, sizeof(buf), off)) > 0) {
		off += n;
		if (!hide) {
			if (imsg_text(iev, type, id, buf, n) == -1)
				r = -1;
			continue;
		}
		/* whole, as a hash may be split between two reads */
		if ((p = realloc(all, len + n)) == NULL)
			fatal("%s", __func__);
		all = p;
		memcpy(all + len, buf, n);
		len += n;
	}
	if (hide && len > 0 &&
	    imsg_text(iev, type, id, all, login_hide(all, len)) == -1)
		r = -1;
	free(all);
	if (ftruncate(STDOUT_FILENO, 0) == -1 ||
	    lseek(STDOUT_FILENO, 0, SEEK_SET) == -1)
		fatal("%s", __func__);
	return (r);
}

/* text no client asked for, logged a line at a time */
void
log_text(const char *text, size_t len)
{
	const char	*nl;
	size_t		 n;

	while (len > 0) {
		nl = memchr(text, '\n', len);
		n = nl != NULL ? (size_t)(nl - text) : len;
		if (n > 0)
			log_warnx("%.*s", (int)n, text);
		if (nl != NULL)
			n++;
		text += n;
		len -= n;
	}
}

/* what nsh's code printed since, logged, as no client asked for it */
void
printed_log(void)
{
	char	 buf[NSHD_TEXT];
	off_t	 off = 0;
	ssize_t	 n;

	fflush(stdout);
	clearerr(stdout);
	while ((n = pread(STDOUT_FILENO, buf, sizeof(buf), off)) > 0) {
		log_text(buf, n);
		off += n;
	}
	if (ftruncate(STDOUT_FILENO, 0) == -1 ||
	    lseek(STDOUT_FILENO, 0, SEEK_SET) == -1)
		fatal("%s", __func__);
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
