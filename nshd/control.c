/*
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
 * A socket's clients: parent binds the socket, and frontend or show
 * listens on it, each with its own handler for what a client sends.
 * And config's routing socket, which parent opens.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <net/route.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "control.h"

#define	CONTROL_BACKLOG	5
#define	CONTROL_QUEUE	1024	/* messages a client may leave unread */

static struct {
	struct event	 ev;
	struct event	 evt;
	int		 fd;
	int		(*opened)(struct ctl_conn *);
	int		(*handler)(struct ctl_conn *, struct imsg *);
	void		(*closed)(struct ctl_conn *);
	int		(*written)(struct ctl_conn *);
} control_state = { .fd = -1 };

static TAILQ_HEAD(, ctl_conn) ctl_conns = TAILQ_HEAD_INITIALIZER(ctl_conns);
static uint32_t control_nextid;

static void		 control_accept(int, short, void *);
static void		 control_dispatch(int, short, void *);
static void		 control_close(struct ctl_conn *);
static struct ctl_conn	*control_connbyfd(int);

/* a socket at path, owned by root and gid, with mode */
int
control_init(const char *path, mode_t mode, gid_t gid)
{
	struct sockaddr_un	 sun;
	mode_t			 old_umask;
	int			 fd;

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    0)) == -1) {
		log_warn("%s: socket", __func__);
		return (-1);
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		close(fd);
		errno = ENAMETOOLONG;
		return (-1);
	}

	if (unlink(path) == -1 && errno != ENOENT) {
		log_warn("%s: unlink %s", __func__, path);
		close(fd);
		return (-1);
	}

	/* no one may connect before it has its owner and mode */
	old_umask = umask(S_IRWXG | S_IRWXO);
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_warn("%s: bind %s", __func__, path);
		close(fd);
		umask(old_umask);
		return (-1);
	}
	umask(old_umask);

	if (chown(path, 0, gid) == -1 || chmod(path, mode) == -1) {
		log_warn("%s: %s", __func__, path);
		close(fd);
		(void)unlink(path);
		return (-1);
	}

	return (fd);
}

/*
 * A routing socket, of every rtable, which reads only what changes
 * interfaces, addresses or routes: -1, errno set, if not
 */
int
control_route(void)
{
	unsigned int	 filter = ROUTE_FILTER(RTM_IFINFO) |
			    ROUTE_FILTER(RTM_IFANNOUNCE) |
			    ROUTE_FILTER(RTM_NEWADDR) |
			    ROUTE_FILTER(RTM_DELADDR) |
			    ROUTE_FILTER(RTM_CHGADDRATTR) |
			    ROUTE_FILTER(RTM_ADD) | ROUTE_FILTER(RTM_DELETE) |
			    ROUTE_FILTER(RTM_CHANGE);
	int		 fd, any = RTABLE_ANY, serrno;

	if ((fd = socket(AF_ROUTE, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    AF_UNSPEC)) == -1)
		return (-1);
	if (setsockopt(fd, AF_ROUTE, ROUTE_MSGFILTER, &filter,
	    sizeof(filter)) == -1 || setsockopt(fd, AF_ROUTE,
	    ROUTE_TABLEFILTER, &any, sizeof(any)) == -1) {
		serrno = errno;
		close(fd);
		errno = serrno;
		return (-1);
	}
	return (fd);
}

/*
 * accept on fd: call opened, if not NULL, for each new client, handler
 * for each message it sends, closed when it goes, and written each time
 * some of what it was sent is written; -1 from opened, handler or written
 * closes the client
 */
int
control_listen(int fd, int (*opened)(struct ctl_conn *),
    int (*handler)(struct ctl_conn *, struct imsg *),
    void (*closed)(struct ctl_conn *), int (*written)(struct ctl_conn *))
{
	if (control_state.fd != -1)
		fatalx("%s: a second socket", __func__);

	control_state.fd = fd;
	control_state.opened = opened;
	control_state.handler = handler;
	control_state.closed = closed;
	control_state.written = written;
	if (listen(fd, CONTROL_BACKLOG) == -1) {
		log_warn("%s: listen", __func__);
		return (-1);
	}

	event_set(&control_state.ev, fd, EV_READ, control_accept, NULL);
	event_add(&control_state.ev, NULL);
	evtimer_set(&control_state.evt, control_accept, NULL);

	return (0);
}

static void
control_accept(int listenfd, short event, void *arg)
{
	struct ctl_conn	*c;
	uid_t		 uid;
	gid_t		 gid;
	int		 connfd;

	event_add(&control_state.ev, NULL);
	if ((event & EV_TIMEOUT))
		return;

	if ((connfd = accept4(listenfd, NULL, NULL,
	    SOCK_CLOEXEC | SOCK_NONBLOCK)) == -1) {
		/* out of descriptors: pause, or libevent loops here */
		if (errno == ENFILE || errno == EMFILE) {
			struct timeval evtpause = { 1, 0 };

			event_del(&control_state.ev);
			evtimer_add(&control_state.evt, &evtpause);
		} else if (errno != EWOULDBLOCK && errno != EINTR &&
		    errno != ECONNABORTED)
			log_warn("%s: accept4", __func__);
		return;
	}

	if (getpeereid(connfd, &uid, &gid) == -1) {
		log_warn("%s: getpeereid", __func__);
		close(connfd);
		return;
	}

	/* an id is never used again, as answers for it can come late */
	if (control_nextid == UINT32_MAX) {
		log_warnx("%s: connection ids exhausted", __func__);
		close(connfd);
		return;
	}

	if ((c = calloc(1, sizeof(*c))) == NULL) {
		log_warn("%s: calloc", __func__);
		close(connfd);
		return;
	}
	if (imsgbuf_init(&c->iev.ibuf, connfd) == -1) {
		log_warn("%s: imsgbuf_init", __func__);
		close(connfd);
		free(c);
		return;
	}
	c->id = ++control_nextid;
	c->uid = uid;
	c->gid = gid;
	if (control_state.opened != NULL && control_state.opened(c) == -1) {
		imsgbuf_clear(&c->iev.ibuf);
		close(connfd);
		free(c);
		return;
	}
	c->iev.handler = control_dispatch;
	c->iev.events = EV_READ;
	event_set(&c->iev.ev, connfd, c->iev.events, c->iev.handler, &c->iev);
	event_add(&c->iev.ev, NULL);

	TAILQ_INSERT_TAIL(&ctl_conns, c, entry);
}

static struct ctl_conn *
control_connbyfd(int fd)
{
	struct ctl_conn	*c;

	TAILQ_FOREACH(c, &ctl_conns, entry)
		if (c->iev.ibuf.fd == fd)
			break;
	return (c);
}

struct ctl_conn *
control_connbyid(uint32_t id)
{
	struct ctl_conn	*c;

	TAILQ_FOREACH(c, &ctl_conns, entry)
		if (c->id == id)
			break;
	return (c);
}

static void
control_close(struct ctl_conn *c)
{
	if (control_state.closed != NULL)
		control_state.closed(c);

	imsgbuf_clear(&c->iev.ibuf);
	TAILQ_REMOVE(&ctl_conns, c, entry);
	event_del(&c->iev.ev);
	close(c->iev.ibuf.fd);

	/* descriptors are free again */
	if (evtimer_pending(&control_state.evt, NULL)) {
		evtimer_del(&control_state.evt);
		event_add(&control_state.ev, NULL);
	}

	free(c);
}

static void
control_dispatch(int fd, short event, void *arg)
{
	struct ctl_conn	*c;
	struct imsg	 imsg;
	int		 n;

	if ((c = control_connbyfd(fd)) == NULL) {
		log_warnx("%s: fd %d: not found", __func__, fd);
		return;
	}

	if (event & EV_READ) {
		if (imsgbuf_read(&c->iev.ibuf) != 1) {
			control_close(c);
			return;
		}
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(&c->iev.ibuf) == -1 ||
		    (control_state.written != NULL &&
		    control_state.written(c) == -1)) {
			control_close(c);
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(&c->iev.ibuf, &imsg)) == -1) {
			control_close(c);
			return;
		}
		if (n == 0)
			break;
		if (control_state.handler(c, &imsg) == -1) {
			imsg_free(&imsg);
			control_close(c);
			return;
		}
		imsg_free(&imsg);
	}

	imsg_event_add(&c->iev);
}

/*
 * a message to the client id, if it is still there: -1 if it has too much
 * unread to take it, and the caller then closes it, so a handler does not
 * close the client it is handling
 */
int
control_reply(uint32_t id, uint32_t type, const void *data, size_t len)
{
	struct ctl_conn	*c;

	if ((c = control_connbyid(id)) == NULL)
		return (0);
	if (imsgbuf_queuelen(&c->iev.ibuf) > CONTROL_QUEUE ||
	    imsg_compose_event(&c->iev, type, 0, 0, -1, data, len) == -1)
		return (-1);
	return (0);
}

/* fd to the client id, as control_reply() says; fd is closed if not */
int
control_pass(uint32_t id, uint32_t type, int fd)
{
	struct ctl_conn	*c;

	if ((c = control_connbyid(id)) == NULL) {
		close(fd);
		return (0);
	}
	imsgbuf_allow_fdpass(&c->iev.ibuf);
	if (imsgbuf_queuelen(&c->iev.ibuf) > CONTROL_QUEUE ||
	    imsg_compose_event(&c->iev, type, 0, 0, fd, NULL, 0) == -1) {
		close(fd);
		return (-1);
	}
	return (0);
}

/* the client id, closed, if it is still there */
void
control_drop(uint32_t id)
{
	struct ctl_conn	*c;

	if ((c = control_connbyid(id)) != NULL)
		control_close(c);
}
