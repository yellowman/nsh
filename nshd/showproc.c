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
 * show: the read-only socket, answered here and nowhere else, with what
 * anyone may see. It has no peer, so nothing a client sends here
 * reaches the processes that change anything.
 */

#include <sys/types.h>
#include <sys/queue.h>

#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "control.h"

static struct imsgev	*iev_relay;

static void	show_dispatch_relay(int, short, void *);
static int	show_client(struct ctl_conn *, struct imsg *);
static int	show_answer(uint32_t, int32_t, const char *);

void
showproc(int debug, int verbose)
{
	child_start("show", debug, verbose);
	privdrop();
	if (pledge("stdio unix", NULL) == -1)
		fatal("pledge");

	if ((iev_relay = imsgev_new(3, show_dispatch_relay, 0)) == NULL)
		fatal(NULL);
	event_dispatch();
	exit(0);
}

static void
show_dispatch_relay(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct imsg	 imsg;
	ssize_t		 n;

	if (imsgev_io(iev, event) == -1)
		exit(0);

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		switch (imsg_get_type(&imsg)) {
		/* its socket is fd 4, from parent */
		case IMSG_STARTUP:
			if (control_listen(4, show_client, NULL) == -1)
				fatalx("cannot listen on %s", NSHD_RO_SOCKET);
			break;
		default:
			log_debug("%s: unexpected imsg %u", __func__,
			    imsg_get_type(&imsg));
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* a client's request, answered; -1 closes it */
static int
show_client(struct ctl_conn *c, struct imsg *imsg)
{
	struct nshd_hello	 hello;
	struct nshd_session	 s;
	struct nshd_show	 show;
	char			 host[HOST_NAME_MAX + 1], *out;
	int			 ret, status = 1;

	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_HELLO:
		if (imsg_get_data(imsg, &hello, sizeof(hello)) == -1)
			return (-1);
		s.version = NSHD_VERSION;
		s.id = c->id;
		s.priv = 0;
		return (control_reply(c->id, IMSG_CTL_HELLO, &s, sizeof(s)));
	case IMSG_CTL_SHOW:
		if (imsg_get_data(imsg, &show, sizeof(show)) == -1 ||
		    memchr(show.words, '\0', sizeof(show.words)) == NULL)
			return (-1);
		if (strcmp(show.words, "hostname") != 0)
			ret = asprintf(&out, "%% show %s: not answered by "
			    "nshd\n", show.words);
		else if (gethostname(host, sizeof(host)) == -1)
			ret = asprintf(&out, "%% gethostname failed\n");
		else {
			ret = asprintf(&out, "%s\n", host);
			status = 0;
		}
		if (ret == -1)
			fatal("%s", __func__);
		ret = show_answer(c->id, status, out);
		free(out);
		return (ret);
	default:
		return (-1);
	}
}

/* to client id, text and then the result status */
static int
show_answer(uint32_t id, int32_t status, const char *text)
{
	struct nshd_result	 r;

	r.status = status;
	if (control_reply(id, IMSG_CTL_OUTPUT, text, strlen(text)) == -1)
		return (-1);
	return (control_reply(id, IMSG_CTL_RESULT, &r, sizeof(r)));
}
