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
 * kernel: root, and nsh's own code, which reads and changes the kernel.
 * It answers config, through relay, one request at a time, in order.
 */

#include <sys/types.h>
#include <sys/queue.h>

#include <event.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "stringlist.h"
#include "externs.h"

static struct imsgev	*iev_relay;

static void	kern_dispatch_relay(int, short, void *);
static void	kern_snapshot(uint32_t);

void
kernproc(int debug, int v)
{
	child_start("kernel", debug, v);

	/* nsh's code here is nsh's as root */
	priv = 1;
	db_create();

	if ((iev_relay = imsgev_new(3, kern_dispatch_relay, 0)) == NULL)
		fatal(NULL);
	event_dispatch();
	exit(0);
}

/* config's requests, through relay */
static void
kern_dispatch_relay(int fd, short event, void *arg)
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
		case IMSG_STARTUP:
		case IMSG_RESTART:
			break;
		case IMSG_KRN_SNAPSHOT:
			kern_snapshot(imsg_get_id(&imsg));
			break;
		default:
			log_debug("%s: unexpected imsg %u", __func__,
			    imsg_get_type(&imsg));
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* the running configuration, as conf() writes it, then how it went */
static void
kern_snapshot(uint32_t id)
{
	struct nshd_result	 r = { 0 };
	FILE			*f;
	char			*buf = NULL;
	size_t			 len = 0;

	if ((f = open_memstream(&buf, &len)) == NULL) {
		log_warn("%s: open_memstream", __func__);
		r.status = -1;
	} else {
		conf(f);
		if (fclose(f) == EOF) {
			log_warn("%s: fclose", __func__);
			r.status = -1;
		} else if (imsg_text(iev_relay, IMSG_KRN_TEXT, id, buf,
		    len) == -1)
			fatal("%s", __func__);
	}
	free(buf);
	if (imsg_compose_event(iev_relay, IMSG_KRN_END, id, 0, -1, &r,
	    sizeof(r)) == -1)
		fatal("%s", __func__);
}
