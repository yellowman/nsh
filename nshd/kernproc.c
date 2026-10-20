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
 * It answers config, through relay, one request at a time, in order:
 * the running configuration as text, and the shows only root may make
 * as facts, with what nsh's code prints as it makes them, as messages.
 * A show's answer is made whole, as it is small, its units as many to a
 * message as fit.
 */

#include <sys/types.h>
#include <sys/queue.h>

#include <event.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "nshd.h"
#include "stringlist.h"
#include "externs.h"
#include "facts.h"
#include "showfacts.h"

#define KERN_BATCH	256	/* records made before what is printed is sent */

static struct imsgev	*iev_relay;
static uint8_t		 units[FACTS_UNIT];	/* not yet sent */
static size_t		 nunits;

static void	kern_dispatch_relay(int, short, void *);
static void	kern_snapshot(uint32_t);
static void	kern_show(uint32_t, char *);
static void	kern_emit(void *, const void *, size_t);
static void	kern_flush(uint32_t);

void
kernproc(int debug, int v)
{
	child_start("kernel", debug, v);
	capture_stdout();

	/* nsh's code here is nsh's as root */
	priv = 1;
	facts_from = FACTS_KERNEL;
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
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct nshd_show	 show;
	ssize_t			 n;

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
		case IMSG_KRN_SHOW:
			if (imsg_get_data(&imsg, &show, sizeof(show)) == -1 ||
			    memchr(show.words, '\0', sizeof(show.words)) ==
			    NULL)
				fatalx("%s: bad IMSG_KRN_SHOW", __func__);
			kern_show(imsg_get_id(&imsg), show.words);
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
		printed(NULL);
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

/* the facts words ask, all of them, then how it went */
static void
kern_show(uint32_t id, char *words)
{
	struct nshd_result	 r = { 0 };
	struct facts_answer	*a;
	struct facts_out	 o;
	char			*out;
	int			 more = 1;

	printed(NULL);
	if ((a = facts_answer(words)) == NULL) {
		if (asprintf(&out, "%% show %s: not answered by nshd\n",
		    words) == -1 ||
		    imsg_text(iev_relay, IMSG_KRN_TEXT, id, out, strlen(out)) ==
		    -1)
			fatal("%s", __func__);
		free(out);
		r.status = 1;
	} else {
		facts_out_init(&o, kern_emit, &id);
		while (more == 1) {
			more = facts_more(a, &o, KERN_BATCH);
			if (printed(&o) == -1)
				more = -1;
		}
		facts_answer_free(a);
		kern_flush(id);
		r.status = more != 0;
	}
	if (imsg_compose_event(iev_relay, IMSG_KRN_END, id, 0, -1, &r,
	    sizeof(r)) == -1)
		fatal("%s", __func__);
}

/* a unit of facts, for request *arg, kept until a message is full */
static void
kern_emit(void *arg, const void *buf, size_t len)
{
	uint32_t	*id = arg;

	if (nunits + len > sizeof(units))
		kern_flush(*id);
	memcpy(units + nunits, buf, len);
	nunits += len;
}

/* the units kept, to config, as one message */
static void
kern_flush(uint32_t id)
{
	if (nunits == 0)
		return;
	if (imsg_compose_event(iev_relay, IMSG_KRN_FACTS, id, 0, -1, units,
	    nunits) == -1)
		fatal("%s", __func__);
	nunits = 0;
}
