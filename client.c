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
 * nsh as a client of nshd(8), where nshd runs. Who may connect to its
 * read-write socket, root or the group _nshd, has what an enabled
 * nsh has there.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "stringlist.h"
#include "externs.h"
#include "facts.h"
#include "showfacts.h"
#include "nshd/nshd.h"

static int	nshd_next(struct imsgbuf *, struct imsg *);
static int	nshd_open(char *, struct imsgbuf *);

/* the next message, read as it comes; -1 if nshd is gone */
static int
nshd_next(struct imsgbuf *ib, struct imsg *imsg)
{
	ssize_t	 n;

	for (;;) {
		if ((n = imsgbuf_get(ib, imsg)) != 0)
			return (n == 1 ? 0 : -1);
		if (imsgbuf_read(ib) != 1)
			return (-1);
	}
}

/*
 * A session on nshd's socket at path: its descriptor, or -1, with
 * EPROTO for an nshd that said something else.
 */
static int
nshd_open(char *path, struct imsgbuf *ib)
{
	struct sockaddr_un	 sun;
	struct nshd_hello	 hello;
	struct nshd_session	 s;
	struct imsg		 imsg;
	int			 fd, saved;

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
		return (-1);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		close(fd);
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1 ||
	    imsgbuf_init(ib, fd) == -1) {
		saved = errno;
		close(fd);
		errno = saved;
		return (-1);
	}

	hello.version = NSHD_VERSION;
	if (imsg_compose(ib, IMSG_CTL_HELLO, 0, 0, -1, &hello,
	    sizeof(hello)) == -1 || imsgbuf_flush(ib) == -1 ||
	    nshd_next(ib, &imsg) == -1) {
		imsgbuf_clear(ib);
		close(fd);
		errno = EPROTO;
		return (-1);
	}
	if (imsg_get_type(&imsg) != IMSG_CTL_HELLO ||
	    imsg_get_data(&imsg, &s, sizeof(s)) == -1 ||
	    s.version != NSHD_VERSION) {
		imsg_free(&imsg);
		imsgbuf_clear(ib);
		close(fd);
		errno = EPROTO;
		return (-1);
	}
	imsg_free(&imsg);
	return (fd);
}

/*
 * show words, as nshd answers them, paged: -1 if there is no nshd to
 * ask, else 1 if the show was answered and 0 if not.
 */
int
nshd_show(char *words)
{
	struct nshd_show	 show;
	struct nshd_result	 r = { 0 };
	struct imsgbuf		 ib;
	struct imsg		 imsg;
	struct ibuf		 b;
	char			 path[] = "/tmp/nshd.XXXXXXXXXX";
	FILE			*f = NULL;
	int			 fd, out = -1, done = 0, ret = 0;

	if ((fd = nshd_open(NSHD_SOCKET, &ib)) == -1) {
		if (errno != EPROTO)
			return (-1);
		printf("%% nshd: not a version nsh speaks\n");
		return (0);
	}

	memset(&show, 0, sizeof(show));
	if (strlcpy(show.words, words, sizeof(show.words)) >=
	    sizeof(show.words)) {
		printf("%% show %s: too long\n", words);
		goto done;
	}
	if ((out = mkstemp(path)) == -1) {
		printf("%% %s: %s\n", path, strerror(errno));
		goto done;
	}
	if ((f = fdopen(out, "w")) == NULL) {
		printf("%% %s: %s\n", path, strerror(errno));
		close(out);
		goto done;
	}

	if (imsg_compose(&ib, IMSG_CTL_SHOW, 0, 0, -1, &show,
	    sizeof(show)) == -1 || imsgbuf_flush(&ib) == -1) {
		printf("%% nshd: %s\n", strerror(errno));
		goto done;
	}
	while (!done) {
		if (nshd_next(&ib, &imsg) == -1) {
			printf("%% nshd: gone before it answered\n");
			goto done;
		}
		switch (imsg_get_type(&imsg)) {
		case IMSG_CTL_OUTPUT:
			if (imsg_get_ibuf(&imsg, &b) == -1 ||
			    fwrite(ibuf_data(&b), 1, ibuf_size(&b), f) !=
			    ibuf_size(&b)) {
				printf("%% %s: %s\n", path, strerror(errno));
				imsg_free(&imsg);
				goto done;
			}
			break;
		case IMSG_CTL_RESULT:
			if (imsg_get_data(&imsg, &r, sizeof(r)) == -1) {
				printf("%% nshd: a result nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			done = 1;
			break;
		default:
			printf("%% nshd: a message nsh does not know\n");
			imsg_free(&imsg);
			goto done;
		}
		imsg_free(&imsg);
	}

	if (fclose(f) == EOF) {
		f = NULL;
		printf("%% %s: %s\n", path, strerror(errno));
		goto done;
	}
	f = NULL;
	more(path);
	ret = r.status == 0;
done:
	if (f != NULL)
		fclose(f);
	if (out != -1)
		unlink(path);
	imsgbuf_clear(&ib);
	close(fd);
	return (ret);
}

/*
 * show words, as nshd's show processes answer them: facts read into in
 * as they come, and text printed. -1 if there is no nshd to ask, else 1
 * if the show was answered and 0 if not.
 */
int
nshd_facts(char *words, struct facts_in *in)
{
	struct nshd_show	 show;
	struct nshd_result	 r = { 0 };
	struct imsgbuf		 ib;
	struct imsg		 imsg;
	struct ibuf		 b;
	int			 fd, done = 0, ret = 0;

	if ((fd = nshd_open(NSHD_RO_SOCKET, &ib)) == -1) {
		if (errno != EPROTO)
			return (-1);
		printf("%% nshd: not a version nsh speaks\n");
		return (0);
	}

	memset(&show, 0, sizeof(show));
	if (strlcpy(show.words, words, sizeof(show.words)) >=
	    sizeof(show.words)) {
		printf("%% show %s: too long\n", words);
		goto done;
	}
	if (imsg_compose(&ib, IMSG_CTL_SHOW, 0, 0, -1, &show,
	    sizeof(show)) == -1 || imsgbuf_flush(&ib) == -1) {
		printf("%% nshd: %s\n", strerror(errno));
		goto done;
	}
	while (!done) {
		if (nshd_next(&ib, &imsg) == -1) {
			printf("%% nshd: gone before it answered\n");
			goto done;
		}
		switch (imsg_get_type(&imsg)) {
		case IMSG_CTL_OUTPUT:
			if (imsg_get_ibuf(&imsg, &b) == -1) {
				printf("%% nshd: output nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			fwrite(ibuf_data(&b), 1, ibuf_size(&b), stdout);
			break;
		case IMSG_CTL_FACTS:
			if (imsg_get_ibuf(&imsg, &b) == -1 ||
			    facts_read(in, ibuf_data(&b), ibuf_size(&b)) ==
			    -1) {
				printf("%% nshd: facts nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			break;
		case IMSG_CTL_RESULT:
			if (imsg_get_data(&imsg, &r, sizeof(r)) == -1) {
				printf("%% nshd: a result nsh cannot read\n");
				imsg_free(&imsg);
				goto done;
			}
			done = 1;
			break;
		default:
			printf("%% nshd: a message nsh does not know\n");
			imsg_free(&imsg);
			goto done;
		}
		imsg_free(&imsg);
	}
	ret = r.status == 0;
done:
	imsgbuf_clear(&ib);
	close(fd);
	return (ret);
}
