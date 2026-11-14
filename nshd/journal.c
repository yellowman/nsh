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
 * journal keeps, past config's end, the candidate that configure's
 * sessions share, as config's text. It keeps it in a directory of its
 * own, NSHDB/journal, which it opens before chroot(2), so no other file
 * is in its reach. What config sends is kept whole, fsynced, or not at
 * all, and journal says which; when config asks, journal sends it what is
 * kept.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
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

#define STORE_DIR		NSHDB "/journal"
#define STORE_CAND	"candidate"
#define STORE_TEMP	"candidate.new"

static int		 dir;		/* STORE_DIR */
static char		*text;		/* to keep, as it comes */
static size_t		 len;
static int		 past;		/* past NSHD_KEEPMAX */

static void	journal_dispatch_config(int, short, void *);
static void	journal_clear(void);
static void	journal_open(void);
static int	journal_keep(void);
static void	journal_load(void);

static struct link	 config = { PROC_CONFIG, journal_dispatch_config };

/* d and v as child_start() takes them: nsh's externs.h has a verbose */
void
journal(int d, int v)
{
	child_start("journal", d, v);
	journal_open();
	privdrop(PROC_JOURNAL);
	/* its pipe to config is fd 3, and no descriptor comes after it */
	if (pledge("stdio rpath wpath cpath", NULL) == -1)
		fatal("pledge");

	links_init(&config, 1, 3);
	event_dispatch();
	exit(0);
}

/* STORE_DIR, made and opened as root, for journal's user alone */
static void
journal_open(void)
{
	uid_t	 uid;
	gid_t	 gid;

	if (proc_user(PROC_JOURNAL, &uid, &gid) == -1)
		fatalx("journal has no user");
	if ((mkdir(NSHDB, 0700) == -1 && errno != EEXIST) ||
	    (mkdir(STORE_DIR, 0700) == -1 && errno != EEXIST))
		fatal("mkdir %s", STORE_DIR);
	if ((dir = open(STORE_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
	    O_CLOEXEC)) == -1)
		fatal("open %s", STORE_DIR);
	if (fchown(dir, uid, gid) == -1 || fchmod(dir, 0700) == -1)
		fatal("%s", STORE_DIR);
}

/* config's text, its requests to keep it, and to load what is kept */
static void
journal_dispatch_config(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsg		 imsg;
	struct ibuf		 b;
	struct nshd_keep	 k;
	uint32_t		 type;
	int			 n;
	char			*p;

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
		switch (type = imsg_get_type(&imsg)) {
		case IMSG_STORE_TEXT:
			if (imsg_get_ibuf(&imsg, &b) == -1)
				goto bad;
			if (ibuf_size(&b) > NSHD_KEEPMAX - len) {
				past = 1;
				break;
			}
			if ((p = realloc(text, len + ibuf_size(&b))) == NULL)
				fatal("%s", __func__);
			text = p;
			memcpy(text + len, ibuf_data(&b), ibuf_size(&b));
			len += ibuf_size(&b);
			break;
		case IMSG_STORE_KEEP:
			if (imsg_get_data(&imsg, &k, sizeof(k)) == -1)
				goto bad;
			k.status = journal_keep();
			/* the next text begins another */
			journal_clear();
			if (link_compose(&config, IMSG_STORE_KEPT, 0, &k,
			    sizeof(k)) == -1)
				fatal("%s", __func__);
			break;
		case IMSG_STORE_LOAD:
			if (imsg_get_len(&imsg) != 0)
				goto bad;
			journal_load();
			break;
		default:
			goto bad;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
	return;
 bad:
	imsg_free(&imsg);
	link_broken(&config, "sent imsg %u, which it may not, or not whole",
	    type);
}

/* the text config sent so far, dropped */
static void
journal_clear(void)
{
	free(text);
	text = NULL;
	len = 0;
	past = 0;
}

/* keep the text config sent in place of the old: 0, or -1, logged */
static int
journal_keep(void)
{
	ssize_t	 n;
	size_t	 done;
	int	 fd;

	if (past) {
		log_warnx("the shared candidate is past %d bytes",
		    NSHD_KEEPMAX);
		return (-1);
	}
	if ((fd = openat(dir, STORE_TEMP, O_WRONLY | O_CREAT | O_TRUNC |
	    O_NOFOLLOW | O_CLOEXEC, 0600)) == -1)
		goto fail;
	for (done = 0; done < len; done += n)
		if ((n = write(fd, text + done, len - done)) == -1) {
			if (errno == EINTR) {
				n = 0;
				continue;
			}
			close(fd);
			goto fail;
		}
	if (fsync(fd) == -1) {
		close(fd);
		goto fail;
	}
	if (close(fd) == -1 ||
	    renameat(dir, STORE_TEMP, dir, STORE_CAND) == -1 ||
	    fsync(dir) == -1)
		goto fail;
	return (0);
 fail:
	log_warn("%s/%s", STORE_DIR, STORE_CAND);
	unlinkat(dir, STORE_TEMP, 0);
	return (-1);
}

/* what is kept, to config, then LOADED; no text if nothing is kept */
static void
journal_load(void)
{
	struct nshd_result	 res = { 0 };
	struct stat		 sb;
	char			 buf[NSHD_TEXT];
	off_t			 sent = 0;
	ssize_t			 n;
	int			 fd;

	if ((fd = openat(dir, STORE_CAND, O_RDONLY | O_NOFOLLOW |
	    O_CLOEXEC)) == -1) {
		if (errno != ENOENT) {
			log_warn("%s/%s", STORE_DIR, STORE_CAND);
			res.status = -1;
		}
		goto done;
	}
	if (fstat(fd, &sb) == -1 || sb.st_size > NSHD_KEEPMAX) {
		log_warnx("%s/%s: not one to load", STORE_DIR, STORE_CAND);
		res.status = -1;
		close(fd);
		goto done;
	}
	while (sent < sb.st_size) {
		if ((n = read(fd, buf, sizeof(buf))) == -1 && errno == EINTR)
			continue;
		if (n == -1)
			log_warn("%s/%s", STORE_DIR, STORE_CAND);
		else if (n == 0)
			log_warnx("%s/%s: shorter than it was", STORE_DIR,
			    STORE_CAND);
		if (n <= 0) {
			res.status = -1;
			break;
		}
		if (n > sb.st_size - sent)
			n = sb.st_size - sent;
		if (link_compose(&config, IMSG_STORE_TEXT, 0, buf, n) == -1)
			fatal("%s", __func__);
		sent += n;
	}
	close(fd);
 done:
	if (link_compose(&config, IMSG_STORE_LOADED, 0, &res, sizeof(res)) ==
	    -1)
		fatal("%s", __func__);
}
