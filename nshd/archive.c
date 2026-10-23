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
 * archive: what config keeps past its end, the candidate configure's
 * sessions share, as config's text, in a directory of archive's own,
 * NSHDB/archive, which it opens before chroot(2), so no other file is
 * in its reach. What config sends is kept whole, fsynced, or not at
 * all, and archive says which; what is kept is what config is sent when
 * it asks.
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

#define ARC_DIR		NSHDB "/archive"
#define ARC_CAND	"candidate"
#define ARC_TEMP	"candidate.new"

static struct imsgev	*iev_relay;
static int		 dir;		/* ARC_DIR */
static char		*text;		/* to keep, as it comes */
static size_t		 len;
static int		 past;		/* past NSHD_KEEPMAX */

static void	archive_dispatch_relay(int, short, void *);
static void	archive_dispatch_config(int, short, void *);
static void	archive_forget_config(void);
static void	archive_open(void);
static int	archive_keep(void);
static void	archive_load(void);

static struct link	 config = {
	PROC_CONFIG, archive_dispatch_config, archive_forget_config
};

/* d and v as child_start() takes them: nsh's externs.h has a verbose */
void
archive(int d, int v)
{
	child_start("archive", d, v);
	archive_open();
	privdrop(PROC_ARCHIVE);
	if (pledge("stdio rpath wpath cpath", NULL) == -1)
		fatal("pledge");

	if ((iev_relay = imsgev_new(3, archive_dispatch_relay, 0)) == NULL)
		fatal(NULL);
	links_init(&config, 1, iev_relay, NULL);
	event_dispatch();
	exit(0);
}

/* ARC_DIR, as root, made archive's user's alone */
static void
archive_open(void)
{
	uid_t	 uid;
	gid_t	 gid;

	if (proc_user(PROC_ARCHIVE, &uid, &gid) == -1)
		fatalx("archive has no user");
	if ((mkdir(NSHDB, 0700) == -1 && errno != EEXIST) ||
	    (mkdir(ARC_DIR, 0700) == -1 && errno != EEXIST))
		fatal("mkdir %s", ARC_DIR);
	if ((dir = open(ARC_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
	    O_CLOEXEC)) == -1)
		fatal("open %s", ARC_DIR);
	if (fchown(dir, uid, gid) == -1 || fchmod(dir, 0700) == -1)
		fatal("%s", ARC_DIR);
}

static void
archive_dispatch_relay(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct imsg	 imsg;
	int		 n;

	if (imsgev_io(iev, event) == -1)
		exit(0);

	for (;;) {
		if ((n = imsgbuf_get(&iev->ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;
		switch (imsg_get_type(&imsg)) {
		case IMSG_STARTUP:
			break;
		default:
			log_debug("%s: unexpected imsg %u", __func__,
			    imsg_get_type(&imsg));
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* config's text, to keep when it says, and its asking for what is kept */
static void
archive_dispatch_config(int fd, short event, void *arg)
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
		case IMSG_ARC_TEXT:
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
		case IMSG_ARC_KEEP:
			if (imsg_get_data(&imsg, &k, sizeof(k)) == -1)
				goto bad;
			k.status = archive_keep();
			/* the next text begins another */
			archive_forget_config();
			if (link_compose(&config, IMSG_ARC_KEPT, 0, &k,
			    sizeof(k)) == -1)
				fatal("%s", __func__);
			break;
		case IMSG_ARC_LOAD:
			if (imsg_get_len(&imsg) != 0)
				goto bad;
			archive_load();
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

/* config started again, or is down: the text it sent is not kept */
static void
archive_forget_config(void)
{
	free(text);
	text = NULL;
	len = 0;
	past = 0;
}

/* the text config sent, kept in place of what was: 0, or -1, logged */
static int
archive_keep(void)
{
	ssize_t	 n;
	size_t	 done;
	int	 fd;

	if (past) {
		log_warnx("the shared candidate is past %d bytes",
		    NSHD_KEEPMAX);
		return (-1);
	}
	if ((fd = openat(dir, ARC_TEMP, O_WRONLY | O_CREAT | O_TRUNC |
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
	if (close(fd) == -1 || renameat(dir, ARC_TEMP, dir, ARC_CAND) == -1 ||
	    fsync(dir) == -1)
		goto fail;
	return (0);
 fail:
	log_warn("%s/%s", ARC_DIR, ARC_CAND);
	unlinkat(dir, ARC_TEMP, 0);
	return (-1);
}

/* what is kept, to config, then that it is all: none if nothing is */
static void
archive_load(void)
{
	struct nshd_result	 res = { 0 };
	struct stat		 sb;
	char			 buf[NSHD_TEXT];
	off_t			 sent = 0;
	ssize_t			 n;
	int			 fd;

	if ((fd = openat(dir, ARC_CAND, O_RDONLY | O_NOFOLLOW |
	    O_CLOEXEC)) == -1) {
		if (errno != ENOENT) {
			log_warn("%s/%s", ARC_DIR, ARC_CAND);
			res.status = -1;
		}
		goto done;
	}
	if (fstat(fd, &sb) == -1 || sb.st_size > NSHD_KEEPMAX) {
		log_warnx("%s/%s: not one to load", ARC_DIR, ARC_CAND);
		res.status = -1;
		close(fd);
		goto done;
	}
	while (sent < sb.st_size) {
		if ((n = read(fd, buf, sizeof(buf))) == -1 && errno == EINTR)
			continue;
		if (n == -1)
			log_warn("%s/%s", ARC_DIR, ARC_CAND);
		else if (n == 0)
			log_warnx("%s/%s: shorter than it was", ARC_DIR,
			    ARC_CAND);
		if (n <= 0) {
			res.status = -1;
			break;
		}
		if (n > sb.st_size - sent)
			n = sb.st_size - sent;
		if (link_compose(&config, IMSG_ARC_TEXT, 0, buf, n) == -1)
			fatal("%s", __func__);
		sent += n;
	}
	close(fd);
 done:
	if (link_compose(&config, IMSG_ARC_LOADED, 0, &res, sizeof(res)) == -1)
		fatal("%s", __func__);
}
