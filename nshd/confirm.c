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
 * The record of a commit not confirmed, which system makes, and parent
 * reads too, so that it knows when system should have taken the commit
 * back: a head line, then the configuration it goes back to.
 *
 *	STATE ID DEADLINE UNTIL ATTEMPTS DEMOTED LENGTH
 *
 * STATE is waiting, until it is confirmed or goes back, or failed, if
 * it could not go back. ID, 16 hex digits and not 0, names the commit.
 * DEADLINE is when it goes back, by the wall clock, and UNTIL, if not
 * 0, when what system does first may end. ATTEMPTS to go back were
 * begun, and DEMOTED is 1 while carp is demoted for it. LENGTH is the
 * configuration's. Each is as written here, or it is not a record.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "nshd.h"
#include "stringlist.h"
#include "externs.h"

#define CONFIRM_RECORD	NSHDB "/confirm"
#define CONFIRM_HEAD	128	/* the head line, at most */
#define HEAD_FORMAT	"%s %016llx %lld %lld %d %d %zu"

static const char *confirm_states[] = { "none", "waiting", "failed" };

static int	readall(int, char *, size_t, off_t);

/*
 * The record into cf, with its configuration if whole, or state
 * CONFIRM_NONE if there is none: -1 if it cannot be read, errno EFTYPE
 * if it is not a record
 */
int
confirm_read(struct confirm *cf, int whole)
{
	struct stat		 sb;
	char			 head[CONFIRM_HEAD + 1], canon[CONFIRM_HEAD];
	char			 state[16], *nl;
	unsigned long long	 id;
	long long		 deadline, until;
	size_t			 len;
	int			 fd, i, serrno;

	memset(cf, 0, sizeof(*cf));
	if ((fd = open(CONFIRM_RECORD, O_RDONLY | O_CLOEXEC)) == -1)
		return (errno == ENOENT ? 0 : -1);
	if (fstat(fd, &sb) == -1)
		goto fail;
	len = sb.st_size < CONFIRM_HEAD ? sb.st_size : CONFIRM_HEAD;
	if (readall(fd, head, len, 0) == -1)
		goto fail;
	head[len] = '\0';
	if ((nl = memchr(head, '\n', len)) == NULL)
		goto bad;
	*nl = '\0';
	if (sscanf(head, "%15s %llx %lld %lld %d %d %zu", state, &id,
	    &deadline, &until, &cf->attempts, &cf->demoted, &cf->backlen) != 7)
		goto bad;
	/* as written, and no other way */
	snprintf(canon, sizeof(canon), HEAD_FORMAT, state, id, deadline, until,
	    cf->attempts, cf->demoted, cf->backlen);
	if (strcmp(canon, head) != 0 || id == 0 || deadline <= 0 ||
	    until < 0 || cf->attempts < 0 || (cf->demoted != 0 &&
	    cf->demoted != 1) || cf->backlen > NSHD_PART ||
	    (nl - head) + 1 + (off_t)cf->backlen != sb.st_size)
		goto bad;
	for (i = CONFIRM_WAITING; i <= CONFIRM_FAILED; i++)
		if (strcmp(state, confirm_states[i]) == 0)
			cf->state = i;
	if (cf->state == CONFIRM_NONE)
		goto bad;
	cf->id = id;
	cf->deadline = deadline;
	cf->until = until;
	if (whole) {
		if ((cf->back = malloc(cf->backlen + 1)) == NULL ||
		    readall(fd, cf->back, cf->backlen, (nl - head) + 1) == -1)
			goto fail;
		cf->back[cf->backlen] = '\0';
	}
	close(fd);
	return (0);
 bad:
	errno = EFTYPE;
 fail:
	serrno = errno;
	close(fd);
	confirm_free(cf);
	cf->state = CONFIRM_NONE;
	errno = serrno;
	return (-1);
}

void
confirm_free(struct confirm *cf)
{
	free(cf->back);
	cf->back = NULL;
}

/* len bytes of fd at off into buf: -1 if not, errno EFTYPE if it is short */
static int
readall(int fd, char *buf, size_t len, off_t off)
{
	ssize_t	 n;
	size_t	 got;

	for (got = 0; got < len; got += n)
		if ((n = pread(fd, buf + got, len - got, off + got)) <= 0) {
			if (n == -1 && errno == EINTR) {
				n = 0;
				continue;
			}
			if (n == 0)
				errno = EFTYPE;
			return (-1);
		}
	return (0);
}
