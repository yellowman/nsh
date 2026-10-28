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
 * The record of an unconfirmed commit, which system makes: a head line,
 * then the rollback configuration.
 *
 *	STATE ID DEADLINE ATTEMPTS DEMOTED LENGTH
 *
 * STATE is waiting, until it is confirmed or rolled back, or failed, if
 * it could not be rolled back. ID, 16 hex digits and not 0, names the
 * commit. DEADLINE is when it is rolled back, by the wall clock. ATTEMPTS
 * is how many rollbacks were begun, and DEMOTED is 1 while carp is
 * demoted for it. LENGTH is the configuration's length. Each is as
 * written here, or it is not a record.
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
#define HEAD_FORMAT	"%s %016llx %lld %d %d %zu"

static const char *confirm_states[] = { "none", "waiting", "failed" };

static int	readall(int, char *, size_t, off_t);
static int	writeall(int, const char *, size_t);
static int	dirsync(void);

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
	long long		 deadline;
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
	if (sscanf(head, "%15s %llx %lld %d %d %zu", state, &id, &deadline,
	    &cf->attempts, &cf->demoted, &cf->backlen) != 6)
		goto bad;
	/* exactly as HEAD_FORMAT writes it */
	snprintf(canon, sizeof(canon), HEAD_FORMAT, state, id, deadline,
	    cf->attempts, cf->demoted, cf->backlen);
	if (strcmp(canon, head) != 0 || id == 0 || deadline <= 0 ||
	    cf->attempts < 0 || (cf->demoted != 0 &&
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

/* cf written as the record, whole or not at all, and synced: -1 if not */
int
confirm_write(struct confirm *cf)
{
	char	 tmp[] = CONFIRM_RECORD ".XXXXXXXXXX", head[CONFIRM_HEAD];
	int	 fd, len, serrno;

	len = snprintf(head, sizeof(head), HEAD_FORMAT "\n",
	    confirm_states[cf->state], (unsigned long long)cf->id,
	    (long long)cf->deadline, cf->attempts, cf->demoted, cf->backlen);
	if (mkdir(NSHDB, 0700) == -1 && errno != EEXIST)
		return (-1);
	if ((fd = mkstemp(tmp)) == -1)
		return (-1);
	if (writeall(fd, head, len) == -1 ||
	    writeall(fd, cf->back, cf->backlen) == -1 || fsync(fd) == -1)
		goto fail;
	if (close(fd) == -1) {
		fd = -1;
		goto fail;
	}
	fd = -1;
	if (rename(tmp, CONFIRM_RECORD) == -1)
		goto fail;
	return (dirsync());
 fail:
	serrno = errno;
	if (fd != -1)
		close(fd);
	unlink(tmp);
	errno = serrno;
	return (-1);
}

/* the record removed, and the removal synced: -1 if not */
int
confirm_clear(void)
{
	if (unlink(CONFIRM_RECORD) == -1)
		return (errno == ENOENT ? 0 : -1);
	return (dirsync());
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

static int
writeall(int fd, const char *buf, size_t len)
{
	ssize_t	 n;

	for (; len > 0; buf += n, len -= n)
		if ((n = write(fd, buf, len)) == -1) {
			if (errno == EINTR) {
				n = 0;
				continue;
			}
			return (-1);
		}
	return (0);
}

/* NSHDB's entries, as they now are, synced: -1 if not */
static int
dirsync(void)
{
	int	 fd, r, serrno;

	if ((fd = open(NSHDB, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		return (-1);
	r = fsync(fd);
	serrno = errno;
	close(fd);
	errno = serrno;
	return (r);
}
