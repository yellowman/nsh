/*	$OpenBSD: which.c,v 1.27 2019/01/25 00:19:27 millert Exp $	*/

/*
 * Copyright (c) 1997 Todd C. Miller <millert@openbsd.org>
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

#include <sys/stat.h>

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "externs.h"

int
findprog(char *prog, char *path, int progmode, int allmatches)
{
	char *p, filename[PATH_MAX];
	int len, rval = 0;
	struct stat sbuf;
	char *pathcpy;

	/* Special case if prog contains '/' */
	if (strchr(prog, '/')) {
		if ((stat(prog, &sbuf) == 0) && S_ISREG(sbuf.st_mode) &&
		    access(prog, X_OK) == 0) {
			return (1);
		} else {
			printf("%% %s: Command not found.\n", prog);
			return (0);
		}
	}

	if ((path = strdup(path)) == NULL) {
		printf("%%: findprog: strdup: %s\n", strerror(errno));
		return 0;
	}
	pathcpy = path;

	while ((p = strsep(&pathcpy, ":")) != NULL) {
		if (*p == '\0')
			p = ".";

		len = strlen(p);
		while (len > 0 && p[len-1] == '/')
			p[--len] = '\0';	/* strip trailing '/' */

		len = snprintf(filename, sizeof(filename), "%s/%s", p, prog);
		if (len < 0 || len >= sizeof(filename)) {
			printf("%% findprog: %s/%s: %s\n", p, prog,
			    strerror(ENAMETOOLONG));
			free(path);
			return (0);
		}
		if ((stat(filename, &sbuf) == 0) && S_ISREG(sbuf.st_mode) &&
		    access(filename, X_OK) == 0) {
			rval = 1;
			if (!allmatches) {
				free(path);
				return (rval);
			}
		}
	}
	(void)free(path);

	/* whereis(1) is silent on failure. */
	if (!rval && progmode != PROG_WHEREIS)
		printf("%% %s: Command not found.\n", prog);
	return (rval);
}
