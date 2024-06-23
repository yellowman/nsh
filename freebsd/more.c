/*
 * Copyright (c) 2008 Chris Cappuccio <chris@nmedia.net>
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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <string.h>
#include <sys/ttycom.h>
#include <sys/ioctl.h>

#include "externs.h"

#define PAGERPROMPT	" --More-- "
#define BACKOVERPROMPT	"\b\b\b\b\b\b\b\b\b\b          \b\b\b\b\b\b\b\b\b\b"

int	nsh_cbreak(void);
void	nsh_nocbreak(void);

static struct termios	oldtty;

struct winsize winsize;

/*
 * Display file
 */
int
more(char *fname)
{
	FILE   *f;
	char   *input, c;
	size_t	s;
	int	i, nopager = 0;

	if ((f = fopen(fname, "r")) == NULL) {
		if (errno == ENOENT)
			printf ("%% File %s not found\n", fname);
		else
			printf ("%% more: fopen(%s): %s\n", fname,
			    strerror(errno));
		return(0);
	}

	if (nsh_cbreak() < 0)
		nopager = 1;

	for (i = 0; (input = fgetln(f, &s)) != NULL; i++) {

		if (!nopager && i == (winsize.ws_row - 1)) {
			printf(PAGERPROMPT);
			fflush(0);
			c = getchar();
			printf(BACKOVERPROMPT);
			if (c == 'q')
				break;			/* stop */
			if (c == '\r' || c == '\n')
				i--;			/* skip one line */
			else
				i = 0;			/* skip one page */
		}

		/*
		 * We replace newline (or whatever was at the end of
	         * the line) with NUL termination
		 */
		input[s-1] = '\0';
		printf("%s\n", input);
	}

	if (!nopager)
		nsh_nocbreak();

	fclose(f);
	return(1);
}

int
nsh_cbreak(void)
{
	struct termios	newtty;

	if (tcgetattr(fileno(stdout), &oldtty) < 0)
		return(-1);

	(void)memcpy(&newtty, &oldtty, sizeof(newtty));

	newtty.c_lflag &= ~(ECHO | ICANON);	/* no echo, canonical */
	newtty.c_cc[VMIN] = 1;			/* one char at a time */
	newtty.c_cc[VTIME] = 0;			/* no timeout */

	if (tcsetattr(fileno(stdout), TCSAFLUSH, &newtty) < 0)
		return(-1);
	return(0);
}

void
nsh_nocbreak(void)
{
	tcsetattr(0, TCSAFLUSH, &oldtty);
}

void
setwinsize(int signo)
{
	int save_errno = errno;

	if (ioctl(fileno(stdout), TIOCGWINSZ, &winsize) != -1) {
		winsize.ws_col = winsize.ws_col ? winsize.ws_col : 80;
		winsize.ws_row = winsize.ws_row ? winsize.ws_row : 24;
	} else {
		winsize.ws_col = 80;
		winsize.ws_row = 24;
	}

	errno = save_errno;
}
