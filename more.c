/* $nsh: more.c,v 1.1 2008/01/20 05:08:35 chris Exp $ */
/*
 * Copyright (c) 2008
 *      Chris Cappuccio.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <string.h>

#include "externs.h"

#define PAGERPROMPT	" --More-- "
#define BACKOVERPROMPT	"\b\b\b\b\b\b\b\b\b\b          \b\b\b\b\b\b\b\b\b\b"

int	nsh_cbreak(void);
void	nsh_nocbreak(void);

static struct termios	oldtty;

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

		/* XXX use termcap to get number of lines in terminal */
		if (i == 24 && !nopager) {
			i = 0;
			printf(PAGERPROMPT);
			fflush(0);
			c = getchar();
			printf(BACKOVERPROMPT);
			if (c == 'q')
				break;
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

	if (tcgetattr(0, &oldtty) < 0)
		return(-1);

	(void)memcpy(&newtty, &oldtty, sizeof(newtty));

	newtty.c_lflag &= ~(ECHO | ICANON);	/* no echo, canonical */
	newtty.c_cc[VMIN] = 1;			/* one char at a time */
	newtty.c_cc[VTIME] = 0;			/* no timeout */

	if (tcsetattr(0, TCSAFLUSH, &newtty) < 0)
		return(-1);
	return(0);
}

void
nsh_nocbreak(void)
{
	tcsetattr(0, TCSAFLUSH, &oldtty);
}
