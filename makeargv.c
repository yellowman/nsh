/*
 * Copyright (c) 1988, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "externs.h"
#include "editing.h"

char line[1024];
char saveline[1024];
int  margc;

char	*margv[NARGS];			/* argv storage */
size_t	cursor_argc;			/* location of cursor in margv */
size_t	cursor_argo;			/* offset of cursor margv[cursor_argc] */

static int split(char *, char **, int, size_t, size_t *, size_t *);

/*
 * line in words, in margv, and how many in margc. A line that starts with
 * ! is the shell's, its first word !. cursor_argc and cursor_argo say
 * where cursor_pos is in them. -1 if they would not fit, with none
 */
int
makeargv(void)
{
	char	*cp = line;
	int	 n = 0;

	margc = 0;
	if (*cp == '!') {	/* Special case shell escape */
		/* save for shell command */
		strlcpy(saveline, line, sizeof(saveline));

		margv[n++] = "!";	/* No room in string to get this */
		cp++;
		cursor_argc = 0;
		cursor_argo = 0;
	}
	if ((n = split(cp, margv, n, NARGS, &cursor_argc,
	    &cursor_argo)) == -1) {
		margv[0] = NULL;
		cursor_argc = 0;
		cursor_argo = 0;
		return -1;
	}
	margc = n;
	if (cursor_pos == line) {
		cursor_argc = 0;
		cursor_argo = 0;
	}
	return 0;
}

/*
 * cp in words, after the n in argv already, and a NULL after them, in
 * argv's max: how many there are then, or -1 if they would not fit.
 * argc and argo say where cp ends: in which word, and how far into it
 */
static int
split(char *cp, char **argv, int n, size_t max, size_t *argc,
    size_t *argo)
{
	char	*cp2, *base, c;

	while ((c = *cp)) {
		int inquote = 0;
		while (isspace((unsigned char)c))
			c = *++cp;
		if (c == '\0')
			break;
		/* this word, and the NULL after it */
		if ((size_t)n + 2 > max)
			return -1;
		argv[n++] = cp;
		*argc = n;
		base = cp;
		for (*argo = 0, cp2 = cp; c != '\0';
		    *argo = (cp + 1) - base, c = *++cp) {
			if (inquote) {
				if (c == inquote) {
					inquote = 0;
					continue;
				}
			} else {
				if (c == '\\') {
					if ((c = *++cp) == '\0')
						break;
				} else if (c == '"') {
					inquote = '"';
					continue;
				} else if (c == '\'') {
					inquote = '\'';
					continue;
				} else if (isspace((unsigned char)c)) {
					*argo = 0;
					break;
				}
			}
			*cp2++ = c;
		}
		*cp2 = '\0';
		if (c == '\0') {
			(*argc)--;
			break;
		}
		cp++;
	}
	argv[n] = NULL;
	return n;
}
