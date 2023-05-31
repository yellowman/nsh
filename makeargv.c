/*
 * Copyright (c) 2002-2008 Chris Cappuccio <chris@nmedia.net>
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

void
makeargv(void)
{
	char	*cp, *cp2, *base, c;
	char	**argp = margv;

	margc = 0;
	cp = line;
	if (*cp == '!') {	/* Special case shell escape */
		/* save for shell command */
		strlcpy(saveline, line, sizeof(saveline));

		*argp++ = "!";	/* No room in string to get this */
		margc++;
		cp++;
	}
	while ((c = *cp)) {
		int inquote = 0;
		while (isspace((unsigned char)c))
			c = *++cp;
		if (c == '\0')
			break;
		*argp++ = cp;
		cursor_argc = margc += 1;
		base = cp;
		for (cursor_argo = 0, cp2 = cp; c != '\0';
		    cursor_argo = (cp + 1) - base, c = *++cp) {
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
					cursor_argo = 0;
					break;
				}
			}
			*cp2++ = c;
		}
		*cp2 = '\0';
		if (c == '\0') {
			cursor_argc--;
			break;
		}
		cp++;
	}
	*argp++ = 0;
	if (cursor_pos == line) {
		cursor_argc = 0;
		cursor_argo = 0;
	}
}
