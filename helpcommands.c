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

#include <sys/param.h>
#include <sys/types.h>

#include <net/if.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "externs.h"
#include "commands.h"

int
show_help(int argc, char **argv, ...)
{
	Menu *s; /* pointer to current command */
	u_int z = 0;

	printf("%% Commands may be abbreviated.\n");
	printf("%% 'show' commands are:\n\n");

	for (s = showlist; s->name; s++) {
		if (strlen(s->name) > z)
			z = strlen(s->name);
	}

	for (s = showlist; s->name; s++) {
		if (s->help)
			printf("  %-*s  %s\n", z, s->name, s->help);
	}
	return 0;
}

void
gen_help(char **x, char *cmdprefix, char *descrsuffix, int szstruct)
{
	/* only for structures starting with char *name; char *help; !! */
	char **y = x;
	struct ghs *ghs;
	int z = 0;

	printf("%% Arguments may be abbreviated\n\n");

	while (*y != 0) {
		if (strlen(*y) > z)
			z = strlen(*y);
		y = (char **)((char *)y + szstruct);
	}

	while (*x != 0) {
		ghs = (struct ghs *)x;
		if (ghs->help)
			printf("  %s %-*s %s %s\n", cmdprefix, z, *x,
			    ghs->help, descrsuffix);
		x = (char **)((char *)x + szstruct);
	}
	return;
}

/*
 * Help command.
 */
int
help(int argc, char **argv, ...)
{
	Command *c;

	if (argc == 1) {
		u_int z = 0;

		printf("%% Commands may be abbreviated.\n");
		printf("%% Commands are:\n\n");

		for (c = cmdtab; c->name; c++)
			if (((c->needpriv && priv) || !c->needpriv)
			    && strlen(c->name) > z)
				z = strlen(c->name);
		for (c = cmdtab; c->name; c++) {
			if (c->help &&
			    ((c->needpriv && priv) || !c->needpriv) &&
			    ((c->needconfig && config_mode) || !c->needconfig))
				printf("  %-*s  %s\n", z, c->name, c->help);
		}
		return 0;
	}
	while (--argc > 0) {
		char *arg;
		arg = *++argv;
		c = getcmd(arg);
		if (Ambiguous(c))
			printf("%% Ambiguous help command %s\n", arg);
		else if (c == (Command *)0)
			printf("%% Invalid help command %s\n", arg);
		else
			printf("%% %s: %s\n", arg, c->help);
	}
	return 0;
}
