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

#include <sys/param.h>	/* MAXHOSTNAMELEN */
#include <net/if.h>	/* IFNAMSIZ */

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "externs.h"
#include "commands.h"
#include "ctl.h"

int
pr_prot1(int argc, char **argv, ...)
{
	struct prot1 *x;
	struct prot *prot;
	char *args[NOPTFILL] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	char **fillargs;
	char prefix[64];

	/* loop protocol list to find table pointer */
	prot = (struct prot *) genget(argv[1], (char **)prots,
	    sizeof(struct prot));
	if (prot == 0) {
		printf("%% Internal error - Invalid argument %s\n", argv[1]);
		return -1;
	} else if (Ambiguous(prot)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[1]);
		return -1;
	}

	snprintf(prefix, sizeof(prefix), "show %s", prot->name);

	/* no clue? we can help */
	if (argc < 3 || argv[2][0] == '?') {
		gen_help((char **)prot->table, prefix, "information",
		    sizeof(struct prot1));
		return 0;
	}
	x = (struct prot1 *) genget(argv[2], (char **)prot->table,
	    sizeof(struct prot1));
	if (x == 0) {
		printf("%% Invalid argument %s\n", argv[2]);
		return -1;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", argv[2]);
		return -1;
	}

	fillargs = step_optreq(x->args, args, argc, argv, 3);
	if (fillargs == NULL)
		return -1;

	/* systat draws on this terminal; prot1_run() runs the rest */
	if (prot1_find(prot->name, x->name) == NULL)
		return cmdargs(fillargs[0], fillargs) == 0 ? 0 : -1;
	return prot1_run(prot->name, x->name, argc - 3, argv + 3, fillargs);
}

/*
 * The show of prot that sub names, as pr_prot1() names them, whose
 * program nshd's system may run: NULL if there is none, as systat's
 * is not, which draws on nsh's terminal
 */
struct prot1 *
prot1_find(char *prot, char *sub)
{
	struct prot *p;
	struct prot1 *x;
	size_t len = strlen(sub);

	for (p = prots; p->name != NULL; p++)
		if (strcmp(p->name, prot) == 0)
			break;
	if (p->name == NULL || strcmp(p->name, "system-stats") == 0)
		return NULL;
	/* a name in the table may end with spaces */
	for (x = p->table; x->name != NULL; x++)
		if (strncmp(x->name, sub, len) == 0 &&
		    x->name[len + strspn(x->name + len, " ")] == '\0')
			return x;
	return NULL;
}

/*
 * x's program and its arguments, in args, with those x leaves to fill
 * taken from argc words of argv, and bgpctl's socket the one of table:
 * NULL if they do not fill them, said why
 */
char **
prot1_args(struct prot1 *x, char **args, int argc, char **argv, int table)
{
	init_bgpd_socket_path(table);
	return step_optreq(x->args, args, argc, argv, 0);
}

char **
step_optreq(char **xargs, char **args, int argc, char **argv, int skip)
{
	int i;
	int fill = 0;	/* total fillable arguments */
	int flc = 0;	/* number of filled arguments */

	/* count fillable arguments */
	for (i = 0; i < NOPTFILL - 1; i++) {
		if (xargs[i] == OPT || xargs[i] == REQ)
			fill++;
		if (xargs[i] == NULL)
			break;
	}

	if (argc - skip > fill) {
		printf("%% Superfluous argument: %s\n", argv[skip + fill]);
		return NULL;
	}

	/* copy xargs to args, replace OPT/REQ args with argv past skip */
	for (i = 0; i < NOPTFILL - 1; i++) {
		if (xargs[i] == NULL) {
			args[i] = NULL;
			if (i > 1)
			/*
			 * all **args passed must have at least two arguments
			 * and a terminating NULL.  the point of this check
			 * is to allow the first two arguments to be NULL but
			 * still fill in fillargs[x] with corresponding NULL
			 */
				break;
		}
		if (xargs[i] == OPT || xargs[i] == REQ) {
			/* copy from argv to args */
			if (argc - skip - flc > 0) {
				args[i] = argv[skip + flc];
				flc++;
			} else if (xargs[i] == REQ) {
				printf("%% Missing required argument\n");
				return NULL;
			} else {
				args[i] = NULL;
				break;
			}
		} else {
			/* copy from xargs to args */
			args[i] = xargs[i];
		}
	}

	return args;
}
