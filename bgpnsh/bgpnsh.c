/*
 * Copyright (c) 2002-2008 Chris Cappuccio <chris@nmedia.net>
 * Copyright (c) 2023 Stefan Sperling <stsp@openbsd.org>
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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>

#include "../externs.h"
#include "../editing.h"
#include "../commands.h"
#include "../ctl.h"

#define BGPNSH_SOCKET "/var/www/run/bgpd.rsock" /* restricted socket */

History *histc = NULL;
History *histi = NULL;
HistEvent ev;
EditLine *elc = NULL;
EditLine *eli = NULL;
EditLine *elp = NULL;
char *cursor_pos = NULL;

pid_t	child;

void sigalarm(int signo)
{
	if (child != -1) {
		kill(child, SIGKILL);
	}
}

int editing = 1, config_mode = 0, interactive_mode = 1;
int cli_rtable;
int bridge;
size_t Intlist_nitems = 0, Bridgelist_nitems = 0;
int priv;

char hbuf[MAXHOSTNAMELEN];	/* host name */
char ifname[IFNAMSIZ];		/* interface name */

struct intlist *whichlist;

extern struct prot1 bgcs[];

struct prot prots[] = {
	{ "bgp",	bgcs },
};

Menu showlist[] = {
	{ "bgp",	"BGP information",
	   CMPL(ta) (char **)bgcs, sizeof(struct prot1), 0, 4, pr_prot1 },
	{ 0, 0, 0, 0, 0 }
};

static int
showcmd(int argc, char **argv, ...)
{
	Menu *s;	/* pointer to current command */

	if (argc < 2) {
		show_help(argc, argv);
		return 0;
	}

	/*
	 * Validate show argument
	 */
	s = (Menu *) genget(argv[1], (char **) showlist, sizeof(Menu));
	if (s == 0) {
		printf("%% Invalid argument %s\n", argv[1]);
		return 0;
	} else if (Ambiguous(s)) {
		printf("%% Ambiguous argument %s\n", argv[1]);
		return 0;
	}
	if (((s->minarg + 2) > argc) || ((s->maxarg + 2) < argc)) {
		printf("%% Wrong number of argument%s to 'show %s' command"
		    " (min %i, max %i)\n", argc <= 2 ? "" : "s", s->name,
		    s->minarg, s->maxarg);
		return 0;
	}

	(*s->handler)(argc, argv, NULL);
	return 0;
}

int
quit(int argc, char **argv, ...)
{
	printf("%% Session terminated.\n");
	exit(0);
	return 0;
}

Command cmdtab[] = {
	{ "show",	"Show system information",
	    CMPL(ta) (char **)showlist, sizeof(Menu), showcmd,	0, 0, 0, 0 },
	{ "quit",	"Close current connection",
	    CMPL0 0, 0, quit,		0, 0, 0, 0 },
	{ "help",	0,
	    CMPL(c) 0, 0, help,		0, 0, 0, 0 },
	{ 0,		0,		CMPL0 0, 0, 0,			0, 0, 0, 0 }
};
size_t cmdtab_nitems = nitems(cmdtab);

Command *
getcmd(char *name)
{
	Command *cm;

	cm = (Command *) genget(name, (char **) cmdtab, sizeof(Command));
	return cm;
}

void
command(void)
{
	Command  *c;
	u_int num;

	for (;;) {
		const char *buf;
		cursor_pos = NULL;

		if ((buf = el_gets(elc, &num)) == NULL || num == 0)
			break;

		if (buf[--num]  == '\n') {
			if (num == 0)
				break;
		}
		if (num >= sizeof(line)) {
			printf("%% Input exceeds permitted length\n");
			break;
		}
		memcpy(line, buf, (size_t)num);
		line[num] = '\0';
		history(histc, &ev, H_ENTER, buf);

		if (line[0] == 0)
			break;
		makeargv();
		if (margv[0] == 0) {
			break;
		}

		c = getcmd(margv[0]);
		if (Ambiguous(c)) {
			printf("%% Ambiguous command\n");
			continue;
		}
		if (c == 0) {
			int val = el_burrito(elc, margc, margv);
			if (val)
				printf("%% Invalid command\n");
			continue;
		}
		if (NO_ARG(margv[0]) && ! c->nocmd) {
			printf("%% Invalid command: %s %s\n", margv[0],
			    margv[1]);
			continue;
		}

		if ((*c->handler) (margc, margv, 0))
			break;
	}
}

int
main(int argc, char *argv[])
{
	char *socket_path;

	if (argc != 1) {
		fprintf(stderr, "usage: %s\n", getprogname());
		return 1;
	}

	inithist();
	initedit();

	if (unveil(BGPCTL, "x") == -1)
		err(1, "unveil %s", BGPCTL);

	if (unveil(NULL, NULL) == -1)
		err(1, "unveil");

	if (pledge("stdio tty proc exec", NULL) == -1)
		err(1, "pledge");

	socket_path = getenv("BGPNSH_SOCKET");
	if (socket_path == NULL)
		socket_path = BGPNSH_SOCKET;
	if (strlcpy(bgpd_socket_path, socket_path, sizeof(bgpd_socket_path)) >=
	    sizeof(bgpd_socket_path))
		err(1, "bgpd socket path too long");

	command();

	return 0;
}
