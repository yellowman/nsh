/*
 * Copyright (c) 2002-2013 Chris Cappuccio <chris@nmedia.net>
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
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <sys/ttycom.h>
#include <sys/signal.h>
#include "editing.h"
#include "stringlist.h"
#include "externs.h"
#include "ctl.h"

void usage(void);

jmp_buf toplevel;

char *vers = NSH_VERSION_STR;
int bridge = 0;		/* bridge mode for interface() */
int verbose = 0;	/* verbose mode */
int priv = 0, cli_rtable = 0;
int editing = 1, config_mode = 0;;
pid_t pid;

History *histi = NULL;
History *histc = NULL;
HistEvent ev;
EditLine *elc = NULL;
EditLine *eli = NULL;
EditLine *elp = NULL;
char *cursor_pos = NULL;

void intr(void);

int
main(int argc, char *argv[])
{
	int top, ch, iflag = 0, cflag = 0;
	char rc[PATH_MAX];

	if(getuid() != 0)
		printf("%% Functionality limited without root privilege.\n");

	pid = getpid();

	while ((ch = getopt(argc, argv, "c:i:v")) != -1)
		switch (ch) {
		case 'c':
			cflag = 1;
			strlcpy(rc, optarg, PATH_MAX);
			break;
		case 'i':
			iflag = 1;
			strlcpy(rc, optarg, PATH_MAX);
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;
	if (cflag && iflag)
		usage();
	if (argc > 0)
		usage();
	if (iflag)
		rmtemp(SQ3DBFILE);

	printf("%% NSH v%s\n", vers);

	/* create temporal tables (if they aren't already there) */
	if (db_create_table_rtables() < 0)
		printf("%% database rtables creation failed\n");
	if (db_create_table_flag_x("ctl") < 0)
		printf("%% database ctl creation failed\n");
	if (db_create_table_flag_x("dhcrelay") < 0)
		printf("%% database dhcrelay creation failed\n");
	if (db_create_table_flag_x("ipv6linklocal") < 0)
		printf("%% database ipv6linklocal creation failed\n");
	if (db_create_table_flag_x("lladdr") < 0)
		printf("%% database lladdr creation failed\n");
	if (db_create_table_flag_x("authkey") < 0)
		printf("%% database authkey creation failed\n");
	if (db_create_table_flag_x("peerkey") < 0)
		printf("%% database peerkey creation failed\n");
	if (db_create_table_nameservers() < 0)
		printf("%% database nameservers creation failed\n");
	if (db_create_table_flag_x("pppoeipaddrmode") < 0)
		printf("%% database pppoeipaddrmode creation failed\n");
	if (db_create_table_flag_x("pin") < 0)
		printf("%% database pin creation failed\n");

	if (iflag) {
		/*
		 * Interpret config file and exit
		 */
		priv = 1;

		/*
		 * Set carp group carpdemote to 128 during initialization
		 */
		carplock(128);

		cmdrc(rc);

		/*
		 * Initialization over
		 */
		carplock(-128);

		exit(0);
	}
	if (cflag) {
		/*
		 * Interpret command file and exit
		 */
		priv = 1;

		cmdrc(rc);

		exit(0);
	}

	top = setjmp(toplevel) == 0;
	if (top) {
		(void)signal(SIGWINCH, setwinsize);
		(void)signal(SIGINT, (sig_t)intr);
		(void)setwinsize(0);
	} else
		putchar('\n');

	for (;;) {
		command();
		top = 1;
	}

	/* NOTREACHED */
	return 0;
}

void
usage(void)
{
	fprintf(stderr, "usage: %s [-v] [-i rcfile | -c rcfile]\n", __progname);
	fprintf(stderr, "           -v indicates verbose operation\n");
	fprintf(stderr, "           -i rcfile loads initial system" \
		    " configuration from rcfile\n");
	fprintf(stderr, "           -c rcfile loads commands from rcfile\n");
	exit(1);
}

void
intr(void)
{
	longjmp(toplevel, 1);
}
