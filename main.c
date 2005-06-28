/* $nsh: main.c,v 1.22 2005/06/28 19:42:32 chris Exp $ */
/*
 * Copyright (c) 2002, 2003
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
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <histedit.h>
#include "externs.h"
#include "editing.h"

void usage(void);
void rmtemp(void);

char *vers = "20050628";
int bridge = 0;		/* bridge mode for interface() */
int verbose = 0;	/* verbose mode for lots of stuff*/
int priv = 0;
int editing;
pid_t pid;

History *histi = NULL;
History *histc = NULL;
HistEvent ev;
EditLine *elc = NULL;
EditLine *eli = NULL;
char *cursor_pos = NULL;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch, iflag = 0;
	char rc[PATH_MAX];
	pid = getpid();

	while ((ch = getopt(argc, argv, "i:v")) != -1)
		switch (ch) {
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

	printf("%% NSH v%s\n", vers);

	if (argc > 0)
		usage();

	/*
	 * For future kvm access
	 */
	load_nlist();

	if (iflag) {
		/*
		 * Run initialization and then exit.
		 */
		rmtemp();
		cmdrc(rc);
		exit(0);
	}

	for (;;) {
		command(1);
	}

	return 0;
}

void
rmtemp(void)
{
	if (unlink(PFCONF_TEMP) != 0)
		if (errno != ENOENT)
			printf("%% Unable to remove temporary PF rules for "
			    "reinitialization %s\n", strerror(errno));
}

void
usage(void)
{
	(void)fprintf(stderr, "usage: %s [-vi rcfile]\n", __progname);
	(void)fprintf(stderr, "           -v indicates verbose operation\n");
	(void)fprintf(stderr, "           -i rcfile loads configuration from rcfile\n");
	exit(1);
}
