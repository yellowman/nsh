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
#include <locale.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <sys/ttycom.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include "editing.h"
#include "stringlist.h"
#include "externs.h"
#include "ctl.h"

void usage(void);

jmp_buf toplevel;

char *vers = NSH_VERSION_STR;
int bridge = 0;		/* bridge mode for interface() */
int verbose = 0;	/* verbose mode */
int priv = 0, privexec = 0, cli_rtable = 0;
int editing = 0, interactive_mode = 0, config_mode = 0;;
pid_t pid;

History *histi = NULL;
History *histc = NULL;
HistEvent ev;
EditLine *elc = NULL;
EditLine *eli = NULL;
EditLine *elp = NULL;
char *cursor_pos = NULL;

struct hashtable *nsh_env;	/* per-user session environment variables */

void intr(void);

static void
load_userenv(void)
{
	char path[PATH_MAX];
	FILE *f;
	size_t linesize = 0;
	ssize_t linelen;
	char *home, *line = NULL;
	int ret;
	struct stat sb;

	home = getenv("HOME");
	if (home == NULL)
		return;

	if (nsh_env == NULL) {
		nsh_env = hashtable_alloc();
		if (nsh_env == NULL) {
			printf("%% hashtable_alloc: %s", strerror(errno));
			return;
		}
	}

	ret = snprintf(path, sizeof(path), "%s/.nshenv", home);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return;

	/* Fail silently if the file does not exist or is inaccessible. */
	f = fopen(path, "r");
	if (f == NULL)
		return;
	if (fstat(fileno(f), &sb) == -1)  {
		fclose(f);
		return;
	}

	/*
	 * Fail silently if the file is owned by a different user.
	 * In particular, we do not want to load a non-root user's
	 * ~/.nshenv file while running as root.
	 * In privileged mode our environment may have already been inherited
	 * from non-root to root through exec, depending on the configuration
	 * in case of doas(1) or su(1).
	 */
	if (sb.st_uid != getuid()) {
		fclose(f);
		return;
	}

	while ((linelen = getline(&line, &linesize, f)) != -1) {
		char *name, *eq, *value;

		while (linelen > 0 && line[linelen - 1] == '\n') {
			line[linelen - 1] = '\0';
			linelen--;
		}

		name = strdup(line);
		if (name == NULL) {
			printf("%% %s: strdup: %s", __func__, strerror(errno));
			break;
		}

		eq = strchr(name, '=');
		if (eq == NULL) {
			free(name);
			continue;
		}

		*eq = '\0';
		value = eq + 1;

		if (setenv(name, value, 1) == -1) {
			printf("%% setenv %s=%s: %s\n",
			    name, value, strerror(errno));
			free(name);
			break;
		}

		if (hashtable_add(nsh_env, name, strlen(name),
		    value, strlen(value))) {
			printf("%% %s: hashtable_add(\"%s\", \"%s\") failed\n",
			    __func__, name, value);
			free(name);
			break;
		}
	}

	free(line);
	fclose(f);
}

int
main(int argc, char *argv[])
{
	int top, ch, iflag = 0, cflag = 0;
	char rc[PATH_MAX];

	setlocale(LC_CTYPE, "");

	pid = getpid();

	while ((ch = getopt(argc, argv, "c:ei:v")) != -1)
		switch (ch) {
		case 'c':
			cflag = 1;
			strlcpy(rc, optarg, PATH_MAX);
			break;
		case 'e':
			if (getuid() != 0) {
				fprintf(stderr, "%s: Use of -e option requires "
				    "root privileges.\n", getprogname());
				exit(1);
			}
			privexec = 1;
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

	interactive_mode = isatty(STDIN_FILENO);
	if (interactive_mode) {
		editing = 1;

		if (getuid() != 0) {
			printf("%% Functionality is limited without "
			    "root privileges.\n%% The 'enable' command "
			    "will switch to the root user.\n");
		}

		if (!privexec)
			printf("%% NSH v%s\n", vers);
	}

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
	if (privexec) {
		/*
		 * We start out in privileged mode.
		 * We are already running as root as per -e option handling.
		 * The privexec flag also affects the behaviour of commands
		 * such as 'disable' and 'quit'. 'disable' will pass control
		 * back to the parent process which runs in non-privileged
		 * mode. "quit' does the same with a special exit code to let
		 * the parent know that it should exit immediately.
		 */
		priv = 1;
	} else if (getuid() == 0) {
		/*
		 * Root users always start out in privileged mode.
		 * They can use 'disable' if they want to exit priv mode.
		 */
		priv = 1;
	}

	load_userenv();

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
