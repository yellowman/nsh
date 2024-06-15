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
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <limits.h>
#include "externs.h"

/* service daemons */
#define SSHD		"/usr/sbin/sshd"

/* table variable (for pkill usage) */
static char table[16];

/* service routines */
void call_editor(char *, char **, char *);
void ctl_symlink(char *, char *, char *);
int rule_writeline(char *, mode_t, char *);
int fill_tmpfile(char **, char *, char **);
int acq_lock(char *);
void rls_lock(int);

/* master daemon list */
struct daemons ctl_daemons[] = {
{ "sshd",	"SSH",	ctl_sshd,	SSHDCONF_TEMP,	0600, 0, 255 },
{ 0, 0, 0, 0, 0, 0 }
};

/* per-daemon commands, and their C or executable functions */ 

/* MOTD */
struct ctl ctl_motd[] = {
        { "edit",           "edit message-of-the-day",
            { "motd", NULL, NULL }, call_editor, 0, T_HANDLER },
        { 0, 0, { 0 }, 0, 0, 0 }
};

/* sshd */
char *ctl_sshd_test[] = { SSHD, "-tf", REQTEMP, NULL };
struct ctl ctl_sshd[] = {
	{ "enable",	"enable service",
	    { SSHD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	    { PKILL, table, "-f", SSHD, "-f", REQTEMP, NULL }, NULL,
	    DB_X_DISABLE, T_EXEC },
	{ "edit",	"edit configuration",
	    { "sshd", (char *)ctl_sshd_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

void
ctl_symlink(char *temp, char *real, char *z)
{
	rmtemp(temp);
	symlink(real, temp);
}

/* flag to other nsh sessions or nsh conf() that actions have been taken */
void
flag_x(char *name, char *daemon, int dbflag, char *data)
{
	if (db_delete_flag_x_ctl(name, daemon) < 0) {
		printf("%% database delete failure ctl ctl\n");
		return;
	}
	if (dbflag == DB_X_REMOVE)
		return;
	if (db_insert_flag_x(name, daemon, cli_rtable, dbflag, data) < 0) {
		printf("%% database insert failure ctl ctl\n");
	}
}

/* the main entry point into ctl.c from CLI */
int
ctlhandler(int argc, char **argv, char *modhvar)
{
	struct daemons *daemons;
	struct ctl *x;
	char tmpfile[PATH_MAX];
	char *step_args[NOPTFILL] = { NULL, NULL, NULL, NULL, NULL, NULL };
	char *tmp_args[NOPTFILL] = { NULL, NULL, NULL, NULL, NULL, NULL };
	char **fillargs;

	/* loop daemon list to find table pointer */
	daemons = (struct daemons *) genget(hname, (char **)ctl_daemons,
	    sizeof(struct daemons));
	if (daemons == 0) {
		printf("%% Internal error - Invalid argument %s\n", argv[1]);
		return 0;
	} else if (Ambiguous(daemons)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[1]);
		return 0;
	}

	if (cli_rtable > daemons->rtablemax) {
		printf("%% Command %s not available via rtable %d\n",
		    daemons->name, cli_rtable);
		return 0;
	}

	snprintf(table, sizeof(table), "-T%d", cli_rtable);
	if (daemons->tmpfile)
		snprintf(tmpfile, sizeof(tmpfile), "%s.%d", daemons->tmpfile,
		    cli_rtable);

	if (modhvar) {
		/* action specified or indented command specified */
		if (argc == 2 && isprefix(argv[1], "rules")) {
			/* skip 'X rules' line */
			return(0);
		}
		if (isprefix(modhvar, "rules")) {
			if (!daemons->tmpfile) {
				printf("%% writeline without tmpfile\n");
				return 0;
			}
			/* write indented line to tmp config file */
			rule_writeline(tmpfile, daemons->mode, saveline);
			return 0;
		}
	}
	if (argc < 2 || argv[1][0] == '?') {
		gen_help((char **)daemons->table, "", "", sizeof(struct ctl));
		return 0;
	}

	x = (struct ctl *) genget(argv[1], (char **)daemons->table,
	    sizeof(struct ctl));
	if (x == 0) {
		printf("%% Invalid argument %s\n", argv[1]);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", argv[1]);
		return 0;
	}

	fillargs = step_optreq(x->args, step_args, argc, argv, 2);
	if (fillargs == NULL)
		return 0;

	switch(x->type) {
		/* fill_tmpfile will return 0 if tmpfile or args are NULL */
	case T_HANDLER:
		/* pointer to handler routine, fill main args */
		if (fill_tmpfile(fillargs, tmpfile, tmp_args)) {
			(*x->handler)(tmp_args[0], tmp_args[1], tmp_args[2]);
		} else {
			(*x->handler)(fillargs[0], fillargs[1], fillargs[2]);
		}
	break;
	case T_HANDLER_FILL1:
		/* pointer to handler routine, fill args @ args[1] pointer */
		if (fill_tmpfile((char **)fillargs[1], tmpfile, tmp_args))
			(*x->handler)(fillargs[0], tmp_args, fillargs[2]);
		else
			(*x->handler)(fillargs[0], (char **)fillargs[1], fillargs[2]);
	break;
	case T_EXEC:
		/* command to execute via execv syscall, fill main args */
		if (fill_tmpfile(fillargs, tmpfile, tmp_args))
			cmdargs(tmp_args[0], tmp_args);
		else
			cmdargs(fillargs[0], fillargs);
	break;
	}

	if (x->flag_x != 0) {
		flag_x("ctl", daemons->name, x->flag_x, NULL);
	}

	return 1;
}

int
fill_tmpfile(char **fillargs, char *tmpfile, char **tmp_args)
{
	int i;

	if (fillargs == NULL || tmpfile == NULL)
		return 0;

	for (i = 0; i < NOPTFILL - 1; i++) {
		if(fillargs[i] == NULL) {
			break;
		}
		if(fillargs[i] == REQTEMP) {
			tmp_args[i] = tmpfile;
		} else {
			tmp_args[i] = fillargs[i];
		}
	}
	return 1;
}

void
call_editor(char *name, char **args, char *z)
{
	int fd, found = 0;
	char *editor, tmpfile[64];
	struct daemons *daemons;

	for (daemons = ctl_daemons; daemons->name != 0; daemons++)
		if (strncmp(daemons->name, name, strlen(name)) == 0) {
			found = 1;
			break;
		}

	if (!found) {
		printf("%% call_editor internal error\n");
		return;
	}

	snprintf(tmpfile, sizeof(tmpfile), "%s.%d", daemons->tmpfile,
	    cli_rtable);

	/* acq lock, call editor, test config with cmd and args, release lock */
	if ((editor = getenv("EDITOR")) == NULL)
		editor = DEFAULT_EDITOR;
	if ((fd = acq_lock(tmpfile)) > 0) {
		char *argv[] = { editor, tmpfile, NULL };
		cmdargs(editor, argv);
		chmod(tmpfile, daemons->mode);
		if (args != NULL)
			cmdargs(args[0], args);
		rls_lock(fd);
	} else
		printf ("%% %s configuration is locked for editing\n",
		    daemons->propername);
}

int
rule_writeline(char *fname, mode_t mode, char *writeline)
{
	FILE *rulefile;

	rulefile = fopen(fname, "a");
	if (rulefile == NULL) {
		printf("%% Rule write failed: %s\n", strerror(errno));
		return(1);
	}
	if (writeline[0] == ' ')
		writeline++;
	fprintf(rulefile, "%s", writeline);
	fclose(rulefile);
	chmod(fname, mode);
	return(0);
}

int
acq_lock(char *fname)
{
	int fd;
	char lockf[SIZE_CONF_TEMP + sizeof(".lock")];

	/*
	 * some text editors lock (vi), some don't (mg)
	 *
	 * here we lock a separate, do-nothing file so we don't interfere
	 * with the editors that do... (lock multiple concurrent nsh users)
	 */
	snprintf(lockf, sizeof(lockf), "%s.lock", fname);
	if ((fd = open(lockf, O_RDWR | O_CREAT, 0600)) == -1)
			return(-1);
	if (flock(fd, LOCK_EX | LOCK_NB) == 0)
		return(fd);
	else {
		close(fd);
		return(-1);
	}
}

void
rls_lock(int fd)
{
	/* best-effort, who cares */
	flock(fd, LOCK_UN);
	close(fd);
	return;
}

void
rmtemp(char *file)
{
	if (unlink(file) != 0)
		if (errno != ENOENT)
			printf("%% Unable to remove temporary file %s: %s\n",
			    file, strerror(errno));
}
