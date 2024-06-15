/*
 * Copyright (c) 2002-2009 Chris Cappuccio <chris@nmedia.net>
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
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <limits.h>
#include "stringlist.h"
#include "externs.h"

#define _PASSWORD_LEN 60

void conf_db_single(FILE *, char *, char *, char *);
void conf_ctl(FILE *, char *, char *, int);
int scantext(char *, char *);

#define TMPSIZ 1024     /* size of temp strings */

int
conf(FILE *output)
{
	char cpass[_PASSWORD_LEN+1];
	char hostbuf[MAXHOSTNAMELEN];

	fprintf(output, "!\n");

	gethostname (hostbuf, sizeof(hostbuf));
	fprintf(output, "hostname %s\n", hostbuf);
	if (read_pass(cpass, sizeof(cpass))) {
		fprintf(output, "enable secret blowfish %s\n", cpass);
	} else {
		if (errno != ENOENT)
			printf("%% Unable to read run-time crypt repository:"
			    " %s\n", strerror(errno));
	}
	fprintf(output, "!\n");
        conf_ctl(output, "", "motd", 0);

	fprintf(output, "!\n");

	conf_ctl(output, "", "sshd", 0);

	fprintf(output, "!\n");

	return(0);
}

void conf_ctl(FILE *output, char *delim, char *name, int rtableid)
{
	FILE *conf;
	struct daemons *x;
	struct ctl *ctl;
	char tmp_str[TMPSIZ], tmpfile[64];
	char *fenablenm = NULL, *fothernm = NULL, *flocalnm = NULL;
	int defenable = 0, pntdrules = 0, pntdflag = 0, dbflag;

	x = (struct daemons *)genget(name, (char **)ctl_daemons,
	    sizeof(struct daemons));
	if (x == 0 || Ambiguous(x)) {
		printf("%% conf_ctl: %s: genget internal failure\n", name);
		return;
	}

	/* print rules if they exist */
	snprintf(tmpfile, sizeof(tmpfile), "%s.%d", x->tmpfile, rtableid);
	if ((conf = fopen(tmpfile, "r")) != NULL) {
		fprintf(output, "%s%s rules\n", delim, name);
		for (;;) {
			if(fgets(tmp_str, TMPSIZ, conf) == NULL)
				break;
			if(tmp_str[0] == 0)
				break;
			fprintf(output, "%s %s", delim, tmp_str);
		}
		fclose(conf);
		fprintf(output, "%s!\n", delim);
		pntdrules = 1;
	} else if (errno != ENOENT || (errno == ENOENT && verbose))
		printf("%% conf_ctl: %s: %s\n", tmpfile, strerror(errno));

	/* fill in argument names from table */
	for (ctl = x->table; ctl != NULL && ctl->name != NULL; ctl++) {
		switch(ctl->flag_x) {
		case DB_X_ENABLE_DEFAULT:
			defenable = 1;
			/* FALLTHROUGH */
		case DB_X_ENABLE:
			fenablenm = ctl->name;
			break;
		case DB_X_LOCAL:
			flocalnm = ctl->name;
			break;
		case DB_X_OTHER:
			fothernm = ctl->name;
			break;
		case DB_X_DISABLE:
		case DB_X_REMOVE:
		case DB_X_DISABLE_ALWAYS:
		case 0:
			break;
		default:
			printf("%% conf_ctl: flag_x %d unknown\n", ctl->flag_x);
			return;
		}
	}
}


/* find string in file */
int scantext(char *fname, char *string)
{
	FILE *file;
	char line[128];
	int found = 0;

	if ((file = fopen(fname, "r")) == 0) {
		printf("%% Unable to open %s: %s\n", fname, strerror(errno));
		return(0);
	}

	for (;;) {
		if (fgets(line, sizeof(line), file) == NULL)
			break;
		if (strcmp(line, string) == 0) {
			found = 1;
			break;
		}
	}

	fclose(file);
	return(found);
}

void
conf_db_single(FILE *output, char *dbname, char *lookup, char *ifname)
{
	StringList *dbreturn;
	dbreturn = sl_init();

	if (db_select_flag_x_ctl(dbreturn, dbname, ifname) < 0) {
		printf("%% conf_db_single %s database select failed\n", dbname);
	}
	if (dbreturn->sl_cur > 0) {
		if (lookup == NULL)
			fprintf(output, " %s\n", dbname);
		else if (strcmp(dbreturn->sl_str[0], lookup) != 0)
			fprintf(output, " %s %s\n", dbname, dbreturn->sl_str[0]);
	}
	sl_free(dbreturn, 1);
}
