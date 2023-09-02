/* $OpenBSD: doas.c,v 1.98 2022/12/22 19:53:22 kn Exp $ */
/*
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
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
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <limits.h>
#include <login_cap.h>
#include <bsd_auth.h>
#include <readpassphrase.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>

#include "externs.h"

#include "doas.h"

static void __dead
usage(void)
{
	fprintf(stderr, "usage: nshdoas [-n] [-a style]\n");
	exit(1);
}

static int
parseuid(const char *s, uid_t *uid)
{
	struct passwd *pw;
	const char *errstr;

	if ((pw = getpwnam(s)) != NULL) {
		*uid = pw->pw_uid;
		if (*uid == UID_MAX)
			return -1;
		return 0;
	}
	*uid = strtonum(s, 0, UID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static int
uidcheck(const char *s, uid_t desired)
{
	uid_t uid;

	if (parseuid(s, &uid) != 0)
		return -1;
	if (uid != desired)
		return -1;
	return 0;
}

static int
parsegid(const char *s, gid_t *gid)
{
	struct group *gr;
	const char *errstr;

	if ((gr = getgrnam(s)) != NULL) {
		*gid = gr->gr_gid;
		if (*gid == GID_MAX)
			return -1;
		return 0;
	}
	*gid = strtonum(s, 0, GID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static int
match(uid_t uid, gid_t *groups, int ngroups, uid_t target, const char *cmd,
    const char **cmdargs, struct rule *r)
{
	int i;

	if (r->ident[0] == ':') {
		gid_t rgid;
		if (parsegid(r->ident + 1, &rgid) == -1)
			return 0;
		for (i = 0; i < ngroups; i++) {
			if (rgid == groups[i])
				break;
		}
		if (i == ngroups)
			return 0;
	} else {
		if (uidcheck(r->ident, uid) != 0)
			return 0;
	}
	if (r->target && uidcheck(r->target, target) != 0)
		return 0;
	if (r->cmd) {
		if (strcmp(r->cmd, cmd))
			return 0;
		if (r->cmdargs) {
			/* if arguments were given, they should match explicitly */
			for (i = 0; r->cmdargs[i]; i++) {
				if (!cmdargs[i])
					return 0;
				if (strcmp(r->cmdargs[i], cmdargs[i]))
					return 0;
			}
			if (cmdargs[i])
				return 0;
		}
	}
	return 1;
}

static int
permit(uid_t uid, gid_t *groups, int ngroups, const struct rule **lastr,
    uid_t target, const char *cmd, const char **cmdargs)
{
	size_t i;

	*lastr = NULL;
	for (i = 0; i < nrules; i++) {
		if (match(uid, groups, ngroups, target, cmd,
		    cmdargs, rules[i]))
			*lastr = rules[i];
	}
	if (!*lastr)
		return 0;
	return (*lastr)->action;
}

static int
parseconfig(const char *filename)
{
	extern FILE *yyfp;
	extern int yyparse(void);
	struct stat sb;

	yyfp = fopen(filename, "r");
	if (!yyfp) {
		printf("doas is not enabled, %s: %s\n", filename,
		    strerror(errno));
		return 1;
	}

	if (fstat(fileno(yyfp), &sb) != 0) {
		printf("fstat(\"%s\"): %s\n", filename, strerror(errno));
		return 1;
	}
	if ((sb.st_mode & (S_IWGRP|S_IWOTH)) != 0) {
		printf("%s is writable by group or other", filename);
		return 1;
	}
	if (sb.st_uid != 0) {
		printf("%s is not owned by root", filename);
		return 1;
	}

	yyparse();
	fclose(yyfp);
	return parse_error ? 1 : 0;
}

static int
authuser_checkpass(char *myname, char *login_style)
{
	char *challenge = NULL, *response, rbuf[1024], cbuf[128];
	auth_session_t *as;

	if (!(as = auth_userchallenge(myname, login_style, "auth-doas",
	    &challenge))) {
		warnx("Authentication failed");
		return AUTH_FAILED;
	}
	if (!challenge) {
		char host[HOST_NAME_MAX + 1];

		if (gethostname(host, sizeof(host)))
			snprintf(host, sizeof(host), "?");
		snprintf(cbuf, sizeof(cbuf),
		    "%s \%.32s@%.32s password: ",
		    getprogname(), myname, host);
		challenge = cbuf;
	}
	response = readpassphrase(challenge, rbuf, sizeof(rbuf),
	    RPP_REQUIRE_TTY);
	if (response == NULL && errno == ENOTTY) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "tty required for %s", myname);
		errx(1, "a tty is required");
	}
	if (!auth_userresponse(as, response, 0)) {
		explicit_bzero(rbuf, sizeof(rbuf));
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "failed auth for %s", myname);
		warnx("Authentication failed");
		return AUTH_FAILED;
	}
	explicit_bzero(rbuf, sizeof(rbuf));
	return AUTH_OK;
}

static void
authuser(char *myname, char *login_style, int persist)
{
	int i, fd = -1;

	if (persist)
		fd = open("/dev/tty", O_RDWR);
	if (fd != -1) {
		if (ioctl(fd, TIOCCHKVERAUTH) == 0)
			goto good;
	}
	for (i = 0; i < AUTH_RETRIES; i++) {
		if (authuser_checkpass(myname, login_style) == AUTH_OK)
			goto good;
	}
	exit(1);
good:
	if (fd != -1) {
		int secs = 5 * 60;
		ioctl(fd, TIOCSETVERAUTH, &secs);
		close(fd);
	}
}

int
main(int argc, char **argv)
{
	const char *p;
	char *const cmd[] = { NSH_REXEC_PATH_STR, "-e", NULL };
	char mypwbuf[_PW_BUF_LEN], targpwbuf[_PW_BUF_LEN];
	struct passwd mypwstore, targpwstore;
	struct passwd *mypw, *targpw;
	const struct rule *rule;
	uid_t uid;
	uid_t target = 0;
	gid_t groups[NGROUPS_MAX + 1];
	int ngroups;
	int ch, rv;
	int nflag = 0;
	char cwdpath[PATH_MAX];
	const char *cwd;
	const char *errstr;
	char *login_style = NULL;
	char **envp = NULL;
	int nshfd = -1, action = 0;

	setprogname("nshdoas");

	uid = getuid();

	while ((ch = getopt(argc, argv, "a:F:n:")) != -1) {
		switch (ch) {
		case 'a':
			login_style = optarg;
			break;
		case 'F':
			nshfd = strtonum(optarg, STDERR_FILENO + 1, INT_MAX,
			    &errstr);
			if (errstr)
				err(1, "nshfd is %s", errstr);
			printf("%s: nshfd is %d\n", getprogname(), nshfd);
			break;
		case 'n':
			nflag = 1;
			break;
		default:
			usage();
			break;
		}
	}
	argv += optind;
	argc -= optind;

	if (argc)
		usage();

	if (nshfd == -1)
		closefrom(STDERR_FILENO + 1);
	else
		closefrom(nshfd + 1);

	rv = getpwuid_r(uid, &mypwstore, mypwbuf, sizeof(mypwbuf), &mypw);
	if (rv != 0)
		err(1, "getpwuid_r failed");
	if (mypw == NULL)
		errx(1, "no passwd entry for self");
	ngroups = getgroups(NGROUPS_MAX, groups);
	if (ngroups == -1)
		err(1, "can't get groups");
	groups[ngroups++] = getgid();

	if (geteuid())
		errx(1, "not installed setuid");

	rv = getpwuid_r(target, &targpwstore, targpwbuf, sizeof(targpwbuf), &targpw);
	if (rv != 0)
		err(1, "getpwuid_r failed");
	if (targpw == NULL)
		errx(1, "no passwd entry for target");

	if (parseconfig("/etc/doas.conf") == 0) {
		action = permit(uid, groups, ngroups, &rule, target, cmd[0],
		    (const char **)cmd + 1);
	}
	if (action == 0) {
		printf("%% No rule for %s found in /etc/doas.conf; "
		    "root password required\n", mypw->pw_name);
		authuser(targpw->pw_name, login_style, 0);
		rule = NULL;
	} else {
		if (action != PERMIT) {
			syslog(LOG_AUTHPRIV | LOG_NOTICE,
			    "command not permitted for %s: %s",
			    mypw->pw_name, cmd[0]);
			errc(1, EPERM, NULL);
		}
		if (!(rule->options & NOPASS)) {
			if (nflag)
				errx(1, "Authentication required");

			authuser(mypw->pw_name, login_style,
			    rule->options & PERSIST);
		}
	}

	if ((p = getenv("PATH")) != NULL)
		formerpath = strdup(p);
	if (formerpath == NULL)
		formerpath = "";

	if (unveil(_PATH_LOGIN_CONF, "r") == -1)
		err(1, "unveil %s", _PATH_LOGIN_CONF);
	if (unveil(_PATH_LOGIN_CONF ".db", "r") == -1)
		err(1, "unveil %s.db", _PATH_LOGIN_CONF);
	if (unveil(_PATH_LOGIN_CONF_D, "r") == -1)
		err(1, "unveil %s", _PATH_LOGIN_CONF_D);
	if (unveil(NSH_REXEC_PATH_STR, "x") == -1)
		err(1, "unveil %s", NSH_REXEC_PATH_STR);

	if (pledge("stdio rpath getpw exec id", NULL) == -1)
		err(1, "pledge");

	if (setusercontext(NULL, targpw, target, LOGIN_SETGROUP |
	    LOGIN_SETPATH |
	    LOGIN_SETPRIORITY | LOGIN_SETRESOURCES | LOGIN_SETUMASK |
	    LOGIN_SETUSER | LOGIN_SETENV | LOGIN_SETRTABLE) != 0)
		errx(1, "failed to set user context for target");

	if (pledge("stdio rpath exec", NULL) == -1)
		err(1, "pledge");

	if (getcwd(cwdpath, sizeof(cwdpath)) == NULL)
		cwd = "(failed)";
	else
		cwd = cwdpath;

	if (pledge("stdio exec", NULL) == -1)
		err(1, "pledge");

	if (rule == NULL || !(rule->options & NOLOG)) {
		syslog(LOG_AUTHPRIV | LOG_INFO,
		    "%s ran command %s as %s from %s",
		    mypw->pw_name, cmd[0], targpw->pw_name, cwd);
	}

	if (rule)
		envp = prepenv(rule, mypw, targpw);

	/* setusercontext set path for the next process, so reset it for us */
	if (setenv("PATH", formerpath, 1) == -1)
		err(1, "failed to set PATH '%s'", formerpath);

	if (nshfd != -1) {
		/*
		 * Redirect stdin to the nsh process pipe.
		 * Commands will arrive here.
		 */
		fpurge(stdin);
		if (dup2(nshfd, STDIN_FILENO) == -1)
			err(1, "dup2");
	}

	execvpe(cmd[0], cmd, envp);
	if (errno == ENOENT)
		errx(1, "%s: command not found", cmd[0]);
	err(1, "%s", cmd[0]);
}
