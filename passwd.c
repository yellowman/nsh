/*
 * Copyright (c) 2004
 *      Christian Gut.  All rights reserved.
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

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <login_cap.h>
#include <bsd_auth.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "externs.h"
#include "settings.h"

int validate_cpass(char *, char *);

/* sanity checks for crypted password input */
int
validate_cpass(char *cipher, char *cpass)
{
	const char *errstr;
	char *rounds, *pw;

	if (!isprefix(cipher, "blowfish")) {
		printf("%% Invalid cipher: %s\n", cipher);
		return 0;
	}

	if (strlen(cpass) > _PASSWORD_LEN) {
		printf("%% Encrypted password is too long\n");
		return 0;
	}

	/* version number: 2b for blowfish */
	if (cpass[0] != '$' || cpass[1] != '2' || cpass[2] != 'b') {
		printf("%% Invalid crypted password version number\n");
		return 0;
	}

	/* Parse the number of rounds. */
	if (cpass[3] != '$') {
		printf("%% Number of blowfish rounds missing from crypted password\n");
		return 0;
	}
	rounds = &cpass[4];
	while (*rounds == '0') /* skip leading zeroes */
		rounds++;

	pw = strchr(rounds, '$');
	if (pw == NULL) {
		printf("%% Encrypted password string is missing\n");
		return 0;
	}

	/* Copy rounds into NUL-terminated buffer for strtonum() */
	rounds = strndup(rounds, pw - rounds);
	if (rounds == NULL) {
		printf("%% validate_cpass: strndup: %s\n", strerror(errno));
		return 0;
		
	}
	strtonum(rounds, 4, 31, &errstr);
	free(rounds);
	if (errstr) {
		printf("%% Number of blowfish rounds is %s\n", errstr);
		return 0;
	}

	pw++; /* skip over '$' separator */
	if (pw[0] == '\0') {
		printf("%% Encrypted password string is empty\n");
		return 0;
	}

	return 1;
}

/*
 * login class and login user: who may do what through nshd.
 *
 * A class is a set of permissions: view, operate, configure, admin and
 * exec. Three classes are built in and cannot be changed: read-only
 * (view), operator (view and operate) and super-user (all five).
 *
 * A user line gives an account its class. If the account does not
 * exist, the line must give a password, and nshd makes the account with
 * it, with nsh as its shell and nshadmin as a group, and records that it
 * made it. Taking that line away deletes the account, but not its home
 * directory. An account nshd did not make, as one an administrator made
 * by hand, gets its class and nothing else: its line may not give a
 * password, and taking the line away leaves the account alone. root is
 * always super-user, so no line names it, and no line names an account
 * whose name begins with '_', as those are daemons'.
 *
 * NSHLOGIN keeps the classes and users that run, one a line, as
 * "class NAME PERMISSION..." and "user NAME CLASS made|found". It
 * outlives a reboot, as the accounts do.
 */

static const struct {
	char *name;
	int perm;
} login_permtab[] = {
	{ "view",	LOGIN_VIEW },
	{ "operate",	LOGIN_OPERATE },
	{ "configure",	LOGIN_CONFIGURE },
	{ "admin",	LOGIN_ADMIN },
	{ "exec",	LOGIN_EXEC },
};

static const struct {
	char *name;
	int perms;
} login_builtin[] = {
	{ "read-only",	LOGIN_VIEW },
	{ "operator",	LOGIN_VIEW | LOGIN_OPERATE },
	{ "super-user",	LOGIN_ALL },
};

#define LOGIN_LINES	1024	/* NSHLOGIN's, at most */

static int
login_usage(void)
{
	printf("%% login class <name> [view] [operate] [configure] [admin] "
	    "[exec]\n");
	printf("%% login user <name> class <class> [password <hash>]\n");
	printf("%% no login class <name>\n");
	printf("%% no login user <name>\n");
	return -1;
}

/* Is name a class's or a user's, as nsh takes them? Said why, if not */
static int
login_name_ok(const char *what, const char *name)
{
	size_t i;

	if (name[0] == '\0' || strlen(name) > 31 || name[0] == '-' ||
	    name[0] == '_' || name[0] == '.') {
		printf("%% login %s %s: a name is 1 to 31 letters, digits, "
		    "'.', '-' or '_', and does not begin with '.', '-' or "
		    "'_'\n", what, name);
		return 0;
	}
	for (i = 0; name[i] != '\0'; i++)
		if (!isalnum((unsigned char)name[i]) && name[i] != '.' &&
		    name[i] != '-' && name[i] != '_') {
			printf("%% login %s %s: a name is 1 to 31 letters, "
			    "digits, '.', '-' or '_'\n", what, name);
			return 0;
		}
	return 1;
}

/* The permissions that words names, as a class's line gives them, or -1 */
static int
login_words_perms(int n, char **words)
{
	int i, perms = 0;
	size_t j;

	for (i = 0; i < n; i++) {
		for (j = 0; j < nitems(login_permtab); j++)
			if (isprefix(words[i], login_permtab[j].name))
				break;
		if (j == nitems(login_permtab)) {
			printf("%% login class: %s is not a permission\n",
			    words[i]);
			return -1;
		}
		perms |= login_permtab[j].perm;
	}
	return perms;
}

/* perms as words, each after a space, as conf() prints them */
static void
login_perms_words(int perms, char *buf, size_t len)
{
	size_t j;

	buf[0] = '\0';
	for (j = 0; j < nitems(login_permtab); j++)
		if (perms & login_permtab[j].perm) {
			strlcat(buf, " ", len);
			strlcat(buf, login_permtab[j].name, len);
		}
}

/* NSHLOGIN's lines, into lines[], each allocated: how many, or -1 */
static int
login_load(char **lines, int max)
{
	FILE *f;
	char buf[1024];
	int n = 0;

	if ((f = fopen(NSHLOGIN, "r")) == NULL) {
		if (errno == ENOENT)
			return 0;
		printf("%% %s: %s\n", NSHLOGIN, strerror(errno));
		return -1;
	}
	while (fgets(buf, sizeof(buf), f) != NULL) {
		buf[strcspn(buf, "\n")] = '\0';
		if (buf[0] == '\0')
			continue;
		if (n == max || (lines[n] = strdup(buf)) == NULL) {
			printf("%% %s: %s\n", NSHLOGIN, n == max ?
			    "too many lines" : strerror(errno));
			break;
		}
		n++;
	}
	if (ferror(f) || !feof(f)) {
		if (ferror(f))
			printf("%% %s: %s\n", NSHLOGIN, strerror(errno));
		fclose(f);
		while (n > 0)
			free(lines[--n]);
		return -1;
	}
	fclose(f);
	return n;
}

static void
login_unload(char **lines, int n)
{
	while (n > 0)
		free(lines[--n]);
}

/* The line of NSHLOGIN's lines that is kind's and name's, or -1 */
static int
login_index(char **lines, int n, const char *kind, const char *name)
{
	size_t k = strlen(kind), m = strlen(name);
	int i;

	for (i = 0; i < n; i++)
		if (strncmp(lines[i], kind, k) == 0 && lines[i][k] == ' ' &&
		    strncmp(lines[i] + k + 1, name, m) == 0 &&
		    (lines[i][k + 1 + m] == ' ' ||
		    lines[i][k + 1 + m] == '\0'))
			return i;
	return -1;
}

/*
 * NSHLOGIN with kind's line for name made rec, or taken away if rec is
 * NULL: written whole, and put in place, so a reader sees one or the
 * other. -1, said why, if it could not be
 */
static int
login_store(const char *kind, const char *name, const char *rec)
{
	char *lines[LOGIN_LINES], tmp[] = NSHLOGIN ".XXXXXXXXXX";
	FILE *f;
	int fd, i, n, r = -1;

	if ((n = login_load(lines, nitems(lines))) == -1)
		return -1;
	if ((i = login_index(lines, n, kind, name)) != -1) {
		free(lines[i]);
		lines[i] = lines[--n];
	}
	if (rec != NULL) {
		if (n == nitems(lines) || (lines[n] = strdup(rec)) == NULL) {
			printf("%% %s: %s\n", NSHLOGIN, n == nitems(lines) ?
			    "too many lines" : strerror(errno));
			goto done;
		}
		n++;
	}
	if ((fd = mkstemp(tmp)) == -1) {
		printf("%% %s: %s\n", tmp, strerror(errno));
		goto done;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		printf("%% %s: %s\n", tmp, strerror(errno));
		close(fd);
		unlink(tmp);
		goto done;
	}
	for (i = 0; i < n; i++)
		fprintf(f, "%s\n", lines[i]);
	if (fflush(f) == EOF || fsync(fd) == -1) {
		printf("%% %s: %s\n", tmp, strerror(errno));
		fclose(f);
		unlink(tmp);
		goto done;
	}
	fclose(f);
	if (rename(tmp, NSHLOGIN) == -1) {
		printf("%% %s: %s\n", NSHLOGIN, strerror(errno));
		unlink(tmp);
		goto done;
	}
	r = 0;
 done:
	login_unload(lines, n);
	return r;
}

/* A class's permissions, the built-in ones' or NSHLOGIN's, or -1 */
int
login_class_perms(const char *class)
{
	char *lines[LOGIN_LINES], *w[nitems(login_permtab) + 3];
	char *p, *q;
	size_t j;
	int i, n, nw, perms = -1;

	for (j = 0; j < nitems(login_builtin); j++)
		if (strcmp(class, login_builtin[j].name) == 0)
			return login_builtin[j].perms;
	if ((n = login_load(lines, nitems(lines))) == -1)
		return -1;
	if ((i = login_index(lines, n, "class", class)) != -1) {
		nw = 0;
		for (p = lines[i]; nw < (int)nitems(w) &&
		    (q = strsep(&p, " ")) != NULL; )
			w[nw++] = q;
		if (nw >= 2 && p == NULL)
			perms = login_words_perms(nw - 2, w + 2);
	}
	login_unload(lines, n);
	return perms;
}

/*
 * The class of the user name, and whether nshd made its account, as
 * NSHLOGIN has them: 1 if it has the user, 0 if not, -1 if it could not
 * be read
 */
static int
login_user_find(const char *name, char *class, size_t len, int *made)
{
	char *lines[LOGIN_LINES], c[64], how[8];
	int i, n, r = 0;

	if ((n = login_load(lines, nitems(lines))) == -1)
		return -1;
	if ((i = login_index(lines, n, "user", name)) != -1 &&
	    sscanf(lines[i], "user %*s %63s %7s", c, how) == 2) {
		strlcpy(class, c, len);
		*made = strcmp(how, "made") == 0;
		r = 1;
	}
	login_unload(lines, n);
	return r;
}

/* Is class a built-in one, or one the candidate has? Said, if not */
static int
login_cand_class(const char *class)
{
	char *l, word[64];
	size_t j, i;

	for (j = 0; j < nitems(login_builtin); j++)
		if (strcmp(class, login_builtin[j].name) == 0)
			return 1;
	for (i = 0; (l = cand_line("login", i)) != NULL; i++)
		if (sscanf(l, "login class %63s", word) == 1 &&
		    strcmp(word, class) == 0)
			return 1;
	printf("%% login user: no class %s\n", class);
	return 0;
}

/* login class NAME [PERMISSION...], or no login class NAME */
static int
login_class(int set, int argc, char **argv)
{
	char perms[64], rec[128];
	size_t j;
	int p;

	if (!login_name_ok("class", argv[2]))
		return -1;
	for (j = 0; j < nitems(login_builtin); j++)
		if (strcmp(argv[2], login_builtin[j].name) == 0) {
			printf("%% login class %s: a built-in class, which "
			    "cannot be changed\n", argv[2]);
			return -1;
		}
	if (!set) {
		if (candidate)
			return cand_setting(ST_OFF, "login class %s", argv[2]);
		return login_store("class", argv[2], NULL);
	}
	if ((p = login_words_perms(argc - 3, argv + 3)) == -1)
		return -1;
	login_perms_words(p, perms, sizeof(perms));
	if (candidate)
		return cand_setting(ST_ON, "login class %s%s", argv[2], perms);
	snprintf(rec, sizeof(rec), "class %s%s", argv[2], perms);
	return login_store("class", argv[2], rec);
}

/* useradd, usermod or userdel for name: 0 if it exited 0, else -1 */
static int
login_run(char *name, char *cmd, char **args)
{
	if (cmdargs(cmd, args) != 0) {
		printf("%% login user %s: %s failed\n", name, cmd);
		return -1;
	}
	return 0;
}

/* The account nshd makes for name, with hash: 0, or -1, said why */
static int
login_make(char *name, char *hash)
{
	char home[PATH_MAX], *args[12];
	struct stat st;
	int n = 0;

	snprintf(home, sizeof(home), "/home/%s", name);
	args[n++] = USERADD;
	/* useradd -m refuses a home kept from an account deleted before */
	if (lstat(home, &st) == -1)
		args[n++] = "-m";
	args[n++] = "-d";
	args[n++] = home;
	args[n++] = "-s";
	args[n++] = NSH_SHELL;
	args[n++] = "-G";
	args[n++] = NSH_GROUP;
	args[n++] = "-p";
	args[n++] = hash;
	args[n++] = name;
	args[n] = NULL;
	return login_run(name, USERADD, args);
}

/* login user NAME class CLASS [password HASH], or no login user NAME */
static int
login_user(int set, int argc, char **argv)
{
	char *name = argv[2], *hash = NULL, class[64], rec[256];
	char *mod[] = { USERMOD, "-p", NULL, name, NULL };
	char *del[] = { USERDEL, name, NULL };
	struct passwd *pw;
	int found, made = 0;

	if (strcmp(name, "root") == 0) {
		printf("%% login user root: root is always super-user\n");
		return -1;
	}
	if (!login_name_ok("user", name))
		return -1;
	if (!set) {
		if (candidate)
			return cand_setting(ST_OFF, "login user %s", name);
		if ((found = login_user_find(name, class, sizeof(class),
		    &made)) == -1)
			return -1;
		if (found && made && getpwnam(name) != NULL &&
		    login_run(name, USERDEL, del) == -1)
			return -1;
		return found ? login_store("user", name, NULL) : 0;
	}
	if ((argc != 5 && argc != 7) || !isprefix(argv[3], "class") ||
	    (argc == 7 && !isprefix(argv[5], "password")))
		return login_usage();
	if (!login_name_ok("class", argv[4]))
		return -1;
	if (argc == 7) {
		hash = argv[6];
		if (!validate_cpass("blowfish", hash))
			return -1;
	}
	if (candidate) {
		if (!login_cand_class(argv[4]))
			return -1;
		return cand_setting(ST_ON, "login user %s class %s%s%s", name,
		    argv[4], hash ? " password " : "", hash ? hash : "");
	}

	if ((found = login_user_find(name, class, sizeof(class), &made)) ==
	    -1)
		return -1;
	if ((pw = getpwnam(name)) == NULL) {
		if (hash == NULL) {
			printf("%% login user %s: no such account, and no "
			    "password to make it with\n", name);
			return -1;
		}
		if (login_make(name, hash) == -1)
			return -1;
		made = 1;
	} else if (found && made) {
		if (hash == NULL) {
			printf("%% login user %s: nshd made this account, so "
			    "its line gives its password\n", name);
			return -1;
		}
		mod[2] = hash;
		if (strcmp(pw->pw_passwd, hash) != 0 &&
		    login_run(name, USERMOD, mod) == -1)
			return -1;
	} else {
		if (hash != NULL) {
			printf("%% login user %s: nshd did not make this "
			    "account, so its line gives no password\n", name);
			return -1;
		}
		made = 0;
	}
	snprintf(rec, sizeof(rec), "user %s %s %s", name, argv[4],
	    made ? "made" : "found");
	return login_store("user", name, rec);
}

/* login class, login user, or their no */
int
loginset(int argc, char **argv, ...)
{
	char line[1024];
	int i, set = 1;

	if (NO_ARG(argv[0])) {
		argv++;
		argc--;
		set = 0;
	}
	if (argc < 3)
		return login_usage();
	/* in a commit's script, of a session without admin (ctl.c's) */
	if (!candidate) {
		line[0] = '\0';
		for (i = 0; i < (set ? argc : 3); i++) {
			if (i > 0)
				strlcat(line, " ", sizeof(line));
			strlcat(line, argv[i], sizeof(line));
		}
		if (!admin_may(line, !set, 3)) {
			printf("%% Commit refused: changing login classes and "
			    "users needs the admin permission\n");
			return -1;
		}
	}
	if (isprefix(argv[1], "class"))
		return login_class(set, argc, argv);
	if (isprefix(argv[1], "user"))
		return login_user(set, argc, argv);
	return login_usage();
}

static int
login_cmp(const void *a, const void *b)
{
	return strcmp(*(char * const *)a, *(char * const *)b);
}

/*
 * The login lines that run, sorted, so the classes come before the
 * users; a user whose account nshd made with its password, as the
 * account has it now
 */
void
conf_login(FILE *output)
{
	char *lines[LOGIN_LINES], name[64], class[64], how[8];
	struct passwd *pw;
	int i, n;

	if ((n = login_load(lines, nitems(lines))) <= 0)
		return;
	qsort(lines, n, sizeof(lines[0]), login_cmp);
	for (i = 0; i < n; i++) {
		if (strncmp(lines[i], "class ", 6) == 0)
			fprintf(output, "login %s\n", lines[i]);
		else if (sscanf(lines[i], "user %63s %63s %7s", name, class,
		    how) == 3) {
			fprintf(output, "login user %s class %s", name, class);
			if (strcmp(how, "made") == 0 &&
			    (pw = getpwnam(name)) != NULL)
				fprintf(output, " password %s", pw->pw_passwd);
			fprintf(output, "\n");
		}
	}
	login_unload(lines, n);
}

/*
 * The permissions of uid's login class: root's are all of them; a user
 * a line names has its class's; anyone else, and a user whose class is
 * gone, has view alone
 */
int
login_perms(uid_t uid)
{
	struct passwd *pw;
	char class[64];
	int made, perms;

	if (uid == 0)
		return LOGIN_ALL;
	if ((pw = getpwuid(uid)) == NULL ||
	    login_user_find(pw->pw_name, class, sizeof(class), &made) != 1 ||
	    (perms = login_class_perms(class)) == -1)
		return LOGIN_VIEW;
	return perms;
}

/*
 * The uid of name, a user a login user line names, but never root, if
 * password is its own, as auth_userokay(3) checks it; else -1, said
 */
int
login_auth(char *name, char *password)
{
	struct passwd *pw;
	char class[64];
	int made;

	if (strcmp(name, "root") == 0 ||
	    login_user_find(name, class, sizeof(class), &made) != 1 ||
	    (pw = getpwnam(name)) == NULL ||
	    !auth_userokay(name, NULL, NULL, password)) {
		printf("%% Login incorrect\n");
		return -1;
	}
	return pw->pw_uid;
}

/*
 * text, len bytes, with the password hash of each login user line made
 * "********", as conf() prints the line and a diff marks it: the hash is
 * the line's last word. The new length, as the text only gets shorter
 */
size_t
login_hide(char *text, size_t len)
{
	static const char pw[] = " password ";
	char *p = text, *end = text + len, *nl, *w, *h;
	size_t n;

	for (; p < end; p = nl + 1) {
		if ((nl = memchr(p, '\n', end - p)) == NULL)
			nl = end;
		w = p;
		if (w < nl && (*w == '+' || *w == '-' || *w == ' '))
			w++;
		if (nl - w > 3 && strncmp(w, "no ", 3) == 0)
			w += 3;
		if (nl - w <= 11 || strncmp(w, "login user ", 11) != 0 ||
		    (h = memmem(w, nl - w, pw, sizeof(pw) - 1)) == NULL)
			continue;
		h += sizeof(pw) - 1;
		if (nl - h <= 8)
			continue;
		memcpy(h, "********", 8);
		n = nl - (h + 8);
		memmove(h + 8, nl, end - nl);
		end -= n;
		nl -= n;
	}
	return end - text;
}
