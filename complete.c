/* From: $OpenBSD: /usr/src/usr.bin/ftp/complete.c,v 1.19 2006/06/23 20:35:25 steven Exp $ */
/*-
 * Copyright (c) 1997 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Luke Mewburn.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/tty.h>
#include <unistd.h>
#include "editing.h"
#include "stringlist.h"
#include "externs.h"
#include "commands.h"
#include "kfacts.h"

int cmplt_remote;	/* for a client: list no local files or environment */

static int	     comparstr(const void *, const void *);
static unsigned char complete_ambiguous(char *, int, StringList *,
				struct cmplt *, char *);
static unsigned char complete_command(char *, int, struct cmplt *, char **,
				int);
static unsigned char complete_subcommand(char *, int, struct cmplt *, char **,
				int);
static unsigned char complete_local(char *, int, struct cmplt *);
static unsigned char complete_ifname(char *, int, struct cmplt *);
static unsigned char complete_ifgroup(char *, int, struct cmplt *);
static unsigned char complete_ifbridge(char *, int, struct cmplt *);
static unsigned char complete_rtable(char *, int, struct cmplt *);
static unsigned char complete_names(char *, int, struct cmplt *, int, char *);
static unsigned char complete_environment(char *, int, struct cmplt *, int);
static unsigned char complete_nocmd(struct ghs *, char *, int, struct cmplt *,
				   char **, int, int);
static unsigned char complete_docmd(struct ghs *, char *, int, struct cmplt *,
				   char **, int, int);
static unsigned char complete_doint(char *, int, struct cmplt *, char **, int,
				int);
static unsigned char complete_noint(char *, int, struct cmplt *, char **, int,
				int);
static unsigned char complete_args(struct ghs *, char *, int, struct cmplt *,
				   char **, int, int);
static void cmplt_list(struct cmplt *, StringList *, StringList *);

static int
comparstr(const void *a, const void *b)
{
	return (strcmp(*(char **)a, *(char **)b));
}

/*
 * Determine if complete is ambiguous. If unique, insert.
 * If no choices, error. If unambiguous prefix, insert that.
 * Otherwise, list choices. words is assumed to be filtered
 * to only contain possible choices.
 * Args:
 *	word	word which started the match
 *	list	list by default
 *	words	stringlist containing possible matches
 *	sep	separator to insert after completed word; usually " "
 */
static unsigned char
complete_ambiguous(char *word, int list, StringList *words, struct cmplt *cp,
    char *sep)
{
	char insertstr[MAXPATHLEN];
	char *lastmatch;
	int i, j;
	size_t matchlen, wordlen;

	wordlen = strlen(word);
	if (words->sl_cur == 0)
		return (CC_ERROR);	/* no choices available */

	if (words->sl_cur == 1 && !cp->help) {	/* only one choice */
		(void)strlcpy(insertstr, words->sl_str[0], sizeof insertstr);
		(void)strlcat(insertstr, sep, sizeof insertstr);
		(void)strlcpy(cp->insert, insertstr + wordlen,
		    sizeof(cp->insert));
		return (CC_REFRESH);
	}

	if (!list && !cp->help) {
		matchlen = 0;
		if ((lastmatch = words->sl_str[0]))
			matchlen = strlen(lastmatch);
		for (i = 1 ; i < words->sl_cur ; i++) {
			for (j = wordlen ; j < strlen(words->sl_str[i]); j++)
				if (lastmatch[j] != words->sl_str[i][j])
					break;
			if (j < matchlen)
				matchlen = j;
		}
		if (matchlen > wordlen) {
			(void)strlcpy(insertstr, lastmatch, matchlen+1);
			(void)strlcpy(cp->insert, insertstr + wordlen,
			    sizeof(cp->insert));
			/*
			 * XXX: really want CC_REFRESH_BEEP
			 */
			return (CC_REFRESH);
		}
	}

	qsort(words->sl_str, words->sl_cur, sizeof(char *), comparstr);
	cmplt_list(cp, words, NULL);
	return (CC_REDISPLAY);
}

/*
 * Complete a command
 */
static unsigned char
complete_command(char *word, int list, struct cmplt *cp, char **table,
    int stlen)
{
	char **c;
	struct ghs *ghs;
	StringList *words, *helps;
	size_t wordlen;
	unsigned char rv;

	if (table == NULL)
		return CC_ERROR;

	words = sl_init();
	helps = sl_init();
	wordlen = strlen(word);

	for (c = table; *c != NULL; c = (char **)((char *)c + stlen)) {
		ghs = (struct ghs *)c;
		if (wordlen > strlen(ghs->name))
			continue;
		if (strncmp(word, ghs->name, wordlen) == 0) {
			sl_add(words, ghs->name);
			sl_add(helps, ghs->help);
		}
	}

	/* with help, list every match in the table's order, with its help */
	if (cp->help && words->sl_cur > 0) {
		cmplt_list(cp, words, helps);
		rv = CC_REDISPLAY;
	} else
		rv = complete_ambiguous(word, list, words, cp, " ");
	sl_free(words, 0);
	sl_free(helps, 0);
	return (rv);
}

/*
 * Complete a (sub)command
 */
static unsigned char
complete_subcommand(char *word, int list, struct cmplt *cp, char **table,
    int stlen)
{
	struct ghs *ghs = NULL;

	if (table == NULL)
		return CC_ERROR;

	ghs = (struct ghs *)genget(margv[cursor_argc-1], table, stlen);
	if (ghs == 0 || Ambiguous(ghs))
		return CC_ERROR;

	/*
	 * XXX completion lists that hit subcommand tables don't get more than
	 * the first CMPL arg tested in complete_args as long as the level
	 * 0 is passed to complete_args
	 */
	return complete_args(ghs, word, list, cp, table, stlen, 0);
}

/*
 * Complete a local file
 */
static unsigned char
complete_local(char *word, int list, struct cmplt *cp)
{
	StringList *words;
	char dir[MAXPATHLEN];
	char *file;
	DIR *dd;
	struct dirent *dp;
	unsigned char rv;

	if (cmplt_remote)
		return (CC_ERROR);
	if ((file = strrchr(word, '/')) == NULL) {
		dir[0] = '.';
		dir[1] = '\0';
		file = word;
	} else {
		if (file == word) {
			dir[0] = '/';
			dir[1] = '\0';
		} else {
			(void)strlcpy(dir, word, (size_t)(file - word) + 1);
		}
		file++;
	}

	if ((dd = opendir(dir)) == NULL)
		return (CC_ERROR);

	words = sl_init();

	for (dp = readdir(dd); dp != NULL; dp = readdir(dd)) {
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		if (strlen(file) > dp->d_namlen)
			continue;
		if (strncmp(file, dp->d_name, strlen(file)) == 0) {
			char *tcp;

			tcp = strdup(dp->d_name);
			if (tcp == NULL)
				errx(1, "Can't allocate memory for local dir");
			sl_add(words, tcp);
		}
	}
	closedir(dd);

	rv = complete_ambiguous(file, list, words, cp, " ");
	sl_free(words, 1);
	return (rv);
}

static unsigned char
complete_showhelp(char *word, struct cmplt *cp, char **table, int stlen,
    char *cmdname, int vertical)
{
	char insertstr[MAXPATHLEN];
	char **c;
	struct ghs *ghs;
	StringList *cmdlist;
	StringList *helplist;
	size_t wordlen;

	cmdlist = sl_init();
	helplist = sl_init();
	wordlen = strlen(word);
	for (c = table; *c != NULL; c = (char **)((char *)c + stlen)) {
		ghs = (struct ghs *)c;
		if (wordlen > strlen(ghs->name))
			continue;
		if (word[0] == '<' || word[0] == '[')
			continue;
		if (strncmp(word, ghs->name, wordlen) == 0) {
			sl_add(cmdlist, ghs->name);
			sl_add(helplist, ghs->help);
		}
	}

	/*
	 * If we match a non-arbitrary parameter (which are not enclosed in
	 * brackets, "<...>" or "[...]") then we can complete this parameter.
	 */
	if (cmdlist->sl_cur == 1 && cmdlist->sl_str[0][0] != '<' &&
	    cmdlist->sl_str[0][0] != '[' && cmdlist->sl_str[0][0] != '^' &&
	    !cp->help) {
		(void)strlcpy(insertstr, cmdlist->sl_str[0], sizeof insertstr);
		(void)strlcat(insertstr, " ", sizeof insertstr);
		(void)strlcpy(cp->insert, insertstr + wordlen,
		    sizeof(cp->insert));
		sl_free(cmdlist, 0);
		sl_free(helplist, 0);
		return (CC_REFRESH);
	}

	cmplt_list(cp, cmdlist, helplist);
	cp->cmdname = cmdname;
	cp->vertical = vertical;
        sl_free(cmdlist, 0);
        sl_free(helplist, 0);
	return (CC_REDISPLAY);
}

/*
 * Complete word from the names of one kind (KF_* in kfacts.h). extra,
 * if not NULL, is one more name to offer.
 */
static unsigned char
complete_names(char *word, int list, struct cmplt *cp, int kind,
    char *extra)
{
	StringList *names, *words;
	size_t wordlen = strlen(word);
	unsigned char rv;
	int i;

	names = sl_init();
	if (kf_names(kind, names) == -1) {
		sl_free(names, 1);
		return (CC_ERROR);
	}
	words = sl_init();
	if (extra != NULL && strncmp(word, extra, wordlen) == 0)
		sl_add(words, extra);
	for (i = 0; i < names->sl_cur; i++)
		if (strncmp(word, names->sl_str[i], wordlen) == 0)
			sl_add(words, names->sl_str[i]);
	rv = complete_ambiguous(word, list, words, cp, " ");
	sl_free(words, 0);
	sl_free(names, 1);
	return (rv);
}

static unsigned char
complete_ifname(char *word, int list, struct cmplt *cp)
{
	/* "show interface" also takes "status" */
	return (complete_names(word, list, cp, KF_IFS, margc >= 2 &&
	    isprefix(margv[0], "show") && isprefix(margv[1], "interface") ?
	    "status" : NULL));
}

static unsigned char
complete_ifgroup(char *word, int list, struct cmplt *cp)
{
	return (complete_names(word, list, cp, KF_GROUPS, NULL));
}

static unsigned char
complete_ifbridge(char *word, int list, struct cmplt *cp)
{
	return (complete_names(word, list, cp, KF_BRIDGES, NULL));
}

static unsigned char
complete_rtable(char *word, int list, struct cmplt *cp)
{
	/*
	 * Routing table 0 always exists even if not created by nsh
	 * and is never present in the database.
	 */
	return (complete_names(word, list, cp, KF_RTABLES, "0"));
}

static unsigned char
complete_environment(char *word, int dolist, struct cmplt *cp, int set)
{
	StringList *words;
	extern char **environ;
	char **ep, *eq, *name;
	size_t wordlen = strlen(word);
	int rv = CC_ERROR;

	if (cmplt_remote)
		return (CC_ERROR);
	words = sl_init();

	for (ep = environ; *ep; ep++) {
		eq = strchr(*ep, '=');
		if (eq == NULL)
			continue;
		name = strndup(*ep, eq - *ep);
		if (name == NULL) {
			sl_free(words, 1);
			return CC_ERROR;
		}
		if (strncmp(word, name, wordlen) == 0)
			sl_add(words, name);
		else
			free(name);
	}

	/*
	 * When a new environment variable is created then hitting the
	 * TAB key makes '=' appear.
	 */
	if (set && words->sl_cur == 0 && wordlen > 0 &&
	    word[wordlen - 1] != '=' && strchr(word, '=') == NULL) {
		name = strdup(word);
		if (name == NULL) {
			sl_free(words, 1);
			return CC_ERROR;
		}
		sl_add(words, name);
	}

	rv = complete_ambiguous(word, dolist, words, cp, set ? "=" : " ");
	sl_free(words, 1);
	return rv;
}

/*
 * Complete the word at the cursor, byte cursor of the len bytes of buf,
 * as table's commands take it. Into cp: text to insert at the cursor,
 * with CC_REFRESH, or the choices, with CC_REDISPLAY; or CC_ERROR.
 * word is the caller's, CMPLT_WORD bytes, the word it completed last:
 * completing the same one again lists the choices. With help, it
 * inserts nothing and lists every choice, each with its help.
 */
unsigned char
complete_line(const char *buf, size_t len, size_t cursor, char *word,
    char **table, size_t stlen, int help, struct cmplt *cp)
{
	struct ghs *c;
	int celems, dolist, level, i;

	memset(cp, 0, sizeof(*cp));
	cp->words = sl_init();
	cp->help = help;
	if (len >= sizeof(line) || cursor > len)
		return (CC_ERROR);
	(void)memcpy(line, buf, len);
	line[len] = '\0';
	if (strlen(word) > len) /* user has erased part of previous line */
		word[len] = '\0';
	cursor_pos = line + cursor;
	/* build argc/argv of current line */
	if (makeargv() == -1)
		return (CC_ERROR);

	if (cursor_argo >= CMPLT_WORD)
		return (CC_ERROR);

	if (margc == 0) {
		dolist = 1;
		return (complete_command(word, dolist, cp, table, stlen));
	} else
		dolist = 0;

	/* if cursor and word is same, list alternatives */
	if (cursor_argo == 0 ||
	    strncmp(word, margv[cursor_argc], cursor_argo) == 0)
		dolist = 1;
	else if (cursor_argo)
		memcpy(word, margv[cursor_argc], cursor_argo);
	word[cursor_argo] = '\0';

	if (cursor_argc == 0)
		return (complete_command(word, dolist, cp, table, stlen));

	if (NO_ARG(margv[0]) && table == (char **)whichlist) {
		return complete_noint(word, dolist, cp, table, stlen,
		    cursor_argc - 1);
	}

	c = (struct ghs *) genget(margv[0], table, stlen);
	if (c == (struct ghs *)-1 || c == 0 || Ambiguous(c))
		return (CC_ERROR);

	if (strcmp(c->name, "do") == 0) { /* Completing "do " command. */
		if (table == (char **)whichlist)
			return (complete_doint(word, dolist, cp, table, stlen,
			    cursor_argc - 1));
		else
			return (complete_docmd(c, word, dolist, cp,
			    (char **)cmdtab, stlen, -1));
	}

	if (strcmp(c->name, "no") == 0) /* Completing "no " command. */
		return complete_nocmd(c, word, dolist, cp, table, stlen, -1);

	celems = strlen(c->complete);

	if (cursor_argc > celems)
		return (CC_ERROR);

	level = cursor_argc - 1;
	i = 1;
	/*
	 * Switch to a nested command table if needed.
	 */
	while (c->table && i < cursor_argc - 1) {
		c = (struct ghs *)c->table;
		table = c->table;
		stlen = c->stlen;
		level = 0; /* table has been switched */
		i++;
	}
	return complete_args(c, word, dolist, cp, table, stlen, level);
}

unsigned char
complete_nocmd(struct ghs *nocmd, char *word, int dolist, struct cmplt *cp,
    char **table, int stlen, int level)
{
	static Command *nocmdtab;
	static size_t nocmdtab_nitems;
	Command *c, *nc;
	int i, j;

	/* One-shot initialization since this is a static variable. */
	if (nocmdtab == NULL) {
		for (i = 0; i < cmdtab_nitems; i++) {
			c = &cmdtab[i];
			if (c->nocmd || c->name == NULL /* sentinel */)
				nocmdtab_nitems++;
		}
		if (nocmdtab_nitems == 0)
			return (CC_ERROR);
		nocmdtab = calloc(nocmdtab_nitems, sizeof(*nocmdtab));
		if (nocmdtab == NULL)
			return (CC_ERROR);
		/*
		 * Copy commands which may be prefixed with "no".
		 * Memory allocated for the nocmdtab array will be
		 * freed when the nsh program exits.
		 */
		j = 0;
		for (i = 0; i < cmdtab_nitems; i++) {
			c = &cmdtab[i];
			if (!c->nocmd)
				continue;
			if (j >= nocmdtab_nitems)
				break;
			nc = &nocmdtab[j++];
			memcpy(nc, c, sizeof(*nc));
		}

		/* sentinel */
		memset(&nocmdtab[nocmdtab_nitems - 1], 0, sizeof(*nocmdtab));
	}

	if (cursor_argc < 2) {
		/* Complete "no " and its command's word, as it stands */
		return (complete_command(word, dolist, cp, (char **)nocmdtab,
		    sizeof(Command)));
	}

	/* Determine whether the no-command's name has been completed. */
	nc = NULL;
	for (i = 0; i < nocmdtab_nitems - 1; i++) {
		c = &nocmdtab[i];
		if (strcmp(c->name, margv[1]) == 0) {
			nc = c;
			break;
		}
	}
	if (nc) {
		struct ghs *ghs = (struct ghs *)nc;

		level = cursor_argc - 2; /* "no" + command name */
		i = 1;
		/*
		 * Switch to a nested command table if needed.
		 */
		while (ghs->table && i < cursor_argc - 2) {
			ghs = (struct ghs *)ghs->table;
			level = 0; /* table has been switched */
			i++;
		}
		/* Complete "no <command name> [more arguments]" */
		return (complete_args(ghs, word, dolist, cp,
		    ghs->table, ghs->stlen, level));
	}

	/* Check for a partially completed valid command name. */
	for (i = 0; i < nocmdtab_nitems - 1; i++) {
		c = &nocmdtab[i];
		if (isprefix(margv[1], c->name) == 0)
			continue;

		/* Complete "no <partial command name>" */
		return (complete_command(word, dolist, cp, (char **)nocmdtab,
		    sizeof(Command)));
	}

	return (CC_ERROR); /* invalid command in margv[1] */
}

unsigned char
complete_docmd(struct ghs *docmd, char *word, int dolist, struct cmplt *cp,
    char **table, int stlen, int level)
{
	Command *c, *dc;
	int i;

	if (cursor_argc < 2) {
		/* Complete "do " and its command's word, as it stands */
		return (complete_command(word, dolist, cp, (char **)cmdtab,
		    sizeof(Command)));
	}

	/* Determine whether the no-command's name has been completed. */
	dc = NULL;
	for (i = 0; i < cmdtab_nitems - 1; i++) {
		c = &cmdtab[i];
		if (strcmp(c->name, margv[1]) == 0) {
			dc = c;
			break;
		}
	}
	if (dc) {
		struct ghs *ghs = (struct ghs *)dc;

		level = cursor_argc - 2; /* "do" + command name */
		i = 1;
		/*
		 * Switch to a nested command table if needed.
		 */
		while (ghs->table && cursor_argc >= 2 && i < cursor_argc - 2) {
			ghs = (struct ghs *)ghs->table;
			level = 0; /* table has been switched */
			i++;
		}
		/* Complete "no <command name> [more arguments]" */
		return (complete_args(ghs, word, dolist, cp,
		    ghs->table, ghs->stlen, level));
	}

	/* Check for a partially completed valid command name. */
	for (i = 0; i < cmdtab_nitems - 1; i++) {
		c = &cmdtab[i];
		if (isprefix(margv[1], c->name) == 0)
			continue;

		/* Complete "do <partial command name>" */
		return (complete_command(word, dolist, cp, (char **)cmdtab,
		    sizeof(Command)));
	}

	return (CC_ERROR); /* invalid command in margv[1] */
}

/* complete a "do ..." command in interface context */
unsigned char
complete_doint(char *word, int dolist, struct cmplt *cp,
    char **whichlist, int stlen, int level)
{
	struct intlist *table = (struct intlist *)whichlist;
	struct intlist *c, *dc;

	if (cursor_argc < 2) {
		/* Complete "do " and its command's word, as it stands */
		return (complete_command(word, dolist, cp, (char **)table,
		    stlen));
	}

	/* Determine whether the no-command's name has been completed. */
	dc = NULL;
	for (c = table; c->name; c++) {
		if (strcmp(c->name, margv[1]) == 0) {
			dc = c;
			break;
		}
	}
	if (dc) {
		struct ghs *ghs = (struct ghs *)dc;

		level = cursor_argc - 2; /* "do" + command name */

		/* Complete "no <command name> [more arguments]" */
		return (complete_args(ghs, word, dolist, cp,
		    ghs->table, ghs->stlen, level));
	}

	/* Check for a partially completed valid command name. */
	for (c = table; c->name; c++) {
		if (isprefix(margv[1], c->name) == 0)
			continue;

		/* Complete "do <partial command name>" */
		return (complete_command(word, dolist, cp,
		    (char **)table, stlen));
	}

	return (CC_ERROR); /* invalid command in margv[1] */
}

unsigned char
complete_noint(char *word, int dolist, struct cmplt *cp,
    char **whichlist, int stlen, int level)
{
	static struct intlist *nointtab, *nobridgetab;
	struct intlist *table = (struct intlist *)whichlist;
	struct intlist *notab, *c, *nc;
	size_t table_nitems, notab_nitems = 0;
	int i, j;

	if (stlen != sizeof(*table))
		return (CC_ERROR);

	/* One-shot initialization since these are static variables. */
	if ((bridge && nobridgetab == NULL) || (!bridge && nointtab == NULL)) {
		if (bridge)
			table_nitems = Bridgelist_nitems;
		else
			table_nitems = Intlist_nitems;
		for (i = 0; i < table_nitems; i++) {
			c = &table[i];
			if (c->nocmd || c->name == NULL /* sentinel */)
				notab_nitems++;
		}
		notab = calloc(notab_nitems, sizeof(*notab));
		if (notab == NULL)
			return (CC_ERROR);
		/*
		 * Copy commands which may be prefixed with "no".
		 * Memory allocated for the notab array will be
		 * freed when the nsh program exits.
		 */
		j = 0;
		for (i = 0; i < table_nitems; i++) {
			c = &table[i];
			if (!c->nocmd)
				continue;
			if (j >= notab_nitems)
				break;
			nc = &notab[j++];
			memcpy(nc, c, sizeof(*nc));
		}

		/* sentinel */
		memset(&notab[notab_nitems - 1], 0, sizeof(*notab));

		if (bridge)
			nobridgetab = notab;
		else
			nointtab = notab;
	} else {
		if (bridge)
			notab = nobridgetab;
		else
			notab = nointtab;
	}

	if (margc == 1) {
		/* Complete "no " using the list of known no-commands. */
		return (complete_command(word, dolist, cp, (char **)notab,
			stlen));
	}

	if (cursor_argc >= 2) {
		/* The no-command's name has been completed. */
		nc = NULL;
		for (c = notab; c->name != NULL; c++) {
			if (strcmp(margv[1], c->name) == 0) {
				nc = c;
				break;
			}
		}
		if (nc == NULL) /* should not happen */
			return (CC_ERROR);

		/* Complete "no <command name> [more arguments]" */
		return (complete_args((struct ghs *)nc,
		    margv[cursor_argc] ? margv[cursor_argc] : "",
		    dolist, cp, nc->table, nc->stlen, 0));
	}

	/* Check for a partially completed valid command name. */
	for (c = notab; c->name != NULL; c++) {
		if (isprefix(margv[1], c->name) == 0)
			continue;

		/* Complete "no <partial command name>" */
		return (complete_command(word, dolist, cp, (char **)notab,
		    stlen));
	}

	return (CC_ERROR); /* invalid command in margv[1] */
}

unsigned char
complete_args(struct ghs *c, char *word, int dolist, struct cmplt *cp,
    char **table, int stlen, int level)
{
	int help_vertical = 0;

	/* a word before or past what the command completes completes nothing */
	if ((size_t)level >= strlen(c->complete))
		return (CC_ERROR);

#ifdef CMPLDEBUG
	printf("[%s]",&c->complete[level]);
#endif
	switch (c->complete[level]) {
	case 'l':	/* local complete */
		return (complete_local(word, dolist, cp));
	case 'c':	/* command complete */
		return (complete_command(word, dolist, cp, table, stlen));
	case 'i':
		return (complete_ifname(word, dolist, cp));
	case 'g':
		return (complete_ifgroup(word, dolist, cp));
	case 'b':
		return (complete_ifbridge(word, dolist, cp));
	case 'r':
		return (complete_rtable(word, dolist, cp));
	case 't':	/* points to a table */
		if (c->table == NULL)
			return CC_ERROR;
		return (complete_command(word, dolist, cp, c->table, c->stlen));
	case 'a':
		if (c->table == NULL)
			return CC_ERROR;
		return (complete_subcommand(word, dolist, cp, c->table,
		    c->stlen));
	case 'H':
		help_vertical = 1;
		/* fallthrough */
	case 'h':
		if (c->table == NULL)
			return CC_ERROR;
		return (complete_showhelp(word, cp, c->table, c->stlen, c->name,
		    help_vertical));
	case 'E':
		return complete_environment(word, dolist, cp, 1);
	case 'e':
		return complete_environment(word, dolist, cp, 0);
	case 'n':			/* no complete */
		return (CC_ERROR);
	}

	return (CC_ERROR);
}

/* words, and if helps is not NULL each one's help, as cp's choices */
static void
cmplt_list(struct cmplt *cp, StringList *words, StringList *helps)
{
	char *s;
	int i;

	if (helps != NULL)
		cp->helps = sl_init();
	for (i = 0; i < words->sl_cur; i++) {
		if ((s = strdup(words->sl_str[i])) == NULL)
			err(1, "strdup");
		sl_add(cp->words, s);
		if (helps == NULL)
			continue;
		if ((s = strdup(helps->sl_str[i] ? helps->sl_str[i] : "")) ==
		    NULL)
			err(1, "strdup");
		sl_add(cp->helps, s);
	}
}

void
cmplt_free(struct cmplt *cp)
{
	sl_free(cp->words, 1);
	if (cp->helps != NULL)
		sl_free(cp->helps, 1);
}
