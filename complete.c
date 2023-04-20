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

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/param.h>
#include <sys/tty.h>
#include <unistd.h>
#include "editing.h"
#include "stringlist.h"
#include "externs.h"

#define ttyout stdout
#define ttyin stdin

unsigned char complete(EditLine *, int, char **, size_t, char *);

static int	     comparstr(const void *, const void *);
static unsigned char complete_ambiguous(char *, int, StringList *, EditLine *);
static unsigned char complete_command(char *, int, EditLine *, char **, int);
static unsigned char complete_subcommand(char *, int, EditLine *, char **, int);
static unsigned char complete_local(char *, int, EditLine *);
static unsigned char complete_ifname(char *, int, EditLine *);
static unsigned char complete_ifgroup(char *, int, EditLine *);
static unsigned char complete_ifbridge(char *, int, EditLine *);
static unsigned char complete_rtable(char *, int, EditLine *);
static unsigned char complete_nocmd(struct ghs *, char *, int, EditLine *,
				   char **, int, int);
static unsigned char complete_noint(char *, int, EditLine *, char **, int, int);
static unsigned char complete_args(struct ghs *, char *, int, EditLine *,
				   char **, int, int);
static void list_vertical(StringList *);

unsigned char complt_c(EditLine *, int);
unsigned char complt_i(EditLine *, int);
unsigned char exit_i(EditLine *, int);

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
 */
static unsigned char
complete_ambiguous(char *word, int list, StringList *words, EditLine *el)
{
	char insertstr[MAXPATHLEN];
	char *lastmatch;
	int i, j;
	size_t matchlen, wordlen;

	wordlen = strlen(word);
	if (words->sl_cur == 0)
		return (CC_ERROR);	/* no choices available */

	if (words->sl_cur == 1) {	/* only one choice available */
		(void)strlcpy(insertstr, words->sl_str[0], sizeof insertstr);
		(void)strlcat(insertstr, " ", sizeof insertstr);
		if (el_insertstr(el, insertstr + wordlen) == -1)
			return (CC_ERROR);
		else
			return (CC_REFRESH);
	}

	if (!list) {
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
			if (el_insertstr(el, insertstr + wordlen) == -1)
				return (CC_ERROR);
			else	
					/*
					 * XXX: really want CC_REFRESH_BEEP
					 */
				return (CC_REFRESH);
		}
	}

	putc('\n', ttyout);
	qsort(words->sl_str, words->sl_cur, sizeof(char *), comparstr);
	list_vertical(words);
	return (CC_REDISPLAY);
}

/*
 * Complete a command
 */
static unsigned char
complete_command(char *word, int list, EditLine *el, char **table, int stlen)
{
	char **c;
	struct ghs *ghs;
	StringList *words;
	size_t wordlen;
	unsigned char rv;

	if (table == NULL)
		return(CC_ERROR);

	words = sl_init();
	wordlen = strlen(word);

	for (c = table; *c != NULL; c = (char **)((char *)c + stlen)) {
		ghs = (struct ghs *)c;
		if (wordlen > strlen(ghs->name))
			continue;
		if (strncmp(word, ghs->name, wordlen) == 0)
			sl_add(words, ghs->name);
	}

	rv = complete_ambiguous(word, list, words, el);
	sl_free(words, 0);
	return (rv);
}

/*
 * Complete a (sub)command
 */
static unsigned char
complete_subcommand(char *word, int list, EditLine *el, char **table, int stlen)
{
	struct ghs *ghs = NULL;

	if (table == NULL)
		return(CC_ERROR);

	ghs = (struct ghs *)genget(margv[cursor_argc-1], table, stlen);
	if (ghs == 0 || Ambiguous(ghs))
		return(CC_ERROR);

	/*
	 * XXX completion lists that hit subcommand tables don't get more than
	 * the first CMPL arg tested in complete_args as long as the level
	 * 0 is passed to complete_args
	 */
	return(complete_args(ghs, word, list, el, table, stlen, 0));
}

/*
 * Complete a local file
 */
static unsigned char
complete_local(char *word, int list, EditLine *el)
{
	StringList *words;
	char dir[MAXPATHLEN];
	char *file;
	DIR *dd;
	struct dirent *dp;
	unsigned char rv;

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

	rv = complete_ambiguous(file, list, words, el);
	sl_free(words, 1);
	return (rv);
}

static unsigned char
complete_showhelp(char *word, EditLine *el, char **table, int stlen,
    char *cmdname, int vertical)
{
	char insertstr[MAXPATHLEN];
	char **c;
	struct ghs *ghs;
	StringList *helplist;
	int i;
	size_t wordlen;

	helplist = sl_init();
	wordlen = strlen(word);
	for (c = table; *c != NULL; c = (char **)((char *)c + stlen)) {
		ghs = (struct ghs *)c;
		if (wordlen > strlen(ghs->name))
			continue;
		if (word[0] == '<' || word[0] == '[')
			continue;
		if (strncmp(word, ghs->name, wordlen) == 0)
			sl_add(helplist, ghs->name);
	}

	/*
	 * If we match a non-arbitrary parameter (which are not enclosed in
	 * brackets, "<...>" or "[...]") then we can complete this parameter.
	 */
	if (helplist->sl_cur == 1 && helplist->sl_str[0][0] != '<' &&
	    helplist->sl_str[0][0] != '[') {
		(void)strlcpy(insertstr, helplist->sl_str[0], sizeof insertstr);
		(void)strlcat(insertstr, " ", sizeof insertstr);
		if (el_insertstr(el, insertstr + wordlen) == -1)
			return (CC_ERROR);
		else
			return (CC_REFRESH);
	}

	if (helplist->sl_cur > 0)
		putc('\n', ttyout);
	if (vertical)
		list_vertical(helplist);
	else {
		for (i = 0 ; i < helplist->sl_cur ; i++)
			fprintf(ttyout, " %s %s\n", cmdname, helplist->sl_str[i]);
	}

        sl_free(helplist, 0);
	return (CC_REDISPLAY);
}

unsigned char
exit_i(EditLine *el, int ch)
{
	printf("\n");
	return CC_EOF;
}

unsigned char
complt_i(EditLine *el, int ch)
{
	return(complete(el, ch, (char **)whichlist, sizeof(struct intlist),
	    NULL));
}

unsigned char
complt_c(EditLine *el, int ch)
{
	return(complete(el, ch, (char **)cmdtab, sizeof(struct cmd), NULL));
}

unsigned char
complete_ifname(char *word, int list, EditLine *el)
{
	StringList *words;
	size_t wordlen;
	unsigned char rv;   
	const char *status_cmd = "status";
	struct if_nameindex *ifn_list, *ifnp;

	words = sl_init();
	wordlen = strlen(word);

	if ((ifn_list = if_nameindex()) == NULL)
		return 0;

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
                if (wordlen > strlen(ifnp->if_name))
                        continue;
                if (strncmp(word, ifnp->if_name, wordlen) == 0)
                        sl_add(words, ifnp->if_name);
        }

	/* Handle the pseudo command "show interface status". */
	if (margc >= 2 && isprefix(margv[0], "show") &&
	    isprefix(margv[1], "interface") &&
	    wordlen <= strlen(status_cmd) &&
	    strncmp(word, status_cmd, wordlen) == 0) {
		char *s = strdup(status_cmd);
		if (s == NULL)
			err(1, "strdup");
		sl_add(words, s);
	}

        rv = complete_ambiguous(word, list, words, el);
	if_freenameindex(ifn_list);
        sl_free(words, 0);
        return (rv);
}

unsigned char
complete_ifgroup(char *word, int list, EditLine *el)
{
	StringList *words;
	size_t wordlen;
	unsigned char rv;   
	struct ifgroupreq ifgr;
	struct ifg_req *ifg;
	int ifs;
	u_int len, ngroups, i;

	words = sl_init();
	wordlen = strlen(word);

	bzero(&ifgr, sizeof(ifgr));

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% complete_ifgroup: %s\n", strerror(errno));
		return(1);
	}

	if (ioctl(ifs, SIOCGIFGLIST, (caddr_t)&ifgr) == -1) {
		printf("%% SIOCGIFGLIST: %s\n", strerror(errno));
		close(ifs);
		return(1);
	}

	len = ifgr.ifgr_len;
	ifgr.ifgr_groups = calloc(1, len);
	if (ifgr.ifgr_groups == NULL) {
		printf("%% calloc: %s\n", strerror(errno));
		close(ifs);
		return(1);
	}

	if (ioctl(ifs, SIOCGIFGLIST, (caddr_t)&ifgr) == -1) {
		printf("%% SIOCGIFGLIST: %s\n", strerror(errno));
		free(ifgr.ifgr_groups);
		close(ifs);
		return(1);
	}

	ngroups = len / sizeof(ifgr.ifgr_groups[0]);
	for (i = 0; i < ngroups; i++) {
		ifg = &ifgr.ifgr_groups[i];
		if (wordlen > strlen(ifg->ifgrq_group))
			continue;
		if (strncmp(word, ifg->ifgrq_group, wordlen) == 0)
			sl_add(words, ifg->ifgrq_group);
	}

	rv = complete_ambiguous(word, list, words, el);
	sl_free(words, 0);
	free(ifgr.ifgr_groups);
	close(ifs);
	return (rv);
}

unsigned char
complete_ifbridge(char *word, int list, EditLine *el)
{
	StringList *words;
	size_t wordlen;
	unsigned char rv;   
	struct if_nameindex *ifn_list, *ifnp;
	int ifs;

	words = sl_init();
	wordlen = strlen(word);

	if ((ifn_list = if_nameindex()) == NULL)
		return 0;

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% complete_ifbridge: %s\n", strerror(errno));
		return(1);
	}

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		if (wordlen > strlen(ifnp->if_name))
			continue;
		if (!is_bridge(ifs, ifnp->if_name))
			continue;
		if (strncmp(word, ifnp->if_name, wordlen) == 0)
			sl_add(words, ifnp->if_name);
	}

	rv = complete_ambiguous(word, list, words, el);
	if_freenameindex(ifn_list);
	sl_free(words, 0);
	close(ifs);
	return (rv);
}

unsigned char
complete_rtable(char *word, int list, EditLine *el)
{
	StringList *words, *rtables;
	size_t wordlen = strlen(word);
	int i, rv = CC_ERROR;
	char *s = NULL;

	words = sl_init();
	rtables = sl_init();

	if (db_select_rtable_rtables(rtables) < 0) {
		printf("%% database failure select rtables rtable\n");
		goto done;
	}

	/*
	 * Routing table 0 always exists even if not created by nsh
	 * and is never present in the database.
	 */
	s = strdup("0");
	if (s == NULL) {
		printf("%% strdup: %s", strerror(errno));
		goto done;
	}
	sl_add(words, s);

	for (i = 0; i < rtables->sl_cur; i++) {
		char *rtable = rtables->sl_str[i];
		if (wordlen > strlen(rtable))
			continue;
		if (strncmp(word, rtable, wordlen) == 0)
			sl_add(words, rtable);
	}

	rv = complete_ambiguous(word, list, words, el);
done:
	sl_free(rtables, 1);
	sl_free(words, 0);
	free(s);
	return (rv);
}

/*
 * Generic complete routine
 */
unsigned char
complete(EditLine *el, int ch, char **table, size_t stlen, char *arg)
{
	static char word[256];
	static int lastc_argc, lastc_argo;
	struct ghs *c;
	const LineInfo *lf;
	int celems, dolist, level, i;
	size_t len;

	(void)ch;	/* not used */
	lf = el_line(el);
	len = lf->lastchar - lf->buffer;
	if (len >= sizeof(line))
		return (CC_ERROR);
	(void)memcpy(line, lf->buffer, len);
	line[len] = '\0';
	if (strlen(word) > len) /* user has erased part of previous line */
		word[len] = '\0';
	cursor_pos = line + (lf->cursor - lf->buffer);
	lastc_argc = cursor_argc;	/* remember last cursor pos */
	lastc_argo = cursor_argo;
	makeargv();			/* build argc/argv of current line */

	if (cursor_argo >= sizeof(word))
		return (CC_ERROR);

	if (margc == 0) {
		dolist = 1;
		return (complete_command(word, dolist, el, table, stlen));
	} else
		dolist = 0;

	/* if cursor and word is same, list alternatives */
	if (lastc_argc == cursor_argc && lastc_argo == cursor_argo
	    && strncmp(word, margv[cursor_argc], cursor_argo) == 0)
		dolist = 1;
	else if (cursor_argo)
		memcpy(word, margv[cursor_argc], cursor_argo);
	word[cursor_argo] = '\0';

	if (cursor_argc == 0)
		return (complete_command(word, dolist, el, table, stlen));

	if (arg == NULL)
		arg = margv[0];

	if (NO_ARG(margv[0]) && table == (char **)whichlist) {
		return(complete_noint(word, dolist, el, table, stlen,
		    cursor_argc - 1));
	}

	c = (struct ghs *) genget(arg, table, stlen);
	if (c == (struct ghs *)-1 || c == 0 || Ambiguous(c))
		return (CC_ERROR);

	if (strcmp(c->name, "no") == 0) /* Completing "no " command. */
		return(complete_nocmd(c, word, dolist, el, table, stlen, -1));

	celems = strlen(c->complete);

	/* check for 'continuation' completes (which are uppercase) */
	if ((cursor_argc > celems) && (celems > 0)
	    && isupper((unsigned char)c->complete[celems-1]))
		cursor_argc = celems;

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
	return(complete_args(c, word, dolist, el, table, stlen, level));
}

unsigned char
complete_nocmd(struct ghs *nocmd, char *word, int dolist, EditLine *el,
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
		memset(&nocmdtab[cmdtab_nitems - 1], 0, sizeof(*nocmdtab));
	}

	if (margc == 1) {
		/* Complete "no " using the list of known no-commands. */
		return (complete_command(word, dolist, el, (char **)nocmdtab,
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
		return (complete_args(ghs, word, dolist, el,
		    ghs->table, ghs->stlen, level));
	}

	/* Check for a partially completed valid command name. */
	for (i = 0; i < nocmdtab_nitems - 1; i++) {
		c = &nocmdtab[i];
		if (isprefix(margv[1], c->name) == 0)
			continue;

		/* Complete "no <partial command name>" */
		return (complete_command(word, dolist, el, (char **)nocmdtab,
		    sizeof(Command)));
	}

	return (CC_ERROR); /* invalid command in margv[1] */
}

unsigned char
complete_noint(char *word, int dolist, EditLine *el,
    char **whichlist, int stlen, int level)
{
	static struct intlist *nointtab, *nobridgetab;
	static size_t notab_nitems;
	struct intlist *table = (struct intlist *)whichlist;
	struct intlist *notab, *c, *nc;
	size_t table_nitems;
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
		return (complete_command(word, dolist, el, (char **)notab,
			stlen));
	}

	if (cursor_argc >= 2) {
		/* The no-command's name has been completed. */
		nc = NULL;
		for (i = 0; i < notab_nitems - 1; i++) {
			c = &notab[i];
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
		    dolist, el, nc->table, nc->stlen, 0));
	}

	/* Check for a partially completed valid command name. */
	for (i = 0; i < notab_nitems - 1; i++) {
		c = &notab[i];
		if (isprefix(margv[1], c->name) == 0)
			continue;

		/* Complete "no <partial command name>" */
		return (complete_command(word, dolist, el, (char **)notab,
		    stlen));
	}

	return (CC_ERROR); /* invalid command in margv[1] */
}

unsigned char
complete_args(struct ghs *c, char *word, int dolist, EditLine *el, char **table,
    int stlen, int level)
{
	int help_vertical = 0;

#ifdef CMPLDEBUG
	printf("[%s]",&c->complete[level]);
#endif
	switch (c->complete[level]) {
	case 'l':	/* local complete */
	case 'L':
		return (complete_local(word, dolist, el));
	case 'c':	/* command complete */
	case 'C':
		return (complete_command(word, dolist, el, table, stlen));
	case 'i':
	case 'I':
		return (complete_ifname(word, dolist, el));
	case 'g':
	case 'G':
		return (complete_ifgroup(word, dolist, el));
	case 'b':
	case 'B':
		return (complete_ifbridge(word, dolist, el));
	case 'r':
	case 'R':
		return (complete_rtable(word, dolist, el));
	case 't':	/* points to a table */
	case 'T':
		if (c->table == NULL)
			return(CC_ERROR);
		return (complete_command(word, dolist, el, c->table, c->stlen));
	case 'a':
	case 'A':
		if (c->table == NULL)
			return(CC_ERROR);
		return (complete_subcommand(word, dolist, el, c->table, c->stlen));
	case 'H':
		help_vertical = 1;
		/* fallthrough */
	case 'h':
		if (c->table == NULL)
			return(CC_ERROR);
		return (complete_showhelp(word, el, c->table, c->stlen, c->name,
		    help_vertical));
	case 'n':			/* no complete */
		return (CC_ERROR);
	}

	return (CC_ERROR);
}

/*
 * List words in stringlist, vertically arranged
 */
void
list_vertical(StringList *sl)
{
	int i, j, w;
	int columns, width, lines;
	char *p;

	width = 0;

	for (i = 0 ; i < sl->sl_cur ; i++) {
		w = strlen(sl->sl_str[i]);
		if (w > width)
			width = w;
	}
	width = (width + 8) &~ 7;

	columns = winsize.ws_col / width;
	if (columns == 0)
		columns = 1;
	lines = (sl->sl_cur + columns - 1) / columns;
	for (i = 0; i < lines; i++) {
		for (j = 0; j < columns; j++) {
			p = sl->sl_str[j * lines + i];
			if (p)
				fputs(p, ttyout);
			if (j * lines + i + lines >= sl->sl_cur) {
				putc('\n', ttyout);
				break;
			}
			if (p)
				w = strlen(p);
			else
				w = 0;
			while (w < width) {
				w = (w + 8) &~ 7;
				(void)putc('\t', ttyout);
			}
		}
	}
}

/*
 * this needs to be called before initedit()
 */
void
inithist()
{
	if (!histc) {
		histc = history_init();	/* init the builtin history */
		history(histc, &ev, H_SETSIZE, 100); /* remember 100 events */
	}
	if (!histi) {
		histi = history_init();
		history(histi, &ev, H_SETSIZE, 100);
	}
}

void
endhist()
{
	if (histc) {
		history_end(histc);	/* deallocate */
		histc = NULL;
	}
	if (histi) {
		history_end(histi);
		histi = NULL;
	}
}

void
initedit()
{
	editing = 1;

	if (!elc) {
		elc = el_init(__progname, stdin, stdout, stderr);
		if (histc)
			el_set(elc, EL_HIST, history, histc); /* use history */
		el_set(elc, EL_EDITOR, "emacs"); /* default type */
		el_set(elc, EL_PROMPT, cprompt); /* set the prompt
						  * function */
		el_set(elc, EL_ADDFN, "complt_c", "Command completion",
		    complt_c);
		el_set(elc, EL_BIND, "\t", "complt_c", NULL);
		el_source(elc, NULL);	/* read ~/.editrc */
		el_set(elc, EL_SIGNAL, 1);
	}
	if (!eli) {
		eli = el_init(__progname, stdin, stdout, stderr);
		if (histi)
			el_set(eli, EL_HIST, history, histi);
		el_set(eli, EL_EDITOR, "emacs");
		el_set(eli, EL_PROMPT, iprompt);
		el_set(eli, EL_ADDFN, "complt_i", "Command completion",
		    complt_i);
		el_set(eli, EL_BIND, "\t", "complt_i", NULL);
		el_set(eli, EL_ADDFN, "exit_i", "Exit", exit_i);
		el_set(eli, EL_BIND, "^X", "exit_i", NULL);
		el_set(eli, EL_BIND, "^D", "exit_i", NULL);
		el_source(eli, NULL);
		el_set(eli, EL_SIGNAL, 1);
	}
}

void
endedit()
{
	editing = 0;

	if (elc) {
		el_end(elc);
		elc = NULL;
	}
	if (eli) {
		el_end(eli);
		eli = NULL;
	}
}
