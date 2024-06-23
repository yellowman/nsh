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

#include <bsd/bsd.h>
#include <ctype.h>
#include <err.h>
#include <dirent.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/param.h>
#include "editing.h"
#include "externs.h"
#include "stringlist.h"

#define ttyout stdout
#define ttyin stdin

unsigned char complete(EditLine *, int, char **, size_t, char *);

static int	     comparstr(const void *, const void *);
static unsigned char complete_ambiguous(char *, int, StringList *, EditLine *);
static unsigned char complete_command(char *, int, EditLine *, char **, int);
static unsigned char complete_subcommand(char *, int, EditLine *, char **, int);
static unsigned char complete_local(char *, int, EditLine *);
static unsigned char complete_ifname(char *, int, EditLine *);
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

	if (words->sl_cur == 1) {	/* only once choice available */
		(void)strlcpy(insertstr, words->sl_str[0], sizeof insertstr);
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
		if (strlen(file) > strlen(dp->d_name))
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

	words = sl_init();
	wordlen = strlen(word);

	struct if_nameindex *ifn_list, *ifnp;

	if ((ifn_list = if_nameindex()) == NULL)
		return 0;

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
                if (wordlen > strlen(ifnp->if_name))
                        continue;
                if (strncmp(word, ifnp->if_name, wordlen) == 0)
                        sl_add(words, ifnp->if_name);
        }

        rv = complete_ambiguous(word, list, words, el);
	if_freenameindex(ifn_list);
        sl_free(words, 0);
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
	int celems, dolist;
	size_t len;

	(void)ch;	/* not used */
	lf = el_line(el);
	len = lf->lastchar - lf->buffer;
	if (len >= sizeof(line))
		return (CC_ERROR);
	(void)memcpy(line, lf->buffer, len);
	line[len] = '\0';
	cursor_pos = line + (lf->cursor - lf->buffer);
	lastc_argc = cursor_argc;	/* remember last cursor pos */
	lastc_argo = cursor_argo;
	makeargv();			/* build argc/argv of current line */

	if (margc == 0 || cursor_argo >= sizeof(word))
		return (CC_ERROR);

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
	c = (struct ghs *) genget(arg, table, stlen);
	if (c == (struct ghs *)-1 || c == 0 || Ambiguous(c))
		return (CC_ERROR);
	celems = strlen(c->complete);

	/* check for 'continuation' completes (which are uppercase) */
	if ((cursor_argc > celems) && (celems > 0)
	    && isupper((unsigned char)c->complete[celems-1]))
		cursor_argc = celems;

	if (cursor_argc > celems)
		return (CC_ERROR);

	return(complete_args(c, word, dolist, el, table, stlen,
	    cursor_argc - 1));
}

unsigned char
complete_args(struct ghs *c, char *word, int dolist, EditLine *el, char **table,
    int stlen, int level)
{
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

	columns = 1;
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
