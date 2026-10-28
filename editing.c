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

/*
 * The editline side of nsh's prompts: the editors and their histories,
 * and Tab, which runs complete_line() on the line, then inserts what it
 * found or lists the choices.
 */

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

#define ttyout stdout

static unsigned char complete(EditLine *, char **, size_t);
static void list_vertical(StringList *);
static void cmplt_print(struct cmplt *);
static char *el_said(EditLine *, const char **);
static int el_runs(const char *);
static int el_off(EditLine *, int, const char *);
static int el_offesc(EditLine *);
static int el_noeditor(EditLine *);

unsigned char complt_c(EditLine *, int);
unsigned char complt_i(EditLine *, int);
unsigned char exit_i(EditLine *, int);

unsigned char
exit_i(EditLine *el, int ch)
{
	printf("\n");
	return CC_EOF;
}

unsigned char
complt_i(EditLine *el, int ch)
{
	return complete(el, (char **)whichlist, sizeof(struct intlist));
}

unsigned char
complt_c(EditLine *el, int ch)
{
	/*
	 * In nshd's configure, nsh's command loop also reads an interface's
	 * mode, so complete from the interface table there.
	 */
	if (nshd_config && ifname[0] != '\0')
		return complt_i(el, ch);
	return complete(el, (char **)cmdtab, sizeof(struct cmd));
}

/*
 * Complete editline's line at its cursor, from table.
 */
static unsigned char
complete(EditLine *el, char **table, size_t stlen)
{
	static char word[CMPLT_WORD];
	const LineInfo *lf;
	struct cmplt c;
	unsigned char rv;

	lf = el_line(el);
	rv = complete_line(lf->buffer, lf->lastchar - lf->buffer,
	    lf->cursor - lf->buffer, word, table, stlen, 0, &c);
	if (rv == CC_REFRESH && el_insertstr(el, c.insert) == -1)
		rv = CC_ERROR;
	else if (rv == CC_REDISPLAY)
		cmplt_print(&c);
	cmplt_free(&c);
	return (rv);
}

/* List cp's choices below the line. */
static void
cmplt_print(struct cmplt *cp)
{
	StringList *w = cp->words, *h = cp->helps;
	int i, len, max = 0;

	if (w->sl_cur > 0)
		putc('\n', ttyout);
	if (h == NULL || cp->vertical) {
		list_vertical(w);
		return;
	}
	for (i = 0; i < w->sl_cur; i++)
		if ((len = strlen(w->sl_str[i])) > max)
			max = len;
	for (i = 0; i < w->sl_cur; i++) {
		if (h->sl_str[i][0] == '\0')
			fprintf(ttyout, " %s %s\n", cp->cmdname, w->sl_str[i]);
		/*
		 * Command help strings beginning with '^' are supposed to be
		 * printed literally.
		 */
		else if (w->sl_str[i][0] == '^')
			fprintf(ttyout, " %-*s  # %s\n", max, &w->sl_str[i][1],
			    h->sl_str[i]);
		else
			fprintf(ttyout, " %s %-*s  # %s\n", cp->cmdname, max,
			    w->sl_str[i], h->sl_str[i]);
	}
}

/*
 * List words in stringlist, vertically arranged
 */
static void
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

/*
 * What bind argv, a list ending in NULL, prints on el, in a string to
 * free, or NULL
 */
static char *
el_said(EditLine *el, const char **argv)
{
	FILE *out, *err, *f;
	char *s = NULL;
	size_t len;
	int argc;

	for (argc = 0; argv[argc] != NULL; argc++)
		;
	if (el_get(el, EL_GETFP, 1, &out) == -1 ||
	    el_get(el, EL_GETFP, 2, &err) == -1 ||
	    (f = open_memstream(&s, &len)) == NULL)
		return (NULL);
	el_set(el, EL_SETFP, 1, f);
	el_set(el, EL_SETFP, 2, f);
	el_parse(el, argc, argv);
	el_set(el, EL_SETFP, 1, out);
	el_set(el, EL_SETFP, 2, err);
	if (fclose(f) == EOF) {
		free(s);
		return (NULL);
	}
	return (s);
}

/*
 * Does a line of bind's output bind a key to vi-histedit, which runs vi,
 * or to ed-command, which runs a bind nsh does not see?  bind prints a
 * key's function last on its line, and a string a key types in quotes.
 */
static int
el_runs(const char *said)
{
	static const char *const funcs[] = { "vi-histedit", "ed-command" };
	const char *p, *e;
	size_t i, n;

	for (p = said; *p != '\0'; p = *e == '\0' ? e : e + 1) {
		if ((e = strchr(p, '\n')) == NULL)
			e = p + strlen(p);
		for (i = 0; i < nitems(funcs); i++) {
			n = strlen(funcs[i]);
			if ((size_t)(e - p) >= n &&
			    strncmp(e - n, funcs[i], n) == 0)
				return (1);
		}
	}
	return (0);
}

/*
 * Unbind key in el (in the alternative map if alt) if it, or a sequence
 * of keys that starts with it, runs vi-histedit or ed-command: -1 if
 * bind cannot be asked, 1 if it was unbound, else 0
 */
static int
el_off(EditLine *el, int alt, const char *key)
{
	const char *ask[2][4] = {
		{ "bind", key, NULL },
		{ "bind", "-a", key, NULL } };
	const char *off[2][5] = {
		{ "bind", "-r", key, NULL },
		{ "bind", "-a", "-r", key, NULL } };
	char *s;
	int runs;

	if ((s = el_said(el, ask[alt])) == NULL)
		return (-1);
	runs = el_runs(s);
	free(s);
	if (runs)
		el_parse(el, 3 + alt, off[alt]);
	return (runs);
}

/*
 * el_off() ESC and each key after it, where the editor puts each meta
 * key's function
 */
static int
el_offesc(EditLine *el)
{
	char key[9];
	int c, r, unbound = 0;

	for (c = 1; c < 0200; c++) {
		(void)snprintf(key, sizeof(key), "\\033\\%03o", c);
		if ((r = el_off(el, 0, key)) == -1)
			return (-1);
		unbound |= r;
	}
	return (unbound);
}

/*
 * For a user without the exec permission: unbind every key of el's that
 * runs vi-histedit or ed-command.  -1, after printing why, if that
 * cannot be verified, 1 if a key was unbound, else 0
 */
static int
el_noeditor(EditLine *el)
{
	const char *all[] = { "bind", NULL };
	const char *vi[] = { "bind", "-v", NULL };
	const char *emacs[] = { "bind", "-e", NULL };
	const char *ed;
	char key[5], *s, *p;
	int c, r, unbound;

	if ((s = el_said(el, all)) == NULL)
		goto fail;
	r = el_runs(s);
	free(s);
	if (!r)
		return (0);

	/*
	 * The editor binds a function to no sequence of keys but ESC and a
	 * key, where it puts each meta key's function.  bind prints a
	 * sequence in a form it cannot always read back, so if another
	 * sequence runs one, the editor's defaults are restored.
	 */
	if ((unbound = el_offesc(el)) == -1 || (s = el_said(el, all)) == NULL)
		goto fail;
	r = (p = strstr(s, "Multi-character bindings")) == NULL || el_runs(p);
	free(s);
	if (r && (el_get(el, EL_EDITOR, &ed) == -1 ||
	    el_parse(el, 2, strcmp(ed, "vi") == 0 ? vi : emacs) != 0 ||
	    el_offesc(el) == -1))
		goto fail;

	for (c = 0; c < 2 * 256; c++) {
		(void)snprintf(key, sizeof(key), "\\%03o", c % 256);
		if ((r = el_off(el, c / 256, key)) == -1)
			goto fail;
		unbound |= r;
	}

	if ((s = el_said(el, all)) == NULL)
		goto fail;
	r = el_runs(s);
	free(s);
	if (!r)
		return (unbound);
fail:
	printf("%% Command line editing off: its keys could not be kept from "
	    "running vi-histedit or ed-command\n");
	return (-1);
}

void
initedit()
{
	if (!isatty(STDIN_FILENO)) {
		printf("%% Command line editing requires a terminal\n");
		editing = 0;
		return;
	}

	editing = 1;

	if (!elc) {
		elc = el_init(getprogname(), stdin, stdout, stderr);
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
		eli = el_init(getprogname(), stdin, stdout, stderr);
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
	if (!elp) {
		elp = el_init(getprogname(), stdin, stdout, stderr);
		el_set(elp, EL_EDITOR, "emacs"); /* default type */
		el_set(elp, EL_PROMPT, pprompt); /* set the prompt
						  * function */
		el_set(eli, EL_ADDFN, "exit_i", "Exit", exit_i);
		el_set(eli, EL_BIND, "^X", "exit_i", NULL);
		el_set(eli, EL_BIND, "^D", "exit_i", NULL);
		el_source(elp, NULL);	/* read ~/.editrc */
		el_set(elp, EL_SIGNAL, 1);
	}
	if (!nshd_execs() && (el_noeditor(elc) == -1 ||
	    el_noeditor(eli) == -1 || el_noeditor(elp) == -1))
		endedit();
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
	if (elp) {
		el_end(elp);
		elp = NULL;
	}
}

/*
 * for the purpose of interface handler routines, 1 here is failure and
 * 0 is success
 */
int
el_burrito(EditLine *el, int argc, char **argv)
{
	char *colon;
	int val;

	if (!editing)	/* Nothing to parse, fail */
		return 1;

	/*
	 * el_parse will always return a non-error status if someone specifies
	 * argv[0] with a colon.  The idea of the colon is to allow host-
	 * specific commands, which is really only useful in .editrc, so
	 * it is invalid here.
	 */
	colon = strchr(argv[0], ':');
	if (colon)
		return 1;

	val = el_parse(el, argc, (const char **)argv);

	if (!nshd_execs())
		switch (el_noeditor(el)) {
		case -1:
			endedit();
			break;
		case 1:
			printf("%% Keys for vi-histedit and ed-command "
			    "unbound: your login class does not have the exec "
			    "permission\n");
			break;
		}

	if (val == 0)
		return 0;
	else
		return 1;
}
