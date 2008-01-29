/* $nsh: editing.c,v 1.6 2008/01/29 06:17:35 chris Exp $ */

#include "editing.h"
#include "externs.h"

int editcmd(EditLine *, int);

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

	if (!elc && histc) {
		elc = el_init(__progname, stdin, stdout, stderr);
		el_set(elc, EL_HIST, history, histc); /* use history */
		el_set(elc, EL_EDITOR, "emacs"); /* default type */
		el_set(elc, EL_PROMPT, cprompt); /* set the prompt
						  * function */
#ifdef notyet
		el_set(elc, EL_ADDFN, "complt", "Command completion", complt);
		el_set(elc, EL_BIND, "\t", "complt", NULL);
#endif
		el_source(elc, NULL);	/* read ~/.editrc */
		el_set(elc, EL_SIGNAL, 1);
	}
	if (!eli && histi) {
		eli = el_init(__progname, stdin, stdout, stderr); /* again */
		el_set(eli, EL_HIST, history, histi);
		el_set(eli, EL_EDITOR, "emacs");
		el_set(eli, EL_PROMPT, iprompt);
#ifdef notyet
		el_set(eli, EL_ADDFN, "exit", "Exit", NULL);
		el_set(eli, EL_BIND, "\026", "exit", NULL);
#endif
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

int
editcmd(EditLine *e, int ch)
{
	return(CC_NEWLINE);
}
