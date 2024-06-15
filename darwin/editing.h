#include <histedit.h>

extern EditLine *elc;		/* editline(3) status structure */
extern EditLine *eli;		/* another one */
extern History *histc;		/* command() editline(3) history structure */
extern History *histi;		/* interface() editline(3) status structure */
extern char	*cursor_pos;	/* cursor position we're looking for */
extern size_t	cursor_argc;	/* location of cursor in margv */
extern size_t	cursor_argo;	/* offset of cursor in margv[cursor_argc] */
