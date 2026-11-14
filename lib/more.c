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
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ttycom.h>
#include <sys/ioctl.h>
#include <wchar.h>

#include "externs.h"

int	nsh_cbreak(void);
void	nsh_nocbreak(void);

static struct termios	oldtty;

struct winsize winsize;

/*
 * The pager's file: where each line starts, so that any line can be
 * shown again, going back as well as forward
 */
struct pages {
	FILE	*f;
	off_t	*at;		/* where each line starts */
	size_t	 n;		/* lines */
};

enum { P_LINE, P_PAGE, P_BACKLINE, P_BACKPAGE, P_QUIT };

/* rows the page has, above the prompt */
static int
page_rows(void)
{
	return (winsize.ws_row > 1 ? winsize.ws_row - 1 : 1);
}

/*
 * Line l of p, printed if show is set; the rows it takes on the
 * terminal, as long lines wrap
 */
static int
page_line(struct pages *p, size_t l, int show)
{
	char	*input;
	size_t	 s, wlen;
	wchar_t	*ws = NULL;
	int	 rows = 1, width;

	if (fseeko(p->f, p->at[l], SEEK_SET) == -1 ||
	    (input = fgetln(p->f, &s)) == NULL)
		return (1);
	input[s - 1] = '\0';
	if (mbs2ws(&ws, &wlen, input) == 0) {
		if ((width = wcswidth(ws, wcslen(ws))) == -1) {
			free(ws);
			ws = NULL;
		} else
			rows += width / winsize.ws_col;
	} else
		ws = NULL;
	if (show) {
		if (ws)
			printf("%ls\n", ws);
		else
			printf("%s\n", input);
	}
	free(ws);
	return (rows);
}

/* the first line of the page that ends before line end */
static size_t
page_top(struct pages *p, size_t end)
{
	int	rows = 0;

	size_t	last = end;

	while (end > 0 && (rows + page_line(p, end - 1, 0) <= page_rows() ||
	    end == last))
		rows += page_line(p, --end, 0);
	return (end);
}

/*
 * Lines from l printed until they fill rows, and at least one, so a
 * line taller than the page is still shown; the line after the last
 * one printed
 */
static size_t
page_fill(struct pages *p, size_t l, int rows)
{
	size_t	first = l;
	int	r;

	while (l < p->n && ((r = page_line(p, l, 0)) <= rows || l == first)) {
		page_line(p, l++, 1);
		rows -= r;
	}
	return (l);
}

/* the page from line top, on a cleared screen */
static size_t
page_redraw(struct pages *p, size_t top)
{
	printf("\033[H\033[2J");
	return (page_fill(p, top, page_rows()));
}

/* a key at the prompt, as what it asks the pager to do */
static int
page_key(void)
{
	int	c;

	for (;;) {
		switch (c = getchar()) {
		case EOF:
		case 'q':
		case 'Q':
			return (P_QUIT);
		case '\r':
		case '\n':
		case 'j':
		case CTRL('n'):
			return (P_LINE);
		case ' ':
		case 'f':
		case CTRL('f'):
			return (P_PAGE);
		case 'k':
		case CTRL('p'):
			return (P_BACKLINE);
		case 'b':
		case CTRL('b'):
			return (P_BACKPAGE);
		case '\033':
			/* the arrows, and page up and down */
			if (getchar() != '[')
				break;
			switch (getchar()) {
			case 'A':
				return (P_BACKLINE);
			case 'B':
				return (P_LINE);
			case '5':
				(void)getchar();
				return (P_BACKPAGE);
			case '6':
				(void)getchar();
				return (P_PAGE);
			}
			break;
		}
	}
}

/*
 * Display file. A page at a time, with ---(more N%)--- below it: N is
 * how much of the file has been shown. Enter, j or the down arrow shows
 * one more line, and space, f or page down the next page; k or the up
 * arrow goes back a line, and b or page up a page. q quits. Once the
 * last line is shown, more returns
 */
int
more(char *fname)
{
	struct pages	 p;
	size_t		 s, end, top, nat = 0;
	int		 k, len;
	off_t		*at;

	memset(&p, 0, sizeof(p));
	if ((p.f = fopen(fname, "r")) == NULL) {
		if (errno == ENOENT)
			printf ("%% File %s not found\n", fname);
		else
			printf ("%% more: fopen(%s): %s\n", fname,
			    strerror(errno));
		return 0;
	}

	/* where each line starts */
	for (;;) {
		if (p.n == nat) {
			nat = nat ? nat * 2 : 1024;
			if ((at = reallocarray(p.at, nat, sizeof(*at))) ==
			    NULL) {
				printf("%% more: %s\n", strerror(errno));
				goto quit;
			}
			p.at = at;
		}
		if ((p.at[p.n] = ftello(p.f)) == -1 ||
		    fgetln(p.f, &s) == NULL)
			break;
		p.n++;
	}

	if (!interactive_mode || nsh_cbreak() < 0) {
		for (end = 0; end < p.n; end++)
			page_line(&p, end, 1);
		goto quit;
	}

	end = page_fill(&p, 0, page_rows());
	while (end < p.n) {
		len = printf("---(more %zu%%)---", end * 100 / p.n);
		fflush(stdout);
		k = page_key();
		printf("\r%*s\r", len, "");
		top = page_top(&p, end);
		if (k == P_QUIT)
			break;
		if (k == P_LINE)
			end = page_fill(&p, end, page_line(&p, end, 0));
		else if (k == P_PAGE)
			end = page_fill(&p, end, page_rows());
		else if (k == P_BACKLINE && top > 0)
			end = page_redraw(&p, top - 1);
		else if (k == P_BACKPAGE && top > 0)
			end = page_redraw(&p, page_top(&p, top));
	}
	nsh_nocbreak();
quit:
	fclose(p.f);
	free(p.at);
	return 1;
}

int
nsh_cbreak(void)
{
	struct termios	newtty;

	if (tcgetattr(fileno(stdout), &oldtty) < 0)
		return -1;

	(void)memcpy(&newtty, &oldtty, sizeof(newtty));

	newtty.c_lflag &= ~(ECHO | ICANON);	/* no echo, canonical */
	newtty.c_cc[VMIN] = 1;			/* one char at a time */
	newtty.c_cc[VTIME] = 0;			/* no timeout */

	if (tcsetattr(fileno(stdout), TCSAFLUSH, &newtty) < 0)
		return -1;
	return 0;
}

void
nsh_nocbreak(void)
{
	tcsetattr(0, TCSAFLUSH, &oldtty);
}

void
setwinsize(int signo)
{
	int save_errno = errno;

	if (ioctl(fileno(stdout), TIOCGWINSZ, &winsize) != -1) {
		winsize.ws_col = winsize.ws_col ? winsize.ws_col : 80;
		winsize.ws_row = winsize.ws_row ? winsize.ws_row : 24;
	} else {
		winsize.ws_col = 80;
		winsize.ws_row = 24;
	}

	errno = save_errno;
}
