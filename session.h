/*
 * Copyright (c) 2026 Chris Cappuccio <chris@nmedia.net>
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


/*
 * A session's state: each global a handler reads or writes and keeps
 * from one request to the next (globals.list's session class), named in
 * an SGLOBAL table of the file that has it, and held by the session
 * while it is not running (session.c)
 */
struct sglobal {
	const char	*name;
	void		*addr;
	size_t		 size;
};
#define SGLOBAL(g)	{ #g, &(g), sizeof(g) }

struct session_state;

extern int in_config;

struct session_state	*session_new(void);
void			 session_free(struct session_state *);
void			 session_enter(struct session_state *);
void			 session_leave(struct session_state *);
const struct sglobal	*session_global(size_t);
int			 session_running(char *, size_t);
int			 session_configure(struct session_state *);
int			 session_line(struct session_state *, char *);
int			 session_exit(struct session_state *);
void			 session_mode(struct session_state *, int *, int *,
			    char *, size_t, int *);
int			 session_candidate(struct session_state *);
