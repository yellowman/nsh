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
 * nshd's answer to a show's words (showwords.h): its show processes and
 * its system collect the records a batch at a time, as the client reads
 * them (answer.c)
 */

#ifndef ANSWER_H
#define ANSWER_H

struct collection;

struct collection *facts_answer_begin(char *);
int		 facts_more(struct collection *, struct facts_out *, int);
void		 facts_answer_end(struct collection *);

/* what nshd's system streams, from a child: a program, or dhcpd's leases */
#define FACTS_PROGRAM	1
#define FACTS_LEASES	2
int		 facts_streams(struct collection *, char ***, int *);

#endif /* ANSWER_H */
