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

/* Where a line is (settings.c) */
#define CTX_TOP		0	/* the top level */
#define CTX_IF		1	/* an interface block */
#define CTX_BRIDGE	2	/* a bridge block */
#define CTX_RTABLE	3	/* an rtable block */

/* How lines of one name go together (settings.c) */
#define S_VALUE		1	/* one line with a value: "mtu 1400" */
#define S_FLAG		2	/* the line, or none: "debug" */
#define S_NOFLAG	3	/* "no" and the line, or none: "no arp" */
#define S_STATE		4	/* the line, "no" and the line, or none */
#define S_LIST		5	/* one line listing values: "group a b" */
#define S_ENTRY		6	/* a line for each key: "inet 192.0.2.1/24" */
#define S_BLOCK		7	/* a top-level block: "interface em0" */

/* What a command did to a setting */
#define ST_ON		1	/* set it, or turned it on */
#define ST_OFF		2	/* turned it off: "no ..." */
#define ST_DEFAULT	3	/* left it so conf() prints no line for it */

/* The edit that puts a setting into a state (setting_edit()) */
struct sedit {
	int op;			/* CE_* */
	int keylen;		/* key length, for CE_SET and CE_UNSET */
	int strict;		/* if it changes nothing, say so */
	char line[1024];
};

int setting_edit(int, int, const char *, struct sedit *);
int setting_has(int, const char *);
