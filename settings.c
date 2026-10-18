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
 * The settings: for each name a configuration line can have, how lines
 * of that name go together.  There is one table for each context, in
 * the order conf() prints the lines.
 *
 * A command in configure private says what it did to a setting (set it
 * or turned it on, turned it off, or left it at its default) and gives
 * the canonical line; the setting's kind turns that into the edit to
 * the candidate.  Commit will use the same kinds to take lines out.
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include "conftree.h"
#include "settings.h"

struct setting {
	char *name;		/* the line's first word, without "no" */
	int kind;		/* S_* */
};

static const struct setting top_settings[] = {
	{ "hostname",		S_VALUE },
	{ "interface",		S_BLOCK },
	{ "bridge",		S_BLOCK },
	{ NULL,			0 }
};

static const struct setting if_settings[] = {
	{ "description",	S_VALUE },
	{ "rdomain",		S_VALUE },
	{ "group",		S_LIST },
	{ "mtu",		S_VALUE },
	{ "metric",		S_VALUE },
	{ "priority",		S_VALUE },
	{ "llpriority",		S_VALUE },
	{ "debug",		S_FLAG },
	{ "arp",		S_NOFLAG },
	{ "staticarp",		S_FLAG },
	{ "shutdown",		S_STATE },
	{ NULL,			0 }
};

static const struct setting bridge_settings[] = {
	{ "description",	S_VALUE },
	{ "shutdown",		S_STATE },
	{ NULL,			0 }
};

/* indexed by CTX_* */
static const struct setting *contexts[] = {
	top_settings, if_settings, bridge_settings,
};

static const struct setting *setting_find(int, const char *);

/*
 * The edit that puts line's setting in context ctx into the given state
 * (ST_*). line is canonical and never starts with "no".  Writes the
 * line to edit to out and returns its CE_* edit, or -1 if no setting
 * has the line's name or out is too small.
 */
int
setting_edit(int ctx, int state, const char *line, char *out, size_t outlen)
{
	const struct setting *s;
	int op, n, neg = 0;

	if ((s = setting_find(ctx, line)) == NULL)
		return -1;

	switch (s->kind) {
	case S_VALUE:
	case S_FLAG:
		op = state == ST_ON ? CE_SET : CE_UNSET;
		break;
	case S_NOFLAG:
		op = state == ST_OFF ? CE_SET : CE_UNSET;
		neg = state == ST_OFF;
		break;
	case S_STATE:
		op = state == ST_DEFAULT ? CE_UNSET : CE_SET;
		neg = state == ST_OFF;
		break;
	case S_LIST:
		op = state == ST_ON ? CE_LISTADD :
		    state == ST_OFF ? CE_LISTDEL : CE_UNSET;
		break;
	case S_ENTRY:
		op = state == ST_ON ? CE_ADD : CE_DEL;
		break;
	case S_BLOCK:
		op = state == ST_ON ? CE_BLOCK : CE_NOBLOCK;
		break;
	default:
		return -1;
	}

	/* an unset needs only the name */
	if (op == CE_UNSET)
		n = snprintf(out, outlen, "%.*s", (int)strcspn(line, " "), line);
	else
		n = snprintf(out, outlen, "%s%s", neg ? "no " : "", line);
	if (n < 0 || (size_t)n >= outlen)
		return -1;
	return op;
}

/* The setting in context ctx named by line's first word */
static const struct setting *
setting_find(int ctx, const char *line)
{
	const struct setting *s;
	size_t len = strcspn(line, " ");

	if (ctx < 0 || ctx >= (int)(sizeof(contexts) / sizeof(contexts[0])))
		return NULL;
	for (s = contexts[ctx]; s->name != NULL; s++)
		if (strlen(s->name) == len && strncmp(s->name, line, len) == 0)
			return s;
	return NULL;
}
