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
	int keylen;		/* its key, if not its name (conftree.h) */
};

static const struct setting top_settings[] = {
	{ "hostname",		S_VALUE },
	{ "interface",		S_BLOCK },
	{ "bridge",		S_BLOCK },
	{ NULL,			0 }
};

static const struct setting if_settings[] = {
	{ "description",	S_VALUE },
	{ "lladdr",		S_VALUE },
	{ "vnetid",		S_VALUE },
	{ "vnetflowid",		S_FLAG },
	{ "parent",		S_VALUE },
	{ "patch",		S_VALUE },
	{ "rdomain",		S_VALUE },
	{ "rtlabel",		S_VALUE },
	{ "group",		S_LIST },
	{ "carpdev",		S_VALUE },
	{ "carppass",		S_VALUE },
	{ "advbase",		S_VALUE },
	{ "vhid",		S_VALUE },
	{ "advskew",		S_VALUE },
	{ "carpnode",		S_ENTRY,	2 },
	{ "carppeer",		S_VALUE },
	{ "balancing",		S_VALUE },
	{ "tunnel",		S_VALUE },
	{ "tunneldomain",	S_VALUE },
	{ "mtu",		S_VALUE },
	{ "metric",		S_VALUE },
	{ "priority",		S_VALUE },
	{ "llpriority",		S_VALUE },
	{ "txprio",		S_VALUE },
	{ "rxprio",		S_VALUE },
	{ "nwid",		S_VALUE },
	{ "nwkey",		S_VALUE },
	{ "txpower",		S_VALUE },
	{ "powersave",		S_VALUE },
	{ "autoconf4",		S_STATE },
	{ "inet",		S_ENTRY,	2 | CK_ADDR },
	{ "media",		S_VALUE },
	{ "keepalive",		S_VALUE },
	{ "syncdev",		S_VALUE },
	{ "syncpeer",		S_VALUE },
	{ "maxupd",		S_VALUE },
	{ "trunkproto",		S_VALUE },
	{ "trunkport",		S_LIST },
	{ "pflow",		S_VALUE },
	{ "mplslabel",		S_VALUE },
	{ "pwe",		S_VALUE },
	{ "mpls",		S_FLAG },
	{ "autoconf6",		S_FLAG },
	{ "temporary",		S_FLAG },
	{ "monitor",		S_FLAG },
	{ "wol",		S_FLAG },
	{ "dhcrelay",		S_VALUE },
	{ "peer",		S_VALUE },
	{ "auth",		S_VALUE },
	{ "pppoe",		S_VALUE },
	{ "wgport",		S_VALUE },
	{ "wgrtable",		S_VALUE },
	{ "wgkey",		S_VALUE },
	{ "wgpeer",		S_ENTRY,	3 },
	{ "apn",		S_VALUE },
	{ "setpin",		S_VALUE },
	{ "roaming",		S_FLAG },
	{ "class",		S_VALUE },
	{ "debug",		S_FLAG },
	{ "link",		S_VALUE },
	{ "arp",		S_NOFLAG },
	{ "staticarp",		S_FLAG },
	{ "shutdown",		S_STATE },
	{ NULL,			0 }
};

static const struct setting bridge_settings[] = {
	{ "description",	S_VALUE },
	{ "vnetid",		S_VALUE },
	{ "parent",		S_VALUE },
	{ "tunneldomain",	S_VALUE },
	{ "txprio",		S_VALUE },
	{ "rxprio",		S_VALUE },
	{ "link",		S_VALUE },
	/* bridge.c's model writes these lines whole */
	{ "priority",		S_VALUE },
	{ "hellotime",		S_VALUE },
	{ "fwddelay",		S_VALUE },
	{ "maxage",		S_VALUE },
	{ "maxaddr",		S_VALUE },
	{ "timeout",		S_VALUE },
	{ "member",		S_VALUE },
	{ "stp",		S_VALUE },
	{ "span",		S_VALUE },
	{ "learning",		S_STATE },
	{ "discover",		S_STATE },
	{ "blocknonip",		S_VALUE },
	{ "ifpriority",		S_ENTRY,	2 },
	{ "ifcost",		S_ENTRY,	2 },
	{ "protect",		S_ENTRY,	2 },
	{ "static",		S_ENTRY,	2 },
	{ "rule",		S_ENTRY,	11 },
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
 * (ST_*). line is canonical and never starts with "no". Fills in e and
 * returns 0, or -1 if no setting has the line's name or the line is too
 * long. Turning off a list value, an entry or a block that is not there
 * is an error, so that edit is strict.
 */
int
setting_edit(int ctx, int state, const char *line, struct sedit *e)
{
	const struct setting *s;
	int op, n, neg = 0;

	if ((s = setting_find(ctx, line)) == NULL)
		return -1;
	e->keylen = s->keylen > 0 ? s->keylen : 1;
	e->strict = state == ST_OFF &&
	    (s->kind == S_LIST || s->kind == S_ENTRY || s->kind == S_BLOCK);

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
		op = state == ST_ON ? CE_SET : CE_UNSET;
		break;
	case S_BLOCK:
		op = state == ST_ON ? CE_BLOCK : CE_NOBLOCK;
		break;
	default:
		return -1;
	}

	/* an unset finds the lines it removes by their key alone */
	n = snprintf(e->line, sizeof(e->line), "%s%s", neg ? "no " : "", line);
	if (n < 0 || (size_t)n >= sizeof(e->line))
		return -1;
	e->op = op;
	return 0;
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
