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
 * nshd's answers to the shows that answer with facts (showfacts.c): its
 * show processes and its system collect a show's records, a batch at a
 * time, as the client reads them. A program's output and dhcpd's leases
 * are text, which system streams from a child.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "externs.h"
#include "nshd.h"
#include "internal.h"
#include "facts.h"
#include "showfacts.h"
#include "showwords.h"
#include "answer.h"

/* nshd's collection: a show's words, and what it has collected so far */
struct collection {
	struct facts_answer	*a;		/* the words */
	struct if_nameindex	*ifn;		/* every interface */
	size_t			 next;
	struct rtdump		*rt;
	char			*cur;
	int			 done;
};

/* a collection for words, or NULL if nshd does not answer them here */
struct collection *
facts_answer_begin(char *words)
{
	struct collection	*c;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		return (NULL);
	if ((c->a = facts_answer(words)) == NULL) {
		free(c);
		return (NULL);
	}
	return (c);
}

/*
 * For config, the show words ask of nshd's system, as values in ss: 0,
 * or NSHD_ELSEWHERE if system does not answer it
 */
int
facts_answer_pack(char *words, struct nshd_sysshow *ss)
{
	struct facts_answer	*a;
	int			 i, r = NSHD_ELSEWHERE;

	memset(ss, 0, sizeof(*ss));
	if ((a = facts_answer(words)) == NULL ||
	    (a->where & FACTS_SYSTEM) == 0)
		goto done;
	ss->type = a->type;
	ss->af = a->af;
	if (a->type == ANS_STATISTICS)
		ss->stats = stats_place(a->stats);
	if (a->type == ANS_PROGRAM) {
		ss->table = a->table;
		ss->prot = prot1_place(a->prog, &ss->sub);
		ss->nargs = a->n - 4;
		for (i = 0; i < ss->nargs; i++)
			strlcpy(ss->args[i], a->w[4 + i], sizeof(ss->args[i]));
	}
	strlcpy(ss->name, a->name, sizeof(ss->name));
	r = 0;
done:
	facts_answer_free(a);
	return (r);
}

/*
 * Begin, for nshd's system, the show values ss ask, which config parsed
 * (facts_answer_pack()), or NULL if they ask none system answers
 */
struct collection *
facts_answer_take(const struct nshd_sysshow *ss)
{
	struct facts_answer	*a;
	struct collection	*c;
	int			 i;

	/* the kinds of facts, as facts_answer() makes them first */
	facts_init();
	if ((a = calloc(1, sizeof(*a))) == NULL)
		return (NULL);
	a->type = ss->type;
	switch (ss->type) {
	case ANS_IP:
		if (ss->af != AF_UNSPEC && ss->af != AF_INET &&
		    ss->af != AF_INET6)
			goto bad;
		a->af = ss->af;
		break;
	case ANS_AUTOCONF:
		strlcpy(a->name, ss->name, sizeof(a->name));
		break;
	case ANS_STATISTICS:
		if ((a->stats = stats_at(ss->stats)) == NULL ||
		    (stats_where(a->stats) & FACTS_SYSTEM) == 0)
			goto bad;
		break;
	case ANS_PROGRAM:
		/* the words the program's arguments take, in a's copy */
		/* system's message check bounds nargs */
		if (ss->table < 0 || ss->table > RT_TABLEID_MAX ||
		    (a->prog = prot1_at(ss->prot, ss->sub)) == NULL ||
		    (a->copy = malloc(sizeof(ss->args))) == NULL)
			goto bad;
		memcpy(a->copy, ss->args, sizeof(ss->args));
		a->table = ss->table;
		a->n = 4 + ss->nargs;
		for (i = 0; i < ss->nargs; i++)
			if (*(a->w[4 + i] = a->copy + i * NSHD_WORDS) == '\0')
				goto bad;
		break;
	case ANS_LEASES:
	case ANS_DAEMONS:
		break;
	default:
		goto bad;
	}
	if ((c = calloc(1, sizeof(*c))) == NULL)
		goto bad;
	c->a = a;
	return (c);
bad:
	facts_answer_free(a);
	return (NULL);
}

/*
 * Some of c's records, about budget of them, into o: 1 if there are
 * more, 0 if c is done, -1 if it failed
 */
int
facts_more(struct collection *c, struct facts_out *o, int budget)
{
	struct facts_answer	*a = c->a;
	int			 r = 0;

	if (c->done)
		return (0);
	switch (a->type) {
	case ANS_INTERFACE:
		if (a->name[0] != '\0')
			r = if_facts(o, a->name, a->detail);
		else if (c->ifn == NULL && (c->ifn = if_nameindex()) == NULL) {
			printf("%% if_nameindex: %s\n", strerror(errno));
			r = -1;
		} else if (c->ifn[c->next].if_name != NULL)
			return (if_facts(o, c->ifn[c->next++].if_name,
			    a->detail) == -1 ? -1 : 1);
		break;
	case ANS_ROUTE:
	case ANS_ARP:
	case ANS_NDP:
	case ANS_SADB:
		if (c->rt == NULL) {
			if (a->type == ANS_SADB) {
				/* sadb_dump() prints why, unless no IPsec */
				if ((c->rt = sadb_dump()) == NULL) {
					r = -1;
					break;
				}
			} else if (a->type == ANS_ROUTE)
				c->rt = getrtdump(a->af, 0, a->table);
			else
				c->rt = getrtdump(a->type == ANS_ARP ?
				    AF_INET : AF_INET6, RTF_LLINFO, a->table);
			if (c->rt == NULL)
				break;
			c->cur = c->rt->buf;
		}
		if (a->type == ANS_SADB)
			r = sadb_facts(o, c->rt, &c->cur, budget);
		else if (a->type == ANS_ROUTE)
			r = route_facts(o, c->rt, &c->cur, a->af, budget);
		else if (a->type == ANS_ARP)
			r = arp_facts(o, c->rt, &c->cur, a->one ? &a->in :
			    NULL, budget);
		else
			r = ndp_facts(o, c->rt, &c->cur, a->one ? &a->sin6 :
			    NULL, budget);
		if (r == 1)
			return (1);
		break;
	case ANS_LOOKUP:
		r = lookup_facts(o, a->w[1], a->table);
		break;
	case ANS_VLAN:
		r = vlan_facts(o, a->start, a->end);
		break;
	case ANS_BRIDGE:
		r = bridge_show_facts(o, a->n == 2 ? a->w[1] : NULL);
		break;
	case ANS_STATISTICS:
		r = stats_facts(o, a->stats);
		break;
	case ANS_VERSION:
		r = version_facts(o);
		break;
	case ANS_USERS:
		r = users_facts(o);
		break;
	case ANS_DAEMONS:
		/* whether pf runs, only with FACTS_SYSTEM */
		r = daemons_facts(o, (facts_from & FACTS_SYSTEM) != 0);
		break;
	case ANS_HOSTNAME:
		r = hostname_facts(o);
		break;
	case ANS_IP:
		/* what configured each address, only with FACTS_SYSTEM */
		r = ip_facts(o, a->af, (facts_from & FACTS_SYSTEM) != 0);
		break;
	case ANS_AUTOCONF:
		r = autoconf_facts(o, a->name[0] != '\0' ? a->name : NULL);
		break;
	case ANS_PROGRAM:
	case ANS_LEASES:
		/* nshd's system streams them from a child (facts_streams()) */
		r = -1;
		break;
	}
	c->done = 1;
	return (r == -1 ? -1 : 0);
}

/*
 * Whether c's show is text nshd's system streams from a child, and
 * which: FACTS_PROGRAM, with the program and its arguments (c's) in
 * *argv and its routing table in *table, or FACTS_LEASES. 0 if it is
 * not, or -1, after printing why, if c's words do not fill the
 * program's arguments
 */
int
facts_streams(struct collection *c, char ***argv, int *table)
{
	struct facts_answer	*a = c->a;

	switch (a->type) {
	case ANS_PROGRAM:
		if ((*argv = prot1_args(a->prog, a->args, a->n - 4, a->w + 4,
		    a->table)) == NULL)
			return (-1);
		*table = a->table;
		return (FACTS_PROGRAM);
	case ANS_LEASES:
		return (FACTS_LEASES);
	default:
		return (0);
	}
}

/* end c: free what facts_more() collected, the words, and c */
void
facts_answer_end(struct collection *c)
{
	if (c == NULL)
		return;
	if (c->ifn != NULL)
		if_freenameindex(c->ifn);
	if (c->rt != NULL)
		freertdump(c->rt);
	facts_answer_free(c->a);
	free(c);
}
