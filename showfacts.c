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
 * The shows that answer with facts. A request is words:
 *
 *	interface [name] [detail]	every interface, or one; with
 *					detail, what show interface
 *					prints only when verbose
 *	route inet|inet6 table		a routing table
 *	lookup address table		the route the kernel would use
 *
 * nshd's show processes answer them a batch at a time, as the client
 * reads; nsh asks nshd, or, where nshd does not run, answers them
 * itself. Either way nsh renders the records as the text it printed
 * before. An interface's records come before its own record, which
 * ends them. What a collector prints, as nsh's helpers always have,
 * reaches the terminal here, and nshd sends it as a message.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "externs.h"
#include "facts.h"
#include "showfacts.h"

static struct facts_field message_fields[] = {
	{ "text",	FACT_STRING },
};
struct facts_kind kind_message = { "message", message_fields, 1 };

static struct facts_kind *kinds[] = {
	&kind_message, &kind_route, &kind_lookup, &kind_interface,
	&kind_address, &kind_media, &kind_carp, &kind_wgpeer, &kind_umb,
	&kind_umbdns, &kind_trunkport, &kind_bridgemember, &kind_bridgeaddr
};

enum answer_type { ANS_INTERFACE, ANS_ROUTE, ANS_LOOKUP };

struct facts_answer {
	enum answer_type	 type;
	struct if_nameindex	*ifn;	/* every interface, or NULL */
	size_t			 next;
	char			 name[IFNAMSIZ];
	struct rtdump		*rt;
	char			*cur;
	int			 af;
	int			 table;
	int			 detail;	/* interface detail */
	char			 query[INET6_ADDRSTRLEN + 5];
	int			 done;
};

/* names for the bits that s, a string for bprintf(), names, in f */
void
facts_bitnames(struct facts_field *f, const char *s)
{
	struct facts_name	*names;
	size_t			 n = 0;
	const char		*p;
	int			 bit;

	if ((names = calloc(32, sizeof(*names))) == NULL)
		return;
	while ((bit = (u_char)*s++) != 0) {
		for (p = s; (u_char)*s > 32; s++)
			;
		if (s == p || bit > 32 || n == 32)
			continue;
		names[n].value = 1ULL << (bit - 1);
		names[n].name = strndup(p, s - p);
		if (names[n].name != NULL)
			n++;
	}
	f->naming = FACT_BITS;
	f->names = names;
	f->nnames = n;
}

/* every kind's names, from the tables nsh prints with */
void
facts_init(void)
{
	static int	 done;

	if (done)
		return;
	done = 1;
	route_facts_init();
	if_facts_init();
	media_facts_init();
	carp_facts_init();
	umb_facts_init();
	trunk_facts_init();
	bridge_facts_init();
}

int
facts_message(struct facts_out *o, const char *fmt, ...)
{
	struct facts_value	 v[1];
	va_list			 ap;
	char			*s;
	int			 r;

	va_start(ap, fmt);
	r = vasprintf(&s, fmt, ap);
	va_end(ap);
	if (r == -1)
		return (-1);
	facts_string(&v[MSG_TEXT], s);
	r = facts_record(o, &kind_message, v);
	free(s);
	return (r);
}

/* sa, an inet, inet6 or link address, as a fact; else absent */
void
facts_sockaddr(struct facts_value *v, struct sockaddr *sa)
{
	struct sockaddr_in6	 sin6;
	struct sockaddr_dl	*sdl;
	uint8_t			 bytes[16];
	size_t			 n;

	v->type = FACT_NONE;
	if (sa == NULL)
		return;
	switch (sa->sa_family) {
	case AF_INET:
		/* a mask the kernel cut short reads as the zeros it left */
		memset(bytes, 0, sizeof(bytes));
		n = sa->sa_len > offsetof(struct sockaddr_in, sin_addr) ?
		    sa->sa_len - offsetof(struct sockaddr_in, sin_addr) : 0;
		memcpy(bytes, &((struct sockaddr_in *)sa)->sin_addr,
		    n < 4 ? n : 4);
		facts_address(v, FACT_INET, bytes, 4, 0);
		break;
	case AF_INET6:
		memset(&sin6, 0, sizeof(sin6));
		memcpy(&sin6, sa, sa->sa_len < sizeof(sin6) ? sa->sa_len :
		    sizeof(sin6));
		if (sa->sa_len >= sizeof(sin6))
			in6_fillscopeid(&sin6);
		facts_address(v, FACT_INET6, &sin6.sin6_addr, 16,
		    sin6.sin6_scope_id);
		break;
	case AF_LINK:
		sdl = (struct sockaddr_dl *)sa;
		facts_address(v, FACT_LINK, LLADDR(sdl), sdl->sdl_alen,
		    sdl->sdl_index);
		break;
	}
}

uint64_t
fu(struct frec *r, int i, uint64_t dflt)
{
	const struct facts_value	*v;

	if ((v = FV(r, i, FACT_U64)) == NULL)
		return (dflt);
	return (v->v.u);
}

/* a string, as facts_copy() kept it, NUL and all; NULL if absent */
const char *
fs(struct frec *r, int i)
{
	const struct facts_value	*v;

	if ((v = FV(r, i, FACT_STRING)) == NULL)
		return (NULL);
	return (v->v.str.s);
}

int
fhas(struct frec *r, int i)
{
	return (r->map[i] != -1 && r->v[r->map[i]].type != FACT_NONE);
}

/* an address fact as the sockaddr it was; 0 if absent */
int
fsockaddr(struct frec *r, int i, struct sockaddr_storage *ss)
{
	const struct facts_value	*v;
	struct sockaddr_in		*sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6		*sin6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_dl		*sdl = (struct sockaddr_dl *)ss;

	memset(ss, 0, sizeof(*ss));
	if ((v = FV(r, i, FACT_ADDRESS)) == NULL)
		return (0);
	switch (v->v.a.family) {
	case FACT_INET:
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, v->v.a.bytes, v->v.a.len < 4 ?
		    v->v.a.len : 4);
		break;
	case FACT_INET6:
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, v->v.a.bytes, v->v.a.len < 16 ?
		    v->v.a.len : 16);
		sin6->sin6_scope_id = v->v.a.scope;
		break;
	case FACT_LINK:
		sdl->sdl_len = sizeof(*sdl);
		sdl->sdl_family = AF_LINK;
		sdl->sdl_index = v->v.a.scope;
		sdl->sdl_alen = v->v.a.len;
		memcpy(sdl->sdl_data, v->v.a.bytes, v->v.a.len);
		break;
	default:
		return (0);
	}
	return (1);
}

/* a link address, with its type and name, as the sockaddr_dl it was */
int
sdl_build(struct frec *r, int addr, int type, int name,
    struct sockaddr_storage *ss)
{
	const struct facts_value	*a;
	struct sockaddr_dl		*sdl = (struct sockaddr_dl *)ss;
	char				*data;
	const char			*n;
	size_t				 nlen;

	memset(ss, 0, sizeof(*ss));
	if ((a = FV(r, addr, FACT_ADDRESS)) == NULL ||
	    a->v.a.family != FACT_LINK)
		return (0);
	n = fs(r, name);
	nlen = n ? strlen(n) : 0;
	if (nlen > IFNAMSIZ)
		nlen = IFNAMSIZ;
	sdl->sdl_family = AF_LINK;
	sdl->sdl_index = a->v.a.scope;
	sdl->sdl_type = fu(r, type, 0);
	sdl->sdl_nlen = nlen;
	sdl->sdl_alen = a->v.a.len;
	data = (char *)ss + offsetof(struct sockaddr_dl, sdl_data);
	if (nlen)
		memcpy(data, n, nlen);
	memcpy(data + nlen, a->v.a.bytes, a->v.a.len);
	sdl->sdl_len = offsetof(struct sockaddr_dl, sdl_data) + nlen +
	    a->v.a.len;
	if (sdl->sdl_len < sizeof(*sdl))
		sdl->sdl_len = sizeof(*sdl);
	return (1);
}

/* the next record of kind k in rs after r, or the first */
struct frec *
frec_next(struct frecs *rs, struct frec *r, const struct facts_kind *k)
{
	for (r = r ? TAILQ_NEXT(r, entry) : TAILQ_FIRST(rs); r != NULL;
	    r = TAILQ_NEXT(r, entry))
		if (r->k == k)
			return (r);
	return (NULL);
}

/* what words ask, or NULL, with why in msg */
struct facts_answer *
facts_answer(char *words)
{
	struct facts_answer	*a;
	char			*w[4], *copy, *p, *last;
	const char		*errstr;
	int			 n = 0;

	facts_init();
	if ((copy = strdup(words)) == NULL)
		return (NULL);
	for (p = strtok_r(copy, " ", &last); p != NULL;
	    p = strtok_r(NULL, " ", &last)) {
		if (n == 4) {
			free(copy);
			return (NULL);
		}
		w[n++] = p;
	}
	if ((a = calloc(1, sizeof(*a))) == NULL) {
		free(copy);
		return (NULL);
	}
	if (n >= 1 && n <= 3 && strcmp(w[0], "interface") == 0) {
		a->type = ANS_INTERFACE;
		if (n > 1 && strcmp(w[n - 1], "detail") == 0) {
			a->detail = 1;
			n--;
		}
		if (n == 3)
			goto bad;
		if (n == 2) {
			if (strlcpy(a->name, w[1], sizeof(a->name)) >=
			    sizeof(a->name))
				goto bad;
		} else if ((a->ifn = if_nameindex()) == NULL)
			goto bad;
	} else if (n == 3 && strcmp(w[0], "route") == 0) {
		a->type = ANS_ROUTE;
		if (strcmp(w[1], "inet") == 0)
			a->af = AF_INET;
		else if (strcmp(w[1], "inet6") == 0)
			a->af = AF_INET6;
		else
			goto bad;
	} else if (n == 3 && strcmp(w[0], "lookup") == 0) {
		a->type = ANS_LOOKUP;
		if (strlcpy(a->query, w[1], sizeof(a->query)) >=
		    sizeof(a->query))
			goto bad;
	} else
		goto bad;
	if (a->type != ANS_INTERFACE) {
		a->table = strtonum(w[2], 0, RT_TABLEID_MAX, &errstr);
		if (errstr)
			goto bad;
	}
	free(copy);
	return (a);
bad:
	free(copy);
	facts_answer_free(a);
	return (NULL);
}

/*
 * Some of a's records, about budget of them, into o: 1 if there are
 * more, 0 if a is done, -1 if a record could not be made
 */
int
facts_more(struct facts_answer *a, struct facts_out *o, int budget)
{
	int	 r = 0;

	if (a->done)
		return (0);
	switch (a->type) {
	case ANS_INTERFACE:
		if (a->ifn == NULL) {
			r = if_facts(o, a->name, a->detail);
			a->done = 1;
			return (r == -1 ? -1 : 0);
		}
		if (a->ifn[a->next].if_name == NULL) {
			a->done = 1;
			return (0);
		}
		if (if_facts(o, a->ifn[a->next++].if_name, a->detail) == -1)
			return (-1);
		return (1);
	case ANS_ROUTE:
		if (a->rt == NULL) {
			if ((a->rt = getrtdump(a->af, 0, a->table)) == NULL) {
				a->done = 1;
				return (0);
			}
			a->cur = a->rt->buf;
		}
		r = route_facts(o, a->rt, &a->cur, a->af, budget);
		if (r != 1)
			a->done = 1;
		return (r);
	case ANS_LOOKUP:
		a->done = 1;
		return (lookup_facts(o, a->query, a->table));
	}
	return (-1);
}

void
facts_answer_free(struct facts_answer *a)
{
	if (a == NULL)
		return;
	if (a->ifn != NULL)
		if_freenameindex(a->ifn);
	if (a->rt != NULL)
		freertdump(a->rt);
	free(a);
}

/* how nsh renders an answer, as the records come */
struct render {
	int			 status;	/* show interface status */
	FILE			*out;
	int			 routes;	/* routes rendered */
	struct frecs		 block;		/* an interface's records */
	const struct facts_kind	*kind[FACTS_KINDS];
	int			 map[FACTS_KINDS][FACTS_FIELDS];
};

static void
block_free(struct frecs *rs)
{
	struct frec	*r;

	while ((r = TAILQ_FIRST(rs)) != NULL) {
		TAILQ_REMOVE(rs, r, entry);
		facts_copy_free(r->t, r->v);
		free(r);
	}
}

static void
render_record(void *arg, const struct facts_template *t,
    const struct facts_value *v)
{
	struct render	*rd = arg;
	struct frec	*r;
	size_t		 i;

	/* bound once, to the kind nsh knows by its name, if any */
	if (rd->kind[t->id] == NULL) {
		for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++)
			if (strcmp(t->kind, kinds[i]->name) == 0) {
				rd->kind[t->id] = kinds[i];
				facts_bind(t, kinds[i], rd->map[t->id]);
			}
		if (rd->kind[t->id] == NULL)
			return;
	}
	if ((r = calloc(1, sizeof(*r))) == NULL)
		return;
	r->k = rd->kind[t->id];
	r->t = t;
	r->map = rd->map[t->id];
	if ((r->v = facts_copy(t, v)) == NULL) {
		free(r);
		return;
	}

	if (r->k == &kind_message) {
		if (fs(r, MSG_TEXT) != NULL)
			printf("%s", fs(r, MSG_TEXT));
	} else if (r->k == &kind_route) {
		route_render(r, &rd->routes);
		fflush(stdout);
	} else if (r->k == &kind_lookup)
		lookup_render(r);
	else {
		TAILQ_INSERT_TAIL(&rd->block, r, entry);
		if (r->k == &kind_interface) {
			if (rd->status)
				if_render_status(&rd->block, rd->out);
			else
				if_render(&rd->block, rd->out);
			block_free(&rd->block);
		}
		return;
	}
	facts_copy_free(t, r->v);
	free(r);
}

static void
render_emit(void *arg, const void *buf, size_t len)
{
	if (facts_read(arg, buf, len) == -1)
		printf("%% facts: a record nsh cannot read\n");
}

/*
 * The words fmt makes, asked of nshd, or of nsh itself where nshd does
 * not run, and rendered to out; "interface status" renders interfaces
 * as show interface status does
 */
int
facts_show(FILE *out, const char *fmt, ...)
{
	struct facts_answer	*a;
	struct facts_out	 o;
	struct facts_in		 in;
	struct render		 rd;
	va_list			 ap;
	char			*words, *w;
	int			 r;

	va_start(ap, fmt);
	r = vasprintf(&words, fmt, ap);
	va_end(ap);
	if (r == -1) {
		printf("%% facts_show: %s\n", strerror(errno));
		return (1);
	}

	facts_init();
	memset(&rd, 0, sizeof(rd));
	TAILQ_INIT(&rd.block);
	rd.out = out;
	w = words;
	if (strcmp(w, "interface status") == 0) {
		rd.status = 1;
		w = "interface";
	}
	facts_in_init(&in, render_record, &rd);
	if (rd.status)
		fputs("% Name    Status  Link        Routing-Domain  Media\n",
		    out);
	if ((r = nshd_facts(w, &in)) == -1) {
		if ((a = facts_answer(w)) == NULL) {
			printf("%% show %s: not a show nsh knows\n", w);
			facts_in_free(&in);
			free(words);
			return (1);
		}
		facts_out_init(&o, render_emit, &in);
		while ((r = facts_more(a, &o, 1024)) == 1)
			;
		facts_answer_free(a);
		r = r == 0;
	}
	block_free(&rd.block);
	facts_in_free(&in);
	free(words);
	return (r == 1 ? 0 : 1);
}
