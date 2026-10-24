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
 *	arp table [address]		the ARP table, or one entry
 *	ndp table [address]		the neighbor cache, or one entry
 *	vlan [tag [tag]]		VLANs: all, one tag, or a range
 *	bridge [name]			bridges, or one
 *	statistics group		a group of kernel statistics
 *	version				what runs, and since when
 *	users				who is logged in
 *	daemons				the daemons nsh starts, and which
 *					run, in which routing tables
 *	hostname			the host's name
 *	ip [inet|inet6]			every address, and, from system,
 *					what configured each IPv4 one
 *	autoconf [name]			what dhcpleased and slaacd know,
 *					from system
 *	sadb				the SPD's IPsec flows
 *	program table prot sub [arg...]	what show prot sub runs, as
 *					text, from system
 *	dhcp leases			dhcpd's leases, as text, from
 *					system
 *
 * statistics pf, too, comes from system, as it needs /dev/pf. system
 * runs a program, or reads the leases, in a child of its own, and
 * streams what it prints as messages, as the client reads them.
 *
 * nshd's show processes answer them a batch at a time, as the client
 * reads; nsh asks nshd, or, where nshd does not run, answers them
 * itself. Either way nsh renders the records as the text it printed
 * before. An interface's or a bridge's records come before its own
 * record, which ends them. What a collector prints, as nsh's helpers
 * always have, reaches the terminal here, and nshd sends it as a
 * message.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <errno.h>
#include <limits.h>
#include <netdb.h>
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
	&kind_umbdns, &kind_trunkport, &kind_bridgemember, &kind_bridgeaddr,
	&kind_bridge, &kind_arp, &kind_ndp, &kind_vlan, &kind_version,
	&kind_login, &kind_hostname, &kind_ip, &kind_dhcplease,
	&kind_dhcproute, &kind_dhcpns, &kind_slaacif, &kind_slaacra,
	&kind_slaacprefix, &kind_slaacrdns, &kind_slaacaddr, &kind_slaacdfr,
	&kind_slaacdns, &kind_flow, &kind_daemon
};

enum answer_type {
	ANS_INTERFACE, ANS_ROUTE, ANS_LOOKUP, ANS_ARP, ANS_NDP, ANS_VLAN,
	ANS_BRIDGE, ANS_STATISTICS, ANS_VERSION, ANS_USERS, ANS_HOSTNAME,
	ANS_IP, ANS_AUTOCONF, ANS_SADB, ANS_PROGRAM, ANS_LEASES, ANS_DAEMONS
};

int	facts_from = FACTS_SHOW | FACTS_SYSTEM;

struct facts_answer {
	enum answer_type	 type;
	int			 where;		/* who answers */
	char			*copy;		/* the words, split */
	char			*w[4 + NOPTFILL - 1];
	int			 n;
	struct prot1		*prog;		/* the show a program makes */
	char			*args[NOPTFILL];	/* and its arguments */
	char			 name[IFNAMSIZ];	/* one interface */
	int			 detail;	/* interface detail */
	int			 af;
	int			 table;
	int			 one;		/* arp, ndp: one address */
	struct in_addr		 in;
	struct sockaddr_in6	 sin6;
	int			 start, end;	/* vlan tags, or -1 */
	struct statgroup	*stats;
	struct if_nameindex	*ifn;		/* every interface */
	size_t			 next;
	struct rtdump		*rt;
	char			*cur;
	int			 done;
};

/* names for the bits that s names (a string for bprintf()), in f */
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
	arp_facts_init();
	ndp_facts_init();
	stats_facts_init();
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

/* len bytes of text as a message, a NUL in them shown as '?' */
int
facts_text(struct facts_out *o, const char *buf, size_t len)
{
	char	*s;
	size_t	 i;
	int	 r;

	if ((s = malloc(len + 1)) == NULL)
		return (-1);
	for (i = 0; i < len; i++)
		s[i] = buf[i] == '\0' ? '?' : buf[i];
	s[len] = '\0';
	r = facts_message(o, "%s", s);
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

static int
answer_table(struct facts_answer *a, const char *w)
{
	const char	*errstr;

	a->table = strtonum(w, 0, RT_TABLEID_MAX, &errstr);
	return (errstr ? -1 : 0);
}

static int
answer_tag(int *tag, const char *w)
{
	const char	*errstr;

	*tag = strtonum(w, EVL_VLID_NULL, EVL_VLID_MAX, &errstr);
	return (errstr ? -1 : 0);
}

/* what words ask, or NULL if they ask nothing a show answers */
struct facts_answer *
facts_answer(char *words)
{
	struct facts_answer	*a;
	struct addrinfo		 hints, *res;
	char			*p, *last, **w;
	int			 n;

	facts_init();
	if ((a = calloc(1, sizeof(*a))) == NULL)
		return (NULL);
	if ((a->copy = strdup(words)) == NULL)
		goto bad;
	for (p = strtok_r(a->copy, " ", &last); p != NULL;
	    p = strtok_r(NULL, " ", &last)) {
		if (a->n == sizeof(a->w) / sizeof(a->w[0]))
			goto bad;
		a->w[a->n++] = p;
	}
	w = a->w;
	n = a->n;
	a->start = a->end = -1;
	a->where = FACTS_SHOW;
	if (n == 0)
		goto bad;
	if (n <= 3 && strcmp(w[0], "interface") == 0) {
		a->type = ANS_INTERFACE;
		if (n > 1 && strcmp(w[n - 1], "detail") == 0) {
			a->detail = 1;
			n--;
		}
		if (n == 3 || (n == 2 && strlcpy(a->name, w[1],
		    sizeof(a->name)) >= sizeof(a->name)))
			goto bad;
	} else if (n == 3 && strcmp(w[0], "route") == 0) {
		a->type = ANS_ROUTE;
		if (strcmp(w[1], "inet") == 0)
			a->af = AF_INET;
		else if (strcmp(w[1], "inet6") == 0)
			a->af = AF_INET6;
		else
			goto bad;
		if (answer_table(a, w[2]) == -1)
			goto bad;
	} else if (n == 3 && strcmp(w[0], "lookup") == 0) {
		a->type = ANS_LOOKUP;
		if (strlen(w[1]) >= INET6_ADDRSTRLEN + 5 ||
		    answer_table(a, w[2]) == -1)
			goto bad;
	} else if ((n == 2 || n == 3) && strcmp(w[0], "arp") == 0) {
		a->type = ANS_ARP;
		if (answer_table(a, w[1]) == -1)
			goto bad;
		if (n == 3 && inet_pton(AF_INET, w[2], &a->in) != 1)
			goto bad;
		a->one = n == 3;
	} else if ((n == 2 || n == 3) && strcmp(w[0], "ndp") == 0) {
		a->type = ANS_NDP;
		if (answer_table(a, w[1]) == -1)
			goto bad;
		if (n == 3) {
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET6;
			hints.ai_flags = AI_NUMERICHOST;
			if (getaddrinfo(w[2], NULL, &hints, &res) != 0)
				goto bad;
			memcpy(&a->sin6, res->ai_addr, sizeof(a->sin6));
			freeaddrinfo(res);
			a->one = 1;
		}
	} else if (n <= 3 && strcmp(w[0], "vlan") == 0) {
		a->type = ANS_VLAN;
		if ((n > 1 && answer_tag(&a->start, w[1]) == -1) ||
		    (n > 2 && answer_tag(&a->end, w[2]) == -1))
			goto bad;
	} else if (n <= 2 && strcmp(w[0], "bridge") == 0)
		a->type = ANS_BRIDGE;
	else if (n == 2 && strcmp(w[0], "statistics") == 0) {
		a->type = ANS_STATISTICS;
		if ((a->stats = stats_group(w[1])) == NULL)
			goto bad;
		a->where = stats_where(a->stats);
	} else if (n <= 2 && strcmp(w[0], "ip") == 0) {
		a->type = ANS_IP;
		a->where = FACTS_SHOW | FACTS_SYSTEM;
		a->af = AF_UNSPEC;
		if (n == 2 && strcmp(w[1], "inet") == 0)
			a->af = AF_INET;
		else if (n == 2 && strcmp(w[1], "inet6") == 0)
			a->af = AF_INET6;
		else if (n == 2)
			goto bad;
	} else if (n <= 2 && strcmp(w[0], "autoconf") == 0) {
		a->type = ANS_AUTOCONF;
		a->where = FACTS_SYSTEM;
		if (n == 2 && strlcpy(a->name, w[1], sizeof(a->name)) >=
		    sizeof(a->name))
			goto bad;
	} else if (n == 1 && strcmp(w[0], "sadb") == 0)
		a->type = ANS_SADB;
	else if (n >= 4 && strcmp(w[0], "program") == 0) {
		a->type = ANS_PROGRAM;
		a->where = FACTS_SYSTEM;
		if (answer_table(a, w[1]) == -1 ||
		    (a->prog = prot1_find(w[2], w[3])) == NULL)
			goto bad;
	} else if (n == 2 && strcmp(w[0], "dhcp") == 0 &&
	    strcmp(w[1], "leases") == 0) {
		a->type = ANS_LEASES;
		a->where = FACTS_SYSTEM;
	} else if (n == 1 && strcmp(w[0], "version") == 0)
		a->type = ANS_VERSION;
	else if (n == 1 && strcmp(w[0], "users") == 0)
		a->type = ANS_USERS;
	else if (n == 1 && strcmp(w[0], "daemons") == 0) {
		a->type = ANS_DAEMONS;
		a->where = FACTS_SHOW | FACTS_SYSTEM;
	}
	else if (n == 1 && strcmp(w[0], "hostname") == 0)
		a->type = ANS_HOSTNAME;
	else
		goto bad;
	if ((a->where & facts_from) == 0)
		goto bad;
	return (a);
bad:
	facts_answer_free(a);
	return (NULL);
}

/*
 * Some of a's records, about budget of them, into o: 1 if there are
 * more, 0 if a is done, -1 if it failed
 */
int
facts_more(struct facts_answer *a, struct facts_out *o, int budget)
{
	char	**args;
	int	  r = 0;

	if (a->done)
		return (0);
	switch (a->type) {
	case ANS_INTERFACE:
		if (a->name[0] != '\0')
			r = if_facts(o, a->name, a->detail);
		else if (a->ifn == NULL && (a->ifn = if_nameindex()) == NULL) {
			printf("%% if_nameindex: %s\n", strerror(errno));
			r = -1;
		} else if (a->ifn[a->next].if_name != NULL)
			return (if_facts(o, a->ifn[a->next++].if_name,
			    a->detail) == -1 ? -1 : 1);
		break;
	case ANS_ROUTE:
	case ANS_ARP:
	case ANS_NDP:
	case ANS_SADB:
		if (a->rt == NULL) {
			if (a->type == ANS_SADB) {
				/* said why, unless there is no IPsec */
				if ((a->rt = sadb_dump()) == NULL) {
					r = -1;
					break;
				}
			} else if (a->type == ANS_ROUTE)
				a->rt = getrtdump(a->af, 0, a->table);
			else
				a->rt = getrtdump(a->type == ANS_ARP ?
				    AF_INET : AF_INET6, RTF_LLINFO, a->table);
			if (a->rt == NULL)
				break;
			a->cur = a->rt->buf;
		}
		if (a->type == ANS_SADB)
			r = sadb_facts(o, a->rt, &a->cur, budget);
		else if (a->type == ANS_ROUTE)
			r = route_facts(o, a->rt, &a->cur, a->af, budget);
		else if (a->type == ANS_ARP)
			r = arp_facts(o, a->rt, &a->cur, a->one ? &a->in :
			    NULL, budget);
		else
			r = ndp_facts(o, a->rt, &a->cur, a->one ? &a->sin6 :
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
		/* whether pf runs, only where system's are */
		r = daemons_facts(o, (facts_from & FACTS_SYSTEM) != 0);
		break;
	case ANS_HOSTNAME:
		r = hostname_facts(o);
		break;
	case ANS_IP:
		/* what configured an address, only where system's are */
		r = ip_facts(o, a->af, (facts_from & FACTS_SYSTEM) != 0);
		break;
	case ANS_AUTOCONF:
		r = autoconf_facts(o, a->name[0] != '\0' ? a->name : NULL);
		break;
	case ANS_PROGRAM:
		/* as nsh runs a program, and as it pages a file */
		if ((args = prot1_args(a->prog, a->args, a->n - 4, a->w + 4,
		    a->table)) == NULL || cmdargs(args[0], args) != 0)
			r = -1;
		break;
	case ANS_LEASES:
		if (!more(DHCPLEASES))
			r = -1;
		break;
	}
	a->done = 1;
	return (r == -1 ? -1 : 0);
}

/*
 * Whether a's show is text nshd's system streams, from a child, and
 * what: FACTS_PROGRAM, the program and its arguments in *argv, which
 * are a's, and the routing table it runs in in *table; or
 * FACTS_LEASES. 0 if it is not, or -1 if a's words do not fill the
 * program's arguments, said why
 */
int
facts_streams(struct facts_answer *a, char ***argv, int *table)
{
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

void
facts_answer_free(struct facts_answer *a)
{
	if (a == NULL)
		return;
	if (a->ifn != NULL)
		if_freenameindex(a->ifn);
	if (a->rt != NULL)
		freertdump(a->rt);
	free(a->copy);
	free(a);
}

/* how nsh renders an answer, as the records come */
struct render {
	int			 status;	/* show interface status */
	FILE			*out;
	int			 count;		/* records rendered */
	char			 failed[NI_MAXHOST];	/* ndp: no info */
	struct frecs		 block;		/* records before their end */
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
	struct render		*rd = arg;
	const struct facts_kind	*k = NULL;
	struct frec		*r;
	size_t			 i;

	/* bound once, to the kind nsh knows by its name, if any */
	if (rd->kind[t->id] == NULL) {
		for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++)
			if (strcmp(t->kind, kinds[i]->name) == 0)
				k = kinds[i];
		if (k == NULL && (k = stats_kind(t->kind)) == NULL)
			return;
		rd->kind[t->id] = k;
		facts_bind(t, k, rd->map[t->id]);
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
		route_render(r, &rd->count);
		fflush(stdout);
	} else if (r->k == &kind_lookup)
		lookup_render(r);
	else if (r->k == &kind_arp) {
		arp_render(r);
		rd->count++;
	} else if (r->k == &kind_ndp) {
		ndp_render(r, rd->failed, sizeof(rd->failed));
		rd->count++;
	} else if (r->k == &kind_vlan)
		vlan_render(r, rd->count++);
	else if (r->k == &kind_login)
		users_render(r, rd->count++);
	else if (r->k == &kind_daemon)
		daemons_render(r, rd->count++);
	else if (r->k == &kind_version)
		version_render(r);
	else if (r->k == &kind_hostname)
		hostname_render(r);
	else if (r->k == &kind_flow)
		sadb_render(r, &rd->count);
	else if (r->k == stats_kind(r->k->name))
		stats_render(r);
	else {
		TAILQ_INSERT_TAIL(&rd->block, r, entry);
		if (r->k == &kind_interface) {
			if (rd->status)
				if_render_status(&rd->block, rd->out);
			else
				if_render(&rd->block, rd->out);
			block_free(&rd->block);
		} else if (r->k == &kind_bridge) {
			bridge_show_render(&rd->block, r, rd->count++);
			block_free(&rd->block);
		} else if (r->k == &kind_dhcplease || r->k == &kind_slaacif) {
			autoconf_render(&rd->block, r);
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
 * show prot sub, a daemon's, with the argc words of argv: nshd's system
 * runs its program, or nsh where nshd does not run; as a handler returns.
 * bgpnsh runs it itself, with args.
 */
int
prot1_run(char *prot, char *sub, int argc, char **argv, char **args)
{
	char	 words[NOPTFILL * 64];
	int	 i;

	words[0] = '\0';
	for (i = 0; i < argc; i++) {
		/* a show's words have no space, none is empty, and they fit */
		if (argv[i][0] == '\0' || strchr(argv[i], ' ') != NULL ||
		    strlcat(words, " ", sizeof(words)) >= sizeof(words) ||
		    strlcat(words, argv[i], sizeof(words)) >= sizeof(words)) {
			printf("%% Invalid argument %s\n", argv[i]);
			return (-1);
		}
	}
	return (facts_show(stdout, "program %d %s %s%s", cli_rtable, prot,
	    sub, words));
}

/* a record of an operation's, which says nothing */
static void
ignore_record(void *arg, const struct facts_template *t,
    const struct facts_value *v)
{
}

/*
 * The operation text, in rtable, which nshd's system runs, what it
 * prints shown, but if quiet: its status, 0, OP_DIFFERS, or another
 * if it failed, said why
 */
int
facts_op(const char *text, int rtable, int quiet)
{
	struct facts_in		 in;
	struct render		 rd;
	int			 r;

	memset(&rd, 0, sizeof(rd));
	TAILQ_INIT(&rd.block);
	rd.out = stdout;
	facts_in_init(&in, quiet ? ignore_record : render_record, &rd);
	r = nshd_op(text, rtable, &in);
	block_free(&rd.block);
	facts_in_free(&in);
	return (r);
}

/*
 * The words fmt makes, asked of nshd, its system where they may be and
 * this user may ask it, else its shows, or of nsh itself where nshd
 * does not run, and rendered to out; "interface status" renders
 * interfaces as show interface status does: 0, or -1 if the show
 * failed, having said why, as a handler returns
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
		return (-1);
	}

	memset(&rd, 0, sizeof(rd));
	TAILQ_INIT(&rd.block);
	rd.out = out;
	w = words;
	if (strcmp(w, "interface status") == 0) {
		rd.status = 1;
		w = "interface";
	}
	if ((a = facts_answer(w)) == NULL) {
		printf("%% show %s: not a show nsh knows\n", w);
		free(words);
		return (-1);
	}
	facts_in_init(&in, render_record, &rd);
	if (rd.status)
		fputs("% Name    Status  Link        Routing-Domain  Media\n",
		    out);
	else if (a->type == ANS_ARP)
		arp_header();
	else if (a->type == ANS_NDP)
		ndp_header();
	r = -1;
	if (a->where & FACTS_SYSTEM)
		r = nshd_facts(1, w, &in);
	if (r == -1 && (a->where & FACTS_SHOW))
		r = nshd_facts(0, w, &in);
	if (r == -1) {
		facts_out_init(&o, render_emit, &in);
		while ((r = facts_more(a, &o, 1024)) == 1)
			;
		r = r == 0;
	}

	/* what a show prints after its records, or for none */
	switch (a->type) {
	case ANS_ARP:
		if (a->one && rd.count == 0)
			arp_noentry(a->w[2]);
		break;
	case ANS_NDP:
		ndp_end(rd.failed, a->one && rd.count == 0 ? a->w[2] : NULL);
		break;
	case ANS_VLAN:
		if (r == 1 && rd.count == 0)
			vlan_none(a->start, a->end);
		break;
	case ANS_USERS:
		if (r == 1)
			users_end(rd.count);
		break;
	case ANS_IP:
		if (r == 1)
			ip_render(&rd.block);
		break;
	case ANS_SADB:
		if (r == 1 && rd.count == 0)
			printf("%% SADB empty\n");
		break;
	default:
		break;
	}
	block_free(&rd.block);
	facts_answer_free(a);
	facts_in_free(&in);
	free(words);
	return (r == 1 ? 0 : -1);
}
