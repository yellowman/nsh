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

/* Facts, written and read: facts.h has the units */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "facts.h"

/* a unit being written, which stops growing at FACTS_UNIT */
struct unit {
	uint8_t		 buf[FACTS_UNIT];
	size_t		 len;
	int		 full;
};

static void
put(struct unit *u, const void *p, size_t n)
{
	if (u->full || n > sizeof(u->buf) - u->len) {
		u->full = 1;
		return;
	}
	memcpy(u->buf + u->len, p, n);
	u->len += n;
}

static void
put8(struct unit *u, uint8_t v)
{
	put(u, &v, 1);
}

static void
put16(struct unit *u, uint16_t v)
{
	uint8_t	 b[2] = { v >> 8, v };

	put(u, b, sizeof(b));
}

static void
put32(struct unit *u, uint32_t v)
{
	uint8_t	 b[4] = { v >> 24, v >> 16, v >> 8, v };

	put(u, b, sizeof(b));
}

static void
put64(struct unit *u, uint64_t v)
{
	put32(u, v >> 32);
	put32(u, v);
}

static void
putstr(struct unit *u, const char *s, size_t n)
{
	if (n > UINT16_MAX) {
		u->full = 1;
		return;
	}
	put16(u, n);
	put(u, s, n);
}

void
facts_out_init(struct facts_out *o, void (*emit)(void *, const void *,
    size_t), void *arg)
{
	memset(o, 0, sizeof(*o));
	o->emit = emit;
	o->arg = arg;
}

/* k's template, as id, the first time o sends a record of k */
static int
template(struct facts_out *o, const struct facts_kind *k, uint16_t *id)
{
	struct unit	*u;
	size_t		 i, j;

	for (i = 0; i < o->nsent; i++)
		if (o->sent[i] == k) {
			*id = i;
			return (0);
		}
	if (o->nsent == FACTS_KINDS || k->nfields > FACTS_FIELDS ||
	    (u = calloc(1, sizeof(*u))) == NULL)
		return (-1);
	put8(u, FACTS_TEMPLATE);
	put16(u, o->nsent);
	putstr(u, k->name, strlen(k->name));
	put16(u, k->nfields);
	for (i = 0; i < k->nfields; i++) {
		putstr(u, k->fields[i].name, strlen(k->fields[i].name));
		put8(u, k->fields[i].type);
		put8(u, k->fields[i].naming);
		put16(u, k->fields[i].nnames);
		for (j = 0; j < k->fields[i].nnames; j++) {
			put64(u, k->fields[i].names[j].value);
			putstr(u, k->fields[i].names[j].name,
			    strlen(k->fields[i].names[j].name));
		}
	}
	if (u->full) {
		free(u);
		return (-1);
	}
	o->emit(o->arg, u->buf, u->len);
	free(u);
	*id = o->nsent;
	o->sent[o->nsent++] = k;
	return (0);
}

/* a record of k, its values in k's order; -1 if it is not one */
int
facts_record(struct facts_out *o, const struct facts_kind *k,
    const struct facts_value *v)
{
	struct unit	*u;
	uint16_t	 id;
	size_t		 i;

	if (template(o, k, &id) == -1 ||
	    (u = calloc(1, sizeof(*u))) == NULL)
		return (-1);
	put8(u, FACTS_RECORD);
	put16(u, id);
	for (i = 0; i < k->nfields; i++) {
		if (v[i].type != FACT_NONE && v[i].type != k->fields[i].type)
			u->full = 1;
		put8(u, v[i].type);
		switch (v[i].type) {
		case FACT_U64:
			put64(u, v[i].v.u);
			break;
		case FACT_I64:
			put64(u, (uint64_t)v[i].v.i);
			break;
		case FACT_STRING:
			putstr(u, v[i].v.str.s, v[i].v.str.len);
			break;
		case FACT_ADDRESS:
			put8(u, v[i].v.a.family);
			put8(u, v[i].v.a.len);
			put(u, v[i].v.a.bytes, v[i].v.a.len);
			put32(u, v[i].v.a.scope);
			break;
		case FACT_TIME:
			put64(u, (uint64_t)v[i].v.t.sec);
			put32(u, v[i].v.t.nsec);
			break;
		}
	}
	if (u->full) {
		free(u);
		return (-1);
	}
	o->emit(o->arg, u->buf, u->len);
	free(u);
	return (0);
}

void
facts_u64(struct facts_value *v, uint64_t u)
{
	v->type = FACT_U64;
	v->v.u = u;
}

void
facts_i64(struct facts_value *v, int64_t i)
{
	v->type = FACT_I64;
	v->v.i = i;
}

/* s, which must outlive the record */
void
facts_string(struct facts_value *v, const char *s)
{
	v->type = FACT_STRING;
	v->v.str.s = s;
	v->v.str.len = strlen(s);
}

void
facts_time(struct facts_value *v, int64_t sec, uint32_t nsec)
{
	v->type = FACT_TIME;
	v->v.t.sec = sec;
	v->v.t.nsec = nsec;
}

void
facts_address(struct facts_value *v, uint8_t family, const void *bytes,
    size_t len, uint32_t scope)
{
	memset(&v->v.a, 0, sizeof(v->v.a));
	v->type = FACT_ADDRESS;
	v->v.a.family = family;
	if (len > FACTS_ADDRLEN)
		len = FACTS_ADDRLEN;
	v->v.a.len = len;
	memcpy(v->v.a.bytes, bytes, len);
	v->v.a.scope = scope;
}

/* a unit being read, which goes bad on any short read */
struct reader {
	const uint8_t	*p;
	size_t		 left;
	int		 bad;
};

static const void *
get(struct reader *r, size_t n)
{
	const void	*p = r->p;

	if (r->bad || n > r->left) {
		r->bad = 1;
		return (NULL);
	}
	r->p += n;
	r->left -= n;
	return (p);
}

static uint8_t
get8(struct reader *r)
{
	const uint8_t	*p = get(r, 1);

	return (p ? p[0] : 0);
}

static uint16_t
get16(struct reader *r)
{
	const uint8_t	*p = get(r, 2);

	return (p ? (uint16_t)(p[0] << 8 | p[1]) : 0);
}

static uint32_t
get32(struct reader *r)
{
	const uint8_t	*p = get(r, 4);

	return (p ? (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	    (uint32_t)p[2] << 8 | p[3] : 0);
}

static uint64_t
get64(struct reader *r)
{
	uint64_t	 v = (uint64_t)get32(r) << 32;

	return (v | get32(r));
}

/* a string, allocated with its NUL; NULL if bad */
static char *
getstr(struct reader *r)
{
	const char	*p;
	char		*s;
	uint16_t	 n;

	n = get16(r);
	if ((p = get(r, n)) == NULL || memchr(p, '\0', n) != NULL ||
	    (s = malloc(n + 1)) == NULL) {
		r->bad = 1;
		return (NULL);
	}
	memcpy(s, p, n);
	s[n] = '\0';
	return (s);
}

static void
template_free(struct facts_template *t)
{
	size_t	 i, j;

	if (t == NULL)
		return;
	for (i = 0; i < t->nfields; i++) {
		for (j = 0; j < t->fields[i].nnames; j++)
			free(t->fields[i].names[j].name);
		free(t->fields[i].names);
		free(t->fields[i].name);
	}
	free(t->fields);
	free(t->kind);
	free(t);
}

static struct facts_template *
template_read(struct reader *r, uint16_t id)
{
	struct facts_template	*t;
	struct facts_tfield	*f;
	size_t			 i, j;

	if ((t = calloc(1, sizeof(*t))) == NULL)
		return (NULL);
	t->id = id;
	t->kind = getstr(r);
	i = get16(r);
	if (r->bad || i > FACTS_FIELDS ||
	    (t->fields = calloc(i ? i : 1, sizeof(*t->fields))) == NULL) {
		template_free(t);
		return (NULL);
	}
	for (t->nfields = 0; t->nfields < i; t->nfields++) {
		f = &t->fields[t->nfields];
		f->name = getstr(r);
		f->type = get8(r);
		f->naming = get8(r);
		f->nnames = get16(r);
		if (r->bad || f->type == FACT_NONE || f->type > FACT_TIME ||
		    f->naming > FACT_VALUES || (f->names = calloc(f->nnames ?
		    f->nnames : 1, sizeof(*f->names))) == NULL) {
			f->nnames = 0;
			t->nfields++;
			template_free(t);
			return (NULL);
		}
		for (j = 0; j < f->nnames; j++) {
			f->names[j].value = get64(r);
			f->names[j].name = getstr(r);
		}
		if (r->bad) {
			t->nfields++;
			template_free(t);
			return (NULL);
		}
	}
	return (t);
}

static int
record_read(struct reader *r, const struct facts_template *t,
    struct facts_value *v)
{
	size_t	 i, n;

	for (i = 0; i < t->nfields; i++) {
		v[i].type = get8(r);
		if (v[i].type != FACT_NONE && v[i].type != t->fields[i].type)
			return (-1);
		switch (v[i].type) {
		case FACT_U64:
			v[i].v.u = get64(r);
			break;
		case FACT_I64:
			v[i].v.i = (int64_t)get64(r);
			break;
		case FACT_STRING:
			n = get16(r);
			v[i].v.str.len = n;
			if ((v[i].v.str.s = get(r, n)) != NULL &&
			    memchr(v[i].v.str.s, '\0', n) != NULL)
				return (-1);
			break;
		case FACT_ADDRESS:
			memset(&v[i].v.a, 0, sizeof(v[i].v.a));
			v[i].v.a.family = get8(r);
			n = get8(r);
			if (n > FACTS_ADDRLEN || v[i].v.a.family == 0 ||
			    v[i].v.a.family > FACT_LINK)
				return (-1);
			v[i].v.a.len = n;
			if (get(r, n) != NULL)
				memcpy(v[i].v.a.bytes, r->p - n, n);
			v[i].v.a.scope = get32(r);
			break;
		case FACT_TIME:
			v[i].v.t.sec = (int64_t)get64(r);
			v[i].v.t.nsec = get32(r);
			break;
		}
		if (r->bad)
			return (-1);
	}
	return (0);
}

void
facts_in_init(struct facts_in *in, void (*record)(void *,
    const struct facts_template *, const struct facts_value *), void *arg)
{
	memset(in, 0, sizeof(*in));
	in->record = record;
	in->arg = arg;
}

/*
 * One unit: a template kept, or a record given to in->record; -1 if
 * it is not one, or names a template not sent, or one sent twice
 */
int
facts_read(struct facts_in *in, const void *buf, size_t len)
{
	struct reader		 r = { buf, len, 0 };
	struct facts_value	 v[FACTS_FIELDS];
	struct facts_template	*t;
	uint8_t			 what;
	uint16_t		 id;

	what = get8(&r);
	id = get16(&r);
	if (r.bad || id >= FACTS_KINDS)
		return (-1);
	switch (what) {
	case FACTS_TEMPLATE:
		if (in->t[id] != NULL || (t = template_read(&r, id)) == NULL)
			return (-1);
		if (r.left != 0) {
			template_free(t);
			return (-1);
		}
		in->t[id] = t;
		return (0);
	case FACTS_RECORD:
		if ((t = in->t[id]) == NULL ||
		    record_read(&r, t, v) == -1 || r.left != 0)
			return (-1);
		in->record(in->arg, t, v);
		return (0);
	}
	return (-1);
}

void
facts_in_free(struct facts_in *in)
{
	size_t	 i;

	for (i = 0; i < FACTS_KINDS; i++) {
		template_free(in->t[i]);
		in->t[i] = NULL;
	}
}

/* map[i]: where k's field i is in t, by name and type, or -1 */
void
facts_bind(const struct facts_template *t, const struct facts_kind *k,
    int *map)
{
	size_t	 i, j;

	for (i = 0; i < k->nfields; i++) {
		map[i] = -1;
		for (j = 0; j < t->nfields; j++)
			if (strcmp(t->fields[j].name, k->fields[i].name) == 0 &&
			    t->fields[j].type == k->fields[i].type) {
				map[i] = j;
				break;
			}
	}
}

/* field i of a record, through a map facts_bind() made; NULL if absent */
const struct facts_value *
facts_get(const struct facts_value *v, const int *map, size_t i,
    uint8_t type)
{
	if (map[i] == -1 || v[map[i]].type != type)
		return (NULL);
	return (&v[map[i]]);
}

/* v, kept past the record: its strings copied */
struct facts_value *
facts_copy(const struct facts_template *t, const struct facts_value *v)
{
	struct facts_value	*c;
	char			*s;
	size_t			 i;

	if ((c = calloc(t->nfields ? t->nfields : 1, sizeof(*c))) == NULL)
		return (NULL);
	for (i = 0; i < t->nfields; i++) {
		c[i] = v[i];
		if (v[i].type != FACT_STRING)
			continue;
		if ((s = malloc(v[i].v.str.len + 1)) == NULL) {
			c[i].type = FACT_NONE;
			facts_copy_free(t, c);
			return (NULL);
		}
		memcpy(s, v[i].v.str.s, v[i].v.str.len);
		s[v[i].v.str.len] = '\0';
		c[i].v.str.s = s;
	}
	return (c);
}

void
facts_copy_free(const struct facts_template *t, struct facts_value *c)
{
	size_t	 i;

	if (c == NULL)
		return;
	for (i = 0; i < t->nfields; i++)
		if (c[i].type == FACT_STRING)
			free((char *)c[i].v.str.s);
	free(c);
}

/* a string value, with its NUL, allocated */
char *
facts_strdup(const struct facts_value *v)
{
	char	*s;

	if ((s = malloc(v->v.str.len + 1)) == NULL)
		return (NULL);
	memcpy(s, v->v.str.s, v->v.str.len);
	s[v->v.str.len] = '\0';
	return (s);
}
