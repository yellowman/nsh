/*
 * Unit tests for facts.c: the units nshd's show process writes and the
 * client reads. The reader takes its input from another process, so
 * besides round trips these check that every malformed unit is refused
 * and that random damage to valid units never crashes the reader.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../facts.h"
#include "test.h"

/* units an answer emitted */
#define MAXUNITS	64

struct sink {
	uint8_t	*buf[MAXUNITS];
	size_t	 len[MAXUNITS];
	size_t	 n;
};

static void
emit(void *arg, const void *p, size_t len)
{
	struct sink *s = arg;

	if (s->n == MAXUNITS)
		return;
	if ((s->buf[s->n] = malloc(len ? len : 1)) == NULL)
		return;
	memcpy(s->buf[s->n], p, len);
	s->len[s->n++] = len;
}

static void
sink_free(struct sink *s)
{
	size_t i;

	for (i = 0; i < s->n; i++)
		free(s->buf[i]);
	memset(s, 0, sizeof(*s));
}

/* what the reader got: the last record, copied */
struct got {
	int				 nrecords;
	const struct facts_template	*t;
	struct facts_value		*v;
};

static void
record(void *arg, const struct facts_template *t, const struct facts_value *v)
{
	struct got *g = arg;

	if (g->v != NULL)
		facts_copy_free(g->t, g->v);
	g->t = t;
	g->v = facts_copy(t, v);
	g->nrecords++;
}

static void
got_free(struct got *g)
{
	if (g->v != NULL)
		facts_copy_free(g->t, g->v);
	memset(g, 0, sizeof(*g));
}

/* An interface-like kind with one field of each type */
static const struct facts_name flagnames[] = {
	{ 0x1, "UP" },
	{ 0x2, "BROADCAST" },
};

static const struct facts_field iffields[] = {
	{ "name",	FACT_STRING,	FACT_PLAIN,	NULL,	   0 },
	{ "mtu",	FACT_U64,	FACT_PLAIN,	NULL,	   0 },
	{ "metric",	FACT_I64,	FACT_PLAIN,	NULL,	   0 },
	{ "flags",	FACT_U64,	FACT_BITS,	flagnames, 2 },
	{ "address",	FACT_ADDRESS,	FACT_PLAIN,	NULL,	   0 },
	{ "changed",	FACT_TIME,	FACT_PLAIN,	NULL,	   0 },
};
#define IF_NAME		0
#define IF_MTU		1
#define IF_METRIC	2
#define IF_FLAGS	3
#define IF_ADDRESS	4
#define IF_CHANGED	5
#define IF_NFIELDS	6

static const struct facts_kind ifkind = { "interface", iffields, IF_NFIELDS };

static const struct facts_field rtfields[] = {
	{ "destination", FACT_ADDRESS,	FACT_PLAIN,	NULL,	0 },
};
static const struct facts_kind rtkind = { "route", rtfields, 1 };

static const uint8_t v4[4] = { 192, 0, 2, 1 };

static void
fill_if(struct facts_value *v)
{
	memset(v, 0, sizeof(*v) * IF_NFIELDS);
	facts_string(&v[IF_NAME], "em0");
	facts_u64(&v[IF_MTU], 1500);
	facts_i64(&v[IF_METRIC], -7);
	facts_u64(&v[IF_FLAGS], 0x3);
	facts_address(&v[IF_ADDRESS], FACT_INET, v4, sizeof(v4), 0);
	facts_time(&v[IF_CHANGED], 1760000000, 999999999);
}

/* Write one interface record; s gets its template and record units */
static int
write_if(struct sink *s)
{
	struct facts_out o;
	struct facts_value v[IF_NFIELDS];

	fill_if(v);
	facts_out_init(&o, emit, s);
	return facts_record(&o, &ifkind, v);
}

/* Read every unit in s; -1 if any was refused */
static int
read_all(struct sink *s, struct got *g)
{
	struct facts_in in;
	size_t i;
	int rv = 0;

	facts_in_init(&in, record, g);
	for (i = 0; i < s->n; i++)
		if (facts_read(&in, s->buf[i], s->len[i]) == -1)
			rv = -1;
	/* keep g's record readable after the templates go */
	if (g->v != NULL) {
		facts_copy_free(g->t, g->v);
		g->v = NULL;
	}
	facts_in_free(&in);
	return rv;
}

static void
test_roundtrip(void)
{
	struct sink s = { 0 };
	struct facts_in in;
	struct got g = { 0 };
	const struct facts_value *v;
	int map[IF_NFIELDS];
	size_t i;
	char *str;

	CHECK(write_if(&s) == 0);
	CHECK(s.n == 2);	/* the template, then the record */
	if (s.n != 2) {
		sink_free(&s);
		return;
	}
	CHECK(s.buf[0][0] == FACTS_TEMPLATE);
	CHECK(s.buf[1][0] == FACTS_RECORD);

	facts_in_init(&in, record, &g);
	for (i = 0; i < s.n; i++)
		CHECK(facts_read(&in, s.buf[i], s.len[i]) == 0);
	CHECK(g.nrecords == 1);
	CHECK(g.t != NULL && g.v != NULL);
	if (g.t == NULL || g.v == NULL)
		goto out;

	CHECK_STR(g.t->kind, "interface");
	CHECK(g.t->nfields == IF_NFIELDS);
	CHECK_STR(g.t->fields[IF_FLAGS].name, "flags");
	CHECK(g.t->fields[IF_FLAGS].naming == FACT_BITS);
	CHECK(g.t->fields[IF_FLAGS].nnames == 2);
	CHECK_STR(g.t->fields[IF_FLAGS].names[1].name, "BROADCAST");
	CHECK(g.t->fields[IF_FLAGS].names[1].value == 0x2);

	facts_bind(g.t, &ifkind, map);
	for (i = 0; i < IF_NFIELDS; i++)
		CHECK(map[i] == (int)i);

	v = facts_get(g.v, map, IF_NAME, FACT_STRING);
	CHECK(v != NULL);
	if (v != NULL) {
		str = facts_strdup(v);
		CHECK_STR(str, "em0");
		free(str);
	}
	v = facts_get(g.v, map, IF_MTU, FACT_U64);
	CHECK(v != NULL && v->v.u == 1500);
	v = facts_get(g.v, map, IF_METRIC, FACT_I64);
	CHECK(v != NULL && v->v.i == -7);
	v = facts_get(g.v, map, IF_ADDRESS, FACT_ADDRESS);
	CHECK(v != NULL && v->v.a.family == FACT_INET && v->v.a.len == 4 &&
	    memcmp(v->v.a.bytes, v4, 4) == 0);
	v = facts_get(g.v, map, IF_CHANGED, FACT_TIME);
	CHECK(v != NULL && v->v.t.sec == 1760000000 &&
	    v->v.t.nsec == 999999999);
	/* asking for the wrong type finds nothing */
	CHECK(facts_get(g.v, map, IF_MTU, FACT_STRING) == NULL);
out:
	if (g.v != NULL)
		facts_copy_free(g.t, g.v);
	facts_in_free(&in);
	sink_free(&s);
}

static void
test_extremes(void)
{
	struct sink s = { 0 };
	struct facts_out o;
	struct facts_in in;
	struct facts_value v[IF_NFIELDS];
	struct got g = { 0 };
	uint8_t a6[16];
	size_t i;

	memset(a6, 0xff, sizeof(a6));
	fill_if(v);
	facts_string(&v[IF_NAME], "");
	facts_u64(&v[IF_MTU], UINT64_MAX);
	facts_i64(&v[IF_METRIC], INT64_MIN);
	facts_address(&v[IF_ADDRESS], FACT_INET6, a6, sizeof(a6), 0xffffffff);
	facts_time(&v[IF_CHANGED], -1, 0);

	facts_out_init(&o, emit, &s);
	CHECK(facts_record(&o, &ifkind, v) == 0);
	facts_in_init(&in, record, &g);
	for (i = 0; i < s.n; i++)
		CHECK(facts_read(&in, s.buf[i], s.len[i]) == 0);
	if (g.v != NULL) {
		CHECK(g.v[IF_NAME].type == FACT_STRING &&
		    g.v[IF_NAME].v.str.len == 0);
		CHECK(g.v[IF_MTU].v.u == UINT64_MAX);
		CHECK(g.v[IF_METRIC].v.i == INT64_MIN);
		CHECK(g.v[IF_ADDRESS].v.a.len == 16 &&
		    g.v[IF_ADDRESS].v.a.scope == 0xffffffff);
		CHECK(g.v[IF_CHANGED].v.t.sec == -1);
		facts_copy_free(g.t, g.v);
	} else
		CHECK(g.v != NULL);
	facts_in_free(&in);
	sink_free(&s);
}

static void
test_absent_fields(void)
{
	struct sink s = { 0 };
	struct facts_out o;
	struct facts_in in;
	struct facts_value v[IF_NFIELDS];
	struct got g = { 0 };
	size_t i;

	memset(v, 0, sizeof(v));		/* every field FACT_NONE */
	facts_string(&v[IF_NAME], "lo0");
	facts_out_init(&o, emit, &s);
	CHECK(facts_record(&o, &ifkind, v) == 0);
	facts_in_init(&in, record, &g);
	for (i = 0; i < s.n; i++)
		CHECK(facts_read(&in, s.buf[i], s.len[i]) == 0);
	CHECK(g.nrecords == 1);
	if (g.v != NULL) {
		CHECK(g.v[IF_NAME].type == FACT_STRING);
		for (i = 1; i < IF_NFIELDS; i++)
			CHECK(g.v[i].type == FACT_NONE);
		facts_copy_free(g.t, g.v);
	}
	facts_in_free(&in);
	sink_free(&s);
}

static void
test_templates_sent_once(void)
{
	struct sink s = { 0 };
	struct facts_out o;
	struct facts_value v[IF_NFIELDS], rv[1];
	struct got g = { 0 };
	size_t i, ntemplates = 0;

	fill_if(v);
	memset(rv, 0, sizeof(rv));
	facts_address(&rv[0], FACT_INET, v4, sizeof(v4), 0);

	facts_out_init(&o, emit, &s);
	CHECK(facts_record(&o, &ifkind, v) == 0);
	CHECK(facts_record(&o, &ifkind, v) == 0);
	CHECK(facts_record(&o, &rtkind, rv) == 0);
	CHECK(facts_record(&o, &ifkind, v) == 0);
	CHECK(facts_record(&o, &rtkind, rv) == 0);
	for (i = 0; i < s.n; i++)
		if (s.buf[i][0] == FACTS_TEMPLATE)
			ntemplates++;
	CHECK(ntemplates == 2);
	CHECK(s.n == 7);
	CHECK(read_all(&s, &g) == 0);
	CHECK(g.nrecords == 5);
	got_free(&g);
	sink_free(&s);
}

static void
test_writer_refuses(void)
{
	struct sink s = { 0 };
	struct facts_out o;
	struct facts_value v[IF_NFIELDS];
	static struct facts_kind kinds[FACTS_KINDS + 1];
	struct facts_value one[1];
	char *big;
	size_t i;

	facts_out_init(&o, emit, &s);

	/* a value of the wrong type for its field */
	fill_if(v);
	facts_u64(&v[IF_NAME], 1);
	CHECK(facts_record(&o, &ifkind, v) == -1);

	/* a record that does not fit in one unit */
	if ((big = malloc(FACTS_UNIT + 1)) != NULL) {
		memset(big, 'x', FACTS_UNIT);
		big[FACTS_UNIT] = '\0';
		fill_if(v);
		facts_string(&v[IF_NAME], big);
		CHECK(facts_record(&o, &ifkind, v) == -1);
		free(big);
	}

	/* no more than FACTS_KINDS kinds in one answer */
	sink_free(&s);
	facts_out_init(&o, emit, &s);
	memset(one, 0, sizeof(one));
	for (i = 0; i <= FACTS_KINDS; i++) {
		kinds[i].name = "k";
		kinds[i].fields = rtfields;
		kinds[i].nfields = 1;
	}
	for (i = 0; i < FACTS_KINDS; i++)
		CHECK(facts_record(&o, &kinds[i], one) == 0);
	CHECK(facts_record(&o, &kinds[FACTS_KINDS], one) == -1);
	sink_free(&s);
}

/* Read one unit into a fresh reader that already has s's template */
static int
read_with_template(struct sink *s, const uint8_t *unit, size_t len)
{
	struct facts_in in;
	struct got g = { 0 };
	int rv;

	facts_in_init(&in, record, &g);
	if (facts_read(&in, s->buf[0], s->len[0]) == -1) {
		facts_in_free(&in);
		return -2;
	}
	rv = facts_read(&in, unit, len);
	if (g.v != NULL)
		facts_copy_free(g.t, g.v);
	facts_in_free(&in);
	return rv;
}

static void
test_reader_refuses(void)
{
	struct sink s = { 0 };
	struct facts_in in;
	struct got g = { 0 };
	uint8_t *u, tmp[64];
	size_t len, i, off;
	int ok;

	if (write_if(&s) != 0 || s.n != 2) {
		CHECK(0);
		sink_free(&s);
		return;
	}
	u = s.buf[1];
	len = s.len[1];

	/* the valid record is taken */
	CHECK(read_with_template(&s, u, len) == 0);

	/* every truncation of a template or a record is refused */
	ok = 1;
	for (i = 0; i < len; i++)
		if (read_with_template(&s, u, i) != -1)
			ok = 0;
	CHECK(ok);
	facts_in_init(&in, record, &g);
	ok = 1;
	for (i = 0; i < s.len[0]; i++)
		if (facts_read(&in, s.buf[0], i) != -1)
			ok = 0;
	CHECK(ok);
	facts_in_free(&in);

	/* a partial unit after a whole one is refused */
	if ((u = malloc(len + 1)) != NULL) {
		memcpy(u, s.buf[1], len);
		u[len] = 0;
		CHECK(read_with_template(&s, u, len + 1) == -1);
		free(u);
	}

	/* a record before its template */
	facts_in_init(&in, record, &g);
	CHECK(facts_read(&in, s.buf[1], s.len[1]) == -1);
	CHECK(g.nrecords == 0);
	/* the same template twice */
	CHECK(facts_read(&in, s.buf[0], s.len[0]) == 0);
	CHECK(facts_read(&in, s.buf[0], s.len[0]) == -1);
	facts_in_free(&in);

	/* an id past FACTS_KINDS, and an unknown unit type */
	tmp[0] = FACTS_RECORD; tmp[1] = 0; tmp[2] = FACTS_KINDS;
	CHECK(read_with_template(&s, tmp, 3) == -1);
	tmp[0] = 9; tmp[1] = 0; tmp[2] = 0;
	CHECK(read_with_template(&s, tmp, 3) == -1);
	CHECK(read_with_template(&s, tmp, 0) == -1);

	/*
	 * Damage the record's values. Its layout: u8 unit, u16 id, then
	 * the name field: u8 type, u16 length, "em0".
	 */
	u = malloc(len);
	if (u == NULL) {
		sink_free(&s);
		return;
	}
	off = 3;
	memcpy(u, s.buf[1], len);
	u[off] = FACT_U64;			/* type not the field's */
	CHECK(read_with_template(&s, u, len) == -1);
	memcpy(u, s.buf[1], len);
	u[off + 4] = '\0';			/* a NUL inside "em0" */
	CHECK(read_with_template(&s, u, len) == -1);
	memcpy(u, s.buf[1], len);
	u[off + 1] = 0xff;			/* length past the unit */
	CHECK(read_with_template(&s, u, len) == -1);

	/*
	 * The address: after name (6), mtu (9), metric (9) and flags (9)
	 * comes u8 type, u8 family, u8 length.
	 */
	off = 3 + 6 + 9 + 9 + 9;
	memcpy(u, s.buf[1], len);
	CHECK(u[off] == FACT_ADDRESS);
	u[off + 1] = 0;				/* no family */
	CHECK(read_with_template(&s, u, len) == -1);
	memcpy(u, s.buf[1], len);
	u[off + 1] = FACT_LINK + 1;		/* unknown family */
	CHECK(read_with_template(&s, u, len) == -1);
	memcpy(u, s.buf[1], len);
	u[off + 2] = FACTS_ADDRLEN + 1;		/* longer than an address */
	CHECK(read_with_template(&s, u, len) == -1);
	free(u);
	sink_free(&s);
}

static void
test_template_refuses(void)
{
	/* hand-built templates: u8 unit, u16 id, kind, u16 fields, ... */
	static const uint8_t badtype[] = {
		FACTS_TEMPLATE, 0, 0, 0, 1, 'k', 0, 1,
		0, 1, 'f', FACT_TIME + 1, FACT_PLAIN, 0, 0
	};
	static const uint8_t nonetype[] = {
		FACTS_TEMPLATE, 0, 0, 0, 1, 'k', 0, 1,
		0, 1, 'f', FACT_NONE, FACT_PLAIN, 0, 0
	};
	static const uint8_t badnaming[] = {
		FACTS_TEMPLATE, 0, 0, 0, 1, 'k', 0, 1,
		0, 1, 'f', FACT_U64, FACT_VALUES + 1, 0, 0
	};
	static const uint8_t nulname[] = {
		FACTS_TEMPLATE, 0, 0, 0, 1, '\0', 0, 0
	};
	/* claims 65535 names but carries none */
	static const uint8_t manynames[] = {
		FACTS_TEMPLATE, 0, 0, 0, 1, 'k', 0, 1,
		0, 1, 'f', FACT_U64, FACT_BITS, 0xff, 0xff
	};
	static const uint8_t good[] = {
		FACTS_TEMPLATE, 0, 0, 0, 1, 'k', 0, 1,
		0, 1, 'f', FACT_U64, FACT_PLAIN, 0, 0
	};
	struct facts_in in;
	struct got g = { 0 };

#define REFUSED(u) do {							\
	facts_in_init(&in, record, &g);					\
	CHECK(facts_read(&in, u, sizeof(u)) == -1);			\
	facts_in_free(&in);						\
} while (0)
	REFUSED(badtype);
	REFUSED(nonetype);
	REFUSED(badnaming);
	REFUSED(nulname);
	REFUSED(manynames);
#undef REFUSED

	facts_in_init(&in, record, &g);
	CHECK(facts_read(&in, good, sizeof(good)) == 0);
	facts_in_free(&in);
}

/*
 * A hand-built template of n plain u64 fields, each named "f", whole:
 * the reader must judge it by its count, not run out of bytes
 */
static uint8_t *
template_of(size_t n, size_t *lenp)
{
	uint8_t *u, *p;
	size_t len = 1 + 2 + 3 + 2 + n * 7;

	if ((u = malloc(len)) == NULL)
		return NULL;
	p = u;
	*p++ = FACTS_TEMPLATE;
	*p++ = 0; *p++ = 0;			/* id */
	*p++ = 0; *p++ = 1; *p++ = 'k';		/* kind */
	*p++ = n >> 8; *p++ = n & 0xff;		/* fields */
	while (n-- > 0) {
		*p++ = 0; *p++ = 1; *p++ = 'f';	/* name */
		*p++ = FACT_U64;
		*p++ = FACT_PLAIN;
		*p++ = 0; *p++ = 0;		/* names */
	}
	*lenp = len;
	return u;
}

static void
test_field_limit(void)
{
	static struct facts_field fields[FACTS_FIELDS + 1];
	struct facts_kind k = { "wide", fields, FACTS_FIELDS };
	struct facts_value v[FACTS_FIELDS + 1];
	struct facts_out o;
	struct facts_in in;
	struct sink s = { 0 };
	struct got g = { 0 };
	uint8_t *u;
	size_t i, len;

	/* the field count is a u16 now: more than a u8 could say */
	CHECK(FACTS_FIELDS > 255);

	for (i = 0; i < FACTS_FIELDS + 1; i++) {
		fields[i].name = "f";
		fields[i].type = FACT_U64;
		fields[i].naming = FACT_PLAIN;
	}
	memset(v, 0, sizeof(v));
	for (i = 0; i < FACTS_FIELDS + 1; i++)
		facts_u64(&v[i], i);

	/* the writer takes FACTS_FIELDS, and the reader reads them back */
	facts_out_init(&o, emit, &s);
	CHECK(facts_record(&o, &k, v) == 0);
	CHECK(s.n == 2);
	CHECK(read_all(&s, &g) == 0);
	CHECK(g.nrecords == 1);
	got_free(&g);
	sink_free(&s);

	/* and refuses one more */
	k.nfields = FACTS_FIELDS + 1;
	facts_out_init(&o, emit, &s);
	CHECK(facts_record(&o, &k, v) == -1);
	CHECK(s.n == 0);
	sink_free(&s);

	/* a whole template of FACTS_FIELDS is taken, of one more refused */
	if ((u = template_of(FACTS_FIELDS, &len)) != NULL) {
		facts_in_init(&in, record, &g);
		CHECK(facts_read(&in, u, len) == 0);
		facts_in_free(&in);
		free(u);
	} else
		CHECK(0);
	if ((u = template_of(FACTS_FIELDS + 1, &len)) != NULL) {
		facts_in_init(&in, record, &g);
		CHECK(facts_read(&in, u, len) == -1);
		facts_in_free(&in);
		free(u);
	} else
		CHECK(0);
}

/* s's units joined into one message, then extra bytes */
static uint8_t *
join(struct sink *s, size_t *lenp, const uint8_t *extra, size_t nextra)
{
	uint8_t *m;
	size_t i, len = nextra, off = 0;

	for (i = 0; i < s->n; i++)
		len += s->len[i];
	if ((m = malloc(len ? len : 1)) == NULL)
		return NULL;
	for (i = 0; i < s->n; i++) {
		memcpy(m + off, s->buf[i], s->len[i]);
		off += s->len[i];
	}
	memcpy(m + off, extra, nextra);
	*lenp = len;
	return m;
}

/* one message may carry several whole units */
static void
test_several_units(void)
{
	struct sink s = { 0 };
	struct facts_out o;
	struct facts_in in;
	struct facts_value v[IF_NFIELDS];
	struct got g = { 0 };
	static const uint8_t partial[] = { FACTS_RECORD, 0 };
	uint8_t *m, *twice;
	size_t len;

	/* a template and three records of it */
	fill_if(v);
	facts_out_init(&o, emit, &s);
	CHECK(facts_record(&o, &ifkind, v) == 0);
	CHECK(facts_record(&o, &ifkind, v) == 0);
	CHECK(facts_record(&o, &ifkind, v) == 0);
	CHECK(s.n == 4);

	/* all in one message: every record is read */
	if ((m = join(&s, &len, NULL, 0)) != NULL) {
		facts_in_init(&in, record, &g);
		CHECK(facts_read(&in, m, len) == 0);
		CHECK(g.nrecords == 3);
		CHECK(g.v != NULL &&
		    strcmp(g.v[IF_NAME].v.str.s, "em0") == 0);
		got_free(&g);
		facts_in_free(&in);
		free(m);
	} else
		CHECK(0);

	/*
	 * a partial unit at the end is refused; the records before it
	 * were given already, so a caller drops the whole answer on -1
	 */
	if ((m = join(&s, &len, partial, sizeof(partial))) != NULL) {
		facts_in_init(&in, record, &g);
		CHECK(facts_read(&in, m, len) == -1);
		CHECK(g.nrecords == 3);
		got_free(&g);
		facts_in_free(&in);
		free(m);
	} else
		CHECK(0);

	/* a template twice in one message is refused, as in two */
	if ((twice = malloc(s.len[0] * 2)) != NULL) {
		memcpy(twice, s.buf[0], s.len[0]);
		memcpy(twice + s.len[0], s.buf[0], s.len[0]);
		facts_in_init(&in, record, &g);
		CHECK(facts_read(&in, twice, s.len[0] * 2) == -1);
		facts_in_free(&in);
		free(twice);
	} else
		CHECK(0);

	/* an empty message is still refused */
	facts_in_init(&in, record, &g);
	CHECK(facts_read(&in, partial, 0) == -1);
	facts_in_free(&in);
	sink_free(&s);
}

static void
test_bind_by_name(void)
{
	/* a reader binds fields by name and type, not position */
	static const struct facts_field reordered[] = {
		{ "changed",	FACT_TIME,	FACT_PLAIN, NULL, 0 },
		{ "mtu",	FACT_U64,	FACT_PLAIN, NULL, 0 },
		{ "name",	FACT_U64,	FACT_PLAIN, NULL, 0 }, /* type */
		{ "gone",	FACT_STRING,	FACT_PLAIN, NULL, 0 },
	};
	static const struct facts_kind rkind = { "interface", reordered, 4 };
	struct sink s = { 0 };
	struct facts_in in;
	struct got g = { 0 };
	int map[4];
	size_t i;

	CHECK(write_if(&s) == 0);
	facts_in_init(&in, record, &g);
	for (i = 0; i < s.n; i++)
		facts_read(&in, s.buf[i], s.len[i]);
	if (g.t != NULL) {
		facts_bind(g.t, &rkind, map);
		CHECK(map[0] == IF_CHANGED);
		CHECK(map[1] == IF_MTU);
		CHECK(map[2] == -1);
		CHECK(map[3] == -1);
		if (g.v != NULL) {
			CHECK(facts_get(g.v, map, 1, FACT_U64) != NULL);
			CHECK(facts_get(g.v, map, 3, FACT_STRING) == NULL);
		}
	} else
		CHECK(g.t != NULL);
	if (g.v != NULL)
		facts_copy_free(g.t, g.v);
	facts_in_free(&in);
	sink_free(&s);
}

/* a small, fixed-seed generator, so a failure can be repeated */
static uint32_t seed = 12345;

static uint32_t
rnd(void)
{
	seed = seed * 1103515245 + 12345;
	return seed >> 8;
}

/*
 * Damage valid units at random - flip, overwrite, cut and extend -
 * and read them. A refused unit is fine; a crash, or a record with a
 * value the template does not allow, is not.
 */
static void
test_mutations(void)
{
	struct sink s = { 0 };
	struct facts_in in;
	struct got g = { 0 };
	uint8_t *u;
	size_t len, i, j, n;
	int bad = 0, taken = 0;

	if (write_if(&s) != 0 || s.n != 2) {
		CHECK(0);
		sink_free(&s);
		return;
	}
	for (i = 0; i < 200000; i++) {
		j = rnd() % 2;
		len = s.len[j] + (rnd() % 4 == 0 ? rnd() % 16 : 0);
		if ((u = malloc(len)) == NULL)
			break;
		memset(u, (int)rnd(), len);
		memcpy(u, s.buf[j], s.len[j] < len ? s.len[j] : len);
		for (n = 1 + rnd() % 4; n > 0; n--)
			u[rnd() % len] ^= 1 << (rnd() % 8);
		if (rnd() % 4 == 0)
			len = rnd() % (len + 1);

		facts_in_init(&in, record, &g);
		if (j == 1 && facts_read(&in, s.buf[0], s.len[0]) == -1)
			bad++;
		if (facts_read(&in, u, len) == 0)
			taken++;
		if (g.v != NULL) {
			for (n = 0; n < g.t->nfields; n++)
				if (g.v[n].type != FACT_NONE &&
				    g.v[n].type != g.t->fields[n].type)
					bad++;
			facts_copy_free(g.t, g.v);
			g.v = NULL;
		}
		facts_in_free(&in);
		free(u);
	}
	CHECK(bad == 0);
	printf("   %d of 200000 damaged units were still valid\n", taken);
	sink_free(&s);
}

int
main(void)
{
	RUN(test_roundtrip);
	RUN(test_extremes);
	RUN(test_absent_fields);
	RUN(test_templates_sent_once);
	RUN(test_writer_refuses);
	RUN(test_reader_refuses);
	RUN(test_template_refuses);
	RUN(test_field_limit);
	RUN(test_several_units);
	RUN(test_bind_by_name);
	RUN(test_mutations);
	DONE();
}
