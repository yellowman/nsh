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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "externs.h"
#include "facts.h"
#include "args.h"

/* the number of c's arguments: its row ends them with one with no name */
size_t
args_n(const struct argcmd *c)
{
	size_t	 n = 0;

	while (c->args != NULL && c->args[n].name != NULL)
		n++;
	return n;
}

/* what a usage calls f: its help, or its name */
const char *
args_called(const struct arg *f)
{
	return f->help != NULL ? f->help : f->name;
}

/* Print the usage of c and of "no c". Returns -1. */
static int
args_usage(const struct argcmd *c)
{
	size_t	 i;
	int	 rest = 0;

	printf("%% %s", c->name);
	for (i = 0; i < args_n(c); i++)
		printf(" <%s>", args_called(&c->args[i]));
	printf("\n%% no %s", c->name);
	for (i = 0; i < args_n(c); i++)
		rest |= c->args[i].type == ARG_REST;
	if (!rest && args_n(c) > 0) {
		printf(" [");
		for (i = 0; i < args_n(c); i++)
			printf("%s%s", i > 0 ? " " : "",
			    args_called(&c->args[i]));
		printf("]");
	}
	printf("\n");
	return -1;
}

/*
 * Parse the arguments of line argv for c into a. argv[0] is c's word or
 * "no". Returns 0, or -1 after printing an error.
 */
int
args_parse(const struct argcmd *c, int argc, char **argv, struct argvals *a)
{
	const struct arg *f;
	const char	*errstr;
	size_t		 i, len;
	int		 j;

	memset(a->v, 0, sizeof(a->v));
	a->rest[0] = '\0';
	a->set = !NO_ARG(argv[0]);
	if (!a->set) {
		argc--;
		argv++;
	}
	argc--;
	argv++;
	/* a "no" line may give the arguments, but they are ignored */
	if (!a->set) {
		for (i = 0; i < args_n(c); i++)
			if (c->args[i].type == ARG_REST)
				return 0;
		return (size_t)argc > args_n(c) ? args_usage(c) : 0;
	}
	for (i = 0; i < args_n(c); i++) {
		f = &c->args[i];
		if (argc < 1)
			return args_usage(c);
		switch (f->type) {
		case ARG_NUM:
			facts_i64(&a->v[i], strtonum(argv[0], f->min, f->max,
			    &errstr));
			if (errstr != NULL) {
				printf("%% Invalid %s %s: %s\n", c->name,
				    argv[0], errstr);
				return -1;
			}
			break;
		case ARG_WORD:
			if (strlen(argv[0]) > (size_t)f->max) {
				printf("%% %s can be at most %lld bytes\n",
				    c->name, f->max);
				return -1;
			}
			facts_string(&a->v[i], argv[0]);
			break;
		case ARG_REST:
			for (j = 0, len = 0; j < argc; j++)
				len += strlen(argv[j]) + (j > 0);
			if (len > (size_t)f->max || len >= sizeof(a->rest)) {
				printf("%% %s can be at most %lld bytes\n",
				    c->name, f->max);
				return -1;
			}
			for (j = 0; j < argc; j++) {
				if (j > 0)
					strlcat(a->rest, " ", sizeof(a->rest));
				strlcat(a->rest, argv[j], sizeof(a->rest));
			}
			facts_string(&a->v[i], a->rest);
			argc = 1;
			break;
		}
		argc--;
		argv++;
	}
	return argc > 0 ? args_usage(c) : 0;
}

/* Parse line argv for c and run c's apply function on ifname */
int
args_run(const struct argcmd *c, int argc, char **argv, char *ifname, int ifs,
    struct cand *cand)
{
	struct argvals	 a;

	if (args_parse(c, argc, argv, &a) == -1)
		return -1;
	return c->apply(c, a.set, a.v, ifname, ifs, cand);
}

/* Describe c's values as a facts kind in k, with its fields in f */
void
args_kind(const struct argcmd *c, struct facts_kind *k,
    struct facts_field *f)
{
	size_t	 i;

	for (i = 0; i < args_n(c); i++) {
		memset(&f[i], 0, sizeof(f[i]));
		f[i].name = c->args[i].name;
		f[i].type = c->args[i].type == ARG_NUM ? FACT_I64 :
		    FACT_STRING;
		f[i].naming = FACT_PLAIN;
	}
	k->name = c->name;
	k->fields = f;
	k->nfields = args_n(c);
}

/*
 * Check that values v, in template t, are valid for c. t must match c's
 * arguments one for one. For a "no" line (set is 0) every value must be
 * absent; otherwise each must be present and within its bounds, and a
 * string must have no control characters. Returns 0 if valid, else -1.
 */
int
args_check(const struct argcmd *c, int set, const struct facts_template *t,
    const struct facts_value *v)
{
	struct facts_field	 f[ARGS_MAX];
	struct facts_kind	 k;
	size_t			 i, j;

	if (args_n(c) > ARGS_MAX)
		return -1;
	args_kind(c, &k, f);
	if (strcmp(t->kind, k.name) != 0 || t->nfields != k.nfields)
		return -1;
	for (i = 0; i < k.nfields; i++) {
		if (strcmp(t->fields[i].name, f[i].name) != 0 ||
		    t->fields[i].type != f[i].type ||
		    t->fields[i].naming != FACT_PLAIN)
			return -1;
		if (!set) {
			if (v[i].type != FACT_NONE)
				return -1;
			continue;
		}
		if (v[i].type != f[i].type)
			return -1;
		if (f[i].type == FACT_I64 && (v[i].v.i < c->args[i].min ||
		    v[i].v.i > c->args[i].max))
			return -1;
		if (f[i].type != FACT_STRING)
			continue;
		if (v[i].v.str.len > (size_t)c->args[i].max)
			return -1;
		for (j = 0; j < v[i].v.str.len; j++)
			if ((unsigned char)v[i].v.str.s[j] < 0x20 ||
			    v[i].v.str.s[j] == 0x7f || (v[i].v.str.s[j] ==
			    ' ' && c->args[i].type == ARG_WORD))
				return -1;
	}
	return 0;
}

/* Copy string value v into buf (len bytes) and NUL-terminate it */
void
args_string(const struct facts_value *v, char *buf, size_t len)
{
	size_t	 n = v->v.str.len < len - 1 ? v->v.str.len : len - 1;

	memcpy(buf, v->v.str.s, n);
	buf[n] = '\0';
}
