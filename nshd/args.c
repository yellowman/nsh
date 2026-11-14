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

/* the number of values argument f holds */
static size_t
arg_vals(const struct arg *f)
{
	return f->many > 1 ? (size_t)f->many : 1;
}

/* the number of c's arguments: its row ends them with one with no name */
size_t
args_n(const struct argcmd *c)
{
	size_t	 n = 0;

	while (c->args != NULL && c->args[n].name != NULL)
		n++;
	return n;
}

/* the number of values c's arguments hold in all */
static size_t
args_nvals(const struct argcmd *c)
{
	size_t	 i, n = 0;

	for (i = 0; i < args_n(c); i++)
		n += arg_vals(&c->args[i]);
	return n;
}

/* what a usage calls f: its help, or its name */
const char *
args_called(const struct arg *f)
{
	return f->help != NULL ? f->help : f->name;
}

/* f's name for errors, or c's name if f is its only argument */
static const char *
arg_label(const struct argcmd *c, const struct arg *f)
{
	return args_n(c) == 1 ? c->name : args_called(f);
}

/* f's keyword matching word, or the only one word abbreviates, or NULL */
static const struct argkey *
arg_key(const struct arg *f, const char *word)
{
	const struct argkey	*k;

	if (f->keys == NULL || *word == '\0')
		return NULL;
	k = (const struct argkey *)genget((char *)word, (char **)f->keys,
	    sizeof(*k));
	return Ambiguous((void *)k) ? NULL : k;
}

/* may argument f be left out? set is 0 for a "no" line */
static int
arg_opt(const struct arg *f, int set)
{
	return (f->flags & ARG_OPT) || (!set && (f->flags & ARG_NOOPT));
}

/* Print f's part of a usage line; ignored is set if "no" ignores f */
static void
arg_usage(const struct arg *f, int set, int ignored)
{
	const struct argkey	*k;

	if (ignored) {
		if (f->type != ARG_REST)
			printf(" [%s%s]", args_called(f), f->type == ARG_BITS ||
			    f->many > 1 ? " ..." : "");
		return;
	}
	if (arg_opt(f, set)) {
		printf(" [%s%s]", args_called(f), f->type == ARG_BITS ||
		    f->many > 1 ? " ..." : "");
		return;
	}
	if (f->keys != NULL && f->type == ARG_NUM && f->min > f->max) {
		printf(" <");
		for (k = f->keys; k->word != NULL; k++)
			printf("%s%s", k != f->keys ? "|" : "", k->word);
		printf(">");
	} else
		printf(" <%s>", args_called(f));
	if (f->type == ARG_BITS || f->many > 1)
		printf(" [%s ...]", args_called(f));
}

/* Print the usage of c and of "no c". Returns -1. */
static int
args_usage(const struct argcmd *c)
{
	size_t	 i;

	printf("%% %s", c->name);
	for (i = 0; i < args_n(c); i++)
		arg_usage(&c->args[i], 1, 0);
	printf("\n%% no %s", c->name);
	for (i = 0; i < args_n(c); i++)
		arg_usage(&c->args[i], 0, (c->args[i].flags & ARG_NO) == 0);
	printf("\n");
	return -1;
}

/* 1 if w has no control characters, else 0 after printing an error */
static int
arg_printable(const struct argcmd *c, const struct arg *f, const char *w)
{
	for (; *w != '\0'; w++)
		if ((unsigned char)*w < 0x20 || *w == 0x7f) {
			printf("%% %s may not hold a control character\n",
			    arg_label(c, f));
			return 0;
		}
	return 1;
}

/* Parse word w for argument f into v; 0, or -1 after printing an error */
static int
arg_word(const struct argcmd *c, const struct arg *f, char *w,
    struct facts_value *v)
{
	const struct argkey	*k;
	const char		*errstr;
	long long		 n;

	switch (f->type) {
	case ARG_NUM:
		if ((k = arg_key(f, w)) != NULL) {
			facts_i64(v, k->value);
			return 0;
		}
		if (f->min > f->max) {
			printf("%% Invalid %s %s\n", arg_label(c, f), w);
			return args_usage(c);
		}
		n = strtonum(w, f->min, f->max, &errstr);
		if (errstr != NULL) {
			printf("%% Invalid %s %s: %s\n", arg_label(c, f), w,
			    errstr);
			return -1;
		}
		facts_i64(v, n);
		return 0;
	case ARG_WORD:
		if (strlen(w) > (size_t)f->max) {
			printf("%% %s can be at most %lld bytes\n",
			    arg_label(c, f), f->max);
			return -1;
		}
		if (strlen(w) < (size_t)f->min) {
			printf("%% %s may not be empty\n", arg_label(c, f));
			return -1;
		}
		if (!arg_printable(c, f, w))
			return -1;
		facts_string(v, w);
		return 0;
	}
	return -1;
}

/* the most words arguments i and after can take, or -1 for no limit */
static int
args_ignored(const struct argcmd *c, size_t i)
{
	const struct arg	*f;
	const struct argkey	*k;
	int			 n = 0;

	for (; i < args_n(c); i++) {
		f = &c->args[i];
		if (f->type == ARG_REST)
			return -1;
		if (f->type == ARG_BITS)
			for (k = f->keys; k->word != NULL; k++)
				n++;
		else
			n += arg_vals(f);
	}
	return n;
}

/*
 * Parse argument f's words, starting at argv[*k], into v, and advance
 * *k past them. set is 0 for a "no" line. Returns 0, or -1 after
 * printing an error.
 */
static int
arg_take(const struct argcmd *c, const struct arg *f, int set, int argc,
    char **argv, int *k, struct facts_value *v, char *rest)
{
	const struct argkey	*key;
	size_t			 j, len;
	long long		 bits = 0;
	int			 i;

	switch (f->type) {
	case ARG_REST:
		if (*k >= argc)
			return arg_opt(f, set) ? 0 : args_usage(c);
		for (i = *k, len = 0; i < argc; i++)
			len += strlen(argv[i]) + (i > *k);
		if (len > (size_t)f->max || len >= ARGS_REST) {
			printf("%% %s can be at most %lld bytes\n",
			    arg_label(c, f), f->max);
			return -1;
		}
		for (i = *k; i < argc; i++) {
			if (i > *k)
				strlcat(rest, " ", ARGS_REST);
			strlcat(rest, argv[i], ARGS_REST);
		}
		if (!arg_printable(c, f, rest))
			return -1;
		facts_string(v, rest);
		*k = argc;
		return 0;
	case ARG_BITS:
		for (; *k < argc; (*k)++) {
			if ((key = arg_key(f, argv[*k])) == NULL) {
				printf("%% Invalid %s %s\n", arg_label(c, f),
				    argv[*k]);
				return args_usage(c);
			}
			bits |= key->value;
		}
		if (bits == 0)
			return arg_opt(f, set) ? 0 : args_usage(c);
		facts_i64(v, bits);
		return 0;
	}
	for (j = 0; j < arg_vals(f) && *k < argc; j++, (*k)++)
		if (arg_word(c, f, argv[*k], &v[j]) == -1)
			return -1;
	if (j == 0 && !arg_opt(f, set))
		return args_usage(c);
	return 0;
}

/*
 * Parse the arguments of line argv for c into a. argv[0] is c's word or
 * "no". Returns 0, or -1 after printing an error.
 */
int
args_parse(const struct argcmd *c, int argc, char **argv, struct argvals *a)
{
	const struct arg	*f;
	size_t			 i, s, n;
	int			 k = 0, ignored;

	memset(a->v, 0, sizeof(a->v));
	a->rest[0] = '\0';
	if (args_nvals(c) > ARGS_MAX) {
		printf("%% %s: too many fields\n", c->name);
		return -1;
	}
	a->set = !NO_ARG(argv[0]);
	if (!a->set) {
		argc--;
		argv++;
	}
	argc--;
	argv++;
	/* parse the arguments in order; for "no", only those with ARG_NO */
	for (i = 0, s = 0; i < args_n(c); i++, s += n) {
		f = &c->args[i];
		n = arg_vals(f);
		if (!a->set && !(f->flags & ARG_NO))
			break;
		if (arg_take(c, f, a->set, argc, argv, &k, &a->v[s],
		    a->rest) == -1)
			return -1;
	}
	/* for "no", the other arguments may be given, but are ignored */
	if (!a->set) {
		ignored = args_ignored(c, i);
		return ignored != -1 && argc - k > ignored ? args_usage(c) : 0;
	}
	return k < argc ? args_usage(c) : 0;
}

/*
 * Parse line argv for c and call fn with each record of values. If c's
 * only argument is a list of separate words, such as group's names, the
 * line may give more words than one record holds (many): each record
 * then takes the next many words, so only the line's length limits the
 * list. Returns what fn last returned, or -1 after printing an error
 */
int
args_each(const struct argcmd *c, int argc, char **argv,
    int (*fn)(const struct argcmd *, struct argvals *, void *), void *arg)
{
	struct argvals		 a;
	char			*w[NARGS];
	int			 head, i, n, per = argc, r = 0;

	head = NO_ARG(argv[0]) ? 2 : 1;
	if (args_n(c) == 1 && c->args[0].type == ARG_WORD &&
	    c->args[0].many > 1)
		per = c->args[0].many;
	if (argc - head <= per)
		return args_parse(c, argc, argv, &a) == -1 ? -1 :
		    fn(c, &a, arg);
	for (i = head; i < argc; i += n) {
		n = argc - i < per ? argc - i : per;
		memcpy(w, argv, head * sizeof(*w));
		memcpy(w + head, argv + i, n * sizeof(*w));
		if (args_parse(c, head + n, w, &a) == -1 ||
		    (r = fn(c, &a, arg)) == -1)
			return -1;
	}
	return r;
}

/*
 * the interface that args_run() runs each record of values on, and the
 * candidate the line edits, or NULL
 */
struct args_on {
	char	*ifname;
	int	 ifs;
	struct cand *cand;
};

static int
args_apply(const struct argcmd *c, struct argvals *a, void *arg)
{
	struct args_on	*on = arg;

	return c->apply(c, a->set, a->v, on->ifname, on->ifs, on->cand);
}

/* Parse line argv for c and run c's apply function on ifname */
int
args_run(const struct argcmd *c, int argc, char **argv, char *ifname, int ifs,
    struct cand *cand)
{
	struct args_on	 on = { ifname, ifs, cand };

	return args_each(c, argc, argv, args_apply, &on);
}

/* Describe c's values as a facts kind in k, one field in f per value */
void
args_kind(const struct argcmd *c, struct facts_kind *k,
    struct facts_field *f)
{
	size_t	 i, j, n = 0;

	for (i = 0; i < args_n(c); i++)
		for (j = 0; j < arg_vals(&c->args[i]) && n < ARGS_MAX; j++) {
			memset(&f[n], 0, sizeof(f[n]));
			f[n].name = c->args[i].name;
			f[n].type = c->args[i].type == ARG_WORD ||
			    c->args[i].type == ARG_REST ? FACT_STRING :
			    FACT_I64;
			f[n].naming = FACT_PLAIN;
			n++;
		}
	k->name = c->name;
	k->fields = f;
	k->nfields = n;
}

/* is present value v valid for argument f? */
static int
arg_value(const struct argcmd *c, const struct arg *f,
    const struct facts_value *v)
{
	const struct argkey	*k;
	long long		 bits = 0;
	size_t			 j;

	switch (f->type) {
	case ARG_NUM:
		for (k = f->keys; k != NULL && k->word != NULL; k++)
			if (v->v.i == k->value)
				return 1;
		return v->v.i >= f->min && v->v.i <= f->max;
	case ARG_BITS:
		for (k = f->keys; k->word != NULL; k++)
			bits |= k->value;
		return v->v.i != 0 && (v->v.i & ~bits) == 0;
	}
	if (v->v.str.len > (size_t)f->max || v->v.str.len < (size_t)f->min)
		return 0;
	for (j = 0; j < v->v.str.len; j++)
		if ((unsigned char)v->v.str.s[j] < 0x20 ||
		    v->v.str.s[j] == 0x7f || (v->v.str.s[j] == ' ' &&
		    f->type == ARG_WORD))
			return 0;
	return 1;
}

/*
 * Check that values v, in template t, are valid for c. t must match c's
 * values one for one. Each argument that is parsed (always, or on a
 * "no" line if it has ARG_NO) must have its present values first, each
 * valid, and at least one unless it is optional; an ignored argument
 * has none. set is 0 for a "no" line. Returns 0 if valid, else -1.
 */
int
args_check(const struct argcmd *c, int set, const struct facts_template *t,
    const struct facts_value *v)
{
	struct facts_field	 f[ARGS_MAX];
	struct facts_kind	 k;
	const struct arg	*a;
	size_t			 i, j, s;
	int			 taken;

	if (args_nvals(c) > ARGS_MAX)
		return -1;
	args_kind(c, &k, f);
	if (strcmp(t->kind, k.name) != 0 || t->nfields != k.nfields)
		return -1;
	for (s = 0; s < k.nfields; s++)
		if (strcmp(t->fields[s].name, f[s].name) != 0 ||
		    t->fields[s].type != f[s].type ||
		    t->fields[s].naming != FACT_PLAIN)
			return -1;
	for (i = 0, s = 0; i < args_n(c); i++) {
		a = &c->args[i];
		taken = set || (a->flags & ARG_NO);
		for (j = 0; j < arg_vals(a); j++, s++) {
			if (v[s].type == FACT_NONE) {
				if (taken && j == 0 && !arg_opt(a, set))
					return -1;
				continue;
			}
			if (!taken || (j > 0 && v[s - 1].type == FACT_NONE) ||
			    !arg_value(c, a, &v[s]))
				return -1;
		}
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
