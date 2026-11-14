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

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <resolv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "externs.h"
#include "facts.h"
#include "args.h"

/* the number of words argument f takes */
static size_t
arg_words(const struct arg *f)
{
	return f->many > 1 ? (size_t)f->many : 1;
}

/*
 * the number of values f holds: two per word with ARG_PORT or
 * ARG_PREFIX, else one
 */
static size_t
arg_vals(const struct arg *f)
{
	return arg_words(f) * ((f->flags & (ARG_PORT | ARG_PREFIX)) ? 2 : 1);
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

/* is f a named argument, such as "ttl 64" or "df"? */
static int
arg_named(const struct arg *f)
{
	return f->type == ARG_FLAG || (f->flags & ARG_NAMED);
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

/* c's named argument called word, or the only one word abbreviates */
static const struct arg *
arg_name(const struct argcmd *c, const char *word)
{
	const struct arg	*f, *found = NULL;
	int			 n;

	if (*word == '\0')
		return NULL;
	/* as genget() finds a word, among the named ones alone */
	for (f = c->args; f != NULL && f->name != NULL; f++) {
		if (!arg_named(f) ||
		    (n = isprefix((char *)word, (char *)f->name)) == 0)
			continue;
		if (n < 0)
			return f;
		if (found != NULL)
			return NULL;
		found = f;
	}
	return found;
}

/* may f be an address of family af (FACT_INET, FACT_INET6, FACT_LINK)? */
static int
arg_family(const struct arg *f, int af)
{
	int	 fl = f->flags & (ARG_INET | ARG_INET6 | ARG_LINK);

	if (fl == 0)
		fl = ARG_INET | ARG_INET6;
	return (af == FACT_INET && (fl & ARG_INET)) ||
	    (af == FACT_INET6 && (fl & ARG_INET6)) ||
	    (af == FACT_LINK && (fl & ARG_LINK));
}

/* may argument f be left out? set is 0 for a "no" line */
static int
arg_opt(const struct arg *f, int set)
{
	return (f->flags & ARG_OPT) || (!set && (f->flags & ARG_NOOPT));
}

/* does c have a named argument that a "no" line parses? */
static int
args_named_no(const struct argcmd *c)
{
	size_t	 i;

	for (i = 0; i < args_n(c); i++)
		if (arg_named(&c->args[i]) && (c->args[i].flags & ARG_NO))
			return 1;
	return 0;
}

/* may f take several words (a list, or keywords without ARG_COMMAS)? */
static int
arg_many(const struct arg *f)
{
	return (f->type == ARG_BITS && !(f->flags & ARG_COMMAS)) ||
	    f->many > 1;
}

/* Print f's placeholder in a usage, <kw1|kw2> if only keywords are valid */
static void
arg_what(const struct arg *f)
{
	const struct argkey	*k;

	if (f->keys != NULL && f->type == ARG_NUM && f->min > f->max) {
		printf("<");
		for (k = f->keys; k->word != NULL; k++)
			printf("%s%s", k != f->keys ? "|" : "", k->word);
		printf(">");
	} else
		printf("<%s>", args_called(f));
}

/* Print f's part of a usage line; ignored is set if "no" ignores f */
static void
arg_usage(const struct arg *f, int set, int ignored)
{
	if (f->type == ARG_FLAG) {
		printf(" [%s]", f->name);
		return;
	}
	if (arg_named(f)) {
		printf(" [%s ", f->name);
		arg_what(f);
		printf("]");
		return;
	}
	if (ignored) {
		if (f->type != ARG_REST)
			printf(" [%s%s]", args_called(f),
			    arg_many(f) ? " ..." : "");
		return;
	}
	if (arg_opt(f, set)) {
		printf(" [%s%s]", args_called(f), arg_many(f) ? " ..." : "");
		return;
	}
	printf(" ");
	arg_what(f);
	if (arg_many(f))
		printf(" [%s ...]", args_called(f));
}

/* Print the usage of c, and of "no c" unless c only sets. Returns -1. */
int
args_usage(const struct argcmd *c)
{
	size_t	 i;

	printf("%% %s", c->name);
	for (i = 0; i < args_n(c); i++)
		arg_usage(&c->args[i], 1, 0);
	printf("\n");
	if (c->flags & CF_SET)
		return -1;
	/* for "no", list only what it parses, if that includes named ones */
	printf("%% no %s", c->name);
	for (i = 0; i < args_n(c); i++)
		if ((c->args[i].flags & ARG_NO) || !args_named_no(c))
			arg_usage(&c->args[i], 0,
			    (c->args[i].flags & ARG_NO) == 0);
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

/*
 * Parse word w as an address for argument f into v. With ARG_PORT, the
 * address may end in a port, as "a.b.c.d:port" or "[v6addr]:port", and
 * the port goes in v[1]. With ARG_PREFIX, it may end in "/length", as
 * inet_net_pton() reads it, and the length goes in v[1]. Returns 0, or
 * -1 after printing an error.
 */
static int
arg_addr(const struct argcmd *c, const struct arg *f, char *w,
    struct facts_value *v)
{
	struct ether_addr	*ea;
	struct addrinfo		*res;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	unsigned char		 a[16];
	char			 buf[NI_MAXHOST], *port = NULL, *p;
	const char		*errstr, *what;
	int			 af, n;

	if (arg_family(f, FACT_LINK) && (ea = ether_aton(w)) != NULL) {
		facts_address(v, FACT_LINK, ea, sizeof(*ea), 0);
		return 0;
	}
	what = !arg_family(f, FACT_INET) && !arg_family(f, FACT_INET6) ?
	    "a MAC address" : arg_family(f, FACT_LINK) ?
	    "an address or a MAC address" : !arg_family(f, FACT_INET6) ?
	    "an IPv4 address" : !arg_family(f, FACT_INET) ?
	    "an IPv6 address" : "an address";
	af = !arg_family(f, FACT_INET6) ? AF_INET : !arg_family(f, FACT_INET) ?
	    AF_INET6 : AF_UNSPEC;
	if (strlcpy(buf, w, sizeof(buf)) >= sizeof(buf))
		goto bad;
	if (f->flags & ARG_PREFIX) {
		/* inet_net_pton() writes only the bytes the prefix covers */
		memset(a, 0, sizeof(a));
		if (arg_family(f, FACT_INET) &&
		    (n = inet_net_pton(AF_INET, buf, a, 4)) != -1) {
			facts_address(v, FACT_INET, a, 4, 0);
			facts_i64(&v[1], n);
			return 0;
		}
		if (arg_family(f, FACT_INET6) &&
		    (n = inet_net_pton(AF_INET6, buf, a, 16)) != -1) {
			facts_address(v, FACT_INET6, a, 16, 0);
			facts_i64(&v[1], n);
			return 0;
		}
		printf("%% %s %s is not %s and its prefix length\n",
		    arg_label(c, f), w, what);
		return -1;
	}
	if ((f->flags & ARG_PORT) && buf[0] == '[' &&
	    ((p = strstr(buf, "]:")) != NULL ||
	    (p = strchr(buf, ']')) == buf + strlen(buf) - 1)) {
		if (p[1] == ':')
			port = p + 2;
		*p = '\0';
		memmove(buf, buf + 1, strlen(buf));
	} else if ((f->flags & ARG_PORT) && (p = strchr(buf, ':')) != NULL &&
	    p == strrchr(buf, ':')) {
		*p++ = '\0';
		port = p;
	}
	if ((arg_family(f, FACT_INET) || arg_family(f, FACT_INET6)) &&
	    numeric_addrinfo(buf, NULL, af, 0, &res) == 0) {
		if (res->ai_family == AF_INET) {
			sin = (struct sockaddr_in *)res->ai_addr;
			facts_address(v, FACT_INET, &sin->sin_addr,
			    sizeof(sin->sin_addr), 0);
		} else {
			sin6 = (struct sockaddr_in6 *)res->ai_addr;
			facts_address(v, FACT_INET6, &sin6->sin6_addr,
			    sizeof(sin6->sin6_addr), sin6->sin6_scope_id);
		}
		freeaddrinfo(res);
		if (port == NULL)
			return 0;
		n = strtonum(port, 0, 65535, &errstr);
		if (errstr == NULL) {
			facts_i64(&v[1], n);
			return 0;
		}
		printf("%% Invalid port %s: %s\n", port, errstr);
		return -1;
	}
 bad:
	printf("%% %s %s is not %s\n", arg_label(c, f), w, what);
	return -1;
}

/*
 * Parse word w for c's argument f into v; a base64 word decodes into a's
 * buffers. Returns 0, or -1 after printing an error.
 */
int
args_word(const struct argcmd *c, const struct arg *f, struct argvals *a,
    char *w, struct facts_value *v)
{
	const struct argkey	*k;
	const char		*errstr;
	long long		 n;

	switch (f->type) {
	case ARG_ADDR:
		return arg_addr(c, f, w, v);
	case ARG_B64:
		if (a->nbin >= ARGS_BINS || f->max >= ARGS_BIN ||
		    b64_pton(w, a->bin[a->nbin], ARGS_BIN) != f->max) {
			printf("%% %s is not a key of %lld bytes in base64\n",
			    arg_label(c, f), f->max);
			return -1;
		}
		facts_bytes(v, a->bin[a->nbin++], f->max);
		return 0;
	case ARG_BYTES:
		if (f->max >= ARGS_BIN ||
		    args_bytes(a, w, NULL, f->max, v) == NULL)
			return -1;
		if (v->v.str.len < (size_t)f->min) {
			printf("%% %s is at least %lld bytes\n",
			    arg_label(c, f), f->min);
			return -1;
		}
		return 0;
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

/*
 * Up to *lenp bytes of val, text or 0x and hex digits, as ifconfig reads
 * them, up to one of sep's characters if sep is not NULL, into buf, and
 * how many into *lenp. Returns where it stopped, or NULL after printing
 * why. Was ieee80211.c's
 */
static const char *
get_string(const char *val, const char *sep, u_int8_t *buf, int *lenp)
{
	int len;
	int hexstr;
	u_int8_t *p;

	len = *lenp;
	p = buf;
	hexstr = (val[0] == '0' && tolower((unsigned char)val[1]) == 'x');
	if (hexstr)
		val += 2;
	for (;;) {
		if (*val == '\0')
			break;
		if (sep != NULL && strchr(sep, *val) != NULL) {
			val++;
			break;
		}
		if (hexstr) {
			if (!isxdigit((unsigned char)val[0]) ||
			    !isxdigit((unsigned char)val[1])) {
				printf("%% get_string: bad hexadecimal digits\n");
				return NULL;
			}
		}
		if (p >= buf + len) {
			if (hexstr)
				printf("%% get_string: hexadecimal digits too long\n");
			else
				printf("%% get_string: strings too long\n");
			return NULL;
		}
		if (hexstr) {
#define tohex(x)        (isdigit((unsigned char)(x)) ? (x) - '0' : \
			    tolower((unsigned char)(x)) - 'a' + 10)
			*p++ = (tohex(val[0]) << 4) | tohex(val[1]);
#undef tohex
			val += 2;
		} else {
			if (*val == '\\' &&
			    sep != NULL && strchr(sep, *(val + 1)) != NULL)
				val++;
			*p++ = *val++;
		}
	}
	len = p - buf;
	if (len < *lenp)
		memset(p, 0, *lenp - len);
	*lenp = len;
	return val;
}

/*
 * Up to max bytes of w, as get_string() reads them, text or 0x and hex
 * digits, up to one of sep's characters if sep is not NULL, into one of
 * a's buffers, and into v. Returns where get_string() stopped, or NULL
 * after printing why
 */
const char *
args_bytes(struct argvals *a, const char *w, const char *sep, size_t max,
    struct facts_value *v)
{
	const char	*end;
	int		 len = max;

	if (a->nbin >= ARGS_BINS || max >= ARGS_BIN) {
		printf("%% too many values\n");
		return NULL;
	}
	if ((end = get_string(w, sep, a->bin[a->nbin], &len)) == NULL)
		return NULL;
	facts_bytes(v, a->bin[a->nbin++], len);
	return end;
}

/*
 * the most words that the named arguments, and arguments i and after,
 * can take, or -1 for no limit
 */
static int
args_ignored(const struct argcmd *c, size_t i)
{
	const struct arg	*f;
	const struct argkey	*k;
	size_t			 j;
	int			 n = 0;

	for (j = 0; j < args_n(c); j++) {
		f = &c->args[j];
		if (j < i && !arg_named(f))
			continue;
		if (f->type == ARG_REST)
			return -1;
		if (f->type == ARG_FLAG)
			n++;
		else if (arg_named(f))
			n += 2 * arg_words(f);
		else if (f->type == ARG_BITS && !(f->flags & ARG_COMMAS))
			for (k = f->keys; k->word != NULL; k++)
				n++;
		else
			n += arg_words(f);
	}
	return n;
}

/*
 * OR into bits the values of the keywords in word w: one keyword, or
 * with ARG_COMMAS, a comma-separated list. Returns 0, or -1 after
 * printing an error.
 */
static int
arg_keys(const struct argcmd *c, const struct arg *f, const char *w,
    long long *bits)
{
	const struct argkey	*key;
	char			 buf[ARGS_REST], *p = buf, *s;

	if (strlcpy(buf, w, sizeof(buf)) >= sizeof(buf)) {
		printf("%% %s can be at most %zu bytes\n", arg_label(c, f),
		    sizeof(buf) - 1);
		return -1;
	}
	while ((s = strsep(&p, (f->flags & ARG_COMMAS) ? "," : "")) != NULL) {
		if ((key = arg_key(f, s)) == NULL) {
			printf("%% Invalid %s %s\n", arg_label(c, f), s);
			return args_usage(c);
		}
		*bits |= key->value;
	}
	return 0;
}

/*
 * Parse argument f's words, starting at argv[*k], into v, and advance
 * *k past them; a holds the buffers for ARG_REST and ARG_B64 values.
 * For a named argument, argv[*k] is the word after its name. set is 0
 * for a "no" line. Returns 0, or -1 after printing an error.
 */
static int
arg_take(const struct argcmd *c, const struct arg *f, int set, int argc,
    char **argv, int *k, struct facts_value *v, struct argvals *a)
{
	char			*rest = a->rest;
	size_t			 j, len, per = arg_vals(f) / arg_words(f);
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
		/* with ARG_COMMAS, all the keywords are in one word */
		for (i = *k; *k < argc && arg_name(c, argv[*k]) == NULL &&
		    (*k == i || !(f->flags & ARG_COMMAS)); (*k)++)
			if (arg_keys(c, f, argv[*k], &bits) == -1)
				return -1;
		if (*k == i)
			return arg_opt(f, set) ? 0 : args_usage(c);
		facts_i64(v, bits);
		return 0;
	}
	if (arg_named(f)) {
		for (j = 0; j < arg_words(f) && v[j * per].type != FACT_NONE;
		    j++)
			;
		if (j == arg_words(f) || (f->type != ARG_FLAG &&
		    *k + 1 >= argc))
			return args_usage(c);
		if (f->type == ARG_FLAG) {
			facts_i64(&v[j], 1);
			(*k)++;
			return 0;
		}
		*k += 2;
		return args_word(c, f, a, argv[*k - 1], &v[j * per]);
	}
	/* a named argument's name ends this argument's words */
	for (j = 0; j < arg_words(f) && *k < argc &&
	    arg_name(c, argv[*k]) == NULL; j++, (*k)++)
		if (args_word(c, f, a, argv[*k], &v[j * per]) == -1)
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
	a->nbin = 0;
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
	if (c->parse != NULL)
		return c->parse(c, argc, argv, a);
	/* the unnamed arguments in order; for "no", only those with ARG_NO */
	for (i = 0, s = 0; i < args_n(c); i++, s += n) {
		f = &c->args[i];
		n = arg_vals(f);
		if (arg_named(f))
			continue;
		if (!a->set && !(f->flags & ARG_NO))
			break;
		if (arg_take(c, f, a->set, argc, argv, &k, &a->v[s],
		    a) == -1)
			return -1;
	}
	/*
	 * A "no" line for a command with named arguments that "no" parses
	 * reads those as usual. For other commands, the remaining arguments
	 * may be given, but are ignored.
	 */
	if (!a->set && !args_named_no(c)) {
		ignored = args_ignored(c, i);
		return ignored != -1 && argc - k > ignored ? args_usage(c) : 0;
	}
	/* then the named arguments, in any order */
	while (k < argc) {
		if ((f = arg_name(c, argv[k])) == NULL ||
		    (!a->set && !(f->flags & ARG_NO)))
			return args_usage(c);
		for (i = 0, s = 0; &c->args[i] != f; i++)
			s += arg_vals(&c->args[i]);
		if (arg_take(c, f, a->set, argc, argv, &k, &a->v[s],
		    a) == -1)
			return -1;
	}
	return 0;
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

/* Describe c's values as a facts kind in k, one field in f per value */
void
args_kind(const struct argcmd *c, struct facts_kind *k,
    struct facts_field *f)
{
	const struct arg	*a;
	size_t			 i, j, n = 0;

	for (i = 0; i < args_n(c); i++) {
		a = &c->args[i];
		for (j = 0; j < arg_vals(a) && n < ARGS_MAX; j++) {
			memset(&f[n], 0, sizeof(f[n]));
			f[n].name = a->name;
			/* a port or prefix length comes after its address */
			f[n].type = a->type == ARG_B64 ||
			    a->type == ARG_BYTES ? FACT_BYTES :
			    a->type == ARG_WORD || a->type == ARG_REST ?
			    FACT_STRING : a->type == ARG_ADDR &&
			    ((a->flags & (ARG_PORT | ARG_PREFIX)) == 0 ||
			    j % 2 == 0) ? FACT_ADDRESS : FACT_I64;
			f[n].naming = FACT_PLAIN;
			n++;
		}
	}
	k->name = c->name;
	k->fields = f;
	k->nfields = n;
}

/* where args_record() writes */
struct args_buf {
	char	*p;
	size_t	 len, size;
	int	 full;
};

static void
args_emit(void *arg, const void *p, size_t len)
{
	struct args_buf	*b = arg;

	if (b->full || len > b->size - b->len) {
		b->full = 1;
		return;
	}
	memcpy(b->p + b->len, p, len);
	b->len += len;
}

/*
 * a's values for c, as a facts record after its template, into buf
 * (size bytes): their length, or -1 after saying they do not fit
 */
ssize_t
args_record(const struct argcmd *c, const struct argvals *a, void *buf,
    size_t size)
{
	struct facts_field	 f[ARGS_MAX];
	struct facts_kind	 k;
	struct facts_out	 o;
	struct args_buf		 b = { buf, 0, size, 0 };

	args_kind(c, &k, f);
	facts_out_init(&o, args_emit, &b);
	if (facts_record(&o, &k, a->v) == -1 || b.full) {
		printf("%% %s: its values do not fit\n", c->name);
		return -1;
	}
	return b.len;
}

/* is present value v valid for argument f? */
static int
arg_value(const struct argcmd *c, const struct arg *f,
    const struct facts_value *v)
{
	const struct argkey	*k;
	long long		 bits = 0;
	size_t			 j;
	int			 none = 0;

	switch (f->type) {
	case ARG_NUM:
		for (k = f->keys; k != NULL && k->word != NULL; k++)
			if (v->v.i == k->value)
				return 1;
		return v->v.i >= f->min && v->v.i <= f->max;
	case ARG_FLAG:
		return v->v.i == 1;
	case ARG_BITS:
		/* a key of 0 stands for no bits */
		for (k = f->keys; k->word != NULL; k++) {
			bits |= k->value;
			none |= k->value == 0;
		}
		return (v->v.i != 0 || none) && (v->v.i & ~bits) == 0;
	case ARG_B64:
		return v->v.str.len == (size_t)f->max;
	case ARG_BYTES:
		return v->v.str.len >= (size_t)f->min &&
		    v->v.str.len <= (size_t)f->max;
	case ARG_ADDR:
		if (!arg_family(f, v->v.a.family))
			return 0;
		if (v->v.a.family == FACT_INET6)
			return v->v.a.len == 16;
		return v->v.a.scope == 0 && v->v.a.len ==
		    (v->v.a.family == FACT_INET ? 4 : 6);
	}
	if (v->v.str.len > (size_t)f->max || v->v.str.len < (size_t)f->min)
		return 0;
	for (j = 0; j < v->v.str.len; j++)
		if ((unsigned char)v->v.str.s[j] < 0x20 ||
		    v->v.str.s[j] == 0x7f || (v->v.str.s[j] == ' ' &&
		    f->type == ARG_WORD && !(f->flags & ARG_BLANKS)))
			return 0;
	return 1;
}

/*
 * Check that values v, in template t, are valid for c. t must match c's
 * values one for one. Each argument that is parsed (always, or on a
 * "no" line if it has ARG_NO) must have its present values first, each
 * valid, and at least one unless it is optional; an ignored argument
 * has none. A port or prefix length may be present only with its
 * address. set is 0 for a "no" line. Returns 0 if valid, else -1.
 */
int
args_check(const struct argcmd *c, int set, const struct facts_template *t,
    const struct facts_value *v)
{
	struct facts_field	 f[ARGS_MAX];
	struct facts_kind	 k;
	const struct arg	*a;
	size_t			 i, j, s, per;
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
		per = arg_vals(a) / arg_words(a);
		for (j = 0; j < arg_words(a); j++, s += per) {
			/*
			 * a port needs its address and fits in 16 bits; a
			 * prefix length needs its address and is at most
			 * the address's length in bits
			 */
			if (per == 2 && (a->flags & ARG_PREFIX) &&
			    ((v[s].type == FACT_NONE) != (v[s + 1].type ==
			    FACT_NONE) || (v[s + 1].type != FACT_NONE &&
			    (v[s + 1].v.i < 0 || v[s + 1].v.i >
			    v[s].v.a.len * 8))))
				return -1;
			if (per == 2 && (a->flags & ARG_PORT) &&
			    v[s + 1].type != FACT_NONE &&
			    (v[s].type == FACT_NONE || v[s + 1].v.i < 0 ||
			    v[s + 1].v.i > 65535))
				return -1;
			if (v[s].type == FACT_NONE) {
				if (taken && j == 0 && !arg_named(a) &&
				    !arg_opt(a, set))
					return -1;
				continue;
			}
			if (!taken || (j > 0 && v[s - per].type ==
			    FACT_NONE && !(a->flags & ARG_GAPS)) ||
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

/*
 * Fill ss from address value v (IPv4 or IPv6) and port. Returns the
 * address family, or AF_UNSPEC if v is not such an address.
 */
int
args_sockaddr(const struct facts_value *v, int port,
    struct sockaddr_storage *ss)
{
	struct sockaddr_in	*sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6	*sin6 = (struct sockaddr_in6 *)ss;

	memset(ss, 0, sizeof(*ss));
	if (v->type != FACT_ADDRESS)
		return AF_UNSPEC;
	if (v->v.a.family == FACT_INET) {
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		memcpy(&sin->sin_addr, v->v.a.bytes, sizeof(sin->sin_addr));
		return AF_INET;
	}
	if (v->v.a.family == FACT_INET6) {
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		memcpy(&sin6->sin6_addr, v->v.a.bytes,
		    sizeof(sin6->sin6_addr));
		sin6->sin6_scope_id = v->v.a.scope;
		return AF_INET6;
	}
	return AF_UNSPEC;
}
