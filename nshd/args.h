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
 * Parsing of interface commands' arguments.
 *
 * Each command's row (struct argcmd) lists its arguments (struct arg). config
 * parses a configuration line's words into typed values with
 * args_parse(), and a commit sends system those values, as a facts
 * record, instead of the words. system checks them with args_check()
 * and passes them to the command's apply function, so system never
 * parses text.
 *
 * Unnamed arguments come first, in order. Named arguments follow in any
 * order, each as its name and its value ("ttl 64"), or as its name
 * alone ("df"). One with ARG_OPT may be left out, and one may take
 * several words (many).
 *
 * A "no" line parses the unnamed arguments with ARG_NO, which come
 * first. If the command has named arguments with ARG_NO, it then parses
 * those, and nothing else may follow. Otherwise the other arguments may
 * be given, but they are ignored and their values are absent.
 */

#ifndef ARGS_H
#define ARGS_H

#include <stdarg.h>

#define ARG_NUM		1	/* a number from min to max, or a key's word:
				   FACT_I64 */
#define ARG_WORD	2	/* one word of min to max bytes: FACT_STRING */
#define ARG_REST	3	/* the rest of the words, joined by spaces,
				   at most max bytes: FACT_STRING */
#define ARG_BITS	4	/* one or more keywords, their values OR'ed
				   together: FACT_I64 */
#define ARG_ADDR	5	/* a numeric address, IPv4 or IPv6 unless the
				   family flags say: FACT_ADDRESS */
#define ARG_FLAG	6	/* a named argument with no value, such as
				   "df": FACT_I64 1 when given */
#define ARG_B64		7	/* a base64 word that decodes to exactly max
				   bytes: FACT_BYTES */

#define ARG_OPT		0x1	/* it may be left out */
#define ARG_NO		0x2	/* parsed on a "no" line too */
#define ARG_NOOPT	0x4	/* with no, it may be left out */
#define ARG_INET	0x8	/* an IPv4 address */
#define ARG_INET6	0x10	/* an IPv6 address */
#define ARG_LINK	0x20	/* a MAC address */
#define ARG_PORT	0x40	/* an address may end in a port, as
				   "a.b.c.d:port" or "[v6addr]:port", kept
				   as a second value, FACT_I64, absent if
				   none */
#define ARG_NAMED	0x80	/* its word follows its name */
#define ARG_PREFIX	0x100	/* an address may end in "/length", as
				   inet_net_pton() reads it, kept as a
				   second value, FACT_I64 */
#define ARG_BLANKS	0x200	/* the word may contain blanks, as a quoted
				   word can */
#define ARG_COMMAS	0x400	/* a set's keys in one word, between commas */

#define ARGS_MAX	FACTS_FIELDS	/* values of a command, at most */
#define ARGS_REST	1024	/* bytes of an ARG_REST field, at most */
#define ARGS_BINS	4	/* ARG_B64 fields of a command, at most */
#define ARGS_BIN	64	/* an ARG_B64 value is shorter than this */

/* a word an ARG_NUM or ARG_BITS field takes, and its value */
struct argkey {
	const char	*word;
	long long	 value;
};

struct arg {
	const char	*name;	/* its facts field, and its word on the line
				   if it is named */
	int		 type;
	long long	 min, max;
	int		 flags;	/* ARG_OPT, ARG_NO, ARG_NAMED, ARG_INET... */
	const struct argkey *keys;	/* NULL, or ended by a NULL word */
	int		 many;	/* values it holds, if more than 1 */
	const char	*help;	/* what a usage calls it, if not its name */
};
/* a command's arguments, in its row: ended by { NULL } */
#define ARGS	(const struct arg[])

/*
 * A command config parses, as args.c takes one: what conf_cmd() makes
 * of its row in its mode's table (cmdtab, Intlist, Bridgelist), in
 * commands.c
 */
struct argcmd;
/*
 * run with the values on an interface; set is 0 for a "no" line. With a
 * candidate, the line edits it, and without one, changes the host
 */
struct cand;
typedef int	args_applyfn(const struct argcmd *, int,
		    const struct facts_value *, char *, int, struct cand *);
struct argcmd {
	const char	*name;	/* the command's word */
	int		 flags;	/* CF_* */
	/* runs its words, where a commit's edit has them */
	int		(*handler)(int, char **, ...);
	args_applyfn	*apply;
	int		 code;	/* which of apply's commands this is */
	const struct arg *args;	/* NULL if it takes none */
};
#define CF_NO		0x1	/* a top-level one takes no */
#define CF_IF		0x2	/* it heads an interface's block */
#define CF_BRIDGE	0x4	/* a bridge's block */
#define CF_RTABLE	0x8	/* an rtable's block */

/*
 * parsed values; strings point into argv, or into rest for ARG_REST,
 * and base64 values into bin
 */
struct argvals {
	int			 set;	/* 0 with no */
	struct facts_value	 v[ARGS_MAX];
	char			 rest[ARGS_REST];
	unsigned char		 bin[ARGS_BINS][ARGS_BIN];
	int			 nbin;
};

/*
 * the codes of the apply functions that serve several commands: carp.c's
 * are CARP_VHID and the rest (externs.h), and a flag's is the flag
 */
enum { MPLSLABEL = 1, TUNNELDOMAIN, TXPRIO, RXPRIO };	/* intmpls_apply() */
enum { IFMETRIC, IFPRIORITY };				/* intmetric_apply() */
enum { TUNNEL_BOTH, TUNNEL_ADDR };			/* inttunnel_apply() */
enum { UMBCMD_APN = 1, UMBCMD_PIN, UMBCMD_PUK, UMBCMD_CHGPIN, UMBCMD_CLASS,
    UMBCMD_ROAMING };					/* intumb_apply() */
enum { WG_PORT, WG_KEY, WG_RTABLE };			/* intwg_apply() */

/* limits the rows share with their files */
#define GROUP_NAMES	16	/* group names to a record; a longer line
				   goes as several (args_each()) */
#define WGPEER_AIPS	120	/* the most aips on one line, more than a
				   1023 byte line can hold */

/* what the rows name: each file's apply functions */
args_applyfn	intcarp_apply, intcpass_apply, intcnode_apply, intcdev_apply;
args_applyfn	intpatch_apply, intmtu_apply, intkeepalive_apply, intmpls_apply,
		intmetric_apply, intllprio_apply, intgroup_apply,
		intrtlabel_apply, intparent_apply, intflags_apply,
		intxflags_apply, intlink_apply, intpowersave_apply,
		intrdomain_apply, intdesc_apply, intvnetflowid_apply;
args_applyfn	intsyncdev_apply, intsyncpeer_apply, intmaxupd_apply;
args_applyfn	intsppp_apply, intpppoe_apply;
args_applyfn	inttrunkport_apply, inttrunkproto_apply, intlacp_apply;
args_applyfn	intvnetid_apply, inttunnel_apply, intcache_apply,
		intendpoint_apply;
args_applyfn	intumb_apply;
args_applyfn	intwg_apply, intwgpeer_apply;
const struct argcmd *conf_cmd(int, int, struct argcmd *);
size_t	args_n(const struct argcmd *);
const char *args_called(const struct arg *);
int	args_parse(const struct argcmd *, int, char **, struct argvals *);
int	args_each(const struct argcmd *, int, char **,
	    int (*)(const struct argcmd *, struct argvals *, void *), void *);
int	args_run(const struct argcmd *, int, char **, char *, int,
    struct cand *);
int	args_usage(const struct argcmd *);
void	args_kind(const struct argcmd *, struct facts_kind *,
	    struct facts_field *);
int	args_check(const struct argcmd *, int, const struct facts_template *,
	    const struct facts_value *);
void	args_string(const struct facts_value *, char *, size_t);
struct sockaddr_storage;
int	args_sockaddr(const struct facts_value *, int,
	    struct sockaddr_storage *);

#endif /* ARGS_H */
