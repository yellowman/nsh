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
 * Kernel statistics: the groups show kernel has, each a structure of
 * the kernel's. rendersys.c holds the groups and prints them; stats.c
 * gets them from the kernel. Include the kernel's headers for struct
 * mbstat, struct kinfo_pool and pf's status first.
 */

#define STATS_SYSCTL	0	/* the group's sysctl */
#define STATS_MBUF	1	/* mbuf statistics, and their pools */
#define STATS_PF	2	/* pf's status, from /dev/pf */

/* a member of a statistics structure, or an array of them */
struct statfield {
	const char	*name;
	size_t		 off;
	size_t		 size;		/* size of one element */
	size_t		 n;
	int		 string;	/* a string, not a number */
};

/* a group of statistics: where it comes from, and how it prints */
struct statgroup {
	const char		*word;
	const char		*fn;		/* name in error messages */
	int			 mib[6];
	u_int			 miblen;
	int			 none;		/* the errno of no such group */
	size_t			 size;
	const struct statfield	*f;
	size_t			 nf;
	int			 get;		/* STATS_*: how nshd gets it */
	void			(*print)(void *);
	int			 root;		/* only root may get it */
	struct facts_kind	 kind;
	size_t			*off, *sz;	/* field offsets and sizes */
};

/* what mb_print() prints */
struct mbinfo {
	struct mbstat		 mbstat;
	struct kinfo_pool	 mbpool, mclpool;
	int			 page_size;
};

/* what pfctl -s info prints */
struct pfinfo {
	struct pf_status	 status;
	struct pfioc_synflwats	 wats;
};
