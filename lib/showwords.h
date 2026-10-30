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
 * A show's words, as facts_answer() (showfacts.c) reads them: what they
 * ask for, and who answers. nsh reads them to ask the one that answers,
 * and nshd to answer them (nshd/answer.c)
 */

#ifndef SHOWWORDS_H
#define SHOWWORDS_H

enum answer_type {
	ANS_INTERFACE, ANS_ROUTE, ANS_LOOKUP, ANS_ARP, ANS_NDP, ANS_VLAN,
	ANS_BRIDGE, ANS_STATISTICS, ANS_VERSION, ANS_USERS, ANS_HOSTNAME,
	ANS_IP, ANS_AUTOCONF, ANS_SADB, ANS_PROGRAM, ANS_LEASES, ANS_DAEMONS
};

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
};

#endif /* SHOWWORDS_H */
