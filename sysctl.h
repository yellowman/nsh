/*
 * Copyright (c) 2012 Chris Cappuccio <chris@nmedia.net>
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

struct ipsysctl {
	char           *name;
	int             mib[6];
	int32_t         def_larg;	/* default value, or 0 for on/off
					 * sysctls */
	int             enable;	/* if on/off sysctl, 0 default is enabled, 1
				 * default is disabled, 2 always show ena ble
				 * or disable */
};

struct sysctltab {
	char           *name;
	int             pf;
	Menu           *table;
	struct ipsysctl *sysctl;
};

extern struct sysctltab sysctls[];
extern struct ipsysctl ipsysctls[];
extern struct ipsysctl ip6sysctls[];
extern struct ipsysctl mplssysctls[];
extern struct ipsysctl ddbsysctls[];
extern struct ipsysctl pipexsysctls[];
extern Menu iptab[];
extern Menu ip6tab[];
extern Menu mplstab[];
extern Menu ddbtab[];
extern Menu pipextab[];

#define DEFAULT_MAXDYNROUTES	4096	/* net.inet6.ip6.maxdynroutes */
#define DEFAULT_NEIGHBORGCTHRESH 2048   /* net.inet6.ip6.neighborgcthresh */
