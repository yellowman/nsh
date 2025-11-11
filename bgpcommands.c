/*
 * Copyright (c) 2008-2009 Chris Cappuccio <chris@nmedia.net>
 * Copyright (c) 2023 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/param.h>
#include <sys/types.h>

#include <net/if.h>

#include <limits.h>
#include <stdio.h>

#include "externs.h"
#include "commands.h"
#include "ctl.h"

char bgpd_socket_path[PATH_MAX];

#define BGPSOCK "-s", bgpd_socket_path

struct prot1 bgcs[] = {
	{ "announced",  "All announced networks",
	    { BGPCTL,  BGPSOCK, "network", "show", OPT, NULL } },
	{ "interfaces", "Interface states",
	    { BGPCTL,  BGPSOCK, "show", "interfaces", NULL } },
	{ "nexthop",	"BGP nexthop routes",
	    { BGPCTL,  BGPSOCK, "show", "nexthop", NULL } },
	{ "summary",	"Neighbor session states and counters",
	    { BGPCTL,  BGPSOCK, "show", "summary", OPT, NULL } },
	{ "rib",	"Routing Information Base",
	    { BGPCTL, BGPSOCK, "show",  "rib", OPT, OPT, OPT, NULL } },
	{ "neighbor",	"Detailed peer",
	    { BGPCTL, BGPSOCK, "show",  "neighbor", REQ, OPT, NULL } },
	{ "ip",		"IP BGP",
	    { BGPCTL, BGPSOCK, "show",  "ip", "bgp", OPT, OPT, OPT, NULL } },
	{ 0, 0, { 0 } }
};

/* Initialize the globally stored BGPD socket path. */
void
init_bgpd_socket_path(int rtable)
{
	snprintf(bgpd_socket_path, sizeof(bgpd_socket_path),
	    "%s.%d", BGPD_SOCKET_PATH, rtable);
}
