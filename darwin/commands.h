/*
 * Copyright (c) 2008-2009 Chris Cappuccio <chris@nmedia.net>
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

static struct fpf {
	char *name;
	char *help;
	char *cmd;
	char *arg;
} fpfs[] = {
	{ "all",	"all PF elements",	PFCTL,	"-Fall" },
	{ "nat",	"NAT rules",		PFCTL,	"-Fnat" },
	{ "queue",	"queue rules",		PFCTL,	"-Fqueue" },
	{ "filter",	"filter rules",		PFCTL,	"-Frules" },
	{ "states",	"NAT/filter states",	PFCTL,	"-Fstate" },
	{ "stats",	"PF statistics",	PFCTL,	"-Finfo" },
	{ "tables",	"PF address tables",	PFCTL,	"-FTables" },
	{ 0, 0, 0, 0 }
};

static struct stt {
	char *name;
	char *help;
	void (*handler) ();
} stts[] = {
	{ 0,		0,					0 }
};

struct prot1 {
	char *name;
	char *help;
	char *args[32];
};

struct prot {
	char *name;
	struct prot1 *table;
};

struct prot1 bgcs[] = {
	{ "announced",  "All announced networks",
	    { BGPCTL,  "network", "show", OPT, NULL } },
	{ "interfaces", "Interface states",
	    { BGPCTL,  "show", "interfaces", NULL } },
	{ "nexthop",	"BGP nexthop routes",
	    { BGPCTL,  "show", "nexthop", NULL } },
	{ "summary",	"Neighbor session states and counters",
	    { BGPCTL,  "show", "summary", OPT, NULL } },
	{ "rib",	"Routing Information Base",
	    { BGPCTL, "show",  "rib", OPT, OPT, OPT, NULL } },
	{ "neighbor",	"Detailed peer",
	    { BGPCTL, "show",  "neighbor", REQ, OPT, NULL } },
	{ "ip",		"IP BGP",
	    { BGPCTL, "show",  "ip", "bgp", OPT, OPT, OPT, NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 oscs[] = {
	{ "fib",	"Forward Information Base",
	    { OSPFCTL, "show", "fib", OPT, OPT, NULL } },
	{ "database",	"Link State Database",
	    { OSPFCTL, "show", "database", OPT, OPT, NULL } },
	{ "interfaces",	"Interface",
	    { OSPFCTL, "show", "interfaces", OPT, NULL } },
	{ "neighbor",	"Neighbor",
	    { OSPFCTL, "show", "neighbor", OPT, NULL } },
	{ "rib",	"Routing Information Base",
	    { OSPFCTL, "show", "rib", OPT, NULL } },
	{ "summary",	"Summary",
	    { OSPFCTL, "show", "summary", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 os6cs[] = {
	{ "fib",        "Forward Information Base",
	    { OSPF6CTL, "show", "fib", OPT, OPT, NULL } },
	{ "database",   "Link State Database",
	    { OSPF6CTL, "show", "database", OPT, OPT, NULL } },
	{ "interfaces", "Interface",
	    { OSPF6CTL, "show", "interfaces", OPT, NULL } },
	{ "neighbor",   "Neighbor",
	    { OSPF6CTL, "show", "neighbor", OPT, NULL } },
	{ "rib",        "Routing Information Base",
	    { OSPF6CTL, "show", "rib", OPT, NULL } },
	{ "summary",    "Summary",
	    { OSPF6CTL, "show", "summary", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 eics[] = {
	{ "interfaces",	"Interface",
	    { EIGRPCTL, "show", "interfaces", OPT, OPT, NULL } },
	{ "neighbor",	"Neighbor",
	    { EIGRPCTL, "show", "neighbor", OPT, OPT, NULL } },
	{ "topology",	"Topology",
	    { EIGRPCTL, "show", "topology", OPT, OPT, NULL } },
	{ "traffic",	"Traffic",
	    { EIGRPCTL, "show", "traffic", OPT, OPT, NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 rics[] = {
	{ "fib",        "Forward Information Base",
	    { RIPCTL, "show", "fib", OPT, NULL } },
	{ "interfaces", "Interfaces",
	    { RIPCTL, "show", "interfaces", NULL } },
	{ "neighbor",   "Neighbor",
	    { RIPCTL, "show", "neighbor", NULL } },
	{ "rib",        "Routing Information Base",
	    { RIPCTL, "show", "rib", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 lics[] = {
	{ "fib",        "Forward Information Base",
	    { LDPCTL, "show", "fib", OPT, NULL } },
	{ "interfaces", "Interfaces",
	    { LDPCTL, "show", "interfaces", NULL } },
	{ "neighbor",   "Neighbors",
	    { LDPCTL, "show", "neighbor", NULL } },
	{ "lib",        "Label Information Base",
	    { LDPCTL, "show", "lib", NULL } },
	{ "discovery",	"Adjacencies",
	    { LDPCTL, "show", "discovery", NULL } },
	{ "l2vpn",	"Pseudowire",
	    { LDPCTL, "show", "l2vpn", OPT, NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 iscs[] = {
	{ "flows",	"Display IPsec flows",
	    { IPSECCTL, "-sf", NULL } },
	{ "sadb",	"Display SADB",
	    { IPSECCTL, "-ss", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 ikcs[] = {
	{ "monitor",	"Monitor internal iked messages",
	    { IKECTL, "monitor", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 dvcs[] = {
	{ "igmp",       "Internet Group Message Protocol",
	    { DVMRPCTL, "show", "igmp", NULL } },
	{ "interfaces", "Interfaces",
	    { DVMRPCTL, "show", "interfaces", OPT, NULL } },
	{ "mfc",        "Multicast Forwarding Cache",
	    { DVMRPCTL, "show", "mfc", OPT, NULL } },
	{ "neighbor",   "Neighbor",
	    { DVMRPCTL, "show", "neighbor", OPT, NULL } },
	{ "rib",        "Routing Information Base",
	    { DVMRPCTL, "show", "rib", OPT, NULL } },
	{ "summary",    "Summary",
	    { DVMRPCTL, "show", "summary", NULL } },
        { 0, 0, { 0 } }
};

struct prot1 rlcs[] = {
	{ "hosts",      "hosts",
	    { RELAYCTL, "show", "hosts", NULL } },
	{ "redirects",  "redirects",
	    { RELAYCTL, "show", "redirects", NULL } },
	{ "status",     "status",
	    { RELAYCTL, "show", "relays", NULL } },
	{ "sessions",   "sessions",
	    { RELAYCTL, "show", "sessions", NULL } },
	{ "summary",    "summary",
	    { RELAYCTL, "show", "summary", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 smcs[] = {
	{ "queue",	"envelopes in queue",
	    { SMTPCTL, "show", "queue", NULL } },
	{ "runqueue",	"envelopes scheduled for delivery",
	    { SMTPCTL, "show", "runqueue", NULL } },
	{ "stats",	"runtime statistics",
	    { SMTPCTL, "show", "stats", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 dhcs[] = {
	{ "leases",	"leases", { 0 } },
	{ 0, 0, { 0 } }
};

struct prot1 ldcs[] = {
	{ "stats",	"statistics counters",
	    { LDAPCTL, "stats", NULL } },
	{ 0, 0, { 0 } }
};

/* show yyy zzz */
struct prot prots[] = {
	{ "bgp",	bgcs },
	{ "ospf",	oscs },
	{ "ospf6",	os6cs },
	{ "rip",	rics },
	{ "ike",	ikcs },
	{ "ipsec",	iscs },
	{ "ldp",	lics },
	{ "dvmrp",	dvcs },
	{ "relay",	rlcs },
	{ "smtp",	smcs },
	{ "ldap",	ldcs },
	{ 0,		0 }
};
