/*
 * Copyright (c) 2008 Chris Cappuccio <chris@nmedia.net>
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

#include <sys/param.h>	/* MAXHOSTNAMELEN */
#include <net/if.h>	/* IFNAMSIZ */

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "externs.h"
#include "commands.h"
#include "ctl.h"

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

struct prot1 pfcs[] = {
	{ "all",           "all pf info except fingerprints and interfaces", 
            { PFCTL, "-sall", NULL, NULL, NULL, NULL } },
	{ "anchors",       "currently loaded anchors in main pf ruleset", 
            { PFCTL, "-sAnchors", NULL, NULL, NULL } },	
        { "info ",         "pf filter statistics, counters and tracking",
            { PFCTL, "-sinfo", "-v", NULL, NULL, NULL } },
        { "labels",        "per rule stats (bytes, packets and states)",        
            { PFCTL, "-slabels", NULL, NULL, NULL, NULL } },
        { "memory",        "current pf pool memory hard limit",
            { PFCTL, "-smemory", NULL, NULL, NULL, NULL } },
	{ "queues",        "currently loaded pf queue definition", 
            { PFCTL, "-squeue", "-v", NULL, NULL, NULL } },
	{ "rules",         "active pf firewall rule",
            { PFCTL, "-srules", NULL, NULL, NULL, NULL } },
	{ "sources",       "contents of the pf source tracking table", 
            { PFCTL, "-sSources", NULL, NULL, NULL, NULL } },
	{ "states",        "contents of the pf state table",
            { PFCTL, "-sstates", NULL, NULL, NULL, NULL } },
        { "tables",        "pf table",
            { PFCTL, "-sTables", NULL, NULL, NULL, NULL } },
	{ "timeouts",      "current pf global timeout", 
            { PFCTL, "-stimeouts", NULL, NULL, NULL, NULL } },
	{ "osfingerprint", "pf Operating System fingerprint", 
            { PFCTL, "-sosfp", NULL, NULL, NULL, NULL } },
	{ "interfaces",    "pf usable interfaces/ interface group", 
            { PFCTL, "-sInterfaces", NULL, NULL, NULL, NULL } },
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

struct prot1 systatcs[] = {
	{ "interface",		"Interface",
		{ SYSTAT,  "-d 3", "ifstat", NULL, NULL, NULL }  },
	{ "net",		"Network connection", 
		{ SYSTAT,  "-d 3", "netstat", NULL, NULL, NULL }  },
	{ "mbuf",		"Network data memory buffer",
		{ SYSTAT,  "-d 3", "mbuf", NULL, NULL, NULL }  }, 
	{ "queues",		"Active Packet Filter queue",
		{ SYSTAT,  "-d 3", "queues", NULL, NULL, NULL }  },
	{ "rules",		"Active Packet Filter rule",
		{ SYSTAT,  "-d 3", "rules", NULL, NULL, NULL }  },
	{ "states",		"Packet Filter connection state",
		{ SYSTAT,  "-d 3", "state", NULL, NULL, NULL }  },
	{ "packet-filter",	"Packet Filter ",
		{ SYSTAT,  "-d 3", "pf", NULL, NULL, NULL }  },
	{ "sensors",		"Supported hardware sensor reading",
		{ SYSTAT,  "-d 3", "sensors", NULL, NULL, NULL }  },
	{ "pigs",		"CPU resource hog program",
		{ SYSTAT,  "-d 3", "pigs", NULL, NULL, NULL }  },
	{ "virtual-memory",	"Virtual memory usage",
		{ SYSTAT,  "-d 3", "vmstat", NULL, NULL, NULL }  },
	{ "cpu",		"CPU usage",
		{ SYSTAT,  "-d 3", "cpu", NULL, NULL, NULL }  },
	{ "uvm",		"UVM subsystem",
		{ SYSTAT,  "-d 3", "uvm", NULL, NULL, NULL }  },
	{ "swap",		"Swap space usage",
		{ SYSTAT,  "-d 3", "swap", NULL, NULL, NULL }  },
	{ "pool",		"Kernel pool usage",
		{ SYSTAT,  "-d 3", "pool", NULL, NULL, NULL }  },
	{ "pcache",		"Kernel pool per CPU cache",
		{ SYSTAT,  "-d 3", "pcache", NULL, NULL, NULL }  },
	{ "malloc",		"Kernel memory allocation type",
		{ SYSTAT,  "-d 3", "malloc", NULL, NULL, NULL }  },
	{ "bucket",             "Kernel malloc bucket",
		{ SYSTAT,  "-d 3", "bucket", NULL, NULL, NULL }  },
	{ 0, 0, { 0 } }
};

int
pr_prot1(int argc, char **argv, ...)
{
	struct prot1 *x;
	struct prot *prot;
	char *args[NOPTFILL] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	char **fillargs;
	char prefix[64];

	/* loop protocol list to find table pointer */
	prot = (struct prot *) genget(argv[1], (char **)prots,
	    sizeof(struct prot));
	if (prot == 0) {
		printf("%% Internal error - Invalid argument %s\n", argv[1]);
		return -1;
	} else if (Ambiguous(prot)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[1]);
		return -1;
	}

	snprintf(prefix, sizeof(prefix), "show %s", prot->name);

	/* no clue? we can help */
	if (argc < 3 || argv[2][0] == '?') {
		gen_help((char **)prot->table, prefix, "information",
		    sizeof(struct prot1));
		return 0;
	}
	x = (struct prot1 *) genget(argv[2], (char **)prot->table,
	    sizeof(struct prot1));
	if (x == 0) {
		printf("%% Invalid argument %s\n", argv[2]);
		return -1;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", argv[2]);
		return -1;
	}

	fillargs = step_optreq(x->args, args, argc, argv, 3);
	if (fillargs == NULL)
		return -1;

	/* systat draws on this terminal; prot1_run() runs the rest */
	if (prot1_find(prot->name, x->name) == NULL)
		return cmdargs(fillargs[0], fillargs) == 0 ? 0 : -1;
	return prot1_run(prot->name, x->name, argc - 3, argv + 3, fillargs);
}

/*
 * The show of prot that sub names, as pr_prot1() names them, whose
 * program nshd's system may run: NULL if there is none, as for systat,
 * which draws on nsh's terminal
 */
struct prot1 *
prot1_find(char *prot, char *sub)
{
	struct prot *p;
	struct prot1 *x;
	size_t len = strlen(sub);

	for (p = prots; p->name != NULL; p++)
		if (strcmp(p->name, prot) == 0)
			break;
	if (p->name == NULL || strcmp(p->name, "system-stats") == 0)
		return NULL;
	/* a name in the table may end with spaces */
	for (x = p->table; x->name != NULL; x++)
		if (strncmp(x->name, sub, len) == 0 &&
		    x->name[len + strspn(x->name + len, " ")] == '\0')
			return x;
	return NULL;
}

/*
 * Put x's program and its arguments in args, filling the arguments x
 * leaves open from the argc words of argv, with bgpctl's socket for
 * rtable table. Returns NULL, after printing why, if the words do not
 * fit
 */
char **
prot1_args(struct prot1 *x, char **args, int argc, char **argv, int table)
{
	init_bgpd_socket_path(table);
	return step_optreq(x->args, args, argc, argv, 0);
}

char **
step_optreq(char **xargs, char **args, int argc, char **argv, int skip)
{
	int i;
	int fill = 0;	/* total fillable arguments */
	int flc = 0;	/* number of filled arguments */

	/* count fillable arguments */
	for (i = 0; i < NOPTFILL - 1; i++) {
		if (xargs[i] == OPT || xargs[i] == REQ)
			fill++;
		if (xargs[i] == NULL)
			break;
	}

	if (argc - skip > fill) {
		printf("%% Superfluous argument: %s\n", argv[skip + fill]);
		return NULL;
	}

	/* copy xargs to args, replace OPT/REQ args with argv past skip */
	for (i = 0; i < NOPTFILL - 1; i++) {
		if (xargs[i] == NULL) {
			args[i] = NULL;
			if (i > 1)
			/*
			 * all **args passed must have at least two arguments
			 * and a terminating NULL.  the point of this check
			 * is to allow the first two arguments to be NULL but
			 * still fill in fillargs[x] with corresponding NULL
			 */
				break;
		}
		if (xargs[i] == OPT || xargs[i] == REQ) {
			/* copy from argv to args */
			if (argc - skip - flc > 0) {
				args[i] = argv[skip + flc];
				flc++;
			} else if (xargs[i] == REQ) {
				printf("%% Missing required argument\n");
				return NULL;
			} else {
				args[i] = NULL;
				break;
			}
		} else {
			/* copy from xargs to args */
			args[i] = xargs[i];
		}
	}

	return args;
}
