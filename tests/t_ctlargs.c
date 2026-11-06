/*
 * Unit tests for ctlargs.c: how "show <protocol> <what> [args]" becomes
 * a daemon control program's argument list. step_optreq() fills each
 * OPT and REQ slot of a table entry from the words typed; prot1_find()
 * says which shows nshd's system may run; pr_prot1() puts them together.
 *
 * Links ctlargs.c and genget.c only. The protocol tables are this
 * file's: the bgp one is bgpcommands.c's, copied, as its socket
 * argument is two words and that is what the known bug is about.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <limits.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../externs.h"
#include "../commands.h"
#include "../ctl.h"
#include "test.h"

/* bgpcommands.c's */
char bgpd_socket_path[PATH_MAX] = BGPD_SOCKET_PATH;
#define BGPSOCK "-s", bgpd_socket_path

/* bgpcommands.c:34-50, as it is */
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

/* commands.c's ospf table, as it is */
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

/* a name that ends in spaces, as some tables' do, and systat's table */
struct prot1 tscs[] = {
	{ "padded   ",	"Padded name",
	    { "/bin/test", "padded", NULL } },
	{ 0, 0, { 0 } }
};
struct prot1 systatcs[] = {
	{ "vmstat",	"Kernel statistics",
	    { "/usr/bin/systat", "vmstat", NULL } },
	{ 0, 0, { 0 } }
};

struct prot prots[] = {
	{ "bgp",		bgcs },
	{ "ospf",		oscs },
	{ "test",		tscs },
	{ "system-stats",	systatcs },
	{ 0,		0 }
};

/* what pr_prot1() handed on */
static char *ran[NOPTFILL + 1];
static int nran, ran_by_nshd, ran_here, helped;

static void
keep(char **args)
{
	int i;

	for (i = 0; i < NOPTFILL && args[i] != NULL; i++)
		ran[i] = args[i];
	ran[i] = NULL;
	nran = i;
}

int
prot1_run(char *prot, char *sub, int argc, char **argv, char **args)
{
	ran_by_nshd++;
	keep(args);
	return 0;
}

int
cmdargs(char *cmd, char **args)
{
	ran_here++;
	keep(args);
	return 0;
}

void
gen_help(char **x, char *cmdprefix, char *dash, int stlen)
{
	helped++;
}

void
init_bgpd_socket_path(int rtable)
{
}

static void
clear(void)
{
	memset(ran, 0, sizeof(ran));
	nran = ran_by_nshd = ran_here = helped = 0;
}

/* "show" and the words given, as pr_prot1() gets them */
static int
show(const char *w0, const char *w1, const char *w2, const char *w3,
    const char *w4)
{
	char *argv[7] = { "show", (char *)w0, (char *)w1, (char *)w2,
	    (char *)w3, (char *)w4, NULL };
	int argc = 1;

	while (argc < 6 && argv[argc] != NULL)
		argc++;
	clear();
	return pr_prot1(argc, argv);
}

/* the argument list that ran: its words from first, as one string */
static const char *
ranfrom(int first)
{
	static char s[512];
	int i;

	s[0] = '\0';
	for (i = first; i < nran; i++) {
		if (i > first)
			strlcat(s, " ", sizeof(s));
		strlcat(s, ran[i], sizeof(s));
	}
	return s;
}

static void
test_step_optreq(void)
{
	char *tmpl[] = { "prog", "show", "x", OPT, OPT, NULL };
	char *req[] = { "prog", "show", REQ, OPT, NULL };
	char *args[NOPTFILL];
	char *words[] = { "a", "b", "c" };
	char **r;

	/* no words: the fixed part, ended at the first OPT */
	memset(args, 0xff, sizeof(args));
	r = step_optreq(tmpl, args, 0, words, 0);
	CHECK(r == args);
	CHECK_STR(args[0], "prog");
	CHECK_STR(args[2], "x");
	CHECK(args[3] == NULL);

	/* each word fills the next OPT */
	memset(args, 0xff, sizeof(args));
	r = step_optreq(tmpl, args, 1, words, 0);
	CHECK(r != NULL && args[3] == words[0] && args[4] == NULL);
	memset(args, 0xff, sizeof(args));
	r = step_optreq(tmpl, args, 2, words, 0);
	CHECK(r != NULL && args[3] == words[0] && args[4] == words[1] &&
	    args[5] == NULL);

	/* more words than slots */
	CHECK(step_optreq(tmpl, args, 3, words, 0) == NULL);

	/* skip: the first words are the command's own */
	memset(args, 0xff, sizeof(args));
	r = step_optreq(tmpl, args, 3, words, 2);
	CHECK(r != NULL && args[3] == words[2] && args[4] == NULL);

	/* a REQ slot must be filled; the OPT after it need not be */
	CHECK(step_optreq(req, args, 0, words, 0) == NULL);
	memset(args, 0xff, sizeof(args));
	r = step_optreq(req, args, 1, words, 0);
	CHECK(r != NULL && args[2] == words[0] && args[3] == NULL);
}

static void
test_prot1_find(void)
{
	CHECK(prot1_find("ospf", "database") == &oscs[1]);
	CHECK(prot1_find("bgp", "neighbor") == &bgcs[5]);
	/* a table name's trailing spaces are not part of it */
	CHECK(prot1_find("test", "padded") == &tscs[0]);
	CHECK(prot1_find("test", "pad") == NULL);
	/* exact names only, unknown ones not */
	CHECK(prot1_find("ospf", "data") == NULL);
	CHECK(prot1_find("nosuch", "database") == NULL);
	/* systat draws on nsh's terminal: never nshd's to run */
	CHECK(prot1_find("system-stats", "vmstat") == NULL);
}

static void
test_pr_prot1(void)
{
	/* help, and refusals */
	CHECK(show("ospf", NULL, NULL, NULL, NULL) == 0 && helped == 1);
	CHECK(show("ospf", "?", NULL, NULL, NULL) == 0 && helped == 1);
	CHECK(show("nosuch", "x", NULL, NULL, NULL) == -1);
	CHECK(show("ospf", "nosuch", NULL, NULL, NULL) == -1);
	CHECK(show("ospf", "rib", "a", "b", NULL) == -1 && nran == 0);

	/* nshd's system runs the daemons' shows, abbreviated or not */
	CHECK(show("ospf", "data", "router", NULL, NULL) == 0);
	CHECK(ran_by_nshd == 1 && ran_here == 0);
	CHECK_STR(ranfrom(1), "show database router");

	/* nsh runs systat itself */
	CHECK(show("system-stats", "vmstat", NULL, NULL, NULL) == 0);
	CHECK(ran_by_nshd == 0 && ran_here == 1);

	/* bgpctl gets its socket */
	CHECK(show("bgp", "summary", NULL, NULL, NULL) == 0);
	CHECK_STR(ranfrom(1), "-s " BGPD_SOCKET_PATH " show summary");
	CHECK(show("bgp", "neighbor", "192.0.2.1", NULL, NULL) == 0);
	CHECK_STR(ranfrom(3), "show neighbor 192.0.2.1");
	CHECK(show("bgp", "neighbor", NULL, NULL, NULL) == -1);
}

/*
 * BGPSOCK is two words, so each bgp entry is two longer than it looks,
 * and step_optreq() sees only NOPTFILL - 1 of them: slots past that are
 * neither counted nor filled
 */
static void
test_bgp_args(void)
{
	int r;

	r = show("bgp", "neighbor", "192.0.2.1", "timers", NULL);
	KNOWN_BUG(r == 0 && strcmp(ranfrom(3),
	    "show neighbor 192.0.2.1 timers") == 0,
	    "show bgp neighbor <peer> timers: Superfluous argument"
	    " (NOPTFILL, ctlargs.c step_optreq)");

	r = show("bgp", "rib", "in", "detail", NULL);
	KNOWN_BUG(r == 0 && strcmp(ranfrom(3), "show rib in detail") == 0,
	    "show bgp rib takes 1 of its 3 arguments (NOPTFILL)");

	r = show("bgp", "ip", "192.0.2.0/24", NULL, NULL);
	KNOWN_BUG(r == 0 && strcmp(ranfrom(3), "show ip bgp 192.0.2.0/24")
	    == 0, "show bgp ip takes none of its 3 arguments (NOPTFILL)");

	/* the longest entry must fit: ip's 9 words and its NULL */
	KNOWN_BUG(NOPTFILL >= 10,
	    "NOPTFILL is less than bgpcommands.c's longest entry needs");
}

int
main(void)
{
	RUN(test_step_optreq);
	RUN(test_prot1_find);
	RUN(test_pr_prot1);
	RUN(test_bgp_args);
	DONE();
}
