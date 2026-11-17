/*
 * Unit tests for session.c: each session's copy of the globals a
 * handler keeps between requests. session_enter() must put a session's
 * own values in place, session_leave() keep them and put back the
 * process's as they were before the first session, and no session may
 * see another's.
 *
 * Links session.c only. The globals are this file's, declared as
 * externs.h declares them, and so are the SGLOBAL tables of
 * candidate.c, commands.c, ctl.c and if.c: one global each, enough to
 * see that every table is walked. t_globals.sh checks the real tables
 * against globals.list.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../externs.h"
#include "../commands.h"
#include "../ctl.h"
#include "../session.h"
#include "test.h"

/* main.c's, makeargv.c's, prompt.c's and bgpcommands.c's */
int priv, cli_rtable, config_mode, bridge, verbose;
char line[1024], saveline[1024];
int margc;
char *margv[NARGS];
size_t cursor_argc, cursor_argo;
char prompt[128], saved_prompt[sizeof(prompt)];
char bgpd_socket_path[PATH_MAX];

/* one global for each of the other files' tables */
static int cand_g, cmd_g, ctl_g, if_g;
struct sglobal candidate_sglobals[] = { SGLOBAL(cand_g), { NULL } };
struct sglobal commands_sglobals[] = { SGLOBAL(cmd_g), { NULL } };
struct sglobal ctl_sglobals[] = { SGLOBAL(ctl_g), { NULL } };
struct sglobal if_sglobals[] = { SGLOBAL(if_g), { NULL } };

/* what session_free() saw when it let go of a session's things */
static int cand_ended, rules_done, priv_at_end;

void
cand_end(void)
{
	cand_ended++;
	priv_at_end = priv;
}

void
ctl_rules_done(void)
{
	rules_done++;
}

static void
test_globals_listed(void)
{
	static const char *want[] = {
		"priv", "cli_rtable", "config_mode", "bridge", "verbose",
		"line", "saveline", "margc", "margv", "cursor_argc",
		"cursor_argo", "prompt", "saved_prompt", "bgpd_socket_path",
		"cand_g", "cmd_g", "ctl_g", "if_g", NULL
	};
	const struct sglobal *g;
	size_t i;

	for (i = 0; want[i] != NULL; i++) {
		g = session_global(i);
		CHECK(g != NULL);
		if (g == NULL)
			return;
		CHECK_STR(g->name, want[i]);
	}
	CHECK(session_global(i) == NULL);

	/* each the size it is, not a pointer's */
	CHECK(session_global(5)->size == sizeof(line));
	CHECK(session_global(8)->size == sizeof(margv));
	CHECK(session_global(13)->size == PATH_MAX);
}

/* the process before any session */
static void
set_process(void)
{
	priv = 0;
	cli_rtable = 0;
	config_mode = 0;
	strlcpy(prompt, "nsh/", sizeof(prompt));
	strlcpy(line, "", sizeof(line));
	margc = 0;
	margv[0] = NULL;
	cand_g = cmd_g = ctl_g = if_g = 0;
}

static void
test_enter_leave(void)
{
	struct session_state *a, *b;

	set_process();
	a = session_new();
	b = session_new();
	CHECK(a != NULL && b != NULL);
	if (a == NULL || b == NULL)
		return;

	/* a new session starts as the process was */
	session_enter(a);
	CHECK(priv == 0 && cli_rtable == 0);
	CHECK_STR(prompt, "nsh/");

	/* what a does stays a's */
	priv = 1;
	cli_rtable = 5;
	config_mode = 1;
	strlcpy(prompt, "nsh(config-p)/", sizeof(prompt));
	cand_g = cmd_g = ctl_g = if_g = 7;
	session_leave(a);

	/* and the process is as it was */
	CHECK(priv == 0 && cli_rtable == 0 && config_mode == 0);
	CHECK_STR(prompt, "nsh/");
	CHECK(cand_g == 0 && cmd_g == 0 && ctl_g == 0 && if_g == 0);

	/* b sees none of it */
	session_enter(b);
	CHECK(priv == 0 && cli_rtable == 0 && config_mode == 0);
	CHECK(cand_g == 0 && if_g == 0);
	verbose = 1;
	session_leave(b);

	/* a has its own back */
	session_enter(a);
	CHECK(priv == 1 && cli_rtable == 5 && config_mode == 1);
	CHECK_STR(prompt, "nsh(config-p)/");
	CHECK(cand_g == 7 && cmd_g == 7 && ctl_g == 7 && if_g == 7);
	CHECK(verbose == 0);
	session_leave(a);

	session_free(a);
	session_free(b);
}

/* margv points into line, which a session keeps too */
static void
test_margv_into_line(void)
{
	struct session_state *a, *b;

	set_process();
	a = session_new();
	b = session_new();
	if (a == NULL || b == NULL) {
		CHECK(0);
		return;
	}
	session_enter(a);
	strlcpy(line, "show route", sizeof(line));
	line[4] = '\0';
	margv[0] = line;
	margv[1] = line + 5;
	margv[2] = NULL;
	margc = 2;
	session_leave(a);

	session_enter(b);
	strlcpy(line, "ping 192.0.2.1", sizeof(line));
	session_leave(b);

	session_enter(a);
	CHECK(margc == 2);
	CHECK(margv[0] == line);
	CHECK_STR(margv[0], "show");
	CHECK_STR(margv[1], "route");
	session_leave(a);

	session_free(a);
	session_free(b);
}

static void
test_free(void)
{
	struct session_state *a;

	set_process();
	if ((a = session_new()) == NULL) {
		CHECK(0);
		return;
	}
	session_enter(a);
	priv = 1;
	session_leave(a);

	/* a's candidate and rules file are let go of as a's */
	cand_ended = rules_done = priv_at_end = 0;
	session_free(a);
	CHECK(cand_ended == 1 && rules_done == 1);
	CHECK(priv_at_end == 1);
	/* and the process is untouched */
	CHECK(priv == 0);

	session_free(NULL);
	CHECK(cand_ended == 1);
}

/* many sessions, each its own */
static void
test_many(void)
{
	struct session_state *s[64];
	int i, ok = 1;

	set_process();
	for (i = 0; i < 64; i++) {
		if ((s[i] = session_new()) == NULL) {
			CHECK(0);
			return;
		}
		session_enter(s[i]);
		cli_rtable = i;
		snprintf(prompt, sizeof(prompt), "s%d/", i);
		session_leave(s[i]);
	}
	for (i = 63; i >= 0; i--) {
		session_enter(s[i]);
		if (cli_rtable != i || strncmp(prompt, "s", 1) != 0 ||
		    atoi(prompt + 1) != i)
			ok = 0;
		session_leave(s[i]);
		session_free(s[i]);
	}
	CHECK(ok);
	CHECK(cli_rtable == 0);
}

int
main(void)
{
	RUN(test_globals_listed);
	RUN(test_enter_leave);
	RUN(test_margv_into_line);
	RUN(test_free);
	RUN(test_many);
	DONE();
}
