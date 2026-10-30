/*
 * Copyright (c) 2002-2008 Chris Cappuccio <chris@nmedia.net>
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
 * Copyright (c) 1988, 1990, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * nsh's command loop.  nsh reads a line and runs it as nshd's command
 * rows say (tables.c): as one of nsh's own commands, which owntab
 * names; as a line of nshd's session; as an operation that nshd's
 * system runs; or as the edit of a daemon's rules.  nsh asks nshd for
 * the rows before each line, until nshd sends them.  Until then, as
 * where nshd does not run, nsh runs only its own commands.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "editing.h"
#include "stringlist.h"
#include "externs.h"
#include "commands.h"
#include "nshcmds.h"
#include "facts.h"
#include "kfacts.h"
#include "tables.h"

static int	run_line(char *);
static int	run(int, char **, char *);
static int	run_code(char **, int, struct ghs *, int, char **, int);
static int	run_own(char *, int, int, char **);
static int	run_op(char *, int, int, char **, int);
static int	rules_edit(char *);
static void	rows_ask(void);
static int	nsh_exit(int, char **, ...);
static int	nsh_rtable(int, char **, ...);

extern volatile sig_atomic_t caught_sigwinch;
extern struct ghs mantab[];

static char	*said;		/* the text being run: a line, or do's part */

/* owntab's flush's words: the flush nsh runs itself, and flush's help */
static struct ghs flushown[] = {
	{ "history",	"Command history",	CMPL0 0, 0 },
	{ "?",		"Options",		CMPL0 0, 0 },
	{ "help",	0,			CMPL0 0, 0 },
	{ 0,		0,			CMPL0 0, 0 }
};

/*
 * nsh's own commands, each with a row like nshd's cmdtab's: the commands
 * that nshd's rows leave to nsh.  Until nshd sends rows, they are nsh's
 * command table
 */
static Command owntab[] = {
	{ "rtable",	rtablehelp,	CMPL0 0, 0, nsh_rtable, 0, 0, 1, 2 },
	{ "show",	showhelp,	CMPL(ta) (char **)showlist,
	    sizeof(Menu), showcmd, 0, 0, 0, 0 },
	{ "flush",	flushhelp,	CMPL(ta) (char **)flushown,
	    sizeof(struct ghs), flushcmd, 1, 0, 0, 0 },
	{ "clear",	clearhelp,	CMPL0 0, 0, clear, 0, 0, 0, 0 },
	{ "ping",	pinghelp,	CMPL0 0, 0, ping, 0, 0, 0, 0 },
	{ "ping6",	ping6help,	CMPL0 0, 0, ping6, 0, 0, 0, 0 },
	{ "traceroute",	tracerthelp,	CMPL0 0, 0, traceroute, 0, 0, 0, 0 },
	{ "traceroute6", tracert6help,	CMPL0 0, 0, traceroute6, 0, 0, 0, 0 },
	{ "ssh",	sshhelp,	CMPL0 0, 0, ssh, 0, 0, 0, 0 },
	{ "telnet",	telnethelp,	CMPL0 0, 0, telnet, 0, 0, 0, 0 },
	{ "reboot",	nreboothelp,	CMPL0 0, 0, nreboot, 1, 0, 0, 0 },
	{ "logger",	loggerhelp,	CMPL0 0, 0, logger, 0, 0, 0, 0 },
	{ "halt",	halthelp,	CMPL0 0, 0, halt, 1, 0, 0, 0 },
	{ "powerdown",	powerdownhelp,	CMPL0 0, 0, powerdown, 1, 0, 0, 0 },
	{ "verbose",	verbosehelp,	CMPL0 0, 0, doverbose, 0, 0, 1, 0 },
	{ "editing",	editinghelp,	CMPL0 0, 0, doediting, 0, 0, 1, 0 },
	{ "configure",	confighelp,	CMPL0 0, 0, doconfig, 1, 0, 1, 0 },
	{ "commit",	commithelp,	CMPL0 0, 0, commit, 1, 0, 0, 0 },
	{ "rollback",	rollbackhelp,	CMPL0 0, 0, cand_rollback, 1, 1, 0, 0 },
	{ "who",	whohelp,	CMPL0 0, 0, who, 0, 0, 0, 0 },
	{ "no",		0,		CMPL(c) 0, 0, nocmd, 0, 0, 0, 0 },
	{ "do",		dohelp,		CMPL(c) 0, 0, docmd, 0, 0, 0, 0 },
	{ "setenv",	setenvhelp,	CMPL(E) 0, 0, setenvcmd, 0, 0, 0, 0 },
	{ "unsetenv",	unsetenvhelp,	CMPL(e) 0, 0, unsetenvcmd, 0, 0, 0, 0 },
	{ "saveenv",	saveenvhelp,	CMPL0 0, 0, saveenvcmd, 0, 0, 0, 0 },
	{ "!",		shellhelp,	CMPL0 0, 0, shell, 1, 0, 0, 0 },
	{ "?",		helphelp,	CMPL(c) 0, 0, help, 0, 0, 0, 0 },
	{ "manual",	manhelp,	CMPL(H) (char **)mantab,
	    sizeof(struct ghs), manual, 0, 0, 0, 0 },
	{ "exit",	exithelp,	CMPL0 0, 0, nsh_exit, 1, 0, 0, 0 },
	{ "quit",	quithelp,	CMPL0 0, 0, quit, 0, 0, 0, 0 },
	{ "help",	0,		CMPL(c) 0, 0, help, 0, 0, 0, 0 },
	{ 0,		0,		CMPL0 0, 0, 0, 0, 0, 0, 0 }
};

/* nsh's own commands in an interface's or a bridge's mode */
static const struct {
	const char	*name;
	int		(*handler)(int, char **, ...);
} ownif[] = {
	{ "ping",	int_ping },
	{ "ping6",	int_ping6 },
	{ "traceroute",	int_traceroute },
	{ "traceroute6", int_traceroute6 },
	{ "ssh",	int_ssh },
	{ "telnet",	int_telnet },
	{ "logger",	int_logger },
	{ "do",		int_do },
	{ "setenv",	int_setenv },
	{ "unsetenv",	int_unsetenv },
	{ "saveenv",	int_saveenv },
	{ "show",	int_show },
	{ "who",	int_who },
	{ "verbose",	int_doverbose },
	{ "editing",	int_doediting },
	{ "clear",	int_clear },
	{ "!",		int_shell },
	{ "?",		int_help },
	{ "manual",	int_manual },
	{ "help",	int_help },
};

/*
 * Read lines and run each, until a line is empty, or a command returns
 * 1; main() then calls this again
 */
void
command(void)
{
	u_int num;

	init_bgpd_socket_path(cli_rtable);

	if (editing) {
		inithist();
		initedit();
	}

	for (;;) {
		if (caught_sigwinch) {
			(void)setwinsize(caught_sigwinch);
			caught_sigwinch = 0;
		}
		if (editing && !isatty(STDIN_FILENO))
			endedit();
		rows_ask();
		if (!editing) {
			if (interactive_mode)
				printf("%s", cprompt());
			if (fgets(line, sizeof(line), stdin) == NULL) {
				if (feof(stdin) || ferror(stdin)) {
					if (interactive_mode)
						printf("\n");
					(void) quit(0, NULL);
					/* NOTREACHED */
				}
				break;
			}
		} else {
			const char *buf;
			cursor_pos = NULL;
			line[0] = '\0';

			if ((buf = el_gets(elc, &num)) == NULL || num == 0)
				break;

			if (buf[--num]  == '\n') {
				if (num == 0)
					break;
			}
			if (num >= sizeof(line)) {
				printf("%% Input exceeds permitted length\n");
				break;
			}
			memcpy(line, buf, (size_t)num);
			line[num] = '\0';
			history(histc, &ev, H_ENTER, buf);
		}

		if (line[0] == 0)
			break;
		if (run_line(line) == 1)
			break;
	}
}

/*
 * Run text, a line as the loop reads it.  Returns what the command
 * returns, or -1 after printing why none ran, or 1 for a line of no
 * words, which leaves the loop
 */
static int
run_line(char *text)
{
	char buf[sizeof(line)];
	int r;

	/* the text as it was typed, which nshd's session reads */
	if (strlcpy(buf, text, sizeof(buf)) >= sizeof(buf) ||
	    strlcpy(line, buf, sizeof(line)) >= sizeof(line)) {
		printf("%% Input exceeds permitted length\n");
		return -1;
	}
	if (makeargv() == -1) {
		printf("%% Too many words\n");
		return -1;
	}
	if (margv[0] == 0)
		return 1;
	said = buf;
	r = run(margc, margv, buf);
	said = NULL;
	return r;
}

/*
 * For do: run the argc words of argv, the words after the first of the
 * text being run, as a line of their own
 */
int
cmd_rest(int argc, char **argv)
{
	said += strspn(said, " \t");
	said += strcspn(said, " \t");
	said += strspn(said, " \t");
	return run(argc, argv, said);
}

/*
 * Run the argc words of argv, from text, in nsh's mode, as nshd's rows
 * say.  Returns what the command returns, or -1 after printing why none
 * ran
 */
static int
run(int argc, char **argv, char *text)
{
	char **table;
	struct ghs *g;
	int inif, stlen, no;

	/* in nshd's configure, a line may be in an interface's mode */
	inif = nshd_config && ifname[0] != '\0';
	table = inif ? (char **)whichlist : (char **)cmdtab;
	stlen = inif ? sizeof(struct intlist) : sizeof(Command);
	no = NO_ARG(argv[0]);
	if (argc < no + 1) {
		printf("%% Invalid command\n");
		return -1;
	}
	g = (struct ghs *)genget(argv[no], table, stlen);
	if (Ambiguous(g)) {
		printf("%% Ambiguous command\n");
		return -1;
	}
	if (g == NULL) {
		/* outside nshd's configure, editline's own commands */
		if (nshd_config || !editing || el_burrito(elc, argc, argv))
			printf("%% Invalid command\n");
		return -1;
	}
	if (no && !(inif ? ((struct intlist *)g)->nocmd :
	    ((Command *)g)->nocmd)) {
		printf("%% Invalid command: %s %s\n", argv[0], argv[1]);
		return -1;
	}
	switch (run_code(table, stlen, g, argc, argv, no)) {
	case RUN_NSH:
		return run_own(g->name, inif, argc, argv);
	case RUN_LINE:
		return nshd_line(text);
	case RUN_OP:
		return run_op(g->name, inif, argc, argv, no);
	case RUN_RULES:
		return rules_edit(g->name);
	case RUN_CONFIGURE:
		printf("%% Command requires configure mode\n");
		return -1;
	case RUN_UNSUPPORTED:
		printf("%% %s is not supported in %s yet\n", g->name,
		    nshd_cname());
		return -1;
	default:
		printf("%% nshd's rows do not say how %s runs\n", g->name);
		return -1;
	}
}

/*
 * How row g, of table, runs in nsh's mode, as nshd's rows say: RUN_*.
 * Where the row under g that the next word names says how it runs, as a
 * daemon's action or a flush does, that row decides.  Until nshd sends
 * rows, nsh runs its own commands, except those that need configure
 */
static int
run_code(char **table, int stlen, struct ghs *g, int argc, char **argv,
    int no)
{
	struct ghs *s;
	int out, conf, code;

	if (!tables_ready())
		return ((Command *)g)->needconfig ? RUN_CONFIGURE : RUN_NSH;
	row_runs(table, stlen, (char *)g, &out, &conf);
	code = nshd_config ? conf : out;
	if (g->table != NULL && argc > no + 1 &&
	    (s = (struct ghs *)genget(argv[no + 1], g->table,
	    g->stlen)) != NULL && !Ambiguous(s)) {
		row_runs(g->table, g->stlen, (char *)s, &out, &conf);
		if ((nshd_config ? conf : out) != 0)
			code = nshd_config ? conf : out;
	}
	return code;
}

/* Run name, one of nsh's own commands in its mode, with argv's words */
static int
run_own(char *name, int inif, int argc, char **argv)
{
	Command *c;
	size_t i;

	if (inif) {
		for (i = 0; i < nitems(ownif); i++)
			if (strcmp(ownif[i].name, name) == 0)
				return (*ownif[i].handler)(argc, argv, ifname,
				    -1);
	} else {
		for (c = owntab; c->name != NULL; c++)
			if (strcmp(c->name, name) == 0)
				break;
		if (c->name != NULL) {
			if (c->needsession != 0 && !nshd_connect(0))
				return -1;
			return (*c->handler)(argc, argv, 0);
		}
	}
	printf("%% %s is not one of nsh's own commands\n", name);
	return -1;
}

/*
 * Ask nshd's system to run command name, with the argc words of argv,
 * as an operation: in an interface's mode, as the interface's
 */
static int
run_op(char *name, int inif, int argc, char **argv, int no)
{
	char *words[NARGS + 2], noname[64];
	int i;

	if (inif) {
		if (argc > NARGS) {
			printf("%% Too many arguments\n");
			return -1;
		}
		words[0] = "interface";
		words[1] = ifname;
		for (i = 0; i < argc; i++)
			words[i + 2] = argv[i];
		return op_ask("interface", argc + 2, words, 0);
	}
	if (no) {
		snprintf(noname, sizeof(noname), "no %s", name);
		return op_ask(noname, argc - 1, argv + 1,
		    nshd_config ? nshd_rtable : cli_rtable);
	}
	return op_ask(name, argc, argv, nshd_config ? nshd_rtable :
	    cli_rtable);
}

/*
 * Edit daemon's rules from nshd's candidate, as the user, with the
 * editor that VISUAL or EDITOR names, in a directory of nsh's own
 */
static int
rules_edit(char *daemon)
{
	char dir[] = "/tmp/nsh.XXXXXXXXXX", path[PATH_MAX], *editor;
	char *argv[3];
	sig_t sigint;
	int ret;

	if ((editor = getenv("VISUAL")) == NULL &&
	    (editor = getenv("EDITOR")) == NULL)
		editor = DEFAULT_EDITOR;
	if (mkdtemp(dir) == NULL) {
		printf("%% mkdtemp %s: %s\n", dir, strerror(errno));
		return -1;
	}
	snprintf(path, sizeof(path), "%s/%s", dir, daemon);
	argv[0] = editor;
	argv[1] = path;
	argv[2] = NULL;
	if ((ret = nshd_rules(daemon, nshd_rtable, 0, path)) == 0) {
		/* ^C goes to the editor */
		sigint = signal(SIGINT, SIG_IGN);
		ret = cmdargs(editor, argv) == 0 ? 0 : -1;
		signal(SIGINT, sigint);
		if (ret == 0)
			ret = nshd_rules(daemon, nshd_rtable, 1, path);
	}
	unlink(path);
	rmdir(dir);
	return ret;
}

/* exit: leave nshd's configure */
static int
nsh_exit(int argc, char **argv, ...)
{
	if (nshd_config)
		return nshd_exit();
	printf("%% Configuration mode is already disabled\n");
	return -1;
}

/*
 * rtable N: run nsh's commands in routing table N.  Naming a table, or
 * removing one, changes the configuration, and needs configure
 */
static int
nsh_rtable(int argc, char **argv, ...)
{
	const char *errstr;
	int table;

	if (NO_ARG(argv[0]) || argc > 2) {
		printf("%% Command requires configure mode\n");
		return -1;
	}
	if (argc < 2) {
		printf("%% rtable <table id>\n");
		return -1;
	}
	table = strtonum(argv[1], 0, RT_TABLEID_MAX, &errstr);
	if (errstr) {
		printf("%% invalid table id: %s\n", errstr);
		return -1;
	}
	if (nsh_setrtable(table))
		return -1;
	cli_rtable = table;
	return 0;
}

/*
 * Unless nsh has nshd's rows, ask nshd for them, and build nsh's tables
 * from them.  Until nshd sends them, nsh's command table is owntab
 */
static void
rows_ask(void)
{
	struct rows *c;
	struct facts_in in;

	if (tables_ready())
		return;
	c = rows_new();
	facts_in_init(&in, rows_record, c);
	if (nshd_tables(0, &in) == 0 && tables_build(c) == -1)
		printf("%% nsh cannot use the command tables nshd sent\n");
	facts_in_free(&in);
	rows_free(c);
	if (!tables_ready()) {
		memcpy(cmdtab, owntab, sizeof(owntab));
		cmdtab_nitems = nitems(owntab);
	}
}

/* kf_names() for complete.c: the names nshd sends, asked for each time */
int
kf_names(int kind, StringList *sl)
{
	struct rows *c;
	struct facts_in in;
	int r = -1;

	c = rows_new();
	facts_in_init(&in, rows_record, c);
	if (nshd_tables(1, &in) == 0)
		r = rows_names(c, kind, sl);
	facts_in_free(&in);
	rows_free(c);
	return r;
}

/* The command of cmdtab that name names, or NULL, or an ambiguous one */
Command *
getcmd(char *name)
{
	return (Command *)genget(name, (char **)cmdtab, sizeof(Command));
}

/*
 * Set nsh's mode as nshd reports it: whether in configure, and the
 * interface or bridge whose mode it is in
 */
void
nshd_mode(int private, char *ifn, int isbridge)
{
	config_mode = private;
	strlcpy(ifname, ifn, sizeof(ifname));
	bridge = isbridge;
	whichlist = bridge ? Bridgelist : Intlist;
}
