/*
 * Copyright (c) 2002
 *      Chris Cappuccio.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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

#include <stdio.h>
#include <kvm.h>
#include <nlist.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <net/if.h>
#include <limits.h>
#include "externs.h"

#define HELPINDENT (7)

static char line[256];
static char saveline[256];
static int  margc;
static char *margv[20];
static char hbuf[MAXHOSTNAMELEN];

int verbose = 0, nflag = 1;

/*
 * Basic
 */

kvm_t *kvmd;

/*
 * Kernel namelist for our use
 */
struct nlist nl[] = {
#define N_MBSTAT 0
	{ "_mbstat" },		/* mbuf stats */
#define N_RTSTAT 1
	{ "_rtstat" },		/* routing stats */
#define N_RTREE 2
	{ "_rt_tables" },	/* routing tree */
#define N_IPSTAT 3
	{ "_ipstat" },		/* ip stats */
#define N_AHSTAT 4
	{ "_ahstat" },		/* ah stats */
#define N_ESPSTAT 5
	{ "_espstat" },		/* esp stats */
#define N_TCPSTAT 6
	{ "_tcpstat" },		/* tcp stats */
#define N_UDPSTAT 7
	{ "_udpstat" },		/* udp stats */
#define N_ICMPSTAT 8
	{ "_icmpstat" },	/* icmp stats */
#define N_IGMPSTAT 9
	{ "_igmpstat" },	/* igmp stats */
#define N_IPCOMPSTAT 10
	{ "_ipcompstat" },	/* ipcomp stats */
#define N_MCLPOOL 11
	{ "_mclpool" },
#define N_MBPOOL 12
	{ "_mbpool" },
	{ "" }
};

typedef struct {
	char *name;		/* command name */
	char *help;		/* help string (NULL for no help) */
	int  (*handler) ();	/* routine which executes command */
	int  needpriv;		/* Do we need privilege to execute? */
	int  ignoreifpriv;	/* Ignore while privileged? */
}		Command;

static Command *getcmd(char *name);
static int     enable(void);
static int     disable(void);
static int     togglev(void);
static int     pr_routes(void);
static int     pr_ip_stats(void);
static int     pr_ah_stats(void);
static int     pr_esp_stats(void);
static int     pr_tcp_stats(void);
static int     pr_udp_stats(void);
static int     pr_icmp_stats(void);
static int     pr_igmp_stats(void);
static int     pr_ipcomp_stats(void);
static int     pr_mbuf_stats(void);
static int     show_help();
static int     hostname (int, char **);
static int     help(int, char**);
static int     shell(int, char*[]);
static int     pr_rt_stats(void);
static int     priv = 0;

/*
 * Quit command
 */

int
quit()
{
	printf("%% Session terminated.\r\n");
	exit(0);
	return 0;
}

/*
 * do nothing
 */

int
noop()
{
	return 0;
}

/*
 * Data structures and routines for the "show" command.
 */

struct showlist {
	char *name;		/* How user refers to it (case independent) */
	char *help;		/* Help information (0 ==> no help) */
	int minarg;		/* Minimum number of arguments */
	int maxarg;		/* Maximum number of arguments */
	int (*handler)();	/* Routine to perform (for special ops) */
};

static struct showlist Showlist[] = {
	{ "hostname",	"Router hostname",	0, 0, hostname },
	{ "interface",	"Interface config",	0, 1, show_int },
	{ "routes",	"IP route table",	0, 0, pr_routes },
	{ "ipstats",	"IP statistics",	0, 0, pr_ip_stats },
#ifdef IPSEC
	{ "ahstats",	"AH statistics",	0, 0, pr_ah_stats },
	{ "espstats",	"ESP statistics",	0, 0, pr_esp_stats },
#endif
	{ "tcpstats",	"TCP statistics",	0, 0, pr_tcp_stats },
	{ "udpstats",	"UDP statistics",	0, 0, pr_udp_stats },
	{ "icmpstats",	"ICMP statistics",	0, 0, pr_icmp_stats },
	{ "igmpstats",	"IGMP statistics",	0, 0, pr_igmp_stats },
#ifdef IPCOMP
	{ "ipcompstats","IPCOMP statistics",	0, 0, pr_ipcomp_stats },
#endif
	{ "rtstats",	"Routing statistics",	0, 0, pr_rt_stats },
	{ "mbufstats",	"Memory management statistics",	0, 0, pr_mbuf_stats },
	{ "version",	"Software information",	0, 0, version },
	{ "?",		"Options",		0, 0, show_help },
	{ "help",	0,			0, 0, show_help },
	{ 0, 0, 0, 0, 0 }
};

#define GETSHOW(name)	((struct showlist *) genget(name, (char **) Showlist, \
			    sizeof(struct showlist)))

static int
showcmd(argc, argv)
	int argc;
	char **argv;
{
	struct showlist *s;	/* pointer to current command */
	int success = 0;

	if (argc < 2) {
		printf("%% Use 'show ?' for help\r\n");
		return 0;
	}

	/*
	 * Validate show argument
	 */
	s = GETSHOW(argv[1]);
	if (s == 0) {
		printf("%% Invalid argument %s\r\n",argv[1]);
		return 0;
	} else if (Ambiguous(s)) {
		printf("%% Ambiguous argument %s\r\n",argv[1]);
		return 0;
	}
	if (((s->minarg + 2) > argc) || ((s->maxarg + 2) < argc)) {
		printf("%% Wrong argument%s to 'show %s' command.\r\n",
		    argc <= 2 ? "" : "s", s->name);
		return 0;
	}
	if (s->handler)	/* As if there was something else we do ? */
		success = (*s->handler)((s->maxarg > 0) ? argv[2] : 0,
		    (s->maxarg > 1) ? argv[3] : 0);

	return(success);
}

static int
show_help()
{
	struct showlist *s; /* pointer to current command */

	printf("%% Commands may be abbreviated.\r\n");
	printf("%% 'show' commands are:\r\n\r\n");

	for (s = Showlist; s->name; s++) {
		if (s->help)
			printf("  %-*s\t%s\r\n", (int)HELPINDENT,
			    s->name, s->help);
	}
	return 0;
}
 
/*
 * Data structures and routines for the "CLI"
 */

static char
	hostnamehelp[] = "Set system hostname",
	showhelp[] =	"Show system information",
	enablehelp[] =	"Enable privileged mode",
	disablehelp[] =	"Disable privileged mode",
	ratehelp[] =	"Rate limit an interface",
	monitorhelp[] = "Monitor routing table changes",
	quithelp[] =	"Close current connection",
	verbosehelp[] =	"Toggle verbose diagnostics",
	shellhelp[] =	"Invoke a subshell",
	helphelp[] =	"Print help information";

/*
 * Primary commands, will be included in help output
 */

static Command  cmdtab[] = {
	{ "hostname",	hostnamehelp,	hostname,	1, 0 },
	{ "show",	showhelp,	showcmd,	0, 0 },
	{ "enable",	enablehelp,	enable,		0, 1 },
	{ "disable",	disablehelp,	disable,	1, 0 },
	{ "rate",	ratehelp,	rate,		1, 0 },
	{ "monitor",	monitorhelp,	monitor,	0, 0 },
	{ "quit",	quithelp,	quit,		0, 0 },
	{ "verbose",	verbosehelp,	togglev,	0, 0 },
	{ "!",		shellhelp,	shell,		1, 0 },
	{ "?",		helphelp,	help,		0, 0 },
	{ "help",	0,		help,		0, 0 },
	{ 0,		0,		0,		0, 0 }
};

/*
 * Mo bettah.  These commands escape ambiguous check and help listings.
 */

static Command  cmdtab2[] = {
	{ 0,		0,		0,		0 }
};

static Command *
getcmd(name)
	char *name;
{
	Command *cm;

	if ((cm = (Command *) genget(name, (char **) cmdtab, sizeof(Command))))
		return cm;
	return (Command *) genget(name, (char **) cmdtab2, sizeof(Command));
}

static void
makeargv()
{
	char *cp, *cp2, c;
	char **argp = margv;

	margc = 0;
	cp = line;
	if (*cp == '!') {	/* Special case shell escape */
		strcpy(saveline, line);	/* save for shell command */
		*argp++ = "!";	/* No room in string to get this */
		margc++;
		cp++;
	}
	while ((c = *cp)) {
		int             inquote = 0;
		while (isspace(c))
			c = *++cp;
		if (c == '\0')
			break;
		*argp++ = cp;
		margc += 1;
		for (cp2 = cp; c != '\0'; c = *++cp) {
			if (inquote) {
				if (c == inquote) {
					inquote = 0;
					continue;
				}
			} else {
				if (c == '\\') {
					if ((c = *++cp) == '\0')
						break;
				} else if (c == '"') {
					inquote = '"';
					continue;
				} else if (c == '\'') {
					inquote = '\'';
					continue;
				} else if (isspace(c))
					break;
			}
			*cp2++ = c;
		}
		*cp2 = '\0';
		if (c == '\0')
			break;
		cp++;
	}
	*argp++ = 0;
}

void
command(top, tbuf, cnt)
	int top;
	char *tbuf;
	int cnt;
{
	Command  *c;

	if (!top) {
		putchar('\n');
	} else {
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGQUIT, SIG_IGN);
	}
	for (;;) {
		if (tbuf) {
			char           *cp;
			cp = line;
			while (cnt > 0 && (*cp++ = *tbuf++) != '\n')
				cnt--;
			tbuf = 0;
			if (cp == line || *--cp != '\n' || cp == line)
				goto getline;
			*cp = '\0';
			printf("%s\r\n", line);
		} else {
	getline:
			gethostname(hbuf, sizeof(hbuf));
			if(priv)
				printf("%s(priv)/", hbuf);
			else
				printf("%s/", hbuf);
			if (fgets(line, sizeof(line), stdin) == NULL) {
				if (feof(stdin) || ferror(stdin)) {
					printf("\r\n");
					(void) quit();
					/* NOTREACHED */
				}
				break;
			}
		}
		if (line[0] == 0)
			break;
		makeargv();
		if (margv[0] == 0) {
			break;
		}
		c = getcmd(margv[0]);
		if (Ambiguous(c)) {
			printf("%% Ambiguous command\r\n");
			continue;
		}
		if (c == 0) {
			printf("%% Invalid command\r\n");
			continue;
		}
		if (c->needpriv != 0 && priv != 1) {
			printf("%% Privilege required\r\n");
			continue;
		}
		if (c->ignoreifpriv == 1 && priv == 1) {
			printf("%% Command invalid while privileged\r\n");
			continue;
		}
		if ((*c->handler) (margc, margv)) {
			break;
		}
	}
}

/*
 * Help command.
 */
static int
help(argc, argv)
	int argc;
	char *argv[];
{
	Command *c;

	if (argc == 1) { 
		printf("%% Commands may be abbreviated.\r\n");
		printf("%% Commands are:\r\n\r\n");
		for (c = cmdtab; c->name; c++)
			if (c->help && ((c->needpriv == priv) ||
			    (c->ignoreifpriv != priv))) {
				printf("  %-*s\t%s\r\n", (int)HELPINDENT,
				    c->name, c->help);
			}
		return 0;
	}
	while (--argc > 0) {
		char *arg;
		arg = *++argv;
		c = getcmd(arg);
		if (Ambiguous(c))
			printf("%% Ambiguous help command %s\r\n", arg);
		else if (c == (Command *)0)
			printf("%% Invalid help command %s\r\n", arg);
		else
			printf("%% %s: %s\r\n", arg, c->help);
	}
	return 0;
}

/*
 * Hostname command.
 */
int
hostname(argc, argv)
	int argc;
	char *argv[];
{
	argv++;
	argc--;

	if (argc > 1) {
		printf("%% Invalid arguments\r\n");
		return 1;
	}

	if (argc == 1) {
		if (sethostname(*argv, strlen(*argv)))
			perror("% sethostname");
	} else {
		if (gethostname(hbuf, sizeof(hbuf)))
			perror("% gethostname");
		printf("%% %s\r\n", hbuf);
        }
	return 0;
}

/*
 * Shell command.
 */
int
shell(argc, argv)
	int argc;
	char *argv[];
{
 	switch(vfork()) {
		case -1:
			perror("% Fork failed");
			break;

		case 0:
		{
			/*
			 * Fire up the shell in the child.
			 */
			char *shellp;
			char *shellname = shellp = "/bin/sh";

			if (argc > 1)
				execl(shellp, shellname, "-c", &saveline[1], (char *)NULL);
			else
				execl(shellp, shellname, (char *)NULL);
			perror("% Execl");
			break;
		}
		default:
			(void)wait((int *)0);  /* Wait for shell to complete */
			break;
	}
	return 1;
}

/*
 * enable privileged mode
 */
int
enable(void)
{
	priv = 1;
	return 0;
}

/*
 * disable privileged mode
 */
int
disable(void)
{
	priv = 0;
	return 0;
}

/*
 * toggle verbose diagnostics
 */
int
togglev(void)
{
	if (verbose)
		verbose = 0;
	else
		verbose = 1;
	printf("%% Diagnostic mode %s\r\n", verbose ? "enabled" : "disabled");

	return 0;
}

/*
 * initialize kvm access
 * load nl with kvm_nlist
 */
int
load_nlist(void)
{
	char *nlistf = NULL, *memf = NULL;
	char buf[_POSIX2_LINE_MAX];

	if ((kvmd = kvm_openfiles(nlistf, memf, NULL, O_RDONLY,
	    buf)) == NULL) {
		printf("%% kvm_openfiles: %s\r\n", buf);
		return 1;
	}
	if(kvm_nlist(kvmd, nl) < 0 || nl[0].n_type == 0) {
		if (nlistf)
			printf("%% kvm_nlist: %s: no namelist\r\n", nlistf);
		else
			printf("%% kvm_nlist: no namelist\r\n");
		return 1;
	}
	return 0;
}

/*
 * read a text file and execute commands
 */
int
cmdrc(rcname)
	char rcname[FILENAME_MAX];
{
	Command     *c;
	FILE        *rcfile;

	if ((rcfile = fopen(rcname, "r")) == 0) {
		printf("%% %s not found\r\n",rcname);
		return 1;
	}
	for (;;) {
		if (fgets(line, sizeof(line), rcfile) == NULL)
			break;
		if (line[0] == 0)
			break;
		if (line[0] == '#')
			continue;
		makeargv();
		if (margv[0] == 0)
			continue;
		c = getcmd(margv[0]);
		if (Ambiguous(c)) {
			printf("%% Ambiguous rc command: %s\r\n", margv[0]);
			continue;
		}
		if (c == 0) {
			printf("%% Invalid rc command: %s\r\n", margv[0]);
			continue;
		}
		(*c->handler) (margc, margv);
	}
	fclose(rcfile);
	return 0;
}

/*
 * Lookup wrappers
 */
int
pr_routes(void)
{
	show(AF_INET);
	return 0;
}


int
pr_rt_stats(void)
{
	rt_stats(nl[N_RTSTAT].n_value);
	return 0;
}

int
pr_ip_stats(void)
{
	ip_stats(nl[N_IPSTAT].n_value);
	return 0;
}

#ifdef IPSEC
int
pr_ah_stats(void)
{
	ah_stats(nl[N_AHSTAT].n_value);
	return 0;
}

int
pr_esp_stats(void)
{
	esp_stats(nl[N_ESPSTAT].n_value);
	return 0;
}
#endif

int
pr_tcp_stats(void)
{
	tcp_stats(nl[N_TCPSTAT].n_value);
	return 0;
}

int
pr_udp_stats(void)
{
	udp_stats(nl[N_UDPSTAT].n_value);
	return 0;
}

int
pr_icmp_stats(void)
{
	icmp_stats(nl[N_ICMPSTAT].n_value);
	return 0;
}

int
pr_igmp_stats(void)
{
	igmp_stats(nl[N_IGMPSTAT].n_value);
	return 0;
}

#ifdef IPCOMP
int
pr_ipcomp_stats(void)
{
	ipcomp_stats(nl[N_IPCOMPSTAT].n_value);
	return 0;
}
#endif

int
pr_mbuf_stats(void)
{
	mbpr(nl[N_MBSTAT].n_value, nl[N_MBPOOL].n_value,   
	    nl[N_MCLPOOL].n_value);
	return 0;
}

