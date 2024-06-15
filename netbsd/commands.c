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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/reboot.h>
#include <sys/sockio.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <limits.h>
#include <util.h>
#include <pwd.h>
#include "editing.h"
#include "stringlist.h"
#include "externs.h"
#include "sysctl.h"

char prompt[128];

char line[1024];
char saveline[1024];
int  margc;
char hname[HSIZE];
static char hbuf[MAXHOSTNAMELEN];	/* host name */
static char ifname[IFNAMSIZ];		/* interface name */
struct intlist *whichlist;

#define RT_TABLEID_MAX 255
#define NARGS  sizeof(line)/2		/* max arguments in char line[] */
char	*margv[NARGS];			/* argv storage */
size_t	cursor_argc;			/* location of cursor in margv */
size_t	cursor_argo;			/* offset of cursor margv[cursor_argc] */

pid_t	child;

static int	quit(void);
static int	disable(void);
static int	doverbose(int, char**);
static int	doediting(int, char**);
static int	hostname(int, char **);
static int	help(int, char**);
static int	shell(int, char*[]);
static int	ping(int, char*[]);
static int	ping6(int, char*[]);
static int      ssh(int, char*[]);
static int      telnet(int, char*[]);
static int	traceroute(int, char*[]);
static int	traceroute6(int, char*[]);
static Command *getcmd(char *);
static void	sigalarm(int);
static int      show_hostname(int, char **);
static int      pr_conf(int, char **);
static int      pr_s_conf(int, char **);
static int      show_help(int, char **);
static int      wr_startup(void);
static int      wr_conf(char *);
static int      el_burrito(EditLine *, int, char **); 
       void     p_argv(int, char **);
static int      flush_history(void);
static int      flush_line(char *);
static int      flush_help(void);
static int      notvalid(void);

#include "commands.h"

void sigalarm(int blahfart)
{
	if (child != -1) {
		kill(child, SIGKILL);
	}
}

/*
 * Quit command
 */

int
quit(void)
{
	printf("%% Session terminated.\n");
	exit(0);
	return 0;
}

/*
 * Data structures and routines for the "show" command.
 */

Menu showlist[] = {
	{ "hostname",	"Router hostname",	CMPL0 0, 0, 0, 0, show_hostname },
        { "version",    "Software information", CMPL0 0, 0, 0, 0, version },
        { "users",      "System users",         CMPL0 0, 0, 0, 0, who },
	{ "running-config",	"Operating configuration", CMPL0 0, 0, 0, 0, pr_conf },
	{ "startup-config", "Startup configuration", CMPL0 0, 0, 0, 0, pr_s_conf },
	{ "?",		"Options",		CMPL0 0, 0, 0, 0, show_help },
	{ "help",	0,			CMPL0 0, 0, 0, 0, show_help },
	{ 0, 0, 0, 0, 0 }
};

/*
 * Data structures and routines for the "flush" command.
 */

Menu flushlist[] = {
        { "line",       "Active user", CMPL0 0, 0, 1, 1, flush_line },
        { "history",    "Command history",      CMPL0 0, 0, 0, 0, flush_history },
        { "?",          "Options",              CMPL0 0, 0, 0, 0, flush_help },
        { "help",       0,                      CMPL0 0, 0, 0, 0, flush_help },
        { 0, 0, 0, 0, 0 }
};

static int
flush_line(char *line)
{
        char *argv[] = { PKILL, "-9", "-t", line, NULL };
        cmdargs(PKILL, argv);
        return (1);
}

static int
flush_help(void)
{
        Menu *f;
        u_int z = 0;

        printf("%% Commands may be abbreviated.\n");
        printf("%% 'flush' commands are:\n\n");

        for (f = flushlist; f->name; f++) {
                if (strlen(f->name) > z)
                        z = strlen(f->name);
        }

        for (f = flushlist; f->name; f++) {
                if (f->help)
                        printf("  %-*s  %s\n", z, f->name, f->help);
        }
        return 0;
}

static int
showcmd(int argc, char **argv)
{
	Menu *s;	/* pointer to current command */
	int success = 0;

	if (argc < 2) {
		show_help(argc, argv);
		return 0;
	}

	/*
	 * Validate show argument
	 */
	s = (Menu *) genget(argv[1], (char **) showlist, sizeof(Menu));
	if (s == 0) {
		printf("%% Invalid argument %s\n", argv[1]);
		return 0;
	} else if (Ambiguous(s)) {
		printf("%% Ambiguous argument %s\n", argv[1]);
		return 0;
	}
	if (((s->minarg + 2) > argc) || ((s->maxarg + 2) < argc)) {
		printf("%% Wrong number of argument%s to 'show %s' command"
		    " (min %i, max %i)\n", argc <= 2 ? "" : "s", s->name,
		    s->minarg, s->maxarg);
		return 0;
	}
	if (s->handler)	/* As if there was something else we do ? */
		success = (*s->handler)(argc, argv);

	return(success);
}

static int
show_help(int argc, char **argv)
{
	Menu *s; /* pointer to current command */
	u_int z = 0;

	printf("%% Commands may be abbreviated.\n");
	printf("%% 'show' commands are:\n\n");

	for (s = showlist; s->name; s++) {
		if (strlen(s->name) > z)
			z = strlen(s->name);
	}

	for (s = showlist; s->name; s++) {
		if (s->help)
			printf("  %-*s  %s\n", z, s->name, s->help);
	}
	return 0;
}

/*
 * Data structures and routines for the main CLI
 */

static char
	hostnamehelp[] = "Set system hostname",
	interfacehelp[] = "Modify interface parameters",
	rtablehelp[] = 	"Routing table switch",
	grouphelp[] =	"Modify group attributes",
	arphelp[] = 	"Static ARP set",
#ifdef notyet
	parphelp[] =	"Proxy ARP set",
#endif
	pfhelp[] =	"Packet filter control",
	ospfhelp[] =	"OSPF control",
	ospf6help[] = 	"OSPF6 control",
	eigrphelp[] =	"EIGRP control",
	bgphelp[] =	"BGP control",
	riphelp[] =	"RIP control",
	ldphelp[] =	"LDP control",
	relayhelp[] =	"Relay control",
	ipsechelp[] =	"IPsec IKEv1 control",
	ikehelp[] =	"IPsec IKEv2 control",
	rtadvhelp[] =	"Router advertisement control",
	dvmrphelp[] = 	"DVMRP control",
	sasynchelp[] =	"SA synchronization control",
	dhcphelp[] =	"DHCP server control",
	snmphelp[] =	"SNMP server control",
	smtphelp[] =	"SMTP server control",
	ldaphelp[] =	"LDAP server control",
	sshdhelp[] =	"SSH server control",
	ntphelp[] =	"NTP synchronization control",
	nppphelp[] =	"PPP server control",
	ifstatehelp[] =	"ifstate server control",
	ftpproxyhelp[] ="ftp-proxy server control",
	tftpproxyhelp[] ="tftp-proxy server control",
	tftphelp[] =	"TFTP server control",
	dnshelp[] =	"DNS rule control",
        motdhelp[] =    "Message of-the-day",
	inethelp[] =	"Inet super-server control",
	bridgehelp[] =	"Modify bridge parameters",
	showhelp[] =	"Show system information",
	iphelp[] =	"Set IP networking parameters",
	ip6help[] =	"Set IPv6 networking parameters",
	mplshelp[] =	"Set MPLS network parameters",
	ddbhelp[] =	"Set DDB parameters",
	pipexhelp[] =	"Set PIPEX parameters",
	flushhelp[] =	"Flush system tables",
	enablehelp[] =	"Enable privileged mode",
	disablehelp[] =	"Disable privileged mode",
	pinghelp[] = 	"Send IPv4 ICMP echo request",
	ping6help[] =   "Send IPv6 ICMP echo request",
	tracerthelp[] =	"Print the route to IPv4 host",
	tracert6help[] ="Print the route to IPv6 host",
	sshhelp[] =	"SSH connection to remote host",
	telnethelp[] =	"Telnet connection to remote host",
	quithelp[] =	"Close current connection",
	verbosehelp[] =	"Set verbose diagnostics",
	editinghelp[] = "Set command line editing",
        whohelp[] =     "Display system users",
	shellhelp[] =	"Invoke a subshell",
	savehelp[] =	"Save the current configuration",
	nreboothelp[] =	"Reboot the system",
	halthelp[] =	"Halt the system",
	helphelp[] =	"Print help information";

/*
 * Primary commands, will be included in help output
 */

#define ssctl sizeof(struct ctl)
Command cmdtab[] = {
	{ "hostname",	hostnamehelp,	CMPL0 0, 0, hostname, 	1, 0, 0 },
	{ "show",	showhelp,	CMPL(ta) (char **)showlist, sizeof(Menu), showcmd,	0, 0, 0 },
	{ "enable",	enablehelp,	CMPL0 0, 0, enable,	0, 0, 0 },
	{ "disable",	disablehelp,	CMPL0 0, 0, disable,	1, 0, 0 },
	{ "ping",	pinghelp,	CMPL0 0, 0, ping,	0, 0, 0 },
	{ "ping6",	ping6help,	CMPL0 0, 0, ping6,	0, 0, 0 },
	{ "traceroute", tracerthelp,	CMPL0 0, 0, traceroute,	0, 0, 0 },
	{ "traceroute6", tracert6help,  CMPL0 0, 0, traceroute6, 0, 0, 0 },
	{ "ssh",	sshhelp,	CMPL0 0, 0, ssh,	0, 0, 0 },
	{ "telnet",	telnethelp,	CMPL0 0, 0, telnet,	0, 0, 0 },
	{ "write-config", savehelp,	CMPL0 0, 0, wr_startup,	1, 0, 0 },
	{ "verbose",	verbosehelp,	CMPL0 0, 0, doverbose,	0, 1, 0 },
	{ "editing",	editinghelp,	CMPL0 0, 0, doediting,	0, 1, 0 },
        { "who",        whohelp,        CMPL0 0, 0, who,        0, 0, 0 },
	{ "!",		shellhelp,	CMPL0 0, 0, shell,	1, 0, 0 },
	{ "?",		helphelp,	CMPL(C) 0, 0, help,	0, 0, 0 },
	{ "quit",	quithelp,	CMPL0 0, 0, quit,	0, 0, 0 },
	{ "help",	0,		CMPL(C) 0, 0, help,	0, 0, 0 },
	{ 0,		0,		CMPL0 0, 0, 0,		0, 0, 0 }
};

/*
 * These commands escape ambiguous check and help listings
 */

static Command  cmdtab2[] = {
	{ "config",	0,		CMPL0 0, 0, notvalid,	0, 0, 0 },
	{ 0,		0,		CMPL0 0, 0, 0,		0, 0, 0 }
};

Command *
getcmd(char *name)
{
	Command *cm;

	if ((cm = (Command *) genget(name, (char **) cmdtab, sizeof(Command))))
		return cm;
	return (Command *) genget(name, (char **) cmdtab2, sizeof(Command));
}

void 
makeargv()
{
	char	*cp, *cp2, *base, c;
	char	**argp = margv;

	margc = 0;
	cp = line;
	if (*cp == '!') {	/* Special case shell escape */
		/* save for shell command */
		strlcpy(saveline, line, sizeof(saveline));

		*argp++ = "!";	/* No room in string to get this */
		margc++;
		cp++;
	}
	while ((c = *cp)) {
		int inquote = 0;
		while (isspace(c))
			c = *++cp;
		if (c == '\0')
			break;
		*argp++ = cp;
		cursor_argc = margc += 1;
		base = cp;
		for (cursor_argo = 0, cp2 = cp; c != '\0';
		    cursor_argo = (cp + 1) - base, c = *++cp) {
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
				} else if (isspace(c)) {
					cursor_argo = 0;
					break;
				}
			}
			*cp2++ = c;
		}
		*cp2 = '\0';
		if (c == '\0') {
			cursor_argc--;
			break;
		}
		cp++;
	}
	*argp++ = 0;
	if (cursor_pos == line) {
		cursor_argc = 0;
		cursor_argo = 0;
	}
}

void
command()
{
	Command  *c;
	u_int num;

	if (editing) {
		inithist();
		initedit();
	}

	for (;;) {
		if (!editing) {
			printf("%s", cprompt());
			if (fgets(line, sizeof(line), stdin) == NULL) {
				if (feof(stdin) || ferror(stdin)) {
					printf("\n");
					(void) quit();
					/* NOTREACHED */
				}
				break;
			}
		} else {
			const char *buf;
			cursor_pos = NULL;

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
		makeargv();
		if (margv[0] == 0) {
			break;
		}
		if (NO_ARG(margv[0]))
			c = getcmd(margv[1]);
		else
			c = getcmd(margv[0]);
		if (Ambiguous(c)) {
			printf("%% Ambiguous command\n");
			continue;
		}
		if (c == 0) {
			int val = 1;

			if (editing)                                
				val = el_burrito(elc, margc, margv);
			if (val)
				printf("%% Invalid command\n");
			continue;
		}
		if (NO_ARG(margv[0]) && ! c->nocmd) {
			printf("%% Invalid command: %s %s\n", margv[0],
			    margv[1]);
			continue;
		}
		if (c->needpriv != 0 && priv != 1) {
			printf("%% Privilege required\n");
			continue;
		}
		if (c->modh)
			strlcpy(hname, c->name, HSIZE);	
		if ((*c->handler) (margc, margv, 0)) {
			break;
		}
	}
}

/*
 * Help command.
 */
static int
help(int argc, char **argv)
{
	Command *c;

	if (argc == 1) { 
		u_int z = 0;

		printf("%% Commands may be abbreviated.\n");
		printf("%% Commands are:\n\n");

		for (c = cmdtab; c->name; c++)
			if (((c->needpriv && priv) || !c->needpriv)
			    && strlen(c->name) > z)
				z = strlen(c->name);
		for (c = cmdtab; c->name; c++) {
			if (c->help && ((c->needpriv && priv) ||
			    !c->needpriv))
				printf("  %-*s  %s\n", z, c->name, c->help);
		}
		return 0;
	}
	while (--argc > 0) {
		char *arg;
		arg = *++argv;
		c = getcmd(arg);
		if (Ambiguous(c))
			printf("%% Ambiguous help command %s\n", arg);
		else if (c == (Command *)0)
			printf("%% Invalid help command %s\n", arg);
		else
			printf("%% %s: %s\n", arg, c->help);
	}
	return 0;
}

/*
 * Hostname command.
 */
int
hostname(int argc, char **argv)
{
	argv++;
	argc--;

	if (argc > 1) {
		printf("%% Invalid arguments\n");
		return 1;
	}

	if (argc == 1) {
		if (sethostname(*argv, strlen(*argv)))
			printf("%% sethostname: %s\n", strerror(errno));
        } else
		show_hostname(0, NULL);
	return 0;
}

int show_hostname(int argc, char **argv)
{
	if (gethostname(hbuf, sizeof(hbuf)))
		printf("%% gethostname: %s\n", strerror(errno));
	else
		printf("%s\n", hbuf);

	return 0;
}

/*
 * Shell command.
 */
int
shell(int argc, char **argv)
{
	sig_t sigint, sigquit, sigchld;

	sigint = signal(SIGINT, SIG_IGN);
	sigquit = signal(SIGQUIT, SIG_IGN);
	sigchld = signal(SIGCHLD, SIG_DFL);

	switch(child = fork()) {
		case -1:
			printf("%% fork failed: %s\n", strerror(errno));
			break;

		case 0:
			{
			signal(SIGQUIT, SIG_DFL);
			signal(SIGINT, SIG_DFL);
			signal(SIGCHLD, SIG_DFL);

			/*
			 * Fire up the shell in the child.
			 */
			char *shellp;
			char *shellname = shellp = "/bin/sh";

			if (argc > 1)
				execl(shellp, shellname, "-c", &saveline[1],
				    (char *)NULL);
			else
				execl(shellp, shellname, (char *)NULL);
			printf("%% execl failed: %s\n", strerror(errno));
			_exit(0);
			}
			break;
		default:
			signal(SIGALRM, sigalarm);
 			wait(0);  /* Wait for shell to complete */
			break;
	}

	signal(SIGINT, sigint);
	signal(SIGQUIT, sigquit);
	signal(SIGCHLD, sigchld);
	signal(SIGALRM, SIG_DFL);
	child = -1;

	return 1;
}

/*
 * ping command.
 */
int
ping(int argc, char *argv[])
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return 1;
	} else {
		cmdargs(PING, argv);
	}
	return 0;
}

int
ping6(int argc, char *argv[])
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return 1;
	} else {
		cmdargs(PING6, argv);
	}
	return 0;
}

/*
 * telnet command.
 */
int
telnet(int argc, char *argv[])
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return 1;
	} else {
		cmdargs(TELNET, argv);
	}
	return 0;
}

/*
 * ssh command.
 */
int
ssh(int argc, char *argv[])
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return 1;
	} else {
		cmdargs(SSH, argv);
	}
	return 0;
}

/*
 * traceroute command.
 */
int
traceroute(int argc, char *argv[])
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return 1;
	} else {
		cmdargs(TRACERT, argv);
	}
	return 0;
}

int
traceroute6(int argc, char *argv[])
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return 1;
	} else {
		cmdargs(TRACERT6, argv);
	}
	return 0;
}

int
argvtostring(int argc, char **argv, char *string, int strlen)
{
	int i, j;

	for (i = 0, j = 0; argc && i < (strlen - 1); i++) {
		if (argv[0][j] == '\0') {
			argc--, argv++;
			string[i] = ' ';
			j = 0;
			continue;
		}
		string[i] = argv[0][j];
		j++;
	}
	if (i > 0)
		i--;
	string[i] = '\0';

	return i;
}

/*
 * cmd, multiple args
 */
int
cmdargs(char *cmd, char *arg[])
{
	sig_t sigint, sigquit, sigchld;

	sigint = signal(SIGINT, SIG_IGN);
	sigquit = signal(SIGQUIT, SIG_IGN);
	sigchld = signal(SIGCHLD, SIG_DFL);

	switch(child = fork()) {
		case -1:
			printf("%% fork failed: %s\n", strerror(errno));
			break;

		case 0:
		{
			signal(SIGQUIT, SIG_DFL);
			signal(SIGINT, SIG_DFL);
			signal(SIGCHLD, SIG_DFL);

			char *shellp = cmd;

			execv(shellp, arg);
			printf("%% execv failed: %s\n", strerror(errno));
			_exit(0);
		}
			break;
		default:
			signal(SIGALRM, sigalarm);
			wait(0);  /* Wait for cmd to complete */
			break;
	}

	signal(SIGINT, sigint);
	signal(SIGQUIT, sigquit);
	signal(SIGCHLD, sigchld);
	signal(SIGALRM, SIG_DFL);
	child = -1;

	return 1; 
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

int
notvalid(void)
{
	printf("%% The command you entered is not necessary with this"
	    " software.\n");

	return(0);
}

/*
 * verbose diagnostics
 */
int
doverbose(int argc, char **argv)
{
	if (argc > 1) {
		if (NO_ARG(argv[0])) {
			verbose = 0;
		} else {
			printf ("%% Invalid argument\n");
			return 1;
		}
	} else {
		verbose = 1;
	}
	
	printf("%% Diagnostic mode %s\n", verbose ? "enabled" : "disabled");

	return 0;
}

int
doediting(int argc, char **argv)
{
	if (argc > 1) {
		if (NO_ARG(argv[0])) {
			endedit();
                } else {
			printf ("%% Invalid argument\n");
			return 1;
		}
	} else {
		initedit();
	}

	printf("%% Command line editing %s\n",
	    editing ? "enabled" : "disabled");

	return 0;
}

int
flush_history(void)
{
	if (!editing) {
		printf("%% Command line editing not enabled\n");
		return(1);
	}

	/*
	 * Editing mode needs to be reinitialized if the histi/histc
	 * pointers are going to change.....
	 */
	endedit();
	endhist();
	inithist();
	initedit();

	return(0);
}

void
gen_help(char **x, char *cmdprefix, char *descrsuffix, int szstruct)
{
	/* only for structures starting with char *name; char *help; !! */
	char **y = x;
	struct ghs *ghs;
	int z = 0;

	printf("%% Arguments may be abbreviated\n\n");

	while (*y != 0) {
		if (strlen(*y) > z)
			z = strlen(*y);
		y = (char **)((char *)y + szstruct);
	}

	while (*x != 0) {
		ghs = (struct ghs *)x;
		if (ghs->help)
			printf("  %s %-*s %s %s\n", cmdprefix, z, *x,
			    ghs->help, descrsuffix);
		x = (char **)((char *)x + szstruct);
	}
	return;
}

/*
 * read a text file and execute commands
 * take into account that we may have mode handlers int cmdtab that 
 * execute indented commands from the rc file
 */
int
cmdrc(char rcname[FILENAME_MAX])
{
	Command	*c = NULL, *savec = NULL;
	FILE	*rcfile;
	char	modhvar[128];	/* required variable in mode handler cmd */
	unsigned int lnum;	/* line number */
	u_int	z = 0;		/* max length of cmdtab argument */

	if ((rcfile = fopen(rcname, "r")) == 0) {
		printf("%% Unable to open %s: %s\n", rcname, strerror(errno));
		return 1;
	}

	for (c = cmdtab; c->name; c++)
		if (strlen(c->name) > z)
			z = strlen(c->name);
	c = NULL;

	for (lnum = 1; ; lnum++) {
		if (fgets(line, sizeof(line), rcfile) == NULL)
			break;
		if (line[0] == 0)
			break;
		if (line[0] == '#')
			continue;
		if (line[0] == '!')
			continue;
		/*
		 * Don't ignore indented comments with pound sign, otherwise
		 * comments won't be saved into daemon/ctl config files.
		 */
		if (line[0] == ' ' && line[1] == '!' && savec && savec->modh == 2)
			continue;
		if (line[0] == ' ')
			strlcpy(saveline, line, sizeof(line));
		makeargv();
		if (margv[0] == 0)
			continue;
		if (line[0] == ' ' && (!savec || savec->modh < 1)) {
			printf("%% No mode handler specified before"
			    " indented command? (line %u) ", lnum);
			p_argv(margc, margv);
			printf("\n");
			continue;
		}
		if (line[0] != ' ' || (line[0] == ' ' && line[1] != ' '
		    && savec && savec->modh == 2)) {
			/*
			 * command was not indented, or indented for a mode 2
			 * handler. process normally.
			 */
			if (NO_ARG(margv[0])) {
				c = getcmd(margv[1]);
				if (line[0] != ' ')
					savec = c;
				if (savec && (savec->nocmd == 0)) {
					printf("%% Invalid rc command (line %u) ",
					    lnum);
					p_argv(margc, margv);
					printf("\n");
					continue;
				}
			} else {
				c = getcmd(margv[0]);
				if (line[0] != ' ')
					savec = c;
				if(savec && savec->modh) {
					/*
					 * any mode handler should have
					 * one value stored, passed on
					 */
					if (margv[1]) {
						strlcpy(hname, c->name,
							    HSIZE);
						strlcpy(modhvar, margv[1],
						    sizeof(modhvar));
					} else {
						printf("%% No argument after"
						    " mode handler (line %u) ",
						    lnum);
						p_argv(margc, margv);
						printf("\n");
						continue;
					}
				}
			}
		}
		if (Ambiguous(c)) {
			printf("%% Ambiguous rc command (line %u) ", lnum);
			p_argv(margc, margv);
			printf("\n");
			continue;
		}
		if (c == 0) {
			printf("%% Invalid rc command (line %u) ", lnum);
			p_argv(margc, margv);
			printf("\n");
			continue;
		}
		if (verbose) {
			printf("%% %4s: %*s%10s (line %u) margv ",
			    savec && savec->modh ? "mode" : "cmd", z,
			    savec && savec->name ? savec->name : "",
			    c != savec ? "(sub-cmd)" : "", lnum);
			p_argv(margc, margv);
			printf("\n");
		}
		if (c->modh == 1)
			(*c->handler) (margc, margv, modhvar);
		else
			(*c->handler) (margc, margv, 0);
	}
	fclose(rcfile);
	return 0;
}

void
p_argv(int argc, char **argv)
{
	int z;

	for (z = 0; z < argc; z++)
		printf("%s%s", z ? " " : "[", argv[z]);
	printf("]");
	return;
}

/*
 * for the purpose of interface handler routines, 1 here is failure and
 * 0 is success
 */
int
el_burrito(EditLine *el, int argc, char **argv)
{
	char *colon;
	int val;

	if (!editing)	/* Nothing to parse, fail */
		return(1);

	/*
	 * el_parse will always return a non-error status if someone specifies
	 * argv[0] with a colon.  The idea of the colon is to allow host-
	 * specific commands, which is really only useful in .editrc, so
	 * it is invalid here.
	 */
	colon = strchr(argv[0], ':');
	if (colon)
		return(1);

	val = el_parse(el, argc, (const char **)argv);

	if (val == 0)
		return(0);
	else
		return(1);
}

char *
cprompt(void)
{
	int pr;
	char tmp[4];

	if (cli_rtable)
		snprintf(tmp, sizeof(tmp), "%d", cli_rtable);

	gethostname(hbuf, sizeof(hbuf));
	pr = priv | cli_rtable;
	snprintf(prompt, sizeof(prompt), "%s%s%s%s%s%s%s%s", hbuf, pr ? "(" : "",
	    priv ? "p" : "", priv && cli_rtable ? "-" : "",
	    cli_rtable ? "rtable " : "", cli_rtable ? tmp : "",
	    pr ?")" : "> ", pr ? "# " : "");

	return(prompt);
}

char *
iprompt(void)
{
	gethostname(hbuf, sizeof(hbuf));
	snprintf(prompt, sizeof(prompt), "%s(%s-%s)>", hbuf,
	    bridge ? "bridge" : "interface", ifname);

	return(prompt);
}

int
wr_startup(void)
{
	char *argv[] = { SAVESCRIPT, NSHRC_TEMP, '\0' };
	
	if (wr_conf(NSHRC_TEMP))
		printf("%% Saving configuration\n");
	else
		printf("%% Unable to save configuration: %s\n",
		    strerror(errno));

	cmdargs(SAVESCRIPT, argv);

	return(1);
}

/*
 * Save configuration
 */
int
wr_conf(char *fname)
{
	FILE *rchandle;
	int error = 1;

	if ((rchandle = fopen(fname, "w")) == NULL) 
		error = 0;
	else {
		conf(rchandle);
		fclose(rchandle);
	}

	return (error);
}

/*
 * Show wrappers
 */
int
pr_conf(int argc, char **argv)
{
	if (priv != 1) {
		printf ("%% Privilege required\n");
		return(0);
	}

	if (!wr_conf(NSHRC_TEMP)) {
		printf("%% Couldn't generate configuration\n");
		return(0);
	}

	more(NSHRC_TEMP);

	return(1);
}

/*
 * Show startup config
 */
int
pr_s_conf(int argc, char **argv)
{
	int ret;

	if (priv != 1) {
		printf ("%% Privilege required\n");
		return(0);
	}

	ret = more(NSHRC);
	
	return(ret);
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
	for (i = 0; i < NOPTFILL - 2; i++) {
		if (xargs[i] == NULL) {
			args[i] = '\0';
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
				args[i] = '\0';
				break;
			}
		} else {
			/* copy from xargs to args */
			args[i] = xargs[i];
		}
	}

	return(args);
}
