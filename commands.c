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
#include <ctype.h>
#include <kvm.h>
#include <nlist.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/wait.h>
#include <net/if.h>
#include <limits.h>
#include <histedit.h>
#include "externs.h"
#include "editing.h"

#define HELPINDENT (7)

char prompt[128];
kvm_t *kvmd;

static char line[256];
static char saveline[256];
static int  margc;
static char *margv[20];
static char hbuf[MAXHOSTNAMELEN];	/* host name */
static char ifname[IFNAMSIZ];		/* interface name */

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
	int (*handler) ();	/* routine which executes command */
	int needpriv;		/* Do we need privilege to execute? */
	int ignoreifpriv;	/* Ignore while privileged? */
	int nocmd;		/* Can we specify 'no ...command...'? */
	int modh;		/* Is it a mode handler for cmdrc()? */
} Command;

static Command	*getcmd(char *name);
static int	quit(void);
static int	noop(void);
static int	enable(void);
static int	disable(void);
static int	doverbose(int, char**);
static int	doediting(int, char**);
static int	pr_routes(void);
static int	pr_ip_stats(void);
static int	pr_ah_stats(void);
static int	pr_esp_stats(void);
static int	pr_tcp_stats(void);
static int	pr_udp_stats(void);
static int	pr_icmp_stats(void);
static int	pr_igmp_stats(void);
static int	pr_ipcomp_stats(void);
static int	pr_mbuf_stats(void);
static int	pr_s_conf(void);
static int	pr_conf(void);
static int	show_help(void);
static int	flush_help(void);
static int	flush_ip_routes(void);
static int	flush_history(void);
static int	int_help(void);
static int	el_burrito(EditLine *, int, char **);
static void	makeargv(void);
static int	hostname (int, char **);
static int	help(int, char**);
static int	shell(int, char*[]);
static int	pr_rt_stats(void);
static void	p_argv(int, char**);
static int	priv = 0;

/*
 * Quit command
 */

int
quit()
{
	printf("%% Session terminated.\n");
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
	{ "ahstats",	"AH statistics",	0, 0, pr_ah_stats },
	{ "espstats",	"ESP statistics",	0, 0, pr_esp_stats },
	{ "tcpstats",	"TCP statistics",	0, 0, pr_tcp_stats },
	{ "udpstats",	"UDP statistics",	0, 0, pr_udp_stats },
	{ "icmpstats",	"ICMP statistics",	0, 0, pr_icmp_stats },
	{ "igmpstats",	"IGMP statistics",	0, 0, pr_igmp_stats },
	{ "ipcompstats","IPCOMP statistics",	0, 0, pr_ipcomp_stats },
	{ "rtstats",	"Routing statistics",	0, 0, pr_rt_stats },
	{ "mbufstats",	"Memory management statistics",	0, 0, pr_mbuf_stats },
	{ "version",	"Software information",	0, 0, version },
	{ "running-c",	"Operating configuration", 0, 0, pr_conf },
#if 0
	{ "startup-c",	"Startup configuration", 0, 0, pr_s_conf },
#endif
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
		printf("%% Use 'show ?' for help\n");
		return 0;
	}

	/*
	 * Validate show argument
	 */
	s = GETSHOW(argv[1]);
	if (s == 0) {
		printf("%% Invalid argument %s\n",argv[1]);
		return 0;
	} else if (Ambiguous(s)) {
		printf("%% Ambiguous argument %s\n",argv[1]);
		return 0;
	}
	if (((s->minarg + 2) > argc) || ((s->maxarg + 2) < argc)) {
		printf("%% Wrong argument%s to 'show %s' command.\n",
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

	printf("%% Commands may be abbreviated.\n");
	printf("%% 'show' commands are:\n\n");

	for (s = Showlist; s->name; s++) {
		if (s->help)
			printf("  %-*s\t%s\n", (int)HELPINDENT,
			    s->name, s->help);
	}
	return 0;
}

/*
 * Data structures and routines for the interface configuration mode
 */

struct intlist {
	char *name;		/* How user refers to it (case independent) */
	char *help;		/* Help information (0 ==> no help) */
	int (*handler)();	/* Routine to perform (for special ops) */
};

static struct intlist Intlist[] = {
#if 0
	{ "ip",		"IP address and netmask",		intip },
	{ "alias",	"Secondary IP address and netmask",	intalias },
	{ "broadcast",	"Specify alternate broadcast",		intbroadcast },
	{ "mtu",	"MTU",					intmtu },
	{ "nwid",	"802.11 network ID",			intnwid },
	{ "nwkey",	"802.11 network key",			intnwkey },
	{ "powersave",	"802.11 powersaving mode",		intpowersave },
	{ "media",	"Media type",				intmedia },
	{ "mediaopt",	"Media options",			intmediaopt },
	{ "metric",	"Metric",				intmetric },
	{ "vlan",	"802.1Q vlan tag and parent",		intvlan },
	{ "trailers",	"Trailer link level encapsulation",	inttrailers },
	{ "tunnel",	"Source and destination on GIF tunnel",	inttunnel },
	{ "link",	"Enable link level options",		intlink },
#ifdef INET6
	{ "vltime",	"IPv6 valid lifetime",			intvltime },
        { "pltime",	"IPv6 preferred lifetime",		intpltime },
	{ "anycast",	"IPv6 anycast address bit",		intanycast },
	{ "tentative",	"IPv6 tentative address bit",		inttentative },
#endif
	{ "debug",	"Driver dependent debugging",		intdebug },
	{ "shutdown",	"Shutdown interface",			intdown },
#endif
	{ "rate",	"Rate limit (token bucket regulator)",	intrate },
	{ "?",		"Options",				int_help },
	{ "help",	0,					int_help },
	{ 0, 0, 0 }
};

#define GETINT(name)	((struct intlist *) genget(name, (char **) Intlist, \
			    sizeof(struct intlist)))

/*
 * Data structures and routines for the "flush" command.
 */

struct flushlist {
	char *name;		/* How user refers to it (case independent) */
	char *help;		/* Help information (0 ==> no help) */
	int minarg;		/* Minimum number of arguments */
	int maxarg;		/* Maximum number of arguments */
	int (*handler)();	/* Routine to perform (for special ops) */
};

static struct flushlist Flushlist[] = {
	{ "routes",	"IP routes",		0, 0, flush_ip_routes },
#if 0
	{ "arp",	"ARP cache",		0, 0, flush_arp_cache },
#endif
	{ "history",	"Command history",	0, 0, flush_history },
	{ "?",		"Options",		0, 0, flush_help },
	{ "help",	0,			0, 0, flush_help },
	{ 0, 0, 0, 0, 0 }
};

#define GETFLUSH(name) ((struct flushlist *) genget(name, (char **) Flushlist, \
			   sizeof(struct flushlist)))

static int
flushcmd(int argc, char **argv)
{
	struct flushlist *f;
	int success = 0;

	if (argc < 2) {
		printf("%% Use 'flush ?' for help\n");
		return 0;
	}

	/*
	 * Validate flush argument
	 */
	f = GETFLUSH(argv[1]);
	if (f == 0) {
		printf("%% Invalid argument %s\n",argv[1]);
		return 0;
	} else if (Ambiguous(f)) {
		printf("%% Ambiguous argument %s\n",argv[1]);
		return 0;
	}
	if (((f->minarg + 2) > argc) || ((f->maxarg + 2) < argc)) {
		printf("%% Wrong argument%s to 'flush %s' command.\n",
		    argc <= 2 ? "" : "s", f->name);
		return 0;
	}
	if (f->handler) /* As if there was something else we do ? */
		success = (*f->handler)((f->maxarg > 0) ? argv[2] : 0,
		    (f->maxarg > 1) ? argv[3] : 0);

	return(success);
}

static int
flush_help()
{
	struct flushlist *f;

	printf("%% Commands may be abbreviated.\n");
	printf("%% 'flush' commands are:\n\n");

	for (f = Flushlist; f->name; f++) {
		if (f->help)
			printf("  %-*s\t%s\n", (int)HELPINDENT,
			    f->name, f->help);
	}
	return 0;
}

/*
 * a big command input loop for interface mode
 * if a function returns to interface() with a 1, interface() will break
 * the user back to command() mode.  interface() will always break from
 * mode handler calls.
 */
static int
interface(int argc, char **argv, char *modhvar)
{
	int z, num;
	struct intlist *i;	/* pointer to current command */

	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);

	if (argc != 2 && !modhvar) {
		printf("%% interface <interface name>\n");
		return(0);
	}

	ifname[IFNAMSIZ-1] = '\0';

	if (modhvar)
		strncpy(ifname, modhvar, sizeof(ifname));
	else
		strncpy(ifname, argv[1], sizeof(ifname));
        if (!is_valid_ifname(ifname)) {
                printf("%% inteface %s not found\n", ifname);
                return(0);
        }

	for (;;) {
		if (!modhvar) {
			/*
			 * interface cli routines for editing and standard
			 * mode
			 */
			if (!editing) {
				printf("%s", iprompt());
				if (fgets(line, sizeof(line), stdin) == NULL) {
					if (feof(stdin) || ferror(stdin)) {
						printf("\n");
						return(0);
					}
					break;
				}
			} else {
				const char *buf;
				cursor_pos = NULL;

				if ((buf = el_gets(eli, &num)) == NULL || num == 0)
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
				history(histi, H_ENTER, buf);
			}
			if (line[0] == 0)
				break;
			makeargv();
			if (margv[0] == 0) {
				break;
			}
		} else {
			/*
			 * a command was supplied directly to interface()
			 */
			for (z = 0; z < argc; z++)
				strncpy(margv[z], argv[z], sizeof(margv[z]));
			margc = argc;
		}
		if (strncasecmp(margv[0], "no", strlen("no")) == 0)
			i = GETINT(margv[1]);
		else
			i = GETINT(margv[0]);
		if (Ambiguous(i)) {
			printf("%% Ambiguous command\n");
		}
		if (i == 0) {
			int val = 1;

			if (editing)
				val = el_burrito(eli, margc, margv);
			if (val)
				printf("%% Invalid command\n");
		} else if ((*i->handler) (ifname, margc, margv)) {
			break;
		}
		if (modhvar) {
			break;
		}
	}
}

static int
int_help()
{
	struct intlist *i; /* pointer to current command */

	printf("%% Commands may be abbreviated.\n");
	printf("%% Press enter at a prompt to leave interface configuration mode.\n");
	printf("%% Interface configuration commands are:\n\n");

	for (i = Intlist; i->name; i++) {
		if (i->help)
			printf("  %-*s\t%s\n", (int)HELPINDENT,
			    i->name, i->help);
	}
	return 0;
}

/*
 * Data structures and routines for the main CLI
 */

static char
	hostnamehelp[] = "Set system hostname",
	interfacehelp[] = "Modify interface parameters",
	showhelp[] =	"Show system information",
	flushhelp[] =	"Flush system tables",
	enablehelp[] =	"Enable privileged mode",
	disablehelp[] =	"Disable privileged mode",
	routehelp[] =	"Add a host or network route",
	monitorhelp[] = "Monitor routing table changes",
	quithelp[] =	"Close current connection",
	verbosehelp[] =	"Set verbose diagnostics",
	editinghelp[] =  "Set command line editing",
	shellhelp[] =	"Invoke a subshell",
	helphelp[] =	"Print help information";

/*
 * Primary commands, will be included in help output
 */

static Command cmdtab[] = {
	{ "hostname",	hostnamehelp,	hostname,	1, 0, 0, 0 },
	{ "interface",	interfacehelp,	interface,	1, 0, 0, 1 },
#if 0
	{ "bridge",	bridgehelp,	bridge,		1, 0, 0, 1 },
#endif
	{ "show",	showhelp,	showcmd,	0, 0, 0, 0 },
	{ "flush",	flushhelp,	flushcmd,	1, 0, 0, 0 },
	{ "enable",	enablehelp,	enable,		0, 1, 0, 0 },
	{ "disable",	disablehelp,	disable,	1, 0, 0, 0 },
	{ "route",	routehelp,	route,		1, 0, 1, 0 },
	{ "monitor",	monitorhelp,	monitor,	0, 0, 0, 0 },
	{ "quit",	quithelp,	quit,		0, 0, 0, 0 },
	{ "verbose",	verbosehelp,	doverbose,	0, 0, 1, 0 },
	{ "editing",	editinghelp,	doediting,	0, 0, 1, 0 },
	{ "!",		shellhelp,	shell,		1, 0, 0, 0 },
	{ "?",		helphelp,	help,		0, 0, 0, 0 },
	{ "help",	0,		help,		0, 0, 0, 0 },
	{ 0,		0,		0,		0, 0, 0, 0 }
};

/*
 * These commands escape ambiguous check and help listings
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
command(top)
	int top;
{
	Command  *c;
	int num;

	inithist();
	initedit();

	if (!top) {
		putchar('\n');
	} else {
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGQUIT, SIG_IGN);
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
			history(histc, H_ENTER, buf);
		}

		if (line[0] == 0)
			break;
		makeargv();
		if (margv[0] == 0) {
			break;
		}
		if (strncasecmp(margv[0], "no", strlen("no")) == 0)
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
		if ((strncasecmp(margv[0], "no", strlen("no")) == 0) && ! c->nocmd) {
			printf("%% Invalid command: %s %s\n", margv[0],
			    margv[1]);
			continue;
		}
		if (c->needpriv != 0 && priv != 1) {
			printf("%% Privilege required\n");
			continue;
		}
		if (c->ignoreifpriv == 1 && priv == 1) {
			printf("%% Command invalid while privileged\n");
			continue;
		}
		if ((*c->handler) (margc, margv, 0)) {
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
		printf("%% Commands may be abbreviated.\n");
		printf("%% Commands are:\n\n");
		for (c = cmdtab; c->name; c++)
			if (c->help && ((c->needpriv == priv) ||
			    (c->ignoreifpriv != priv))) {
				printf("  %-*s\t%s\n", (int)HELPINDENT,
				    c->name, c->help);
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
hostname(argc, argv)
	int argc;
	char *argv[];
{
	argv++;
	argc--;

	if (argc > 1) {
		printf("%% Invalid arguments\n");
		return 1;
	}

	if (argc == 1) {
		if (sethostname(*argv, strlen(*argv)))
			perror("% sethostname");
	} else {
		if (gethostname(hbuf, sizeof(hbuf)))
			perror("% gethostname");
		printf("%% %s\n", hbuf);
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
 * verbose diagnostics
 */
int
doverbose(int argc, char **argv)
{
	if (argc > 1) {
		if (strncasecmp(argv[0], "no", strlen("no")) == 0) {
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
		if (strncasecmp(argv[0], "no", strlen("no")) == 0) { 
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
		return(0);
	}

	/*
	 * Editing mode needs to be reinitialized if the histi/histc
	 * pointers are going to change.....
	 */
	endedit();
	endhist();
	inithist();
	initedit();
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
		printf("%% kvm_openfiles: %s\n", buf);
		return 1;
	}
	if(kvm_nlist(kvmd, nl) < 0 || nl[0].n_type == 0) {
		if (nlistf)
			printf("%% kvm_nlist: %s: no namelist\n", nlistf);
		else
			printf("%% kvm_nlist: no namelist\n");
		return 1;
	}
	return 0;
}

/*
 * read a text file and execute commands
 * take into account that we may have mode handlers int cmdtab that 
 * execute indented commands from the rc file
 */
int
cmdrc(rcname)
	char rcname[FILENAME_MAX];
{
	Command	*c;
	FILE	*rcfile;
	char	modhvar[128];	/* required variable name in mode handler cmd */
	int	modhcmd; 	/* do we execute under another mode? */
	int	lnum;		/* line number */
	int	maxlen;		/* max length of cmdtab argument */

	if ((rcfile = fopen(rcname, "r")) == 0) {
		printf("%% %s not found\n",rcname);
		return 1;
	}

	for (c = cmdtab; c->name; c++)
		if (maxlen < strlen(c->name))
			maxlen = strlen(c->name);
	c = 0;

	for (lnum = 1; ; lnum++) {
		if (fgets(line, sizeof(line), rcfile) == NULL)
			break;
		if (line[0] == 0)
			break;
		if (line[0] == '#')
			continue;
		makeargv();
		if (margv[0] == 0)
			continue;
		if (line[0] == ' ') {
			/*
			 * here, if a command starts with a space, it is
			 * considered part of a mode handler
			 */
			modhcmd = 0;
			if (c)
				if (c->modh)
					modhcmd = 1;

			if (!modhcmd) {
				printf("%% No mode handler specified before indented command? (line %i) ", lnum);
				p_argv(margc, margv);
				printf("\n");
				continue;
			}
		} else {
			/*
			 * command was not indented.  process normally.
			 */
			modhcmd = 0;
			if (strncasecmp(margv[0], "no", strlen("no")) == 0) {
				c = getcmd(margv[1]);
				if (c)
					if(c->modh) {
						/*
						 * ..command is a mode handler
						 * then it cannot be 'no cmd'
						 */
						printf("%% Argument 'no' is invalid for a mode handler (line %i) ", lnum);
						p_argv(margc, margv);
						printf("\n");
						continue;
					}
			} else {
				c = getcmd(margv[0]);
				if(c)
					if(c->modh) {
						/*
						 * any mode handler should have
						 * one value stored, passed on
						 */
						if (margv[1]) {
							strncpy(modhvar,
							    margv[1],
							    sizeof(modhvar));
						} else {
							printf("%% No argument after mode handler (line %i) ", lnum);
							p_argv(margc, margv);
							printf("\n");
							continue;
						}
					}
			}
		}
		if (Ambiguous(c)) {
			printf("%% Ambiguous rc command (line %i) ", lnum);
			p_argv(margc, margv);
			printf("\n");
			continue;
		}
		if (c == 0) {
			printf("%% Invalid rc command (line %i) ", lnum);
			p_argv(margc, margv);
			printf("\n");
			continue;
		}
		if (verbose) {
			printf("%% %4s: %*s%10s (line %i) margv ",
			    c->modh ? "mode" : "cmd", maxlen, c->name,
			    modhcmd ? "(sub-cmd)" : "", lnum);
			p_argv(margc, margv);
			printf("\n");
		}
		if (!modhcmd) {
			/*
			 * normal processing, there is no sub-mode cmd to be
			 * dealt with
			 */
			if ((strncasecmp(margv[0], "no", strlen("no")) == 0) &&
		 	   !c->nocmd) {
				printf("%% Invalid rc command (line %i) ",
				    lnum);
				p_argv(margc, margv);
				printf("\n");
				continue;
			}
			if (c->modh) {
				/*
				 * we took the first argument after the command
				 * name, wait till the next line to actually do
				 * something!
				 */
				continue;
			}
		}
		if (c->modh && modhcmd)
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
el_burrito(EditLine *el, int margc, char **margv)
{
	char *colon;
	int val;

	if(!editing)	/* Nothing to parse, fail */
		return(1);

	/*
	 * el_parse will always return a non-error status if someone specifies
	 * argv[0] with a colon.  The idea of the colon is to allow host-
	 * specific commands, which is really only useful in .editrc, so
	 * it is invalid here.
	 */
	colon = (char *)strchr(margv[0], ':');
	if(colon)
		return(1);

	val = el_parse(el, margc, margv);

	if (val == 0)
		return(0);
	else
		return(1);
}

char *
cprompt(void)
{
	gethostname(hbuf, sizeof(hbuf));
	snprintf(prompt, sizeof(prompt), "%s%s/", hbuf, priv ? "(priv)" : "");

	return(prompt);
}

char *
iprompt(void)
{
	gethostname(hbuf, sizeof(hbuf));
	snprintf(prompt, sizeof(prompt), "%s(interface-%s)/", hbuf, ifname);

	return(prompt);
}

/*
 * Flush wrappers
 */
int
flush_ip_routes(void)
{
	flushroutes(AF_INET);
}

/*
 * Show wrappers
 */
int
pr_conf(void)
{
	conf(stdout);
}

int
pr_s_conf(void)
{
	printf("%% Not yet implemented\n");
}

int
pr_routes(void)
{
	routepr(nl[N_RTREE].n_value, AF_INET);
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

int
pr_ipcomp_stats(void)
{
	ipcomp_stats(nl[N_IPCOMPSTAT].n_value);
	return 0;
}

int
pr_mbuf_stats(void)
{
	mbpr(nl[N_MBSTAT].n_value, nl[N_MBPOOL].n_value,   
	    nl[N_MCLPOOL].n_value);
	return 0;
}

