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
 * nsh's own commands, which nsh runs as the user: the programs it starts,
 * such as ping, ssh and the shell, its settings and environment, the
 * manual, and the shows, each of which asks nshd and prints the answer.
 * nshd's command tables name these commands too, so nshd links this
 * file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/reboot.h>
#include <sys/sockio.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <limits.h>
#include <util.h>
#include <pwd.h>
#include "editing.h"
#include "stringlist.h"
#include "ip.h"
#include "externs.h"
#include "sysctl.h"
#include "ctl.h"
#include "conftree.h"
#include "settings.h"
#include "facts.h"
#include "showfacts.h"
#include "session.h"
#include "commands.h"
#include "nshcmds.h"

#define CONFIRMMIN	10	/* commit confirmed's minutes, if not given */
#define CONFIRMMAX	1440

static int	pr_crontab(int, char **, ...);
static int	pr_daemons(int, char **, ...);
static int	pr_routes(int, char **, ...);
static int	pr_routes6(int, char **, ...);
static int	pr_arp(int, char **, ...);
static int	pr_ndp(int, char **, ...);
static int	pr_sadb(int, char **, ...);
static int	pr_kernel(int, char **, ...);
static int	pr_dhcp(int, char **, ...);
static int	pr_conf(int, char **, ...);
static int	pr_s_conf(int, char **, ...);
static int	pr_a_conf(int, char **, ...);
static int	pr_conf_diff(int, char **, ...);
static int	pr_environment(int, char **, ...);

/* the help of nsh's own commands, which nshd's tables show too */
char
	rtablehelp[] = 	"Routing table switch",
	clearhelp[]=	"Clear the terminal screen",
	showhelp[] =	"Show system information",
	flushhelp[] =	"Flush system tables",
	pinghelp[] = 	"Send IPv4 ICMP echo request",
	ping6help[] =   "Send IPv6 ICMP echo request",
	tracerthelp[] =	"Print the route to IPv4 host",
	tracert6help[] ="Print the route to IPv6 host",
	sshhelp[] =	"SSH connection to remote host",
	telnethelp[] =	"Telnet connection to remote host",
	quithelp[] =	"Close current connection",
	exithelp[] =	"Leave configuration mode",
	verbosehelp[] =	"Set verbose diagnostics",
	editinghelp[] = "Set command line editing",
	confighelp[] =	"Set configuration mode",
	rollbackhelp[] = "Discard the candidate's changes, or load a saved configuration",
	loggerhelp[] =  "Write a message to syslog on the system",
	whohelp[] =	"Display system users",
	dohelp[] =	"Superfluous, do is ignored and its arguments executed",
	setenvhelp[] =	"Set an environment variable",
	unsetenvhelp[] ="Delete an environment variable",
	saveenvhelp[] =	"Save environment variables set by setenv to ~/.nshenv",
	shellhelp[] =	"Invoke a subshell or run an executable",
	commithelp[] =	"Make the candidate the running configuration, and save it",
	nreboothelp[] =	"Reboot the system",
	halthelp[] =	"Halt the system",
	powerdownhelp[] ="Power the system down",
	helphelp[] =	"Print help information",
	manhelp[] =	"Display the NSH manual";

/* kernel statistics, each shown from the facts "statistics <name>" */
static struct stt {
	char *name;
	char *help;
} stts[] = {
	{ "ip",		"Internet Protocol" },
	{ "ah",		"Authentication Header" },
	{ "esp",	"Encapsulated Security Payload" },
	{ "tcp",	"Transmission Control Protocol" },
	{ "udp",	"Unreliable Datagram Protocol" },
	{ "icmp",	"Internet Control Message Protocol" },
	{ "igmp",	"Internet Group Management Protocol" },
	{ "ipcomp",	"IP Compression" },
	{ "route",	"Routing" },
	{ "carp",	"Common Address Redundancy Protocol" },
	{ "mbuf",	"Packet memory buffer" },
	{ "pf",		"Packet Filter" },
	{ 0,		0 }
};


/*
 * Quit command
 */

int
quit(int argc, char **argv, ...)
{
	if (interactive_mode)
		printf("%% Session terminated.\n");
	exit(0);
	return 0;
}

struct ghs showroutetab[] = {
	{ "<cr>", "Type Enter to run command", CMPL0 NULL, 0 },
	{ "<address[/prefix-length]>", "IP address parameter" , CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs showarptab[] = {
	{ "<cr>", "Type Enter to run command", CMPL0 NULL, 0 },
	{ "<IPv4-address>", "IPv4 address parameter", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs showndptab[] = {
	{ "<cr>", "Type Enter to run command", CMPL0 NULL, 0 },
	{ "<IPv6-address>", "IPv6 address parameter", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs showvlantab[] = {
	{ "<cr>", "Type Enter to run command", CMPL0 NULL, 0 },
	{ "<VLAN Tag>", "VLAN tag parameter", CMPL0 NULL, 0 },
	{ "<VLAN Start Tag> <VLAN End Tag>", "VLAN tag range parameters", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

/*
 * Data structures and routines for the "show" command.
 */

/* show yyy zzz */
struct prot prots[] = {
	{ "bgp",		bgcs },
	{ "ospf",		oscs },
	{ "ospf6",		os6cs },
	{ "pf",			pfcs },
	{ "eigrp",		eics },
	{ "rip",		rics },
	{ "ike",		ikcs },
	{ "ipsec",		iscs },
	{ "ldp",		lics },
	{ "dvmrp",		dvcs },
	{ "relay",		rlcs },
	{ "smtp",		smcs },
	{ "ldap",		ldcs },
	{ "system-stats",	systatcs },
	{ 0,		0 }
};

Menu showlist[] = {
	{ "hostname",	"Router hostname",	CMPL0 0, 0, 0, 0, show_hostname },
	{ "interface",	"Interface config",	CMPL(i) 0, 0, 0, 2, show_int },
	{ "autoconf",	"IPv4/IPv6 autoconf state", CMPL(i) 0, 0, 0, 1, show_autoconf },
	{ "ip",		"IP address information", CMPL0 0, 0, 0, 0, show_ip },
	{ "inet",	"IPv4 address information", CMPL0 0, 0, 0, 0, show_ip },
	{ "inet6",	"IPv6 address information", CMPL0 0, 0, 0, 0, show_ip },
	{ "route",	"IPv4 route table or route lookup", CMPL(h) (char **)showroutetab, sizeof(struct ghs), 0, 1, pr_routes },
	{ "route6",	"IPv6 route table or route lookup", CMPL(h) (char **)showroutetab, sizeof(struct ghs), 0, 1, pr_routes6 },
	{ "sadb",	"Security Association Database", CMPL0 0, 0, 0, 0, pr_sadb },
	{ "arp",	"ARP table",		CMPL(h) (char **)showarptab, sizeof(struct ghs), 0, 1, pr_arp },
	{ "ndp",	"NDP table",		CMPL(h) (char **)showndptab, sizeof(struct ghs), 0, 1, pr_ndp },
	{ "vlan",	"802.1Q/802.1ad VLANs",	CMPL(h) (char **)showvlantab, sizeof(struct ghs), 0, 2, show_vlans },
	{ "bridge",	"Ethernet bridges",	CMPL(b) 0, 0, 0, 1, show_bridges },
	{ "kernel",	"Kernel statistics",	CMPL(ta) (char **)stts, sizeof(struct stt), 0, 1, pr_kernel },
	{ "bgp",	"BGP information",	CMPL(ta) (char **)bgcs, sizeof(struct prot1), 0, 4, pr_prot1 },
	{ "ospf",	"OSPF information",	CMPL(ta) (char **)oscs, sizeof(struct prot1), 0, 3, pr_prot1 },
	{ "ospf6",	"OSPF6 information",	CMPL(ta) (char **)os6cs, sizeof(struct prot1), 0, 3, pr_prot1 },
	{ "pf",		"Packet Filter firewall information", CMPL(ta) (char **)pfcs, sizeof(struct prot1), 0, 3, pr_prot1 },
	{ "eigrp",	"EIGRP information",	CMPL(ta) (char **)eics, sizeof(struct prot1), 0, 3, pr_prot1 },
	{ "rip",	"RIP information",	CMPL(ta) (char **)rics, sizeof(struct prot1), 0, 3, pr_prot1 },
	{ "ldp",	"LDP information",	CMPL(ta) (char **)lics, sizeof(struct prot1), 0, 3, pr_prot1 },
	{ "ike",	"IKE information",	CMPL(ta) (char **)ikcs, sizeof(struct prot1), 0, 3, pr_prot1 },
	{ "ipsec",	"IPsec information",	CMPL(ta) (char **)iscs, sizeof(struct prot1), 0, 1, pr_prot1 },
	{ "dvmrp",	"DVMRP information",	CMPL(ta) (char **)dvcs, sizeof(struct prot1), 0, 2, pr_prot1 },
	{ "relay",	"Relay server",		CMPL(ta) (char **)rlcs, sizeof(struct prot1), 0, 1, pr_prot1 },
	{ "dhcp",	"DHCP server",		CMPL(ta) (char **)dhcs, sizeof(struct prot1), 0, 1, pr_dhcp },
	{ "smtp",	"SMTP server",		CMPL(ta) (char **)smcs, sizeof(struct prot1), 0, 1, pr_prot1 },
	{ "ldap",	"LDAP server",		CMPL(ta) (char **)ldcs, sizeof(struct prot1), 0, 1, pr_prot1 },
	{ "monitor",	"Monitor routing/arp table changes", CMPL0 0, 0, 0, 0, monitor },
	{ "log",	"Follow daemon, messages, authlog or pflog, until ^C", CMPL0 0, 0, 1, 1, show_log },
	{ "system-stats",	"System, firewall and kernel statistics", CMPL(ta) (char **)systatcs, sizeof(struct prot1), 0, 3, pr_prot1 },
	{ "version",	"Software information",	CMPL0 0, 0, 0, 0, version },
	{ "users",	"System users",		CMPL0 0, 0, 0, 0, who },
	{ "daemons",	"Daemons, and whether each runs",	CMPL0 0, 0, 0, 0, pr_daemons },
	{ "crontab",	"Scheduled background jobs",	CMPL0 0, 0, 0, 0, pr_crontab },
	{ "scheduler",	"Scheduled background jobs",	CMPL0 0, 0, 0, 0, pr_crontab },
	{ "running-config",	"Operating configuration", CMPL0 0, 0, 0, 0, pr_conf },
	{ "startup-config", "Startup configuration", CMPL0 0, 0, 0, 0, pr_s_conf },
	{ "active-config", "Configuration of active context", CMPL0 0, 0, 0, 0, pr_a_conf },
	{ "diff-config", "Show differences between startup and running config, or running and candidate", CMPL0 0, 0, 0, 0, pr_conf_diff },
	{ "candidate-config", "Candidate configuration", CMPL0 0, 0, 0, 0, pr_cand_conf },
	{ "rollback",	"Configurations saved, one of them, or what it changed", CMPL0 0, 0, 0, 2, pr_rollback },
	{ "environment", "Show environment variables",	CMPL(e) 0, 0, 0, 1, pr_environment },
	{ "?",		"Options",		CMPL0 0, 0, 0, 0, show_help },
	{ "help",	0,			CMPL0 0, 0, 0, 0, show_help },
	{ 0, 0, 0, 0, 0 }
};

int
showcmd(int argc, char **argv, ...)
{
	Menu *s;	/* pointer to current command */
	int error = 0, outfd = -1;
	char outpath[PATH_MAX];
	struct stat sb;

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
		return -1;
	} else if (Ambiguous(s)) {
		printf("%% Ambiguous argument %s\n", argv[1]);
		return -1;
	}
	if (((s->minarg + 2) > argc) || ((s->maxarg + 2) < argc)) {
		printf("%% Wrong number of argument%s to 'show %s' command"
		    " (min %i, max %i)\n", argc <= 2 ? "" : "s", s->name,
		    s->minarg, s->maxarg);
		return -1;
	}

	if (strlcpy(outpath, "/tmp/nsh.show.XXXXXXXX", sizeof(outpath)) >=
	    sizeof(outpath))
		return 0;

	outfd = mkstemp(outpath);
	if (outfd == -1) {
		printf("%% mkstemp %s: %s\n", outpath, strerror(errno));
		return -1;
	}

	if (fstat(outfd, &sb) == -1) {
		printf("%% fstat %s: %s\n", outpath, strerror(errno));
		error = -1;
		goto done;
	}

	if (s->handler)	{
		FILE *f;
		int fd;

		fd = dup(outfd);
		if (fd == -1) {
			printf("%% dup %s\n", strerror(errno));
			error = -1;
			goto done;
		}

		f = fdopen(fd, "w+");
		if (f == NULL) {
			printf("%% dup %s\n", strerror(errno));
			close(fd);
			error = -1;
			goto done;
		}
		error = (*s->handler)(argc, argv, f);
		if (fflush(f) == EOF) {
			printf("%% fflush %s: %s\n", outpath, strerror(errno));
			error = -1;
		}
		fclose(f); /* fd is closed via f */
	}

	/*
	 * Until all show commands have been converted to write to the output
	 * file we need to check here whether the file has been modified before
	 * piping it to the pager.
	 */
	if (error == 0) {
		struct stat sb2;

		lseek(outfd, 0, SEEK_SET);
		if (fstat(outfd, &sb2) == -1) {
			printf("%% fstat %s: %s\n", outpath, strerror(errno));
			error = -1;
			goto done;
		}
		if (sb.st_size != sb2.st_size ||
		    sb.st_mtim.tv_sec != sb2.st_mtim.tv_sec ||
		    sb.st_mtim.tv_nsec != sb2.st_mtim.tv_nsec)
			more(outpath);
	}
done:
	if (close(outfd) == EOF) {
		printf("%% close %s: %s\n", outpath, strerror(errno));
		error = -1;
	}
	if (unlink(outpath) == -1) {
		printf("%% unlink %s: %s\n", outpath, strerror(errno));
		error = -1;
	}
	return error ? -1 : 0;
}

/*
 * Ask nshd's system to run name, with argv's words after the first, as
 * an operation in rtable. Returns 0, or -1 on error
 */
int
op_ask(char *name, int argc, char **argv, int rtable)
{
	char op[sizeof(line)];
	int i;

	strlcpy(op, name, sizeof(op));
	for (i = 1; i < argc; i++)
		if (strlcat(op, " ", sizeof(op)) >= sizeof(op) ||
		    strlcat(op, argv[i], sizeof(op)) >= sizeof(op)) {
			printf("%% Input exceeds permitted length\n");
			return -1;
		}
	return facts_op(op, rtable, 0) == 0 ? 0 : -1;
}

int
int_logger(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return logger(argc, argv) == -1 ? -1 : 0;
}

int
int_ping(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return ping(argc, argv) == -1 ? -1 : 0;
}

int
int_ping6(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return ping6(argc, argv) == -1 ? -1 : 0;
}

int
int_traceroute(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return traceroute(argc, argv) == -1 ? -1 : 0;
}

int
int_traceroute6(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return traceroute6(argc, argv) == -1 ? -1 : 0;
}

int
int_ssh(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return ssh(argc, argv) == -1 ? -1 : 0;
}

int
int_telnet(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return telnet(argc, argv) == -1 ? -1 : 0;
}

int
int_do(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return docmd(argc, argv) == -1 ? -1 : 0;
}

int
int_setenv(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return setenvcmd(argc, argv) == -1 ? -1 : 0;
}

int
int_unsetenv(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return unsetenvcmd(argc, argv) == -1 ? -1 : 0;
}

int
int_saveenv(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return saveenvcmd(argc, argv) == -1 ? -1 : 0;
}

int
int_show(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return showcmd(argc, argv) == -1 ? -1 : 0;
}

int
int_who(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return who(argc, argv) == -1 ? -1 : 0;
}

int
int_doverbose(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return doverbose(argc, argv) == -1 ? -1 : 0;
}

int
int_doediting(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return doediting(argc, argv) == -1 ? -1 : 0;
}

int
int_manual(int argc, char **argv, ...)
{
	/* do not leave interface context */
	return manual(argc, argv) == -1 ? -1 : 0;
}

int
int_shell(int argc, char **argv, ...)
{
	if (argc > 1) 
	{
		shell(argc, argv);
		return 0; /* do not leave interface context after execution */
	}
	else
	return 1; /* this is to allow for pasting configs with "!" separators */
}

int
int_clear(int argc, char **argv, ...)
{
	return clear(argc, argv);
}

int
int_help(int argc, char **argv, ...)
{
	struct intlist *i; /* pointer to current command */
	u_int z = 0;

	printf("%% Commands may be abbreviated.\n");
	printf("%% Type 'exit' at a prompt to leave %s configuration mode.\n",
	    bridge ? "bridge" : "interface");
	printf("%% %s configuration commands are:\n\n",
	    bridge ? "Bridge" : "Interface");

	for (i = whichlist; i->name; i++) {
		if (strlen(i->name) > z)
			z = strlen(i->name);
	}

	for (i = whichlist; i->name; i++) {
		if (i->help)
			printf("  %-*s  %s\n", z, i->name, i->help);
	}
	return 0;
}

/*
 * Manual command.
 */

static void
manual_usage(void)
{
	printf("%% manual [search tag]\n");
}

int
manual(int argc, char **argv, ...)
{
	sig_t sigint, sigquit, sigchld;
	char term[32], *termenv = NULL;
	char tag[64], *tagarg = NULL;
	const char *lessenv, *nsh8;

	if (argc != 1 && argc != 2) {
		manual_usage();
		return -1;
	}

	if (argc == 2) {
		if (strcmp(argv[1], "?") == 0) {
			manual_usage();
			return 0;
		}
		snprintf(tag, sizeof(tag), "tag=%s", argv[1]);
		tagarg = tag;
		lessenv = "LESS=-P [j/k]-scroll down/up "
		    "[t]-jump to next tag "
		    "[T]-jump to previous tag "
		    "[q]-quit";
	} else {
		lessenv = "LESS=-P [j/k]-scroll down/up "
		    "[q]-quit";
	}

	termenv = getenv("TERM");
	if (termenv) {
		snprintf(term, sizeof(term), "TERM=%s", getenv("TERM"));
		termenv = term;
	}

	nsh8 = getenv("NSH_MANUAL_PAGE");
	if (nsh8 == NULL)
		nsh8 = "/usr/local/man/man8/nsh.8";

	sigint = signal(SIGINT, SIG_IGN);
	sigquit = signal(SIGQUIT, SIG_IGN);
	sigchld = signal(SIGCHLD, SIG_DFL);

	switch (child = fork()) {
		case -1:
			printf("%% fork failed: %s\n", strerror(errno));
			break;

		case 0:
			signal(SIGQUIT, SIG_DFL);
			signal(SIGINT, SIG_DFL);
			signal(SIGCHLD, SIG_DFL);

			/*
			 * Fire up man(1) in the child.
			 */
			const char *env[] = {
				"PAGER=less",
				"LESSSECURE=1",
				lessenv,
				termenv,
				NULL
			};

			if (tagarg == NULL) {
				execle("/usr/bin/man", "man", "-l",
				    nsh8, NULL, env);
			} else {
				execle("/usr/bin/man", "man", "-l",
				    "-O", tagarg, nsh8, NULL, env);
			}
			printf("%% execl '/usr/bin/man' failed: %s\n",
			   strerror(errno));
			_exit(0);
			break;
		default:
			signal(SIGALRM, sigalarm);
 			wait(0);  /* Wait for man(1) to complete */
			break;
	}

	signal(SIGINT, sigint);
	signal(SIGQUIT, sigquit);
	signal(SIGCHLD, sigchld);
	signal(SIGALRM, SIG_DFL);
	child = -1;

	return 1;
}

int
show_hostname(int argc, char **argv, ...)
{
	return facts_show(stdout, "hostname");
}

/* logger command */

int
logger(int argc, char *argv[], ...)
{
        if (argc < 2) {  
                printf("%% Invalid arguments\n");
                return -1;
        } else {
                cmdargs(LOGGER, argv);
        }
        return 0;
}


/*
 * "no" command
 * This is a pseudo command table entry used for TAB-completion purposes.
 */
int
nocmd(int argc, char **argv, ...)
{
	Command  *cmd = NULL, *c;

	if (!NO_ARG(argv[0])) {
		printf("%% nocmd: invalid command %s\n", argv[0]);
		return -1;
	}

	if (argc < 2) {
		printf("%% nocmd: command name not provided\n");
		return -1;
	}

	for (c = cmdtab; c->name; c++) {
		if (c->nocmd && strcmp(c->name, argv[1]) == 0) {
			cmd = c;
			break;
		}
	}

	if (cmd == NULL) {
		printf("%% nocmd: command %s not found\n", argv[1]);
		return -1;
	}

	return (*c->handler)(argc, argv, 0);
}

/*
 * "do" command
 * This is a pseudo command which exists for people used to routers and
 * switches which offer a "do" command for context switching.
 */
int
docmd(int argc, char **argv, ...)
{
	if (argc < 2) {
		printf("%% command name not provided\n");
		return -1;
	}
	if (NO_ARG(argv[1])) {
		printf("%% 'no' commands are not supported with 'do'\n");
		return -1;
	}
	return cmd_rest(argc - 1, argv + 1);
}

static void
usage_setenv(void)
{
	printf("%% setenv NAME=VALUE\n");
	printf("%% setenv NAME=\"VALUE with spaces\"\n");
	printf("%% setenv \"NAME with spaces\"=VALUE\n");
}

int
setenvcmd(int argc, char **argv, ...)
{
	char *name, *eq, *value;
	void *name0;

	if (argc != 2) {
		usage_setenv();
		return 0;
	}

	if (nsh_env == NULL) {
		nsh_env = hashtable_alloc();
		if (nsh_env == NULL) {
			printf("%% hashtable_alloc: %s", strerror(errno));
			return -1;
		}
	}

	name = strdup(argv[1]);
	if (name == NULL) {
		printf("%% setenvcmd: strndup: %s\n", strerror(errno));
		return -1;
	}

	eq = strchr(name, '=');
	if (eq == NULL) {
		usage_setenv();
		free(name);
		return 0;
	}

	*eq = '\0';
	value = eq + 1;
	if (setenv(name, value, 1) == -1)
		printf("%% setenv %s=%s: %s\n", name, value, strerror(errno));

	/* Try to remove first, in case of updating an existing variable. */
	if (hashtable_remove(nsh_env, &name0, NULL, NULL,
	    name, strlen(name)) == 0)
		free(name0);

	if (hashtable_add(nsh_env, name, strlen(name), value, strlen(value))) {
		printf("%% %s: hashtable_add(\"%s\", \"%s\") failed\n",
		    __func__, name, value);
		free(name);
	}

	return 0;
}

int
unsetenvcmd(int argc, char **argv, ...)
{
	char *name;
	void *name0;

	if (argc != 2) {
		printf("%% unsetenv NAME\n");
		return -1;
	}

	name = argv[1];

	if (unsetenv(name) == -1)
		printf("%% unsetenv %s: %s\n", name, strerror(errno));
	
	if (hashtable_remove(nsh_env, &name0, NULL, NULL,
	    name, strlen(name)) == 0)
		free(name0);

	return 0;
}

static int
savevar(void *keyptr, size_t keysize, void *value, size_t valsize, void *arg)
{
	FILE *f = arg;
	char *name = keyptr;
	char *val = value;
	int ret;

	ret = fprintf(f, "%s=%s\n", name, val);
	if (ret != keysize + valsize + 2) {
		printf("%% could not save %s=%s: %s\n", name, val,
		    ferror(f) ? strerror(errno) : "bad write");
		return -1;
	}

	return 0;
}

int
saveenvcmd(int argc, char **argv, ...)
{
	char tmppath[PATH_MAX], path[PATH_MAX];
	FILE *f;
	char *home;
	int ret, fd;

	if (argc != 1) {
		printf("%% usage: saveenv\n");
		return -1;
	}

	if (nsh_env == NULL)
		return 0;

	home = getenv("HOME");
	if (home == NULL) {
		printf("%% cannot find home directory; HOME is not set!\n");
		return -1;
	}

	ret = snprintf(path, sizeof(path), "%s/.nshenv", home);
	if (ret < 0 || (size_t)ret >= sizeof(path)) {
		printf("%% path to ~/.nshenv is too long\n");
		return -1;
	}

	ret = snprintf(tmppath, sizeof(tmppath), "%s/.nshenv-XXXXXXXXXX", home);
	if (ret < 0 || (size_t)ret >= sizeof(tmppath)) {
		printf("%% path to ~/.nshenv is too long\n");
		return -1;
	}

	fd = mkstemp(tmppath);
	if (fd == -1) {
		printf("%s: mkstemp %s: %s", __func__, tmppath,
		    strerror(errno));
		return 0;
	}


	f = fdopen(fd, "w");
	if (f == NULL) {
		printf("%% fdopen %s: %s\n", tmppath, strerror(errno));
		close(fd);
		if (unlink(tmppath) == -1)
			printf("%% unlink %s: %s\n", tmppath, strerror(errno));
		return -1;
	}

	if (fchmod(fileno(f), S_IRUSR | S_IWUSR) == -1)
		printf("%% chmod 600 %s: %s\n", tmppath, strerror(errno));

	hashtable_foreach(nsh_env, savevar, f);

	if (rename(tmppath, path) == -1) {
		printf("%% rename %s %s: %s\n", tmppath, path, strerror(errno));
		if (unlink(tmppath) == -1)
			printf("%% unlink %s: %s\n", tmppath, strerror(errno));
	}

	fclose(f);

	return 0;
}

/*
 * Shell command.
 */
int
shell(int argc, char **argv, ...)
{
	sig_t sigint, sigquit, sigchld;

	/* a command needs the exec permission */
	if (argc > 1 && !nshd_runs("/bin/sh"))
		return 1;
	sigint = signal(SIGINT, SIG_IGN);
	sigquit = signal(SIGQUIT, SIG_IGN);
	sigchld = signal(SIGCHLD, SIG_DFL);
        if (argc <= 1) /* only fork if you have a command or shell to execute*/
		return 1;
	else {
		switch(child = fork()) {
		case -1:
			printf("%% fork failed: %s\n", strerror(errno));
			break;

		case 0:
			{
			signal(SIGQUIT, SIG_DFL);
			signal(SIGINT, SIG_DFL);
			signal(SIGCHLD, SIG_DFL);

			if (nsh_setrtable(cli_rtable))
				_exit(0);
			/*
			 * Fire up the shell in the child.
			 */
			char *shellp;
			char *shellname = shellp = "/bin/sh";
			execl(shellp, shellname, "-c", &saveline[1],
				(char *)NULL);
			printf("%% execl '%s' failed: %s\n", shellp,
				strerror(errno));
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
	
}

/*
 * ping command.
 */
int
ping(int argc, char *argv[], ...)
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return -1;
	} else {
		cmdargs(PING, argv);
	}
	return 0;
}

int
ping6(int argc, char *argv[], ...)
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return -1;
	} else {
		cmdargs(PING6, argv);
	}
	return 0;
}

/*
 * telnet command.
 */
int
telnet(int argc, char *argv[], ...)
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return -1;
	} else {
		cmdargs(TELNET, argv);
	}
	return 0;
}

/*
 * ssh command.
 */
int
ssh(int argc, char *argv[], ...)
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return -1;
	} else {
		cmdargs(SSH, argv);
	}
	return 0;
}

/*
 * traceroute command.
 */
int
traceroute(int argc, char *argv[], ...)
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return -1;
	} else {
		cmdargs(TRACERT, argv);
	}
	return 0;
}

int
traceroute6(int argc, char *argv[], ...)
{
	if (argc < 2) {
		printf("%% Invalid arguments\n");
		return -1;
	} else {
		cmdargs(TRACERT6, argv);
	}
	return 0;
}

//clear terminal screen
int
clear(int argc, char **argv, ...)
{
	char *args[] = {CLEAR, NULL, NULL };	
        cmdargs(CLEAR, args);
	return 0; 
}

/*
 * verbose diagnostics
 */
int
doverbose(int argc, char **argv, ...)
{
	if (argc > 1) {
		if (NO_ARG(argv[0])) {
			verbose = 0;
		} else {
			printf ("%% Invalid argument\n");
			return -1;
		}
	} else {
		verbose = 1;
	}

	printf("%% Diagnostic mode %s\n", verbose ? "enabled" : "disabled");

	return 0;
}

int
doediting(int argc, char **argv, ...)
{
	if (argc > 1) {
		if (NO_ARG(argv[0])) {
			endedit();
                } else {
			printf ("%% Invalid argument\n");
			return -1;
		}
	} else {
		initedit();
	}

	printf("%% Command line editing %s\n",
	    editing ? "enabled" : "disabled");

	return 0;
}

/*
 * flush history, and flush's help: nsh runs these, and nshd's system
 * the other flushes, as nshd's rows say
 */
int
flushcmd(int argc, char **argv, ...)
{
	Command *c = getcmd("flush");
	struct ghs *g;
	char *p;
	u_int z = 0;

	if (argc >= 2) {
		g = (struct ghs *)genget(argv[1], c->table, c->stlen);
		if (g == 0) {
			printf("%% Invalid argument %s\n", argv[1]);
			return -1;
		} else if (Ambiguous(g)) {
			printf("%% Ambiguous argument %s\n", argv[1]);
			return -1;
		}
		if (strcmp(g->name, "history") == 0) {
			if (argc > 2) {
				printf("%% Wrong arguments to 'flush history'"
				    " command.\n");
				return -1;
			}
			return flush_history(argc, argv);
		}
		if (strcmp(g->name, "?") != 0 && strcmp(g->name, "help") != 0) {
			printf("%% flush %s is not one of nsh's own commands\n",
			    g->name);
			return -1;
		}
	}

	printf("%% Commands may be abbreviated.\n");
	printf("%% 'flush' commands are:\n\n");
	for (p = (char *)c->table; (g = (struct ghs *)p)->name;
	    p += c->stlen)
		if (strlen(g->name) > z)
			z = strlen(g->name);
	for (p = (char *)c->table; (g = (struct ghs *)p)->name;
	    p += c->stlen)
		if (g->help)
			printf("  %-*s  %s\n", z, g->name, g->help);
	return 0;
}

int
flush_history(int argc, char **argv, ...)
{
	if (!editing) {
		printf("%% Command line editing not enabled\n");
		return -1;
	}

	/*
	 * Editing mode needs to be reinitialized if the histi/histc
	 * pointers are going to change.....
	 */
	endedit();
	endhist();
	inithist();
	initedit();

	return 0;
}

static int
do_reboot(int how)
{
	const char *buf, *op, *prompt;
	char linebuf[64];
	int ret = 0, num, have_changes;

	switch (how) {
	case RB_AUTOBOOT:
		op = "reboot";
		prompt = "Proceed with reboot? [yes/no] ";
		break;
	case RB_HALT:
		op = "halt";
		prompt = "Proceed with shutdown? [yes/no] ";
		break;
	case RB_POWERDOWN:
		op = "powerdown";
		prompt = "Proceed with powerdown? [yes/no] ";
		break;
	default:
		printf("%% Invalid reboot parameter 0x%x\n", how);
		return -1;
	}

	/* nshd's system compares the running and saved configurations */
	have_changes = facts_op("diff-config", cli_rtable, 1);
	if (have_changes != 0 && have_changes != OP_DIFFERS)
		return -1;
	else if (have_changes) {
		printf("%% WARNING: The running configuration contains "
		    "unsaved changes!\n"
		    "%% The 'show diff-config' command will display unsaved "
		    "changes.\n"
		    "%% The 'commit' command will save changes to %s.\n",
		    SAVED);
		if (!interactive_mode)
			return -1;
	}

	if (!interactive_mode) {
		if (facts_op(op, cli_rtable, 0) != 0)
			printf("%% %s failed\n", op);
		return -1;
	}

	setprompt(prompt);
	for (;;) {
		if (!isatty(STDIN_FILENO) || elp == NULL) {
			if (fgets(linebuf, sizeof(linebuf), stdin) == NULL) {
				ret = -1;
				goto done;
			}
			buf = linebuf;
		} else if ((buf = el_gets(elp, &num)) == NULL) {
			if (num == -1) {
				ret = -1;
				goto done;
			}
			/* EOF, e.g. ^X or ^D via exit_i() in editing.c */
			goto done;
		}

		if (strcasecmp(buf, "yes\n") == 0)
			break;

		if (strcasecmp(buf, "no\n") == 0)
			goto done;

		printf("%% Please type \"yes\" or \"no\"\n");
	}

	if (how == RB_AUTOBOOT)
		printf("%% Reboot initiated\n");
	else
		printf("%% Shutdown initiated\n");

	if (facts_op(op, cli_rtable, 0) != 0)
		printf("%% %s failed\n", op);
done:
	restoreprompt();
	return ret;
}

/*
 * Reboot
 */
int
nreboot(int argc, char **argv, ...)
{
	return do_reboot(RB_AUTOBOOT);
}

int
halt(int argc, char **argv, ...)
{
	return do_reboot(RB_HALT);
}

int
powerdown(int argc, char **argv, ...)
{
	return do_reboot(RB_POWERDOWN);
}

/*
 * Show wrappers
 */
static int
pr_conf(int argc, char **argv, ...)
{
	return nshd_show("running-config") ? 0 : -1;
}

/*
 * Show startup config, as nshd reports it
 */
static int
pr_s_conf(int argc, char **argv, ...)
{
	return nshd_show("startup-config") ? 0 : -1;
}

/*
 * Show running-config for the active context.
 * Currently only supports the interface/bridge context.
 */
static int
pr_a_conf(int argc, char **argv, ...)
{
	if (ifname[0] == '\0') {
		printf ("%% Interface or Bridge context required\n");
		return -1;
	}

	return nshd_show_if(ifname);
}

/*
 * show differences between startup and running config, as nshd's system
 * shows them, or in configure between running config and the candidate,
 * as its config does, block by block.
 *
 * the lines of a block are compared as a set, a daemon's rules as a
 * sequence.
 */
static int
pr_conf_diff(int argc, char **argv, ...)
{
	int r;

	/* in a configure session that nshd holds */
	if (nshd_config)
		return nshd_cshow("diff-config");

	r = facts_op("diff-config", cli_rtable, 0);
	return r == 0 || r == OP_DIFFERS ? 0 : -1;
}

/* the daemons nsh starts, and whether each runs */
static int
pr_daemons(int argc, char **argv, ...)
{
	return facts_show(stdout, "daemons");
}

/* root's crontab, as nshd's system shows it */
static int
pr_crontab(int argc, char **argv, ...)
{
	return facts_op("crontab", cli_rtable, 0) == 0 ? 0 : -1;
}

static int
pr_routes(int argc, char **argv, ...)
{
	switch(argc) {
	case 2:
		/* show primary routing table */
		return facts_show(stdout, "route inet %d", cli_rtable);
	case 3:
		/* show a specific route */
		return show_route(argv[2], cli_rtable);
	}

	return 0;
}

static int
pr_routes6(int argc, char **argv, ...)
{
	switch(argc) {
	case 2:
		/* show primary routing table */
		return facts_show(stdout, "route inet6 %d", cli_rtable);
	case 3:
		/* show a specific route */
		return show_route(argv[2], cli_rtable);
	}

	return 0;
}

int
pr_arp(int argc, char **argv, ...)
{
	struct in_addr in;

	switch(argc) {
	case 2:
		/* show arp table */
		return facts_show(stdout, "arp %d", cli_rtable);
	case 3:
		/* specific address */
		if (getinetaddr(argv[2], &in) == -1) {
			printf("%% arpget: getinetaddr: failure %s\n",
			    strerror(errno));
			return -1;
		}
		return facts_show(stdout, "arp %d %s", cli_rtable,
		    inet_ntoa(in));
	}
	return 0;
}

static int
pr_ndp(int argc, char **argv, ...)
{
	struct sockaddr_in6 sin6;

	switch(argc) {
	case 2:
		/* show ndp table */
		return facts_show(stdout, "ndp %d", cli_rtable);
	case 3:
		/* specific address */
		if (parse_host(argv[2], &sin6))
			return -1;
		return facts_show(stdout, "ndp %d %s", cli_rtable, argv[2]);
	}
	return 0;
}

static int
pr_sadb(int argc, char **argv, ...)
{
	return facts_show(stdout, "sadb");
}

static int
pr_kernel(int argc, char **argv, ...)
{
	struct stt *x;

	if (argc < 3 || argv[2][0] == '?') {
		gen_help((char **)stts, "show kernel", "statistics",
		    sizeof(struct stt));
		return 0;
	}
	x = (struct stt *) genget(argv[2], (char **)stts, sizeof(struct stt));
	if (x == 0) {
		printf("%% Invalid argument %s\n", argv[2]);
		return -1;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", argv[2]);
		return -1;
	}
	return facts_show(stdout, "statistics %s", x->name);
}

static int
pr_dhcp(int argc, char **argv, ...)
{
	if (argc == 3 && argv[2][0] != '?') {
		if (isprefix(argv[2], "leases")) {
			return facts_show(stdout, "dhcp leases");
		}
		printf("%% argument %s not recognized\n", argv[2]);
		return -1;
	}
	printf("%% show dhcp leases\n");
	return -1;
}

static int
envcmp(const void *item1, const void *item2)
{
	const char *a = *(const char **)item1;
	const char *b = *(const char **)item2;

	return strcmp(a, b);
}

static int
pr_environment(int argc, char **argv, ...)
{
	extern char **environ;
	char **ep;
	int fd, ret = -1;
	char path[PATH_MAX];

	if (strlcpy(path, "/tmp/nshrc.env.XXXXXXXX", sizeof(path)) >=
	    sizeof(path))
		return 0;

	fd = mkstemp(path);
	if (fd == -1) {
		printf("%% mkstemp %s: %s\n", path, strerror(errno));
		return -1;
	}

	if (argc >= 3) {
		char *name, *eq, *value;

		name = argv[2];
		for (ep = environ; *ep; ep++) {
			eq = strchr(*ep, '=');
			if (eq && strncmp(name, *ep, eq - *ep) == 0) {
				value = eq + 1;
				dprintf(fd, "%s\n", value);
				break;
			}
		}
	} else {
		char **sorted_environ;
		int nenv;

		for (nenv = 0, ep = environ; *ep; ep++) {
			if (strchr(*ep, '=') != NULL)
				nenv++;
		}	
			
		sorted_environ = calloc(nenv + 1, sizeof(*sorted_environ));
		if (sorted_environ == NULL) {
			printf("%% pr_environment: calloc: %s\n", strerror(errno));
			goto done;
		}

		for (nenv = 0, ep = environ; *ep; ep++) {
			if (strchr(*ep, '=') != NULL)
				sorted_environ[nenv++] = *ep;
		}

		qsort(sorted_environ, nenv, sizeof(*sorted_environ), envcmp);
		sorted_environ[nenv] = NULL;

		for (ep = sorted_environ; *ep; ep++)
			dprintf(fd, "%s\n", *ep);

		free(sorted_environ);
	}

	fsync(fd);

	ret = more(path) ? 0 : -1;
done:
	unlink(path);
	close(fd);
	return ret;
}

/* show interface [status|name]: asked of nshd, and rendered here */
int
show_int(int argc, char **argv, ...)
{
	FILE		*outfile;
	va_list		 ap;
	char		 ifname[IFNAMSIZ];

	memset(ifname, 0, sizeof(ifname));

	va_start(ap, argv);
	outfile = va_arg(ap, FILE *);
	va_end(ap);

	if (argc == 4) {
		/*
		 * Allow "interface-name interface-number" as some
		 * network switches do: interface em 0
		 */
		const char *errstr;
		size_t len2 = strlen(argv[2]);
		strlcpy(ifname, argv[2], sizeof(ifname));
		strtonum(argv[3], 0, INT_MAX, &errstr);
		if (errstr) {
			printf("%% interface unit %s is %s\n", argv[3], errstr);
			return -1;
		}
		if (len2 > 0 && isdigit((unsigned char)(argv[2][len2 - 1]))) {
			printf("%% interface unit %s is redundant\n", argv[3]);
			return -1;
		}
		strlcat(ifname, argv[3], sizeof(ifname));
		printf("%% Interface name is %s not \"%s %s\"\n",
		    ifname, argv[2], argv[3]);
	} if (argc == 3)
		strlcpy(ifname, argv[2], sizeof(ifname));

	if (ifname[0] == '\0')
		return (facts_show(outfile, "interface%s",
		    verbose ? " detail" : ""));
	if (isprefix(ifname, "status"))
		return (facts_show(outfile, "interface status"));
	if (!is_valid_ifname(ifname)) {
		printf("%% interface %s not found\n", ifname);
		return -1;
	}
	return (facts_show(outfile, "interface %s%s", ifname,
	    verbose ? " detail" : ""));
}

/* show autoconf: asked of nshd, and rendered here */
int
show_autoconf(int argc, char **argv, ...)
{
	char *ifname = NULL;

	if (argc == 3) {
		ifname = argv[2];
		if (!is_valid_ifname(ifname)) {
			printf("%% interface %s not found\n", ifname);
			return -1;
		}
	}
	return (facts_show(stdout, "autoconf%s%s", ifname ? " " : "",
	    ifname ? ifname : ""));
}

/* show ip, show inet and show inet6: asked of nshd, and rendered here */
int
show_ip(int argc, char **argv, ...)
{
	if (strcmp(argv[1], "inet") == 0)
		return facts_show(stdout, "ip inet");
	if (strcmp(argv[1], "inet6") == 0)
		return facts_show(stdout, "ip inet6");
	return facts_show(stdout, "ip");
}

int
show_vlans(int argc, char **argv, ...)
{
	long long start_vnetid = -1, end_vnetid = -1;
	const char *errstr;

	switch (argc) {
	case 2:
		return facts_show(stdout, "vlan");
	case 3:
		start_vnetid = strtonum(argv[2], EVL_VLID_NULL,
		    EVL_VLID_MAX, &errstr);
		if (errstr) {
			printf("%% VLAN tag %s is %s\n", argv[2], errstr);
			return -1;
		}
		return facts_show(stdout, "vlan %lld", start_vnetid);
	case 4:
		start_vnetid = strtonum(argv[2], EVL_VLID_NULL,
		    EVL_VLID_MAX, &errstr);
		if (errstr) {
			printf("%% VLAN tag %s is %s\n", argv[2], errstr);
			return -1;
		}
		end_vnetid = strtonum(argv[3], EVL_VLID_NULL,
		    EVL_VLID_MAX, &errstr);
		if (errstr) {
			printf("%% VLAN tag %s is %s\n", argv[3], errstr);
			return -1;
		}
		if (start_vnetid >= end_vnetid) {
			printf("%% VLAN Start Tag must be smaller "
			    "than VLAN End Tag\n");
			return -1;
		}
		return facts_show(stdout, "vlan %lld %lld", start_vnetid,
		    end_vnetid);
	}
	return 0;
}

int
show_bridges(int argc, char **argv, ...)
{
	switch (argc) {
	case 2:
		return facts_show(stdout, "bridge");
	case 3:
		return facts_show(stdout, "bridge %s", argv[2]);
	}
	return 0;
}

int
who(int argc, char **argv, ...)
{
	if (argc == 2 && !isprefix(argv[1], "users")) {
		printf("%% Too many arguments\n");
		return -1;
	}

	return facts_show(stdout, "users");
}

/*
 * show rollback [N [diff]]: when each configuration kept was saved, who
 * saved it and their comment, or configuration N, or what it changed
 */
int
pr_rollback(int argc, char **argv, ...)
{
	char words[sizeof("rollback 99 diff")];
	const char *errstr;
	int n;

	if (argc == 4 && !isprefix(argv[3], "diff")) {
		printf("%% show rollback N takes diff after N, not %s\n",
		    argv[3]);
		return -1;
	}
	if (argc >= 3) {
		n = strtonum(argv[2], 0, ROLLBACKS - 1, &errstr);
		if (errstr != NULL) {
			printf("%% rollback %s is %s\n", argv[2], errstr);
			return -1;
		}
	}
	/* nshd shows it */
	if (argc >= 3)
		snprintf(words, sizeof(words), "rollback %d%s", n,
		    argc == 4 ? " diff" : "");
	else
		strlcpy(words, "rollback", sizeof(words));
	return nshd_show(words) ? 0 : -1;
}

/* show candidate-config: nshd has the candidate */
int
pr_cand_conf(int argc, char **argv, ...)
{
	if (!nshd_config) {
		printf("%% Not in configure\n");
		return -1;
	}
	return nshd_cshow("candidate-config");
}

/*
 * configure [terminal | private | exclusive]: enter one of nshd's
 * configure modes, in nsh's session.  no configure leaves it
 */
int
doconfig(int argc, char **argv, ...)
{
	if (NO_ARG(argv[0])) {
		if (nshd_config)
			return nshd_exit();
		printf("%% Configuration mode is already disabled\n");
		return -1;
	}
	if (nshd_config) {
		printf("%% configure is not supported in %s yet\n",
		    nshd_cname());
		return -1;
	}
	if (argc > 1) {
		if (isprefix(argv[1], "terminal")) {
			/* each line committed by nshd, not saved */
			return nshd_configure(NSHD_CTERMINAL);
		} else if (isprefix(argv[1], "private")) {
			return nshd_configure(NSHD_CPRIVATE);
		} else if (isprefix(argv[1], "exclusive")) {
			return nshd_configure(NSHD_CEXCLUSIVE);
		} else {
			printf ("%% Invalid argument\n");
			return -1;
		}
	}
	/* the candidate nshd's sessions share */
	return nshd_configure(NSHD_CSHARED);
}

/*
 * commit [confirmed [minutes]] [comment text]: in configure, nshd makes
 * the candidate the running configuration, all of it or none, then
 * saves the running configuration; or with confirmed, does not save it,
 * and rolls it back unless a commit confirms it in time. Outside
 * configure, nshd saves the running configuration. The comment is kept
 * with what is saved.
 */
int
commit(int argc, char **argv, ...)
{
	char comment[COMMENTMAX] = "";
	const char *errstr;
	int minutes = 0, checking = 0, i, j, said = 1;

	/* comment, at least "com" of it, and the words after it */
	for (i = 1; i < argc && (strlen(argv[i]) < 3 ||
	    !isprefix(argv[i], "comment")); i++)
		;
	if (i < argc) {
		said = i + 1 < argc;
		for (j = i + 1; j < argc; j++)
			if ((j > i + 1 && strlcat(comment, " ",
			    sizeof(comment)) >= sizeof(comment)) ||
			    strlcat(comment, argv[j], sizeof(comment)) >=
			    sizeof(comment)) {
				printf("%% comment is longer than %d\n",
				    COMMENTMAX - 1);
				return -1;
			}
		argc = i;
	}
	if (argc > 1) {
		checking = isprefix(argv[1], "check") != 0;
		/* c alone could be either */
		if (checking == (isprefix(argv[1], "confirmed") != 0) ||
		    (checking && argc > 2))
			argc = 4;
	}
	if (argc > 3 || !said) {
		printf("%% commit [check | confirmed [minutes]] "
		    "[comment text]\n");
		return -1;
	}
	if (comment[0] != '\0' && argc > 1) {
		printf("%% commit %s saves nothing to comment\n",
		    checking ? "check" : "confirmed");
		return -1;
	}
	if (argc > 1 && !checking) {
		minutes = CONFIRMMIN;
		if (argc == 3 && (minutes = strtonum(argv[2], 1, CONFIRMMAX,
		    &errstr)) == 0) {
			printf("%% minutes %s is %s\n", argv[2], errstr);
			return -1;
		}
	}
	/* nshd commits its candidate, or saves the running configuration */
	return nshd_commit(checking, minutes, comment);
}

/*
 * rollback [N]: drop this session's changes to the candidate, which is
 * the running configuration again, or configuration N as it was saved
 */
int
cand_rollback(int argc, char **argv, ...)
{
	const char *errstr;
	int n = 0;

	if (!nshd_config) {
		printf("%% rollback requires configure\n");
		return -1;
	}
	if (argc > 2) {
		printf("%% rollback [0-%d]\n", ROLLBACKS - 1);
		return -1;
	}
	if (argc == 2) {
		n = strtonum(argv[1], 0, ROLLBACKS - 1, &errstr);
		if (errstr != NULL) {
			printf("%% rollback %s is %s\n", argv[1], errstr);
			return -1;
		}
	}
	/* nshd has the candidate */
	return nshd_rollback(n);
}

int 	sigflag = 0;

static void
_monitor_sig(int signo)
{
	sigflag = signo;
	return;
}

int
monitor(int argc, char **argv, ...)
{
	int s, m, n, saveverbose;
	fd_set fds; 
	struct timeval to;
	char msg[2048];

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		printf("%% Unable to open routing socket: %s\n",
		    strerror(errno));
		return -1;
	}
	saveverbose = verbose;
	verbose = 1;

	/* set up signal handler */
	if (signal (SIGINT, _monitor_sig) == SIG_ERR) {
		perror (strerror(errno));
		verbose = saveverbose;
		close (s);
		return (-1);
	}

	printf("%% Entering monitor mode ... press ENTER or ^C to leave ...\n");

	for(; sigflag != SIGINT ;) {
		time_t now;

		FD_ZERO (&fds);
		FD_SET (s, &fds);
		FD_SET (0, &fds);
		to.tv_sec = 1;
		to.tv_usec = 0;

		m = select (s + 1, &fds, NULL, NULL, &to);

		if (m < 0) {
			printf ("%% select: %s\n", strerror(errno));
			break;
		}

		if (m > 0) {
			if (FD_ISSET (s, &fds)) {
				ioctl (s, FIONBIO, 1); 	/* non-blocking io */
				n = read (s, msg, 2048);
				now = time(NULL);
				printf("%% Message of size %d on %s", n, ctime(&now));
				print_rtmsg((struct rt_msghdr *)msg);
			}
			if (FD_ISSET (0, &fds)) 
				break; 
		}
	}

	sigflag = -1;
	verbose = saveverbose;
	(void)signal(SIGINT, (sig_t)intr);
	close(s);
	return 0;
}

/* show route address: asked of nshd, and rendered here */
int
show_route(char *arg, int tableid)
{
	ip_t dest;

	memset(&dest, 0, sizeof(ip_t));
	parse_ip_pfx(arg, NO_NETMASK, &dest);
	if (dest.family == 0)
		return -1;
	return facts_show(stdout, "lookup %s %d", arg, tableid);
}
