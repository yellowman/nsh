/* $nsh: commands.c,v 1.14 2003/02/18 09:39:02 chris Exp $ */
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
#include <stdlib.h>
#include <ctype.h>
#include <kvm.h>
#include <nlist.h>
#include <unistd.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/reboot.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/wait.h>
#include <net/if.h>
#include <limits.h>
#include <histedit.h>
#include "externs.h"
#include "editing.h"

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
static int	enable(void);
static int	disable(void);
static int	doverbose(int, char**);
static int	doediting(int, char**);
static int	pr_routes(char *);
static int	pr_pf_stats(void);
static int	pr_ip_stats(void);
static int	pr_ah_stats(void);
static int	pr_esp_stats(void);
static int	pr_tcp_stats(void);
static int	pr_udp_stats(void);
static int	pr_icmp_stats(void);
static int	pr_igmp_stats(void);
static int	pr_ipcomp_stats(void);
static int	pr_mbuf_stats(void);
static int	pr_conf(void);
static int	wr_conf(void);
static int	show_help(void);
static void	flush_help(void);
static void	flush_ip_routes(void);
static void	flush_arp_cache(void);
static void	flush_history(void);
static void	flush_pfall(void);
static void	flush_pfnat(void);
static void	flush_pfqueue(void);
static void	flush_pfrules(void);
static void	flush_pfstates(void);
static void	flush_pfstats(void);
static void	flush_pftables(void);
static int	int_help(void);
static int	el_burrito(EditLine *, int, char **);
static void	makeargv(void);
static int	hostname(int, char **);
static int	help(int, char**);
static int	shell(int, char*[]);
static int	cmdarg(char *, char *);
static int	pr_rt_stats(void);
static void	p_argv(int, char **);
static int	config(void);
static int	priv = 0;
static int 	reload(void);
static int 	shut_down(void);
static int	pf(int, char **, char *);

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
	{ "route",	"IP route table or route lookup", 0, 1, pr_routes },
	{ "pfstats",	"PF statistics",	0, 0, pr_pf_stats },
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
	{ "monitor",	"Monitor routing/arp table changes", 0, 0, monitor },
	{ "version",	"Software information",	0, 0, version },
	{ "running-config",	"Operating configuration", 0, 0, pr_conf },
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
		printf("%% Invalid argument %s\n", argv[1]);
		return 0;
	} else if (Ambiguous(s)) {
		printf("%% Ambiguous argument %s\n", argv[1]);
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
	int z = 0;

	printf("%% Commands may be abbreviated.\n");
	printf("%% 'show' commands are:\n\n");

	for (s = Showlist; s->name; s++) {
		if (strlen(s->name) > z)
			z = strlen(s->name);
	}

	for (s = Showlist; s->name; s++) {
		if (s->help)
			printf("  %-*s  %s\n", z, s->name, s->help);
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
	int bridge;		/* 0 == Interface, 1 == Bridge, 2 == Both */
};

static struct intlist Intlist[] = {
/* Interface mode commands */
	{ "ip",		"IP address and other parameters",	intip,	0 },
	{ "alias",	"Additional IP addresses and other parameters",	intip, 0},
	{ "mtu",	"Set Maximum Transmission Unit",	intmtu, 0 },
	{ "metric",	"Set routing metric",			intmetric, 0 },
	{ "link",	"Set link level options",		intlink, 2 },
	{ "arp",	"Set Address Resolution Protocol",	intflags, 0 },
	{ "nwid",	"802.11 network ID",			intnwid, 0 },
	{ "nwkey",	"802.11 network key",			intnwkey, 0 },
	{ "powersave",	"802.11 powersaving mode",		intpowersave, 0 },
	{ "media",	"Media type",				intmedia, 0 },
	{ "mediaopt",	"Media options",			intmediaopt, 0 },
#ifdef INET6
	{ "vltime",	"IPv6 valid lifetime",			intvltime, 0 },
        { "pltime",	"IPv6 preferred lifetime",		intpltime, 0 },
	{ "anycast",	"IPv6 anycast address bit",		intanycast, 0 },
	{ "tentative",	"IPv6 tentative address bit",		inttentative, 0 },
#endif
	{ "tunnel",	"Source/destination for GIF tunnel",	inttunnel, 0 },
	{ "vlan",	"802.1Q vlan tag and parent",		intvlan, 0 },
	{ "debug",	"Driver dependent debugging",		intflags, 0 },
	{ "shutdown",	"Shutdown interface",			intflags, 2 },
	{ "rate",	"Rate limit (token bucket regulator)",	intrate, 0 },
/* Bridge mode commands */
	{ "member",	"Bridge member(s)",			brport, 1 },
	{ "span",	"Bridge spanning port(s)",		brport, 1 },
	{ "blocknonip",	"Block non-IP traffic forwarding on member(s)",	brport, 1 },
	{ "discover",	"Mark member(s) as discovery port(s)",	brport, 1 },
	{ "learning",	"Mark member(s) as learning port(s)",	brport, 1 },
	{ "stp",	"Enable 802.1D spanning tree protocol on member(s)", brport, 1 },
	{ "maxaddr",	"Maximum address cache size",		brval, 1 },
	{ "timeout",	"Address cache timeout",		brval, 1 },
	{ "maxage",	"Time for 802.1D configuration to remain valid", brval, 1 },
	{ "fwddelay",	"Time before bridge begins forwarding packets", brval, 1 },
	{ "hellotime",	"Time between broadcasting 802.1D configuration packets", brval, 1 },
	{ "priority",	"Spanning priority for all members on an 802.1D bridge", brval, 1 },
	{ "rule",	"Bridge layer 2 filtering rules",	brrule, 1 },
	{ "static",	"Static bridge address entry",		brstatic, 1 },
	{ "ifpriority",	"Spanning priority of a member on an 802.1D bridge", brpri, 1 },
/* Help commands */
	{ "?",		"Options",				int_help, 2 },
	{ "help",	0,					int_help, 2 },
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
	void (*handler)();	/* Routine to perform (for special ops) */
};

static struct flushlist Flushlist[] = {
	{ "routes",	"IP routes",		0, 0, flush_ip_routes },
	{ "arp",	"ARP cache",		0, 0, flush_arp_cache },
	{ "bridge-dyn",	"Dynamically learned bridge addresses", 1, 1, flush_bridgedyn },
	{ "bridge-all",	"Dynamic and static bridge addresses", 1, 1, flush_bridgeall },
	{ "bridge-rule", "Layer 2 filter rules for a bridge member port", 2, 2, flush_bridgerule },
	{ "pf",		"pf NAT/filter/queue rules, states, tables", 1, 1, flush_pfall },
	{ "pf-nat",	"pf NAT rules only", 	0, 0, flush_pfnat },
	{ "pf-queue",	"pf queue rules only",	0, 0, flush_pfqueue },
	{ "pf-rules",	"pf filter rules only",	0, 0, flush_pfrules },
	{ "pf-states",	"pf NAT/filter states",	0, 0, flush_pfstates },
	{ "pf-stats",	"pf statistics",	0, 0, flush_pfstats },
	{ "pf-tables",	"pf tables",		0, 0, flush_pftables },
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

	if (argc < 2) {
		printf("%% Use 'flush ?' for help\n");
		return 0;
	}

	/*
	 * Validate flush argument
	 */
	f = GETFLUSH(argv[1]);
	if (f == 0) {
		printf("%% Invalid argument %s\n", argv[1]);
		return 0;
	} else if (Ambiguous(f)) {
		printf("%% Ambiguous argument %s\n", argv[1]);
		return 0;
	}
	if (((f->minarg + 2) > argc) || ((f->maxarg + 2) < argc)) {
		printf("%% Wrong argument%s to 'flush %s' command.\n",
		    argc <= 2 ? "" : "s", f->name);
		return 0;
	}
	if (f->handler)
		(*f->handler)((f->maxarg > 0) ? argv[2] : 0,
		    (f->maxarg > 1) ? argv[3] : 0);

	return(1);
}

static void
flush_help()
{
	struct flushlist *f;
	int z = 0;

	printf("%% Commands may be abbreviated.\n");
	printf("%% 'flush' commands are:\n\n");

	for (f = Flushlist; f->name; f++) {
		if (strlen(f->name) > z)
			z = strlen(f->name);
	}

	for (f = Flushlist; f->name; f++) {
		if (f->help)
			printf("  %-*s  %s\n", z, f->name, f->help);
	}
	return;
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
	int z = 0;
	int num, ifs;
	char *tmp;
	struct intlist *i;	/* pointer to current command */

	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);

	if (argc != 2 && !modhvar) {
		printf("%% interface <interface name>\n");
		return(0);
	}

	ifname[IFNAMSIZ-1] = '\0';

	if (modhvar)
		tmp = modhvar;
	else
		tmp = argv[1];
	if (strlen(tmp) > IFNAMSIZ-1) {
		printf("%% interface name too long\n");
		return(0);
	}
	strlcpy(ifname, tmp, IFNAMSIZ);

        if (!is_valid_ifname(ifname)) {
                printf("%% interface %s not found\n", ifname);
                return(0);
        }

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% socket failed: %s\n", strerror(errno));
		return(1);
	}

	if (!modhvar) {
		if (CMP_ARG(argv[0], "br")) {
			if (!is_bridge(ifs, ifname)) {
				printf("%% Using interface configuration mode for %s\n",
				    ifname);
				bridge = 0;
			} else {
				bridge = 1;
			}
		} else if (is_bridge(ifs, ifname)) {
			printf("%% Using bridge configuration mode for %s\n",
			    ifname);
			bridge = 1;
		} else {
			bridge = 0;
		}
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
						close(ifs);
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
				margv[z] = argv[z];
			margc = argc;
		}
		if (NO_ARG(margv[0]))
			i = GETINT(margv[1]);
		else
			i = GETINT(margv[0]);
		if (Ambiguous(i)) {
			printf("%% Ambiguous command\n");
			continue;
		}
		if (i == 0) {
			int val = 1;

			if (editing)
				val = el_burrito(eli, margc, margv);
			if (val)
				printf("%% Invalid command\n");
			continue;
		} else {
			if ((bridge && !i->bridge) ||
			    (!bridge && (i->bridge == 1))) {
				printf("%% Invalid command\n");
			} else if ((*i->handler) (ifname, ifs, margc, margv)) {
				break;
			}
		}
		if (modhvar) {
			break;
		}
	}
	close(ifs);
	return(0);
}

static int
pf(int argc, char **argv, char *modhvar)
{
	int z = 0, action = 0;
	char arg[256];
	char *editor, *aarg;
	FILE *rulefile;

	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);

	if ((argc != 2 && !modhvar) || (argc == 2 && CMP_ARG(argv[1],"?"))) {
		printf("%% pf edit\n");
		printf("%% pf reload\n");
		printf("%% pf enable\n");
		printf("%% pf disable\n");
		return(0);
	}

	aarg = argv[0];

	if (modhvar && CMP_ARG(modhvar, "action"))
		action = 1;

	if (!modhvar) {
		action = 1;
		aarg = argv[1];
	}

	if (action) {
		if(CMP_ARG(aarg, "ed")) {	/* edit */
			if ((editor = getenv("EDITOR")) == NULL)
				editor = DEFAULT_EDITOR;
			/* check for valid path from user supplied env var */
			/* check for locking and return if already locked */
			cmdarg(editor, PFCONF_TEMP);
			/* undo locking when we are done editing */
			snprintf(arg, sizeof(arg), "-nf%s", PFCONF_TEMP);
			cmdarg(PFCTL, arg);
			return(0);
		}
		if(CMP_ARG(aarg, "r")) {	/* reload */
			snprintf(arg, sizeof(arg), "-f%s", PFCONF_TEMP);
			cmdarg(PFCTL, arg);
			return(0);
		}
		if(CMP_ARG(aarg, "en")) {	/* enable */
			cmdarg(PFCTL, "-e");
			return(0);
		}
		if(CMP_ARG(aarg, "d")) {	/* disable */
			cmdarg(PFCTL, "-d");
			return(0);
		}
		printf("%% invalid or ambiguous argument: %s\n", argv[1]);
		return(0);
	}

	/* nshrc routines */
	if (CMP_ARG(modhvar, "rules")) {
		rulefile = fopen(PFCONF_TEMP, "a");
		if (rulefile == NULL) {
			printf("%% Rule write failed: %s\n", strerror(errno));
			return(1);
		}
		for (z = 0; z < argc; z++)
			fprintf(rulefile, "%s%s", z ? " " : "", argv[z]);
		fprintf(rulefile, "\n");
		fclose(rulefile);
		return(0);
	}

	if (modhvar)
		printf ("%% Unknown rulefile modifier %s\n", modhvar);

	return(0);
}

static int
int_help()
{
	struct intlist *i; /* pointer to current command */
	int z = 0;

	printf("%% Commands may be abbreviated.\n");
	printf("%% Press enter at a prompt to leave %s configuration mode.\n",
	    bridge ? "bridge" : "interface");
	printf("%% %s configuration commands are:\n\n",
	    bridge ? "Bridge" : "Interface");

	for (i = Intlist; i->name; i++) {
		if ((bridge && !i->bridge) || (!bridge && (i->bridge == 1)))
			continue;
		if (strlen(i->name) > z)
			z = strlen(i->name);
	}

	for (i = Intlist; i->name; i++) {
		if ((bridge && !i->bridge) || (!bridge && (i->bridge == 1)))
			continue;
		if (i->help)
			printf("  %-*s  %s\n", z, i->name, i->help);
	}
	return 0;
}

/*
 * Data structures and routines for the main CLI
 */

static char
	hostnamehelp[] = "Set system hostname",
	interfacehelp[] = "Modify interface parameters",
	pfhelp[] =	"Packet filter rule handler",
	bridgehelp[] =	"Modify bridge parameters",
	showhelp[] =	"Show system information",
	flushhelp[] =	"Flush system tables",
	enablehelp[] =	"Enable privileged mode",
	disablehelp[] =	"Disable privileged mode",
	routehelp[] =	"Add a host or network route",
	quithelp[] =	"Close current connection",
	verbosehelp[] =	"Set verbose diagnostics",
	editinghelp[] = "Set command line editing",
	shellhelp[] =	"Invoke a subshell",
	savehelp[] =	"Save the current configuration",
	reloadhelp[] =	"Reboot the system",
	shutdownhelp[] = "Shut the system down",
	helphelp[] =	"Print help information";

/*
 * Primary commands, will be included in help output
 */

static Command cmdtab[] = {
	{ "hostname",	hostnamehelp,	hostname,	1, 0, 0, 0 },
	{ "interface",	interfacehelp,	interface,	1, 0, 0, 1 },
	{ "bridge",	bridgehelp,	interface,	1, 0, 0, 1 },
	{ "show",	showhelp,	showcmd,	0, 0, 0, 0 },
	{ "flush",	flushhelp,	flushcmd,	1, 0, 0, 0 },
	{ "enable",	enablehelp,	enable,		0, 1, 0, 0 },
	{ "disable",	disablehelp,	disable,	1, 0, 0, 0 },
	{ "route",	routehelp,	route,		1, 0, 1, 0 },
	{ "pf",		pfhelp,		pf,		1, 0, 1, 0 },
	{ "quit",	quithelp,	quit,		0, 0, 0, 0 },
	{ "reload",	reloadhelp,	reload,		1, 0, 0, 0 },
	{ "shutdown",	shutdownhelp,	shut_down,	1, 0, 0, 0 },
	{ "write-config", savehelp,	wr_conf,	1, 0, 0, 0 },
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
	{ "config",	0,		config,		0, 0, 0, 0 },
	{ 0,		0,		0,		0, 0, 0, 0 }
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
help(int argc, char **argv)
{
	Command *c;

	if (argc == 1) { 
		int z = 0;

		printf("%% Commands may be abbreviated.\n");
		printf("%% Commands are:\n\n");

		for (c = cmdtab; c->name; c++) {
			if ((c->needpriv == priv) || (c->ignoreifpriv != priv))
				if (strlen(c->name) > z)
					z = strlen(c->name);
		}
		for (c = cmdtab; c->name; c++) {
			if (c->help && ((c->needpriv == priv) ||
			    (c->ignoreifpriv != priv)))
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
			printf("%% sethostname: %s\n", strerror(errno));
	} else {
		if (gethostname(hbuf, sizeof(hbuf)))
			printf("%% gethostname: %s\n", strerror(errno));
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
			printf("%% fork failed: %s\n", strerror(errno));
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
			printf("%% execl failed: %s\n", strerror(errno));
			exit(0);
		}
		default:
			(void)wait((int *)0);  /* Wait for shell to complete */
			break;
	}
	return 1;
}

/*
 * cmd, arg!@
 */
int
cmdarg(cmd, arg)
	char *cmd;
	char *arg;
{
	switch(vfork()) {
		case -1:
			printf("%% fork failed: %s\n", strerror(errno));
			break;

		case 0:
		{
			char *shellp;
			char *shellname = shellp = cmd;

			execl(shellp, shellname, arg, (char *)NULL);
			printf("%% execl failed: %s\n", strerror(errno));
			exit(0);
		}
		default:
			(void)wait((int *)0);  /* Wait for cmd to complete */
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

int
config(void)
{
	printf("%% Configuration mode is unnecessary with this software.\n");

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

void
flush_history(void)
{
	if (!editing) {
		printf("%% Command line editing not enabled\n");
		return;
	}

	/*
	 * Editing mode needs to be reinitialized if the histi/histc
	 * pointers are going to change.....
	 */
	endedit();
	endhist();
	inithist();
	initedit();

	return;
}

/*
 * pf toilet flusher
 */

void
flush_pfall(void)
{
	printf("%% Flushing all pf filter rules, NAT rules, queue rules,"
	    "   address tables, states, and statistics\n");
	cmdarg(PFCTL, "-Fall");

	return;
}

void
flush_pfnat(void)
{
	printf("%% Flushing pf NAT rules\n");
	cmdarg(PFCTL, "-Fnat");

	return;
}

void 
flush_pfqueue(void)
{
	printf("%% Flushing pf queue rules\n");
	cmdarg(PFCTL, "-Fqueue");

	return;
}

void
flush_pfrules(void)
{
	printf("%% Flushing pf filter rules\n");
	cmdarg(PFCTL, "-Frules");

	return;
}

void
flush_pfstates(void)
{
	printf("%% Flushing pf NAT/filter states\n");
	cmdarg(PFCTL, "-Fstate");

	return;
}

void
flush_pfstats(void)
{
	printf("%% Flushing pf statistics\n");
	cmdarg(PFCTL, "-Finfo");

	return;
}

void
flush_pftables(void)
{
	printf("%% Flushing pf address tables\n");
	cmdarg(PFCTL, "-FTables");

	return;
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
	char	modhvar[128];	/* required variable in mode handler cmd */
	int	modhcmd; 	/* do we execute under another mode? */
	int	lnum;		/* line number */
	int	z = 0;		/* max length of cmdtab argument */

	if ((rcfile = fopen(rcname, "r")) == 0) {
		printf("%% %s not found\n",rcname);
		return 1;
	}

	for (c = cmdtab; c->name; c++)
		if (strlen(c->name) > z)
			z = strlen(c->name);
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
			if (c && c->modh)
				modhcmd = 1;
			else
				modhcmd = 0;

			if (!modhcmd) {
				printf("%% No mode handler specified before"
				    " indented command? (line %i) ", lnum);
				p_argv(margc, margv);
				printf("\n");
				continue;
			}
		} else {
			/*
			 * command was not indented.  process normally.
			 */
			modhcmd = 0;
			if (NO_ARG(margv[0])) {
				c = getcmd(margv[1]);
				if (c && c->modh) {
					/*
					 * ..command is a mode handler
					 * then it cannot be 'no cmd'
					 */
					printf("%% Argument 'no' is invalid"
					    " for a mode handler (line %i) ",
					    lnum);
					p_argv(margc, margv);
					printf("\n");
					continue;
				}
			} else {
				c = getcmd(margv[0]);
				if(c && c->modh) {
					/*
					 * any mode handler should have
					 * one value stored, passed on
					 */
					if (margv[1]) {
						strncpy(modhvar, margv[1],
						    sizeof(modhvar));
					} else {
						printf("%% No argument after"
						    " mode handler (line %i) ",
						    lnum);
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
			    c->modh ? "mode" : "cmd", z, c->name,
			    modhcmd ? "(sub-cmd)" : "", lnum);
			p_argv(margc, margv);
			printf("\n");
		}
		if (!modhcmd) {
			/*
			 * normal processing, there is no sub-mode cmd to be
			 * dealt with
			 */
			if (!c->nocmd && NO_ARG(margv[0])) {
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
	snprintf(prompt, sizeof(prompt), "%s(%s-%s)/", hbuf,
	    bridge ? "bridge" : "interface", ifname);

	return(prompt);
}

/*
 * Save configuration
 */
int
wr_conf(void)
{
	FILE *rchandle;
	rchandle = fopen(NSHRC_TEMP, "w");
	if (rchandle != NULL) {
		printf("%% Saving configuration\n");
		conf(rchandle);
	} else {
		printf("%% Unable to save configuration: %s\n",
		    strerror(errno));
	}
	fclose(rchandle);

	cmdarg(SAVESCRIPT, NSHRC_TEMP);

	return (1);
}

/*
 * Reboot
 */
int
reload(void)
{
	printf ("%% Reload initiated\n");
	if (reboot (RB_AUTOBOOT) == -1)
		printf("%% reboot: RB_AUTOBOOT: %s\n", strerror(errno));
	return(1);
}
               
int
shut_down(void)
{
	printf ("%% Shutdown initiated\n");
	if (reboot (RB_HALT) == -1)
		printf("%% reboot: RB_HALT: %s\n", strerror(errno));
	return(1);
}

/*
 * Flush wrappers
 */
void
flush_ip_routes(void)
{
	flushroutes(AF_INET, AF_INET);
}

void
flush_arp_cache(void)
{
	flushroutes(AF_INET, AF_LINK);
}

/*
 * Show wrappers
 */
int
pr_conf(void)
{
	conf(stdout);

	return(1);
}

int
pr_routes(char *route)
{
	if (route == 0)
		/* show entire routing table */
		routepr(nl[N_RTREE].n_value, AF_INET);
	else
		/* show a specific route */
		show_route(route);
		
	return 0;
}


int
pr_rt_stats(void)
{
	rt_stats(nl[N_RTSTAT].n_value);
	return 0;
}

int 
pr_pf_stats(void)
{
	printf("%% pf statistics:\n");
	cmdarg(PFCTL, "-sinfo");
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

