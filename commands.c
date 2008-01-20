/* $nsh: commands.c,v 1.69 2008/01/20 06:08:49 chris Exp $ */
/*
 * Copyright (c) 2002-2007
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
#include <histedit.h>
#include <util.h>
#include <pwd.h>
#include "externs.h"
#include "editing.h"

char prompt[128];

static char line[256];
static char saveline[256];
static int  margc;
static char *margv[20];
static char hbuf[MAXHOSTNAMELEN];	/* host name */
static char ifname[IFNAMSIZ];		/* interface name */

typedef struct {
	char *name;		/* command name */
	char *help;		/* help string (NULL for no help) */
	int (*handler) ();	/* routine which executes command */
	int needpriv;		/* Do we need privilege to execute? */
	int ignoreifpriv;	/* Ignore while privileged? */
	int nocmd;		/* Can we specify 'no ...command...'? */
	int modh;		/* Is it a mode handler for cmdrc()? */
	int noesc;		/* Does the shell interpret escape sequences
				 * or pass them as arguments ? */
} Command;

typedef struct {
	char *name;		/* How user refers to it (case independent) */
	char *help;		/* Help information (0 ==> no help) */
	int minarg;		/* Minimum number of arguments */
	int maxarg;		/* Maximum number of arguments */
	int (*handler)();	/* Routine to perform (for special ops) */
} Menu;

static Command	*getcmd(char *);
static Menu	*getip(char *);
static int	quit(void);
static int	disable(void);
static int	doverbose(int, char**);
static int	doediting(int, char**);
static int	group(int, char**);
static int	pr_routes(char *);
static int	pr_arp(char *);
static int	pr_sadb(void);
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
static int	pr_carp_stats(void);
static int	pr_pfsync_stats(void);
static int	pr_conf(void);
static int	pr_s_conf(void);
static int	wr_startup(void);
static int	wr_conf(char *);
static int	show_help(void);
static int	ip_help(void);
static int	flush_help(void);
static int	flush_line(char *);
static int	flush_ip_routes(void);
static int	flush_arp_cache(void);
static int	flush_history(void);
static int	flush_pfall(void);
static int	flush_pfnat(void);
static int	flush_pfqueue(void);
static int	flush_pfrules(void);
static int	flush_pfstates(void);
static int	flush_pfstats(void);
static int	flush_pftables(void);
static int	int_help(void);
static int	el_burrito(EditLine *, int, char **);
static void	makeargv(int);
static int	hostname(int, char **);
static int	help(int, char**);
static int	shell(int, char*[]);
static int	ping(int, char*[]);
static int	traceroute(int, char*[]);
static int	ssh(int, char*[]);
static int	telnet(int, char*[]);
static int	pr_rt_stats(void);
static void	p_argv(int, char **);
static int	notvalid(void);
static int 	reload(void);
static int 	halt(void);

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

static Menu showlist[] = {
	{ "hostname",	"Router hostname",	0, 0, hostname },
	{ "interface",	"Interface config",	0, 1, show_int },
	{ "route",	"IP route table or route lookup", 0, 1, pr_routes },
	{ "sadb",	"Security Association Database", 0, 0, pr_sadb },
	{ "arp",	"ARP table",		0, 1, pr_arp },
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
	{ "carpstats",	"CARP statistics",	0, 0, pr_carp_stats },
	{ "pfsyncstats", "pfsync statistics",	0, 0, pr_pfsync_stats },
	{ "mbufstats",	"Memory management statistics",	0, 0, pr_mbuf_stats },
	{ "monitor",	"Monitor routing/arp table changes", 0, 0, monitor },
	{ "ap",		"Wireless access points", 1, 1, wi_printaplist },
	{ "version",	"Software information",	0, 0, version },
	{ "users",	"System users",		0, 0, who },
	{ "running-config",	"Operating configuration", 0, 0, pr_conf },
	{ "startup-config", "Startup configuration", 0, 0, pr_s_conf },
	{ "?",		"Options",		0, 0, show_help },
	{ "help",	0,			0, 0, show_help },
	{ 0, 0, 0, 0, 0 }
};

#define GETSHOW(name)	((Menu *) genget(name, (char **) showlist, \
			    sizeof(Menu)))

static int
showcmd(int argc, char **argv)
{
	Menu *s;	/* pointer to current command */
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
		printf("%% Wrong number of argument%s to 'show %s' command"
		    " (min %i, max %i)\n", argc <= 2 ? "" : "s", s->name,
		    s->minarg, s->maxarg);
		return 0;
	}
	if (s->handler)	/* As if there was something else we do ? */
		success = (*s->handler)((s->maxarg > 0) ? argv[2] : 0,
		    (s->maxarg > 1) ? argv[3] : 0);

	return(success);
}

static int
show_help(void)
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
 * Data structures and routines for the "ip" command.
 */

static Menu iptab[] = {
	{ "forwarding",	"Enable IPv4 Forwarding",	0, 0,	ipsysctl },
	{ "ipip",	"Allow IP-in-IP Encapsulation", 0, 0,	ipsysctl },
	{ "gre",	"Allow Generic Route Encapsulation",	0, 0,	ipsysctl },
	{ "wccp",	"Allow Web Cache Control Protocol",	0, 0,	ipsysctl },
	{ "mobileip",	"Allow Mobile IP Encapsulation",	0, 0,	ipsysctl },
	{ "etherip",	"Allow Ether-IP Encapsulation",	0, 0,	ipsysctl },
	{ "ipcomp",	"Allow IP Compression",		0, 0,	ipsysctl },	
	{ "esp",	"Allow Encapsulated Security Payload", 0, 0,	ipsysctl },
	{ "ah",		"Allow Authentication Header",	0, 0,	ipsysctl },
	{ "sourceroute", "Process Loose/Strict Source Route Options", 0, 0, ipsysctl },
	{ "encdebug",	"Enable if_enc debugging",		0, 0,	ipsysctl },
	{ "maxqueue",	"Set Max queued packets",		1, 1,	ipsysctl },
	{ "send-redirects", "Send ICMP redirects",	0, 0,	ipsysctl },
	{ "directed-broadcast", "Allow directed broadcasts", 0, 0, ipsysctl },
#ifdef notyet
	{ "default-mtu", "Default interface MTU",	1, 1,	ipsysctl },
#endif
	{ "default-ttl", "Set Default IP packet TTL",	1, 1,	ipsysctl },
	{ "classless",	0,			0, 0,	notvalid },
	{ "?",		"Options",		0, 0,	ip_help },
	{ "help",	0,			0, 0,	ip_help },
	{ 0, 0, 0, 0, 0 }
};

static Menu iptab2[] = {
	{ "classless",	0,			0, 0,	notvalid },
	{ "subnet-zero", 0,			0, 0,	notvalid },
	{ 0, 0, 0, 0, 0 }
};

Menu *
getip(char *name)
{
	Menu *i;

        if ((i = (Menu *) genget(name, (char **) iptab, sizeof(Menu))))
                return i;
        return (Menu *) genget(name, (char **) iptab2, sizeof(Menu));
}

static int
ipcmd(int argc, char **argv)
{
	Menu *i;     /* pointer to current command */
	int set, success = 0;

	if (NO_ARG(argv[0])) {
		argv++;
		argc--;
		set = 0;
	} else
		set = 1;

	if (argc < 2) {
		printf("%% Use 'ip ?' for help\n");
		return 0;
	}

	/*
	 * Validate ip argument
	 */
        i = getip(argv[1]);
	if (i == 0) {
		printf("%% Invalid argument %s\n", argv[1]);
		return 0;
	} else if (Ambiguous(i)) {
		printf("%% Ambiguous argument %s\n", argv[1]);
		return 0;
	}
	if (((i->minarg + 2) > argc) || ((i->maxarg + 2) < argc)) {
		printf("%% Wrong argument%s to 'ip %s' command.\n",
		    argc <= 2 ? "" : "s", i->name);
		return 0;
	}

	if (i->handler)
		success = (*i->handler)(set, argv[1],
		    (i->maxarg > 0) ? argv[2] : 0);
	return(success);
}

static int
ip_help(void)
{
	Menu *i; /* pointer to current command */
	u_int z = 0;

	printf("%% Commands may be abbreviated.\n");
	printf("%% 'ip' commands are:\n\n");

	for (i = iptab; i->name; i++) {
		if (strlen(i->name) > z)
			z = strlen(i->name);
	}

	for (i = iptab; i->name; i++) {
		if (i->help)
			printf("  %-*s  %s\n", z, i->name, i->help);
	}
	return 0;
}

/*
 * Data structures and routines for the "flush" command.
 */

static Menu flushlist[] = {
	{ "routes",	"IP routes",		0, 0, flush_ip_routes },
	{ "arp",	"ARP cache",		0, 0, flush_arp_cache },
	{ "line",	"Active user",		1, 1, flush_line },
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

#define GETFLUSH(name) ((Menu *) genget(name, (char **) flushlist, \
			   sizeof(Menu)))

static int
flushcmd(int argc, char **argv)
{
	Menu *f;

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

static int
flush_line(char *line)
{
	char *argv[] = { PKILL, "-9", "-t", line, '\0' };
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
	{ "ip",		"IP address and other parameters",	intip,  0 },
	{ "alias",	"Additional IP addresses and other parameters", intip, 0 },
	{ "description", "Interface description",		intdesc, 0 },
	{ "group",	"Interface group",			intgroup, 0 },
	{ "rtlabel",	"Interface route labels",		intrtlabel, 0 },
	{ "mtu",	"Set Maximum Transmission Unit",	intmtu, 0 },
	{ "metric",	"Set routing metric",			intmetric, 0 },
	{ "link",	"Set link level options",		intlink, 2 },
	{ "arp",	"Set Address Resolution Protocol",	intflags, 0 },
	{ "lladdr",	"Set Link Level (MAC) Address",		intlladdr, 0 },
	{ "nwid",	"802.11 network ID",			intnwid, 0 },
	{ "nwkey",	"802.11 network key",			intnwkey, 0 },
	{ "powersave",	"802.11 powersaving mode",		intpowersave, 0 },
	{ "txpower",	"802.11 transmit power",		inttxpower, 0 },
	{ "bssid",	"802.11 bss id",			intbssid, 0 },
	{ "media",	"Media type",				intmedia, 0 },
	{ "mediaopt",	"Media options",			intmediaopt, 0 },
#ifdef INET6
	{ "vltime",	"IPv6 valid lifetime",			intvltime, 0 },
	{ "pltime",	"IPv6 preferred lifetime",		intpltime, 0 },
	{ "anycast",	"IPv6 anycast address bit",		intanycast, 0 },
	{ "tentative",	"IPv6 tentative address bit",		inttentative, 0 },
#endif
	{ "tunnel",	"Source/destination for GIF tunnel",	inttunnel, 0 },
	{ "syncdev",	"PFsync control message interface",	intsyncdev, 0 },
	{ "syncpeer",	"PFsync peer address",			intsyncpeer, 0},
	{ "maxupd", 	"Collapsable max updates for a single state", intmaxupd, 0 },
	{ "vhid",	"CARP virtual host ID",			intcarp, 0 },
	{ "advbase",	"CARP advertisement interval",		intcarp, 0 },
	{ "advskew",	"CARP advertisement skew",		intcarp, 0 },
	{ "cpass",	"CARP passphrase",			intcpass, 0 },
	{ "carpdev",	"CARP device",				intcdev, 0 },
	{ "carpnode",	"CARP additional vhid/advskew",		intcnode, 0 },
	{ "vlan",	"802.1Q vlan tag and parent",		intvlan, 0 },
	{ "timeslots",	"TDM timeslots",			inttimeslot, 0},
	{ "debug",	"Driver dependent debugging",		intflags, 0 },
	{ "shutdown",	"Shutdown interface",			intflags, 2 },
/* Bridge mode commands */
	{ "member",	"Bridge member(s)",			brport, 1 },
	{ "span",	"Bridge spanning port(s)",		brport, 1 },
	{ "blocknonip",	"Block non-IP traffic forwarding on member(s)", brport, 1 },
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
	{ "ifcost",	"Spanning tree path cost of a member on 802.1D bridge", brpri, 1},
	{ "trunkport",  "Add child interface(s) to trunk",	inttrunkport, 0 },
	{ "trunkproto",	"Define trunkproto",		 	inttrunkproto, 0 },

/* Help commands */
	{ "?",		"Options",				int_help, 2 },
	{ "help",	0,					int_help, 2 },
	{ 0, 0, 0, 0 }
};

#define GETINT(name)	((struct intlist *) genget(name, (char **) Intlist, \
			    sizeof(struct intlist)))

/*
 * a big command input loop for interface mode
 * XXX yes, i will totally rewrite this crap, yes, it's horrible
 * if a function returns to interface() with a 1, interface() will break
 * the user back to command() mode.  interface() will always break from
 * mode handler calls.
 */
static int
interface(int argc, char **argv, char *modhvar)
{
	int z = 0;
	u_int num;
	int ifs, set = 1;
	char *tmp;
	struct intlist *i;	/* pointer to current command */
	struct ifreq ifr;

	if (!modhvar) {
		/*
		 * setup pieces which are valid ONLY for interactive routine
		 */
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGQUIT, SIG_IGN);

		if (NO_ARG(argv[0])) {
			argv++;
			argc--;
			set = 0;
		}
	
		if (argc != 2) {
			printf("%% [no] interface <interface name>\n");
			return(0);
		}
		tmp = argv[1];
	} else {
		tmp = modhvar;
	}

	if (strlen(tmp) > IFNAMSIZ-1) {
		printf("%% interface name too long\n");
		return(0);
	}

	ifname[IFNAMSIZ-1] = '\0';
	strlcpy(ifname, tmp, IFNAMSIZ);
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% socket failed: %s\n", strerror(errno));
		return(1);
	}

	if (!is_valid_ifname(ifname)) {
		if (set == 0 && !modhvar) {
			printf("%% interface %s not found\n", ifname);
			close(ifs);
			return(0);
		}
		if (ioctl(ifs, SIOCIFCREATE, &ifr) == -1) {
			if (errno == EINVAL)
				printf("%% interface %s not found\n", ifname);
			else
				printf("%% unable to create interface %s: %s\n",
				    ifname, strerror(errno));
			close(ifs);
			return(0);
		}
	}

	if (set == 0 && !modhvar) {
		if (ioctl(ifs, SIOCIFDESTROY, &ifr) == -1) {
			printf("%% unable to remove interface %s: %s\n",
			    ifname, strerror(errno));
		} else {
			/* remove interface routes? */
		}
		close(ifs);
		return(0);
	}

	if (is_bridge(ifs, ifname)) {
		bridge = 1;
		if (CMP_ARG(modhvar ? modhvar : argv[0], "i"))
			printf("%% Using bridge configuration mode"
			    " for %s\n", ifname);
	} else {
		bridge = 0; 
		if (CMP_ARG(modhvar ? modhvar : argv[0], "b"))
			printf("%% Using interface configuration mode"
			    " for %s\n", ifname);
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
				history(histi, &ev, H_ENTER, buf);
			}
			if (line[0] == 0)
				break;
			makeargv(0);
			if (margv[0] == 0)
				break;
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
		} else if (i == 0) {
			int val = 1;

			if (editing)
				val = el_burrito(eli, margc, margv);
			if (val)
				printf("%% Invalid command\n");
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
int_help(void)
{
	struct intlist *i; /* pointer to current command */
	u_int z = 0;

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
	grouphelp[] =	"Modify group attributes",
	arphelp[] = 	"Static ARP set",
#ifdef notyet
	parphelp[] =	"Proxy ARP set",
#endif
	pfhelp[] =	"Packet filter control",
	ospfhelp[] =	"OSPF control",
	bgphelp[] =	"BGP control",
	riphelp[] =	"RIP control",
	relayhelp[] =	"Relay control",
	ipsechelp[] =	"IPsec control",
	dvmrphelp[] = 	"DVMRP control",
	sasynchelp[] =	"SA synchronization control",
	dhcphelp[] =	"DHCP server control",
	snmphelp[] =	"SNMP server control",
	bridgehelp[] =	"Modify bridge parameters",
	showhelp[] =	"Show system information",
	iphelp[] =	"Set IP networking parameters",
	flushhelp[] =	"Flush system tables",
	enablehelp[] =	"Enable privileged mode",
	disablehelp[] =	"Disable privileged mode",
	routehelp[] =	"Add a host or network route",
	pinghelp[] = 	"Send ICMP echo request",
	tracerthelp[] =	"Print the route to host",
	sshhelp[] =	"SSH connection to remote host",
	telnethelp[] =	"Telnet connection to remote host",
	quithelp[] =	"Close current connection",
	verbosehelp[] =	"Set verbose diagnostics",
	editinghelp[] = "Set command line editing",
	whohelp[] =	"Display system users",
	shellhelp[] =	"Invoke a subshell",
	savehelp[] =	"Save the current configuration",
	reloadhelp[] =	"Reboot the system",
	halthelp[] =	"Halt the system",
	helphelp[] =	"Print help information";

/*
 * Primary commands, will be included in help output
 */

static Command cmdtab[] = {
	{ "hostname",	hostnamehelp,	hostname,	1, 0, 0, 0, 0 },
	{ "interface",	interfacehelp,	interface,	1, 0, 1, 1, 0 },
	{ "group",	grouphelp,	group,		1, 0, 1, 0, 0 },
	{ "arp",	arphelp,	arpset,		1, 0, 1, 0, 0 },
#ifdef notyet
	{ "proxy-arp",	parphelp,	arpset,		1, 0, 1, 0, 0 },
#endif
	{ "bridge",	bridgehelp,	interface,	1, 0, 0, 1, 0 },
	{ "show",	showhelp,	showcmd,	0, 0, 0, 0, 0 },
	{ "ip",		iphelp,		ipcmd,		1, 0, 1, 0, 0 },
	{ "flush",	flushhelp,	flushcmd,	1, 0, 0, 0, 0 },
	{ "enable",	enablehelp,	enable,		0, 0, 0, 0, 0 },
	{ "disable",	disablehelp,	disable,	1, 0, 0, 0, 0 },
	{ "route",	routehelp,	route,		1, 0, 1, 0, 0 },
	{ "pf",		pfhelp,		pfctl,		1, 0, 0, 1, 1 },
	{ "ospf",	ospfhelp,	ospfctl,	1, 0, 0, 1, 1 },
	{ "bgp",	bgphelp,	bgpctl,		1, 0, 0, 1, 1 },
	{ "rip",	riphelp,	ripctl,		1, 0, 0, 1, 1 },
	{ "relay",	relayhelp,	relayctl,	1, 0, 0, 1, 1 },
	{ "ipsec",	ipsechelp,	ipsecctl,	1, 0, 0, 1, 1 },
	{ "dvmrp",	dvmrphelp,	dvmrpctl,	1, 0, 0, 1, 1 },
	{ "sasync",	sasynchelp,	sasyncctl,	1, 0, 0, 1, 1 },
	{ "dhcp",	dhcphelp,	dhcpctl,	1, 0, 0, 1, 1 },
	{ "snmp",	snmphelp,	snmpctl,	1, 0, 0, 1, 1 },
	{ "quit",	quithelp,	quit,		0, 0, 0, 0, 0 },
	{ "ping",	pinghelp,	ping,		0, 0, 0, 0, 0 },
	{ "traceroute", tracerthelp,	traceroute,	0, 0, 0, 0, 0 },
	{ "ssh",	sshhelp,	ssh,		0, 0, 0, 0, 0 },
	{ "telnet",	telnethelp,	telnet,		0, 0, 0, 0, 0 },
	{ "reload",	reloadhelp,	reload,		1, 0, 0, 0, 0 },
	{ "halt",	halthelp,	halt,		1, 0, 0, 0, 0 },
	{ "write-config", savehelp,	wr_startup,	1, 0, 0, 0, 0 },
	{ "verbose",	verbosehelp,	doverbose,	0, 0, 1, 0, 0 },
	{ "editing",	editinghelp,	doediting,	0, 0, 1, 0, 0 },
	{ "who",	whohelp,	who,		0, 0, 0, 0, 0 },
	{ "!",		shellhelp,	shell,		1, 0, 0, 0, 0 },
	{ "?",		helphelp,	help,		0, 0, 0, 0, 0 },
	{ "help",	0,		help,		0, 0, 0, 0, 0 },
	{ 0,		0,		0,		0, 0, 0, 0, 0 }
};

/*
 * These commands escape ambiguous check and help listings
 */

static Command  cmdtab2[] = {
	{ "config",	0,		notvalid,	0, 0, 0, 0, 0 },
	{ 0,		0,		0,		0, 0, 0, 0, 0 }
};

static Command *
getcmd(char *name)
{
	Command *cm;

	if ((cm = (Command *) genget(name, (char **) cmdtab, sizeof(Command))))
		return cm;
	return (Command *) genget(name, (char **) cmdtab2, sizeof(Command));
}

static void
makeargv(int x)
{
	char *cp, *cp2, c;
	char **argp = margv;

	margc = 0;
	cp = line;
	if (*cp == '!') {	/* Special case shell escape */
		strlcpy(saveline, line, sizeof(saveline));
						/* save for shell command */
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
		margc += 1;
		for (cp2 = cp; c != '\0'; c = *++cp) {
			if (inquote) {
				if (c == inquote) {
					inquote = 0;
					continue;
				}
			} else {
				if (!x && c == '\\') {
					if ((c = *++cp) == '\0')
						break;
				} else if (!x && c == '"') {
					inquote = '"';
					continue;
				} else if (!x && c == '\'') {
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
command(int top)
{
	Command  *c;
	u_int num;

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
			history(histc, &ev, H_ENTER, buf);
		}

		if (line[0] == 0)
			break;
		makeargv(0);
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
		u_int z = 0;

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
hostname(int argc, char *argv[])
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
				execl(shellp, shellname, "-c", &saveline[1],
				    (char *)NULL);
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


/*
 * Group attribute command.
 */
static int
group(int argc, char **argv)
{
	int counter = 1, set, ifs;
	const char *errstr;
	struct ifgroupreq ifgr;

	if (NO_ARG(argv[0])) {
		argv++;
		argc--;
		set = 0;
	} else
		set = 1;

	if ((argc < 3) || ((argc == 3 || argc == 4) &&
	    !CMP_ARG(argv[2], "c"))) {
		printf("%% group <group-name> carpdemote [demotion-counter]\n");
		printf("%% no group <group-name> carpdemote [demotion-counter]\n");
		return 1;
	}

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% group: socket: %s\n", strerror(errno));

		return 1;
	}

	bzero(&ifgr, sizeof(ifgr));
	strlcpy(ifgr.ifgr_name, argv[1], sizeof(ifgr.ifgr_name));

	if (set) {
		if (argc == 4) {
			counter = strtonum(argv[3], 0, 128, &errstr);
			if (errstr) {
				printf("%% invalid carp demotion: %s\n", errstr);
				return 1;
			}
		} else
			counter = 1;
		ifgr.ifgr_attrib.ifg_carp_demoted = counter;
	} else
		ifgr.ifgr_attrib.ifg_carp_demoted = 0;

	if (ioctl(ifs, SIOCSIFGATTR, (caddr_t)&ifgr) == -1) {
		if (errno == ENOENT)
			printf("%% group %s does not exist\n", ifgr.ifgr_name);
		else
			printf("%% group: SIOCSIFGATTR: %s\n", strerror(errno));
	}

	return 0;
}

/*
 * cmd, single arg
 */
int
cmdarg(char *cmd, char *arg)
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
 * cmd, multiple args
 */
int
cmdargs(char *cmd, char *arg[])
{
	switch(vfork()) {
		case -1:
			printf("%% fork failed: %s\n", strerror(errno));
			break;

		case 0:
		{
			char *shellp = cmd;

			execv(shellp, arg);
			printf("%% execv failed: %s\n", strerror(errno));
			exit(0);
		}
		default:
			(void)wait((int *)0);  /* Wait for cmd to complete */
			break;
	}
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

/*
 * pf toilet flusher
 */

int
flush_pfall(void)
{
	printf("%% Flushing all pf filter rules, NAT rules, queue rules,"
	    "   address tables, states, and statistics\n");
	cmdarg(PFCTL, "-Fall");

	return(0);
}

int
flush_pfnat(void)
{
	printf("%% Flushing pf NAT rules\n");
	cmdarg(PFCTL, "-Fnat");

	return(0);
}

int
flush_pfqueue(void)
{
	printf("%% Flushing pf queue rules\n");
	cmdarg(PFCTL, "-Fqueue");

	return(0);
}

int
flush_pfrules(void)
{
	printf("%% Flushing pf filter rules\n");
	cmdarg(PFCTL, "-Frules");

	return(0);
}

int
flush_pfstates(void)
{
	printf("%% Flushing pf NAT/filter states\n");
	cmdarg(PFCTL, "-Fstate");

	return(0);
}

int
flush_pfstats(void)
{
	printf("%% Flushing pf statistics\n");
	cmdarg(PFCTL, "-Finfo");

	return(0);
}

int
flush_pftables(void)
{
	printf("%% Flushing pf address tables\n");
	cmdarg(PFCTL, "-FTables");

	return(0);
}

/*
 * read a text file and execute commands
 * take into account that we may have mode handlers int cmdtab that 
 * execute indented commands from the rc file
 */
int
cmdrc(char rcname[FILENAME_MAX])
{
	Command	*c;
	FILE	*rcfile;
	char	modhvar[128];	/* required variable in mode handler cmd */
	int	modhcmd; 	/* do we execute under another mode? */
	unsigned int lnum;	/* line number */
	u_int	z = 0;		/* max length of cmdtab argument */

	if ((rcfile = fopen(rcname, "r")) == 0) {
		printf("%% Unable to open %s: %s\n", rcname, strerror(errno));
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
		if (line[0] == '!')
			continue;
		if (c && c->modh)
			makeargv(c->noesc);
		else
			makeargv(0);
		if (margv[0] == 0)
			continue;
		if (line[0] == ' ') {
			/*
			 * here, if a command starts with a space, it is
			 * considered part of a mode handler
			 */
			if (c && c->modh) {
				modhcmd = 1;
			} else {
				/*
				 * a command was specified with indentation
				 * but the last run of this loop was not a
				 * mode handler!
				 */
				modhcmd = 0;
				printf("%% No mode handler specified before"
				    " indented command? (line %u) ", lnum);
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
					    " for a mode handler (line %u) ",
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
				printf("%% Invalid rc command (line %u) ",
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

	if (!editing)	/* Nothing to parse, fail */
		return(1);

	/*
	 * el_parse will always return a non-error status if someone specifies
	 * argv[0] with a colon.  The idea of the colon is to allow host-
	 * specific commands, which is really only useful in .editrc, so
	 * it is invalid here.
	 */
	colon = strchr(margv[0], ':');
	if (colon)
		return(1);

	val = el_parse(el, margc, (const char **)margv);

	if (val == 0)
		return(0);
	else
		return(1);
}

char *
cprompt(void)
{
	gethostname(hbuf, sizeof(hbuf));
	snprintf(prompt, sizeof(prompt), "%s%s/", hbuf, priv ? "(p)" : "");

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

int
wr_startup(void)
{
	if (wr_conf(NSHRC_TEMP))
		printf("%% Saving configuration\n");
	else
		printf("%% Unable to save configuration: %s\n",
		    strerror(errno));

	cmdarg(SAVESCRIPT, NSHRC_TEMP);

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
halt(void)
{
	printf ("%% Shutdown initiated\n");
	if (reboot (RB_HALT) == -1)
		printf("%% reboot: RB_HALT: %s\n", strerror(errno));
	return(1);
}

/*
 * Flush wrappers
 */
int
flush_ip_routes(void)
{
	flushroutes(AF_INET, AF_INET);

	return(0);
}

int
flush_arp_cache(void)
{
	flushroutes(AF_INET, AF_LINK);

	return(0);
}

/*
 * Show wrappers
 */
int
pr_conf(void)
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
pr_s_conf(void)
{
	int ret;

	if (priv != 1) {
		printf ("%% Privilege required\n");
		return(0);
	}

	ret = more(NSHRC);
	
	return(ret);
}

int
pr_routes(char *route)
{
	if (route == 0)
		/* show primary routing table */
		p_rttables(AF_INET, 0, 0);
	else
		/* show a specific route */
		show_route(route);
		
	return 0;
}

int
pr_arp(char *arp)
{
	if (arp == 0)
		/* show arp table */
		p_rttables(AF_INET, 0, RTF_LLINFO);
	else
		/* specific address */
		arpget(arp);
	return 0;
}

int
pr_sadb(void)
{
	p_rttables(PF_KEY, 0, 0);

	return 0;
}

int
pr_rt_stats(void)
{
	rt_stats();
	return 0;
}

int
pr_carp_stats(void)
{
	carp_stats();
	return 0;
}

int
pr_pfsync_stats(void)
{
	pfsync_stats();
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
	ip_stats();
	return 0;
}

int
pr_ah_stats(void)
{
	ah_stats();
	return 0;
}

int
pr_esp_stats(void)
{
	esp_stats();
	return 0;
}

int
pr_tcp_stats(void)
{
	tcp_stats();
	return 0;
}

int
pr_udp_stats(void)
{
	udp_stats();
	return 0;
}

int
pr_icmp_stats(void)
{
	icmp_stats();
	return 0;
}

int
pr_igmp_stats(void)
{
	igmp_stats();
	return 0;
}

int
pr_ipcomp_stats(void)
{
	ipcomp_stats();
	return 0;
}

int
pr_mbuf_stats(void)
{
	mbpr();
	return 0;
}
