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

#define NARGS  sizeof(line)/2		/* max arguments in char line[] */
char	*margv[NARGS];			/* argv storage */
size_t	cursor_argc;			/* location of cursor in margv */
size_t	cursor_argo;			/* offset of cursor margv[cursor_argc] */

pid_t	child;

static int	quit(void);
static int	disable(void);
static int	doverbose(int, char**);
static int	doediting(int, char**);
static int	doconfig(int, char**);
static int	exitconfig(int, char**);
int		rtable(int, char**);
int		group(int, char**);
static int	nsh_setrtable(int);
static int	pr_routes(int, char **);
static int	pr_routes6(int, char **);
static int	pr_arp(int, char **);
static int	pr_ndp(int, char **);
static int	pr_sadb(int, char **);
static int	pr_kernel(int, char **);
static int	pr_prot1(int, char **);
static int	pr_dhcp(int, char **);
static int	pr_conf(int, char **);
static int	pr_s_conf(int, char **);
static int	show_hostname(int, char **);
static int	wr_startup(void);
static int	wr_conf(char *);
static int	show_help(int, char **);
static int	sysctlhelp(int, char **, char **, int);
static int	flush_pf(char *);
static int	flush_help(void);
static int	flush_line(char *);
static int	flush_ip_routes(void);
static int	flush_arp_cache(void);
static int	flush_ndp_cache(void);
static int	flush_history(void);
static int	is_bad_input(const char *, size_t);
static int	read_command_line(EditLine *, History *);
static int	int_ping(char *, int, int, char **);
static int	int_ping6(char *, int, int, char **);
static int	int_traceroute(char *, int, int, char **);
static int	int_traceroute6(char *, int, int, char **);
static int	int_ssh(char *, int, int, char **);
static int	int_telnet(char *, int, int, char **);
static int	int_show(char *, int, int, char **);
static int	int_doverbose(char *, int, int, char **);
static int	int_doediting(char *, int, int, char **);
static int	int_manual(char *, int, int, char **);
static int	int_help(void);
static int	int_exit(void);
static int	el_burrito(EditLine *, int, char **);
static int	hostname(int, char **);
static int	help(int, char**);
static int	manual(int, char**);
static int	nocmd(int, char **);
static int	shell(int, char*[]);
static int	ping(int, char*[]);
static int	ping6(int, char*[]);
static int	traceroute(int, char*[]);
static int	traceroute6(int, char*[]);
static int	ssh(int, char*[]);
static int	telnet(int, char*[]);
       void	p_argv(int, char **);
static int 	nreboot(void);
static int 	halt(void);
static Command *getcmd(char *);
static void	pf_stats(void);
static void	sigalarm(int);

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
	{ "version",	"Software information",	CMPL0 0, 0, 0, 0, version },
	{ "users",	"System users",		CMPL0 0, 0, 0, 0, who },
	{ "running-config",	"Operating configuration", CMPL0 0, 0, 0, 0, pr_conf },
	{ "startup-config", "Startup configuration", CMPL0 0, 0, 0, 0, pr_s_conf },
	{ "?",		"Options",		CMPL0 0, 0, 0, 0, show_help },
	{ "help",	0,			CMPL0 0, 0, 0, 0, show_help },
	{ 0, 0, 0, 0, 0 }
};

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
 * Data structures and routines for the "ip" command.
 */

Menu iptab[] = {
	{ "arptimeout",	"Seconds for ARP entries to remain in cache",	CMPL0 0, 0, 1, 1, ipsysctl },
	{ "arpdown",	"Seconds before resending unanswered ARP requests", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "carp",	"Allow CARP",			CMPL0 0, 0, 0, 0, ipsysctl },
	{ "carp-log",	"CARP Logging Priority",	CMPL0 0, 0, 0, 1, ipsysctl },
	{ "carp-preempt", "CARP Virtual Host Preemption", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "forwarding",	"Enable IPv4 Forwarding",	CMPL0 0, 0, 0, 0, ipsysctl },
	{ "mforwarding", "Enable IPv4 Multicast Forwarding", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "ipip",	"Allow IP-in-IP Encapsulation", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "gre",	"Allow Generic Route Encapsulation", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "wccp",	"Allow Web Cache Control Protocol", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "etherip",	"Allow Ether-IP Encapsulation",	CMPL0 0, 0, 0, 0, ipsysctl },
	{ "ipcomp",	"Allow IP Compression",		CMPL0 0, 0, 0, 0, ipsysctl },	
	{ "esp",	"Allow Encapsulated Security Payload", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "esp-udpencap","Allow ESP encapsulation within UDP", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "esp-udpencap-port","UDP port number for encapsulation", CMPL0 0, 0, 0, 1, ipsysctl },  
	{ "ah",		"Allow Authentication Header",	CMPL0 0, 0, 0, 0, ipsysctl },
	{ "sourceroute", "Process Loose/Strict Source Route Options", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "encdebug",	"Enable if_enc debugging",	CMPL0 0, 0, 0, 0, ipsysctl },
	{ "send-redirects", "Send ICMP redirects",	CMPL0 0, 0, 0, 0, ipsysctl },
	{ "directed-broadcast", "Allow directed broadcasts", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "multipath",	"Multipath routing",		CMPL0 0, 0, 0, 0, ipsysctl },
	{ "maxqueue", "Maximum unassembled IP fragments in the fragment queue",      CMPL0 0, 0, 1, 1, ipsysctl  },
        { "mtudisc", "Enable Path MTU Discovery",       CMPL0 0, 0, 0, 0, ipsysctl },
        { "mtudisctimeout", "Timeout in seconds for routes added by Path MTU discovery engine", CMPL0 0, 0, 1, 1, ipsysctl },
        { "ipsec-timeout", "Seconds after a SA is established before it will expire", CMPL0 0, 0, 1, 1, ipsysctl },
        { "ipsec-soft-timeout", "Seconds after a SA is established before being renegotiated", CMPL0 0, 0, 1, 1, ipsysctl },
        { "ipsec-allocs", "Maximum IPSEC flows that can use a SA before it expires", CMPL0 0, 0, 1, 1, ipsysctl },
        { "ipsec-soft-allocs", "Maximum IPSEC flows a SA uses before renegotiation", CMPL0 0, 0, 1, 1, ipsysctl },
        { "ipsec-bytes", "Maximum bytes processed by a security association before it expires", CMPL0 0, 0, 1, 1, ipsysctl },
        { "ipsec-soft-bytes", "Maximum bytes a SA processes before renegotiation", CMPL0 0, 0, 1, 1, ipsysctl },
        { "ipsec-expire-acquire", "Seconds the kernel allows to dynamically acquire SAs before a request", CMPL0 0, 0, 1, 1, ipsysctl },
        { "ipsec-firstuse", "Seconds after security association is first used before it expires", CMPL0 0, 0, 1, 1, ipsysctl },
        { "ipsec-soft-firstuse", "Seconds after a SA is first used before it is sent for renegotiation", CMPL0 0, 0, 1, 1, ipsysctl },
        { "ipsec-invalid-life", "Lifetime of Embryonic SAs in seconds", CMPL0 0, 0, 1, 1, ipsysctl },
        { "ipsec-pfs", "Enables Perfect Forward Secrecy when establishing SAs", CMPL0 0, 0, 1, 1, ipsysctl },
        { "portfirst", "Minimum registered port number for TCP/UDP port allocation", CMPL0 0, 0, 1, 1, ipsysctl },
        { "porthifirst", "Minimum dynamic/private port number for TCP/UDP port allocation", CMPL0 0, 0, 1, 1, ipsysctl },
        { "porthilast", "Maximum dynamic/private port number for TCP/UDP port allocation", CMPL0 0, 0, 1, 1, ipsysctl },
        { "portlast", "Maximum regisrered port number for TCP/UDP port allocation", CMPL0 0, 0, 1, 1, ipsysctl },
#ifdef notyet
	{ "default-mtu", "Default interface MTU",	CMPL0 0, 0, 1, 1, ipsysctl },
#endif
	{ "default-ttl", "Default IP packet TTL",	CMPL0 0, 0, 1, 1, ipsysctl },
	{ "?",		"Options",			CMPL0 0, 0, 0, 0, sysctlhelp },
	{ 0, 0, 0, 0, 0, 0, 0, 0 }
};

Menu ip6tab[] = {
	{ "auto_flowlabel", "Fill the IPv6 flowlabel field to help intermediate routers identify packet flows", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "dad_count", "Configures the number of IPv6 D.A.D. probe packets", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "dad_pending", "Displays number of pending IPv6 D.A.D. before completion", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "defmcasthlim", "The default hop limit value for an IPv6 multicast packet sourced by the system", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "forwarding", "Enable IPv6 Forwarding",       CMPL0 0, 0, 0, 0, ipsysctl },
	{ "hdrnestlimit", "The number of IPv6 extension headers permitted on incoming IPv6 packets", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "hoplimit", "The default hop limit for IPv6 unicast packet sourced by the system", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "log_interval", "Configures the amount of logs generated by the IPv6 packet forwarding engine", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "maxdynroutes", "Max IPv6 Dyn Routes",        CMPL0 0, 0, 0, 0, ipsysctl },
	{ "maxfragpackets", "The maximum number of fragmented packets the system will accept", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "maxfrags", "The maximum number of fragments the node will accept", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "maxifdefrouters", "Max if IPv6 Def Routers", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "maxifprefixes", "Max if IPv6 Prefixes",      CMPL0 0, 0, 0, 0, ipsysctl },
	{ "mforwarding", "Enable IPv6 Multicast Forwarding", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "mtudisctimeout", "Seconds after which a route added by the Path MTU Discovery engine will time out", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "multicast_mtudisc", "Enables ICMPv6 too big messages when machine is an IPv6 multicast router", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "multipath",  "Multipath routing",            CMPL0 0, 0, 0, 0, ipsysctl },
	{ "neighborgcthresh", "Maximum number of entries in neighbor cache", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "send-redirect", "Enables sending ICMPv6 redirects by the system", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "?",          "Help",                         CMPL0 0, 0, 0, 0, sysctlhelp },
	{ 0, 0, 0, 0, 0, 0, 0, 0 }
};

Menu mplstab[] = {
	{ "ttl",	"MPLS ttl",			CMPL0 0, 0, 0, 1, ipsysctl },
	{ "mapttl-ip",	"MPLS mapttl IPv4",		CMPL0 0, 0, 0, 1, ipsysctl },
	{ "mapttl-ip6",	"MPLS mapttl IPv6",		CMPL0 0, 0, 0, 1, ipsysctl },
	{ "?",		"Help",				CMPL0 0, 0, 0, 0, sysctlhelp },
	{ 0, 0, 0, 0, 0, 0, 0, 0 }
};

Menu ddbtab[] = {
	{ "panic",	"DDB panic",			CMPL0 0, 0, 0, 0, ipsysctl },
	{ "console",	"DDB console",			CMPL0 0, 0, 0, 0, ipsysctl },
	{ "log",	"DDB log",			CMPL0 0, 0, 0, 0, ipsysctl },
	{ "?",		"Help",				CMPL0 0, 0, 0, 0, sysctlhelp },
	{ 0, 0, 0, 0, 0, 0, 0, 0 }
};

Menu pipextab[] = {
	{ "enable",	"PIPEX enable",			CMPL0 0, 0, 0, 0, ipsysctl },
	{ "?",		"Help",				CMPL0 0, 0, 0, 0, sysctlhelp },
	{ 0, 0, 0, 0, 0, 0, 0, 0 }
};

static int
ipcmd(int argc, char **argv)
{
	Menu *i;     /* pointer to current command */
	struct sysctltab *stab;
	int set, success = 0;

	if (NO_ARG(argv[0])) {
		argv++;
		argc--;
		set = 0;
	} else
		set = 1;

	/*
	 * Find ourself in the great divide
	 */
	stab = (struct sysctltab *)genget(argv[0], (char **)sysctls,
	    sizeof(struct sysctltab));
        if (stab == 0) {
                printf("%% Invalid argument %s\n", argv[0]);
                return 0;
        } else if (Ambiguous(stab)) {
                printf("%% Ambiguous argument %s\n", argv[0]);
                return 0;
        }

	if (argc < 2) {
		sysctlhelp(0, NULL, NULL, stab->pf);
		return 0;
	}

	/*
	 * Validate ip argument
	 */
        i = (Menu *)genget(argv[1], (char **)stab->table, sizeof(Menu));
	if (i == 0) {
		printf("%% Invalid argument %s\n", argv[1]);
		return 0;
	} else if (Ambiguous(i)) {
		printf("%% Ambiguous argument %s\n", argv[1]);
		return 0;
	}
	if (((i->minarg + 2) > argc) || ((i->maxarg + 2) < argc)) {
		printf("%% Wrong argument%s to '%s %s' command.\n",
		    argc <= 2 ? "" : "s", argv[0], i->name);
		return 0;
	}

	if (i->handler)
		success = (*i->handler)(set, argv[1],
		    (i->maxarg > 0) ? argv[2] : 0, stab->pf);
	return(success);
}

static int
sysctlhelp(int unused1, char **unused2, char **unused3, int type)
{
	Menu *i = NULL, *j = NULL; /* pointer to current command */
	char *prefix = NULL;
	u_int z = 0;
	struct sysctltab *stab;
	
	for (stab = sysctls; stab->name != NULL; stab++)
		if (stab->pf == type) {
			prefix = stab->name;
			i = j = stab->table;
			break;
		}
	if (stab->pf != type) {
		printf("%% table lookup failed (%d)\n", type);
		return 0;
	}

	printf("%% Commands may be abbreviated.\n");
	printf("%% '%s' commands are:\n\n", prefix);

	for (; i && i->name; i++) {
		if (strlen(i->name) > z)
			z = strlen(i->name);
	}

	for (; j && j->name; j++) {
		if (j->help)
			printf("  %-*s  %s\n", z, j->name, j->help);
	}
	return 0;
}

/*
 * Data structures and routines for the "flush" command.
 */

Menu flushlist[] = {
	{ "routes",	"IP routes", CMPL0 0, 0, 0, 0, flush_ip_routes },
	{ "arp",	"ARP cache", CMPL0 0, 0, 0, 0, flush_arp_cache },
	{ "ndp",	"NDP cache", CMPL0 0, 0, 0, 0, flush_ndp_cache },
	{ "line",	"Active user", CMPL0 0, 0, 1, 1, flush_line },
	{ "bridge-dyn",	"Dynamically learned bridge addresses", CMPL0 0, 0, 1, 1, flush_bridgedyn },
	{ "bridge-all",	"Dynamic and static bridge addresses", CMPL0 0, 0, 1, 1, flush_bridgeall },
	{ "bridge-rule", "Layer 2 filter rules for a bridge member port", CMPL0 0, 0, 2, 2, flush_bridgerule },
	{ "pf",		"pf NAT/filter/queue rules, states, tables", CMPL(t) (char**)fpfs, sizeof(struct fpf), 0, 1, flush_pf },
	{ "history",	"Command history",	CMPL0 0, 0, 0, 0, flush_history },
	{ "?",		"Options",		CMPL0 0, 0, 0, 0, flush_help },
	{ "help",	0,			CMPL0 0, 0, 0, 0, flush_help },
	{ 0, 0, 0, 0, 0 }
};

static int
flushcmd(int argc, char **argv)
{
	Menu *f;

	if (argc < 2) {
		flush_help();
		return 0;
	}

	/*
	 * Validate flush argument
	 */
	f = (Menu *) genget(argv[1], (char **)flushlist, sizeof(Menu));
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

/*
 * Data structures and routines for the interface configuration mode
 */

static char pinghelp[];
static char ping6help[];
static char tracerthelp[];
static char tracert6help[];
static char sshhelp[];
static char telnethelp[];
static char showhelp[];
static char verbosehelp[];
static char editinghelp[];
static char manhelp[];
struct ghs mantab[];

struct intlist Intlist[] = {
/* Interface mode commands */
	{ "inet",	"IPv4/IPv6 addresses",			CMPL(h) (char **)intiphelp, sizeof(struct ghs), intip, 1},
	{ "ip",		"Alias for \"inet\" command",		CMPL(h) (char **)intiphelp, sizeof(struct ghs), intip, 1 },
	{ "alias",	NULL, /* backwards compatibilty */	CMPL(h) (char **)intiphelp, sizeof(struct ghs), intip, 1 },
#ifdef IFXF_AUTOCONF4		/* 6.6+ */
	{ "autoconf4",  "IPv4 Autoconfigurable address (DHCP)",	CMPL0 0, 0, intxflags, 1 },
#endif
	{ "description", "Interface description",		CMPL0 0, 0, intdesc, 1 },
	{ "group",	"Interface group",			CMPL0 0, 0, intgroup, 1 },
	{ "rdomain",	"Interface routing domain",		CMPL0 0, 0, intrdomain, 1 },
	{ "rtlabel",	"Interface route labels",		CMPL0 0, 0, intrtlabel, 1 },
	{ "priority",	"Data packet priority",			CMPL0 0, 0, intmetric, 1 },
	{ "llpriority",	"Link Level packet priority",		CMPL0 0, 0, intllprio, 1 },
	{ "mtu",	"Maximum Transmission Unit",		CMPL0 0, 0, intmtu, 1 },
	{ "metric",	"Routing metric",			CMPL0 0, 0, intmetric, 1 },
	{ "link",	"Link level options",			CMPL0 0, 0, intlink, 1 },
	{ "arp",	"Address Resolution Protocol",		CMPL0 0, 0, intflags, 1 },
	{ "staticarp",	"Always use static ARP to find other hosts",CMPL0 0, 0, intflags, 1 },
	{ "lladdr",	"Link Level (MAC) Address",		CMPL0 0, 0, intlladdr, 1 },
	{ "nwid",	"802.11 network ID",			CMPL0 0, 0, intnwid, 1 },
	{ "nwkey",	"802.11 network key",			CMPL0 0, 0, intnwkey, 1 },
	{ "powersave",	"802.11 powersaving mode",		CMPL0 0, 0, intpowersave, 1 },
	{ "txpower",	"802.11 transmit power",		CMPL0 0, 0, inttxpower, 1 },
	{ "bssid",	"802.11 bss id",			CMPL0 0, 0, intbssid, 1 },
	{ "media",	"Media type",				CMPL0 0, 0, intmedia, 1 },
	{ "mediaopt",	"Media options",			CMPL0 0, 0, intmediaopt, 1 },
	{ "auth",	"PPP authentication",			CMPL0 0, 0, intsppp, 1 },
	{ "peer",	"PPP peer authentication",		CMPL0 0, 0, intsppp, 1},
	{ "pppoe",	"PPPoE settings",			CMPL0 0, 0, intpppoe, 1 },
#ifdef notyet
	{ "vltime",	"IPv6 valid lifetime",			CMPL0 0, 0, intvltime, 1 },
	{ "pltime",	"IPv6 preferred lifetime",		CMPL0 0, 0, intpltime, 1 },
	{ "anycast",	"IPv6 anycast address bit",		CMPL0 0, 0, intanycast, 1 },
	{ "tentative",	"IPv6 tentative address bit",		CMPL0 0, 0, inttentative, 1 },
	{ "eui64",	"IPv6 automatic interface index",	CMPL0 0, 0, inteui64, 1 },
#endif
	{ "tunnel",	"Tunnel parameters",			CMPL0 0, 0, inttunnel, 1},
	{ "tunneldomain", "Tunnel routing domain for transit",	CMPL0 0, 0, intmpls, 1 },
	{ "txprio",	"Priority in tunnel protocol headers",	CMPL0 0, 0, intmpls, 1 },
	{ "rxprio",	"Source used for packet priority",	CMPL0 0, 0, intmpls, 1 },
	{ "vnetid",	"Virtual interface network identifier",	CMPL0 0, 0, intvnetid, 1 },
	{ "vnetflowid",	"Use part of vnetid as flowid",		CMPL0 0, 0, intvnetflowid, 1 },
	{ "parent",	"Parent interface",			CMPL(i) 0, 0, intparent, 1 },
	{ "patch",	"Pair interface",			CMPL(i) 0, 0, intpatch, 1 },
	{ "ping",	pinghelp,				CMPL0 0, 0, int_ping, 0 },
	{ "ping6",	ping6help,				CMPL0 0, 0, int_ping6, 0 },
	{ "traceroute", tracerthelp,				CMPL0 0, 0, int_traceroute, 0 },
	{ "traceroute6", tracert6help,				CMPL0 0, 0, int_traceroute6, 0 },
	{ "ssh",	sshhelp,				CMPL0 0, 0, int_ssh, 0 },
	{ "telnet",	telnethelp,				CMPL0 0, 0, int_telnet,	0 },
	{ "keepalive",	"GRE tunnel keepalive",			CMPL0 0, 0, intkeepalive, 1},
	{ "mplslabel",	"MPLS local label",			CMPL0 0, 0, intmpls, 1 },
	{ "pwe",	"MPLS PWE3",				CMPL0 0, 0, intpwe3, 1 },
	{ "syncdev",	"PFsync control message interface",	CMPL(i) 0, 0, intsyncdev, 1 },
	{ "syncpeer",	"PFsync peer address",			CMPL0 0, 0, intsyncpeer, 1 },
	{ "maxupd", 	"PFsync max updates, defer first packet", CMPL0 0, 0, intmaxupd, 1 },
	{ "vhid",	"CARP virtual host ID",			CMPL0 0, 0, intcarp, 1 },
	{ "advbase",	"CARP advertisement interval",		CMPL0 0, 0, intcarp, 1 },
	{ "advskew",	"CARP advertisement skew",		CMPL0 0, 0, intcarp, 1 },
	{ "carppass",	"CARP passphrase",			CMPL0 0, 0, intcpass, 1 },
	{ "carpdev",	"CARP device",				CMPL(i) 0, 0, intcdev, 1 },
	{ "carpnode",	"CARP additional vhid/advskew",		CMPL0 0, 0, intcnode, 1 },
	{ "carppeer",	"CARP peer",				CMPL0 0, 0, intcarp, 1 },
	{ "balancing",	"CARP balancing mode",			CMPL0 0, 0, intcarp, 1 },
	{ "pflow",	"pflow data export",			CMPL0 0, 0, intpflow, 1 },
	{ "debug",	"Driver dependent debugging",		CMPL0 0, 0, intflags, 1 },
	{ "dhcrelay",	"DHCP Relay Agent",			CMPL0 0, 0, intdhcrelay, 1 },
	{ "wol",	"Wake On LAN",				CMPL0 0, 0, intxflags, 1 },
	{ "mpls",	"MPLS",					CMPL0 0, 0, intxflags, 1 },
	{ "inet6",	"IPv6 addresses",			CMPL(h) (char **)intip6help, sizeof(struct ghs), intip, 1 },
	{ "autoconf6",  "IPv6 Autoconfigurable address",	CMPL0 0, 0, intxflags, 1 },
#ifdef IFXF_INET6_NOPRIVACY	/* pre-6.9 */
	{ "autoconfprivacy", "Privacy addresses for IPv6 autoconf", CMPL0 0, 0, intxflags, 1 },
#endif
#ifdef IFXF_AUTOCONF6TEMP	/* 6.9+ */
	{ "autoconfprivacy", "Privacy addresses for IPv6 autoconf", CMPL0 0, 0, intxflags, 1 }, /* XXX bkcompat */
	{ "temporary",	"Temporary addresses for IPv6 autoconf", CMPL0 0, 0, intxflags, 1 },
#endif
#ifdef IFXF_MONITOR		/* 6.9+ */
	{ "monitor",	"Monitor mode for incoming traffic",	CMPL0 0, 0, intxflags, 1 },
#endif
	{ "wgpeer",	"Wireguard peer config",		CMPL0 0, 0, intwgpeer, 1 },
	{ "wgport",	"Wireguard UDP port",			CMPL0 0, 0, intwg, 1 },
	{ "wgkey",	"Wireguard private key",		CMPL0 0, 0, intwg, 1 },
	{ "wgrtable",	"Wireguard routing table",		CMPL0 0, 0, intwg, 1 },
	{ "trunkport",	"Add child interface(s) to trunk",	CMPL0 0, 0, inttrunkport, 1 },
	{ "trunkproto",	"Define trunkproto",			CMPL0 0, 0, inttrunkproto, 1 },
	{ "shutdown",   "Shutdown interface",			CMPL0 0, 0, intflags, 1 },
	{ "show",	showhelp,				CMPL(ta) (char **)showlist, sizeof(Menu), int_show, 0 },
	{ "verbose",	verbosehelp,				CMPL0 0, 0, int_doverbose, 1 },
	{ "editing",	editinghelp,				CMPL0 0, 0, int_doediting, 1 },
        { "?",		"Options",				CMPL0 0, 0, int_help, 0 },
	{ "manual",	manhelp,				CMPL(H) (char **)mantab, sizeof(struct ghs), int_manual, 0 },
        { "help",	0,					CMPL0 0, 0, int_help, 0 },
	{ "exit",	"Leave interface config mode and return to global config mode ",
								CMPL0 0, 0, int_exit, 0 },

	{ 0, 0, 0, 0, 0 }
};

size_t Intlist_nitems = nitems(Intlist);

struct intlist Bridgelist[] = {
/* Bridge mode commands */
	{ "description", "Bridge description",			CMPL0 0, 0, intdesc, 1 },
	{ "member",	"Bridge member(s)",			CMPL(i) 0, 0, brport, 1 },
	{ "span",	"Bridge spanning port(s)",		CMPL(i) 0, 0, brport, 1 },
	{ "blocknonip",	"Block non-IP traffic forwarding on member(s)",		CMPL0 0, 0, brport, 1 },
	{ "discover",	"Mark member(s) as discovery port(s)",	CMPL0 0, 0, brport, 1 },
	{ "learning",	"Mark member(s) as learning port(s)",	CMPL0 0, 0, brport, 1 },
	{ "stp",	"Enable 802.1D spanning tree protocol on member(s)",	CMPL0 0, 0, brport, 1 },
	{ "maxaddr",	"Maximum address cache size",		CMPL0 0, 0, brval, 1 },
	{ "timeout",	"Address cache timeout",		CMPL0 0, 0, brval, 1 },
	{ "maxage",	"Time for 802.1D configuration to remain valid",	CMPL0 0, 0, brval, 1 },
	{ "fwddelay",	"Time before bridge begins forwarding packets",		CMPL0 0, 0, brval, 1 },
	{ "hellotime",	"802.1D configuration packet broadcast interval",	CMPL0 0, 0, brval, 1 },
	{ "priority",	"Spanning priority for all members on an 802.1D bridge",CMPL0 0, 0, brval, 1},
	{ "ping",	pinghelp,				CMPL0 0, 0, int_ping, 0 },
	{ "ping6",	ping6help,				CMPL0 0, 0, int_ping6, 0 },
	{ "traceroute", tracerthelp,				CMPL0 0, 0, int_traceroute, 0 },
	{ "traceroute6", tracert6help,				CMPL0 0, 0, int_traceroute6, 0 },
	{ "ssh",	sshhelp,				CMPL0 0, 0, int_ssh, 0 },
	{ "telnet",	telnethelp,				CMPL0 0, 0, int_telnet,	0 },
	{ "rule",	"Bridge layer 2 filtering rules",	CMPL0 0, 0, brrule, 0 },
	{ "static",	"Static bridge address entry",		CMPL0 0, 0, brstatic, 1 },
	{ "ifpriority",	"Spanning priority of a member on an 802.1D bridge",	CMPL0 0, 0, brpri, 1 },
	{ "ifcost",	"Spanning tree path cost of a member on 802.1D bridge", CMPL0 0, 0, brpri, 1 },
	{ "link",	"Link level options",			CMPL0 0, 0, intlink, 1 },
	{ "txprio",     "Priority in tunnel protocol headers",	CMPL0 0, 0, intmpls, 1 },
	{ "rxprio",     "Source used for packet priority",	CMPL0 0, 0, intmpls, 1 },
	{ "vnetid",	"Virtual interface network identifier",	CMPL0 0, 0, intvnetid, 1 },
	{ "parent",	"Parent interface",			CMPL(i) 0, 0, intparent, 1 },
	{ "tunneldomain", "Tunnel parameters",			CMPL0 0, 0, intmpls, 1 },
	{ "protect",	"Configure protected bridge domains",	CMPL0 0, 0, brprotect, 1 },
	{ "shutdown",	"Shutdown bridge",			CMPL0 0, 0, intflags, 1 },
	{ "show",	showhelp,				CMPL(ta) (char **)showlist, sizeof(Menu), int_show, 0 },
	{ "verbose",	verbosehelp,				CMPL0 0, 0, int_doverbose, 1 },
	{ "editing",	editinghelp,				CMPL0 0, 0, int_doediting, 1 },

/* Help commands */
	{ "?",		"Options",				CMPL0 0, 0, int_help, 0 },
	{ "manual",	manhelp,				CMPL(H) (char **)mantab, sizeof(struct ghs), int_manual, 0 },
	{ "help",	0,					CMPL0 0, 0, int_help, 0 },
	{ "exit",	"Leave bridge config mode and return to global config mode ",
								CMPL0 0, 0, int_exit },
	{ 0, 0, 0, 0, 0, 0 }
};

size_t Bridgelist_nitems = nitems(Bridgelist);

static int
is_bad_input(const char *buf, size_t num)
{
	int i;

	if (num >= sizeof(line)) {
		printf("%% Input exceeds permitted length\n");
		return 1;
	}

	for (i = 0; i < num; i++) {
		if (!isprint((unsigned char)buf[i])) {
			printf("%% Input contains bad character\n");
			return 1;
		}
	}

	return 0;
}

/*
 * Try to read a non-empty command into the global line buffer.
 * Return -1 upon error from el_gets().
 * If successful, enter the command into editing history and
 * return the amount of characters read.
 * The Enter key by itself has no effect.
 * Return 0 if EOF or ".." is read.
 * Do not add ".." to editing history.
 */
static int
read_command_line(EditLine *el, History *hist)
{
	const char *buf;
	int num;

	do {
		num = 0;
		if ((buf = el_gets(el, &num)) == NULL) {
			if (num == -1)
				return -1;
			/* EOF, e.g. ^X or ^D via exit_i() in complete.c */
			return 0;
		}
		while (num > 0 && isspace((unsigned char)buf[num - 1]))
			num--;
		if (is_bad_input(buf, num))
			continue;
	} while (num == 0); /* Enter key */

	if (num == 2 && strncmp(buf, "..", num) == 0)
		return 0;
	
	memcpy(line, buf, (size_t)num);
	line[num] = '\0';
	history(hist, &ev, H_ENTER, buf);
	return num;
}

/*
 * command handler for interface and bridge modes
 *
 * acts as a loop for human keyboard user, and as a one time command
 * lookup for rcfile -c or -i usage
 *
 * if a function returns to interface() with a 1, interface() will break
 * the user back to command() mode.
 */
static int
interface(int argc, char **argv, char *modhvar)
{
	int ifs, set = 1;
	char *tmp;
	char *ifunit = NULL;
	struct intlist *i;	/* pointer to current command */
	struct ifreq ifr;

	if (!modhvar) {
		if (NO_ARG(argv[0])) {
			argv++;
			argc--;
			set = 0;
		}
		if (argc == 3) {
			/*
			 * Allow "interface-name interface-number" as some
			 * network switches do: interface em 0
			 */
			ifunit = argv[2];
		} else if (argc != 2) {
			printf("%% [no] interface <interface name>\n");
			return(0);
		}
		tmp = argv[1];
	} else {
		/* called from cmdrc(), processing config file rules only */
		if (argc == 2 && strcmp(modhvar, argv[1]) == 0) {
			 /* do-nothing */
			return(0);
		}
		tmp = modhvar;
	}

	if (strlen(tmp) > IFNAMSIZ-1) {
		printf("%% interface name too long\n");
		return(0);
	}

	ifname[IFNAMSIZ-1] = '\0';
	strlcpy(ifname, tmp, IFNAMSIZ);
	if (ifunit) {
		const char *errstr;
		size_t len = strlen(ifname);
		strtonum(ifunit, 0, INT_MAX, &errstr);
		if (errstr) {
			printf("%% interface unit %s is %s\n", ifunit, errstr);
			return(1);
		}
		if (len > 0 && isdigit((unsigned char)(ifname[len - 1]))) {
			printf("%% interface unit %s is redundant\n", ifunit);
			return(1);
		}
		strlcat(ifname, ifunit, sizeof(ifname));
		printf("%% Interface name is %s not \"%s %s\"\n",
		    ifname, tmp, ifunit);
	}
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% socket failed: %s\n", strerror(errno));
		return(1);
	}

	if (!is_valid_ifname(ifname)) {
		if (set == 0) {
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

	if (set == 0) {
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
		/* whichlist also used by help, command completion code */
		whichlist = Bridgelist;
		bridge = 1;
	} else {
		whichlist = Intlist;
		bridge = 0; 
	}

	imr_init(ifname);

	if (modhvar) {
		/* direct rcfile -i or -c initialization */
		char *argp;

		if (argc - 1 > NARGS)
			argc = NARGS;
		if (argv[0] == 0)
			return(0);
		if (NO_ARG(argv[0]))
			argp = argv[1];
		else
			argp = argv[0];
		i = (struct intlist *) genget(argp, (char **)
		    whichlist, sizeof(struct intlist));
		if (Ambiguous(i)) {
			printf("%% Ambiguous command\n");
		} else if (i == 0) {
			printf("%% Invalid command\n");
		} else {
			int save_cli_rtable = cli_rtable;
			cli_rtable = 0;

			((*i->handler) (ifname, ifs, argc, argv));

			cli_rtable = save_cli_rtable;
		}

		return(0);
	}

	/* human at the keyboard */
	for (;;) {
		char *margp;

		if (!editing) {
			/* command line editing disabled */
			printf("%s", iprompt());
			if (fgets(line, sizeof(line), stdin) == NULL) {
				if (feof(stdin) || ferror(stdin)) {
					printf("\n");
					close(ifs);
					return(0);
				}
				break;
			}
			if (line[0] == '\0')
				break;
		} else {
			int num;

			cursor_pos = NULL;
			num = read_command_line(eli, histi);
			if (num == 0)
				break;
			if (num == -1) {
				printf("%% Input error: %s\n",
				    strerror(errno));
				close(ifs);
				return(1);
			}
		}

		makeargv();
		if (margv[0] == 0)
			break;
		if (NO_ARG(margv[0]))
			margp = margv[1];
		else
			margp = margv[0];
		i = (struct intlist *) genget(margp, (char **)
		    whichlist, sizeof(struct intlist));
		if (Ambiguous(i)) {
			printf("%% Ambiguous command\n");
		} else if (i == 0) {
			int val = 1;

			if (editing)
				val = el_burrito(eli, margc, margv);
			if (val)
				printf("%% Invalid command\n");
		} else {
			int save_cli_rtable = cli_rtable;
			cli_rtable = 0;

			if ((*i->handler) (ifname, ifs, margc, margv)) {
				cli_rtable = save_cli_rtable;
				break;
			}
			cli_rtable = save_cli_rtable;
		}
	}

	close(ifs);
	return(0);
}

static int
int_ping(char *ifname, int ifs, int argc, char **argv)
{
	ping(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_ping6(char *ifname, int ifs, int argc, char **argv)
{
	ping6(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_traceroute(char *ifname, int ifs, int argc, char **argv)
{
	traceroute(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_traceroute6(char *ifname, int ifs, int argc, char **argv)
{
	traceroute6(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_ssh(char *ifname, int ifs, int argc, char **argv)
{
	ssh(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_telnet(char *ifname, int ifs, int argc, char **argv)
{
	telnet(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_show(char *ifname, int ifs, int argc, char **argv)
{
	showcmd(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_doverbose(char *ifname, int ifs, int argc, char **argv)
{
	doverbose(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_doediting(char *ifname, int ifs, int argc, char **argv)
{
	doediting(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_manual(char *ifname, int ifs, int argc, char **argv)
{
	manual(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_help(void)
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

static int
int_exit(void)
{
	return 1; /* leave interface config mode */
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
	ndphelp[] = 	"Static NDP set",
	nameserverhelp[] ="set or remove static DNS nameservers",
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
	radhelp[] =	"Router advertisement control",
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
	resolvhelp[] =	"Resolver configuration control",
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
	routehelp[] =	"Add a host or network route",
	pinghelp[] = 	"Send IPv4 ICMP echo request",
	ping6help[] =   "Send IPv6 ICMP echo request",
	tracerthelp[] =	"Print the route to IPv4 host",
	tracert6help[] ="Print the route to IPv6 host",
	sshhelp[] =	"SSH connection to remote host",
	telnethelp[] =	"Telnet connection to remote host",
	quithelp[] =	"Close current connection",
	exithelp[] =	"Leave configuration mode and return to privileged mode",
	verbosehelp[] =	"Set verbose diagnostics",
	editinghelp[] = "Set command line editing",
	confighelp[] =	"Set configuration mode",
	whohelp[] =	"Display system users",
	shellhelp[] =	"Invoke a subshell",
	savehelp[] =	"Save the current configuration",
	nreboothelp[] =	"Reboot the system",
	halthelp[] =	"Halt the system",
	helphelp[] =	"Print help information",
	manhelp[] =	"Display the NSH manual";

struct ghs secrettab[] = {
	{ "<password>", "Password parameter", CMPL0 NULL, 0 },
	{ "<cipher> <hash>", "Encrypted password parameter", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

Menu enabletab[] = {
	{ "<cr>",	"Enable privileged mode", CMPL0 0, 0, 0, 0, enable },
	{ "secret",	"Set privileged mode secret", CMPL(h) (char **)secrettab, sizeof(struct ghs), 0, 0, enable },
	{ 0, 0, 0, 0, 0 }
};

struct ghs rtabletab[] = {
	{ "<cr>", "Type Enter to run command", CMPL0 NULL, 0 },
	{ "<table id> [name]", "Routing table ID parameter", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs demotecountertab[] = {
	{ "[demotion-counter]", "CARP demotion counter parameter", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

Menu grouptab[] = {
	{ "carpdemote",	"Set carp demote counter", CMPL(h) (char **)demotecountertab, sizeof(struct ghs), 0, 0, group },
	{ 0, 0, 0, 0, 0 }
};

/* Keep in sync with grep '^\.Tg' nsh.8 | sort | uniq */
struct ghs mantab[] = {
	{ "ah", "Search for tag ah", CMPL0 NULL, 0 },
	{ "arp", "Search for tag arp", CMPL0 NULL, 0 },
	{ "auth", "Search for tag auth", CMPL0 NULL, 0 },
	{ "autoconf", "Search for tag autoconf", CMPL0 NULL, 0 },
	{ "bgp", "Search for tag bgp", CMPL0 NULL, 0 },
	{ "bgpctl", "Search for tag bgpctl", CMPL0 NULL, 0 },
	{ "bgpd", "Search for tag bgpd", CMPL0 NULL, 0 },
	{ "bridge", "Search for tag bridge", CMPL0 NULL, 0 },
	{ "bridgeport", "Search for tag bridgeport", CMPL0 NULL, 0 },
	{ "carp", "Search for tag carp", CMPL0 NULL, 0 },
	{ "config", "Search for tag config", CMPL0 NULL, 0 },
	{ "configure", "Search for tag configure", CMPL0 NULL, 0 },
	{ "csh", "Search for tag csh", CMPL0 NULL, 0 },
	{ "ddb", "Search for tag ddb", CMPL0 NULL, 0 },
	{ "dhcp", "Search for tag dhcp", CMPL0 NULL, 0 },
	{ "dhcpd", "Search for tag dhcpd", CMPL0 NULL, 0 },
	{ "dhcprelay", "Search for tag dhcprelay", CMPL0 NULL, 0 },
	{ "dhcrelay", "Search for tag dhcrelay", CMPL0 NULL, 0 },
	{ "disable", "Search for tag disable", CMPL0 NULL, 0 },
	{ "dvmrp", "Search for tag dvmrp", CMPL0 NULL, 0 },
	{ "dvmrpd", "Search for tag dvmrpd", CMPL0 NULL, 0 },
	{ "editing", "Search for tag editing", CMPL0 NULL, 0 },
	{ "eigrp", "Search for tag eigrp", CMPL0 NULL, 0 },
	{ "eigrpd", "Search for tag eigrpd", CMPL0 NULL, 0 },
	{ "enable", "Search for tag enable", CMPL0 NULL, 0 },
	{ "esp", "Search for tag esp", CMPL0 NULL, 0 },
	{ "firewall", "Search for tag firewall", CMPL0 NULL, 0 },
	{ "flow", "Search for tag flow", CMPL0 NULL, 0 },
	{ "flush", "Search for tag flush", CMPL0 NULL, 0 },
	{ "ftp-proxy", "Search for tag ftp-proxy", CMPL0 NULL, 0 },
	{ "group", "Search for tag group", CMPL0 NULL, 0 },
	{ "halt", "Search for tag halt", CMPL0 NULL, 0 },
	{ "help", "Search for tag help", CMPL0 NULL, 0 },
	{ "hostname", "Search for tag hostname", CMPL0 NULL, 0 },
	{ "hsrp", "Search for tag hsrp", CMPL0 NULL, 0 },
	{ "icmp", "Search for tag icmp", CMPL0 NULL, 0 },
	{ "ifstate", "Search for tag ifstate", CMPL0 NULL, 0 },
	{ "ifstated", "Search for tag ifstated", CMPL0 NULL, 0 },
	{ "igmp", "Search for tag igmp", CMPL0 NULL, 0 },
	{ "ike", "Search for tag ike", CMPL0 NULL, 0 },
	{ "iked", "Search for tag iked", CMPL0 NULL, 0 },
	{ "ikev2", "Search for tag ikev2", CMPL0 NULL, 0 },
	{ "inet", "Search for tag inet", CMPL0 NULL, 0 },
	{ "inetd", "Search for tag inetd", CMPL0 NULL, 0 },
	{ "interface", "Search for tag interface", CMPL0 NULL, 0 },
	{ "ip", "Search for tag ip", CMPL0 NULL, 0 },
	{ "ip6", "Search for tag ip6", CMPL0 NULL, 0 },
	{ "ipcomp", "Search for tag ipcomp", CMPL0 NULL, 0 },
	{ "ipsec", "Search for tag ipsec", CMPL0 NULL, 0 },
	{ "isakmpd", "Search for tag isakmpd", CMPL0 NULL, 0 },
	{ "isolation", "Search for tag isolation", CMPL0 NULL, 0 },
	{ "kernel", "Search for tag kernel", CMPL0 NULL, 0 },
	{ "ksh", "Search for tag ksh", CMPL0 NULL, 0 },
	{ "l2vpn", "Search for tag l2vpn", CMPL0 NULL, 0 },
	{ "label", "Search for tag label", CMPL0 NULL, 0 },
	{ "layer2", "Search for tag layer2", CMPL0 NULL, 0 },
	{ "ldap", "Search for tag ldap", CMPL0 NULL, 0 },
	{ "ldapd", "Search for tag ldapd", CMPL0 NULL, 0 },
	{ "ldp", "Search for tag ldp", CMPL0 NULL, 0 },
	{ "ldpd", "Search for tag ldpd", CMPL0 NULL, 0 },
	{ "lease", "Search for tag lease", CMPL0 NULL, 0 },
	{ "lladdr", "Search for tag lladdr", CMPL0 NULL, 0 },
	{ "macaddress", "Search for tag macaddress", CMPL0 NULL, 0 },
	{ "manual", "Search for tag manual", CMPL0 NULL, 0 },
	{ "mbuf", "Search for tag mbuf", CMPL0 NULL, 0 },
	{ "monitor", "Search for tag monitor", CMPL0 NULL, 0 },
	{ "mpls", "Search for tag mpls", CMPL0 NULL, 0 },
	{ "multicast", "Search for tag multicast", CMPL0 NULL, 0 },
	{ "nameserver", "Search for tag nameserver", CMPL0 NULL, 0 },
	{ "ndp", "Search for tag ndp", CMPL0 NULL, 0 },
	{ "nppp", "Search for tag nppp", CMPL0 NULL, 0 },
	{ "npppd", "Search for tag npppd", CMPL0 NULL, 0 },
	{ "ntp", "Search for tag ntp", CMPL0 NULL, 0 },
	{ "ntpd", "Search for tag ntpd", CMPL0 NULL, 0 },
	{ "ospf", "Search for tag ospf", CMPL0 NULL, 0 },
	{ "ospf6", "Search for tag ospf6", CMPL0 NULL, 0 },
	{ "ospfv3", "Search for tag ospfv3", CMPL0 NULL, 0 },
	{ "packetfilter", "Search for tag packetfilter", CMPL0 NULL, 0 },
	{ "pair", "Search for tag pair", CMPL0 NULL, 0 },
	{ "patch", "Search for tag patch", CMPL0 NULL, 0 },
	{ "pf", "Search for tag pf", CMPL0 NULL, 0 },
	{ "pfsync", "Search for tag pfsync", CMPL0 NULL, 0 },
	{ "ping", "Search for tag ping", CMPL0 NULL, 0 },
	{ "ping6", "Search for tag ping6", CMPL0 NULL, 0 },
	{ "pipex", "Search for tag pipex", CMPL0 NULL, 0 },
	{ "port", "Search for tag port", CMPL0 NULL, 0 },
	{ "privileged", "Search for tag privileged", CMPL0 NULL, 0 },
	{ "protected", "Search for tag protected", CMPL0 NULL, 0 },
	{ "quit", "Search for tag quit", CMPL0 NULL, 0 },
	{ "rad", "Search for tag rad", CMPL0 NULL, 0 },
	{ "rdomain", "Search for tag rdomain", CMPL0 NULL, 0 },
	{ "reboot", "Search for tag reboot", CMPL0 NULL, 0 },
	{ "relay", "Search for tag relay", CMPL0 NULL, 0 },
	{ "relayd", "Search for tag relayd", CMPL0 NULL, 0 },
	{ "resolv", "Search for tag resolv", CMPL0 NULL, 0 },
	{ "resolv.conf", "Search for tag resolv.conf", CMPL0 NULL, 0 },
	{ "rip", "Search for tag rip", CMPL0 NULL, 0 },
	{ "ripd", "Search for tag ripd", CMPL0 NULL, 0 },
	{ "route", "Search for tag route", CMPL0 NULL, 0 },
	{ "route6", "Search for tag route6", CMPL0 NULL, 0 },
	{ "rtable", "Search for tag rtable", CMPL0 NULL, 0 },
	{ "sa", "Search for tag sa", CMPL0 NULL, 0 },
	{ "sadb", "Search for tag sadb", CMPL0 NULL, 0 },
	{ "sasync", "Search for tag sasync", CMPL0 NULL, 0 },
	{ "sasyncd", "Search for tag sasyncd", CMPL0 NULL, 0 },
	{ "sensor", "Search for tag sensor", CMPL0 NULL, 0 },
	{ "sh", "Search for tag sh", CMPL0 NULL, 0 },
	{ "shell", "Search for tag shell", CMPL0 NULL, 0 },
	{ "show", "Search for tag show", CMPL0 NULL, 0 },
	{ "smtp", "Search for tag smtp", CMPL0 NULL, 0 },
	{ "smtpd", "Search for tag smtpd", CMPL0 NULL, 0 },
	{ "sniff", "Search for tag sniff", CMPL0 NULL, 0 },
	{ "snmp", "Search for tag snmp", CMPL0 NULL, 0 },
	{ "snmpd", "Search for tag snmpd", CMPL0 NULL, 0 },
	{ "span", "Search for tag span", CMPL0 NULL, 0 },
	{ "ssh", "Search for tag ssh", CMPL0 NULL, 0 },
	{ "sshd", "Search for tag sshd", CMPL0 NULL, 0 },
	{ "switch", "Search for tag switch", CMPL0 NULL, 0 },
	{ "switchport", "Search for tag switchport", CMPL0 NULL, 0 },
	{ "sync", "Search for tag sync", CMPL0 NULL, 0 },
	{ "syncdev", "Search for tag syncdev", CMPL0 NULL, 0 },
	{ "tcp", "Search for tag tcp", CMPL0 NULL, 0 },
	{ "telnet", "Search for tag telnet", CMPL0 NULL, 0 },
	{ "tftp", "Search for tag tftp", CMPL0 NULL, 0 },
	{ "tftp-proxy", "Search for tag tftp-proxy", CMPL0 NULL, 0 },
	{ "tpmr", "Search for tag tpmr", CMPL0 NULL, 0 },
	{ "traceroute", "Search for tag traceroute", CMPL0 NULL, 0 },
	{ "traceroute6", "Search for tag traceroute6", CMPL0 NULL, 0 },
	{ "unprivileged", "Search for tag unprivileged", CMPL0 NULL, 0 },
	{ "veb", "Search for tag veb", CMPL0 NULL, 0 },
	{ "verbose", "Search for tag verbose", CMPL0 NULL, 0 },
	{ "vlan", "Search for tag vlan", CMPL0 NULL, 0 },
	{ "vnetid", "Search for tag vnetid", CMPL0 NULL, 0 },
	{ "vni", "Search for tag vni", CMPL0 NULL, 0 },
	{ "vpls", "Search for tag vpls", CMPL0 NULL, 0 },
	{ "vrrp", "Search for tag vrrp", CMPL0 NULL, 0 },
	{ "vxlan", "Search for tag vxlan", CMPL0 NULL, 0 },
	{ "wake", "Search for tag wake", CMPL0 NULL, 0 },
	{ "wg", "Search for tag wg", CMPL0 NULL, 0 },
	{ "wireguard", "Search for tag wireguard", CMPL0 NULL, 0 },
	{ "wol", "Search for tag wol", CMPL0 NULL, 0 },
	{ "write-config", "Search for tag write-config", CMPL0 NULL, 0 },
	{ "<cr>", "Read entire manual", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

/*
 * Primary commands, will be included in help output
 */

#define ssctl sizeof(struct ctl)
Command cmdtab[] = {
	{ "hostname",	hostnamehelp,	CMPL0 0, 0, hostname,		1, 1, 0, 0 },
	{ "interface",	interfacehelp,	CMPL(i) 0, 0, interface,	1, 1, 1, 1 },
	{ "rtable",	rtablehelp,	CMPL(h) (char **)rtabletab, sizeof(struct ghs), rtable, 0, 0, 1, 2 },
	{ "group",	grouphelp,	CMPL(gth) (char **)grouptab, sizeof(Menu), group, 1, 1, 1, 0 },
	{ "arp",	arphelp,	CMPL0 0, 0, arpset,		1, 1, 1, 0 },
	{ "ndp",	ndphelp,	CMPL0 0, 0, ndpset,		1, 1, 1, 0 },
	{ "nameserver",	nameserverhelp,	CMPL0 0, 0, nameserverset,	1, 1, 1, 0 },
	{ "bridge",	bridgehelp,	CMPL(i) 0, 0, interface,	1, 1, 1, 1 },
	{ "show",	showhelp,	CMPL(ta) (char **)showlist, sizeof(Menu), showcmd,	0, 0, 0, 0 },
	{ "ip",		iphelp,		CMPL(ta) (char **)iptab, sizeof(Menu), ipcmd,		1, 1, 1, 0 },
	{ "ip6",	ip6help,	CMPL(ta) (char **)ip6tab, sizeof(Menu), ipcmd,		1, 1, 1, 0 },
	{ "mpls",	mplshelp,	CMPL(ta) (char **)mplstab, sizeof(Menu), ipcmd,		1, 1, 1, 0 },
	{ "ddb",	ddbhelp,	CMPL(ta) (char **)ddbtab, sizeof(Menu), ipcmd,		1, 1, 1, 0 },
	{ "pipex",	pipexhelp,	CMPL(ta) (char **)pipextab, sizeof(Menu), ipcmd,	1, 1, 1, 0 },
	{ "flush",	flushhelp,	CMPL(ta) (char **)flushlist, sizeof(Menu), flushcmd,	1, 0, 0, 0 },
	{ "enable",	enablehelp,	CMPL(ta) (char **)enabletab, sizeof(Menu), enable,	0, 0, 0, 0 },
	{ "disable",	disablehelp,	CMPL0 0, 0, disable,		1, 0, 0, 0 },
	{ "route",	routehelp,	CMPL0 0, 0, route,		1, 1, 1, 0 },
	{ "pf",		pfhelp,		CMPL(t) (char **)ctl_pf, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "ospf",	ospfhelp,	CMPL(t) (char **)ctl_ospf, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "ospf6",	ospf6help,	CMPL(t) (char **)ctl_ospf6, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "eigrp",	eigrphelp,	CMPL(t) (char **)ctl_eigrp, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "bgp",	bgphelp,	CMPL(t) (char **)ctl_bgp, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "rip",	riphelp,	CMPL(t) (char **)ctl_rip, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "ldp",	ldphelp,	CMPL(t) (char **)ctl_ldp, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "relay",	relayhelp,	CMPL(t) (char **)ctl_relay, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "ipsec",	ipsechelp,	CMPL(t) (char **)ctl_ipsec, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "ike",	ikehelp,	CMPL(t) (char **)ctl_ike, ssctl, ctlhandler, 	1, 1, 0, 1 },
	{ "dvmrp",	dvmrphelp,	CMPL(t) (char **)ctl_dvmrp, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "rad",	radhelp,	CMPL(t) (char **)ctl_rad, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "sasync",	sasynchelp,	CMPL(t) (char **)ctl_sasync, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "dhcp",	dhcphelp,	CMPL(t) (char **)ctl_dhcp, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "snmp",	snmphelp,	CMPL(t) (char **)ctl_snmp, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "ldap",	ldaphelp,	CMPL(t) (char **)ctl_ldap, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "smtp",	smtphelp,	CMPL(t) (char **)ctl_smtp, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "sshd",	sshdhelp,	CMPL(t) (char **)ctl_sshd, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "ntp",	ntphelp,	CMPL(t) (char **)ctl_ntp, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "nppp",	nppphelp,	CMPL(t) (char **)ctl_nppp, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "ifstate",	ifstatehelp,	CMPL(t) (char **)ctl_ifstate, ssctl, ctlhandler, 1, 1, 0, 1 },
	{ "ftp-proxy",  ftpproxyhelp,	CMPL(t) (char **)ctl_ftpproxy, ssctl, ctlhandler,  1, 1, 0, 1 },
	{ "tftp-proxy",	tftpproxyhelp,	CMPL(t) (char **)ctl_tftpproxy, ssctl, ctlhandler, 1, 1, 0, 1 },
	{ "tftp",	tftphelp,	CMPL(t) (char **)ctl_tftp, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "resolv",	resolvhelp,	CMPL(t) (char **)ctl_resolv, ssctl, ctlhandler, 1, 1, 0, 1 },
	{ "motd",       motdhelp,       CMPL(t) (char **)ctl_motd, ssctl, ctlhandler,    1, 1, 0, 1 },
	{ "inet",	inethelp,	CMPL(t) (char **)ctl_inet, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "ping",	pinghelp,	CMPL0 0, 0, ping,		0, 0, 0, 0 },
	{ "ping6",	ping6help,	CMPL0 0, 0, ping6,		0, 0, 0, 0 },
	{ "traceroute", tracerthelp,	CMPL0 0, 0, traceroute,		0, 0, 0, 0 },
	{ "traceroute6", tracert6help,  CMPL0 0, 0, traceroute6,	 0, 0, 0, 0 },
	{ "ssh",	sshhelp,	CMPL0 0, 0, ssh,		0, 0, 0, 0 },
	{ "telnet",	telnethelp,	CMPL0 0, 0, telnet,		0, 0, 0, 0 },
	{ "reboot",	nreboothelp,	CMPL0 0, 0, nreboot,		1, 0, 0, 0 },
	{ "halt",	halthelp,	CMPL0 0, 0, halt,		1, 0, 0, 0 },
	{ "write-config", savehelp,	CMPL0 0, 0, wr_startup,		1, 0, 0, 0 },
	{ "verbose",	verbosehelp,	CMPL0 0, 0, doverbose,		0, 0, 1, 0 },
	{ "editing",	editinghelp,	CMPL0 0, 0, doediting,		0, 0, 1, 0 },
	{ "configure",	confighelp,	CMPL0 0, 0, doconfig,		1, 0, 1, 0 },
	{ "who",	whohelp,	CMPL0 0, 0, who,		0, 0, 0, 0 },
	{ "no",		0,		CMPL(C) 0, 0, nocmd,		0, 0, 0, 0 },
	{ "!",		shellhelp,	CMPL0 0, 0, shell,		1, 0, 0, 0 },
	{ "?",		helphelp,	CMPL(C) 0, 0, help,		0, 0, 0, 0 },
	{ "manual",	manhelp,	CMPL(H) (char **)mantab, sizeof(struct ghs), manual,0, 0, 0, 0 },
	{ "exit",	exithelp,	CMPL0 0, 0, exitconfig,		1, 0, 0, 0 },
	{ "quit",	quithelp,	CMPL0 0, 0, quit,		0, 0, 0, 0 },
	{ "help",	0,		CMPL(C) 0, 0, help,		0, 0, 0, 0 },
	{ 0,		0,		CMPL0 0, 0, 0,			0, 0, 0, 0 }
};

size_t cmdtab_nitems = nitems(cmdtab);

/*
 * These commands escape ambiguous check and help listings
 */

static Command  cmdtab2[] = {
	{ 0,		0,		CMPL0 0, 0, 0,		0, 0, 0, 0 }
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
		while (isspace((unsigned char)c))
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
				} else if (isspace((unsigned char)c)) {
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
		if (c->needconfig != 0 && config_mode != 1) {
			printf("%% Command requires configure mode\n");
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
			if (c->help &&
			    ((c->needpriv && priv) || !c->needpriv) &&
			    ((c->needconfig && config_mode) || !c->needconfig))
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
 * Manual command.
 */

static void
manual_usage(void)
{
	printf("%% manual [search tag]\n");
}

static int
manual(int argc, char **argv)
{
	sig_t sigint, sigquit, sigchld;
	char term[32], *termenv = NULL;
	char tag[64], *tagarg = NULL;
	const char *lessenv, *nsh8;

	if (argc != 1 && argc != 2) {
		manual_usage();
		return 1;
	}

	if (argc == 2) {
		if (strcmp(argv[1], "?") == 0) {
			manual_usage();
			return 1;
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
			printf("%% execl failed: %s\n", strerror(errno));
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

int
nsh_setrtable(int rtableid)
{
	int cur_rtable;
	errno = 0;

	cur_rtable = getrtable();
	if (cur_rtable != rtableid && setrtable(rtableid) < 0)
		switch(errno) {
		case EINVAL:
			printf("%% rtable %d not initialized\n",
			    cli_rtable);
			break;
		case EPERM:
			printf("%% nsh not running as root?\n");
			break;
		default:
			printf("%% setrtable failed: %d\n", errno);
		}
	return(errno);
}

/*
 * "no" command
 * This is a pseudo command table entry used for TAB-completion purposes.
 */
static int
nocmd(int argc, char **argv)
{
	Command  *cmd = NULL, *c;

	if (!NO_ARG(argv[0])) {
		printf("%% nocmd: invalid command %s\n", argv[0]);
		return 0;
	}

	if (argc < 2) {
		printf("%% nocmd: command name not provided\n");
		return 0;
	}

	for (c = cmdtab; c->name; c++) {
		if (c->nocmd && strcmp(c->name, argv[1]) == 0) {
			cmd = c;
			break;
		}
	}

	if (cmd == NULL) {
		printf("%% nocmd: command %s not found\n", argv[1]);
		return 0;
	}

	return (*c->handler)(argc, argv, 0);
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

			if (nsh_setrtable(cli_rtable))
				_exit(0);
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

int
rtable(int argc, char **argv)
{
	int table, set, pos, found;
	const char *errstr;
	char rtname[64];
	StringList *resp;

	if (NO_ARG(argv[0])) {
		argv++;
		argc--;
		set = 0;
		/* Disallow unprivileged users from removing an rtable */
		if (!priv) {
			printf("%% Privilege required\n");
			return 1;
		}
	} else {
		set = 1;
	}

	if (argc < 2) {
		printf("%% rtable <table id> [name]\n");
		printf("%% no rtable <table id>\n");
		return 1;
	}

	table = strtonum(argv[1], 0, RT_TABLEID_MAX, &errstr);
	if (errstr) {
		printf("%% invalid table id: %s\n", errstr);
		return 1;
	}

	argc -= 2;
	argv += 2;

	/* Convert any remaining argv (name) back to string */
	pos = argvtostring(argc, argv, rtname, sizeof(rtname));

	resp = sl_init();
	if (db_select_rtables_rtable(resp, table) < 0)
		printf("%% rtable select error\n");
	found = resp->sl_cur;
	sl_free(resp, 1);

	/*
	 * Disallow unprivileged users from adding a new
	 * rtable to the database or specifying a name
	 * (thus changing the database).
	 */
	if ((!found || pos) && !priv) {
		printf("%% Privilege required\n");
		return 1;
	}

	if (set && (found && !pos)) {
		/* Table found, skip database action */
		cli_rtable = table;
		return 0;
	}
	if (!set && !found) {
		printf("%% rtable %d does not exist in database\n",
		    table);
		return 1;
	}
	if (db_delete_rtables_rtable(table) < 0) {
		printf("%% rtable db removal error\n");
		return 1;
	}
	if (set) {
		if (db_insert_rtables(table, rtname) < 0) {
			printf("%% rtable db insertion error\n");
			return 1;
		}
		cli_rtable = table;
	} else {
		cli_rtable = 0;
	}

	return 0;
}

/*
 * Group attribute command.
 */
int
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
	    !isprefix(argv[2], "carpdemote"))) {
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
 * cmd, multiple args
 *
 * If no error occurs then return the program's exit code (>= 0).
 * Return -1 on error to run the program or if the program was
 * terminated in an abnormal way, such as being killed by a signal.
 */
int
cmdargs(char *cmd, char *arg[])
{
	return cmdargs_output(cmd, arg, -1, -1);
}

/*
 * cmd, multiple args, capture stdout and stderr output
 *
 * If no error occurs then return the program's exit code (>= 0).
 * Return -1 on error to run the program or if the program was
 * terminated in an abnormal way, such as being killed by a signal.
 */
int
cmdargs_output(char *cmd, char *arg[], int stdoutfd, int stderrfd)
{
	sig_t sigint, sigquit, sigchld;
	int status = -1;

	sigint = signal(SIGINT, SIG_IGN);
	sigquit = signal(SIGQUIT, SIG_IGN);
	sigchld = signal(SIGCHLD, SIG_DFL);

	switch (child = fork()) {
		case -1:
			printf("%% fork failed: %s\n", strerror(errno));
			return -1;

		case 0:
		{
			char *shellp = cmd;

			signal(SIGQUIT, SIG_DFL);
			signal(SIGINT, SIG_DFL);
			signal(SIGCHLD, SIG_DFL);

			if (cli_rtable != 0 && nsh_setrtable(cli_rtable))
				_exit(0);

			if (stdoutfd != -1) {
				if (stdoutfd != STDOUT_FILENO &&
				    dup2(stdoutfd, STDOUT_FILENO) == -1) {
					printf("%% dup2: %s\n",
					    strerror(errno));
					_exit(0);
				}
			}
			if (stderrfd != -1) {
				if (stderrfd != STDERR_FILENO &&
				    dup2(stderrfd, STDERR_FILENO) == -1) {
					printf("%% dup2 failed: %s\n",
					    strerror(errno));
					_exit(0);
				}
			}

			execv(shellp, arg);
			printf("%% execv failed: %s\n", strerror(errno));
			_exit(127); /* same as what ksh(1) would do here */
		}
			break;
		default:
			signal(SIGALRM, sigalarm);
			wait(&status);  /* Wait for cmd to complete */
			if (WIFEXITED(status)) /* normal exit? */
				status = WEXITSTATUS(status); /* exit code */
			break;
	}

	signal(SIGINT, sigint);
	signal(SIGQUIT, sigquit);
	signal(SIGCHLD, sigchld);
	signal(SIGALRM, SIG_DFL);
	child = -1;

	return status;
}

/*
 * disable privileged mode
 */
int
disable(void)
{
	priv = 0;
	config_mode = 0;
	return 0;
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
doconfig(int argc, char **argv)
{
	if (argc > 1) {
		if (NO_ARG(argv[0])) {
			return exitconfig(argc, argv);
		} else if (isprefix(argv[1], "terminal")) {
			config_mode = 1;
		} else {
			printf ("%% Invalid argument\n");
			return 1;
		}
	} else {
		config_mode = 1;
	}

	return 0;
}

int
exitconfig(int argc, char **argv)
{
	if (!config_mode) {
		printf ("%% Configuration mode is already disabled\n");
		return 1;
	}

	config_mode = 0;
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
 * pf toilet flusher
 */
int
flush_pf(char *arg)
{
	struct fpf *x;

	if (!arg || arg[0] == '?') {
		gen_help((char **)fpfs, "flush pf", "flush",
		    sizeof(struct fpf));
		return 0;
	}
	x = (struct fpf *) genget(arg, (char **)fpfs, sizeof(struct fpf));
	if (x == 0) {
		printf("%% Invalid argument %s\n", arg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", arg);
		return 0;
	}

	{
		char *argv[] = { x->cmd, x->arg, NULL };
		cmdargs(x->cmd, argv);
	}

	return(1);
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
			strlcpy(saveline, line, sizeof(saveline));
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
	pr = priv | cli_rtable | config_mode;
	snprintf(prompt, sizeof(prompt), "%s%s%s%s%s%s%s%s%s/", hbuf,
	    pr ? "(" : "",
	    config_mode ? "config" : "",
	    config_mode && priv ? "-" : "",
	    priv ? "p" : "",
	    (( priv && cli_rtable) || (config_mode && cli_rtable)) ? "-" : "",
	    cli_rtable ? "rtable " : "", cli_rtable ? tmp : "",
	    pr ?")" : "");

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
	char *argv[] = { SAVESCRIPT, NSHRC_TEMP, NULL };
	
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
 * Reboot
 */
int
nreboot(void)
{
	printf ("%% Reboot initiated\n");
	if (reboot (RB_AUTOBOOT) == -1)
		printf("%% reboot: RB_AUTOBOOT: %s\n", strerror(errno));
	return(0);
}
               
int
halt(void)
{
	printf ("%% Shutdown initiated\n");
	if (reboot (RB_HALT) == -1)
		printf("%% reboot: RB_HALT: %s\n", strerror(errno));
	return(0);
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

int
flush_ndp_cache(void)
{
	ndpdump(NULL, 1);
	return(0);
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

int
pr_routes(int argc, char **argv)
{
	switch(argc) {
	case 2:
		/* show primary routing table */
		p_rttables(AF_INET, cli_rtable, 0);
		break;
	case 3:
		/* show a specific route */
		show_route(argv[2], cli_rtable);
		break;
	}

	return 0;
}

int
pr_routes6(int argc, char **argv)
{
	switch(argc) {
	case 2:
		/* show primary routing table */
		p_rttables(AF_INET6, cli_rtable, 0);
		break;
	case 3:
		/* show a specific route */
		show_route(argv[2], cli_rtable);
		break;
	}

	return 0;
}

int
pr_arp(int argc, char **argv)
{
	switch(argc) {
	case 2:
		/* show arp table */
		arpdump();
		break;
	case 3:
		/* specific address */
		arpget(argv[2]);
		break;
	}
	return 0;
}

int
pr_ndp(int argc, char **argv)
{
	switch(argc) {
	case 2:
		/* show ndp table */
		ndpdump(NULL, 0);
		break;
	case 3:
		/* specific address */
		ndpget(argv[2]);
		break;
	}
	return 0;
}

int
pr_sadb(int argc, char **argv)
{
	p_rttables(PF_KEY, 0, 0);

	return 0;
}

int
pr_kernel(int argc, char **argv)
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
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", argv[2]);
		return 0;
	}
	if (x->handler) /* not likely to be false */
		(*x->handler)();
		
	return(0);
}

void
pf_stats(void)
{
	char *argv[] = { PFCTL, "-sinfo", NULL };

	printf("%% pf statistics:\n");

	cmdargs(PFCTL, argv);
	return;
}

int
pr_prot1(int argc, char **argv)
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
		return 0;
	} else if (Ambiguous(prot)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[1]);
		return 0;
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
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", argv[2]);
		return 0;
	}

	fillargs = step_optreq(x->args, args, argc, argv, 3);
	if (fillargs == NULL)
		return 0;

	cmdargs(fillargs[0], fillargs);

	return 1;
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

	return(args);
}

int
pr_dhcp(int argc, char **argv)
{
	if (argc == 3 && argv[2][0] != '?') {
		if (isprefix(argv[2], "leases")) {
			more(DHCPLEASES);
			return(0);
		}
		printf("%% argument %s not recognized\n", argv[2]);
		return(1);
	}
	printf("%% show dhcp leases\n");
	return(1);
}
