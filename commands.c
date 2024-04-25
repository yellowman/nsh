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
#include <sys/stat.h>
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
#include "ctl.h"

char hname[HSIZE];
char hbuf[MAXHOSTNAMELEN];	/* host name */
char ifname[IFNAMSIZ];		/* interface name */
struct intlist *whichlist;

pid_t	child;

static int	disable(void);
static int	doverbose(int, char**);
static int	doediting(int, char**);
static int	doconfig(int, char**);
static int	exitconfig(int, char**);
int		rtable(int, char**);
int		group(int, char**);
static int	pr_crontab(int, char **, FILE *);
static int	pr_routes(int, char **);
static int	pr_routes6(int, char **);
static int	pr_arp(int, char **);
static int	pr_ndp(int, char **);
static int	pr_sadb(int, char **);
static int	pr_kernel(int, char **);
static int	pr_dhcp(int, char **);
static int	pr_conf(int, char **);
static int	pr_s_conf(int, char **);
static int	pr_a_conf(int, char **);
static int	pr_conf_diff(int, char **);
static int	pr_environment(int, char **);
static int	show_hostname(int, char **);
static int	wr_startup(void);
static int	wr_conf(char *);
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
static int	int_do(char *, int, int, char **);
static int	int_setenv(char *, int, int, char **);
static int	int_unsetenv(char *, int, int, char **);
static int	int_saveenv(char *, int, int, char **);
static int	int_show(char *, int, int, char **);
static int	int_who(char *, int, int, char **);
static int	int_doverbose(char *, int, int, char **);
static int	int_doediting(char *, int, int, char **);
static int	int_manual(char *, int, int, char **);
static int	int_shell(char *, int, int, char **);
static int	int_help(void);
static int	int_exit(void);
static int	hostname(int, char **);
static int	manual(int, char**);
static int	nocmd(int, char **);
static int	docmd(int, char **);
static int	setenvcmd(int, char **);
static int	unsetenvcmd(int, char **);
static int	saveenvcmd(int, char **);
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
static int 	powerdown(void);
static void	pf_stats(void);

#include "commands.h"

void sigalarm(int blahfart)
{
	if (child != -1) {
		kill(child, SIGKILL);
	}
}

static struct fpf {
	char *name;
	char *help;
	char *cmd;
	char *arg;
} fpfs[] = {
	{ "all",	"all PF elements",	PFCTL,	"-Fall" },
	{ "nat",	"NAT rules",		PFCTL,	"-Fnat" },
	{ "queue",	"queue rules",		PFCTL,	"-Fqueue" },
	{ "filter",	"filter rules",		PFCTL,	"-Frules" },
	{ "states",	"NAT/filter states",	PFCTL,	"-Fstate" },
	{ "stats",	"PF statistics",	PFCTL,	"-Finfo" },
	{ "tables",	"PF address tables",	PFCTL,	"-FTables" },
	{ 0, 0, 0, 0 }
};

static struct stt {
	char *name;
	char *help;
	void (*handler) ();
} stts[] = {
	{ "ip",		"Internet Protocol",			ip_stats },
	{ "ah",		"Authentication Header",		ah_stats },
	{ "esp",	"Encapsulated Security Payload",	esp_stats },
	{ "tcp",	"Transmission Control Protocol",	tcp_stats },
	{ "udp",	"Unreliable Datagram Protocol",		udp_stats },
	{ "icmp",	"Internet Control Message Protocol",	icmp_stats },
	{ "igmp",	"Internet Group Management Protocol",	igmp_stats },
	{ "ipcomp",	"IP Compression",			ipcomp_stats },
	{ "route",	"Routing",				rt_stats },
	{ "carp",	"Common Address Redundancy Protocol",	carp_stats },
	{ "mbuf",	"Packet memory buffer",			mbpr },
	{ "pf",		"Packet Filter",			pf_stats },
	{ 0,		0,					0 }
};


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

struct prot1 os6cs[] = {
	{ "fib",        "Forward Information Base",
	    { OSPF6CTL, "show", "fib", OPT, OPT, NULL } },
	{ "database",   "Link State Database",
	    { OSPF6CTL, "show", "database", OPT, OPT, NULL } },
	{ "interfaces", "Interface",
	    { OSPF6CTL, "show", "interfaces", OPT, NULL } },
	{ "neighbor",   "Neighbor",
	    { OSPF6CTL, "show", "neighbor", OPT, NULL } },
	{ "rib",        "Routing Information Base",
	    { OSPF6CTL, "show", "rib", OPT, NULL } },
	{ "summary",    "Summary",
	    { OSPF6CTL, "show", "summary", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 pfcs[] = {
	{ "all",           "all pf info except fingerprints and interfaces", 
            { PFCTL, "-sall", NULL, NULL, NULL, NULL } },
	{ "anchors",       "currently loaded anchors in main pf ruleset", 
            { PFCTL, "-sAnchors", NULL, NULL, NULL } },	
        { "info ",         "pf filter statistics, counters and tracking",
            { PFCTL, "-sinfo", "-v", NULL, NULL, NULL } },
        { "labels",        "per rule stats (bytes, packets and states)",        
            { PFCTL, "-slabels", NULL, NULL, NULL, NULL } },
        { "memory",        "current pf pool memory hard limit",
            { PFCTL, "-smemory", NULL, NULL, NULL, NULL } },
	{ "queues",        "currently loaded pf queue definition", 
            { PFCTL, "-squeue", "-v", NULL, NULL, NULL } },
	{ "rules",         "active pf firewall rule",
            { PFCTL, "-srules", NULL, NULL, NULL, NULL } },
	{ "sources",       "contents of the pf source tracking table", 
            { PFCTL, "-sSources", NULL, NULL, NULL, NULL } },
	{ "states",        "contents of the pf state table",
            { PFCTL, "-sstates", NULL, NULL, NULL, NULL } },
        { "tables",        "pf table",
            { PFCTL, "-sTables", NULL, NULL, NULL, NULL } },
	{ "timeouts",      "current pf global timeout", 
            { PFCTL, "-stimeouts", NULL, NULL, NULL, NULL } },
	{ "osfingerprint", "pf Operating System fingerprint", 
            { PFCTL, "-sosfp", NULL, NULL, NULL, NULL } },
	{ "interfaces",    "pf usable interfaces/ interface group", 
            { PFCTL, "-sInterfaces", NULL, NULL, NULL, NULL } },
	{ 0, 0, { 0 } }                                                         
};
struct prot1 eics[] = {
	{ "interfaces",	"Interface",
	    { EIGRPCTL, "show", "interfaces", OPT, OPT, NULL } },
	{ "neighbor",	"Neighbor",
	    { EIGRPCTL, "show", "neighbor", OPT, OPT, NULL } },
	{ "topology",	"Topology",
	    { EIGRPCTL, "show", "topology", OPT, OPT, NULL } },
	{ "traffic",	"Traffic",
	    { EIGRPCTL, "show", "traffic", OPT, OPT, NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 rics[] = {
	{ "fib",        "Forward Information Base",
	    { RIPCTL, "show", "fib", OPT, NULL } },
	{ "interfaces", "Interfaces",
	    { RIPCTL, "show", "interfaces", NULL } },
	{ "neighbor",   "Neighbor",
	    { RIPCTL, "show", "neighbor", NULL } },
	{ "rib",        "Routing Information Base",
	    { RIPCTL, "show", "rib", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 lics[] = {
	{ "fib",        "Forward Information Base",
	    { LDPCTL, "show", "fib", OPT, NULL } },
	{ "interfaces", "Interfaces",
	    { LDPCTL, "show", "interfaces", NULL } },
	{ "neighbor",   "Neighbors",
	    { LDPCTL, "show", "neighbor", NULL } },
	{ "lib",        "Label Information Base",
	    { LDPCTL, "show", "lib", NULL } },
	{ "discovery",	"Adjacencies",
	    { LDPCTL, "show", "discovery", NULL } },
	{ "l2vpn",	"Pseudowire",
	    { LDPCTL, "show", "l2vpn", OPT, NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 iscs[] = {
	{ "flows",	"Display IPsec flows",
	    { IPSECCTL, "-sf", NULL } },
	{ "sadb",	"Display SADB",
	    { IPSECCTL, "-ss", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 ikcs[] = {
	{ "monitor",	"Monitor internal iked messages",
	    { IKECTL, "monitor", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 dvcs[] = {
	{ "igmp",       "Internet Group Message Protocol",
	    { DVMRPCTL, "show", "igmp", NULL } },
	{ "interfaces", "Interfaces",
	    { DVMRPCTL, "show", "interfaces", OPT, NULL } },
	{ "mfc",        "Multicast Forwarding Cache",
	    { DVMRPCTL, "show", "mfc", OPT, NULL } },
	{ "neighbor",   "Neighbor",
	    { DVMRPCTL, "show", "neighbor", OPT, NULL } },
	{ "rib",        "Routing Information Base",
	    { DVMRPCTL, "show", "rib", OPT, NULL } },
	{ "summary",    "Summary",
	    { DVMRPCTL, "show", "summary", NULL } },
        { 0, 0, { 0 } }
};

struct prot1 rlcs[] = {
	{ "hosts",      "hosts",
	    { RELAYCTL, "show", "hosts", NULL } },
	{ "redirects",  "redirects",
	    { RELAYCTL, "show", "redirects", NULL } },
	{ "status",     "status",
	    { RELAYCTL, "show", "relays", NULL } },
	{ "sessions",   "sessions",
	    { RELAYCTL, "show", "sessions", NULL } },
	{ "summary",    "summary",
	    { RELAYCTL, "show", "summary", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 smcs[] = {
	{ "queue",	"envelopes in queue",
	    { SMTPCTL, "show", "queue", NULL } },
	{ "runqueue",	"envelopes scheduled for delivery",
	    { SMTPCTL, "show", "runqueue", NULL } },
	{ "stats",	"runtime statistics",
	    { SMTPCTL, "show", "stats", NULL } },
	{ 0, 0, { 0 } }
};

struct prot1 dhcs[] = {
	{ "leases",	"leases", { 0 } },
	{ 0, 0, { 0 } }
};

struct prot1 ldcs[] = {
	{ "stats",	"statistics counters",
	    { LDAPCTL, "stats", NULL } },
	{ 0, 0, { 0 } }
};

extern struct prot1 bgcs[];

/* show yyy zzz */
struct prot prots[] = {
	{ "bgp",	bgcs },
	{ "ospf",	oscs },
	{ "ospf6",	os6cs },
	{ "pf",		pfcs },
	{ "eigrp",	eics },
	{ "rip",	rics },
	{ "ike",	ikcs },
	{ "ipsec",	iscs },
	{ "ldp",	lics },
	{ "dvmrp",	dvcs },
	{ "relay",	rlcs },
	{ "smtp",	smcs },
	{ "ldap",	ldcs },
	{ 0,		0 }
};


/*
 * Quit command
 */

int
quit(void)
{
	if (privexec) {
		exit(NSH_REXEC_EXIT_CODE_QUIT);
	} else {
		if (interactive_mode)
			printf("%% Session terminated.\n");
		exit(0);
	}
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
	{ "crontab",	"Scheduled background jobs",	CMPL0 0, 0, 0, 0, pr_crontab },
	{ "scheduler",	"Scheduled background jobs",	CMPL0 0, 0, 0, 0, pr_crontab },
	{ "running-config",	"Operating configuration", CMPL0 0, 0, 0, 0, pr_conf },
	{ "startup-config", "Startup configuration", CMPL0 0, 0, 0, 0, pr_s_conf },
	{ "active-config", "Configuration of active context", CMPL0 0, 0, 0, 0, pr_a_conf },
	{ "diff-config", "Show differences between startup and running config", CMPL0 0, 0, 0, 0, pr_conf_diff },
	{ "environment", "Show environment variables",	CMPL(e) 0, 0, 0, 1, pr_environment },
	{ "?",		"Options",		CMPL0 0, 0, 0, 0, show_help },
	{ "help",	0,			CMPL0 0, 0, 0, 0, show_help },
	{ 0, 0, 0, 0, 0 }
};

static int
showcmd(int argc, char **argv)
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

	if (strlcpy(outpath, "/tmp/nsh.show.XXXXXXXX", sizeof(outpath)) >=
	    sizeof(outpath))
		return 0;

	outfd = mkstemp(outpath);
	if (outfd == -1) {
		printf("%% mkstemp %s: %s\n", outpath, strerror(errno));
		return 0;
	}

	if (fstat(outfd, &sb) == -1) {
		printf("%% fstat %s: %s\n", outpath, strerror(errno));
		goto done;
	}

	if (s->handler)	{
		FILE *f;
		int fd;

		fd = dup(outfd);
		if (fd == -1) {
			printf("%% dup %s\n", strerror(errno));
			goto done;
		}

		f = fdopen(fd, "w+");
		if (f == NULL) {
			printf("%% dup %s\n", strerror(errno));
			close(fd);
			goto done;
		}
		error = (*s->handler)(argc, argv, f);
		if (fflush(f) == EOF)
			printf("%% fflush %s: %s\n", outpath, strerror(errno));
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
			goto done;
		}
		if (sb.st_size != sb2.st_size ||
		    sb.st_mtim.tv_sec != sb2.st_mtim.tv_sec ||
		    sb.st_mtim.tv_nsec != sb2.st_mtim.tv_nsec)
			more(outpath);
	}
done:
	if (close(outfd) == EOF)
		printf("%% close %s: %s\n", outpath, strerror(errno));
	if (unlink(outpath) == -1)
		printf("%% unlink %s: %s\n", outpath, strerror(errno));
	return(error);
}

/*
 * Data structures and routines for the "ip" command.
 */

struct ghs arptimeouttab[] = {
	{ "<seconds>", "Seconds for ARP entries to remain in cache", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs arpdowntab[] = {
	{ "<seconds>", "Seconds before resending unanswered ARP requests", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs carptab[] = {
	{ "^no ip carp <cr>", "Disallow CARP", CMPL0 NULL, 0 },
	{ "^ip carp <cr>", "Allow CARP", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs carploggingtab[] = {
	{ "0", "CARP logging priority 0", CMPL0 NULL, 0 },
	{ "1", "CARP logging priority 1", CMPL0 NULL, 0 },
	{ "2", "CARP logging priority 2", CMPL0 NULL, 0 },
	{ "3", "CARP logging priority 3", CMPL0 NULL, 0 },
	{ "4", "CARP logging priority 4", CMPL0 NULL, 0 },
	{ "5", "CARP logging priority 5", CMPL0 NULL, 0 },
	{ "6", "CARP logging priority 6", CMPL0 NULL, 0 },
	{ "7", "CARP logging priority 7", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs carppreempttab[] = {
	{ "^no ip carp-preempt <cr>", "Disallow virtual CARP hosts to preempt each other", CMPL0 NULL, 0 },
	{ "^ip carp-preempt <cr>", "Allow virtual CARP hosts to preempt each other", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs forwardingtab[] = {
	{ "^no ip forwarding <cr>", "Disable IPv4 Forwarding", CMPL0 NULL, 0 },
	{ "^ip forwarding <cr>", "Enable IPv4 Forwarding", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs mforwardingtab[] = {
	{ "^no ip mforwarding <cr>", "Disable IPv4 Multicast Forwarding", CMPL0 NULL, 0 },
	{ "^ip mforwarding <cr>", "Enable IPv4 Multicast Forwarding", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipiptab[] = {
	{ "^no ip ipip <cr>", "Disallow IP-in-IP Encapsulation", CMPL0 NULL, 0 },
	{ "^ip ipip <cr>", "Allow IP-in-IP Encapsulation", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs gretab[] = {
	{ "^no ip gre <cr>", "Disallow Generic Routing Encapsulation", CMPL0 NULL, 0 },
	{ "^ip gre <cr>", "Allow Generic Routing Encapsulation", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs wccptab[] = {
	{ "^no ip wccp <cr>", "Disallow Web Cache Control Protocol", CMPL0 NULL, 0 },
	{ "^ip wccp <cr>", "Allow Web Cache Control Protocol", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs etheriptab[] = {
	{ "^no ip etherip <cr>", "Disallow Ether-IP Encapsulation", CMPL0 NULL, 0 },
	{ "^ip etherip <cr>", "Allow Ether-IP Encapsulation", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipcomptab[] = {
	{ "^no ip ipcomp <cr>", "Disallow IP Compression", CMPL0 NULL, 0 },
	{ "^ip ipcomp <cr>", "Allow IP Compression", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs esptab[] = {
	{ "^no ip esp <cr>", "Disallow Encapsulated Security Payload", CMPL0 NULL, 0 },
	{ "^ip esp <cr>", "Allow Encapsulated Security Payload", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs espudpencaptab[] = {
	{ "^no ip esp-udpencap <cr>", "Disallow ESP encapsulation within UDP", CMPL0 NULL, 0 },
	{ "^ip esp-udpencap <cr>", "Allow ESP encapsulation within UDP", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs espudpencapporttab[] = {
	{ "<number>", "UDP port number for encapsulation", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ahtab[] = {
	{ "^no ip ah <cr>", "Disallow Authentication Header", CMPL0 NULL, 0 },
	{ "^ip ah <cr>", "Allow Authentication Header", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs sourceroutetab[] = {
	{ "^no ip sourceroute <cr>", "Disallow Forwarding of Source-Routed Packets", CMPL0 NULL, 0 },
	{ "^ip sourceroute <cr>", "Allow Forwarding of Source-Routed Packets", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs encdebugtab[] = {
	{ "^no ip encdebug <cr>", "Disable enc(4) interface debugging", CMPL0 NULL, 0 },
	{ "^ip encdebug <cr>", "Enable enc(4) interface debugging", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs sendredirectstab[] = {
	{ "^no ip send-redirects <cr>", "Do not send ICMP redirects", CMPL0 NULL, 0 },
	{ "^ip send-redirects <cr>", "Send ICMP redirects", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs directedbroadcaststab[] = {
	{ "^no ip directed-broadcast <cr>", "Disallow directed broadcasts", CMPL0 NULL, 0 },
	{ "^ip directed-broadcast <cr>", "Allow directed broadcasts", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs multipathtab[] = {
	{ "^no ip multipath <cr>", "Disable Multipath Routing", CMPL0 NULL, 0 },
	{ "^ip multipath <cr>", "Enable Multipath Routing", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs maxqueuetab[] = {
	{ "<number>", "Maximum unassembled IP fragments in the fragment queue", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs mtudisctab[] = {
	{ "^no ip mtudisc <cr>", "Disable Path MTU Discovery", CMPL0 NULL, 0 },
	{ "^ip mtudisc <cr>", "Enable Path MTU Discovery", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs mtudisctimeouttab[] = {
	{ "<seconds>", "Timeout in seconds for routes added by Path MTU discovery engine", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipsectimeouttab[] = {
	{ "<seconds>", "Seconds after a SA is established before it will expire", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipsecsofttimeouttab[] = {
	{ "<seconds>", "Seconds after a SA is established before being renegotiated", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipsecallocstab[] = {
	{ "<number>", "Maximum IPSEC flows that can use a SA before it expires", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipsecsoftallocstab[] = {
	{ "<number>", "Maximum IPSEC flows that can use a SA before being renegotiated", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipsecbytestab[] = {
	{ "<number>", "Maximum bytes processed by a security association before it expires", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipsecsoftbytestab[] = {
	{ "<number>", "Maximum bytes processed by a security association before being renegotiated", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipsecexpireacquiretab[] = {
	{ "<seconds>", "Seconds the kernel allows to dynamically acquire SAs before a request", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipsecfirstusetab[] = {
	{ "<seconds>", "Seconds after security association is first used before it expires", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipsecsoftfirstusetab[] = {
	{ "<seconds>", "Seconds after a SA is first used before it is sent for renegotiation", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipsecinvalidlifetab[] = {
	{ "<seconds>", "Lifetime of Embryonic SAs in seconds", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs ipsecpfstab[] = {
	{ "^no ip ipsec-pfs <cr>", "Disable Perfect Forward Secrecy", CMPL0 NULL, 0 },
	{ "^ip ipsec-pfs <cr>", "Enable Perfect Forward Secrecy", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs portfirsttab[] = {
	{ "<number>", "Minimum registered port number for TCP/UDP port allocation", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs porthifirsttab[] = {
	{ "<number>", "Minimum dynamic/private port number for TCP/UDP port allocation", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs porthilasttab[] = {
	{ "<number>", "Maximum dynamic/private port number for TCP/UDP port allocation", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

struct ghs portlasttab[] = {
	{ "<number>", "Maximum registered port number for TCP/UDP port allocation", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

#ifdef notyet
struct ghs defaultmtutab[] = {
	{ "<number>", "Default interface MTU", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};
#endif

struct ghs defaultttltab[] = {
	{ "<number>", "Default IP packet TTL", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

Menu iptab[] = {
	{ "arptimeout",	"Seconds for ARP entries to remain in cache",	CMPL(h) (char **)arptimeouttab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "arpdown",	"Seconds before resending unanswered ARP requests", CMPL(h) (char **)arpdowntab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "carp",	"Allow CARP",			CMPL(h) (char **)carptab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "carp-log",	"CARP Logging Priority",	CMPL(h) (char **)carploggingtab, sizeof(struct ghs), 0, 1, ipsysctl },
	{ "carp-preempt", "CARP Virtual Host Preemption", CMPL(h) (char **)carppreempttab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "forwarding",	"Enable IPv4 Forwarding",	CMPL(h) (char **)forwardingtab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "mforwarding", "Enable IPv4 Multicast Forwarding", CMPL(h) (char **)mforwardingtab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "ipip",	"Allow IP-in-IP Encapsulation", CMPL(h) (char **)ipiptab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "gre",	"Allow Generic Route Encapsulation", CMPL(h) (char **)gretab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "wccp",	"Allow Web Cache Control Protocol", CMPL(h) (char **)wccptab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "etherip",	"Allow Ether-IP Encapsulation",	CMPL(h) (char **)etheriptab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "ipcomp",	"Allow IP Compression",		CMPL(h) (char **)ipcomptab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "esp",	"Allow Encapsulated Security Payload", CMPL(h) (char **)esptab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "esp-udpencap","Allow ESP encapsulation within UDP", CMPL(h) (char **)espudpencaptab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "esp-udpencap-port","UDP port number for encapsulation", CMPL(h) (char **)espudpencapporttab, sizeof(struct ghs), 0, 1, ipsysctl },
	{ "ah",		"Allow Authentication Header",	CMPL(h) (char**)ahtab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "sourceroute", "Process Loose/Strict Source Route Options", CMPL(h) (char**)sourceroutetab, sizeof(struct ghs), 0, 1, ipsysctl },
	{ "encdebug",	"Enable if_enc debugging",	CMPL(h) (char **)encdebugtab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "send-redirects", "Send ICMP redirects",	CMPL(h) (char **)sendredirectstab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "directed-broadcast", "Allow directed broadcasts", CMPL(h) (char **)directedbroadcaststab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "multipath",	"Multipath routing",		CMPL(h) (char **)multipathtab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "maxqueue", "Maximum unassembled IP fragments in the fragment queue", CMPL(h) (char **)maxqueuetab, sizeof(struct ghs), 1, 1, ipsysctl  },
	{ "mtudisc", "Enable Path MTU Discovery",       CMPL(h) (char **)mtudisctab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "mtudisctimeout", "Timeout in seconds for routes added by Path MTU discovery engine", CMPL(h) (char **)mtudisctimeouttab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "ipsec-timeout", "Seconds after a SA is established before it will expire", CMPL(h) (char **)ipsectimeouttab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "ipsec-soft-timeout", "Seconds after a SA is established before being renegotiated", CMPL(h) (char **)ipsecsofttimeouttab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "ipsec-allocs", "Maximum IPSEC flows that can use a SA before it expires", CMPL(h) (char **)ipsecallocstab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "ipsec-soft-allocs", "Maximum IPSEC flows a SA uses before renegotiation", CMPL(h) (char **)ipsecsoftallocstab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "ipsec-bytes", "Maximum bytes processed by a security association before it expires", CMPL(h) (char **)ipsecbytestab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "ipsec-soft-bytes", "Maximum bytes a SA processes before renegotiation", CMPL(h) (char **)ipsecsoftbytestab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "ipsec-expire-acquire", "Seconds the kernel allows to dynamically acquire SAs before a request", CMPL(h) (char **)ipsecexpireacquiretab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "ipsec-firstuse", "Seconds after security association is first used before it expires", CMPL(h) (char **)ipsecfirstusetab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "ipsec-soft-firstuse", "Seconds after a SA is first used before it is sent for renegotiation", CMPL(h) (char **)ipsecsoftfirstusetab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "ipsec-invalid-life", "Lifetime of Embryonic SAs in seconds", CMPL(h) (char **)ipsecinvalidlifetab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "ipsec-pfs", "Enables Perfect Forward Secrecy when establishing SAs", CMPL(h) (char **)ipsecpfstab, sizeof(struct ghs), 0, 0, ipsysctl },
	{ "portfirst", "Minimum registered port number for TCP/UDP port allocation", CMPL(h) (char **)portfirsttab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "porthifirst", "Minimum dynamic/private port number for TCP/UDP port allocation", CMPL(h) (char **)porthifirsttab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "porthilast", "Maximum dynamic/private port number for TCP/UDP port allocation", CMPL(h) (char **)porthilasttab, sizeof(struct ghs), 1, 1, ipsysctl },
	{ "portlast", "Maximum registered port number for TCP/UDP port allocation", CMPL(h) (char **)portlasttab, sizeof(struct ghs), 1, 1, ipsysctl },
#ifdef notyet
	{ "default-mtu", "Default interface MTU",	CMPL(h) (char **)defaultmtutab, sizeof(struct ghs), 1, 1, ipsysctl },
#endif
	{ "default-ttl", "Default IP packet TTL",	CMPL(h) (char **)defaultttltab, sizeof(struct ghs), 1, 1, ipsysctl },
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
static char crontabhelp[];
static char showhelp[];
static char whohelp[];
static char dohelp[];
static char setenvhelp[];
static char unsetenvhelp[];
static char saveenvhelp[];
static char verbosehelp[];
static char editinghelp[];
static char shellhelp[];
static char manhelp[];
extern struct ghs mantab[];

struct intlist Intlist[] = {
/* Interface mode commands */
	{ "inet",	"IPv4/IPv6 addresses",			CMPL(h) (char **)intiphelp, sizeof(struct ghs), intip, 1 },
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
	{ "do",		dohelp,					CMPL(c) 0, 0, int_do, 0 },
	{ "setenv",	setenvhelp,				CMPL(e) 0, 0, int_setenv, 0 },
	{ "unsetenv",	unsetenvhelp,				CMPL(e) 0, 0, int_unsetenv, 0 },
	{ "saveenv",	saveenvhelp,				CMPL0 0, 0, int_saveenv, 0 },
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
	{ "apn",	"Access Point Name",			CMPL0 0, 0, intumb, 1 },
	{ "setpin",	"Set SIM card PIN",			CMPL0 0, 0, intumb, 1 },
	{ "setpuk",	"Set new SIM card PIN using PUK for validation", CMPL0 0, 0, intumb, 0 },
	{ "chgpin",	"Permanently change SIM PIN",		CMPL0 0, 0, intumb, 0 },
	{ "class",	"Preferred cell classes",		CMPL0 0, 0, intumb, 1 },
	{ "roaming",	"Enable data roaming",			CMPL0 0, 0, intumb, 1 },
	{ "shutdown",   "Shutdown interface",			CMPL0 0, 0, intflags, 1 },
	{ "show",	showhelp,				CMPL(ta) (char **)showlist, sizeof(Menu), int_show, 0 },
	{ "who",	whohelp,				CMPL0 0, 0, int_who, 0 },
	{ "verbose",	verbosehelp,				CMPL0 0, 0, int_doverbose, 1 },
	{ "editing",	editinghelp,				CMPL0 0, 0, int_doediting, 1 },
	{ "!",		shellhelp,				CMPL0 0, 0, int_shell, 0 },
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
	{ "do",		dohelp,					CMPL(c) 0, 0, int_do, 0 },
	{ "setenv",	setenvhelp,				CMPL(e) 0, 0, int_setenv, 0 },
	{ "unsetenv",	unsetenvhelp,				CMPL(e) 0, 0, int_unsetenv, 0 },
	{ "saveenv",	saveenvhelp,				CMPL0 0, 0, int_saveenv, 0 },
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
	{ "who",	whohelp,				CMPL0 0, 0, int_who, 0 },
	{ "verbose",	verbosehelp,				CMPL0 0, 0, int_doverbose, 1 },
	{ "editing",	editinghelp,				CMPL0 0, 0, int_doediting, 1 },
	{ "!",		shellhelp,				CMPL0 0, 0, int_shell, 0 },

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
 *
 * While this function is active the global ifname buffer contains the
 * name of the interface being configured.
 * Ensure that the ifname buffer gets cleared on exit. This allows nested
 * commands to tell whether a interface/bridge context is active, and which
 * interface/bridge is being configured.
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

	strlcpy(ifname, tmp, IFNAMSIZ);
	if (ifunit) {
		const char *errstr;
		size_t len = strlen(ifname);
		strtonum(ifunit, 0, INT_MAX, &errstr);
		if (errstr) {
			printf("%% interface unit %s is %s\n", ifunit, errstr);
			ifname[0] = '\0';
			return(1);
		}
		if (len > 0 && isdigit((unsigned char)(ifname[len - 1]))) {
			printf("%% interface unit %s is redundant\n", ifunit);
			ifname[0] = '\0';
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
		ifname[0] = '\0';
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
			ifname[0] = '\0';
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
		ifname[0] = '\0';
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
		if (argv[0] == 0) {
			ifname[0] = '\0';
			return(0);
		}
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

		ifname[0] = '\0';
		return(0);
	}

	/* human at the keyboard or commands on stdin */
	for (;;) {
		char *margp;

		if (!editing) {
			/* command line editing disabled */
			if (interactive_mode)
				printf("%s", iprompt());
			if (fgets(line, sizeof(line), stdin) == NULL) {
				if (feof(stdin) || ferror(stdin)) {
					if (interactive_mode)
						printf("\n");
					ifname[0] = '\0';
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
				ifname[0] = '\0';
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

	ifname[0] = '\0';
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
int_do(char *ifname, int ifs, int argc, char **argv)
{
	docmd(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_setenv(char *ifname, int ifs, int argc, char **argv)
{
	setenvcmd(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_unsetenv(char *ifname, int ifs, int argc, char **argv)
{
	unsetenvcmd(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_saveenv(char *ifname, int ifs, int argc, char **argv)
{
	saveenvcmd(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_show(char *ifname, int ifs, int argc, char **argv)
{
	showcmd(argc, argv);
	return 0; /* do not leave interface context */
}

static int
int_who(char *ifname, int ifs, int argc, char **argv)
{
	who(argc, argv);
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
int_shell(char *ifname, int ifs, int argc, char **argv)
{
	shell(argc, argv);
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
	crontabhelp[] =	"Configure scheduled background jobs",
	quithelp[] =	"Close current connection",
	exithelp[] =	"Leave configuration mode and return to privileged mode",
	verbosehelp[] =	"Set verbose diagnostics",
	editinghelp[] = "Set command line editing",
	confighelp[] =	"Set configuration mode",
	whohelp[] =	"Display system users",
	dohelp[] =	"Superfluous, do is ignored and its arguments executed",
	setenvhelp[] =	"Set an environment variable",
	unsetenvhelp[] ="Delete an environment variable",
	saveenvhelp[] =	"Save environment variables set by setenv to ~/.nshenv",
	shellhelp[] =	"Invoke a subshell",
	savehelp[] =	"Save the current configuration",
	nreboothelp[] =	"Reboot the system",
	halthelp[] =	"Halt the system",
	powerdownhelp[] ="Power the system down",
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
	{ "<table id>", "Switch to the given rtable", CMPL0 NULL, 0 },
	{ "<table id> [name]", "Create the given rtable", CMPL0 NULL, 0 },
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

/*
 * Primary commands, will be included in help output
 */

#define ssctl sizeof(struct ctl)
#define ssctl2 sizeof(struct ctl2)
Command cmdtab[] = {
	{ "hostname",	hostnamehelp,	CMPL0 0, 0, hostname,		1, 1, 0, 0 },
	{ "interface",	interfacehelp,	CMPL(i) 0, 0, interface,	1, 1, 1, 1 },
	{ "rtable",	rtablehelp,	CMPL(rh) (char **)rtabletab, sizeof(struct ghs), rtable,	0, 0, 1, 2 },
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
	{ "dhcp",	dhcphelp,	CMPL(t) (char **)ctl_dhcp, ssctl2, ctlhandler,	1, 1, 0, 1 },
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
	{ "crontab",    crontabhelp,    CMPL(t) (char **)ctl_crontab, ssctl, ctlhandler,    1, 1, 0, 1 },
	{ "scheduler",  crontabhelp,    CMPL(t) (char **)ctl_crontab, ssctl, ctlhandler,    1, 1, 0, 1 },
	{ "inet",	inethelp,	CMPL(t) (char **)ctl_inet, ssctl, ctlhandler,	1, 1, 0, 1 },
	{ "ping",	pinghelp,	CMPL0 0, 0, ping,		0, 0, 0, 0 },
	{ "ping6",	ping6help,	CMPL0 0, 0, ping6,		0, 0, 0, 0 },
	{ "traceroute", tracerthelp,	CMPL0 0, 0, traceroute,		0, 0, 0, 0 },
	{ "traceroute6", tracert6help,  CMPL0 0, 0, traceroute6,	 0, 0, 0, 0 },
	{ "ssh",	sshhelp,	CMPL0 0, 0, ssh,		0, 0, 0, 0 },
	{ "telnet",	telnethelp,	CMPL0 0, 0, telnet,		0, 0, 0, 0 },
	{ "reboot",	nreboothelp,	CMPL0 0, 0, nreboot,		1, 0, 0, 0 },
	{ "halt",	halthelp,	CMPL0 0, 0, halt,		1, 0, 0, 0 },
	{ "powerdown",	powerdownhelp,	CMPL0 0, 0, powerdown,		1, 0, 0, 0 },
	{ "write-config", savehelp,	CMPL0 0, 0, wr_startup,		1, 0, 0, 0 },
	{ "verbose",	verbosehelp,	CMPL0 0, 0, doverbose,		0, 0, 1, 0 },
	{ "editing",	editinghelp,	CMPL0 0, 0, doediting,		0, 0, 1, 0 },
	{ "configure",	confighelp,	CMPL0 0, 0, doconfig,		1, 0, 1, 0 },
	{ "who",	whohelp,	CMPL0 0, 0, who,		0, 0, 0, 0 },
	{ "no",		0,		CMPL(c) 0, 0, nocmd,		0, 0, 0, 0 },
	{ "do",		dohelp,		CMPL(c) 0, 0, docmd,		0, 0, 0, 0 },
	{ "setenv",	setenvhelp,	CMPL(E) 0, 0, setenvcmd,	0, 0, 0, 0 },
	{ "unsetenv",	unsetenvhelp,	CMPL(e) 0, 0, unsetenvcmd,	0, 0, 0, 0 },
	{ "saveenv",	saveenvhelp,	CMPL0 0, 0, saveenvcmd,		0, 0, 0, 0 },
	{ "!",		shellhelp,	CMPL0 0, 0, shell,		1, 0, 0, 0 },
	{ "?",		helphelp,	CMPL(c) 0, 0, help,		0, 0, 0, 0 },
	{ "manual",	manhelp,	CMPL(H) (char **)mantab, sizeof(struct ghs), manual,0, 0, 0, 0 },
	{ "exit",	exithelp,	CMPL0 0, 0, exitconfig,		1, 0, 0, 0 },
	{ "quit",	quithelp,	CMPL0 0, 0, quit,		0, 0, 0, 0 },
	{ "help",	0,		CMPL(c) 0, 0, help,		0, 0, 0, 0 },
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
command()
{
	Command  *c;
	u_int num;

	init_bgpd_socket_path(getrtable());

	if (editing) {
		inithist();
		initedit();
	}

	for (;;) {
		if (!editing) {
			if (interactive_mode)
				printf("%s", cprompt());
			if (fgets(line, sizeof(line), stdin) == NULL) {
				if (feof(stdin) || ferror(stdin)) {
					if (interactive_mode)
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
 * "do" command
 * This is a pseudo command which exists for people used to routers and
 * switches which offer a "do" command for context switching.
 */
static int
docmd(int argc, char **argv)
{
	Command *c;

	if (argc < 2) {
		printf("%% command name not provided\n");
		return 0;
	}

	argv++;
	argc--;

	if (NO_ARG(argv[0])) {
		printf("%% 'no' commands are not supported with 'do'\n");
		return 0;
	}

	c = getcmd(argv[0]);
	if (Ambiguous(c))
		printf("%% Ambiguous command %s\n", argv[0]);
	else if (c == NULL)
		printf("%% Invalid command %s\n", argv[0]);
	else
		return (*c->handler)(argc, argv, 0);

	return 0;
}

static void
usage_setenv(void)
{
	printf("%% setenv NAME=VALUE\n");
	printf("%% setenv NAME=\"VALUE with spaces\"\n");
	printf("%% setenv \"NAME with spaces\"=VALUE\n");
}

static int
setenvcmd(int argc, char **argv)
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
			return 0;
		}
	}

	name = strdup(argv[1]);
	if (name == NULL) {
		printf("%% setenvcmd: strndup: %s\n", strerror(errno));
		return 0;
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

static int
unsetenvcmd(int argc, char **argv)
{
	char *name;
	void *name0;

	if (argc != 2) {
		printf("%% unsetenv NAME\n");
		return 0;
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

static int
saveenvcmd(int argc, char **argv)
{
	char tmppath[PATH_MAX], path[PATH_MAX];
	FILE *f;
	char *home;
	int ret, fd;

	if (argc != 1) {
		printf("%% usage: saveenv\n");
		return 0;
	}

	if (nsh_env == NULL)
		return 0;

	home = getenv("HOME");
	if (home == NULL) {
		printf("%% cannot find home directory; HOME is not set!\n");
		return 0;
	}

	ret = snprintf(path, sizeof(path), "%s/.nshenv", home);
	if (ret < 0 || (size_t)ret >= sizeof(path)) {
		printf("%% path to ~/.nshenv is too long\n");
		return 0;
	}

	ret = snprintf(tmppath, sizeof(tmppath), "%s/.nshenv-XXXXXXXXXX", home);
	if (ret < 0 || (size_t)ret >= sizeof(tmppath)) {
		printf("%% path to ~/.nshenv is too long\n");
		return 0;
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
		return 0;
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
	if (!set) {
		if (!found) {
			printf("%% rtable %d does not exist in database\n",
			    table);
			return 1;
		} else if (table == 0) {
			printf("%% cannot remove rtable %d\n", table);
			return 1;
		}
	} else if (table == 0)  {
		/* Do not add the kernel's default rtable 0 to the database. */
		cli_rtable = 0;
		return 0;
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
 * disable privileged mode
 */
int
disable(void)
{
	if (privexec) {
		exit(0);
		return 0;
	}
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

	init_bgpd_socket_path(getrtable());

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
	int success = 1;

	if ((rchandle = fopen(fname, "w")) == NULL)
		success = 0;
	else {
		fchmod(fileno(rchandle), 0640);
		conf(rchandle);
		fclose(rchandle);
	}

	return (success);
}

static int
conf_has_unsaved_changes(void)
{
	int conf_fd = -1, nshrc_fd = -1;
	char confpath[PATH_MAX];
	char buf1[8192];
	char buf2[8192];
	int ret = -1;

	if (priv != 1) {
		printf("%% Privilege required\n");
		return -1;
	}

	if (getuid() != 0) {
		printf("%% Root privileges required\n");
		return -1;
	}

	if (strlcpy(confpath, "/tmp/nshrc.XXXXXXXX", sizeof(confpath)) >=
	    sizeof(confpath))
		return -1;

	conf_fd = mkstemp(confpath);
	if (conf_fd == -1) {
		printf("%% mkstemp %s: %s\n", confpath, strerror(errno));
		return -1;
	}

	if (!wr_conf(confpath)) {
		printf("%% Couldn't generate configuration\n");
		goto done;
	}

	nshrc_fd = open(NSHRC, O_RDONLY);
	if (nshrc_fd == -1){
		if (errno == ENOENT)
			ret = 1;
		else
			printf("%% open %s: %s\n", NSHRC, strerror(errno));
		goto done;
	}

	lseek(conf_fd, 0, SEEK_SET);

	for (;;) {
		ssize_t r1, r2;

		r1 = read(nshrc_fd, buf1, sizeof(buf1));
		if (r1 == -1) {
			printf("%% read %s: %s\n", NSHRC, strerror(errno));
			goto done;
		}

		r2 = read(conf_fd, buf2, sizeof(buf2));
		if (r2 == -1) {
			printf("%% read %s: %s\n", confpath, strerror(errno));
			goto done;
		}

		if (r1 == 0 && r2 == 0) {
			ret = 0;
			break;
		} else if (r1 != r2 || memcmp(buf1, buf2, r1) != 0) {
			ret = 1;
			break;
		}
	}
done:
	if (conf_fd != -1) {
		unlink(confpath);
		close(conf_fd);
	}
	if (nshrc_fd != -1)
		close(nshrc_fd);
	return ret;
}

static int
do_reboot(int how)
{
	const char *buf;
	int ret = 0, num, have_changes;
	char *argv[3] = { REBOOT, NULL, NULL };

	have_changes = conf_has_unsaved_changes();
	if (have_changes == -1)
		return -1;
	else if (have_changes) {
		printf("%% WARNING: The running configuration contains "
		    "unsaved changes!\n"
		    "%% The 'show diff-config' command will display unsaved "
		    "changes.\n"
		    "%% The 'write-config' command will save changes to %s.\n",
		    NSHRC);
		if (!interactive_mode)
			return -1;
	}

	if (!interactive_mode) {
		if (cmdargs(argv[0], argv) != 0)
			printf("%% %s command failed\n", argv[0]);
		return 0;
	}

	switch (how) {
	case RB_AUTOBOOT:
		setprompt("Proceed with reboot? [yes/no] ");
		break;
	case RB_HALT:
		argv[0] = HALT;
		setprompt("Proceed with shutdown? [yes/no] ");
		break;
	case RB_POWERDOWN:
		argv[0] = HALT;
		argv[1] = "-p";
		setprompt("Proceed with powerdown? [yes/no] ");
		break;
	default:
		printf("%% Invalid reboot parameter 0x%x\n", how);
		return 0;
	}

	for (;;) {
		if ((buf = el_gets(elp, &num)) == NULL) {
			if (num == -1) {
				ret = -1;
				goto done;
			}
			/* EOF, e.g. ^X or ^D via exit_i() in complete.c */
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

	if (cmdargs(argv[0], argv) != 0)
		printf("%% %s command failed\n", argv[0]);
done:
	restoreprompt();
	return ret;
}

/*
 * Reboot
 */
int
nreboot(void)
{
	return do_reboot(RB_AUTOBOOT);
}

int
halt(void)
{
	return do_reboot(RB_HALT);
}

int
powerdown(void)
{
	return do_reboot(RB_POWERDOWN);
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

/*
 * Show running-config for the active context.
 * Currently only supports the interface/bridge context.
 */
int
pr_a_conf(int argc, char **argv)
{
	if (priv != 1) {
		printf ("%% Privilege required\n");
		return(0);
	}

	if (ifname[0] == '\0') {
		printf ("%% Interface or Bridge context required\n");
		return(0);
	}

	conf_interfaces(stdout, ifname, 1);
	return(0);
}

/*
 * Show differences between startup and running config.
 */
int
pr_conf_diff(int argc, char **argv)
{
	int conf_fd = -1, diff_fd = -1;
	char confpath[PATH_MAX];
	char diffpath[PATH_MAX];
	char *diff_argv[9] = {
	    DIFF, "-u", "-L", NULL, "-L", NULL, NULL, NULL, NULL
	};

	if (priv != 1) {
		printf("%% Privilege required\n");
		return 0;
	}

	if (getuid() != 0) {
		printf("%% Root privileges required\n");
		return 0;
	}

	if (strlcpy(confpath, "/tmp/nshrc.XXXXXXXX", sizeof(confpath)) >=
	    sizeof(confpath))
		return 0;
	if (strlcpy(diffpath, "/tmp/nshrc.diff.XXXXXXXX", sizeof(diffpath)) >=
	    sizeof(diffpath))
		return 0;

	conf_fd = mkstemp(confpath);
	if (conf_fd == -1) {
		printf("%% mkstemp %s: %s\n", confpath, strerror(errno));
		return 0;
	}

	diff_fd = mkstemp(diffpath);
	if (diff_fd == -1) {
		printf("%% mkstemp %s: %s\n", diffpath, strerror(errno));
		goto done;
	}

	if (!wr_conf(confpath)) {
		printf("%% Couldn't generate configuration\n");
		goto done;
	}

	diff_argv[3] = "startup-config";
	diff_argv[5] = "running-config";
	if (access(NSHRC, R_OK) == -1) {
		if (errno != ENOENT) {
			printf("%% access %s: %s\n", NSHRC, strerror(errno));
			goto done;
		}
		diff_argv[6] = "/dev/null";
	} else
		diff_argv[6] = NSHRC;
	diff_argv[7] = confpath;

	if (cmdargs_output(DIFF, diff_argv, diff_fd, -1) > 1)
		printf("%% %s command failed\n", DIFF);

	more(diffpath);
done:
	if (diff_fd != -1) {
		unlink(diffpath);
		close(diff_fd);
	}
	if (conf_fd != -1) {
		unlink(confpath);
		close(conf_fd);
	}
	return 0;
}

static int
pr_crontab(int argc, char **argv, FILE *outfile)
{
	char *crontab_argv[] = { CRONTAB, "-l", "-u", "root", NULL };

	if (priv != 1) {
		printf("%% Privilege required\n");
		return 0 ;
	}

	fprintf(outfile, "%% To view crontab syntax documentation in NSH, "
	    "run: !man 5 crontab\n\n");
	fflush(outfile);

	if (cmdargs_output(CRONTAB, crontab_argv, fileno(outfile), -1) != 0)
		printf("%% crontab command failed\n");

	return 0;
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

static int
envcmp(const void *item1, const void *item2)
{
	const char *a = *(const char **)item1;
	const char *b = *(const char **)item2;

	return strcmp(a, b);
}

static int
pr_environment(int argc, char **argv)
{
	extern char **environ;
	char **ep;
	int fd;
	char path[PATH_MAX];

	if (strlcpy(path, "/tmp/nshrc.env.XXXXXXXX", sizeof(path)) >=
	    sizeof(path))
		return 0;

	fd = mkstemp(path);
	if (fd == -1) {
		printf("%% mkstemp %s: %s\n", path, strerror(errno));
		return 0;
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
	}

	fsync(fd);

	more(path);
done:
	unlink(path);
	close(fd);
	return 0;
}
