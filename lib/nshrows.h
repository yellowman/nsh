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
 * The rows and the help of nsh's own commands. nsh runs each show by
 * its row's handler, and includes this file with RUNS(f) as f
 * (nshcmds.c). nshd sends the rows to a client that completes lines,
 * and runs none of them: it includes this file with RUNS(f) as NULL
 * (nshd's commands.c).
 */

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
	{ "hostname",	"Router hostname",	CMPL0 0, 0, 0, 0, RUNS(show_hostname) },
	{ "interface",	"Interface config",	CMPL(i) 0, 0, 0, 2, RUNS(show_int) },
	{ "autoconf",	"IPv4/IPv6 autoconf state", CMPL(i) 0, 0, 0, 1, RUNS(show_autoconf) },
	{ "ip",		"IP address information", CMPL0 0, 0, 0, 0, RUNS(show_ip) },
	{ "inet",	"IPv4 address information", CMPL0 0, 0, 0, 0, RUNS(show_ip) },
	{ "inet6",	"IPv6 address information", CMPL0 0, 0, 0, 0, RUNS(show_ip) },
	{ "route",	"IPv4 route table or route lookup", CMPL(h) (char **)showroutetab, sizeof(struct ghs), 0, 1, RUNS(pr_routes) },
	{ "route6",	"IPv6 route table or route lookup", CMPL(h) (char **)showroutetab, sizeof(struct ghs), 0, 1, RUNS(pr_routes6) },
	{ "sadb",	"Security Association Database", CMPL0 0, 0, 0, 0, RUNS(pr_sadb) },
	{ "arp",	"ARP table",		CMPL(h) (char **)showarptab, sizeof(struct ghs), 0, 1, RUNS(pr_arp) },
	{ "ndp",	"NDP table",		CMPL(h) (char **)showndptab, sizeof(struct ghs), 0, 1, RUNS(pr_ndp) },
	{ "vlan",	"802.1Q/802.1ad VLANs",	CMPL(h) (char **)showvlantab, sizeof(struct ghs), 0, 2, RUNS(show_vlans) },
	{ "bridge",	"Ethernet bridges",	CMPL(b) 0, 0, 0, 1, RUNS(show_bridges) },
	{ "kernel",	"Kernel statistics",	CMPL(ta) (char **)stts, sizeof(struct stt), 0, 1, RUNS(pr_kernel) },
	{ "bgp",	"BGP information",	CMPL(ta) (char **)bgcs, sizeof(struct prot1), 0, 4, RUNS(pr_prot1) },
	{ "ospf",	"OSPF information",	CMPL(ta) (char **)oscs, sizeof(struct prot1), 0, 3, RUNS(pr_prot1) },
	{ "ospf6",	"OSPF6 information",	CMPL(ta) (char **)os6cs, sizeof(struct prot1), 0, 3, RUNS(pr_prot1) },
	{ "pf",		"Packet Filter firewall information", CMPL(ta) (char **)pfcs, sizeof(struct prot1), 0, 3, RUNS(pr_prot1) },
	{ "eigrp",	"EIGRP information",	CMPL(ta) (char **)eics, sizeof(struct prot1), 0, 3, RUNS(pr_prot1) },
	{ "rip",	"RIP information",	CMPL(ta) (char **)rics, sizeof(struct prot1), 0, 3, RUNS(pr_prot1) },
	{ "ldp",	"LDP information",	CMPL(ta) (char **)lics, sizeof(struct prot1), 0, 3, RUNS(pr_prot1) },
	{ "ike",	"IKE information",	CMPL(ta) (char **)ikcs, sizeof(struct prot1), 0, 3, RUNS(pr_prot1) },
	{ "ipsec",	"IPsec information",	CMPL(ta) (char **)iscs, sizeof(struct prot1), 0, 1, RUNS(pr_prot1) },
	{ "dvmrp",	"DVMRP information",	CMPL(ta) (char **)dvcs, sizeof(struct prot1), 0, 2, RUNS(pr_prot1) },
	{ "relay",	"Relay server",		CMPL(ta) (char **)rlcs, sizeof(struct prot1), 0, 1, RUNS(pr_prot1) },
	{ "dhcp",	"DHCP server",		CMPL(ta) (char **)dhcs, sizeof(struct prot1), 0, 1, RUNS(pr_dhcp) },
	{ "smtp",	"SMTP server",		CMPL(ta) (char **)smcs, sizeof(struct prot1), 0, 1, RUNS(pr_prot1) },
	{ "ldap",	"LDAP server",		CMPL(ta) (char **)ldcs, sizeof(struct prot1), 0, 1, RUNS(pr_prot1) },
	{ "monitor",	"Monitor routing/arp table changes", CMPL0 0, 0, 0, 0, RUNS(monitor) },
	{ "log",	"Follow daemon, messages, authlog or pflog, until ^C", CMPL0 0, 0, 1, 1, RUNS(show_log) },
	{ "system-stats",	"System, firewall and kernel statistics", CMPL(ta) (char **)systatcs, sizeof(struct prot1), 0, 3, RUNS(pr_prot1) },
	{ "version",	"Software information",	CMPL0 0, 0, 0, 0, RUNS(version) },
	{ "users",	"System users",		CMPL0 0, 0, 0, 0, RUNS(who) },
	{ "daemons",	"Daemons, and whether each runs",	CMPL0 0, 0, 0, 0, RUNS(pr_daemons) },
	{ "crontab",	"Scheduled background jobs",	CMPL0 0, 0, 0, 0, RUNS(pr_crontab) },
	{ "scheduler",	"Scheduled background jobs",	CMPL0 0, 0, 0, 0, RUNS(pr_crontab) },
	{ "running-config",	"Operating configuration", CMPL0 0, 0, 0, 0, RUNS(pr_conf) },
	{ "startup-config", "Startup configuration", CMPL0 0, 0, 0, 0, RUNS(pr_s_conf) },
	{ "active-config", "Configuration of active context", CMPL0 0, 0, 0, 0, RUNS(pr_a_conf) },
	{ "diff-config", "Show differences between startup and running config, or running and candidate", CMPL0 0, 0, 0, 0, RUNS(pr_conf_diff) },
	{ "candidate-config", "Candidate configuration", CMPL0 0, 0, 0, 0, RUNS(pr_cand_conf) },
	{ "rollback",	"Configurations saved, one of them, or what it changed", CMPL0 0, 0, 0, 2, RUNS(pr_rollback) },
	{ "environment", "Show environment variables",	CMPL(e) 0, 0, 0, 1, RUNS(pr_environment) },
	{ "?",		"Options",		CMPL0 0, 0, 0, 0, RUNS(show_help) },
	{ "help",	0,			CMPL0 0, 0, 0, 0, RUNS(show_help) },
	{ 0, 0, 0, 0, 0 }
};
