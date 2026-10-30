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
#include <arpa/inet.h>
#include <limits.h>
#include <util.h>
#include <pwd.h>
#include "editing.h"
#include "stringlist.h"
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

char hname[HSIZE];
char next_ifname[IFNAMSIZ];	/* switch interfaces in interface context */
struct intlist *whichlist;

static int in_rc;		/* a commit's edits run */
static int rc_head;		/* and this one is a block's head */
static int oneline;		/* run by cmdline(); a mode stays entered */
static struct cnode *snapshot;	/* config's running configuration */

/* globals of this file each session has a copy of (session.c) */
struct sglobal commands_sglobals[] = {
	SGLOBAL(hname), SGLOBAL(ifname), SGLOBAL(next_ifname),
	SGLOBAL(whichlist), SGLOBAL(in_rc), SGLOBAL(rc_head),
	{ NULL }
};

extern volatile sig_atomic_t caught_sigwinch;

static int	doconfig(int, char**, ...);
static int	exitconfig(int, char **, ...);
static int	rtable(int, char**, ...);
static int	conf_run_if(int, const struct confcmd *, int, char **,
		    char *);
static int	cand_leave(void);
static int	cmdline_if(void);
static int	wr_conf(char *);
static int	sysctlhelp(int, char **, ...);
static int	flush_pf(int, char **, ...);
static int	flush_help(int, char **, ...);
static int	flush_line(int, char **, ...);
static int	flush_ip_routes(int, char **, ...);
static int	flush_arp_cache(int, char **, ...);
static int	flush_ndp_cache(int, char **, ...);
static int	flush_run(int, char **);
static Menu	*flush_find(char *);
static int	int_op(int, char **, ...);
static struct intlist *int_op_find(int, char **);
static int	is_bad_input(const char *, size_t);
static int	read_command_line(EditLine *, History *);
static int	int_exit(int, char **, ...);
static int	hostname(int, char **, ...);
static int	interface(int, char **, ...);
static int	int_interface(int, char **, ...);

static struct fpf {
	char *name;
	char *help;
	char *cmd;
	char *arg;
} fpfs[] = {
	{ "all",            "all PF elements",	        PFCTL,  "-Fall" },
	{ "filter",         "filter rules",		PFCTL,  "-Frules" },
	{ "os-fingerprint", "passive OS detection fingerprints",  PFCTL,  "-Fosfp" },
	{ "reset",          "limits, timeouts and options",       PFCTL,  "-FReset" },
	{ "source-table",   "source tracking table",    PFCTL,  "-FSources" },
	{ "states",         "NAT/filter states",	PFCTL,  "-Fstate" },
	{ "stats",          "info and stats",	        PFCTL,  "-Finfo" },
	{ "tables",         "PF address tables",	PFCTL,  "-FTables" },
	{ 0, 0, 0, 0 }
};

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
	{ "carp-log",	"CARP Logging Priority",	CMPL(h) (char **)carploggingtab, sizeof(struct ghs), 1, 1, ipsysctl },
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
	{ "esp-udpencap-port","UDP port number for encapsulation", CMPL(h) (char **)espudpencapporttab, sizeof(struct ghs), 1, 1, ipsysctl },
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
	{ "dad_count", "Configures the number of IPv6 D.A.D. probe packets", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "defmcasthlim", "The default hop limit value for an IPv6 multicast packet sourced by the system", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "forwarding", "Enable IPv6 Forwarding",       CMPL0 0, 0, 0, 0, ipsysctl },
	{ "hdrnestlimit", "The number of IPv6 extension headers permitted on incoming IPv6 packets", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "hoplimit", "The default hop limit for IPv6 unicast packet sourced by the system", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "log_interval", "Configures the amount of logs generated by the IPv6 packet forwarding engine", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "maxdynroutes", "Max IPv6 Dyn Routes",        CMPL0 0, 0, 1, 1, ipsysctl },
	{ "maxfragpackets", "The maximum number of fragmented packets the system will accept", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "maxfrags", "The maximum number of fragments the node will accept", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "mforwarding", "Enable IPv6 Multicast Forwarding", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "mtudisctimeout", "Seconds after which a route added by the Path MTU Discovery engine will time out", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "multicast_mtudisc", "Enables ICMPv6 too big messages when machine is an IPv6 multicast router", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "multipath",  "Multipath routing",            CMPL0 0, 0, 0, 0, ipsysctl },
	{ "neighborgcthresh", "Maximum number of entries in neighbor cache", CMPL0 0, 0, 1, 1, ipsysctl },
	{ "send-redirect", "Enables sending ICMPv6 redirects by the system", CMPL0 0, 0, 0, 0, ipsysctl },
	{ "?",          "Help",                         CMPL0 0, 0, 0, 0, sysctlhelp },
	{ 0, 0, 0, 0, 0, 0, 0, 0 }
};

Menu mplstab[] = {
	{ "ttl",	"MPLS ttl",			CMPL0 0, 0, 1, 1, ipsysctl },
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
ipcmd(int argc, char **argv, ...)
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
                return -1;
        } else if (Ambiguous(stab)) {
                printf("%% Ambiguous argument %s\n", argv[0]);
                return -1;
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
		return -1;
	} else if (Ambiguous(i)) {
		printf("%% Ambiguous argument %s\n", argv[1]);
		return -1;
	}
	if (((i->minarg + 2) > argc) || ((i->maxarg + 2) < argc)) {
		printf("%% Wrong argument%s to '%s %s' command.\n",
		    argc <= 2 ? "" : "s", argv[0], i->name);
		return -1;
	}

	if (i->handler)
		success = (*i->handler)(set, &argv[1],
		    (i->maxarg > 0) ? argv[2] : 0, stab->pf);
	return success;
}

static int
sysctlhelp(int unused1, char **unused2, ...)
{
	Menu *i = NULL, *j = NULL; /* pointer to current command */
	char *prefix = NULL;
	u_int z = 0;
	struct sysctltab *stab;
	va_list ap;
	char **unused3 = NULL;
	int type;

	va_start(ap, unused2);
	unused3 = va_arg(ap, char **);
	if (unused3) { /* silence "unused variable" compiler warning */ }
	type = va_arg(ap, int);
	va_end(ap);

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

struct ghs flushtab[] = {
	{ "<cr>", "Type Enter to run command", CMPL0 NULL, 0 },
	{ "verbose", "Show verbose diagnostics", CMPL0 NULL, 0 },
	{ NULL, NULL, NULL, NULL, 0 }
};

Menu flushlist[] = {
	{ "routes",	"IP routes", CMPL(h) (char **)flushtab,
	    sizeof(struct ghs), 0, 1, flush_ip_routes },
	{ "arp",	"ARP cache", CMPL(h) (char **)flushtab,
	    sizeof(struct ghs), 0, 1, flush_arp_cache },
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

/* flush: nshd's system runs it as an operation, except help and history */
static int
flushcmd(int argc, char **argv, ...)
{
	Menu *f;

	if (argc >= 2 && (f = flush_find(argv[1])) != NULL &&
	    f->handler != flush_help && f->handler != flush_history)
		return op_ask("flush", argc, argv, cli_rtable);
	return flush_run(argc, argv);
}

/* flush's entry for word, or NULL */
static Menu *
flush_find(char *word)
{
	Menu *f;

	f = (Menu *)genget(word, (char **)flushlist, sizeof(Menu));
	return f == 0 || Ambiguous(f) ? NULL : f;
}

/* run a flush command */
static int
flush_run(int argc, char **argv)
{
	Menu *f;

	if (argc < 2) {
		flush_help(argc, argv);
		return 0;
	}

	/*
	 * Validate flush argument
	 */
	f = (Menu *) genget(argv[1], (char **)flushlist, sizeof(Menu));
	if (f == 0) {
		printf("%% Invalid argument %s\n", argv[1]);
		return -1;
	} else if (Ambiguous(f)) {
		printf("%% Ambiguous argument %s\n", argv[1]);
		return -1;
	}
	if (((f->minarg + 2) > argc) || ((f->maxarg + 2) < argc)) {
		printf("%% Wrong argument%s to 'flush %s' command.\n",
		    argc <= 2 ? "" : "s", f->name);
		return -1;
	}
	if (f->handler &&
	    (*f->handler)(0, NULL, (f->maxarg > 0) ? argv[2] : 0,
	    (f->maxarg > 1) ? argv[3] : 0) == -1)
		return -1;

	return 0;
}

static int
flush_line(int argc, char **argv, ...)
{
	va_list ap;
	char *line;
	char * args[5] = { PKILL, "-9", "-t", /* line */ NULL, NULL };
	int r;

	va_start(ap, argv);
	line = va_arg(ap, char *);
	va_end(ap);

	args[3] = line;
	/* pkill exits 1 if no process ran on the line */
	r = cmdargs(PKILL, args);
	return r == -1 || r > 1 ? -1 : 0;
}

/*
 * The operations nshd's system runs, as root, for a privileged session:
 * flush, except help and history; reboot, halt and powerdown, which nsh
 * has the user confirm first; diff-config, of the saved configuration
 * against the running one; crontab, root's crontab; a daemon's action
 * that runs a program and does not change its configuration; an
 * interface's bssid, setpuk and chgpin; and a group's carp demotion
 * counter, as group or no group sets it. Each is its first word, as nsh
 * names it, and the words after it as typed. 1 if argv is one, or 0
 * after saying it is not.
 */
int
op_allowed(int argc, char **argv)
{
	Menu *f;

	if (argc == 1 && (strcmp(argv[0], "reboot") == 0 ||
	    strcmp(argv[0], "halt") == 0 ||
	    strcmp(argv[0], "powerdown") == 0 ||
	    strcmp(argv[0], "diff-config") == 0 ||
	    strcmp(argv[0], "crontab") == 0))
		return 1;
	if (argc >= 2 && strcmp(argv[0], "flush") == 0 &&
	    (f = flush_find(argv[1])) != NULL && f->handler != flush_help &&
	    f->handler != flush_history)
		return 1;
	if (argc >= 3 && strcmp(argv[0], "interface") == 0 &&
	    strlen(argv[1]) < IFNAMSIZ && int_op_find(argc - 2, argv + 2))
		return 1;
	if (argc >= 2 && ctl_op(argv[0], argv[1], 0))
		return 1;
	if (strcmp(argv[0], "group") == 0 || (argc >= 2 &&
	    strcmp(argv[0], "no") == 0 && strcmp(argv[1], "group") == 0))
		return 1;
	printf("%% %s: not an operation nshd runs\n", argv[0]);
	return 0;
}

/*
 * Run an operation op_allowed() takes; return as a handler does, but
 * OP_DIFFERS from diff-config if the configurations differ. With hide,
 * for a session that sees no password hash, diff-config hides each one
 */
int
op_run(int argc, char **argv, int hide)
{
	struct daemons *d;
	struct intlist *i;
	char *rb[] = { REBOOT, NULL }, *ht[] = { HALT, NULL, NULL };
	char *cr[] = { CRONTAB, "-l", "-u", "root", NULL };
	int ifs, r;

	if (strcmp(argv[0], "flush") == 0)
		return flush_run(argc, argv);
	if (strcmp(argv[0], "reboot") == 0)
		return cmdargs(rb[0], rb) == 0 ? 0 : -1;
	if (strcmp(argv[0], "halt") == 0 || strcmp(argv[0], "powerdown") == 0) {
		if (argv[0][0] == 'p')
			ht[1] = "-p";
		return cmdargs(ht[0], ht) == 0 ? 0 : -1;
	}
	if (strcmp(argv[0], "diff-config") == 0)
		return (r = saved_diff(hide)) == 1 ? OP_DIFFERS : r;
	if (strcmp(argv[0], "crontab") == 0) {
		printf("%% To view crontab syntax documentation in NSH, "
		    "run: !man 5 crontab\n\n");
		fflush(stdout);
		if (cmdargs(cr[0], cr) != 0) {
			printf("%% crontab command failed\n");
			return -1;
		}
		return 0;
	}
	if (strcmp(argv[0], "interface") == 0) {
		i = int_op_find(argc - 2, argv + 2);
		if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
			printf("%% socket: %s\n", strerror(errno));
			return -1;
		}
		r = strcmp(i->name, "bssid") == 0 ?
		    intbssid(argc - 2, argv + 2, argv[1], ifs) :
		    intumb(argc - 2, argv + 2, argv[1], ifs);
		close(ifs);
		return r;
	}
	if (strcmp(argv[0], "group") == 0 || strcmp(argv[0], "no") == 0)
		return group(argc, argv);
	d = (struct daemons *)genget(argv[0], (char **)ctl_daemons,
	    sizeof(struct daemons));
	strlcpy(hname, d->name, sizeof(hname));
	return ctlhandler(argc, argv, NULL);
}

/*
 * In an interface's mode, bssid, setpuk and chgpin, as operations nshd's
 * system runs
 */
static int
int_op(int argc, char **argv, ...)
{
	char *ifn, *words[NARGS + 2];
	va_list ap;
	int i;

	va_start(ap, argv);
	ifn = va_arg(ap, char *);
	va_end(ap);

	if (argc > NARGS) {
		printf("%% Too many arguments\n");
		return -1;
	}
	words[0] = "interface";
	words[1] = ifn;
	for (i = 0; i < argc; i++)
		words[i + 2] = argv[i];
	return op_ask("interface", argc + 2, words, 0);
}

/* The interface operation argv names, or NULL */
static struct intlist *
int_op_find(int argc, char **argv)
{
	struct intlist *i;
	char *w = NO_ARG(argv[0]) ? argv[1] : argv[0];

	if (w == NULL)
		return NULL;
	i = (struct intlist *)genget(w, (char **)Intlist,
	    sizeof(struct intlist));
	return i == 0 || Ambiguous(i) || i->handler != int_op ? NULL : i;
}

static int
flush_help(int argc, char **argv, ...)
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

static char crontabhelp[];
static char interfacehelp[];
extern struct ghs mantab[];

struct intlist Intlist[] = {
/* Interface mode commands */
	{ "inet",	"IPv4/IPv6 addresses",			CMPL(h) (char **)intiphelp, sizeof(struct ghs), intip, 1, CAND_EDIT },
	{ "ip",		"Alias for \"inet\" command",		CMPL(h) (char **)intiphelp, sizeof(struct ghs), intip, 1, CAND_EDIT },
	{ "alias",	NULL, /* backwards compatibilty */	CMPL(h) (char **)intiphelp, sizeof(struct ghs), intip, 1, CAND_EDIT },
	{ "autoconf4",  "IPv4 Autoconfigurable address (DHCP)",	CMPL0 0, 0, intxflags, 1, CAND_EDIT },
	{ "description", "Interface description",		CMPL0 0, 0, intdesc, 1, CAND_EDIT },
	{ "group",	"Interface group",			CMPL0 0, 0, intgroup, 1, CAND_EDIT },
	{ "rdomain",	"Interface routing domain",		CMPL0 0, 0, intrdomain, 1, CAND_EDIT },
	{ "rtlabel",	"Interface route labels",		CMPL0 0, 0, intrtlabel, 1, CAND_EDIT },
	{ "priority",	"Data packet priority",			CMPL0 0, 0, intmetric, 1, CAND_EDIT },
	{ "llpriority",	"Link Level packet priority",		CMPL0 0, 0, intllprio, 1, CAND_EDIT },
	{ "mtu",	"Maximum Transmission Unit",		CMPL0 0, 0, intmtu, 1, CAND_EDIT },
	{ "metric",	"Routing metric",			CMPL0 0, 0, intmetric, 1, CAND_EDIT },
	{ "link",	"Link level options",			CMPL0 0, 0, intlink, 1, CAND_EDIT },
	{ "arp",	"Address Resolution Protocol",		CMPL0 0, 0, intflags, 1, CAND_EDIT },
	{ "staticarp",	"Always use static ARP to find other hosts",CMPL0 0, 0, intflags, 1, CAND_EDIT },
	{ "lladdr",	"Link Level (MAC) Address",		CMPL0 0, 0, intlladdr, 1, CAND_EDIT },
	{ "nwid",	"802.11 network ID",			CMPL0 0, 0, intnwid, 1, CAND_EDIT },
	{ "nwkey",	"802.11 network key",			CMPL0 0, 0, intnwkey, 1, CAND_EDIT },
	{ "powersave",	"802.11 powersaving mode",		CMPL0 0, 0, intpowersave, 1, CAND_EDIT },
	{ "txpower",	"802.11 transmit power",		CMPL0 0, 0, inttxpower, 1, CAND_EDIT },
	{ "bssid",	"802.11 bss id",			CMPL0 0, 0, int_op, 1, CAND_RUN },
	{ "media",	"Media type",				CMPL0 0, 0, intmedia, 1, CAND_EDIT },
	{ "mediaopt",	"Media options",			CMPL0 0, 0, intmediaopt, 1, CAND_EDIT },
	{ "auth",	"PPP authentication",			CMPL0 0, 0, intsppp, 1, CAND_EDIT },
	{ "peer",	"PPP peer authentication",		CMPL0 0, 0, intsppp, 1, CAND_EDIT },
	{ "pppoe",	"PPPoE settings",			CMPL0 0, 0, intpppoe, 1, CAND_EDIT },
	{ "tunnel",	"Tunnel parameters",			CMPL0 0, 0, inttunnel, 1, CAND_EDIT },
	{ "tunneldomain", "Tunnel routing domain for transit",	CMPL0 0, 0, intmpls, 1, CAND_EDIT },
	{ "txprio",	"Priority in tunnel protocol headers",	CMPL0 0, 0, intmpls, 1, CAND_EDIT },
	{ "rxprio",	"Source used for packet priority",	CMPL0 0, 0, intmpls, 1, CAND_EDIT },
	{ "vnetid",	"Virtual interface network identifier",	CMPL0 0, 0, intvnetid, 1, CAND_EDIT },
	{ "vnetflowid",	"Use part of vnetid as flowid",		CMPL0 0, 0, intvnetflowid, 1, CAND_EDIT },
	{ "parent",	"Parent interface",			CMPL(i) 0, 0, intparent, 1, CAND_EDIT },
	{ "patch",	"Pair interface",			CMPL(i) 0, 0, intpatch, 1, CAND_EDIT },
	{ "ping",	pinghelp,				CMPL0 0, 0, int_ping, 0, CAND_RUN },
	{ "ping6",	ping6help,				CMPL0 0, 0, int_ping6, 0, CAND_RUN },
	{ "traceroute", tracerthelp,				CMPL0 0, 0, int_traceroute, 0, CAND_RUN },
	{ "traceroute6", tracert6help,				CMPL0 0, 0, int_traceroute6, 0, CAND_RUN },
	{ "ssh",	sshhelp,				CMPL0 0, 0, int_ssh, 0, CAND_RUN },
	{ "telnet",	telnethelp,				CMPL0 0, 0, int_telnet,	0, CAND_RUN },
	{ "logger",     loggerhelp,                             CMPL0 0, 0, int_logger, 0, CAND_RUN },
	{ "do",		dohelp,					CMPL(c) 0, 0, int_do, 0, CAND_RUN },
	{ "setenv",	setenvhelp,				CMPL(e) 0, 0, int_setenv, 0, CAND_RUN },
	{ "unsetenv",	unsetenvhelp,				CMPL(e) 0, 0, int_unsetenv, 0, CAND_RUN },
	{ "saveenv",	saveenvhelp,				CMPL0 0, 0, int_saveenv, 0, CAND_RUN },
	{ "keepalive",	"GRE tunnel keepalive",			CMPL0 0, 0, intkeepalive, 1, CAND_EDIT },
	{ "mplslabel",	"MPLS local label",			CMPL0 0, 0, intmpls, 1, CAND_EDIT },
	{ "pwe",	"MPLS PWE3",				CMPL0 0, 0, intpwe3, 1, CAND_EDIT },
	{ "syncdev",	"PFsync control message interface",	CMPL(i) 0, 0, intsyncdev, 1, CAND_EDIT },
	{ "syncpeer",	"PFsync peer address",			CMPL0 0, 0, intsyncpeer, 1, CAND_EDIT },
	{ "maxupd", 	"PFsync max updates, defer first packet", CMPL0 0, 0, intmaxupd, 1, CAND_EDIT },
	{ "vhid",	"CARP virtual host ID",			CMPL0 0, 0, intcarp, 1, CAND_EDIT },
	{ "advbase",	"CARP advertisement interval",		CMPL0 0, 0, intcarp, 1, CAND_EDIT },
	{ "advskew",	"CARP advertisement skew",		CMPL0 0, 0, intcarp, 1, CAND_EDIT },
	{ "carppass",	"CARP passphrase",			CMPL0 0, 0, intcpass, 1, CAND_EDIT },
	{ "carpdev",	"CARP device",				CMPL(i) 0, 0, intcdev, 1, CAND_EDIT },
	{ "carpnode",	"CARP additional vhid/advskew",		CMPL0 0, 0, intcnode, 1, CAND_EDIT },
	{ "carppeer",	"CARP peer",				CMPL0 0, 0, intcarp, 1, CAND_EDIT },
	{ "balancing",	"CARP balancing mode",			CMPL0 0, 0, intcarp, 1, CAND_EDIT },
	{ "pflow",	"pflow data export",			CMPL0 0, 0, intpflow, 1, CAND_EDIT },
	{ "debug",	"Driver dependent debugging",		CMPL0 0, 0, intflags, 1, CAND_EDIT },
	{ "dhcrelay",	"DHCP Relay Agent",			CMPL0 0, 0, intdhcrelay, 1, CAND_EDIT },
	{ "wol",	"Wake On LAN",				CMPL0 0, 0, intxflags, 1, CAND_EDIT },
	{ "mpls",	"MPLS",					CMPL0 0, 0, intxflags, 1, CAND_EDIT },
	{ "inet6",	"IPv6 addresses",			CMPL(h) (char **)intip6help, sizeof(struct ghs), intip, 1, CAND_EDIT },
	{ "autoconf6",  "IPv6 Autoconfigurable address",	CMPL0 0, 0, intxflags, 1, CAND_EDIT },
	{ "autoconfprivacy", "Privacy addresses for IPv6 autoconf", CMPL0 0, 0, intxflags, 1, CAND_EDIT }, /* XXX bkcompat */
	{ "temporary",	"Temporary addresses for IPv6 autoconf", CMPL0 0, 0, intxflags, 1, CAND_EDIT },
	{ "monitor",	"Monitor mode for incoming traffic",	CMPL0 0, 0, intxflags, 1, CAND_EDIT },
	{ "wgpeer",	"Wireguard peer config",		CMPL0 0, 0, intwgpeer, 1, CAND_EDIT },
	{ "wgport",	"Wireguard UDP port",			CMPL0 0, 0, intwg, 1, CAND_EDIT },
	{ "wgkey",	"Wireguard private key",		CMPL0 0, 0, intwg, 1, CAND_EDIT },
	{ "wgrtable",	"Wireguard routing table",		CMPL0 0, 0, intwg, 1, CAND_EDIT },
	{ "trunkport",	"Add child interface(s) to trunk",	CMPL0 0, 0, inttrunkport, 1, CAND_EDIT },
	{ "trunkproto",	"Define trunkproto",			CMPL0 0, 0, inttrunkproto, 1, CAND_EDIT },
	{ "apn",	"Access Point Name",			CMPL0 0, 0, intumb, 1, CAND_EDIT },
	{ "setpin",	"Set SIM card PIN",			CMPL0 0, 0, intumb, 1, CAND_EDIT },
	{ "setpuk",	"Set new SIM card PIN using PUK for validation", CMPL0 0, 0, int_op, 0, CAND_RUN },
	{ "chgpin",	"Permanently change SIM PIN",		CMPL0 0, 0, int_op, 0, CAND_RUN },
	{ "class",	"Preferred cell classes",		CMPL0 0, 0, intumb, 1, CAND_EDIT },
	{ "roaming",	"Enable data roaming",			CMPL0 0, 0, intumb, 1, CAND_EDIT },
	{ "interface",  interfacehelp,				CMPL(i) 0, 0, int_interface, 1, CAND_EDIT },
	{ "shutdown",   "Shutdown interface",			CMPL0 0, 0, intflags, 1, CAND_EDIT },
	{ "show",	showhelp,				CMPL(ta) (char **)showlist, sizeof(Menu), int_show, 0, CAND_RUN },
	{ "who",	whohelp,				CMPL0 0, 0, int_who, 0, CAND_RUN },
	{ "verbose",	verbosehelp,				CMPL0 0, 0, int_doverbose, 1, CAND_RUN },
	{ "editing",	editinghelp,				CMPL0 0, 0, int_doediting, 1, CAND_RUN },
	{ "clear",	clearhelp,				CMPL0 0, 0, int_clear, 0, CAND_RUN },
	{ "!",		shellhelp,				CMPL0 0, 0, int_shell, 0, CAND_RUN },
        { "?",		"Options",				CMPL0 0, 0, int_help, 0, CAND_RUN },
	{ "manual",	manhelp,				CMPL(H) (char **)mantab, sizeof(struct ghs), int_manual, 0, CAND_RUN },
        { "help",	0,					CMPL0 0, 0, int_help, 0, CAND_RUN },
	{ "exit",	"Leave interface config mode and return to global config mode ",
								CMPL0 0, 0, int_exit, 0, CAND_RUN },

	{ 0, 0, 0, 0, 0 }
};

size_t Intlist_nitems = nitems(Intlist);

struct intlist Bridgelist[] = {
/* Bridge mode commands */
	{ "description", "Bridge description",			CMPL0 0, 0, intdesc, 1, CAND_EDIT },
	{ "member",	"Bridge member(s)",			CMPL(i) 0, 0, brport, 1, CAND_EDIT },
	{ "span",	"Bridge spanning port(s)",		CMPL(i) 0, 0, brport, 1, CAND_EDIT },
	{ "blocknonip",	"Block non-IP traffic forwarding on member(s)",		CMPL0 0, 0, brport, 1, CAND_EDIT },
	{ "discover",	"Mark member(s) as discovery port(s)",	CMPL0 0, 0, brport, 1, CAND_EDIT },
	{ "learning",	"Mark member(s) as learning port(s)",	CMPL0 0, 0, brport, 1, CAND_EDIT },
	{ "stp",	"Enable 802.1D spanning tree protocol on member(s)",	CMPL0 0, 0, brport, 1, CAND_EDIT },
	{ "maxaddr",	"Maximum address cache size",		CMPL0 0, 0, brval, 1, CAND_EDIT },
	{ "timeout",	"Address cache timeout",		CMPL0 0, 0, brval, 1, CAND_EDIT },
	{ "maxage",	"Time for 802.1D configuration to remain valid",	CMPL0 0, 0, brval, 1, CAND_EDIT },
	{ "fwddelay",	"Time before bridge begins forwarding packets",		CMPL0 0, 0, brval, 1, CAND_EDIT },
	{ "hellotime",	"802.1D configuration packet broadcast interval",	CMPL0 0, 0, brval, 1, CAND_EDIT },
	{ "priority",	"Spanning priority for all members on an 802.1D bridge",CMPL0 0, 0, brval, 1, CAND_EDIT },
	{ "ping",	pinghelp,				CMPL0 0, 0, int_ping, 0, CAND_RUN },
	{ "ping6",	ping6help,				CMPL0 0, 0, int_ping6, 0, CAND_RUN },
	{ "traceroute", tracerthelp,				CMPL0 0, 0, int_traceroute, 0, CAND_RUN },
	{ "traceroute6", tracert6help,				CMPL0 0, 0, int_traceroute6, 0, CAND_RUN },
	{ "ssh",	sshhelp,				CMPL0 0, 0, int_ssh, 0, CAND_RUN },
	{ "telnet",	telnethelp,				CMPL0 0, 0, int_telnet,	0, CAND_RUN },
	{ "logger",     loggerhelp,                             CMPL0 0, 0, int_logger, 0, CAND_RUN },
	{ "do",		dohelp,					CMPL(c) 0, 0, int_do, 0, CAND_RUN },
	{ "setenv",	setenvhelp,				CMPL(e) 0, 0, int_setenv, 0, CAND_RUN },
	{ "unsetenv",	unsetenvhelp,				CMPL(e) 0, 0, int_unsetenv, 0, CAND_RUN },
	{ "saveenv",	saveenvhelp,				CMPL0 0, 0, int_saveenv, 0, CAND_RUN },
	{ "rule",	"Bridge layer 2 filtering rules",	CMPL0 0, 0, brrule, 0, CAND_EDIT },
	{ "static",	"Static bridge address entry",		CMPL0 0, 0, brstatic, 1, CAND_EDIT },
	{ "ifpriority",	"Spanning priority of a member on an 802.1D bridge",	CMPL0 0, 0, brpri, 1, CAND_EDIT },
	{ "ifcost",	"Spanning tree path cost of a member on 802.1D bridge", CMPL0 0, 0, brpri, 1, CAND_EDIT },
	{ "link",	"Link level options",			CMPL0 0, 0, intlink, 1, CAND_EDIT },
	{ "txprio",     "Priority in tunnel protocol headers",	CMPL0 0, 0, intmpls, 1, CAND_EDIT },
	{ "rxprio",     "Source used for packet priority",	CMPL0 0, 0, intmpls, 1, CAND_EDIT },
	{ "vnetid",	"Virtual interface network identifier",	CMPL0 0, 0, intvnetid, 1, CAND_EDIT },
	{ "parent",	"Parent interface",			CMPL(i) 0, 0, intparent, 1, CAND_EDIT },
	{ "tunneldomain", "Tunnel parameters",			CMPL0 0, 0, intmpls, 1, CAND_EDIT },
	{ "protect",	"Configure protected bridge domains",	CMPL0 0, 0, brprotect, 1, CAND_EDIT },
	{ "interface",  interfacehelp,				CMPL(i) 0, 0, int_interface, 1, CAND_EDIT },
	{ "shutdown",	"Shutdown bridge",			CMPL0 0, 0, intflags, 1, CAND_EDIT },
	{ "show",	showhelp,				CMPL(ta) (char **)showlist, sizeof(Menu), int_show, 0, CAND_RUN },
	{ "who",	whohelp,				CMPL0 0, 0, int_who, 0, CAND_RUN },
	{ "verbose",	verbosehelp,				CMPL0 0, 0, int_doverbose, 1, CAND_RUN },
	{ "editing",	editinghelp,				CMPL0 0, 0, int_doediting, 1, CAND_RUN },
	{ "clear",	clearhelp,				CMPL0 0, 0, int_clear, 0, CAND_RUN },
	{ "!",		shellhelp,				CMPL0 0, 0, int_shell, 0, CAND_RUN },

/* Help commands */
	{ "?",		"Options",				CMPL0 0, 0, int_help, 0, CAND_RUN },
	{ "manual",	manhelp,				CMPL(H) (char **)mantab, sizeof(struct ghs), int_manual, 0, CAND_RUN },
	{ "help",	0,					CMPL0 0, 0, int_help, 0, CAND_RUN },
	{ "exit",	"Leave bridge config mode and return to global config mode ",
								CMPL0 0, 0, int_exit, 0, CAND_RUN },
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
			/* EOF, e.g. ^X or ^D via exit_i() in editing.c */
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
 * acts as a loop for human keyboard user. With rc_head, for the head of
 * a block in a commit's edits, it only creates the interface, or with
 * no, destroys it.
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
interface(int argc, char **argv, ...)
{
	int ifs, set = 1, r;
	char *tmp;
	char *ifunit = NULL;
	struct intlist *i;	/* pointer to current command */
	struct ifreq ifr;

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
		return -1;
	}
	tmp = argv[1];

	if (strlen(tmp) > IFNAMSIZ-1) {
		printf("%% interface name too long\n");
		return -1;
	}

	strlcpy(ifname, tmp, IFNAMSIZ);
	if (ifunit) {
		const char *errstr;
		size_t len = strlen(ifname);
		strtonum(ifunit, 0, INT_MAX, &errstr);
		if (errstr) {
			printf("%% interface unit %s is %s\n", ifunit, errstr);
			ifname[0] = '\0';
			return -1;
		}
		if (len > 0 && isdigit((unsigned char)(ifname[len - 1]))) {
			printf("%% interface unit %s is redundant\n", ifunit);
			ifname[0] = '\0';
			return -1;
		}
		strlcat(ifname, ifunit, sizeof(ifname));
		printf("%% Using interface \"%s\", not \"%s %s\"\n",
		    ifname, tmp, ifunit);
	}
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	/* configure private asks the kernel only through kfacts.c */
	if (candidate)
		ifs = -1;
	else if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% socket failed: %s\n", strerror(errno));
		ifname[0] = '\0';
		return -1;
	}

	if (candidate && (r = cand_interface(set, ifname, &bridge)) != 0) {
		ifname[0] = '\0';
		close(ifs);
		return r == -1 ? -1 : 0;
	}

	if (!candidate && !is_valid_ifname(ifname)) {
		if (set == 0) {
			printf("%% interface %s not found\n", ifname);
			close(ifs);
			return -1;
		}
		if (ioctl(ifs, SIOCIFCREATE, &ifr) == -1) {
			if (errno == EINVAL)
				printf("%% interface %s not found\n", ifname);
			else
				printf("%% unable to create interface %s: %s\n",
				    ifname, strerror(errno));
			ifname[0] = '\0';
			close(ifs);
			return -1;
		}
	}

	if (!candidate && set == 0) {
		r = 0;
		if (ioctl(ifs, SIOCIFDESTROY, &ifr) == -1) {
			printf("%% unable to remove interface %s: %s\n",
			    ifname, strerror(errno));
			r = -1;
		}
		ifname[0] = '\0';
		close(ifs);
		return r;
	}

	/* a block's head in a commit only creates a cloned interface */
	if (rc_head) {
		ifname[0] = '\0';
		close(ifs);
		return 0;
	}

	if (candidate)
		whichlist = bridge ? Bridgelist : Intlist;
	else if (is_bridge(ifs, ifname)) {
		/* whichlist also used by help, command completion code */
		whichlist = Bridgelist;
		bridge = 1;
	} else {
		whichlist = Intlist;
		bridge = 0;
	}

	imr_init(ifname);

	/* a line at a time (cmdline()): the mode is entered, and stays */
	if (oneline) {
		close(ifs);
		return 0;
	}

	/* human at the keyboard or commands on stdin */
	for (;;) {
		char *margp;

		if (editing && !isatty(STDIN_FILENO))
			endedit();
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
					return 0;
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
				return -1;
			}
		}

		if (makeargv() == -1) {
			printf("%% Too many words\n");
			continue;
		}
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
		} else if (cand_refused(i->name, i->cand)) {
			/* cand_refused() said why */
		} else {
			int save_cli_rtable = cli_rtable;
			int ret;

			/*
			 * Run the handler in the default routing domain.
			 * This requires privileged mode if we are not
			 * already in rdomain 0.
			 */
			if (getrtable() != 0 && !priv) {
				printf("%% Privilege required\n");
				ifname[0] = '\0';
				close(ifs);
				return -1;
			}

			if (cli_rtable != 0 && nsh_setrtable(0) == 0)
				cli_rtable = 0;

			ret = (*i->handler)(margc, margv, ifname, ifs);

			if (cli_rtable != save_cli_rtable &&
			    nsh_setrtable(save_cli_rtable) == 0)
				cli_rtable = save_cli_rtable;

			if (ret == 1)
				break;
		}

		if (i && i->handler == int_interface && next_ifname[0] != '\0' &&
		    strcmp(next_ifname, ifname) != 0) {
			strlcpy(ifname, next_ifname, sizeof(ifname));
			memset(next_ifname, 0, sizeof(next_ifname));
			strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
			imr_init(ifname);
			if (candidate ? cand_isbridge(ifname) :
			    is_bridge(ifs, ifname)) {
				whichlist = Bridgelist;
				bridge = 1;
			} else {
				whichlist = Intlist;
				bridge = 0;
			}
		}
	}

	ifname[0] = '\0';
	close(ifs);
	return 0;
}

static int
int_interface(int argc, char **argv, ...)
{
	struct ifreq ifr;
	char *new_ifname;
	int set = 1, r;
	va_list ap;
	char *old_ifname;
	int ifs;

	va_start(ap, argv);
	old_ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);
	
	if (NO_ARG(argv[0])) {
		argv++;
		argc--;
		set = 0;
	}

	if (argc != 2) {
		printf("%% usage: [no] interface <ifname>\n");
		return -1;
	}

	new_ifname = argv[1];
	if (candidate) {
		int isbridge;

		if ((r = cand_interface(set, new_ifname, &isbridge)) == -1)
			return -1;
		if (r == 0)
			strlcpy(next_ifname, new_ifname, sizeof(next_ifname));
		/* if this mode's interface was removed, leave the mode */
		return !set && strcmp(old_ifname, new_ifname) == 0;
	}
	if (!is_valid_ifname(new_ifname)) {
		if (set == 0) {
			printf("%% interface %s not found\n", new_ifname);
			return -1;
		}
		strlcpy(ifr.ifr_name, new_ifname, sizeof(ifr.ifr_name));
		if (ioctl(ifs, SIOCIFCREATE, &ifr) == -1) {
			if (errno == EINVAL)
				printf("%% interface %s not found\n", new_ifname);
			else
				printf("%% unable to create interface %s: %s\n",
				    new_ifname, strerror(errno));
			return -1;
		}
		strlcpy(next_ifname, new_ifname, sizeof(next_ifname));
		return 0; /* do not leave interface context */
	}

	if (set == 0) {
		strlcpy(ifr.ifr_name, new_ifname, sizeof(ifr.ifr_name));
		if (ioctl(ifs, SIOCIFDESTROY, &ifr) == -1) {
			printf("%% unable to remove interface %s: %s\n",
			    new_ifname, strerror(errno));
			return -1;
		}
		if (strcmp(old_ifname, new_ifname) == 0)
			return 1; /* leave interface context */
		return 0; /* do not leave interface context */
	}

	strlcpy(next_ifname, new_ifname, sizeof(next_ifname));
	return 0; /* do not leave interface context */
}

static int
int_exit(int argc, char **argv, ...)
{
	return 1; /* leave interface config mode */
}

/*
 * Data structures and routines for the main CLI
 */

static char
	hostnamehelp[] = "Set system hostname",
	loginhelp[] =	"Login classes and users",
	interfacehelp[] = "Modify interface parameters",
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
	iphelp[] =	"Set IP networking parameters",
	ip6help[] =	"Set IPv6 networking parameters",
	mplshelp[] =	"Set MPLS network parameters",
	ddbhelp[] =	"Set DDB parameters",
	pipexhelp[] =	"Set PIPEX parameters",
	routehelp[] =	"Add a host or network route",
	crontabhelp[] =	"Configure scheduled background jobs";

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
Command cmdtab[] = {
	{ "hostname",	hostnamehelp,	CMPL0 0, 0, hostname,		1, 1, 0, 0, CAND_EDIT },
	{ "login",	loginhelp,	CMPL0 0, 0, loginset,		1, 1, 1, 0, CAND_EDIT },
	{ "interface",	interfacehelp,	CMPL(i) 0, 0, interface,	1, 1, 1, 1, CAND_EDIT },
	{ "rtable",	rtablehelp,	CMPL(rh) (char **)rtabletab, sizeof(struct ghs), rtable,	0, 0, 1, 2, CAND_EDIT },
	{ "group",	grouphelp,	CMPL(gth) (char **)grouptab, sizeof(Menu), group, 1, 1, 1, 0, CAND_RUN },
	{ "arp",	arphelp,	CMPL0 0, 0, arpset,		1, 1, 1, 0, CAND_EDIT },
	{ "ndp",	ndphelp,	CMPL0 0, 0, ndpset,		1, 1, 1, 0, CAND_EDIT },
	{ "nameserver",	nameserverhelp,	CMPL0 0, 0, nameserverset,	1, 1, 1, 0, CAND_EDIT },
	{ "bridge",	bridgehelp,	CMPL(i) 0, 0, interface,	1, 1, 1, 1, CAND_EDIT },
	{ "show",	showhelp,	CMPL(ta) (char **)showlist, sizeof(Menu), showcmd,	0, 0, 0, 0 },
	{ "ip",		iphelp,		CMPL(ta) (char **)iptab, sizeof(Menu), ipcmd,		1, 1, 1, 0, CAND_EDIT },
	{ "ip6",	ip6help,	CMPL(ta) (char **)ip6tab, sizeof(Menu), ipcmd,		1, 1, 1, 0, CAND_EDIT },
	{ "mpls",	mplshelp,	CMPL(ta) (char **)mplstab, sizeof(Menu), ipcmd,		1, 1, 1, 0, CAND_EDIT },
	{ "ddb",	ddbhelp,	CMPL(ta) (char **)ddbtab, sizeof(Menu), ipcmd,		1, 1, 1, 0, CAND_EDIT },
	{ "pipex",	pipexhelp,	CMPL(ta) (char **)pipextab, sizeof(Menu), ipcmd,	1, 1, 1, 0, CAND_EDIT },
	{ "flush",	flushhelp,	CMPL(ta) (char **)flushlist, sizeof(Menu), flushcmd,	1, 0, 0, 0 },
	{ "clear",      clearhelp,      CMPL0 0, 0, clear,              0, 0, 0, 0 },
	{ "route",	routehelp,	CMPL0 0, 0, route,		1, 1, 1, 0, CAND_EDIT },
	{ "pf",		pfhelp,		CMPL(t) (char **)ctl_pf, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "ospf",	ospfhelp,	CMPL(t) (char **)ctl_ospf, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "ospf6",	ospf6help,	CMPL(t) (char **)ctl_ospf6, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "eigrp",	eigrphelp,	CMPL(t) (char **)ctl_eigrp, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "bgp",	bgphelp,	CMPL(t) (char **)ctl_bgp, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "rip",	riphelp,	CMPL(t) (char **)ctl_rip, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "ldp",	ldphelp,	CMPL(t) (char **)ctl_ldp, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "relay",	relayhelp,	CMPL(t) (char **)ctl_relay, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "ipsec",	ipsechelp,	CMPL(t) (char **)ctl_ipsec, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "ike",	ikehelp,	CMPL(t) (char **)ctl_ike, ssctl, ctlhandler, 	1, 1, 0, 1, CAND_EDIT },
	{ "dvmrp",	dvmrphelp,	CMPL(t) (char **)ctl_dvmrp, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "rad",	radhelp,	CMPL(t) (char **)ctl_rad, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "sasync",	sasynchelp,	CMPL(t) (char **)ctl_sasync, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "dhcp",	dhcphelp,	CMPL(t) (char **)ctl_dhcp, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "snmp",	snmphelp,	CMPL(t) (char **)ctl_snmp, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "ldap",	ldaphelp,	CMPL(t) (char **)ctl_ldap, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "smtp",	smtphelp,	CMPL(t) (char **)ctl_smtp, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "sshd",	sshdhelp,	CMPL(t) (char **)ctl_sshd, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "ntp",	ntphelp,	CMPL(t) (char **)ctl_ntp, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "nppp",	nppphelp,	CMPL(t) (char **)ctl_nppp, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "ifstate",	ifstatehelp,	CMPL(t) (char **)ctl_ifstate, ssctl, ctlhandler, 1, 1, 0, 1, CAND_EDIT },
	{ "ftp-proxy",  ftpproxyhelp,	CMPL(t) (char **)ctl_ftpproxy, ssctl, ctlhandler,  1, 1, 0, 1, CAND_EDIT },
	{ "tftp-proxy",	tftpproxyhelp,	CMPL(t) (char **)ctl_tftpproxy, ssctl, ctlhandler, 1, 1, 0, 1, CAND_EDIT },
	{ "tftp",	tftphelp,	CMPL(t) (char **)ctl_tftp, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "resolv",	resolvhelp,	CMPL(t) (char **)ctl_resolv, ssctl, ctlhandler, 1, 1, 0, 1, CAND_EDIT },
	{ "motd",       motdhelp,       CMPL(t) (char **)ctl_motd, ssctl, ctlhandler,    1, 1, 0, 1, CAND_EDIT },
	{ "crontab",    crontabhelp,    CMPL(t) (char **)ctl_crontab, ssctl, ctlhandler,    1, 1, 0, 1, CAND_EDIT },
	{ "scheduler",  crontabhelp,    CMPL(t) (char **)ctl_crontab, ssctl, ctlhandler,    1, 1, 0, 1, CAND_EDIT },
	{ "inet",	inethelp,	CMPL(t) (char **)ctl_inet, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
	{ "ping",	pinghelp,	CMPL0 0, 0, ping,		0, 0, 0, 0 },
	{ "ping6",	ping6help,	CMPL0 0, 0, ping6,		0, 0, 0, 0 },
	{ "traceroute", tracerthelp,	CMPL0 0, 0, traceroute,		0, 0, 0, 0 },
	{ "traceroute6", tracert6help,  CMPL0 0, 0, traceroute6,	 0, 0, 0, 0 },
	{ "ssh",	sshhelp,	CMPL0 0, 0, ssh,		0, 0, 0, 0 },
	{ "telnet",	telnethelp,	CMPL0 0, 0, telnet,		0, 0, 0, 0 },
	{ "reboot",	nreboothelp,	CMPL0 0, 0, nreboot,		1, 0, 0, 0 },
	{ "logger",     loggerhelp,     CMPL0 0, 0, logger,             0, 0, 0, 0 },
	{ "halt",	halthelp,	CMPL0 0, 0, halt,		1, 0, 0, 0 },
	{ "powerdown",	powerdownhelp,	CMPL0 0, 0, powerdown,		1, 0, 0, 0 },
	{ "verbose",	verbosehelp,	CMPL0 0, 0, doverbose,		0, 0, 1, 0 },
	{ "editing",	editinghelp,	CMPL0 0, 0, doediting,		0, 0, 1, 0 },
	{ "configure",	confighelp,	CMPL0 0, 0, doconfig,		1, 0, 1, 0 },
	{ "commit",	commithelp,	CMPL0 0, 0, commit,		1, 0, 0, 0, CAND_RUN },
	{ "rollback",	rollbackhelp,	CMPL0 0, 0, cand_rollback,	1, 1, 0, 0, CAND_RUN },
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
 * The commands a configuration has, and nothing else: a commit's edits
 * name them by their place here (commit.c), so a commit runs no command
 * that is not one of them. The tables cover the top level, except
 * daemons, which ctl.c handles (ctl_act()); interface mode; and bridge
 * mode. A top-level command takes no if CF_NO says so, as its row in
 * cmdtab does; any interface command can take no
 */
static const struct confcmd conf_top[] = {
	{ "hostname",	hostname,	0 },
	{ "login",	loginset,	CF_NO },
	{ "interface",	interface,	CF_NO | CF_IF },
	{ "rtable",	rtable,		CF_NO | CF_RTABLE },
	{ "arp",	arpset,		CF_NO },
	{ "ndp",	ndpset,		CF_NO },
	{ "nameserver",	nameserverset,	CF_NO },
	{ "bridge",	interface,	CF_NO | CF_BRIDGE },
	{ "ip",		ipcmd,		CF_NO },
	{ "ip6",	ipcmd,		CF_NO },
	{ "mpls",	ipcmd,		CF_NO },
	{ "ddb",	ipcmd,		CF_NO },
	{ "pipex",	ipcmd,		CF_NO },
	{ "route",	route,		CF_NO },
};

static const struct confcmd conf_if[] = {
	{ "inet",	intip },
	{ "ip",		intip },
	{ "alias",	intip },
	{ "autoconf4",	intxflags },
	{ "description",	intdesc },
	{ "group",	intgroup },
	{ "rdomain",	intrdomain },
	{ "rtlabel",	intrtlabel },
	{ "priority",	intmetric },
	{ "llpriority",	intllprio },
	{ "mtu",	intmtu },
	{ "metric",	intmetric },
	{ "link",	intlink },
	{ "arp",	intflags },
	{ "staticarp",	intflags },
	{ "lladdr",	intlladdr },
	{ "nwid",	intnwid },
	{ "nwkey",	intnwkey },
	{ "powersave",	intpowersave },
	{ "txpower",	inttxpower },
	{ "media",	intmedia },
	{ "mediaopt",	intmediaopt },
	{ "auth",	intsppp },
	{ "peer",	intsppp },
	{ "pppoe",	intpppoe },
	{ "tunnel",	inttunnel },
	{ "tunneldomain",	intmpls },
	{ "txprio",	intmpls },
	{ "rxprio",	intmpls },
	{ "vnetid",	intvnetid },
	{ "vnetflowid",	intvnetflowid },
	{ "parent",	intparent },
	{ "patch",	intpatch },
	{ "keepalive",	intkeepalive },
	{ "mplslabel",	intmpls },
	{ "pwe",	intpwe3 },
	{ "syncdev",	intsyncdev },
	{ "syncpeer",	intsyncpeer },
	{ "maxupd",	intmaxupd },
	{ "vhid",	intcarp },
	{ "advbase",	intcarp },
	{ "advskew",	intcarp },
	{ "carppass",	intcpass },
	{ "carpdev",	intcdev },
	{ "carpnode",	intcnode },
	{ "carppeer",	intcarp },
	{ "balancing",	intcarp },
	{ "pflow",	intpflow },
	{ "debug",	intflags },
	{ "dhcrelay",	intdhcrelay },
	{ "wol",	intxflags },
	{ "mpls",	intxflags },
	{ "inet6",	intip },
	{ "autoconf6",	intxflags },
	{ "autoconfprivacy",	intxflags },
	{ "temporary",	intxflags },
	{ "monitor",	intxflags },
	{ "wgpeer",	intwgpeer },
	{ "wgport",	intwg },
	{ "wgkey",	intwg },
	{ "wgrtable",	intwg },
	{ "trunkport",	inttrunkport },
	{ "trunkproto",	inttrunkproto },
	{ "apn",	intumb },
	{ "setpin",	intumb },
	{ "class",	intumb },
	{ "roaming",	intumb },
	{ "shutdown",	intflags },
};

static const struct confcmd conf_bridge[] = {
	{ "description",	intdesc },
	{ "member",	brport },
	{ "span",	brport },
	{ "blocknonip",	brport },
	{ "discover",	brport },
	{ "learning",	brport },
	{ "stp",	brport },
	{ "maxaddr",	brval },
	{ "timeout",	brval },
	{ "maxage",	brval },
	{ "fwddelay",	brval },
	{ "hellotime",	brval },
	{ "priority",	brval },
	{ "rule",	brrule },
	{ "static",	brstatic },
	{ "ifpriority",	brpri },
	{ "ifcost",	brpri },
	{ "link",	intlink },
	{ "txprio",	intmpls },
	{ "rxprio",	intmpls },
	{ "vnetid",	intvnetid },
	{ "parent",	intparent },
	{ "tunneldomain",	intmpls },
	{ "protect",	brprotect },
	{ "shutdown",	intflags },
};

/*
 * These commands escape ambiguous check and help listings
 */

static Command  cmdtab2[] = {
	{ "reload",     nreboothelp,    CMPL0 0, 0, nreboot,            1, 0, 0, 0 },
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
		/* a configure session that nshd holds */
		if (nshd_config) {
			cmdline_nshd(line);
			continue;
		}
		if (makeargv() == -1) {
			printf("%% Too many words\n");
			continue;
		}
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
		if (c->needpriv != 0 && !nshd_priv(0))
			continue;
		/* nshd's system runs daemon operations outside configure too */
		if (c->handler == ctlhandler && margc > 1 &&
		    ctl_op(c->name, margv[1], 0)) {
			op_ask(c->name, margc, margv, cli_rtable);
			continue;
		}
		if (c->needconfig != 0 && config_mode != 1) {
			printf("%% Command requires configure mode\n");
			continue;
		}
		if ((c->needconfig || c->modh) && cand_refused(c->name, c->cand))
			continue;
		if (c->modh)
			strlcpy(hname, c->name, HSIZE);
		if ((*c->handler) (margc, margv, 0) == 1)
			break;
	}
}

/*
 * Run one line, as a terminal gives it, in configure private. In an
 * interface's mode, run the interface command; int_exit() leaves the
 * mode. Otherwise run the command; interface or bridge enters its mode,
 * which stays for the following lines. In nshd's config process, allow
 * only commands that edit the candidate, and leaving a mode. Returns
 * what the handler returns, or -1 after printing why if none ran.
 */
int
cmdline(char *text)
{
	Command *c;
	char *p;
	int r;

	if (strlcpy(line, text, sizeof(line)) >= sizeof(line)) {
		printf("%% Input exceeds permitted length\n");
		return -1;
	}
	if (makeargv() == -1) {
		printf("%% Too many words\n");
		return -1;
	}
	if (margv[0] == NULL)
		return 0;
	if (ifname[0] != '\0')
		return cmdline_if();
	if ((p = NO_ARG(margv[0]) ? margv[1] : margv[0]) == NULL ||
	    (c = getcmd(p)) == 0) {
		printf("%% Invalid command\n");
		return -1;
	}
	if (Ambiguous(c)) {
		printf("%% Ambiguous command\n");
		return -1;
	}
	if (NO_ARG(margv[0]) && ! c->nocmd) {
		printf("%% Invalid command: %s %s\n", margv[0], margv[1]);
		return -1;
	}
	if (c->needpriv != 0 && !nshd_priv(0))
		return -1;
	/* nshd's system runs daemon operations outside configure too */
	if (!in_config && c->handler == ctlhandler && margc > 1 &&
	    ctl_op(c->name, margv[1], 0))
		return op_ask(c->name, margc, margv, cli_rtable);
	if (c->needconfig != 0 && config_mode != 1) {
		printf("%% Command requires configure mode\n");
		return -1;
	}
	if ((c->needconfig || c->modh) && cand_refused(c->name, c->cand))
		return -1;
	if (in_config && c->cand != CAND_EDIT && c->handler != exitconfig) {
		printf("%% %s is not through nshd's configure\n", c->name);
		return -1;
	}
	if (c->modh)
		strlcpy(hname, c->name, HSIZE);
	oneline = 1;
	r = (*c->handler)(margc, margv, 0);
	oneline = 0;
	return r;
}

/* A line in an interface's mode, as interface()'s loop runs it */
static int
cmdline_if(void)
{
	struct intlist *i = NULL;
	char *p;
	int r;

	if ((p = NO_ARG(margv[0]) ? margv[1] : margv[0]) != NULL)
		i = (struct intlist *)genget(p, (char **)whichlist,
		    sizeof(struct intlist));
	if (Ambiguous(i)) {
		printf("%% Ambiguous command\n");
		return -1;
	}
	if (i == 0) {
		printf("%% Invalid command\n");
		return -1;
	}
	if (cand_refused(i->name, i->cand))
		return -1;
	if (in_config && i->cand != CAND_EDIT && i->handler != int_exit) {
		printf("%% %s is not through nshd's configure\n", i->name);
		return -1;
	}
	if ((r = (*i->handler)(margc, margv, ifname, -1)) == 1) {
		ifname[0] = '\0';
		return 0;
	}
	if (i->handler == int_interface && next_ifname[0] != '\0' &&
	    strcmp(next_ifname, ifname) != 0) {
		strlcpy(ifname, next_ifname, sizeof(ifname));
		memset(next_ifname, 0, sizeof(next_ifname));
		imr_init(ifname);
		bridge = cand_isbridge(ifname);
		whichlist = bridge ? Bridgelist : Intlist;
	}
	return r;
}

/*
 * Run a line of a configure session that nshd holds (nshd_config).
 * Commands that edit the candidate, and leaving a mode or configure, go
 * to nshd as text. Commands that run as they do outside a candidate run
 * here; commit, rollback and show candidate-config send their requests
 * to nshd as they run. Commands a candidate refuses are refused. Returns
 * what the handler returns, or -1 after printing why if none ran
 */
int
cmdline_nshd(char *text)
{
	struct intlist *i = NULL;
	char buf[sizeof(line)], *p;
	Command *c;

	if (strlcpy(buf, text, sizeof(buf)) >= sizeof(buf) ||
	    strlcpy(line, buf, sizeof(line)) >= sizeof(line)) {
		printf("%% Input exceeds permitted length\n");
		return -1;
	}
	if (makeargv() == -1) {
		printf("%% Too many words\n");
		return -1;
	}
	if (margv[0] == NULL)
		return 0;
	p = NO_ARG(margv[0]) ? margv[1] : margv[0];
	if (ifname[0] != '\0') {
		if (p != NULL)
			i = (struct intlist *)genget(p, (char **)whichlist,
			    sizeof(struct intlist));
		if (Ambiguous(i)) {
			printf("%% Ambiguous command\n");
			return -1;
		}
		if (i == 0) {
			printf("%% Invalid command\n");
			return -1;
		}
		if (i->cand == CAND_EDIT || i->handler == int_exit)
			return nshd_line(buf);
		if (i->cand == CAND_RUN)
			return (*i->handler)(margc, margv, ifname, -1);
		printf("%% %s is not supported in %s yet\n", i->name,
		    nshd_cname());
		return -1;
	}
	if (p == NULL || (c = getcmd(p)) == 0) {
		printf("%% Invalid command\n");
		return -1;
	}
	if (Ambiguous(c)) {
		printf("%% Ambiguous command\n");
		return -1;
	}
	if (NO_ARG(margv[0]) && ! c->nocmd) {
		printf("%% Invalid command: %s %s\n", margv[0], margv[1]);
		return -1;
	}
	/* nshd's system runs daemon operations not applied to the candidate */
	if (c->handler == ctlhandler && margc > 1 &&
	    ctl_op(c->name, margv[1], 1))
		return op_ask(c->name, margc, margv, nshd_rtable);
	/* edit a daemon's rules from nshd's candidate here, as the user */
	if (c->handler == ctlhandler && margc > 1 &&
	    ctl_edits(c->name, margv[1]))
		return ctl_nshd_edit(c->name);
	if (c->cand == CAND_EDIT)
		return nshd_line(buf);
	if (c->handler == exitconfig ||
	    (c->handler == doconfig && NO_ARG(margv[0])))
		return nshd_exit();
	if (c->handler == doconfig || (c->needconfig &&
	    c->cand != CAND_RUN)) {
		printf("%% %s is not supported in %s yet\n", c->name,
		    nshd_cname());
		return -1;
	}
	if (c->modh)
		strlcpy(hname, c->name, HSIZE);
	return (*c->handler)(margc, margv, 0);
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

/*
 * How row, of table, whose rows are stlen bytes, runs outside configure
 * (*out) and in configure (*conf), as nshd's CTL_COMMANDS rows say. Each
 * is RUN_*, or 0 where the row of the command above it says how it
 * runs. A command, and a command in an interface's or a bridge's mode,
 * always says; a row under a command says only where it runs otherwise:
 * a daemon's action (ctl_runs()) and flush's operations.
 */
void
row_runs(char **table, int stlen, char *row, int *out, int *conf)
{
	Command *c;
	struct intlist *i;
	Menu *f;

	*out = *conf = 0;
	if (table == (char **)cmdtab) {
		c = (Command *)row;
		*out = c->needconfig ? RUN_CONFIGURE : RUN_NSH;
		if (c->handler == group)
			*conf = RUN_OP;
		else if (c->cand == CAND_EDIT)
			*conf = RUN_LINE;
		else if (c->needconfig && c->cand != CAND_RUN)
			*conf = RUN_UNSUPPORTED;
		else
			*conf = RUN_NSH;
	} else if (table == (char **)Intlist || table == (char **)Bridgelist) {
		/* an interface's mode is only in configure */
		i = (struct intlist *)row;
		if (i->cand == CAND_EDIT || i->handler == int_exit)
			*conf = RUN_LINE;
		else if (i->handler == int_op)
			*conf = RUN_OP;
		else if (i->cand == CAND_RUN)
			*conf = RUN_NSH;
		else
			*conf = RUN_UNSUPPORTED;
	} else if (table == (char **)flushlist) {
		f = (Menu *)row;
		if (f->handler != flush_help && f->handler != flush_history)
			*out = *conf = RUN_OP;
	} else if (stlen == sizeof(struct ctl))
		ctl_runs((struct ctl *)row, out, conf);
}

/* Leave configure, from any mode, as exit does at the top */
int
cmdexit(void)
{
	char *argv[] = { "exit", NULL };

	ifname[0] = '\0';
	return exitconfig(1, argv);
}

/*
 * Hostname command.
 */
static int
hostname(int argc, char **argv, ...)
{
	argv++;
	argc--;

	if (argc > 1) {
		printf("%% Invalid arguments\n");
		return -1;
	}

	if (argc == 1) {
		if (candidate)
			return cand_setting(ST_ON, "hostname %s", *argv);
		if (sethostname(*argv, strlen(*argv))) {
			printf("%% sethostname: %s\n", strerror(errno));
			return -1;
		}
		return 0;
	}
	return show_hostname(0, NULL);
}

int
hostname_facts(struct facts_out *o)
{
	struct facts_value v[1];
	char host[MAXHOSTNAMELEN];

	if (gethostname(host, sizeof(host))) {
		printf("%% gethostname: %s\n", strerror(errno));
		return (-1);
	}
	memset(v, 0, sizeof(v));
	facts_string(&v[HOST_NAME], host);
	return (facts_record(o, &kind_hostname, v));
}

int
argvtostring(int argc, char **argv, char *string, int strlen)
{
	int i, j, sep = 0;

	for (i = 0, j = 0; argc && i < (strlen - 1); i++) {
		if (argv[0][j] == '\0') {
			argc--, argv++;
			string[i] = ' ';
			j = 0;
			sep = 1;
			continue;
		}
		string[i] = argv[0][j];
		j++;
		sep = 0;
	}
	/* drop the space after the last word, not a character of it */
	if (sep)
		i--;
	string[i] = '\0';

	return i;
}

/*
 * Move to table.  While a commit's edits run, a table the kernel does
 * not have yet takes its block's lines all the same: a route among them
 * makes the table (RTM_ADD does), and the process moves into it then
 * (conf_settle())
 */
static int
rtable_enter(int table)
{
	if (in_rc && getrtable() != table) {
		if (setrtable(table) == 0)
			init_bgpd_socket_path(table);
		else if (errno != EINVAL)
			return nsh_setrtable(table);
		cli_rtable = table;
		return 0;
	}
	if (nsh_setrtable(table))
		return 1;
	cli_rtable = table;
	return 0;
}

static int
rtable(int argc, char **argv, ...)
{
	int table, set, pos, found, curtable;
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
			return -1;
		}
	} else {
		set = 1;
	}

	if (argc < 2) {
		printf("%% rtable <table id> [name]\n");
		printf("%% no rtable <table id>\n");
		return -1;
	}

	table = strtonum(argv[1], 0, RT_TABLEID_MAX, &errstr);
	if (errstr) {
		printf("%% invalid table id: %s\n", errstr);
		return -1;
	}

	if (candidate) {
		pos = argvtostring(argc - 2, argv + 2, rtname, sizeof(rtname));
		return cand_rtable_set(set, table, pos ? rtname : NULL);
	}

	curtable = getrtable();
	if (cli_rtable != curtable) {
		printf("%% WARNING: nsh process rtable is out of sync "
		    "(want %d, have %d); "
		    "This is probably a bug in nsh, please report it.\n",
		    cli_rtable, curtable);
	}

	/*
	 * The kernel will prevent unprivileged users from switching
	 * away from rdomains other than 0.
	 */
	if (set && !priv && cli_rtable != 0 && cli_rtable != table) {
		printf("%% Privilege required\n");
		return -1;
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
		return -1;
	}

	if (set && (found && !pos)) {
		if (!priv && cli_rtable != 0) {
			printf("%% Privilege required\n");
			return -1;
		}
		/* Table found, skip database action */
		return rtable_enter(table) ? -1 : 0;
	}
	if (!set) {
		if (!found) {
			printf("%% rtable %d does not exist in database\n",
			    table);
			return -1;
		} else if (table == 0) {
			printf("%% cannot remove rtable %d\n", table);
			return -1;
		}
	} else if (table == 0)  {
		/* Do not add the kernel's default rtable 0 to the database. */
		if (nsh_setrtable(0))
			return -1;
		cli_rtable = 0;
		return 0;
	}
	if (db_delete_rtables_rtable(table) < 0) {
		printf("%% rtable db removal error\n");
		return -1;
	}
	if (set) {
		if (db_insert_rtables(table, rtname) < 0) {
			printf("%% rtable db insertion error\n");
			return -1;
		}
		if (rtable_enter(table))
			return -1;
	} else {
		if (nsh_setrtable(0))
			return -1;
		cli_rtable = 0;
	}

	return 0;
}

/*
 * Group attribute command.
 */
int
group(int argc, char **argv, ...)
{
	int counter = 1, set, ifs, ret = 0;
	const char *errstr;
	struct ifgroupreq ifgr;

	if (NO_ARG(argv[0])) {
		argv++;
		argc--;
		set = 0;
	} else
		set = 1;

	if (argc < 3 || argc > 4 || !isprefix(argv[2], "carpdemote")) {
		printf("%% group <group-name> carpdemote [demotion-counter]\n");
		printf("%% no group <group-name> carpdemote [demotion-counter]\n");
		return -1;
	}

	if (argc == 4) {
		counter = strtonum(argv[3], 0, 128, &errstr);
		if (errstr) {
			printf("%% invalid carp demotion: %s\n", errstr);
			return -1;
		}
	}

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% group: socket: %s\n", strerror(errno));

		return -1;
	}

	bzero(&ifgr, sizeof(ifgr));
	strlcpy(ifgr.ifgr_name, argv[1], sizeof(ifgr.ifgr_name));

	/* the kernel adds the counter to the group's */
	ifgr.ifgr_attrib.ifg_carp_demoted = set ? counter : -counter;

	if (ioctl(ifs, SIOCSIFGATTR, (caddr_t)&ifgr) == -1) {
		if (errno == ENOENT)
			printf("%% group %s does not exist\n", ifgr.ifgr_name);
		else if (errno == EINVAL)
			printf("%% group %s: demotion counter must stay within"
			    " 0 and 255\n", ifgr.ifgr_name);
		else
			printf("%% group: SIOCSIFGATTR: %s\n", strerror(errno));
		ret = -1;
	}
	close(ifs);

	return ret;
}

static int
doconfig(int argc, char **argv, ...)
{
	if (argc > 1) {
		if (NO_ARG(argv[0])) {
			return exitconfig(argc, argv);
		} else if (isprefix(argv[1], "terminal")) {
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
	} else {
		/* the candidate nshd's sessions share */
		return nshd_configure(NSHD_CSHARED);
	}

	return 0;
}

static int
exitconfig(int argc, char **argv, ...)
{
	if (!config_mode) {
		printf ("%% Configuration mode is already disabled\n");
		return -1;
	}
	if (cand_leave())
		return -1;

	config_mode = 0;
	return 0;
}

int
cand_refused(char *name, int cand)
{
	if (!candidate || cand != CAND_NO)
		return 0;
	printf("%% %s is not supported in configure private yet\n", name);
	return 1;
}

static int
cand_leave(void)
{
	/* a shared candidate stays for the sessions that share it */
	if (cand_sharing) {
		cand_detach();
		return 0;
	}
	if (cand_changed()) {
		printf("%% The candidate has uncommitted changes;"
		    " 'rollback' discards them\n");
		return 1;
	}
	if (candidate)
		cand_end();
	return 0;
}

/*
 * pf toilet flusher
 */
static int
flush_pf(int argc, char **argv, ...)
{
	struct fpf *x;
	va_list ap;
	char *arg;

	va_start(ap, argv);
	arg = va_arg(ap, char *);
	va_end(ap);

	if (!arg || arg[0] == '?') {
		gen_help((char **)fpfs, "flush pf", "flush",
		    sizeof(struct fpf));
		return 0;
	}
	x = (struct fpf *) genget(arg, (char **)fpfs, sizeof(struct fpf));
	if (x == 0) {
		printf("%% Invalid argument %s\n", arg);
		return -1;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", arg);
		return -1;
	}

	{
		char *argv[] = { x->cmd, x->arg, NULL };
		return cmdargs(x->cmd, argv) == 0 ? 0 : -1;
	}
}

/*
 * Save configuration
 */
int
wr_conf(char *fname)
{
	FILE *rchandle;
	int fd;

	/* its secrets are never for others to read, not even at first */
	if ((fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0640)) == -1)
		return 0;
	if (fchmod(fd, 0640) == -1 || (rchandle = fdopen(fd, "w")) == NULL) {
		close(fd);
		return 0;
	}
	conf(rchandle);
	return fclose(rchandle) != EOF;
}

/*
 * Flush wrappers
 */
static int
flush_ip_routes(int argc, char **argv, ...)
{
	va_list ap;
	char *verbose_arg;

	va_start(ap, argv);
	verbose_arg = va_arg(ap, char *);
	va_end(ap);

	flushroutes(AF_INET, AF_INET, verbose_arg != NULL);

	return 0;
}

static int
flush_arp_cache(int argc, char **argv, ...)
{
	va_list ap;
	char *verbose_arg;

	va_start(ap, argv);
	verbose_arg = va_arg(ap, char *);
	va_end(ap);

	flushroutes(AF_INET, AF_LINK, verbose_arg != NULL);

	return 0;
}

static int
flush_ndp_cache(int argc, char **argv, ...)
{
	ndpflush();
	return 0;
}

/*
 * the command a configuration line names, as the prompt reads it
 */
static Command *
conf_command(char *line)
{
	char word[2][64];
	Command *c;
	int n;

	if ((n = sscanf(line, "%63s %63s", word[0], word[1])) < 1)
		return NULL;
	if (NO_ARG(word[0])) {
		if (n < 2)
			return NULL;
		c = getcmd(word[1]);
	} else
		c = getcmd(word[0]);
	if (c == NULL || Ambiguous(c))
		return NULL;
	return c;
}

/*
 * what the statement in line does with the indented lines after it
 */
int
conf_mode(char *line)
{
	Command *c;

	if ((c = conf_command(line)) == NULL)
		return CT_LEAF;
	if (c->modh == 2)
		return CT_NESTED;
	if (c->modh == 1)
		return CT_LINES;
	return CT_LEAF;
}

/*
 * whether line is "<daemon> rules", whose indented lines are the
 * daemon's configuration file, in order
 */
int
conf_ordered(char *line)
{
	char word[2][64];
	Command *c;

	if (sscanf(line, "%63s %63s", word[0], word[1]) != 2)
		return 0;
	c = getcmd(word[0]);
	return (c != NULL && !Ambiguous(c) && c->handler == ctlhandler &&
	    isprefix(word[1], "rules"));
}

/*
 * Row n of the commands a configuration has in ctx, CTX_TOP, CTX_IF or
 * CTX_BRIDGE, or NULL if there is no such row
 */
const struct confcmd *
conf_cmd(int ctx, int n)
{
	const struct confcmd *t;
	size_t len;

	switch (ctx) {
	case CTX_TOP:
		t = conf_top;
		len = nitems(conf_top);
		break;
	case CTX_IF:
		t = conf_if;
		len = nitems(conf_if);
		break;
	case CTX_BRIDGE:
		t = conf_bridge;
		len = nitems(conf_bridge);
		break;
	default:
		return NULL;
	}
	return n >= 0 && (size_t)n < len ? &t[n] : NULL;
}

/*
 * The row (conf_cmd()) of the command word names in ctx, as nsh reads
 * it at the top level, or in an interface's or a bridge's mode. -1 if
 * word names none, or a command a configuration does not have; at the
 * top level, -2 for a daemon, with its name in *daemon
 */
int
conf_find(int ctx, char *word, char **daemon)
{
	const struct confcmd *c;
	struct intlist *i;
	Command *t;
	char *name;
	int n;

	if (ctx == CTX_TOP) {
		if ((t = getcmd(word)) == NULL || Ambiguous(t))
			return -1;
		if (t->handler == ctlhandler) {
			*daemon = t->name;
			return -2;
		}
		name = t->name;
	} else if (ctx == CTX_IF || ctx == CTX_BRIDGE) {
		i = (struct intlist *)genget(word, (char **)(ctx == CTX_IF ?
		    Intlist : Bridgelist), sizeof(struct intlist));
		if (i == NULL || Ambiguous(i))
			return -1;
		name = i->name;
	} else
		return -1;
	/* each name appears only once in its table */
	for (n = 0; (c = conf_cmd(ctx, n)) != NULL; n++)
		if (strcmp(c->name, name) == 0)
			return n;
	return -1;
}

/*
 * Run row n of ctx's commands (conf_cmd()) with argv, as a commit runs a
 * line of its edits: at the top level a statement, a block's head
 * included, and in an interface's or a bridge's mode a line of name's
 * block. Returns what the command returns
 */
int
conf_run(int ctx, int n, int argc, char **argv, char *name)
{
	const struct confcmd *c = conf_cmd(ctx, n);
	int r;

	if (ctx != CTX_TOP)
		return conf_run_if(ctx == CTX_BRIDGE, c, argc, argv, name);
	if ((c->flags & (CF_IF | CF_BRIDGE)) == 0)
		return (*c->handler)(argc, argv, 0);
	/* a block's head creates a cloned interface, or with no, destroys it */
	rc_head = 1;
	r = (*c->handler)(argc, argv, 0);
	rc_head = 0;
	return r;
}

/*
 * Run c, an interface command or, with bridgeline, a bridge command,
 * with argv on name in rtable 0, as interface mode runs a line. name
 * must exist, and must be a bridge only if c is a bridge command.
 * Returns 0, or -1 if c failed or did not run, after printing why
 */
static int
conf_run_if(int bridgeline, const struct confcmd *c, int argc, char **argv,
    char *name)
{
	int ifs, r = -1, rt = cli_rtable;

	if (strlcpy(ifname, name, sizeof(ifname)) >= sizeof(ifname)) {
		printf("%% interface name too long\n");
		ifname[0] = '\0';
		return -1;
	}
	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		printf("%% socket failed: %s\n", strerror(errno));
		ifname[0] = '\0';
		return -1;
	}
	/* its block's head made it, if it could */
	if (!is_valid_ifname(ifname)) {
		printf("%% interface %s not found\n", ifname);
		goto done;
	}
	if ((bridge = is_bridge(ifs, ifname)) != bridgeline) {
		printf("%% %s is %sa bridge\n", ifname, bridge ? "" : "not ");
		goto done;
	}
	imr_init(ifname);
	if (getrtable() != 0 && !priv) {
		printf("%% Privilege required\n");
		goto done;
	}
	if (cli_rtable != 0 && nsh_setrtable(0) == 0)
		cli_rtable = 0;
	r = (*c->handler)(argc, argv, ifname, ifs) == -1 ? -1 : 0;
	if (rt != cli_rtable && nsh_setrtable(rt) == 0)
		cli_rtable = rt;
done:
	ifname[0] = '\0';
	close(ifs);
	return r;
}

/* Mark that a commit's edits are running (on) or have finished */
void
conf_reading(int on)
{
	in_rc = on;
	if (on)
		init_bgpd_socket_path(cli_rtable);
}

/* A block of a commit's edits ended: return to routing table rt */
void
conf_block_end(int rt)
{
	if (cli_rtable != rt && nsh_setrtable(rt) == 0)
		cli_rtable = rt;
}

/* An edit ran: the process goes in the table it left */
void
conf_settle(void)
{
	if (cli_rtable != getrtable() && setrtable(cli_rtable) == 0)
		init_bgpd_socket_path(cli_rtable);
}

/*
 * The running configuration as a tree: running_set() and running_tree()
 */
/*
 * nshd's config: the running configuration as system's last snapshot
 * gave it, which running_tree() gives from now on
 */
void
running_set(struct cnode *t)
{
	conftree_free(snapshot);
	snapshot = t;
}

struct cnode *
running_tree(void)
{
	char path[PATH_MAX];
	struct cnode *t = NULL;
	int fd;

	if (snapshot != NULL) {
		if ((t = conftree_copy(snapshot)) == NULL)
			printf("%% running_tree: %s\n", strerror(errno));
		return t;
	}

	if (strlcpy(path, "/tmp/nshrc.XXXXXXXX", sizeof(path)) >= sizeof(path))
		return NULL;
	if ((fd = mkstemp(path)) == -1) {
		printf("%% mkstemp %s: %s\n", path, strerror(errno));
		return NULL;
	}
	if (wr_conf(path))
		t = conftree_read(path, conf_mode, conf_ordered);
	else
		printf("%% Couldn't generate configuration\n");
	unlink(path);
	close(fd);
	return t;
}
