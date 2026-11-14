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
#include <netinet/if_ether.h>
#include <netinet/ip_carp.h>
#include <netinet6/nd6.h>
#include <net/if_bridge.h>
#include <net/if_media.h>
#include <net/if_pflow.h>
#include <net/if_pppoe.h>
#include <net/if_sppp.h>
#include <net/if_trunk.h>
#include <net/if_wg.h>
#include <net/ppp_defs.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <netmpls/mpls.h>
#include <dev/usb/mbim.h>
#include <dev/usb/if_umb.h>
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
#include "args.h"
#include "showfacts.h"
#include "session.h"
#include "commands.h"
#include "nshcmds.h"

/*
 * The rows and help of nsh's own commands, which the tables here name
 * for a client that completes lines. nsh runs them: a row of them has
 * no handler here
 */
#define RUNS(f)	NULL
#include "nshrows.h"

static int in_rc;		/* a commit's edits run */
static struct cnode *snapshot;	/* config's running configuration */

static int	exitconfig(int, char **, ...);
static int	cmdline_if_edits(char *, int, FILE *);
static edit_runfn	line_ran, ifline_ran, head_ran;
static const struct argcmd *int_cmd(const struct intlist *, struct argcmd *);
static const struct argcmd *top_cmd(const Command *, struct argcmd *);
static args_applyfn	ipcmd_apply, flush_ip_routes, flush_arp_cache,
			flush_ndp_cache, flush_line, flush_pf, op_halt, op_diff,
			op_crontab, demote_apply, interface_apply,
			hostname_apply, rtable_apply;
static args_parsefn	ipcmd_parse, flush_pf_parse, demote_parse,
			interface_parse;
static int	conf_run_if(int, const struct argcmd *, int,
		    const struct facts_value *, char *);
static int	cand_leave(struct cand *);
static int	cmdline_if(void);
static int	sysctlhelp(int, char **, ...);
static int	flush_op(int, char **, ...);
static Menu	*flush_find(char *);
static int	int_op(int, char **, ...);
static struct intlist *int_op_find(int, char **);
static int	int_exit(int, char **, ...);
static int	hostname(int, char **, ...);
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
	{ "arptimeout",	"Seconds for ARP entries to remain in cache",	CMPL(h) (char **)arptimeouttab, sizeof(struct ghs), 1, 1 },
	{ "arpdown",	"Seconds before resending unanswered ARP requests", CMPL(h) (char **)arpdowntab, sizeof(struct ghs), 1, 1 },
	{ "carp",	"Allow CARP",			CMPL(h) (char **)carptab, sizeof(struct ghs), 0, 0 },
	{ "carp-log",	"CARP Logging Priority",	CMPL(h) (char **)carploggingtab, sizeof(struct ghs), 1, 1 },
	{ "carp-preempt", "CARP Virtual Host Preemption", CMPL(h) (char **)carppreempttab, sizeof(struct ghs), 0, 0 },
	{ "forwarding",	"Enable IPv4 Forwarding",	CMPL(h) (char **)forwardingtab, sizeof(struct ghs), 0, 0 },
	{ "mforwarding", "Enable IPv4 Multicast Forwarding", CMPL(h) (char **)mforwardingtab, sizeof(struct ghs), 0, 0 },
	{ "ipip",	"Allow IP-in-IP Encapsulation", CMPL(h) (char **)ipiptab, sizeof(struct ghs), 0, 0 },
	{ "gre",	"Allow Generic Route Encapsulation", CMPL(h) (char **)gretab, sizeof(struct ghs), 0, 0 },
	{ "wccp",	"Allow Web Cache Control Protocol", CMPL(h) (char **)wccptab, sizeof(struct ghs), 0, 0 },
	{ "etherip",	"Allow Ether-IP Encapsulation",	CMPL(h) (char **)etheriptab, sizeof(struct ghs), 0, 0 },
	{ "ipcomp",	"Allow IP Compression",		CMPL(h) (char **)ipcomptab, sizeof(struct ghs), 0, 0 },
	{ "esp",	"Allow Encapsulated Security Payload", CMPL(h) (char **)esptab, sizeof(struct ghs), 0, 0 },
	{ "esp-udpencap","Allow ESP encapsulation within UDP", CMPL(h) (char **)espudpencaptab, sizeof(struct ghs), 0, 0 },
	{ "esp-udpencap-port","UDP port number for encapsulation", CMPL(h) (char **)espudpencapporttab, sizeof(struct ghs), 1, 1 },
	{ "ah",		"Allow Authentication Header",	CMPL(h) (char**)ahtab, sizeof(struct ghs), 0, 0 },
	{ "sourceroute", "Process Loose/Strict Source Route Options", CMPL(h) (char**)sourceroutetab, sizeof(struct ghs), 0, 1 },
	{ "encdebug",	"Enable if_enc debugging",	CMPL(h) (char **)encdebugtab, sizeof(struct ghs), 0, 0 },
	{ "send-redirects", "Send ICMP redirects",	CMPL(h) (char **)sendredirectstab, sizeof(struct ghs), 0, 0 },
	{ "directed-broadcast", "Allow directed broadcasts", CMPL(h) (char **)directedbroadcaststab, sizeof(struct ghs), 0, 0 },
	{ "multipath",	"Multipath routing",		CMPL(h) (char **)multipathtab, sizeof(struct ghs), 0, 0 },
	{ "maxqueue", "Maximum unassembled IP fragments in the fragment queue", CMPL(h) (char **)maxqueuetab, sizeof(struct ghs), 1, 1 },
	{ "mtudisc", "Enable Path MTU Discovery",       CMPL(h) (char **)mtudisctab, sizeof(struct ghs), 0, 0 },
	{ "mtudisctimeout", "Timeout in seconds for routes added by Path MTU discovery engine", CMPL(h) (char **)mtudisctimeouttab, sizeof(struct ghs), 1, 1 },
	{ "ipsec-timeout", "Seconds after a SA is established before it will expire", CMPL(h) (char **)ipsectimeouttab, sizeof(struct ghs), 1, 1 },
	{ "ipsec-soft-timeout", "Seconds after a SA is established before being renegotiated", CMPL(h) (char **)ipsecsofttimeouttab, sizeof(struct ghs), 1, 1 },
	{ "ipsec-allocs", "Maximum IPSEC flows that can use a SA before it expires", CMPL(h) (char **)ipsecallocstab, sizeof(struct ghs), 1, 1 },
	{ "ipsec-soft-allocs", "Maximum IPSEC flows a SA uses before renegotiation", CMPL(h) (char **)ipsecsoftallocstab, sizeof(struct ghs), 1, 1 },
	{ "ipsec-bytes", "Maximum bytes processed by a security association before it expires", CMPL(h) (char **)ipsecbytestab, sizeof(struct ghs), 1, 1 },
	{ "ipsec-soft-bytes", "Maximum bytes a SA processes before renegotiation", CMPL(h) (char **)ipsecsoftbytestab, sizeof(struct ghs), 1, 1 },
	{ "ipsec-expire-acquire", "Seconds the kernel allows to dynamically acquire SAs before a request", CMPL(h) (char **)ipsecexpireacquiretab, sizeof(struct ghs), 1, 1 },
	{ "ipsec-firstuse", "Seconds after security association is first used before it expires", CMPL(h) (char **)ipsecfirstusetab, sizeof(struct ghs), 1, 1 },
	{ "ipsec-soft-firstuse", "Seconds after a SA is first used before it is sent for renegotiation", CMPL(h) (char **)ipsecsoftfirstusetab, sizeof(struct ghs), 1, 1 },
	{ "ipsec-invalid-life", "Lifetime of Embryonic SAs in seconds", CMPL(h) (char **)ipsecinvalidlifetab, sizeof(struct ghs), 1, 1 },
	{ "ipsec-pfs", "Enables Perfect Forward Secrecy when establishing SAs", CMPL(h) (char **)ipsecpfstab, sizeof(struct ghs), 0, 0 },
	{ "portfirst", "Minimum registered port number for TCP/UDP port allocation", CMPL(h) (char **)portfirsttab, sizeof(struct ghs), 1, 1 },
	{ "porthifirst", "Minimum dynamic/private port number for TCP/UDP port allocation", CMPL(h) (char **)porthifirsttab, sizeof(struct ghs), 1, 1 },
	{ "porthilast", "Maximum dynamic/private port number for TCP/UDP port allocation", CMPL(h) (char **)porthilasttab, sizeof(struct ghs), 1, 1 },
	{ "portlast", "Maximum registered port number for TCP/UDP port allocation", CMPL(h) (char **)portlasttab, sizeof(struct ghs), 1, 1 },
#ifdef notyet
	{ "default-mtu", "Default interface MTU",	CMPL(h) (char **)defaultmtutab, sizeof(struct ghs), 1, 1 },
#endif
	{ "default-ttl", "Default IP packet TTL",	CMPL(h) (char **)defaultttltab, sizeof(struct ghs), 1, 1 },
	{ "?",		"Options",			CMPL0 0, 0, 0, 0, sysctlhelp },
	{ 0, 0, 0, 0, 0, 0, 0, 0 }
};

Menu ip6tab[] = {
	{ "auto_flowlabel", "Fill the IPv6 flowlabel field to help intermediate routers identify packet flows", CMPL0 0, 0, 0, 0 },
	{ "dad_count", "Configures the number of IPv6 D.A.D. probe packets", CMPL0 0, 0, 1, 1 },
	{ "defmcasthlim", "The default hop limit value for an IPv6 multicast packet sourced by the system", CMPL0 0, 0, 1, 1 },
	{ "forwarding", "Enable IPv6 Forwarding",       CMPL0 0, 0, 0, 0 },
	{ "hdrnestlimit", "The number of IPv6 extension headers permitted on incoming IPv6 packets", CMPL0 0, 0, 1, 1 },
	{ "hoplimit", "The default hop limit for IPv6 unicast packet sourced by the system", CMPL0 0, 0, 1, 1 },
	{ "log_interval", "Configures the amount of logs generated by the IPv6 packet forwarding engine", CMPL0 0, 0, 1, 1 },
	{ "maxdynroutes", "Max IPv6 Dyn Routes",        CMPL0 0, 0, 1, 1 },
	{ "maxfragpackets", "The maximum number of fragmented packets the system will accept", CMPL0 0, 0, 1, 1 },
	{ "maxfrags", "The maximum number of fragments the node will accept", CMPL0 0, 0, 1, 1 },
	{ "mforwarding", "Enable IPv6 Multicast Forwarding", CMPL0 0, 0, 0, 0 },
	{ "mtudisctimeout", "Seconds after which a route added by the Path MTU Discovery engine will time out", CMPL0 0, 0, 1, 1 },
	{ "multicast_mtudisc", "Enables ICMPv6 too big messages when machine is an IPv6 multicast router", CMPL0 0, 0, 0, 0 },
	{ "multipath",  "Multipath routing",            CMPL0 0, 0, 0, 0 },
	{ "neighborgcthresh", "Maximum number of entries in neighbor cache", CMPL0 0, 0, 1, 1 },
	{ "send-redirect", "Enables sending ICMPv6 redirects by the system", CMPL0 0, 0, 0, 0 },
	{ "?",          "Help",                         CMPL0 0, 0, 0, 0, sysctlhelp },
	{ 0, 0, 0, 0, 0, 0, 0, 0 }
};

Menu mplstab[] = {
	{ "ttl",	"MPLS ttl",			CMPL0 0, 0, 1, 1 },
	{ "mapttl-ip",	"MPLS mapttl IPv4",		CMPL0 0, 0, 0, 1 },
	{ "mapttl-ip6",	"MPLS mapttl IPv6",		CMPL0 0, 0, 0, 1 },
	{ "?",		"Help",				CMPL0 0, 0, 0, 0, sysctlhelp },
	{ 0, 0, 0, 0, 0, 0, 0, 0 }
};

Menu ddbtab[] = {
	{ "panic",	"DDB panic",			CMPL0 0, 0, 0, 0 },
	{ "console",	"DDB console",			CMPL0 0, 0, 0, 0 },
	{ "log",	"DDB log",			CMPL0 0, 0, 0, 0 },
	{ "?",		"Help",				CMPL0 0, 0, 0, 0, sysctlhelp },
	{ 0, 0, 0, 0, 0, 0, 0, 0 }
};

Menu pipextab[] = {
	{ "enable",	"PIPEX enable",			CMPL0 0, 0, 0, 0 },
	{ "?",		"Help",				CMPL0 0, 0, 0, 0, sysctlhelp },
	{ 0, 0, 0, 0, 0, 0, 0, 0 }
};

/*
 * ip, ip6, mpls, ddb and pipex: a sysctl of the table the line's word
 * names, as its index there, and its value, if it takes one
 * (ipcmd_parse())
 */

/* The table of sysctls c is for */
static struct sysctltab *
ipcmd_tab(const struct argcmd *c)
{
	struct sysctltab *stab;

	for (stab = sysctls; stab->name != NULL &&
	    strcmp(stab->name, c->name) != 0; stab++)
		;
	return stab;
}

static int
ipcmd(int argc, char **argv, ...)
{
	struct sysctltab *stab;
	int n = NO_ARG(argv[0]) ? 1 : 0;

	/*
	 * Find ourself in the great divide
	 */
	stab = (struct sysctltab *)genget(argv[n], (char **)sysctls,
	    sizeof(struct sysctltab));
        if (stab == 0) {
                printf("%% Invalid argument %s\n", argv[n]);
                return -1;
        } else if (Ambiguous(stab)) {
                printf("%% Ambiguous argument %s\n", argv[n]);
                return -1;
        }

	/* with no sysctl, or "?", the table's help */
	if (argc < n + 2 || strcmp(argv[n + 1], "?") == 0) {
		sysctlhelp(0, NULL, NULL, stab->pf);
		return 0;
	}
	return LINE_ARGS;
}

/* the sysctl's word, and its value */
static int
ipcmd_parse(const struct argcmd *c, int argc, char **argv,
    struct argvals *a)
{
	struct sysctltab *stab = ipcmd_tab(c);
	struct ipsysctl *x;
	Menu *i;

	if (argc < 1) {
		sysctlhelp(0, NULL, NULL, stab->pf);
		return -1;
	}
	/*
	 * Validate ip argument
	 */
        i = (Menu *)genget(argv[0], (char **)stab->table, sizeof(Menu));
	if (i == 0) {
		printf("%% Invalid argument %s\n", argv[0]);
		return -1;
	} else if (Ambiguous(i)) {
		printf("%% Ambiguous argument %s\n", argv[0]);
		return -1;
	}
	if (((i->minarg + 1) > argc) || ((i->maxarg + 1) < argc)) {
		printf("%% Wrong argument%s to '%s %s' command.\n",
		    argc <= 1 ? "" : "s", c->name, i->name);
		return -1;
	}
	x = (struct ipsysctl *)genget(i->name, (char **)stab->sysctl,
	    sizeof(struct ipsysctl));
	if (x == 0 || Ambiguous(x)) {
		printf("%% Invalid argument %s\n", argv[0]);
		return -1;
	}
	facts_i64(&a->v[0], x - stab->sysctl);
	/* a "no" line's value is ignored */
	if (argc == 2 && a->set &&
	    args_word(c, &c->args[1], a, argv[1], &a->v[1]) == -1)
		return -1;
	return 0;
}

static int
ipcmd_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	struct sysctltab *stab = ipcmd_tab(c);
	struct ipsysctl *x;
	int n;

	for (x = stab->sysctl, n = 0; x->name != NULL && n < v[0].v.i; x++)
		n++;
	if (x->name == NULL) {
		printf("%% %s has no sysctl %lld\n", c->name,
		    (long long)v[0].v.i);
		return -1;
	}
	/* a sysctl set with no value is on */
	return ipsysctl_set(stab, x, !set ? x->def_larg :
	    v[1].type != FACT_NONE ? v[1].v.i : 1, cand);
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
	    sizeof(struct ghs), 0, 1, flush_op },
	{ "arp",	"ARP cache", CMPL(h) (char **)flushtab,
	    sizeof(struct ghs), 0, 1, flush_op },
	{ "ndp",	"NDP cache", CMPL0 0, 0, 0, 0, flush_op },
	{ "line",	"Active user", CMPL0 0, 0, 1, 1, flush_op },
	{ "bridge-dyn",	"Dynamically learned bridge addresses", CMPL0 0, 0, 1, 1, flush_op },
	{ "bridge-all",	"Dynamic and static bridge addresses", CMPL0 0, 0, 1, 1, flush_op },
	{ "bridge-rule", "Layer 2 filter rules for a bridge member port", CMPL0 0, 0, 2, 2, flush_op },
	{ "pf",		"pf NAT/filter/queue rules, states, tables", CMPL(t) (char**)fpfs, sizeof(struct fpf), 0, 1, flush_op },
	{ "history",	"Command history",	CMPL0 0, 0, 0, 0, 0 },
	{ "?",		"Options",		CMPL0 0, 0, 0, 0, 0 },
	{ "help",	0,			CMPL0 0, 0, 0, 0, 0 },
	{ 0, 0, 0, 0, 0 }
};

/*
 * flush's operations: each row of flushlist with flush_op is one of
 * ops[], called "flush" and its name
 */
/* fpfs's row; with none, flush pf's help */

/* flush's entry for word, or NULL */
static Menu *
flush_find(char *word)
{
	Menu *f;

	f = (Menu *)genget(word, (char **)flushlist, sizeof(Menu));
	return f == 0 || Ambiguous(f) ? NULL : f;
}

/*
 * flush's rows that are operations of nshd's system (row_runs()). nsh
 * asks nshd's system for them itself, so nothing runs here
 */
static int
flush_op(int argc, char **argv, ...)
{
	printf("%% flush is an operation of nshd's system\n");
	return -1;
}

static int
flush_line(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	char tty[sizeof(line)];
	char * args[5] = { PKILL, "-9", "-t", tty, NULL };
	int r;

	args_string(&v[0], tty, sizeof(tty));
	/* pkill exits 1 if no process ran on the line */
	r = cmdargs(PKILL, args);
	return r == -1 || r > 1 ? -1 : 0;
}

/*
 * reboot, halt and powerdown, which nsh has the user confirm first;
 * diff-config, of the saved configuration against the running one; and
 * crontab, root's crontab
 */
static int op_hide;		/* diff-config hides each password hash */

static const struct arg flushbridge_args[] = {
	{ "bridge",	ARG_WORD, 1, IFNAMSIZ - 1 },
	{ NULL }
};

static const struct arg flushverbose_args[] = {
	{ "verbose",	ARG_FLAG },
	{ NULL }
};

/*
 * The operations nshd's system runs, as root, for a privileged session:
 * those above; flush, except help and history, which nsh runs; a
 * daemon's action that runs a program and does not change its
 * configuration (daemon_cmd); an interface's bssid, setpuk and chgpin;
 * and a group's carp demotion counter, as group or no group sets it.
 * config parses nsh's words for one (op_parse()), and system checks the
 * values with args_check() and runs them (op_run())
 */
enum { OP_REBOOT, OP_HALT, OP_POWERDOWN };	/* op_halt()'s */
const struct argcmd ops[] = {
	{ "reboot", .flags = CF_SET, .apply = op_halt, .code = OP_REBOOT },
	{ "halt", .flags = CF_SET, .apply = op_halt, .code = OP_HALT },
	{ "powerdown", .flags = CF_SET, .apply = op_halt,
	  .code = OP_POWERDOWN },
	{ "diff-config", .flags = CF_SET, .apply = op_diff },
	{ "crontab", .flags = CF_SET, .apply = op_crontab },
	{ "flush routes", .flags = CF_SET, .apply = flush_ip_routes,
	  .args = flushverbose_args },
	{ "flush arp", .flags = CF_SET, .apply = flush_arp_cache,
	  .args = flushverbose_args },
	{ "flush ndp", .flags = CF_SET, .apply = flush_ndp_cache },
	{ "flush line", .flags = CF_SET, .apply = flush_line,
	  .args = ARGS{
		{ "line",	ARG_WORD, 1, sizeof(line) - 1 },
		{ NULL } } },
	{ "flush bridge-dyn", .flags = CF_SET, .apply = flush_bridgedyn,
	  .args = flushbridge_args },
	{ "flush bridge-all", .flags = CF_SET, .apply = flush_bridgeall,
	  .args = flushbridge_args },
	{ "flush bridge-rule", .flags = CF_SET, .apply = flush_bridgerule,
	  .args = ARGS{
		{ "bridge",	ARG_WORD, 1, IFNAMSIZ - 1 },
		{ "member",	ARG_WORD, 1, IFNAMSIZ - 1 },
		{ NULL } } },
	{ "flush pf", .flags = CF_SET, .apply = flush_pf,
	  .parse = flush_pf_parse,
	  .args = ARGS{
		{ "pf",		ARG_NUM, 0, nitems(fpfs) - 2, ARG_OPT },
		{ NULL } } },
	{ "bssid", .flags = CF_INIF, .apply = bssid_apply,
	  .args = ARGS{
		{ "bssid",	ARG_ADDR, 0, 0, ARG_LINK },
		{ NULL } } },
	{ "setpuk", .flags = CF_INIF | CF_SET, .apply = intumb_apply,
	  .code = UMBCMD_PUK,
	  .args = ARGS{
		{ "puk",	ARG_WORD, 1, MBIM_PIN_MAXLEN / 2 },
		{ "newpin",	ARG_WORD, 1, MBIM_PIN_MAXLEN / 2 },
		{ NULL } } },
	{ "chgpin", .flags = CF_INIF | CF_SET, .apply = intumb_apply,
	  .code = UMBCMD_CHGPIN,
	  .args = ARGS{
		{ "oldpin",	ARG_WORD, 1, MBIM_PIN_MAXLEN / 2 },
		{ "newpin",	ARG_WORD, 1, MBIM_PIN_MAXLEN / 2 },
		{ NULL } } },
	{ "group", .apply = demote_apply, .parse = demote_parse,
	  .args = ARGS{
		{ "group",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO },
		{ "carpdemote",	ARG_NUM, 0, 128, ARG_OPT | ARG_NO },
		{ NULL } } },
	{ "daemon", .flags = CF_SET, .apply = daemon_apply,
	  .parse = daemon_parse,
	  .args = ARGS{
		{ "daemon",	ARG_NUM, 0, INT_MAX },
		{ "action",	ARG_NUM, 0, INT_MAX },
		{ "words",	ARG_WORD, 1, sizeof(line) - 1, ARG_OPT, NULL,
		    NOPTFILL - 1 },
		{ NULL } } },
};
const size_t nops = nitems(ops);

/* The row of ops[] called name, an interface's if inif; nops if none */
static size_t
op_find(const char *name, int inif)
{
	size_t row;

	for (row = 0; row < nops; row++)
		if (((ops[row].flags & CF_INIF) != 0) == inif &&
		    strcmp(ops[row].name, name) == 0)
			break;
	return row;
}

/*
 * Parse nsh's words for an operation, w (n of them), into a with the
 * arguments of the row of ops[] that runs it, and an interface's
 * operation's interface into ifname (len bytes). Each is its first
 * word, as nsh names it, and the words after it as typed. The row, or
 * -1 after saying why not
 */
int
op_parse(int n, char **w, struct argvals *a, char *ifname, size_t len)
{
	struct intlist *i;
	Menu *f;
	char *dw[NARGS + 1], fname[32], **argv = w;
	const char *name = w[0];
	int argc = n, inif = 0;
	size_t row;

	ifname[0] = '\0';
	if (n >= 3 && strcmp(w[0], "interface") == 0 &&
	    (i = int_op_find(n - 2, w + 2)) != NULL) {
		if (strlcpy(ifname, w[1], len) >= len) {
			printf("%% interface name too long\n");
			return -1;
		}
		name = i->name;
		inif = 1;
		argc = n - 2;
		argv = w + 2;
	} else if (n >= 2 && strcmp(w[0], "flush") == 0 &&
	    (f = flush_find(w[1])) != NULL && f->handler == flush_op) {
		snprintf(fname, sizeof(fname), "flush %s", f->name);
		name = fname;
		argc = n - 1;
		argv = w + 1;
	} else if (n >= 2 && strcmp(w[0], "no") == 0 &&
	    strcmp(w[1], "group") == 0)
		name = "group";
	else if (n >= 2 && n <= NARGS && ctl_op(w[0], w[1])) {
		/* daemon_cmd takes the daemon's word and the action's */
		dw[0] = "daemon";
		memcpy(dw + 1, w, n * sizeof(*w));
		name = dw[0];
		argc = n + 1;
		argv = dw;
	}
	if ((row = op_find(name, inif)) == nops) {
		printf("%% %s: not an operation nshd runs\n", w[0]);
		return -1;
	}
	if (args_parse(&ops[row], argc, argv, a) == -1)
		return -1;
	return row;
}

/*
 * Run the row of ops[] with values v, which args_check() takes for it
 * (set is 0 for "no"), on interface ifname if it is an interface's. As
 * the row's apply function returns, OP_DIFFERS from diff-config if the
 * configurations differ. With hide, for a session that sees no password
 * hash, diff-config hides each one
 */
int
op_run(int row, int set, const struct facts_value *v, char *ifname,
    int hide)
{
	const struct argcmd *o = &ops[row];
	int inif = (o->flags & CF_INIF) != 0;
	int ifs = -1, r;

	op_hide = hide;
	if (inif && (ifs = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		printf("%% socket: %s\n", strerror(errno));
		return -1;
	}
	r = o->apply(o, set, v, inif ? ifname : NULL, ifs, NULL);
	if (ifs != -1)
		close(ifs);
	return r;
}

static int
op_halt(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	char *rb[] = { REBOOT, NULL }, *ht[] = { HALT, NULL, NULL };

	if (c->code == OP_REBOOT)
		return cmdargs(rb[0], rb) == 0 ? 0 : -1;
	if (c->code == OP_POWERDOWN)
		ht[1] = "-p";
	return cmdargs(ht[0], ht) == 0 ? 0 : -1;
}

static int
op_diff(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	int r;

	return (r = saved_diff(op_hide)) == 1 ? OP_DIFFERS : r;
}

static int
op_crontab(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	char *cr[] = { CRONTAB, "-l", "-u", "root", NULL };

	printf("%% To view crontab syntax documentation in NSH, "
	    "run: !man 5 crontab\n\n");
	fflush(stdout);
	if (cmdargs(cr[0], cr) != 0) {
		printf("%% crontab command failed\n");
		return -1;
	}
	return 0;
}

/*
 * In an interface's mode, bssid, setpuk and chgpin, as operations nshd's
 * system runs.  This handler marks their rows (row_runs()); nsh asks
 * nshd's system for them itself, so nothing runs here
 */
static int
int_op(int argc, char **argv, ...)
{
	printf("%% %s is an operation of nshd's system\n", argv[0]);
	return -1;
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

/*
 * Data structures and routines for the interface configuration mode
 */

static char crontabhelp[];
static char interfacehelp[];
extern struct ghs mantab[];

/* the words arguments take, by the table of each */
static const struct argkey balancing_keys[] = {
	{ "none", CARP_BAL_NONE }, { "ip", CARP_BAL_IP },
	{ "ip-stealth", CARP_BAL_IPSTEALTH },
	{ "ip-unicast", CARP_BAL_IPUNICAST }, { NULL }
};
static const struct argkey brprotos[] = {
	{ "stp", BSTP_PROTO_STP }, { "rstp", BSTP_PROTO_RSTP }, { NULL }
};
static const struct argkey bractions[] = {
	{ "block", BRL_ACTION_BLOCK }, { "pass", BRL_ACTION_PASS }, { NULL }
}, brdirs[] = {
	{ "in", BRL_FLAG_IN }, { "out", BRL_FLAG_OUT },
	{ "in/out", BRL_FLAG_IN | BRL_FLAG_OUT }, { NULL }
};
static const struct argkey brpvids[] = {
	{ "passthrough", IFBR_PVID_DECLINE }, { "none", IFBR_PVID_NONE },
	{ "default", EVL_VLID_NULL }, { NULL }
};
/* data class names, as umb_classes() prints them, plus 2g, 3g and 4g */
static const struct argkey class_keys[] = {
	{ "none", MBIM_DATACLASS_NONE }, { "GPRS", MBIM_DATACLASS_GPRS },
	{ "EDGE", MBIM_DATACLASS_EDGE }, { "UMTS", MBIM_DATACLASS_UMTS },
	{ "HSDPA", MBIM_DATACLASS_HSDPA }, { "HSUPA", MBIM_DATACLASS_HSUPA },
	{ "HSPA", MBIM_DATACLASS_HSDPA | MBIM_DATACLASS_HSUPA },
	{ "LTE", MBIM_DATACLASS_LTE }, { "CDMA2000", MBIM_DATACLASS_1XRTT },
	{ "custom", MBIM_DATACLASS_CUSTOM },
	{ "2g", MBIM_DATACLASS_GPRS | MBIM_DATACLASS_EDGE },
	{ "3g", MBIM_DATACLASS_UMTS | MBIM_DATACLASS_HSDPA |
	    MBIM_DATACLASS_HSUPA },
	{ "4g", MBIM_DATACLASS_LTE }, { NULL }
};
static const struct argkey defer_keys[] = { { "defer", 1 }, { NULL } };
static const struct argkey proto_keys[] = {
	{ "pap", PPP_PAP }, { "chap", PPP_CHAP }, { NULL }
};
static const struct argkey flag_keys[] = {
	{ "callin", AUTHFLAG_NOCALLOUT },
	{ "norechallenge", AUTHFLAG_NORECHALLENGE }, { NULL }
};
/* the protocols that the kernel's TRUNK_PROTOS names, except its default */
static const struct argkey trunkproto_keys[] = {
	{ "roundrobin", TRUNK_PROTO_ROUNDROBIN },
	{ "failover", TRUNK_PROTO_FAILOVER }, { "lacp", TRUNK_PROTO_LACP },
	{ "loadbalance", TRUNK_PROTO_LOADBALANCE },
	{ "broadcast", TRUNK_PROTO_BROADCAST }, { "none", TRUNK_PROTO_NONE },
	{ NULL }
};
static const struct argkey lacpmode_keys[] = {
	{ "active", 1 }, { "passive", 0 }, { NULL }
};
static const struct argkey lacptimeout_keys[] = {
	{ "fast", 1 }, { "slow", 0 }, { NULL }
};
static const struct argkey txprio_keys[] = {
	{ "packet", IF_HDRPRIO_PACKET }, { "payload", IF_HDRPRIO_PAYLOAD },
	{ NULL }
};
static const struct argkey rxprio_keys[] = {
	{ "packet", IF_HDRPRIO_PACKET }, { "payload", IF_HDRPRIO_PAYLOAD },
	{ "outer", IF_HDRPRIO_OUTER }, { NULL }
};
static const struct argkey link_keys[] = {
	{ "0", IFF_LINK0 }, { "1", IFF_LINK1 }, { "2", IFF_LINK2 }, { NULL }
};
/* "ttl copy" copies each packet's own ttl */
static const struct argkey ttl_keys[] = { { "copy", -1 }, { NULL } };

/* the arguments that several rows have */
static const struct arg brport_args[] = {
	{ "interface",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO, NULL,
	    BRPORTS },
	{ NULL }
};

static const struct arg brpvlan_args[] = {
	{ "primary-vlan", ARG_NUM, EVL_VLID_MIN, EVL_VLID_MAX, ARG_NO },
	{ "vlan",	ARG_NUM, EVL_VLID_MIN, EVL_VLID_MAX, ARG_NO },
	{ NULL }
};

static const struct arg ipcmd_args[] = {
	{ "sysctl",	ARG_NUM, 0, 255, ARG_NO },
	{ "value",	ARG_NUM, 0, INT_MAX, ARG_OPT },
	{ NULL }
};

static const struct arg interface_args[] = {
	{ "name",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO,
	  .help = "interface name" },
	{ NULL }
};

static const struct arg ip_args[] = {
	{ "address",	ARG_ADDR, 0, 0, ARG_OPT | ARG_NO },
	{ "prefixlen",	ARG_NUM, 0, 128, ARG_OPT | ARG_NO,
	  .help = "prefix length" },
	{ "destination", ARG_ADDR, 0, 0, ARG_OPT | ARG_NO },
	{ "autoconf",	ARG_FLAG, 0, 0, ARG_NO },
	{ "anycast",	ARG_FLAG, 0, 0, ARG_NO },
	{ "eui64",	ARG_FLAG, 0, 0, ARG_NO },
	{ "vltime",	ARG_NUM, 1, ND6_INFINITE_LIFETIME - 1,
	    ARG_OPT | ARG_NO },
	{ "pltime",	ARG_NUM, 0, ND6_INFINITE_LIFETIME - 1,
	    ARG_OPT | ARG_NO },
	{ NULL }
};

static const struct arg description_args[] = {
	/* SIOCSIFDESCR refuses a longer one (ENAMETOOLONG) */
	{ "text",	ARG_REST, 0, IFDESCRSIZE - 1,
	  .help = "text of description" },
	{ NULL }
};

static const struct arg link_args[] = {
	{ "link",	ARG_BITS, 0, 0, ARG_NO | ARG_NOOPT, link_keys,
	  .help = "012" },
	{ NULL }
};

static const struct arg txprio_args[] = {
	{ "priority",	ARG_NUM, IF_HDRPRIO_MIN, IF_HDRPRIO_MAX, 0,
	    txprio_keys,
	  .help = "priority or packet|payload" },
	{ NULL }
};

static const struct arg rxprio_args[] = {
	{ "priority",	ARG_NUM, IF_HDRPRIO_MIN, IF_HDRPRIO_MAX, 0,
	    rxprio_keys,
	  .help = "priority or packet|payload|outer" },
	{ NULL }
};

static const struct arg vnetid_args[] = {
	{ "vnetid",	ARG_NUM, 0, INT64_MAX },
	{ NULL }
};

struct intlist Intlist[] = {
/* Interface mode commands */
	{ "inet", "IPv4/IPv6 addresses", CMPL(h)
	  .table = (char **)intiphelp, .stlen = sizeof(struct ghs),
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intip_apply, .code = ADDR_INET, .parse = intip_parse,
	  .args = ip_args },
	{ "ip", "Alias for \"inet\" command", CMPL(h)
	  .table = (char **)intiphelp, .stlen = sizeof(struct ghs),
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intip_apply, .code = ADDR_IP, .parse = intip_parse,
	  .args = ip_args },
	{ "alias", NULL, CMPL(h)	/* backwards compatibilty */
	  .table = (char **)intiphelp, .stlen = sizeof(struct ghs),
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intip_apply, .code = ADDR_ALIAS, .parse = intip_parse,
	  .args = ip_args },
	{ "autoconf4", "IPv4 Autoconfigurable address (DHCP)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intxflags_apply, .code = IFXF_AUTOCONF4 },
	{ "description", "Interface description", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intdesc_apply, .args = description_args },
	{ "group", "Interface group", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intgroup_apply,
	  .args = ARGS{
		{ "group-name",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO, NULL,
		    GROUP_NAMES },
		{ NULL } } },
	{ "rdomain", "Interface routing domain", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intrdomain_apply,
	  .args = ARGS{
		{ "rdomain",	ARG_NUM, 0, RT_TABLEID_MAX,
		  .help = "routing domain number" },
		{ NULL } } },
	{ "rtlabel", "Interface route labels", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intrtlabel_apply,
	  .args = ARGS{
		{ "route-label", ARG_WORD, 0, RTLABEL_LEN - 1 },
		{ NULL } } },
	{ "priority", "Data packet priority", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmetric_apply, .code = IFPRIORITY,
	  .args = ARGS{
		{ "priority",	ARG_NUM, 0, 15 },
		{ NULL } } },
	{ "llpriority", "Link Level packet priority", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intllprio_apply,
	  .args = ARGS{
		{ "priority",	ARG_NUM, IFQ_MINPRIO, IFQ_MAXPRIO },
		{ NULL } } },
	{ "mtu", "Maximum Transmission Unit", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmtu_apply,
	  .args = ARGS{
		{ "mtu",	ARG_NUM, 1, INT_MAX },
		{ NULL } } },
	{ "metric", "Routing metric", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmetric_apply, .code = IFMETRIC,
	  .args = ARGS{
		{ "metric",	ARG_NUM, 0, INT_MAX },
		{ NULL } } },
	{ "link", "Link level options", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intlink_apply, .args = link_args },
	{ "arp", "Address Resolution Protocol", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intflags_apply, .code = -IFF_NOARP },
	{ "staticarp", "Always use static ARP to find other hosts", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intflags_apply, .code = IFF_STATICARP },
	{ "lladdr", "Link Level (MAC) Address", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intlladdr_apply, .parse = intlladdr_parse,
	  .args = ARGS{
		{ "lladdr",	ARG_ADDR, 0, 0, ARG_LINK },
		{ NULL } } },
	{ "nwid", "802.11 network ID", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intnwid_apply,
	  .args = ARGS{
		{ "nwid",	ARG_BYTES, 0, IEEE80211_NWID_LEN },
		{ NULL } } },
	{ "nwkey", "802.11 network key", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intnwkey_apply, .parse = intnwkey_parse,
	  .args = ARGS{
		{ "key",	ARG_WORD, 1, NWKEY_TEXT, ARG_BLANKS },
		{ "persist",	ARG_NUM, 0, 2 },
		{ "defkid",	ARG_NUM, 0, IEEE80211_WEP_NKID },
		{ "keys",	ARG_BYTES, 0, NWKEY_LEN, ARG_OPT, NULL,
		    IEEE80211_WEP_NKID },
		{ NULL } } },
	{ "wpakey", "802.11 WPA passphrase or key", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intwpakey_apply, .parse = intwpakey_parse,
	  .args = ARGS{
		{ "key",	ARG_WORD, 8, 2 + 2 * WPA_PSKLEN, ARG_BLANKS },
		{ "psk",	ARG_BYTES, WPA_PSKLEN, WPA_PSKLEN, ARG_OPT },
		{ NULL } } },
	{ "wpa", "802.11 WPA, as for 802.1x", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intwpa_apply },
	{ "wpaprotos", "802.11 WPA protocols", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intwpalist_apply,
	  .args = ARGS{
		{ "protos",	ARG_BITS, 0, 0, ARG_COMMAS, wpaprotos },
		{ NULL } } },
	{ "wpaakms", "802.11 WPA key management", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intwpalist_apply,
	  .args = ARGS{
		{ "akms",	ARG_BITS, 0, 0, ARG_COMMAS, wpaakms },
		{ NULL } } },
	{ "wpaciphers", "802.11 WPA pairwise ciphers", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intwpalist_apply,
	  .args = ARGS{
		{ "ciphers",	ARG_BITS, 0, 0, ARG_COMMAS, wpaciphers },
		{ NULL } } },
	{ "wpagroupcipher", "802.11 WPA group cipher", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intwpalist_apply,
	  .args = ARGS{
		{ "cipher",	ARG_NUM, 1, 0, 0, wpagroupciphers },
		{ NULL } } },
	{ "join", "802.11 network to join when found", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intjoin_apply, .parse = intjoin_parse,
	  .args = ARGS{
		{ "nwid",	ARG_BYTES, 0, IEEE80211_NWID_LEN, ARG_NO },
		{ "kind",	ARG_NUM, JOIN_WPAKEY, JOIN_NWKEY, ARG_OPT },
		{ "key",	ARG_WORD, 1, NWKEY_TEXT, ARG_OPT | ARG_BLANKS },
		{ "psk",	ARG_BYTES, WPA_PSKLEN, WPA_PSKLEN, ARG_OPT },
		{ "wepkey",	ARG_BYTES, 0, NWKEY_LEN, ARG_OPT },
		{ NULL } } },
	{ "powersave", "802.11 powersaving mode", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intpowersave_apply,
	  .args = ARGS{
		{ "milisec",	ARG_NUM, 0, 1000, ARG_OPT },
		{ NULL } } },
	{ "txpower", "802.11 transmit power", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = inttxpower_apply,
	  .args = ARGS{
		{ "dBm",	ARG_NUM, INT16_MIN, INT16_MAX },
		{ NULL } } },
	{ "chan", "802.11 channel", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intchan_apply,
	  .args = ARGS{
		{ "chan",	ARG_NUM, 0, UINT16_MAX },
		{ NULL } } },
	{ "nwflag", "802.11 flags", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intnwflag_apply,
	  .args = ARGS{
		{ "flag",	ARG_BITS, 0, 0, ARG_NO, nwflags },
		{ NULL } } },
	{ "bssid",	"802.11 bss id",			CMPL0 0, 0, int_op, 1, CAND_RUN },
	{ "media", "Media type", CMPL0
	  .handler = intmedia, .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmedia_apply, .parse = intmedia_parse,
	  .args = ARGS{
		{ "type",	ARG_NUM, 0,
		    MEDIA_SUBTYPES - 1 },
		{ "instance",	ARG_NUM, 0, IFM_INST_MAX, ARG_OPT | ARG_NO },
		{ "mediaopt",	ARG_NUM, 0, MEDIA_OPTS, ARG_NAMED | ARG_OPT },
		{ NULL } } },
	{ "mediaopt", "Media options", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmediaopt_apply, .parse = intmediaopt_parse,
	  .args = ARGS{
		{ "mediaopt",	ARG_NUM, 0, MEDIA_OPTS, ARG_NO | ARG_NOOPT },
		{ NULL } } },
	{ "auth", "PPP authentication", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intsppp_apply, .code = SPPPIOSMAUTH,
	  .args = ARGS{
		{ "proto",	ARG_NUM, 1, 0, ARG_NAMED, proto_keys },
		{ "name",	ARG_WORD, 1, AUTHMAXLEN - 1, ARG_NAMED },
		{ "key",	ARG_WORD, 1, AUTHMAXLEN - 1, ARG_NAMED },
		{ NULL } } },
	/* auth's arguments, and flag */
	{ "peer", "PPP peer authentication", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intsppp_apply, .code = SPPPIOSHAUTH,
	  .args = ARGS{
		{ "proto",	ARG_NUM, 1, 0, ARG_NAMED, proto_keys },
		{ "name",	ARG_WORD, 1, AUTHMAXLEN - 1, ARG_NAMED },
		{ "key",	ARG_WORD, 1, AUTHMAXLEN - 1, ARG_NAMED },
		{ "flag",	ARG_NUM, 1, 0, ARG_NAMED, flag_keys, 2 },
		{ NULL } } },
	{ "pppoe", "PPPoE settings", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intpppoe_apply,
	  .args = ARGS{
		{ "ac",		ARG_WORD, 1, PPPOE_NAMELEN - 1, ARG_NAMED },
		{ "dev",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NAMED },
		{ "svc",	ARG_WORD, 1, PPPOE_NAMELEN - 1, ARG_NAMED },
		{ NULL } } },
	{ "tunnel", "Tunnel parameters", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = inttunnel_apply, .code = TUNNEL_BOTH,
	  .args = ARGS{
		{ "src",	ARG_ADDR, 0, 0, ARG_PORT,
		  .help = "src ip[:port]" },
		{ "dest",	ARG_ADDR, 0, 0, ARG_PORT, .help = "dest ip" },
		{ "rdomain",	ARG_NUM, 0, RT_TABLEID_MAX, ARG_NAMED },
		{ "ttl",	ARG_NUM, 1, 255, ARG_NAMED, ttl_keys },
		{ "df",		ARG_FLAG },
		{ "ecn",	ARG_FLAG },
		{ NULL } } },
	{ "tunneladdr", "Tunnel source, with no destination", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = inttunnel_apply, .code = TUNNEL_ADDR,
	  .args = ARGS{
		{ "src",	ARG_ADDR, 0, 0, ARG_PORT,
		  .help = "src ip[:port]" },
		{ "rdomain",	ARG_NUM, 0, RT_TABLEID_MAX, ARG_NAMED },
		{ "ttl",	ARG_NUM, 1, 255, ARG_NAMED, ttl_keys },
		{ "df",		ARG_FLAG },
		{ "ecn",	ARG_FLAG },
		{ NULL } } },
	{ "tunneldomain", "Tunnel routing domain for transit", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmpls_apply, .code = TUNNELDOMAIN,
	  .args = ARGS{
		{ "rdomain",	ARG_NUM, 0, RT_TABLEID_MAX },
		{ NULL } } },
	{ "maxaddr", "Maximum address cache size", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intcache_apply,
	  .args = ARGS{
		{ "maxaddr",	ARG_NUM, 1, 4096, .help = "1-4096" },
		{ NULL } } },
	{ "timeout", "Address cache timeout", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intcache_apply,
	  .args = ARGS{
		{ "timeout",	ARG_NUM, 8, 3600, .help = "8-3600" },
		{ NULL } } },
	{ "endpoint", "Tunnel endpoint of a MAC address", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intendpoint_apply,
	  .args = ARGS{
		{ "lladdr",	ARG_ADDR, 0, 0, ARG_LINK | ARG_NO,
		  .help = "mac address" },
		{ "endpoint",	ARG_ADDR, 0, 0,
		    ARG_INET | ARG_INET6 | ARG_LINK },
		{ NULL } } },
	{ "txprio", "Priority in tunnel protocol headers", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmpls_apply, .code = TXPRIO, .args = txprio_args },
	{ "rxprio", "Source used for packet priority", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmpls_apply, .code = RXPRIO, .args = rxprio_args },
	{ "vnetid", "Virtual interface network identifier", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intvnetid_apply, .args = vnetid_args },
	{ "vnetflowid", "Use part of vnetid as flowid", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intvnetflowid_apply },
	{ "parent", "Parent interface", CMPL(i)
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intparent_apply,
	  .args = ARGS{
		{ "parent",	ARG_WORD, 0, IFNAMSIZ - 1,
		  .help = "parent interface" },
		{ NULL } } },
	{ "patch", "Pair interface", CMPL(i)
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intpatch_apply,
	  .args = ARGS{
		{ "pair",	ARG_WORD, 0, IFNAMSIZ - 1,
		  .help = "pair interface" },
		{ NULL } } },
	{ "ping",	pinghelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "ping6",	ping6help,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "traceroute", tracerthelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "traceroute6", tracert6help,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "ssh",	sshhelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "telnet",	telnethelp,				CMPL0 0, 0, 0,	0, CAND_RUN },
	{ "logger",     loggerhelp,                             CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "do",		dohelp,					CMPL(c) 0, 0, 0, 0, CAND_RUN },
	{ "setenv",	setenvhelp,				CMPL(e) 0, 0, 0, 0, CAND_RUN },
	{ "unsetenv",	unsetenvhelp,				CMPL(e) 0, 0, 0, 0, CAND_RUN },
	{ "saveenv",	saveenvhelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "keepalive", "GRE tunnel keepalive", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intkeepalive_apply,
	  .args = ARGS{
		{ "period",	ARG_NUM, 1, 3600 },
		/* the kernel takes a count of at most 256 */
		{ "count",	ARG_NUM, 2, 256 },
		{ NULL } } },
	{ "mplslabel", "MPLS local label", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmpls_apply, .code = MPLSLABEL,
	  .args = ARGS{
		/* the kernel keeps labels 0 to 15 for itself */
		{ "label",	ARG_NUM, MPLS_LABEL_RESERVED_MAX + 1,
		    MPLS_LABEL_MAX, .help = "local mpls label" },
		{ NULL } } },
	{ "pwe", "MPLS PWE3", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intpwe3_apply, .parse = intpwe3_parse,
	  .args = ARGS{
		{ "cw",		ARG_FLAG, 0, 0, ARG_NO },
		{ "fat",	ARG_FLAG, 0, 0, ARG_NO },
		{ "neighbor",	ARG_FLAG, 0, 0, ARG_NO },
		{ "label",	ARG_NUM, MPLS_LABEL_RESERVED_MAX + 1,
		    MPLS_LABEL_MAX, ARG_OPT,
		  .help = "neighbor label" },
		{ "address",	ARG_ADDR, 0, 0, ARG_OPT,
		  .help = "neighbor ip" },
		{ NULL } } },
	{ "syncdev", "PFsync control message interface", CMPL(i)
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intsyncdev_apply,
	  .args = ARGS{
		{ "if",		ARG_WORD, 1, IFNAMSIZ - 1 },
		{ NULL } } },
	{ "syncpeer", "PFsync peer address", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intsyncpeer_apply,
	  .args = ARGS{
		{ "peer",	ARG_ADDR, 0, 0, ARG_INET,
		  .help = "IPv4 peer address" },
		{ NULL } } },
	{ "maxupd", "PFsync max updates, defer first packet", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmaxupd_apply,
	  .args = ARGS{
		/* the kernel takes at most 255 */
		{ "updates",	ARG_NUM, 0, 255, .help = "max pfsync updates" },
		{ "defer",	ARG_NUM, 1, 0, ARG_OPT, defer_keys },
		{ NULL } } },
	{ "vhid", "CARP virtual host ID", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intcarp_apply, .code = CARP_VHID,
	  .args = ARGS{
		{ "id",		ARG_NUM, 1, 255 },
		{ NULL } } },
	{ "advbase", "CARP advertisement interval", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intcarp_apply, .code = CARP_ADVBASE,
	  .args = ARGS{
		{ "seconds",	ARG_NUM, 0, 254 },
		{ NULL } } },
	{ "advskew", "CARP advertisement skew", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intcarp_apply, .code = CARP_ADVSKEW,
	  .args = ARGS{
		{ "skew",	ARG_NUM, 0, 254 },
		{ NULL } } },
	{ "carppass", "CARP passphrase", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intcpass_apply,
	  .args = ARGS{
		{ "passphrase",	ARG_WORD, 0, CARP_KEY_LEN - 1 },
		{ NULL } } },
	{ "carpdev", "CARP device", CMPL(i)
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intcdev_apply,
	  .args = ARGS{
		{ "carpdev",	ARG_WORD, 1, IFNAMSIZ - 1 },
		{ NULL } } },
	{ "carpnode", "CARP additional vhid/advskew", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intcnode_apply,
	  .args = ARGS{
		{ "vhid",	ARG_NUM, 1, 255, ARG_NO },
		/* carp_vhids_ioctl() refuses an advskew of 255 */
		{ "advskew",	ARG_NUM, 0, 254, ARG_OPT | ARG_NO },
		{ NULL } } },
	{ "carppeer", "CARP peer", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intcarp_apply, .code = CARP_PEER,
	  .args = ARGS{
		{ "peer",	ARG_ADDR, 0, 0, ARG_INET },
		{ NULL } } },
	{ "balancing", "CARP balancing mode", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intcarp_apply, .code = CARP_BALANCING,
	  .args = ARGS{
		{ "mode",	ARG_NUM, 1, 0, 0, balancing_keys,
		  .help = "balancing mode" },
		{ NULL } } },
	{ "pflow", "pflow data export", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intpflow_apply,
	  .args = ARGS{
		{ "sender",	ARG_ADDR, 0, 0, ARG_PORT | ARG_NAMED },
		{ "receiver",	ARG_ADDR, 0, 0, ARG_PORT | ARG_NAMED },
		{ "version",	ARG_NUM, PFLOW_PROTO_5, PFLOW_PROTO_MAX,
		    ARG_NAMED | ARG_OPT },
		{ NULL } } },
	{ "debug", "Driver dependent debugging", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intflags_apply, .code = IFF_DEBUG },
	{ "dhcrelay", "DHCP Relay Agent", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intdhcrelay_apply,
	  .args = ARGS{
		{ "relayserver", ARG_ADDR, 0, 0,
		    ARG_INET | ARG_NO | ARG_NOOPT },
		{ NULL } } },
	{ "dhcrelay6", "DHCPv6 Relay Agent", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intdhcrelay6_apply, .parse = intdhcrelay6_parse,
	  .args = ARGS{
		{ "interface",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO | ARG_NOOPT,
		    NULL, DHCRELAY6_DESTS },
		{ "address",	ARG_ADDR, 0, 0,
		    ARG_INET6 | ARG_NO | ARG_OPT | ARG_GAPS, NULL,
		    DHCRELAY6_DESTS },
		{ NULL } } },
	{ "wol", "Wake On LAN", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intxflags_apply, .code = IFXF_WOL },
	{ "mpls", "MPLS", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intxflags_apply, .code = IFXF_MPLS },
	{ "inet6", "IPv6 addresses", CMPL(h)
	  .table = (char **)intip6help, .stlen = sizeof(struct ghs),
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intip_apply, .code = ADDR_INET6, .parse = intip_parse,
	  .args = ip_args },
	{ "autoconf6", "IPv6 Autoconfigurable address", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intxflags_apply, .code = IFXF_AUTOCONF6 },
	{ "autoconfprivacy",
	  "Privacy addresses for IPv6 autoconf", CMPL0	/* XXX bkcompat */
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intxflags_apply, .code = IFXF_AUTOCONF6TEMP },
	{ "temporary", "Temporary addresses for IPv6 autoconf", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intxflags_apply, .code = IFXF_AUTOCONF6TEMP },
	{ "monitor", "Monitor mode for incoming traffic", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intxflags_apply, .code = IFXF_MONITOR },
	{ "soii", "Stable IPv6 autoconf addresses (RFC 7217)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intxflags_apply, .code = -IFXF_INET6_NOSOII },
	{ "tcplro", "TCP large receive offload", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intxflags_apply, .code = IFXF_LRO },
	{ "wgpeer", "Wireguard peer config", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intwgpeer_apply,
	  .args = ARGS{
		{ "key",	ARG_B64, 0, WG_KEY_LEN, ARG_NO | ARG_NOOPT,
		  .help = "public key" },
		{ "endpoint",	ARG_ADDR, 0, 0, ARG_PORT | ARG_NAMED | ARG_NO },
		{ "aip",	ARG_ADDR, 0, 0, ARG_PREFIX | ARG_NAMED | ARG_NO,
		    NULL, WGPEER_AIPS },
		{ "psk",	ARG_B64, 0, WG_KEY_LEN, ARG_NAMED | ARG_NO },
		/* 43200 == 12h, reasonable for a 16 bit value */
		{ "pka",	ARG_NUM, 0, 43200, ARG_NAMED | ARG_NO },
#ifdef WG_PEER_SET_DESCRIPTION
		/* the kernel would cut a longer description short */
		{ "description", ARG_WORD, 0, IFDESCRSIZE - 1,
		    ARG_NAMED | ARG_NO | ARG_BLANKS },
#endif
		{ NULL } } },
	{ "wgport", "Wireguard UDP port", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intwg_apply, .code = WG_PORT,
	  .args = ARGS{
		{ "port",	ARG_NUM, 0, 65535, .help = "local port" },
		{ NULL } } },
	{ "wgkey", "Wireguard private key", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intwg_apply, .code = WG_KEY,
	  .args = ARGS{
		{ "key",	ARG_B64, 0, WG_KEY_LEN, ARG_OPT,
		  .help = "private key" },
		{ NULL } } },
	{ "wgrtable", "Wireguard routing table", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intwg_apply, .code = WG_RTABLE,
	  .args = ARGS{
		{ "rtable",	ARG_NUM, 0, RT_TABLEID_MAX },
		{ NULL } } },
	{ "trunkport", "Add child interface(s) to trunk", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = inttrunkport_apply,
	  .args = ARGS{
		{ "ifname",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO, NULL,
		    TRUNK_MAX_PORTS },
		{ NULL } } },
	{ "trunkproto", "Define trunkproto", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = inttrunkproto_apply,
	  .args = ARGS{
		{ "proto",	ARG_NUM, 1, 0, 0, trunkproto_keys },
		{ NULL } } },
	{ "lacpmode", "LACP mode of an aggr interface", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intlacp_apply, .code = TRUNK_OPT_LACP_MODE,
	  .args = ARGS{
		{ "mode",	ARG_NUM, 1, 0, 0, lacpmode_keys },
		{ NULL } } },
	{ "lacptimeout", "LACP timeout of an aggr interface", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intlacp_apply, .code = TRUNK_OPT_LACP_TIMEOUT,
	  .args = ARGS{
		{ "timeout",	ARG_NUM, 1, 0, 0, lacptimeout_keys },
		{ NULL } } },
	{ "apn", "Access Point Name", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intumb_apply, .code = UMBCMD_APN,
	  .args = ARGS{
		/* the kernel holds an APN and a PIN as UTF-16 */
		{ "apn",	ARG_WORD, 1, UMB_APN_MAXLEN,
		  .help = "access point name" },
		{ NULL } } },
	{ "setpin", "Set SIM card PIN", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intumb_apply, .code = UMBCMD_PIN,
	  .args = ARGS{
		{ "pin",	ARG_WORD, 1, MBIM_PIN_MAXLEN / 2,
		  .help = "sim card pin" },
		{ NULL } } },
	{ "setpuk",	"Set new SIM card PIN using PUK for validation", CMPL0 0, 0, int_op, 0, CAND_RUN },
	{ "chgpin",	"Permanently change SIM PIN",		CMPL0 0, 0, int_op, 0, CAND_RUN },
	{ "class", "Preferred cell classes", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intumb_apply, .code = UMBCMD_CLASS,
	  .args = ARGS{
		{ "class",	ARG_BITS, 0, 0, ARG_COMMAS, class_keys,
		  .help = "preferred cell class" },
		{ NULL } } },
	{ "roaming", "Enable data roaming", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intumb_apply, .code = UMBCMD_ROAMING },
	{ "interface",  interfacehelp,				CMPL(i) 0, 0, int_interface, 1, CAND_EDIT },
	{ "shutdown", "Shutdown interface", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intflags_apply, .code = -IFF_UP },
	{ "show",	showhelp,				CMPL(ta) (char **)showlist, sizeof(Menu), 0, 0, CAND_RUN },
	{ "who",	whohelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "verbose",	verbosehelp,				CMPL0 0, 0, 0, 1, CAND_RUN },
	{ "editing",	editinghelp,				CMPL0 0, 0, 0, 1, CAND_RUN },
	{ "clear",	clearhelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "!",		shellhelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
        { "?",		"Options",				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "manual",	manhelp,				CMPL(H) (char **)mantab, sizeof(struct ghs), 0, 0, CAND_RUN },
        { "help",	0,					CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "exit",	"Leave interface config mode and return to global config mode ",
								CMPL0 0, 0, int_exit, 0, CAND_RUN },

	{ 0, 0, 0, 0, 0 }
};

size_t Intlist_nitems = nitems(Intlist);

struct intlist Bridgelist[] = {
/* Bridge mode commands */
	{ "description", "Bridge description", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intdesc_apply, .args = description_args },
	{ "member", "Bridge member(s)", CMPL(i)
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "span", "Bridge spanning port(s)", CMPL(i)
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "blocknonip", "Block non-IP traffic forwarding on member(s)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "discover", "Mark member(s) as discovery port(s)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "learning", "Mark member(s) as learning port(s)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "stp", "Enable 802.1D spanning tree protocol on member(s)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "edge", "Mark STP member(s) as edge ports", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "autoedge", "Detect whether STP member(s) are edge ports", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "ptp", "Mark STP member(s) as point-to-point links", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "autoptp", "Detect whether STP member(s) are point-to-point", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "locked",
	  "Accept only cached source addresses on member(s) (veb)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "maxaddr", "Maximum address cache size", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brval_apply,
	  .args = ARGS{
		{ "maxaddr",	ARG_NUM, 0, UINT32_MAX },
		{ NULL } } },
	{ "timeout", "Address cache timeout", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brval_apply,
	  .args = ARGS{
		{ "timeout",	ARG_NUM, 0, INT_MAX },
		{ NULL } } },
	{ "maxage", "Time for 802.1D configuration to remain valid", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brval_apply,
	  .args = ARGS{
		{ "maxage",	ARG_NUM, 0, 0xff },
		{ NULL } } },
	{ "fwddelay", "Time before bridge begins forwarding packets", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brval_apply,
	  .args = ARGS{
		{ "fwddelay",	ARG_NUM, 0, 0xff },
		{ NULL } } },
	{ "hellotime", "802.1D configuration packet broadcast interval", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brval_apply,
	  .args = ARGS{
		{ "hellotime",	ARG_NUM, 0, 0xff },
		{ NULL } } },
	{ "priority",
	  "Spanning priority for all members on an 802.1D bridge", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brval_apply,
	  .args = ARGS{
		{ "priority",	ARG_NUM, 0, 0xffff },
		{ NULL } } },
	{ "holdcnt", "Spanning tree packets sent before rate limiting", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brval_apply,
	  .args = ARGS{
		{ "holdcnt",	ARG_NUM, 0, UINT32_MAX },
		{ NULL } } },
	{ "proto", "Spanning tree protocol, stp or rstp", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brproto_apply,
	  .args = ARGS{
		{ "proto",	ARG_NUM, 1, 0, 0, brprotos },
		{ NULL } } },
	{ "ping",	pinghelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "ping6",	ping6help,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "traceroute", tracerthelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "traceroute6", tracert6help,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "ssh",	sshhelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "telnet",	telnethelp,				CMPL0 0, 0, 0,	0, CAND_RUN },
	{ "logger",     loggerhelp,                             CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "do",		dohelp,					CMPL(c) 0, 0, 0, 0, CAND_RUN },
	{ "setenv",	setenvhelp,				CMPL(e) 0, 0, 0, 0, CAND_RUN },
	{ "unsetenv",	unsetenvhelp,				CMPL(e) 0, 0, 0, 0, CAND_RUN },
	{ "saveenv",	saveenvhelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "rule", "Bridge layer 2 filtering rules", CMPL0
	  .cand = CAND_EDIT,
	  .apply = brrule_apply,
	  .args = ARGS{
		{ "action",	ARG_NUM, 1, 0, 0, bractions },
		{ "direction",	ARG_NUM, 1, 0, 0, brdirs },
		{ "on",		ARG_WORD, 1, IFNAMSIZ - 1, ARG_NAMED },
		{ "src",	ARG_ADDR, 0, 0,
		    ARG_LINK | ARG_NAMED | ARG_OPT },
		{ "dst",	ARG_ADDR, 0, 0,
		    ARG_LINK | ARG_NAMED | ARG_OPT },
		{ "tag",	ARG_WORD, 1, PF_TAG_NAME_SIZE - 1,
		    ARG_NAMED | ARG_OPT },
		{ NULL } } },
	{ "static", "Static bridge address entry", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brstatic_apply, .parse = brstatic_parse,
	  .args = ARGS{
		{ "address",	ARG_ADDR, 0, 0, ARG_LINK | ARG_NO },
		{ "vlan",	ARG_NUM, EVL_VLID_MIN, EVL_VLID_MAX,
		    ARG_OPT | ARG_NO },
		{ "member",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO | ARG_NOOPT },
		{ NULL } } },
	{ "ifpriority",
	  "Spanning priority of a member on an 802.1D bridge", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brpri_apply,
	  .args = ARGS{
		{ "member",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO },
		{ "priority",	ARG_NUM, 0, 0xff },
		{ NULL } } },
	{ "ifcost",
	  "Spanning tree path cost of a member on 802.1D bridge", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brpri_apply,
	  .args = ARGS{
		{ "member",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO },
		{ "cost",	ARG_NUM, 0, UINT32_MAX },
		{ NULL } } },
	{ "link", "Link level options", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intlink_apply, .args = link_args },
	{ "txprio", "Priority in 802.1Q headers (veb)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmpls_apply, .code = TXPRIO, .args = txprio_args },
	{ "rxprio", "Source used for packet priority (veb)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intmpls_apply, .code = RXPRIO, .args = rxprio_args },
	{ "vnetid", "Untagged VLAN of members added (veb)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intvnetid_apply, .args = vnetid_args },
	{ "protect", "Configure protected bridge domains", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brprotect_apply, .parse = brprotect_parse,
	  .args = ARGS{
		{ "member",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO },
		{ "domains",	ARG_NUM, 1, 0x7fffffff },
		{ NULL } } },
	{ "untagged", "VLAN of a member's untagged frames (veb)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brvlan_apply, .code = BRVLAN_UNTAGGED,
	  .args = ARGS{
		{ "member",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO },
		{ "vlan",	ARG_NUM, EVL_VLID_MIN, EVL_VLID_MAX, 0,
		    brpvids },
		{ NULL } } },
	{ "tagged", "VLANs a member carries tagged (veb)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brvlan_apply, .code = BRVLAN_TAGGED, .parse = brtagged_parse,
	  .args = ARGS{
		{ "member",	ARG_WORD, 1, IFNAMSIZ - 1, ARG_NO },
		{ "vlans",	ARG_BYTES, BRVLAN_MAP, BRVLAN_MAP,
		    ARG_OPT | ARG_NO },
		{ NULL } } },
	{ "pvlan", "Primary VLAN of a private VLAN (veb)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brpvlan_apply,
	  .args = ARGS{
		{ "primary-vlan", ARG_NUM, EVL_VLID_MIN, EVL_VLID_MAX, ARG_NO },
		{ NULL } } },
	{ "pvlan-isolated", "Isolated VLAN of a private VLAN (veb)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brpvlan_apply, .args = brpvlan_args },
	{ "pvlan-community", "Community VLAN of a private VLAN (veb)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brpvlan_apply, .args = brpvlan_args },
	{ "pvptags", "Tag private VLANs with their primary (veb)", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = brport_apply, .args = brport_args },
	{ "interface",  interfacehelp,				CMPL(i) 0, 0, int_interface, 1, CAND_EDIT },
	{ "shutdown", "Shutdown bridge", CMPL0
	  .nocmd = 1, .cand = CAND_EDIT,
	  .apply = intflags_apply, .code = -IFF_UP },
	{ "show",	showhelp,				CMPL(ta) (char **)showlist, sizeof(Menu), 0, 0, CAND_RUN },
	{ "who",	whohelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "verbose",	verbosehelp,				CMPL0 0, 0, 0, 1, CAND_RUN },
	{ "editing",	editinghelp,				CMPL0 0, 0, 0, 1, CAND_RUN },
	{ "clear",	clearhelp,				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "!",		shellhelp,				CMPL0 0, 0, 0, 0, CAND_RUN },

/* Help commands */
	{ "?",		"Options",				CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "manual",	manhelp,				CMPL(H) (char **)mantab, sizeof(struct ghs), 0, 0, CAND_RUN },
	{ "help",	0,					CMPL0 0, 0, 0, 0, CAND_RUN },
	{ "exit",	"Leave bridge config mode and return to global config mode ",
								CMPL0 0, 0, int_exit, 0, CAND_RUN },
	{ 0, 0, 0, 0, 0, 0 }
};

size_t Bridgelist_nitems = nitems(Bridgelist);

/*
 * interface and bridge: the interface's name, also with no
 * (interface_parse())
 */

/*
 * The interface's name, or as some network switches take it, its name
 * and unit: interface em 0
 */
static int
interface_parse(const struct argcmd *c, int argc, char **argv,
    struct argvals *a)
{
	const char *errstr;
	size_t len;

	if (argc != 1 && argc != 2)
		return args_usage(c);
	if (argc == 1)
		return args_word(c, &c->args[0], a, argv[0], &a->v[0]);
	strtonum(argv[1], 0, INT_MAX, &errstr);
	if (errstr) {
		printf("%% interface unit %s is %s\n", argv[1], errstr);
		return -1;
	}
	len = strlen(argv[0]);
	if (len > 0 && isdigit((unsigned char)(argv[0][len - 1]))) {
		printf("%% interface unit %s is redundant\n", argv[1]);
		return -1;
	}
	snprintf(a->rest, sizeof(a->rest), "%s%s", argv[0], argv[1]);
	printf("%% Using interface \"%s\", not \"%s %s\"\n", a->rest,
	    argv[0], argv[1]);
	return args_word(c, &c->args[0], a, a->rest, &a->v[0]);
}

/*
 * interface and bridge: the mode of an interface or a bridge
 *
 * For a line of configure, in config, the candidate makes the
 * interface's block, or with no removes it, and the session's mode is
 * that interface's, and stays: cand has the name of the interface being
 * configured, and whether it is a bridge. With no candidate, for the
 * head of a block in a commit's edits, it only creates the interface,
 * or with no, destroys it.
 */
static int
interface_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *name, int s, struct cand *cand)
{
	char ifn[IFNAMSIZ];
	struct ifreq ifr;
	int ifs, r = 0;

	/* a line of configure: its block, and the session's mode */
	if (cand != NULL) {
		args_string(&v[0], cand->ifname, sizeof(cand->ifname));
		r = cand_interface(cand, set, cand->ifname, &cand->bridge);
		if (r != 0)
			cand->ifname[0] = '\0';
		return r == -1 ? -1 : 0;
	}

	args_string(&v[0], ifn, sizeof(ifn));
	strlcpy(ifr.ifr_name, ifn, sizeof(ifr.ifr_name));
	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% socket failed: %s\n", strerror(errno));
		return -1;
	}

	if (!is_valid_ifname(ifn)) {
		if (set == 0) {
			printf("%% interface %s not found\n", ifn);
			close(ifs);
			return -1;
		}
		if (ioctl(ifs, SIOCIFCREATE, &ifr) == -1) {
			if (errno == EINVAL)
				printf("%% interface %s not found\n", ifn);
			else
				printf("%% unable to create interface %s: %s\n",
				    ifn, strerror(errno));
			close(ifs);
			return -1;
		}
	}

	if (set == 0 && ioctl(ifs, SIOCIFDESTROY, &ifr) == -1) {
		printf("%% unable to remove interface %s: %s\n", ifn,
		    strerror(errno));
		r = -1;
	}
	close(ifs);
	return r;
}

/*
 * In an interface's mode, the interface line. This handler marks its
 * rows: cmdline_if_edits() reads the line as the top level's, so nothing
 * runs here
 */
static int
int_interface(int argc, char **argv, ...)
{
	return 0;
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
	dhcp6leasehelp[] = "DHCPv6 prefix delegation control",
	lldphelp[] =	"LLDP control",
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
	{ "hostname", hostnamehelp, CMPL0
	  .handler = hostname, .needsession = 1, .needconfig = 1,
	  .cand = CAND_EDIT,
	  .apply = hostname_apply,
	  .args = ARGS{
		{ "hostname",	ARG_WORD, 1, MAXHOSTNAMELEN - 1 },
		{ NULL } } },
	{ "login", loginhelp, CMPL0
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .cand = CAND_EDIT,
	  .apply = login_apply, .parse = login_parse,
	  .args = ARGS{
		{ "kind",	ARG_NUM, 1, 0, ARG_NO, login_kinds,
		  .help = "class|user" },
		{ "name",	ARG_WORD, 1, 31, ARG_NO },
		{ "permission",	ARG_BITS, 0, 0, ARG_OPT, login_permtab },
		{ "class",	ARG_WORD, 1, 31, ARG_NAMED | ARG_OPT },
		{ "password",	ARG_WORD, 1, _PASSWORD_LEN,
		    ARG_NAMED | ARG_OPT },
		{ NULL } } },
	{ "interface", interfacehelp, CMPL(i)
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .modh = 1,
	  .cand = CAND_EDIT,
	  .apply = interface_apply, .code = CF_IF, .parse = interface_parse,
	  .args = interface_args },
	{ "rtable", rtablehelp, CMPL(rh)
	  .table = (char **)rtabletab, .stlen = sizeof(struct ghs), .nocmd = 1,
	  .modh = 2, .cand = CAND_EDIT,
	  .apply = rtable_apply,
	  .args = ARGS{
		{ "id",		ARG_NUM, 0, RT_TABLEID_MAX, ARG_NO,
		  .help = "table id" },
		{ "name",	ARG_REST, 1, 63, ARG_OPT },
		{ NULL } } },
	{ "group",	grouphelp,	CMPL(gth) (char **)grouptab, sizeof(Menu), group, 1, 1, 1, 0, CAND_RUN },
	{ "arp", arphelp, CMPL0
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .cand = CAND_EDIT,
	  .apply = arpentry_apply,
	  .args = ARGS{
		{ "address",	ARG_ADDR, 0, 0, ARG_INET | ARG_NO,
		  .help = "inet addr" },
		{ "lladdr",	ARG_ADDR, 0, 0, ARG_LINK,
		  .help = "ether addr" },
		{ "flags",	ARG_BITS, 0, 0, ARG_OPT, arpentry_keys,
		  .help = "temp|permanent|pub" },
		{ NULL } } },
	{ "ndp", ndphelp, CMPL0
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .cand = CAND_EDIT,
	  .apply = ndpentry_apply,
	  .args = ARGS{
		{ "address",	ARG_ADDR, 0, 0, ARG_INET6 | ARG_NO,
		  .help = "inet6 addr" },
		{ "lladdr",	ARG_ADDR, 0, 0, ARG_LINK,
		  .help = "ether addr" },
		{ "flags",	ARG_BITS, 0, 0, ARG_OPT, ndpentry_keys,
		  .help = "temp|proxy" },
		{ NULL } } },
	{ "nameserver", nameserverhelp, CMPL0
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .cand = CAND_EDIT,
	  .apply = nameserver_apply,
	  .args = ARGS{
		{ "address",	ARG_ADDR, 0, 0, 0, NULL, NAMESERVERS },
		{ NULL } } },
	{ "bridge", bridgehelp, CMPL(i)
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .modh = 1,
	  .cand = CAND_EDIT,
	  .apply = interface_apply, .code = CF_BRIDGE, .parse = interface_parse,
	  .args = interface_args },
	{ "show",	showhelp,	CMPL(ta) (char **)showlist, sizeof(Menu), 0,	0, 0, 0, 0 },
	{ "ip", iphelp, CMPL(ta)
	  .table = (char **)iptab, .stlen = sizeof(Menu), .handler = ipcmd,
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .cand = CAND_EDIT,
	  .apply = ipcmd_apply, .parse = ipcmd_parse, .args = ipcmd_args },
	{ "ip6", ip6help, CMPL(ta)
	  .table = (char **)ip6tab, .stlen = sizeof(Menu), .handler = ipcmd,
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .cand = CAND_EDIT,
	  .apply = ipcmd_apply, .parse = ipcmd_parse, .args = ipcmd_args },
	{ "mpls", mplshelp, CMPL(ta)
	  .table = (char **)mplstab, .stlen = sizeof(Menu), .handler = ipcmd,
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .cand = CAND_EDIT,
	  .apply = ipcmd_apply, .parse = ipcmd_parse, .args = ipcmd_args },
	{ "ddb", ddbhelp, CMPL(ta)
	  .table = (char **)ddbtab, .stlen = sizeof(Menu), .handler = ipcmd,
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .cand = CAND_EDIT,
	  .apply = ipcmd_apply, .parse = ipcmd_parse, .args = ipcmd_args },
	{ "pipex", pipexhelp, CMPL(ta)
	  .table = (char **)pipextab, .stlen = sizeof(Menu), .handler = ipcmd,
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .cand = CAND_EDIT,
	  .apply = ipcmd_apply, .parse = ipcmd_parse, .args = ipcmd_args },
	{ "flush",	flushhelp,	CMPL(ta) (char **)flushlist, sizeof(Menu), 0,	1, 0, 0, 0 },
	{ "clear",      clearhelp,      CMPL0 0, 0, 0,              0, 0, 0, 0 },
	{ "route", routehelp, CMPL0
	  .needsession = 1, .needconfig = 1, .nocmd = 1, .cand = CAND_EDIT,
	  .apply = route_apply, .parse = route_parse,
	  .args = ARGS{
		{ "destination", ARG_ADDR, 0, 0, ARG_PREFIX | ARG_NO },
		{ "gateway",	ARG_ADDR, 0, 0, ARG_NO | ARG_NOOPT },
		{ "flags",	ARG_BITS, 0, 0, ARG_OPT | ARG_NO, route_keys },
		{ "expire",	ARG_NUM, 0, INT_MAX,
		    ARG_NAMED | ARG_OPT | ARG_NO },
		{ "mtu",	ARG_NUM, 64, 65536,
		    ARG_NAMED | ARG_OPT | ARG_NO },
		{ NULL } } },
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
	{ "dhcp6lease",	dhcp6leasehelp,	CMPL(t) (char **)ctl_dhcp6lease, ssctl, ctlhandler, 1, 1, 0, 1, CAND_EDIT },
	{ "lldp",	lldphelp,	CMPL(t) (char **)ctl_lldp, ssctl, ctlhandler,	1, 1, 0, 1, CAND_EDIT },
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
	{ "ping",	pinghelp,	CMPL0 0, 0, 0,		0, 0, 0, 0 },
	{ "ping6",	ping6help,	CMPL0 0, 0, 0,		0, 0, 0, 0 },
	{ "traceroute", tracerthelp,	CMPL0 0, 0, 0,		0, 0, 0, 0 },
	{ "traceroute6", tracert6help,  CMPL0 0, 0, 0,	 0, 0, 0, 0 },
	{ "ssh",	sshhelp,	CMPL0 0, 0, 0,		0, 0, 0, 0 },
	{ "telnet",	telnethelp,	CMPL0 0, 0, 0,		0, 0, 0, 0 },
	{ "reboot",	nreboothelp,	CMPL0 0, 0, 0,		1, 0, 0, 0 },
	{ "logger",     loggerhelp,     CMPL0 0, 0, 0,             0, 0, 0, 0 },
	{ "halt",	halthelp,	CMPL0 0, 0, 0,		1, 0, 0, 0 },
	{ "powerdown",	powerdownhelp,	CMPL0 0, 0, 0,		1, 0, 0, 0 },
	{ "verbose",	verbosehelp,	CMPL0 0, 0, 0,		0, 0, 1, 0 },
	{ "editing",	editinghelp,	CMPL0 0, 0, 0,		0, 0, 1, 0 },
	{ "configure",	confighelp,	CMPL0 0, 0, 0,		1, 0, 1, 0 },
	{ "commit",	commithelp,	CMPL0 0, 0, 0,		1, 0, 0, 0, CAND_RUN },
	{ "rollback",	rollbackhelp,	CMPL0 0, 0, 0,	1, 1, 0, 0, CAND_RUN },
	{ "who",	whohelp,	CMPL0 0, 0, 0,		0, 0, 0, 0 },
	{ "no",		0,		CMPL(c) 0, 0, 0,		0, 0, 0, 0 },
	{ "do",		dohelp,		CMPL(c) 0, 0, 0,		0, 0, 0, 0 },
	{ "setenv",	setenvhelp,	CMPL(E) 0, 0, 0,	0, 0, 0, 0 },
	{ "unsetenv",	unsetenvhelp,	CMPL(e) 0, 0, 0,	0, 0, 0, 0 },
	{ "saveenv",	saveenvhelp,	CMPL0 0, 0, 0,		0, 0, 0, 0 },
	{ "!",		shellhelp,	CMPL0 0, 0, 0,		1, 0, 0, 0 },
	{ "?",		helphelp,	CMPL(c) 0, 0, 0,		0, 0, 0, 0 },
	{ "manual",	manhelp,	CMPL(H) (char **)mantab, sizeof(struct ghs), 0,0, 0, 0, 0 },
	{ "exit",	exithelp,	CMPL0 0, 0, exitconfig,		1, 0, 0, 0 },
	{ "quit",	quithelp,	CMPL0 0, 0, 0,		0, 0, 0, 0 },
	{ "help",	0,		CMPL(c) 0, 0, 0,		0, 0, 0, 0 },
	{ 0,		0,		CMPL0 0, 0, 0,			0, 0, 0, 0 }
};

size_t cmdtab_nitems = nitems(cmdtab);

/*
 * These commands escape ambiguous check and help listings
 */

static Command  cmdtab2[] = {
	{ "reload",     nreboothelp,    CMPL0 0, 0, 0,            1, 0, 0, 0 },
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

/*
 * Read one line of nshd's configure, as a terminal gives it, into its
 * edits, written to f: the row of its command and the values its words
 * parse to, which cmdline_run() runs. A session's frontend reads it, in
 * the mode config last told it the session is in: at the top level of
 * configure, or with ifn not "", in the mode of that interface, a
 * bridge's if isbridge. config runs it, so the words a client sends are
 * read in that client's own process. In an interface's
 * mode the line is one of that mode's, and exit leaves the mode; at the
 * top level it is a command that edits the candidate, or exit, which
 * leaves configure. Returns 0 after writing the line's edits, none for
 * an empty line or one that only printed help, or -1 after printing why
 * the line is none of the candidate's.
 */
int
cmdline_edits(char *text, char *ifn, int isbridge, FILE *f)
{
	struct argcmd row;
	struct edit e;
	Command *c;
	char *p;
	int d, act, r;

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
	if (ifn[0] != '\0')
		return cmdline_if_edits(ifn, isbridge, f);
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
	if ((c->needconfig || c->modh) && c->cand == CAND_NO) {
		printf("%% %s is not supported in configure private yet\n",
		    c->name);
		return -1;
	}
	if (c->cand != CAND_EDIT && c->handler != exitconfig) {
		printf("%% %s is not through nshd's configure\n", c->name);
		return -1;
	}
	memset(&e, 0, sizeof(e));
	if (c->handler == exitconfig) {
		e.kind = EDIT_LEAVE;
		return edit_put(f, &e, NULL, 0);
	}
	if (c->handler == ctlhandler) {
		if ((r = ctl_parse(c->name, margc, margv, &d, &act)) != 1)
			return r;
		e.kind = EDIT_ACT;
		e.row = d;
		e.act = act;
		return edit_put(f, &e, NULL, 0);
	}
	if (top_cmd(c, &row) == NULL) {
		printf("%% %s: internal failure\n", c->name);
		return -1;
	}
	/* a handler has work of its own before its line's arguments */
	if (c->handler != NULL &&
	    (r = (*c->handler)(margc, margv, 0)) != LINE_ARGS)
		return r;
	e.kind = EDIT_TOP;
	e.row = c - cmdtab;
	return edit_args(f, &e, &row, margc, margv);
}

/* cmdline_edits() of a line in an interface's or a bridge's mode */
static int
cmdline_if_edits(char *ifn, int isbridge, FILE *f)
{
	struct intlist *list = isbridge ? Bridgelist : Intlist, *i = NULL;
	struct argcmd row;
	struct edit e;
	char *p;
	int n, r;

	if ((p = NO_ARG(margv[0]) ? margv[1] : margv[0]) != NULL)
		i = (struct intlist *)genget(p, (char **)list,
		    sizeof(struct intlist));
	if (Ambiguous(i)) {
		printf("%% Ambiguous command\n");
		return -1;
	}
	if (i == 0) {
		printf("%% Invalid command\n");
		return -1;
	}
	if (i->cand == CAND_NO) {
		printf("%% %s is not supported in configure private yet\n",
		    i->name);
		return -1;
	}
	if (i->cand != CAND_EDIT && i->handler != int_exit) {
		printf("%% %s is not through nshd's configure\n", i->name);
		return -1;
	}
	memset(&e, 0, sizeof(e));
	if (i->handler == int_exit) {
		e.kind = EDIT_END;
		return edit_put(f, &e, NULL, 0);
	}
	if (i->handler == int_interface) {
		/* another interface's mode: the top level's interface line */
		if (margc - (NO_ARG(margv[0]) ? 1 : 0) != 2) {
			printf("%% usage: [no] interface <ifname>\n");
			return -1;
		}
		for (n = 0; cmdtab[n].apply != interface_apply ||
		    cmdtab[n].code != CF_IF; n++)
			;
		e.kind = EDIT_TOP;
		e.row = n;
		return edit_args(f, &e, top_cmd(&cmdtab[n], &row), margc,
		    margv);
	}
	if (int_cmd(i, &row) == NULL) {
		printf("%% %s: internal failure\n", i->name);
		return -1;
	}
	if (i->handler != NULL &&
	    (r = (*i->handler)(margc, margv, ifn, -1)) != LINE_ARGS)
		return r;
	e.kind = isbridge ? EDIT_BRIDGE : EDIT_IF;
	e.row = i - list;
	return edit_args(f, &e, &row, margc, margv);
}

/*
 * Run a line's edits (cmdline_edits()), buf's len bytes, in configure
 * private, as nsh runs the line they were read from. In an interface's
 * mode, an edit runs that mode's command on the interface, the end of a
 * block leaves the mode, and an interface line goes to that interface's
 * mode; at the top level, an edit runs its command, interface or bridge
 * enters its mode, which stays for the following lines, and leaving
 * leaves configure. The edits come from a session's frontend, which
 * read them in the mode config last told it. So each is checked before
 * it runs: it is whole, the session is in configure, it is of a kind a
 * line has, its row a command of the mode the session is in now that
 * edits the candidate, and its values those the row's arguments take
 * (args_check()). Returns 0, or -1 after printing why if one failed or
 * may not run; none after that one runs.
 */
int
cmdline_run(char *buf, size_t len, struct cand *cand)
{
	const struct argcmd *c;
	struct argcmd cmd;
	struct intlist *list;
	struct edit e;
	char *p;
	size_t off;
	int r = 0;

	for (off = 0; off < len && r != -1; off += sizeof(e) + e.len) {
		if (len - off < sizeof(e))
			goto bad;
		memcpy(&e, buf + off, sizeof(e));
		p = buf + off + sizeof(e);
		if (e.len > len - off - sizeof(e) || e.no > 1)
			goto bad;
		if (!cand->on) {
			printf("%% Command requires configure mode\n");
			return -1;
		}
		switch (e.kind) {
		case EDIT_TOP:
			if ((c = conf_cmd(CTX_TOP, e.row, &cmd)) == NULL ||
			    cmdtab[e.row].cand != CAND_EDIT || e.typed != 1 ||
			    (e.no && (c->flags & CF_NO) == 0))
				goto bad;
			if (cand->ifname[0] != '\0') {
				if (c->apply != interface_apply ||
				    c->code != CF_IF)
					goto bad;
				r = edit_values(c, &e, p, head_ran, cand);
				break;
			}
			r = edit_values(c, &e, p, line_ran, cand);
			break;
		case EDIT_IF:
		case EDIT_BRIDGE:
			list = e.kind == EDIT_IF ? Intlist : Bridgelist;
			if (cand->ifname[0] == '\0' ||
			    list != (cand->bridge ? Bridgelist : Intlist) ||
			    (c = conf_cmd(e.kind == EDIT_IF ? CTX_IF :
			    CTX_BRIDGE, e.row, &cmd)) == NULL ||
			    list[e.row].cand != CAND_EDIT || e.typed != 1)
				goto bad;
			if ((r = edit_values(c, &e, p, ifline_ran,
			    cand)) == 1) {
				cand->ifname[0] = '\0';
				r = 0;
			}
			break;
		case EDIT_END:
			if (cand->ifname[0] == '\0' || e.len != 0)
				goto bad;
			cand->ifname[0] = '\0';
			break;
		case EDIT_LEAVE:
			if (cand->ifname[0] != '\0' || e.len != 0)
				goto bad;
			r = cmdexit(cand);
			break;
		case EDIT_ACT:
			if (cand->ifname[0] != '\0' || e.len != 0)
				goto bad;
			r = ctl_cand_act(e.row, e.act, cand);
			break;
		default:
			goto bad;
		}
	}
	return r == -1 ? -1 : 0;
bad:
	printf("%% nshd: the edit at byte %zu is no line of the session's "
	    "mode\n", off);
	return -1;
}

/*
 * cmdline_run()'s edit, run: a command of the top level, in the
 * candidate of the session whose line it is
 */
static int
line_ran(const struct argcmd *c, int set, const struct facts_value *v,
    void *arg)
{
	struct cand *cand = arg;

	return c->apply(c, set, v, NULL, -1, cand);
}

/* and a command of the mode of the interface the session is in */
static int
ifline_ran(const struct argcmd *c, int set, const struct facts_value *v,
    void *arg)
{
	struct cand *cand = arg;

	return c->apply(c, set, v, cand->ifname, -1, cand);
}

/*
 * An interface line in an interface's mode: the candidate has its
 * block, and the mode is that interface's from now on; with no, the
 * block is removed, which leaves the mode if it is this one's
 */
static int
head_ran(const struct argcmd *c, int set, const struct facts_value *v,
    void *arg)
{
	struct cand *cand = arg;
	char name[IFNAMSIZ];
	int isbridge;

	args_string(&v[0], name, sizeof(name));
	if (cand_interface(cand, set, name, &isbridge) == -1)
		return -1;
	if (!set) {
		if (strcmp(cand->ifname, name) == 0)
			cand->ifname[0] = '\0';
		return 0;
	}
	if (strcmp(cand->ifname, name) != 0) {
		strlcpy(cand->ifname, name, sizeof(cand->ifname));
		cand->bridge = isbridge;
	}
	return 0;
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
		if (f->handler != NULL)
			*out = *conf = RUN_OP;
	} else if (stlen == sizeof(struct ctl))
		ctl_runs((struct ctl *)row, out, conf);
}

/* Leave configure, from any mode, as exit does at the top */
int
cmdexit(struct cand *cand)
{
	cand->ifname[0] = '\0';
	return cand_leave(cand) ? -1 : 0;
}

/* hostname: with a name, set it, and without one, show it */

static int
hostname(int argc, char **argv, ...)
{
	if (argc == 1)
		return facts_show(stdout, "hostname");
	return LINE_ARGS;
}

static int
hostname_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	char name[MAXHOSTNAMELEN];

	args_string(&v[0], name, sizeof(name));
	if (cand != NULL)
		return cand_setting(cand, ST_ON, "hostname %s", name);
	if (sethostname(name, strlen(name))) {
		printf("%% sethostname: %s\n", strerror(errno));
		return -1;
	}
	return 0;
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

/* rtable: the table, and with a name, the table's name */

static int
rtable_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	int table = v[0].v.i, pos, found, curtable;
	char rtname[64] = "";
	StringList *resp;

	if (v[1].type != FACT_NONE)
		args_string(&v[1], rtname, sizeof(rtname));
	pos = rtname[0] != '\0';
	if (cand != NULL)
		return cand_rtable_set(cand, set, table, pos ? rtname : NULL);

	curtable = getrtable();
	if (cli_rtable != curtable) {
		printf("%% WARNING: nsh process rtable is out of sync "
		    "(want %d, have %d); "
		    "This is probably a bug in nsh, please report it.\n",
		    cli_rtable, curtable);
	}

	resp = sl_init();
	if (db_select_rtables_rtable(resp, table) < 0)
		printf("%% rtable select error\n");
	found = resp->sl_cur;
	sl_free(resp, 1);

	if (set && (found && !pos)) {
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
 * group's row, an operation of nshd's system (row_runs()). nsh asks
 * nshd's system for it itself, so nothing runs here
 */
int
group(int argc, char **argv, ...)
{
	printf("%% group is an operation of nshd's system\n");
	return -1;
}

/* the group's name, carpdemote, and maybe a counter: 1 if it has none */
static int
demote_parse(const struct argcmd *c, int argc, char **argv,
    struct argvals *a)
{
	if (argc < 2 || argc > 3 || !isprefix(argv[1], "carpdemote")) {
		printf("%% group <group-name> carpdemote [demotion-counter]\n");
		printf("%% no group <group-name> carpdemote [demotion-counter]\n");
		return -1;
	}
	if (args_word(c, &c->args[0], a, argv[0], &a->v[0]) == -1)
		return -1;
	if (argc == 3 &&
	    args_word(c, &c->args[1], a, argv[2], &a->v[1]) == -1)
		return -1;
	return 0;
}

static int
demote_apply(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	int counter = 1, s, ret = 0;
	struct ifgroupreq ifgr;

	if (v[1].type != FACT_NONE)
		counter = v[1].v.i;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		printf("%% group: socket: %s\n", strerror(errno));

		return -1;
	}

	bzero(&ifgr, sizeof(ifgr));
	args_string(&v[0], ifgr.ifgr_name, sizeof(ifgr.ifgr_name));

	/* the kernel adds the counter to the group's */
	ifgr.ifgr_attrib.ifg_carp_demoted = set ? counter : -counter;

	if (ioctl(s, SIOCSIFGATTR, (caddr_t)&ifgr) == -1) {
		if (errno == ENOENT)
			printf("%% group %s does not exist\n", ifgr.ifgr_name);
		else if (errno == EINVAL)
			printf("%% group %s: demotion counter must stay within"
			    " 0 and 255\n", ifgr.ifgr_name);
		else
			printf("%% group: SIOCSIFGATTR: %s\n", strerror(errno));
		ret = -1;
	}
	close(s);

	return ret;
}

/*
 * exit's row at the top level. This handler marks the row:
 * cmdline_edits() reads the line, and cmdexit() leaves configure, so
 * nothing runs here
 */
static int
exitconfig(int argc, char **argv, ...)
{
	return 0;
}

static int
cand_leave(struct cand *cand)
{
	/* a shared candidate stays for the sessions that share it */
	if (cand_attached(cand)) {
		cand_detach(cand);
		return 0;
	}
	if (cand_changed(cand)) {
		printf("%% The candidate has uncommitted changes;"
		    " 'rollback' discards them\n");
		return 1;
	}
	cand_end(cand);
	return 0;
}

/*
 * pf toilet flusher
 */
static int
flush_pf(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	struct fpf *x;

	if (v[0].type == FACT_NONE) {
		gen_help((char **)fpfs, "flush pf", "flush",
		    sizeof(struct fpf));
		return 0;
	}
	x = &fpfs[v[0].v.i];

	{
		char *argv[] = { x->cmd, x->arg, NULL };
		return cmdargs(x->cmd, argv) == 0 ? 0 : -1;
	}
}

/* flush pf's word, as its row of fpfs; none, or ?, for help */
static int
flush_pf_parse(const struct argcmd *c, int argc, char **argv,
    struct argvals *a)
{
	struct fpf *x;

	if (argc > 1)
		return args_usage(c);
	if (argc == 0 || argv[0][0] == '?')
		return 0;
	x = (struct fpf *) genget(argv[0], (char **)fpfs, sizeof(struct fpf));
	if (x == 0) {
		printf("%% Invalid argument %s\n", argv[0]);
		return -1;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", argv[0]);
		return -1;
	}
	facts_i64(&a->v[0], x - fpfs);
	return 0;
}

/*
 * Flush wrappers
 */
static int
flush_ip_routes(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	flushroutes(AF_INET, AF_INET, v[0].type != FACT_NONE);

	return 0;
}

static int
flush_arp_cache(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
{
	flushroutes(AF_INET, AF_LINK, v[0].type != FACT_NONE);

	return 0;
}

static int
flush_ndp_cache(const struct argcmd *c, int set, const struct facts_value *v,
    char *ifname, int ifs, struct cand *cand)
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
 * c, row i of an interface's or a bridge's mode (Intlist, Bridgelist),
 * as args.c takes a command, if the row's line is parsed into values:
 * the row has the function that applies them. NULL if it has none. Any
 * line of these modes can take no
 */
static const struct argcmd *
int_cmd(const struct intlist *i, struct argcmd *c)
{
	if (i->apply == NULL)
		return NULL;
	memset(c, 0, sizeof(*c));
	c->name = i->name;
	c->apply = i->apply;
	c->code = i->code;
	c->args = i->args;
	c->parse = i->parse;
	return c;
}

/*
 * int_cmd() for row t of cmdtab: it takes no if its row says so, and it
 * heads a block if its row starts one, an rtable's, or the one its code
 * names, an interface's or a bridge's
 */
static const struct argcmd *
top_cmd(const Command *t, struct argcmd *c)
{
	if (t->apply == NULL)
		return NULL;
	memset(c, 0, sizeof(*c));
	c->name = t->name;
	c->flags = t->nocmd ? CF_NO : CF_SET;
	if (t->modh == 2)
		c->flags |= CF_RTABLE;
	else if (t->modh)
		c->flags |= t->code;
	c->apply = t->apply;
	c->code = t->code;
	c->args = t->args;
	c->parse = t->parse;
	return c;
}

/*
 * Row n of ctx's table, cmdtab, Intlist or Bridgelist for CTX_TOP,
 * CTX_IF or CTX_BRIDGE, as c, if it is a command a configuration has:
 * one whose line is parsed (int_cmd(), top_cmd()). NULL for any other row, and
 * where there is no such row. A commit's edits name a command by its
 * row (commit.c), so a commit runs no row that is not one of these: a
 * daemon's, which ctl.c handles (ctl_act()), has no arguments here
 */
const struct argcmd *
conf_cmd(int ctx, int n, struct argcmd *c)
{
	if (n < 0)
		return NULL;
	switch (ctx) {
	case CTX_TOP:
		return (size_t)n < nitems(cmdtab) - 1 ?
		    top_cmd(&cmdtab[n], c) : NULL;
	case CTX_IF:
		return (size_t)n < nitems(Intlist) - 1 ?
		    int_cmd(&Intlist[n], c) : NULL;
	case CTX_BRIDGE:
		return (size_t)n < nitems(Bridgelist) - 1 ?
		    int_cmd(&Bridgelist[n], c) : NULL;
	}
	return NULL;
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
	struct intlist *i, *list;
	struct argcmd c;
	Command *t;
	int n;

	if (ctx == CTX_TOP) {
		if ((t = getcmd(word)) == NULL || Ambiguous(t))
			return -1;
		if (t->handler == ctlhandler) {
			*daemon = t->name;
			return -2;
		}
		/* one of cmdtab2's is no configuration's command */
		if (t < cmdtab || t >= cmdtab + nitems(cmdtab))
			return -1;
		n = t - cmdtab;
	} else if (ctx == CTX_IF || ctx == CTX_BRIDGE) {
		list = ctx == CTX_IF ? Intlist : Bridgelist;
		i = (struct intlist *)genget(word, (char **)list,
		    sizeof(struct intlist));
		if (i == NULL || Ambiguous(i))
			return -1;
		n = i - list;
	} else
		return -1;
	return conf_cmd(ctx, n, &c) != NULL ? n : -1;
}

/*
 * Run the command at row n of ctx's commands (conf_cmd()) with values v,
 * as a commit runs a line of its edits: at the top level a statement, a
 * block's head included, and in an interface's or a bridge's mode a line
 * of name's block. set is 0 for "no".
 */
int
conf_run_values(int ctx, int n, int set, const struct facts_value *v,
    char *name)
{
	struct argcmd row;
	const struct argcmd *c = conf_cmd(ctx, n, &row);

	if (ctx != CTX_TOP)
		return conf_run_if(ctx == CTX_BRIDGE, c, set, v, name);
	/* a block's head creates a cloned interface, or with no, destroys it */
	return c->apply(c, set, v, NULL, -1, NULL) == -1 ? -1 : 0;
}

/*
 * Run c, an interface command, or a bridge command if bridgeline, on
 * name in rtable 0, as interface mode runs a line: the apply function of
 * c's argcmd runs with values v. set is 0 for "no". name must exist, and
 * must be a bridge exactly when c is a bridge command. Returns 0, or -1
 * after printing why c failed or did not run.
 */
static int
conf_run_if(int bridgeline, const struct argcmd *c, int set,
    const struct facts_value *v, char *name)
{
	char ifn[IFNAMSIZ];
	int ifs, isbridge, r = -1, rt = cli_rtable;

	if (strlcpy(ifn, name, sizeof(ifn)) >= sizeof(ifn)) {
		printf("%% interface name too long\n");
		return -1;
	}
	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		printf("%% socket failed: %s\n", strerror(errno));
		return -1;
	}
	/* its block's head made it, if it could */
	if (!is_valid_ifname(ifn)) {
		printf("%% interface %s not found\n", ifn);
		goto done;
	}
	if ((isbridge = is_bridge(ifs, ifn)) != bridgeline) {
		printf("%% %s is %sa bridge\n", ifn, isbridge ? "" : "not ");
		goto done;
	}
	if (cli_rtable != 0 && nsh_setrtable(0) == 0)
		cli_rtable = 0;
	r = c->apply(c, set, v, ifn, ifs, NULL) == -1 ? -1 : 0;
	if (rt != cli_rtable && nsh_setrtable(rt) == 0)
		cli_rtable = rt;
done:
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
	struct cnode *t = NULL;

	if (snapshot == NULL)
		printf("%% running_tree: no snapshot of the running "
		    "configuration\n");
	else if ((t = conftree_copy(snapshot)) == NULL)
		printf("%% running_tree: %s\n", strerror(errno));
	return t;
}
