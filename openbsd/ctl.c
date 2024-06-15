/*
 * Copyright (c) 2008 Chris Cappuccio <chris@nmedia.net>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <histedit.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <net/if.h>
#include "externs.h"
#include "editing.h"
#include "ctl.h"

static inline void
ctl2toctl(struct ctl *ctl, const struct ctl2 *ctl2)
{
	ctl->name = ctl2->name;
	ctl->help = ctl2->help;
	memcpy(ctl->args, ctl2->args, sizeof(ctl->args));
	if (ctl2->type == T_HANDLER_FILL1)
		ctl->args[1] = (char *)ctl2->test_args;
	ctl->handler = ctl2->handler;
	ctl->flag_x = ctl->flag_x;
	ctl->type = ctl->type;
}

static inline int
daemons2todaemons(struct daemons *daemons, const struct daemons2 *daemons2)
{
	size_t nentries = 0;
	struct ctl *ctl1;
	struct ctl2 *ctl2;

	ctl2 = daemons2->table;
	while (ctl2 && ctl2->name) {
		nentries++;
		ctl2++;
	}
	daemons->table = calloc(nentries + 1, sizeof(struct ctl));
	if (daemons->table == NULL) {
		printf("%% %s: malloc: %s\n", __func__, strerror(errno));
		return 1;
	}
	ctl1 = daemons->table;
	ctl2 = daemons2->table;
	while (ctl2 && ctl2->name) {
		ctl2toctl(ctl1, ctl2);
		ctl1++;
		ctl2++;
	}

	daemons->name = daemons2->name;
	daemons->propername = daemons2->propername;
	daemons->tmpfile = daemons2->tmpfile;
	daemons->mode = daemons2->mode;
	daemons->doreload = daemons2->doreload;
	daemons->rtablemax = daemons2->rtablemax;

	return 0;
}

/* table variable (for pkill usage) */
static char table[16];

/* service routines */
void edit_crontab(char *);
void install_crontab(char *);
void edit_motd(char *);
void call_editor(char *, char **, char *);
void start_dhcpd(char *, char *, char *, char *, char *);
void restart_dhcpd(char *, char *, char *, char *, char *);
int edit_file(char *, mode_t, char *, char **);
void ctl_symlink(char *, char *, char *);
int rule_writeline(char *, mode_t, char *);
int fill_tmpfile(char **, char *, char **);
int acq_lock(char *);
void rls_lock(int);

/* master daemon list */
struct daemons ctl_daemons[] = {
{ "pf",		"PF",	ctl_pf,		PFCONF_TEMP,	0600, 1, 0 },
{ "ospf",	"OSPF",	ctl_ospf,	OSPFCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "ospf6",	"OSPF6",ctl_ospf6,	OSPF6CONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "eigrp",	"EIGRP",ctl_eigrp,	EIGRPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "bgp",	"BGP",	ctl_bgp,	BGPCONF_TEMP,	0600, 0, 0 },
{ "rip",	"RIP",	ctl_rip,	RIPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "ldp",	"LDP",	ctl_ldp,	LDPCONF_TEMP,	0600, 0, 0 },
{ "relay",	"Relay",ctl_relay,	RELAYCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "ipsec",	"IPsec IKEv1",ctl_ipsec,IPSECCONF_TEMP,	0600, 1, RT_TABLEID_MAX },
{ "ike",	"IPsec IKEv2",ctl_ike,	IKECONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "rad",	"rad",	ctl_rad,	RADCONF_TEMP,	0600, 0, 0 },
{ "dvmrp",	"DVMRP",ctl_dvmrp,	DVMRPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "sasync",	"SAsync",ctl_sasync,	SASYNCCONF_TEMP,0600, 0, RT_TABLEID_MAX },
{ "snmp",	"SNMP",	ctl_snmp,	SNMPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "sshd",	"SSH",	ctl_sshd,	SSHDCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "ntp",	"NTP",	ctl_ntp,	NTPCONF_TEMP,	0600, 0, 0 },
{ "ifstate",	"ifstate",ctl_ifstate,	IFSTATECONF_TEMP,0600, 0, RT_TABLEID_MAX },
{ "ftp-proxy",	"FTP proxy",ctl_ftpproxy,FTPPROXY_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "tftp-proxy",	"TFTP proxy",ctl_tftpproxy,TFTPPROXY_TEMP,0600, 0, RT_TABLEID_MAX },
{ "tftp",	"TFTP",	ctl_tftp,	TFTP_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "nppp",	"PPP",	ctl_nppp,	NPPPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "resolv",	"resolvd",ctl_resolv,	NULL,		0, 0, 0 },
{ "inet",	"Inet",	ctl_inet,	INETCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "smtp",	"SMTP",	ctl_smtp,	SMTPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "ldap",	"LDAP",	ctl_ldap,	LDAPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "ifstate",	"If state",ctl_ifstate,	IFSTATECONF_TEMP,0600, 0, RT_TABLEID_MAX },
{ "motd",        "MOTD",  ctl_motd,        MOTD_TEMP,0644, 0, 0 },
{ "crontab",	"crontab",  ctl_crontab, CRONTAB_TEMP, 0600, 0, 0 },
{ "scheduler",	"scheduler",  ctl_crontab, CRONTAB_TEMP, 0600, 0, 0 },
{ 0, 0, 0, 0, 0, 0 }
};

struct daemons2 ctl_daemons2[] = {
{ "dhcp",	"DHCP",	ctl_dhcp,	DHCPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ NULL, NULL, NULL, NULL, 0, 0, 0 }
};

/* per-daemon commands, and their C or executable functions */ 

/* CRONTAB */
struct ctl ctl_crontab[] = {
        { "edit",           "edit scheduled background jobs",
            { "crontab", NULL, NULL }, edit_crontab, 0, T_HANDLER },
        { "install",           "install scheduled background job config",
            { "crontab", NULL, NULL }, install_crontab, 0, T_HANDLER },
        { 0, 0, { 0 }, 0, 0, 0 }
};


/* MOTD */
struct ctl ctl_motd[] = {
        { "edit",           "edit message-of-the-day",
            { "motd", NULL, NULL }, edit_motd, 0, T_HANDLER },
        { 0, 0, { 0 }, 0, 0, 0 }
};

/* PF, pfctl */
char *ctl_pf_test[] = { PFCTL, "-nf", REQTEMP, NULL };
struct ctl ctl_pf[] = {
	{ "enable",	"enable pf firewall",
	    { PFCTL, "-e", NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable pf firewall",
	    { PFCTL, "-d", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",	"edit, test and stage firewall rules",
	    { "pf", (char *)ctl_pf_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "check-config",     "test and display staged firewall rules",
            { PFCTL, "-nvvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "reload",	"test and apply staged firewall rules",
	    { PFCTL, "-f", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ospfd, ospfctl */
char *ctl_ospf_test[] = { OSPFD, "-nf", REQTEMP, NULL };
struct ctl ctl_ospf[] = {
	{ "enable",        "enable OSPFd daemon",
	    { OSPFD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",       "disable OSPFd daemon",
	{ PKILL, table, "ospfd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",          "edit, test and stage OSPFd config",
	    { "ospf", (char *)ctl_ospf_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "check-config",  "test staged OSPFd config",
            { OSPFD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "reload",        "test and appy staged OSPFd config",
	    { OSPFCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",           "fib couple/decouple",
	    { OSPFCTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "log",           "config OSPFd logging, brief/verbose",
            { OSPFCTL, "log", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",	   "show OSPFd db/fib/interfaces/neighbor/rib/summary",
	    { OSPFCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ospf6d, ospf6ctl */
char *ctl_ospf6_test[] = { OSPF6D, "-nf", REQTEMP, NULL };
struct ctl ctl_ospf6[] = {
	{ "enable",         "enable OSPF6d OSPFv3 daemon",
	    { OSPF6D, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",        "disable OSPF6d OSPFv3 daemon",
	    { PKILL, table, "ospf6d", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",           "edit, test and stage OSPF6d config",
	    { "ospf6", (char *)ctl_ospf6_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "check-config",   "test staged OSPF6d config",   
            { OSPF6D, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "reload",         "test and apply staged OSPF6d config",
	    { OSPF6CTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",            "fib couple/decouple",
	    { OSPF6CTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "log",	    "config OSPF6d logging, brief/verbose",
	    { OSPF6CTL, "log", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* eigrpd, eigrpctl */
char *ctl_eigrp_test[] = { EIGRPD, "-nf", REQTEMP, NULL };
struct ctl ctl_eigrp[] = {
	{ "enable",         "enable EIGRPd daemon",
	    { EIGRPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",        "disable EIGRPd daemon",
	    { PKILL, table, "eigrpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",           "edit, test and stage EIGRPd config",
	    { "eigrp", (char *)ctl_eigrp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
        { "check-config",   "test staged EIGRPd config",
            { EIGRPD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "reload",         "test and apply stagged EIGRPd config",
	    { EIGRPCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",            "fib couple/decouple",
	    { EIGRPCTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "log",            "config EIGRPd loggging, brief/verbose",
	    { EIGRPCTL, "lob", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",           "show fib/interfaces/neighbor/topology/traffic",
            { EIGRPCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* bgpd, bgpctl */
char *ctl_bgp_test[] = { BGPD, "-nf", REQTEMP, NULL, NULL };
struct ctl ctl_bgp[] = {
	{ "enable",          "enable OpenBGPD daemon",
	    { BGPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",         "disable OpenBGPD daemon",
	    { PKILL, "bgpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",            "edit, test and stage OpenBGPD config",
	    { "bgp", (char *)ctl_bgp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "check-config",    "test staged OpenBGPD config",
            { BGPD, "-nvf",REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "reload",          "test and apply staged OpenBGPD config",
	    { BGPCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",	     "fib couple/decouple",
	    { BGPCTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "neighbor",	     "neighbor up/down/clear/refresh",
	    { BGPCTL, "neighbor", OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "network",	     "network add/delete/flush/show",
	    { BGPCTL, "network", REQ, OPT, NULL }, NULL, 0, T_EXEC },
        { 0, 0, { 0 }, 0, 0, 0 }
};

/* ripd, ripctl */
char *ctl_rip_test[] = { RIPD, "-nf", REQTEMP, NULL };
struct ctl ctl_rip[] = {
	{ "enable",          "enable RIPd Routing Internet protocol daemon",
	    { RIPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",         "disable RIPd daemon",
	    { PKILL, table, "ripd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",            "edit, test and stage RIPd config",
	    { "rip", (char *)ctl_rip_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "check-config",    "test staged RIPd config",
            { RIPD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "reload",	     "test and apply staged ripd config",
	    { RIPCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",             "fib couple/decouple",
	    { RIPCTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",            "show fib/interfaces/neighbor/rib",
            { RIPCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ldpd, ldpctl */
char *ctl_ldp_test[] = { LDPD, "-nf", REQTEMP, NULL };
struct ctl ctl_ldp[] = {
	{ "enable",        "enable Label Distribution Protocol Daemon",
	   { LDPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",       "disable LDPd ",
	   { PKILL, "ldpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",          "edit, test and stage LDPd config",
	   { "ldp", (char *)ctl_ldp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
        { "check-config",  "test staged LDPd config",
            { LDPD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "reload",        "test and apply staged LDPd config",
	    { LDPCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",           "fib couple/decouple",
	   { LDPCTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "clear",         "clear LDPd neighbors",
            { LDPCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",          "show LDPd fib/interfaces/discovery/neighbor/lib",
            { LDPCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* isakmpd, ipsecctl */
char *ctl_ipsec_test[] = { IPSECCTL, "-nf", REQTEMP, NULL };
struct ctl ctl_ipsec[] = {
	{ "enable",         "enable isakmpd IKEv1 daemon",
	    { ISAKMPD, "-Kv", NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",        "disable isakmpd IKEv1 daemon",
	    { PKILL, table, "isakmpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",           "edit, test and stage isakmpd config",   
	    { "ipsec", (char *)ctl_ipsec_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "check-config",   "test staged isakmpd config",
            { IPSECCTL, "-nvvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "reload",         "test and apply staged isakmpd config",
	    { IPSECCTL, "-f", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "show",           "show isakmpd flow/sa/all",
            { IPSECCTL, "-s", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* iked, ikectl */
char *ctl_ike_test[] = { IKED, "-nf", REQTEMP, NULL };
struct ctl ctl_ike[] = {
	{ "enable",         "enable Internet Key Exchange V2 daemon",
	    { IKED, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",        "disable IKEv2 daemon",
	    { PKILL, table, "iked", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "active",         "force IKE active mode",
	    { IKECTL, "active", NULL }, NULL, 0, T_EXEC },
	{ "passive",        "force IKE passive mode",
	    { IKECTL, "passive", NULL }, NULL, 0, T_EXEC },
	{ "couple",         "load SAs and flows into kernel",
	    { IKECTL, "couple", NULL }, NULL, 0, T_EXEC },
	{ "decouple",       "unload SAs and flows from kernel",
	    { IKECTL, "decouple", NULL }, NULL, 0, T_EXEC },
	{ "edit",           "edit, test and stage IKEd config",
	    { "ike", (char *)ctl_ike_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "check-config",   "test IKEd config",
            { IKED, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "reload",         "test and apply IKEd config",
	    { IKECTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "reset",          "reset IKEd state, policies, SAs or user database",
	    { IKECTL, "reset", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",           "show security associations",
            { IKECTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* dvmrpd */
char *ctl_dvmrp_test[] = { DVMRPD, "-nf", REQTEMP, NULL };
struct ctl ctl_dvmrp[] = {
	{ "enable",        "enable Distance Vector Multicast Routing daemon",
	    { DVMRPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",       "disable DVMRPd daemon",   
	    { PKILL, table, "dvmrpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",          "edit,test and stage DVMRPd config",
	    { "dvmrp", (char *)ctl_dvmrp_test,  NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "config-test",   "test staged DVMRPd config",
            { DVMRPD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "log",           "configure DVMRPd logging, brief/verbose",
            { DVMRPCTL, "log", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",          "show igmp/interfaces/mfc/neighbor/rib/summary",
            { DVMRPCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* rad */
char *ctl_rad_test[] = { RAD, "-nf", REQTEMP, NULL };
struct ctl ctl_rad[] = {
	{ "enable",	    "enable RAD Router Advertisement daemon",
	    { RAD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	    "disable RAD daemon",
	    { PKILL, "rad", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",           "edit,test and stage RAD config",
	    { "rad", (char *)ctl_rad_test, NULL}, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "check-config",   "test staged RAD config",                                   
            { RAD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ifstated */
char *ctl_ifstate_test[] = { IFSTATED, "-nf", REQTEMP, NULL };
struct ctl ctl_ifstate[] = {
	{ "enable",         "enable ifstated daemon",
	    { IFSTATED, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",        "disable ifstated daemon",
	    { PKILL, table, "ifstated", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",           "edit, test and stage ifstated config",
	    { "ifstate", (char *)ctl_ifstate_test,  NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "config-test",    "test staged ifstated config ",
            { IFSTATED, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* sasyncd */
char *ctl_sasync_test[] = { SASYNCD, "-nvvc", REQTEMP, NULL };
struct ctl ctl_sasync[] = {
	{ "enable",       "enable SAsyncd daemon",
	    { SASYNCD, "-c", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",      "disable SAsyncd daemon",
	    { PKILL, table, "sasyncd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",         "edit, test and stage SAsyncd config",
	    { "sasync", (char *)ctl_sasync_test, NULL }, call_editor, 0, T_HANDLER_FILL1 },
	{ "check-config", "test staged SAsyncd config",
            { SASYNCD, "-nvvc", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0 }
};

/* npppd, npppctl */
char *ctl_nppp_test[] = { NPPPD, "-nf", REQTEMP, NULL };
struct ctl ctl_nppp[] = {
	{ "enable",	    "enable nPPPd Point to Point Protocol daemon",
	    { NPPPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	    "disable nNPPPd daemon",
	    { PKILL, table, "npppd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "clear",	    "disconnect nPPPd sessions",
	    { NPPPCTL, "clear", REQ, OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "session", 	    "show nPPPd sessions",
	    { NPPPCTL, "session", REQ, OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "monitor",	    "monitor nPPPd sessions",
	    { NPPPCTL, "monitor", REQ, OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "edit",	    "edit ,test and stage nPPPd config",
	    { "nppp", (char *)ctl_nppp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "check-config",   "test staged nPPPd config",
            { NPPPD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* dhcpd */
struct ctl2 ctl_dhcp[] = {
	{ "enable",        "enable DHCPd daemon",
	    { DHCPD, "-c", REQTEMP, "-l", DHCPLEASES, NULL }, { NULL, },
	    start_dhcpd, DB_X_ENABLE, T_HANDLER },
	{ "disable",       "disable DHCPd daemon",
	    { PKILL, table, "dhcpd", NULL }, { NULL, }, NULL,
	    DB_X_DISABLE, T_EXEC },
	{ "edit",          "edit,test and stage DHCPd config",
	    { "dhcp", NULL }, { DHCPD, "-nc", REQTEMP, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "config-test",   "test staged DHCPd config",
            { DHCPD, "-nc", REQTEMP, "-l", DHCPLEASES, NULL }, { NULL, },
	    NULL, 0, T_EXEC },
	{ "restart",        "restart DHCPd daemon",
	    { DHCPD, "-c", REQTEMP, "-l", DHCPLEASES, NULL }, { NULL, },
	    restart_dhcpd, DB_X_ENABLE, T_HANDLER },
	{ NULL, NULL, { NULL }, { NULL }, NULL, 0, 0 }
};

/* snmpd, snmpctl */
char *ctl_snmp_test[] = { SNMPD, "-nf", REQTEMP, NULL };
struct ctl ctl_snmp[] = {
	{ "enable",        "enable OpenSNMPD daemon",
	    { SNMPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",       "disable OpenSNMPD daemon",
	    { PKILL, table, "snmpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",          "edit,test and stage OpenSNMPD config",
	    { "snmp", (char *)ctl_snmp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "config-test",   "test staged OpenSNMPD config",
            { SNMPD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "trap",	   "send traps",
	    { SNMPCTL, "trap", "send", REQ, OPT, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* sshd */
char *ctl_sshd_test[] = { SSHD, "-tf", REQTEMP, NULL };
struct ctl ctl_sshd[] = {
	{ "enable",          "enable OpenSSHD daemon",
	    { SSHD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",         "disable OpenSSHD daemon",
	    { PKILL, table, "-f", SSHD, "-f", REQTEMP, NULL }, NULL,
	    DB_X_DISABLE, T_EXEC },
	{ "edit",            "edit, test and stage OpenSSHD config",
	    { "sshd", (char *)ctl_sshd_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "config-test",     "test staged OpenSSHD config",
            { SSHD, "-tf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ntpd */
char *ctl_ntp_test[] = { NTPD, "-nf", REQTEMP, NULL };
struct ctl ctl_ntp[] = {
	{ "enable",           "enable OpenNTPD daemon",
	    { NTPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",          "disable OpenNTPD daemon",
	    { PKILL, "ntpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",             "edit, test and stage OpenNTPD config",
	    { "ntp", (char *)ctl_ntp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "check-config",     "test staged OpenNTPD config",
            { NTPD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* relayd, relayctl */
char *ctl_relay_test[] = { RELAYD, "-nf", REQTEMP, NULL };
struct ctl ctl_relay[] = {
	{ "enable",           "enable load balancing relayd daemon",
	    { RELAYD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
        { "disable",	      "disable load balancing relayd daemon",
	    { PKILL, table, "relayd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
        { "edit",             "edit, test and stage relayd config",
	    { "relay", (char *)ctl_relay_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "check-config",     "test staged relayd config",
            { RELAYD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
        { "reload",           "test and apply staged relayd config",
	    { RELAYCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "host",             "per-host control",
	    { RELAYCTL, "host", OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "table",            "relayd per-table control",
	    { RELAYCTL, "table", OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "redirect",         "relayd per-redirect control",
	    { RELAYCTL, "redirect", OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "monitor",          "enable relayd monitor mode",
	    { RELAYCTL, "monitor", NULL }, NULL, 0, T_EXEC },
	{ "poll",             "relayd poll mode",
	    { RELAYCTL, "poll", NULL }, NULL, 0, T_EXEC },
	{ "show",             "show hosts/redirects/relays/routers/sessions/summary",
            { RELAYCTL, "show",  NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* smtpd, smptpdctl */
char *ctl_smtp_test[] = { SMTPD, "-nf", REQTEMP, NULL };
struct ctl ctl_smtp[] = {
	{ "enable",        "enable OpenSMTPD daemon",
	    { SMTPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",       "disable OpenSMTPD daemon",
	    { PKILL, table, "smtpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",          "edit,test and stage OpenSMTPD config",
	    { "smtp", (char *)ctl_smtp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "config-test",   "test OpenSMTPD config",
            { SMTPD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "log",           "set OpenSMTPD logging brief/verbose config",
	    { SMTPCTL, "log", REQ, NULL }, NULL, 0, T_EXEC },
	{ "pause",         "pause mda/mta/smtp listener",
	    { SMTPCTL, "pause", REQ, NULL }, NULL, 0, T_EXEC },
	{ "remove",        "remove message or envelope",
	    { SMTPCTL, "remove", REQ, NULL }, NULL, 0, T_EXEC },
	{ "resume",        "resume mda/mta/smtp listener",
	    { SMTPCTL, "resume", REQ, NULL }, NULL, 0, T_EXEC },
	{ "schedule-all",  "schedule all envelopes for immediate delivery",
	    { SMTPCTL, "schedule-all", NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ftpproxy */
struct ctl ctl_ftpproxy[] = {
	{ "enable",	"enable ftp proxy daemon",
	    { FTPPROXY, "-D", "2", NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable ftp proxy daemon",
	    { PKILL, table, "ftp-proxy", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* tftpproxy */
struct ctl ctl_tftpproxy[] = {
	{ "enable",     "enable TFTP proxy daemon",
	    { TFTPPROXY, "-v", "-l", "127.0.0.1", NULL }, NULL, DB_X_ENABLE,
	    T_EXEC },
	{ "disable",    "disable TFTP proxy daemon",
	    { PKILL, table, "tftp-proxy", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* tftpd */
struct ctl ctl_tftp[] = {
	{ "enable", 	"enable TFTPd daemon",
	   { TFTPD, "-l", "127.0.0.1", "/tftpboot", NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable TFTPd daemon",
	   { PKILL, table, "tftpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* resolvd */
struct ctl ctl_resolv[] = {
	{ "enable",	"enable resolvd daemon",
	   { RESOLVD, NULL }, NULL, DB_X_ENABLE_DEFAULT, T_EXEC },
	{ "disable",    "disable resolvd daemon",
	   { PKILL, "resolvd", NULL }, NULL, DB_X_DISABLE_ALWAYS, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* inetd */
struct ctl ctl_inet[] = {
	{ "enable",     "enable inetd daemon",
	    { INETD, REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable inetd daemon",
	    { PKILL, table, "inetd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit inetd superserver config",
	    { "inet", NULL, NULL }, call_editor, 0, T_HANDLER_FILL1 },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ldapd, ldapctl */
char *ctl_ldap_test[] = { LDAPD, "-nf", REQTEMP, NULL };
struct ctl ctl_ldap[] = {
	{ "enable",         "enable LDAPd daemon",
	    { LDAPD, REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",        "disable LDAPd daemon",
	    { PKILL, table, "ldapd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",           "edit, test and stage LDAPd config",
	    { "ldap", (char *)ctl_ldap_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "config-test",    "test staged LDAPd config",
            { LDAPD, "-nvf", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "log",            "config LDAPd logging, brief/verbose",
	    { LDAPCTL, "log", REQ, NULL }, NULL, 0, T_EXEC },
	{ "compact",        "compact all LDAPd databases",
	    { LDAPCTL, "compact", NULL }, NULL, 0, T_EXEC },
	{ "index",          "re-index all LDAPd databases",
	    { LDAPCTL, "index", NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

void
ctl_symlink(char *temp, char *real, char *z)
{
	rmtemp(temp);
	symlink(real, temp);
}

/* flag to other nsh sessions or nsh conf() that actions have been taken */
void
flag_x(char *name, char *daemon, int dbflag, char *data)
{
	if (db_delete_flag_x_ctl(name, daemon, cli_rtable) < 0) {
		printf("%% database delete failure ctl ctl\n");
		return;
	}
	if (dbflag == DB_X_REMOVE)
		return;
	if (db_insert_flag_x(name, daemon, cli_rtable, dbflag, data) < 0) {
		printf("%% database insert failure ctl ctl\n");
	}
}

/* the main entry point into ctl.c from CLI */
int
ctlhandler(int argc, char **argv, char *modhvar)
{
	struct daemons *daemons;
	struct daemons2 *daemons2;
	struct ctl *x;
	struct ctl2 *x2;
	struct daemons daemons1;
	char tmpfile[PATH_MAX];
	char *step_args[NOPTFILL] = { NULL, NULL, NULL, NULL, NULL, NULL };
	char *tmp_args[NOPTFILL] = { NULL, NULL, NULL, NULL, NULL, NULL };
	char **fillargs;
	char **xargs;
	int xtype;
	void (*xhandler)();
	int xflag_x;
	char **xtest_args = NULL;
	int rv = 0;
	int nargs;

	memset(&daemons1, 0, sizeof(daemons1));


	/* loop daemon list to find table pointer */
	daemons = (struct daemons *) genget(hname, (char **)ctl_daemons,
	    sizeof(struct daemons));
	if (daemons == NULL) {
		daemons2 = (struct daemons2 *) genget(hname,
		    (char **)ctl_daemons2, sizeof(struct daemons2));
		if (daemons2 == NULL || Ambiguous(daemons2)) {
			printf("%% Internal error - Invalid argument %s\n", argv[1]);
			return 0;
		}
		if (daemons2todaemons(&daemons1, daemons2))
			goto done;
		daemons = &daemons1;
	} else if (Ambiguous(daemons)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[1]);
		return 0;
	}

	if (cli_rtable > daemons->rtablemax) {
		printf("%% Command %s not available via rtable %d\n",
		    daemons->name, cli_rtable);
		goto done;
	}

	snprintf(table, sizeof(table), "-T%d", cli_rtable);
	if (daemons->tmpfile)
		snprintf(tmpfile, sizeof(tmpfile), "%s.%d", daemons->tmpfile,
		    cli_rtable);

	if (modhvar) {
		/* action specified or indented command specified */
		if (argc == 2 && isprefix(argv[1], "rules")) {
			/* skip 'X rules' line */
			goto done;
		}
		if (isprefix(modhvar, "rules")) {
			if (!daemons->tmpfile) {
				printf("%% writeline without tmpfile\n");
				goto done;
			}
			/* write indented line to tmp config file */
			rule_writeline(tmpfile, daemons->mode, saveline);
			goto done;
		}
	}
	if (argc < 2 || argv[1][0] == '?') {
		gen_help((char **)daemons->table, "", "", sizeof(struct ctl));
		goto done;
	}

	if (daemons1.name != NULL) {
		x2 = (struct ctl2 *) genget(argv[1],
		    (char **)daemons2->table, sizeof(struct ctl2));
		if (x2 == NULL) {
			printf("%% Invalid argument %s\n", argv[1]);
			goto done;
		} else if (Ambiguous(x2)) {
			printf("%% Ambiguous argument %s\n", argv[1]);
			goto done;
		}
		xargs = x2->args;
		xtype = x2->type;
		xhandler = x2->handler;
		xflag_x = x2->flag_x;
		xtest_args = x2->test_args;
	} else {
		x = (struct ctl *) genget(argv[1], (char **)daemons->table,
		    sizeof(struct ctl));
		if (x == NULL) {
			printf("%% Invalid argument %s\n", argv[1]);
			goto done;
		} else if (Ambiguous(x)) {
			printf("%% Ambiguous argument %s\n", argv[1]);
			goto done;
		}
		xargs = x->args;
		xtype = x->type;
		xhandler = x->handler;
		xflag_x = x->flag_x;
		if (x->type == T_HANDLER_FILL1)
			xtest_args = (char **)x->args[1];
	}

	fillargs = step_optreq(xargs, step_args, argc, argv, 2);
	if (fillargs == NULL)
		goto done;

	switch(xtype) {
		/* fill_tmpfile will return 0 if tmpfile or args are NULL */
	case T_HANDLER:
		/* pointer to handler routine, fill main args */
		nargs = fill_tmpfile(fillargs, tmpfile, tmp_args);
		switch (nargs) {
		case 0:
			(*xhandler)();
			break;
		case 1:
			(*xhandler)(tmp_args[0]);
			break;
		case 2:
			(*xhandler)(tmp_args[0], tmp_args[1]);
			break;
		case 3:
			(*xhandler)(tmp_args[0], tmp_args[1], tmp_args[2]);
			break;
		case 4:
			(*xhandler)(tmp_args[0], tmp_args[1], tmp_args[2],
			    tmp_args[3]);
			break;
		case 5:
			(*xhandler)(tmp_args[0], tmp_args[1], tmp_args[2],
			    tmp_args[3], tmp_args[4]);
			break;
		case 6:
			(*xhandler)(tmp_args[0], tmp_args[1], tmp_args[2],
			    tmp_args[3], tmp_args[4], tmp_args[5]);
			break;
		case NOPTFILL: /* bump this when adding more cases */
		default:
			printf("%% handler %s %s requires too many "
			    "arguments: %d\n", hname, argv[1], nargs);
			break;
		}
	break;
	case T_HANDLER_FILL1:
		/* pointer to handler routine, fill args @ args[1] pointer */
		if (fill_tmpfile(xtest_args, tmpfile, tmp_args))
			(*xhandler)(fillargs[0], tmp_args, fillargs[2]);
		else
			(*xhandler)(fillargs[0], xtest_args, fillargs[2]);
	break;
	case T_EXEC:
		/* command to execute via execv syscall, fill main args */
		if (fill_tmpfile(fillargs, tmpfile, tmp_args))
			cmdargs(tmp_args[0], tmp_args);
		else
			cmdargs(fillargs[0], fillargs);
	break;
	}

	if (xflag_x != 0) {
		flag_x("ctl", daemons->name, xflag_x, NULL);
	}
	rv = 1;
done:
	free(daemons1.table);
	return rv;
}

void
restart_dhcpd(char *arg0, char *arg1, char *arg2, char *arg3, char *arg4)
{
	char *argv_pkill[] = { PKILL, table, "dhcpd", NULL };

	cmdargs(argv_pkill[0], argv_pkill);
	sleep(1);
	start_dhcpd(arg0, arg1, arg2, arg3, arg4);
}

/*
 * Copy arguments from fillargs to tmp_args with temporary filenames
 * expanded. Return the number of arguments stored in tmp_args.
 * The maximum number of arguments allowed is NOPTFILL - 1.
 */
int
fill_tmpfile(char **fillargs, char *tmpfile, char **tmp_args)
{
	int i, n;

	if (fillargs == NULL || tmpfile == NULL)
		return 0;

	for (i = 0, n = 0; i < NOPTFILL - 1; i++) {
		if(fillargs[i] == NULL) {
			break;
		}
		if(fillargs[i] == REQTEMP) {
			tmp_args[i] = tmpfile;
		} else {
			tmp_args[i] = fillargs[i];
		}
		n++;
	}

	return n;
}

void
edit_crontab(char *name)
{
	char *crontab_argv[] = { CRONTAB, "-u", "root", "-l", NULL };
	char tmpfile[PATH_MAX];
	int found = 0;
	struct daemons *daemons;
	int fd = -1;

	for (daemons = ctl_daemons; daemons->name != 0; daemons++)
		if (strncmp(daemons->name, name, strlen(name)) == 0) {
			found = 1;
			break;
		}

	if (!found) {
		printf("%% edit_crontab internal error\n");
		return;
	}

	snprintf(tmpfile, sizeof(tmpfile), "%s.%d", daemons->tmpfile,
	    cli_rtable);

	fd = open(tmpfile, O_RDWR | O_EXCL);
	if (fd == -1) {
		if (errno != ENOENT) {
			printf("%% open %s: %s\n", tmpfile, strerror(errno));
			return;
		}
		fd = open(tmpfile, O_RDWR | O_CREAT | O_EXCL, daemons->mode);
		if (fd == -1) {
			printf("%% open %s: %s\n", tmpfile, strerror(errno));
			return;
		}

		/* Populate temporary file with current crontab. */
		if (cmdargs_output(CRONTAB, crontab_argv, fd, -1) != 0) {
			printf("%% crontab -l command failed\n");
			goto done;
		}
	}

	if (edit_file(tmpfile, daemons->mode, daemons->propername, NULL) == 0) {
		crontab_argv[3] = tmpfile;
		if (cmdargs(CRONTAB, crontab_argv) != 0)
			printf("%% failed to install crontab\n");
	}
done:
	close(fd);
}

void
install_crontab(char *name)
{
	char *crontab_argv[] = { CRONTAB, "-u", "root", NULL, NULL };
	char tmpfile[PATH_MAX];
	int fd, found = 0;
	struct daemons *daemons;

	for (daemons = ctl_daemons; daemons->name != 0; daemons++)
		if (strncmp(daemons->name, name, strlen(name)) == 0) {
			found = 1;
			break;
		}

	if (!found) {
		printf("%% install_crontab internal error\n");
		return;
	}

	snprintf(tmpfile, sizeof(tmpfile), "%s.%d", daemons->tmpfile,
	    cli_rtable);

	if ((fd = acq_lock(tmpfile)) > 0) {
		crontab_argv[3] = tmpfile;
		if (cmdargs(CRONTAB, crontab_argv) != 0)
			printf("%% failed to install crontab\n");
		rls_lock(fd);
	}
}

void
edit_motd(char *name)
{
	call_editor(name, NULL, NULL);
}

void
call_editor(char *name, char **args, char *z)
{
	int found = 0;
	char tmpfile[64];
	struct daemons *daemons;
	struct daemons2 *daemons2;

	for (daemons = ctl_daemons; daemons->name != 0; daemons++) {
		if (strncmp(daemons->name, name, strlen(name)) == 0) {
			found = 1;
			break;
		}
	}
	if (found) {
		snprintf(tmpfile, sizeof(tmpfile), "%s.%d", daemons->tmpfile,
		    cli_rtable);
		edit_file(tmpfile, daemons->mode, daemons->propername, args);
		return;
	}

	for (daemons2 = ctl_daemons2; daemons2->name != 0; daemons2++) {
		if (strncmp(daemons2->name, name, strlen(name)) == 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		printf("%% call_editor internal error\n");
		return;
	}
	snprintf(tmpfile, sizeof(tmpfile), "%s.%d", daemons2->tmpfile,
	    cli_rtable);
	edit_file(tmpfile, daemons2->mode, daemons2->propername, args);
}

static int
provide_example_config(char *filename)
{
	char *name;
	char path[PATH_MAX];
	char tmpprompt[sizeof(prompt)];
	FILE *f = NULL, *example = NULL;
	int ret = 0, n, num;
	struct stat sb;
	size_t len, remain;

	memset(tmpprompt, 0, sizeof(tmpprompt));

	f = fopen(filename, "a+");
	if (f == NULL)
		return 0;

	if (fstat(fileno(f), &sb) == -1)
		goto done;
	
	if (sb.st_size != 0)
		goto done;

	name = basename(filename);
	if (name == NULL)
		goto done;
	
	n = snprintf(path, sizeof(path), "/etc/examples/%s", name);
	if (n < 0 || (size_t)n >= sizeof(path))
		goto done;

	/* Snip off rdomain trailer at end of filename. */
	len = strlen(path);
	while (len > 0) {
		if (path[len - 1] >= '0' && path[len - 1] <= '9') {
			path[len - 1] = '\0';
			len--;
		} else {
			if (path[len - 1] == '.') {
				path[len - 1] = '\0';
				len--;
			}
			break;
		}
	}
	if (len == 0)
		goto done;

	example = fopen(path, "r");
	if (example == NULL)
		goto done;

	if (fstat(fileno(example), &sb) == -1)
		goto done;

	if (sb.st_size == 0)
		goto done;
	
	snprintf(tmpprompt, sizeof(tmpprompt),
	    "%s is empty. Load an example config? [Y/n]\n", filename);
	setprompt(tmpprompt);

	for (;;) {
		const char *buf;

		if ((buf = el_gets(elp, &num)) == NULL) {
			if (num == -1) {
				ret = -1;
				goto done;
			}
			/* EOF, e.g. ^X or ^D via exit_i() in complete.c */
			goto done;
		}

		if (strcmp(buf, "\n") == 0 ||
		    strcasecmp(buf, "yes\n") == 0 ||
		    strcasecmp(buf, "y\n") == 0)
			break;

		if (strcasecmp(buf, "no\n") == 0 ||
		    strcasecmp(buf, "n\n") == 0)
			goto done;

		printf("%% Please type \"yes\" or \"no\"\n");
	}

	remain = sb.st_size;
	while (remain > 0) {
		char buf[8192];
		ssize_t r;
		size_t w;

		len = (remain < sizeof(buf) ? remain : sizeof(buf));
		r = fread(buf, 1, len, example);
		if (r != len) {
			if (ferror(f)) {
				printf("%% fread %s: %s\n",
				    path, strerror(errno));
			}
			break;
		}

		w = fwrite(buf, 1, len, f);
		if (w != len) {
			if (ferror(f)) {
				printf("%% fwrite %s: %s\n",
				    filename, strerror(errno));
			}
			break;
		}

		remain -= len;
	}
done:
	fclose(f);
	if (tmpprompt[0] != '\0')
		restoreprompt();
	if (example)
		fclose(example);
	return ret;
}

int
edit_file(char *tmpfile, mode_t mode, char *propername, char **args)
{
	char *editor;
	int fd;
	int ret = 0;
	sig_t sigint;

	/* acq lock, call editor, test config with cmd and args, release lock */
	if ((editor = getenv("VISUAL")) == NULL) {
		if ((editor = getenv("EDITOR")) == NULL)
			editor = DEFAULT_EDITOR;
	}
	if ((fd = acq_lock(tmpfile)) > 0) {
		char *argv[] = { editor, tmpfile, NULL };

		/*
		 * Temporarily disable command.c intr() handler to ensure
		 * we tidy up the lock file when the user hits Ctrl-C at
		 * at prompt.
		 */
		sigint = signal(SIGINT, SIG_IGN);

		ret = provide_example_config(tmpfile);
		if (ret == 0)
			ret = cmdargs(editor, argv);
		if (ret == 0 && chmod(tmpfile, mode) == -1) {
			printf("%% chmod %o %s: %s\n",
			    mode, tmpfile, strerror(errno));
			ret = 1;
		}
		if (ret == 0 && args != NULL)
			ret = cmdargs(args[0], args);
		rls_lock(fd);
		signal(SIGINT, sigint); /* Restore SIGINT handler. */
	} else {
		printf ("%% %s configuration is locked for editing\n",
		    propername);
		return 1;
	}

	return ret;
}

int
rule_writeline(char *fname, mode_t mode, char *writeline)
{
	FILE *rulefile;

	rulefile = fopen(fname, "a");
	if (rulefile == NULL) {
		printf("%% Rule write failed: %s\n", strerror(errno));
		return(1);
	}
	if (writeline[0] == ' ')
		writeline++;
	fprintf(rulefile, "%s", writeline);
	fclose(rulefile);
	chmod(fname, mode);
	return(0);
}

int
acq_lock(char *fname)
{
	int fd;
	char lockf[SIZE_CONF_TEMP + sizeof(".lock")];

	/*
	 * some text editors lock (vi), some don't (mg)
	 *
	 * here we lock a separate, do-nothing file so we don't interfere
	 * with the editors that do... (lock multiple concurrent nsh users)
	 */
	snprintf(lockf, sizeof(lockf), "%s.lock", fname);
	if ((fd = open(lockf, O_RDWR | O_CREAT, 0600)) == -1)
			return(-1);
	if (flock(fd, LOCK_EX | LOCK_NB) == 0)
		return(fd);
	else {
		close(fd);
		return(-1);
	}
}

void
rls_lock(int fd)
{
	/* best-effort, who cares */
	flock(fd, LOCK_UN);
	close(fd);
	return;
}

void
rmtemp(char *file)
{
	if (unlink(file) != 0)
		if (errno != ENOENT)
			printf("%% Unable to remove temporary file %s: %s\n",
			    file, strerror(errno));
}

void
start_dhcpd(char *arg0, char *arg1, char *arg2, char *arg3, char *arg4)
{
	struct if_nameindex *ifn_list, *ifnp;
	char **dhcpd_args = NULL;
	size_t niface = 0;
	int ifs, i;
	char leasedb[PATH_MAX];

	/*
	 * For rdomains other than zero dhcpd(8) expects a list of
	 * interfaces on its command line. If no interface arguments
	 * are given then dhcpd will move itself into rdomain zero
	 * so we really must specify a list here.
	 *
	 * All named interfaces must be part of the same rdomain. We
	 * provide the list of all interfaces in our current rdomain.
	 * dhcpd will listen on any with matching subnets in dhcpd.conf.
	 */
	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% %s: if_nameindex failed\n", __func__);
		return;
	}

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% %s socket: %s\n", __func__, strerror(errno));
		goto done;
	}

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		int flags, rdomain;

		flags = get_ifflags(ifnp->if_name, ifs);
		if ((flags & IFF_LOOPBACK) ||
		    (flags & IFF_POINTOPOINT) ||
		    (!(flags & IFF_BROADCAST)))
			continue;

		rdomain = get_rdomain(ifs, ifnp->if_name);
		if (rdomain == cli_rtable)
			niface++;
	}

	dhcpd_args = calloc(5 + niface + 1, sizeof(char *));
	if (dhcpd_args == NULL) {
		printf("%% calloc: %s\n", strerror(errno));
		goto done;
	}

	i = 0;
	dhcpd_args[i++] = arg0; /* dhcpd */
	dhcpd_args[i++] = arg1; /* -c */
	dhcpd_args[i++] = arg2; /* dhcpd.conf */
	dhcpd_args[i++] = arg3; /* -l */
	if (cli_rtable != 0) {
		snprintf(leasedb, sizeof(leasedb), "%s.%d",
		    arg4, cli_rtable);
		dhcpd_args[i++] = leasedb; /* rdomain's leasedb */
	} else 
		dhcpd_args[i++] = arg4; /* default leasedb */

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		int flags, rdomain;

		flags = get_ifflags(ifnp->if_name, ifs);
		if ((flags & IFF_LOOPBACK) ||
		    (flags & IFF_POINTOPOINT) ||
		    (!(flags & IFF_BROADCAST)))
			continue;

		rdomain = get_rdomain(ifs, ifnp->if_name);
		if (rdomain == cli_rtable)
			dhcpd_args[i++] = ifnp->if_name;
	}
	dhcpd_args[i] = NULL;

	cmdargs(arg0, dhcpd_args);
done:
	if_freenameindex(ifn_list);
	free(dhcpd_args);
}
