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
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include "externs.h"

/* service daemons */
#define OSPFD		"/usr/sbin/ospfd"
#define OSPF6D		"/usr/sbin/ospf6d"
#define EIGRPD		"/usr/sbin/eigrpd"
#define BGPD		"/usr/sbin/bgpd"
#define RIPD		"/usr/sbin/ripd"
#define ISAKMPD		"/sbin/isakmpd"
#define IKED		"/sbin/iked"
#define DVMRPD		"/usr/sbin/dvmrpd"
#define RELAYD		"/usr/sbin/relayd"
#define DHCPD		"/usr/sbin/dhcpd"
#define SASYNCD		"/usr/sbin/sasyncd"
#define	SNMPD		"/usr/sbin/snmpd"
#define NTPD		"/usr/sbin/ntpd"
#define FTPPROXY	"/usr/sbin/ftp-proxy"
#define TFTPPROXY	"/usr/sbin/tftp-proxy"
#define TFTPD		"/usr/sbin/tftpd"
#define INETD		"/usr/sbin/inetd"
#define SSHD		"/usr/sbin/sshd"
#define LDPD		"/usr/sbin/ldpd"
#define SMTPD		"/usr/sbin/smtpd"
#define LDAPD		"/usr/sbin/ldapd"
#define IFSTATED	"/usr/sbin/ifstated"
#define NPPPD		"/usr/sbin/npppd"
#define NPPPCTL		"/usr/sbin/npppctl"
#define RESOLVD		"/sbin/resolvd"
#ifndef DHCPLEASES
#define DHCPLEASES	"/var/db/dhcpd.leases"
#endif

/* table variable (for pkill usage) */
static char table[16];

/* service routines */
void call_editor(char *, char **, char *);
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
{ "dhcp",	"DHCP",	ctl_dhcp,	DHCPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "snmp",	"SNMP",	ctl_snmp,	SNMPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "sshd",	"SSH",	ctl_sshd,	SSHDCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "ntp",	"NTP",	ctl_ntp,	NTPCONF_TEMP,	0600, 0, 0 },
{ "ifstate",	"ifstate",ctl_ifstate,	IFSTATECONF_TEMP,0600, 0, RT_TABLEID_MAX },
{ "ftp-proxy",	"FTP proxy",ctl_ftpproxy,FTPPROXY_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "tftp-proxy",	"TFTP proxy",ctl_tftpproxy,TFTPPROXY_TEMP,0600, 0, RT_TABLEID_MAX },
{ "tftp",	"TFTP",	ctl_tftp,	TFTP_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "nppp",	"PPP",	ctl_nppp,	NPPPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "resolv",	"resolvd",ctl_resolv,	NULL,		0, 0, 0 },
{ "dns",	"DNS",	ctl_dns,	RESOLVCONF_TEMP,0644, 0, 0 },
{ "inet",	"Inet",	ctl_inet,	INETCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "smtp",	"SMTP",	ctl_smtp,	SMTPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "ldap",	"LDAP",	ctl_ldap,	LDAPCONF_TEMP,	0600, 0, RT_TABLEID_MAX },
{ "ifstate",	"If state",ctl_ifstate,	IFSTATECONF_TEMP,0600, 0, RT_TABLEID_MAX },
{ "motd",        "MOTD",  ctl_motd,        MOTD_TEMP,0644, 0, 0 },
{ 0, 0, 0, 0, 0, 0 }
};

/* per-daemon commands, and their C or executable functions */ 

/* MOTD */
struct ctl ctl_motd[] = {
        { "edit",           "edit message-of-the-day",
            { "motd", NULL, NULL }, call_editor, 0, T_HANDLER },
        { 0, 0, { 0 }, 0, 0, 0 }
};

/* PF, pfctl */
char *ctl_pf_test[] = { PFCTL, "-nf", REQTEMP, NULL };
struct ctl ctl_pf[] = {
	{ "enable",	"enable service",
	    { PFCTL, "-e", NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	    { PFCTL, "-d", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",	"edit configuration",
	    { "pf", (char *)ctl_pf_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "reload",	"reload service",
	    { PFCTL, "-f", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ospfd, ospfctl */
char *ctl_ospf_test[] = { OSPFD, "-nf", REQTEMP, NULL };
struct ctl ctl_ospf[] = {
	{ "enable",     "enable service",
	    { OSPFD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, table, "ospfd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "ospf", (char *)ctl_ospf_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "reload",     "reload service",
	    { OSPFCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",        "fib couple/decouple",
	    { OSPFCTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "log",        "log brief/verbose",
            { OSPFCTL, "log", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",	"show database/fib/interfaces/neighbor/rib/summary",
	    { OSPFCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ospf6d, ospf6ctl */
char *ctl_ospf6_test[] = { OSPF6D, "-nf", REQTEMP, NULL };
struct ctl ctl_ospf6[] = {
	{ "enable",     "enable service",
	    { OSPF6D, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, table, "ospf6d", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "ospf6", (char *)ctl_ospf6_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "reload",     "reload service",
	    { OSPF6CTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",        "fib couple/decouple",
	    { OSPF6CTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "log",	"log brief/verbose",
	    { OSPF6CTL, "log", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* eigrpd, eigrpctl */
char *ctl_eigrp_test[] = { EIGRPD, "-nf", REQTEMP, NULL };
struct ctl ctl_eigrp[] = {
	{ "enable",	"enable service",
	    { EIGRPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	    { PKILL, table, "eigrpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",	"edit configuration",
	    { "eigrp", (char *)ctl_eigrp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "reload",	"reload service",
	    { EIGRPCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",	"fib couple/decouple",
	    { EIGRPCTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "log",	"log brief/verbose",
	    { EIGRPCTL, "lob", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",       "show fib/interfaces/neighbor/topology/traffic",
            { EIGRPCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* bgpd, bgpctl */
char *ctl_bgp_test[] = { BGPD, "-nf", REQTEMP, NULL, NULL };
struct ctl ctl_bgp[] = {
	{ "enable",     "enable service",
	    { BGPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, "bgpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "bgp", (char *)ctl_bgp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "reload",     "reload service",
	    { BGPCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",	"fib couple/decouple",
	    { BGPCTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "irrfilter",	"generate bgpd filters",
	    { BGPCTL, "irrfilter", REQ, OPT, NULL }, NULL, 0, T_EXEC },
	{ "neighbor",	"neighbor up/down/clear/refresh",
	    { BGPCTL, "neighbor", OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "network",	"network add/delete/flush/show",
	    { BGPCTL, "network", REQ, OPT, NULL }, NULL, 0, T_EXEC },
        { 0, 0, { 0 }, 0, 0, 0 }
};

/* ripd, ripctl */
char *ctl_rip_test[] = { RIPD, "-nf", REQTEMP, NULL };
struct ctl ctl_rip[] = {
	{ "enable",     "enable service",
	    { RIPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, table, "ripd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "rip", (char *)ctl_rip_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "reload",	"reload service",
	    { RIPCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",        "fib couple/decouple",
	    { RIPCTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",       "show fib/interfaces/neighbor/rib",
            { RIPCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ldpd, ldpctl */
char *ctl_ldp_test[] = { LDPD, "-nf", REQTEMP, NULL };
struct ctl ctl_ldp[] = {
	{ "enable",	"enable service",
	   { LDPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	   { PKILL, "ldpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",	"edit configuration",
	   { "ldp", (char *)ctl_ldp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "reload",	"reload service",
	    { LDPCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "fib",	"fib couple/decouple",
	   { LDPCTL, "fib", REQ, NULL }, NULL, 0, T_EXEC },
	{ "clear",       "clear neighbors",
            { LDPCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",       "show fib/interfaces/discovery/neighbor/lib",
            { LDPCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* isakmpd, ipsecctl */
char *ctl_ipsec_test[] = { IPSECCTL, "-nf", REQTEMP, NULL };
struct ctl ctl_ipsec[] = {
	{ "enable",     "enable service",
	    { ISAKMPD, "-Kv", NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, table, "isakmpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",   
	    { "ipsec", (char *)ctl_ipsec_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "reload",     "reload service",
	    { IPSECCTL, "-f", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ "show",       "show flow/sa/all",
            { IPSECCTL, "-s", REQTEMP, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* iked, ikectl */
char *ctl_ike_test[] = { IKED, "-nf", REQTEMP, NULL };
struct ctl ctl_ike[] = {
	{ "enable",	"enable service",
	    { IKED, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	    { PKILL, table, "iked", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "active",	"force IKE active mode",
	    { IKECTL, "active", NULL }, NULL, 0, T_EXEC },
	{ "passive",	"force IKE passive mode",
	    { IKECTL, "passive", NULL }, NULL, 0, T_EXEC },
	{ "couple",	"load SAs and flows into kernel",
	    { IKECTL, "couple", NULL }, NULL, 0, T_EXEC },
	{ "decouple",	"unload SAs and flows from kernel",
	    { IKECTL, "decouple", NULL }, NULL, 0, T_EXEC },
	{ "edit",	"edit configuration",
	    { "ike", (char *)ctl_ike_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "reload",	"reload service",
	    { IKECTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "reset",	"reset state, policies, SAs or user database",
	    { IKECTL, "reset", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",       "show sa",
            { IKECTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* dvmrpd */
char *ctl_dvmrp_test[] = { DVMRPD, "-nf", REQTEMP, NULL };
struct ctl ctl_dvmrp[] = {
	{ "enable",     "enable service",
	    { DVMRPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable service",   
	    { PKILL, table, "dvmrpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "dvmrp", (char *)ctl_dvmrp_test,  NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "log",       "log brief/verbose",
            { DVMRPCTL, "log", REQ, NULL }, NULL, 0, T_EXEC },
	{ "show",       "show igmp/interfaces/mfc/neighbor/rib/summary",
            { DVMRPCTL, "show", REQ, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* rad */
char *ctl_rad_test[] = { RAD, "-nf", REQTEMP, NULL };
struct ctl ctl_rad[] = {
	{ "enable",	"enable service",
	    { RAD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	    { PKILL, "rad", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",  "edit configuration",
	    { "rad", (char *)ctl_rad_test, NULL}, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ifstated */
char *ctl_ifstate_test[] = { IFSTATED, "-nf", REQTEMP, NULL };
struct ctl ctl_ifstate[] = {
	{ "enable",     "enable service",
	    { IFSTATED, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, table, "ifstated", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "ifstate", (char *)ctl_ifstate_test,  NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* sasyncd */
struct ctl ctl_sasync[] = {
	{ "enable",     "enable service",
	    { SASYNCD, "-c", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, table, "sasyncd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "sasync", NULL, NULL }, call_editor, 0, T_HANDLER_FILL1 },
	{ 0, 0, { 0 }, 0, 0 }
};

/* npppd, npppctl */
char *ctl_nppp_test[] = { NPPPD, "-nf", REQTEMP, NULL };
struct ctl ctl_nppp[] = {
	{ "enable",	"enable service",
	    { NPPPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	    { PKILL, table, "npppd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "clear",	"disconnect PPP sessions",
	    { NPPPCTL, "clear", REQ, OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "session", 	"show PPP sessions",
	    { NPPPCTL, "session", REQ, OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "monitor",	"monitor PPP sessions",
	    { NPPPCTL, "monitor", REQ, OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "edit",	"edit configuration",
	    { "nppp", (char *)ctl_nppp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* dhcpd */
char *ctl_dhcp_test[] = { DHCPD, "-nc", REQTEMP, NULL };
struct ctl ctl_dhcp[] = {
	{ "enable",     "enable service",
	    { DHCPD, "-c", REQTEMP, "-l", DHCPLEASES, NULL }, NULL, DB_X_ENABLE,
	    T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, table, "dhcpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "dhcp", (char *)ctl_dhcp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* snmpd, snmpctl */
char *ctl_snmp_test[] = { SNMPD, "-nf", REQTEMP, NULL };
struct ctl ctl_snmp[] = {
	{ "enable",     "enable service",
	    { SNMPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, table, "snmpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "snmp", (char *)ctl_snmp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "trap",	"send traps",
	    { SNMPCTL, "trap", "send", REQ, OPT, NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* sshd */
char *ctl_sshd_test[] = { SSHD, "-tf", REQTEMP, NULL };
struct ctl ctl_sshd[] = {
	{ "enable",	"enable service",
	    { SSHD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	    { PKILL, table, "-f", SSHD, "-f", REQTEMP, NULL }, NULL,
	    DB_X_DISABLE, T_EXEC },
	{ "edit",	"edit configuration",
	    { "sshd", (char *)ctl_sshd_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ntpd */
char *ctl_ntp_test[] = { NTPD, "-nf", REQTEMP, NULL };
struct ctl ctl_ntp[] = {
	{ "enable",     "enable service",
	    { NTPD, "-sf", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, "ntpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "ntp", (char *)ctl_ntp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* relayd, relayctl */
char *ctl_relay_test[] = { RELAYD, "-nf", REQTEMP, NULL };
struct ctl ctl_relay[] = {
	{ "enable",	"enable service",
	    { RELAYD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
        { "disable",	"disable service",
	    { PKILL, table, "relayd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
        { "edit",	"edit configuration",
	    { "relay", (char *)ctl_relay_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
        { "reload",	"reload configuration",
	    { RELAYCTL, "reload", NULL }, NULL, 0, T_EXEC },
	{ "host",	"per-host control",
	    { RELAYCTL, "host", OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "table",	"per-table control",
	    { RELAYCTL, "table", OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "redirect",	"per-redirect control",
	    { RELAYCTL, "redirect", OPT, OPT, NULL }, NULL, 0, T_EXEC },
	{ "monitor",	"monitor mode",
	    { RELAYCTL, "monitor", NULL }, NULL, 0, T_EXEC },
	{ "poll",	"poll mode",
	    { RELAYCTL, "poll", NULL }, NULL, 0, T_EXEC },
	{ "show",       "show hosts/redirects/relays/routers/sessions/summary",
            { RELAYCTL, "show",  NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* snmpd, snmpctl */
char *ctl_smtp_test[] = { SMTPD, "-nf", REQTEMP, NULL };
struct ctl ctl_smtp[] = {
	{ "enable",	"enable service",
	    { SMTPD, "-f", REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	    { PKILL, table, "smtpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",	"edit configuration",
	    { "smtp", (char *)ctl_smtp_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "log",	"brief/verbose logging configuration",
	    { SMTPCTL, "log", REQ, NULL }, NULL, 0, T_EXEC },
	{ "pause",	"pause mda/mta/smtp listener",
	    { SMTPCTL, "pause", REQ, NULL }, NULL, 0, T_EXEC },
	{ "remove",	"remove message or envelope",
	    { SMTPCTL, "remove", REQ, NULL }, NULL, 0, T_EXEC },
	{ "resume",	"resume mda/mta/smtp listener",
	    { SMTPCTL, "resume", REQ, NULL }, NULL, 0, T_EXEC },
	{ "schedule-all", "schedule all envelopes for immediate delivery",
	    { SMTPCTL, "schedule-all", NULL }, NULL, 0, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ftpproxy */
struct ctl ctl_ftpproxy[] = {
	{ "enable",	"enable service",
	    { FTPPROXY, "-D", "2", NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	    { PKILL, table, "ftp-proxy", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* tftpproxy */
struct ctl ctl_tftpproxy[] = {
	{ "enable",     "enable service",
	    { TFTPPROXY, "-v", "-l", "127.0.0.1", NULL }, NULL, DB_X_ENABLE,
	    T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, table, "tftp-proxy", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* tftpd */
struct ctl ctl_tftp[] = {
	{ "enable", 	"enable service",
	   { TFTPD, "-l", "127.0.0.1", "/tftpboot", NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	   { PKILL, table, "tftpd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* resolvd */
struct ctl ctl_resolv[] = {
	{ "enable",	"enable service",
	   { RESOLVD, NULL }, NULL, DB_X_ENABLE_DEFAULT, T_EXEC },
	{ "disable",    "disable service",
	   { PKILL, "resolvd", NULL }, NULL, DB_X_DISABLE_ALWAYS, T_EXEC },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* resolv.conf */
struct ctl ctl_dns[] = {
	{ "local-control", "local control over DNS settings",
	    { RESOLVCONF_SYM, REQTEMP, NULL }, ctl_symlink,
	    DB_X_LOCAL, T_HANDLER },
	{ "dhcp-control",   "DHCP client control over DNS settings",
	    { RESOLVCONF_SYM, RESOLVCONF_DHCP, NULL }, ctl_symlink,
	    DB_X_OTHER, T_HANDLER },
	{ "edit",	    "edit DNS settings",
	    { "dns", NULL, NULL }, call_editor, 0, T_HANDLER },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* inetd */
struct ctl ctl_inet[] = {
	{ "enable",     "enable service",
	    { INETD, REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",    "disable service",
	    { PKILL, table, "inetd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "inet", NULL, NULL }, call_editor, 0, T_HANDLER_FILL1 },
	{ 0, 0, { 0 }, 0, 0, 0 }
};

/* ldapd, ldapctl */
char *ctl_ldap_test[] = { LDAPD, "-nf", REQTEMP, NULL };
struct ctl ctl_ldap[] = {
	{ "enable",	"enable service",
	    { LDAPD, REQTEMP, NULL }, NULL, DB_X_ENABLE, T_EXEC },
	{ "disable",	"disable service",
	    { PKILL, table, "ldapd", NULL }, NULL, DB_X_DISABLE, T_EXEC },
	{ "edit",       "edit configuration",
	    { "ldap", (char *)ctl_ldap_test, NULL }, call_editor, 0,
	    T_HANDLER_FILL1 },
	{ "log", 	"brief/verbose logging",
	    { LDAPCTL, "log", REQ, NULL }, NULL, 0, T_EXEC },
	{ "compact",	"compact all databases",
	    { LDAPCTL, "compact", NULL }, NULL, 0, T_EXEC },
	{ "index",	"re-index all databases",
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
	if (db_delete_flag_x_ctl(name, daemon) < 0) {
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
	struct ctl *x;
	char tmpfile[PATH_MAX];
	char *step_args[NOPTFILL] = { NULL, NULL, NULL, NULL, NULL, NULL };
	char *tmp_args[NOPTFILL] = { NULL, NULL, NULL, NULL, NULL, NULL };
	char **fillargs;

	/* loop daemon list to find table pointer */
	daemons = (struct daemons *) genget(hname, (char **)ctl_daemons,
	    sizeof(struct daemons));
	if (daemons == 0) {
		printf("%% Internal error - Invalid argument %s\n", argv[1]);
		return 0;
	} else if (Ambiguous(daemons)) {
		printf("%% Internal error - Ambiguous argument %s\n", argv[1]);
		return 0;
	}

	if (cli_rtable > daemons->rtablemax) {
		printf("%% Command %s not available via rtable %d\n",
		    daemons->name, cli_rtable);
		return 0;
	}

	snprintf(table, sizeof(table), "-T%d", cli_rtable);
	if (daemons->tmpfile)
		snprintf(tmpfile, sizeof(tmpfile), "%s.%d", daemons->tmpfile,
		    cli_rtable);

	if (modhvar) {
		/* action specified or indented command specified */
		if (argc == 2 && isprefix(argv[1], "rules")) {
			/* skip 'X rules' line */
			return(0);
		}
		if (isprefix(modhvar, "rules")) {
			if (!daemons->tmpfile) {
				printf("%% writeline without tmpfile\n");
				return 0;
			}
			/* write indented line to tmp config file */
			rule_writeline(tmpfile, daemons->mode, saveline);
			return 0;
		}
	}
	if (argc < 2 || argv[1][0] == '?') {
		gen_help((char **)daemons->table, "", "", sizeof(struct ctl));
		return 0;
	}

	x = (struct ctl *) genget(argv[1], (char **)daemons->table,
	    sizeof(struct ctl));
	if (x == 0) {
		printf("%% Invalid argument %s\n", argv[1]);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", argv[1]);
		return 0;
	}

	fillargs = step_optreq(x->args, step_args, argc, argv, 2);
	if (fillargs == NULL)
		return 0;

	switch(x->type) {
		/* fill_tmpfile will return 0 if tmpfile or args are NULL */
	case T_HANDLER:
		/* pointer to handler routine, fill main args */
		if (fill_tmpfile(fillargs, tmpfile, tmp_args)) {
			(*x->handler)(tmp_args[0], tmp_args[1], tmp_args[2]);
		} else {
			(*x->handler)(fillargs[0], fillargs[1], fillargs[2]);
		}
	break;
	case T_HANDLER_FILL1:
		/* pointer to handler routine, fill args @ args[1] pointer */
		if (fill_tmpfile((char **)fillargs[1], tmpfile, tmp_args))
			(*x->handler)(fillargs[0], tmp_args, fillargs[2]);
		else
			(*x->handler)(fillargs[0], (char **)fillargs[1], fillargs[2]);
	break;
	case T_EXEC:
		/* command to execute via execv syscall, fill main args */
		if (fill_tmpfile(fillargs, tmpfile, tmp_args))
			cmdargs(tmp_args[0], tmp_args);
		else
			cmdargs(fillargs[0], fillargs);
	break;
	}

	if (x->flag_x != 0) {
		flag_x("ctl", daemons->name, x->flag_x, NULL);
	}

	return 1;
}

int
fill_tmpfile(char **fillargs, char *tmpfile, char **tmp_args)
{
	int i;

	if (fillargs == NULL || tmpfile == NULL)
		return 0;

	for (i = 0; i < NOPTFILL - 1; i++) {
		if(fillargs[i] == NULL) {
			break;
		}
		if(fillargs[i] == REQTEMP) {
			tmp_args[i] = tmpfile;
		} else {
			tmp_args[i] = fillargs[i];
		}
	}
	return 1;
}

void
call_editor(char *name, char **args, char *z)
{
	int fd, found = 0;
	char *editor, tmpfile[64];
	struct daemons *daemons;

	for (daemons = ctl_daemons; daemons->name != 0; daemons++)
		if (strncmp(daemons->name, name, strlen(name)) == 0) {
			found = 1;
			break;
		}

	if (!found) {
		printf("%% call_editor internal error\n");
		return;
	}

	snprintf(tmpfile, sizeof(tmpfile), "%s.%d", daemons->tmpfile,
	    cli_rtable);

	/* acq lock, call editor, test config with cmd and args, release lock */
	if ((editor = getenv("EDITOR")) == NULL)
		editor = DEFAULT_EDITOR;
	if ((fd = acq_lock(tmpfile)) > 0) {
		char *argv[] = { editor, tmpfile, NULL };
		cmdargs(editor, argv);
		chmod(tmpfile, daemons->mode);
		if (args != NULL)
			cmdargs(args[0], args);
		rls_lock(fd);
	} else
		printf ("%% %s configuration is locked for editing\n",
		    daemons->propername);
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
