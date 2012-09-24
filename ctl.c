/* $nsh: ctl.c,v 1.30 2012/05/23 05:45:35 chris Exp $ */
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
#include "externs.h"

/* service daemons */
#define OSPFD		"/usr/sbin/ospfd"
#define OSPF6D		"/usr/sbin/ospf6d"
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
#ifndef DHCPLEASES
#define DHCPLEASES	"/var/db/dhcpd.leases"
#endif

void call_editor(char *, char **, char *);
void ctl_symlink(char *, char **, char *);
int rule_writeline(char *, mode_t, char *);
int acq_lock(char *);
void rls_lock(int);

char *ctl_pf_test[] = { PFCTL, "-nf", PFCONF_TEMP, '\0' };
struct ctl ctl_pf[] = {
	{ "enable",	"enable service",
	    { PFCTL, "-e", NULL }, NULL, X_ENABLE },
	{ "disable",	"disable service",
	    { PFCTL, "-d", NULL }, NULL, X_DISABLE },
	{ "edit",	"edit configuration",
	    { "pf", (char *)ctl_pf_test, NULL }, call_editor, NULL },
	{ "reload",	"reload service",
	    { PFCTL, "-f", PFCONF_TEMP, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ospf_test[] = { OSPFD, "-nf", OSPFCONF_TEMP, '\0' };
struct ctl ctl_ospf[] = {
	{ "enable",     "enable service",
	    { OSPFD, "-f", OSPFCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "ospfd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "ospf", (char *)ctl_ospf_test, NULL }, call_editor, NULL },
	{ "reload",     "reload service",
	    { OSPFCTL, "reload", NULL }, NULL, NULL },
	{ "fib",        "fib couple/decouple",
	    { OSPFCTL, "fib", REQ, NULL }, NULL, NULL },
	{ "log",	"log brief/verbose",
	    { OSPFCTL, "log", REQ, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ospf6_test[] = { OSPF6D, "-nf", OSPF6CONF_TEMP, '\0' };
struct ctl ctl_ospf6[] = {
	{ "enable",     "enable service",
	    { OSPF6D, "-f", OSPF6CONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "ospf6d", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "ospf6", (char *)ctl_ospf6_test, NULL }, call_editor, NULL },
	{ "reload",     "reload service",
	    { OSPF6CTL, "reload", NULL }, NULL, NULL },
	{ "fib",        "fib couple/decouple",
	    { OSPF6CTL, "fib", REQ, NULL }, NULL, NULL },
	{ "log",	"log brief/verbose",
	    { OSPF6CTL, "log", REQ, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_bgp_test[] = { BGPD, "-nf", BGPCONF_TEMP, NULL, '\0' };
struct ctl ctl_bgp[] = {
	{ "enable",     "enable service",
	    { BGPD, "-f", BGPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "bgpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "bgp", (char *)ctl_bgp_test, NULL }, call_editor, NULL },
	{ "reload",     "reload service",
	    { BGPCTL, "reload", NULL }, NULL, NULL },
	{ "fib",	"fib couple/decouple",
	    { BGPCTL, "fib", REQ, NULL }, NULL, NULL },
	{ "irrfilter",	"generate bgpd filters",
	    { BGPCTL, "irrfilter", REQ, OPT, NULL }, NULL, NULL },
	{ "neighbor",	"neighbor up/down/clear/refresh",
	    { BGPCTL, "neighbor", OPT, OPT, NULL }, NULL, NULL },
	{ "network",	"network add/delete/flush/show",
	    { BGPCTL, "network", REQ, OPT, NULL }, NULL, NULL },
        { 0, 0, { 0 }, 0, 0 }
};

char *ctl_rip_test[] = { RIPD, "-nf", RIPCONF_TEMP, '\0' };
struct ctl ctl_rip[] = {
	{ "enable",     "enable service",
	    { RIPD, "-f", RIPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "ripd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "rip", (char *)ctl_rip_test, NULL }, call_editor, NULL },
	{ "reload",	"reload service",
	    { RIPCTL, "reload", NULL }, NULL, NULL },
	{ "fib",        "fib couple/decouple",
	    { RIPCTL, "fib", REQ, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ldp_test[] = { LDPD, "-nf", LDPCONF_TEMP, '\0' };
struct ctl ctl_ldp[] = {
	{ "enable",	"enable service",
	   { LDPD, "-f", LDPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",	"disable service",
	   { PKILL, "ldpd", NULL }, NULL, X_DISABLE },
	{ "edit",	"edit configuration",
	   { "ldp", (char *)ctl_ldp_test, NULL }, call_editor, NULL },
	{ "fib",	"fib couple/decouple",
	   { LDPCTL, "fib", REQ, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ipsec_test[] = { IPSECCTL, "-nf", IPSECCONF_TEMP, '\0' };
struct ctl ctl_ipsec[] = {
	{ "enable",     "enable service",
	    { ISAKMPD, "-Sa", NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",                   
	    { PKILL, "isakmpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",   
	    { "ipsec", (char *)ctl_ipsec_test, NULL }, call_editor, NULL },
	{ "reload",     "reload service",
	    { IPSECCTL, "-f", IPSECCONF_TEMP, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ike_test[] = { IKED, "-nf", IKECONF_TEMP, '\0' };
struct ctl ctl_ike[] = {
	{ "enable",	"enable service",
	    { IKED, "-f", IKECONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",	"disable service",
	    { PKILL, "iked", NULL }, NULL, X_DISABLE },
	{ "active",	"force IKE active mode",
	    { IKECTL, "active", NULL }, NULL, NULL },
	{ "passive",	"force IKE passive mode",
	    { IKECTL, "passive", NULL }, NULL, NULL },
	{ "couple",	"load SAs and flows into kernel",
	    { IKECTL, "couple", NULL }, NULL, NULL },
	{ "decouple",	"unload SAs and flows from kernel",
	    { IKECTL, "decouple", NULL }, NULL, NULL},
	{ "edit",	"edit configuration",
	    { "ike", (char *)ctl_ike_test, NULL }, call_editor, NULL},
	{ "reload",	"reload service",
	    { IKECTL, "reload", NULL }, NULL, NULL },
	{ "reset",	"reset state, policies, SAs or user database",
	    { IKECTL, "reset", REQ, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_dvmrp_test[] = { DVMRPD, "-nf", DVMRPCONF_TEMP, '\0' };
struct ctl ctl_dvmrp[] = {
	{ "enable",     "enable service",
	    { DVMRPD, "-f", DVMRPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",   
	    { PKILL, "dvmrpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "dvmrp", (char *)ctl_dvmrp_test,  NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ifstate_test[] = { IFSTATED, "-nf", IFSTATECONF_TEMP, '\0' };
struct ctl ctl_ifstate[] = {
	{ "enable",     "enable service",
	    { IFSTATED, "-f", IFSTATECONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "ifstated", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "ifstate", (char *)ctl_ifstate_test,  NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

struct ctl ctl_sasync[] = {
	{ "enable",     "enable service",
	    { SASYNCD, "-c", SASYNCCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "sasyncd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "sasync", NULL, NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_nppp_test[] = { NPPPD, "-nf", NPPPCONF_TEMP, '\0' };
struct ctl ctl_nppp[] = {
	{ "enable",	"enable service",
	    { NPPPD, "-f", NPPPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",	"disable service",
	    { PKILL, "npppd", NULL }, NULL, X_DISABLE },
	{ "clear",	"disconnect PPP sessions",
	    { NPPPCTL, "clear", REQ, OPT, OPT, NULL }, NULL, NULL },
	{ "session", 	"show PPP sessions",
	    { NPPPCTL, "session", REQ, OPT, OPT, NULL }, NULL, NULL },
	{ "edit",	"edit configuration",
	    { "nppp", (char *)ctl_nppp_test, NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_dhcp_test[] = { DHCPD, "-nc", DHCPCONF_TEMP, '\0' };
struct ctl ctl_dhcp[] = {
	{ "enable",     "enable service",
	    { DHCPD, "-c", DHCPCONF_TEMP, "-l", DHCPLEASES, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "dhcpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "dhcp", (char *)ctl_dhcp_test, NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_snmp_test[] = { SNMPD, "-nf", SNMPCONF_TEMP, '\0' };
struct ctl ctl_snmp[] = {
	{ "enable",     "enable service",
	    { SNMPD, "-f", SNMPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "snmpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "snmp", (char *)ctl_snmp_test, NULL }, call_editor, NULL },
	{ "trap",	"send traps",
	    { SNMPCTL, "trap", "send", REQ, OPT, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

struct ctl ctl_sshd[] = {
	{ "enable",	"enable service",
	    { SSHD, "-f", SSHDCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",	"disable service",
	    { PKILL, "-f", SSHD, "-f", SSHDCONF_TEMP, NULL }, NULL, X_DISABLE },
	{ "edit",	"edit configuration",
	    { "sshd", NULL, NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ntp_test[] = { NTPD, "-nf", NTPCONF_TEMP, '\0' };
struct ctl ctl_ntp[] = {
	{ "enable",     "enable service",
	    { NTPD, "-sf", NTPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "ntpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "ntp", (char *)ctl_ntp_test, NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_relay_test[] = { RELAYD, "-nf", RELAYCONF_TEMP, '\0' };
struct ctl ctl_relay[] = {
	{ "enable",	"enable service",
	    { RELAYD, "-f", RELAYCONF_TEMP, NULL }, NULL, X_ENABLE },
        { "disable",	"disable service",
	    { PKILL, "relayd", NULL }, NULL, X_DISABLE },
        { "edit",	"edit configuration",
	    { "relay", (char *)ctl_relay_test, NULL }, call_editor, NULL },
        { "reload",	"reload configuration",
	    { RELAYCTL, "reload", NULL }, NULL, NULL },
	{ "host",	"per-host control",
	    { RELAYCTL, "host", OPT, OPT, NULL }, NULL, NULL },
	{ "table",	"per-table control",
	    { RELAYCTL, "table", OPT, OPT, NULL }, NULL, NULL },
	{ "redirect",	"per-redirect control",
	    { RELAYCTL, "redirect", OPT, OPT, NULL }, NULL, NULL },
	{ "monitor",	"monitor mode",
	    { RELAYCTL, "monitor", NULL }, NULL, NULL },
	{ "poll",	"poll mode",
	    { RELAYCTL, "poll", NULL }, NULL, NULL},
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_smtp_test[] = { SMTPD, "-nf", SMTPCONF_TEMP, '\0' };
struct ctl ctl_smtp[] = {
	{ "enable",	"enable service",
	    { SMTPD, "-f", SMTPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",	"disable service",
	    { PKILL, "smtpd", NULL }, NULL, X_DISABLE },
	{ "edit",	"edit configuration",
	    { "smtp", (char *)ctl_smtp_test, NULL }, call_editor, NULL },
	{ "log",	"brief/verbose logging configuration",
	    { SMTPCTL, "log", REQ, NULL }, NULL, NULL },
	{ "pause",	"pause mda/mta/smtp listener",
	    { SMTPCTL, "pause", REQ, NULL }, NULL, NULL },
	{ "remove",	"remove message or envelope",
	    { SMTPCTL, "remove", REQ, NULL }, NULL, NULL },
	{ "resume",	"resume mda/mta/smtp listener",
	    { SMTPCTL, "resume", REQ, NULL }, NULL, NULL },
	{ "schedule-all", "schedule all envelopes for immediate delivery",
	    { SMTPCTL, "schedule-all", NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

struct ctl ctl_ftpproxy[] = {
	{ "enable",	"enable service",
	    { FTPPROXY, "-D", "2", NULL }, NULL, X_ENABLE },
	{ "disable",	"disable service",
	    { PKILL, "ftp-proxy", NULL }, NULL, X_DISABLE },
	{ 0, 0, { 0 }, 0, 0 }
};

struct ctl ctl_tftpproxy[] = {
	{ "enable",     "enable service",
	    { TFTPPROXY, "-v", "-l", "127.0.0.1", NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "tftp-proxy", NULL }, NULL, X_DISABLE },
	{ 0, 0, { 0 }, 0, 0 }
};

struct ctl ctl_tftp[] = {
	{ "enable", 	"enable service",
	   { TFTPD, "-l", "127.0.0.1", NULL }, NULL, X_ENABLE },
	{ "disable",	"disable service",
	   { PKILL, "tftpd", NULL }, NULL, X_DISABLE },
	{ 0, 0, { 0 }, 0, 0 }
};

struct ctl ctl_dns[] = {
	{ "local-control", "local control over DNS settings",
	    { RESOLVCONF_SYM, NULL, RESOLVCONF_TEMP, NULL }, ctl_symlink,
	    X_LOCAL },
	{ "dhcp-control",   "DHCP client control over DNS settings",
	    { RESOLVCONF_SYM, NULL, RESOLVCONF_DHCP, NULL }, ctl_symlink,
	    X_OTHER },
	{ "edit",	    "edit DNS settings",
	    { "dns", NULL, NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

struct ctl ctl_inet[] = {
	{ "enable",     "enable service",
	    { INETD, INETCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "inetd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "inet", NULL, NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

struct ctl ctl_ldap[] = {
	{ "enable",	"enable service",
	    { LDAPD, LDAPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",	"disable service",
	    { PKILL, "ldapd", NULL }, NULL, X_DISABLE },
	{ "log", 	"brief/verbose logging",
	    { LDAPCTL, "log", REQ, NULL }, NULL, NULL },
	{ "compact",	"compact all databases",
	    { LDAPCTL, "compact", NULL }, NULL, NULL },
	{ "index",	"re-index all databases",
	    { LDAPCTL, "index", NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0, }
};

struct daemons ctl_daemons[] = {
	{ "pf",		"PF",	ctl_pf,		PFCONF_TEMP,	0600, 1 },
	{ "ospf",	"OSPF", ctl_ospf,	OSPFCONF_TEMP,	0600, 0 },
	{ "ospf6",	"OSPF6", ctl_ospf6,	OSPF6CONF_TEMP, 0600, 0 },
	{ "bgp",	"BGP",	ctl_bgp,	BGPCONF_TEMP,	0600, 0 },
	{ "rip",	"RIP",	ctl_rip,	RIPCONF_TEMP,	0600, 0 },
	{ "ldp",	"LDP",	ctl_ldp,	LDPCONF_TEMP,	0600, 0 },
	{ "relay",	"Relay", ctl_relay,	RELAYCONF_TEMP,	0600, 0 },
	{ "ipsec",	"IPsec IKEv1", ctl_ipsec,	IPSECCONF_TEMP,	0600, 1 },
	{ "ike",	"IPsec IKEv2", ctl_ike,		IKECONF_TEMP, 0600, 0 },
	{ "dvmrp",	"DVMRP", ctl_dvmrp,	DVMRPCONF_TEMP, 0600, 0 },
	{ "sasync",	"SAsync", ctl_sasync,	SASYNCCONF_TEMP,0600, 0 },
	{ "dhcp",	"DHCP",	ctl_dhcp,	DHCPCONF_TEMP,	0600, 0 },
	{ "snmp",	"SNMP",	ctl_snmp,	SNMPCONF_TEMP,	0600, 0 },
	{ "sshd",	"SSH",	ctl_sshd,	SSHDCONF_TEMP,	0600, 0 },
	{ "ntp",	"NTP",	ctl_ntp,	NTPCONF_TEMP,	0600, 0 },
	{ "ifstate",	"ifstate", ctl_ifstate,	IFSTATECONF_TEMP, 0600, 0 },
	{ "ftp-proxy",  "FTP proxy", ctl_ftpproxy, FTPPROXY_TEMP, 0600, 0 },
	{ "tftp-proxy",	"TFTP proxy", ctl_tftpproxy, TFTPPROXY_TEMP, 0600, 0 },
	{ "tftp",	"TFTP", ctl_tftp,	TFTP_TEMP,	0600, 0 },
	{ "nppp",	"PPP",	ctl_nppp,	NPPPCONF_TEMP,	0600, 0 },
	{ "dns", 	"DNS", ctl_dns,		RESOLVCONF_TEMP,0644, 0 },
	{ "inet",	"Inet", ctl_inet,	INETCONF_TEMP,	0600, 0 },
	{ "smtp",	"SMTP", ctl_smtp,	SMTPCONF_TEMP,	0600, 0 },
	{ "ldap",	"LDAP", ctl_ldap,	LDAPCONF_TEMP,	0600, 0 },
	{ "ifstate",	"Interface state", ctl_ifstate,	IFSTATECONF_TEMP, 0600, 0 },
	{ 0, 0, 0, 0, 0 }
};

void
ctl_symlink(char *temp, char **z, char *real)
{
	rmtemp(temp);
	symlink(real,temp);
}

/* flag to other nsh sessions or nsh conf() that actions have been taken with parameter in text file*/
void
flag_x(char *fname, int *y, char *data)
{
	FILE *file;
	char fenabled[SIZE_CONF_TEMP + sizeof(".enabled") + 1];
	char fother[SIZE_CONF_TEMP + sizeof(".other") + 1];
	char flocal[SIZE_CONF_TEMP + sizeof(".local") + 1];

	snprintf(fenabled, sizeof(fenabled), "%s.enabled", fname);
	snprintf(fother, sizeof(fother), "%s.other", fname);
	snprintf(flocal, sizeof(flocal), "%s.local", fname);

	if (y == X_ENABLE) {
		if ((file = fopen(fenabled, "w")) == NULL)
			return;
		chmod(fenabled, 0600);
		if (data)
			fprintf(file, "%s", data);
		fclose(file);
	} else if (y == X_DISABLE) {
		rmtemp(fenabled);
	} else if (y == X_OTHER) {
		rmtemp(flocal);
		if ((file = fopen(fother, "w")) == NULL)
			return;
		chmod(fother, 0600);
		if (data)
			fprintf(file, "%s", data);
		fclose(file);   
	} else if (y == X_LOCAL) {
		rmtemp(fother);
		if ((file = fopen(flocal, "w")) == NULL)
			return;
		chmod(flocal, 0600);
		if (data)
			fprintf(file, "%s", data);
		fclose(file);
	}
}

int
ctlhandler(int argc, char **argv, char *modhvar)
{
	struct daemons *daemons;
	struct ctl *x;
	char *args[NOPTFILL] = { NULL, NULL, NULL, NULL, NULL, NULL, '\0' };
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

	if (modhvar) {
		/* action specified or indented command specified */
		if (argc == 2 && isprefix(argv[1], "rules")) {
			/* skip 'X rules' line */
			return(0);
		}
		if (argc == 2 && isprefix(argv[1], "action")) {
			printf("%% Old configuration WILL NOT WORK! FIX IT!\n");
			return(0);
		}
		if (isprefix(modhvar, "rules")) {
			/* write indented line to tmp config file */
			rule_writeline(daemons->tmpfile, daemons->mode,
			    saveline);
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

	fillargs = step_optreq(x->args, args, argc, argv, 2);
	if (fillargs == NULL)
		return 0;

	if (x->handler)
		(*x->handler)(fillargs[0], (char **)fillargs[1], fillargs[2]);
	else
		cmdargs(fillargs[0], fillargs);

	if (x->flag_x != NULL)
		flag_x(daemons->tmpfile, x->flag_x, NULL);

	return 1;
}

void
call_editor(char *name, char **args, char *z)
{
	int fd, found = 0;
	char *editor;
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

	/* acq lock, call editor, test config with cmd and args, release lock */

	if ((editor = getenv("EDITOR")) == NULL || *editor == '\0')
		editor = DEFAULT_EDITOR;
	if ((fd = acq_lock(daemons->tmpfile)) > 0) {
		char *argv[] = { editor, daemons->tmpfile, '\0' };
		cmdargs(editor, argv);
		chmod(daemons->tmpfile, daemons->mode);
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
	 * with the editors that do...
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
