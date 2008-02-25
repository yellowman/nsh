/* $nsh: ctl.c,v 1.18 2008/02/25 06:18:00 chris Exp $ */
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
#include "externs.h"

/* service daemons */
#define OSPFD		"/usr/sbin/ospfd"
#define BGPD		"/usr/sbin/bgpd"
#define RIPD		"/usr/sbin/ripd"
#define ISAKMPD		"/sbin/isakmpd"
#define DVMRPD		"/usr/sbin/dvmrpd"
#define RELAYD		"/usr/sbin/relayd"
#define DHCPD		"/usr/sbin/dhcpd"
#define SASYNCD		"/usr/sbin/sasyncd"
#define	SNMPD		"/usr/sbin/snmpd"
#define NTPD		"/usr/sbin/ntpd"
#define FTPPROXY	"/usr/sbin/ftp-proxy"

void call_editor(char *, char **, char *);
void ctl_symlink(char *, char **, char *);
int rule_writeline(char *, char *);
int acq_lock(char *);
void rls_lock(int);
void flag_x(char *, int *);

char *ctl_pf_test[] = { PFCTL, "-nf", PFCONF_TEMP, '\0' };
struct ctl ctl_pf[] = {
	{ "enable",	"enable service",
	    { PFCTL, "-e", NULL }, NULL, X_ENABLE },
	{ "disable",	"disable service",
	    { PFCTL, "-d", NULL }, NULL, X_DISABLE },
	{ "edit",	"edit configuration",
	    { "PF", (char *)ctl_pf_test, PFCONF_TEMP, NULL }, call_editor,
	    NULL },
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
	    { "OSPF", (char *)ctl_ospf_test, OSPFCONF_TEMP, NULL },
	    call_editor, NULL },
	{ "reload",     "reload service",
	    { OSPFCTL, "reload", NULL }, NULL, NULL },
	{ "fib",        "fib couple/decouple",
	    { OSPFCTL, "fib", REQ, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_bgp_test[] = { BGPD, "-nf", BGPCONF_TEMP, NULL, '\0' };
struct ctl ctl_bgp[] = {
	{ "enable",     "enable service",
	    { BGPD, "-f", BGPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "bgpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "BGP", (char *)ctl_bgp_test, BGPCONF_TEMP, NULL }, call_editor,
	    NULL },
	{ "reload",     "reload service",
	    { BGPCTL, "reload", NULL }, NULL, NULL },
	{ "fib",	"fib couple/decouple",
	    { BGPCTL, "fib", REQ, NULL }, NULL, NULL },
	{ "irrfilter",	"generate bgpd filters",
	    { BGPCTL, "irrfilter", REQ, OPT, NULL }, NULL, NULL },
	{ "neighbor",	"neighbor up/down/clear/refresh",
	    { BGPCTL, "neighbor", REQ, REQ, NULL }, NULL, NULL },
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
	    { "RIP", (char *)ctl_rip_test, RIPCONF_TEMP, NULL }, call_editor,
	    NULL },
	{ "reload",     "reload service",
	    { RIPCTL, "reload", NULL }, NULL, NULL },
	{ "fib",        "fib couple/decouple",
	    { RIPCTL, "fib", REQ, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ipsec_test[] = { IPSECCTL, "-nf", IPSECCONF_TEMP, '\0' };
struct ctl ctl_ipsec[] = {
	{ "enable",     "enable service",
	    { ISAKMPD, "-Sa", NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",                   
	    { PKILL, "isakmpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",   
	    { "IPsec", (char *)ctl_ipsec_test, IPSECCONF_TEMP, NULL },
	    call_editor, NULL },
	{ "reload",     "reload service",
	    { IPSECCTL, "-f", IPSECCONF_TEMP, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_dvmrp_test[] = { DVMRPD, "-nf", DVMRPCONF_TEMP, '\0' };
struct ctl ctl_dvmrp[] = {
	{ "enable",     "enable service",
	    { DVMRPD, "-f", DVMRPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",   
	    { PKILL, "dvmrpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "DVMRP", (char *)ctl_dvmrp_test,  DVMRPCONF_TEMP, NULL },
	    call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

struct ctl ctl_sasync[] = {
	{ "enable",     "enable service",
	    { SASYNCD, "-c", SASYNCCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "sasyncd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "sasync", NULL, SASYNCCONF_TEMP, NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_dhcp_test[] = { DHCPD, "-nc", DHCPCONF_TEMP, '\0' };
struct ctl ctl_dhcp[] = {
	{ "enable",     "enable service",
	    { DHCPD, "-c", DHCPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "dhcpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "DHCP", (char *)ctl_dhcp_test, DHCPCONF_TEMP, NULL },
	    call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_snmp_test[] = { SNMPD, "-nf", SNMPCONF_TEMP, '\0' };
struct ctl ctl_snmp[] = {
	{ "enable",     "enable service",
	    { SNMPD, "-f", SNMPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "snmpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "SNMP", (char *)ctl_snmp_test, SNMPCONF_TEMP, NULL }, call_editor,
	    NULL },
	{ "trap",	"send traps",
	    { SNMPCTL, "trap", "send", REQ, OPT, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ntp_test[] = { NTPD, "-nf", NTPCONF_TEMP, '\0' };
struct ctl ctl_ntp[] = {
	{ "enable",     "enable service",
	    { NTPD, "-sf", NTPCONF_TEMP, NULL }, NULL, X_ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "ntpd", NULL }, NULL, X_DISABLE },
	{ "edit",       "edit configuration",
	    { "NTP", (char *)ctl_ntp_test, NTPCONF_TEMP, NULL },
	    call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_relay_test[] = { RELAYD, "-nf", RELAYCONF_TEMP, '\0' };
struct ctl ctl_relay[] = {
	{ "enable",	"enable service",
	    { RELAYD, "-f", RELAYCONF_TEMP, NULL }, NULL, X_ENABLE },
        { "disable",	"disable service",
	    { PKILL, "relayd", NULL }, NULL, X_DISABLE },
        { "edit",	"edit configuration",
	    { "Relay", (char *)ctl_relay_test, RELAYCONF_TEMP, NULL },
	    call_editor, NULL },
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

struct ctl ctl_ftpproxy[] = {
	{ "enable",	"enable service",
	    { FTPPROXY, "-T", "ftp-proxy", NULL }, NULL, X_ENABLE },
	{ "disable",	"disable service",
	    { PKILL, "ftp-proxy", NULL }, NULL, X_DISABLE },
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
	    { "DNS", NULL, RESOLVCONF_TEMP, NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

struct daemons ctl_daemons[] = {
	{ "pf",		ctl_pf,		PFCONF_TEMP,	1 },
	{ "ospf",	ctl_ospf,	OSPFCONF_TEMP,	0 },
	{ "bgp",	ctl_bgp,	BGPCONF_TEMP,	0 },
	{ "rip",	ctl_rip,	RIPCONF_TEMP,	0 },
	{ "relay",	ctl_relay,	RELAYCONF_TEMP,	0 },
	{ "ipsec",	ctl_ipsec,	IPSECCONF_TEMP,	1 },
	{ "dvmrp",	ctl_dvmrp,	DVMRPCONF_TEMP, 0 },
	{ "sasync",	ctl_sasync,	SASYNCCONF_TEMP,0 },
	{ "dhcp",	ctl_dhcp,	DHCPCONF_TEMP,	0 },
	{ "snmp",	ctl_snmp,	SNMPCONF_TEMP,	0 },
	{ "ntp",	ctl_ntp,	NTPCONF_TEMP,	0 },
	{ "ftp-proxy",	ctl_ftpproxy,	FTPPROXY_TEMP,	0 },
	{ "dns",	ctl_dns,	RESOLVCONF_TEMP,0 },
	{ 0, 0, 0, 0 }
};

void
ctl_symlink(char *temp, char **z, char *real)
{
	rmtemp(temp);
	symlink(real,temp);
}

/* flag to other nsh sessions or nsh conf() that actions have been taken */
void
flag_x(char *fname, int *y)
{
	int fd;
	char fenabled[SIZE_CONF_TEMP + sizeof(".enabled") + 1];
	char fother[SIZE_CONF_TEMP + sizeof(".other") + 1];
	char flocal[SIZE_CONF_TEMP + sizeof(".local") +1];

	snprintf(fenabled, sizeof(fenabled), "%s.enabled", fname);
	snprintf(fother, sizeof(fother), "%s.other", fname);
	snprintf(flocal, sizeof(flocal), "%s.local", fname);

	if (y == X_ENABLE) {
		if ((fd = open(fenabled, O_RDWR | O_CREAT, 0600)) == -1)
			return;
		close(fd);
	} else if (y == X_DISABLE) {
		rmtemp(fenabled);
	} else if (y == X_OTHER) {
		rmtemp(flocal);
		if ((fd = open(fother, O_RDWR | O_CREAT, 0600)) == -1)
			return;
		close(fd);
	} else if (y == X_LOCAL) {
		rmtemp(fother);
		if ((fd = open(flocal, O_RDWR | O_CREAT, 0600)) == -1)
			return;
		close(fd);
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
			rule_writeline(daemons->tmpfile, saveline);
			return 0;
		}
	}
	if (argc < 2 || argv[1][0] == '?') {
		gen_help((char **)daemons->table, "", "",
		    sizeof(struct ctl));
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
		flag_x(daemons->tmpfile, x->flag_x);

	return 1;
}

void
call_editor(char *name, char **args, char *tmpfile)
{
	int fd;
	char *editor;

	/* acq lock, call editor, test config with cmd and args, release lock */

	if ((editor = getenv("EDITOR")) == NULL || *editor == '\0')
		editor = DEFAULT_EDITOR;
	if ((fd = acq_lock(tmpfile)) > 0) {
		cmdarg(editor, tmpfile);
		if (args != NULL)
			cmdargs(args[0], args);
		rls_lock(fd);
	} else
		printf ("%% %s configuration is locked for editing\n", name);
}

int
rule_writeline(char *fname, char *writeline)
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
