/* $nsh: ctl.c,v 1.11 2008/02/06 16:51:44 chris Exp $ */
/*
 * Copyright (c) 2008
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/signal.h>
#include "externs.h"

#define ENABLE	(void *)1 
#define DISABLE	(void *)2
#define OPT	(void *)1
#define REQ	(void *)2
#define INVALID "Invalid or ambiguous argument"

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

struct ctl {
	char *name;
	char *help;
	char *args[32];
	void (*handler)(char *, char **, char *);
	int *flag_x;
};

char *setup (char *, char *, int, char **, struct ctl *, char *, int);   
void call_editor(char *, char **, char *);
int rule_writeline(char *, int, char **);
int acq_lock(char *);
void rls_lock(int);
void flag_x(char *, int *);

char *ctl_pf_test[] = { PFCTL, "-nf", PFCONF_TEMP, '\0' };
static struct ctl ctl_pf[] = {
	{ "enable",	"enable service",
	    { PFCTL, "-e", NULL }, NULL, ENABLE },
	{ "disable",	"disable service",
	    { PFCTL, "-d", NULL }, NULL, DISABLE },
	{ "edit",	"edit configuration",
	    { "PF", (char *)ctl_pf_test, PFCONF_TEMP, NULL }, call_editor,
	    NULL },
	{ "reload",	"reload service",
	    { PFCTL, "-f", PFCONF_TEMP, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ospf_test[] = { OSPFD, "-nf", OSPFCONF_TEMP, '\0' };
static struct ctl ctl_ospf[] = {
	{ "enable",     "enable service",
	    { OSPFD, "-f", OSPFCONF_TEMP, NULL }, NULL, ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "ospfd", NULL }, NULL, DISABLE },
	{ "edit",       "edit configuration",
	    { "OSPF", (char *)ctl_ospf_test, OSPFCONF_TEMP, NULL },
	    call_editor, NULL },
	{ "reload",     "reload service",
	    { OSPFCTL, "reload", NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_bgp_test[] = { BGPD, "-nf", BGPCONF_TEMP, NULL, '\0' };
static struct ctl ctl_bgp[] = {
	{ "enable",     "enable service",
	    { BGPD, "-f", BGPCONF_TEMP, NULL }, NULL, ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "bgpd", NULL }, NULL, DISABLE },
	{ "edit",       "edit configuration",
	    { "BGP", (char *)ctl_bgp_test, BGPCONF_TEMP, NULL }, call_editor,
	    NULL },
	{ "reload",     "reload service",
	    { BGPCTL, "reload", NULL }, NULL, NULL },
        { 0, 0, { 0 }, 0, 0 }
};

char *ctl_rip_test[] = { RIPD, "-nf", RIPCONF_TEMP, '\0' };
static struct ctl ctl_rip[] = {
	{ "enable",     "enable service",
	    { RIPD, "-f", RIPCONF_TEMP, NULL }, NULL, ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "ripd", NULL }, NULL, DISABLE },
	{ "edit",       "edit configuration",
	    { "RIP", (char *)ctl_rip_test, RIPCONF_TEMP, NULL }, call_editor,
	    NULL },
	{ "reload",     "reload service",
	    { RIPCTL, "reload", NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ipsec_test[] = { IPSECCTL, "-nf", IPSECCONF_TEMP, '\0' };
static struct ctl ctl_ipsec[] = {
	{ "enable",     "enable service",
	    { ISAKMPD, "-Sa", NULL }, NULL, ENABLE },
	{ "disable",    "disable service",                   
	    { PKILL, "isakmpd", NULL }, NULL, DISABLE },
	{ "edit",       "edit configuration",   
	    { "IPsec", (char *)ctl_ipsec_test, IPSECCONF_TEMP, NULL },
	    call_editor, NULL },
	{ "reload",     "reload service",
	    { IPSECCTL, "-f", IPSECCONF_TEMP, NULL }, NULL, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_dvmrp_test[] = { DVMRPD, "-nf", DVMRPCONF_TEMP, '\0' };
static struct ctl ctl_dvmrp[] = {
	{ "enable",     "enable service",
	    { DVMRPD, "-f", DVMRPCONF_TEMP, NULL }, NULL, ENABLE },
	{ "disable",    "disable service",   
	    { PKILL, "dvmrpd", NULL }, NULL, DISABLE },
	{ "edit",       "edit configuration",
	    { "DVMRP", (char *)ctl_dvmrp_test,  DVMRPCONF_TEMP, NULL },
	    call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

static struct ctl ctl_sasync[] = {
	{ "enable",     "enable service",
	    { SASYNCD, "-c", SASYNCCONF_TEMP, NULL }, NULL, ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "sasyncd", NULL }, NULL, DISABLE },
	{ "edit",       "edit configuration",
	    { "sasync", NULL, SASYNCCONF_TEMP, NULL }, call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_dhcp_test[] = { DHCPD, "-nc", DHCPCONF_TEMP, '\0' };
static struct ctl ctl_dhcp[] = {
	{ "enable",     "enable service",
	    { DHCPD, "-c", DHCPCONF_TEMP, NULL }, NULL, ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "dhcpd", NULL }, NULL, DISABLE },
	{ "edit",       "edit configuration",
	    { "DHCP", (char *)ctl_dhcp_test, DHCPCONF_TEMP, NULL },
	    call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_snmp_test[] = { SNMPD, "-nf", SNMPCONF_TEMP, '\0' };
static struct ctl ctl_snmp[] = {
	{ "enable",     "enable service",
	    { SNMPD, "-f", SNMPCONF_TEMP, NULL }, NULL, ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "snmpd", NULL }, NULL, DISABLE },
	{ "edit",       "edit configuration",
	    { "SNMP", (char *)ctl_snmp_test, SNMPCONF_TEMP, NULL },
	    call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_ntp_test[] = { NTPD, "-nf", NTPCONF_TEMP, '\0' };
static struct ctl ctl_ntp[] = {
	{ "enable",     "enable service",
	    { NTPD, "-sf", NTPCONF_TEMP, NULL }, NULL, ENABLE },
	{ "disable",    "disable service",
	    { PKILL, "ntpd", NULL }, NULL, DISABLE },
	{ "edit",       "edit configuration",
	    { "NTP", (char *)ctl_ntp_test, NTPCONF_TEMP, NULL },
	    call_editor, NULL },
	{ 0, 0, { 0 }, 0, 0 }
};

char *ctl_relay_test[] = { RELAYD, "-nf", RELAYCONF_TEMP, '\0' };
static struct ctl ctl_relay[] = {
	{ "enable",	"enable service",
	    { RELAYD, "-f", RELAYCONF_TEMP, NULL }, NULL, ENABLE },
        { "disable",	"disable service",
	    { PKILL, "relayd", NULL }, NULL, DISABLE },
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

static struct daemons {
	char *name;
	struct ctl *table;
	char *tmpfile;
} ctl_daemons[] = {
	{ "pf",		ctl_pf,		PFCONF_TEMP },
	{ "ospf",	ctl_ospf,	OSPFCONF_TEMP },
	{ "bgp",	ctl_bgp,	BGPCONF_TEMP },
	{ "rip",	ctl_rip,	RIPCONF_TEMP },
	{ "relay",	ctl_relay,	RELAYCONF_TEMP },
	{ "ipsec",	ctl_ipsec, 	IPSECCONF_TEMP },
	{ "dvmrp",	ctl_dvmrp,	DVMRPCONF_TEMP },
	{ "sasync",	ctl_sasync,	SASYNCCONF_TEMP },
	{ "dhcp",	ctl_dhcp,	DHCPCONF_TEMP },
	{ "snmp",	ctl_snmp,	SNMPCONF_TEMP },
	{ "ntp",	ctl_ntp,	NTPCONF_TEMP },
	{ 0, 0, 0 }
};

void
flag_x(char *fname, int *y)
{
	int fd;
	char fenabled[SIZE_CONF_TEMP + sizeof(".enabled") + 1];

	snprintf(fenabled, sizeof(fenabled), "%s.enabled", fname);

	if (y == ENABLE) {
		if ((fd = open(fenabled, O_RDWR | O_CREAT, 0600)) == -1)
			return;
		close(fd);
	} else if (y == DISABLE) {
		rmtemp(fenabled);
	}
		
}

int
ctlhandler(int argc, char **argv, char *modhvar)
{
	struct daemons *daemons;
	struct ctl *x;
#define NARGS 7
	char *args[NARGS] = { NULL, NULL, NULL, NULL, NULL, NULL, '\0' };
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
                if (isprefix(modhvar, "action")) {
                        /* float on down the river */
                } else if (isprefix(modhvar, "rules")) {
                        rule_writeline(daemons->tmpfile, argc, argv);
                        return 0;
                } else {
                        printf("%% Unknown rulefile modifier %s\n", modhvar);
                        return 0;
                }
        } else {
		if (argc < 2 || argv[1][0] == '?') {
			gen_help((char **)daemons->table, "", "control",
			    sizeof(struct ctl));
			return 0;
		}
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
		if (args[0] != NULL)
			cmdargs(args[0], args);
		rls_lock(fd);
	} else
		printf ("%% %s configuration is locked for editing\n", name);
}

int
rule_writeline(char *fname, int argc, char **argv)
{
	int z;
	FILE *rulefile;

	rulefile = fopen(fname, "a");
	if (rulefile == NULL) {
		printf("%% Rule write failed: %s\n", strerror(errno));
		return(1);
	}
	for (z = 0; z < argc; z++)
		fprintf(rulefile, "%s%s", z ? " " : "", argv[z]);
	fprintf(rulefile, "\n");
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
			printf("%% Unable to remove temporary file for "
			    "reinitialization %s: %s\n", file, strerror(errno));
}
