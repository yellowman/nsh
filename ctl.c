/* $nsh: ctl.c,v 1.9 2008/02/04 02:49:46 chris Exp $ */
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

#define ENABLE 0
#define DISABLE 1
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
	int handler_action;
};

char *setup (char *, char *, int, char **, struct ctl *, char *, int);   
void call_editor(char *, char **, char *, char *);
int rule_writeline(char *, int, char **);
int acq_lock(char *);
void rls_lock(int);
void flag_x(char *, int);

#define CTL_ENABLE 0
#define CTL_DISABLE 1
#define CTL_EDIT 2
static struct ctl ctl_edds[] = {
	{ "enable",	"enable service",	CTL_ENABLE },
	{ "disable",	"disable service",	CTL_DISABLE },
	{ "edit",	"edit configuration",	CTL_EDIT },
	{ 0,		0,			0 }
};

#define CTL_RELOAD 3
static struct ctl ctl_eddrs[] = {
	{ "enable",	"enable service",	CTL_ENABLE },
	{ "disable",	"disable service",	CTL_DISABLE },
	{ "edit",	"edit configuration",	CTL_EDIT },
	{ "reload",	"reload configuration",	CTL_RELOAD },
	{ 0,		0,			0 }
};

#define CTL_HOST 4
#define CTL_TABLE 5
#define CTL_REDIRECT 6
#define CTL_MONITOR 7
#define CTL_POLL 8
static struct ctl ctl_relay[] = {
	{ "enable",	"enable service",	CTL_ENABLE },
        { "disable",	"disable service",	CTL_DISABLE },
        { "edit",	"edit configuration",	CTL_EDIT },
        { "reload",	"reload configuration",	CTL_RELOAD },
	{ "host",	"per-host control",	CTL_HOST },
	{ "table",	"per-table control",	CTL_TABLE },
	{ "redirect",	"per-redirect control",	CTL_REDIRECT },
	{ "monitor",	"monitor mode",		CTL_MONITOR },
	{ "poll",	"poll mode",		CTL_POLL },
	{ 0,		0,			0 }
};

int
pfctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];
	char *edit_args[] = { PFCTL, "-nf", PFCONF_TEMP, '\0' };
	char *reload_args[] = { PFCTL, "-f", PFCONF_TEMP, '\0' };
	struct ctl *x;

	aarg = setup(modhvar, aarg, argc, argv, ctl_eddrs, PFCONF_TEMP, 2);
	if (aarg == NULL)
		return(0);

	x = (struct ctl *) genget(aarg, (char **)ctl_eddrs,
	    sizeof(struct ctl));
	if (x == 0) {
		printf("%% Invalid argument %s\n", aarg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", aarg);
		return 0;
	}

	switch (x->handler_action) {
	case CTL_EDIT:
		call_editor("PF", edit_args, PFCONF_TEMP, PFCTL);
		break;
	case CTL_RELOAD:
		cmdargs(PFCTL, reload_args);
		break;
	case CTL_ENABLE:
		cmdarg(PFCTL, "-e");
		flag_x(PFCONF_TEMP, ENABLE);
		break;
	case CTL_DISABLE:
		cmdarg(PFCTL, "-d");
		flag_x(PFCONF_TEMP, DISABLE);
		break;
	}

	return(0);
}

int
ospfctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];
	char *edit_args[] = { OSPFD, "-nf", OSPFCONF_TEMP, '\0' };
	char *enable_args[] = { OSPFD, "-f", OSPFCONF_TEMP, '\0' };
	struct ctl *x;

	aarg = setup(modhvar, aarg, argc, argv, ctl_eddrs, OSPFCONF_TEMP, 2);
	if (aarg == NULL)
		return(0);

	x = (struct ctl *) genget(aarg, (char **)ctl_eddrs,
	    sizeof(struct ctl));
	if (x == 0) {
		printf("%% Invalid argument %s\n", aarg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", aarg);
		return 0;
	}

	switch (x->handler_action) {
	case CTL_EDIT:
		call_editor("OSPF", edit_args, OSPFCONF_TEMP, OSPFD);
		break;
	case CTL_RELOAD:
		cmdarg(OSPFCTL, "reload");
		break;
	case CTL_ENABLE:
		cmdargs(OSPFD, enable_args);
		flag_x(OSPFCONF_TEMP, ENABLE);
		break;
	case CTL_DISABLE:
		cmdarg(PKILL, "ospfd");
		flag_x(OSPFCONF_TEMP, DISABLE);
		break;
	}

	return(0);
}

int
bgpctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];
	char *edit_args[] = { BGPD, "-nf", BGPCONF_TEMP, '\0' };
	char *enable_args[] = { BGPD, "-f", BGPCONF_TEMP, '\0' };
	struct ctl *x;

	aarg = setup(modhvar, aarg, argc, argv, ctl_eddrs, BGPCONF_TEMP, 2);
	if (aarg == NULL)
		return(0);

	x = (struct ctl *) genget(aarg, (char **)ctl_eddrs,
	    sizeof(struct ctl));
	if (x == 0) {
		printf("%% Invalid argument %s\n", aarg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", aarg);
		return 0;
	}

	switch (x->handler_action) {
	case CTL_EDIT:
		call_editor("BGP", edit_args, BGPCONF_TEMP, BGPD);
		break;
	case CTL_RELOAD:
		cmdarg(BGPCTL, "reload");
		break;
	case CTL_ENABLE:
		cmdargs(BGPD, enable_args);
		flag_x(BGPCONF_TEMP, ENABLE);
		break;
	case CTL_DISABLE:
		cmdarg(PKILL, "bgpd");
		flag_x(BGPCONF_TEMP, DISABLE);
		break;
	}

	return(0);
}

int
ripctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];
	char *edit_args[] = { RIPD, "-nf", RIPCONF_TEMP, '\0' };
	char *enable_args[] = { RIPD, "-f", RIPCONF_TEMP, '\0' };
	struct ctl *x;

	aarg = setup(modhvar, aarg, argc, argv, ctl_eddrs, RIPCONF_TEMP, 2);
	if (aarg == NULL)
		return(0);

	x = (struct ctl *) genget(aarg, (char **)ctl_eddrs,
	    sizeof(struct ctl));
	if (x == 0) { 
		printf("%% Invalid argument %s\n", aarg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", aarg);
		return 0;
	}

	switch (x->handler_action) {
	case CTL_EDIT:
		call_editor("RIP", edit_args, RIPCONF_TEMP, RIPD);
		break;
	case CTL_RELOAD:
		cmdarg(RIPCTL, "reload");
		break;
	case CTL_ENABLE:
		cmdargs(RIPD, enable_args);
		flag_x(RIPCONF_TEMP, ENABLE);
		break;
	case CTL_DISABLE:
		cmdarg(PKILL, "ripd");
		flag_x(RIPCONF_TEMP, DISABLE);
		break;
	}

	return(0);
}

int
relayctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];
	char *relayctl_args[] = { RELAYCTL, NULL, NULL, NULL, '\0' };
	char *edit_args[] = { RELAYD, "-nf", RELAYCONF_TEMP, '\0' };
	char *enable_args[] = { RELAYD, "-f", RELAYCONF_TEMP, '\0' };
	struct ctl *x;

	aarg = setup(modhvar, aarg, argc, argv, ctl_relay, RELAYCONF_TEMP, 4);
	if (aarg == NULL)
		return(0);

	x = (struct ctl *) genget(aarg, (char **)ctl_relay,
	    sizeof(struct ctl));
	if (x == 0) { 
		printf("%% Invalid argument %s\n", aarg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", aarg);
		return 0;
	}

	switch(x->handler_action) {
	case CTL_HOST:
	case CTL_TABLE:
	case CTL_REDIRECT:
		if (argc != 4) {
			printf("%% relay %s enable|disable <name|id>\n",
			    x->name);
			return 0;
		}
		relayctl_args[1] = x->name;
		relayctl_args[3] = argv[3];
		if (isprefix(argv[2], "disable"))
			relayctl_args[2] = "disable";
		if (isprefix(argv[2], "enable"))
			relayctl_args[2] = "enable";
		if (relayctl_args[1] != NULL && relayctl_args[2] != NULL) {
			cmdargs(RELAYCTL, relayctl_args);
			return(0);
		} else
			printf("%% relay %s enable|disable <name|id>\n",
			    x->name);
		break;
	case CTL_MONITOR:
		cmdarg(RELAYCTL, "monitor");
		break;
	case CTL_POLL:
		cmdarg(RELAYCTL, "poll");
		break;
	case CTL_EDIT:
		call_editor("Relay", edit_args, RELAYCONF_TEMP, RELAYD);
		break;
	case CTL_RELOAD:
		cmdarg(RELAYCTL, "reload");
		break;
	case CTL_ENABLE:
		cmdargs(RELAYD, enable_args);
		flag_x(RELAYCONF_TEMP, ENABLE);
		break;
	case CTL_DISABLE:
		cmdarg(PKILL, "relayd");
		flag_x(RELAYCONF_TEMP, DISABLE);
		break;
	}

	return(0);
}

int
ipsecctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];
	char *edit_args[] = { IPSECCTL, "-nf", IPSECCONF_TEMP, '\0' };
	char *reload_args[] = { IPSECCTL, "-f", IPSECCONF_TEMP, '\0' };
	struct ctl *x;

	aarg = setup(modhvar, aarg, argc, argv, ctl_eddrs, IPSECCONF_TEMP, 2);
	if (aarg == NULL)
		return(0);

	x = (struct ctl *) genget(aarg, (char **)ctl_eddrs,
	    sizeof(struct ctl));
	if (x == 0) { 
		printf("%% Invalid argument %s\n", aarg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", aarg);
		return 0;
	}

	switch (x->handler_action) {
	case CTL_EDIT:
		call_editor("IPsec", edit_args, IPSECCONF_TEMP, IPSECCTL);
		break;
	case CTL_RELOAD:
		cmdargs(IPSECCTL, reload_args);
		break;
	case CTL_ENABLE:
		cmdarg(ISAKMPD, "-Sa");
		flag_x(IPSECCONF_TEMP, ENABLE);
		break;
	case CTL_DISABLE:
		cmdarg(PKILL, "isakmpd");
		flag_x(IPSECCONF_TEMP, DISABLE);
		break;
	}

	return(0);
}

int
dvmrpctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];
	char *edit_args[] = { DVMRPD, "-nf", DVMRPCONF_TEMP, '\0' };
	char *enable_args[] = { DVMRPD, "-f", DVMRPCONF_TEMP, '\0' };
	struct ctl *x;

	aarg = setup(modhvar, aarg, argc, argv, ctl_edds, DVMRPCONF_TEMP, 2);
	if (aarg == NULL)
		return(0);

	x = (struct ctl *) genget(aarg, (char **)ctl_edds,
	    sizeof(struct ctl));
	if (x == 0) { 
		printf("%% Invalid argument %s\n", aarg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", aarg);
		return 0;
	}

	switch (x->handler_action) {
	case CTL_EDIT:
		call_editor("DVMRP", edit_args, DVMRPCONF_TEMP, DVMRPD);
		break;
	case CTL_ENABLE:
		cmdargs(DVMRPD, enable_args);
		flag_x(DVMRPCONF_TEMP, ENABLE);
		break;
	case CTL_DISABLE:
		cmdarg(PKILL, "dvmrpd");
		flag_x(DVMRPCONF_TEMP, DISABLE);
		break;
	}

	return(0);
}

int
sasyncctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];
	char *enable_args[] = { SASYNCD, "-c", SASYNCCONF_TEMP, '\0' };
	struct ctl *x;

	aarg = setup(modhvar, aarg, argc, argv, ctl_edds, SASYNCCONF_TEMP, 2);
	if (aarg == NULL)
		return(0);

	x = (struct ctl *) genget(aarg, (char **)ctl_edds,
	    sizeof(struct ctl));
	if (x == 0) { 
		printf("%% Invalid argument %s\n", aarg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", aarg);
		return 0;
	}

	switch (x->handler_action) {
	case CTL_EDIT:
		call_editor("sasync", NULL, SASYNCCONF_TEMP, NULL);
		break;
	case CTL_ENABLE:
		cmdargs(SASYNCD, enable_args);
		flag_x(SASYNCCONF_TEMP, ENABLE);
		break;
	case CTL_DISABLE:
		cmdarg(PKILL, "sasyncd");
		flag_x(SASYNCCONF_TEMP, DISABLE);
		break;
	}

	return(0);
}

int
dhcpctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];
	char *edit_args[] = { DHCPD, "-nc", DHCPCONF_TEMP, '\0' };
	char *enable_args[] = { DHCPD, "-c", DHCPCONF_TEMP, '\0' };
	struct ctl *x;

	aarg = setup(modhvar, aarg, argc, argv, ctl_edds, DHCPCONF_TEMP, 2);
	if (aarg == NULL)
		return(0);

	x = (struct ctl *) genget(aarg, (char **)ctl_edds,
	    sizeof(struct ctl));
	if (x == 0) { 
		printf("%% Invalid argument %s\n", aarg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", aarg);
		return 0;
	}

	switch (x->handler_action) {
	case CTL_EDIT:
		call_editor("DHCP", edit_args, DHCPCONF_TEMP, DHCPD);
		break;
	case CTL_ENABLE:
#if 0
		/* XXX not required by -current dhcpd? */
		/* /var/db/dhcpd.leases must exist before dhcpd begins */
		if ((fd = open(DHCPDB, O_RDWR | O_CREAT, 0644)) == -1) {
			printf("%% Cannot enable DHCP (failed to establish"
			    " DHCP lease database: %s)\n", strerror(errno));
			return(0);
		}		
		close(fd);
#endif
		cmdargs(DHCPD, enable_args);
		flag_x(DHCPCONF_TEMP, ENABLE);
		break;
	case CTL_DISABLE:
		cmdarg(PKILL, "dhcpd");
		flag_x(DHCPCONF_TEMP, DISABLE);
		break;
	}

	return(0);
}

int
snmpctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];
	char *edit_args[] = { SNMPD, "-nf", SNMPCONF_TEMP, '\0' };
	char *enable_args[] = { SNMPD, "-f", SNMPCONF_TEMP, '\0' };
	struct ctl *x;

	aarg = setup(modhvar, aarg, argc, argv, ctl_edds, SNMPCONF_TEMP, 2);
	if (aarg == NULL)
		return(0);

	x = (struct ctl *) genget(aarg, (char **)ctl_edds,
	    sizeof(struct ctl));
	if (x == 0) { 
		printf("%% Invalid argument %s\n", aarg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", aarg);
		return 0;
	}

	switch (x->handler_action) {
	case CTL_EDIT:
		call_editor("SNMP", edit_args, SNMPCONF_TEMP, SNMPD);
		break;
	case CTL_ENABLE:
		cmdargs(SNMPD, enable_args);
		flag_x(SNMPCONF_TEMP, ENABLE);
		break;
	case CTL_DISABLE:
		cmdarg(PKILL, "snmpd");
		flag_x(SNMPCONF_TEMP, DISABLE);
		break;
	}

	return(0);
}

int
ntpctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];
	char *edit_args[] = { NTPD, "-nf", NTPCONF_TEMP, '\0' };
	char *enable_args[] = { NTPD, "-sf", NTPCONF_TEMP, '\0' };
	struct ctl *x;
         
	aarg = setup(modhvar, aarg, argc, argv, ctl_edds, NTPCONF_TEMP, 2);
	if (aarg == NULL)
		return(0);

	x = (struct ctl *) genget(aarg, (char **)ctl_edds,
	    sizeof(struct ctl));
	if (x == 0) { 
		printf("%% Invalid argument %s\n", aarg);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% Ambiguous argument %s\n", aarg);
		return 0;
	}

	switch (x->handler_action) {
	case CTL_EDIT:
		call_editor("NTP", edit_args, NTPCONF_TEMP, NTPD);
		break;
	case CTL_ENABLE:
		cmdargs(NTPD, enable_args);
		flag_x(NTPCONF_TEMP, ENABLE);
		break;
	case CTL_DISABLE:
		cmdarg(PKILL, "ntpd");
		flag_x(NTPCONF_TEMP, DISABLE);
		break;
	}
         
	return(0);
}

void
flag_x(char *fname, int y)
{
	int fd;
	char fenabled[SIZE_CONF_TEMP + sizeof(".enabled") + 1];

	snprintf(fenabled, sizeof(fenabled), "%s.enabled", fname);

	switch(y) {
	case ENABLE:
		if ((fd = open(fenabled, O_RDWR | O_CREAT, 0600)) == -1)
			return;
		close(fd);
		break;
	case DISABLE:
		rmtemp(fenabled);
		break;
	}
		
}

char *
setup(char *modhvar, char *aarg, int argc, char **argv, struct ctl *x,
      char *tmpfile, int maxarg)
{
	if (modhvar) {
		if (isprefix(modhvar, "action"))
			return (aarg);
		else if (isprefix(modhvar, "rules")) {
			rule_writeline(tmpfile, argc, argv);
			return (NULL);
		} else {
			printf("%% Unknown rulefile modifier %s\n", modhvar);
			return (NULL);
		}
	} else {
		if (argc < 2 || argc > maxarg || (argc == 2 &&
		    argv[1][0] == '?')) {
			gen_help(x, argv[0], "", sizeof(struct ctl));
			return (NULL);
		}
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGQUIT, SIG_IGN);

		return(argv[1]);
	}
}

void
call_editor(char *name, char **args, char *tmpfile, char *cmd)
{
	int fd;
	char *editor;

	/* acq lock, call editor, test config with cmd and args, release lock */

	if ((editor = getenv("EDITOR")) == NULL || *editor == '\0')
		editor = DEFAULT_EDITOR;
	if ((fd = acq_lock(tmpfile)) > 0) {
		cmdarg(editor, tmpfile);
		if (cmd != NULL)
			cmdargs(cmd, args);
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
