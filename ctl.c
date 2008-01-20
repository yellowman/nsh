/* $nsh: ctl.c,v 1.5 2008/01/20 06:08:49 chris Exp $ */
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

#define DHCPDB		"/var/db/dhcpd.leases"

#define	PFUSAGE	"%% pf edit\n%% pf reload\n%% pf enable\n%% pf disable\n"
#define BGPUSAGE "%% bgp edit\n%% bgp reload\n%% bgp enable\n%% bgp disable\n"
#define OSPFUSAGE "%% ospf edit\n%% ospf reload\n%% ospf enable\n%% ospf disable\n"
#define RIPUSAGE "%% rip edit\n%% rip reload\n%% rip enable\n%% rip disable\n"
#define DVMRPUSAGE "%% dvmrp edit\n%% dvmrp enable\n%% dvmrp disable\n"
#define RELAYUSAGE "%% relay edit\n%% relay reload\n%% relay enable\n%% relay disable\n"
#define IPSECUSAGE "%% ipsec edit\n%% ipsec reload\n%% ipsec enable\n%% ipsec disable\n"
#define DHCPUSAGE "%% dhcp edit\n%% dhcp enable\n%% dhcp disable\n"
#define SASYNCUSAGE "%% sasync edit\n%% sasync enable\n%% sasync disable\n"
#define SNMPUSAGE "%% snmp edit\%% snmp enable\n%% snmp disable\n"

char *setup (char *, char *, int, char **, char *, char *);
void call_editor(char *, char **, char *, char *);
int rule_writeline(char *, int, char **);
int acq_lock(char *);
void rls_lock(int);

int
pfctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];

	aarg = setup(modhvar, aarg, argc, argv, PFUSAGE, PFCONF_TEMP);
	if (aarg == NULL)
		return(0);

	if (CMP_ARG(aarg, "ed")) {	/* edit */
		char *args[] = { PFCTL, "-nf", PFCONF_TEMP, '\0' };

		call_editor("PF", args, PFCONF_TEMP, PFCTL);
		return(0);
	}
	if (CMP_ARG(aarg, "r")) {	/* reload */
		char *args[] = { PFCTL, "-f", PFCONF_TEMP, '\0' };

		cmdargs(PFCTL, args);
		return(0);
	}
	if (CMP_ARG(aarg, "en")) {	/* enable */
		cmdarg(PFCTL, "-e");
		return(0);
	}
	if (CMP_ARG(aarg, "d")) {	/* disable */
		cmdarg(PFCTL, "-d");
		return(0);
	}
	printf("%% %s: %s\n", INVALID, argv[1]);

	return(0);
}

int
ospfctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];

	aarg = setup(modhvar, aarg, argc, argv, OSPFUSAGE, OSPFCONF_TEMP);
	if (aarg == NULL)
		return(0);

	if (CMP_ARG(aarg, "ed")) {	/* edit */
		char *args[] = { OSPFD, "-nf", OSPFCONF_TEMP, '\0' };

		call_editor("OSPF", args, OSPFCONF_TEMP, OSPFD);
		return(0);
	}
	if (CMP_ARG(aarg, "r")) {	/* reload */
		cmdarg(OSPFCTL, "reload");
		return(0);
	}
	if (CMP_ARG(aarg, "en")) {	/* enable */
		char *args[] = { OSPFD, "-f", OSPFCONF_TEMP, '\0' };

		cmdargs(OSPFD, args);
		return(0);
	}
	if (CMP_ARG(aarg, "d")) {	/* disable */
		cmdarg(PKILL, "ospfd");
		return(0);
	}
	printf("%% %s: %s\n", INVALID, argv[1]);

	return(0);
}

int
bgpctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];

	aarg = setup(modhvar, aarg, argc, argv, BGPUSAGE, BGPCONF_TEMP);
	if (aarg == NULL)
		return(0);

	if (CMP_ARG(aarg, "ed")) {	/* edit */
		char *args[] = { BGPD, "-nf", BGPCONF_TEMP, '\0' };

		call_editor("BGP", args, BGPCONF_TEMP, BGPD);
		return(0);
	}
	if (CMP_ARG(aarg, "r")) {	/* reload */
		cmdarg(BGPCTL, "reload");
		return(0);
	}
	if (CMP_ARG(aarg, "en")) {	/* enable */
		char *args[] = { BGPD, "-f", BGPCONF_TEMP, '\0' };
		
		cmdargs(BGPD, args);
		return(0);
	}
	if (CMP_ARG(aarg, "d")) {	/* disable */
		cmdarg(PKILL, "bgpd");
		return(0);
	}
	printf("%% %s: %s\n", INVALID, argv[1]);

	return(0);
}

int
ripctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];

	aarg = setup(modhvar, aarg, argc, argv, RIPUSAGE, RIPCONF_TEMP);
	if (aarg == NULL)
		return(0);

	if(CMP_ARG(aarg, "ed")) {	/* edit */
		char *args[] = { RIPD, "-nf", RIPCONF_TEMP, '\0' };

		call_editor("RIP", args, RIPCONF_TEMP, RIPD);
		return(0);
	}
	if (CMP_ARG(aarg, "r")) {	/* reload */
		cmdarg(RIPCTL, "reload");
		return(0);
	}
	if (CMP_ARG(aarg, "en")) {	/* enable */
		char *args[] = { RIPD, "-f", RIPCONF_TEMP, '\0' };

		cmdargs(RIPD, args);
		return(0);
	}
	if (CMP_ARG(aarg, "d")) {	/* disable */
		cmdarg(PKILL, "ripd");
		return(0);
	}
	printf("%% %s: %s\n", INVALID, argv[1]);

	return(0);
}

int
relayctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];

	aarg = setup(modhvar, aarg, argc, argv, RELAYUSAGE, RELAYCONF_TEMP);
	if (aarg == NULL)
		return(0);

	if(CMP_ARG(aarg, "ed")) {	/* edit */
		char *args[] = { RELAYD, "-nf", RELAYCONF_TEMP, '\0' };

		call_editor("Relay", args, RELAYCONF_TEMP, RELAYD);
		return(0);
	}
	if (CMP_ARG(aarg, "r")) {	/* reload */
		cmdarg(RELAYCTL, "reload");
		return(0);
	}
	if (CMP_ARG(aarg, "en")) {	/* enable */
		char *args[] = { RELAYD, "-f", RELAYCONF_TEMP, '\0' };

		cmdargs(RELAYD, args);
		return(0);
	}
	if (CMP_ARG(aarg, "d")) {	/* disable */
		cmdarg(PKILL, "relayd");
		return(0);
	}
	printf("%% %s: %s\n", INVALID, argv[1]);

	return(0);
}

int
ipsecctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];

	aarg = setup(modhvar, aarg, argc, argv, IPSECUSAGE, IPSECCONF_TEMP);
	if (aarg == NULL)
		return(0);

	if (CMP_ARG(aarg, "ed")) {	/* edit */
		char *args[] = { IPSECCTL, "-nf", IPSECCONF_TEMP, '\0' };
		call_editor("IPsec", args, IPSECCONF_TEMP, IPSECCTL);
		return(0);
	}
	if (CMP_ARG(aarg, "r")) {	/* reload */
		char *args[] = { IPSECCTL, "-f", IPSECCONF_TEMP, '\0' };

		cmdargs(IPSECCTL, args);
		return(0);
	}
	if (CMP_ARG(aarg, "en")) {	/* enable */
		cmdarg(ISAKMPD, "-Sa");
		return(0);
	}
	if (CMP_ARG(aarg, "d")) {	/* disable */
		cmdarg(PKILL, "isakmpd");
		return(0);
	}
	printf("%% %s: %s\n", INVALID, argv[1]);

	return(0);
}

int
dvmrpctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];

	aarg = setup(modhvar, aarg, argc, argv, DVMRPUSAGE, DVMRPCONF_TEMP);
	if (aarg == NULL)
		return(0);

	if(CMP_ARG(aarg, "ed")) {	/* edit */
		char *args[] = { DVMRPD, "-nf", DVMRPCONF_TEMP, '\0' };

		call_editor("DVMRP", args, DVMRPCONF_TEMP, DVMRPD);
		return(0);
	}
	/* no dvmrpctl reload command available! */
	if (CMP_ARG(aarg, "en")) {	/* enable */
		char *args[] = { DVMRPD, "-f", DVMRPCONF_TEMP, '\0' };

		cmdargs(DVMRPD, args);
		return(0);
	}
	if (CMP_ARG(aarg, "d")) {	/* disable */
		cmdarg(PKILL, "dvmrpd");
		return(0);
	}
	printf("%% %s: %s\n", INVALID, argv[1]);

	return(0);
}

int
sasyncctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];

	aarg = setup(modhvar, aarg, argc, argv, SASYNCUSAGE, SASYNCCONF_TEMP);
	if (aarg == NULL)
		return(0);

	if(CMP_ARG(aarg, "ed")) {       /* edit */
		call_editor("sasync", NULL, SASYNCCONF_TEMP, NULL);
		return(0);
	}
	/* no sasyncd reload command available! */
	if (CMP_ARG(aarg, "en")) {      /* enable */
		char *args[] = { SASYNCD, "-c", SASYNCCONF_TEMP, '\0' };

		cmdargs(SASYNCD, args);
		return(0);
	}
	if (CMP_ARG(aarg, "d")) {       /* disable */
		cmdarg(PKILL, "sasyncd");
		return(0);
	}
	printf("%% %s: %s\n", INVALID, argv[1]);

	return(0);
}

int
dhcpctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];

	aarg = setup(modhvar, aarg, argc, argv, DHCPUSAGE, DHCPCONF_TEMP);
	if (aarg == NULL)
		return(0);

	if(CMP_ARG(aarg, "ed")) {       /* edit */
		char *args[] = { DHCPD, "-nc", DHCPCONF_TEMP, '\0' };

		call_editor("DHCP", args, DHCPCONF_TEMP, DHCPD);
		return(0);
	}
	/* no dhcpd reload command available! */
	if (CMP_ARG(aarg, "en")) {      /* enable */
		int fd;
		char *args[] = { DHCPD, "-c", DHCPCONF_TEMP, '\0' };

		/* XXX not required by -current dhcpd? */
		/* /var/db/dhcpd.leases must exist before dhcpd begins */
		if ((fd = open(DHCPDB, O_RDWR | O_CREAT, 0644)) == -1) {
			printf("%% Cannot enable DHCP (failed to establish"
			    " DHCP lease database: %s)\n", strerror(errno));
			return(0);
		}		
		close(fd);

		cmdargs(DHCPD, args);
		return(0);
	}
	if (CMP_ARG(aarg, "d")) {       /* disable */
		cmdarg(PKILL, "dhcpd");
		return(0);
	}
	printf("%% %s: %s\n", INVALID, argv[1]);

	return(0);
}

int
snmpctl(int argc, char **argv, char *modhvar)
{
	char *aarg = argv[0];

	aarg = setup(modhvar, aarg, argc, argv, SNMPUSAGE, SNMPCONF_TEMP);
	if (aarg == NULL)
		return(0);

	if(CMP_ARG(aarg, "ed")) {	/* edit */
		char *args[] = { SNMPD, "-nc", SNMPCONF_TEMP, '\0' };

		call_editor("SNMP", args, SNMPCONF_TEMP, SNMPD);
		return(0);
	}
	/* no snmpd reload command available! */
	if (CMP_ARG(aarg, "en")) {	/* enable */
		char *args[] = { SNMPD, "-c", SNMPCONF_TEMP, '\0' };

		cmdargs(SNMPD, args);
		return(0);
	}
        if (CMP_ARG(aarg, "d")) {	/* disable */
		cmdarg(PKILL, "snmpd");
		return(0);
	}
	printf("%% %s: %s\n", INVALID, argv[1]);

	return(0);
}

char *
setup(char *modhvar, char *aarg, int argc, char **argv, char *usage,
      char *tmpfile)
{
	if (modhvar) {
		if(CMP_ARG(modhvar, "action"))
			return (aarg);
		else if(CMP_ARG(modhvar, "rules")) {
			rule_writeline(tmpfile, argc, argv);
			return (NULL);
		} else {
			printf("%% Unknown rulefile modifier %s\n", modhvar);
			return (NULL);
		}
	} else {
		if (argc != 2 || (argc == 2 && argv[1][0] == '?')) {
			printf(usage);
			return(NULL);
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
	char lockf[64];

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
