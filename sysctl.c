/* $nsh: sysctl.c,v 1.5 2003/04/23 18:58:42 chris Exp $ */
/*
 * Copyright (c) 2003
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
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_ether.h>
#include <netinet/ip_ipip.h>
#include <netinet/ip_gre.h>
#include <netinet/ip_ipcomp.h>
#include <netinet/ip_esp.h>
#include <netinet/ip_ah.h>
#include "externs.h"

/*
 * sysctl_inet: get or set an int value from PF_INET tree
 *
 * val - value to set in sysctl
 * read - are we just reading the value (1), or setting it? (0)
 */

int
sysctl_inet(int mib2, int mib3, int val, int read)
{
	int mib[4], old, len;
	int *valp;

	if (read)
		valp = NULL;
	else
		valp = &val;

	mib[0] = CTL_NET;
	mib[1] = PF_INET;
	mib[2] = mib2;
	mib[3] = mib3;

	len = sizeof(old);

	if (sysctl(mib, 4, &old, &len, valp, sizeof(int)) == -1) {
		if (read && errno != ENOPROTOOPT)
			printf("%% sysctl_inet: sysctl: %s\n", strerror(errno));
		return(-1);
	}

	return(old);
}

int
ipsysctl(int set, char *cmd, char *arg)
{
	int mib2, mib3;
	int32_t larg;
	char *endptr;   

	if (arg) {
		larg = strtol(arg, &endptr, 0);
		if (arg[0] == '\0' || endptr[0] != '\0' ||
		    (errno == ERANGE && larg == LONG_MAX) || larg > INT_MAX) {
			printf("%% Invalid argument: %s\n", arg);
			return(0);
		}
	} else if (set)
		larg = 1;
	else
		larg = 0;

	if (CMP_ARG(cmd, "f")) { /* forwarding */
		mib2 = IPPROTO_IP;
		mib3 = IPCTL_FORWARDING;
	} else if (CMP_ARG(cmd, "ipi")) { /* ipip */
		mib2 = IPPROTO_IPIP;
		mib3 = IPIPCTL_ALLOW;
	} else if (CMP_ARG(cmd, "g")) { /* gre */
		mib2 = IPPROTO_GRE;
		mib3 = GRECTL_ALLOW;
	} else if (CMP_ARG(cmd, "w")) { /* wccp */
		mib2 = IPPROTO_GRE;
		mib3 = GRECTL_WCCP;
	} else if (CMP_ARG(cmd, "mo")) { /* mobileip */
		mib2 = IPPROTO_MOBILE;
		mib3 = MOBILEIPCTL_ALLOW;
	} else if (CMP_ARG(cmd, "et")) { /* etherip */
		mib2 = IPPROTO_ETHERIP;
		mib3 = ETHERIPCTL_ALLOW;
	} else if (CMP_ARG(cmd, "ipc")) { /* ipcomp */
		mib2 = IPPROTO_IPCOMP;
		mib3 = IPCOMPCTL_ENABLE;
	} else if (CMP_ARG(cmd, "es")) { /* esp */
		mib2 = IPPROTO_ESP;
		mib3 = ESPCTL_ENABLE;
	} else if (CMP_ARG(cmd, "a")) { /* ah */
		mib2 = IPPROTO_AH;
		mib3 = AHCTL_ENABLE;
	} else if (CMP_ARG(cmd, "so")) { /* sourceroute */
		mib2 = IPPROTO_IP;
		mib3 = IPCTL_SOURCEROUTE;
	} else if (CMP_ARG(cmd, "en")) { /* encdebug */
		mib2 = IPPROTO_IP;
		mib3 = IPCTL_ENCDEBUG;
	} else if (CMP_ARG(cmd, "ma")) { /* maxqueue */
		mib2 = IPPROTO_IP;
		mib3 = IPCTL_IPPORT_MAXQUEUE;
		if (!set)
			larg = DEFAULT_MAXQUEUE;
	} else if (CMP_ARG(cmd, "se")) { /* send-redirects */
		mib2 = IPPROTO_IP;
		mib3 = IPCTL_SENDREDIRECTS;
	} else if (CMP_ARG(cmd, "di")) { /* directed-broadcast */
		mib2 = IPPROTO_IP;
		mib3 = IPCTL_DIRECTEDBCAST;
#ifdef notyet
	} else if (CMP_ARG(cmd, "default-m")) { /* default-mtu */
		mib2 = IPPROTO_IP;
		mib3 = IPCTL_DEFMTU;
		if (!set)
			larg = DEFAULT_MTU;
#endif
	} else if (CMP_ARG(cmd, "de")) { /* default-ttl */
		mib2 = IPPROTO_IP;
		mib3 = IPCTL_DEFTTL;
		if (!set)
			larg = DEFAULT_TTL;
	} else {
		printf("%% Internal error\n");
		return(0);
	}

	sysctl_inet(mib2, mib3, larg, 0);

	return(1);
}

void
conf_ipsysctl(FILE *output)
{
	int tmp;

	/*
	 * Some people use kernels with option IPFORWARDING/option
	 * GATEWAY, and others don't, so let's have this set in the
	 * config either way!!  The general rule in conf.c is to only display
	 * a configuration entry if it is not a system default, but in this
	 * case, we don't know the default, since the kernel could be
	 * compiled either way.
	 */
	if ((tmp = sysctl_inet(IPPROTO_IP, IPCTL_FORWARDING, 0, 1)) == 1)
		fprintf(output, "ip forwarding\n");
	else if (tmp == 0)
		fprintf(output, "no ip forwarding\n");
	if (sysctl_inet(IPPROTO_IPIP, IPIPCTL_ALLOW, 0, 1) == 1)
		fprintf(output, "ip ipip\n");
	if (sysctl_inet(IPPROTO_GRE, GRECTL_ALLOW, 0, 1) == 1)
		fprintf(output, "ip gre\n");
	if (sysctl_inet(IPPROTO_GRE, GRECTL_WCCP, 0, 1) == 1)
		fprintf(output, "ip wccp\n");
	if (sysctl_inet(IPPROTO_MOBILE, MOBILEIPCTL_ALLOW, 0, 1) == 1)
		fprintf(output, "ip mobileip\n");
	if (sysctl_inet(IPPROTO_ETHERIP, ETHERIPCTL_ALLOW, 0, 1) == 1)
		fprintf(output, "ip etherip\n");
	if (sysctl_inet(IPPROTO_IPCOMP, IPCOMPCTL_ENABLE, 0, 1) == 1)
		fprintf(output, "ip ipcomp\n");
	if (sysctl_inet(IPPROTO_ESP, ESPCTL_ENABLE, 0, 1) == 0)
		fprintf(output, "no ip esp\n");
	if (sysctl_inet(IPPROTO_AH, AHCTL_ENABLE, 0, 1) == 0)
		fprintf(output, "no ip ah\n");
	if (sysctl_inet(IPPROTO_IP, IPCTL_SOURCEROUTE, 0, 1) == 1)
		fprintf(output, "ip sourceroute\n");
	/*
	 * Your kernel must have option ENCDEBUG for this to do anything
	 */
	if (sysctl_inet(IPPROTO_IP, IPCTL_ENCDEBUG, 0, 1) == 1)
		fprintf(output, "ip encdebug\n");
	if ((tmp = sysctl_inet(IPPROTO_IP, IPCTL_IPPORT_MAXQUEUE, 0, 1)) !=
	    DEFAULT_MAXQUEUE && tmp != -1)
		fprintf(output, "ip maxqueue %i\n", tmp);
	if (sysctl_inet(IPPROTO_IP, IPCTL_SENDREDIRECTS, 0, 1) == 0)
		fprintf(output, "no ip send-redirects\n");
	if (sysctl_inet(IPPROTO_IP, IPCTL_DIRECTEDBCAST, 0, 1) == 1)
		fprintf(output, "ip directed-broadcast\n");
#ifdef notyet
	if ((tmp = sysctl_inet(IPPROTO_IP, IPCTL_DEFMTU, 0, 1)) !=
	    DEFAULT_MTU && tmp != -1)
		fprintf(output, "ip default-mtu %i\n", tmp);
#endif
	if ((tmp = sysctl_inet(IPPROTO_IP, IPCTL_DEFTTL, 0, 1)) !=
	    DEFAULT_TTL && tmp != -1)
		fprintf(output, "ip default-ttl %i\n", tmp);
}
