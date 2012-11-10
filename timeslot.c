/* From: $OpenBSD: ifconfig.c,v 1.192 2007/11/27 16:21:02 chl Exp $	*/

/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "externs.h"

unsigned long get_ts_map(int, int, int);

/*
 * Note: 
 * bits:       0   1   2   3   4   5   ....   24   25   ...   30   31
 * T1 mode:   N/A ch1 ch2 ch3 ch4 ch5        ch24  N/A        N/A  N/A
 * E1 mode:   ts0 ts1 ts2 ts3 ts4 ts5        ts24  ts25       ts30 ts31
 */
/* ARGSUSED */
int
inttimeslot(char *ifname, int ifs, int argc, char **argv)
{
#define SINGLE_CHANNEL	0x1
#define RANGE_CHANNEL	0x2
#define ALL_CHANNELS	0xFFFFFFFF
	unsigned long	ts_map = 0;
	struct ifreq	ifr;
	char	*ptr, *val;
	int		ts_flag = 0, set;
	int		ts = 0, ts_start = 0;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	ptr = val = argv[0];

	if ((!set && argc != 1) || (set && argc != 2)) {	
		printf("%% timeslots <x-y>\n");
		printf("%% timeslots all\n");
		printf("%% no timeslots\n");
		return 0;
	}

	if (set == 0) {
		ts_map = ALL_CHANNELS;
	} else if (strcmp(val,"all") == 0) {
		ts_map = ALL_CHANNELS;
	} else {
		while (*ptr != '\0') {
			if (isdigit(*ptr)) {
				ts = strtoul(ptr, &ptr, 10);
				ts_flag |= SINGLE_CHANNEL;
			} else {
				if (*ptr == '-') {
					ts_flag |= RANGE_CHANNEL;
					ts_start = ts;
				} else {
					ts_map |= get_ts_map(ts_flag,
					    ts_start, ts);
					ts_flag = 0;
				}
				ptr++;
			}
		}
		if (ts_flag)
			ts_map |= get_ts_map(ts_flag, ts_start, ts);

	}
	(void) strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&ts_map;

	if (ioctl(ifs, SIOCSIFTIMESLOT, (caddr_t)&ifr) < 0) {
		if (errno == ENOTTY)
			printf("%% timeslot not applicable to %s\n", ifname);
		else
			printf("%% inttimeslot: SIOCSIFTIMESLOT: %s\n",
			    strerror(errno));
	}
	return 0;
}

unsigned long
get_ts_map(int ts_flag, int ts_start, int ts_stop)
{
	int		i = 0;
	unsigned long	map = 0, mask = 0;

	if ((ts_flag & (SINGLE_CHANNEL | RANGE_CHANNEL)) == 0)
		return 0;
	if (ts_flag & RANGE_CHANNEL) { /* Range of channels */
		for (i = ts_start; i <= ts_stop; i++) {
			mask = 1 << i;
			map |=mask;
		}
	} else { /* Single channel */
		mask = 1 << ts_stop;
		map |= mask;
	}
	return map;
}

int
timeslot_status(int ifs, char *ifname, char *str, int str_len)
{
	char		*sep = " ";
	unsigned long	 ts_map = 0;
	u_int		 i;
	int		 start = -1;
	struct ifreq	 ifr;

	ifr.ifr_data = (caddr_t)&ts_map;

	if (ioctl(ifs, SIOCGIFTIMESLOT, (caddr_t)&ifr) == -1)
		return 0;

	for (i = 0; i < sizeof(ts_map) * 8; i++) {
		if (start == -1 && ts_map & (1 << i))
			start = i;
		else if (start != -1 && !(ts_map & (1 << i))) {
			if (start == i - 1)
				snprintf(str, str_len, "%s%d", sep, start);
			else
				snprintf(str, str_len, "%s%d-%d", sep, start,
				    i-1);
			sep = ",";
			start = -1;
		}
	}
	if (start != -1) {
		if (start == i - 1)
			snprintf(str, str_len, "%s%d", sep, start);
		else
			snprintf(str, str_len, "%s%d-%d", sep, start, i-1);
	}

	if (ts_map == ALL_CHANNELS)
		return 2;
	else
		return 1;
}
