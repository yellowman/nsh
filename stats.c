/* From: $OpenBSD: inet.c,v 1.104 2007/12/19 01:47:00 deraadt Exp $ */

/*
 * Copyright (c) 1983, 1988, 1993
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
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/sysctl.h>
#include <sys/pool.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <errno.h>
#include <fcntl.h>

#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/igmp_var.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_debug.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip_ipsp.h>
#include <netinet/ip_ah.h>
#include <netinet/ip_esp.h>
#include <netinet/ip_ipip.h>
#include <netinet/ip_ipcomp.h>
#include <netinet/ip_ether.h>
#include <netinet/ip_carp.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <net/if_pfsync.h>

#include <arpa/inet.h>
#include <limits.h>
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include "externs.h"
#include "facts.h"
#include "showfacts.h"
#include "stats.h"

/*
 * Get mbuf statistics.
 */
static int
mb_get(struct statgroup *g, void *p)
{
	struct mbinfo *mb = p;
	int i, mib[4], npools, flag = 0;
	struct kinfo_pool pool;
	size_t size;
	int nmbtypes = nitems(mb->mbstat.m_mtypes);

	 if (nmbtypes != MT_NTYPES) {
		printf("%% mbpr: unexpected change to mbstat; check source\n");
		return (-1);
	}

	mib[0] = CTL_KERN;
	mib[1] = KERN_MBSTAT;
	size = sizeof(mb->mbstat);

	if (sysctl(mib, 2, &mb->mbstat, &size, NULL, 0) < 0) {
		printf("%% mbpr: sysctl mbstat: %s\n", strerror(errno));
		return (-1);
	}

	mib[0] = CTL_KERN;
	mib[1] = KERN_POOL;
	mib[2] = KERN_POOL_NPOOLS;
	size = sizeof(npools);

	if (sysctl(mib, 3, &npools, &size, NULL, 0) < 0) {
		printf("%% mbpr: sysctl npools: %s\n", strerror(errno));
		return (-1);
	}

	for (i = 1; npools; i++) {
		char name[32];

		mib[0] = CTL_KERN;
		mib[1] = KERN_POOL;
		mib[2] = KERN_POOL_POOL;
		mib[3] = i;
		size = sizeof(struct kinfo_pool);
		if (sysctl(mib, 4, &pool, &size, NULL, 0) < 0) {
			if (errno == ENOENT)
				continue;
			printf("%% mbpr: sysctl pool size: %s\n",
			    strerror(errno));
			return (-1);
		}
		npools--;
		mib[2] = KERN_POOL_NAME;
		size = sizeof(name);
		if (sysctl(mib, 4, &name, &size, NULL, 0) < 0) {
			printf("%% mbpr: sysctl pool name: %s\n",
			    strerror(errno));
			return (-1);
		}

		if (!strncmp(name, "mbpl", strlen("mbpl"))) {
			bcopy(&pool, &mb->mbpool, sizeof(struct kinfo_pool));
			flag++;
		} else {
			if (!strncmp(name, "mclpl", strlen("mclpl"))) {
				bcopy(&pool, &mb->mclpool,
				    sizeof(struct kinfo_pool));
				flag++;
			}
		}

		if (flag == 2)
			break;
	}
	mb->page_size = getpagesize();
	return (0);
}

/*
 * Get pf's status, which only root may.
 */
static int
pf_get(struct statgroup *g, void *p)
{
	struct pfinfo *pi = p;
	int dev, r = -1;

	if ((dev = open("/dev/pf", O_RDONLY)) == -1) {
		printf("%% pf_stats: /dev/pf: %s\n", strerror(errno));
		return (-1);
	}
	if (ioctl(dev, DIOCGETSTATUS, &pi->status) == -1)
		printf("%% pf_stats: DIOCGETSTATUS: %s\n", strerror(errno));
	else if (ioctl(dev, DIOCGETSYNFLWATS, &pi->wats) == -1)
		printf("%% pf_stats: DIOCGETSYNFLWATS: %s\n",
		    strerror(errno));
	else
		r = 0;
	close(dev);
	return (r);
}

/* Is pf enabled: 1 or 0, or -1 after printing why, as only root may ask */
int
pf_enabled(void)
{
	struct pf_status st;
	int dev, r = -1;

	if ((dev = open("/dev/pf", O_RDONLY)) == -1) {
		printf("%% pf: /dev/pf: %s\n", strerror(errno));
		return (-1);
	}
	if (ioctl(dev, DIOCGETSTATUS, &st) == -1)
		printf("%% pf: DIOCGETSTATUS: %s\n", strerror(errno));
	else
		r = st.running != 0;
	close(dev);
	return (r);
}

/* g's structure, from the kernel: 0, 1 if it has none, -1 */
static int
stats_sysctl(struct statgroup *g, void *p)
{
	size_t	 len = g->size;

	if (sysctl(g->mib, g->miblen, p, &len, NULL, 0) == -1) {
		if (errno == g->none)
			return (1);
		printf("%% %s: sysctl: %s\n", g->fn, strerror(errno));
		return (-1);
	}
	return (0);
}

static uint64_t
member_get(const char *p, size_t size)
{
	uint8_t		 u8;
	uint16_t	 u16;
	uint32_t	 u32;
	uint64_t	 u64 = 0;

	switch (size) {
	case 1:
		memcpy(&u8, p, size);
		return (u8);
	case 2:
		memcpy(&u16, p, size);
		return (u16);
	case 4:
		memcpy(&u32, p, size);
		return (u32);
	case 8:
		memcpy(&u64, p, size);
	}
	return (u64);
}

/* g, as a record; a group the kernel does not have makes none */
int
stats_facts(struct facts_out *o, struct statgroup *g)
{
	struct facts_value	*v;
	char			*p;
	size_t			 i;
	int			 r;

	p = calloc(1, g->size);
	v = calloc(g->kind.nfields, sizeof(*v));
	if (p == NULL || v == NULL) {
		printf("%% stats_facts: %s\n", strerror(errno));
		free(p);
		free(v);
		return (-1);
	}
	if (g->get == STATS_MBUF)
		r = mb_get(g, p);
	else if (g->get == STATS_PF)
		r = pf_get(g, p);
	else
		r = stats_sysctl(g, p);
	if (r == 0) {
		for (i = 0; i < g->kind.nfields; i++) {
			if (g->kind.fields[i].type == FACT_STRING) {
				p[g->off[i] + g->sz[i] - 1] = '\0';
				facts_string(&v[i], p + g->off[i]);
			} else
				facts_u64(&v[i], member_get(p + g->off[i],
				    g->sz[i]));
		}
		r = facts_record(o, &g->kind, v);
	}
	free(v);
	free(p);
	return (r == -1 ? -1 : 0);
}
