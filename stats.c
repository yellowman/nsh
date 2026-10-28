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

/*
 * pf_print() is print_status() of pfctl_parser.c:
 *
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2013 Henning Brauer <henning@openbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define SYSLOG_NAMES	/* pf's debug level, as pfctl names it */
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
#define TCPSTATES
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

static int sflag = 1;

#define YES     1
typedef int bool;

/* a member of a statistics structure, or an array of them */
struct statfield {
	const char	*name;
	size_t		 off;
	size_t		 size;		/* size of one element */
	size_t		 n;
	int		 string;	/* a string, not a number */
};

#define SF(s, f)	{ #f, offsetof(struct s, f), \
			    sizeof(((struct s *)0)->f), 1 }
#define SFA(s, f)	{ #f, offsetof(struct s, f), \
			    sizeof(((struct s *)0)->f[0]), \
			    nitems(((struct s *)0)->f) }
#define SFS(s, f)	{ #f, offsetof(struct s, f), \
			    sizeof(((struct s *)0)->f), 1, 1 }

/* a group of statistics: where it comes from, and how it prints */
struct statgroup {
	const char		*word;
	const char		*fn;		/* name in error messages */
	int			 mib[6];
	u_int			 miblen;
	int			 none;		/* the errno of no such group */
	size_t			 size;
	const struct statfield	*f;
	size_t			 nf;
	int			(*get)(struct statgroup *, void *);
	void			(*print)(void *);
	int			 root;		/* only root may get it */
	struct facts_kind	 kind;
	size_t			*off, *sz;	/* field offsets and sizes */
};

static int	stats_sysctl(struct statgroup *, void *);

char	*inet6name(struct in6_addr *);
void	inet6print(struct in6_addr *, int, char *, int);

/*
 * Dump TCP statistics structure.
 */
static void
tcp_print(void *p)
{
	struct tcpstat tcpstat = *(struct tcpstat *)p;

	printf ("%% tcp:\n");

#define	p(f, m) if (tcpstat.f || sflag <= 1) \
    printf(m, tcpstat.f, plural(tcpstat.f))
#define	p1(f, m) if (tcpstat.f || sflag <= 1) \
    printf(m, tcpstat.f)
#define	p2(f1, f2, m) if (tcpstat.f1 || tcpstat.f2 || sflag <= 1) \
    printf(m, tcpstat.f1, plural(tcpstat.f1), tcpstat.f2, plural(tcpstat.f2))
#define	p2a(f1, f2, m) if (tcpstat.f1 || tcpstat.f2 || sflag <= 1) \
    printf(m, tcpstat.f1, plural(tcpstat.f1), tcpstat.f2)
#define	p3(f, m) if (tcpstat.f || sflag <= 1) \
    printf(m, tcpstat.f, plurales(tcpstat.f))

	p(tcps_sndtotal, "\t%u packet%s sent\n");
	p2(tcps_sndpack,tcps_sndbyte,
		"\t\t%u data packet%s (%qd byte%s)\n");
	p2(tcps_sndrexmitpack, tcps_sndrexmitbyte,
		"\t\t%u data packet%s (%qd byte%s) retransmitted\n");
	p(tcps_sndrexmitfast, "\t\t%qd fast retransmitted packet%s\n");
	p2a(tcps_sndacks, tcps_delack,
		"\t\t%u ack-only packet%s (%u delayed)\n");
	p(tcps_sndurg, "\t\t%u URG only packet%s\n");
	p(tcps_sndprobe, "\t\t%u window probe packet%s\n");
	p(tcps_sndwinup, "\t\t%u window update packet%s\n");
	p(tcps_sndctrl, "\t\t%u control packet%s\n");
	p(tcps_outswcsum, "\t\t%u packet%s software-checksummed\n");
	p(tcps_rcvtotal, "\t%u packet%s received\n");
	p2(tcps_rcvackpack, tcps_rcvackbyte, "\t\t%u ack%s (for %qd byte%s)\n");
	p(tcps_rcvdupack, "\t\t%u duplicate ack%s\n");
	p(tcps_rcvacktoomuch, "\t\t%u ack%s for unsent data\n");
	p(tcps_rcvacktooold, "\t\t%u ack%s for old data\n");
	p2(tcps_rcvpack, tcps_rcvbyte,
		"\t\t%u packet%s (%qu byte%s) received in-sequence\n");
	p2(tcps_rcvduppack, tcps_rcvdupbyte,
		"\t\t%u completely duplicate packet%s (%qd byte%s)\n");
	p(tcps_pawsdrop, "\t\t%u old duplicate packet%s\n");
	p2(tcps_rcvpartduppack, tcps_rcvpartdupbyte,
	    "\t\t%u packet%s with some duplicate data (%qd byte%s duplicated)\n");
	p2(tcps_rcvoopack, tcps_rcvoobyte,
		"\t\t%u out-of-order packet%s (%qd byte%s)\n");
	p2(tcps_rcvpackafterwin, tcps_rcvbyteafterwin,
		"\t\t%u packet%s (%qd byte%s) of data after window\n");
	p(tcps_rcvwinprobe, "\t\t%u window probe%s\n");
	p(tcps_rcvwinupd, "\t\t%u window update packet%s\n");
	p(tcps_rcvafterclose, "\t\t%u packet%s received after close\n");
	p(tcps_rcvbadsum, "\t\t%u discarded for bad checksum%s\n");
	p(tcps_rcvbadoff, "\t\t%u discarded for bad header offset field%s\n");
	p1(tcps_rcvshort, "\t\t%u discarded because packet too short\n");
	p1(tcps_rcvnosec, "\t\t%u discarded for missing IPsec protection\n");
	p1(tcps_rcvmemdrop, "\t\t%u discarded due to memory shortage\n");
	p(tcps_inswcsum, "\t\t%u packet%s software-checksummed\n");
	p(tcps_rcvbadsig, "\t\t%u bad/missing md5 checksum%s\n");
	p(tcps_rcvgoodsig, "\t\t%qd good md5 checksum%s\n");
	p(tcps_connattempt, "\t%u connection request%s\n");
	p(tcps_accepts, "\t%u connection accept%s\n");
	p(tcps_connects, "\t%u connection%s established (including accepts)\n");
	p2(tcps_closed, tcps_drops,
		"\t%u connection%s closed (including %u drop%s)\n");
	p(tcps_conndrained, "\t%qd connection%s drained\n");
	p(tcps_conndrops, "\t%u embryonic connection%s dropped\n");
	p2(tcps_rttupdated, tcps_segstimed,
		"\t%u segment%s updated rtt (of %u attempt%s)\n");
	p(tcps_rexmttimeo, "\t%u retransmit timeout%s\n");
	p(tcps_timeoutdrop, "\t\t%u connection%s dropped by retransmit timeout\n");
	p(tcps_persisttimeo, "\t%u persist timeout%s\n");
	p(tcps_keeptimeo, "\t%u keepalive timeout%s\n");
	p(tcps_keepprobe, "\t\t%u keepalive probe%s sent\n");
	p(tcps_keepdrops, "\t\t%u connection%s dropped by keepalive\n");
	p(tcps_predack, "\t%u correct ACK header prediction%s\n");
	p(tcps_preddat, "\t%u correct data packet header prediction%s\n");
	p3(tcps_pcbhashmiss, "\t%u PCB cache miss%s\n");

	p(tcps_ecn_accepts, "\t%u ECN connection%s accepted\n");
	p(tcps_ecn_rcvece, "\t\t%u ECE packet%s received\n");
	p(tcps_ecn_rcvcwr, "\t\t%u CWR packet%s received\n");
	p(tcps_ecn_rcvce, "\t\t%u CE packet%s received\n");
	p(tcps_ecn_sndect, "\t\t%u ECT packet%s sent\n");
	p(tcps_ecn_sndece, "\t\t%u ECE packet%s sent\n");
	p(tcps_ecn_sndcwr, "\t\t%u CWR packet%s sent\n");
	p1(tcps_cwr_frecovery, "\t\t\tcwr by fastrecovery: %u\n");
	p1(tcps_cwr_timeout, "\t\t\tcwr by timeout: %u\n");
	p1(tcps_cwr_ecn, "\t\t\tcwr by ecn: %u\n");

	p(tcps_badsyn, "\t%u bad connection attempt%s\n");
	p1(tcps_sc_added, "\t%qd SYN cache entries added\n");
	p(tcps_sc_collisions, "\t\t%qd hash collision%s\n");
	p1(tcps_sc_completed, "\t\t%qd completed\n");
	p1(tcps_sc_aborted, "\t\t%qd aborted (no space to build PCB)\n");
	p1(tcps_sc_timed_out, "\t\t%qd timed out\n");
	p1(tcps_sc_overflowed, "\t\t%qd dropped due to overflow\n");
	p1(tcps_sc_bucketoverflow, "\t\t%qd dropped due to bucket overflow\n");
	p1(tcps_sc_reset, "\t\t%qd dropped due to RST\n");
	p1(tcps_sc_unreach, "\t\t%qd dropped due to ICMP unreachable\n");
	p(tcps_sc_retransmitted, "\t%qd SYN,ACK%s retransmitted\n");
	p(tcps_sc_dupesyn, "\t%qd duplicate SYN%s received for entries "
	    "already in the cache\n");
	p(tcps_sc_dropped, "\t%qd SYN%s dropped (no route or no space)\n");

	p(tcps_sack_recovery_episode, "\t%qd SACK recovery episode%s\n");
	p(tcps_sack_rexmits,
	    "\t\t%qd segment rexmit%s in SACK recovery episodes\n");
	p(tcps_sack_rexmit_bytes,
	    "\t\t%qd byte rexmit%s in SACK recovery episodes\n");
	p(tcps_sack_rcv_opts,
	    "\t%qd SACK option%s received\n");
	p(tcps_sack_snd_opts, "\t%qd SACK option%s sent\n");

#undef p
#undef p1
#undef p2
#undef p2a
#undef p3
}

/*
 * Dump UDP statistics structure.
 */
static void
udp_print(void *p)
{
	struct udpstat udpstat = *(struct udpstat *)p;
	u_long delivered;

	printf("%% udp:\n");
#define	p(f, m) if (udpstat.f || sflag <= 1) \
    printf(m, udpstat.f, plural(udpstat.f))
#define	p1(f, m) if (udpstat.f || sflag <= 1) \
    printf(m, udpstat.f)
	p(udps_ipackets, "\t%lu datagram%s received\n");
	p1(udps_hdrops, "\t%lu with incomplete header\n");
	p1(udps_badlen, "\t%lu with bad data length field\n");
	p1(udps_badsum, "\t%lu with bad checksum\n");
	p1(udps_nosum, "\t%lu with no checksum\n");
	p(udps_inswcsum, "\t%lu input packet%s software-checksummed\n");
	p(udps_outswcsum, "\t%lu output packet%s software-checksummed\n");
	p1(udps_noport, "\t%lu dropped due to no socket\n");
	p(udps_noportbcast, "\t%lu broadcast/multicast datagram%s dropped due to no socket\n");
	p1(udps_nosec, "\t%lu dropped due to missing IPsec protection\n");
	p1(udps_fullsock, "\t%lu dropped due to full socket buffers\n");
	delivered = udpstat.udps_ipackets -
		    udpstat.udps_hdrops -
		    udpstat.udps_badlen -
		    udpstat.udps_badsum -
		    udpstat.udps_noport -
		    udpstat.udps_noportbcast -
		    udpstat.udps_fullsock;
	if (delivered || sflag <= 1)
		printf("\t%lu delivered\n", delivered);
	p(udps_opackets, "\t%lu datagram%s output\n");
	p1(udps_pcbhashmiss, "\t%lu missed PCB cache\n");
#undef p
#undef p1
}

/*
 * Dump IP statistics structure.
 */
static void
ip_print(void *p)
{
	struct ipstat ipstat = *(struct ipstat *)p;

	printf("%% ip:\n");

#define	p(f, m) if (ipstat.f || sflag <= 1) \
    printf(m, ipstat.f, plural(ipstat.f))
#define	p1(f, m) if (ipstat.f || sflag <= 1) \
    printf(m, ipstat.f)

	p(ips_total, "\t%lu total packet%s received\n");
	p(ips_badsum, "\t%lu bad header checksum%s\n");
	p1(ips_toosmall, "\t%lu with size smaller than minimum\n");
	p1(ips_tooshort, "\t%lu with data size < data length\n");
	p1(ips_badhlen, "\t%lu with header length < data size\n");
	p1(ips_badlen, "\t%lu with data length < header length\n");
	p1(ips_badoptions, "\t%lu with bad options\n");
	p1(ips_badvers, "\t%lu with incorrect version number\n");
	p(ips_fragments, "\t%lu fragment%s received\n");
	p(ips_fragdropped, "\t%lu fragment%s dropped (duplicates or out of space)\n");
	p(ips_badfrags, "\t%lu malformed fragment%s dropped\n");
	p(ips_fragtimeout, "\t%lu fragment%s dropped after timeout\n");
	p(ips_reassembled, "\t%lu packet%s reassembled ok\n");
	p(ips_delivered, "\t%lu packet%s for this host\n");
	p(ips_noproto, "\t%lu packet%s for unknown/unsupported protocol\n");
	p(ips_forward, "\t%lu packet%s forwarded\n");
	p(ips_cantforward, "\t%lu packet%s not forwardable\n");
	p(ips_redirectsent, "\t%lu redirect%s sent\n");
	p(ips_localout, "\t%lu packet%s sent from this host\n");
	p(ips_rawout, "\t%lu packet%s sent with fabricated ip header\n");
	p(ips_odropped, "\t%lu output packet%s dropped due to no bufs, etc.\n");
	p(ips_noroute, "\t%lu output packet%s discarded due to no route\n");
	p(ips_fragmented, "\t%lu output datagram%s fragmented\n");
	p(ips_ofragments, "\t%lu fragment%s created\n");
	p(ips_cantfrag, "\t%lu datagram%s that can't be fragmented\n");
	p1(ips_rcvmemdrop, "\t%lu fragment floods\n");
	p(ips_toolong, "\t%lu packet%s with ip length > max ip packet size\n");
	p(ips_nogif, "\t%lu tunneling packet%s that can't find gif\n");
	p(ips_badaddr, "\t%lu datagram%s with bad address in header\n");
	p(ips_inswcsum, "\t%lu input datagram%s software-checksummed\n");
	p(ips_outswcsum, "\t%lu output datagram%s software-checksummed\n");
	p(ips_notmember, "\t%lu multicast packet%s which we don't join\n");
#undef p
#undef p1
}

static	char *icmpnames[ICMP_MAXTYPE + 1] = {
	"echo reply",
	"#1",
	"#2",
	"destination unreachable",
	"source quench",
	"routing redirect",
	"#6",
	"#7",
	"echo",
	"router advertisement",
	"router solicitation",
	"time exceeded",
	"parameter problem",
	"time stamp",
	"time stamp reply",
	"information request",
	"information request reply",
	"address mask request",
	"address mask reply",
	"#19",
	"#20",
	"#21",
	"#22",
	"#23",
	"#24",
	"#25",
	"#26",
	"#27",
	"#28",
	"#29",
	"traceroute",
	"data conversion error",
	"mobile host redirect",
	"IPv6 where-are-you",
	"IPv6 i-am-here",
	"mobile registration request",
	"mobile registration reply",
	"#37",
	"#38",
	"SKIP",
	"Photuris",
};

/*
 * Dump ICMP statistics.
 */
static void
icmp_print(void *p)
{
	struct icmpstat icmpstat = *(struct icmpstat *)p;
	int i, first;

	printf("%% icmp:\n");

#define	p(f, m) if (icmpstat.f || sflag <= 1) \
    printf(m, icmpstat.f, plural(icmpstat.f))

	p(icps_error, "\t%lu call%s to icmp_error\n");
	p(icps_oldicmp,
	    "\t%lu error%s not generated because old message was icmp\n");
	for (first = 1, i = 0; i < ICMP_MAXTYPE + 1; i++)
		if (icmpstat.icps_outhist[i] != 0) {
			if (first) {
				printf("\tOutput packet histogram:\n");
				first = 0;
			}
			if (icmpnames[i])
				printf("\t\t%s:", icmpnames[i]);
			else
				printf("\t\t#%d:", i);
			printf(" %lu\n", icmpstat.icps_outhist[i]);
		}
	p(icps_badcode, "\t%lu message%s with bad code fields\n");
	p(icps_tooshort, "\t%lu message%s < minimum length\n");
	p(icps_checksum, "\t%lu bad checksum%s\n");
	p(icps_badlen, "\t%lu message%s with bad length\n");
	for (first = 1, i = 0; i < ICMP_MAXTYPE + 1; i++)
		if (icmpstat.icps_inhist[i] != 0) {
			if (first) {
				printf("\tInput packet histogram:\n");
				first = 0;
			}
			if (icmpnames[i])
				printf("\t\t%s:", icmpnames[i]);
			else
				printf("\t\t#%d:", i);
			printf(" %lu\n", icmpstat.icps_inhist[i]);
		}
	p(icps_reflect, "\t%lu message response%s generated\n");
#undef p
}

/*
 * Dump IGMP statistics structure.
 */
static void
igmp_print(void *p)
{
	struct igmpstat igmpstat = *(struct igmpstat *)p;

	printf("%% igmp:\n");

#define	p(f, m) if (igmpstat.f || sflag <= 1) \
    printf(m, igmpstat.f, plural(igmpstat.f))
#define	py(f, m) if (igmpstat.f || sflag <= 1) \
    printf(m, igmpstat.f, igmpstat.f != 1 ? "ies" : "y")
	p(igps_rcv_total, "\t%lu message%s received\n");
	p(igps_rcv_tooshort, "\t%lu message%s received with too few bytes\n");
	p(igps_rcv_badsum, "\t%lu message%s received with bad checksum\n");
	py(igps_rcv_queries, "\t%lu membership quer%s received\n");
	py(igps_rcv_badqueries, "\t%lu membership quer%s received with invalid field(s)\n");
	p(igps_rcv_reports, "\t%lu membership report%s received\n");
	p(igps_rcv_badreports, "\t%lu membership report%s received with invalid field(s)\n");
	p(igps_rcv_ourreports, "\t%lu membership report%s received for groups to which we belong\n");
	p(igps_snd_reports, "\t%lu membership report%s sent\n");
#undef p
#undef py
}

/*
 * Dump AH statistics structure.
 */
static void
ah_print(void *p)
{
	struct ahstat ahstat = *(struct ahstat *)p;

	printf("%% ah:\n");

#define p(f, m) if (ahstat.f || sflag <= 1) \
    printf(m, ahstat.f, plural(ahstat.f))
#define p1(f, m) if (ahstat.f || sflag <= 1) \
    printf(m, ahstat.f)

	p1(ahs_input, "\t%llu input AH packets\n");
	p1(ahs_output, "\t%llu output AH packets\n");
	p(ahs_nopf, "\t%llu packet%s from unsupported protocol families\n");
	p(ahs_hdrops, "\t%llu packet%s shorter than header shows\n");
	p(ahs_pdrops, "\t%llu packet%s dropped due to policy\n");
	p(ahs_notdb, "\t%llu packet%s for which no TDB was found\n");
	p(ahs_badkcr, "\t%llu input packet%s that failed to be processed\n");
	p(ahs_badauth, "\t%llu packet%s that failed verification received\n");
	p(ahs_noxform, "\t%llu packet%s for which no XFORM was set in TDB received\n");
	p(ahs_qfull, "\t%llu packet%s were dropped due to full output queue\n");
	p(ahs_wrap, "\t%llu packet%s where counter wrapping was detected\n");
	p(ahs_replay, "\t%llu possibly replayed packet%s received\n");
	p(ahs_badauthl, "\t%llu packet%s with bad authenticator length received\n");
	p(ahs_invalid, "\t%llu packet%s attempted to use an invalid tdb\n");
	p(ahs_toobig, "\t%llu packet%s got larger than max IP packet size\n");
	p(ahs_crypto, "\t%llu packet%s that failed crypto processing\n");
	p(ahs_ibytes, "\t%qu input byte%s\n");
	p(ahs_obytes, "\t%qu output byte%s\n");

#undef p
#undef p1
}

/*
 * Dump ESP statistics structure.
 */
static void
esp_print(void *p)
{
	struct espstat espstat = *(struct espstat *)p;

	printf("%% esp:\n");

#define p(f, m) if (espstat.f || sflag <= 1) \
    printf(m, espstat.f, plural(espstat.f))

	p(esps_input, "\t%llu input ESP packet%s\n");
	p(esps_output, "\t%llu output ESP packet%s\n");
	p(esps_nopf, "\t%llu packet%s from unsupported protocol families\n");
	p(esps_hdrops, "\t%llu packet%s shorter than header shows\n");
	p(esps_pdrops, "\t%llu packet%s dropped due to policy\n");
	p(esps_notdb, "\t%llu packet%s for which no TDB was found\n");
	p(esps_badkcr, "\t%llu input packet%s that failed to be processed\n");
	p(esps_badenc, "\t%llu packet%s with bad encryption received\n");
	p(esps_badauth, "\t%llu packet%s that failed verification received\n");
	p(esps_noxform, "\t%llu packet%s for which no XFORM was set in TDB received\n");
	p(esps_qfull, "\t%llu packet%s were dropped due to full output queue\n");
	p(esps_wrap, "\t%llu packet%s where counter wrapping was detected\n");
	p(esps_replay, "\t%llu possibly replayed packet%s received\n");
	p(esps_badilen, "\t%llu packet%s with bad payload size or padding received\n");
	p(esps_invalid, "\t%llu packet%s attempted to use an invalid tdb\n");
	p(esps_toobig, "\t%llu packet%s got larger than max IP packet size\n");
	p(esps_crypto, "\t%llu packet%s that failed crypto processing\n");
	p(esps_udpencin, "\t%llu input UDP encapsulated ESP packet%s\n");
	p(esps_udpencout, "\t%llu output UDP encapsulated ESP packet%s\n");
	p(esps_udpinval, "\t%llu UDP packet%s for non-encapsulating TDB received\n");
	p(esps_ibytes, "\t%qu input byte%s\n");
	p(esps_obytes, "\t%qu output byte%s\n");

#undef p
}

/*
 * Dump IP-in-IP statistics structure.
 */
static void
ipip_print(void *p)
{
	struct ipipstat ipipstat = *(struct ipipstat *)p;

	printf("%% ipip:\n");

#define p(f, m) if (ipipstat.f || sflag <= 1) \
    printf(m, ipipstat.f, plural(ipipstat.f))

	p(ipips_ipackets, "\t%llu total input packet%s\n");
	p(ipips_opackets, "\t%llu total output packet%s\n");
	p(ipips_hdrops, "\t%llu packet%s shorter than header shows\n");
	p(ipips_pdrops, "\t%llu packet%s dropped due to policy\n");
	p(ipips_spoof, "\t%llu packet%s with possibly spoofed local addresses\n");
	p(ipips_qfull, "\t%llu packet%s were dropped due to full output queue\n");
	p(ipips_ibytes, "\t%qu input byte%s\n");
	p(ipips_obytes, "\t%qu output byte%s\n");
	p(ipips_family, "\t%llu protocol family mismatche%s\n");
	p(ipips_unspec, "\t%llu attempts to use tunnel with unspecified endpoint%s\n");
#undef p
}

/*
 * Dump CARP statistics structure.
 */
static void
carp_print(void *p)
{
	struct carpstats carpstat = *(struct carpstats *)p;

	printf("%% carp:\n");
#define p(f, m) if (carpstat.f || sflag <= 1) \
	printf(m, carpstat.f, plural(carpstat.f))
#define p2(f, m) if (carpstat.f || sflag <= 1) \
	printf(m, carpstat.f)

	p(carps_ipackets, "\t%llu packet%s received (IPv4)\n");
	p(carps_ipackets6, "\t%llu packet%s received (IPv6)\n");
	p(carps_badif, "\t\t%llu packet%s discarded for bad interface\n");
	p(carps_badttl, "\t\t%llu packet%s discarded for wrong TTL\n");
	p(carps_hdrops, "\t\t%llu packet%s shorter than header\n");
	p(carps_badsum, "\t\t%llu discarded for bad checksum%s\n");
	p(carps_badver, "\t\t%llu discarded packet%s with a bad version\n");
	p2(carps_badlen, "\t\t%llu discarded because packet too short\n");
	p2(carps_badauth, "\t\t%llu discarded for bad authentication\n");
	p2(carps_badvhid, "\t\t%llu discarded for bad vhid\n");
	p2(carps_badaddrs, "\t\t%llu discarded because of a bad address list\n");
	p(carps_opackets, "\t%llu packet%s sent (IPv4)\n");
	p(carps_opackets6, "\t%llu packet%s sent (IPv6)\n");
	p2(carps_onomem, "\t\t%llu send failed due to mbuf memory error\n");
	p(carps_preempt, "\t%llu transition%s to master\n");
#undef p
#undef p2
}

/*
 * Dump pfsync statistics structure.
 */
static void
pfsync_print(void *p)
{
	struct pfsyncstats pfsyncstat = *(struct pfsyncstats *)p;

	printf("%% pfsync:\n");
#define p(f, m) if (pfsyncstat.f || sflag <= 1) \
	printf(m, pfsyncstat.f, plural(pfsyncstat.f))
#define p2(f, m) if (pfsyncstat.f || sflag <= 1) \
	printf(m, pfsyncstat.f)
	p(pfsyncs_ipackets, "\t%llu packet%s received (IPv4)\n");
	p(pfsyncs_ipackets6, "\t%llu packet%s received (IPv6)\n");
	p(pfsyncs_badif, "\t\t%llu packet%s discarded for bad interface\n");
	p(pfsyncs_badttl, "\t\t%llu packet%s discarded for bad ttl\n");
	p(pfsyncs_hdrops, "\t\t%llu packet%s shorter than header\n");
	p(pfsyncs_badver, "\t\t%llu packet%s discarded for bad version\n");
	p(pfsyncs_badauth, "\t\t%llu packet%s discarded for bad HMAC\n");
	p(pfsyncs_badact,"\t\t%llu packet%s discarded for bad action\n");
	p(pfsyncs_badlen, "\t\t%llu packet%s discarded for short packet\n");
	p(pfsyncs_badval, "\t\t%llu state%s discarded for bad values\n");
	p(pfsyncs_stale, "\t\t%llu stale state%s\n");
	p(pfsyncs_badstate, "\t\t%llu failed state lookup/insert%s\n");
	p(pfsyncs_opackets, "\t%llu packet%s sent (IPv4)\n");
	p(pfsyncs_opackets6, "\t%llu packet%s sent (IPv6)\n");
	p2(pfsyncs_onomem, "\t\t%llu send failed due to mbuf memory error\n");
	p2(pfsyncs_oerrors, "\t\t%llu send error\n");
#undef p
#undef p2
}

/*
 * Dump IPCOMP statistics structure.
 */
static void
ipcomp_print(void *p)
{
	struct ipcompstat ipcompstat = *(struct ipcompstat *)p;

	printf("%% ipcomp:\n");

#define p(f, m) if (ipcompstat.f || sflag <= 1) \
    printf(m, ipcompstat.f, plural(ipcompstat.f))

	p(ipcomps_input, "\t%llu input IPCOMP packet%s\n");
	p(ipcomps_output, "\t%llu output IPCOMP packet%s\n");
	p(ipcomps_nopf, "\t%llu packet%s from unsupported protocol families\n");
	p(ipcomps_hdrops, "\t%llu packet%s shorter than header shows\n");
	p(ipcomps_pdrops, "\t%llu packet%s dropped due to policy\n");
	p(ipcomps_notdb, "\t%llu packet%s for which no TDB was found\n");
	p(ipcomps_badkcr, "\t%llu input packet%s that failed to be processed\n");
	p(ipcomps_noxform, "\t%llu packet%s for which no XFORM was set in TDB received\n");
	p(ipcomps_qfull, "\t%llu packet%s were dropped due to full output queue\n");
	p(ipcomps_wrap, "\t%llu packet%s where counter wrapping was detected\n");
	p(ipcomps_invalid, "\t%llu packet%s attempted to use an invalid tdb\n");
	p(ipcomps_toobig, "\t%llu packet%s got larger than max IP packet size\n");
	p(ipcomps_crypto, "\t%llu packet%s that failed (de)compression processing\n");
	p(ipcomps_minlen, "\t%llu packet%s less than minimum compression length\n");
	p(ipcomps_ibytes, "\t%qu input byte%s\n");
	p(ipcomps_obytes, "\t%qu output byte%s\n");

#undef p
}

/*
 * Print routing statistics
 */
static void
rt_print(void *p)
{
	struct rtstat rtstat = *(struct rtstat *)p;

	printf("%% routing:\n");
	printf("\t%u bad routing redirect%s\n",
	    rtstat.rts_badredirect, plural(rtstat.rts_badredirect));   
	printf("\t%u dynamically created route%s\n",
	    rtstat.rts_dynamic, plural(rtstat.rts_dynamic));
	printf("\t%u new gateway%s due to redirects\n",
	    rtstat.rts_newgateway, plural(rtstat.rts_newgateway));
	printf("\t%u destination%s found unreachable\n",
	    rtstat.rts_unreach, plural(rtstat.rts_unreach));
	printf("\t%u use%s of a wildcard route\n",
	    rtstat.rts_wildcard, plural(rtstat.rts_wildcard));
}

char *
plural(int n)
{
	return (n != 1 ? "s" : "");
}

char *
plurales(int n)
{
	return (n != 1 ? "es" : "");
}

static struct mbtypes {
	int	mt_type;
	char	*mt_name;
} mbtypes[] = {
	{ MT_DATA,	"data" },
	{ MT_OOBDATA,	"oob data" },
	{ MT_CONTROL,	"ancillary data" },
	{ MT_HEADER,	"packet headers" },
	{ MT_FTABLE,	"fragment reassembly queue headers" },	/* XXX */
	{ MT_SONAME,	"socket names and addresses" },
	{ MT_SOOPTS,	"socket options" },
	{ 0, 0 }
};

/* what mb_print() prints */
struct mbinfo {
	struct mbstat		 mbstat;
	struct kinfo_pool	 mbpool, mclpool;
	int			 page_size;
};

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
 * Print mbuf statistics.
 */
static void
mb_print(void *p)
{
	struct mbinfo *mb = p;
	struct mbstat mbstat = mb->mbstat;
	struct kinfo_pool mbpool = mb->mbpool, mclpool = mb->mclpool;
	int totmem, totused, totmbufs, totpct;
	int i;
	bool seen[256];
	struct mbtypes *mp;
	int page_size = mb->page_size;
	int nmbtypes = nitems(mbstat.m_mtypes);

	memset(&seen, 0, sizeof(seen));

	totmbufs = 0;
	for (mp = mbtypes; mp->mt_name; mp++)
		totmbufs += mbstat.m_mtypes[mp->mt_type];
	printf("\t%d mbuf%s in use:\n", totmbufs, plural(totmbufs));
	for (mp = mbtypes; mp->mt_name; mp++)
		if (mbstat.m_mtypes[mp->mt_type]) {
			seen[mp->mt_type] = YES;
			printf("\t\t%lu mbuf%s allocated to %s\n",
			    mbstat.m_mtypes[mp->mt_type],
			    plural((int)mbstat.m_mtypes[mp->mt_type]),
			    mp->mt_name);
		}
	seen[MT_FREE] = YES;
	for (i = 0; i < nmbtypes; i++)
		if (!seen[i] && mbstat.m_mtypes[i]) {
			printf("\t\t%lu mbuf%s allocated to <mbuf type %d>\n",
			    mbstat.m_mtypes[i],
			    plural((int)mbstat.m_mtypes[i]), i);
		}
	printf("\t%lu/%lu/%lu mbuf clusters in use (current/peak/max)\n",
	    (u_long)(mclpool.pr_nout),
	    (u_long)(mclpool.pr_hiwat * mclpool.pr_itemsperpage),
	    (u_long)(mclpool.pr_maxpages * mclpool.pr_itemsperpage));
	totmem = (mbpool.pr_npages * page_size) +
	    (mclpool.pr_npages * page_size);
	totused = mbpool.pr_nout * mbpool.pr_size +
	    mclpool.pr_nout * mclpool.pr_size;
	totpct = (totmem == 0)? 0 : ((totused * 100)/totmem);
	printf("\t%d Kbytes allocated to network (%d%% in use)\n",
	    totmem / 1024, totpct);
	printf("\t%lu requests for memory denied\n", mbstat.m_drops);
	printf("\t%lu requests for memory delayed\n", mbstat.m_wait);
	printf("\t%lu calls to protocol drain routines\n", mbstat.m_drain);
}

/* what pfctl -s info prints */
struct pfinfo {
	struct pf_status	 status;
	struct pfioc_synflwats	 wats;
};

static const char	*pf_reasons[PFRES_MAX+1] = PFRES_NAMES;
static const char	*pf_fcounters[FCNT_MAX+1] =
    { "searches", "inserts", "removals", NULL };

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

/* a debug level's name, as pfctl's loglevel_to_string() gives it */
static const char *
pf_loglevel(int level)
{
	CODE *c;

	for (c = prioritynames; c->c_name; c++)
		if (c->c_val == level)
			return (c->c_name);
	return ("unknown");
}

/*
 * Print pf's status, as pfctl -s info does.
 */
static void
pf_print(void *p)
{
	struct pfinfo	*pi = p;
	struct pf_status *s = &pi->status;
	char		 statline[80], debug[32];
	const char	*running;
	time_t		 runtime = 0;
	struct timespec	 uptime;
	int		 i;

	printf("%% pf statistics:\n");
	if (!clock_gettime(CLOCK_BOOTTIME, &uptime))
		runtime = uptime.tv_sec - s->since;
	running = s->running ? "Enabled" : "Disabled";

	if (runtime) {
		unsigned int	sec, min, hrs;
		time_t		day = runtime;

		sec = day % 60;
		day /= 60;
		min = day % 60;
		day /= 60;
		hrs = day % 24;
		day /= 24;
		snprintf(statline, sizeof(statline),
		    "Status: %s for %lld days %.2u:%.2u:%.2u",
		    running, (long long)day, hrs, min, sec);
	} else
		snprintf(statline, sizeof(statline), "Status: %s", running);
	printf("%-44s", statline);
	snprintf(debug, sizeof(debug), "Debug: %s", pf_loglevel(s->debug));
	printf("%15s\n\n", debug);

	if (s->ifname[0] != 0) {
		printf("Interface Stats for %-16s %5s %16s\n",
		    s->ifname, "IPv4", "IPv6");
		printf("  %-25s %14llu %16llu\n", "Bytes In",
		    (unsigned long long)s->bcounters[0][0],
		    (unsigned long long)s->bcounters[1][0]);
		printf("  %-25s %14llu %16llu\n", "Bytes Out",
		    (unsigned long long)s->bcounters[0][1],
		    (unsigned long long)s->bcounters[1][1]);
		printf("  Packets In\n");
		printf("    %-23s %14llu %16llu\n", "Passed",
		    (unsigned long long)s->pcounters[0][0][PF_PASS],
		    (unsigned long long)s->pcounters[1][0][PF_PASS]);
		printf("    %-23s %14llu %16llu\n", "Blocked",
		    (unsigned long long)s->pcounters[0][0][PF_DROP],
		    (unsigned long long)s->pcounters[1][0][PF_DROP]);
		printf("  Packets Out\n");
		printf("    %-23s %14llu %16llu\n", "Passed",
		    (unsigned long long)s->pcounters[0][1][PF_PASS],
		    (unsigned long long)s->pcounters[1][1][PF_PASS]);
		printf("    %-23s %14llu %16llu\n\n", "Blocked",
		    (unsigned long long)s->pcounters[0][1][PF_DROP],
		    (unsigned long long)s->pcounters[1][1][PF_DROP]);
	}
	printf("%-27s %14s %16s\n", "State Table", "Total", "Rate");
	printf("  %-25s %14u %14s\n", "current entries", s->states, "");
	printf("  %-25s %14u %14s\n", "half-open tcp", s->states_halfopen, "");
	for (i = 0; i < FCNT_MAX; i++) {
		printf("  %-25s %14llu ", pf_fcounters[i],
			    (unsigned long long)s->fcounters[i]);
		if (runtime > 0)
			printf("%14.1f/s\n",
			    (double)s->fcounters[i] / (double)runtime);
		else
			printf("%14s\n", "");
	}
	printf("Counters\n");
	for (i = 0; i < PFRES_MAX; i++) {
		printf("  %-25s %14llu ", pf_reasons[i],
		    (unsigned long long)s->counters[i]);
		if (runtime > 0)
			printf("%14.1f/s\n",
			    (double)s->counters[i] / (double)runtime);
		else
			printf("%14s\n", "");
	}
}

/*
 * Each group of statistics is a kind of record, its fields the members
 * of the kernel's structure, by their names: an array's elements are
 * name[i]. nsh puts what the record says back where it came from and
 * prints the structure as it always has.
 */
static const struct statfield ip_fields[] = {
	SF(ipstat, ips_total), SF(ipstat, ips_badsum),
	SF(ipstat, ips_toosmall), SF(ipstat, ips_tooshort),
	SF(ipstat, ips_badhlen), SF(ipstat, ips_badlen),
	SF(ipstat, ips_badoptions), SF(ipstat, ips_badvers),
	SF(ipstat, ips_fragments), SF(ipstat, ips_fragdropped),
	SF(ipstat, ips_badfrags), SF(ipstat, ips_fragtimeout),
	SF(ipstat, ips_reassembled), SF(ipstat, ips_delivered),
	SF(ipstat, ips_noproto), SF(ipstat, ips_forward),
	SF(ipstat, ips_cantforward), SF(ipstat, ips_redirectsent),
	SF(ipstat, ips_localout), SF(ipstat, ips_rawout),
	SF(ipstat, ips_odropped), SF(ipstat, ips_noroute),
	SF(ipstat, ips_fragmented), SF(ipstat, ips_ofragments),
	SF(ipstat, ips_cantfrag), SF(ipstat, ips_rcvmemdrop),
	SF(ipstat, ips_toolong), SF(ipstat, ips_nogif),
	SF(ipstat, ips_badaddr), SF(ipstat, ips_inswcsum),
	SF(ipstat, ips_outswcsum), SF(ipstat, ips_notmember),
};
static const struct statfield ah_fields[] = {
	SF(ahstat, ahs_input), SF(ahstat, ahs_output), SF(ahstat, ahs_nopf),
	SF(ahstat, ahs_hdrops), SF(ahstat, ahs_pdrops), SF(ahstat, ahs_notdb),
	SF(ahstat, ahs_badkcr), SF(ahstat, ahs_badauth),
	SF(ahstat, ahs_noxform), SF(ahstat, ahs_qfull), SF(ahstat, ahs_wrap),
	SF(ahstat, ahs_replay), SF(ahstat, ahs_badauthl),
	SF(ahstat, ahs_invalid), SF(ahstat, ahs_toobig),
	SF(ahstat, ahs_crypto), SF(ahstat, ahs_ibytes),
	SF(ahstat, ahs_obytes),
};
static const struct statfield esp_fields[] = {
	SF(espstat, esps_input), SF(espstat, esps_output),
	SF(espstat, esps_nopf), SF(espstat, esps_hdrops),
	SF(espstat, esps_pdrops), SF(espstat, esps_notdb),
	SF(espstat, esps_badkcr), SF(espstat, esps_badenc),
	SF(espstat, esps_badauth), SF(espstat, esps_noxform),
	SF(espstat, esps_qfull), SF(espstat, esps_wrap),
	SF(espstat, esps_replay), SF(espstat, esps_badilen),
	SF(espstat, esps_invalid), SF(espstat, esps_toobig),
	SF(espstat, esps_crypto), SF(espstat, esps_udpencin),
	SF(espstat, esps_udpencout), SF(espstat, esps_udpinval),
	SF(espstat, esps_ibytes), SF(espstat, esps_obytes),
};
static const struct statfield tcp_fields[] = {
	SF(tcpstat, tcps_sndtotal), SF(tcpstat, tcps_sndpack),
	SF(tcpstat, tcps_sndbyte), SF(tcpstat, tcps_sndrexmitpack),
	SF(tcpstat, tcps_sndrexmitbyte), SF(tcpstat, tcps_sndrexmitfast),
	SF(tcpstat, tcps_sndacks), SF(tcpstat, tcps_delack),
	SF(tcpstat, tcps_sndurg), SF(tcpstat, tcps_sndprobe),
	SF(tcpstat, tcps_sndwinup), SF(tcpstat, tcps_sndctrl),
	SF(tcpstat, tcps_outswcsum), SF(tcpstat, tcps_rcvtotal),
	SF(tcpstat, tcps_rcvackpack), SF(tcpstat, tcps_rcvackbyte),
	SF(tcpstat, tcps_rcvdupack), SF(tcpstat, tcps_rcvacktoomuch),
	SF(tcpstat, tcps_rcvacktooold), SF(tcpstat, tcps_rcvpack),
	SF(tcpstat, tcps_rcvbyte), SF(tcpstat, tcps_rcvduppack),
	SF(tcpstat, tcps_rcvdupbyte), SF(tcpstat, tcps_pawsdrop),
	SF(tcpstat, tcps_rcvpartduppack), SF(tcpstat, tcps_rcvpartdupbyte),
	SF(tcpstat, tcps_rcvoopack), SF(tcpstat, tcps_rcvoobyte),
	SF(tcpstat, tcps_rcvpackafterwin), SF(tcpstat, tcps_rcvbyteafterwin),
	SF(tcpstat, tcps_rcvwinprobe), SF(tcpstat, tcps_rcvwinupd),
	SF(tcpstat, tcps_rcvafterclose), SF(tcpstat, tcps_rcvbadsum),
	SF(tcpstat, tcps_rcvbadoff), SF(tcpstat, tcps_rcvshort),
	SF(tcpstat, tcps_rcvnosec), SF(tcpstat, tcps_rcvmemdrop),
	SF(tcpstat, tcps_inswcsum), SF(tcpstat, tcps_rcvbadsig),
	SF(tcpstat, tcps_rcvgoodsig), SF(tcpstat, tcps_connattempt),
	SF(tcpstat, tcps_accepts), SF(tcpstat, tcps_connects),
	SF(tcpstat, tcps_closed), SF(tcpstat, tcps_drops),
	SF(tcpstat, tcps_conndrained), SF(tcpstat, tcps_conndrops),
	SF(tcpstat, tcps_rttupdated), SF(tcpstat, tcps_segstimed),
	SF(tcpstat, tcps_rexmttimeo), SF(tcpstat, tcps_timeoutdrop),
	SF(tcpstat, tcps_persisttimeo), SF(tcpstat, tcps_keeptimeo),
	SF(tcpstat, tcps_keepprobe), SF(tcpstat, tcps_keepdrops),
	SF(tcpstat, tcps_predack), SF(tcpstat, tcps_preddat),
	SF(tcpstat, tcps_pcbhashmiss), SF(tcpstat, tcps_ecn_accepts),
	SF(tcpstat, tcps_ecn_rcvece), SF(tcpstat, tcps_ecn_rcvcwr),
	SF(tcpstat, tcps_ecn_rcvce), SF(tcpstat, tcps_ecn_sndect),
	SF(tcpstat, tcps_ecn_sndece), SF(tcpstat, tcps_ecn_sndcwr),
	SF(tcpstat, tcps_cwr_frecovery), SF(tcpstat, tcps_cwr_timeout),
	SF(tcpstat, tcps_cwr_ecn), SF(tcpstat, tcps_badsyn),
	SF(tcpstat, tcps_sc_added), SF(tcpstat, tcps_sc_collisions),
	SF(tcpstat, tcps_sc_completed), SF(tcpstat, tcps_sc_aborted),
	SF(tcpstat, tcps_sc_timed_out), SF(tcpstat, tcps_sc_overflowed),
	SF(tcpstat, tcps_sc_bucketoverflow), SF(tcpstat, tcps_sc_reset),
	SF(tcpstat, tcps_sc_unreach), SF(tcpstat, tcps_sc_retransmitted),
	SF(tcpstat, tcps_sc_dupesyn), SF(tcpstat, tcps_sc_dropped),
	SF(tcpstat, tcps_sack_recovery_episode),
	SF(tcpstat, tcps_sack_rexmits), SF(tcpstat, tcps_sack_rexmit_bytes),
	SF(tcpstat, tcps_sack_rcv_opts), SF(tcpstat, tcps_sack_snd_opts),
};
static const struct statfield udp_fields[] = {
	SF(udpstat, udps_ipackets), SF(udpstat, udps_hdrops),
	SF(udpstat, udps_badlen), SF(udpstat, udps_badsum),
	SF(udpstat, udps_nosum), SF(udpstat, udps_inswcsum),
	SF(udpstat, udps_outswcsum), SF(udpstat, udps_noport),
	SF(udpstat, udps_noportbcast), SF(udpstat, udps_nosec),
	SF(udpstat, udps_fullsock), SF(udpstat, udps_opackets),
	SF(udpstat, udps_pcbhashmiss),
};
static const struct statfield icmp_fields[] = {
	SF(icmpstat, icps_error), SF(icmpstat, icps_oldicmp),
	SFA(icmpstat, icps_outhist), SF(icmpstat, icps_badcode),
	SF(icmpstat, icps_tooshort), SF(icmpstat, icps_checksum),
	SF(icmpstat, icps_badlen), SFA(icmpstat, icps_inhist),
	SF(icmpstat, icps_reflect),
};
static const struct statfield igmp_fields[] = {
	SF(igmpstat, igps_rcv_total), SF(igmpstat, igps_rcv_tooshort),
	SF(igmpstat, igps_rcv_badsum), SF(igmpstat, igps_rcv_queries),
	SF(igmpstat, igps_rcv_badqueries), SF(igmpstat, igps_rcv_reports),
	SF(igmpstat, igps_rcv_badreports), SF(igmpstat, igps_rcv_ourreports),
	SF(igmpstat, igps_snd_reports),
};
static const struct statfield ipip_fields[] = {
	SF(ipipstat, ipips_ipackets), SF(ipipstat, ipips_opackets),
	SF(ipipstat, ipips_hdrops), SF(ipipstat, ipips_pdrops),
	SF(ipipstat, ipips_spoof), SF(ipipstat, ipips_qfull),
	SF(ipipstat, ipips_ibytes), SF(ipipstat, ipips_obytes),
	SF(ipipstat, ipips_family), SF(ipipstat, ipips_unspec),
};
static const struct statfield carp_fields[] = {
	SF(carpstats, carps_ipackets), SF(carpstats, carps_ipackets6),
	SF(carpstats, carps_badif), SF(carpstats, carps_badttl),
	SF(carpstats, carps_hdrops), SF(carpstats, carps_badsum),
	SF(carpstats, carps_badver), SF(carpstats, carps_badlen),
	SF(carpstats, carps_badauth), SF(carpstats, carps_badvhid),
	SF(carpstats, carps_badaddrs), SF(carpstats, carps_opackets),
	SF(carpstats, carps_opackets6), SF(carpstats, carps_onomem),
	SF(carpstats, carps_preempt),
};
static const struct statfield pfsync_fields[] = {
	SF(pfsyncstats, pfsyncs_ipackets), SF(pfsyncstats, pfsyncs_ipackets6),
	SF(pfsyncstats, pfsyncs_badif), SF(pfsyncstats, pfsyncs_badttl),
	SF(pfsyncstats, pfsyncs_hdrops), SF(pfsyncstats, pfsyncs_badver),
	SF(pfsyncstats, pfsyncs_badauth), SF(pfsyncstats, pfsyncs_badact),
	SF(pfsyncstats, pfsyncs_badlen), SF(pfsyncstats, pfsyncs_badval),
	SF(pfsyncstats, pfsyncs_stale), SF(pfsyncstats, pfsyncs_badstate),
	SF(pfsyncstats, pfsyncs_opackets), SF(pfsyncstats, pfsyncs_opackets6),
	SF(pfsyncstats, pfsyncs_onomem), SF(pfsyncstats, pfsyncs_oerrors),
};
static const struct statfield ipcomp_fields[] = {
	SF(ipcompstat, ipcomps_input), SF(ipcompstat, ipcomps_output),
	SF(ipcompstat, ipcomps_nopf), SF(ipcompstat, ipcomps_hdrops),
	SF(ipcompstat, ipcomps_pdrops), SF(ipcompstat, ipcomps_notdb),
	SF(ipcompstat, ipcomps_badkcr), SF(ipcompstat, ipcomps_noxform),
	SF(ipcompstat, ipcomps_qfull), SF(ipcompstat, ipcomps_wrap),
	SF(ipcompstat, ipcomps_invalid), SF(ipcompstat, ipcomps_toobig),
	SF(ipcompstat, ipcomps_crypto), SF(ipcompstat, ipcomps_minlen),
	SF(ipcompstat, ipcomps_ibytes), SF(ipcompstat, ipcomps_obytes),
};
static const struct statfield rt_fields[] = {
	SF(rtstat, rts_badredirect), SF(rtstat, rts_dynamic),
	SF(rtstat, rts_newgateway), SF(rtstat, rts_unreach),
	SF(rtstat, rts_wildcard),
};

static const struct statfield mb_fields[] = {
	SF(mbinfo, mbstat.m_drops), SF(mbinfo, mbstat.m_wait),
	SF(mbinfo, mbstat.m_drain), SFA(mbinfo, mbstat.m_mtypes),
	SF(mbinfo, mbpool.pr_size), SF(mbinfo, mbpool.pr_npages),
	SF(mbinfo, mbpool.pr_nout), SF(mbinfo, mclpool.pr_size),
	SF(mbinfo, mclpool.pr_npages), SF(mbinfo, mclpool.pr_nout),
	SF(mbinfo, mclpool.pr_hiwat), SF(mbinfo, mclpool.pr_itemsperpage),
	SF(mbinfo, mclpool.pr_maxpages), SF(mbinfo, page_size),
};

static const struct statfield pf_fields[] = {
	SFA(pfinfo, status.counters), SFA(pfinfo, status.lcounters),
	SFA(pfinfo, status.fcounters), SFA(pfinfo, status.scounters),
	SFA(pfinfo, status.ncounters), SFA(pfinfo, status.pcounters[0][0]),
	SFA(pfinfo, status.pcounters[0][1]),
	SFA(pfinfo, status.pcounters[1][0]),
	SFA(pfinfo, status.pcounters[1][1]), SFA(pfinfo, status.bcounters[0]),
	SFA(pfinfo, status.bcounters[1]), SF(pfinfo, status.stateid),
	SFA(pfinfo, status.syncookies_inflight), SF(pfinfo, status.since),
	SF(pfinfo, status.running), SF(pfinfo, status.states),
	SF(pfinfo, status.states_halfopen), SF(pfinfo, status.src_nodes),
	SF(pfinfo, status.fragments), SF(pfinfo, status.debug),
	SF(pfinfo, status.hostid), SF(pfinfo, status.reass),
	SF(pfinfo, status.syncookies_active),
	SF(pfinfo, status.syncookies_mode), SFS(pfinfo, status.ifname),
	SFA(pfinfo, status.pf_chksum), SF(pfinfo, wats.hiwat),
	SF(pfinfo, wats.lowat),
};

#define G(w, s, f, n, ...) \
	{ w, #f "_stats", { __VA_ARGS__ }, n, ENOPROTOOPT, sizeof(struct s), \
	    f##_fields, nitems(f##_fields), stats_sysctl, f##_print }

static struct statgroup groups[] = {
	G("ip", ipstat, ip, 4, CTL_NET, AF_INET, IPPROTO_IP, IPCTL_STATS),
	G("ah", ahstat, ah, 4, CTL_NET, AF_INET, IPPROTO_AH, AHCTL_STATS),
	G("esp", espstat, esp, 4, CTL_NET, AF_INET, IPPROTO_ESP, ESPCTL_STATS),
	G("tcp", tcpstat, tcp, 4, CTL_NET, AF_INET, IPPROTO_TCP, TCPCTL_STATS),
	G("udp", udpstat, udp, 4, CTL_NET, AF_INET, IPPROTO_UDP, UDPCTL_STATS),
	G("icmp", icmpstat, icmp, 4,
	    CTL_NET, AF_INET, IPPROTO_ICMP, ICMPCTL_STATS),
	G("igmp", igmpstat, igmp, 4,
	    CTL_NET, AF_INET, IPPROTO_IGMP, IGMPCTL_STATS),
	G("ipip", ipipstat, ipip, 4,
	    CTL_NET, AF_INET, IPPROTO_IPIP, IPIPCTL_STATS),
	G("carp", carpstats, carp, 4,
	    CTL_NET, AF_INET, IPPROTO_CARP, CARPCTL_STATS),
	G("pfsync", pfsyncstats, pfsync, 4,
	    CTL_NET, AF_INET, IPPROTO_PFSYNC, PFSYNCCTL_STATS),
	G("ipcomp", ipcompstat, ipcomp, 4,
	    CTL_NET, AF_INET, IPPROTO_IPCOMP, IPCOMPCTL_STATS),
	/* routing always says why it failed */
	{ "route", "rt_stats", { CTL_NET, PF_ROUTE, 0, 0, NET_RT_STATS, 0 },
	    6, 0, sizeof(struct rtstat), rt_fields, nitems(rt_fields),
	    stats_sysctl, rt_print },
	{ "mbuf", "mbpr", { 0 }, 0, 0, sizeof(struct mbinfo), mb_fields,
	    nitems(mb_fields), mb_get, mb_print },
	{ "pf", "pf_stats", { 0 }, 0, 0, sizeof(struct pfinfo), pf_fields,
	    nitems(pf_fields), pf_get, pf_print, 1 },
};

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

/* each group's kind, its fields one per member, or per element */
void
stats_facts_init(void)
{
	struct statgroup	*g;
	struct facts_field	*ff;
	size_t			 i, j, n, total;
	char			*s;

	for (g = groups; g < groups + nitems(groups); g++) {
		for (total = 0, i = 0; i < g->nf; i++)
			total += g->f[i].n;
		ff = calloc(total, sizeof(*ff));
		g->off = calloc(total, sizeof(*g->off));
		g->sz = calloc(total, sizeof(*g->sz));
		if (ff == NULL || g->off == NULL || g->sz == NULL)
			continue;
		for (n = 0, i = 0; i < g->nf; i++)
			for (j = 0; j < g->f[i].n; j++) {
				if (g->f[i].n == 1)
					ff[n].name = g->f[i].name;
				else if (asprintf(&s, "%s[%zu]", g->f[i].name,
				    j) == -1)
					continue;
				else
					ff[n].name = s;
				ff[n].type = g->f[i].string ? FACT_STRING :
				    FACT_U64;
				g->off[n] = g->f[i].off + j * g->f[i].size;
				g->sz[n++] = g->f[i].size;
			}
		if (n != total || asprintf(&s, "%s-statistics", g->word) == -1)
			continue;
		g->kind.name = s;
		g->kind.fields = ff;
		g->kind.nfields = n;
	}
}

struct statgroup *
stats_group(const char *word)
{
	struct statgroup	*g;

	for (g = groups; g < groups + nitems(groups); g++)
		if (g->kind.name != NULL && strcmp(g->word, word) == 0)
			return (g);
	return (NULL);
}

/* who may answer for g */
int
stats_where(struct statgroup *g)
{
	return (g->root ? FACTS_SYSTEM : FACTS_SHOW);
}

const struct facts_kind *
stats_kind(const char *name)
{
	struct statgroup	*g;

	for (g = groups; g < groups + nitems(groups); g++)
		if (g->kind.name != NULL && strcmp(g->kind.name, name) == 0)
			return (&g->kind);
	return (NULL);
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

static void
member_put(char *p, size_t size, uint64_t u64)
{
	uint8_t		 u8 = u64;
	uint16_t	 u16 = u64;
	uint32_t	 u32 = u64;

	switch (size) {
	case 1:
		memcpy(p, &u8, size);
		break;
	case 2:
		memcpy(p, &u16, size);
		break;
	case 4:
		memcpy(p, &u32, size);
		break;
	case 8:
		memcpy(p, &u64, size);
	}
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
	if ((r = g->get(g, p)) == 0) {
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

/* a group's record, printed as nsh printed its structure */
void
stats_render(struct frec *r)
{
	struct statgroup	*g;
	char			*p;
	size_t			 i;

	for (g = groups; g < groups + nitems(groups); g++)
		if (r->k == &g->kind)
			break;
	if (g == groups + nitems(groups) || (p = calloc(1, g->size)) == NULL)
		return;
	for (i = 0; i < g->kind.nfields; i++) {
		if (g->kind.fields[i].type != FACT_STRING)
			member_put(p + g->off[i], g->sz[i], fu(r, i, 0));
		else if (fs(r, i) != NULL)
			strlcpy(p + g->off[i], fs(r, i), g->sz[i]);
	}
	g->print(p);
	free(p);
}
