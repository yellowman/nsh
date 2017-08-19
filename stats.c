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
#include <errno.h>

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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "externs.h"

static int sflag = 1;

#define YES     1
typedef int bool;

struct  mbstat mbstat;
struct kinfo_pool mbpool, mclpool;

char	*inet6name(struct in6_addr *);
void	inet6print(struct in6_addr *, int, char *, int);

/*
 * Dump TCP statistics structure.
 */
void
tcp_stats()
{
	struct tcpstat tcpstat;
	int mib[] = { CTL_NET, AF_INET, IPPROTO_TCP, TCPCTL_STATS };
	size_t len = sizeof(tcpstat);

	if (sysctl(mib, nitems(mib), &tcpstat, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% tcp_stats: sysctl: %s\n",strerror(errno));
		return;
	}

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
void
udp_stats()
{
	struct udpstat udpstat;
	u_long delivered;
	int mib[] = { CTL_NET, AF_INET, IPPROTO_UDP, UDPCTL_STATS };
	size_t len = sizeof(udpstat);

	if (sysctl(mib, nitems(mib), &udpstat, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% udp_stats: sysctl: %s\n",strerror(errno));
		return;
	}

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
void
ip_stats()
{
	struct ipstat ipstat;
	int mib[] = { CTL_NET, AF_INET, IPPROTO_IP, IPCTL_STATS };
	size_t len = sizeof(ipstat);

	if (sysctl(mib, nitems(mib), &ipstat, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% ip_stats: sysctl: %s\n",strerror(errno));
		return;
	}

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
void
icmp_stats()
{
	struct icmpstat icmpstat;
	int i, first;
	int mib[] = { CTL_NET, AF_INET, IPPROTO_ICMP, ICMPCTL_STATS };
	size_t len = sizeof(icmpstat);

	if (sysctl(mib, nitems(mib), &icmpstat, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% icmp_stats: sysctl: %s\n",strerror(errno));
		return;
	}

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
void
igmp_stats()
{
	struct igmpstat igmpstat;
	int mib[] = { CTL_NET, AF_INET, IPPROTO_IGMP, IGMPCTL_STATS };
	size_t len = sizeof(igmpstat);

	if (sysctl(mib, nitems(mib), &igmpstat, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% igmp_stats: sysctl: %s\n",strerror(errno));
		return;
	}

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
void
ah_stats()
{
	struct ahstat ahstat;
	int mib[] = { CTL_NET, AF_INET, IPPROTO_AH, AHCTL_STATS };
	size_t len = sizeof(ahstat);

	if (sysctl(mib, nitems(mib), &ahstat, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% ah_stats: sysctl: %s\n",strerror(errno));
                return;
        }

	printf("%% ah:\n");

#define p(f, m) if (ahstat.f || sflag <= 1) \
    printf(m, ahstat.f, plural(ahstat.f))
#define p1(f, m) if (ahstat.f || sflag <= 1) \
    printf(m, ahstat.f)

	p1(ahs_input, "\t%u input AH packets\n");
	p1(ahs_output, "\t%u output AH packets\n");
	p(ahs_nopf, "\t%u packet%s from unsupported protocol families\n");
	p(ahs_hdrops, "\t%u packet%s shorter than header shows\n");
	p(ahs_pdrops, "\t%u packet%s dropped due to policy\n");
	p(ahs_notdb, "\t%u packet%s for which no TDB was found\n");
	p(ahs_badkcr, "\t%u input packet%s that failed to be processed\n");
	p(ahs_badauth, "\t%u packet%s that failed verification received\n");
	p(ahs_noxform, "\t%u packet%s for which no XFORM was set in TDB received\n");
	p(ahs_qfull, "\t%u packet%s were dropped due to full output queue\n");
	p(ahs_wrap, "\t%u packet%s where counter wrapping was detected\n");
	p(ahs_replay, "\t%u possibly replayed packet%s received\n");
	p(ahs_badauthl, "\t%u packet%s with bad authenticator length received\n");
	p(ahs_invalid, "\t%u packet%s attempted to use an invalid tdb\n");
	p(ahs_toobig, "\t%u packet%s got larger than max IP packet size\n");
	p(ahs_crypto, "\t%u packet%s that failed crypto processing\n");
	p(ahs_ibytes, "\t%qu input byte%s\n");
	p(ahs_obytes, "\t%qu output byte%s\n");

#undef p
#undef p1
}

/*
 * Dump ESP statistics structure.
 */
void
esp_stats()
{
	struct espstat espstat;
	int mib[] = { CTL_NET, AF_INET, IPPROTO_ESP, ESPCTL_STATS };
	size_t len = sizeof(espstat);

	if (sysctl(mib, nitems(mib), &espstat, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% esp_stats: sysctl: %s\n",strerror(errno));
		return;
	}

	printf("%% esp:\n");

#define p(f, m) if (espstat.f || sflag <= 1) \
    printf(m, espstat.f, plural(espstat.f))

	p(esps_input, "\t%u input ESP packet%s\n");
	p(esps_output, "\t%u output ESP packet%s\n");
	p(esps_nopf, "\t%u packet%s from unsupported protocol families\n");
	p(esps_hdrops, "\t%u packet%s shorter than header shows\n");
	p(esps_pdrops, "\t%u packet%s dropped due to policy\n");
	p(esps_notdb, "\t%u packet%s for which no TDB was found\n");
	p(esps_badkcr, "\t%u input packet%s that failed to be processed\n");
	p(esps_badenc, "\t%u packet%s with bad encryption received\n");
	p(esps_badauth, "\t%u packet%s that failed verification received\n");
	p(esps_noxform, "\t%u packet%s for which no XFORM was set in TDB received\n");
	p(esps_qfull, "\t%u packet%s were dropped due to full output queue\n");
	p(esps_wrap, "\t%u packet%s where counter wrapping was detected\n");
	p(esps_replay, "\t%u possibly replayed packet%s received\n");
	p(esps_badilen, "\t%u packet%s with bad payload size or padding received\n");
	p(esps_invalid, "\t%u packet%s attempted to use an invalid tdb\n");
	p(esps_toobig, "\t%u packet%s got larger than max IP packet size\n");
	p(esps_crypto, "\t%u packet%s that failed crypto processing\n");
	p(esps_udpencin, "\t%u input UDP encapsulated ESP packet%s\n");
	p(esps_udpencout, "\t%u output UDP encapsulated ESP packet%s\n");
	p(esps_udpinval, "\t%u UDP packet%s for non-encapsulating TDB received\n");
	p(esps_ibytes, "\t%qu input byte%s\n");
	p(esps_obytes, "\t%qu output byte%s\n");

#undef p
}

/*
 * Dump IP-in-IP statistics structure.
 */
void
ipip_stats()
{
	struct ipipstat ipipstat;
	int mib[] = { CTL_NET, AF_INET, IPPROTO_IPIP, IPIPCTL_STATS };
	size_t len = sizeof(ipipstat);

	if (sysctl(mib, nitems(mib), &ipipstat, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% ipip_stats: sysctl: %s\n",strerror(errno));
		return;
	}
	
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
void
carp_stats()
{
	struct carpstats carpstat;
	int mib[] = { CTL_NET, AF_INET, IPPROTO_CARP, CARPCTL_STATS };
	size_t len = sizeof(carpstat);

	if (sysctl(mib, nitems(mib), &carpstat, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% carp_stats: sysctl: %s\n",strerror(errno));
		return;
	}

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
void
pfsync_stats()
{
	struct pfsyncstats pfsyncstat;
	int mib[] = { CTL_NET, AF_INET, IPPROTO_PFSYNC, PFSYNCCTL_STATS };
	size_t len = sizeof(pfsyncstat);

	if (sysctl(mib, nitems(mib), &pfsyncstat, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% pfsync_stats: sysctl: %s\n",strerror(errno));
		return;
	}

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
void
ipcomp_stats()
{
	struct ipcompstat ipcompstat;
	int mib[] = { CTL_NET, AF_INET, IPPROTO_IPCOMP, IPCOMPCTL_STATS };
	size_t len = sizeof(ipcompstat);

	if (sysctl(mib, nitems(mib), &ipcompstat, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			printf("%% ipcomp_stats: sysctl: %s\n",strerror(errno));
		return;
	}

	printf("%% ipcomp:\n");

#define p(f, m) if (ipcompstat.f || sflag <= 1) \
    printf(m, ipcompstat.f, plural(ipcompstat.f))

	p(ipcomps_input, "\t%u input IPCOMP packet%s\n");
	p(ipcomps_output, "\t%u output IPCOMP packet%s\n");
	p(ipcomps_nopf, "\t%u packet%s from unsupported protocol families\n");
	p(ipcomps_hdrops, "\t%u packet%s shorter than header shows\n");
	p(ipcomps_pdrops, "\t%u packet%s dropped due to policy\n");
	p(ipcomps_notdb, "\t%u packet%s for which no TDB was found\n");
	p(ipcomps_badkcr, "\t%u input packet%s that failed to be processed\n");
	p(ipcomps_noxform, "\t%u packet%s for which no XFORM was set in TDB received\n");
	p(ipcomps_qfull, "\t%u packet%s were dropped due to full output queue\n");
	p(ipcomps_wrap, "\t%u packet%s where counter wrapping was detected\n");
	p(ipcomps_invalid, "\t%u packet%s attempted to use an invalid tdb\n");
	p(ipcomps_toobig, "\t%u packet%s got larger than max IP packet size\n");
	p(ipcomps_crypto, "\t%u packet%s that failed (de)compression processing\n");
	p(ipcomps_minlen, "\t%u packet%s less than minimum compression length\n");
	p(ipcomps_ibytes, "\t%qu input byte%s\n");
	p(ipcomps_obytes, "\t%qu output byte%s\n");

#undef p
}

/*
 * Print routing statistics
 */
void
rt_stats()
{
	struct rtstat rtstat;
 	int mib[] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_STATS, 0 };
 	size_t size = sizeof (rtstat);
 
	if (sysctl(mib, nitems(mib), &rtstat, &size, NULL, 0) < 0) {
		printf("%% rt_stats: sysctl: %s\n", strerror(errno));
		return;
	}
 
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

/*
 * Print mbuf statistics.
 */
void
mbpr(void)
{
	int totmem, totused, totmbufs, totpct;
	int i, mib[4], npools, flag = 0;
	bool seen[256];
	struct kinfo_pool pool;
	struct mbtypes *mp;
	size_t size;
	int page_size = getpagesize();
	int nmbtypes = sizeof(mbstat.m_mtypes) / sizeof(short);

	memset(&seen, 0, sizeof(seen));

	if (nmbtypes != 256) {
		printf("%% mbpr: unexpected change to mbstat; check source\n");
		return;
	}

	mib[0] = CTL_KERN;
	mib[1] = KERN_MBSTAT;
	size = sizeof(mbstat);

	if (sysctl(mib, 2, &mbstat, &size, NULL, 0) < 0) {
		printf("%% mbpr: sysctl mbstat: %s\n", strerror(errno));
		return;
	}

	mib[0] = CTL_KERN;
	mib[1] = KERN_POOL;
	mib[2] = KERN_POOL_NPOOLS;
	size = sizeof(npools);

	if (sysctl(mib, 3, &npools, &size, NULL, 0) < 0) {
		printf("%% mbpr: sysctl npools: %s\n", strerror(errno));
		return;
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
			return;
		}
		npools--;
		mib[2] = KERN_POOL_NAME;
		size = sizeof(name);
		if (sysctl(mib, 4, &name, &size, NULL, 0) < 0) {
			printf("%% mbpr: sysctl pool name: %s\n",
			    strerror(errno));
			return;
		}

		if (!strncmp(name, "mbpl", strlen("mbpl"))) {
			bcopy(&pool, &mbpool, sizeof(struct kinfo_pool));
			flag++;
		} else {
			if (!strncmp(name, "mclpl", strlen("mclpl"))) {
				bcopy(&pool, &mclpool,
				    sizeof(struct kinfo_pool));
				flag++;
			}
		}

		if (flag == 2)
			break;
	}

	totmbufs = 0;
	for (mp = mbtypes; mp->mt_name; mp++)
		totmbufs += mbstat.m_mtypes[mp->mt_type];
	printf("\t%u mbuf%s in use:\n", totmbufs, plural(totmbufs));
	for (mp = mbtypes; mp->mt_name; mp++)
		if (mbstat.m_mtypes[mp->mt_type]) {
			seen[mp->mt_type] = YES;
			printf("\t\t%u mbuf%s allocated to %s\n",
			    mbstat.m_mtypes[mp->mt_type],
			    plural((int)mbstat.m_mtypes[mp->mt_type]),
			    mp->mt_name);
		}
	seen[MT_FREE] = YES;
	for (i = 0; i < nmbtypes; i++)
		if (!seen[i] && mbstat.m_mtypes[i]) {
			printf("\t\t%u mbuf%s allocated to <mbuf type %d>\n",
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
	printf("\t%u Kbytes allocated to network (%d%% in use)\n",
	    totmem / 1024, totpct);
	printf("\t%lu requests for memory denied\n", mbstat.m_drops);
	printf("\t%lu requests for memory delayed\n", mbstat.m_wait);
	printf("\t%lu calls to protocol drain routines\n", mbstat.m_drain);
}
