/* $nsh $ */

/* From: $OpenBSD: wicontrol.c,v 1.44 2002/12/12 04:21:18 deraadt Exp $ */

/*
 * Copyright (c) 1997, 1998, 1999
 *      Bill Paul <wpaul@ctr.columbia.edu>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 *      $FreeBSD: wicontrol.c,v 1.6 1999/05/22 16:12:49 wpaul Exp $
 */

#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_ieee80211.h>

#include <dev/ic/if_wi_ieee.h>
#include <dev/ic/if_wireg.h>
#include <dev/ic/if_wi_hostap.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include "externs.h"

int wi_getval(char *, struct wi_req *);
int wi_setval(char *, struct wi_req *);
int wi_porttype(char *);
int wi_printlevels(char *);
int wi_printaplist(char *);
void wi_dumpstats(char *);
void wi_dumpstations(char *);
void wi_printwords(struct wi_req *);
void wi_printbool(struct wi_req *);

int
wi_getval(char *iface, struct wi_req * wreq)
{
	struct ifreq    ifr;
	int             s;

	bzero((char *) &ifr, sizeof(ifr));

	strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t) wreq;

	s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s == -1) {
		printf("%% wi_getval: socket: %s\n", strerror(errno));
		return(-1);
	}

	if (ioctl(s, SIOCGWAVELAN, &ifr) == -1) {
		printf("%% wi_getval: SIOCGWAVELAN: %s\n", strerror(errno));
		close(s);
		return(-1);
	}

	close(s);
	return(0);
}

int
wi_setval(char *iface, struct wi_req * wreq)
{
	struct ifreq    ifr;
	int             s;

	bzero((char *) &ifr, sizeof(ifr));

	strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t) wreq;

	s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s == -1) {
		printf("%% wi_setval: socket: %s\n", strerror(errno));
		return(-1);
	}

	if (ioctl(s, SIOCSWAVELAN, &ifr) == -1) {
		printf("%% wi_setval: SIOCSWAVELAN: %s\n", strerror(errno));
		close(s);
		return(-1);
	}

	close(s);
	return(0);
}

int
wi_printaplist(char *iface)
{
	int prism2, len, i = 0, j, s, flags, nap;
	struct wi_req   wreq;
	struct wi_scan_p2_hdr *wi_p2_h;
	struct wi_scan_res *res;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		printf("wi_printaplist: socket: %s\n", strerror(errno));
		return(-1);
	}

	if (!is_wavelan(s, iface)) {
		if (!is_valid_ifname(iface))
			printf("%% Not a valid interface: %s\n", iface);
		else
			printf("%% Interface not compatible with this"
			    " function: %s\n", iface);
		close(s);
		return(-1);
	}

	if (wi_porttype(iface) != WI_PORT_BSS) {
		printf("%% Interface must be in BSS (infrastructure) mode to"
		    " use this function\n");
		close(s);
		return(-1);
	}

	flags = get_ifflags(iface, s);
	if ((flags & IFF_UP) == 0)
		flags = set_ifflags(iface, s, flags | IFF_UP);

	/* first determine whether this is a prism2 card or not */
	wreq.wi_len = WI_MAX_DATALEN;
	wreq.wi_type = WI_RID_PRISM2;

	if (wi_getval(iface, &wreq) != 0) {
		close(s);
		return(-1);
	}
	prism2 = wreq.wi_val[0];

	/* send out a scan request */
	wreq.wi_len = prism2 ? 3 : 1;
	wreq.wi_type = WI_RID_SCAN_REQ;

	if (prism2) {
		wreq.wi_val[0] = 0x3FFF;
		wreq.wi_val[1] = 0x000F;
	}
	if (wi_setval(iface, &wreq) != 0) {
		close(s);
		return(-1);
	}

	/*
         * sleep for 200 milliseconds so there's enough time for the card
         * to respond... prism2's take a little longer.
         */
	usleep(prism2 ? 700000 : 200000);

	/* get the scan results */
	wreq.wi_len = WI_MAX_DATALEN;
	wreq.wi_type = WI_RID_SCAN_RES;

	if (wi_getval(iface, &wreq) != 0) {
		close(s);
		return(-1);
	}

	if (prism2) {
		wi_p2_h = (struct wi_scan_p2_hdr *) wreq.wi_val;

		/* if the reason is 0, this info is invalid */
		if (wi_p2_h->wi_reason == 0)
			return(-1);

		i = 4;
	}
	len = prism2 ? WI_PRISM2_RES_SIZE : WI_WAVELAN_RES_SIZE;

	if (i >= (wreq.wi_len * 2) - len)
		printf("%% No access point detected or link busy\n");
	else
		printf("%% AP Information:\n");

	for (nap = 0; i < (wreq.wi_len * 2) - len; i += len) {
		res = (struct wi_scan_res *) ((char *) wreq.wi_val + i);

		res->wi_ssid[letoh16(res->wi_ssid_len)] = '\0';
		res->wi_chan = letoh16(res->wi_chan);
		res->wi_noise = letoh16(res->wi_noise);
		res->wi_signal = letoh16(res->wi_signal);
		res->wi_interval = letoh16(res->wi_interval);
		res->wi_capinfo = letoh16(res->wi_capinfo);

		printf("ap[%d]:", nap++);
		printf("\tnetname (SSID):\t\t\t[ %s ]\n", res->wi_ssid);
		printf("\tBSSID:\t\t\t\t[ %02x:%02x:%02x:%02x:%02x:%02x ]\n",
		    res->wi_bssid[0], res->wi_bssid[1],
		    res->wi_bssid[2], res->wi_bssid[3],
		    res->wi_bssid[4], res->wi_bssid[5]);
		printf("\tChannel:\t\t\t[ %d ]\n", res->wi_chan);
		printf("\tBeacon Interval:\t\t[ %d ]\n", res->wi_interval);
		printf("\tQuality/Signal/Noise [signal]:\t[ %d / %d / %d ]\n",
		       res->wi_signal - res->wi_noise, res->wi_signal,
		       res->wi_noise);
		if (!prism2)
			printf("\t\t\t\t[dBm]:\t[ %d / %d / %d ]\n",
			       res->wi_signal - res->wi_noise,
			       res->wi_signal - 149, res->wi_noise - 149);

		if (res->wi_capinfo) {
			printf("\tCapinfo:\t\t\t[ ");
			if (res->wi_capinfo & WI_CAPINFO_ESS)
				printf("ESS ");
			if (res->wi_capinfo & WI_CAPINFO_IBSS)
				printf("IBSS ");
			if (res->wi_capinfo & WI_CAPINFO_PRIV)
				printf("PRIV ");
			printf("]\n");
		}
		if (prism2) {
			printf("\tDataRate [Mbps]:\t\t[ %2.1f ]\n",
			       res->wi_rate == 0xa ? 1 :
			       (res->wi_rate == 0x14 ? 2 :
				(res->wi_rate == 0x37 ? 5.5 :
				 (res->wi_rate == 0x6e ? 11 : 0))));

			printf("\tAvailableRates [Mbps]:\t\t[ ");
			for (j = 0; res->wi_srates[j] != 0; j++) {
				res->wi_srates[j] = res->wi_srates[j] &
					WI_VAR_SRATES_MASK;
				printf("%d.%d ", res->wi_srates[j] / 2,
				       (res->wi_srates[j] % 2) * 5);
			}
			printf("]\n");
		}
	}
	set_ifflags(iface, s, flags);
	close(s);
	return(0);
}

void
wi_dumpstats(char *iface)
{
	struct wi_req   wreq;
	struct wi_counters *c;

	bzero((char *) &wreq, sizeof(wreq));
	wreq.wi_len = WI_MAX_DATALEN;
	wreq.wi_type = WI_RID_IFACE_STATS;

	if (wi_getval(iface, &wreq) != 0)
		return;

	c = (struct wi_counters *) & wreq.wi_val;

	/* XXX native byte order */
	printf("  TX:\n");
	printf("   %u unicast frames,", c->wi_tx_unicast_frames);
	printf(" %u multicast frames,", c->wi_tx_multicast_frames);
	printf(" %u fragments\n", c->wi_tx_fragments);
	printf("   %u unicast octets,", c->wi_tx_unicast_octets);
	printf(" %u multicast octets,", c->wi_tx_multicast_octets);
	printf(" %u single retries\n", c->wi_tx_single_retries);
	printf("   %u multiple retries,", c->wi_tx_multi_retries);
	printf(" %u retry lim exceed,", c->wi_tx_retry_limit);
	printf(" %u discards,", c->wi_tx_discards);
	printf(" %u wrong SA\n", c->wi_tx_discards_wrong_sa);

	printf("  RX:\n");
	printf("   %u unicast frames,", c->wi_rx_unicast_frames);
	printf(" %u multicast frames,", c->wi_rx_multicast_frames);
	printf(" %u fragments\n", c->wi_rx_fragments);
	printf("   %u unicast octets,", c->wi_rx_unicast_octets);
	printf(" %u multicast octets,", c->wi_rx_multicast_octets);
	printf(" %u FCS errors\n", c->wi_rx_fcs_errors);
	printf("   %u discards,", c->wi_rx_discards_nobuf);
	printf(" %u WEP decrypt fail,", c->wi_rx_WEP_cant_decrypt);
	printf(" %u msg frag,", c->wi_rx_msg_in_msg_frags);
	printf(" %u msg bad frag\n", c->wi_rx_msg_in_bad_msg_frags);
}

void
wi_dumpstations(char *iface)
{
	struct hostap_getall reqall;
	struct hostap_sta stas[WIHAP_MAX_STATIONS];
	struct ifreq    ifr;
	int             i, s;

	if (wi_porttype(iface) != WI_PORT_HOSTAP) {
#ifdef userfunction
		printf("%% Interface must be in Access Point mode to use this"
		    " function\n");
#endif
		return;
	}

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t) & reqall;
	bzero(&reqall, sizeof(reqall));
	reqall.size = sizeof(stas);
	reqall.addr = stas;
	bzero(&stas, sizeof(stas));

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		printf("%% wi_dumpstations: socket: %s\n", strerror(errno));
		return;
	}

	if (ioctl(s, SIOCHOSTAP_GETALL, &ifr) < 0) {
		printf("%% wi_dumpstations: SIOCHOSTAP_GETALL: %s\n",
		    strerror(errno));
		close(s);
		return;
	}

	printf("  %d associated station%s%s\n", reqall.nstations,
	    reqall.nstations != 1 ? "s" : "",
	    reqall.nstations == 0 ? "" : ":");
	for (i = 0; i < reqall.nstations; i++) {
		struct hostap_sta *info = &stas[i];

		printf("   %02x:%02x:%02x:%02x:%02x:%02x  asid=%04x",
		       info->addr[0], info->addr[1], info->addr[2],
		       info->addr[3], info->addr[4], info->addr[5],
		       info->asid - 0xc001);

		printf(", flags");
		bprintf(stdout, info->flags, HOSTAP_FLAGS_BITS);
		printf(", caps");
		bprintf(stdout, info->capinfo, IEEE80211_CAPINFO_BITS);
		printf(", rates");
		bprintf(stdout, info->rates, WI_RATES_BITS);

		if (info->sig_info)
			printf(", sig=%d/%d",
			       info->sig_info >> 8, info->sig_info & 0xff);
		putchar('\n');
	}

	close(s);
	return;
}

void
wi_printwords(struct wi_req *wreq)
{
	int i;   

	printf("[ ");
	for (i = 0; i < wreq->wi_len - 1; i++)
		printf("%d ", letoh16(wreq->wi_val[i]));
	printf("]");
}

void 
wi_printbool(struct wi_req *wreq)
{
	if (letoh16(wreq->wi_val[0]))
		printf("[ On ]");
	else
		printf("[ Off ]");
}

/*
void
wi_printcardid(struct wi_req *wreq, u_int16_t chip_id)
{
	const char *chip_name;
	const struct wi_card_ident *id;

	if (wreq->wi_len < 4)
		return;

	for (id = wi_card_ident; id->firm_type != WI_NOTYPE; id++) {
		if (chip_id == id->card_id)
			break;
	}
	if (id->firm_type != WI_NOTYPE)
		chip_name = id->card_name;
	else {
		if (chip_id & htole16(0x8000))
			chip_name = "Unknown PRISM chip";
		else
			chip_name = "Unknown Lucent chip";
	}
  
*/
	/* XXX - doesn't decode Symbol firmware */
/*
	if (chip_id & htole16(0x8000))
		printf("[ %s, Firmware %d.%d.%d ]", chip_name,
		    letoh16(wreq->wi_val[2]), letoh16(wreq->wi_val[3]),
		    letoh16(wreq->wi_val[1]));
	else
		printf("[ %s, Firmware %d.%d variant %d ]", chip_name,
		    letoh16(wreq->wi_val[2]), letoh16(wreq->wi_val[3]),
		    letoh16(wreq->wi_val[1]));
}
*/

int
wi_porttype(char *iface)
{
	struct wi_req wreq;

	bzero((char *)&wreq, sizeof(wreq));
	wreq.wi_type = WI_RID_PORTTYPE;
	wreq.wi_len = 2;
	if (wi_getval(iface, &wreq) != 0)
		return(-1);

	return(letoh16(wreq.wi_val[0]));
}

int
wi_printlevels(char *iface)
{
	struct wi_req wreq;
	int quality, signal, noise;

	bzero((char *)&wreq, sizeof(wreq));
	wreq.wi_type = WI_RID_COMMS_QUALITY;
	wreq.wi_len = WI_MAX_DATALEN;
	if (wi_getval(iface, &wreq) != 0)
		return(-1);

	quality = letoh16(wreq.wi_val[0]);
	signal = letoh16(wreq.wi_val[1]);
	noise = letoh16(wreq.wi_val[2]);

	/*
	 * Some cards will report the Prism chip's initial values of
	 * 0/81/27 or 0/27/27 when the MAC port is not enabled.
	 * (This may reflect a driver issue?)
	 *
	 * Never the less, don't try and confuse the user with strange
	 * data.
	 */
	if (quality == 0 && noise == 27) {
		signal = 0;
		noise = 0;
	}

	printf("%i/%i/%i", quality, signal, noise);

	return(0);
}

/* A serious abuse of ioctl, ifreq, and wi_req */
int
is_wavelan(int s, char *iface)
{
	struct ifreq ifr;
	struct wi_req wreq;

	bzero((char *) &ifr, sizeof(ifr));
	bzero((char *) &wreq, sizeof(wreq));

	strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t) &wreq;
	
	if (ioctl(s, SIOCGWAVELAN, &ifr) == -1)
		return 0;
	else
		return 1;
}
