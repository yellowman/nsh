/* From: $OpenBSD: /usr/src/sbin/ifconfig/ifconfig.c,v 1.68 2002/06/19 18:53:53 millert Exp $ */
/*
 * Copyright (c) 1983, 1993
 *      The Regents of the University of California.  All rights reserved.
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

/*-
 * Copyright (c) 1997, 1998, 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/limits.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include "stringlist.h"
#include "externs.h"
#include "settings.h"
#include "kernel.h"

static int cand_80211(char *, char *);
static void nwkey_str(char *, size_t, char *);
static int cand_nwkey(char *, struct ieee80211_nwkey *, char *);
static int cand_txpower(char *, int);

const char *
get_string(const char *val, const char *sep, u_int8_t *buf, int *lenp)
{
	int len;
	int hexstr;
	u_int8_t *p;

	len = *lenp;
	p = buf;
	hexstr = (val[0] == '0' && tolower((unsigned char)val[1]) == 'x');
	if (hexstr)
		val += 2;
	for (;;) {
		if (*val == '\0')
			break;
		if (sep != NULL && strchr(sep, *val) != NULL) {
			val++;
			break;
		}
		if (hexstr) {
			if (!isxdigit((unsigned char)val[0]) ||
			    !isxdigit((unsigned char)val[1])) {
				printf("%% get_string: bad hexadecimal digits\n");
				return NULL;
			}
		}
		if (p >= buf + len) {
			if (hexstr)
				printf("%% get_string: hexadecimal digits too long\n");
			else
				printf("%% get_string: strings too long\n");
			return NULL;
		}
		if (hexstr) {
#define tohex(x)        (isdigit((unsigned char)(x)) ? (x) - '0' : \
			    tolower((unsigned char)(x)) - 'a' + 10)
			*p++ = (tohex(val[0]) << 4) | tohex(val[1]);
#undef tohex
			val += 2;
		} else {
			if (*val == '\\' &&
			    sep != NULL && strchr(sep, *(val + 1)) != NULL)
				val++;
			*p++ = *val++;
		}
	}
	len = p - buf;
	if (len < *lenp)
		memset(p, 0, *lenp - len);
	*lenp = len;
	return val;
}

/* was print_string() */
void
make_string(char *str, int str_len, const u_int8_t *buf, int buf_len)
{
	int i;
	int hasspc;
	char tmp[128];

	str_len--;
	i = 0;
	hasspc = 0;
	if (buf_len < 2 || buf[0] != '0' ||
	    tolower((unsigned char)buf[1]) != 'x') {
		for (; i < buf_len; i++) {
			/* Only print 7-bit ASCII keys */
			if (buf[i] & 0x80 ||
			    !isprint((unsigned char)buf[i]))
				break;
			if (isspace((unsigned char)buf[i]))
				hasspc++;
		}
	}
	if (i == buf_len) {
		if (hasspc || buf_len == 0)
			snprintf(str, str_len, "\"%.*s\"", buf_len, buf);
		else
			snprintf(str, str_len, "%.*s", buf_len, buf);
	} else {
		snprintf(str, str_len, "0x");
		for (i = 0; i < buf_len; i++) {
			snprintf(tmp, sizeof(tmp), "%02x", buf[i]);
			strlcat(str, tmp, str_len);
		}
	}
}

/* was setifnwkey() */
int
intnwkey(int argc, char **argv, ...)
{
	int i, len, set;
	char *val = NULL;
	struct ieee80211_nwkey nwkey;
	u_int8_t keybuf[IEEE80211_WEP_NKID][16];
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;
	argc--;
	argv++;

	if((!set && argc > 1) || (set && argc != 1)) {
		printf("%% nwkey <key>\n");
		printf("%% nwkey persist\n");
		printf("%% nwkey persist:<key>\n");
		printf("%% nwkey <n>:<k1>,<k2>,<k3>,<k4>\n");
		printf("%% no nwkey [key]\n");
		return 0;
	}
	if(set)
		val = argv[0];

	nwkey.i_wepon = IEEE80211_NWKEY_WEP;
	nwkey.i_defkid = 1;
	if (!set) {
		/* disable WEP encryption */
		nwkey.i_wepon = 0;
		i = 0;
	} else if (strcasecmp("persist", val) == 0) {
		/* use all values from persistent memory */
		nwkey.i_wepon |= IEEE80211_NWKEY_PERSIST;
		nwkey.i_defkid = 0;
		for (i = 0; i < IEEE80211_WEP_NKID; i++)
			nwkey.i_key[i].i_keylen = -1;
	} else if (strncasecmp(val, "persist:", 8) == 0) {
		val += 8;
		/* program keys in persistent memory */
		nwkey.i_wepon |= IEEE80211_NWKEY_PERSIST;
		goto set_nwkey;
	} else {
set_nwkey:
		if (isdigit((unsigned char)val[0]) && val[1] == ':') {
			/* specifying a full set of four keys */
			nwkey.i_defkid = val[0] - '0';
			val += 2;
			for (i = 0; i < IEEE80211_WEP_NKID; i++) {
				len = sizeof(keybuf[i]);
				val = (char *)get_string(val, ",", keybuf[i], &len);
				if (val == NULL)
					return 0;
				nwkey.i_key[i].i_keylen = len;
				nwkey.i_key[i].i_keydat = keybuf[i];
			}
			if (*val != '\0') {
				printf("%% intnwkey: too many keys\n");
				return 0;
			}
		} else {
			len = sizeof(keybuf[i]);
			val = (char *)get_string(val, NULL, keybuf[0], &len);
			if (val == NULL)
				return 0;
			nwkey.i_key[0].i_keylen = len;
			nwkey.i_key[0].i_keydat = keybuf[0];
			i = 1;
		}
	}
	/* zero out any unset keys */
	for (; i < IEEE80211_WEP_NKID; i++) {
		nwkey.i_key[i].i_keylen = 0;
		nwkey.i_key[i].i_keydat = NULL;
	}
	if (candidate)
		return cand_nwkey(ifname, &nwkey, set ? argv[0] : NULL);
	(void) strlcpy(nwkey.i_name, ifname, sizeof(nwkey.i_name));
	if (ioctl(ifs, SIOCS80211NWKEY, (caddr_t)&nwkey) == -1) {
		printf("%% intnwkey: SIOCS80211NWKEY: %s\n", strerror(errno));
		return 0;
	}
	/* the kernel shows no key, so get_nwinfo() prints the one kept here */
	db_delete_flag_x_ctl("nwkey", ifname, 0);
	if (set)
		db_insert_flag_x("nwkey", ifname, 0, DB_X_ENABLE, argv[0]);
	return 0;
}

/*
 * mangled ieee80211_status()
 */
int
get_nwinfo(char *ifname, char *str, int str_len, int type)
{
	int ifs, len;

	ifs = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifs < 0) {
		printf("%% get_nwinfo: socket: %s\n", strerror(errno));
		return 0;
        }

	memset(str, 0, str_len);

	switch(type) {
	case NWID:
	{
		struct ieee80211_nwid nwid;
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_data = (caddr_t)&nwid;
		(void) strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(ifs, SIOCG80211NWID, (caddr_t) & ifr) == 0) {
			/* nwid.i_nwid is not NUL terminated. */
			len = nwid.i_len;
			if (len > IEEE80211_NWID_LEN)
				len = IEEE80211_NWID_LEN;
			make_string(str, str_len, nwid.i_nwid, len);
		}
	}
	break;
	case TXPOWER:
	{
		struct ieee80211_txpower txpower;

		memset(&txpower, 0, sizeof(txpower));
		(void) strlcpy(txpower.i_name, ifname, sizeof(txpower.i_name));
		if (ioctl(ifs, SIOCG80211TXPOWER, (caddr_t) &txpower) == 0) {
			/* XXX FIXED is always set? For now, check for == 100,
			   txpower is totally broken in the kernel anyways */
			if (txpower.i_mode == IEEE80211_TXPOWER_MODE_FIXED &&
			    txpower.i_val != 100)
				snprintf(str, str_len, "%d", txpower.i_val);
		} else {
			if (errno != EINVAL) {
				printf("%% get_nwinfo: SIOCG80211TXPOWER: %s\n",
				    strerror(errno));
			}
		}
	}
	break;
	case POWERSAVE:
	{
		struct ieee80211_power power;

		memset(&power, 0, sizeof(power));
		strlcpy(power.i_name, ifname, sizeof(power.i_name));

		if (ioctl(ifs, SIOCG80211POWER, &power) == 0) {
			if (power.i_enabled)
				snprintf(str, str_len, "%d", power.i_maxsleep);
		} else {
			printf("%% get_nwinfo: SIOCG80211POWER: %s\n",
			    strerror(errno));
		}
	}
	break;
	case BSSID:
	{
		struct ieee80211_bssid bssid;
		struct ether_addr ea;
		u_int8_t zero_bssid[IEEE80211_ADDR_LEN];

		memset(&zero_bssid, 0, sizeof(zero_bssid));
		strlcpy(bssid.i_name, ifname, sizeof(bssid.i_name));

		if (ioctl(ifs, SIOCG80211BSSID, &bssid) == 0) {
			if (memcmp(bssid.i_bssid, zero_bssid,
			    IEEE80211_ADDR_LEN) != 0) {
				memcpy(&ea.ether_addr_octet, bssid.i_bssid,
				    sizeof(ea.ether_addr_octet));
				snprintf(str, str_len, "%s", ether_ntoa(&ea));
			}
		} else {
			printf("%% get_nwinfo: SIOCG80211BSSID: %s\n",
			    strerror(errno));
		}
	}
	break;
	case NWKEY:
	{
		struct ieee80211_nwkey nwkey;
		StringList *key;

		memset(&nwkey, 0, sizeof(nwkey));
		(void) strlcpy(nwkey.i_name, ifname, sizeof(nwkey.i_name));
		if (ioctl(ifs, SIOCG80211NWKEY, (caddr_t) & nwkey) == 0 &&
		    nwkey.i_wepon > 0) {
			key = sl_init();
			if (db_select_flag_x_ctl(key, "nwkey", ifname) >= 0 &&
			    key->sl_cur > 0)
				nwkey_str(str, str_len, key->sl_str[0]);
			sl_free(key, 1);
		}
	}
	break;
	} /* switch {} */

	close(ifs);
	return strlen(str);
}

int
inttxpower(int argc, char **argv, ...)
{
	const char *errmsg = NULL;
	struct ieee80211_txpower txpower;
	short dbm, set;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	argv++;
	argc--;

	if ((set && argc != 1) || (!set && argc > 1)) {
		printf("%% txpower <dBm>\n");
		printf("%% no txpower     (auto-select)\n");
		return 0;
	}

	strlcpy(txpower.i_name, ifname, sizeof(txpower.i_name));
   
	if (!set) {
		txpower.i_val = 100;
		txpower.i_mode = IEEE80211_TXPOWER_MODE_AUTO;
	} else {
		dbm = strtonum(argv[0], SHRT_MIN, SHRT_MAX, &errmsg);
		if (errmsg) {
			printf("%% inttxpower: txpower %sdBm: %s\n", argv[0],
			    errmsg);
			return 0;
		}
		txpower.i_val = (int16_t)dbm;
		txpower.i_mode = IEEE80211_TXPOWER_MODE_FIXED;
	}

	if (candidate)
		return cand_txpower(ifname, txpower.i_val);

	if (ioctl(ifs, SIOCS80211TXPOWER, (caddr_t)&txpower) == -1)
		printf("%% inttxpower: SIOCS80211TXPOWER failed: %s\n",
		    strerror(errno));

	return 0;
}

int
intbssid(int argc, char **argv, ...)
{
	struct ieee80211_bssid bssid;
	struct ether_addr *ea;
	short set;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	if (NO_ARG(argv[0])) {
		set = 0;
		argv++;
		argc--;
	} else
		set = 1;

	argv++;
	argc--;

	if ((set && argc != 1) || (!set && argc > 1)) {
		printf("%% bssid <xx:xx:xx:xx:xx:xx>\n");
		printf("%% no bssid       (auto-select)\n");
		return 0;
	}

	if (set) {
		ea = ether_aton(argv[0]);
		if (ea == NULL) {
			printf("%% Invalid bssid\n");
			return 0;
		}
		memcpy(&bssid.i_bssid, ea->ether_addr_octet,
		    sizeof(bssid.i_bssid));
	} else
		memset(&bssid.i_bssid, 0, sizeof(bssid.i_bssid));

	strlcpy(bssid.i_name, ifname, sizeof(bssid.i_name));
	if (ioctl(ifs, SIOCS80211BSSID, &bssid) == -1) {
		printf("%% intbssid: SIOCS80211BSSID failed: %s\n",
		    strerror(errno));
	}

	return (0);
}

/*
 * Is name an 802.11 interface, in configure private? It is if
 * SIOCG80211NWID answers, as conf_ifmetrics() asks; if not, the
 * handler's error is what says so.
 */
static int
cand_80211(char *name, char *what)
{
	char tmp[IEEE80211_NWID_LEN * 2 + 8];

	if (get_nwinfo(name, tmp, sizeof(tmp), NWID) != 0)
		return 1;
	printf("%% %s: %s\n", what, strerror(ENOTTY));
	return 0;
}

/* A WEP key as intnwkey() kept it, quoted as makeargv() reads it back */
static void
nwkey_str(char *buf, size_t len, char *key)
{
	if (strpbrk(key, " \t") != NULL)
		snprintf(buf, len, "\"%s\"", key);
	else
		strlcpy(buf, key, len);
}

/*
 * nwid in configure private. SIOCS80211NWID turns WEP off, so the nwkey
 * line goes too.
 */
int
cand_nwid(char *ifname, u_int8_t *nwid, int len)
{
	char str[IEEE80211_NWID_LEN * 2 + 8];

	if (!cand_80211(ifname, "intnwid: SIOCS80211NWID"))
		return 0;
	make_string(str, sizeof(str), nwid, len);
	cand_setting(ST_ON, "nwid %s", str);
	return cand_setting(ST_DEFAULT, "nwkey");
}

/* nwkey in configure private, as ieee80211_ioctl_setnwkeys() takes it */
static int
cand_nwkey(char *ifname, struct ieee80211_nwkey *nwkey, char *key)
{
	char str[256];

	if (!cand_80211(ifname, "intnwkey: SIOCS80211NWKEY"))
		return 0;
	if (nwkey->i_wepon == IEEE80211_NWKEY_OPEN)
		return cand_setting(ST_DEFAULT, "nwkey");
	if (nwkey->i_defkid < 1 || nwkey->i_defkid > IEEE80211_WEP_NKID) {
		printf("%% intnwkey: SIOCS80211NWKEY: %s\n", strerror(EINVAL));
		return 0;
	}
	nwkey_str(str, sizeof(str), key);
	return cand_setting(ST_ON, "nwkey %s", str);
}

/* txpower in configure private: conf prints none for the most */
static int
cand_txpower(char *ifname, int dbm)
{
	if (!cand_80211(ifname, "inttxpower: SIOCS80211TXPOWER failed"))
		return 0;
	if (dbm < kern_txpower_min || dbm > kern_txpower_max) {
		printf("%% inttxpower: SIOCS80211TXPOWER failed: %s\n",
		    strerror(EINVAL));
		return 0;
	}
	if (dbm == kern_txpower_max)
		return cand_setting(ST_DEFAULT, "txpower");
	return cand_setting(ST_ON, "txpower %d", dbm);
}

/* powersave in configure private */
int
cand_powersave(char *ifname, int set, int maxsleep)
{
	if (!cand_80211(ifname, "intpowersave: SIOCG80211POWER"))
		return 0;
	if (!set)
		return cand_setting(ST_DEFAULT, "powersave");
	return cand_setting(ST_ON, "powersave %d", maxsleep);
}
