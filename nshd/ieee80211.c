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
#include <net/if_media.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <util.h>
#include "stringlist.h"
#include "externs.h"
#include "settings.h"
#include "kernel.h"
#include "kfacts.h"

static int cand_80211(char *, char *);
static void nwkey_str(char *, size_t, char *);
static int cand_nwkey(char *, struct ieee80211_nwkey *, char *);
static int cand_txpower(char *, int);
static int cand_nowpa(int);
static int cand_wpaon(void);
static u_int wpa_bits(int, char *);
static void wpa_names(char *, size_t, int, u_int);
static int wpa_default(int, u_int, u_int);
static int wpa_keykind(char *);
static int wpa_keypsk(char *, int, const u_int8_t *, size_t, u_int8_t *);
static int station(int, char *);
static int joinrow(char *, char *);

/* WPA's lists, by the names ifconfig gives them, in the order conf() prints */
struct wpaname {
	const char *name;
	u_int bit;
};
static const struct wpaname wpaprotos[] = {
	{ "wpa1",	IEEE80211_WPA_PROTO_WPA1 },
	{ "wpa2",	IEEE80211_WPA_PROTO_WPA2 },
	{ NULL,		0 }
}, wpaakms[] = {
	{ "psk",	IEEE80211_WPA_AKM_PSK },
	{ "sha256-psk",	IEEE80211_WPA_AKM_SHA256_PSK },
	{ "802.1x",	IEEE80211_WPA_AKM_8021X },
	{ NULL,		0 }
}, wpaciphers[] = {	/* the ones ieee80211_ioctl_setwpaparms() takes */
	{ "usegroup",	IEEE80211_WPA_CIPHER_USEGROUP },
	{ "tkip",	IEEE80211_WPA_CIPHER_TKIP },
	{ "ccmp",	IEEE80211_WPA_CIPHER_CCMP },
	{ NULL,		0 }
}, wpagroupciphers[] = {
	{ "wep40",	IEEE80211_WPA_CIPHER_WEP40 },
	{ "tkip",	IEEE80211_WPA_CIPHER_TKIP },
	{ "ccmp",	IEEE80211_WPA_CIPHER_CCMP },
	{ "wep104",	IEEE80211_WPA_CIPHER_WEP104 },
	{ NULL,		0 }
};

/* A WPA pre-shared key's length */
#define WPA_PSKLEN	sizeof(((struct ieee80211_wpapsk *)0)->i_psk)

/* nwflag's flags, by the names ifconfig gives them */
static const struct ieee80211_flags nwflags[] = IEEE80211_FLAGS;

/* The commands that set them, by WPA_* */
#define WPA_PROTOS	0
#define WPA_AKMS	1
#define WPA_CIPHERS	2
#define WPA_GROUPCIPHER	3
static const struct {
	const char *cmd;
	const struct wpaname *names;
} wpalists[] = {
	{ "wpaprotos",		wpaprotos },
	{ "wpaakms",		wpaakms },
	{ "wpaciphers",		wpaciphers },
	{ "wpagroupcipher",	wpagroupciphers },
};

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
		return -1;
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
					return -1;
				nwkey.i_key[i].i_keylen = len;
				nwkey.i_key[i].i_keydat = keybuf[i];
			}
			if (*val != '\0') {
				printf("%% intnwkey: too many keys\n");
				return -1;
			}
		} else {
			len = sizeof(keybuf[i]);
			val = (char *)get_string(val, NULL, keybuf[0], &len);
			if (val == NULL)
				return -1;
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
		return -1;
	}
	/* the kernel shows no key, so get_nwinfo() prints the one kept here */
	db_delete_flag_x_ctl("nwkey", ifname, 0);
	if (set)
		db_insert_flag_x("nwkey", ifname, 0, DB_X_ENABLE, argv[0]);
	return 0;
}

/*
 * wpakey: a passphrase, which the kernel takes hashed with the nwid, or
 * the hashed key. It turns WEP off and WPA on, and no wpakey turns WPA
 * off. The kernel never shows the key, so nsh keeps it, as for nwkey.
 */
int
intwpakey(int argc, char **argv, ...)
{
	struct ieee80211_wpaparams wpa;
	struct ieee80211_wpapsk psk;
	struct ieee80211_nwid nwid;
	struct ifreq ifr;
	va_list ap;
	char *ifname;
	int ifs, set, hex = 0;

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

	if ((set && argc != 1) || (!set && argc > 1)) {
		printf("%% wpakey <passphrase>|<0x and 64 hex digits>\n");
		printf("%% no wpakey\n");
		return -1;
	}

	if (set && (hex = wpa_keykind(argv[0])) == -1)
		return -1;

	if (candidate)
		return cand_wpakey(ifname, set ? argv[0] : NULL, hex);

	memset(&psk, 0, sizeof(psk));
	if (set) {
		memset(&nwid, 0, sizeof(nwid));
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_data = (caddr_t)&nwid;
		strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (!hex && ioctl(ifs, SIOCG80211NWID, &ifr) == -1) {
			printf("%% intwpakey: SIOCG80211NWID: %s\n",
			    strerror(errno));
			return -1;
		}
		if (wpa_keypsk(argv[0], hex, nwid.i_nwid, nwid.i_len,
		    psk.i_psk) == -1)
			return -1;
	}
	psk.i_enabled = set;
	strlcpy(psk.i_name, ifname, sizeof(psk.i_name));
	if (ioctl(ifs, SIOCS80211WPAPSK, &psk) == -1) {
		printf("%% intwpakey: SIOCS80211WPAPSK: %s\n",
		    strerror(errno));
		explicit_bzero(&psk, sizeof(psk));
		return -1;
	}
	explicit_bzero(&psk, sizeof(psk));

	/* WPA comes on or goes off with the key, as ifconfig does */
	memset(&wpa, 0, sizeof(wpa));
	strlcpy(wpa.i_name, ifname, sizeof(wpa.i_name));
	if (ioctl(ifs, SIOCG80211WPAPARMS, &wpa) == -1) {
		printf("%% intwpakey: SIOCG80211WPAPARMS: %s\n",
		    strerror(errno));
		return -1;
	}
	wpa.i_enabled = set;
	if (ioctl(ifs, SIOCS80211WPAPARMS, &wpa) == -1) {
		printf("%% intwpakey: SIOCS80211WPAPARMS: %s\n",
		    strerror(errno));
		return -1;
	}

	db_delete_flag_x_ctl("wpakey", ifname, 0);
	if (set)
		db_insert_flag_x("wpakey", ifname, 0, DB_X_ENABLE, argv[0]);
	return 0;
}

/* wpa: WPA on, as without a key for 802.1x, or off */
int
intwpa(int argc, char **argv, ...)
{
	struct ieee80211_wpaparams wpa;
	va_list ap;
	char *ifname;
	int ifs, set;

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

	if (argc != 1) {
		printf("%% wpa\n");
		printf("%% no wpa\n");
		return -1;
	}
	if (candidate)
		return cand_wpa(ifname, set);

	memset(&wpa, 0, sizeof(wpa));
	strlcpy(wpa.i_name, ifname, sizeof(wpa.i_name));
	if (ioctl(ifs, SIOCG80211WPAPARMS, &wpa) == -1) {
		printf("%% intwpa: SIOCG80211WPAPARMS: %s\n",
		    strerror(errno));
		return -1;
	}
	wpa.i_enabled = set;
	if (ioctl(ifs, SIOCS80211WPAPARMS, &wpa) == -1) {
		printf("%% intwpa: SIOCS80211WPAPARMS: %s\n",
		    strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * wpaprotos, wpaakms, wpaciphers and wpagroupcipher, which only take
 * effect while WPA is on. A new wpaprotos sets the ciphers back to
 * their defaults, as ifconfig does.
 */
int
intwpalist(int argc, char **argv, ...)
{
	struct ieee80211_wpaparams wpa;
	const struct wpaname *wn;
	va_list ap;
	char *ifname;
	u_int bits = 0;
	int ifs, set, which;

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

	for (which = 0; which < (int)nitems(wpalists) - 1; which++)
		if (isprefix(argv[0], (char *)wpalists[which].cmd))
			break;
	argc--;
	argv++;

	if (set && argc == 1)
		bits = wpa_bits(which, argv[0]);
	if ((set && (argc != 1 || bits == 0)) || (!set && argc > 1)) {
		printf("%% %s ", wpalists[which].cmd);
		for (wn = wpalists[which].names; wn->name != NULL; wn++)
			printf("%s%s", wn == wpalists[which].names ? "" :
			    which == WPA_GROUPCIPHER ? "|" : ",", wn->name);
		printf("\n");
		printf("%% no %s\n", wpalists[which].cmd);
		return -1;
	}

	if (candidate)
		return cand_wpalist(ifname, which, bits);

	memset(&wpa, 0, sizeof(wpa));
	strlcpy(wpa.i_name, ifname, sizeof(wpa.i_name));
	if (ioctl(ifs, SIOCG80211WPAPARMS, &wpa) == -1) {
		printf("%% intwpalist: SIOCG80211WPAPARMS: %s\n",
		    strerror(errno));
		return -1;
	}
	if (!wpa.i_enabled) {
		printf("%% wpa is off on %s: set wpakey or wpa first\n",
		    ifname);
		return -1;
	}
	switch (which) {
	case WPA_PROTOS:
		wpa.i_protos = bits;
		wpa.i_ciphers = 0;
		wpa.i_groupcipher = 0;
		break;
	case WPA_AKMS:
		wpa.i_akms = bits;
		break;
	case WPA_CIPHERS:
		wpa.i_ciphers = bits;
		break;
	case WPA_GROUPCIPHER:
		wpa.i_groupcipher = bits;
		break;
	}
	if (ioctl(ifs, SIOCS80211WPAPARMS, &wpa) == -1) {
		printf("%% intwpalist: SIOCS80211WPAPARMS: %s\n",
		    strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * An 802.11 interface's WPA lines: the key nsh kept while the kernel
 * says there is one, wpa or no wpa where the key does not say it, and
 * the lists that are not the defaults while WPA is on
 */
void
conf_wpa(FILE *output, int ifs, char *ifname)
{
	struct ieee80211_wpaparams wpa;
	struct ieee80211_wpapsk psk;
	StringList *key;
	char str[256];
	u_int bits[nitems(wpalists)];
	size_t i;
	int haskey = 0;

	memset(&psk, 0, sizeof(psk));
	strlcpy(psk.i_name, ifname, sizeof(psk.i_name));
	memset(&wpa, 0, sizeof(wpa));
	strlcpy(wpa.i_name, ifname, sizeof(wpa.i_name));
	if (ioctl(ifs, SIOCG80211WPAPSK, &psk) == -1 ||
	    ioctl(ifs, SIOCG80211WPAPARMS, &wpa) == -1)
		return;
	if (psk.i_enabled) {
		key = sl_init();
		if (db_select_flag_x_ctl(key, "wpakey", ifname) >= 0 &&
		    key->sl_cur > 0) {
			nwkey_str(str, sizeof(str), key->sl_str[0]);
			fprintf(output, " wpakey %s\n", str);
			haskey = 1;
		}
		sl_free(key, 1);
	}
	if (wpa.i_enabled != haskey)
		fprintf(output, " %swpa\n", wpa.i_enabled ? "" : "no ");
	if (!wpa.i_enabled)
		return;
	bits[WPA_PROTOS] = wpa.i_protos;
	bits[WPA_AKMS] = wpa.i_akms;
	bits[WPA_CIPHERS] = wpa.i_ciphers;
	bits[WPA_GROUPCIPHER] = wpa.i_groupcipher;
	for (i = 0; i < nitems(wpalists); i++)
		if (!wpa_default(i, bits[i], wpa.i_protos)) {
			wpa_names(str, sizeof(str), i, bits[i]);
			fprintf(output, " %s %s\n", wpalists[i].cmd, str);
		}
}

/*
 * join: a network the interface joins when it finds it, open, with a
 * WPA key, or with a WEP key. The kernel never shows the keys, so nsh
 * keeps each one with its network ID, as for wpakey.
 */
int
intjoin(int argc, char **argv, ...)
{
	struct ieee80211_join join;
	u_int8_t wepkey[16];
	struct ifreq ifr;
	char nwid[IEEE80211_NWID_LEN * 2 + 8], *kind = NULL;
	StringList *rows;
	va_list ap;
	char *ifname;
	size_t i;
	int ifs, set, len, hex = 0;

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

	if (set && argc == 3 && isprefix(argv[1], "wpakey"))
		kind = "wpakey";
	else if (set && argc == 3 && isprefix(argv[1], "nwkey"))
		kind = "nwkey";
	if (argc < 1 || (set && argc != 1 && kind == NULL)) {
		printf("%% join <nwid> [wpakey <key> | nwkey <key>]\n");
		printf("%% no join <nwid>\n");
		return -1;
	}

	memset(&join, 0, sizeof(join));
	len = sizeof(join.i_nwid);
	if (get_string(argv[0], NULL, join.i_nwid, &len) == NULL)
		return -1;
	join.i_len = len;
	/* an empty network ID joins any open network */
	if (len == 0)
		join.i_flags |= IEEE80211_JOIN_ANY;
	make_string(nwid, sizeof(nwid), join.i_nwid, len);
	if (!set)
		join.i_flags |= IEEE80211_JOIN_DEL;
	else if (kind != NULL && strcmp(kind, "wpakey") == 0) {
		if ((hex = wpa_keykind(argv[2])) == -1)
			return -1;
		/* a passphrase is hashed with the network ID */
		if (!hex && join.i_len == 0) {
			printf("%% join: a passphrase needs a network ID\n");
			return -1;
		}
		join.i_flags |= IEEE80211_JOIN_WPA | IEEE80211_JOIN_WPAPSK;
		join.i_wpaparams.i_enabled = 1;
		join.i_wpapsk.i_enabled = 1;
	} else if (kind != NULL) {
		len = sizeof(wepkey);
		if (get_string(argv[2], NULL, wepkey, &len) == NULL)
			return -1;
		join.i_flags |= IEEE80211_JOIN_NWKEY;
		join.i_nwkey.i_wepon = IEEE80211_NWKEY_WEP;
		join.i_nwkey.i_defkid = 1;
		join.i_nwkey.i_key[0].i_keylen = len;
		join.i_nwkey.i_key[0].i_keydat = wepkey;
	}
	/* the kernel ignores join outside station mode */
	if (set && !station(ifs, ifname)) {
		printf("%% join: %s is not in station mode\n", ifname);
		return -1;
	}

	if (candidate)
		return cand_join(ifname, set, nwid, kind, kind ? argv[2] :
		    NULL);

	if (kind != NULL && strcmp(kind, "wpakey") == 0 &&
	    wpa_keypsk(argv[2], hex, join.i_nwid, join.i_len,
	    join.i_wpapsk.i_psk) == -1)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&join;
	if (ioctl(ifs, SIOCS80211JOIN, &ifr) == -1) {
		printf("%% intjoin: SIOCS80211JOIN: %s\n", strerror(errno));
		explicit_bzero(&join, sizeof(join));
		return -1;
	}
	explicit_bzero(&join, sizeof(join));

	/* a row for the network ID: it and the rest of the join line */
	rows = sl_init();
	if (db_select_flag_x_ctl(rows, "joinkey", ifname) >= 0)
		for (i = 0; i < rows->sl_cur; i++)
			if (joinrow(rows->sl_str[i], nwid))
				db_delete_flag_x_ctl_data("joinkey", ifname,
				    rows->sl_str[i]);
	sl_free(rows, 1);
	if (kind != NULL) {
		char key[256], row[512];

		nwkey_str(key, sizeof(key), argv[2]);
		snprintf(row, sizeof(row), "%s %s %s", nwid, kind, key);
		db_insert_flag_x("joinkey", ifname, 0, DB_X_ENABLE, row);
	}
	return 0;
}

/* Is row, a join line's after "join ", for the network ID nwid? */
static int
joinrow(char *row, char *nwid)
{
	size_t len = strlen(nwid);

	return strncmp(row, nwid, len) == 0 && row[len] == ' ';
}

/* Is the interface in station mode, as its media options say? */
static int
station(int ifs, char *ifname)
{
	uint64_t media = init_current_media(ifs, ifname);

	return media != (uint64_t)-1 && (IFM_OPTIONS(media) &
	    (IFM_IEEE80211_HOSTAP | IFM_IEEE80211_IBSS |
	    IFM_IEEE80211_MONITOR)) == 0;
}

/*
 * An 802.11 interface's join lines, from the kernel's list: an open
 * network's, and one with a key nsh kept
 */
void
conf_join(FILE *output, int ifs, char *ifname)
{
	struct ieee80211_joinreq_all ja;
	struct ieee80211_join *jn = NULL, *p;
	char nwid[IEEE80211_NWID_LEN * 2 + 8];
	StringList *rows;
	size_t i, n = 100;
	int j;

	memset(&ja, 0, sizeof(ja));
	strlcpy(ja.ja_ifname, ifname, sizeof(ja.ja_ifname));
	for (;;) {
		if ((p = reallocarray(jn, n, sizeof(*jn))) == NULL) {
			free(jn);
			return;
		}
		jn = p;
		ja.ja_node = jn;
		ja.ja_size = n * sizeof(*jn);
		if (ioctl(ifs, SIOCG80211JOINALL, &ja) == 0)
			break;
		if (errno != E2BIG) {
			free(jn);
			return;
		}
		n += 100;
	}
	rows = sl_init();
	db_select_flag_x_ctl(rows, "joinkey", ifname);
	for (j = 0; j < ja.ja_nodes; j++) {
		make_string(nwid, sizeof(nwid), jn[j].i_nwid, jn[j].i_len);
		if (jn[j].i_flags & (IEEE80211_JOIN_WPAPSK |
		    IEEE80211_JOIN_NWKEY)) {
			for (i = 0; i < rows->sl_cur; i++)
				if (joinrow(rows->sl_str[i], nwid))
					break;
			if (i < rows->sl_cur)
				fprintf(output, " join %s\n",
				    rows->sl_str[i]);
		} else if (!(jn[j].i_flags & IEEE80211_JOIN_WPA))
			fprintf(output, " join %s\n", nwid);
	}
	sl_free(rows, 1);
	free(jn);
}

/* chan: the channel an 802.11 interface uses, or with no, any */
int
intchan(int argc, char **argv, ...)
{
	struct ieee80211chanreq chan;
	const char *errstr;
	char num[8];
	va_list ap;
	char *ifname;
	int ifs, set;

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

	if ((set && argc != 1) || (!set && argc > 1)) {
		printf("%% chan <1-%d>\n", kern_chan_max);
		printf("%% no chan\n");
		return -1;
	}
	memset(&chan, 0, sizeof(chan));
	strlcpy(chan.i_name, ifname, sizeof(chan.i_name));
	chan.i_channel = IEEE80211_CHAN_ANY;
	if (set) {
		chan.i_channel = strtonum(argv[0], 1, kern_chan_max, &errstr);
		if (errstr) {
			printf("%% chan %s is %s: 1 to %d\n", argv[0], errstr,
			    kern_chan_max);
			return -1;
		}
	}

	if (candidate) {
		if (!cand_80211(ifname, "intchan: SIOCS80211CHANNEL"))
			return -1;
		if (!set)
			return cand_setting(ST_DEFAULT, "chan");
		return cand_setting(ST_ON, "chan %u", chan.i_channel);
	}

	if (ioctl(ifs, SIOCS80211CHANNEL, &chan) == -1) {
		printf("%% intchan: SIOCS80211CHANNEL: %s\n",
		    strerror(errno));
		return -1;
	}
	/* the kernel shows the channel in use, so nsh keeps the one set */
	db_delete_flag_x_ctl("chan", ifname, 0);
	if (set) {
		snprintf(num, sizeof(num), "%u", chan.i_channel);
		db_insert_flag_x("chan", ifname, 0, DB_X_ENABLE, num);
	}
	return 0;
}

/* Is the interface in hostap mode, as its media options say? */
static int
hostap(int ifs, char *ifname)
{
	uint64_t media = init_current_media(ifs, ifname);

	return media != (uint64_t)-1 &&
	    (IFM_OPTIONS(media) & IFM_IEEE80211_HOSTAP) != 0;
}

/*
 * nwflag: 802.11 flags. hidenwid and nobridge are for hostap mode, and
 * the kernel refuses them otherwise.
 */
int
intnwflag(int argc, char **argv, ...)
{
	struct ifreq ifr;
	char flags[256];
	va_list ap;
	char *ifname;
	u_int bits = 0;
	size_t i;
	int ifs, set, n;

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

	for (n = 0; n < argc; n++) {
		for (i = 0; i < nitems(nwflags); i++)
			if (strcmp(argv[n], nwflags[i].f_name) == 0)
				break;
		if (i == nitems(nwflags))
			break;
		bits |= nwflags[i].f_flag;
	}
	if (argc < 1 || n < argc) {
		printf("%% nwflag <flag> [flag ...]\n");
		printf("%% no nwflag <flag> [flag ...]\n");
		printf("%% flags:");
		for (i = 0; i < nitems(nwflags); i++)
			printf(" %s", nwflags[i].f_name);
		printf("\n");
		return -1;
	}
	if (set && (bits & IEEE80211_F_HOSTAPMASK) && !hostap(ifs, ifname)) {
		printf("%% nwflag: hidenwid and nobridge need mediaopt "
		    "hostap\n");
		return -1;
	}

	if (candidate) {
		if (!cand_80211(ifname, "intnwflag: SIOCS80211FLAGS"))
			return -1;
		argvtostring(argc, argv, flags, sizeof(flags));
		return cand_setting(set ? ST_ON : ST_OFF, "nwflag %s", flags);
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCG80211FLAGS, &ifr) == -1) {
		printf("%% intnwflag: SIOCG80211FLAGS: %s\n",
		    strerror(errno));
		return -1;
	}
	if (set)
		ifr.ifr_flags |= bits;
	else
		ifr.ifr_flags &= ~bits;
	if (ioctl(ifs, SIOCS80211FLAGS, &ifr) == -1) {
		printf("%% intnwflag: SIOCS80211FLAGS: %s\n",
		    strerror(errno));
		return -1;
	}
	return 0;
}

/* An 802.11 interface's chan, which nsh kept, and its nwflags */
void
conf_80211(FILE *output, int ifs, char *ifname)
{
	struct ifreq ifr;
	StringList *chan;
	size_t i;
	int n = 0;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCG80211FLAGS, &ifr) == -1)
		return;
	chan = sl_init();
	if (db_select_flag_x_ctl(chan, "chan", ifname) >= 0 &&
	    chan->sl_cur > 0)
		fprintf(output, " chan %s\n", chan->sl_str[0]);
	sl_free(chan, 1);
	for (i = 0; i < nitems(nwflags); i++)
		if (ifr.ifr_flags & nwflags[i].f_flag)
			fprintf(output, "%s %s", n++ ? "" : " nwflag",
			    nwflags[i].f_name);
	if (n > 0)
		fprintf(output, "\n");
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
		return -1;
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
			return -1;
		}
		txpower.i_val = (int16_t)dbm;
		txpower.i_mode = IEEE80211_TXPOWER_MODE_FIXED;
	}

	if (candidate)
		return cand_txpower(ifname, txpower.i_val);

	if (ioctl(ifs, SIOCS80211TXPOWER, (caddr_t)&txpower) == -1) {
		printf("%% inttxpower: SIOCS80211TXPOWER failed: %s\n",
		    strerror(errno));
		return -1;
	}

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
		return -1;
	}

	if (set) {
		ea = ether_aton(argv[0]);
		if (ea == NULL) {
			printf("%% Invalid bssid\n");
			return -1;
		}
		memcpy(&bssid.i_bssid, ea->ether_addr_octet,
		    sizeof(bssid.i_bssid));
	} else
		memset(&bssid.i_bssid, 0, sizeof(bssid.i_bssid));

	strlcpy(bssid.i_name, ifname, sizeof(bssid.i_name));
	if (ioctl(ifs, SIOCS80211BSSID, &bssid) == -1) {
		printf("%% intbssid: SIOCS80211BSSID failed: %s\n",
		    strerror(errno));
		return -1;
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
	if (kf_wifi(name))
		return 1;
	printf("%% %s: %s\n", what, strerror(ENOTTY));
	return 0;
}

/* A key as intnwkey() or intwpakey() kept it, quoted as makeargv() reads it */
static void
nwkey_str(char *buf, size_t len, char *key)
{
	if (strpbrk(key, " \t") != NULL)
		snprintf(buf, len, "\"%s\"", key);
	else
		strlcpy(buf, key, len);
}

/*
 * nwid in configure private. SIOCS80211NWID turns WEP and WPA off, so
 * their lines go too.
 */
int
cand_nwid(char *ifname, u_int8_t *nwid, int len)
{
	char str[IEEE80211_NWID_LEN * 2 + 8];

	if (!cand_80211(ifname, "intnwid: SIOCS80211NWID"))
		return -1;
	make_string(str, sizeof(str), nwid, len);
	if (cand_setting(ST_ON, "nwid %s", str) == -1 ||
	    cand_setting(ST_DEFAULT, "nwkey") == -1)
		return -1;
	return cand_nowpa(1);
}

/* nwkey in configure private, as ieee80211_ioctl_setnwkeys() takes it */
static int
cand_nwkey(char *ifname, struct ieee80211_nwkey *nwkey, char *key)
{
	char str[256];

	if (!cand_80211(ifname, "intnwkey: SIOCS80211NWKEY"))
		return -1;
	if (nwkey->i_wepon == IEEE80211_NWKEY_OPEN)
		return cand_setting(ST_DEFAULT, "nwkey");
	if (nwkey->i_defkid < 1 || nwkey->i_defkid > IEEE80211_WEP_NKID) {
		printf("%% intnwkey: SIOCS80211NWKEY: %s\n", strerror(EINVAL));
		return -1;
	}
	/* WEP turns WPA off */
	if (cand_nowpa(1) == -1)
		return -1;
	nwkey_str(str, sizeof(str), key);
	return cand_setting(ST_ON, "nwkey %s", str);
}

/* txpower in configure private: conf prints none for the maximum */
static int
cand_txpower(char *ifname, int dbm)
{
	if (!cand_80211(ifname, "inttxpower: SIOCS80211TXPOWER failed"))
		return -1;
	if (dbm < kern_txpower_min || dbm > kern_txpower_max) {
		printf("%% inttxpower: SIOCS80211TXPOWER failed: %s\n",
		    strerror(EINVAL));
		return -1;
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
		return -1;
	if (!set)
		return cand_setting(ST_DEFAULT, "powersave");
	return cand_setting(ST_ON, "powersave %d", maxsleep);
}

/*
 * The WPA lines go when WPA goes off: the lists, and with key, wpakey
 * and wpa too
 */
static int
cand_nowpa(int key)
{
	size_t i;

	if (key && (cand_setting(ST_DEFAULT, "wpakey") == -1 ||
	    cand_setting(ST_DEFAULT, "wpa") == -1))
		return -1;
	for (i = 0; i < nitems(wpalists); i++)
		if (cand_setting(ST_DEFAULT, "%s", wpalists[i].cmd) == -1)
			return -1;
	return 0;
}

/* Is WPA on, as the candidate's wpakey and wpa lines say? */
static int
cand_wpaon(void)
{
	char *l;

	if ((l = cand_line("wpa", 0)) != NULL)
		return strcmp(l, "wpa") == 0;
	return cand_line("wpakey", 0) != NULL;
}

/*
 * wpakey in configure private. A passphrase needs the nwid it is hashed
 * with. A key turns WEP off and WPA on; no key turns WPA off.
 */
int
cand_wpakey(char *ifname, char *key, int hex)
{
	char str[256], *l;

	if (!cand_80211(ifname, "intwpakey: SIOCS80211WPAPSK"))
		return -1;
	if (key == NULL)
		return cand_nowpa(1);
	if (!hex && ((l = cand_line("nwid", 0)) == NULL ||
	    strcmp(l, "nwid \"\"") == 0)) {
		printf("%% wpakey: nwid not set\n");
		return -1;
	}
	if (cand_setting(ST_DEFAULT, "nwkey") == -1 ||
	    cand_setting(ST_DEFAULT, "wpa") == -1)
		return -1;
	nwkey_str(str, sizeof(str), key);
	return cand_setting(ST_ON, "wpakey %s", str);
}

/*
 * wpa in configure private: a line where wpakey does not say it. No wpa
 * takes the lists away.
 */
int
cand_wpa(char *ifname, int set)
{
	int key = cand_line("wpakey", 0) != NULL;

	if (!cand_80211(ifname, "intwpa: SIOCS80211WPAPARMS"))
		return -1;
	if (set)
		return cand_setting(key ? ST_DEFAULT : ST_ON, "wpa");
	if (cand_nowpa(0) == -1)
		return -1;
	return cand_setting(key ? ST_OFF : ST_DEFAULT, "wpa");
}

/*
 * One of WPA's lists in configure private, while WPA is on: a line
 * unless the kernel's default. A new wpaprotos takes the ciphers away.
 */
int
cand_wpalist(char *ifname, int which, u_int bits)
{
	char str[128], *l;
	u_int protos = 0;

	if (!cand_80211(ifname, "intwpalist: SIOCS80211WPAPARMS"))
		return -1;
	if (!cand_wpaon()) {
		printf("%% wpa is off on %s: set wpakey or wpa first\n",
		    ifname);
		return -1;
	}
	if (which == WPA_PROTOS) {
		protos = bits;
		if (cand_setting(ST_DEFAULT, "wpaciphers") == -1 ||
		    cand_setting(ST_DEFAULT, "wpagroupcipher") == -1)
			return -1;
	} else if ((l = cand_line("wpaprotos", 0)) != NULL)
		protos = wpa_bits(WPA_PROTOS, l + strlen("wpaprotos "));
	if (bits == 0 || wpa_default(which, bits, protos))
		return cand_setting(ST_DEFAULT, "%s", wpalists[which].cmd);
	wpa_names(str, sizeof(str), which, bits);
	return cand_setting(ST_ON, "%s %s", wpalists[which].cmd, str);
}

/*
 * The bits of a WPA list that words names, separated by commas, or 0:
 * one name for the group cipher, and usegroup alone
 */
static u_int
wpa_bits(int which, char *words)
{
	const struct wpaname *wn;
	char buf[128], *w, *p;
	u_int bits = 0;
	int n;

	strlcpy(buf, words, sizeof(buf));
	for (n = 0, p = buf; (w = strsep(&p, ",")) != NULL; n++) {
		for (wn = wpalists[which].names; wn->name != NULL; wn++)
			if (strcasecmp(w, wn->name) == 0)
				break;
		if (wn->name == NULL || (which == WPA_GROUPCIPHER && n > 0))
			return 0;
		bits |= wn->bit;
	}
	if ((bits & IEEE80211_WPA_CIPHER_USEGROUP) &&
	    bits != IEEE80211_WPA_CIPHER_USEGROUP && which == WPA_CIPHERS)
		return 0;
	return bits;
}

/* A WPA list's bits by their names, separated by commas */
static void
wpa_names(char *buf, size_t len, int which, u_int bits)
{
	const struct wpaname *wn;

	buf[0] = '\0';
	for (wn = wpalists[which].names; wn->name != NULL; wn++)
		if (bits & wn->bit) {
			if (buf[0] != '\0')
				strlcat(buf, ",", len);
			strlcat(buf, wn->name, len);
		}
}

/*
 * Are a WPA list's bits what the kernel sets when it gets none, with
 * protocols protos (ieee80211_ioctl_setwpaparms())? With management
 * frame protection, its default key management has SHA256 PSK too.
 */
static int
wpa_default(int which, u_int bits, u_int protos)
{
	int wpa1 = (protos & IEEE80211_WPA_PROTO_WPA1) != 0;

	switch (which) {
	case WPA_PROTOS:
		return bits == IEEE80211_WPA_PROTO_WPA2;
	case WPA_AKMS:
		return bits == IEEE80211_WPA_AKM_PSK ||
		    bits == (IEEE80211_WPA_AKM_PSK |
		    IEEE80211_WPA_AKM_SHA256_PSK);
	case WPA_CIPHERS:
		return bits == (IEEE80211_WPA_CIPHER_CCMP |
		    (wpa1 ? IEEE80211_WPA_CIPHER_TKIP : 0));
	default:
		return bits == (wpa1 ? IEEE80211_WPA_CIPHER_TKIP :
		    IEEE80211_WPA_CIPHER_CCMP);
	}
}

/*
 * A WPA key as ifconfig takes it: 1 for 0x and 64 hex digits, 0 for a
 * passphrase of 8 to 63 characters, or -1 after saying why
 */
static int
wpa_keykind(char *key)
{
	size_t len = strlen(key);

	if (len == 2 + 2 * WPA_PSKLEN && key[0] == '0' &&
	    key[1] == 'x')
		return 1;
	if (len < 8 || len > 63) {
		printf("%% wpakey: a passphrase is 8 to 63 characters\n");
		return -1;
	}
	return 0;
}

/*
 * The pre-shared key a WPA key gives: its hex digits, or the passphrase
 * hashed with the network ID. 0, or -1 after saying why.
 */
static int
wpa_keypsk(char *key, int hex, const u_int8_t *nwid, size_t nwidlen,
    u_int8_t *psk)
{
	int len = WPA_PSKLEN;

	if (hex) {
		if (get_string(key, NULL, psk, &len) == NULL ||
		    (size_t)len != WPA_PSKLEN) {
			printf("%% wpakey: invalid pre-shared key\n");
			return -1;
		}
		return 0;
	}
	if (nwidlen == 0) {
		printf("%% wpakey: nwid not set\n");
		return -1;
	}
	if (pkcs5_pbkdf2(key, strlen(key), nwid, nwidlen, psk, WPA_PSKLEN,
	    4096) != 0) {
		printf("%% wpakey: passphrase hashing failed\n");
		return -1;
	}
	return 0;
}

/*
 * join in configure private: a line for each network ID, with its key
 * as it was typed
 */
int
cand_join(char *ifname, int set, char *nwid, char *kind, char *key)
{
	char str[256];

	if (!cand_80211(ifname, "intjoin: SIOCS80211JOIN"))
		return -1;
	if (!set)
		return cand_setting(ST_DEFAULT, "join %s", nwid);
	if (kind == NULL)
		return cand_setting(ST_ON, "join %s", nwid);
	nwkey_str(str, sizeof(str), key);
	return cand_setting(ST_ON, "join %s %s %s", nwid, kind, str);
}
