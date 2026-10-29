/* From: $OpenBSD: ifconfig.c,v 1.453 2022/03/07 08:13:13 stsp Exp $	*/

#include <sys/socket.h>

#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_types.h>
#include <arpa/inet.h>

#include <netdb.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include <dev/usb/mbim.h>
#include <dev/usb/if_umb.h>

#include "stringlist.h"
#include "externs.h"
#include "settings.h"
#include "facts.h"
#include "showfacts.h"
void	umb_classes(char *, size_t, uint32_t);
int	umb_parse_classes(const char *);
int	umb_setpin(int, char *, const char *);
int	umb_chgpin(int, char *, const char *, const char *);
int	umb_puk(int, char *, const char *, const char *);
int	umb_pinop(int, char *, int, int, const char *, const char *);
int	umb_apn(int, char *, const char *);
int	umb_setclass(int, char *, const char *);
int	umb_roaming(int, char *, int);
void	conf_umb_pin(FILE *, char *);
void	utf16_to_char(uint16_t *, int, char *, size_t);
int	char_to_utf16(const char *, uint16_t *, size_t);
static int cand_umb(char *, int, int, char *);
static const struct umb_valdescr umb_dataclass[] = MBIM_DATACLASS_DESCRIPTIONS;
const struct umb_valdescr umb_pktstate[] = MBIM_PKTSRV_STATE_DESCRIPTIONS;
const struct umb_valdescr umb_actstate[] = MBIM_ACTIVATION_STATE_DESCRIPTIONS;

const struct umb_valdescr umb_classalias[] = {
	{ MBIM_DATACLASS_GPRS | MBIM_DATACLASS_EDGE, "2g" },
	{ MBIM_DATACLASS_UMTS | MBIM_DATACLASS_HSDPA | MBIM_DATACLASS_HSUPA,
	    "3g" },
	{ MBIM_DATACLASS_LTE, "4g" },
	{ 0, NULL }
};

static int
umb_descr2val(const struct umb_valdescr *vdp, char *str)
{
	while (vdp->descr != NULL) {
		if (!strcasecmp(vdp->descr, str))
			return vdp->val;
		vdp++;
	}
	return 0;
}

/* a string of the kernel's, if it has one */
static void
umb_string(struct facts_value *v, uint16_t *in, int inlen, char *out,
    size_t outlen)
{
	utf16_to_char(in, inlen, out, outlen);
	if (out[0] != '\0')
		facts_string(v, out);
}

/* ifname's umb, and its name servers */
void
umb_facts(struct facts_out *o, int ifs, char *ifname)
{
	struct facts_value v[UMB_NFIELDS], dv[UMBDNS_NFIELDS];
	struct umb_info mi;
	struct ifreq ifr;

	char	 provider[UMB_PROVIDERNAME_MAXLEN+1];
	char	 providerid[UMB_PROVIDERID_MAXLEN+1];
	char	 roamingtxt[UMB_ROAMINGTEXT_MAXLEN+1];
	char	 devid[UMB_DEVID_MAXLEN+1];
	char	 fwinfo[UMB_FWINFO_MAXLEN+1];
	char	 hwinfo[UMB_HWINFO_MAXLEN+1];
	char	 sid[UMB_SUBSCRIBERID_MAXLEN+1];
	char	 iccid[UMB_ICCID_MAXLEN+1];
	char	 apn[UMB_APN_MAXLEN+1];
	char	 pn[UMB_PHONENR_MAXLEN+1];

	int 	 i;

	memset((char *)&mi, 0, sizeof(mi));
	ifr.ifr_data = (caddr_t)&mi;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCGUMBINFO, (caddr_t)&ifr) == -1)
		return;

	memset(v, 0, sizeof(v));
	if (mi.nwerror)
		facts_u64(&v[UMB_ERROR], (uint32_t)mi.nwerror);
	facts_u64(&v[UMB_ROAMING], mi.enable_roaming ? 1 : 0);
	facts_u64(&v[UMB_REGSTATE], (uint32_t)mi.regstate);
	umb_string(&v[UMB_ROAMINGTEXT], mi.roamingtxt, UMB_ROAMINGTEXT_MAXLEN,
	    roamingtxt, sizeof(roamingtxt));
	facts_u64(&v[UMB_CLASSES], mi.supportedclasses);
	facts_u64(&v[UMB_STATE], (uint32_t)mi.state);
	facts_u64(&v[UMB_CELLCLASS], mi.cellclass);
	facts_u64(&v[UMB_HIGHESTCLASS], mi.highestclass);
	if (mi.rssi != UMB_VALUE_UNKNOWN)
		facts_i64(&v[UMB_RSSI], mi.rssi);
	facts_u64(&v[UMB_UPLINK], mi.uplink_speed);
	facts_u64(&v[UMB_DOWNLINK], mi.downlink_speed);
	facts_u64(&v[UMB_SIMSTATE], (uint32_t)mi.sim_state);
	facts_u64(&v[UMB_PINSTATE], (uint32_t)mi.pin_state);
	if (mi.pin_attempts_left != UMB_VALUE_UNKNOWN)
		facts_i64(&v[UMB_PINLEFT], mi.pin_attempts_left);
	umb_string(&v[UMB_SID], mi.sid, UMB_SUBSCRIBERID_MAXLEN, sid,
	    sizeof(sid));
	umb_string(&v[UMB_ICCID], mi.iccid, UMB_ICCID_MAXLEN, iccid,
	    sizeof(iccid));
	umb_string(&v[UMB_PROVIDER], mi.provider, UMB_PROVIDERNAME_MAXLEN,
	    provider, sizeof(provider));
	umb_string(&v[UMB_PROVIDERID], mi.providerid, UMB_PROVIDERID_MAXLEN,
	    providerid, sizeof(providerid));
	umb_string(&v[UMB_HWINFO], mi.hwinfo, UMB_HWINFO_MAXLEN, hwinfo,
	    sizeof(hwinfo));
	umb_string(&v[UMB_DEVID], mi.devid, UMB_DEVID_MAXLEN, devid,
	    sizeof(devid));
	umb_string(&v[UMB_FWINFO], mi.fwinfo, UMB_FWINFO_MAXLEN, fwinfo,
	    sizeof(fwinfo));
	umb_string(&v[UMB_PHONE], mi.pn, UMB_PHONENR_MAXLEN, pn, sizeof(pn));
	umb_string(&v[UMB_APN], mi.apn, UMB_APN_MAXLEN, apn, sizeof(apn));
	facts_string(&v[UMB_IF], ifname);
	facts_record(o, &kind_umb, v);

	for (i = 0; i < UMB_MAX_DNSSRV; i++) {
		if (mi.ipv4dns[i].s_addr == INADDR_ANY)
			break;
		memset(dv, 0, sizeof(dv));
		facts_address(&dv[UMBDNS_ADDRESS], FACT_INET, &mi.ipv4dns[i],
		    sizeof(mi.ipv4dns[i]), 0);
		facts_string(&dv[UMBDNS_IF], ifname);
		facts_record(o, &kind_umbdns, dv);
	}
	for (i = 0; i < UMB_MAX_DNSSRV; i++) {
		if (memcmp(&mi.ipv6dns[i], &in6addr_any,
		    sizeof (mi.ipv6dns[i])) == 0)
			break;
		memset(dv, 0, sizeof(dv));
		facts_address(&dv[UMBDNS_ADDRESS], FACT_INET6, &mi.ipv6dns[i],
		    sizeof(mi.ipv6dns[i]), 0);
		facts_string(&dv[UMBDNS_IF], ifname);
		facts_record(o, &kind_umbdns, dv);
	}
}

/* The classes in c, one name for each, as umb_parse_classes() reads them */
void
umb_classes(char *buf, size_t len, uint32_t c)
{
	uint32_t v;
	int i;

	strlcpy(buf, c ? "" : "none", len);
	for (i = 0; umb_dataclass[i].descr != NULL; i++) {
		v = umb_dataclass[i].val;
		if (!(c & v) || (v & (v - 1)) != 0)
			continue;
		if (buf[0] != '\0')
			strlcat(buf, ",", len);
		strlcat(buf, umb_dataclass[i].descr, len);
	}
}

int
umb_parse_classes(const char *spec)
{
	char	*optlist, *str;
	int	 c = 0, v;

	if ((optlist = strdup(spec)) == NULL) {
		printf("%% umb_parse_classes: strdup: %s\n", strerror(errno));
		return -1;
	}
	str = strtok(optlist, ",");
	while (str != NULL) {
		if ((v = umb_descr2val(umb_dataclass, str)) != 0 ||
		    (v = umb_descr2val(umb_classalias, str)) != 0)
			c |= v;
		else if (strcasecmp(str, "none") != 0) {
			printf("%% Unknown class %s\n", str);
			free(optlist);
			return -1;
		}
		str = strtok(NULL, ",");
	}
	free(optlist);
	return c;
}

int
umb_setpin(int ifs, char *ifname, const char *pin)
{
	if (umb_pinop(ifs, ifname, MBIM_PIN_OP_ENTER, 0, pin, NULL) == -1)
		return -1;
	db_delete_flag_x_ctl("pin", ifname, 0);
	if (pin != NULL)
		db_insert_flag_x("pin", ifname, 0, 0, (char *)pin);
	return 0;
}

int
umb_chgpin(int ifs, char *ifname, const char *pin, const char *newpin)
{
	return umb_pinop(ifs, ifname, MBIM_PIN_OP_CHANGE, 0, pin, newpin);
}

int
umb_puk(int ifs, char *ifname, const char *pin, const char *newpin)
{
	return umb_pinop(ifs, ifname, MBIM_PIN_OP_ENTER, 1, pin, newpin);
}

int
umb_pinop(int ifs, char *ifname, int op, int is_puk, const char *pin,
    const char *newpin)
{
	struct umb_parameter mp;
	struct ifreq ifr;

	memset(&mp, 0, sizeof (mp));
	ifr.ifr_data = (caddr_t)&mp;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCGUMBPARAM, (caddr_t)&ifr) == -1) {
		printf("%% umb_pinop: SIOCGUMBPARAM: %s\n", strerror(errno));
		return -1;
	}

	mp.op = op;
	mp.is_puk = is_puk;
	if (pin) {
		if ((mp.pinlen = char_to_utf16(pin, (uint16_t *)mp.pin,
		    sizeof (mp.pin))) == -1) {
			printf("%% PIN too long\n");
			return -1;
		}
	}

	if (newpin) {
		if ((mp.newpinlen = char_to_utf16(newpin, (uint16_t *)mp.newpin,
		    sizeof (mp.newpin))) == -1) {
			printf("%% new PIN too long\n");
			return -1;
		}
	}

	if (ioctl(ifs, SIOCSUMBPARAM, (caddr_t)&ifr) == -1) {
		printf("%% umb_pinop: SIOCSUMBPARAM: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
umb_apn(int ifs, char *ifname, const char *apn)
{
	struct umb_parameter mp;
	struct ifreq ifr;

	memset(&mp, 0, sizeof (mp));
	ifr.ifr_data = (caddr_t)&mp;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCGUMBPARAM, (caddr_t)&ifr) == -1) {
		printf("%% umb_apn: SIOCGUMBPARAM: %s\n", strerror(errno));
		return -1;
	}

	if (apn == NULL) {
		/* the length is what the next connect sends */
		memset(mp.apn, 0, sizeof (mp.apn));
		mp.apnlen = 0;
	} else if ((mp.apnlen = char_to_utf16(apn, mp.apn,
	    sizeof (mp.apn))) == -1) {
		printf("%% APN too long\n");
		return -1;
	}

	if (ioctl(ifs, SIOCSUMBPARAM, (caddr_t)&ifr) == -1) {
		printf("%% umb_apn: SIOCSUMBPARAM: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int
umb_setclass(int ifs, char *ifname, const char *val)
{
	struct umb_parameter mp;
	struct ifreq ifr;

	memset(&mp, 0, sizeof (mp));
	ifr.ifr_data = (caddr_t)&mp;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCGUMBPARAM, (caddr_t)&ifr) == -1) {
		printf("%% umb_setclass: SIOCGUMBPARAM: %s\n", strerror(errno));
		return -1;
	}
	if (val)
		mp.preferredclasses = umb_parse_classes(val);
	else
		mp.preferredclasses = MBIM_DATACLASS_NONE;
	if (mp.preferredclasses == -1)
		return -1;
	if (ioctl(ifs, SIOCSUMBPARAM, (caddr_t)&ifr) == -1) {
		printf("%% umb_setclass: SIOCSUMBPARAM: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int
umb_roaming(int ifs, char *ifname, int roaming)
{
	struct umb_parameter mp;
	struct ifreq ifr;

	memset(&mp, 0, sizeof (mp));
	ifr.ifr_data = (caddr_t)&mp;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCGUMBPARAM, (caddr_t)&ifr) == -1) {
		printf("%% umb_roaming: SIOCGUMBPARAM: %s\n", strerror(errno));
		return -1;
	}
	mp.roaming = roaming;
	if (ioctl(ifs, SIOCSUMBPARAM, (caddr_t)&ifr) == -1) {
		printf("%% umb_roaming: SIOCSUMBPARAM: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

void
utf16_to_char(uint16_t *in, int inlen, char *out, size_t outlen)
{
	uint16_t c;

	while (outlen > 0) {
		c = inlen > 0 ? letoh16(*in) : 0;
		if (c == 0 || --outlen == 0) {
			/* always NUL terminate result */
			*out = '\0';
			break;
		}
		*out++ = isascii(c) ? (char)c : '?';
		in++;
		inlen--;
	}
}

int
char_to_utf16(const char *in, uint16_t *out, size_t outlen)
{
	int	 n = 0;
	uint16_t c;

	for (;;) {
		c = *in++;

		if (c == '\0') {
			/*
			 * NUL termination is not required, but zero out the
			 * residual buffer
			 */
			memset(out, 0, outlen);
			return n;
		}
		if (outlen < sizeof (*out))
			return -1;

		*out++ = htole16(c);
		n += sizeof (*out);
		outlen -= sizeof (*out);
	}
}

#define UMB_APN 1
#define UMB_PIN 2
#define UMB_PUK 3
#define UMB_CHGPIN 4
#define UMB_CLASS 5
#define UMB_ROAMING 6

static struct umbc {
	char *name;
	char *descr;
	char *descr2;
	int type;
} umbcs[] = {
	{ "apn",	"access point name",	"",		UMB_APN },
	{ "setpin",	"sim card pin",		"",		UMB_PIN },
	{ "setpuk",	"puk",			"newpin",	UMB_PUK },
	{ "chgpin",	"oldpin",		"newpin",	UMB_CHGPIN },
	{ "class",	"preferred cell class",	"",		UMB_CLASS },
	{ "roaming",	"data roaming",		"",		UMB_ROAMING },
	{ 0,		0,			0,		0 }
};

int
intumb(int argc, char **argv, ...)
{
	int set, r;
	struct umbc *x;
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

	x=(struct umbc *) genget(argv[0], (char **)umbcs, sizeof(struct umbc));
	if (x == 0) {
		printf("%% intumb: Internal error - Invalid argument %s\n", argv[0]);
		return -1;
	} else if (Ambiguous(x)) {
		printf("%% intumb: Internal error - Ambiguous argument %s\n", argv[0]);
		return -1;
	}

	argc--;
	argv++;

	if ((x->type == UMB_ROAMING) &&
	    ((!set && argc > 0) || (set && argc != 0))) {
		printf("%% %s\n", x->name);
		printf("%% no %s\n", x->name);
		return -1;
	}

	if (((x->type == UMB_CHGPIN) || (x->type == UMB_PUK)) &&
	    (set && argc != 2)) {
		printf("%% %s <%s> <%s>\n", x->name, x->descr, x->descr2);
		return -1;
	}

	if ((x->type == UMB_APN || x->type == UMB_PIN || x->type ==
	    UMB_CLASS) &&
	    ((!set && argc > 1) || (set && argc != 1))) {
		printf("%% %s <%s>\n", x->name, x->descr);
		printf("%% no %s [%s]\n", x->name, x->descr);
		return -1;
	}

	/* setpuk and chgpin act on the SIM, even in configure private */
	if (candidate && x->type != UMB_PUK && x->type != UMB_CHGPIN)
		return cand_umb(ifname, set, x->type, argv[0]);

	switch(x->type) {
	case UMB_APN:
		if (!set) {
			r = umb_apn(ifs, ifname, NULL);
		} else {
			r = umb_apn(ifs, ifname, argv[0]);
		}
		break;

	case UMB_PIN:
		if (!set) {
			r = umb_setpin(ifs, ifname, NULL);
		} else {
			r = umb_setpin(ifs, ifname, argv[0]);
		}
		break;

	case UMB_PUK:
		if (!set) {
			r = umb_puk(ifs, ifname, NULL, NULL);
		} else {
			r = umb_puk(ifs, ifname, argv[0], argv[1]);
		}
		break;

	case UMB_CHGPIN:
		if (!set) {
			r = umb_chgpin(ifs, ifname, NULL, NULL);
		} else {
			r = umb_chgpin(ifs, ifname, argv[0], argv[1]);
		}
		break;

	case UMB_CLASS:
		if (!set) {
			r = umb_setclass(ifs, ifname, NULL);
		} else {
			r = umb_setclass(ifs, ifname, argv[0]);
		}
		break;

	case UMB_ROAMING:
		if (!set) {
			r = umb_roaming(ifs, ifname, 0);
		} else {
			r = umb_roaming(ifs, ifname, 1);
		}
		break;

	default:
		printf("%% intumb: internal error\n");
		r = -1;
	}
	return r;
}

/*
 * apn, setpin, class and roaming in configure private, as conf_umb()
 * would print them once umb took them
 */
static int
cand_umb(char *ifname, int set, int type, char *arg)
{
	static char *fn[] = { NULL, "umb_apn", "umb_pinop", NULL, NULL,
	    "umb_setclass", "umb_roaming" };
	char buf[256];
	size_t i;
	int c;

	if (cand_gettype(ifname) != IFT_MBIM) {
		printf("%% %s: SIOCGUMBPARAM: %s\n", fn[type], strerror(ENOTTY));
		return -1;
	}
	switch (type) {
	case UMB_APN:
		if (!set)
			return cand_setting(ST_DEFAULT, "apn");
		if (strlen(arg) > UMB_APN_MAXLEN) {
			printf("%% APN too long\n");
			return -1;
		}
		/* utf16_to_char() prints a character outside ASCII as '?' */
		strlcpy(buf, arg, sizeof(buf));
		for (i = 0; buf[i] != '\0'; i++)
			if (!isascii((unsigned char)buf[i]))
				buf[i] = '?';
		return cand_setting(ST_ON, "apn %s", buf);
	case UMB_PIN:
		if (!set)
			return cand_setting(ST_DEFAULT, "setpin");
		if (strlen(arg) > MBIM_PIN_MAXLEN / 2) {
			printf("%% PIN too long\n");
			return -1;
		}
		return cand_setting(ST_ON, "setpin %s", arg);
	case UMB_CLASS:
		if ((c = set ? umb_parse_classes(arg) : MBIM_DATACLASS_NONE) == -1)
			return -1;
		umb_classes(buf, sizeof(buf), c);
		return cand_setting(ST_ON, "class %s", buf);
	case UMB_ROAMING:
		return cand_setting(set ? ST_ON : ST_DEFAULT, "roaming");
	}
	return 0;
}

void
conf_umb(FILE *output, int ifs, char *ifname)
{
	struct umb_parameter mp;
	struct ifreq ifr;
	char apn[UMB_APN_MAXLEN+1], classes[128];

	memset((char *)&mp, 0, sizeof(mp));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&mp;

	if (ioctl(ifs, SIOCGUMBPARAM, (caddr_t)&ifr) == -1)
		return;

	utf16_to_char(mp.apn, UMB_APN_MAXLEN, apn, sizeof(apn));
	if (apn[0])
		fprintf(output, " apn %s\n", apn);
	conf_umb_pin(output, ifname);
	if (mp.roaming)
		fprintf(output, " roaming\n");
	umb_classes(classes, sizeof(classes), mp.preferredclasses);
	fprintf(output, " class %s\n", classes);
}

void
conf_umb_pin(FILE *output, char *ifname)
{
	StringList *pin;

	pin = sl_init();

	if (db_select_flag_x_ctl(pin, "pin", ifname) < 0) {
		printf("%% pin database select failed\n");
	}
	if (pin->sl_cur > 0)
		fprintf(output, " setpin %s\n", pin->sl_str[0]);

	sl_free(pin, 1);
}
