/* From: $OpenBSD: ifconfig.c,v 1.453 2022/03/07 08:13:13 stsp Exp $	*/

#include <sys/socket.h>

#include <sys/ioctl.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <netdb.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include <dev/usb/mbim.h>
#include <dev/usb/if_umb.h>

#include "stringlist.h"
#include "externs.h"

void	umb_printclasses(char *, int, FILE *);
int	umb_parse_classes(const char *);
void	umb_setpin(int, char *, const char *);
void	umb_chgpin(int, char *, const char *, const char *);
void	umb_puk(int, char *, const char *, const char *);
int	umb_pinop(int, char *, int, int, const char *, const char *);
void	umb_apn(int, char *, const char *);
void	umb_setclass(int, char *, const char *);
void	umb_roaming(int, char *, int);
void	conf_umb_pin(FILE *, char *);
void	utf16_to_char(uint16_t *, int, char *, size_t);
int	char_to_utf16(const char *, uint16_t *, size_t);

const struct umb_valdescr umb_regstate[] = MBIM_REGSTATE_DESCRIPTIONS;
const struct umb_valdescr umb_dataclass[] = MBIM_DATACLASS_DESCRIPTIONS;
const struct umb_valdescr umb_simstate[] = MBIM_SIMSTATE_DESCRIPTIONS;
const struct umb_valdescr umb_istate[] = UMB_INTERNAL_STATE_DESCRIPTIONS;
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

void
show_umb(int ifs, char *ifname, FILE *outfile)
{
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
	char	 astr[INET6_ADDRSTRLEN];

	int 	 i,n;

	memset((char *)&mi, 0, sizeof(mi));
	ifr.ifr_data = (caddr_t)&mi;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCGUMBINFO, (caddr_t)&ifr) == -1)
		return;

	if (mi.nwerror) {
		/* 3GPP 24.008 Cause Code */
		fprintf(outfile, "  error: ");
		switch (mi.nwerror) {
		case 2:
			fprintf(outfile, "SIM not activated");
			break;
		case 4:
			fprintf(outfile, "Roaming not supported");
			break;
		case 6:
			fprintf(outfile, "SIM reported stolen");
			break;
		case 7:
			fprintf(outfile, "No GPRS subscription");
			break;
		case 8:
			fprintf(outfile, "GPRS and non-GPRS services "
			    "not allowed");
			break;
		case 11:
			fprintf(outfile, "Subscription expired");
			break;
		case 12:
			fprintf(outfile, "Subscription does not cover "
			    "current location");
			break;
		case 13:
			fprintf(outfile, "No roaming in this location");
			break;
		case 14:
			fprintf(outfile, "GPRS not supported");
			break;
		case 15:
			fprintf(outfile, "No subscription for the service");
			break;
		case 17:
			fprintf(outfile, "Registration failed");
			break;
		case 22:
			fprintf(outfile, "Network congestion");
			break;
		default:
			fprintf(outfile, "Error code %d", mi.nwerror);
			break;
		}
		putc('\n', outfile);
	}

	fprintf(outfile, "  roaming %s registration %s",
	    mi.enable_roaming ? "enabled" : "disabled",
	    umb_val2descr(umb_regstate, mi.regstate));
	utf16_to_char(mi.roamingtxt, UMB_ROAMINGTEXT_MAXLEN,
	    roamingtxt, sizeof (roamingtxt));
	if (roamingtxt[0])
		fprintf(outfile, " [%s]", roamingtxt);
	fputc('\n', outfile);

	umb_printclasses("available classes", mi.supportedclasses, outfile);
	fprintf(outfile, "  state %s cell-class %s",
	    umb_val2descr(umb_istate, mi.state),
	    umb_val2descr(umb_dataclass, mi.highestclass));
	if (mi.rssi != UMB_VALUE_UNKNOWN && mi.rssi != 0)
		fprintf(outfile, " rssi %ddBm", mi.rssi);
	if (mi.uplink_speed != 0 || mi.downlink_speed != 0) {
		char s[2][FMT_SCALED_STRSIZE];
		if (fmt_scaled(mi.uplink_speed, s[0]) != 0)
			snprintf(s[0], sizeof (s[0]), "%llu", mi.uplink_speed);
		if (fmt_scaled(mi.downlink_speed, s[1]) != 0)
			snprintf(s[1], sizeof (s[1]), "%llu", mi.downlink_speed);
		fprintf(outfile, " speed %sbps up %sbps down", s[0], s[1]);
	}
	fputc('\n', outfile);

	fprintf(outfile, "  SIM %s PIN ",
	    umb_val2descr(umb_simstate, mi.sim_state));
	switch (mi.pin_state) {
	case UMB_PIN_REQUIRED:
		fprintf(outfile, "required");
		break;
	case UMB_PIN_UNLOCKED:
		fprintf(outfile, "valid");
		break;
	case UMB_PUK_REQUIRED:
		fprintf(outfile, "locked (PUK required)");
		break;
	default:
		fprintf(outfile, "unknown state (%d)", mi.pin_state);
		break;
	}
	if (mi.pin_attempts_left != UMB_VALUE_UNKNOWN)
		fprintf(outfile, " (%d attempts left)", mi.pin_attempts_left);
	fputc('\n', outfile);

	utf16_to_char(mi.sid, UMB_SUBSCRIBERID_MAXLEN, sid, sizeof (sid));
	utf16_to_char(mi.iccid, UMB_ICCID_MAXLEN, iccid, sizeof (iccid));
	utf16_to_char(mi.provider, UMB_PROVIDERNAME_MAXLEN,
	    provider, sizeof (provider));
	utf16_to_char(mi.providerid, UMB_PROVIDERID_MAXLEN,
	    providerid, sizeof (providerid));
	if (sid[0] || iccid[0]) {
		fprintf(outfile, "  ");
		n = 0;
		if (sid[0])
			fprintf(outfile, "%ssubscriber-id %s",
			    n++ ? " " : "", sid);
		if (iccid[0])
			fprintf(outfile, "%sICC-id %s", n++ ? " " : "", iccid);
		printf("\n");
	}

	utf16_to_char(mi.hwinfo, UMB_HWINFO_MAXLEN, hwinfo, sizeof (hwinfo));
	utf16_to_char(mi.devid, UMB_DEVID_MAXLEN, devid, sizeof (devid));
	utf16_to_char(mi.fwinfo, UMB_FWINFO_MAXLEN, fwinfo, sizeof (fwinfo));
	if (hwinfo[0] || devid[0] || fwinfo[0]) {
		fprintf(outfile, "  ");
		n = 0;
		if (hwinfo[0])
			fprintf(outfile, "%sdevice %s", n++ ? " " : "", hwinfo);
		if (devid[0]) {
			fprintf(outfile, "%s", n++ ? " " : "");
			switch (mi.cellclass) {
			case MBIM_CELLCLASS_GSM:
				fprintf(outfile, "IMEI");
				break;
			case MBIM_CELLCLASS_CDMA:
				n = strlen(devid);
				if (n == 8 || n == 11) {
					fprintf(outfile, "ESN");
					break;
				} else if (n == 14 || n == 18) {
					fprintf(outfile, "MEID");
					break;
				}
				/*FALLTHROUGH*/
			default:
				fprintf(outfile, "ID");
				break;
			}
			fprintf(outfile, " %s", devid);
		}
		if (fwinfo[0])
			fprintf(outfile, "%sfirmware %s", n++ ? " " : "",
			    fwinfo);
		fputc('\n', outfile);
	}

	utf16_to_char(mi.pn, UMB_PHONENR_MAXLEN, pn, sizeof (pn));
	utf16_to_char(mi.apn, UMB_APN_MAXLEN, apn, sizeof (apn));
	if (pn[0] || apn[0] || provider[0] || providerid[0]) {
		fprintf(outfile, "  ");
		n = 0;
		if (pn[0])
			fprintf(outfile, "%sphone# %s", n++ ? " " : "", pn);
		if (apn[0])
			fprintf(outfile, "%sAPN %s", n++ ? " " : "", apn);
		if (provider[0])
			fprintf(outfile, "%sprovider %s", n++ ? " " : "",
			    provider);
		if (providerid[0])
			fprintf(outfile, "%sprovider-id %s", n ? " " : "",
			    providerid);
		fputc('\n', outfile);
	}

	for (i = 0, n = 0; i < UMB_MAX_DNSSRV; i++) {
		if (mi.ipv4dns[i].s_addr == INADDR_ANY)
			break;
		fprintf(outfile, "%s %s", n++ ? "" : "  dns",
		    inet_ntop(AF_INET, &mi.ipv4dns[i], astr, sizeof(astr)));
	}

	for (i = 0; i < UMB_MAX_DNSSRV; i++) {
		if (memcmp(&mi.ipv6dns[i], &in6addr_any,
		    sizeof (mi.ipv6dns[i])) == 0)
			break;
		fprintf(outfile, "%s %s", n++ ? "" : "  dns",
		    inet_ntop(AF_INET6, &mi.ipv6dns[i], astr, sizeof(astr)));
	}

	if (n)
		fputc('\n', outfile);
}

void
umb_printclasses(char *tag, int c, FILE *outfile)
{
	int	 i;
	char	*sep = "";

	fprintf(outfile, "  %s: ", tag);
	i = 0;
	while (umb_dataclass[i].descr) {
		if (umb_dataclass[i].val & c) {
			fprintf(outfile, "%s%s", sep, umb_dataclass[i].descr);
			sep = ",";
		}
		i++;
	}
	fputc('\n', outfile);
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
		str = strtok(NULL, ",");
	}
	free(optlist);
	return c;
}

void
umb_setpin(int ifs, char *ifname, const char *pin)
{
	if (umb_pinop(ifs, ifname, MBIM_PIN_OP_ENTER, 0, pin, NULL)
	    == 0) {
		db_delete_flag_x_ctl("pin", ifname, 0);
		if (pin != NULL)
			db_insert_flag_x("pin", ifname, 0, 0, (char *)pin);
	}
}

void
umb_chgpin(int ifs, char *ifname, const char *pin, const char *newpin)
{
	umb_pinop(ifs, ifname, MBIM_PIN_OP_CHANGE, 0, pin, newpin);
}

void
umb_puk(int ifs, char *ifname, const char *pin, const char *newpin)
{
	umb_pinop(ifs, ifname, MBIM_PIN_OP_ENTER, 1, pin, newpin);
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

void
umb_apn(int ifs, char *ifname, const char *apn)
{
	struct umb_parameter mp;
	struct ifreq ifr;

	memset(&mp, 0, sizeof (mp));
	ifr.ifr_data = (caddr_t)&mp;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCGUMBPARAM, (caddr_t)&ifr) == -1) {
		printf("%% umb_apn: SIOCGUMBPARAM: %s\n", strerror(errno));
		return;
	}

	if (apn == NULL)
		memset(mp.apn, 0, sizeof (mp.apn));
	else if ((mp.apnlen = char_to_utf16(apn, mp.apn,
	    sizeof (mp.apn))) == -1) {
		printf("%% APN too long\n");
		return;
	}

	if (ioctl(ifs, SIOCSUMBPARAM, (caddr_t)&ifr) == -1)
		printf("%% umb_apn: SIOCSUMBPARAM: %s\n", strerror(errno));
}

void
umb_setclass(int ifs, char *ifname, const char *val)
{
	struct umb_parameter mp;
	struct ifreq ifr;

	memset(&mp, 0, sizeof (mp));
	ifr.ifr_data = (caddr_t)&mp;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCGUMBPARAM, (caddr_t)&ifr) == -1) {
		printf("%% umb_setclass: SIOCGUMBPARAM: %s\n", strerror(errno));
		return;
	}
	if (val)
		mp.preferredclasses = umb_parse_classes(val);
	else
		mp.preferredclasses = MBIM_DATACLASS_NONE;
	if (mp.preferredclasses == -1)
		return;
	if (ioctl(ifs, SIOCSUMBPARAM, (caddr_t)&ifr) == -1)
		printf("%% umb_setclass: SIOCSUMBPARAM: %s\n", strerror(errno));
}

void
umb_roaming(int ifs, char *ifname, int roaming)
{
	struct umb_parameter mp;
	struct ifreq ifr;

	memset(&mp, 0, sizeof (mp));
	ifr.ifr_data = (caddr_t)&mp;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifs, SIOCGUMBPARAM, (caddr_t)&ifr) == -1) {
		printf("%% umb_roaming: SIOCGUMBPARAM: %s\n", strerror(errno));
		return;
	}
	mp.roaming = roaming;
	if (ioctl(ifs, SIOCSUMBPARAM, (caddr_t)&ifr) == -1)
		printf("%% umb_roaming: SIOCSUMBPARAM: %s\n", strerror(errno));
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
intumb(char *ifname, int ifs, int argc, char **argv)
{
	int set;
	struct umbc *x;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	x=(struct umbc *) genget(argv[0], (char **)umbcs, sizeof(struct umbc));
	if (x == 0) {
		printf("%% intumb: Internal error - Invalid argument %s\n", argv[0]);
		return(0);
	} else if (Ambiguous(x)) {
		printf("%% intumb: Internal error - Ambiguous argument %s\n", argv[0]);
		return(0);
	}

	argc--;
	argv++;

	if ((x->type == UMB_ROAMING) &&
	    ((!set && argc > 0) || (set && argc != 0))) {
		printf("%% %s\n", x->name);
		printf("%% no %s\n", x->name);
		return(0);
	}

	if (((x->type == UMB_CHGPIN) || (x->type == UMB_PUK)) &&
	    (set && argc != 2)) {
		printf("%% %s <%s> <%s>\n", x->name, x->descr, x->descr2);
		return(0);
	}

	if ((x->type == UMB_APN || x->type == UMB_PIN || x->type ==
	    UMB_CLASS) &&
	    ((!set && argc > 1) || (set && argc != 1))) {
		printf("%% %s <%s>\n", x->name, x->descr);
		printf("%% no %s [%s]\n", x->name, x->descr);
		return(0);
	}

	switch(x->type) {
	case UMB_APN:
		if (!set) {
			umb_apn(ifs, ifname, NULL);
		} else {
			umb_apn(ifs, ifname, argv[0]);
		}
		break;

	case UMB_PIN:
		if (!set) {
			umb_setpin(ifs, ifname, NULL);
		} else {
			umb_setpin(ifs, ifname, argv[0]);
		}
		break;

	case UMB_PUK:
		if (!set) {
			umb_puk(ifs, ifname, NULL, NULL);
		} else {
			umb_puk(ifs, ifname, argv[0], argv[1]);
		}
		break;

	case UMB_CHGPIN:
		if (!set) {
			umb_chgpin(ifs, ifname, NULL, NULL);
		} else {
			umb_chgpin(ifs, ifname, argv[0], argv[1]);
		}
		break;

	case UMB_CLASS:
		if (!set) {
			umb_setclass(ifs, ifname, NULL);
		} else {
			umb_setclass(ifs, ifname, argv[0]);
		}
		break;

	case UMB_ROAMING:
		if (!set) {
			umb_roaming(ifs, ifname, 0);
		} else {
			umb_roaming(ifs, ifname, 1);
		}
		break;

	default:
		printf("%% intumb: internal error\n");
	}
	return 0;
}

void
conf_umb(FILE *output, int ifs, char *ifname)
{
	struct umb_parameter mp;
	struct ifreq ifr;
	char apn[UMB_APN_MAXLEN+1];

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
	fprintf(output, " class %s\n",
	    umb_val2descr(umb_dataclass, mp.preferredclasses));
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
