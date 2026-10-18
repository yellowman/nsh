/*
 * Copyright (c) 2002-2009 Chris Cappuccio <chris@nmedia.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/limits.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <net/if_vlan_var.h>
#include <net/route.h>
#include <net/pfvar.h>
#include <netmpls/mpls.h>
#include <netinet/ip_ipsp.h>
#include <net/if_pfsync.h>
#include <net/if_pflow.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <limits.h>
#include "stringlist.h"
#include "externs.h"
#include "bridge.h"
#include "ctl.h"
#include "sysctl.h"

#define IPSIZ  256	/*
			 * max theoretical size of ipv4 or ipv6
			 * text representation
			 */
#define TMPSIZ 1024	/* size of temp strings */
#define ROUTEMTU 32768	/* common route MTU */

void conf_db_single(FILE *, char *, char *, char *);
void conf_print_rtm(FILE *, struct rt_msghdr *, char *, int);
int conf_ifaddrs(FILE *, char *, int, int);
int conf_ifaddr_dhcp(FILE *, char *, int, int);
void conf_lladdr(FILE *, char *);
void conf_ifflags(FILE *, int, char *, int, u_char);
void conf_vnetid(FILE *, int, char *);
void conf_vnetflowid(FILE *, int, char *);
void conf_parent(FILE *, int, char *);
void conf_patch(FILE *, int, char *);
void conf_ifxflags(FILE *, int, char *);
void conf_rtables(FILE *);
void conf_rtables_rtable(FILE *, int);
void conf_rdomain(FILE *, int, char *);
void conf_tunnel(FILE *, int, char *);
void conf_ifmetrics(FILE *, int, struct if_data, char *);
void conf_pflow(FILE *, int, char *);
void conf_pwe3(FILE *, int, char *);
void conf_ctl(FILE *, char *, char *, int);
void conf_intrtlabel(FILE *, int, char *);
void conf_intgroup(FILE *, int, char *);
void conf_keepalive(FILE *, int, char *);
void conf_rtflags(char *, int, struct rt_msghdr *rtm);
int dhcpleased_has_defaultroute(struct sockaddr_rtlabel *);
int dhcpleased_controls_interface(char *, int);
int islateif(char *);
int isdefaultroute(struct sockaddr *, struct sockaddr *);
int scantext(char *, char *);
int ipv6ll_db_compare(struct sockaddr_in6 *, struct sockaddr_in6 *,
    char *);

static const struct {
	char *name;
	u_long mtu;
} defmtus[] = {
	{ "gre",	1476 },
	{ "wg",		1420 },
	{ "gif",	1280 },
	{ "enc",	1536 },
	{ "pflow",	MTU_IGNORE },
	{ "pflog",	MTU_IGNORE },
	{ "pfsync",	MTU_IGNORE },
	{ "lo",		MTU_IGNORE },
};

static const struct {
	char *name;
	int rxprio;
	int txprio;
} defprios[] = {
	{ "bpe",	IF_HDRPRIO_OUTER,	IF_HDRPRIO_PACKET },
	{ "nvgre",	IF_HDRPRIO_PACKET,	0 },
	{ "etherip",	IF_HDRPRIO_PACKET,	0 },
	{ "gre",	IF_HDRPRIO_PACKET,	IF_HDRPRIO_PAYLOAD },
	{ "mgre",	IF_HDRPRIO_PACKET,	IF_HDRPRIO_PAYLOAD },
	{ "egre",	IF_HDRPRIO_PACKET,	0 },
	{ "mpe",	IF_HDRPRIO_PACKET,	0 },
	{ "mpip",	IF_HDRPRIO_PACKET,	0 },
	{ "mpw",	IF_HDRPRIO_PACKET,	0 },
	{ "vxlan",	IF_HDRPRIO_OUTER,	0 },
	{ "vlan",	IF_HDRPRIO_OUTER,	IF_HDRPRIO_PACKET },
	{ "svlan",	IF_HDRPRIO_OUTER,	IF_HDRPRIO_PACKET },
	{ "gif",	IF_HDRPRIO_PAYLOAD,	IF_HDRPRIO_PAYLOAD },
	{ "eoip",	IF_HDRPRIO_PACKET,	0 },
};

static const struct {
	char *name;
	int llpriority;
} defllpriority[] = {
	{ "gre",	IFQ_TOS2PRIO(IPTOS_PREC_INTERNETCONTROL) },
	{ "aggr",	IFQ_MAXPRIO },
	{ "tpmr",	IFQ_MAXPRIO },
};

static void conf_hostname(FILE *);
static void conf_secret(FILE *);
static void conf_top_arp(FILE *);
static void conf_top_ndp(FILE *);
static void conf_top_routes(FILE *);
static void conf_top_routes6(FILE *);
static void conf_crontab(FILE *);

#define CONF_SEP	0	/* a "!" line */
#define CONF_FUNC	1	/* conf(output) prints the section */
#define CONF_IFS	2	/* interfaces named name*, or with NULL the rest */
#define CONF_CTL	3	/* the daemon called name */

/*
 * CONF_IFS interfaces get started in a specific order
 *
 * pfsync gets delayed until pf rules are loaded
 *
 * /etc/netstart says:
 *
 * The trunk interfaces need to come up first in this list.
 * The (s)vlan interfaces need to come up after trunk.
 * Configure all the carp interfaces which we know about before default route.
 *
 * Configure PPPoE, GIF, GRE and TUN interfaces, delayed because they require
 * routes to be set.  TUN might depend on PPPoE, and GIF or GRE may depend on
 * either of them.
 */
static const struct {
	int kind;
	char *name;
	void (*conf)(FILE *);
} confrows[] = {
	{ CONF_SEP,	NULL,		NULL },
	{ CONF_FUNC,	NULL,		conf_hostname },
	{ CONF_FUNC,	NULL,		conf_secret },
	{ CONF_SEP,	NULL,		NULL },
	{ CONF_CTL,	"motd",		NULL },
	/* start all interfaces not named in a CONF_IFS row */
	{ CONF_IFS,	NULL,		NULL },
	/* start these interfaces in specific order */
	{ CONF_IFS,	"aggr",		NULL },
	{ CONF_IFS,	"trunk",	NULL },
	{ CONF_IFS,	"svlan",	NULL },
	{ CONF_IFS,	"vlan",		NULL },
	{ CONF_IFS,	"carp",		NULL },
	{ CONF_IFS,	"pppoe",	NULL },
	{ CONF_SEP,	NULL,		NULL },
	/*
	 * check out how sysctls are doing these days
	 *
	 * Each of these options, like most other things in the config output
	 * (such as interface flags), must display if the kernel's default
	 * setting is not currently set.
	 */
	{ CONF_FUNC,	NULL,		conf_sysctls },
	{ CONF_SEP,	NULL,		NULL },
	/* print static arp and route entries in configuration file format */
	{ CONF_FUNC,	NULL,		conf_top_arp },
	{ CONF_FUNC,	NULL,		conf_top_ndp },
	{ CONF_FUNC,	NULL,		conf_top_routes },
	{ CONF_FUNC,	NULL,		conf_top_routes6 },
	{ CONF_SEP,	NULL,		NULL },
	/* these interfaces must start after routes are set */
	{ CONF_IFS,	"tun",		NULL },
	{ CONF_IFS,	"tap",		NULL },
	{ CONF_IFS,	"gif",		NULL },
	{ CONF_IFS,	"etherip",	NULL },
	{ CONF_IFS,	"gre",		NULL },
	{ CONF_IFS,	"egre",		NULL },
	{ CONF_IFS,	"nvgre",	NULL },
	{ CONF_IFS,	"eoip",		NULL },
	{ CONF_IFS,	"vxlan",	NULL },
	{ CONF_IFS,	"wg",		NULL },
	{ CONF_IFS,	"bridge",	NULL },
	{ CONF_IFS,	"veb",		NULL },
	{ CONF_IFS,	"tpmr",		NULL },
	{ CONF_SEP,	NULL,		NULL },
	{ CONF_CTL,	"pf",		NULL },
	/* these interfaces must start after pf is loaded */
	{ CONF_IFS,	"pfsync",	NULL },
	{ CONF_IFS,	"pflow",	NULL },
	{ CONF_CTL,	"snmp",		NULL },
	{ CONF_CTL,	"resolv",	NULL },
	{ CONF_CTL,	"ldp",		NULL },
	{ CONF_CTL,	"rip",		NULL },
	{ CONF_CTL,	"ospf",		NULL },
	{ CONF_CTL,	"ospf6",	NULL },
	{ CONF_CTL,	"bgp",		NULL },
	{ CONF_CTL,	"ifstate",	NULL },
	{ CONF_CTL,	"ipsec",	NULL },
	{ CONF_CTL,	"ike",		NULL },
	{ CONF_CTL,	"rad",		NULL },
	{ CONF_CTL,	"dvmrp",	NULL },
	{ CONF_CTL,	"relay",	NULL },
	{ CONF_CTL,	"sasync",	NULL },
	{ CONF_CTL,	"dhcp",		NULL },
	{ CONF_CTL,	"ntp",		NULL },
	{ CONF_CTL,	"smtp",		NULL },
	{ CONF_CTL,	"ldap",		NULL },
	{ CONF_CTL,	"ftp-proxy",	NULL },
	{ CONF_CTL,	"inet",		NULL },
	{ CONF_CTL,	"sshd",		NULL },
	{ CONF_FUNC,	NULL,		conf_crontab },
	{ CONF_FUNC,	NULL,		conf_rtables },
	{ CONF_SEP,	NULL,		NULL },
	{ CONF_FUNC,	NULL,		conf_nameserver },
};

int
conf(FILE *output)
{
	size_t i;

	for (i = 0; i < nitems(confrows); i++) {
		switch (confrows[i].kind) {
		case CONF_SEP:
			fprintf(output, "!\n");
			break;
		case CONF_FUNC:
			confrows[i].conf(output);
			break;
		case CONF_IFS:
			conf_interfaces(output, confrows[i].name, 0);
			break;
		case CONF_CTL:
			conf_ctl(output, "", confrows[i].name, 0);
			break;
		}
	}

	return 0;
}

static void
conf_hostname(FILE *output)
{
	char hostbuf[MAXHOSTNAMELEN];

	gethostname (hostbuf, sizeof(hostbuf));
	fprintf(output, "hostname %s\n", hostbuf);
}

static void
conf_secret(FILE *output)
{
	char cpass[_PASSWORD_LEN+1];

	if (read_pass(cpass, sizeof(cpass))) {
		fprintf(output, "enable secret blowfish %s\n", cpass);
	} else {
		if (errno != ENOENT)
			printf("%% Unable to read run-time crypt repository:"
			    " %s\n", strerror(errno));
	}
}

static void
conf_top_arp(FILE *output)
{
	conf_arp(output, "arp ");
}

static void
conf_top_ndp(FILE *output)
{
	conf_ndp(output, "ndp ");
}

static void
conf_top_routes(FILE *output)
{
	conf_routes(output, "route ", AF_INET, RTF_STATIC, 0);
}

static void
conf_top_routes6(FILE *output)
{
	conf_routes(output, "route ", AF_INET6, RTF_STATIC, 0);
}

static void
conf_crontab(FILE *output)
{
	off_t offset;

	offset = ftello(output);
	conf_ctl(output, "", "crontab", 0);
	if (offset != ftello(output)) /* we have custom crontab rules */
		fprintf(output, "crontab install\n");
}

void
conf_rtables(FILE *output)
{
	int i, rtableid;
	StringList *rtables;

	rtables = sl_init();
	if (db_select_rtable_rtables(rtables) < 0) {
		printf("%% database failure select rtables rtable\n");
		sl_free(rtables, 1);
		return;
	}
	for (i = 0; i < rtables->sl_cur; i++) {
		const char *errmsg = NULL;

		rtableid = strtonum(rtables->sl_str[i], 0, RT_TABLEID_MAX, &errmsg);
		if (rtableid == 0)
			continue;
		if (errmsg) {
			printf("%% Invalid route table (%d) %s: %s\n",  i,
			    rtables->sl_str[i], errmsg);
			continue;
		}
		conf_rtables_rtable(output, rtableid);
	}

	sl_free(rtables, 1);
}

void
conf_rtables_rtable(FILE *output, int rtableid)
{
	int i;
	StringList *rtable_name, *rtable_daemons;

	rtable_name = sl_init();

	if (db_select_name_rtable(rtable_name, rtableid) < 0) {
		printf("%% database failure select rtables name\n");
		sl_free(rtable_name, 1);
		return;
	} else {
		fprintf(output, "rtable %d %s\n", rtableid,
		    rtable_name->sl_str[0]);
	}

	sl_free(rtable_name, 1);

	/*
	 * Routes must be printed before we attempt to start daemons,
	 * else rtables will not be created in the kernel (Unless an
	 * rdomain is created by specifing one on an interface prior
	 * to this point. An rdomain creates a new corresponding rtable)
	 */
	conf_arp(output, " arp ");
	conf_ndp(output, " ndp ");
	conf_routes(output, " route ", AF_INET, RTF_STATIC, rtableid);
	conf_routes(output, " route ", AF_INET6, RTF_STATIC, rtableid);

	rtable_daemons = sl_init();

	if (db_select_flag_x_ctl_rtable(rtable_daemons, "ctl", rtableid) < 0) {
		printf("%% database failure select ctl rtable\n");
		sl_free(rtable_daemons, 1);
		return;
	} else {
		for (i = 0; i < rtable_daemons->sl_cur; i++)
			conf_ctl(output, " ", rtable_daemons->sl_str[i], rtableid);
	}

	sl_free(rtable_daemons, 1);

	fprintf(output, "!\n");
}

/*
 * Figure out whether this particular ctl accepts the standard "enable",
 * etc. argument or calls them something else.
 * This is done by mapping DB_X_ flags to ctl table entry names.
 *
 * XXX This currently ignores "disable" arguments; They will always be
 * displayed as "disable" even when the table entry with the DB_X_DISABLE
 * flag uses a different name...
 */ 
static void
get_argnames(int flag_x, char *name, int *defenable, char **fenablenm,
    char **flocalnm, char **fothernm)
{
	switch(flag_x) {
	case DB_X_ENABLE_DEFAULT:
		*defenable = 1;
		/* FALLTHROUGH */
	case DB_X_ENABLE:
		*fenablenm = name;
		break;
	case DB_X_LOCAL:
		*flocalnm = name;
		break;
	case DB_X_OTHER:
		*fothernm = name;
		break;
	case DB_X_DISABLE:
	case DB_X_REMOVE:
	case DB_X_DISABLE_ALWAYS:
	case 0:
		break;
	default:
		printf("%% conf_ctl: flag_x %d unknown\n", flag_x);
	}
}

void
conf_ctl(FILE *output, char *delim, char *name, int rtableid)
{
	FILE *conf;
	struct daemons *x;
	struct ctl *ctl;
	char tmp_str[TMPSIZ], tmpfile[64];
	char *fenablenm = NULL, *fothernm = NULL, *flocalnm = NULL;
	int defenable = 0, pntdrules = 0, pntdflag = 0, dbflag;

	x = (struct daemons *)genget(name, (char **)ctl_daemons,
	    sizeof(struct daemons));
	if (x == NULL || Ambiguous(x)) {
		printf("%% conf_ctl: %s: genget internal failure\n",
		    name);
		return;
	}

	/* print rules if they exist (only when tmpfile base is defined) */
	if (x->tmpfile != NULL) {
		snprintf(tmpfile, sizeof(tmpfile), "%s.%d", x->tmpfile, rtableid);
		if ((conf = fopen(tmpfile, "r")) != NULL) {
			fprintf(output, "%s%s rules\n", delim, name);
			for (;;) {
				if(fgets(tmp_str, TMPSIZ, conf) == NULL)
					break;
				if(tmp_str[0] == 0)
					break;
				fprintf(output, "%s %s", delim, tmp_str);
			}
			fclose(conf);
			fprintf(output, "%s!\n", delim);
			pntdrules = 1;
		} else if (errno != ENOENT || (errno == ENOENT && verbose))
			printf("%% conf_ctl: %s: %s\n", tmpfile, strerror(errno));
	}

	/* fill in argument names from table */
	for (ctl = x->table; ctl != NULL && ctl->name != NULL; ctl++) {
		get_argnames(ctl->flag_x, ctl->name, &defenable, &fenablenm,
		    &flocalnm, &fothernm);
	}

	/* print rules as currently enabled in running time database */
	if ((dbflag = db_select_flag_x_dbflag_rtable("ctl", x->name, rtableid))
	    < 0) {
		printf("%% database ctl select failure (%s, %d)\n", x->name,
		    rtableid);
		return;
	}
	switch(dbflag) {
	case DB_X_ENABLE:
		fprintf(output, "%s%s %s\n", delim, x->name, fenablenm ?
		    fenablenm : "enable");
		pntdflag = 1;
		break;
	case DB_X_LOCAL:
		fprintf(output, "%s%s %s\n", delim, x->name, flocalnm ?
		    flocalnm : "local");
		pntdflag = 1;
		break;
	case DB_X_OTHER:
		fprintf(output, "%s%s %s\n", delim, x->name, fothernm ?
		    fothernm : "other");
		pntdflag = 1;
		break;
	case DB_X_DISABLE_ALWAYS:
		fprintf(output, "%s%s disable\n", delim, x->name);
		pntdflag = 1;
		/* FALLTHROUGH */
	case DB_X_DISABLE:
		defenable = 0;
		break;
	case DB_X_REMOVE:
	case DB_X_ENABLE_DEFAULT:
	case 0:
		break;
	default:
		printf("%% conf_ctl: dbflag %d unknown\n", dbflag);
	}
	if (defenable) {
		fprintf(output, "%s%s %s\n", delim, x->name, fenablenm ?
		    fenablenm : "enable");
		pntdflag = 1;
	}
	if (pntdrules && x->doreload) {
		fprintf(output, "%s%s reload\n", delim, x->name);
		pntdflag = 1;
	}
	if (pntdflag)
		fprintf(output, "%s!\n", delim);
}

int
dhcpleased_has_defaultroute(struct sockaddr_rtlabel *sr)
{
	return (sr != NULL && strcmp(sr->sr_label, "dhcpleased") == 0);
}

/* Check whether IPv4 addresses on an interface are managed by dhcpleased. */
int
dhcpleased_controls_interface(char *ifname, int ifs)
{
	int ifxflags;

	if (!dhcpleased_is_running())
		return 0;

	ifxflags = get_ifxflags(ifname, ifs);
	return ((ifxflags & IFXF_AUTOCONF4) != 0);
}

/*
 * Check whether a specific IPv4 addresses on an interface is
 * managed by dhcpleased.
 */
int
dhcpleased_has_address(char *ifname, const char *address,
    const char *netmask)
{
	char *argv[] = { DHCPLEASECTL, "-l", ifname, NULL };
	int address_found = 0;
	char ortext[128];
	char outpath[PATH_MAX];
	int fd = -1, nullfd = -1;

	if (!dhcpleased_is_running())
		return 0;

	snprintf(ortext, sizeof(ortext), "\tinet %s netmask %s\n",
	    address, netmask);

	nullfd = open("/dev/null", O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
	if (nullfd == -1) {
		printf("%% open /dev/null: %s\n", strerror(errno));
		return 0;
	}

	strlcpy(outpath, "/tmp/nsh-XXXXXX", sizeof(outpath));
	fd = mkstemp(outpath);
	if (fd == -1) {
		printf("%% mkstemp: %s\n", strerror(errno));
		close(nullfd);
		return 0;
	}

	if (cmdargs_output(DHCPLEASECTL, argv, fd, nullfd) == 0 &&
	    scantext(outpath, ortext))
		address_found = 1;

	unlink(outpath);
	close(fd);
	close(nullfd);
	return (address_found);
}

/* find string in file */
int
scantext(char *fname, char *string)
{
	FILE *file;
	char line[128];
	int found = 0;

	if ((file = fopen(fname, "r")) == 0) {
		printf("%% Unable to open %s: %s\n", fname, strerror(errno));
		return 0;
	}

	for (;;) {
		if (fgets(line, sizeof(line), file) == NULL)
			break;
		if (strcmp(line, string) == 0) {
			found = 1;
			break;
		}
	}

	fclose(file);
	return found;
}

int
islateif(char *ifname)
{
	size_t i;

	for (i = 0; i < nitems(confrows); i++)
		if (confrows[i].kind == CONF_IFS && confrows[i].name != NULL &&
		    isprefix(confrows[i].name, ifname))
			return 1;

	return 0;
}

void
conf_db_single(FILE *output, char *dbname, char *lookup, char *ifname)
{
	StringList *dbreturn;
	dbreturn = sl_init();

	if (db_select_flag_x_ctl(dbreturn, dbname, ifname) < 0) {
		printf("%% conf_db_single %s database select failed\n", dbname);
	}
	if (dbreturn->sl_cur > 0) {
		if (lookup == NULL)
			fprintf(output, " %s\n", dbname);
		else if (strcmp(dbreturn->sl_str[0], lookup) != 0)
			fprintf(output, " %s %s\n", dbname, dbreturn->sl_str[0]);
	}
	sl_free(dbreturn, 1);
}

/*
 * What conf_interfaces() knows about the interface it is printing
 */
struct intconf {
	FILE *output;
	int ifs;
	char *ifname;
	int flags;			/* from SIOCGIFFLAGS */
	struct if_data *if_data;	/* from SIOCGIFDATA */
	int ippntd;			/* set by the address row */
};

static void
intconf_description(struct intconf *ic)
{
	char ifdescr[IFDESCRSIZE];
	struct ifreq ifrdesc;

	/*
	 * description, if available
	 * copied straight from ifconfig.c
	 */
	memset(&ifrdesc, 0, sizeof(ifrdesc));
	strlcpy(ifrdesc.ifr_name, ic->ifname, sizeof(ifrdesc.ifr_name));
	ifrdesc.ifr_data = (caddr_t)&ifdescr;
	if (ioctl(ic->ifs, SIOCGIFDESCR, &ifrdesc) == 0 &&
	    strlen(ifrdesc.ifr_data))
		fprintf(ic->output, " description %s\n", ifrdesc.ifr_data);
}

static void
intconf_lladdr(struct intconf *ic)
{
	conf_lladdr(ic->output, ic->ifname);
}

static void
intconf_carp(struct intconf *ic)
{
	conf_carp(ic->output, ic->ifs, ic->ifname);
}

static void
intconf_ifmetrics(struct intconf *ic)
{
	conf_ifmetrics(ic->output, ic->ifs, *ic->if_data, ic->ifname);
}

static void
intconf_ifaddr(struct intconf *ic)
{
	ic->ippntd = conf_ifaddr_dhcp(ic->output, ic->ifname, ic->ifs,
	    ic->flags);
}

static void
intconf_media_status(struct intconf *ic)
{
	conf_media_status(ic->output, ic->ifs, ic->ifname);
}

static void
intconf_pfsync(struct intconf *ic)
{
	conf_pfsync(ic->output, ic->ifs, ic->ifname);
}

static void
intconf_trunk(struct intconf *ic)
{
	conf_trunk(ic->output, ic->ifs, ic->ifname);
}

static void
intconf_dhcrelay(struct intconf *ic)
{
	char tmp[24];

	if (conf_dhcrelay(ic->ifname, tmp, sizeof(tmp)) > 0)
		fprintf(ic->output, " dhcrelay %s\n", tmp);
}

static void
intconf_ifflags(struct intconf *ic)
{
	conf_ifflags(ic->output, ic->flags, ic->ifname, ic->ippntd,
	    ic->if_data->ifi_type);
}

#define INTCONF_ALL		0	/* every interface */
#define INTCONF_BRIDGE		1	/* bridge interfaces only */
#define INTCONF_NOTBRIDGE	2	/* every other interface */

/*
 * What conf_interfaces() prints for each interface, one row at a time.
 *
 * The output order is important!
 */
static const struct {
	int scope;
	void (*conf)(FILE *, int, char *);
	void (*conf_ic)(struct intconf *);
} intconf_rows[] = {
	{ INTCONF_ALL,		NULL,			intconf_description },
	{ INTCONF_ALL,		NULL,			intconf_lladdr },
	{ INTCONF_ALL,		conf_vnetid,		NULL },
	{ INTCONF_ALL,		conf_vnetflowid,	NULL },
	{ INTCONF_ALL,		conf_parent,		NULL },
	{ INTCONF_ALL,		conf_patch,		NULL },
	{ INTCONF_ALL,		conf_rdomain,		NULL },
	{ INTCONF_ALL,		conf_intrtlabel,	NULL },
	{ INTCONF_ALL,		conf_intgroup,		NULL },
	{ INTCONF_ALL,		NULL,			intconf_carp },
	{ INTCONF_ALL,		conf_tunnel,		NULL },
	{ INTCONF_ALL,		NULL,			intconf_ifmetrics },
	{ INTCONF_ALL,		NULL,			intconf_ifaddr },
	{ INTCONF_BRIDGE,	conf_brcfg,		NULL },
	{ INTCONF_NOTBRIDGE,	NULL,			intconf_media_status },
	{ INTCONF_NOTBRIDGE,	conf_keepalive,		NULL },
	{ INTCONF_NOTBRIDGE,	NULL,			intconf_pfsync },
	{ INTCONF_NOTBRIDGE,	NULL,			intconf_trunk },
	{ INTCONF_NOTBRIDGE,	conf_pflow,		NULL },
	{ INTCONF_NOTBRIDGE,	conf_pwe3,		NULL },
	{ INTCONF_NOTBRIDGE,	conf_ifxflags,		NULL },
	{ INTCONF_NOTBRIDGE,	NULL,			intconf_dhcrelay },
	{ INTCONF_NOTBRIDGE,	conf_sppp,		NULL },
	{ INTCONF_NOTBRIDGE,	conf_pppoe,		NULL },
	{ INTCONF_NOTBRIDGE,	conf_wg,		NULL },
	{ INTCONF_NOTBRIDGE,	conf_umb,		NULL },
	{ INTCONF_ALL,		NULL,			intconf_ifflags },
};

void
conf_interfaces(FILE *output, char *only, int exact_match)
{
	int ifs, flags, br;
	size_t i;
	struct intconf ic;

	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr;
	struct if_data if_data;

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% conf_interfaces: if_nameindex failed\n");
		return;
	}

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% conf_interfaces socket: %s\n", strerror(errno));
		if_freenameindex(ifn_list);
		return;
	}

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		if (only) {
			/* only interfaces which match, or start with ... */
			if (exact_match) {
				if (strcmp(only, ifnp->if_name) != 0)
					continue;
			} else if (!isprefix(only, ifnp->if_name))
				continue;
		}
		if (!only && islateif(ifnp->if_name))
			/* interface prefixes to exclude on generic run */
			continue;

		strlcpy(ifr.ifr_name, ifnp->if_name, sizeof(ifr.ifr_name));

		if (ioctl(ifs, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
			printf("%% conf: SIOCGIFFLAGS: %s\n", strerror(errno));
			continue;
		}
		flags = ifr.ifr_flags;

		ifr.ifr_data = (caddr_t)&if_data;
		if (ioctl(ifs, SIOCGIFDATA, (caddr_t)&ifr) < 0) {
			printf("%% conf: SIOCGIFDATA: %s\n", strerror(errno));
			continue;
		}

		/* set interface/bridge mode */
		if (!(br = is_bridge(ifs, ifnp->if_name)))
			br = 0;
		fprintf(output, "%s %s\n", br ? "bridge" : "interface",
		    ifnp->if_name);

		ic.output = output;
		ic.ifs = ifs;
		ic.ifname = ifnp->if_name;
		ic.flags = flags;
		ic.if_data = &if_data;
		ic.ippntd = 0;

		for (i = 0; i < nitems(intconf_rows); i++) {
			if ((intconf_rows[i].scope == INTCONF_BRIDGE && !br) ||
			    (intconf_rows[i].scope == INTCONF_NOTBRIDGE && br))
				continue;
			if (intconf_rows[i].conf != NULL)
				intconf_rows[i].conf(output, ifs,
				    ifnp->if_name);
			else
				intconf_rows[i].conf_ic(&ic);
		}
	}
	close(ifs);
	if_freenameindex(ifn_list);
}

void
conf_lladdr(FILE *output, char *ifname)
{
	StringList *hwdaddr;
	char *lladdr;

	/* We assume lladdr only useful if interface can get_hwdaddr */
	if ((lladdr = get_hwdaddr(ifname)) == NULL)
		return;

	hwdaddr = sl_init();

	if (db_select_flag_x_ctl(hwdaddr, "lladdr", ifname) < 0) {
		printf("%% lladdr database select failed\n");
	}
	if (hwdaddr->sl_cur > 0 && (strcmp(hwdaddr->sl_str[0],
	    lladdr) != 0))
		fprintf(output, " lladdr %s\n", lladdr);

	sl_free(hwdaddr, 1);
}

int
conf_ifaddr_dhcp(FILE *output, char *ifname, int ifs, int flags)
{
	int ippntd;

	/* find dhcpleased controlled interfaces */
	if (dhcpleased_controls_interface(ifname, ifs)) {
		fprintf(output, " autoconf4\n");
		/* print all non-autoconf ipv6 addresses */
		conf_ifaddrs(output, ifname, flags, AF_INET6);
		ippntd = 1;
	} else if (is_pppoe(ifname, ifs)) {
		int ipaddrmode = pppoe_get_ipaddrmode(ifname);
		if (ipaddrmode == NSH_PPPOE_IPADDR_IPCP) {
			fprintf(output, " autoconf4\n");
			ippntd = 1;
		} else if (ipaddrmode == NSH_PPPOE_IPADDR_STATIC) {
			fprintf(output, " no autoconf4\n");
			/* print all non-autoconf addresses */
			ippntd = conf_ifaddrs(output, ifname, flags, 0);
		} else
			ippntd = 0;
	} else {
		/* print all non-autoconf addresses */
		ippntd = conf_ifaddrs(output, ifname, flags, 0);
	}

	return ippntd;
}

void
conf_vnetid(FILE *output, int ifs, char *ifname)
{
	int64_t vnetid;

	if (((vnetid = get_vnetid(ifs, ifname)) != 0)) {
		if (vnetid < 0)
			fprintf(output, " vnetid any\n");
		else
			fprintf(output, " vnetid %lld\n", vnetid);
	}
}

void
conf_vnetflowid(FILE *output, int ifs, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGVNETFLOWID, &ifr) == -1)
		return;

	if (ifr.ifr_vnetid)
		fprintf(output, " vnetflowid\n");
}

void
conf_patch(FILE *output, int ifs, char *ifname)
{
	struct ifreq ifr;
	char ifix_buf[IFNAMSIZ];

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGIFPAIR, &ifr) == 0 && ifr.ifr_index != 0 &&
	    if_indextoname(ifr.ifr_index, ifix_buf) != NULL)
		fprintf(output, " patch %s\n", ifix_buf);
}

void
conf_parent(FILE *output, int ifs, char *ifname)
{
	struct if_parent ifp;

	memset(&ifp, 0, sizeof(ifp));
	strlcpy(ifp.ifp_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGIFPARENT, (caddr_t)&ifp) == -1) {
		if (errno != EADDRNOTAVAIL && errno != ENOTTY)
			printf("%% SIOCGIFPARENT %s: %s\n", ifname,
			    strerror(errno));
		return;
	}

	fprintf(output, " parent %s\n", ifp.ifp_parent);
}

void
conf_ifflags(FILE *output, int flags, char *ifname, int ippntd, u_char ift)
{
	if (flags & IFF_DEBUG)
		fprintf(output, " debug\n");
	if (flags & (IFF_LINK0|IFF_LINK1|IFF_LINK2))
		fprintf(output, " link%s%s%s\n",
		    flags & IFF_LINK0 ? " 0" : "",
		    flags & IFF_LINK1 ? " 1" : "",
		    flags & IFF_LINK2 ? " 2" : "");

	/* wg(4) sets IFF_NOARP by default and this should not be changed. */
	if (ift != IFT_WIREGUARD) {
		if (flags & IFF_NOARP)
			fprintf(output, " no arp\n");
		if (flags & IFF_STATICARP)
			fprintf(output, " staticarp\n");
	}

	if (isprefix("pppoe", ifname)) {		/* XXX */
		fprintf(output, " no shutdown\n");
	} else {
		/*
		 * address X/Y turns the interface up (just like 'no shutdown')
		 * ...but if we never had an ip address set and the interface
		 * is up, we need to save this state explicitly.
		 */
		if (!ippntd && (flags & IFF_UP))
			fprintf(output, " no shutdown\n");
		else if (!(flags & IFF_UP))
			fprintf(output, " shutdown\n");
	}
	fprintf(output, "!\n");
}

int
conf_dhcrelay(char *ifname, char *server, int serverlen)
{
	StringList *data;
	int alen;

	data = sl_init();
	if ((alen = db_select_flag_x_data_ctl_rtable(data, "dhcrelay", ifname, 0))
	    > 0) {
		strlcpy(server, data->sl_str[0], serverlen);
		alen = strlen(data->sl_str[0]);
	}
	sl_free(data, 1);

	return alen;
}

void
conf_pflow(FILE *output, int ifs, char *ifname)
{
	char sender[PFLOW_ADDRSTRLEN];
	char receiver[PFLOW_ADDRSTRLEN];
	char version[PFLOW_ADDRSTRLEN];

	if (pflow_status(PFLOW_SENDER, ifs, ifname, sender)) {
		return;
	}
	if (pflow_status(PFLOW_RECEIVER, ifs, ifname, receiver)) {
		return;
	}
	if (pflow_status(PFLOW_VERSION, ifs, ifname, version)) {
		return;
	}
	fprintf(output, " pflow sender %s receiver %s version %s\n",
	    sender, receiver, version);
}

void
conf_ifxflags(FILE *output, int ifs, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGIFXFLAGS, (caddr_t)&ifr) != -1) {
 		/* set mpls mode for eth interfaces */
		if (ifr.ifr_flags & IFXF_MPLS)
			fprintf(output, " mpls\n");
		if (ifr.ifr_flags & IFXF_AUTOCONF6)
			fprintf(output, " autoconf6\n");
		if (ifr.ifr_flags & IFXF_AUTOCONF6TEMP)
			fprintf(output, " temporary\n");
		if (ifr.ifr_flags & IFXF_MONITOR)
			fprintf(output, " monitor\n");
		if (ifr.ifr_flags & IFXF_WOL)
			fprintf(output, " wol\n");
	}
}

void
conf_rdomain(FILE *output, int ifs, char *ifname)
{
	int rdomainid;

	rdomainid = get_rdomain(ifs, ifname);
	if (rdomainid > 0)
		fprintf(output, " rdomain %d\n", rdomainid);
}
	
int
get_rdomain(int ifs, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGIFRDOMAIN, (caddr_t)&ifr) != -1)
		return ifr.ifr_rdomainid;
	return -1;
}

void
conf_keepalive(FILE *output, int ifs, char *ifname)
{
	struct ifkalivereq ikar;

	bzero(&ikar, sizeof(ikar));
	strlcpy(ikar.ikar_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGETKALIVE, &ikar) == 0 &&
	    (ikar.ikar_timeo != 0 || ikar.ikar_cnt != 0))
		fprintf(output, " keepalive %d %d\n",
		    ikar.ikar_timeo, ikar.ikar_cnt);
}

void
conf_pwe3(FILE *output, int ifs, char *ifname)
{
	int error, nei = 0, fat = 0, cw = 0;
	struct shim_hdr shim;
	struct ifreq ifr;

	struct if_laddrreq req;
	char hbuf[NI_MAXHOST];
	struct sockaddr_mpls *smpls;

	bzero(&ifr, sizeof(ifr));
	bzero(&shim, sizeof(shim));
	bzero(&req, sizeof(req));

	ifr.ifr_data = (caddr_t)&shim;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	strlcpy(req.iflr_name, ifname, sizeof(req.iflr_name));

	if (ioctl(ifs, SIOCGETLABEL, (caddr_t) &ifr) >= 0) {
		fprintf(output, " mplslabel %u\n", shim.shim_label);
	}

	if (ioctl(ifs, SIOCGPWE3NEIGHBOR, (caddr_t)&req) >= 0) {
		if (req.dstaddr.ss_family == AF_MPLS) {
			smpls = (struct sockaddr_mpls *)&req.dstaddr;
			error = getnameinfo((struct sockaddr *)&req.addr,
			    sizeof(req.addr), hbuf, sizeof(hbuf), NULL, 0,
			    NI_NUMERICHOST);
			if (error != 0) {
				printf("%% conf_pwe3: getnameinfo: %s\n",
				    gai_strerror(error));
			} else {
				nei = 1;
			}
		}
				
	}

	if (ioctl(ifs,  SIOCGPWE3FAT, (caddr_t)&ifr) >= 0) {
		if (ifr.ifr_pwe3)
			fat = 1;
	}

	if (ioctl(ifs,  SIOCGPWE3CTRLWORD, (caddr_t)&ifr) >= 0) {
		if (ifr.ifr_pwe3)
			cw = 1;
	}

	if (nei || cw || fat)
		fprintf(output, " pwe");
	if (nei)
		fprintf(output, " neighbor %u %s", smpls->smpls_label, hbuf);
	if (cw)
		fprintf(output, " cw");
	if (fat)
		fprintf(output, " fat");
	if (nei || cw || fat)
		fprintf(output, "\n");

}

void
conf_tunnel(FILE *output, int ifs, char *ifname)
{
	int dstport, physrtable;
	char tmpa[IPSIZ], tmpb[IPSIZ];

	if ((dstport=
	    phys_status(ifs, ifname, tmpa, tmpb, IPSIZ, IPSIZ)) >= 0) {
		int physttl;

		fprintf(output, " tunnel %s %s", tmpa, tmpb);
		if (dstport > 0)
			fprintf(output, ":%i", dstport);
		if ((physttl = get_physttl(ifs, ifname)) > 0)
			fprintf(output, " ttl %i", physttl);
		if ((get_physecn(ifs, ifname)) > 0)
			fprintf(output, " ecn");
		if ((get_physdf(ifs, ifname)) > 0)
			fprintf(output, " df");	
		fprintf(output, "\n");
	}
	/* non-tunnel interfaces can have a tunneldomain */
	if ((physrtable = get_physrtable(ifs, ifname)) != 0)
		fprintf(output, " tunneldomain %i\n", physrtable);
}

void
conf_ifmetrics(FILE *output, int ifs, struct if_data if_data,
    char *ifname)
{
	char tmp[TMPSIZ];
	struct ifreq ifr;

	/*
	 * print interface mtu, metric
	 */
	if (conf_mtu_shown(ifname, if_data.ifi_mtu))
		fprintf(output, " mtu %u\n", if_data.ifi_mtu);
	if (if_data.ifi_metric)
		fprintf(output, " metric %u\n", if_data.ifi_metric);

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(ifs, SIOCGIFPRIORITY, (caddr_t)&ifr) == 0 &&
	    ifr.ifr_metric)
		fprintf(output, " priority %u\n", ifr.ifr_metric);
	if (ioctl(ifs, SIOCGIFLLPRIO, (caddr_t)&ifr) == 0 &&
	    ifr.ifr_llprio != default_llpriority(ifr.ifr_name))
		fprintf(output, " llpriority %u\n", ifr.ifr_llprio);
	if (ioctl(ifs, SIOCGTXHPRIO, (caddr_t)&ifr) == 0 &&
	    ifr.ifr_hdrprio != default_txprio(ifr.ifr_name)) {
		switch(ifr.ifr_hdrprio) {
			case IF_HDRPRIO_PACKET:
				fprintf(output, " txprio packet\n");
				break;
			case IF_HDRPRIO_PAYLOAD:
				fprintf(output, " txprio payload\n");
				break;
			default:
				fprintf(output, " txprio %u\n",
				    ifr.ifr_hdrprio);
		}
	}
	if (ioctl(ifs, SIOCGRXHPRIO, (caddr_t)&ifr) == 0 &&
	    ifr.ifr_hdrprio != default_rxprio(ifr.ifr_name)) {
		switch(ifr.ifr_hdrprio) {
			case IF_HDRPRIO_PACKET:
				fprintf(output, " rxprio packet\n");
				break;
			case IF_HDRPRIO_PAYLOAD:
				fprintf(output, " rxprio payload\n");
				break;
			case IF_HDRPRIO_OUTER:
				fprintf(output, " rxprio outer\n");
				break;
			default:
				fprintf(output, " rxprio %u\n",
				    ifr.ifr_hdrprio);
		}
	}

	if (get_nwinfo(ifname, tmp, TMPSIZ, NWID) != 0) {
		fprintf(output, " nwid %s\n", tmp);
		if (get_nwinfo(ifname, tmp, TMPSIZ, NWKEY) != 0)
			fprintf(output, " nwkey %s\n", tmp);
		if (get_nwinfo(ifname, tmp, TMPSIZ, TXPOWER) != 0)
			fprintf(output, " txpower %s\n", tmp);
		if (get_nwinfo(ifname, tmp, TMPSIZ, POWERSAVE) != 0)
			fprintf(output, " powersave %s\n", tmp);
	}
}

int
ipv6ll_db_compare(struct sockaddr_in6 *sin6, struct sockaddr_in6 *sin6mask,
    char *ifname)
{
	int count, scope;
	StringList *data;
	struct in6_addr store;

	if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_INTFACELOCAL(&sin6->sin6_addr)) {
		/*
		 * Save any scope or embedded scope.
		 * The kernel does not set sin6_scope_id.
		 * But if it ever does, we're already prepared.
		 */
		store.s6_addr[0] = sin6->sin6_addr.s6_addr[2];
		store.s6_addr[1] = sin6->sin6_addr.s6_addr[3];
		sin6->sin6_addr.s6_addr[2] = sin6->sin6_addr.s6_addr[3] = 0;
		scope = sin6->sin6_scope_id;
		sin6->sin6_scope_id = 0;
		
		data = sl_init();
		db_select_flag_x_ctl_data(data, "ipv6linklocal", ifname,
		    netname6(sin6, sin6mask));
		count = data->sl_cur;
		sl_free(data, 1);

		/* restore any scope or embedded scope */
		sin6->sin6_addr.s6_addr[2] = store.s6_addr[0];
		sin6->sin6_addr.s6_addr[3] = store.s6_addr[1];
		sin6->sin6_scope_id = scope;
		return count;
	}
	return 1;
}


int
conf_ifaddrs(FILE *output, char *ifname, int flags, int af)
{
	struct ifaddrs *ifa, *ifap;
	struct sockaddr_in *sin, *sinmask, *sindest;
	struct sockaddr_in6 *sin6, *sin6mask, *sin6dest;
	struct in6_ifreq ifr6;
	struct in6_addrlifetime lt;
	char opts[sizeof(" anycast vltime 4294967295 pltime 4294967295")];
	int ippntd = 0, s6 = -1, anycast;

	if (getifaddrs(&ifap) != 0) {
		printf("%% conf: getifaddrs failed: %s\n",
		strerror(errno));
		return -1;
	}

	/*
	 * Cycle through getifaddrs for interfaces with our
	 * desired name that sport af or (AF_INET | AF_INET6).
	 * Print the IP and related information.
	 */
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (strncmp(ifname, ifa->ifa_name, IFNAMSIZ))
			continue;

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			if (af != AF_INET && af != 0)
				continue;
			sin = (struct sockaddr_in *)ifa->ifa_addr;
			if (sin->sin_addr.s_addr == INADDR_ANY)
				continue;
			sinmask = (struct sockaddr_in *)ifa->ifa_netmask;
			if (flags & IFF_POINTOPOINT) {
				sindest = (struct sockaddr_in *)ifa->ifa_dstaddr;
				fprintf(output, " inet %s",
				    routename4(sin->sin_addr.s_addr));
				if (ntohl(sindest->sin_addr.s_addr) !=
				    INADDR_ANY)
					fprintf(output, " %s",
					    inet_ntoa(sindest->sin_addr));
			} else if (flags & IFF_BROADCAST) {
				sindest = (struct sockaddr_in *)ifa->ifa_broadaddr;
				fprintf(output, " inet %s",
				    netname4(sin->sin_addr.s_addr, sinmask));
				/*
				 * don't save a broadcast address that would be
				 * automatically calculated by the kernel anyways
				 */
				if (ntohl(sindest->sin_addr.s_addr) !=
				    in4_brdaddr(sin->sin_addr.s_addr,
				    sinmask->sin_addr.s_addr) &&
				    ntohl(sindest->sin_addr.s_addr) !=
				    INADDR_ANY)
					fprintf(output, " %s",
					    inet_ntoa(sindest->sin_addr));
			} else {
				fprintf(output, " inet %s",
				    netname4(sin->sin_addr.s_addr, sinmask));
			}
			ippntd = 1;
			break;
		case AF_INET6:
			if (af != AF_INET6 && af != 0)
				continue;
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			sin6mask = (struct sockaddr_in6 *)ifa->ifa_netmask;

			if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
				continue;
			if (!ipv6ll_db_compare(sin6, sin6mask, ifname))
				continue;
			in6_fillscopeid(sin6);

			if (s6 == -1 &&
			    (s6 = socket(PF_INET6, SOCK_DGRAM, 0)) == -1)
				printf("%% conf_ifaddrs: socket: %s\n",
				    strerror(errno));

			/* get address flags */
			anycast = 0;
			memset(&ifr6, 0, sizeof(ifr6));
			strlcpy(ifr6.ifr_name, ifname, sizeof(ifr6.ifr_name));
			memcpy(&ifr6.ifr_addr, sin6, sizeof(ifr6.ifr_addr));
			if (ioctl(s6, SIOCGIFAFLAG_IN6, (caddr_t)&ifr6) < 0) {
				if (errno != EADDRNOTAVAIL)
					printf("%% conf_ifaddrs: " \
					    "SIOCGIFAFLAG_IN6: %s\n",
					    strerror(errno));
			} else {
				/* skip autoconf addresses */
				if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_AUTOCONF)
					continue;
				anycast = (ifr6.ifr_ifru.ifru_flags6 &
				    IN6_IFF_ANYCAST) != 0;
			}

			/* and lifetimes, as they were given */
			lt.ia6t_vltime = lt.ia6t_pltime = ND6_INFINITE_LIFETIME;
			memset(&ifr6, 0, sizeof(ifr6));
			strlcpy(ifr6.ifr_name, ifname, sizeof(ifr6.ifr_name));
			memcpy(&ifr6.ifr_addr, sin6, sizeof(ifr6.ifr_addr));
			if (ioctl(s6, SIOCGIFALIFETIME_IN6, (caddr_t)&ifr6) == 0)
				lt = ifr6.ifr_ifru.ifru_lifetime;
			else if (errno != EADDRNOTAVAIL)
				printf("%% conf_ifaddrs: SIOCGIFALIFETIME_IN6:"
				    " %s\n", strerror(errno));
			ip6_optstr(opts, sizeof(opts), anycast,
			    lt.ia6t_vltime, lt.ia6t_pltime);

			if (flags & IFF_POINTOPOINT) {
				fprintf(output, " inet %s", routename6(sin6));
				sin6dest = (struct sockaddr_in6 *)ifa->ifa_dstaddr;
				in6_fillscopeid(sin6dest);
				fprintf(output, " %s", routename6(sin6dest));
			} else {
				fprintf(output, " inet %s",
				    netname6(sin6, sin6mask));
			}
			fprintf(output, "%s", opts);
			ippntd = 1;
			break;
		default:
			continue;
		}
		fprintf(output, "\n");
	}
	freeifaddrs(ifap);
	if (s6 != -1)
		close(s6);

	return ippntd;
}

u_long
default_mtu(char *ifname)
{
	u_int i;

	for (i = 0; i < nitems(defmtus); i++)
		if (isprefix(defmtus[i].name, ifname))  
			return defmtus[i].mtu;

	return DEFAULT_MTU; /* default mtu */
}

int
default_txprio(char *ifname)
{
	u_int i;

	for (i = 0; i < nitems(defprios); i++)
		if (isprefix(defprios[i].name, ifname))
			return defprios[i].txprio;

	return 0;	/* default txprio */
}

int
default_rxprio(char *ifname)
{
	u_int i;

	for (i = 0; i < nitems(defprios); i++)
		if (isprefix(defprios[i].name, ifname))
			return defprios[i].rxprio;

	return 0;	/* default rxprio */
}

/* Does conf() print this mtu for ifname: is it set, and not the default? */
int
conf_mtu_shown(char *ifname, u_long mtu)
{
	return mtu != 0 && default_mtu(ifname) != MTU_IGNORE &&
	    mtu != default_mtu(ifname);
}

int
default_llpriority(char *ifname)
{
	u_int i;

	for (i = 0; i < nitems(defllpriority); i++)
		if (isprefix(defllpriority[i].name, ifname))
			return defllpriority[i].llpriority;

	return IFQ_DEFPRIO;	/* default llpriority */
}

/*
 * Show IPv4/6 or ARP entries from the routing table
 */
int
conf_routes(FILE *output, char *delim, int af, int flags, int tableid)
{
	char *next;
	struct rt_msghdr *rtm;
	struct rtdump *rtdump;
	struct sockaddr *sa;

	if (tableid < 0 || tableid > RT_TABLEID_MAX) {
		printf("%% conf_routes: tableid %d out of range\n", tableid);
		return 1;
	}
	rtdump = getrtdump(0, flags, tableid);
	if (rtdump == NULL)
		return 1;

	/* walk through routing table */
	for (next = rtdump->buf; next < rtdump->lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		sa = (struct sockaddr *)(next + rtm->rtm_hdrlen);
		if (af != AF_UNSPEC && sa->sa_family != af)
			continue;
		/* an expiring route is not configuration */
		if (rtm->rtm_rmx.rmx_expire)
			continue;
		if (!rtm->rtm_errno) {
			if (rtm->rtm_addrs)
				conf_print_rtm(output, rtm, delim, af);
		} else if (verbose)
			printf("%% conf_routes: rtm: %s (errno %d)\n",
			    strerror(rtm->rtm_errno), rtm->rtm_errno);
	}
	freertdump(rtdump);
	return 1;
}

void
conf_intgroup(FILE *output, int ifs, char *ifname)
{
	/* ripped straight from ifconfig.c */
	int cnt;
	u_int len;
	struct ifgroupreq	ifgr;
	struct ifg_req		*ifg;

	bzero(&ifgr, sizeof(ifgr));
	strlcpy(ifgr.ifgr_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGIFGROUP, (caddr_t)&ifgr) == -1) {
		if (errno != ENOTTY)
			printf("%% conf_intgroup: SIOCGIFGROUP/1: %s\n",
			    strerror(errno));
		return;
	}

	len = ifgr.ifgr_len;
	ifgr.ifgr_groups =
	    (struct ifg_req *)calloc(len / sizeof(struct ifg_req),
	    sizeof(struct ifg_req));
	if (ifgr.ifgr_groups == NULL) {
		printf("%% conf_intgroup: calloc: %s\n", strerror(errno));
		return;
	}
	if (ioctl(ifs, SIOCGIFGROUP, (caddr_t)&ifgr) == -1) {
		printf("%% conf_intgroup: SIOCGIFGROUP/2: %s\n",
		    strerror(errno));
		free(ifgr.ifgr_groups);
		return;
	}

	ifg = ifgr.ifgr_groups;
	for (cnt = 0; ifg && len >= sizeof(struct ifg_req); ifg++) {
		len -= sizeof(struct ifg_req);
		if (strcmp(ifg->ifgrq_group, "all")) {
			if (cnt == 0)
				fprintf(output, " group");
			cnt++;
			fprintf(output, " %s", ifg->ifgrq_group);
		}
	}
	if (cnt)
		fprintf(output, "\n");
	free(ifgr.ifgr_groups);
}

void
conf_intrtlabel(FILE *output, int ifs, char *ifname)
{
	struct ifreq ifr;
	char ifrtlabelbuf[RTLABEL_LEN];

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_data = (caddr_t)&ifrtlabelbuf;

	if (ioctl(ifs, SIOCGIFRTLABEL, (caddr_t)&ifr) == -1) {
		if (errno != ENOENT)
			printf("%% conf_intrtlabel: SIOCGIFRTLABEL: %s\n",
			    strerror(errno));
		return;
	}

	fprintf(output, " rtlabel %s\n", ifr.ifr_data);
}

int
isdefaultroute(struct sockaddr *sa, struct sockaddr *samask)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

	switch (sa->sa_family) {
	case AF_INET:
		/* XXX check for zero mask */
		return
		    (((struct sockaddr_in *)sa)->sin_addr.s_addr) == INADDR_ANY;
		break;
	case AF_INET6:
		/* XXX check for zero mask */
		return (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr));
		break;
	default:
		break;
	}
	return 0;
}

static const struct {
	char *name;
	long flag;
} rtflags[] = {
	{ "blackhole",	RTF_BLACKHOLE },
	{ "cloning",	RTF_CLONING },
	{ "iface",	-RTF_GATEWAY },
	{ "llinfo",	RTF_LLINFO },
	{ "nostatic",	-RTF_STATIC },
	{ "proto1",	RTF_PROTO1 },
	{ "proto2",	RTF_PROTO2 },
	{ "reject",	RTF_REJECT }
};

void
conf_rtflags(char *txt, int flags, struct rt_msghdr *rtm)
{
	int i;

	for (i = 0; i < nitems(rtflags); i++)
		if (rtflags[i].flag < 0) {
			if (!(flags & -rtflags[i].flag)) {
				strlcat(txt, " ", TMPSIZ);
				strlcat(txt, rtflags[i].name, TMPSIZ);
			}
		} else if ((flags & rtflags[i].flag)) {
				strlcat(txt, " ", TMPSIZ);
				strlcat(txt, rtflags[i].name, TMPSIZ);
		}

	if (rtm->rtm_rmx.rmx_mtu && rtm->rtm_rmx.rmx_mtu != ROUTEMTU) {
		char sn1[16];
		snprintf(sn1, sizeof(sn1), " mtu %d", rtm->rtm_rmx.rmx_mtu);
		strlcat(txt, sn1, TMPSIZ);
	}
}

void
conf_print_rtm(FILE *output, struct rt_msghdr *rtm, char *delim, int af)
{
	int i;
	char *cp, flags[TMPSIZ], ifname[IFNAMSIZ];
	struct sockaddr *dst = NULL, *gate = NULL, *mask = NULL;
	struct sockaddr_rtlabel *sa_rl = NULL;
	struct sockaddr *sa;
	struct sockaddr_in sin;
	struct sockaddr_dl *ifp = NULL;

	memset(ifname, 0, sizeof(ifname));

	sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	bzero(&flags, TMPSIZ);

	cp = ((char *)rtm + rtm->rtm_hdrlen);
	for (i = 1; i; i <<= 1)
		if (i & rtm->rtm_addrs) {
			sa = (struct sockaddr *)cp;

			switch (i) {
			case RTA_DST:
				/* allow arp to print when af==AF_LINK */
				if (sa->sa_family == af) {
					conf_rtflags(flags, rtm->rtm_flags,
					    rtm);
					dst = sa;
				}
				break;
			case RTA_GATEWAY:
				if (sa->sa_family == af)
					gate = sa;
				break;
			case RTA_NETMASK:
				/* netmasks will not have a valid sa_family */
				mask = sa;
				break;
			case RTA_IFP:
				if (sa->sa_family == AF_LINK &&
				   ((struct sockaddr_dl *)sa)->sdl_nlen) {
					ifp = (struct sockaddr_dl *)sa;
					if (ifp->sdl_nlen < sizeof(ifname)) {
						memcpy(ifname, ifp->sdl_data,
						    ifp->sdl_nlen);
					}
				}
				break;
			case RTA_LABEL:
				sa_rl = (struct sockaddr_rtlabel *)sa;
				break;
			}
			ADVANCE(cp, sa);
		}
	if (dst && gate && mask && (af == AF_INET || af == AF_INET6)) {
		/* Special case for dynamic default route via pppoe(4) */
		if (af == AF_INET && isdefaultroute(dst, mask) &&
		    isprefix("pppoe", ifname)) {
			pppoe_conf_default_route(output, ifname,
			    delim, netname(dst, mask),
			    routename(gate), flags);
		}
		/*
		 * Suppress printing IPv4 route if it's the default
		 * route and dhcp (dhcpleased) is enabled.
		 */
		else if (!(af == AF_INET && isdefaultroute(dst, mask)
		    && dhcpleased_has_defaultroute(sa_rl))) {
			fprintf(output, "%s%s ", delim, netname(dst, mask));
			fprintf(output, "%s%s\n", routename(gate), flags);
		}
	} else if (dst && gate && (af == AF_LINK)) {
		/* print arp */
		fprintf(output, "%s%s ", delim, routename(dst));
		fprintf(output, "%s\n", routename(gate));
	}
	explicit_bzero(flags, TMPSIZ);
}
