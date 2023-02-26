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
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet6/in6_var.h>
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
#include "sysctl.h"

#define IPSIZ  256	/*
			 * max theoretical size of ipv4 or ipv6
			 * text representation
			 */
#define TMPSIZ 1024	/* size of temp strings */
#define ROUTEMTU 32768	/* common route MTU */
#define MTU_IGNORE ULONG_MAX	/* ignore this "default" mtu */

void conf_db_single(FILE *, char *, char *, char *);
void conf_interfaces(FILE *, char *);
void conf_print_rtm(FILE *, struct rt_msghdr *, char *, int);
int conf_ifaddrs(FILE *, char *, int, int);
int conf_ifaddr_dhcp(FILE *, char *, int, int);
void conf_lladdr(FILE *, char *);
void conf_ifflags(FILE *, int, char *, int, u_char);
void conf_vnetid(FILE *, int, char *);
void conf_vnetflowid(FILE *, int, char *);
void conf_parent(FILE *, int, char *);
void conf_patch(FILE *, int, char *);
void conf_brcfg(FILE *, int, struct if_nameindex *, char *);
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
int dhcpleased_has_defaultroute(char *);
int dhcpleased_controls_interface(char *, int);
int dhclient_isenabled(char *);
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
	{ "sl",		296 },
	{ "enc",	1536 },
	{ "pflow",	MTU_IGNORE },
	{ "pflog",	MTU_IGNORE },
	{ "pfsync",	MTU_IGNORE },
	{ "lo",		MTU_IGNORE },
};

/*
 * these interfaces get started in a specific order
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
	char *name;
} latestartifs[] = {
	{ "trunk" },
	{ "svlan" },
	{ "vlan" },
	{ "carp" },
	{ "gif" },
	{ "gre" },
	{ "pfsync" },
	{ "pppoe" },
	{ "bridge" },
	{ "pflow" },
};

int
conf(FILE *output)
{
	char cpass[_PASSWORD_LEN+1];
	char hostbuf[MAXHOSTNAMELEN];

	fprintf(output, "!\n");

	gethostname (hostbuf, sizeof(hostbuf));
	fprintf(output, "hostname %s\n", hostbuf);
	if (read_pass(cpass, sizeof(cpass))) {
		fprintf(output, "enable secret blowfish %s\n", cpass);
	} else {
		if (errno != ENOENT)
			printf("%% Unable to read run-time crypt repository:"
			    " %s\n", strerror(errno));
	}
	fprintf(output, "!\n");
	conf_ctl(output, "", "dns", 0);
	conf_ctl(output, "", "rad", 0);
        conf_ctl(output, "", "motd", 0);

	/*
	 * start all intefaces not listed in 'latestartifs'
	 */
	conf_interfaces(output, NULL);
	/*
	 * start these interfaces in specific order
	 */
	conf_interfaces(output, "trunk");
	conf_interfaces(output, "svlan");
	conf_interfaces(output, "vlan");
	conf_interfaces(output, "carp");

	fprintf(output, "!\n");

	/*
	 * check out how sysctls are doing these days
	 *
	 * Each of these options, like most other things in the config output
	 * (such as interface flags), must display if the kernel's default
	 * setting is not currently set.
	 */
	conf_sysctls(output);

	fprintf(output, "!\n");

	/*
	 * print static arp and route entries in configuration file format
	 */
	conf_arp(output, "arp ");
	conf_routes(output, "route ", AF_INET, RTF_STATIC, 0);
	conf_routes(output, "route ", AF_INET6, RTF_STATIC, 0);

	fprintf(output, "!\n");
	/*
	 * these interfaces must start after routes are set
	 */
	conf_interfaces(output, "pppoe");
	conf_interfaces(output, "gif");
	conf_interfaces(output, "gre");
	conf_interfaces(output, "bridge");

	fprintf(output, "!\n");
	conf_ctl(output, "", "pf", 0);

	/*
	 * this interface must start after pf is loaded
	 */
	conf_interfaces(output, "pfsync");
	conf_interfaces(output, "pflow");

	conf_ctl(output, "", "snmp", 0);
	conf_ctl(output, "", "resolv", 0);
	conf_ctl(output, "", "ldp", 0);
	conf_ctl(output, "", "rip", 0);
	conf_ctl(output, "", "ospf", 0);
	conf_ctl(output, "", "ospf6", 0);
	conf_ctl(output, "", "bgp", 0);
	conf_ctl(output, "", "ifstate", 0);
	conf_ctl(output, "", "ipsec", 0);
	conf_ctl(output, "", "ike", 0);
	conf_ctl(output, "", "dvmrp", 0);
	conf_ctl(output, "", "relay", 0);
	conf_ctl(output, "", "sasync", 0);
	conf_ctl(output, "", "dhcp", 0);
	conf_ctl(output, "", "ntp", 0);
	conf_ctl(output, "", "smtp", 0);
	conf_ctl(output, "", "ldap", 0);
	conf_ctl(output, "", "ftp-proxy", 0);
	conf_ctl(output, "", "inet", 0);
	conf_ctl(output, "", "sshd", 0);

	conf_rtables(output);

	fprintf(output, "!\n");
	conf_nameserver(output);

	return(0);
}

void conf_rtables(FILE *output)
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

void conf_rtables_rtable(FILE *output, int rtableid)
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

void conf_ctl(FILE *output, char *delim, char *name, int rtableid)
{
	FILE *conf;
	struct daemons *x;
	struct ctl *ctl;
	char tmp_str[TMPSIZ], tmpfile[64];
	char *fenablenm = NULL, *fothernm = NULL, *flocalnm = NULL;
	int defenable = 0, pntdrules = 0, pntdflag = 0, dbflag;

	x = (struct daemons *)genget(name, (char **)ctl_daemons,
	    sizeof(struct daemons));
	if (x == 0 || Ambiguous(x)) {
		printf("%% conf_ctl: %s: genget internal failure\n", name);
		return;
	}

	/* print rules if they exist */
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

	/* fill in argument names from table */
	for (ctl = x->table; ctl != NULL && ctl->name != NULL; ctl++) {
		switch(ctl->flag_x) {
		case DB_X_ENABLE_DEFAULT:
			defenable = 1;
			/* FALLTHROUGH */
		case DB_X_ENABLE:
			fenablenm = ctl->name;
			break;
		case DB_X_LOCAL:
			flocalnm = ctl->name;
			break;
		case DB_X_OTHER:
			fothernm = ctl->name;
			break;
		case DB_X_DISABLE:
		case DB_X_REMOVE:
		case DB_X_DISABLE_ALWAYS:
		case 0:
			break;
		default:
			printf("%% conf_ctl: flag_x %d unknown\n", ctl->flag_x);
			return;
		}
	}

	/* print rules as currently enabled in running time database */
	if ((dbflag = db_select_flag_x_dbflag_rtable("ctl", x->name, rtableid))
	    < 0) {
		printf("%% database ctl select failure (%s, %d)\n", x->name, rtableid);
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

/* Check if 'dhcpleasectl -l $if' shows a default route pointing at 'dst'. */
int
dhcpleased_has_defaultroute(char *dst)
{
	int gatewayfound = 0;
	struct if_nameindex *ifn_list, *ifnp;
	char ortext[128];
	char outpath[PATH_MAX];
	int fd = -1, nullfd = -1;

	if (!dhcpleased_is_running())
		return 0;

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% if_nameindex: %s\n", strerror(errno));
		return 0;
	}

	snprintf(ortext, sizeof(ortext), "\tdefault gateway %s\n", dst);

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

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		char *argv[] = { DHCPLEASECTL, "-l", ifnp->if_name, NULL };

		if (ftruncate(fd, 0) == -1) {
			printf("%% ftruncate: %s\n", strerror(errno));
			break;
		}
		lseek(fd, SEEK_SET, 0);

		if (cmdargs_output(DHCPLEASECTL, argv, fd, nullfd) &&
		    scantext(outpath, ortext)) {
			gatewayfound = 1;
			break;
		}
	}

	if_freenameindex(ifn_list);
	unlink(outpath);
	close(fd);
	close(nullfd);
	return (gatewayfound);
}

/* Check whether IPv4 addresses on an interface are managed by dhcpleased. */
int
dhcpleased_controls_interface(char *ifname, int ifs)
{
#ifdef IFXF_AUTOCONF4		/* 6.6+ */
	int ifxflags;

	if (!dhcpleased_is_running())
		return 0;

	ifxflags = get_ifxflags(ifname, ifs);
	return ((ifxflags & IFXF_AUTOCONF4) != 0);
#else
	return 0;
#endif
}

/*
 * see if ("option routers %s;\n",dst) is preset in any possible dhclient
 * lease file
 */
int dhclient_isenabled(char *dst)
{
	int gatewayfound = 0;
	struct stat enst;
	struct if_nameindex *ifn_list, *ifnp;
	char ortext[128];
	char leasefile[sizeof(LEASEPREFIX)+IFNAMSIZ+1];

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% dhclient_isenabled: if_nameindex failed\n");
		return 0;
	}

	snprintf(ortext, sizeof(ortext), "  option routers %s;\n", dst);

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		snprintf(leasefile, sizeof(leasefile), "%s.%s", LEASEPREFIX,
		    ifnp->if_name);
		if (stat(leasefile, &enst) == 0 && S_ISREG(enst.st_mode))
			if(scantext(leasefile, ortext)) {
				gatewayfound = 1;
				break;
			}
	}

	if_freenameindex(ifn_list);

	return (gatewayfound);
}

/* find string in file */
int scantext(char *fname, char *string)
{
	FILE *file;
	char line[128];
	int found = 0;

	if ((file = fopen(fname, "r")) == 0) {
		printf("%% Unable to open %s: %s\n", fname, strerror(errno));
		return(0);
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
	return(found);
}

int islateif(char *ifname)
{
	int i;

	for (i = 0; i < nitems(latestartifs); i++)
		if (isprefix(latestartifs[i].name, ifname))  
			return(1);

	return(0);
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

void conf_interfaces(FILE *output, char *only)
{
	int ifs, flags, ippntd, br;
	char ifdescr[IFDESCRSIZE];

	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr, ifrdesc;
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
		if (only && !isprefix(only, ifnp->if_name))
			/* only display interfaces which start with ... */
			continue;
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

		/* The output order is important! */

		/* set interface/bridge mode */
		if (!(br = is_bridge(ifs, ifnp->if_name)))
			br = 0;
		fprintf(output, "%s %s\n", br ? "bridge" : "interface",
		    ifnp->if_name);

		/*
		 * description, if available
		 * copied straight from ifconfig.c
		 */
		memset(&ifrdesc, 0, sizeof(ifrdesc));
		strlcpy(ifrdesc.ifr_name, ifnp->if_name,
		    sizeof(ifrdesc.ifr_name));
		ifrdesc.ifr_data = (caddr_t)&ifdescr;
		if (ioctl(ifs, SIOCGIFDESCR, &ifrdesc) == 0 &&
		    strlen(ifrdesc.ifr_data))
			fprintf(output, " description %s\n", ifrdesc.ifr_data);

		conf_lladdr(output, ifnp->if_name);

		conf_vnetid(output, ifs, ifnp->if_name);
		conf_vnetflowid(output, ifs, ifnp->if_name);
		conf_parent(output, ifs, ifnp->if_name);
		conf_patch(output, ifs, ifnp->if_name);
		conf_rdomain(output, ifs, ifnp->if_name);
		conf_intrtlabel(output, ifs, ifnp->if_name);
		conf_intgroup(output, ifs, ifnp->if_name);
		conf_carp(output, ifs, ifnp->if_name);
		conf_tunnel(output,  ifs, ifnp->if_name);
		conf_ifmetrics(output,  ifs, if_data, ifnp->if_name);

		ippntd = conf_ifaddr_dhcp(output, ifnp->if_name, ifs, flags);

		if (br) {
			conf_brcfg(output, ifs, ifn_list, ifnp->if_name);
		} else {
			char tmp[24];

			conf_media_status(output, ifs, ifnp->if_name);
			conf_keepalive(output, ifs, ifnp->if_name);
			conf_pfsync(output, ifs, ifnp->if_name);
			conf_trunk(output, ifs, ifnp->if_name);
			conf_pflow(output, ifs, ifnp->if_name);
			conf_pwe3(output, ifs, ifnp->if_name);
			conf_ifxflags(output, ifs, ifnp->if_name);
			if (conf_dhcrelay(ifnp->if_name, tmp, sizeof(tmp))
			    > 0)
				fprintf(output, " dhcrelay %s\n", tmp);
			conf_sppp(output, ifs, ifnp->if_name);
			conf_pppoe(output, ifs, ifnp->if_name);
			conf_wg(output, ifs, ifnp->if_name);
		}
		conf_ifflags(output, flags, ifnp->if_name, ippntd,
		    if_data.ifi_type);
	}
	close(ifs);
	if_freenameindex(ifn_list);
}

void conf_lladdr(FILE *output, char *ifname)
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

int conf_ifaddr_dhcp(FILE *output, char *ifname, int ifs, int flags)
{
	FILE *dhcpif = NULL;
	int ippntd; 
	char leasefile[sizeof(LEASEPREFIX)+1+IFNAMSIZ];

	/* find dhcpleased/dhclient controlled interfaces */
	snprintf(leasefile, sizeof(leasefile), "%s.%s",
	    LEASEPREFIX, ifname);
	if (dhcpleased_controls_interface(ifname, ifs) ||
	    (dhcpif = fopen(leasefile, "r")) != NULL) {
		fprintf(output, " ip dhcp\n");
		if (dhcpif)
			fclose(dhcpif);
		/* print all non-autoconf ipv6 addresses */
		conf_ifaddrs(output, ifname, flags, AF_INET6);
		ippntd = 1;
	} else {
		/* print all non-autoconf addresses */
		ippntd = conf_ifaddrs(output, ifname, flags, 0);
	}

	return ippntd;
}

void conf_vnetid(FILE *output, int ifs, char *ifname)
{
	int64_t vnetid;

	if (((vnetid = get_vnetid(ifs, ifname)) != 0)) {
		if (vnetid < 0)
			fprintf(output, " vnetid any\n");
		else
			fprintf(output, " vnetid %lld\n", vnetid);
	}
}

void conf_vnetflowid(FILE *output, int ifs, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGVNETFLOWID, &ifr) == -1)
		return;

	if (ifr.ifr_vnetid)
		fprintf(output, " vnetflowid\n");
}

void conf_patch(FILE *output, int ifs, char *ifname)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGIFPAIR, &ifr) == 0 && ifr.ifr_index != 0 &&
	    if_indextoname(ifr.ifr_index, ifname) != NULL)
		fprintf(output, " patch %s\n", ifname);
}

void conf_parent(FILE *output, int ifs, char *ifname)
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

void conf_ifflags(FILE *output, int flags, char *ifname, int ippntd, u_char ift)
{
	if (flags & IFF_DEBUG)
		fprintf(output, " debug\n");
	if (flags & (IFF_LINK0|IFF_LINK1|IFF_LINK2)) {
		fprintf(output, " link ");
		if(flags & IFF_LINK0)
			fprintf(output, "0 ");
		if(flags & IFF_LINK1)
			fprintf(output, "1 ");
		if(flags & IFF_LINK2)
			fprintf(output, "2");
		fprintf(output, "\n");
	}
	if (flags & IFF_NOARP && ift != IFT_WIREGUARD)
		fprintf(output, " no arp\n");

	if (isprefix("pppoe", ifname)) {		/* XXX */
		fprintf(output, " no shutdown\n");
	} else {
		/*
		 * ip X/Y turns the interface up (just like 'no shutdown')
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

int conf_dhcrelay(char *ifname, char *server, int serverlen)
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

	return(alen);
}

void conf_pflow(FILE *output, int ifs, char *ifname)
{
	char sender[INET6_ADDRSTRLEN];
	char receiver[INET6_ADDRSTRLEN];
	char version[INET6_ADDRSTRLEN];

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

void conf_ifxflags(FILE *output, int ifs, char *ifname)
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
#ifdef IFXF_INET6_NOPRIVACY	/* pre-6.9 */
		if (ifr.ifr_flags & IFXF_INET6_NOPRIVACY)
			fprintf(output, " no autoconfprivacy\n");
#endif
#ifdef IFXF_AUTOCONF6TEMP	/* 6.9+ */
		if (ifr.ifr_flags & IFXF_AUTOCONF6TEMP)
			fprintf(output, " temporary\n");
#endif
#ifdef IFXF_MONITOR		/* 6.9+ */
		if (ifr.ifr_flags & IFXF_MONITOR)
			fprintf(output, " monitor\n");
#endif
		if (ifr.ifr_flags & IFXF_WOL)
			fprintf(output, " wol\n");
	}
}

void conf_rdomain(FILE *output, int ifs, char *ifname)
{
	int rdomainid;

	rdomainid = get_rdomain(ifs, ifname);
	if (rdomainid > 0)
		fprintf(output, " rdomain %d\n", rdomainid);
}
	
int get_rdomain(int ifs, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGIFRDOMAIN, (caddr_t)&ifr) != -1)
		return ifr.ifr_rdomainid;
	return -1;
}

void conf_keepalive(FILE *output, int ifs, char *ifname)
{
	struct ifkalivereq ikar;

	bzero(&ikar, sizeof(ikar));
	strlcpy(ikar.ikar_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGETKALIVE, &ikar) == 0 &&
	    (ikar.ikar_timeo != 0 || ikar.ikar_cnt != 0))
		fprintf(output, " keepalive %d %d\n",
		    ikar.ikar_timeo, ikar.ikar_cnt);
}

void conf_pwe3(FILE *output, int ifs, char *ifname)
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

void conf_tunnel(FILE *output, int ifs, char *ifname)
{
	int dstport, physrtable, physdf, physecn;
	char tmpa[IPSIZ], tmpb[IPSIZ];

	if ((dstport=
	    phys_status(ifs, ifname, tmpa, tmpb, IPSIZ, IPSIZ)) >= 0) {
		int physttl;

		fprintf(output, " tunnel %s %s", tmpa, tmpb);
		if (dstport > 0)
			fprintf(output, ":%i", dstport);
		if ((physttl = get_physttl(ifs, ifname)) > 0)
			fprintf(output, " ttl %i", physttl);
		if ((physecn = get_physecn(ifs, ifname)) > 0)
			fprintf(output, " ecn");
		if ((physdf = get_physdf(ifs, ifname)) > 0)
			fprintf(output, " df");	
		fprintf(output, "\n");
	}
	/* non-tunnel interfaces can have a tunneldomain */
	if ((physrtable = get_physrtable(ifs, ifname)) != 0)
		fprintf(output, " tunneldomain %i\n", physrtable);
}

void conf_ifmetrics(FILE *output, int ifs, struct if_data if_data,
    char *ifname)
{
	char tmp[TMPSIZ];
	struct ifreq ifr;

	/*
	 * print interface mtu, metric
	 */
	if (if_data.ifi_mtu != default_mtu(ifname) &&
	   default_mtu(ifname) != MTU_IGNORE && if_data.ifi_mtu != 0)
		fprintf(output, " mtu %u\n", if_data.ifi_mtu);
	if (if_data.ifi_metric)
		fprintf(output, " metric %u\n", if_data.ifi_metric);

	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(ifs, SIOCGIFPRIORITY, (caddr_t)&ifr) == 0 &&
	    ifr.ifr_metric)
		fprintf(output, " priority %u\n", ifr.ifr_metric);
	if (ioctl(ifs, SIOCGIFLLPRIO, (caddr_t)&ifr) == 0 &&
	    ifr.ifr_llprio != DEFAULT_LLPRIORITY)
		fprintf(output, " llpriority %u\n", ifr.ifr_llprio);
	if (ioctl(ifs, SIOCGTXHPRIO, (caddr_t)&ifr) == 0 &&
	    ifr.ifr_hdrprio != DEFAULT_TXPRIO) {
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
	    ifr.ifr_hdrprio != DEFAULT_RXPRIO) {
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

void conf_brcfg(FILE *output, int ifs, struct if_nameindex *ifn_list,
    char *ifname)
{
	struct if_nameindex *br_ifnp;

	char tmp_str[TMPSIZ];
	long l_tmp;

	if ((l_tmp = bridge_cfg(ifs, ifname, PRIORITY))
	    != -1 && l_tmp != DEFAULT_PRIORITY)
		fprintf(output, " priority %lu\n", l_tmp);
	if ((l_tmp = bridge_cfg(ifs, ifname, HELLOTIME))
	    != -1 && l_tmp != DEFAULT_HELLOTIME)
		fprintf(output, " hellotime %lu\n", l_tmp);
	if ((l_tmp = bridge_cfg(ifs, ifname, FWDDELAY))
	    != -1 && l_tmp != DEFAULT_FWDDELAY)
		fprintf(output, " fwddelay %lu\n", l_tmp);
	if ((l_tmp = bridge_cfg(ifs, ifname, MAXAGE))
	    != -1 && l_tmp != DEFAULT_MAXAGE)
		fprintf(output, " maxage %lu\n", l_tmp);
	if ((l_tmp = bridge_cfg(ifs, ifname, MAXADDR))
	    != -1 && l_tmp != DEFAULT_MAXADDR)
		fprintf(output, " maxaddr %lu\n", l_tmp);
	if ((l_tmp = bridge_cfg(ifs, ifname, TIMEOUT))
	    != -1 && l_tmp != DEFAULT_TIMEOUT)
		fprintf(output, " timeout %lu\n", l_tmp);

	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, MEMBER))
		fprintf(output, " member %s\n", tmp_str);
	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, STP))
		fprintf(output, " stp %s\n", tmp_str);
	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, SPAN))
		fprintf(output, " span %s\n", tmp_str);
	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, NOLEARNING))
		fprintf(output, " no learning %s\n", tmp_str);
	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, NODISCOVER))
		fprintf(output, " no discover %s\n", tmp_str);
	if (bridge_list(ifs, ifname, NULL, tmp_str, TMPSIZ, BLOCKNONIP))
		fprintf(output, " blocknonip %s\n", tmp_str);
	if (bridge_list(ifs, ifname, " ", tmp_str, TMPSIZ, CONF_IFPRIORITY))
		fprintf(output, "%s", tmp_str);
	if (bridge_list(ifs, ifname, " ", tmp_str, TMPSIZ, CONF_IFCOST))
		fprintf(output, "%s", tmp_str);
	if (bridge_list(ifs, ifname, " ", tmp_str, TMPSIZ, PROTECTED))
		fprintf(output, "%s", tmp_str);
	bridge_confaddrs(ifs, ifname, " static ", output);

	for (br_ifnp = ifn_list; br_ifnp->if_name != NULL; br_ifnp++)
		/* try all interface names for member rules */
		bridge_rules(ifs, ifname, br_ifnp->if_name, " rule ",
		    output);
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
		return(count);
	}
	return 1;
}


int conf_ifaddrs(FILE *output, char *ifname, int flags, int af)
{
	struct ifaddrs *ifa, *ifap;
	struct sockaddr_in *sin, *sinmask, *sindest;
	struct sockaddr_in6 *sin6, *sin6mask, *sin6dest;
	struct in6_ifreq ifr6;
	int ippntd = 0;

	if (getifaddrs(&ifap) != 0) {
		printf("%% conf: getifaddrs failed: %s\n",
		strerror(errno));
		return(-1);
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
		int s;
		case AF_INET:
			if (af != AF_INET && af != 0)
				continue;
			sin = (struct sockaddr_in *)ifa->ifa_addr;
			if (sin->sin_addr.s_addr == INADDR_ANY)
				continue;
			sinmask = (struct sockaddr_in *)ifa->ifa_netmask;
			if (flags & IFF_POINTOPOINT) {
				sindest = (struct sockaddr_in *)ifa->ifa_dstaddr;
				fprintf(output, " ip %s",
				    routename4(sin->sin_addr.s_addr));
				if (ntohl(sindest->sin_addr.s_addr) !=
				    INADDR_ANY)
					fprintf(output, " %s",
					    inet_ntoa(sindest->sin_addr));
			} else if (flags & IFF_BROADCAST) {
				sindest = (struct sockaddr_in *)ifa->ifa_broadaddr;
				fprintf(output, " ip %s",
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
				fprintf(output, " ip %s",
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

			/* get address flags */
			memset(&ifr6, 0, sizeof(ifr6));
			strlcpy(ifr6.ifr_name, ifname, sizeof(ifr6.ifr_name));
			memcpy(&ifr6.ifr_addr, &sin6, sizeof(ifr6.ifr_addr));
			s = socket(PF_INET6, SOCK_DGRAM, 0);
			if (s < 0)
				printf("%% conf_ifaddrs: socket: %s\n",
				    strerror(errno));
			if (ioctl(s, SIOCGIFAFLAG_IN6, (caddr_t)&ifr6) < 0) {
				if (errno != EADDRNOTAVAIL)
					printf("%% conf_ifaddrs: " \
					    "SIOCGIFAFLAG_IN6: %s\n",
					    strerror(errno));
			} else {
				/* skip autoconf addresses */
				if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_AUTOCONF)
					continue;
			}

			if (flags & IFF_POINTOPOINT) {
				fprintf(output, " ip %s", routename6(sin6));
				sin6dest = (struct sockaddr_in6 *)ifa->ifa_dstaddr;
				in6_fillscopeid(sin6dest);
				fprintf(output, " %s", routename6(sin6dest));
			} else {
				fprintf(output, " ip %s",
				    netname6(sin6, sin6mask));
			}
			ippntd = 1;
			break;
		default:
			continue;
		}
		fprintf(output, "\n");
	}
	freeifaddrs(ifap);

	return ippntd;
}

u_long
default_mtu(char *ifname)
{
	u_int i;

	for (i = 0; i < nitems(defmtus); i++)
		if (strncasecmp(defmtus[i].name, ifname,
		    strlen(defmtus[i].name)) == 0)
			return(defmtus[i].mtu);

	return(DEFAULT_MTU); /* default mtu */
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
		return(1);
	}
	rtdump = getrtdump(0, flags, tableid);
	if (rtdump == NULL) {
		printf("%% conf_routes: getrtdump failure\n");
		return(1);
	}

	/* walk through routing table */
	for (next = rtdump->buf; next < rtdump->lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		sa = (struct sockaddr *)(next + rtm->rtm_hdrlen);
		if (af != AF_UNSPEC && sa->sa_family != af)
			continue;
		if (!rtm->rtm_errno) {
			if (rtm->rtm_addrs)
				conf_print_rtm(output, rtm, delim, af);
		} else if (verbose)
			printf("%% conf_routes: rtm: %s (errno %d)\n",
			    strerror(rtm->rtm_errno), rtm->rtm_errno);
	}
	freertdump(rtdump);
	return(1);
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
	{ "nompath",	-RTF_MPATH },
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
	if (rtm->rtm_rmx.rmx_expire) {
		char sn1[16];
		snprintf(sn1, sizeof(sn1), " expire %lld",
		    rtm->rtm_rmx.rmx_expire);
		strlcat(txt, sn1, TMPSIZ);
	}
}

void
conf_print_rtm(FILE *output, struct rt_msghdr *rtm, char *delim, int af)
{
	int i;
	char *cp, flags[TMPSIZ];
	struct sockaddr *dst = NULL, *gate = NULL, *mask = NULL;
	struct sockaddr *sa;
	struct sockaddr_in sin;

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
			}
			ADVANCE(cp, sa);
		}
	if (dst && gate && mask && (af == AF_INET || af == AF_INET6)) {
		/*
		 * Suppress printing IPv4 route if it's the default
		 * route and dhcp (dhcpleased or dhclient) is enabled.
		 */
		if (!(af == AF_INET && isdefaultroute(dst, mask)
		    && (dhcpleased_has_defaultroute(routename(gate)) ||
		    dhclient_isenabled(routename(gate))))) {
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
