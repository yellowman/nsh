/* $nsh: conf.c,v 1.73 2012/05/23 05:45:35 chris Exp $ */
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
#include <tzfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
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
#include <net/if_vlan_var.h>
#include <net/route.h>
#include <net/pfvar.h>
#include <netmpls/mpls.h>
#include <net/if_pfsync.h>
#include <net/if_pflow.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <limits.h>
#include "stringlist.h"
#include "externs.h"
#include "bridge.h"

#define IPSIZ  256	/*
			 * max theoretical size of ipv4 or ipv6
			 * text representation
			 */
#define TMPSIZ 1024	/* size of temp strings */
#define MTU_IGNORE ULONG_MAX	/* ignore this "default" mtu */

void conf_interfaces(FILE *, char *);
void conf_print_rtm(FILE *, struct rt_msghdr *, char *, int);
int conf_ifaddrs(FILE *, char *, int);
void conf_brcfg(FILE *, int, struct if_nameindex *, char *);
void conf_ifxflags(FILE *, int, char *);
void conf_rtables(FILE *);
void conf_rtables_rtable(FILE *, int);
void conf_rdomain(FILE *, int, char *);
void conf_ifmetrics(FILE *, int, struct if_data, char *);
void conf_pflow(FILE *, int, char *);
void conf_ctl(FILE *, char *, char *, int);
void conf_intrtlabel(FILE *, int, char *);
void conf_intgroup(FILE *, int, char *);
void conf_keepalive(FILE *, int, char *);
void conf_groupattrib(FILE *);
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
	{ "gif",	1280 },
	{ "sl",		296 },
	{ "enc",	1536 },
	{ "pflow",	MTU_IGNORE },
	{ "pflog",	MTU_IGNORE },
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
	{ "tun" },
	{ "bridge" },
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

	conf_groupattrib(output);

	fprintf(output, "!\n");

	/*
	 * check out how sysctls are doing these days
	 *
	 * Each of these options, like most other things in the config output
	 * (such as interface flags), must display if the kernel's default
	 * setting is not currently set.
	 */
	conf_ipsysctl(output);

	fprintf(output, "!\n");

	/*
	 * print static arp and route entries in configuration file format
	 */
	conf_routes(output, "arp ", AF_LINK, RTF_STATIC, 0);
	conf_routes(output, "route ", AF_INET, RTF_STATIC, 0);
	conf_routes(output, "route ", AF_INET6, RTF_STATIC, 0);

	fprintf(output, "!\n");
	/*
	 * these interfaces must start after routes are set
	 */
	conf_interfaces(output, "pppoe");
	conf_interfaces(output, "tun");
	conf_interfaces(output, "gif");
	conf_interfaces(output, "gre");
	conf_interfaces(output, "bridge");

	fprintf(output, "!\n");
	conf_ctl(output, "", "pf", 0);

	/*
	 * this interface must start after pf is loaded
	 */
	conf_interfaces(output, "pfsync");

	conf_ctl(output, "", "snmp", 0);
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
		rtableid = atoi(rtables->sl_str[i]);
		if (rtableid == 0)
			continue;
		conf_rtables_rtable(output, rtableid);
	}

	sl_free(rtables, 1);
}

void conf_rtables_rtable(FILE *output, int rtableid)
{
	int i;
	StringList *rtable_name, *rtable_daemons;

	rtable_name = sl_init();
	rtable_daemons = sl_init();

	if (db_select_name_rtable(rtable_name, rtableid) < 0)
		printf("%% database failure select rtables name\n");
	else
		fprintf(output, "rtable %d %s\n", rtableid,
		    rtable_name->sl_str[0]);

	/*
	 * Routes must be printed before we attempt to start daemons,
	 * else rtables will not be created in the kernel (Unless an
	 * rdomain is created by specifing one on an interface prior
	 * to this point. An rdomain creates a new corresponding rtable)
	 */
	conf_routes(output, " arp ", AF_LINK, RTF_STATIC, rtableid);
	conf_routes(output, " route ", AF_INET, RTF_STATIC, rtableid);
	conf_routes(output, " route ", AF_INET6, RTF_STATIC, rtableid);

	if (db_select_flag_x_ctl_rtable(rtable_daemons, "ctl", rtableid) < 0)
		printf("%% database failure select ctl rtable\n");
	else
		for (i = 0; i < rtable_daemons->sl_cur; i++)
			conf_ctl(output, " ", rtable_daemons->sl_str[i], rtableid);

	sl_free(rtable_daemons, 1);
	sl_free(rtable_name, 1);

	fprintf(output, "!\n");
}

void conf_ctl(FILE *output, char *delim, char *name, int rtableid)
{
	FILE *conf;
	struct daemons *x;
	struct ctl *ctl;
	char tmp_str[TMPSIZ], tmpfile[64];
	char *fenablednm = NULL, *fothernm = NULL, *flocalnm = NULL;
	int pntdrules = 0, pntdflag = 0, dbflag;

	x = (struct daemons *)genget(name, (char **)ctl_daemons,
	    sizeof(struct daemons));
	if (x == 0 || Ambiguous(x)) {
		printf("%% conf_ctl: %s: genget internal failure\n", name);
		return;
	}

	/* print rules */
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
	} else if (errno != ENOENT || (errno != ENOENT && verbose))
		printf("%% conf_ctl: %s: %s\n", tmpfile, strerror(errno));

	for (ctl = x->table; ctl != NULL && ctl->name != NULL; ctl++) {
		if (ctl->flag_x == DB_X_LOCAL)
			flocalnm = ctl->name;
		if (ctl->flag_x == DB_X_OTHER)
			fothernm = ctl->name;
		if (ctl->flag_x == DB_X_ENABLE)
			fenablednm = ctl->name;
	}

	if ((dbflag = db_select_flag_x_dbflag_rtable("ctl", x->name, rtableid))
	    < 0) {
		printf("%% database ctl select failure (%s, %d)\n", x->name, rtableid);
		return;
	}
	switch(dbflag) {
	case DB_X_ENABLE:
		fprintf(output, "%s%s %s\n", delim, x->name, fenablednm ?
		    fenablednm : "enable");
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
	case DB_X_DISABLE:
	case 0:
		break;
	default:
		printf("%% conf_ctl dbflag %d unknown\n", dbflag);
	}
	if (pntdrules && x->doreload) {
		fprintf(output, "%s%s reload\n", delim, x->name);
		pntdflag = 1;
	}
	if (pntdflag)
		fprintf(output, "%s!\n", delim);
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

	for (i = 0; i < sizeof(latestartifs) / sizeof(latestartifs[0]); i++)
		if (isprefix(latestartifs[i].name, ifname))  
			return(1);

	return(0);
}

void conf_interfaces(FILE *output, char *only)
{
	FILE *dhcpif, *llfile;
	int ifs, flags, ippntd, br;
#define	LLPREFIX	"/var/run/lladdr"
	char leasefile[sizeof(LEASEPREFIX)+1+IFNAMSIZ];
	char *lladdr, llorig[IFNAMSIZ];
	char llfn[sizeof(LLPREFIX)+IFNAMSIZ];
	char ifdescr[IFDESCRSIZE];

	struct if_nameindex *ifn_list, *ifnp;
	struct ifreq ifr, ifrdesc;
	struct if_data if_data;
	struct vlanreq vreq;

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

		/*
		 * Keep in mind that the order in which things are displayed
		 * here is important.  For instance, we want to setup the
		 * vlan tag before setting the IP address since the vlan
		 * must know what parent to inherit the parent interface
		 * flags from before it is brought up.  Another example of
		 * this would be that we need to setup the members on a
		 * bridge before we setup flags on them.
		 */

		/*
		 * set interface/bridge mode
		 */
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

		/*
		 * print lladdr if necessary
		 */
		if ((lladdr = get_hwdaddr(ifnp->if_name)) != NULL) {
			/* We assume lladdr only useful if we can get_hwdaddr */
			snprintf(llfn, sizeof(llfn), "%s.%s", LLPREFIX,
			    ifnp->if_name);
			if ((llfile = fopen(llfn, "r"))) {
				fgets(llorig, sizeof(llorig), llfile);
				if (strcmp(llorig, lladdr) != 0) {
					fprintf(output, " lladdr %s\n",
					    lladdr);
				}
				fclose(llfile);
			}
		}
		 
		/*
		 * print vlan tag, parent if available.  if a tag is set
		 * but there is no parent, discard.
		 */
		bzero(&vreq, sizeof(struct vlanreq));
		ifr.ifr_data = (caddr_t)&vreq;  

		if (ioctl(ifs, SIOCGETVLAN, (caddr_t)&ifr) != -1) {
			if(vreq.vlr_tag && (vreq.vlr_parent[0] != '\0')) {
				fprintf(output, " vlan %d parent %s",
				    vreq.vlr_tag, vreq.vlr_parent);
				fprintf(output, "\n");
			}
		}

		conf_rdomain(output, ifs, ifnp->if_name);
		conf_intrtlabel(output, ifs, ifnp->if_name);
		conf_intgroup(output, ifs, ifnp->if_name);

		snprintf(leasefile, sizeof(leasefile), "%s.%s",
		    LEASEPREFIX, ifnp->if_name);
		if ((dhcpif = fopen(leasefile, "r"))) {
			fprintf(output, " ip dhcp\n");
			fclose(dhcpif);
			ippntd = 1;
		} else {
			ippntd = conf_ifaddrs(output, ifnp->if_name, flags);
		}

		if (br) {
			conf_brcfg(output, ifs, ifn_list, ifnp->if_name);
		} else {
			char tmp[24];

			conf_media_status(output, ifs, ifnp->if_name);
			conf_ifmetrics(output, ifs, if_data, ifnp->if_name);
			conf_keepalive(output, ifs, ifnp->if_name);
			conf_pfsync(output, ifs, ifnp->if_name);
			conf_carp(output, ifs, ifnp->if_name);
			conf_trunk(output, ifs, ifnp->if_name);
			conf_pflow(output, ifs, ifnp->if_name);
			conf_ifxflags(output, ifs, ifnp->if_name);
			if (timeslot_status(ifs, ifnp->if_name, tmp,
			    sizeof(tmp)) == 1) 
				fprintf(output, " timeslots %s\n", tmp);
			if (conf_dhcrelay(ifnp->if_name, tmp, sizeof(tmp))
			    > 0)
				fprintf(output, " dhcrelay %s\n", tmp);
		}

		/*
		 * print various flags
		 */
		if (flags & IFF_DEBUG)
			fprintf(output, " debug\n");
		if (flags & (IFF_LINK0|IFF_LINK1|IFF_LINK2)) {
			fprintf(output, " link ");
				fprintf(output, "0 ");
			if(flags & IFF_LINK1)
				fprintf(output, "1 ");
			if(flags & IFF_LINK2)
				fprintf(output, "2");
			fprintf(output, "\n");
		}
		if (flags & IFF_NOARP)
			fprintf(output, " no arp\n");
		/*
		 * ip X/Y turns the interface up (just like 'no shutdown')
		 * ...but if we never had an ip address set and the interface
		 * is up, we need to save this state explicitly.
		 */
		if (!ippntd && (flags & IFF_UP))
			fprintf(output, " no shutdown\n");
		else if (!(flags & IFF_UP))
			fprintf(output, " shutdown\n");
		fprintf(output, "!\n");
	}
	close(ifs);
	if_freenameindex(ifn_list);
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
	struct pflowreq preq;
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	bzero((char *)&preq, sizeof(struct pflowreq));
	ifr.ifr_data = (caddr_t)&preq;

	if (ioctl(ifs, SIOCGETPFLOW, (caddr_t)&ifr) == -1)
		return;

	fprintf(output, " pflow sender %s", inet_ntoa(preq.sender_ip));
	fprintf(output, " receiver %s:%u", inet_ntoa(preq.receiver_ip), ntohs(preq.receiver_port));
	if (preq.version != 5)
		fprintf(output, " version %i", preq.version);
	fprintf(output, "\n");
}

void conf_ifxflags(FILE *output, int ifs, char *ifname)
{
	struct ifreq ifr;
	struct shim_hdr shim;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGIFXFLAGS, (caddr_t)&ifr) != -1) {
 		/* set mpls mode for eth interfaces */
		if (ifr.ifr_flags & IFXF_MPLS)
			fprintf(output, " mpls\n");
		if (ifr.ifr_flags & IFXF_NOINET6)
			fprintf(output, " no inet6\n");
		if (ifr.ifr_flags & IFXF_INET6_NOPRIVACY)
			fprintf(output, " no autoconfprivacy\n");
		if (ifr.ifr_flags & IFXF_WOL)
			fprintf(output, " wol\n");
	}

	bzero(&shim, sizeof(shim));
	ifr.ifr_data = (caddr_t)&shim;

	/* set label for mpe */
	if (ioctl(ifs, SIOCGETLABEL , (caddr_t)&ifr) != -1)
		if (shim.shim_label > 0)
			fprintf(output, " label %d\n", shim.shim_label);
}

void conf_rdomain(FILE *output, int ifs, char *ifname)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ifs, SIOCGIFRDOMAIN, (caddr_t)&ifr) != -1)
		if (ifr.ifr_rdomainid != 0)
			fprintf(output, " rdomain %d\n", ifr.ifr_rdomainid);
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
	

void conf_ifmetrics(FILE *output, int ifs, struct if_data if_data,
    char *ifname)
{
	char tmpa[IPSIZ], tmpb[IPSIZ], tmpc[TMPSIZ];
	int buf;

	/*
	 * Various metrics valid for non-bridge interfaces
	 */
	if (phys_status(ifs, ifname, tmpa, tmpb, IPSIZ, IPSIZ, &buf) > 0) {
		/* future os may use this for more than tunnel? */
		fprintf(output, " tunnel %s %s", tmpa, tmpb);
		if (&buf != NULL && buf > 0)
			fprintf(output, " rdomain %i", buf);
		fprintf(output, "\n");
	}

	/*
	 * print interface mtu, metric
	 *
	 * ignore interfaces named "pfsync" since their mtu
	 * is dynamic and controlled by the kernel
	 */
	if (!MIN_ARG(ifname, "pfsync") && (if_mtu != default_mtu(ifname) &&
	    default_mtu(ifname) != MTU_IGNORE) && if_mtu != 0)
		fprintf(output, " mtu %u\n", if_mtu);
	if (if_metric)
		fprintf(output, " metric %u\n", if_metric);

	if (get_nwinfo(ifname, tmpc, TMPSIZ, NWID) != 0) {
		fprintf(output, " nwid %s\n", tmpc);
		if (get_nwinfo(ifname, tmpc, TMPSIZ, NWKEY) != 0)
			fprintf(output, " nwkey %s\n", tmpc);
		if (get_nwinfo(ifname, tmpc, TMPSIZ, TXPOWER) != 0)
			fprintf(output, " txpower %s\n", tmpc);
		if (get_nwinfo(ifname, tmpc, TMPSIZ, POWERSAVE) != 0)
			fprintf(output, " powersave %s\n", tmpc);
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


int conf_ifaddrs(FILE *output, char *ifname, int flags)
{
	struct ifaddrs *ifa, *ifap;
	struct sockaddr_in *sin, *sinmask, *sindest;
	struct sockaddr_in6 *sin6, *sin6mask, *sin6dest;
	int ippntd = 0;

	if (getifaddrs(&ifap) != 0) {
		printf("%% conf: getifaddrs failed: %s\n",
		strerror(errno));
		return(-1);
	}

	/*
	 * Cycle through getifaddrs for interfaces with our
	 * desired name that sport AF_INET | AF_INET6. Print
	 * the IP and related information.
	 */
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strncmp(ifname, ifa->ifa_name, IFNAMSIZ))
			continue;

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)ifa->ifa_addr;
			if (sin->sin_addr.s_addr == 0)
				continue;
			sinmask = (struct sockaddr_in *)ifa->ifa_netmask;
			if (flags & IFF_POINTOPOINT) {
				sindest = (struct sockaddr_in *)ifa->ifa_dstaddr;
				fprintf(output, " ip %s",
				    routename4(sin->sin_addr.s_addr));
				fprintf(output, " %s", inet_ntoa(sindest->sin_addr));
			} else if (flags & IFF_BROADCAST) {
				sindest = (struct sockaddr_in *)ifa->ifa_broadaddr;
				fprintf(output, " ip %s",
				    netname4(sin->sin_addr.s_addr, sinmask));
				/*
				 * no reason to save the broadcast addr
				 * if it is standard (this should always 
				 * be true unless someone has messed up their
				 * network or they are playing around...)
				 */
				if (ntohl(sindest->sin_addr.s_addr) !=
				    in4_brdaddr(sin->sin_addr.s_addr,
				    sinmask->sin_addr.s_addr))
					fprintf(output, " %s",
					    inet_ntoa(sindest->sin_addr));
			} else {
				fprintf(output, " ip %s",
				    netname4(sin->sin_addr.s_addr, sinmask));
			}
			ippntd = 1;
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			sin6mask = (struct sockaddr_in6 *)ifa->ifa_netmask;
			if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
				continue;
			if (!ipv6ll_db_compare(sin6, sin6mask, ifname))
				continue;
			in6_fillscopeid(sin6);
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

	for (i = 0; i < sizeof(defmtus) / sizeof(defmtus[0]); i++)
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

	if (tableid < 0 || tableid > RT_TABLEID_MAX) {
		printf("%% conf_routes: tableid %d out of range\n", tableid);
		return(1);
	}
	rtdump = getrtdump(0, flags, tableid);
	if (rtdump == NULL)
		return(1);

	/* walk through routing table */
	for (next = rtdump->buf; next < rtdump->lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if ((rtm->rtm_flags & flags) == 0)
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
conf_groupattrib(FILE *output)
{
	int ifs;
	u_int len;
	struct ifgroupreq	ifgr, ifgr_a;
	struct ifg_req		*ifg;
	struct if_nameindex *ifn_list, *ifnp;

	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% conf_groupattrib: if_nameindex failed\n");
		return;
	}

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% conf_groupattrib socket: %s\n", strerror(errno));
		if_freenameindex(ifn_list);
		return;
        }

	/*
	 * The only way to get attributes for each group is to loop through
	 * all the groups on all the interfaces and ask for the attribs.
	 * (The loop through all groups on an interface code is ripped
	 * straight from ifconfig.c)
	 * XXX need to keep track of what groups we printed so we don't
	 * print them twice
	 */

	for (ifnp = ifn_list; ifnp->if_name != NULL; ifnp++) {
		bzero(&ifgr, sizeof(ifgr));
		strlcpy(ifgr.ifgr_name, ifnp->if_name, IFNAMSIZ);

		if (ioctl(ifs, SIOCGIFGROUP, (caddr_t)&ifgr) == -1 &&
		    errno != ENOTTY) {
			printf("%% conf_groupattrib: SIOCGIFGROUP/1: %s\n",
				    strerror(errno));
			return;
		}

		len = ifgr.ifgr_len;
		ifgr.ifgr_groups =
		    (struct ifg_req *)calloc(len / sizeof(struct ifg_req),
		    sizeof(struct ifg_req));
		if (ifgr.ifgr_groups == NULL) {
			printf("%% conf_groupattrib: calloc: %s\n",
			    strerror(errno));
			return;
		}
		if (ioctl(ifs, SIOCGIFGROUP, (caddr_t)&ifgr) == -1) {
			printf("%% conf_groupattrib: SIOCGIFGROUP/2: %s\n",
			    strerror(errno));
			free(ifgr.ifgr_groups);
		}
		ifg = ifgr.ifgr_groups;
		for (; ifg && len >= sizeof(struct ifg_req); ifg++) {
			len -= sizeof(struct ifg_req);

			bzero(&ifgr_a, sizeof(ifgr_a));
			strlcpy(ifgr_a.ifgr_name, ifg->ifgrq_group, IFNAMSIZ);

			if (ioctl(ifs, SIOCGIFGATTR, (caddr_t)&ifgr_a) == -1)
				continue;
			/* group attribs are only 'carpdemoted' for now */
			if (ifgr_a.ifgr_attrib.ifg_carp_demoted != 0)
				fprintf(output, "group %s carpdemote %d\n",
				    ifg->ifgrq_group,
				    ifgr_a.ifgr_attrib.ifg_carp_demoted);
		}
		free(ifgr.ifgr_groups);
	}
	if_freenameindex(ifn_list);
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
	struct sockaddr_in6 *sin6mask = (struct sockaddr_in6 *)samask;

	switch (sa->sa_family) {
	case AF_INET:
		if ((((struct sockaddr_in *)samask)->sin_addr.s_addr) == INADDR_ANY);
			return
			    (((struct sockaddr_in *)sa)->sin_addr.s_addr) == INADDR_ANY;
		break;
	case AF_INET6:
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6mask->sin6_addr))
			return (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr));
		break;
	default:
		break;
	}
	return 0;
}

void
conf_print_rtm(FILE *output, struct rt_msghdr *rtm, char *delim, int af)
{
	int i;
	char *cp, flags[64];
	struct sockaddr *dst = NULL, *gate = NULL, *mask = NULL;
	struct sockaddr *sa;
	struct sockaddr_in sin;

	sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	cp = ((char *)rtm + rtm->rtm_hdrlen);
	for (i = 1; i; i <<= 1)
		if (i & rtm->rtm_addrs) {
			sa = (struct sockaddr *)cp;
			switch (i) {
			case RTA_DST:
				/* allow arp to get printed with af==AF_LINK */
				if ((sa->sa_family == af) ||
				    (af == AF_LINK && sa->sa_family == AF_INET)) {
					if (rtm->rtm_flags & RTF_REJECT)
						snprintf(flags, sizeof(flags),
						    " reject");
					else
						flags[0] = '\0';
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
		 * Suppress printing IP route if it's the default
		 * route and dhcp (dhclient) is enabled.
		 */
		if (!(isdefaultroute(dst, mask)
		    && dhclient_isenabled(routename(gate)))) {
			fprintf(output, "%s%s ", delim, netname(dst, mask));
			fprintf(output, "%s%s\n", routename(gate), flags);
		}
	} else if (dst && gate && (af == AF_LINK)) {
		/* print arp */
		fprintf(output, "%s%s ", delim, routename(dst));
		fprintf(output, "%s%s\n", routename(gate), flags);
	}
}
