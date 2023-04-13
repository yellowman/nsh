/* define constants and functions associated with
   daemon control */

/* if.c related */
#define DHCLIENT        "/sbin/dhclient"
#define DHCRELAY        "/usr/sbin/dhcrelay"
#define RAD             "/usr/sbin/rad"
#define DHCPLEASED_SOCK "/dev/dhcpleased.sock"
#define SLAACD_SOCK     "/dev/slaacd.sock"
#define IFDATA_MTU 1            /* request for if_data.ifi_mtu */
#define IFDATA_BAUDRATE 2       /* request for if_data.ifi_baudrate */
#define IFDATA_IFTYPE 3         /* request for if_data.ifi_type */
#define MBPS(bps) (bps / 1000 / 1000)
#define ROUNDMBPS(bps) ((float)bps == ((bps / 1000 / 1000) * 1000 * 1000))
#define ROUNDKBPS(bps) ((float)bps == ((bps / 1000) * 1000))
#define ROUNDKBYTES(bytes) ((float)bytes == ((bytes / 1024) * 1024))
#define DEFAULT_LLPRIORITY 3

/* service daemons */
#define OSPFD           "/usr/sbin/ospfd"
#define OSPF6D          "/usr/sbin/ospf6d"
#define EIGRPD          "/usr/sbin/eigrpd"
#define BGPD            "/usr/sbin/bgpd"
#define RIPD            "/usr/sbin/ripd"
#define ISAKMPD         "/sbin/isakmpd"
#define IKED            "/sbin/iked"
#define DVMRPD          "/usr/sbin/dvmrpd"
#define RELAYD          "/usr/sbin/relayd"
#define DHCPD           "/usr/sbin/dhcpd"
#define SASYNCD         "/usr/sbin/sasyncd"
#define SNMPD           "/usr/sbin/snmpd"  
#define NTPD            "/usr/sbin/ntpd"
#define FTPPROXY        "/usr/sbin/ftp-proxy"
#define TFTPPROXY       "/usr/sbin/tftp-proxy"
#define TFTPD           "/usr/sbin/tftpd"
#define INETD           "/usr/sbin/inetd"
#define SSHD            "/usr/sbin/sshd"
#define LDPD            "/usr/sbin/ldpd"                                        
#define SMTPD           "/usr/sbin/smtpd"
#define LDAPD           "/usr/sbin/ldapd"
#define IFSTATED        "/usr/sbin/ifstated"
#define NPPPD           "/usr/sbin/npppd"
#define NPPPCTL         "/usr/sbin/npppctl"
#define RESOLVD         "/sbin/resolvd"
#ifndef DHCPLEASES
#define DHCPLEASES      "/var/db/dhcpd.leases"
#endif

/* control programs */   
#define PFCTL           "/sbin/pfctl"
#define OSPFCTL         "/usr/sbin/ospfctl"
#define OSPF6CTL        "/usr/sbin/ospf6ctl"
#define EIGRPCTL        "/usr/sbin/eigrpctl"
#define BGPCTL          "/usr/sbin/bgpctl"
#define RIPCTL          "/usr/sbin/ripctl"
#define LDPCTL          "/usr/sbin/ldpctl"
#define IPSECCTL        "/sbin/ipsecctl"
#define IKECTL          "/usr/sbin/ikectl"
#define DVMRPCTL        "/usr/sbin/dvmrpctl"
#define RELAYCTL        "/usr/sbin/relayctl"
#define SNMPCTL         "/usr/sbin/snmpctl"
#define SMTPCTL         "/usr/sbin/smtpctl"
#define LDAPCTL         "/usr/sbin/ldapctl"

/* argument list replacement */
#define OPT     (void *)1
#define REQ     (void *)2
#define IFNAME  (void *)3
#define REQTEMP (void *)4                                                       
#define SIZE_CONF_TEMP 64
int ctlhandler(int, char **, char *);
void rmtemp(char *);
struct ctl {
        char *name;
        char *help;
        char *args[32];
        void (*handler)();
        int flag_x;
        int type;
};

#define T_HANDLER       1
#define T_HANDLER_FILL1 2
#define T_EXEC          3
struct daemons {
        char *name;
        char *propername;
        struct ctl *table;
        char *tmpfile;
        mode_t mode;
        int doreload;
        int rtablemax;
};


/* tmp config locations */
#define PFCONF_TEMP     "/var/run/pf.conf"
#define OSPFCONF_TEMP   "/var/run/ospfd.conf"
#define OSPF6CONF_TEMP  "/var/run/ospf6d.conf"
#define EIGRPCONF_TEMP  "/var/run/eigrpd.conf"
#define BGPCONF_TEMP    "/var/run/bgpd.conf"
#define RIPCONF_TEMP    "/var/run/ripd.conf"
#define LDPCONF_TEMP    "/var/run/ldpd.conf"
#define IPSECCONF_TEMP  "/var/run/ipsec.conf"
#define IKECONF_TEMP    "/var/run/iked.conf"
#define DVMRPCONF_TEMP  "/var/run/dvmrpd.conf"
#define RADCONF_TEMP    "/var/run/rad.conf"
#define RELAYCONF_TEMP  "/var/run/relayd.conf"
#define SASYNCCONF_TEMP "/var/run/sasyncd.conf"
#define DHCPCONF_TEMP   "/var/run/dhcpd.conf"
#define SNMPCONF_TEMP   "/var/run/snmpd.conf"
#define NTPCONF_TEMP    "/var/run/ntpd.conf"
#define IFSTATE_TEMP    "/var/run/ifstated.conf"
#define NPPPCONF_TEMP   "/var/run/npppd.conf"
#define FTPPROXY_TEMP   "/var/run/ftp-proxy"
#define TFTPPROXY_TEMP  "/var/run/tftp-proxy"
#define TFTP_TEMP       "/var/run/tftpd"
#define INETCONF_TEMP   "/var/run/inetd.conf"
#define SSHDCONF_TEMP   "/var/run/sshd.conf"
#define SMTPCONF_TEMP   "/var/run/smtpd.conf"
#define LDAPCONF_TEMP   "/var/run/ldapd.conf"
#define IFSTATECONF_TEMP "/var/run/ifstated.conf"
#define MOTD_TEMP "/var/run/motd"

/* ctl tests*/
static char *ctl_bgp_test[] = { BGPD, "-nf", REQTEMP, NULL, NULL };
static char *ctl_dhcp_test[] = { DHCPD, "-nc", REQTEMP, NULL };
static char *ctl_dvmrp_test[] = { DVMRPD, "-nf", REQTEMP, NULL };
static char *ctl_eigrp_test[] = { EIGRPD, "-nf", REQTEMP, NULL };
/* ftpproxy test ? */
static char *ctl_ifstate_test[] = { IFSTATED, "-nf", REQTEMP, NULL };
static char *ctl_ike_test[] = { IKED, "-nf", REQTEMP, NULL };
/* inetd test ? */ 
static char *ctl_ipsec_test[] = { IPSECCTL, "-nf", REQTEMP, NULL };
static char *ctl_ldap_test[] = { LDAPD, "-nf", REQTEMP, NULL };
static char *ctl_ldp_test[] = { LDPD, "-nf", REQTEMP, NULL };
static char *ctl_nppp_test[] = { NPPPD, "-nf", REQTEMP, NULL };
static char *ctl_ntp_test[] = { NTPD, "-nf", REQTEMP, NULL };
static char *ctl_pf_test[] = { PFCTL, "-nf", REQTEMP, NULL };
static char *ctl_ospf_test[] = { OSPFD, "-nf", REQTEMP, NULL };
static char *ctl_ospf6_test[] = { OSPF6D, "-nf", REQTEMP, NULL };
static char *ctl_rad_test[] = { RAD, "-nf", REQTEMP, NULL };
static char *ctl_relay_test[] = { RELAYD, "-nf", REQTEMP, NULL };
/* resolvd test how can this be done ? */
static char *ctl_rip_test[] = { RIPD, "-nf", REQTEMP, NULL };
static char *ctl_sasync_test[] = { SASYNCD, "-nc", REQTEMP, NULL };
static char *ctl_smtp_test[] = { SMTPD, "-nf", REQTEMP, NULL };
static char *ctl_snmp_test[] = { SNMPD, "-nf", REQTEMP, NULL };
static char *ctl_sshd_test[] = { SSHD, "-tf", REQTEMP, NULL };
/* tftpd test how this can be done ? */
/* tftpproxy  how this can be done ? */

extern struct daemons ctl_daemons[];
extern struct ctl ctl_pf[];
extern struct ctl ctl_ospf[];
extern struct ctl ctl_ospf6[];
extern struct ctl ctl_eigrp[];
extern struct ctl ctl_relay[];
extern struct ctl ctl_bgp[];
extern struct ctl ctl_rip[];
extern struct ctl ctl_ldp[];
extern struct ctl ctl_ipsec[];
extern struct ctl ctl_nppp[];
extern struct ctl ctl_ifstate[];
extern struct ctl ctl_ike[];
extern struct ctl ctl_dvmrp[];
extern struct ctl ctl_rad[];
extern struct ctl ctl_sasync[];
extern struct ctl ctl_dhcp[];
extern struct ctl ctl_snmp[];
extern struct ctl ctl_smtp[];
extern struct ctl ctl_sshd[];
extern struct ctl ctl_ntp[];
extern struct ctl ctl_ftpproxy[];
extern struct ctl ctl_tftpproxy[];
extern struct ctl ctl_tftp[];
extern struct ctl ctl_dns[];
extern struct ctl ctl_inet[];
extern struct ctl ctl_ldap[];
extern struct ctl ctl_motd[];
extern struct ctl ctl_resolv[];
void flag_x(char *, char *, int, char *);
