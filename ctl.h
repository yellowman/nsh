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
#define RADIUSD         "/usr/sbin/radiusd"
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
#define RADIUSCTL	"/usr/sbin/radiusctl"
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
#define RADIUSCONF_TEMP	"/var/run/radiusd.conf"
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
#define CRONTAB_TEMP     "/var/run/crontab"

/* ctl tests*/
extern char *ctl_bgp_test[];
extern char *ctl_dhcp_test[];
extern char *ctl_dvmrp_test[];
extern char *ctl_eigrp_test[];
/* ftpproxy test no config test yet */
extern char *ctl_ifstate_test[];
extern char *ctl_ike_test[];
/* inetd test  no config test yet */ 
extern char *ctl_ipsec_test[];
extern char *ctl_ldap_test[];
extern char *ctl_ldp_test[];
extern char *ctl_nppp_test[];
extern char *ctl_ntp_test[];
extern char *ctl_pf_test[];
extern char *ctl_ospf_test[];
extern char *ctl_ospf6_test[];
extern char *ctl_rad_test[];
extern char *ctl_radius_test[];
extern char *ctl_relay_test[];
/* resolvd test no config test yet */
extern char *ctl_rip_test[];
extern char *ctl_sasync_test[];
extern char *ctl_smtp_test[];
extern char *ctl_snmp_test[];
extern char *ctl_sshd_test[];
/* tftpd test no config test yet */
/* tftpproxy test no config test yet */

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
extern struct ctl ctl_radius[];
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
extern struct ctl ctl_crontab[];
extern struct ctl ctl_resolv[];
void flag_x(char *, char *, int, char *);
