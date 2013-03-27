/*
 * nsh externs, prototypes and macros
 */

#define NO_ARG(x)	(strcasecmp(x, "no") == 0) /* absolute "no" */
#define MIN_ARG(x,y)	(strncasecmp(x, y, strlen(y)) == 0) /* mabye arg y */

#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0])) /* sys/param.h */

struct rtdump {
	char *buf;	/* start of routing table */
	char *lim;	/* end of routing table */
};

extern char *__progname;	/* duh */
extern char *vers;		/* the version of nsh */
extern char saveline[1024];	/* command line */
extern char line[1024];		/* command line for makeargv() */
extern int  margc;		/* makeargv() arg count */
extern char *margv[];		/* makeargv() args */
extern int verbose;		/* is verbose mode on? */
extern int editing;		/* is command line editing mode on? */
extern int bridge;		/* are we in bridge mode (or interface mode?) */
extern int priv;		/* privileged mode or not? */
extern pid_t pid;		/* process id of nsh */
extern int cli_rtable;		/* environment rtable */

#define HSIZE	64
extern char hname[HSIZE];	/* prefix name to mode handler */

#ifdef _HISTEDIT_H_
extern HistEvent ev;		/* ev */
#endif

/* defaults */
#define	DEFAULT_MTU	1500		/* net.inet.ip.defmtu */
#define	DEFAULT_TTL	64		/* net.inet.ip.defttl */
#define DEFAULT_MTTL	255		/* net.mpls.ttl */
#define ESP_UDPENCAP_PORT 4500		/* net.inet.esp.udpencap_port */

/* conf.c */
#define LEASEPREFIX	"/var/db/dhclient.leases"
int conf(FILE *);
u_long default_mtu(char *);
int conf_routes(FILE *, char *, int, int, int);
int conf_dhcrelay(char *, char *, int);

/* show.c */
void p_rttables(int, u_int, int);
#ifdef _NETINET_IN_H_
char *routename4(in_addr_t);
char *netname4(in_addr_t, struct sockaddr_in *);
#endif
#ifdef _NETINET6_IN6_H_
char *routename6(struct sockaddr_in6 *);
char *netname6(struct sockaddr_in6 *, struct sockaddr_in6 *);
void in6_fillscopeid(struct sockaddr_in6 *);
void in6_clearscopeid(struct sockaddr_in6 *);
#endif
#ifdef _SYS_SOCKET_H_
char *routename(struct sockaddr *);
char *netname(struct sockaddr *, struct sockaddr *);
char *any_ntoa(const struct sockaddr *);
#endif

/* alignment constraint for routing socket */
#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

/* routesys.c */
#ifdef _NET_ROUTE_H_
struct m_rtmsg {
        struct  rt_msghdr m_rtm;
        char    m_space[512];
};
extern struct m_rtmsg m_rtmsg;
#endif
#ifdef _WANT_SO_
union   sockunion {
	struct	sockaddr sa;
	struct	sockaddr_in sin;
	struct	sockaddr_in6 sin6;
	struct	sockaddr_dl sdl;
	struct	sockaddr_inarp sinarp;
};
extern union sockunion so_dst, so_mask, so_gate, so_ifp;
#endif
#ifdef _NETINET6_IN6_H_
int prefixlen(int, struct sockaddr_in6 *);
#endif
extern int rtm_addrs;
extern u_long rtm_inits;
#define FLUSH 0
struct rtdump *getrtdump(int, int, int);
void freertdump(struct rtdump *);
int monitor(int, char **);
int rtmsg(int, int, int, int, int);
void flushroutes(int, int);
void bprintf(FILE *, int, u_char *);
#ifdef _NET_IF_DL_H_
char *mylink_ntoa(const struct sockaddr_dl *);
#endif
extern char ifnetflags[];
extern char routeflags[];
extern char addrnames[];
extern char metricnames[];

/* ctl.c */
/* tmp config locations */
#define PFCONF_TEMP	"/var/run/pf.conf"
#define OSPFCONF_TEMP	"/var/run/ospfd.conf"
#define OSPF6CONF_TEMP	"/var/run/ospf6d.conf"
#define BGPCONF_TEMP	"/var/run/bgpd.conf"
#define RIPCONF_TEMP	"/var/run/ripd.conf"
#define LDPCONF_TEMP	"/var/run/ldpd.conf"
#define IPSECCONF_TEMP	"/var/run/ipsec.conf"
#define IKECONF_TEMP	"/var/run/iked.conf"
#define DVMRPCONF_TEMP	"/var/run/dvmrpd.conf"
#define RTADVCONF_TEMP	"/var/run/rtadvd.conf"
#define RELAYCONF_TEMP	"/var/run/relayd.conf"
#define SASYNCCONF_TEMP	"/var/run/sasyncd.conf"
#define DHCPCONF_TEMP	"/var/run/dhcpd.conf"
#define SNMPCONF_TEMP	"/var/run/snmpd.conf"
#define NTPCONF_TEMP	"/var/run/ntpd.conf"
#define IFSTATE_TEMP	"/var/run/ifstated.conf"
#define NPPPCONF_TEMP	"/var/run/npppd.conf"
#define FTPPROXY_TEMP	"/var/run/ftp-proxy"
#define TFTPPROXY_TEMP	"/var/run/tftp-proxy"
#define TFTP_TEMP	"/var/run/tftpd"
#define RESOLVCONF_TEMP	"/var/run/resolv.conf"
#define RESOLVCONF_SYM	"/var/run/resolv.conf.symlink"
#define RESOLVCONF_DHCP	"/var/run/resolv.conf.dhcp"
#define MOTDCONF_TEMP	"/var/run/motd"
#define INETCONF_TEMP	"/var/run/inetd.conf"
#define SSHDCONF_TEMP	"/var/run/sshd.conf"
#define SMTPCONF_TEMP 	"/var/run/smtpd.conf"
#define LDAPCONF_TEMP	"/var/run/ldapd.conf"
#define IFSTATECONF_TEMP "/var/run/ifstated.conf"
/* argument list replacement */
#define OPT     (void *)1
#define REQ     (void *)2
#define IFNAME  (void *)3
#define REQTEMP (void *)4
#define SIZE_CONF_TEMP 64
int ctlhandler(int, char **, char *);
void rmtemp(char *);
/* control programs */
#define PFCTL		"/sbin/pfctl"
#define OSPFCTL		"/usr/sbin/ospfctl"
#define OSPF6CTL	"/usr/sbin/ospf6ctl"
#define BGPCTL		"/usr/sbin/bgpctl"
#define RIPCTL		"/usr/sbin/ripctl"
#define LDPCTL		"/usr/sbin/ldpctl"
#define IPSECCTL	"/sbin/ipsecctl"
#define IKECTL		"/usr/sbin/ikectl"
#define DVMRPCTL	"/usr/sbin/dvmrpctl"
#define RELAYCTL	"/usr/sbin/relayctl"
#define SNMPCTL		"/usr/sbin/snmpctl"
#define SMTPCTL		"/usr/sbin/smtpctl"
#define LDAPCTL		"/usr/sbin/ldapctl"
struct ctl {
	char *name;
	char *help;
	char *args[32];
	void (*handler)();
	int flag_x;
	int type;
};
#define	T_HANDLER	1
#define T_HANDLER_FILL1	2
#define	T_EXEC		3
struct daemons {
        char *name;
	char *propername;
        struct ctl *table;
        char *tmpfile;
	mode_t mode;
	int doreload;
	int rtablemax;
};
extern struct daemons ctl_daemons[];
extern struct ctl ctl_pf[];
extern struct ctl ctl_ospf[];
extern struct ctl ctl_ospf6[];
extern struct ctl ctl_relay[];
extern struct ctl ctl_bgp[];
extern struct ctl ctl_rip[];
extern struct ctl ctl_ldp[];
extern struct ctl ctl_ipsec[];
extern struct ctl ctl_nppp[];
extern struct ctl ctl_ifstate[];
extern struct ctl ctl_ike[];
extern struct ctl ctl_dvmrp[];
extern struct ctl ctl_rtadv[];
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
extern struct ctl ctl_motd[];
extern struct ctl ctl_inet[];
extern struct ctl ctl_ldap[];
void flag_x(char *, char *, int, char *);

/* commands.c */
#define NOPTFILL	7
#define DEFAULT_EDITOR	"/usr/bin/vi"
#define NSHRC_TEMP	"/var/run/nshrc"
#define NSHRC		"/etc/nshrc"
#define PING		"/sbin/ping"
#define PING6		"/sbin/ping6"
#define TRACERT		"/usr/sbin/traceroute"
#define TRACERT6	"/usr/sbin/traceroute6"
#define TELNET		"/usr/bin/telnet"
#define SSH		"/usr/bin/ssh"
#define PKILL		"/usr/bin/pkill"
#define SAVESCRIPT	"/usr/local/bin/save.sh"
/* tmp config locations */
#define DHCPDB          "/var/db/dhcpd.leases"
void command(void);
char **step_optreq(char **, char **, int, char **, int);
int argvtostring(int, char **, char *, int);
int cmdrc(char rcname[FILENAME_MAX]);
int cmdargs(char *, char **);
char *iprompt(void);
char *cprompt(void);
char *pprompt(void);
int group (int, char **);
void gen_help(char **, char *, char *, int);
void makeargv(void);
extern size_t cursor_argc;
extern size_t cursor_argo;

typedef struct cmd {
	char *name;		/* command name */
	char *help;		/* help string (NULL for no help) */
	char *complete;		/* context sensitive completion list */
	char **table;		/* next table for context completion */
	int stlen;		/* struct length (for rows in next table) */
	int (*handler) ();	/* routine which executes command */
	int needpriv;		/* Do we need privilege to execute? */   
	int nocmd;		/* Can we specify 'no ...command...'? */
	int modh;		/* Is it a mode handler for cmdrc()? */
} Command;
 
typedef struct menu {
	char *name;		/* How user refers to it (case independent) */
	char *help;		/* Help information (0 ==> no help) */
	char *complete;		/* context sensitive completion list */
	char **table;		/* next table for context completion */
	int stlen;		/* struct length (for rows in next table) */
	int minarg;		/* Minimum number of arguments */
	int maxarg;		/* Maximum number of arguments */
	int (*handler)();	/* Routine to perform (for special ops) */
} Menu;

struct intlist {
	char *name;             /* How user refers to it (case independent) */
	char *help;             /* Help information (0 ==> no help) */
	char *complete;		/* context sensitive completion list */
	char **table;		/* next table for context completion */
	int stlen;		/* struct length (for rows in next table) */
	int (*handler)();       /* Routine to perform (for special ops) */
	int bridge;             /* 0 == Interface, 1 == Bridge, 2 == Both */
};

/* generic help /complt struct */
struct ghs {
	char *name;
	char *help;
	char *complete;
	char **table;
	int stlen;
};

extern Command cmdtab[];
extern struct intlist Intlist[];
extern struct intlist Bridgelist[];
extern struct intlist *whichlist;

/* ieee80211.c */
#define NWID 0
#define NWKEY 1
#define POWERSAVE 2
#define TXPOWER 3
#define BSSID 4
#define DEFAULT_POWERSAVE 100	/* 100 ms */
const char *get_string(const char *, const char *, u_int8_t *, int *);
void make_string(char *str, int, const u_int8_t *buf, int);
int get_nwinfo(char *, char *, int, int);
int get_nwpowersave(int, char *);
int intnwkey(char *, int, int, char **);
int inttxpower(char *, int, int, char **);
int intbssid(char *, int, int, char **);

/* stats.c */
void rt_stats(void);
void tcp_stats(void);
void udp_stats(void);
void ip_stats(void);
void icmp_stats(void);
void igmp_stats(void);
void ah_stats(void);
void esp_stats(void);
void ipip_stats(void);
void carp_stats(void);
void pfsync_stats(void);
void ipcomp_stats(void);

/* mbuf.c */
void mbpr(void);

/* kread.c */
char *plural(int);
char *plurales(int);

/* genget.c */
int isprefix(char *, char*);
char **genget(char *, char **, int);
int Ambiguous(void *);

/* sysctl.c */
int sysctl_int(int[], int, int);
int ipsysctl(int, char *, char *, int);
void conf_sysctls(FILE *);

/* route.c */
#define NO_NETMASK 0
#define ASSUME_NETMASK 1
int route(int, char**);
void show_route(char *, int);
#ifdef _IP_T_
void parse_ip_pfx(char *, int, ip_t *);
int ip_route(ip_t *, ip_t *, u_short, int, int);
#endif
#ifdef _NETINET6_IN6_H_
int parse_ipv6(char *, struct in6_addr *);
#endif

/* if.c */
#define DHCLIENT	"/sbin/dhclient"
#define DHCRELAY	"/usr/sbin/dhcrelay"
#define RTSOL		"/sbin/rtsol"
#define RTADVD		"/usr/sbin/rtadvd"
#define IFDATA_MTU 1		/* request for if_data.ifi_mtu */
#define IFDATA_BAUDRATE 2	/* request for if_data.ifi_baudrate */
#define MBPS(bps) (bps / 1000 / 1000)
#define ROUNDMBPS(bps) ((float)bps == ((bps / 1000 / 1000) * 1000 * 1000))
#define ROUNDKBPS(bps) ((float)bps == ((bps / 1000) * 1000))
#define ROUNDKBYTES(bytes) ((float)bytes == ((bytes / 1024) * 1024))
int is_valid_ifname(char *);
int show_int(int, char **);
int get_rdomain(int, char *);
int get_ifdata(char *, int);
int get_ifflags(char *, int);
int set_ifflags(char *, int, int);
int get_ifxflags(char *, int);
int set_ifxflags(char *, int, int);
u_int32_t in4_netaddr(u_int32_t, u_int32_t);
u_int32_t in4_brdaddr(u_int32_t, u_int32_t);
int intip(char *, int, int, char **);
int intmtu(char *, int, int, char **);
int intkeepalive(char *, int, int, char **);
int intlabel(char *, int, int, char **);
int intrdomain(char *, int, int, char **);
int intdhcrelay(char *, int, int, char **);
int intmetric(char *, int, int, char **);
int intrtd(char *, int, int, char **);
int intvlan(char *, int, int, char **);
int intflags(char *, int, int, char **);
int intxflags(char *, int, int, char **);
int intlink(char *, int, int, char **);
int intnwid(char *, int, int, char **);
int intpowersave(char *, int, int, char **);
int intdesc(char *, int, int, char **);
int intpflow(char *, int, int, char **);
int intlladdr(char *, int, int, char **);
int intgroup(char *, int, int, char **);
int intrtlabel(char *, int, int, char **);
char *get_hwdaddr(char *);

/* main.c */
void intr(void);

/* version.c */
int version(int, char **);

/* compile.c */
extern char compiled[], compiledby[], compiledon[], compilehost[];

/* bridge.c */
long bridge_cfg(int, char *, int);
int bridge_confaddrs(int, char *, char *, FILE *);
int bridge_rules(int, char *, char *, char *, FILE *);
int bridge_list(int, char *, char *, char *, int, int);
int bridge_addrs(int, char *, char *, char *);
int set_ifflag(int, char *, short);
int clr_ifflag(int, char *, short);
int is_bridge(int, char *);
int brport(char *, int, int, char **);
int brval(char *, int, int, char **);
int brrule(char *, int, int, char **);
int brstatic(char *, int, int, char **);
int brpri(char *, int, int, char **);
int flush_bridgedyn(char *);
int flush_bridgeall(char *);
int flush_bridgerule(char *, char*);

/* tunnel.c */
int inttunnel(char *, int, int, char **);

/* media.c */
#define DEFAULT_MEDIA_TYPE	"autoselect"
void media_status(int, char *, char *);
void media_supported(int, char *, char *, char *);
int phys_status(int, char *, char *, char *, int, int, int *);
int intmedia(char *, int, int, char **);
int intmediaopt(char *, int, int, char **);
int conf_media_status(FILE *, int, char *);

/* passwd.c */
#define NSHPASSWD_TEMP "/var/run/nshpasswd"
int read_pass(char *, size_t);
int gen_salt(char *, size_t);
int enable(int, char **);

/* pfsync.c */
#define PFSYNC_MAXUPDATES 128
int intsyncdev(char *, int, int, char **);
int intsyncpeer(char *, int, int, char  **);
int intmaxupd(char *, int, int, char **);
int conf_pfsync(FILE *, int, char *);

/* carp.c */
#define CARP_ADVSKEW 0
#define CARP_ADVBASE 1
#define CARP_VHID 2
#define CARP_PEER 3
#define CARP_BALANCING 4
int intcarp(char *, int, int, char **);
int intcpass(char *, int, int, char **);
int intcnode(char *, int, int, char **);
int conf_carp(FILE *, int, char *);
int carp_state(int, char *);
int intcdev(char *, int, int, char **);

/* trunk.c */
int inttrunkport(char *, int, int, char **);
int inttrunkproto(char *, int, int, char **);
int conf_trunk(FILE *output, int ifs, char *ifname);
void show_trunk(int ifs, char *ifname);

/* who.c */
int who(int, char **);

/* timeslot.c */
int inttimeslot(char *, int, int, char **);
int timeslot_status(int, char *, char *, int);

/* arp.c */
int arpget(const char *);
int arpset(int, char **);

/* more.c */
int more(char *);
int nsh_cbreak(void);
void nsh_nocbreak(void);
void setwinsize(int);
#ifdef _SYS_TTYCOM_H_
extern struct winsize winsize;
#endif

/* complete.c */
#ifdef _HISTEDIT_H_
unsigned char complt_c(EditLine *, int);
unsigned char complt_i(EditLine *, int);
#endif
#define CMPL(x) __STRING(x),
#define CMPL0   "",
void inithist(void);
void endhist(void);
void initedit(void);
void endedit(void);

/* utils.c */
int string_index(char *, char **);
char *format_time(time_t);
char *format_k(uint64_t amt);

/* sqlite3.c */
#define SQ3DBFILE "/var/run/nsh.db"
#define DB_X_ENABLE 1
#define DB_X_DISABLE 2
#define DB_X_LOCAL 3
#define DB_X_OTHER 4
#define DB_X_REMOVE 5
int db_create_table_rtables(void);
int db_create_table_flag_x(char *);
int db_insert_flag_x(char *, char *, int, int, char *);
int db_insert_rtables(int, char *);
int db_delete_rtables_rtable(int);
int db_delete_flag_x_ctl(char *, char *);
int db_delete_flag_x_ctl_data(char *, char *, char *);
#ifdef _STRINGLIST_H
int db_select_flag_x_ctl_data(StringList *, char *, char *, char *);
int db_select_flag_x_ctl(StringList *, char *, char *);
int db_select_rtable_rtables(StringList *);
int db_select_rtables_rtable(StringList *, int);
int db_select_rtables_ctl(StringList *, char *);
int db_select_name_rtable(StringList *, int);
int db_select_flag_x_ctl_rtable(StringList *, char *, int);
int db_select_flag_x_data_ctl_rtable(StringList *, char *, char *, int);
#endif
int db_select_flag_x_dbflag_rtable(char *, char *, int);
