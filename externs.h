/*
 * nsh externs, prototypes and macros
 */

#ifndef NSH_VERSION
#error "NSH_VERSION is undefined"
#endif

#define NSH_STRINGIFY_VERSION(x) #x
#define NSH_STRINGVAL_VERSION(x) NSH_STRINGIFY_VERSION(x)

#define NSH_VERSION_STR NSH_STRINGVAL_VERSION(NSH_VERSION)

#define NO_ARG(x)	(strcasecmp(x, "no") == 0) /* absolute "no" */

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
extern int config_mode;		/* are we in comfig mode? */
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

/* nopt.c */
#define no_arg		1
#define req_arg		2
#define req_2arg	3
struct nopts {
	char *name;
	int type;
	int arg;
};
extern int noptind;
extern char *nopterr;
int nopt(int, char **, struct nopts *);

/* ppp.c */
int intsppp(char *, int, int, char **);
void pppoe_ipcp(char *, int, int);
int intpppoe(char *, int, int, char **);
int is_pppoe(char *, int);
#define NSH_PPPOE_IPADDR_IPCP 1
#define NSH_PPPOE_IPADDR_STATIC 2
int pppoe_get_ipaddrmode(char *);
void pppoe_conf_default_route(FILE *, char *, char *, char *, char *, char *);
void conf_pppoe(FILE *, int, char *);
void conf_sppp(FILE *, int, char *);

/* conf.c */
#define LEASEPREFIX	"/var/db/dhclient.leases"
#define DHCPLEASECTL	"/usr/sbin/dhcpleasectl"
#define SLAACCTL	"/usr/sbin/slaacctl"
int conf(FILE *);
void conf_interfaces(FILE *, char *, int);
u_long default_mtu(char *);
int conf_routes(FILE *, char *, int, int, int);
int conf_dhcrelay(char *, char *, int);
int dhcpleased_has_address(char *, const char *, const char *);

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
struct rtmsg {
	struct	rt_msghdr m_rtm;
	char	m_space[512];
};
extern struct rtmsg m_rtmsg;
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

/* ctl.c declarations moved to ctl.h */

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
#define DIFF		"/usr/bin/diff"
#define SAVESCRIPT	"/usr/local/bin/save.sh"
#ifndef DHCPLEASES
#define DHCPLEASES	"/var/db/dhcpd.leases"
#endif
void command(void);
char **step_optreq(char **, char **, int, char **, int);
int argvtostring(int, char **, char *, int);
int cmdrc(char rcname[FILENAME_MAX]);
int cmdargs_output(char *, char **, int, int);
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
	int needconfig;		/* Do we need config mode to execute? */
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
	int nocmd;		/* Can we specify 'no ...command...'? */
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
extern size_t cmdtab_nitems;
extern struct intlist Intlist[];
extern struct intlist Bridgelist[];
extern struct intlist *whichlist;
extern size_t Intlist_nitems;
extern size_t Bridgelist_nitems;

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
int is_ip_addr(char *);
#ifdef _IP_T_
void parse_ip_pfx(char *, int, ip_t *);
int ip_route(ip_t *, ip_t *, u_short, int, int, struct rt_metrics, int inits);
#endif
int rtnameserver(int, char *[], int);
#ifdef _NETINET6_IN6_H_
int parse_ipv6(char *, struct in6_addr *);
#endif

/* if.c */
#define DHCLIENT	"/sbin/dhclient"
#define DHCRELAY	"/usr/sbin/dhcrelay"
#define RAD		"/usr/sbin/rad"
#define DHCPLEASED_SOCK	"/dev/dhcpleased.sock"
#define SLAACD_SOCK	"/dev/slaacd.sock"
#define IFDATA_MTU 1		/* request for if_data.ifi_mtu */
#define IFDATA_BAUDRATE 2	/* request for if_data.ifi_baudrate */
#define IFDATA_IFTYPE 3		/* request for if_data.ifi_type */
#define MBPS(bps) (bps / 1000 / 1000)
#define ROUNDMBPS(bps) ((float)bps == ((bps / 1000 / 1000) * 1000 * 1000))
#define ROUNDKBPS(bps) ((float)bps == ((bps / 1000) * 1000))
#define ROUNDKBYTES(bytes) ((float)bytes == ((bytes / 1024) * 1024))
#define DEFAULT_LLPRIORITY 3
void imr_init(char *);
int is_valid_ifname(char *);
int show_int(int, char **);
int show_vlans(int, char **);
int show_ip(int, char **);
int show_autoconf(int, char **);
int get_rdomain(int, char *);
int get_ifdata(char *, int);
int get_ifflags(char *, int);
int set_ifflags(char *, int, int);
int get_ifxflags(char *, int);
int set_ifxflags(char *, int, int);
u_int32_t in4_netaddr(u_int32_t, u_int32_t);
u_int32_t in4_brdaddr(u_int32_t, u_int32_t);
extern struct ghs intiphelp[];
extern struct ghs intip6help[];
int intip(char *, int, int, char **);
int intipcp(char *, int, int, char **);
int intmtu(char *, int, int, char **);
int intkeepalive(char *, int, int, char **);
int intrdomain(char *, int, int, char **);
int intdhcrelay(char *, int, int, char **);
int intmetric(char *, int, int, char **);
int intllprio(char *, int, int, char **);
int intflags(char *, int, int, char **);
int intxflags(char *, int, int, char **);
int intaf(char *, int, int, char **);
int intlink(char *, int, int, char **);
int intnwid(char *, int, int, char **);
int intpowersave(char *, int, int, char **);
int intdesc(char *, int, int, char **);
int intpflow(char *, int, int, char **);
int intlladdr(char *, int, int, char **);
int intgroup(char *, int, int, char **);
int intrtlabel(char *, int, int, char **);
int intparent(char *, int, int, char **);
int intpatch(char *, int, int, char **);
int intmpls(char *, int, int, char **);
int intpwe3(char *, int, int, char **);
int intvnetflowid(char *, int, int, char **);
int addaf(char *, int, int);
int removeaf(char *, int, int);
int check_daemon_control_socket(const char *);
int dhcpleased_is_running(void);
int slaacd_is_running(void);
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
int bridge_member_search(int, char *);
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
int brprotect(char *, int, int, char **);
int show_bridges(int, char **);

/* tunnel.c */
int inttunnel(char *, int, int, char **);
int intvnetid(char *, int, int, char **);
int get_physrtable(int, char *);
int get_physttl(int, char *);
int get_physecn(int, char *);
int get_physdf(int, char *);
int64_t get_vnetid(int, char *);

/* media.c */
#define DEFAULT_MEDIA_TYPE	"autoselect"
void media_status(int, char *, char *);
void media_supported(int, char *, char *, char *);
int phys_status(int, char *, char *, char *, int, int);
int intmedia(char *, int, int, char **);
int intmediaopt(char *, int, int, char **);
int conf_media_status(FILE *, int, char *);
struct ifmediareq;
const char *get_ifm_linkstate_str(struct ifmediareq *);
const char *get_ifm_options_str(char *, size_t, uint64_t, uint64_t *);
const char *get_ifm_type_str(uint64_t);
const char *get_ifm_subtype_str(uint64_t);

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
void carplock(int);

/* trunk.c */
int inttrunkport(char *, int, int, char **);
int inttrunkproto(char *, int, int, char **);
int conf_trunk(FILE *output, int ifs, char *ifname);
void show_trunk(int ifs, char *ifname);

/* who.c */
int who(int, char **);

/* arp.c */
int arpget(const char *);
int arpset(int, char **);
void arpdump(void);
void conf_arp(FILE *, char *);
char *sec2str(time_t);
struct sockaddr_dl;
char *ether_str(struct sockaddr_dl *);

/* ndp.c */
int ndpset(int, char **);
void ndpget(const char *);
int ndpdelete(const char *);
struct sockaddr_in6;
void ndpdump(struct sockaddr_in6 *, int);
void conf_ndp(FILE *output, char *delim);

/* nameserver.c */
int nameserverset(int, char **);
void conf_nameserver(FILE *);

/* more.c */
int more(char *);
int nsh_cbreak(void);
void nsh_nocbreak(void);
void setwinsize(int);
#ifdef _SYS_TTYCOM_H_
extern struct winsize winsize;
#endif

/* complete.c */
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
#define DB_X_ENABLE 1		/* enable command */
#define DB_X_DISABLE 2		/* disable command */
#define DB_X_LOCAL 3		/* local control command */
#define DB_X_OTHER 4		/* other command */
#define DB_X_REMOVE 5		/* remove command */
#define DB_X_ENABLE_DEFAULT 6	/* enable command, always prints enable until disabled */
#define DB_X_DISABLE_ALWAYS 7	/* disable command, always prints if disabled */
int db_create_table_rtables(void);
int db_create_table_flag_x(char *);
int db_create_table_nameservers(void);
int db_insert_flag_x(char *, char *, int, int, char *);
int db_insert_rtables(int, char *);
int db_insert_nameserver(char *);
int db_delete_rtables_rtable(int);
int db_delete_flag_x_ctl(char *, char *, int);
int db_delete_flag_x_ctl_data(char *, char *, char *);
int db_delete_nameservers(void);
#ifdef _STRINGLIST_H
int db_select_flag_x_ctl_data(StringList *, char *, char *, char *);
int db_select_flag_x_ctl(StringList *, char *, char *);
int db_select_rtable_rtables(StringList *);
int db_select_rtables_rtable(StringList *, int);
int db_select_rtables_ctl(StringList *, char *);
int db_select_name_rtable(StringList *, int);
int db_select_flag_x_ctl_rtable(StringList *, char *, int);
int db_select_flag_x_data_ctl_rtable(StringList *, char *, char *, int);
int db_select_nameservers(StringList *);
#endif
int db_select_flag_x_dbflag_rtable(char *, char *, int);

/* pflow.c */
#define PFLOW_SENDER 0
#define PFLOW_RECEIVER 1
#define PFLOW_VERSION 2
#ifdef _SYS_SOCKET_H_
int pflow_addr(const char *, struct sockaddr_storage *);
#endif
int pflow_status(int, int, char *, char *);

/* wg.c */
int intwg(char *, int, int, char **);
int intwgpeer(char *, int, int, char **);
void conf_wg(FILE *, int, char *);
void show_wg(int, char *);

/* umb.c */
int intumb(char *, int, int, char **);
void conf_umb(FILE *, int, char *);
void show_umb(int, char *);
