/* $nsh: externs.h,v 1.36 2007/12/25 22:46:14 chris Exp $ */
/*
 * nsh externs and more
 */

#define NO_ARG(x) (strcasecmp(x, "no") == 0) /* absolute "no" */
#define CMP_ARG(x,y) (strncasecmp(x, y, strlen(y)) == 0) /* mabye arg y */

struct rtdump {
	char *buf;	/* start of routing table */
	char *lim;	/* end of routing table */
};

extern char *__progname;	/* duh */
extern char *vers;		/* the version of nsh */
extern int verbose;		/* is verbose mode on? */
extern int editing;		/* is command line editing mode on? */
extern int bridge;		/* are we in bridge mode (or interface mode?) */
extern int priv;		/* privileged mode or not? */
extern pid_t pid;		/* process id of nsh */
#ifdef _HISTEDIT_H_
extern HistEvent ev;		/* ev */
#endif

/* defaults */
#define	DEFAULT_MTU	1500		/* net.inet.ip.defmtu */
#define	DEFAULT_TTL	64		/* net.inet.ip.defttl */
#define	DEFAULT_MAXQUEUE	300	/* net.inet.ip.maxqueue */

/* conf.c */
int conf(FILE *);
int default_mtu(char *);
int conf_routes(FILE *, char *, int, int);

/* routepr.c */
char *netname(in_addr_t, in_addr_t);
void routepr(u_long, int);

/* alignment constraint for routing socket */
#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

/* routesys.c */
#define FLUSH 0
struct rtdump *getrtdump(int);
void freertdump(struct rtdump *);
int monitor(void);
void flushroutes(int, int);
void bprintf(FILE *, int, u_char *);
extern char ifnetflags[];
extern char routeflags[];
extern char addrnames[];
extern char metricnames[];

/* commands.c */
#define DEFAULT_EDITOR	"/usr/bin/vi"
#define PFCONF_TEMP	"/var/run/pf.conf"
#define NSHRC_TEMP	"/var/run/nshrc"
#define NSHRC		"/etc/nshrc"
#define PFCTL		"/sbin/pfctl"
#define PING		"/sbin/ping"
#define PING6		"/sbin/ping6"
#define TRACERT		"/usr/sbin/traceroute"
#define TRACERT6	"/usr/sbin/traceroute6"
#define SAVESCRIPT	"/usr/local/bin/save.sh"
void command(int);
int cmdrc(char rcname[FILENAME_MAX]);
int cmdarg(char *, char *);
int load_nlist(void);
char *iprompt(void);
char *cprompt(void);
char *pprompt(void);

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
int kread(u_long, char *, int);
char *plural(int);
char *plurales(int);

/* genget.c */
int isprefix(char *, char*);
char **genget(char *, char **, int);
int Ambiguous(void *);

/* sysctl.c */
int sysctl_inet(int, int, int, int);
int ipsysctl(int, char *, char *);
void conf_ipsysctl(FILE *);

/* route.c */
#define NO_NETMASK 0
#define ASSUME_NETMASK 1
int route(int, char**);
void show_route(char *);
#ifdef _IP_T_
ip_t parse_ip(char *, int);
int ip_route(ip_t *, ip_t *, u_short);
#endif

/* if.c */
#define DHCLIENT	"/sbin/dhclient"
#define DHKILLSCRIPT	"/usr/local/bin/dhclient-kill.sh"
#define IFDATA_MTU 1		/* request for if_data.ifi_mtu */
#define IFDATA_BAUDRATE 2	/* request for if_data.ifi_baudrate */
#define MBPS(bps) (bps / 1000 / 1000)
#define ROUNDMBPS(bps) ((float)bps == ((bps / 1000 / 1000) * 1000 * 1000))
#define ROUNDKBPS(bps) ((float)bps == ((bps / 1000) * 1000))
#define ROUNDKBYTES(bytes) ((float)bytes == ((bytes / 1024) * 1024))
int is_valid_ifname(char *);
int show_int(char *);
int get_ifdata(char *, int);
int get_ifflags(char *, int);
int set_ifflags(char *, int, int);
u_int32_t in4_netaddr(u_int32_t, u_int32_t);
u_int32_t in4_brdaddr(u_int32_t, u_int32_t);
int intip(char *, int, int, char **);
int intmtu(char *, int, int, char **);
int intmetric(char *, int, int, char **);
int intvlan(char *, int, int, char **);
int intflags(char *, int, int, char **);
int intlink(char *, int, int, char **);
int intnwid(char *, int, int, char **);
int intpowersave(char *, int, int, char **);
int intdesc(char *, int, int, char **);
int intlladdr(char *, int, int, char **);
char *get_hwdaddr(char *);

/* version.c */
int version(void);

/* compile.c */
extern char compiled[], compiledby[], compiledon[], compilehost[];

/* editing.c */
void inithist(void);
void endhist(void);
void initedit(void);
void endedit(void);

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
int settunnel(int, char *, char *, char *);
int deletetunnel(int, char *);

/* media.c */
#define DEFAULT_MEDIA_TYPE	"autoselect"
void media_status(int, char *, char *);
void media_supported(int, char *, char *, char *);
int phys_status(int, char *, char *, char *, int, int);
int intmedia(char *, int, int, char **);
int intmediaopt(char *, int, int, char **);
int conf_media_status(FILE *, int, char *);

/* wi.c */
#define WI_PORT_BSS	1
#define WI_PORT_ADHOC	3
#define WI_PORT_HOSTAP	6
int wi_printaplist(char *);
void wi_dumpstats(char *);
void wi_dumpstations(char *);
int is_wavelan(int, char *);
int wi_porttype(char *);
int wi_printlevels(char *);

/* passwd.c */
#define NSHPASSWD_TEMP "/var/run/nshpasswd"
int read_pass(char *, size_t);
int write_pass(char *, size_t);
int gen_salt(char *, size_t);
int enable(int, char **);

/* pfsync.c */
#define PFSYNC_MAXUPDATES 128
int intsyncdev(char *, int, int, char **);
int intmaxupd(char *, int, int, char **);
int conf_pfsync(FILE *, int, char *);

/* carp.c */
#define CARP_ADVSKEW 0
#define CARP_ADVBASE 1
#define CARP_VHID 2
int intcarp(char *, int, int, char **);
int intcpass(char *, int, int, char **);
int intcnode(char *, int, int, char **);
int conf_carp(FILE *, int, char *);
const char *carp_state(int, char *);
int intcdev(char *, int, int, char **);

/* trunk.c */
int inttrunkport(char *, int, int, char **);
int inttrunkproto(char *, int, int, char **);
int conf_trunk(FILE *output, int ifs, char *ifname);
void show_trunk(int ifs, char *ifname);
