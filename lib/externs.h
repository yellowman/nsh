/*
 * nsh externs, prototypes and macros
 */

#ifndef NSH_VERSION
#error "NSH_VERSION is undefined"
#endif

#define NSH_STRINGIFY(x) #x
#define NSH_STRINGVAL(x) NSH_STRINGIFY(x)

#define NSH_VERSION_STR NSH_STRINGVAL(NSH_VERSION)

#define NO_ARG(x)	(strcasecmp(x, "no") == 0) /* absolute "no" */

#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0])) /* sys/param.h */

struct rtdump {
	char *buf;	/* start of routing table */
	char *lim;	/* end of routing table */
};

extern char *vers;		/* the version of nsh */
extern char saveline[1024];	/* command line */
#define NARGS  (sizeof(line)/2)	/* max arguments in char line[] */
extern char line[1024];		/* command line for makeargv() */
extern int  margc;		/* makeargv() arg count */
extern char *margv[NARGS];	/* makeargv() args */
extern int verbose;		/* is verbose mode on? */
extern int editing;		/* is command line editing mode on? */
extern int interactive_mode;	/* are we in interactive mode? */
extern int config_mode;		/* nsh's: are we in config mode? */
extern int bridge;		/* nsh's: in bridge mode (or interface mode?) */
extern pid_t pid;		/* process id of nsh */
extern int cli_rtable;		/* environment rtable */
struct cand;
struct hashtable;
extern struct hashtable *nsh_env;/* per-user session environment variables */


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
int pppoe_ipcp(char *, int, int, struct cand *);
int is_pppoe(char *, int);
#define NSH_PPPOE_IPADDR_IPCP 1
#define NSH_PPPOE_IPADDR_STATIC 2
int pppoe_get_ipaddrmode(char *);
int pppoe_show_ipaddrmode(char *);
void pppoe_conf_default_route(FILE *, char *, char *, char *, char *, char *);
void conf_pppoe(FILE *, int, char *);
void conf_sppp(FILE *, int, char *);

/* conf.c */
int conf(FILE *);
int conf_rank(char *);
int conf_rank_rtable(char *);
void conf_interfaces(FILE *, char *, int);
#define MTU_IGNORE ULONG_MAX	/* ignore this "default" mtu */
u_long default_mtu(char *);
int default_llpriority(char *);
int default_txprio(char *);
int default_rxprio(char *);
int64_t default_vnetid(char *);
int conf_mtu_shown(char *, u_long);
int conf_routes(FILE *, char *, int, int, int);
struct rt_msghdr;
void conf_print_rtm(FILE *, struct rt_msghdr *, char *, int);
int conf_dhcrelay(char *, char *, int);
int conf_dhcrelay6(char *, char *, int);

/* show.c */
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
int monitor(int, char **, ...);
int rtmsg(int, int, int, int, int, struct cand *);
void flushroutes(int, int, int);
void bprintf(FILE *, int, u_char *);
#ifdef _NET_IF_DL_H_
#endif
extern char ifnetflags[];
extern char routeflags[];
extern char addrnames[];
extern char metricnames[];

/* ctl.c declarations moved to ctl.h */

/* cmdargs.c */
int cmdargs_output_setenv(char *, char **, int, int, char **, int);
int cmdargs_output(char *, char **, int, int);
int cmdargs(char *, char **);
int nsh_setrtable(int);

/* commands.c */
extern pid_t child;
#define NOPTFILL	7
#define DEFAULT_EDITOR	"/usr/bin/vi"
#define NSHRC		"/etc/nshrc"
#define NSHDB		"/var/db/nsh"	/* the configurations saved */
#define SAVED		NSHDB "/nshrc"	/* nshd's saved configuration */
#define ROLLBACKS	50		/* number saved; 0 is the newest */
#define ROLLBACK	NSHDB "/nshrc.%d"
#define ROLLBACK_HEAD	"# saved by "	/* who saved it, and why */
#define ROLLBACK_GEN	"# generation "	/* then which save it was */
#define CLEAR		"/usr/bin/clear"
#define LOGGER		"/usr/bin/logger"
#define PING		"/sbin/ping"
#define PING6		"/sbin/ping6"
#define TRACERT		"/usr/sbin/traceroute"
#define TRACERT6	"/usr/sbin/traceroute6"
#define TELNET		"/usr/bin/telnet"
#define SSH		"/usr/bin/ssh"
#define PKILL		"/usr/bin/pkill"
#define CRONTAB		"/usr/bin/crontab"
#define REBOOT		"/sbin/reboot"
#define HALT		"/sbin/halt"
#define SU		"/usr/bin/su"
#define USERADD		"/usr/sbin/useradd"
#define USERMOD		"/usr/sbin/usermod"
#define USERDEL		"/usr/sbin/userdel"
#define NSH_SHELL	"/usr/local/bin/nsh"	/* shell of nshd's accounts */
#define NSH_GROUP	"nshadmin"	/* nshd.h's NSHD_GROUP */
#define NSHLOGIN	NSHDB "/login"	/* the login classes and users */
#define DOAS		"/usr/bin/doas"
#ifndef DHCPLEASES
#define DHCPLEASES	"/var/db/dhcpd.leases"
#endif
int quit(int, char **, ...);
void sigalarm(int);
void command(void);
int cmd_rest(int, char **);
int argvtostring(int, char **, char *, int);
int cmdline_edits(char *, char *, int, FILE *);
int cmdline_run(char *, size_t, struct cand *);
int cmdexit(struct cand *);
/* a handler's: its work before its line's arguments is done; they are next */
#define LINE_ARGS	2
void nshd_mode(int, char *, int);
/* how a command runs, as nshd's CTL_COMMANDS rows say (row_runs()) */
#define RUN_NSH		1	/* nsh runs it */
#define RUN_LINE	2	/* a line to nshd's session */
#define RUN_OP		3	/* an operation nshd's system runs */
#define RUN_RULES	4	/* nsh edits a daemon's rules */
#define RUN_CONFIGURE	5	/* refused: it needs configure */
#define RUN_UNSUPPORTED	6	/* refused: nshd's configure cannot run it */
void row_runs(char **, int, char *, int *, int *);
extern int in_config;
int conf_mode(char *);
int conf_ordered(char *);

/* the commands a configuration has (conf_cmd(), args.h) */
int conf_find(int, char *, char **);
struct facts_value;
int conf_run_values(int, int, int, const struct facts_value *, char *);
void conf_reading(int);
void conf_block_end(int);
void conf_settle(void);


/* prompt.c */
char *iprompt(void);
char *cprompt(void);
char *pprompt(void);
void setprompt(const char *);
void restoreprompt(void);
extern char prompt[128];
extern char saved_prompt[sizeof(prompt)];

int group (int, char **, ...);
int makeargv(void);
int argsplit(char *, char **, size_t);
extern size_t cursor_argc;
extern size_t cursor_argo;

/*
 * A command's handler returns 0 when it did what was asked, -1 when it
 * did not, having said why, and 1 to leave the mode it runs in
 */
struct arg;
struct argcmd;
struct argvals;
typedef struct cmd {
	char *name;		/* command name */
	char *help;		/* help string (NULL for no help) */
	char *complete;		/* context sensitive completion list */
	char **table;		/* next table for context completion */
	int stlen;		/* struct length (for rows in next table) */
	int (*handler) (int, char **, ...); /* routine which executes command */
	int needsession;	/* Do we need nshd's session to execute? */
	int needconfig;		/* Do we need config mode to execute? */
	int nocmd;		/* Can we specify 'no ...command...'? */
	int modh;		/* Does it start a block? 2 for an rtable */
	int cand;		/* What it does in configure private (CAND_*) */
	/*
	 * If the command's line is parsed into values (nshd's
	 * args.h): the function that applies them, a code that tells it
	 * which of its commands this is, the line's arguments, ended by
	 * one with no name, and for a grammar the arguments cannot say,
	 * the function that reads the line's words. Such a row needs no
	 * handler
	 */
	int (*apply)(const struct argcmd *, int, const struct facts_value *,
	    char *, int, struct cand *);
	int code;
	const struct arg *args;
	int (*parse)(const struct argcmd *, int, char **, struct argvals *);
} Command;

typedef struct menu {
	char *name;		/* How user refers to it (case independent) */
	char *help;		/* Help information (0 ==> no help) */
	char *complete;		/* context sensitive completion list */
	char **table;		/* next table for context completion */
	int stlen;		/* struct length (for rows in next table) */
	int minarg;		/* Minimum number of arguments */
	int maxarg;		/* Maximum number of arguments */
	int (*handler)(int, char **, ...);	/* Routine to perform */
} Menu;

struct intlist {
	char *name;             /* How user refers to it (case independent) */
	char *help;             /* Help information (0 ==> no help) */
	char *complete;		/* context sensitive completion list */
	char **table;		/* next table for context completion */
	int stlen;		/* struct length (for rows in next table) */
	int (*handler)(int, char **, ...);       /* Routine to perform */
	int nocmd;		/* Can we specify 'no ...command...'? */
	int cand;		/* What it does in configure private (CAND_*) */
	/* as a Command's: what the line is parsed with, if it is */
	int (*apply)(const struct argcmd *, int, const struct facts_value *,
	    char *, int, struct cand *);
	int code;
	const struct arg *args;
	int (*parse)(const struct argcmd *, int, char **, struct argvals *);
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
void make_string(char *str, int, const u_int8_t *buf, int);
int get_nwinfo(char *, char *, int, int);
int get_nwpowersave(int, char *);
void conf_wpa(FILE *, int, char *);
void conf_80211(FILE *, int, char *);
int cand_join(struct cand *, char *, int, char *, char *, char *);
void conf_join(FILE *, int, char *);
uint64_t init_current_media(int, char *, struct cand *);
int cand_nwid(struct cand *, char *, u_int8_t *, int);
int cand_wpakey(struct cand *, char *, char *, int);
int cand_wpa(struct cand *, char *, int);
int cand_wpalist(struct cand *, char *, int, u_int);
int cand_powersave(struct cand *, char *, int, int);

/* stats.c */
char *plural(int);
char *plurales(int);
int pf_enabled(void);

/* genget.c */
int isprefix(char *, char*);
char **genget(char *, char **, int);
int Ambiguous(void *);
void gen_help(char **, char *, char *, int);

/* sysctl.c */
int sysctl_int(int[], int, int);
void conf_sysctls(FILE *);

/* route.c */
#define NO_NETMASK 0
#define ASSUME_NETMASK 1
int show_route(char *, int);
int is_ip_addr(char *);
#ifdef _IP_T_
void parse_ip_pfx(char *, int, ip_t *);
int ip_route(ip_t *, ip_t *, u_short, int, int, struct rt_metrics, int inits,
    struct cand *);
#endif
int route_cand(struct rt_msghdr *, struct cand *);
struct in_addr;
struct in6_addr;
int rtnameserver(char *, struct in_addr *, size_t, struct in6_addr *, size_t,
    int);
#ifdef _NETINET6_IN6_H_
int parse_ipv6(char *, struct in6_addr *);
#endif

/* if.c */
#define DHCRELAY	"/usr/sbin/dhcrelay"
#define DHCRELAY6	"/usr/sbin/dhcrelay6"
#define DHCRELAY6_DESTS	8	/* the destinations nsh gives dhcrelay6 */
#define ROUTE		"/sbin/route"
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
int cand_upline(struct cand *, char *, int);
int is_valid_ifname(char *);
int plainword(const char *, const char *);
int show_int(int, char **, ...);
void ip6_optstr(char *, size_t, int, u_int32_t, u_int32_t);
int show_vlans(int, char **, ...);
int show_ip(int, char **, ...);
int show_autoconf(int, char **, ...);
int get_rdomain(int, char *);
int get_ifdata(char *, int);
int get_ifflags(char *, int);
int set_ifflags(char *, int, int);
int ioctl_down(int, char *, u_long, void *);
int get_ifxflags(char *, int);
int set_ifxflags(char *, int, int);
u_int32_t in4_netaddr(u_int32_t, u_int32_t);
u_int32_t in4_brdaddr(u_int32_t, u_int32_t);
extern struct ghs intiphelp[];
extern struct ghs intip6help[];
int intipcp(char *, int, int, char **, struct cand *);
int addaf(char *, int, int);
int removeaf(char *, int, int);
int check_daemon_control_socket(const char *);
int dhcpleased_is_running(void);
char *get_hwdaddr(char *);

/* main.c */
void intr(void);

/* version.c */
int version(int, char **, ...);

/* compile.c */
extern char compiled[], compiledby[], compiledon[], compilehost[];

/* bridge.c */
long bridge_cfg(int, char *, int);
void conf_brcfg(FILE *, int, char *);
int bridge_confaddrs(int, char *, char *, FILE *);
int bridge_rules(int, char *, char *, char *, FILE *);
int bridge_list(int, char *, char *, char *, int, int);
int bridge_member_search(int, char *);
int brport_list(char *);
int brport_one(char *);
int set_ifflag(int, char *, short);
int is_bridge(int, char *);
int bridge_learns(int, char *);
int brvlan_gone(FILE *, const char *, char *, char *);
int show_bridges(int, char **, ...);

/* tunnel.c */
#define VXLAN_PORT	4789	/* vxlan's UDP port, unless given another */
void conf_cache(FILE *, int, char *);
int get_physrtable(int, char *);
int get_physttl(int, char *);
int get_physecn(int, char *);
int get_physdf(int, char *);
int64_t get_vnetid(int, char *);
int cand_vnetflowid(struct cand *);

/* media.c */
#define DEFAULT_MEDIA_TYPE	"autoselect"
void media_supported(int, char *, char *, char *, FILE *);
int phys_status(int, char *, char *, char *, int, int);
int intmedia(int, char **, ...);
int conf_media_status(FILE *, int, char *);
struct ifmediareq;

/* renderif.c */
const char *get_ifm_linkstate_str(struct ifmediareq *);
const char *get_ifm_options_str(char *, size_t, uint64_t, uint64_t *);
const char *get_ifm_type_str(uint64_t);
const char *get_ifm_subtype_str(uint64_t);
const char *get_media_type_string(uint64_t);
const char *get_media_subtype_string(uint64_t);
void print_media_word(uint64_t, int, int, FILE *);

/* passwd.c */
#define LOGIN_VIEW	0x1	/* a login class's permissions */
#define LOGIN_OPERATE	0x2
#define LOGIN_CONFIGURE	0x4
#define LOGIN_ADMIN	0x8
#define LOGIN_EXEC	0x10
#define LOGIN_ALL	0x1f
int login_class_perms(const char *);
int login_perms(uid_t);
/* a login class or user, as a configuration's line gives it */
struct login_line {
	int32_t user;			/* 1 a user's, 0 a class's */
	int32_t perms;			/* a class's, or -1 if not ones */
	char name[32];
	char class[32];			/* a user's */
};
/* a line of NSHLOGIN's, as the parser reads it (login_file()) */
#define LOGIN_LINES	1024		/* NSHLOGIN holds at most this many */
struct login_rec {
	int32_t user;			/* 1 a user's, 0 a class's */
	int32_t perms;			/* a class's, or -1 if not ones */
	int32_t made;			/* a user's: nshd made its account */
	char name[32];
	char class[64];			/* a user's */
};
int login_file(char *, size_t, struct login_rec *);
int login_kept(struct login_rec *, int);
int login_answer(int);
int login_words_perms(int, char **);
int login_lines(char *, size_t, uint32_t, struct login_line **, uint32_t *);
int login_perms_by(uid_t, int, struct login_line *, uint32_t);
int login_auth(char *, char *, const char **);
int login_may(const char *, uid_t);
size_t login_hide(char *, size_t);
void conf_login(FILE *);
/*
 * the parser's checks of what a session without admin commits, against
 * the running configuration (ctl.c, passwd.c, commit.c)
 */
void admin_begin(int, char *, size_t);
void admin_end(void);
int admin_may(char *, int, int);
int admin_test(char *, char *, size_t);
int admin_rules(int, int, char *, size_t);
int admin_cleared(char *);
struct facts_value;
int login_admin(int, const struct facts_value *);

/* pfsync.c */
#define PFSYNC_MAXUPDATES 128
int conf_pfsync(FILE *, int, char *);

/* carp.c */
#define CARP_ADVSKEW 0
#define CARP_ADVBASE 1
#define CARP_VHID 2
#define CARP_PEER 3
#define CARP_BALANCING 4
int conf_carp(FILE *, int, char *);
int carplock(int);

/* trunk.c */
int conf_trunk(FILE *output, int ifs, char *ifname);

/* who.c */
int who(int, char **, ...);

/* arp.c */
struct in_addr;
struct addrinfo;
int numeric_addrinfo(const char *, const char *, int, int,
    struct addrinfo **);
int getinetaddr(const char *, struct in_addr *);
void conf_arp(FILE *, char *, int);
char *sec2str(time_t);
struct sockaddr_dl;
char *ether_str(struct sockaddr_dl *);

/* ndp.c */
struct sockaddr_in6;
int ndpdelete(const struct sockaddr_in6 *);
int parse_host(const char *, struct sockaddr_in6 *);
void ndpflush(void);
void conf_ndp(FILE *output, char *delim, int);

/* nameserver.c */
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
#define CMPLT_WORD	256	/* the longest word completed, with its NUL */
#ifdef _STRINGLIST_H
/* what completing a line's word found: text to insert, or the choices */
struct cmplt {
	char		 insert[1024];	/* at the cursor */
	StringList	*words;		/* or the choices, to list */
	StringList	*helps;		/* and each one's help, or NULL */
	char		*cmdname;	/* a choice with help: "cmdname word" */
	int		 vertical;	/* list the choices in columns anyway */
	int		 help;		/* insert nothing; list every choice */
};
#endif
struct cmplt;
unsigned char complete_line(const char *, size_t, size_t, char *, char **,
    size_t, int, struct cmplt *);
void cmplt_free(struct cmplt *);
extern int cmplt_remote;
void inithist(void);
void endhist(void);
void initedit(void);
void endedit(void);

/* utils.c */
char *format_k(uint64_t amt);

/* client.c */
#define NSHD_CPRIVATE	1	/* configure private, nshd's NSHD_PRIVATE */
#define NSHD_CSHARED	2	/* configure, NSHD_SHARED */
#define NSHD_CEXCLUSIVE	3	/* configure exclusive, NSHD_EXCLUSIVE */
#define NSHD_CTERMINAL	4	/* configure terminal, NSHD_TERMINAL */
extern int nshd_config;
extern int nshd_rtable;
int nshd_show(char *);
void nshd_why(void);
int nshd_runs(const char *);
int nshd_execs(void);
int nshd_connect(int);
int nshd_configure(int);
const char *nshd_cname(void);
int nshd_line(char *);
int nshd_exit(void);
int nshd_commit(int, int, char *);
int nshd_load(const char *);
int nshd_rollback(int);
int nshd_cshow(char *);
int nshd_rules(char *, int, int, char *);
struct facts_in;
int nshd_tables(int, struct facts_in *);
int nshd_show_if(const char *);
int show_log(int, char **, ...);

/* sqlite3.c */
#define SQ3DBFILE "/var/run/nsh.db"
#define DB_X_ENABLE 1		/* enable command */
#define DB_X_DISABLE 2		/* disable command */
#define DB_X_LOCAL 3		/* local control command */
#define DB_X_OTHER 4		/* other command */
#define DB_X_REMOVE 5		/* remove command */
#define DB_X_ENABLE_DEFAULT 6	/* enable command, always prints enable until disabled */
#define DB_X_DISABLE_ALWAYS 7	/* disable command, always prints if disabled */
void db_create(void);
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
int db_select_flag_x_data_ctl_rtable(StringList *, char *, char *, int);
int db_select_nameservers(StringList *);
#endif
int db_select_flag_x_dbflag_rtable(char *, char *, int);

/* pflow.c */
#define PFLOW_SENDER 0
#define PFLOW_RECEIVER 1
#define PFLOW_VERSION 2
#define PFLOW_ADDRSTRLEN (NI_MAXHOST + sizeof("[]:65535"))
#ifdef _SYS_SOCKET_H_
int pflow_addr(const char *, struct sockaddr_storage *);
int pflow_addrstr(struct sockaddr_storage *, char *);
#endif
int pflow_status(int, int, char *, char *);

/* wg.c */
void conf_wg(FILE *, int, char *);

/* umb.c */
void conf_umb(FILE *, int, char *);

/* utf8.c */
#ifdef _WCHAR_H_
int mbs2ws(wchar_t **, size_t *, const char *);
#endif
int mbsavis(char**, int *, const char *);

/* ctlargs.c */
struct prot1;
int pr_prot1(int, char **, ...);
char **step_optreq(char **, char **, int, char **, int);
struct prot1 *prot1_find(char *, char *);
int prot1_place(struct prot1 *, int *);
struct prot1 *prot1_at(int, int);
int prot1_run(char *, char *, int, char **, char **);
char **prot1_args(struct prot1 *, char **, int, char **, int);

/* hashtable.c */
struct hashtable;
struct hashtable *hashtable_alloc(void);
int hashtable_add(struct hashtable *, void *key, size_t keysize,
    void *value, size_t valsize);
int hashtable_remove(struct hashtable *, void **keyptr, void **value,
    size_t *valsize, void *key, size_t keysize);
int hashtable_foreach(struct hashtable *,
    int (*cb)(void *, size_t, void *, size_t, void *),
    void *cb_arg);

/* candidate.c */
#define CAND_NO		0	/* refused in configure private, for now */
#define CAND_RUN	1	/* runs as it does outside configure private */
#define CAND_EDIT	2	/* its handler edits the candidate */
struct cnode;
int cand_begin(struct cand *);
void cand_end(struct cand *);
int cand_changed(struct cand *);
struct cand_state;
void cand_attach(struct cand *, struct cand_state *);
int cand_attached(struct cand *);
void cand_detach(struct cand *);
int cand_conflicts(struct cand *, struct cnode *, int);
int cand_setting(struct cand *, int, const char *, ...)
    __attribute__((__format__ (printf, 3, 4)));
char *cand_line(struct cand *, char *, size_t);
int cand_putlines(struct cand *, char **, size_t, char *);
int cand_ifsetting(struct cand *, char *, int, const char *, ...)
    __attribute__((__format__ (printf, 4, 5)));
char *cand_ifline(struct cand *, char *, char *, size_t);
char *cand_ifname(struct cand *, size_t);
int rtable_there(int, struct cand *);
int pppoe_maxmtu(int, char *, struct cand *);
int cand_state(struct cand *, char *);
int cand_getflags(char *, int);
int cand_gettype(struct cand *, char *);
int cand_ispppoe(char *);
int cand_takes(char *, u_long);
int cand_hasif(struct cand *, char *);
char *cand_listowner(struct cand *, char *, char *, char *);
int cand_interface(struct cand *, int, char *, int *);
int cand_isbridge(struct cand *, char *);
struct cnode *cand_tree(struct cand *);
int pr_cand_conf(int, char **, ...);
int cand_rollback(int, char **, ...);
int cand_restart(struct cand *, struct cnode *, int);
int cand_rtable_set(struct cand *, int, int, char *);
char *cand_rule(struct cand *, char *, size_t);
int cand_setrules(struct cand *, char *, char **, size_t);
int cand_hasrtable(struct cand *, int);
struct cnode *running_tree(void);
void running_set(struct cnode *);
int cand_cloneable(char *);
int cand_write(struct cand *, FILE *);

/* commit.c */
#define MAXCLEARS	64
#define COMMENTMAX	256	/* a commit's comment, with its NUL */
/* Edits that change one configuration into another */
struct script {
	char *text;			/* lines, as conf() prints them */
	size_t len;
	char *edits;			/* edits, run by script_run() */
	size_t elen;
	struct {
		char name[32];
		int rtable;
		int keep;
	} clears[MAXCLEARS];		/* daemon rules to empty or remove */
	int nclears;
};
/*
 * An edit. Each record is this header followed by len bytes: for a
 * line, the values its command's arguments parse to (an argcmd in its
 * row, args.h), as a facts template and record; for a daemon's rules,
 * their lines, each ending in a newline. A script holds the first six
 * kinds (commit.c). A line of nshd's configure, as a session's frontend
 * parsed it for config, holds any but EDIT_RULES (cmdline_edits())
 */
struct edit {
	uint8_t		kind;		/* EDIT_* */
	uint8_t		no;		/* 1 if the line starts with "no" */
	uint8_t		typed;		/* 1 if the bytes are parsed values */
	uint16_t	row;		/* command row, or daemon index */
	int32_t		act;		/* what the daemon does (ctl_act()),
					   or EDIT_ACT's row of its table */
	uint32_t	len;
};
#define EDIT_TOP	1	/* a top-level statement, CTX_TOP's */
#define EDIT_IF		2	/* a line of an interface's block, CTX_IF's */
#define EDIT_BRIDGE	3	/* a line of a bridge's block, CTX_BRIDGE's */
#define EDIT_END	4	/* a block's end */
#define EDIT_RULES	5	/* a daemon's rules */
#define EDIT_DAEMON	6	/* a daemon's state, or what follows its
				   rules */
#define EDIT_LEAVE	7	/* a session's: leave configure */
#define EDIT_ACT	8	/* a session's: a daemon's line, by its row */
struct argcmd;
struct facts_value;
typedef int edit_runfn(const struct argcmd *, int,
	    const struct facts_value *, void *);
int edit_put(FILE *, struct edit *, char *, size_t);
int edit_args(FILE *, struct edit *, const struct argcmd *, int, char **);
int edit_values(const struct argcmd *, const struct edit *, char *,
	    edit_runfn *, void *);
int edits_admin(struct script *);
int commit(int, char **, ...);
int pr_rollback(int, char **, ...);
int rollback_keep(const char *, const char *, const char *);
int saved_write(void);
int saved_diff(int);
char *saved_read(size_t *);
/* how two configurations differ, as the parser says (parserproc.c) */
int parser_diff(char *, size_t, char *, size_t, char *, int);
/* operations, which nshd's system runs */
#define OP_DIFFERS	3	/* an operation's status: what it compared differs */
int saved_text(FILE *);
int saved_first(void);
int commit_problems(struct cnode *, struct cnode *);
int commit_verdict(int, int);
struct plan_test;
int commit_deferred(struct plan_test **);
int commit_refused_by(char *, char *);
int commit_took(struct cnode *, struct cnode *);
void commit_untaken(struct cnode *, struct cnode *, int);
int commit_back(struct cnode *, struct cnode *);
int commit_booted(struct cnode *, struct cnode *);
int commit_reads(char *, size_t, char *, size_t);
int logins_differ(struct cnode *, struct cnode *);
int commit_logins(char *, size_t, char *, size_t);
int commit_verify(char *, size_t, char *, size_t, int, int);
int commit_plan(char *, size_t, char *, size_t, struct script *);
int commit_undone(char *, size_t, char *, size_t);
int commit_diff(char *, size_t, char *, size_t, char *, int, int);
int rollback_text(int, FILE *);
int rollback_texts(int, char **, size_t *, char **, size_t *);
void rollback_list(FILE *);
/* a kept configuration's head lines, as the parser reads them */
#define ROLLBACK_SLOT	512	/* the first bytes of each, which it reads */
struct rollback_head {
	uint64_t gen;			/* its generation, 0 if it has none */
	uint32_t len;			/* the head lines' length */
	int32_t saved;			/* its first line says who saved it */
	char who[64];
	char why[COMMENTMAX];
};
void rollback_slots(char *);
void rollback_heads(char *, struct rollback_head *);
int rollback_heads_kept(struct rollback_head *);
int script_make(struct cnode *, struct cnode *, struct script *, int);
int script_run(struct script *);
void script_free(struct script *);
