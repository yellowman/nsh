/*
 * nsh externs
 */

extern char *__progname, *vers;
extern int verbose, editing;

/* conf.c */
int conf(FILE *);
int default_mtu(const char *);

/* routepr.c */
void routepr(u_long, int);

/* alignment constraint for routing socket */
#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

/* routesys.c */
int monitor(void);
void flushroutes(int);
void bprintf(FILE *, int, u_char *);
extern char ifnetflags[];
extern char routeflags[];
extern char addrnames[];
extern char metricnames[];

/* commands.c */
void command(int);
int cmdrc(char rcname[FILENAME_MAX]);
int load_nlist(void);
char *iprompt(void);
char *cprompt(void);

/* ieee80211.c */
#define NWID 0
#define NWKEY 1
const char *get_string(const char *, const char *, u_int8_t *, int *);
int get_nwinfo(const char *, char *, int, int);
void make_string(char *str, int, const u_int8_t *buf, int);
int intnwkey(const char *, int, char **);

/* stats.c */
void rt_stats(u_long);
void tcp_stats(u_long);
void udp_stats(u_long);
void ip_stats(u_long);
void icmp_stats(u_long);
void igmp_stats(u_long);
void ah_stats(u_long);
void esp_stats(u_long);
void ipip_stats(u_long);
void ipcomp_stats(u_long);

/* mbuf.c */
void mbpr(u_long, u_long, u_long);

/* kread.c */
int kread(u_long, char *, int);
char *plural(int);
char *plurales(int);

/* genget.c */
int isprefix(char *, char*);
char **genget(char *, char **, int);
int Ambiguous(void *);

/* rate.c */
#define TBR_RATE 1		/* request for TBR token rate */
#define TBR_BUCKET 2		/* request for TBR bucket size */
int intrate(char *ifname, int, char**);
u_int size_bucket(const char *, const u_int);
u_int autosize_bucket(const char *, const u_int);
u_long get_tbr(const char *, int);
u_long atobps(const char *);
u_long atobytes(const char *);

/* route.c */
int route(int, char**);

/* if.c */
#define IFDATA_MTU 1		/* request for if_data.ifi_mtu */
#define IFDATA_BAUDRATE 2	/* request for if_data.ifi_baudrate */
#define MBPS(bps) (bps / 1000 / 1000)
#define ROUNDMBPS(bps) ((float)bps == ((bps / 1000 / 1000) * 1000 * 1000))
#define ROUNDKBPS(bps) ((float)bps == ((bps / 1000) * 1000))
#define ROUNDKBYTES(bytes) ((float)bytes == ((bytes / 1024) * 1024))
int is_valid_ifname(const char *);
int show_int(const char *);
int get_ifdata(const char *, int);
int get_ifflags(const char *);
int set_ifflags(const char *, int);
int intip(const char *, int, char **);
int intmtu(const char *, int, char **);
int intmetric(const char *, int, char **);
int intflags(const char *, int, char **);
int intlink(const char *, int, char **);
int intnwid(const char *, int, char **);
int intpowersave(const char *, int, char **);

/* version.c */
int version(void);

/* compile.c */
extern char compiled[], compiledby[], compiledon[];

/* editing.c */
void inithist(void);
void endhist(void);
void initedit(void);
void endedit(void);
