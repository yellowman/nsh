/*
 * nsh externs
 */

extern char *__progname, *vers;
extern int verbose;

/* routepr.c */
extern void routepr(u_long, int);

/* alignment constraint for routing socket */
#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

/* routesys.c */
extern int monitor(void);
extern void flushroutes(int);
extern void bprintf(FILE *, int, u_char *);
extern char ifnetflags[];
extern char routeflags[];
extern char addrnames[];
extern char metricnames[];

/* commands.c */
extern void command(int, char *, int);
extern int cmdrc(char rcname[FILENAME_MAX]);
extern int load_nlist(void);

/* stats.c */
extern void rt_stats(u_long);
extern void tcp_stats(u_long);
extern void udp_stats(u_long);
extern void ip_stats(u_long);
extern void icmp_stats(u_long);
extern void igmp_stats(u_long);
extern void ah_stats(u_long);
extern void esp_stats(u_long);
extern void ipip_stats(u_long);
extern void ipcomp_stats(u_long);

/* mbuf.c */
extern void mbpr(u_long, u_long, u_long);

/* kread.c */
extern int kread(u_long, char *, int);
extern char *plural(int);
extern char *plurales(int);

/* genget.c */
extern int isprefix(char *, char*);
extern char **genget(char *, char **, int);
extern int Ambiguous(void *);

/* rate.c */
#define TBR_RATE 1		/* request for TBR token rate */
#define TBR_BUCKET 2		/* request for TBR bucket size */
extern int intrate(char *ifname, int, char**);
extern u_long get_tbr(const char *, int);
extern u_long atobps(const char *);
extern u_long atobytes(const char *);

/* route.c */
extern int route(int, char**);

/* if.c */
#define IFDATA_MTU 1		/* request for if_data.ifi_mtu */
#define IFDATA_BAUDRATE 2	/* request for if_data.ifi_baudrate */
#define MBPS(bps) (bps / 1000 / 1000)
extern int show_int(const char *);
extern int get_ifdata(const char *, int);

/* version.c */
extern int version(void);

/* compile.c */
extern char compiled[], compiledby[];

