#include <sys/param.h>
#include <kvm.h>
#include <nlist.h>

char		hbuf[MAXHOSTNAMELEN];

extern int cmdrc	(char rcname[FILENAME_MAX]);
extern void routepr(u_long);
extern void rt_stats(u_long);
extern void tcp_stats (u_long);
extern void udp_stats (u_long);
extern void ip_stats (u_long);
extern void icmp_stats (u_long);
extern void igmp_stats (u_long);
extern void ah_stats (u_long);
extern void esp_stats (u_long);
extern void ipip_stats (u_long);
extern void ipcomp_stats (u_long);

