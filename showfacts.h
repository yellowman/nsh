/*
 * Copyright (c) 2026 Chris Cappuccio <chris@nmedia.net>
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

/*
 * The shows that answer with facts: the kinds of record each makes,
 * what collects them, in nshd's show processes and its system, and what
 * renders them as nsh's text
 */

#ifndef SHOWFACTS_H
#define SHOWFACTS_H

#include <sys/queue.h>

struct rtdump;
struct rt_msghdr;
struct statgroup;
struct sockaddr;
struct sockaddr_storage;
struct in_addr;
struct sockaddr_in6;

/* a record kept for rendering, bound to the kind nsh knows it as */
struct frec {
	TAILQ_ENTRY(frec)	 entry;
	const struct facts_kind	*k;
	const struct facts_template *t;
	const int		*map;
	struct facts_value	*v;
};
TAILQ_HEAD(frecs, frec);

/* field i of r, of type t, or NULL */
#define FV(r, i, t)	facts_get((r)->v, (r)->map, (i), (t))
uint64_t	 fu(struct frec *, int, uint64_t);
const char	*fs(struct frec *, int);
int		 fsockaddr(struct frec *, int, struct sockaddr_storage *);
int		 fhas(struct frec *, int);

/*
 * Who answers: nshd's show processes, for anyone, or its system, for
 * root and nshadmin. nsh asks either for any words
 */
#define FACTS_SHOW	0x1
#define FACTS_SYSTEM	0x2
extern int	 facts_from;	/* what this process answers */

/* what to answer: a show's words (showwords.h), as nsh and nshd read them */
struct facts_answer *facts_answer(char *);
void		 facts_answer_free(struct facts_answer *);
int		 facts_show(FILE *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));
int		 facts_op(const char *, int, int);

/* each kind of record, shared by what makes it and what renders it */
void		 facts_init(void);
void		 facts_bitnames(struct facts_field *, const char *);
int		 facts_message(struct facts_out *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));
int		 facts_text(struct facts_out *, const char *, size_t);
void		 facts_sockaddr(struct facts_value *, struct sockaddr *);
struct frec	*frec_next(struct frecs *, struct frec *,
		    const struct facts_kind *);

extern struct facts_kind kind_message, kind_route, kind_lookup;
extern struct facts_kind kind_interface, kind_address, kind_media;
extern struct facts_kind kind_carp, kind_wgpeer, kind_umb, kind_umbdns;
extern struct facts_kind kind_trunkport, kind_bridgemember;
extern struct facts_kind kind_bridgeaddr, kind_bridge, kind_arp, kind_ndp;
extern struct facts_kind kind_vlan, kind_version, kind_login, kind_hostname;
extern struct facts_kind kind_ip, kind_dhcplease, kind_dhcproute;
extern struct facts_kind kind_dhcpns, kind_slaacif, kind_slaacra;
extern struct facts_kind kind_slaacprefix, kind_slaacrdns, kind_slaacaddr;
extern struct facts_kind kind_slaacdfr, kind_slaacdns, kind_flow;
extern struct facts_kind kind_daemon;

enum { MSG_TEXT };

enum {
	RT_DST, RT_MASK, RT_GATEWAY, RT_GWTYPE, RT_GWNAME, RT_FLAGS,
	RT_REFS, RT_USE, RT_MTU, RT_LOCKS, RT_PRIORITY, RT_IF, RT_NFIELDS
};

enum {
	LK_QUERY, LK_ERRNO, LK_RTERRNO, LK_DST, LK_MASK, LK_GATEWAY,
	LK_GWTYPE, LK_GWNAME, LK_GENMASK, LK_IFP, LK_IFPTYPE, LK_IFPNAME,
	LK_IFA, LK_BRD, LK_LABEL, LK_FLAGS, LK_ADDRS, LK_MTU, LK_HOPCOUNT,
	LK_EXPIRE, LK_LOCKS, LK_INITS, LK_NFIELDS
};

enum {
	IF_NAME, IF_DESCR, IF_BRIDGE, IF_FLAGS, IF_LASTCHANGE, IF_TYPE,
	IF_LLADDR, IF_LINK, IF_RDOMAIN, IF_MTU, IF_HARDMTU, IF_BAUDRATE,
	IF_IPACKETS, IF_IBYTES, IF_IERRORS, IF_IQDROPS, IF_OPACKETS,
	IF_OBYTES, IF_OERRORS, IF_NOPROTO, IF_COLLISIONS, IF_CAPABILITIES,
	IF_MEDIACOUNT, IF_MEDIASTATUS, IF_TUNSRC, IF_TUNDST, IF_TUNPORT,
	IF_TUNRDOMAIN, IF_TUNTTL, IF_VNETID, IF_PARENT, IF_SSID, IF_POWERSAVE,
	IF_CARPBALANCING, IF_CARPPEER, IF_CARPDEV, IF_CARPADVBASE,
	IF_WGPUBLIC, IF_TRUNKPARENT, IF_TRUNKFLAGS, IF_TRUNKPROTO,
	IF_NFIELDS
};

enum { ADDR_ADDRESS, ADDR_MASK, ADDR_DST, ADDR_BRD, ADDR_IF, ADDR_NFIELDS };

enum { MEDIA_ROLE, MEDIA_WORD, MEDIA_TYPE, MEDIA_SUBTYPE, MEDIA_INSTANCE,
	MEDIA_OPTIONS, MEDIA_IF, MEDIA_NFIELDS };
#define MEDIA_CURRENT	0
#define MEDIA_ACTIVE	1
#define MEDIA_SUPPORTED	2

enum { CARPV_VHID, CARPV_STATE, CARPV_ADVSKEW, CARPV_IF, CARPV_NFIELDS };

enum { WGP_PUBLIC, WGP_DESCR, WGP_HANDSHAKE, WGP_IF, WGP_NFIELDS };

enum {
	UMB_ERROR, UMB_ROAMING, UMB_REGSTATE, UMB_ROAMINGTEXT, UMB_CLASSES,
	UMB_STATE, UMB_CELLCLASS, UMB_HIGHESTCLASS, UMB_RSSI, UMB_UPLINK,
	UMB_DOWNLINK, UMB_SIMSTATE, UMB_PINSTATE, UMB_PINLEFT, UMB_SID,
	UMB_ICCID, UMB_PROVIDER, UMB_PROVIDERID, UMB_HWINFO, UMB_DEVID,
	UMB_FWINFO, UMB_PHONE, UMB_APN, UMB_IF, UMB_NFIELDS
};

enum { UMBDNS_ADDRESS, UMBDNS_IF, UMBDNS_NFIELDS };

enum { TPORT_NAME, TPORT_FLAGS, TPORT_IF, TPORT_NFIELDS };

enum { BRM_NAME, BRM_FLAGS, BRM_STATE, BRM_IF, BRM_NFIELDS };

enum { BRA_ADDRESS, BRA_MEMBER, BRA_AGE, BRA_FLAGS, BRA_IF, BRA_NFIELDS };

enum { BR_NAME, BR_FLAGS, BR_DESCR, BR_NFIELDS };

enum { IP_ADDRESS, IP_MASK, IP_IF, IP_RDOMAIN, IP_FLAGS6, IP_SOURCE,
	IP_NFIELDS };
/* what configured an IPv4 address */
#define NSH_IP_FLAG_DHCP	0x01
#define NSH_IP_FLAG_IPCP	0x02
#define NSH_IP_FLAG_STATIC	0x04

enum { DHCP_IF, DHCP_STATE, DHCP_ADDRESS, DHCP_MASK, DHCP_REQUESTED,
	DHCP_LEASE, DHCP_SERVER, DHCP_NFIELDS };
enum { DHCPR_DEST, DHCPR_MASK, DHCPR_GW, DHCPR_IF, DHCPR_NFIELDS };
enum { DHCPNS_ADDRESS, DHCPNS_IF, DHCPNS_NFIELDS };

enum { SLAAC_IF, SLAAC_INDEX, SLAAC_RUNNING, SLAAC_TEMPORARY, SLAAC_LLADDR,
	SLAAC_INET6, SLAAC_NFIELDS };
enum { SRA_ROUTER, SRA_WHEN, SRA_SEEN, SRA_HOPLIMIT, SRA_MANAGED,
	SRA_OTHER, SRA_LIFETIME, SRA_PREF, SRA_REACHABLE, SRA_RETRANS,
	SRA_MTU, SRA_IF, SRA_NFIELDS };
enum { SPFX_PREFIX, SPFX_LEN, SPFX_ONLINK, SPFX_AUTONOMOUS, SPFX_VLTIME,
	SPFX_PLTIME, SPFX_ROUTER, SPFX_IF, SPFX_NFIELDS };
enum { SRDNS_ADDRESS, SRDNS_LIFETIME, SRDNS_ROUTER, SRDNS_IF,
	SRDNS_NFIELDS };
/* slaacd's proposals: what each has, then what its kind has */
enum { SP_ID, SP_STATE, SP_TIMEOUT, SP_WHEN, SP_SEEN, SP_IF, SP_NFIELDS };
enum { SADDR_ADDRESS = SP_NFIELDS, SADDR_PREFIX, SADDR_LEN,
	SADDR_TEMPORARY, SADDR_VLTIME, SADDR_PLTIME, SADDR_NFIELDS };
enum { SDFR_ROUTER = SP_NFIELDS, SDFR_LIFETIME, SDFR_PREF, SDFR_NFIELDS };
#define SLAAC_RDNS	8	/* name servers a proposal has, at most */
enum { SDNS_ROUTER = SP_NFIELDS, SDNS_LIFETIME, SDNS_SERVER,
	SDNS_NFIELDS = SDNS_SERVER + SLAAC_RDNS };

enum { ARP_ADDRESS, ARP_LLADDR, ARP_IF, ARP_FLAGS, ARP_PROXY, ARP_EXPIRE,
	ARP_NFIELDS };

enum { NDP_ADDRESS, NDP_LLADDR, NDP_IF, NDP_FLAGS, NDP_EXPIRE, NDP_STATE,
	NDP_ROUTER, NDP_PROBES, NDP_ERRNO, NDP_NFIELDS };

enum { VLAN_NAME, VLAN_VNETID, VLAN_FLAGS, VLAN_RDOMAIN, VLAN_PARENT,
	VLAN_BRIDGE, VLAN_DESCR, VLAN_NFIELDS };

enum {
	VER_NSH, VER_COMPILED, VER_COMPILEDBY, VER_COMPILEHOST, VER_BOOTTIME,
	VER_SYSNAME, VER_MACHINE, VER_RELEASE, VER_CPU, VER_MEMORY,
	VER_KERNEL, VER_NFIELDS
};

enum { LOGIN_USER, LOGIN_LINE, LOGIN_TIME, LOGIN_HOST, LOGIN_NFIELDS };
enum { DAEMON_NAME, DAEMON_PROGRAM, DAEMON_RTABLE, DAEMON_RUNNING,
    DAEMON_PROCS, DAEMON_NFIELDS };

enum { FLOW_SRC, FLOW_SRCMASK, FLOW_SRCPORT, FLOW_DST, FLOW_DSTMASK,
	FLOW_DSTPORT, FLOW_PROTO, FLOW_PEER, FLOW_SATYPE, FLOW_TYPE,
	FLOW_DIRECTION, FLOW_NFIELDS };

enum { HOST_NAME };

/* collectors and renderers, in the files of what they show */
void	 route_facts_init(void);
void	 lookup_facts_init(void);
void	 carp_balnames(struct facts_field *);
void	 trunk_names(struct facts_field *, struct facts_field *);
void	 if_facts_init(void);
void	 media_facts_init(void);
void	 carp_facts_init(void);
void	 umb_facts_init(void);
void	 trunk_facts_init(void);
void	 bridge_facts_init(void);
void	 if_typenames(struct facts_field *);
int	 sdl_build(struct frec *, int, int, int, struct sockaddr_storage *);
void	 facts_sdl(struct facts_value *, struct facts_value *, char *, size_t,
	    struct sockaddr *);
int	 nshd_facts(int, char *, struct facts_in *);
int	 nshd_op(const char *, int, struct facts_in *);
int	 route_facts(struct facts_out *, struct rtdump *, char **, int, int);
void	 route_render(struct frec *, int *);
int	 lookup_facts(struct facts_out *, char *, int);
void	 lookup_render(struct frec *);
void	 print_rtmsg(struct rt_msghdr *);
void	 pmsg_common(struct rt_msghdr *);
void	 pmsg_addrs(char *, int);
void	 print_addrs(char *, int);
int	 if_facts(struct facts_out *, char *, int);
void	 if_render(struct frecs *, FILE *);
void	 if_render_status(struct frecs *, FILE *);
void	 media_facts(struct facts_out *, int, char *, struct facts_value *,
	    int);
void	 media_render(struct frecs *, struct frec *, FILE *);
void	 media_render_supported(struct frecs *, struct frec *, FILE *);
const char *media_linkstate(struct frecs *, struct frec *);
void	 media_status_words(struct frecs *, uint64_t *, uint64_t *);
void	 carp_facts(struct facts_out *, int, char *, struct facts_value *);
void	 carp_render(struct frecs *, struct frec *, FILE *);
void	 wg_facts(struct facts_out *, int, char *, struct facts_value *);
void	 wg_render(struct frecs *, struct frec *, FILE *);
void	 umb_facts(struct facts_out *, int, char *);
void	 umb_render(struct frecs *, FILE *);
void	 trunk_facts(struct facts_out *, int, char *, struct facts_value *);
void	 trunk_render(struct frecs *, struct frec *, FILE *);
void	 bridge_facts(struct facts_out *, int, char *);
void	 bridge_render(struct frecs *, FILE *);
int	 bridge_show_facts(struct facts_out *, char *);
void	 bridge_show_render(struct frecs *, struct frec *, int);
void	 arp_facts_init(void);
int	 arp_facts(struct facts_out *, struct rtdump *, char **,
	    struct in_addr *, int);
void	 arp_header(void);
void	 arp_render(struct frec *);
void	 arp_noentry(const char *);
void	 ndp_facts_init(void);
int	 ndp_facts(struct facts_out *, struct rtdump *, char **,
	    struct sockaddr_in6 *, int);
void	 ndp_header(void);
void	 ndp_render(struct frec *, char *, size_t);
void	 ndp_end(const char *, const char *);
int	 vlan_facts(struct facts_out *, int, int);
void	 vlan_render(struct frec *, int);
void	 vlan_none(int, int);
void	 stats_facts_init(void);
struct statgroup *stats_group(const char *);
int	 stats_where(struct statgroup *);
const struct facts_kind *stats_kind(const char *);
int	 stats_facts(struct facts_out *, struct statgroup *);
void	 stats_render(struct frec *);
int	 version_facts(struct facts_out *);
void	 version_render(struct frec *);
extern int utmpfd;
int	 users_facts(struct facts_out *);
void	 users_render(struct frec *, int);
void	 users_end(int);
int	 daemons_facts(struct facts_out *, int);
void	 daemons_render(struct frec *, int);
int	 hostname_facts(struct facts_out *);
void	 hostname_render(struct frec *);
int	 ip_facts(struct facts_out *, int, int);
int	 dhcpleased_has_lease(char *, struct in_addr *, struct in_addr *);
void	 ip_render(struct frecs *);
int	 autoconf_facts(struct facts_out *, char *);
void	 autoconf_render(struct frecs *, struct frec *);
struct rtdump *sadb_dump(void);
int	 sadb_facts(struct facts_out *, struct rtdump *, char **, int);
void	 sadb_render(struct frec *, int *);

#endif /* SHOWFACTS_H */
