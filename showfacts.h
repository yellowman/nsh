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
 * what collects them, where nshd's show processes run, or nsh where
 * nshd does not, and what renders them as nsh's text
 */

#ifndef SHOWFACTS_H
#define SHOWFACTS_H

#include <sys/queue.h>

struct rtdump;

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

/* what to answer: words, a request from a client, as nshd takes them */
struct facts_answer *facts_answer(char *);
int		 facts_more(struct facts_answer *, struct facts_out *, int);
void		 facts_answer_free(struct facts_answer *);
int		 facts_show(FILE *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));

/* each kind, for the record it is and the renderer that knows it */
void		 facts_init(void);
void		 facts_bitnames(struct facts_field *, const char *);
int		 facts_message(struct facts_out *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));
void		 facts_sockaddr(struct facts_value *, struct sockaddr *);
struct frec	*frec_next(struct frecs *, struct frec *,
		    const struct facts_kind *);

extern struct facts_kind kind_message, kind_route, kind_lookup;
extern struct facts_kind kind_interface, kind_address, kind_media;
extern struct facts_kind kind_carp, kind_wgpeer, kind_umb, kind_umbdns;
extern struct facts_kind kind_trunkport, kind_bridgemember;
extern struct facts_kind kind_bridgeaddr;

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

enum { ADDR_ADDRESS, ADDR_MASK, ADDR_DST, ADDR_BRD, ADDR_NFIELDS };

enum { MEDIA_ROLE, MEDIA_WORD, MEDIA_TYPE, MEDIA_SUBTYPE, MEDIA_INSTANCE,
	MEDIA_OPTIONS, MEDIA_NFIELDS };
#define MEDIA_CURRENT	0
#define MEDIA_ACTIVE	1
#define MEDIA_SUPPORTED	2

enum { CARPV_VHID, CARPV_STATE, CARPV_ADVSKEW, CARPV_NFIELDS };

enum { WGP_PUBLIC, WGP_DESCR, WGP_HANDSHAKE, WGP_NFIELDS };

enum {
	UMB_ERROR, UMB_ROAMING, UMB_REGSTATE, UMB_ROAMINGTEXT, UMB_CLASSES,
	UMB_STATE, UMB_CELLCLASS, UMB_HIGHESTCLASS, UMB_RSSI, UMB_UPLINK,
	UMB_DOWNLINK, UMB_SIMSTATE, UMB_PINSTATE, UMB_PINLEFT, UMB_SID,
	UMB_ICCID, UMB_PROVIDER, UMB_PROVIDERID, UMB_HWINFO, UMB_DEVID,
	UMB_FWINFO, UMB_PHONE, UMB_APN, UMB_NFIELDS
};

enum { UMBDNS_ADDRESS, UMBDNS_NFIELDS };

enum { TPORT_NAME, TPORT_FLAGS, TPORT_NFIELDS };

enum { BRM_NAME, BRM_FLAGS, BRM_STATE, BRM_NFIELDS };

enum { BRA_ADDRESS, BRA_MEMBER, BRA_AGE, BRA_FLAGS, BRA_NFIELDS };

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
int	 nshd_facts(char *, struct facts_in *);
int	 route_facts(struct facts_out *, struct rtdump *, char **, int, int);
void	 route_render(struct frec *, int *);
int	 lookup_facts(struct facts_out *, char *, int);
void	 lookup_render(struct frec *);
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

#endif /* SHOWFACTS_H */
