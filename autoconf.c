/*
 * Copyright (c) 2026 Chris Cappuccio <chris@nmedia.net>
 * Copyright (c) 2017, 2021 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
 * Ask dhcpleased(8) and slaacd(8), on their control sockets, which only
 * root may use, what they know about each interface they configure, and
 * report it as facts. Render the facts as dhcpleasectl(8) and
 * slaacctl(8) print them. The control messages are theirs, from
 * dhcpleased.h and slaacd.h.
 *
 * The daemons give times on a monotonic clock. Each is sent as the time
 * of day it was ("seen" is when the daemon answered), and a duration
 * after it as seconds.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/un.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>

#include <errno.h>
#include <imsg.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "externs.h"
#include "facts.h"
#include "showfacts.h"

#define CTL_WAIT	5000	/* ms a daemon has to answer */

/* from dhcpleased.h */
#define DL_SHOW_INTERFACE_INFO	2
#define DL_END			5
#define DL_ROUTES		256
#define DL_NAMESERVERS		8

struct dl_route {
	struct in_addr		 dst;
	struct in_addr		 mask;
	struct in_addr		 gw;
};

struct dl_info {
	uint32_t		if_index;
	int			running;
	int			link_state;
	char			state[sizeof("IF_INIT_REBOOT")];
	struct timespec		request_time;
	struct in_addr		server_identifier;
	struct in_addr		dhcp_server; /* for unicast */
	struct in_addr		requested_ip;
	struct in_addr		mask;
	struct dl_route		routes[DL_ROUTES];
	uint32_t		routes_len;
	struct in_addr		nameservers[DL_NAMESERVERS];
	uint32_t		lease_time;
	uint32_t		renewal_time;
	uint32_t		rebinding_time;
};

/* from slaacd.h */
#define SL_SHOW_INTERFACE_INFO	2
#define SL_RA			3
#define SL_RA_PREFIX		4
#define SL_RA_RDNS		5
#define SL_ADDR_PROPOSAL	7
#define SL_DFR_PROPOSAL		9
#define SL_RDNS_PROPOSAL	11
#define SL_END			12
#define SL_RDNS			SLAAC_RDNS

struct sl_info {
	uint32_t		if_index;
	int			running;
	int			autoconf;
	int			temporary;
	int			soii;
	struct ether_addr	hw_address;
	struct sockaddr_in6	ll_address;
};

struct sl_ra {
	struct sockaddr_in6	 from;
	struct timespec		 when;
	struct timespec		 uptime;
	uint8_t			 curhoplimit;
	int			 managed;
	int			 other;
	char			 rpref[sizeof("MEDIUM")];
	uint16_t		 router_lifetime;	/* in seconds */
	uint32_t		 reachable_time;	/* in milliseconds */
	uint32_t		 retrans_time;		/* in milliseconds */
	uint32_t		 mtu;
};

struct sl_ra_prefix {
	struct in6_addr		prefix;
	uint8_t			prefix_len;
	int			onlink;
	int			autonomous;
	uint32_t		vltime;
	uint32_t		pltime;
};

struct sl_ra_rdns {
	uint32_t		lifetime;
	struct in6_addr		rdns;
};

struct sl_addr_proposal {
	int64_t			 id;
	char			 state[sizeof("PROPOSAL_NEARLY_EXPIRED")];
	time_t			 next_timeout;
	struct timespec		 when;
	struct timespec		 uptime;
	struct sockaddr_in6	 addr;
	struct in6_addr		 prefix;
	int			 temporary;
	uint8_t			 prefix_len;
	uint32_t		 vltime;
	uint32_t		 pltime;
};

struct sl_dfr_proposal {
	int64_t			 id;
	char			 state[sizeof("PROPOSAL_NEARLY_EXPIRED")];
	time_t			 next_timeout;
	struct timespec		 when;
	struct timespec		 uptime;
	struct sockaddr_in6	 addr;
	uint32_t		 router_lifetime;
	char			 rpref[sizeof("MEDIUM")];
};

struct sl_rdns_proposal {
	int64_t			 id;
	char			 state[sizeof("PROPOSAL_NEARLY_EXPIRED")];
	time_t			 next_timeout;
	struct timespec		 when;
	struct timespec		 uptime;
	struct sockaddr_in6	 from;
	uint32_t		 rdns_lifetime;
	int			 rdns_count;
	struct in6_addr		 rdns[SL_RDNS];
};

/* a lease, after its routes and name servers */
static struct facts_field dhcp_fields[] = {
	[DHCP_IF] =		{ "interface",		FACT_STRING },
	[DHCP_STATE] =		{ "state",		FACT_STRING },
	[DHCP_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[DHCP_MASK] =		{ "netmask",		FACT_ADDRESS },
	[DHCP_REQUESTED] =	{ "requested",		FACT_TIME },
	[DHCP_LEASE] =		{ "lease-time",		FACT_U64 },
	[DHCP_SERVER] =		{ "server",		FACT_ADDRESS },
};
struct facts_kind kind_dhcplease = { "dhcp-lease", dhcp_fields,
    DHCP_NFIELDS };

static struct facts_field dhcproute_fields[] = {
	[DHCPR_DEST] =		{ "destination",	FACT_ADDRESS },
	[DHCPR_MASK] =		{ "netmask",		FACT_ADDRESS },
	[DHCPR_GW] =		{ "gateway",		FACT_ADDRESS },
	[DHCPR_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_dhcproute = { "dhcp-route", dhcproute_fields,
    DHCPR_NFIELDS };

static struct facts_field dhcpns_fields[] = {
	[DHCPNS_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[DHCPNS_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_dhcpns = { "dhcp-name-server", dhcpns_fields,
    DHCPNS_NFIELDS };

/* an interface slaacd knows, after its other records */
static struct facts_field slaac_fields[] = {
	[SLAAC_IF] =		{ "interface",		FACT_STRING },
	[SLAAC_INDEX] =		{ "index",		FACT_U64 },
	[SLAAC_RUNNING] =	{ "running",		FACT_U64 },
	[SLAAC_TEMPORARY] =	{ "temporary",		FACT_U64 },
	[SLAAC_LLADDR] =	{ "link-address",	FACT_ADDRESS },
	[SLAAC_INET6] =		{ "link-local",		FACT_ADDRESS },
};
struct facts_kind kind_slaacif = { "slaac-interface", slaac_fields,
    SLAAC_NFIELDS };

static struct facts_field slaacra_fields[] = {
	[SRA_ROUTER] =		{ "router",		FACT_ADDRESS },
	[SRA_WHEN] =		{ "when",		FACT_TIME },
	[SRA_SEEN] =		{ "seen",		FACT_TIME },
	[SRA_HOPLIMIT] =	{ "hop-limit",		FACT_U64 },
	[SRA_MANAGED] =		{ "managed",		FACT_U64 },
	[SRA_OTHER] =		{ "other",		FACT_U64 },
	[SRA_LIFETIME] =	{ "router-lifetime",	FACT_U64 },
	[SRA_PREF] =		{ "preference",		FACT_STRING },
	[SRA_REACHABLE] =	{ "reachable-time",	FACT_U64 },
	[SRA_RETRANS] =		{ "retransmit-time",	FACT_U64 },
	[SRA_MTU] =		{ "mtu",		FACT_U64 },
	[SRA_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_slaacra = { "slaac-router-advertisement",
    slaacra_fields, SRA_NFIELDS };

static struct facts_field slaacprefix_fields[] = {
	[SPFX_PREFIX] =		{ "prefix",		FACT_ADDRESS },
	[SPFX_LEN] =		{ "prefix-length",	FACT_U64 },
	[SPFX_ONLINK] =		{ "on-link",		FACT_U64 },
	[SPFX_AUTONOMOUS] =	{ "autonomous",		FACT_U64 },
	[SPFX_VLTIME] =		{ "valid-lifetime",	FACT_U64 },
	[SPFX_PLTIME] =		{ "preferred-lifetime",	FACT_U64 },
	[SPFX_ROUTER] =		{ "router",		FACT_ADDRESS },
	[SPFX_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_slaacprefix = { "slaac-prefix", slaacprefix_fields,
    SPFX_NFIELDS };

static struct facts_field slaacrdns_fields[] = {
	[SRDNS_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[SRDNS_LIFETIME] =	{ "lifetime",		FACT_U64 },
	[SRDNS_ROUTER] =	{ "router",		FACT_ADDRESS },
	[SRDNS_IF] =		{ "interface",		FACT_STRING },
};
struct facts_kind kind_slaacrdns = { "slaac-name-server", slaacrdns_fields,
    SRDNS_NFIELDS };

#define PROPOSAL_FIELDS \
	[SP_ID] =		{ "id",			FACT_I64 }, \
	[SP_STATE] =		{ "state",		FACT_STRING }, \
	[SP_TIMEOUT] =		{ "timeout",		FACT_I64 }, \
	[SP_WHEN] =		{ "when",		FACT_TIME }, \
	[SP_SEEN] =		{ "seen",		FACT_TIME }, \
	[SP_IF] =		{ "interface",		FACT_STRING }

static struct facts_field slaacaddr_fields[] = {
	PROPOSAL_FIELDS,
	[SADDR_ADDRESS] =	{ "address",		FACT_ADDRESS },
	[SADDR_PREFIX] =	{ "prefix",		FACT_ADDRESS },
	[SADDR_LEN] =		{ "prefix-length",	FACT_U64 },
	[SADDR_TEMPORARY] =	{ "temporary",		FACT_U64 },
	[SADDR_VLTIME] =	{ "valid-lifetime",	FACT_U64 },
	[SADDR_PLTIME] =	{ "preferred-lifetime",	FACT_U64 },
};
struct facts_kind kind_slaacaddr = { "slaac-address-proposal",
    slaacaddr_fields, SADDR_NFIELDS };

static struct facts_field slaacdfr_fields[] = {
	PROPOSAL_FIELDS,
	[SDFR_ROUTER] =		{ "router",		FACT_ADDRESS },
	[SDFR_LIFETIME] =	{ "router-lifetime",	FACT_U64 },
	[SDFR_PREF] =		{ "preference",		FACT_STRING },
};
struct facts_kind kind_slaacdfr = { "slaac-router-proposal",
    slaacdfr_fields, SDFR_NFIELDS };

static struct facts_field slaacdns_fields[] = {
	PROPOSAL_FIELDS,
	[SDNS_ROUTER] =		{ "router",		FACT_ADDRESS },
	[SDNS_LIFETIME] =	{ "lifetime",		FACT_U64 },
	[SDNS_SERVER] =		{ "name-server[0]",	FACT_ADDRESS },
	[SDNS_SERVER + 1] =	{ "name-server[1]",	FACT_ADDRESS },
	[SDNS_SERVER + 2] =	{ "name-server[2]",	FACT_ADDRESS },
	[SDNS_SERVER + 3] =	{ "name-server[3]",	FACT_ADDRESS },
	[SDNS_SERVER + 4] =	{ "name-server[4]",	FACT_ADDRESS },
	[SDNS_SERVER + 5] =	{ "name-server[5]",	FACT_ADDRESS },
	[SDNS_SERVER + 6] =	{ "name-server[6]",	FACT_ADDRESS },
	[SDNS_SERVER + 7] =	{ "name-server[7]",	FACT_ADDRESS },
};
struct facts_kind kind_slaacdns = { "slaac-name-server-proposal",
    slaacdns_fields, SDNS_NFIELDS };

/* a connection to the control socket at path; -1 if there is none */
static int
ctl_open(const char *path, struct imsgbuf *ib)
{
	struct sockaddr_un	 sun;
	int			 fd;

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
		return (-1);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1 ||
	    imsgbuf_init(ib, fd) == -1) {
		close(fd);
		return (-1);
	}
	return (fd);
}

static void
ctl_close(int *fd, struct imsgbuf *ib)
{
	if (*fd < 0)
		return;
	imsgbuf_clear(ib);
	close(*fd);
	*fd = -1;
}

/* ask about if_index; -1 if the daemon is gone */
static int
ctl_ask(struct imsgbuf *ib, uint32_t type, uint32_t if_index)
{
	if (imsg_compose(ib, type, 0, 0, -1, &if_index,
	    sizeof(if_index)) == -1 || imsgbuf_flush(ib) == -1)
		return (-1);
	return (0);
}

/* the next message; -1 if none came in time or it cannot be read */
static int
ctl_next(int fd, struct imsgbuf *ib, struct imsg *imsg, const char *who)
{
	struct pollfd	 pfd;
	ssize_t		 n;

	for (;;) {
		if ((n = imsgbuf_get(ib, imsg)) == 1)
			return (0);
		if (n == -1) {
			printf("%% %s: an answer nsh cannot read\n", who);
			return (-1);
		}
		pfd.fd = fd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, CTL_WAIT) != 1 || imsgbuf_read(ib) != 1) {
			printf("%% %s did not answer\n", who);
			return (-1);
		}
	}
}

/* the time of day it was at t, a time of the monotonic clock */
static void
facts_monotonic(struct facts_value *v, const struct timespec *t)
{
	struct timespec	 mono, now, ago;

	clock_gettime(CLOCK_MONOTONIC, &mono);
	clock_gettime(CLOCK_REALTIME, &now);
	timespecsub(&mono, t, &ago);
	timespecsub(&now, &ago, &now);
	facts_time(v, now.tv_sec, now.tv_nsec);
}

/* dhcpleased's answer for if_index; 1 if it has none, -1 if it failed */
static int
dhcp_info(int fd, struct imsgbuf *ib, uint32_t if_index,
    struct dl_info *dl)
{
	struct imsg	 imsg;
	int		 r = -1;

	if (ctl_ask(ib, DL_SHOW_INTERFACE_INFO, if_index) == -1 ||
	    ctl_next(fd, ib, &imsg, "dhcpleased") == -1)
		return (-1);
	switch (imsg_get_type(&imsg)) {
	case DL_SHOW_INTERFACE_INFO:
		if (imsg_get_data(&imsg, dl, sizeof(*dl)) == 0)
			r = 0;
		else
			printf("%% dhcpleased: an answer nsh cannot read\n");
		break;
	case DL_END:
		r = 1;
		break;
	default:
		printf("%% dhcpleased: an answer nsh cannot read\n");
	}
	imsg_free(&imsg);
	return (r);
}

/* whether dhcpleased leased addr, with mask, to ifname */
int
dhcpleased_has_lease(char *ifname, struct in_addr *addr,
    struct in_addr *mask)
{
	struct imsgbuf	 ib;
	struct dl_info	 dl;
	uint32_t	 if_index;
	int		 fd, r = 0;

	if ((if_index = if_nametoindex(ifname)) == 0 ||
	    (fd = ctl_open(DHCPLEASED_SOCK, &ib)) == -1)
		return (0);
	if (dhcp_info(fd, &ib, if_index, &dl) == 0 &&
	    dl.requested_ip.s_addr != INADDR_ANY &&
	    dl.requested_ip.s_addr == addr->s_addr &&
	    dl.mask.s_addr == mask->s_addr)
		r = 1;
	ctl_close(&fd, &ib);
	return (r);
}

/* ifname's lease, its routes and name servers first; -1 if they failed */
static int
dhcp_facts(struct facts_out *o, int *fd, struct imsgbuf *ib, char *ifname,
    uint32_t if_index)
{
	struct facts_value	 v[DHCP_NFIELDS], rv[DHCPR_NFIELDS];
	struct facts_value	 nv[DHCPNS_NFIELDS];
	struct dl_info		 dl;
	uint32_t		 i;
	int			 r;

	if ((r = dhcp_info(*fd, ib, if_index, &dl)) == -1)
		ctl_close(fd, ib);
	if (r != 0)
		return (0);

	for (i = 0; i < dl.routes_len && i < DL_ROUTES; i++) {
		memset(rv, 0, sizeof(rv));
		facts_address(&rv[DHCPR_DEST], FACT_INET, &dl.routes[i].dst,
		    4, 0);
		facts_address(&rv[DHCPR_MASK], FACT_INET, &dl.routes[i].mask,
		    4, 0);
		facts_address(&rv[DHCPR_GW], FACT_INET, &dl.routes[i].gw, 4,
		    0);
		facts_string(&rv[DHCPR_IF], ifname);
		if (facts_record(o, &kind_dhcproute, rv) == -1)
			return (-1);
	}
	for (i = 0; i < DL_NAMESERVERS &&
	    dl.nameservers[i].s_addr != INADDR_ANY; i++) {
		memset(nv, 0, sizeof(nv));
		facts_address(&nv[DHCPNS_ADDRESS], FACT_INET,
		    &dl.nameservers[i], 4, 0);
		facts_string(&nv[DHCPNS_IF], ifname);
		if (facts_record(o, &kind_dhcpns, nv) == -1)
			return (-1);
	}

	memset(v, 0, sizeof(v));
	facts_string(&v[DHCP_IF], ifname);
	dl.state[sizeof(dl.state) - 1] = '\0';
	facts_string(&v[DHCP_STATE], dl.state);
	if (dl.requested_ip.s_addr != INADDR_ANY) {
		facts_address(&v[DHCP_ADDRESS], FACT_INET, &dl.requested_ip,
		    4, 0);
		facts_address(&v[DHCP_MASK], FACT_INET, &dl.mask, 4, 0);
		facts_monotonic(&v[DHCP_REQUESTED], &dl.request_time);
		facts_u64(&v[DHCP_LEASE], dl.lease_time);
	}
	if (dl.server_identifier.s_addr != INADDR_ANY)
		facts_address(&v[DHCP_SERVER], FACT_INET,
		    &dl.server_identifier, 4, 0);
	else if (dl.dhcp_server.s_addr != INADDR_ANY)
		facts_address(&v[DHCP_SERVER], FACT_INET, &dl.dhcp_server, 4,
		    0);
	return (facts_record(o, &kind_dhcplease, v));
}

/* a proposal's fields that every proposal has */
static void
proposal(struct facts_value *v, char *ifname, int64_t id, char *state,
    size_t len, time_t timeout, struct timespec *when,
    struct timespec *uptime)
{
	state[len - 1] = '\0';
	facts_i64(&v[SP_ID], id);
	facts_string(&v[SP_STATE], state);
	if (timeout != 0)
		facts_i64(&v[SP_TIMEOUT], timeout);
	facts_time(&v[SP_WHEN], when->tv_sec, when->tv_nsec);
	facts_monotonic(&v[SP_SEEN], uptime);
	facts_string(&v[SP_IF], ifname);
}

/*
 * One message of slaacd's answer, as a record: -1 if the record failed,
 * 1 if the message cannot be read
 */
static int
slaac_record(struct facts_out *o, struct imsg *imsg, char *ifname,
    struct sockaddr_in6 *router)
{
	struct facts_value	 v[SDNS_NFIELDS];
	struct sl_ra		 ra;
	struct sl_ra_prefix	 pfx;
	struct sl_ra_rdns	 rdns;
	struct sl_addr_proposal	 ap;
	struct sl_dfr_proposal	 dp;
	struct sl_rdns_proposal	 np;
	int			 i;

	memset(v, 0, sizeof(v));
	switch (imsg_get_type(imsg)) {
	case SL_RA:
		if (imsg_get_data(imsg, &ra, sizeof(ra)) == -1)
			return (1);
		*router = ra.from;
		facts_sockaddr(&v[SRA_ROUTER], (struct sockaddr *)&ra.from);
		facts_time(&v[SRA_WHEN], ra.when.tv_sec, ra.when.tv_nsec);
		facts_monotonic(&v[SRA_SEEN], &ra.uptime);
		facts_u64(&v[SRA_HOPLIMIT], ra.curhoplimit);
		facts_u64(&v[SRA_MANAGED], ra.managed != 0);
		facts_u64(&v[SRA_OTHER], ra.other != 0);
		facts_u64(&v[SRA_LIFETIME], ra.router_lifetime);
		ra.rpref[sizeof(ra.rpref) - 1] = '\0';
		facts_string(&v[SRA_PREF], ra.rpref);
		facts_u64(&v[SRA_REACHABLE], ra.reachable_time);
		facts_u64(&v[SRA_RETRANS], ra.retrans_time);
		facts_u64(&v[SRA_MTU], ra.mtu);
		facts_string(&v[SRA_IF], ifname);
		return (facts_record(o, &kind_slaacra, v));
	case SL_RA_PREFIX:
		if (imsg_get_data(imsg, &pfx, sizeof(pfx)) == -1)
			return (1);
		facts_address(&v[SPFX_PREFIX], FACT_INET6, &pfx.prefix, 16,
		    0);
		facts_u64(&v[SPFX_LEN], pfx.prefix_len);
		facts_u64(&v[SPFX_ONLINK], pfx.onlink != 0);
		facts_u64(&v[SPFX_AUTONOMOUS], pfx.autonomous != 0);
		facts_u64(&v[SPFX_VLTIME], pfx.vltime);
		facts_u64(&v[SPFX_PLTIME], pfx.pltime);
		facts_sockaddr(&v[SPFX_ROUTER], (struct sockaddr *)router);
		facts_string(&v[SPFX_IF], ifname);
		return (facts_record(o, &kind_slaacprefix, v));
	case SL_RA_RDNS:
		if (imsg_get_data(imsg, &rdns, sizeof(rdns)) == -1)
			return (1);
		facts_address(&v[SRDNS_ADDRESS], FACT_INET6, &rdns.rdns, 16,
		    0);
		facts_u64(&v[SRDNS_LIFETIME], rdns.lifetime);
		facts_sockaddr(&v[SRDNS_ROUTER], (struct sockaddr *)router);
		facts_string(&v[SRDNS_IF], ifname);
		return (facts_record(o, &kind_slaacrdns, v));
	case SL_ADDR_PROPOSAL:
		if (imsg_get_data(imsg, &ap, sizeof(ap)) == -1)
			return (1);
		proposal(v, ifname, ap.id, ap.state, sizeof(ap.state),
		    ap.next_timeout, &ap.when, &ap.uptime);
		facts_sockaddr(&v[SADDR_ADDRESS], (struct sockaddr *)&ap.addr);
		facts_address(&v[SADDR_PREFIX], FACT_INET6, &ap.prefix, 16,
		    0);
		facts_u64(&v[SADDR_LEN], ap.prefix_len);
		facts_u64(&v[SADDR_TEMPORARY], ap.temporary != 0);
		facts_u64(&v[SADDR_VLTIME], ap.vltime);
		facts_u64(&v[SADDR_PLTIME], ap.pltime);
		return (facts_record(o, &kind_slaacaddr, v));
	case SL_DFR_PROPOSAL:
		if (imsg_get_data(imsg, &dp, sizeof(dp)) == -1)
			return (1);
		proposal(v, ifname, dp.id, dp.state, sizeof(dp.state),
		    dp.next_timeout, &dp.when, &dp.uptime);
		facts_sockaddr(&v[SDFR_ROUTER], (struct sockaddr *)&dp.addr);
		facts_u64(&v[SDFR_LIFETIME], dp.router_lifetime);
		dp.rpref[sizeof(dp.rpref) - 1] = '\0';
		facts_string(&v[SDFR_PREF], dp.rpref);
		return (facts_record(o, &kind_slaacdfr, v));
	case SL_RDNS_PROPOSAL:
		if (imsg_get_data(imsg, &np, sizeof(np)) == -1)
			return (1);
		proposal(v, ifname, np.id, np.state, sizeof(np.state),
		    np.next_timeout, &np.when, &np.uptime);
		facts_sockaddr(&v[SDNS_ROUTER], (struct sockaddr *)&np.from);
		facts_u64(&v[SDNS_LIFETIME], np.rdns_lifetime);
		for (i = 0; i < np.rdns_count && i < SL_RDNS; i++)
			facts_address(&v[SDNS_SERVER + i], FACT_INET6,
			    &np.rdns[i], 16, 0);
		return (facts_record(o, &kind_slaacdns, v));
	}
	return (0);	/* a section's heading */
}

/*
 * What slaacd knows of ifname, the interface last; -1 if a record
 * failed
 */
static int
slaac_facts(struct facts_out *o, int *fd, struct imsgbuf *ib, char *ifname,
    uint32_t if_index)
{
	struct facts_value	 v[SLAAC_NFIELDS];
	struct sockaddr_in6	 router;
	struct sl_info		 si;
	struct imsg		 imsg;
	uint32_t		 type;
	int			 have = 0, bad = 0, r = 0;

	memset(&router, 0, sizeof(router));
	if (ctl_ask(ib, SL_SHOW_INTERFACE_INFO, if_index) == -1) {
		ctl_close(fd, ib);
		return (0);
	}
	/* slaacd sends the interface first; its record is sent last */
	for (;;) {
		if (ctl_next(*fd, ib, &imsg, "slaacd") == -1) {
			ctl_close(fd, ib);
			break;
		}
		type = imsg_get_type(&imsg);
		if (type == SL_END) {
			imsg_free(&imsg);
			break;
		}
		if (bad)
			;
		else if (type == SL_SHOW_INTERFACE_INFO && !have) {
			if (imsg_get_data(&imsg, &si, sizeof(si)) == 0)
				have = 1;
			else
				bad = 1;
		} else if (!have)
			bad = 1;
		else if ((r = slaac_record(o, &imsg, ifname, &router)) == 1)
			bad = 1;
		imsg_free(&imsg);
		if (r == -1)
			return (-1);
	}
	if (bad) {
		printf("%% slaacd: an answer nsh cannot read\n");
		ctl_close(fd, ib);
	}
	if (!have)
		return (0);

	memset(v, 0, sizeof(v));
	facts_string(&v[SLAAC_IF], ifname);
	facts_u64(&v[SLAAC_INDEX], si.if_index);
	facts_u64(&v[SLAAC_RUNNING], si.running != 0);
	facts_u64(&v[SLAAC_TEMPORARY], si.temporary != 0);
	facts_address(&v[SLAAC_LLADDR], FACT_LINK, &si.hw_address,
	    ETHER_ADDR_LEN, 0);
	facts_sockaddr(&v[SLAAC_INET6], (struct sockaddr *)&si.ll_address);
	return (facts_record(o, &kind_slaacif, v));
}

/*
 * What dhcpleased and slaacd know of each interface they configure,
 * or only ifname; -1 on error
 */
int
autoconf_facts(struct facts_out *o, char *ifname)
{
	struct if_nameindex	*ifn_list, *ifnp;
	struct imsgbuf		 dib, sib;
	int			 ifs, ifxflags, dfd = -2, sfd = -2, r = 0;

	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("%% socket: %s\n", strerror(errno));
		return (-1);
	}
	if ((ifn_list = if_nameindex()) == NULL) {
		printf("%% if_nameindex: %s\n", strerror(errno));
		close(ifs);
		return (-1);
	}
	/* connect to each daemon only when it is first needed */
	for (ifnp = ifn_list; ifnp->if_name != NULL && r != -1; ifnp++) {
		if (ifname && strcmp(ifname, ifnp->if_name) != 0)
			continue;

		ifxflags = get_ifxflags(ifnp->if_name, ifs);
		if (ifxflags & IFXF_AUTOCONF4) {
			if (dfd == -2)
				dfd = ctl_open(DHCPLEASED_SOCK, &dib);
			if (dfd != -1)
				r = dhcp_facts(o, &dfd, &dib, ifnp->if_name,
				    ifnp->if_index);
		}
		if ((ifxflags & IFXF_AUTOCONF6) && r != -1) {
			if (sfd == -2)
				sfd = ctl_open(SLAACD_SOCK, &sib);
			if (sfd != -1)
				r = slaac_facts(o, &sfd, &sib, ifnp->if_name,
				    ifnp->if_index);
		}
	}

	ctl_close(&dfd, &dib);
	ctl_close(&sfd, &sib);
	if_freenameindex(ifn_list);
	close(ifs);
	return (r);
}

/* fact i of r, a string, or empty */
static const char *
str(struct frec *r, int i)
{
	return (fs(r, i) != NULL ? fs(r, i) : "");
}

/* a proposal's id */
static long long
prop_id(struct frec *r)
{
	const struct facts_value	*v;

	return ((v = FV(r, SP_ID, FACT_I64)) != NULL ? v->v.i : 0);
}

/* seconds since fact i of r, a time, by this clock */
static long long
ago(struct frec *r, int i)
{
	const struct facts_value	*v;
	struct timespec			 now, t, d;

	if ((v = FV(r, i, FACT_TIME)) == NULL)
		return (0);
	clock_gettime(CLOCK_REALTIME, &now);
	t.tv_sec = v->v.t.sec;
	t.tv_nsec = v->v.t.nsec;
	timespecsub(&now, &t, &d);
	return (d.tv_sec);
}

/* fact i of r, a time, as slaacctl prints one */
static const char *
when(struct frec *r, int i, char *buf, size_t len)
{
	const struct facts_value	*v;
	struct tm			*tm;
	time_t				 t;

	buf[0] = '\0';
	if ((v = FV(r, i, FACT_TIME)) != NULL) {
		t = v->v.t.sec;
		if ((tm = localtime(&t)) != NULL)
			strftime(buf, len, "%F %T", tm);
	}
	return (buf);
}

/* fact i of r, an address, as numbers, its scope too */
static const char *
host(struct frec *r, int i, char *buf, size_t len)
{
	struct sockaddr_storage	 ss;

	if (!fsockaddr(r, i, &ss) || getnameinfo((struct sockaddr *)&ss,
	    ss.ss_len, buf, len, NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV))
		buf[0] = '\0';
	return (buf);
}

/* a lease, after its routes and name servers, as dhcpleasectl -l */
static void
dhcp_render(struct frecs *rs, struct frec *o)
{
	struct sockaddr_storage	 dst, mask;
	struct frec		*r;
	long long		 d, h, m, s;
	char			 ipbuf[NI_MAXHOST], maskbuf[NI_MAXHOST];
	char			 gwbuf[NI_MAXHOST];
	int			 n = 0;

	printf("%s [%s]\n", fs(o, DHCP_IF) != NULL ? fs(o, DHCP_IF) :
	    "unknown", str(o, DHCP_STATE));
	if (fhas(o, DHCP_ADDRESS)) {
		printf("\tinet %s netmask %s\n",
		    host(o, DHCP_ADDRESS, ipbuf, sizeof(ipbuf)),
		    host(o, DHCP_MASK, maskbuf, sizeof(maskbuf)));
		for (r = NULL; (r = frec_next(rs, r, &kind_dhcproute)); ) {
			fsockaddr(r, DHCPR_DEST, &dst);
			fsockaddr(r, DHCPR_MASK, &mask);
			host(r, DHCPR_GW, gwbuf, sizeof(gwbuf));
			if (((struct sockaddr_in *)&dst)->sin_addr.s_addr ==
			    INADDR_ANY &&
			    ((struct sockaddr_in *)&mask)->sin_addr.s_addr ==
			    INADDR_ANY)
				printf("\tdefault gateway %s\n", gwbuf);
			else
				printf("\troute %s/%d gateway %s\n",
				    host(r, DHCPR_DEST, ipbuf, sizeof(ipbuf)),
				    33 - ffs(ntohl(((struct sockaddr_in *)
				    &mask)->sin_addr.s_addr)), gwbuf);
		}
		for (r = NULL; (r = frec_next(rs, r, &kind_dhcpns)); n++)
			printf("%s %s", n == 0 ? "\tnameservers" : "",
			    host(r, DHCPNS_ADDRESS, ipbuf, sizeof(ipbuf)));
		if (n)
			printf("\n");

		s = (long long)fu(o, DHCP_LEASE, 0) - ago(o, DHCP_REQUESTED);
		if (s < 0)
			s = 0;

		if (s > 86400) {
			d = s / 86400;

			/* round up */
			if (s - d * 86400 > 43200)
				d++;
			printf("\tlease %lld day%s\n", d, d > 1 ? "s" : "");
		} else if (s > 3600) {
			h = s / 3600;

			/* round up */
			if (s - h * 3600 > 1800)
				h++;
			printf("\tlease %lld hour%s\n", h, h > 1 ? "s" : "");
		} else if (s > 60) {
			m = s / 60;

			/* round up */
			if (s - m * 60 > 30)
				m++;
			printf("\tlease %lld minute%s\n", m, m > 1 ? "s" : "");
		} else
			printf("\tlease %lld second%s\n", s, s > 1 ? "s" : "");
	}
	if (fhas(o, DHCP_SERVER))
		printf("\tdhcp server %s\n",
		    host(o, DHCP_SERVER, ipbuf, sizeof(ipbuf)));
}

/* vltime and pltime, as slaacctl prints them */
static void
lifetimes(const char *indent, uint64_t vltime, uint64_t pltime)
{
	if (vltime == ND6_INFINITE_LIFETIME)
		printf("%svltime: %10s, ", indent, "infinity");
	else
		printf("%svltime: %10u, ", indent, (u_int)vltime);
	if (pltime == ND6_INFINITE_LIFETIME)
		printf("pltime: %10s", "infinity");
	else
		printf("pltime: %10u", (u_int)pltime);
}

/* when a proposal was updated, and its timeout, as slaacctl prints them */
static void
updated(struct frec *r, int timeout_first)
{
	const struct facts_value	*t;
	char				 whenbuf[255];
	long long			 diff;

	diff = ago(r, SP_SEEN);
	t = FV(r, SP_TIMEOUT, FACT_I64);
	if (!timeout_first)
		printf("\t\tupdated: %s; %llds ago",
		    when(r, SP_WHEN, whenbuf, sizeof(whenbuf)), diff);
	if (t != NULL)
		printf(", timeout: %10llds\n", (long long)t->v.i - diff);
	else
		printf("\n");
	if (timeout_first)
		printf("\t\tupdated: %s; %llds ago\n",
		    when(r, SP_WHEN, whenbuf, sizeof(whenbuf)), diff);
}

/*
 * An interface slaacd knows, after its other records, as slaacctl
 * show interface prints it
 */
static void
slaac_render(struct frecs *rs, struct frec *o)
{
	const struct facts_kind		*prev = NULL;
	const struct facts_value	*v;
	struct ether_addr		 ea;
	struct frec			*r;
	char				 hbuf[NI_MAXHOST], whenbuf[255];
	char				 ntopbuf[NI_MAXHOST];
	int				 i;

	printf("%s:\n", fs(o, SLAAC_IF) != NULL ? fs(o, SLAAC_IF) :
	    "unknown");
	printf("\t index: %3u ", (u_int)fu(o, SLAAC_INDEX, 0));
	printf("running: %3s ", fu(o, SLAAC_RUNNING, 0) ? "yes" : "no");
	printf("temporary: %3s\n", fu(o, SLAAC_TEMPORARY, 0) ? "yes" :
	    "no");
	memset(&ea, 0, sizeof(ea));
	if ((v = FV(o, SLAAC_LLADDR, FACT_ADDRESS)) != NULL)
		memcpy(&ea, v->v.a.bytes, v->v.a.len < sizeof(ea) ?
		    v->v.a.len : sizeof(ea));
	printf("\tlladdr: %s\n", ether_ntoa(&ea));
	printf("\t inet6: %s\n", host(o, SLAAC_INET6, hbuf, sizeof(hbuf)));

	TAILQ_FOREACH(r, rs, entry) {
		if (r->k == &kind_slaacra) {
			printf("\tRouter Advertisement from %s\n",
			    host(r, SRA_ROUTER, hbuf, sizeof(hbuf)));
			printf("\t\treceived: %s; %llds ago\n",
			    when(r, SRA_WHEN, whenbuf, sizeof(whenbuf)),
			    ago(r, SRA_SEEN));
			printf("\t\tCur Hop Limit: %3u, M: %d, O: %d, Router "
			    "Lifetime: %5us\n", (u_int)fu(r, SRA_HOPLIMIT, 0),
			    fu(r, SRA_MANAGED, 0) ? 1 : 0,
			    fu(r, SRA_OTHER, 0) ? 1 : 0,
			    (u_int)fu(r, SRA_LIFETIME, 0));
			printf("\t\tDefault Router Preference: %s\n",
			    str(r, SRA_PREF));
			printf("\t\tReachable Time: %9ums, Retrans Timer: "
			    "%9ums\n", (u_int)fu(r, SRA_REACHABLE, 0),
			    (u_int)fu(r, SRA_RETRANS, 0));
			if (fu(r, SRA_MTU, 0))
				printf("\t\tMTU: %u bytes\n",
				    (u_int)fu(r, SRA_MTU, 0));
		} else if (r->k == &kind_slaacprefix) {
			printf("\t\tprefix: %s/%u\n", host(r, SPFX_PREFIX,
			    ntopbuf, sizeof(ntopbuf)),
			    (u_int)fu(r, SPFX_LEN, 0));
			printf("\t\t\tOn-link: %d, Autonomous "
			    "address-configuration: %d\n",
			    fu(r, SPFX_ONLINK, 0) ? 1 : 0,
			    fu(r, SPFX_AUTONOMOUS, 0) ? 1 : 0);
			lifetimes("\t\t\t", fu(r, SPFX_VLTIME, 0),
			    fu(r, SPFX_PLTIME, 0));
			printf("\n");
		} else if (r->k == &kind_slaacrdns) {
			printf("\t\trdns: %s, lifetime: %u\n",
			    host(r, SRDNS_ADDRESS, ntopbuf, sizeof(ntopbuf)),
			    (u_int)fu(r, SRDNS_LIFETIME, 0));
		} else if (r->k == &kind_slaacaddr) {
			if (prev != r->k)
				printf("\tAddress proposals\n");
			printf("\t\tid: %4lld, state: %15s, temporary: %s\n",
			    prop_id(r), str(r, SP_STATE), fu(r, SADDR_TEMPORARY, 0) ?
			    "y" : "n");
			lifetimes("\t\t", fu(r, SADDR_VLTIME, 0),
			    fu(r, SADDR_PLTIME, 0));
			updated(r, 1);
			printf("\t\t%s, %s/%u\n",
			    host(r, SADDR_ADDRESS, hbuf, sizeof(hbuf)),
			    host(r, SADDR_PREFIX, ntopbuf, sizeof(ntopbuf)),
			    (u_int)fu(r, SADDR_LEN, 0));
		} else if (r->k == &kind_slaacdfr) {
			if (prev != r->k)
				printf("\tDefault router proposals\n");
			printf("\t\tid: %4lld, state: %15s\n",
			    prop_id(r), str(r, SP_STATE));
			printf("\t\trouter: %s\n",
			    host(r, SDFR_ROUTER, hbuf, sizeof(hbuf)));
			printf("\t\trouter lifetime: %10u\n",
			    (u_int)fu(r, SDFR_LIFETIME, 0));
			printf("\t\tPreference: %s\n", str(r, SDFR_PREF));
			updated(r, 0);
		} else if (r->k == &kind_slaacdns) {
			if (prev != r->k)
				printf("\trDNS proposals\n");
			printf("\t\tid: %4lld, state: %15s\n",
			    prop_id(r), str(r, SP_STATE));
			printf("\t\trouter: %s\n",
			    host(r, SDNS_ROUTER, hbuf, sizeof(hbuf)));
			printf("\t\trdns lifetime: %10u\n",
			    (u_int)fu(r, SDNS_LIFETIME, 0));
			printf("\t\trdns:\n");
			for (i = 0; i < SL_RDNS; i++)
				if (fhas(r, SDNS_SERVER + i))
					printf("\t\t\t%s\n", host(r,
					    SDNS_SERVER + i, ntopbuf,
					    sizeof(ntopbuf)));
			updated(r, 0);
		}
		prev = r->k;
	}
}

/* what dhcpleased or slaacd knows of interface o, after its other records */
void
autoconf_render(struct frecs *rs, struct frec *o)
{
	if (o->k == &kind_dhcplease)
		dhcp_render(rs, o);
	else
		slaac_render(rs, o);
}
