/* From: $OpenBSD: /usr/src/sbin/route/show.c,v 1.61 2007/09/05 20:30:21 claudio Exp $	*/

/*
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/pfkeyv2.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip_ipsp.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "externs.h"
#include "facts.h"
#include "showfacts.h"

#define PLEN  (LONG_BIT / 4 + 2)

#define PFKEYV2_CHUNK sizeof(u_int64_t)
void	index_pfk(struct sadb_msg *, void **);

/*
 * The SPD's flows, as the kernel dumps them; NULL if it cannot, after
 * printing why, unless the kernel has no IPsec
 */
struct rtdump *
sadb_dump(void)
{
	struct rtdump	*spd;
	size_t		 needed;
	char		*p;
	int		 mib[4] = { CTL_NET, PF_KEY, PF_KEY_V2,
			    NET_KEY_SPD_DUMP };

	if ((spd = calloc(1, sizeof(*spd))) == NULL) {
		printf("%% sadb_dump: %s\n", strerror(errno));
		return (NULL);
	}
	for (;;) {
		if (sysctl(mib, 4, NULL, &needed, NULL, 0) == -1) {
			if (errno != ENOPROTOOPT)
				printf("%% sadb_dump: spd-sysctl-estimate: "
				    "%s\n", strerror(errno));
			break;
		}
		if ((p = realloc(spd->buf, needed)) == NULL) {
			printf("%% sadb_dump: spd malloc: %s\n",
			    strerror(errno));
			break;
		}
		spd->buf = p;
		if (sysctl(mib, 4, spd->buf, &needed, NULL, 0) == 0) {
			spd->lim = spd->buf + needed;
			return (spd);
		}
		/* the SPD grew since it was estimated */
		if (errno != ENOMEM) {
			printf("%% sadb_dump: spd sysctl: %s\n",
			    strerror(errno));
			break;
		}
	}
	freertdump(spd);
	return (NULL);
}

static void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int	i;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			sa = (struct sockaddr *)((char *)(sa) +
			    ROUNDUP(sa->sa_len));
		} else
			rti_info[i] = NULL;
	}
}

/* a link address's type and name, as facts */
void
facts_sdl(struct facts_value *type, struct facts_value *name, char *buf,
    size_t len, struct sockaddr *sa)
{
	struct sockaddr_dl	*sdl = (struct sockaddr_dl *)sa;

	if (sa == NULL || sa->sa_family != AF_LINK)
		return;
	facts_u64(type, sdl->sdl_type);
	if (sdl->sdl_nlen == 0)
		return;
	snprintf(buf, len, "%.*s", sdl->sdl_nlen, sdl->sdl_data);
	facts_string(name, buf);
}

/*
 * The routes of rt, from *cur, that are of af, as facts, at most budget
 * of them. 1 if there are more, 0 if not, -1 if a record failed.
 */
int
route_facts(struct facts_out *o, struct rtdump *rt, char **cur, int af,
    int budget)
{
	struct facts_value	 v[RT_NFIELDS];
	struct rt_msghdr	*rtm;
	struct sockaddr		*sa, *rti_info[RTAX_MAX];
	char			 ifbuf[IF_NAMESIZE], gwname[IFNAMSIZ + 1];
	int			 n = 0;

	for (; *cur < rt->lim; *cur += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)*cur;
		if (n == budget)
			return (1);
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		sa = (struct sockaddr *)(*cur + rtm->rtm_hdrlen);
		if ((af != AF_UNSPEC && sa->sa_family != af) ||
		    sa->sa_family == AF_KEY)
			continue;
		get_rtaddrs(rtm->rtm_addrs, sa, rti_info);
		if (rti_info[RTAX_DST] == NULL)
			continue;
		memset(v, 0, sizeof(v));
		facts_sockaddr(&v[RT_DST], rti_info[RTAX_DST]);
		facts_sockaddr(&v[RT_MASK], rti_info[RTAX_NETMASK]);
		facts_sockaddr(&v[RT_GATEWAY], rti_info[RTAX_GATEWAY]);
		facts_sdl(&v[RT_GWTYPE], &v[RT_GWNAME], gwname,
		    sizeof(gwname), rti_info[RTAX_GATEWAY]);
		facts_u64(&v[RT_FLAGS], rtm->rtm_flags);
		facts_u64(&v[RT_REFS], rtm->rtm_rmx.rmx_refcnt);
		facts_u64(&v[RT_USE], rtm->rtm_rmx.rmx_pksent);
		facts_u64(&v[RT_MTU], rtm->rtm_rmx.rmx_mtu);
		facts_u64(&v[RT_LOCKS], rtm->rtm_rmx.rmx_locks);
		facts_u64(&v[RT_PRIORITY], rtm->rtm_priority);
		if (if_indextoname(rtm->rtm_index, ifbuf) != NULL)
			facts_string(&v[RT_IF], ifbuf);
		if (facts_record(o, &kind_route, v) == -1)
			return (-1);
		n++;
	}
	return (0);
}

/* the address the message's extension ext holds, or NULL */
static struct sockaddr *
flow_sa(void **headers, int ext)
{
	struct sadb_address	*saddr = headers[ext];

	return (saddr != NULL ? (struct sockaddr *)(saddr + 1) : NULL);
}

static uint16_t
flow_port(struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (ntohs(((struct sockaddr_in *)sa)->sin_port));
	case AF_INET6:
		return (ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
	}
	return (0);
}

/*
 * The flows of spd, from *cur, as facts, at most budget of them. 1 if
 * there are more, 0 if not, -1 if a record failed.
 */
int
sadb_facts(struct facts_out *o, struct rtdump *spd, char **cur, int budget)
{
	struct facts_value	 v[FLOW_NFIELDS];
	struct sadb_msg		*msg;
	struct sadb_protocol	*sap, *saft;
	struct sockaddr		*src, *srcmask, *dst, *dstmask;
	void			*headers[SADB_EXT_MAX + 1];
	int			 n = 0;

	for (; *cur < spd->lim; *cur += msg->sadb_msg_len * PFKEYV2_CHUNK) {
		msg = (struct sadb_msg *)*cur;
		if (msg->sadb_msg_len == 0)
			break;
		if (n == budget)
			return (1);
		bzero(headers, sizeof(headers));
		index_pfk(msg, headers);
		sap = headers[SADB_X_EXT_PROTOCOL];
		saft = headers[SADB_X_EXT_FLOW_TYPE];
		/* always set, and bypass and deny flows have no peer */
		if ((src = flow_sa(headers, SADB_X_EXT_SRC_FLOW)) == NULL ||
		    (srcmask = flow_sa(headers, SADB_X_EXT_SRC_MASK)) ==
		    NULL ||
		    (dst = flow_sa(headers, SADB_X_EXT_DST_FLOW)) == NULL ||
		    (dstmask = flow_sa(headers, SADB_X_EXT_DST_MASK)) ==
		    NULL || sap == NULL || saft == NULL)
			continue;
		memset(v, 0, sizeof(v));
		facts_sockaddr(&v[FLOW_SRC], src);
		facts_sockaddr(&v[FLOW_SRCMASK], srcmask);
		facts_u64(&v[FLOW_SRCPORT], flow_port(src));
		facts_sockaddr(&v[FLOW_DST], dst);
		facts_sockaddr(&v[FLOW_DSTMASK], dstmask);
		facts_u64(&v[FLOW_DSTPORT], flow_port(dst));
		facts_u64(&v[FLOW_PROTO], sap->sadb_protocol_proto);
		facts_sockaddr(&v[FLOW_PEER],
		    flow_sa(headers, SADB_EXT_ADDRESS_DST));
		facts_u64(&v[FLOW_SATYPE], msg->sadb_msg_satype);
		facts_u64(&v[FLOW_TYPE], saft->sadb_protocol_proto);
		facts_u64(&v[FLOW_DIRECTION], saft->sadb_protocol_direction);
		if (facts_record(o, &kind_flow, v) == -1)
			return (-1);
		n++;
	}
	return (0);
}

void
in6_clearscopeid(struct sockaddr_in6 *sin6)
{
	if ((IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_INTFACELOCAL(&sin6->sin6_addr)) &&
	    *(u_int16_t *)&sin6->sin6_addr.s6_addr[2] == 0 &&
	    sin6->sin6_scope_id) {
		*(u_int16_t *)&sin6->sin6_addr.s6_addr[2] =
		    htons(sin6->sin6_scope_id & 0xffff);
		sin6->sin6_scope_id = 0;
	}
}

void
index_pfk(struct sadb_msg *msg, void **headers)
{
	struct sadb_ext	*ext;

	for (ext = (struct sadb_ext *)(msg + 1);
	    (size_t)((u_int8_t *)ext - (u_int8_t *)msg) <
	    msg->sadb_msg_len * PFKEYV2_CHUNK && ext->sadb_ext_len > 0;
	    ext = (struct sadb_ext *)((u_int8_t *)ext +
	    ext->sadb_ext_len * PFKEYV2_CHUNK)) {
		switch (ext->sadb_ext_type) {
		case SADB_EXT_ADDRESS_SRC:
			headers[SADB_EXT_ADDRESS_SRC] = (void *)ext;
			break;
		case SADB_EXT_ADDRESS_DST:
			headers[SADB_EXT_ADDRESS_DST] = (void *)ext;
			break;
		case SADB_X_EXT_PROTOCOL:
			headers[SADB_X_EXT_PROTOCOL] = (void *)ext;
			break;
		case SADB_X_EXT_SRC_FLOW:
			headers[SADB_X_EXT_SRC_FLOW] = (void *)ext;
			break;
		case SADB_X_EXT_DST_FLOW:
			headers[SADB_X_EXT_DST_FLOW] = (void *)ext;
			break;
		case SADB_X_EXT_SRC_MASK:
			headers[SADB_X_EXT_SRC_MASK] = (void *)ext;
			break;
		case SADB_X_EXT_DST_MASK:
			headers[SADB_X_EXT_DST_MASK] = (void *)ext;
			break;
		case SADB_X_EXT_FLOW_TYPE:
			headers[SADB_X_EXT_FLOW_TYPE] = (void *)ext;
		default:
			/* Ignore. */
			break;
		}
	}
}
