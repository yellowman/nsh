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
 * What configure private reads of the kernel, each read here, from the
 * kernel, or from the facts kfacts_set() gave, as nshd's config has
 * them from system's last snapshot. Measured, the reads its handlers
 * make are these and no other: an interface's index, flags, type and
 * capabilities, whether it is 802.11, the link-level address it came
 * with, its link-local address, its media and the media its driver
 * lists; the cloners, the routing tables there, and whether dhcpleased
 * answers. kfacts_scan() reads all of them, for system to send.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "stringlist.h"
#include "externs.h"
#include "ctl.h"
#include "facts.h"
#include "kfacts.h"

static struct kfacts *kf;	/* the snapshot's, or NULL: the kernel's */

static struct kif *kif(char *);
static int k_media(int, char *, uint64_t *, uint64_t **, size_t *);
static int k_rtable(int);
static int scan_if(int, struct kif *, struct ifaddrs *);
static int scan_cloners(int, struct kfacts *);
static int scan_groups(int, struct kfacts *);
static int k_names(int, StringList *);

void
kfacts_set(struct kfacts *k)
{
	kf = k;
}

/* name's facts, or NULL with errno ENXIO */
static struct kif *
kif(char *name)
{
	size_t i;

	for (i = 0; i < kf->nifs; i++)
		if (strcmp(kf->ifs[i].name, name) == 0)
			return &kf->ifs[i];
	errno = ENXIO;
	return NULL;
}

/* if_nametoindex() */
unsigned int
kf_index(char *name)
{
	struct kif *k;

	if (kf == NULL)
		return if_nametoindex(name);
	return (k = kif(name)) != NULL ? k->index : 0;
}

/* is_valid_ifname(): one interface of that name, in any case */
int
kf_valid(char *name)
{
	size_t i;
	int n = 0;

	if (kf == NULL)
		return is_valid_ifname(name);
	for (i = 0; i < kf->nifs; i++)
		if (strcasecmp(kf->ifs[i].name, name) == 0)
			n++;
	return n == 1;
}

/* get_ifflags(), of an interface that is there */
int
kf_flags(char *name, int ifs)
{
	struct kif *k;

	if (kf == NULL)
		return get_ifflags(name, ifs);
	if ((k = kif(name)) == NULL) {
		printf("%% get_ifflags: SIOCGIFFLAGS: %s\n", strerror(errno));
		return 0;
	}
	return k->flags;
}

/* get_ifdata()'s IFDATA_IFTYPE */
int
kf_type(char *name)
{
	struct kif *k;

	if (kf == NULL)
		return get_ifdata(name, IFDATA_IFTYPE);
	return (k = kif(name)) != NULL ? k->type : 0;
}

/* get_ifdata()'s IFDATA_CAPABILITIES */
int
kf_caps(char *name)
{
	struct kif *k;

	if (kf == NULL)
		return get_ifdata(name, IFDATA_CAPABILITIES);
	return (k = kif(name)) != NULL ? k->caps : 0;
}

/* Does SIOCG80211NWID answer for name? */
int
kf_wifi(char *name)
{
	char tmp[IEEE80211_NWID_LEN * 2 + 8];
	struct kif *k;

	if (kf == NULL)
		return get_nwinfo(name, tmp, sizeof(tmp), NWID) != 0;
	return (k = kif(name)) != NULL && k->wifi;
}

/*
 * The link-level address name came with: the one the database kept when
 * lladdr first changed it, or else the one it has; NULL if none
 */
char *
kf_lladdr(char *name)
{
	static char buf[KF_LLADDR];
	StringList *orig;
	struct kif *k;
	char *cur;

	if (kf != NULL)
		return (k = kif(name)) != NULL && k->lladdr[0] != '\0' ?
		    k->lladdr : NULL;
	orig = sl_init();
	if (db_select_flag_x_ctl(orig, "lladdr", name) < 0) {
		printf("%% lladdr database select failed\n");
		cur = NULL;
	} else if (orig->sl_cur > 0) {
		strlcpy(buf, orig->sl_str[0], sizeof(buf));
		cur = buf;
	} else
		cur = get_hwdaddr(name);
	sl_free(orig, 1);
	return cur;
}

/*
 * name's link-local address, in a: 1, or 0 if it has none, or -1 if
 * the kernel could not say, errno set
 */
int
kf_ll6(char *name, struct in6_addr *a)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in6 *sin6;
	struct kif *k;
	int found = 0;

	if (kf != NULL) {
		if ((k = kif(name)) == NULL || !k->hasll6)
			return 0;
		*a = k->ll6;
		return 1;
	}
	if (getifaddrs(&ifap) != 0)
		return -1;
	for (ifa = ifap; ifa != NULL && !found; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL ||
		    ifa->ifa_addr->sa_family != AF_INET6 ||
		    strcmp(ifa->ifa_name, name) != 0)
			continue;
		sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
			*a = sin6->sin6_addr;
			found = 1;
		}
	}
	freeifaddrs(ifap);
	return found;
}

/*
 * SIOCGIFMEDIA, on s for the kernel: name's current media word in
 * *cur, and if list is not NULL, the words its driver lists, allocated,
 * in *list and their number in *n; -1 if it has none, errno set
 */
int
kf_media(int s, char *name, uint64_t *cur, uint64_t **list, size_t *n)
{
	struct kif *k;

	if (kf == NULL)
		return k_media(s, name, cur, list, n);
	if ((k = kif(name)) == NULL)
		return -1;
	if (k->media == 0) {
		errno = ENOTTY;
		return -1;
	}
	*cur = k->media;
	if (list == NULL)
		return 0;
	if ((*list = calloc(k->nmedias ? k->nmedias : 1,
	    sizeof(**list))) == NULL)
		return -1;
	memcpy(*list, k->medias, k->nmedias * sizeof(**list));
	*n = k->nmedias;
	return 0;
}

/* kf_media(), of the kernel */
static int
k_media(int s, char *name, uint64_t *cur, uint64_t **list, size_t *n)
{
	struct ifmediareq ifmr;
	uint64_t *l;

	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, name, sizeof(ifmr.ifm_name));
	/* E2BIG: there are more than the none asked for */
	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) == -1 &&
	    (list != NULL || errno != E2BIG))
		return -1;
	*cur = ifmr.ifm_current;
	if (list == NULL)
		return 0;
	if ((l = calloc(ifmr.ifm_count ? ifmr.ifm_count : 1,
	    sizeof(*l))) == NULL)
		return -1;
	ifmr.ifm_ulist = l;
	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) == -1) {
		free(l);
		return -1;
	}
	*list = l;
	*n = ifmr.ifm_count;
	return 0;
}

/* Is there a cloner called the first len bytes of name? */
int
kf_cloner(char *name, size_t len)
{
	struct kfacts k;
	size_t i;
	int s, ret = 0;

	if (kf != NULL) {
		for (i = 0; i < kf->ncloners; i++)
			if (strnlen(kf->cloners[i], IFNAMSIZ) == len &&
			    strncmp(kf->cloners[i], name, len) == 0)
				return 1;
		return 0;
	}
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return 0;
	memset(&k, 0, sizeof(k));
	if (scan_cloners(s, &k) == 0)
		for (i = 0; i < k.ncloners && !ret; i++)
			ret = strnlen(k.cloners[i], IFNAMSIZ) == len &&
			    strncmp(k.cloners[i], name, len) == 0;
	free(k.cloners);
	close(s);
	return ret;
}

/* Is there routing table id? */
int
kf_rtable(int id)
{
	if (kf != NULL)
		return id >= 0 && (size_t)id < sizeof(kf->rtables) &&
		    kf->rtables[id];
	return k_rtable(id);
}

static int
k_rtable(int id)
{
	int mib[6] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_TABLE, id };
	struct rt_tableinfo info;
	size_t len = sizeof(info);

	return sysctl(mib, 6, &info, &len, NULL, 0) != -1;
}

/* Does dhcpleased answer on its control socket? */
int
kf_dhcpleased(void)
{
	if (kf != NULL)
		return kf->dhcpleased;
	return dhcpleased_is_running();
}

/*
 * Add the names of one kind (KF_*) that completion lists to sl, each in
 * its own allocation.  Return 0, or -1 after printing why the kernel or
 * the database could not be read.  From a snapshot, the bridges are the
 * interfaces of type IFT_BRIDGE, and the routing tables are those the
 * snapshot has.  Without one, nsh asks the kernel, uses is_bridge() for
 * the bridges, and reads the routing tables from its database.
 */
int
kf_names(int kind, StringList *sl)
{
	char *s;
	size_t i;

	if (kf == NULL)
		return k_names(kind, sl);
	if (kind == KF_RTABLES) {
		for (i = 1; i < sizeof(kf->rtables); i++)
			if (kf->rtables[i]) {
				if (asprintf(&s, "%zu", i) == -1)
					return -1;
				sl_add(sl, s);
			}
		return 0;
	}
	if (kind == KF_GROUPS) {
		for (i = 0; i < kf->ngroups; i++) {
			if ((s = strndup(kf->groups[i], IFNAMSIZ)) == NULL)
				return -1;
			sl_add(sl, s);
		}
		return 0;
	}
	for (i = 0; i < kf->nifs; i++) {
		if (kind == KF_BRIDGES && kf->ifs[i].type != IFT_BRIDGE)
			continue;
		if ((s = strdup(kf->ifs[i].name)) == NULL)
			return -1;
		sl_add(sl, s);
	}
	return 0;
}

/* kf_names() without a snapshot: read the kernel and nsh's database */
static int
k_names(int kind, StringList *sl)
{
	struct if_nameindex *ifn, *p;
	struct kfacts k;
	char *s;
	size_t i;
	int ifs, r = 0;

	if (kind == KF_RTABLES) {
		if (db_select_rtable_rtables(sl) < 0) {
			printf("%% database failure select rtables rtable\n");
			return -1;
		}
		return 0;
	}
	if ((ifs = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		printf("%% socket: %s\n", strerror(errno));
		return -1;
	}
	if (kind == KF_GROUPS) {
		memset(&k, 0, sizeof(k));
		if (scan_groups(ifs, &k) == -1) {
			printf("%% SIOCGIFGLIST: %s\n", strerror(errno));
			close(ifs);
			return -1;
		}
		for (i = 0; i < k.ngroups && r == 0; i++)
			if ((s = strndup(k.groups[i], IFNAMSIZ)) == NULL)
				r = -1;
			else
				sl_add(sl, s);
		free(k.groups);
		close(ifs);
		return r;
	}
	if ((ifn = if_nameindex()) == NULL) {
		close(ifs);
		return -1;
	}
	for (p = ifn; p->if_name != NULL && r == 0; p++) {
		if (kind == KF_BRIDGES && !is_bridge(ifs, p->if_name))
			continue;
		if ((s = strdup(p->if_name)) == NULL)
			r = -1;
		else
			sl_add(sl, s);
	}
	if_freenameindex(ifn);
	close(ifs);
	return r;
}

/*
 * All of it, from the kernel, as system sends it; NULL if it could not
 * be read, errno set
 */
struct kfacts *
kfacts_scan(void)
{
	struct if_nameindex *ifn = NULL, *p;
	struct ifaddrs *ifap = NULL;
	struct kfacts *k;
	size_t n;
	int i, s, saved;

	if ((k = calloc(1, sizeof(*k))) == NULL)
		return NULL;
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		free(k);
		return NULL;
	}
	if ((ifn = if_nameindex()) == NULL || getifaddrs(&ifap) == -1 ||
	    scan_cloners(s, k) == -1 || scan_groups(s, k) == -1)
		goto fail;
	for (n = 0; ifn[n].if_index != 0; n++)
		;
	if ((k->ifs = calloc(n ? n : 1, sizeof(*k->ifs))) == NULL)
		goto fail;
	for (p = ifn; p->if_index != 0; p++) {
		strlcpy(k->ifs[k->nifs].name, p->if_name, IFNAMSIZ);
		k->ifs[k->nifs].index = p->if_index;
		if (scan_if(s, &k->ifs[k->nifs++], ifap) == -1)
			goto fail;
	}
	for (i = 0; i < (int)sizeof(k->rtables); i++)
		k->rtables[i] = k_rtable(i);
	k->dhcpleased = dhcpleased_is_running();
	freeifaddrs(ifap);
	if_freenameindex(ifn);
	close(s);
	return k;
 fail:
	saved = errno;
	if (ifap != NULL)
		freeifaddrs(ifap);
	if (ifn != NULL)
		if_freenameindex(ifn);
	close(s);
	kfacts_free(k);
	errno = saved;
	return NULL;
}

/* One interface's facts, which has its name; -1 if memory ran out */
static int
scan_if(int s, struct kif *ki, struct ifaddrs *ifap)
{
	struct ieee80211_nwid nwid;
	struct sockaddr_in6 *sin6;
	struct sockaddr_dl *sdl;
	struct ifaddrs *ifa;
	struct if_data ifd;
	struct ifreq ifr;
	StringList *orig;
	uint64_t cur;
	u_char *ea;
	int i, zero;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ki->name, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) == 0)
		ki->flags = ifr.ifr_flags;
	ifr.ifr_data = (caddr_t)&ifd;
	if (ioctl(s, SIOCGIFDATA, (caddr_t)&ifr) == 0) {
		ki->type = ifd.ifi_type;
		ki->caps = ifd.ifi_capabilities;
	}
	ifr.ifr_data = (caddr_t)&nwid;
	ki->wifi = ioctl(s, SIOCG80211NWID, (caddr_t)&ifr) == 0;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, ki->name))
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET6 && !ki->hasll6) {
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
				ki->ll6 = sin6->sin6_addr;
				ki->hasll6 = 1;
			}
		}
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		/* as get_hwdaddr(): Ethernet's or 802.11's, but zero */
		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_alen != ETHER_ADDR_LEN ||
		    (sdl->sdl_type != IFT_ETHER &&
		    sdl->sdl_type != IFT_IEEE80211))
			continue;
		ea = (u_char *)LLADDR(sdl);
		for (zero = 1, i = 0; i < ETHER_ADDR_LEN; i++)
			if (ea[i] != 0)
				zero = 0;
		if (!zero)
			strlcpy(ki->lladdr,
			    ether_ntoa((struct ether_addr *)ea),
			    sizeof(ki->lladdr));
	}
	orig = sl_init();
	if (db_select_flag_x_ctl(orig, "lladdr", ki->name) > 0)
		strlcpy(ki->lladdr, orig->sl_str[0], sizeof(ki->lladdr));
	sl_free(orig, 1);

	if (k_media(s, ki->name, &cur, &ki->medias, &ki->nmedias) == -1) {
		if (errno == ENOMEM)
			return -1;
	} else
		ki->media = cur;
	return 0;
}

/* The kernel's cloners, into k; -1 if it could not say */
static int
scan_cloners(int s, struct kfacts *k)
{
	struct if_clonereq ifcr;
	char *buf;

	memset(&ifcr, 0, sizeof(ifcr));
	if (ioctl(s, SIOCIFGCLONERS, &ifcr) == -1)
		return -1;
	if ((buf = calloc(ifcr.ifcr_total ? ifcr.ifcr_total : 1,
	    IFNAMSIZ)) == NULL)
		return -1;
	ifcr.ifcr_count = ifcr.ifcr_total;
	ifcr.ifcr_buffer = buf;
	if (ioctl(s, SIOCIFGCLONERS, &ifcr) == -1) {
		free(buf);
		return -1;
	}
	if (ifcr.ifcr_count > ifcr.ifcr_total)
		ifcr.ifcr_count = ifcr.ifcr_total;
	k->cloners = (char (*)[IFNAMSIZ])buf;
	k->ncloners = ifcr.ifcr_count;
	return 0;
}

/* Read the kernel's interface groups into k.  Return -1 if that fails. */
static int
scan_groups(int s, struct kfacts *k)
{
	struct ifgroupreq ifgr;
	size_t i, n;

	memset(&ifgr, 0, sizeof(ifgr));
	if (ioctl(s, SIOCGIFGLIST, (caddr_t)&ifgr) == -1)
		return -1;
	if ((ifgr.ifgr_groups = calloc(1, ifgr.ifgr_len ? ifgr.ifgr_len :
	    1)) == NULL)
		return -1;
	if (ioctl(s, SIOCGIFGLIST, (caddr_t)&ifgr) == -1) {
		free(ifgr.ifgr_groups);
		return -1;
	}
	n = ifgr.ifgr_len / sizeof(ifgr.ifgr_groups[0]);
	if ((k->groups = calloc(n ? n : 1, IFNAMSIZ)) == NULL) {
		free(ifgr.ifgr_groups);
		return -1;
	}
	for (i = 0; i < n; i++)
		memcpy(k->groups[i], ifgr.ifgr_groups[i].ifgrq_group,
		    IFNAMSIZ);
	k->ngroups = n;
	free(ifgr.ifgr_groups);
	return 0;
}

void
kfacts_free(struct kfacts *k)
{
	size_t i;

	if (k == NULL)
		return;
	for (i = 0; i < k->nifs; i++)
		free(k->ifs[i].medias);
	free(k->ifs);
	free(k->cloners);
	free(k->groups);
	free(k);
}

/* As facts: what system sends config, and how config reads them */

static const struct facts_field kiffields[] = {
	{ "name",	FACT_STRING },
	{ "index",	FACT_U64 },
	{ "flags",	FACT_U64 },
	{ "type",	FACT_U64 },
	{ "capabilities", FACT_U64 },
	{ "wifi",	FACT_U64 },
	{ "lladdr",	FACT_STRING },
	{ "linklocal",	FACT_ADDRESS },
	{ "media",	FACT_U64 },
};
static const struct facts_kind kind_if = { "kinterface", kiffields,
	nitems(kiffields) };
enum { KIF_NAME, KIF_INDEX, KIF_FLAGS, KIF_TYPE, KIF_CAPS, KIF_WIFI,
	KIF_LLADDR, KIF_LL6, KIF_MEDIA };

static const struct facts_field kmfields[] = {
	{ "interface",	FACT_STRING },
	{ "word",	FACT_U64 },
};
static const struct facts_kind kind_media = { "kmedia", kmfields,
	nitems(kmfields) };

static const struct facts_field kcfields[] = {
	{ "name",	FACT_STRING },
};
static const struct facts_kind kind_cloner = { "kcloner", kcfields,
	nitems(kcfields) };
static const struct facts_kind kind_group = { "kgroup", kcfields,
	nitems(kcfields) };

static const struct facts_field krfields[] = {
	{ "table",	FACT_U64 },
};
static const struct facts_kind kind_rtable = { "krtable", krfields,
	nitems(krfields) };

static const struct facts_field kdfields[] = {
	{ "dhcpleased",	FACT_U64 },
};
static const struct facts_kind kind_daemons = { "kdaemons", kdfields,
	nitems(kdfields) };

/* k, as records to o; -1 if one could not be made */
int
kfacts_emit(struct facts_out *o, struct kfacts *k)
{
	struct facts_value v[nitems(kiffields)];
	struct kif *ki;
	char name[IFNAMSIZ + 1];
	size_t i, j, len;

	for (i = 0; i < k->nifs; i++) {
		ki = &k->ifs[i];
		memset(v, 0, sizeof(v));
		facts_string(&v[KIF_NAME], ki->name);
		facts_u64(&v[KIF_INDEX], ki->index);
		facts_u64(&v[KIF_FLAGS], (uint16_t)ki->flags);
		facts_u64(&v[KIF_TYPE], ki->type);
		facts_u64(&v[KIF_CAPS], ki->caps);
		facts_u64(&v[KIF_WIFI], ki->wifi);
		if (ki->lladdr[0] != '\0')
			facts_string(&v[KIF_LLADDR], ki->lladdr);
		if (ki->hasll6)
			facts_address(&v[KIF_LL6], FACT_INET6, &ki->ll6,
			    sizeof(ki->ll6), 0);
		if (ki->media != 0)
			facts_u64(&v[KIF_MEDIA], ki->media);
		if (facts_record(o, &kind_if, v) == -1)
			return -1;
		for (j = 0; j < ki->nmedias; j++) {
			memset(v, 0, sizeof(v));
			facts_string(&v[0], ki->name);
			facts_u64(&v[1], ki->medias[j]);
			if (facts_record(o, &kind_media, v) == -1)
				return -1;
		}
	}
	for (i = 0; i < k->ncloners; i++) {
		memset(v, 0, sizeof(v));
		len = strnlen(k->cloners[i], IFNAMSIZ);
		memcpy(name, k->cloners[i], len);
		name[len] = '\0';
		facts_string(&v[0], name);
		if (facts_record(o, &kind_cloner, v) == -1)
			return -1;
	}
	for (i = 0; i < k->ngroups; i++) {
		memset(v, 0, sizeof(v));
		len = strnlen(k->groups[i], IFNAMSIZ);
		memcpy(name, k->groups[i], len);
		name[len] = '\0';
		facts_string(&v[0], name);
		if (facts_record(o, &kind_group, v) == -1)
			return -1;
	}
	for (i = 0; i < sizeof(k->rtables); i++) {
		if (!k->rtables[i])
			continue;
		memset(v, 0, sizeof(v));
		facts_u64(&v[0], i);
		if (facts_record(o, &kind_rtable, v) == -1)
			return -1;
	}
	memset(v, 0, sizeof(v));
	facts_u64(&v[0], k->dhcpleased);
	return facts_record(o, &kind_daemons, v);
}

/* A string value into buf, as long as it fits; -1 if it does not */
static int
kf_str(const struct facts_value *v, char *buf, size_t len)
{
	if (v == NULL || v->v.str.len >= len || memchr(v->v.str.s, '\0',
	    v->v.str.len) != NULL)
		return -1;
	memcpy(buf, v->v.str.s, v->v.str.len);
	buf[v->v.str.len] = '\0';
	return 0;
}

/*
 * A record of k's, for facts_in_init(): into the struct kfacts arg,
 * whose failed says one could not be kept, or was not one of these
 */
void
kfacts_record(void *arg, const struct facts_template *t,
    const struct facts_value *v)
{
	struct kfacts *k = arg;
	const struct facts_value *f;
	struct kif *ki;
	char name[IFNAMSIZ];
	int map[nitems(kiffields)];
	uint64_t *l;
	void *p;
	size_t i;

	if (strcmp(t->kind, kind_if.name) == 0) {
		facts_bind(t, &kind_if, map);
		if ((p = reallocarray(k->ifs, k->nifs + 1,
		    sizeof(*k->ifs))) == NULL)
			goto bad;
		k->ifs = p;
		ki = &k->ifs[k->nifs];
		memset(ki, 0, sizeof(*ki));
		if (kf_str(facts_get(v, map, KIF_NAME, FACT_STRING), ki->name,
		    sizeof(ki->name)) == -1)
			goto bad;
		k->nifs++;
		if ((f = facts_get(v, map, KIF_INDEX, FACT_U64)) != NULL)
			ki->index = f->v.u;
		if ((f = facts_get(v, map, KIF_FLAGS, FACT_U64)) != NULL)
			ki->flags = (short)f->v.u;
		if ((f = facts_get(v, map, KIF_TYPE, FACT_U64)) != NULL)
			ki->type = f->v.u;
		if ((f = facts_get(v, map, KIF_CAPS, FACT_U64)) != NULL)
			ki->caps = f->v.u;
		if ((f = facts_get(v, map, KIF_WIFI, FACT_U64)) != NULL)
			ki->wifi = f->v.u != 0;
		if ((f = facts_get(v, map, KIF_LLADDR, FACT_STRING)) != NULL &&
		    kf_str(f, ki->lladdr, sizeof(ki->lladdr)) == -1)
			goto bad;
		if ((f = facts_get(v, map, KIF_LL6, FACT_ADDRESS)) != NULL) {
			if (f->v.a.family != FACT_INET6 ||
			    f->v.a.len != sizeof(ki->ll6))
				goto bad;
			memcpy(&ki->ll6, f->v.a.bytes, sizeof(ki->ll6));
			ki->hasll6 = 1;
		}
		if ((f = facts_get(v, map, KIF_MEDIA, FACT_U64)) != NULL)
			ki->media = f->v.u;
	} else if (strcmp(t->kind, kind_media.name) == 0) {
		facts_bind(t, &kind_media, map);
		if (kf_str(facts_get(v, map, 0, FACT_STRING), name,
		    sizeof(name)) == -1 ||
		    (f = facts_get(v, map, 1, FACT_U64)) == NULL)
			goto bad;
		/* its interface's, which came before it */
		for (i = 0; i < k->nifs; i++)
			if (strcmp(k->ifs[i].name, name) == 0)
				break;
		if (i == k->nifs)
			goto bad;
		ki = &k->ifs[i];
		if ((l = reallocarray(ki->medias, ki->nmedias + 1,
		    sizeof(*l))) == NULL)
			goto bad;
		ki->medias = l;
		ki->medias[ki->nmedias++] = f->v.u;
	} else if (strcmp(t->kind, kind_cloner.name) == 0) {
		facts_bind(t, &kind_cloner, map);
		if (kf_str(facts_get(v, map, 0, FACT_STRING), name,
		    sizeof(name)) == -1)
			goto bad;
		if ((p = reallocarray(k->cloners, k->ncloners + 1,
		    sizeof(*k->cloners))) == NULL)
			goto bad;
		k->cloners = p;
		memcpy(k->cloners[k->ncloners++], name, sizeof(name));
	} else if (strcmp(t->kind, kind_group.name) == 0) {
		facts_bind(t, &kind_group, map);
		if (kf_str(facts_get(v, map, 0, FACT_STRING), name,
		    sizeof(name)) == -1)
			goto bad;
		if ((p = reallocarray(k->groups, k->ngroups + 1,
		    sizeof(*k->groups))) == NULL)
			goto bad;
		k->groups = p;
		memcpy(k->groups[k->ngroups++], name, sizeof(name));
	} else if (strcmp(t->kind, kind_rtable.name) == 0) {
		facts_bind(t, &kind_rtable, map);
		if ((f = facts_get(v, map, 0, FACT_U64)) == NULL ||
		    f->v.u >= sizeof(k->rtables))
			goto bad;
		k->rtables[f->v.u] = 1;
	} else if (strcmp(t->kind, kind_daemons.name) == 0) {
		facts_bind(t, &kind_daemons, map);
		if ((f = facts_get(v, map, 0, FACT_U64)) != NULL)
			k->dhcpleased = f->v.u != 0;
	} else
		goto bad;
	return;
 bad:
	k->failed = 1;
}
