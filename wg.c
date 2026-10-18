/* From: $OpenBSD: ifconfig.c,v 1.430 2020/11/06 21:24:47 kn Exp $	*/

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <net/if_wg.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <stddef.h>
#include <resolv.h>

#include "externs.h"
#include "settings.h"

int	setwgpeer(const char *);
int	setwgpeerep(const char *);
int	setwgpeerdesc(const char *);
int	setwgpeeraip(const char *);
int	setwgpeerpsk(const char *);
int	setwgpeerpka(const char *);
int	setwgport(const char *);

int	setwgkey(const char *);
int	setwgrtable(const char *);

int	unsetwgpeerpsk(void);
int	unsetwgpeerall(void);

int	growwgdata(size_t);
int	ensurewginterface(void);

void	process_wg_commands(char *, int);
int	getwg(int);

void	wgpeerusage(void);
static void wg_quote(FILE *, char *);
static void wg_unquote(char *, char *, size_t);
static int wg_key(const char *, uint8_t *);
static int wg_readaip(const char *, struct wg_aip_io *);
static int wg_sameaip(struct wg_aip_io *, struct wg_aip_io *);
static int wg_set(int, struct wg_data_io *);

/*
 * A wg interface as wg_ioctl_get() would list it: the kernel's, for
 * conf_wg(), or the candidate's in configure private
 */
struct wgifpeer {
	uint8_t			 public[WG_KEY_LEN];
	uint8_t			 psk[WG_KEY_LEN];	/* none if 0 */
	uint16_t		 pka;			/* none if 0 */
	struct sockaddr_storage	 sa;			/* none if AF_UNSPEC */
	char			 descr[IFDESCRSIZE];
	struct wg_aip_io	*aips;			/* in the order given */
	size_t			 naips;
};

struct wgif {
	int			 hasprivate;
	uint8_t			 private[WG_KEY_LEN];
	uint16_t		 port;			/* none if 0 */
	int			 rtable;		/* none if 0 */
	struct wgifpeer		*peers;
	size_t			 npeers;
};

static struct wgifpeer *wgif_peer(struct wgif *, uint8_t *, int);
static void wgif_delpeer(struct wgif *, size_t);
static int wgif_addaip(struct wgifpeer *, struct wg_aip_io *);
static int wgif_aip(struct wgif *, struct wgifpeer *, struct wg_aip_io *);
static void wgif_free(struct wgif *);
static int wgif_kernel(struct wgif *, struct wg_interface_io *);
static int wgif_apply(struct wgif *, struct wg_interface_io *);
static int wgif_line(struct wgif *, char *);
static void wgif_print(FILE *, struct wgif *);
static int cand_setwg(char *, struct wg_interface_io *);
static int cand_wgif(struct wgif *);
static int wgif_get(int, char *, struct wgif *);
static int wgpeer_keepaips(int, char *, struct wg_aip_io *, size_t);

/*
 * WireGuard configuration
 *
 * WG_BASE64_KEY_LEN specifies the size of a base64 encoded WireGuard key.
 * WG_TMP_KEY_LEN specifies the size of a decoded base64 key. For every 4
 * input (base64) bytes, 3 output bytes will be produced. The output will be
 * padded with 0 bits, therefore we need more than the regular 32 bytes of
 * space.
 */
#define WG_BASE64_KEY_LEN (4 * ((WG_KEY_LEN + 2) / 3))
#define WG_TMP_KEY_LEN (WG_BASE64_KEY_LEN / 4 * 3)
#define WG_LOAD_KEY(dst, src, fn_name) do {				\
	uint8_t _tmp[WG_KEY_LEN]; int _r;				\
	if (strlen(src) != WG_BASE64_KEY_LEN) {				\
		printf("%% " fn_name ": invalid length\n");		\
		return -1;						\
	}								\
	if ((_r = b64_pton(src, _tmp, sizeof(_tmp))) != sizeof(_tmp)) {	\
		printf("%% " fn_name ": invalid base64 %d/%zu\n",	\
		    _r, sizeof(_tmp));					\
		return -1;						\
	}								\
	memcpy(dst, _tmp, WG_KEY_LEN);					\
} while (0)

struct wg_data_io	 wgdata = { 0 };
struct wg_interface_io	*wg_interface = NULL;
struct wg_peer_io	*wg_peer = NULL;
struct wg_aip_io	*wg_aip = NULL;

int
ensurewginterface(void)
{
	if (wg_interface != NULL)
		return 0;
	wgdata.wgd_size = sizeof(*wg_interface);
	wgdata.wgd_interface = wg_interface = calloc(1, wgdata.wgd_size);
	if (wg_interface == NULL) {
		printf("%% ensurewginterface: calloc: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int
growwgdata(size_t by)
{
	ptrdiff_t peer_offset, aip_offset;
	struct wg_interface_io	*p;

	if (wg_interface == NULL)
		wgdata.wgd_size = sizeof(*wg_interface);

	peer_offset = (void *)wg_peer - (void *)wg_interface;
	aip_offset = (void *)wg_aip - (void *)wg_interface;

	wgdata.wgd_size += by;
	p = realloc(wg_interface, wgdata.wgd_size);
	if (p == NULL) {
		printf("%% growwgdata: realloc: %s\n", strerror(errno));
		return -1;
	}
	wgdata.wgd_interface = p;
	if (wg_interface == NULL)
		bzero(wgdata.wgd_interface, sizeof(*wg_interface));
	wg_interface = wgdata.wgd_interface;

	if (wg_peer != NULL)
		wg_peer = (void *)wg_interface + peer_offset;
	if (wg_aip != NULL)
		wg_aip = (void *)wg_interface + aip_offset;

	bzero((char *)wg_interface + wgdata.wgd_size - by, by);
	return 0;
}

int
setwgpeer(const char *peerkey_b64)
{
	if (growwgdata(sizeof(*wg_peer)) < 0)
		return -1;
	if (wg_aip)
		wg_peer = (struct wg_peer_io *)wg_aip;
	else
		wg_peer = &wg_interface->i_peers[0];
	wg_aip = &wg_peer->p_aips[0];
	wg_peer->p_flags |= WG_PEER_HAS_PUBLIC;
	WG_LOAD_KEY(wg_peer->p_public, peerkey_b64, "setwgpeer");
	wg_interface->i_peers_count++;
	return 0;
}

 
int
setwgpeerdesc(const char *descr)
{
#ifdef WG_PEER_SET_DESCRIPTION /* OpenBSD 7.4+ */
	if (wg_peer == NULL) {
		printf("%% setwgpeerdesc: wgpeer not set\n");
		return -1;
	}
	wg_peer->p_flags |= WG_PEER_SET_DESCRIPTION;
	strlcpy(wg_peer->p_description, descr, IFDESCRSIZE);
#endif
	return 0;
}

/* An aip as inet_net_pton() reads it */
static int
wg_readaip(const char *s, struct wg_aip_io *a)
{
	int res;

	memset(a, 0, sizeof(*a));
	if ((res = inet_net_pton(AF_INET, s, &a->a_ipv4,
	    sizeof(a->a_ipv4))) != -1)
		a->a_af = AF_INET;
	else if ((res = inet_net_pton(AF_INET6, s, &a->a_ipv6,
	    sizeof(a->a_ipv6))) != -1)
		a->a_af = AF_INET6;
	else
		return -1;
	a->a_cidr = res;
	return 0;
}

int
setwgpeeraip(const char *aip)
{
	if (wg_peer == NULL) {
		printf("%% setwgpeeraip: wgpeer not set\n");
		return -1;
	}

	if (growwgdata(sizeof(*wg_aip)) < 0)
		return -1;

	if (wg_readaip(aip, wg_aip) == -1) {
		printf("%% setwgpeeraip: bad address\n");
		return -1;
	}

	wg_peer->p_flags |= WG_PEER_REPLACE_AIPS;
	wg_peer->p_aips_count++;

	wg_aip++;
	return 0;
}

int
setwgpeerep(const char *hostport)
{
	struct sockaddr_storage ss;

	if (wg_peer == NULL) {
		printf("%% setwgpeerep: wgpeer not set\n");
		return -1;
	}

	if (pflow_addr(hostport, &ss) < 0)
		return -1;

	wg_peer->p_flags |= WG_PEER_HAS_ENDPOINT;
	memcpy(&wg_peer->p_sa, &ss, ss.ss_len);
	return 0;
}

int
setwgpeerpsk(const char *psk_b64)
{
	if (wg_peer == NULL) {
		printf("%% setwgpeerpsk: wgpsk: wgpeer not set\n");
		return -1;
	}
	wg_peer->p_flags |= WG_PEER_HAS_PSK;
	WG_LOAD_KEY(wg_peer->p_psk, psk_b64, "setwgpeerpsk");
	return 0;
}

int
setwgpeerpka(const char *pka)
{
	const char *errmsg = NULL;
	if (wg_peer == NULL) {
		printf("%% setwgpeerpka: wgpeer not set\n");
		return -1;
	}

	/* 43200 == 12h, reasonable for a 16 bit value */
	wg_peer->p_flags |= WG_PEER_HAS_PKA;
	wg_peer->p_pka = strtonum(pka, 0, 43200, &errmsg);
	if (errmsg) {
		printf("%% setwgpeerpka: %s, %s\n", pka, errmsg);
		return -1;
	}
	return 0;
}

int
setwgport(const char *port)
{
	const char *errmsg = NULL;
	if (ensurewginterface() < 0)
		return -1;
	wg_interface->i_flags |= WG_INTERFACE_HAS_PORT;
	wg_interface->i_port = strtonum(port, 0, 65535, &errmsg);
	if (errmsg) {
		printf("%% setwgport: wgport: %s, %s\n", port, errmsg);
		return -1;
	}
	return 0;
}

int
setwgkey(const char *private_b64)
{
	if (ensurewginterface() < 0)
		return -1;
	wg_interface->i_flags |= WG_INTERFACE_HAS_PRIVATE;
	WG_LOAD_KEY(wg_interface->i_private, private_b64, "setwgkey");
	return 0;
}

int
setwgrtable(const char *id)
{
	const char *errmsg = NULL;
	if (ensurewginterface() < 0)
		return -1;
	wg_interface->i_flags |= WG_INTERFACE_HAS_RTABLE;
	wg_interface->i_rtable = strtonum(id, 0, RT_TABLEID_MAX, &errmsg);
	if (errmsg) {
		printf("%% setwgrtable: wgrtable %s: %s\n", id, errmsg);
		return -1;
	}
	return 0;
}

int
unsetwgpeerpsk()
{
	if (wg_peer == NULL) {
		printf("%% unsetwgpeerpsk: wgpeer not set\n");
		return -1;
	}
	wg_peer->p_flags |= WG_PEER_HAS_PSK;
	bzero(wg_peer->p_psk, WG_KEY_LEN);
	return 0;
}

int
unsetwgpeerall()
{
	if (ensurewginterface() < 0)
		return -1;
	wg_interface->i_flags |= WG_INTERFACE_REPLACE_PEERS;
	return 0;
}

int
getwg(int ifs)
{
	int last_size;

	for (last_size = wgdata.wgd_size;; last_size = wgdata.wgd_size) {
		if (ioctl(ifs, SIOCGWG, (caddr_t)&wgdata) < 0) {
			if (errno == ENOTTY)
				return -1;
                        printf("%% getwg: SIOCGWG: %s\n", strerror(errno));
			free(wgdata.wgd_interface);
			return -1;
		}
		if (last_size >= wgdata.wgd_size)
			break;
		wgdata.wgd_interface = realloc(wgdata.wgd_interface,
		    wgdata.wgd_size);
		if (!wgdata.wgd_interface) {
			printf("%% getwg: realloc: %s\n", strerror(errno));
			return -1;
		}
	}
	return 0;
}

void
show_wg(int ifs, char *ifname, FILE *outfile)
{
	int			 i;
	struct timespec		 now;
	char			 key[WG_BASE64_KEY_LEN + 1];

	strlcpy(wgdata.wgd_name, ifname, sizeof(wgdata.wgd_name));
	wgdata.wgd_size = 0;
	wgdata.wgd_interface = NULL;

	if (getwg(ifs) < 0)
		return;
	wg_interface = wgdata.wgd_interface;

	if (wg_interface->i_flags & WG_INTERFACE_HAS_PUBLIC) {
		b64_ntop(wg_interface->i_public, WG_KEY_LEN,
		    key, sizeof(key));
		fprintf(outfile, "  Wireguard publickey %s\n", key);
	}

	wg_peer = &wg_interface->i_peers[0];
	for (i = 0; i < wg_interface->i_peers_count; i++) {
		b64_ntop(wg_peer->p_public, WG_KEY_LEN,
		    key, sizeof(key));
		fprintf(outfile, "  Wireguard peer %s", key);
#ifdef WG_PEER_SET_DESCRIPTION	/* OpenBSD 7.4+ */
		if (strlen(wg_peer->p_description)) {
			printf(" (%s)\n", wg_peer->p_description);
		}
#endif

		if (wg_peer->p_last_handshake.tv_sec != 0) {
			timespec_get(&now, TIME_UTC);
			fprintf(outfile, " last handshake: %lld seconds ago\n",
			    now.tv_sec - wg_peer->p_last_handshake.tv_sec);
		}
		putc('\n', outfile);
	}
	free(wgdata.wgd_interface);
}

/* A description, quoted as makeargv() reads it back */
static void
wg_quote(FILE *output, char *s)
{
	if (strpbrk(s, " \t\"'\\") == NULL)
		fprintf(output, "%s", s);
	else if (strchr(s, '"') == NULL)
		fprintf(output, "\"%s\"", s);
	else
		for (; *s != '\0'; s++)
			fprintf(output, "%s%c",
			    strchr(" \t\"'\\", *s) != NULL ? "\\" : "", *s);
}

/* A description as wg_quote() wrote it */
static void
wg_unquote(char *s, char *d, size_t len)
{
	size_t n = strlen(s);

	if (n >= 2 && s[0] == '"' && s[n - 1] == '"') {
		s[n - 1] = '\0';
		strlcpy(d, s + 1, len);
		return;
	}
	for (; *s != '\0' && len > 1; s++, len--) {
		if (*s == '\\' && s[1] != '\0')
			s++;
		*d++ = *s;
	}
	*d = '\0';
}

static int
wg_key(const char *b64, uint8_t *key)
{
	WG_LOAD_KEY(key, b64, "wg_key");
	return 0;
}

/* Do a and b name one prefix, as the kernel's aip table finds them? */
static int
wg_sameaip(struct wg_aip_io *a, struct wg_aip_io *b)
{
	uint8_t *x = (uint8_t *)&a->a_addr, *y = (uint8_t *)&b->a_addr;
	int n = a->a_cidr;

	if (a->a_af != b->a_af || a->a_cidr != b->a_cidr ||
	    memcmp(x, y, n / 8) != 0)
		return 0;
	return n % 8 == 0 || ((x[n / 8] ^ y[n / 8]) & 0xff << (8 - n % 8)) == 0;
}

/* w's peer with public key public, added last if add and w has none */
static struct wgifpeer *
wgif_peer(struct wgif *w, uint8_t *public, int add)
{
	struct wgifpeer *p;
	size_t i;

	for (i = 0; i < w->npeers; i++)
		if (memcmp(w->peers[i].public, public, WG_KEY_LEN) == 0)
			return &w->peers[i];
	if (!add)
		return NULL;
	if ((p = reallocarray(w->peers, w->npeers + 1, sizeof(*p))) == NULL) {
		printf("%% wgif_peer: %s\n", strerror(errno));
		return NULL;
	}
	w->peers = p;
	p = &w->peers[w->npeers++];
	memset(p, 0, sizeof(*p));
	memcpy(p->public, public, WG_KEY_LEN);
	return p;
}

static void
wgif_delpeer(struct wgif *w, size_t i)
{
	free(w->peers[i].aips);
	memmove(&w->peers[i], &w->peers[i + 1],
	    (w->npeers - i - 1) * sizeof(*w->peers));
	w->npeers--;
}

static int
wgif_addaip(struct wgifpeer *p, struct wg_aip_io *a)
{
	struct wg_aip_io *aips;

	aips = reallocarray(p->aips, p->naips + 1, sizeof(*aips));
	if (aips == NULL) {
		printf("%% wgif_addaip: %s\n", strerror(errno));
		return -1;
	}
	p->aips = aips;
	p->aips[p->naips++] = *a;
	return 0;
}

/*
 * wg_aip_add(): a prefix is one peer's aip, and given to another peer
 * it moves there, as it was first given
 */
static int
wgif_aip(struct wgif *w, struct wgifpeer *p, struct wg_aip_io *a)
{
	struct wgifpeer *q;
	struct wg_aip_io b;
	size_t i, j;

	for (i = 0; i < w->npeers; i++) {
		q = &w->peers[i];
		for (j = 0; j < q->naips; j++) {
			if (!wg_sameaip(&q->aips[j], a))
				continue;
			if (q == p)
				return 0;
			b = q->aips[j];
			memmove(&q->aips[j], &q->aips[j + 1],
			    (q->naips - j - 1) * sizeof(*q->aips));
			q->naips--;
			return wgif_addaip(p, &b);
		}
	}
	return wgif_addaip(p, a);
}

static void
wgif_free(struct wgif *w)
{
	size_t i;

	for (i = 0; i < w->npeers; i++)
		free(w->peers[i].aips);
	free(w->peers);
	memset(w, 0, sizeof(*w));
}

/* w from what SIOCGWG listed */
static int
wgif_kernel(struct wgif *w, struct wg_interface_io *wi)
{
	struct wg_peer_io *p = &wi->i_peers[0];
	struct wgifpeer *wp;
	size_t i, j;

	memset(w, 0, sizeof(*w));
	if (wi->i_flags & WG_INTERFACE_HAS_PORT)
		w->port = wi->i_port;
	if (wi->i_flags & WG_INTERFACE_HAS_RTABLE)
		w->rtable = wi->i_rtable;
	if (wi->i_flags & WG_INTERFACE_HAS_PRIVATE) {
		w->hasprivate = 1;
		memcpy(w->private, wi->i_private, WG_KEY_LEN);
	}
	for (i = 0; i < wi->i_peers_count; i++) {
		if ((wp = wgif_peer(w, p->p_public, 1)) == NULL)
			return -1;
		if (p->p_flags & WG_PEER_HAS_PSK)
			memcpy(wp->psk, p->p_psk, WG_KEY_LEN);
		if (p->p_flags & WG_PEER_HAS_PKA)
			wp->pka = p->p_pka;
		if (p->p_flags & WG_PEER_HAS_ENDPOINT)
			memcpy(&wp->sa, &p->p_sa, p->p_sa.sa_len);
#ifdef WG_PEER_SET_DESCRIPTION	/* OpenBSD 7.4+ */
		strlcpy(wp->descr, p->p_description, sizeof(wp->descr));
#endif
		/* the kernel lists the last aip given first */
		for (j = p->p_aips_count; j-- > 0; )
			if (wgif_addaip(wp, &p->p_aips[j]) == -1)
				return -1;
		p = (struct wg_peer_io *)&p->p_aips[p->p_aips_count];
	}
	return 0;
}

/*
 * What wg_ioctl_set() makes of w and wi. The kernel also drops a peer
 * whose public key is the interface's own, which needs curve25519.
 */
static int
wgif_apply(struct wgif *w, struct wg_interface_io *wi)
{
	struct wg_peer_io *p = &wi->i_peers[0];
	struct wgifpeer *wp;
	size_t i, j;

	if (wi->i_flags & WG_INTERFACE_REPLACE_PEERS)
		while (w->npeers > 0)
			wgif_delpeer(w, 0);
	if (wi->i_flags & WG_INTERFACE_HAS_PRIVATE) {
		w->hasprivate = 1;
		memcpy(w->private, wi->i_private, WG_KEY_LEN);
		/* noise_local_set_private() keeps it clamped */
		w->private[0] &= 248;
		w->private[31] = (w->private[31] & 127) | 64;
	}
	if (wi->i_flags & WG_INTERFACE_HAS_PORT)
		w->port = wi->i_port;
	if (wi->i_flags & WG_INTERFACE_HAS_RTABLE)
		w->rtable = wi->i_rtable;

	for (i = 0; i < wi->i_peers_count;
	    i++, p = (struct wg_peer_io *)&p->p_aips[p->p_aips_count]) {
		if (!(p->p_flags & WG_PEER_HAS_PUBLIC))
			continue;
		if ((wp = wgif_peer(w, p->p_public, 0)) == NULL) {
			if (p->p_flags & (WG_PEER_REMOVE | WG_PEER_UPDATE))
				continue;
			if ((wp = wgif_peer(w, p->p_public, 1)) == NULL)
				return -1;
		}
		if (p->p_flags & WG_PEER_REMOVE) {
			wgif_delpeer(w, wp - w->peers);
			continue;
		}
		if (p->p_flags & WG_PEER_HAS_ENDPOINT) {
			/* whole, so AF_UNSPEC takes it away */
			memset(&wp->sa, 0, sizeof(wp->sa));
			memcpy(&wp->sa, &p->p_sin6, sizeof(p->p_sin6));
		}
		if (p->p_flags & WG_PEER_HAS_PSK)
			memcpy(wp->psk, p->p_psk, WG_KEY_LEN);
		if (p->p_flags & WG_PEER_HAS_PKA)
			wp->pka = p->p_pka;
		if (p->p_flags & WG_PEER_REPLACE_AIPS)
			wp->naips = 0;
#ifdef WG_PEER_SET_DESCRIPTION
		if (p->p_flags & WG_PEER_SET_DESCRIPTION)
			strlcpy(wp->descr, p->p_description, sizeof(wp->descr));
#endif
		for (j = 0; j < p->p_aips_count; j++)
			if (wgif_aip(w, wp, &p->p_aips[j]) == -1)
				return -1;
	}
	return 0;
}

/* Read one of wgif_print()'s lines into w */
static int
wgif_line(struct wgif *w, char *line)
{
	char buf[1024], *p, *word, *val;
	uint8_t key[WG_KEY_LEN];
	struct wgifpeer *wp;
	struct wg_aip_io a;
	const char *errmsg;

	if (strlcpy(buf, line, sizeof(buf)) >= sizeof(buf))
		return -1;
	p = buf;
	word = strsep(&p, " ");
	if (p == NULL)
		return -1;
	if (strcmp(word, "wgport") == 0) {
		w->port = strtonum(p, 0, 65535, &errmsg);
		return errmsg ? -1 : 0;
	}
	if (strcmp(word, "wgrtable") == 0) {
		w->rtable = strtonum(p, 0, RT_TABLEID_MAX, &errmsg);
		return errmsg ? -1 : 0;
	}
	if (strcmp(word, "wgkey") == 0) {
		w->hasprivate = 1;
		return wg_key(p, w->private);
	}
	if (wg_key(strsep(&p, " "), key) == -1 ||
	    (wp = wgif_peer(w, key, 1)) == NULL)
		return -1;
	while ((word = strsep(&p, " ")) != NULL) {
		if (p == NULL)
			return -1;
		if (strcmp(word, "description") == 0) {
			wg_unquote(p, wp->descr, sizeof(wp->descr));
			break;
		}
		val = strsep(&p, " ");
		if (strcmp(word, "psk") == 0) {
			if (wg_key(val, wp->psk) == -1)
				return -1;
		} else if (strcmp(word, "pka") == 0) {
			wp->pka = strtonum(val, 0, 43200, &errmsg);
			if (errmsg)
				return -1;
		} else if (strcmp(word, "endpoint") == 0) {
			if (pflow_addr(val, &wp->sa) == -1)
				return -1;
		} else if (strcmp(word, "aip") == 0) {
			if (wg_readaip(val, &a) == -1 ||
			    wgif_addaip(wp, &a) == -1)
				return -1;
		} else
			return -1;
	}
	return 0;
}

/* conf_wg()'s lines for w */
static void
wgif_print(FILE *output, struct wgif *w)
{
	static const uint8_t	 zero[WG_KEY_LEN];
	struct wgifpeer		*p;
	size_t			 i, j;
	char			 hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	char			 key[WG_BASE64_KEY_LEN + 1],psk[WG_BASE64_KEY_LEN + 1];

	if (w->port)
		fprintf(output, " wgport %hu\n", w->port);
	if (w->rtable)
		fprintf(output, " wgrtable %d\n", w->rtable);
	if (w->hasprivate) {
		b64_ntop(w->private, WG_KEY_LEN, key, sizeof(key));
		fprintf(output, " wgkey %s\n", key);
	}

	for (i = 0; i < w->npeers; i++) {
		p = &w->peers[i];
		b64_ntop(p->public, WG_KEY_LEN, key, sizeof(key));
		if (memcmp(p->psk, zero, WG_KEY_LEN) == 0 && p->pka == 0 &&
		    p->sa.ss_family == AF_UNSPEC && p->descr[0] == '\0' &&
		    p->naips == 0)
			fprintf(output, " wgpeer %s\n", key);

		if (p->descr[0] != '\0') {
			fprintf(output, " wgpeer %s description ", key);
			wg_quote(output, p->descr);
			fprintf(output, "\n");
		}

		if (memcmp(p->psk, zero, WG_KEY_LEN) != 0) {
			b64_ntop(p->psk, WG_KEY_LEN, psk, sizeof(psk));
			fprintf(output, " wgpeer %s psk %s\n", key, psk);
		}

		if (p->pka)
			fprintf(output, " wgpeer %s pka %u\n", key, p->pka);

		if (p->sa.ss_family != AF_UNSPEC) {
			if (getnameinfo((struct sockaddr *)&p->sa, p->sa.ss_len,
			    hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
			    NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
				if (p->sa.ss_family == AF_INET6)
					fprintf(output, " wgpeer %s endpoint [%s]:%s\n", key, hbuf, sbuf);
				else
					fprintf(output, " wgpeer %s endpoint %s:%s\n", key, hbuf, sbuf);
			} else {
				printf("%% conf_wg: wgendpoint unable to print\n");
			}
		}

		if (p->naips)
			fprintf(output, " wgpeer %s", key);
		for (j = 0; j < p->naips; j++) {
			inet_ntop(p->aips[j].a_af, &p->aips[j].a_addr,
			    hbuf, sizeof(hbuf));
			fprintf(output, " aip %s/%d", hbuf, p->aips[j].a_cidr);
		}
		if (p->naips)
			fprintf(output, "\n");
	}
}

void
conf_wg(FILE *output, int ifs, char *ifname)
{
	struct wgif w;

	strlcpy(wgdata.wgd_name, ifname, sizeof(wgdata.wgd_name));
	wgdata.wgd_size = 0;
	wgdata.wgd_interface = NULL;

	if (getwg(ifs) < 0)
		return;
	if (wgif_kernel(&w, wgdata.wgd_interface) == 0)
		wgif_print(output, &w);
	wgif_free(&w);
	free(wgdata.wgd_interface);
}

/* The names of the lines conf_wg() prints */
static char *wg_names[] = { "wgport", "wgrtable", "wgkey", "wgpeer" };

/*
 * SIOCSWG in configure private: the interface's wg lines become what
 * conf_wg() would print once the kernel had made the change
 */
static int
cand_setwg(char *name, struct wg_interface_io *wi)
{
	struct wgif w;
	char *buf = NULL;
	size_t len;
	FILE *f;
	int ret = -1;

	if (!cand_takes(name, SIOCSWG)) {
		errno = ENOTTY;
		return -1;
	}
	if (cand_wgif(&w) == -1)
		goto done;
	if (wgif_apply(&w, wi) == -1)
		goto done;
	if ((f = open_memstream(&buf, &len)) == NULL)
		goto done;
	wgif_print(f, &w);
	if (fclose(f) == EOF)
		goto done;
	ret = cand_putlines(wg_names, nitems(wg_names), buf);
done:
	free(buf);
	wgif_free(&w);
	return ret;
}

/* w from the candidate's wg lines for the current interface */
static int
cand_wgif(struct wgif *w)
{
	char *l;
	size_t i, n;

	memset(w, 0, sizeof(*w));
	for (i = 0; i < nitems(wg_names); i++)
		for (n = 0; (l = cand_line(wg_names[i], n)) != NULL; n++)
			if (wgif_line(w, l) == -1) {
				printf("%% cand_wgif: cannot read \"%s\"\n", l);
				errno = EINVAL;
				return -1;
			}
	return 0;
}

/*
 * w from ifname's wg interface, the kernel's, or in configure private
 * the candidate's; the request wgdata holds is kept
 */
static int
wgif_get(int ifs, char *ifname, struct wgif *w)
{
	struct wg_data_io req = wgdata;
	int ret = -1;

	if (candidate)
		return cand_wgif(w);
	memset(w, 0, sizeof(*w));
	strlcpy(wgdata.wgd_name, ifname, sizeof(wgdata.wgd_name));
	wgdata.wgd_size = 0;
	wgdata.wgd_interface = NULL;
	if (getwg(ifs) == 0) {
		ret = wgif_kernel(w, wgdata.wgd_interface);
		free(wgdata.wgd_interface);
	}
	wgdata = req;
	return ret;
}

/*
 * The aips of the request's peer: those it has but drop's.  The kernel
 * takes a peer's aips away only all at once, and no wgpeer names some.
 */
static int
wgpeer_keepaips(int ifs, char *ifname, struct wg_aip_io *drop, size_t ndrop)
{
	struct wgifpeer *p;
	struct wgif w;
	size_t i, j;
	int ret = 0;

	if (wgif_get(ifs, ifname, &w) == -1)
		return -1;
	wg_peer->p_flags |= WG_PEER_REPLACE_AIPS;
	if ((p = wgif_peer(&w, wg_peer->p_public, 0)) != NULL)
		for (i = 0; ret == 0 && i < p->naips; i++) {
			for (j = 0; j < ndrop; j++)
				if (wg_sameaip(&p->aips[i], &drop[j]))
					break;
			if (j < ndrop)
				continue;
			if ((ret = growwgdata(sizeof(*wg_aip))) == 0) {
				*wg_aip++ = p->aips[i];
				wg_peer->p_aips_count++;
			}
		}
	wgif_free(&w);
	return ret;
}

/* SIOCSWG, or in configure private its change to the candidate */
static int
wg_set(int ifs, struct wg_data_io *wgd)
{
	if (candidate)
		return cand_setwg(wgd->wgd_name, wgd->wgd_interface);
	return ioctl(ifs, SIOCSWG, (caddr_t)wgd);
}

#define WGPEER 1
#define WGPORT 2
#define WGKEY 3
#define WGRTABLE 4

static struct wgc {
        char *name;
        char *descr;
        int type;
} wgcs[] = {
	{ "wgport",	"local port",	WGPORT },
	{ "wgkey",	"private key",	WGKEY },
	{ "wgrtable",	"rtable",	WGRTABLE },
	{ 0,		0,		0 }
};

int
intwg(int argc, char **argv, ...)
{
	int set;
	struct wgc *x;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	/* freshen up at the NULL basin */
        wgdata.wgd_size = 0;
        wgdata.wgd_interface = wg_interface = NULL;
	wg_aip = NULL;
	wg_peer = NULL;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
 	} else
  		set = 1;

	x=(struct wgc *) genget(argv[0], (char **)wgcs, sizeof(struct wgc));
	if (x == 0) {
		printf("%% intwg: Internal error - Invalid argument %s\n", argv[0]);
		return 0;
	} else if (Ambiguous(x)) {
		printf("%% intwg: Internal error - Ambiguous argument %s\n", argv[0]);
		return 0;
 	}

	argc--;
	argv++;

	if ((!set && argc > 1) || (x->type != WGKEY && set && argc != 1) ||
	    (x->type == WGKEY && argc > 1)) {
		printf("%% %s <%s>\n", x->name, x->descr);
		if (x->type != WGKEY)
			printf("%% no %s [%s]\n", x->name, x->descr);
		return 0;
	}

	/* SIOCSWG sets a private key, and nothing takes one away */
	if (x->type == WGKEY && !set) {
		printf("%% The private key of %s cannot be removed\n", ifname);
		return 0;
	}

	switch(x->type) {
	case WGPORT:
		if (setwgport(set ? argv[0] : "0") < 0)
			goto wgerr;
		break;

	case WGKEY:
		if (argc == 1) {
			if (setwgkey(argv[0]) < 0)
				goto wgerr;
		} else {
			uint8_t key[WG_KEY_LEN];
			char keyb64[WG_BASE64_KEY_LEN+1];

			printf("%% Using randomly generated private key for %s\n", ifname);

			arc4random_buf(key, WG_KEY_LEN);
			/* we encode just to instantly decode, unroll setwgkey? */
			b64_ntop(key, WG_KEY_LEN, keyb64, WG_BASE64_KEY_LEN+1);

			if (setwgkey(keyb64) < 0)
				goto wgerr;
		}
		break;

	case WGRTABLE:
		if (setwgrtable(set ? argv[0] : "0") < 0)
			goto wgerr;
		break;
	}

	strlcpy(wgdata.wgd_name, ifname, sizeof(wgdata.wgd_name));

	if (wg_set(ifs, &wgdata) == -1)
		printf("%% intwg: SIOCSWG: %s\n", strerror(errno));
wgerr:
	free(wgdata.wgd_interface);
        wgdata.wgd_size = 0;

	return 0;
}

void
wgpeerusage(void)
{
	printf("%% wgpeer <public key>\n");
#ifdef WG_PEER_SET_DESCRIPTION
	printf("%% wgpeer <public key> description <description> ...\n");
#endif
	printf("%% wgpeer <public key> endpoint <endpoint ip:port> ...\n");
	printf("%% wgpeer <public key> endpoint <[endpoint ipv6]:port> ...\n");
	printf("%% wgpeer <public key> aip <allowed ip/prefix> ...\n");
	printf("%% wgpeer <public key> psk <pre-shared key> ...\n");
	printf("%% wgpeer <public key> pka <interval> ...\n");
	printf("%% no wgpeer [public key]\n");
	printf("%% no wgpeer <public key> description|endpoint|aip|psk|pka"
	    " [value] ...\n");
}

int
intwgpeer(int argc, char **argv, ...)
{
	struct wg_aip_io *drop = NULL, *d;
	size_t ndrop = 0;
	int set, ch;
	va_list ap;
	char *ifname;
	int ifs;

	va_start(ap, argv);
	ifname = va_arg(ap, char *);
	ifs = va_arg(ap, int);
	va_end(ap);

	/* command options for 'wgpeer' */
	static struct nopts wgpeeropts[] = {
		{ "endpoint",	req_arg,	'e' },
		{ "aip",	req_arg,	'a' },
		{ "psk",	req_arg,	'p' },
		{ "pka",	req_arg,	'k' },
#ifdef WG_PEER_SET_DESCRIPTION
		{ "description", req_arg,	'd' },
#endif
		{ NULL,		0,		0 }
	};

        /* freshen up at the NULL basin */
        wgdata.wgd_size = 0;
        wgdata.wgd_interface = wg_interface = NULL;
        wg_aip = NULL;
        wg_peer = NULL;

	if (NO_ARG(argv[0])) {
		set = 0;
		argc--;
		argv++;
	} else
		set = 1;

	argc--;
	argv++;

	/* usage or 'no wgpeer' to unset all */
	if (argc == 0) {
		if (set) {
			wgpeerusage();
			return 0;
		} else {
			if (unsetwgpeerall() < 0)
				goto wgerr;
		}
	}

	/* handle peer public key first */
	if (argc >= 1) {
		if (setwgpeer(argv[0]) < 0)
			goto wgerr;

		if (!set && argc == 1)
			wg_peer->p_flags |= WG_PEER_REMOVE;
		else if (!set)
			/* change a peer, never add one */
			wg_peer->p_flags |= WG_PEER_UPDATE;

		/* hide public key from nopt */
		argc--;
		argv++;
	}

	/* parse wgpeer opts */
	noptind = 0;
	while ((ch = nopt(argc, argv, wgpeeropts)) != -1)
		switch (ch) {
		case 'e':	/* endpoint */
			if (!set) {
				/* AF_UNSPEC: wg_peer_get_sockaddr() has none */
				wg_peer->p_flags |= WG_PEER_HAS_ENDPOINT;
				bzero(&wg_peer->p_sin6, sizeof(wg_peer->p_sin6));
				break;
			}
			if (setwgpeerep(argv[noptind - 1]) < 0)
				goto wgerr;
			break;
		case 'a':	/* aip */
			if (!set) {
				d = reallocarray(drop, ndrop + 1, sizeof(*drop));
				if (d == NULL) {
					printf("%% intwgpeer: %s\n",
					    strerror(errno));
					goto wgerr;
				}
				drop = d;
				if (wg_readaip(argv[noptind - 1],
				    &drop[ndrop++]) == -1) {
					printf("%% intwgpeer: bad address\n");
					goto wgerr;
				}
				break;
			}
			if (setwgpeeraip(argv[noptind - 1]) < 0)
				goto wgerr;
			break;
		case 'p':	/* psk */
			if (set &&
			    setwgpeerpsk(argv[noptind - 1]) < 0) {
				goto wgerr;
			} else if (!set) {
			    if (unsetwgpeerpsk() < 0)
				goto wgerr;
			}
			break;
		case 'k':	/* pka */
			if (setwgpeerpka(set ? argv[noptind - 1] : "0") < 0)
				goto wgerr;
			break;
#ifdef WG_PEER_SET_DESCRIPTION
		case 'd':	/* description */
			if (setwgpeerdesc(set ? argv[noptind - 1] : "") < 0)
				goto wgerr;
			break;
#endif
		default:
			printf("%% intwgpeer: nopt table error\n");
			return 0;
		}

	if (argc - noptind != 0) {
		/* leftover salmon */
		printf("%% %s", nopterr);
		if (argv[noptind])
			printf(": %s", argv[noptind]);
		printf("\n");
		wgpeerusage();
		goto wgerr;
	}

	/* no wgpeer takes what wgpeer does, and takes those away */
	if (ndrop > 0 && wgpeer_keepaips(ifs, ifname, drop, ndrop) == -1)
		goto wgerr;

	strlcpy(wgdata.wgd_name, ifname, sizeof(wgdata.wgd_name));

	if (wg_set(ifs, &wgdata) == -1)
		printf("%% intwgpeer: SIOCSWG: %s\n", strerror(errno));
wgerr:
	free(drop);
	free(wgdata.wgd_interface);
	wgdata.wgd_size = 0;

	return 0;
}
