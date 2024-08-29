/* From: $OpenBSD: ifconfig.c,v 1.430 2020/11/06 21:24:47 kn Exp $	*/

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
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
		return(-1);						\
	}								\
	if ((_r = b64_pton(src, _tmp, sizeof(_tmp))) != sizeof(_tmp)) {	\
		printf("%% " fn_name ": invalid base64 %d/%zu\n",	\
		    _r, sizeof(_tmp));					\
		return(-1);						\
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
		return(0);
	wgdata.wgd_size = sizeof(*wg_interface);
	wgdata.wgd_interface = wg_interface = calloc(1, wgdata.wgd_size);
	if (wg_interface == NULL) {
		printf("%% ensurewginterface: calloc: %s\n", strerror(errno));
		return(-1);
	}
	return(0);
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
		return(-1);
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
	return(0);
}

int
setwgpeer(const char *peerkey_b64)
{
	if (growwgdata(sizeof(*wg_peer)) < 0)
		return(-1);
	if (wg_aip)
		wg_peer = (struct wg_peer_io *)wg_aip;
	else
		wg_peer = &wg_interface->i_peers[0];
	wg_aip = &wg_peer->p_aips[0];
	wg_peer->p_flags |= WG_PEER_HAS_PUBLIC;
	WG_LOAD_KEY(wg_peer->p_public, peerkey_b64, "setwgpeer");
	wg_interface->i_peers_count++;
	return(0);
}

 
int
setwgpeerdesc(const char *descr)
{
#ifdef WG_PEER_SET_DESCRIPTION /* OpenBSD 7.4+ */
	if (wg_peer == NULL) {
		printf("%% setwgpeerdesc: wgpeer not set\n");
		return(-1);
	}
	wg_peer->p_flags |= WG_PEER_SET_DESCRIPTION;
	strlcpy(wg_peer->p_description, descr, IFDESCRSIZE);
#endif
	return(0);
}

int
setwgpeeraip(const char *aip)
{
	int res;
	if (wg_peer == NULL) {
		printf("%% setwgpeeraip: wgpeer not set\n");
		return(-1);
	}

	if (growwgdata(sizeof(*wg_aip)) < 0)
		return(-1);

	if ((res = inet_net_pton(AF_INET, aip, &wg_aip->a_ipv4,
	    sizeof(wg_aip->a_ipv4))) != -1) {
		wg_aip->a_af = AF_INET;
	} else if ((res = inet_net_pton(AF_INET6, aip, &wg_aip->a_ipv6,
	    sizeof(wg_aip->a_ipv6))) != -1) {
		wg_aip->a_af = AF_INET6;
	} else {
		printf("%% setwgpeeraip: bad address\n");
		return(-1);
	}

	wg_aip->a_cidr = res;

	wg_peer->p_flags |= WG_PEER_REPLACE_AIPS;
	wg_peer->p_aips_count++;

	wg_aip++;
	return(0);
}

int
setwgpeerep(const char *hostport)
{
	struct sockaddr_storage ss;

	if (wg_peer == NULL) {
		printf("%% setwgpeerep: wgpeer not set\n");
		return(-1);
	}

	if (pflow_addr(hostport, &ss) < 0)
		return(-1);

	wg_peer->p_flags |= WG_PEER_HAS_ENDPOINT;
	memcpy(&wg_peer->p_sa, &ss, ss.ss_len);
	return(0);
}

int
setwgpeerpsk(const char *psk_b64)
{
	if (wg_peer == NULL) {
		printf("%% setwgpeerpsk: wgpsk: wgpeer not set\n");
		return(-1);
	}
	wg_peer->p_flags |= WG_PEER_HAS_PSK;
	WG_LOAD_KEY(wg_peer->p_psk, psk_b64, "setwgpeerpsk");
	return(0);
}

int
setwgpeerpka(const char *pka)
{
	const char *errmsg = NULL;
	if (wg_peer == NULL) {
		printf("%% setwgpeerpka: wgpeer not set\n");
		return(-1);
	}

	/* 43200 == 12h, reasonable for a 16 bit value */
	wg_peer->p_flags |= WG_PEER_HAS_PKA;
	wg_peer->p_pka = strtonum(pka, 0, 43200, &errmsg);
	if (errmsg) {
		printf("%% setwgpeerpka: %s, %s\n", pka, errmsg);
		return(-1);
	}
	return(0);
}

int
setwgport(const char *port)
{
	const char *errmsg = NULL;
	if (ensurewginterface() < 0)
		return(-1);
	wg_interface->i_flags |= WG_INTERFACE_HAS_PORT;
	wg_interface->i_port = strtonum(port, 0, 65535, &errmsg);
	if (errmsg) {
		printf("%% setwgport: wgport: %s, %s\n", port, errmsg);
		return(-1);
	}
	return(0);
}

int
setwgkey(const char *private_b64)
{
	if (ensurewginterface() < 0)
		return(-1);
	wg_interface->i_flags |= WG_INTERFACE_HAS_PRIVATE;
	WG_LOAD_KEY(wg_interface->i_private, private_b64, "setwgkey");
	return(0);
}

int
setwgrtable(const char *id)
{
	const char *errmsg = NULL;
	if (ensurewginterface() < 0)
		return(-1);
	wg_interface->i_flags |= WG_INTERFACE_HAS_RTABLE;
	wg_interface->i_rtable = strtonum(id, 0, RT_TABLEID_MAX, &errmsg);
	if (errmsg) {
		printf("%% setwgrtable: wgrtable %s: %s\n", id, errmsg);
		return(-1);
	}
	return(0);
}

int
unsetwgpeerpsk()
{
	if (wg_peer == NULL) {
		printf("%% unsetwgpeerpsk: wgpeer not set\n");
		return(-1);
	}
	wg_peer->p_flags |= WG_PEER_HAS_PSK;
	bzero(wg_peer->p_psk, WG_KEY_LEN);
	return(0);
}

int
unsetwgpeerall()
{
	if (ensurewginterface() < 0)
		return(-1);
	wg_interface->i_flags |= WG_INTERFACE_REPLACE_PEERS;
	return(0);
}

int
getwg(int ifs)
{
	int last_size;

	for (last_size = wgdata.wgd_size;; last_size = wgdata.wgd_size) {
		if (ioctl(ifs, SIOCGWG, (caddr_t)&wgdata) < 0) {
			if (errno == ENOTTY)
				return(-1);
                        printf("%% getwg: SIOCGWG: %s\n", strerror(errno));
			free(wgdata.wgd_interface);
			return(-1);
		}
		if (last_size >= wgdata.wgd_size)
			break;
		wgdata.wgd_interface = realloc(wgdata.wgd_interface,
		    wgdata.wgd_size);
		if (!wgdata.wgd_interface) {
			printf("%% getwg: realloc: %s\n", strerror(errno));
			return(-1);
		}
	}
	return(0);
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

void
conf_wg(FILE *output, int ifs, char *ifname)
{
	size_t			 i, j;
	char			 hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	char			 key[WG_BASE64_KEY_LEN + 1],psk[WG_BASE64_KEY_LEN + 1];

	strlcpy(wgdata.wgd_name, ifname, sizeof(wgdata.wgd_name));
	wgdata.wgd_size = 0;
	wgdata.wgd_interface = NULL;

	if (getwg(ifs) < 0)
		return;
	wg_interface = wgdata.wgd_interface;

	if (wg_interface->i_flags & WG_INTERFACE_HAS_PORT)
		fprintf(output, " wgport %hu\n", wg_interface->i_port);
	if (wg_interface->i_flags & WG_INTERFACE_HAS_RTABLE)
		fprintf(output, " wgrtable %d\n", wg_interface->i_rtable);
	if (wg_interface->i_flags & WG_INTERFACE_HAS_PRIVATE) {
		b64_ntop(wg_interface->i_private, WG_KEY_LEN,
		    key, sizeof(key));
		fprintf(output, " wgkey %s\n", key);
	}

	wg_peer = &wg_interface->i_peers[0];
	for (i = 0; i < wg_interface->i_peers_count; i++) {
		b64_ntop(wg_peer->p_public, WG_KEY_LEN,
		    key, sizeof(key));
		if (!(wg_peer->p_flags & WG_PEER_HAS_PSK) &&
		    !(wg_peer->p_flags & WG_PEER_HAS_PKA) &&
		    !(wg_peer->p_flags & WG_PEER_HAS_ENDPOINT) &&
#ifdef WG_PEER_SET_DESCRIPTION	/* OpenBSD 7.4+ */
		    !(strlen(wg_peer->p_description)) &&
#endif
		    (wg_peer->p_aips_count == 0))
			fprintf(output, " wgpeer %s\n", key);

#ifdef WG_PEER_SET_DESCRIPTION
		if (strlen(wg_peer->p_description)) {
			fprintf(output, " wgpeer %s description %s\n", key, wg_peer->p_description);
		}
#endif

		if (wg_peer->p_flags & WG_PEER_HAS_PSK) {
			b64_ntop(wg_peer->p_psk, WG_KEY_LEN, psk,
			    sizeof(psk));
			fprintf(output, " wgpeer %s psk %s\n", key, psk);
		}

		if (wg_peer->p_flags & WG_PEER_HAS_PKA && wg_peer->p_pka)
			fprintf(output, " wgpeer %s pka %u\n", key, wg_peer->p_pka);

		if (wg_peer->p_flags & WG_PEER_HAS_ENDPOINT) {
			if (getnameinfo(&wg_peer->p_sa, wg_peer->p_sa.sa_len,
			    hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
			    NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
				if (wg_peer->p_sa.sa_family == AF_INET6)
					fprintf(output, " wgpeer %s endpoint [%s]:%s\n", key, hbuf, sbuf);
				else
					fprintf(output, " wgpeer %s endpoint %s:%s\n", key, hbuf, sbuf);
			} else {
				printf("%% conf_wg: wgendpoint unable to print\n");
			}
		}

		wg_aip = &wg_peer->p_aips[0];
		if (wg_peer->p_aips_count)
			fprintf(output, " wgpeer %s", key);
		for (j = 0; j < wg_peer->p_aips_count; j++) {
			inet_ntop(wg_aip->a_af, &wg_aip->a_addr,
			    hbuf, sizeof(hbuf));
			fprintf(output, " aip %s/%d", hbuf, wg_aip->a_cidr);
			wg_aip++;
		}
		if (wg_peer->p_aips_count)
			fprintf(output, "\n");
		wg_peer = (struct wg_peer_io *)wg_aip;
	}
	free(wgdata.wgd_interface);
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
intwg(char *ifname, int ifs, int argc, char **argv)
{
	int set;
	struct wgc *x;

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
		return(0);
	} else if (Ambiguous(x)) {
		printf("%% intwg: Internal error - Ambiguous argument %s\n", argv[0]);
		return(0);
 	}

	argc--;
	argv++;

	if ((!set && argc > 1) || (x->type != WGKEY && set && argc != 1) ||
	    (x->type == WGKEY && argc > 1)) {
		printf("%% %s <%s>\n", x->name, x->descr);
		printf("%% no %s [%s]\n", x->name, x->descr);
		return(0);
	}

	switch(x->type) {
	case WGPORT:
		if (!set) {
			setwgport("0");
		} else {
			setwgport(argv[0]);
		}
		break;

	case WGKEY:
		if (!set) {
			setwgkey("");
		} else {
			if (argc == 1) {
				setwgkey(argv[0]);
			} else {
				uint8_t key[WG_KEY_LEN];
				char keyb64[WG_BASE64_KEY_LEN+1];

				printf("%% Using randomly generated private key for %s\n", ifname);

				arc4random_buf(key, WG_KEY_LEN);
				/* we encode just to instantly decode, unroll setwgkey? */
				b64_ntop(key, WG_KEY_LEN, keyb64, WG_BASE64_KEY_LEN+1);

				setwgkey(keyb64);
			}
		}
		break;

	case WGRTABLE:
		if (!set) {
			setwgrtable("0");
		} else {
			setwgrtable(argv[0]);
		}
		break;
	}

	strlcpy(wgdata.wgd_name, ifname, sizeof(wgdata.wgd_name));

	if (ioctl(ifs, SIOCSWG, (caddr_t)&wgdata) == -1)
		printf("%% intwg: SIOCSWG: %s\n", strerror(errno));
	free(wgdata.wgd_interface);
        wgdata.wgd_size = 0;

	return(0);
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
	printf("%% no wgpeer <public key> psk [pre-shared key]\n");
}

int
intwgpeer(char *ifname, int ifs, int argc, char **argv)
{
	int set, ch;

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
			return(0);
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
				wgpeerusage();
				goto wgerr;
			}
			if (setwgpeerep(argv[noptind - 1]) < 0)
				goto wgerr;
			break;
		case 'a':	/* aip */
			if (!set) {
				wgpeerusage();
				goto wgerr;
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
			if (!set) {
				wgpeerusage();
				goto wgerr;
			}
			if (setwgpeerpka(argv[noptind - 1]) < 0)
				goto wgerr;
			break;
#ifdef WG_PEER_SET_DESCRIPTION
		case 'd':	/* description */
			if (!set) {
				wgpeerusage();
				goto wgerr;
			}
			if (setwgpeerdesc(argv[noptind - 1]) < 0)
				goto wgerr;
			break;
#endif
		default:
			printf("%% intwgpeer: nopt table error\n");
			return(0);
		}

	if (argc - noptind != 0) {
		/* leftover salmon */
		printf("%% %s", nopterr);
		if (argv[noptind])
			printf(": %s", argv[noptind]);
		printf("\n");
		wgpeerusage();
		return(0);
	}

	strlcpy(wgdata.wgd_name, ifname, sizeof(wgdata.wgd_name));

	if (ioctl(ifs, SIOCSWG, (caddr_t)&wgdata) == -1)
		printf("%% intwgpeer: SIOCSWG: %s\n", strerror(errno));
wgerr:
	free(wgdata.wgd_interface);
	wgdata.wgd_size = 0;

	return(0);
}
