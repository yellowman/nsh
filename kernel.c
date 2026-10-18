/*
 * What the kernel's interface cloners make: the if_type and if_flags
 * each create function sets, whether is_bridge() calls it a bridge, and
 * which of nsh's driver ioctls it takes.
 * Made by scripts/kernscan.pl; do not edit. From:
 *	OpenBSD-current, git c30c84965dc4 of 2026-10-17
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_pflow.h>
#include <net/if_trunk.h>
#include <net/if_wg.h>
#include <net/ppp_defs.h>
#include <net/if_sppp.h>
#include <net/if_pppoe.h>
#include "kernel.h"

const char kernel_source[] = "OpenBSD-current, git c30c84965dc4 of 2026-10-17";

const int kern_txpower_min = -50;	/* IEEE80211_TXPOWER_MIN */
const int kern_txpower_max = 100;	/* IEEE80211_TXPOWER_MAX */
const int kern_bstp_port_admcost = 0x0008;	/* BSTP_PORT_ADMCOST */
const int kern_bstp_max_path_cost = 200000000;	/* BSTP_MAX_PATH_COST */

static const u_long aggr_ioctls[] = {
	SIOCSTRUNK,
	SIOCSTRUNKPORT,
	SIOCSTRUNKDELPORT,
	0
};

static const u_long bpe_ioctls[] = {
	SIOCSVNETID,
	SIOCSIFPARENT,
	SIOCDIFPARENT,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long bridge_ioctls[] = {
	0
};

static const u_long carp_ioctls[] = {
	SIOCSVH,
	0
};

static const u_long egre_ioctls[] = {
	SIOCSLIFPHYADDR,
	SIOCDIFPHYADDR,
	SIOCSLIFPHYRTABLE,
	SIOCSLIFPHYTTL,
	SIOCSLIFPHYDF,
	SIOCSVNETID,
	SIOCDVNETID,
	SIOCSVNETFLOWID,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long enc_ioctls[] = {
	0
};

static const u_long eoip_ioctls[] = {
	SIOCSLIFPHYADDR,
	SIOCDIFPHYADDR,
	SIOCSLIFPHYRTABLE,
	SIOCSLIFPHYTTL,
	SIOCSLIFPHYDF,
	SIOCSVNETID,
	SIOCSETKALIVE,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long erspan_ioctls[] = {
	SIOCSLIFPHYADDR,
	SIOCDIFPHYADDR,
	SIOCSLIFPHYRTABLE,
	SIOCSLIFPHYTTL,
	SIOCSLIFPHYDF,
	SIOCSVNETID,
	SIOCDVNETID,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long etherip_ioctls[] = {
	SIOCSLIFPHYADDR,
	SIOCDIFPHYADDR,
	SIOCSLIFPHYRTABLE,
	SIOCSLIFPHYTTL,
	SIOCSLIFPHYDF,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long gif_ioctls[] = {
	SIOCSLIFPHYADDR,
	SIOCDIFPHYADDR,
	SIOCSLIFPHYRTABLE,
	SIOCSLIFPHYTTL,
	SIOCSLIFPHYDF,
	SIOCSLIFPHYECN,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long gre_ioctls[] = {
	SIOCSLIFPHYADDR,
	SIOCDIFPHYADDR,
	SIOCSLIFPHYRTABLE,
	SIOCSLIFPHYTTL,
	SIOCSLIFPHYDF,
	SIOCSLIFPHYECN,
	SIOCSVNETID,
	SIOCDVNETID,
	SIOCSVNETFLOWID,
	SIOCSETKALIVE,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long lo_ioctls[] = {
	0
};

static const u_long mgre_ioctls[] = {
	SIOCSLIFPHYADDR,
	SIOCDIFPHYADDR,
	SIOCSLIFPHYRTABLE,
	SIOCSLIFPHYTTL,
	SIOCSLIFPHYDF,
	SIOCSLIFPHYECN,
	SIOCSVNETID,
	SIOCDVNETID,
	SIOCSVNETFLOWID,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long mpe_ioctls[] = {
	SIOCSLIFPHYRTABLE,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	SIOCSETLABEL,
	SIOCDELLABEL,
	0
};

static const u_long mpip_ioctls[] = {
	SIOCSLIFPHYRTABLE,
	SIOCSLIFPHYTTL,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	SIOCSETLABEL,
	SIOCDELLABEL,
	SIOCSPWE3CTRLWORD,
	SIOCSPWE3FAT,
	SIOCSPWE3NEIGHBOR,
	SIOCDPWE3NEIGHBOR,
	0
};

static const u_long mpw_ioctls[] = {
	SIOCSLIFPHYRTABLE,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	SIOCSETLABEL,
	SIOCDELLABEL,
	SIOCSPWE3CTRLWORD,
	SIOCSPWE3FAT,
	SIOCSPWE3NEIGHBOR,
	SIOCDPWE3NEIGHBOR,
	0
};

static const u_long nvgre_ioctls[] = {
	SIOCSLIFPHYADDR,
	SIOCDIFPHYADDR,
	SIOCSLIFPHYRTABLE,
	SIOCSLIFPHYTTL,
	SIOCSLIFPHYDF,
	SIOCSVNETID,
	SIOCSIFPARENT,
	SIOCDIFPARENT,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long pair_ioctls[] = {
	SIOCSIFPAIR,
	0
};

static const u_long pflog_ioctls[] = {
	0
};

static const u_long pflow_ioctls[] = {
	SIOCSETPFLOW,
	0
};

static const u_long pfsync_ioctls[] = {
	SIOCSIFPARENT,
	SIOCDIFPARENT,
	SIOCSETPFSYNC,
	0
};

static const u_long ppp_ioctls[] = {
	0
};

static const u_long pppoe_ioctls[] = {
	SIOCSSPPPPARAMS,
	PPPOESETPARMS,
	0
};

static const u_long rport_ioctls[] = {
	SIOCSIFPARENT,
	SIOCDIFPARENT,
	0
};

static const u_long sec_ioctls[] = {
	SIOCSLIFPHYDF,
	0
};

static const u_long svlan_ioctls[] = {
	SIOCSVNETID,
	SIOCDVNETID,
	SIOCSIFPARENT,
	SIOCDIFPARENT,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long tap_ioctls[] = {
	0
};

static const u_long tpmr_ioctls[] = {
	0
};

static const u_long trunk_ioctls[] = {
	SIOCSTRUNK,
	SIOCSTRUNKPORT,
	SIOCSTRUNKDELPORT,
	0
};

static const u_long tun_ioctls[] = {
	0
};

static const u_long veb_ioctls[] = {
	SIOCSVNETID,
	SIOCDVNETID,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long vether_ioctls[] = {
	0
};

static const u_long vlan_ioctls[] = {
	SIOCSVNETID,
	SIOCDVNETID,
	SIOCSIFPARENT,
	SIOCDIFPARENT,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long vport_ioctls[] = {
	0
};

static const u_long vxlan_ioctls[] = {
	SIOCSLIFPHYADDR,
	SIOCDIFPHYADDR,
	SIOCSLIFPHYRTABLE,
	SIOCSLIFPHYTTL,
	SIOCSLIFPHYDF,
	SIOCSVNETID,
	SIOCDVNETID,
	SIOCSIFPARENT,
	SIOCDIFPARENT,
	SIOCSTXHPRIO,
	SIOCSRXHPRIO,
	0
};

static const u_long wg_ioctls[] = {
	SIOCSWG,
	0
};

const struct kcloner kcloners[] = {
	{ "aggr", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    aggr_ioctls },
	{ "bpe", IFT_ETHER, 1,
	    IFF_BROADCAST | IFF_MULTICAST,
	    bpe_ioctls },
	{ "bridge", IFT_BRIDGE, 1,
	    0,
	    bridge_ioctls },
	{ "carp", IFT_CARP, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    carp_ioctls },
	{ "egre", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    egre_ioctls },
	{ "enc", IFT_ENC, 0,
	    0,
	    enc_ioctls },
	{ "eoip", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    eoip_ioctls },
	{ "erspan", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    erspan_ioctls },
	{ "etherip", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    etherip_ioctls },
	{ "gif", IFT_GIF, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT,
	    gif_ioctls },
	{ "gre", IFT_TUNNEL, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT,
	    gre_ioctls },
	{ "lo", IFT_LOOP, 0,
	    IFF_LOOPBACK | IFF_MULTICAST,
	    lo_ioctls },
	{ "mgre", IFT_L3IPVLAN, 0,
	    IFF_MULTICAST | IFF_SIMPLEX,
	    mgre_ioctls },
	{ "mpe", IFT_MPLS, 0,
	    IFF_POINTOPOINT,
	    mpe_ioctls },
	{ "mpip", IFT_TUNNEL, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT,
	    mpip_ioctls },
	{ "mpw", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    mpw_ioctls },
	{ "nvgre", IFT_ETHER, 1,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    nvgre_ioctls },
	{ "pair", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    pair_ioctls },
	{ "pflog", IFT_PFLOG, 0,
	    0,
	    pflog_ioctls },
	{ "pflow", IFT_PFLOW, 0,
	    IFF_UP,
	    pflow_ioctls },
	{ "pfsync", IFT_PFSYNC, 0,
	    0,
	    pfsync_ioctls },
	{ "ppp", IFT_PPP, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT,
	    ppp_ioctls },
	{ "pppoe", IFT_PPP, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT | IFF_SIMPLEX,
	    pppoe_ioctls },
	{ "rport", IFT_TUNNEL, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT,
	    rport_ioctls },
	{ "sec", IFT_TUNNEL, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT,
	    sec_ioctls },
	{ "svlan", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST,
	    svlan_ioctls },
	{ "tap", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    tap_ioctls },
	{ "tpmr", IFT_BRIDGE, 1,
	    IFF_POINTOPOINT,
	    tpmr_ioctls },
	{ "trunk", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    trunk_ioctls },
	{ "tun", IFT_TUNNEL, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT,
	    tun_ioctls },
	{ "veb", IFT_BRIDGE, 1,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    veb_ioctls },
	{ "vether", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    vether_ioctls },
	{ "vlan", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST,
	    vlan_ioctls },
	{ "vport", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    vport_ioctls },
	{ "vxlan", IFT_ETHER, 1,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    vxlan_ioctls },
	{ "wg", IFT_WIREGUARD, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_NOARP,
	    wg_ioctls },
	{ NULL, 0, 0, 0, NULL }
};
