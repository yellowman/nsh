/*
 * What the kernel's interface cloners make: the if_type and if_flags
 * each create function sets, and whether is_bridge() calls it a bridge.
 * Made by scripts/kernscan.pl; do not edit. From:
 *	OpenBSD-current, git c30c84965dc4 of 2026-10-17
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_types.h>
#include "kernel.h"

const char kernel_source[] = "OpenBSD-current, git c30c84965dc4 of 2026-10-17";

const struct kcloner kcloners[] = {
	{ "aggr", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "bpe", IFT_ETHER, 1,
	    IFF_BROADCAST | IFF_MULTICAST },
	{ "bridge", IFT_BRIDGE, 1,
	    0 },
	{ "carp", IFT_CARP, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "egre", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "enc", IFT_ENC, 0,
	    0 },
	{ "eoip", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "erspan", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "etherip", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "gif", IFT_GIF, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT },
	{ "gre", IFT_TUNNEL, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT },
	{ "lo", IFT_LOOP, 0,
	    IFF_LOOPBACK | IFF_MULTICAST },
	{ "mgre", IFT_L3IPVLAN, 0,
	    IFF_MULTICAST | IFF_SIMPLEX },
	{ "mpe", IFT_MPLS, 0,
	    IFF_POINTOPOINT },
	{ "mpip", IFT_TUNNEL, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT },
	{ "mpw", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "nvgre", IFT_ETHER, 1,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "pair", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "pflog", IFT_PFLOG, 0,
	    0 },
	{ "pflow", IFT_PFLOW, 0,
	    IFF_UP },
	{ "pfsync", IFT_PFSYNC, 0,
	    0 },
	{ "ppp", IFT_PPP, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT },
	{ "pppoe", IFT_PPP, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT | IFF_SIMPLEX },
	{ "rport", IFT_TUNNEL, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT },
	{ "sec", IFT_TUNNEL, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT },
	{ "svlan", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST },
	{ "tap", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "tpmr", IFT_BRIDGE, 1,
	    IFF_POINTOPOINT },
	{ "trunk", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "tun", IFT_TUNNEL, 0,
	    IFF_MULTICAST | IFF_POINTOPOINT },
	{ "veb", IFT_BRIDGE, 1,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "vether", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "vlan", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST },
	{ "vport", IFT_ETHER, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "vxlan", IFT_ETHER, 1,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX },
	{ "wg", IFT_WIREGUARD, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_NOARP },
	{ NULL, 0, 0, 0 }
};
