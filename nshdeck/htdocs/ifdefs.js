/*
 * ifdefs.js: every setting of nsh's interface and bridge modes, written
 * by hand from nsh(8) and nsh's handlers, for the interface inspector.
 *
 * Each has its key, the word that begins its line; a label; its group;
 * its kind; its syntax and help, as nsh(8) gives them; and the drivers
 * it is for, or all.  Kinds:
 *
 *	text	one value: "key value", and "no key" to remove it
 *	number	the same, between min and max
 *	choice	the same, one of choices
 *	flag	"key" on, "no key" off; off when the configuration says
 *		nothing
 *	noflag	the same, but on when the configuration says nothing
 *	down	shutdown: "shutdown" when down, "no shutdown" when up
 *	words	words, each added as "key word" and taken away as
 *		"no key word"
 *	lines	whole lines after the key, each added and taken away as one
 */
"use strict";

/* drivers, as interfaces' names begin */
var TUNNELS = ["gif", "gre", "egre", "mgre", "nvgre", "eoip", "etherip",
    "vxlan"];
var MPLSIFS = ["mpe", "mpw", "mpip"];
var VLANS = ["vlan", "svlan"];

var IFDEFS = [
	/* Essentials */
	{ key: "description", label: "Description", group: "Essentials",
	    kind: "text", syntax: "description text",
	    help: "A label for the interface, shown by show interface." },
	{ key: "inet", label: "Addresses", group: "Essentials",
	    kind: "lines", syntax: "inet address/prefix-length",
	    placeholder: "192.0.2.1/24 or 2001:db8::1/64",
	    help: "IPv4 or IPv6 addresses, each with its prefix length or " +
	    "netmask. IPv6 may add anycast, eui64, vltime and pltime." },
	{ key: "shutdown", label: "Enabled", group: "Essentials",
	    kind: "down", syntax: "[no] shutdown",
	    help: "Turned off, the interface is administratively down. " +
	    "Turning it off and on again resets it." },
	{ key: "mtu", label: "MTU", group: "Essentials", kind: "number",
	    min: 64, max: 65535, syntax: "mtu mtu-bytes",
	    help: "The largest packet the interface sends. It cannot exceed " +
	    "the hardmtu that show interface reports." },
	{ key: "group", label: "Groups", group: "Essentials", kind: "words",
	    syntax: "group group-name", placeholder: "egress",
	    help: "Group labels, which pf and others can refer to. An " +
	    "interface can be in several." },
	{ key: "autoconf4", label: "IPv4 by DHCP", group: "Essentials",
	    kind: "flag", syntax: "[no] autoconf4",
	    help: "A DHCP client on the interface. The first DHCP interface " +
	    "to get a lease sets the default route." },
	{ key: "autoconf6", label: "IPv6 autoconfiguration",
	    group: "Essentials", kind: "flag", syntax: "[no] autoconf6",
	    help: "Stateless IPv6 autoconfiguration. Alone, the address is " +
	    "repeatable, from the hardware address." },

	/* Routing */
	{ key: "rdomain", label: "Routing domain", group: "Routing",
	    kind: "number", min: 0, max: 255, syntax: "rdomain number",
	    help: "The rdomain(4) the interface is in. Setting it clears the " +
	    "interface's addresses, so set it first." },
	{ key: "rtlabel", label: "Route label", group: "Routing",
	    kind: "text", syntax: "rtlabel label",
	    help: "A route label for routes through the interface, for " +
	    "policy routing." },
	{ key: "priority", label: "Route priority", group: "Routing",
	    kind: "number", min: 0, max: 15, syntax: "priority 0-15",
	    help: "Lower is better. Connected routes get this plus 4, static " +
	    "routes this plus 8." },
	{ key: "metric", label: "Metric", group: "Routing", kind: "number",
	    min: 0, max: 2147483647, syntax: "metric 0-2147483647",
	    help: "The routing metric of the interface; 0 by default." },
	{ key: "dhcrelay", label: "DHCP relay to", group: "Routing",
	    kind: "text", syntax: "dhcrelay dhcp-server-ip",
	    placeholder: "10.1.1.2",
	    help: "Relay DHCP requests heard on the interface to this " +
	    "server, with dhcrelay(8)." },

	/* Link layer */
	{ key: "lladdr", label: "MAC address", group: "Link layer",
	    kind: "text", syntax: "lladdr mac-address | random",
	    placeholder: "00:11:22:33:44:55",
	    help: "A hardware address in colons, or random." },
	{ key: "llpriority", label: "Link priority", group: "Link layer",
	    kind: "number", min: 0, max: 7, syntax: "llpriority 0-7",
	    help: "The priority of the interface's own link layer packets: " +
	    "ARP, NDP, BPF, PPPoE." },
	{ key: "arp", label: "ARP", group: "Link layer", kind: "noflag",
	    syntax: "[no] arp", help: "Address resolution; on by default." },
	{ key: "staticarp", label: "Static ARP only", group: "Link layer",
	    kind: "flag", syntax: "[no] staticarp",
	    help: "Reach only hosts in the static ARP table; send no ARP " +
	    "requests, but still answer for the interface's addresses." },
	{ key: "media", label: "Media", group: "Link layer", kind: "text",
	    syntax: "media [type] [instance] [mediaopt options]",
	    placeholder: "autoselect", physical: true,
	    help: "The media type, such as 1000baseT or autoselect, and its " +
	    "options. show interface, in verbose mode, lists what the " +
	    "driver takes." },
	{ key: "mediaopt", label: "Media options", group: "Link layer",
	    kind: "words", syntax: "mediaopt option", physical: true,
	    placeholder: "full-duplex", help: "Media options, such as " +
	    "full-duplex." },
	{ key: "link", label: "Link flags", group: "Link layer",
	    kind: "words", syntax: "link 0 | 1 | 2",
	    help: "Link flags, whose meaning each driver gives." },
	{ key: "wol", label: "Wake on LAN", group: "Link layer",
	    kind: "flag", syntax: "[no] wol", physical: true,
	    help: "If the hardware and firmware support it." },
	{ key: "monitor", label: "Monitor only", group: "Link layer",
	    kind: "flag", syntax: "[no] monitor",
	    help: "Packets in are not processed by the network stack: for " +
	    "sniffing and intrusion detection." },
	{ key: "temporary", label: "IPv6 temporary addresses",
	    group: "Link layer", kind: "flag", syntax: "[no] temporary",
	    help: "With autoconf6, random addresses that change, so the host " +
	    "is harder to track." },
	{ key: "debug", label: "Driver debugging", group: "Link layer",
	    kind: "flag", syntax: "[no] debug",
	    help: "The driver's own debugging flag." },

	/* VLANs and tunnels */
	{ key: "parent", label: "Parent", group: "VLAN and tunnel",
	    kind: "text", syntax: "parent parent-interface",
	    on: VLANS.concat(["vxlan", "nvgre", "bpe"]), placeholder: "em0",
	    help: "The interface a VLAN, or a tunnel that has one, runs on." },
	{ key: "vnetid", label: "VNI or VLAN ID", group: "VLAN and tunnel",
	    kind: "number", min: 0, max: 16777215,
	    syntax: "vnetid 1-4094 | 0-16777215",
	    on: VLANS.concat(TUNNELS, ["bpe"]),
	    help: "A VLAN's 802.1Q ID, 1 to 4094, or a tunnel's 24 bit " +
	    "virtual network identifier." },
	{ key: "vnetflowid", label: "Flow ID from VNI",
	    group: "VLAN and tunnel", kind: "flag", syntax: "[no] vnetflowid",
	    on: TUNNELS, help: "Use part of the virtual network identifier " +
	    "as a flow identifier, to spread traffic over links." },
	{ key: "tunnel", label: "Tunnel", group: "VLAN and tunnel",
	    kind: "text", on: TUNNELS,
	    syntax: "tunnel source-ip destination-ip [ttl 1-255] [df] [ecn]",
	    placeholder: "192.0.2.1 198.51.100.1",
	    help: "The tunnel's endpoints, and its TTL, don't-fragment and " +
	    "ECN." },
	{ key: "tunneldomain", label: "Tunnel routing domain",
	    group: "VLAN and tunnel", kind: "number", min: 0, max: 255,
	    syntax: "tunneldomain rdomain", on: TUNNELS.concat(MPLSIFS),
	    help: "The routing domain the encapsulated packets travel in." },
	{ key: "txprio", label: "Transmit priority",
	    group: "VLAN and tunnel", kind: "text",
	    syntax: "txprio 0-7 | packet | payload",
	    on: TUNNELS.concat(MPLSIFS, VLANS),
	    help: "The priority in the headers it adds: a value, or the " +
	    "packet's or payload's." },
	{ key: "rxprio", label: "Receive priority",
	    group: "VLAN and tunnel", kind: "text",
	    syntax: "rxprio 0-7 | packet | payload",
	    on: TUNNELS.concat(MPLSIFS, VLANS),
	    help: "Where a received packet's priority comes from." },
	{ key: "keepalive", label: "Keepalive", group: "VLAN and tunnel",
	    kind: "text", syntax: "keepalive period count",
	    on: ["gre", "egre", "eoip"], placeholder: "1 3",
	    help: "Send a keepalive every period seconds; the link is down " +
	    "after count of them are not answered." },
	{ key: "patch", label: "Patched to", group: "VLAN and tunnel",
	    kind: "text", syntax: "patch pair-interface", on: ["pair"],
	    help: "Another pair(4), connected as with a cable." },

	/* CARP */
	{ key: "vhid", label: "Virtual host ID", group: "CARP",
	    kind: "number", min: 1, max: 255, syntax: "vhid 1-255",
	    on: ["carp"], help: "The CARP group's virtual host ID." },
	{ key: "carpdev", label: "Device", group: "CARP", kind: "text",
	    syntax: "carpdev interface", on: ["carp"],
	    help: "The real interface its advertisements go out and come in " +
	    "on." },
	{ key: "advbase", label: "Advertisement base", group: "CARP",
	    kind: "number", min: 0, max: 254, syntax: "advbase 0-254",
	    on: ["carp"], help: "Seconds between the master's " +
	    "advertisements." },
	{ key: "advskew", label: "Advertisement skew", group: "CARP",
	    kind: "number", min: 0, max: 254, syntax: "advskew 0-254",
	    on: ["carp"], help: "Higher is less likely to become master; " +
	    "the interval is advbase + advskew / 255." },
	{ key: "carppass", label: "Passphrase", group: "CARP",
	    kind: "text", syntax: "carppass passphrase", on: ["carp"],
	    help: "Up to 19 characters; none by default." },
	{ key: "carppeer", label: "Peer", group: "CARP", kind: "text",
	    syntax: "carppeer peer-address", on: ["carp"],
	    help: "Advertise by unicast to this peer, not by multicast." },
	{ key: "balancing", label: "Balancing", group: "CARP",
	    kind: "choice", choices: ["none", "ip", "ip-stealth",
	    "ip-unicast"], syntax: "balancing none | ip | ip-stealth | " +
	    "ip-unicast", on: ["carp"],
	    help: "Spread traffic across the nodes; ip needs a switch that " +
	    "takes multicast MACs." },
	{ key: "carpnode", label: "Nodes", group: "CARP", kind: "lines",
	    syntax: "carpnode vhid [advskew]", on: ["carp"],
	    placeholder: "2 100",
	    help: "More vhids, for balancing across nodes; configure the " +
	    "same list on every side." },

	/* pfsync */
	{ key: "syncdev", label: "Sync device", group: "pfsync",
	    kind: "text", syntax: "syncdev interface", on: ["pfsync"],
	    help: "The interface pfsync's messages go out on; it has no " +
	    "authentication, so use a direct cable or a tunnel." },
	{ key: "syncpeer", label: "Sync peer", group: "pfsync",
	    kind: "text", syntax: "syncpeer address", on: ["pfsync"],
	    help: "Send to this peer by unicast, not to 224.0.0.240." },
	{ key: "maxupd", label: "Max updates", group: "pfsync",
	    kind: "text", syntax: "maxupd 0-255 [defer]", on: ["pfsync"],
	    placeholder: "128",
	    help: "Updates collapsed into one for a state; defer holds a " +
	    "connection's first packet until the peer has its state." },

	/* Aggregation */
	{ key: "trunkproto", label: "Protocol", group: "Aggregation",
	    kind: "choice", choices: ["roundrobin", "failover", "lacp",
	    "loadbalance", "broadcast", "none"],
	    syntax: "trunkproto protocol", on: ["trunk", "aggr"],
	    help: "How the ports share traffic." },
	{ key: "trunkport", label: "Ports", group: "Aggregation",
	    kind: "words", syntax: "trunkport interface",
	    on: ["trunk", "aggr"], placeholder: "em2",
	    help: "The interfaces the aggregate uses." },

	/* WireGuard */
	{ key: "wgkey", label: "Private key", group: "WireGuard",
	    kind: "text", syntax: "wgkey [private-key]", on: ["wg"],
	    help: "32 bytes, base64. Without one, nsh makes one." },
	{ key: "wgport", label: "UDP port", group: "WireGuard",
	    kind: "number", min: 0, max: 65535, syntax: "wgport 0-65535",
	    on: ["wg"], help: "The local port; chosen by the kernel if " +
	    "not set." },
	{ key: "wgrtable", label: "Routing table", group: "WireGuard",
	    kind: "number", min: 0, max: 255, syntax: "wgrtable rtable",
	    on: ["wg"], help: "The routing table its traffic with its " +
	    "peers goes through." },
	{ key: "wgpeer", label: "Peers", group: "WireGuard", kind: "lines",
	    syntax: "wgpeer public-key [endpoint ip:port] [aip prefix] " +
	    "[psk key] [pka seconds]", on: ["wg"],
	    help: "Each peer by its public key, with its endpoint, allowed " +
	    "addresses, pre-shared key and keepalive." },

	/* Wireless */
	{ key: "nwid", label: "Network ID", group: "Wireless",
	    kind: "text", syntax: "nwid network-id", wireless: true,
	    help: "The 802.11 network to join." },
	{ key: "nwkey", label: "WEP key", group: "Wireless", kind: "text",
	    syntax: "nwkey key", wireless: true,
	    help: "A WEP key; no nwkey turns WEP off." },
	{ key: "powersave", label: "Power saving", group: "Wireless",
	    kind: "number", min: 0, max: 100000, syntax: "powersave ms",
	    wireless: true, help: "802.11 power saving, in milliseconds." },
	{ key: "txpower", label: "Transmit power", group: "Wireless",
	    kind: "number", min: -100, max: 100, syntax: "txpower dBm",
	    wireless: true, help: "In dBm; automatic if not set." },

	/* Mobile broadband */
	{ key: "apn", label: "Access point name", group: "Mobile broadband",
	    kind: "text", syntax: "apn name", on: ["umb"],
	    help: "The carrier's access point name." },
	{ key: "setpin", label: "SIM PIN", group: "Mobile broadband",
	    kind: "text", syntax: "setpin pin", on: ["umb"],
	    help: "The PIN that unlocks the SIM card." },
	{ key: "class", label: "Cell classes", group: "Mobile broadband",
	    kind: "words", syntax: "class class", on: ["umb"],
	    placeholder: "4g", help: "Preferred classes, such as 3g or 4g." },
	{ key: "roaming", label: "Roaming", group: "Mobile broadband",
	    kind: "flag", syntax: "[no] roaming", on: ["umb"],
	    help: "Allow data while roaming." },

	/* PPP */
	{ key: "pppoe", label: "PPPoE", group: "PPP", kind: "text",
	    syntax: "pppoe dev interface [ac concentrator] [svc service]",
	    on: ["pppoe"], placeholder: "dev em0",
	    help: "The Ethernet interface PPPoE runs on, and the access " +
	    "concentrator and service to ask for." },
	{ key: "auth", label: "Authentication", group: "PPP", kind: "text",
	    syntax: "auth proto pap | chap name name key key",
	    on: ["pppoe", "ppp"], help: "How this end authenticates." },
	{ key: "peer", label: "Peer authentication", group: "PPP",
	    kind: "text", syntax: "peer proto pap | chap name name key key " +
	    "[flag callin | norechallenge]", on: ["pppoe", "ppp"],
	    help: "How the peer must authenticate." },

	/* MPLS */
	{ key: "mpls", label: "MPLS", group: "MPLS", kind: "flag",
	    syntax: "[no] mpls", help: "The interface sends and receives " +
	    "MPLS." },
	{ key: "mplslabel", label: "Local label", group: "MPLS",
	    kind: "number", min: 16, max: 1048575, syntax: "mplslabel " +
	    "16-1048575", on: MPLSIFS,
	    help: "The label taken off here; 0 to 15 are reserved." },
	{ key: "pwe", label: "Pseudowire", group: "MPLS", kind: "lines",
	    syntax: "pwe neighbor label ip | pwe cw | pwe fat",
	    on: ["mpw", "mpip"], help: "The PWE3 neighbor, by its label " +
	    "and address, the control word and flow-aware transport." },

	/* pflow */
	{ key: "pflow", label: "Export", group: "pflow", kind: "text",
	    syntax: "pflow sender ip receiver ip:port [version 5 | 10]",
	    on: ["pflow"], placeholder: "sender 10.1.1.1 receiver " +
	    "10.1.1.2:4739 version 10",
	    help: "Where flows go: from an address of this system to a " +
	    "collector, as NetFlow 5 or IPFIX (10)." }
];

/* a bridge's settings: bridge(4), veb(4) and tpmr(4) */
var BRDEFS = [
	{ key: "description", label: "Description", group: "Essentials",
	    kind: "text", syntax: "description text",
	    help: "A label for the bridge." },
	{ key: "member", label: "Members", group: "Essentials",
	    kind: "words", syntax: "member interface", placeholder: "vlan101",
	    help: "The interfaces the bridge forwards between." },
	{ key: "shutdown", label: "Enabled", group: "Essentials",
	    kind: "down", syntax: "[no] shutdown",
	    help: "Turned off, the bridge is administratively down." },
	{ key: "span", label: "Span ports", group: "Forwarding",
	    kind: "words", syntax: "span interface",
	    help: "Ports that get a copy of every frame the bridge sees." },
	{ key: "learning", label: "Learning", group: "Forwarding",
	    kind: "words", syntax: "learning member",
	    help: "Members whose source addresses the bridge learns." },
	{ key: "discover", label: "Discovery", group: "Forwarding",
	    kind: "words", syntax: "discover member",
	    help: "Members that get frames for unknown destinations." },
	{ key: "blocknonip", label: "Block non-IP", group: "Forwarding",
	    kind: "words", syntax: "blocknonip member",
	    help: "Members that forward only IP, ARP and RARP." },
	{ key: "protect", label: "Protected domains", group: "Forwarding",
	    kind: "lines", syntax: "protect member domain-ids",
	    placeholder: "vlan101 20",
	    help: "Members in one domain cannot reach each other." },
	{ key: "maxaddr", label: "Address cache", group: "Forwarding",
	    kind: "number", min: 0, max: 4294967295,
	    syntax: "maxaddr size", help: "Addresses the bridge keeps, at " +
	    "most." },
	{ key: "timeout", label: "Cache timeout", group: "Forwarding",
	    kind: "number", min: 0, max: 4294967295, syntax: "timeout " +
	    "seconds", help: "Seconds a learned address is kept." },
	{ key: "static", label: "Static addresses", group: "Forwarding",
	    kind: "lines", syntax: "static mac-address member",
	    placeholder: "00:11:22:33:44:55 vlan101",
	    help: "Addresses the bridge always sends to a member." },
	{ key: "rule", label: "Rules", group: "Forwarding", kind: "lines",
	    syntax: "rule block | pass in | out | in/out on member [src " +
	    "mac] [dst mac]",
	    help: "Layer 2 filtering, in order." },
	{ key: "stp", label: "Spanning tree", group: "Spanning tree",
	    kind: "words", syntax: "stp member",
	    help: "Members that take part in 802.1D spanning tree." },
	{ key: "priority", label: "Bridge priority", group: "Spanning tree",
	    kind: "number", min: 0, max: 61440, syntax: "priority value",
	    help: "Lower becomes the root bridge." },
	{ key: "hellotime", label: "Hello time", group: "Spanning tree",
	    kind: "number", min: 1, max: 2, syntax: "hellotime seconds",
	    help: "Seconds between configuration messages." },
	{ key: "fwddelay", label: "Forward delay", group: "Spanning tree",
	    kind: "number", min: 4, max: 30, syntax: "fwddelay seconds",
	    help: "Seconds before a port forwards." },
	{ key: "maxage", label: "Max age", group: "Spanning tree",
	    kind: "number", min: 6, max: 40, syntax: "maxage seconds",
	    help: "Seconds a configuration message is valid." },
	{ key: "ifpriority", label: "Member priorities",
	    group: "Spanning tree", kind: "lines",
	    syntax: "ifpriority member priority", placeholder: "em1 128",
	    help: "Each member's spanning tree priority." },
	{ key: "ifcost", label: "Member costs", group: "Spanning tree",
	    kind: "lines", syntax: "ifcost member cost",
	    placeholder: "em1 20000", help: "Each member's path cost." },
	{ key: "vnetid", label: "VNI", group: "Encapsulation",
	    kind: "number", min: 0, max: 16777215, syntax: "vnetid id",
	    help: "The virtual network identifier, where the bridge has one." },
	{ key: "parent", label: "Parent", group: "Encapsulation",
	    kind: "text", syntax: "parent interface", help: "The interface " +
	    "it runs on, where it has one." },
	{ key: "tunneldomain", label: "Tunnel routing domain",
	    group: "Encapsulation", kind: "number", min: 0, max: 255,
	    syntax: "tunneldomain rdomain", help: "The routing domain its " +
	    "encapsulated packets travel in." },
	{ key: "txprio", label: "Transmit priority", group: "Encapsulation",
	    kind: "text", syntax: "txprio 0-7 | packet | payload",
	    help: "The priority in the headers it adds." },
	{ key: "rxprio", label: "Receive priority", group: "Encapsulation",
	    kind: "text", syntax: "rxprio 0-7 | packet | payload",
	    help: "Where a received packet's priority comes from." },
	{ key: "link", label: "Link flags", group: "Encapsulation",
	    kind: "words", syntax: "link 0 | 1 | 2",
	    help: "Link flags, whose meaning each driver gives." }
];
