/*
 * registry.js: definitions of every setting the page shows. A field's ?
 * button opens its entry: what the setting does, its values, default,
 * scope, dependencies, risk, how to undo it, its keyword and its manual
 * page. The interface inspector builds its settings from the if and
 * bridge entries, which have these kinds:
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
 *
 * Where an entry has no values, default or undo, they follow from its
 * kind. Risk is given only where it is high.
 */
"use strict";

/* the OpenBSD release whose manual pages the entries follow */
var REGISTRY_OS = "OpenBSD 8.0";

/* each module's scope, manual page and what checks its settings */
var REGISTRY_MODULES = {
	if: { scope: "interfaces", man: "ifconfig.8",
	    check: "nsh, as each line is staged" },
	bridge: { scope: "bridges: bridge(4), veb(4) and tpmr(4)",
	    man: "ifconfig.8", check: "nsh, as each line is staged" },
	daemon: { scope: "daemons", man: "nsh.8",
	    check: "nsh, as each line is staged" },
	pf: { scope: "pf's rules", man: "pf.conf.5",
	    check: "pfctl -n, at Validate and at commit" },
	bgp: { scope: "bgpd's configuration", man: "bgpd.conf.5",
	    check: "bgpd -n, at Validate and at commit" },
	ospf: { scope: "ospfd's configuration", man: "ospfd.conf.5",
	    check: "ospfd -n, at Validate and at commit" },
	ospf6: { scope: "ospf6d's configuration", man: "ospf6d.conf.5",
	    check: "ospf6d -n, at Validate and at commit" },
	eigrp: { scope: "eigrpd's configuration", man: "eigrpd.conf.5",
	    check: "eigrpd -n, at Validate and at commit" },
	rip: { scope: "ripd's configuration", man: "ripd.conf.5",
	    check: "ripd -n, at Validate and at commit" },
	ldp: { scope: "ldpd's configuration", man: "ldpd.conf.5",
	    check: "ldpd -n, at Validate and at commit" },
	dvmrp: { scope: "dvmrpd's configuration", man: "dvmrpd.conf.5",
	    check: "dvmrpd -n, at Validate and at commit" },
	ntp: { scope: "ntpd's configuration", man: "ntpd.conf.5",
	    check: "ntpd -n, at Validate and at commit" },
	sasync: { scope: "sasyncd's configuration", man: "sasyncd.conf.5",
	    check: "sasyncd -n, at Validate and at commit" },
	rad: { scope: "rad's configuration", man: "rad.conf.5",
	    check: "rad -n, at Validate and at commit" },
	relay: { scope: "relayd's configuration", man: "relayd.conf.5",
	    check: "relayd -n, at Validate and at commit" }
};

/* drivers, as interfaces' names begin */
var TUNNELS = ["gif", "gre", "egre", "mgre", "nvgre", "eoip", "etherip",
    "vxlan"];
var MPLSIFS = ["mpe", "mpw", "mpip"];
var VLANS = ["vlan", "svlan"];

var REGISTRY = {
	/* Essentials */
	"if.description": { label: "Description", group: "Essentials",
	    kind: "text", keyword: "description text", definition: "A label " +
	    "for the interface, which show interface and the page show " +
	    "beside its name.", values: "text", default: "none" },
	"if.inet": { label: "Addresses", group: "Essentials", kind: "lines",
	    placeholder: "192.0.2.1/24 or 2001:db8::1/64", keyword: "inet " +
	    "address/prefix-length", definition: "The interface's IPv4 and " +
	    "IPv6 addresses, each with its prefix length or netmask. Each " +
	    "address also makes a connected route to its network. IPv6 may " +
	    "add anycast, eui64, vltime and pltime.", values: "an address " +
	    "with /prefix-length, a line each", default: "none",
	    needs: "rdomain, if any, set first: setting it clears the " +
	    "addresses", risk: "high: taking away the address a session " +
	    "comes in on ends it" },
	"if.shutdown": { label: "Enabled", group: "Essentials", kind: "down",
	    keyword: "[no] shutdown", definition: "Turned off, the interface " +
	    "is administratively down: it sends and receives nothing. " +
	    "Turning it off and on again resets it.", default: "on (no " +
	    "shutdown)", risk: "high: turning off the interface a session " +
	    "comes in on ends it", undo: "shutdown, or no shutdown" },
	"if.mtu": { label: "MTU", group: "Essentials", kind: "number", min: 64,
	    max: 65535, units: "bytes", keyword: "mtu mtu-bytes",
	    definition: "The largest packet the interface sends. It cannot " +
	    "exceed the hardmtu that show interface reports, and both ends " +
	    "of a link should agree.", default: "the driver's; 1500 on " +
	    "Ethernet" },
	"if.group": { label: "Groups", group: "Essentials", kind: "words",
	    placeholder: "egress", keyword: "group group-name",
	    definition: "Group labels, which pf rules and other commands can " +
	    "name in place of the interface. An interface can be in several.",
	    values: "names of up to 15 characters, not ending in a digit",
	    default: "the driver's name, such as em; egress for the " +
	    "interface of the default route" },
	"if.autoconf4": { label: "IPv4 by DHCP", group: "Essentials",
	    kind: "flag", keyword: "[no] autoconf4", definition: "A DHCP " +
	    "client on the interface. The lease gives an address, and the " +
	    "first interface to get one sets the default route and the name " +
	    "servers.", risk: "high: a lease can replace the default route" },
	"if.autoconf6": { label: "IPv6 autoconfiguration", group: "Essentials",
	    kind: "flag", keyword: "[no] autoconf6", definition: "Stateless " +
	    "IPv6 autoconfiguration from router advertisements. Alone, the " +
	    "address is the same every time, made from the network's prefix." },

	/* Routing */
	"if.rdomain": { label: "Routing domain", group: "Routing",
	    kind: "number", min: 0, max: 255, keyword: "rdomain number",
	    definition: "The routing domain the interface is in: its " +
	    "addresses and routes live in that domain's tables, apart from " +
	    "the others.", default: "0", risk: "high: setting it clears the " +
	    "interface's addresses, so set it first" },
	"if.rtlabel": { label: "Route label", group: "Routing", kind: "text",
	    keyword: "rtlabel label", definition: "A label put on the routes " +
	    "made through the interface, which route and pf can match, for " +
	    "policy routing.", values: "a label of up to 31 characters",
	    default: "none" },
	"if.priority": { label: "Route priority", group: "Routing",
	    kind: "number", min: 0, max: 15, keyword: "priority 0-15",
	    definition: "Lower is better. The interface's connected routes " +
	    "get this plus 4, and static routes through it this plus 8, so " +
	    "one link can be preferred to another.", default: "0; 4 on " +
	    "802.11, 6 on umb, 15 on carp" },
	"if.metric": { label: "Metric", group: "Routing", kind: "number",
	    min: 0, max: 2147483647, keyword: "metric 0-2147483647",
	    definition: "The interface's routing metric, which routing " +
	    "daemons can read. Higher makes its routes less favoured.",
	    default: "0" },
	"if.dhcrelay": { label: "DHCP relay to", group: "Routing", kind: "text",
	    placeholder: "10.1.1.2", keyword: "dhcrelay dhcp-server-ip",
	    definition: "DHCP requests heard on the interface go to this " +
	    "server, through dhcrelay(8), and its answers come back.",
	    values: "the server's IPv4 address", default: "none",
	    man: "dhcrelay.8" },

	/* Link layer */
	"if.lladdr": { label: "MAC address", group: "Link layer", kind: "text",
	    placeholder: "00:11:22:33:44:55", keyword: "lladdr mac-address | " +
	    "random", definition: "The interface's hardware address. " +
	    "Neighbours' ARP and NDP entries for the old one go stale until " +
	    "they ask again.", values: "six bytes in hex, with colons, or " +
	    "random", default: "the hardware's own" },
	"if.llpriority": { label: "Link priority", group: "Link layer",
	    kind: "number", min: 0, max: 7, keyword: "llpriority 0-7",
	    definition: "The priority of the interface's own link layer " +
	    "packets: ARP, NDP, BPF and PPPoE.", default: "3" },
	"if.arp": { label: "ARP", group: "Link layer", kind: "noflag",
	    keyword: "[no] arp", definition: "Address resolution: finding " +
	    "neighbours' hardware addresses. Without it, only static ARP " +
	    "entries are reached." },
	"if.staticarp": { label: "Static ARP only", group: "Link layer",
	    kind: "flag", keyword: "[no] staticarp", definition: "Reach only " +
	    "hosts in the static ARP table. The interface sends no ARP " +
	    "requests, but still answers for its own addresses." },
	"if.media": { label: "Media", group: "Link layer", kind: "text",
	    placeholder: "autoselect", physical: true, keyword: "media " +
	    "[type] [instance] [mediaopt options]", definition: "The media " +
	    "type, such as 1000baseT or autoselect, and its options. A type " +
	    "the other end does not use leaves the link down.", values: "a " +
	    "type the driver lists; show interface, in verbose mode, lists " +
	    "them", default: "autoselect" },
	"if.mediaopt": { label: "Media options", group: "Link layer",
	    kind: "words", placeholder: "full-duplex", physical: true,
	    keyword: "mediaopt option", definition: "Options for the media " +
	    "type, such as full-duplex.", values: "options the driver lists",
	    default: "none" },
	"if.link": { label: "Link flags", group: "Link layer", kind: "words",
	    keyword: "link 0 | 1 | 2", definition: "Link flags, whose " +
	    "meaning each driver gives in its own manual.", values: "0, 1 " +
	    "and 2", default: "none" },
	"if.wol": { label: "Wake on LAN", group: "Link layer", kind: "flag",
	    physical: true, keyword: "[no] wol", definition: "The system " +
	    "wakes when a magic packet comes in, if the hardware and " +
	    "firmware support it." },
	"if.monitor": { label: "Monitor only", group: "Link layer",
	    kind: "flag", keyword: "[no] monitor", definition: "Packets " +
	    "coming in are not processed by the network stack, only seen by " +
	    "BPF: for sniffing and intrusion detection." },
	"if.temporary": { label: "IPv6 temporary addresses", group: "Link " +
	    "layer", kind: "flag", keyword: "[no] temporary",
	    definition: "Random IPv6 addresses, made beside the " +
	    "autoconfigured one and changed over time, so the host is harder " +
	    "to track.", needs: "autoconf6" },
	"if.debug": { label: "Driver debugging", group: "Link layer",
	    kind: "flag", keyword: "[no] debug", definition: "The driver's " +
	    "own debugging flag, which makes some drivers log more." },

	/* VLANs and tunnels */
	"if.parent": { label: "Parent", group: "VLAN and tunnel", kind: "text",
	    placeholder: "em0", on: VLANS.concat(["vxlan", "nvgre", "bpe"]),
	    keyword: "parent parent-interface", definition: "The interface a " +
	    "VLAN, or a tunnel that has one, sends and receives on.",
	    values: "an interface's name", default: "none", needs: "vnetid, " +
	    "for a VLAN" },
	"if.vnetid": { label: "VNI or VLAN ID", group: "VLAN and tunnel",
	    kind: "number", min: 0, max: 16777215,
	    on: VLANS.concat(TUNNELS, ["bpe"]), keyword: "vnetid 1-4094 | " +
	    "0-16777215", definition: "A VLAN's 802.1Q ID, or a tunnel's " +
	    "virtual network identifier, which the other end must match.",
	    values: "1 to 4094 for a VLAN; 0 to 16777215 for a tunnel",
	    default: "none" },
	"if.vnetflowid": { label: "Flow ID from VNI", group: "VLAN and tunnel",
	    kind: "flag", on: TUNNELS, keyword: "[no] vnetflowid",
	    definition: "Part of the virtual network identifier is used as a " +
	    "flow identifier, to spread traffic over links.", needs: "vnetid" },
	"if.tunnel": { label: "Tunnel", group: "VLAN and tunnel", kind: "text",
	    placeholder: "192.0.2.1 198.51.100.1", on: TUNNELS,
	    keyword: "tunnel source-ip destination-ip [ttl 1-255] [df] [ecn]",
	    definition: "The tunnel's two ends, and the TTL, don't-fragment " +
	    "and ECN of the packets that carry it.", values: "two addresses " +
	    "of one family, then ttl 1 to 255, df and ecn", default: "none" },
	"if.tunneldomain": { label: "Tunnel routing domain", group: "VLAN " +
	    "and tunnel", kind: "number", min: 0, max: 255,
	    on: TUNNELS.concat(MPLSIFS), keyword: "tunneldomain rdomain",
	    definition: "The routing domain the encapsulated packets travel " +
	    "in, which can differ from the interface's own.", default: "0",
	    needs: "tunnel" },
	"if.txprio": { label: "Transmit priority", group: "VLAN and tunnel",
	    kind: "text", on: TUNNELS.concat(MPLSIFS, VLANS),
	    keyword: "txprio 0-7 | packet | payload", definition: "The " +
	    "priority written in the headers the interface adds: a fixed " +
	    "value, the packet's, or the payload's.", values: "0 to 7, " +
	    "packet or payload", default: "the driver's: packet on VLANs, " +
	    "payload or 0 on tunnels" },
	"if.rxprio": { label: "Receive priority", group: "VLAN and tunnel",
	    kind: "text", on: TUNNELS.concat(MPLSIFS, VLANS),
	    keyword: "rxprio 0-7 | packet | payload | outer",
	    definition: "Where a received packet's priority comes from: a " +
	    "fixed value, the packet's, the outer headers' or the payload's.",
	    values: "0 to 7, packet, outer or payload, as the driver takes",
	    default: "packet" },
	"if.keepalive": { label: "Keepalive", group: "VLAN and tunnel",
	    kind: "text", placeholder: "1 3", on: ["gre", "egre", "eoip"],
	    keyword: "keepalive period count", definition: "A keepalive is " +
	    "sent every period seconds, and the link is down after count of " +
	    "them go unanswered.", values: "seconds, then a count",
	    default: "off", needs: "tunnel" },
	"if.patch": { label: "Patched to", group: "VLAN and tunnel",
	    kind: "text", on: ["pair"], keyword: "patch pair-interface",
	    definition: "Another pair(4) interface, connected to this one as " +
	    "with a cable.", values: "a pair interface's name",
	    default: "none" },

	/* CARP */
	"if.vhid": { label: "Virtual host ID", group: "CARP", kind: "number",
	    min: 1, max: 255, on: ["carp"], keyword: "vhid 1-255",
	    definition: "The CARP group the interface belongs to. The " +
	    "systems that share an address use the same vhid.",
	    default: "none" },
	"if.carpdev": { label: "Device", group: "CARP", kind: "text",
	    on: ["carp"], keyword: "carpdev interface", definition: "The " +
	    "real interface CARP's advertisements go out and come in on.",
	    values: "an interface's name", default: "the interface on the " +
	    "CARP address's network", needs: "vhid" },
	"if.advbase": { label: "Advertisement base", group: "CARP",
	    kind: "number", min: 0, max: 254, units: "seconds", on: ["carp"],
	    keyword: "advbase 0-254", definition: "Seconds between the " +
	    "master's advertisements. A backup takes over after three " +
	    "intervals without one.", default: "1", needs: "vhid" },
	"if.advskew": { label: "Advertisement skew", group: "CARP",
	    kind: "number", min: 0, max: 254, on: ["carp"],
	    keyword: "advskew 0-254", definition: "Higher is less likely to " +
	    "become master: the interval is advbase + advskew / 256 seconds.",
	    default: "0", needs: "vhid" },
	"if.carppass": { label: "Passphrase", group: "CARP", kind: "text",
	    on: ["carp"], keyword: "carppass passphrase", definition: "A " +
	    "passphrase the members of the group share, which authenticates " +
	    "their advertisements.", values: "up to 19 characters",
	    default: "none", needs: "vhid", secret: true },
	"if.carppeer": { label: "Peer", group: "CARP", kind: "text",
	    on: ["carp"], keyword: "carppeer peer-address",
	    definition: "Advertisements go by unicast to this peer, not by " +
	    "multicast, for networks that do not carry multicast.",
	    values: "an address", default: "224.0.0.18, by multicast",
	    needs: "vhid" },
	"if.balancing": { label: "Balancing", group: "CARP", kind: "choice",
	    choices: ["none", "ip", "ip-stealth", "ip-unicast"], on: ["carp"],
	    keyword: "balancing none | ip | ip-stealth | ip-unicast",
	    definition: "Traffic is spread across the nodes. ip needs a " +
	    "switch that takes multicast MAC addresses.", default: "none",
	    needs: "carpnode" },
	"if.carpnode": { label: "Nodes", group: "CARP", kind: "lines",
	    placeholder: "2 100", on: ["carp"], keyword: "carpnode vhid " +
	    "[advskew]", definition: "More vhids, one for each node, for " +
	    "balancing. Every node must have the same list.", values: "vhid " +
	    "1 to 255, and advskew 0 to 254, a line each", default: "none" },

	/* pfsync */
	"if.syncdev": { label: "Sync device", group: "pfsync", kind: "text",
	    on: ["pfsync"], keyword: "syncdev interface", definition: "The " +
	    "interface pfsync's state messages go out on. They have no " +
	    "authentication, so use a direct cable or a tunnel.",
	    values: "an interface's name", default: "none" },
	"if.syncpeer": { label: "Sync peer", group: "pfsync", kind: "text",
	    on: ["pfsync"], keyword: "syncpeer address", definition: "State " +
	    "messages go to this peer by unicast, not by multicast.",
	    values: "an IPv4 address", default: "224.0.0.240, by multicast",
	    needs: "syncdev" },
	"if.maxupd": { label: "Max updates", group: "pfsync", kind: "text",
	    placeholder: "128", on: ["pfsync"], keyword: "maxupd 0-255 [defer]",
	    definition: "Updates to one state collapsed into one message. " +
	    "defer holds a connection's first packet until the peer has its " +
	    "state.", values: "0 to 255, then defer", default: "128",
	    needs: "syncdev" },

	/* Aggregation */
	"if.trunkproto": { label: "Protocol", group: "Aggregation",
	    kind: "choice", choices: ["roundrobin", "failover", "lacp",
	    "loadbalance", "broadcast", "none"], on: ["trunk", "aggr"],
	    keyword: "trunkproto protocol", definition: "How the ports share " +
	    "traffic, and how they agree with the switch.",
	    default: "roundrobin" },
	"if.trunkport": { label: "Ports", group: "Aggregation", kind: "words",
	    placeholder: "em2", on: ["trunk", "aggr"], keyword: "trunkport " +
	    "interface", definition: "The interfaces the aggregate sends and " +
	    "receives on.", values: "interfaces' names", default: "none",
	    risk: "high: a port added stops working on its own, with its " +
	    "addresses" },

	/* WireGuard */
	"if.wgkey": { label: "Private key", group: "WireGuard", kind: "text",
	    on: ["wg"], keyword: "wgkey [private-key]", definition: "The " +
	    "interface's private key, from which peers know its public key.",
	    values: "32 bytes, in base64", default: "none; nsh makes one",
	    secret: true },
	"if.wgport": { label: "UDP port", group: "WireGuard", kind: "number",
	    min: 0, max: 65535, on: ["wg"], keyword: "wgport 0-65535",
	    definition: "The local UDP port the interface exchanges traffic " +
	    "with its peers on.", default: "one chosen at random" },
	"if.wgrtable": { label: "Routing table", group: "WireGuard",
	    kind: "number", min: 0, max: 255, on: ["wg"], keyword: "wgrtable " +
	    "rtable", definition: "The routing table the encrypted traffic " +
	    "to and from its peers goes through.", default: "0" },
	"if.wgpeer": { label: "Peers", group: "WireGuard", kind: "lines",
	    on: ["wg"], keyword: "wgpeer public-key [endpoint ip:port] [aip " +
	    "prefix] [psk key] [pka seconds]", definition: "Each peer, by " +
	    "its public key, with its endpoint, the addresses it may send " +
	    "from, a pre-shared key and a keepalive.", values: "a peer a line",
	    default: "none", needs: "wgkey", secret: true },

	/* Wireless */
	"if.nwid": { label: "Network ID", group: "Wireless", kind: "text",
	    wireless: true, keyword: "nwid network-id", definition: "The " +
	    "802.11 network to join.", values: "up to 32 characters, or 0x " +
	    "and up to 64 hex digits", default: "none" },
	"if.nwkey": { label: "WEP key", group: "Wireless", kind: "text",
	    wireless: true, keyword: "nwkey key", definition: "A WEP key. " +
	    "WEP is weak, so use it only where nothing better is offered.",
	    values: "5 or 13 characters, or 0x and 10 or 26 hex digits",
	    default: "none: WEP off", secret: true },
	"if.powersave": { label: "Power saving", group: "Wireless",
	    kind: "number", min: 0, max: 100000, units: "milliseconds",
	    wireless: true, keyword: "powersave ms", definition: "802.11 " +
	    "power saving, with the time to sleep. Modern drivers save power " +
	    "without it.", default: "off" },
	"if.txpower": { label: "Transmit power", group: "Wireless",
	    kind: "number", min: -100, max: 100, units: "dBm", wireless: true,
	    keyword: "txpower dBm", definition: "The transmit power, where " +
	    "the driver lets it be set.", default: "automatic" },

	/* Mobile broadband */
	"if.apn": { label: "Access point name", group: "Mobile broadband",
	    kind: "text", on: ["umb"], keyword: "apn name", definition: "The " +
	    "carrier's access point name.", values: "text", default: "none" },
	"if.setpin": { label: "SIM PIN", group: "Mobile broadband",
	    kind: "text", on: ["umb"], keyword: "setpin pin",
	    definition: "The PIN that unlocks the SIM card. A wrong one, " +
	    "given too often, locks it.", values: "4 to 8 digits",
	    default: "none", secret: true },
	"if.class": { label: "Cell classes", group: "Mobile broadband",
	    kind: "words", placeholder: "4g", on: ["umb"], keyword: "class " +
	    "class", definition: "The cell classes preferred, such as 3g or " +
	    "4g.", values: "classes the device lists", default: "any" },
	"if.roaming": { label: "Roaming", group: "Mobile broadband",
	    kind: "flag", on: ["umb"], keyword: "[no] roaming",
	    definition: "Data is allowed while roaming, which can cost more." },

	/* PPP */
	"if.pppoe": { label: "PPPoE", group: "PPP", kind: "text",
	    placeholder: "dev em0", on: ["pppoe"], keyword: "pppoe dev " +
	    "interface [ac concentrator] [svc service]", definition: "The " +
	    "Ethernet interface PPPoE runs on, and the access concentrator " +
	    "and service to ask for.", values: "dev, an interface's name, " +
	    "then ac and svc names", default: "none" },
	"if.auth": { label: "Authentication", group: "PPP", kind: "text",
	    on: ["pppoe", "ppp"], keyword: "auth proto pap | chap name name " +
	    "key key", definition: "How this end authenticates to the peer.",
	    values: "proto pap or chap, then name and key", default: "none",
	    secret: true },
	"if.peer": { label: "Peer authentication", group: "PPP", kind: "text",
	    on: ["pppoe", "ppp"], keyword: "peer proto pap | chap name name " +
	    "key key [flag callin | norechallenge]", definition: "How the " +
	    "peer must authenticate to this end.", values: "proto pap or " +
	    "chap, then name, key and flags", default: "none: the peer is " +
	    "not asked", secret: true },

	/* MPLS */
	"if.mpls": { label: "MPLS", group: "MPLS", kind: "flag",
	    keyword: "[no] mpls", definition: "The interface sends and " +
	    "receives MPLS, for ldpd and labelled routes." },
	"if.mplslabel": { label: "Local label", group: "MPLS", kind: "number",
	    min: 16, max: 1048575, on: MPLSIFS, keyword: "mplslabel 16-1048575",
	    definition: "The label packets for this interface arrive with, " +
	    "and which is taken off here. 0 to 15 are reserved.",
	    default: "none" },
	"if.pwe": { label: "Pseudowire", group: "MPLS", kind: "lines",
	    on: ["mpw", "mpip"], keyword: "pwe neighbor label ip | pwe cw | " +
	    "pwe fat", definition: "The PWE3 neighbor, by its label and " +
	    "address, and the control word and flow-aware transport.",
	    values: "neighbor, a label and an address; cw; fat; a line each",
	    default: "none" },

	/* pflow */
	"if.pflow": { label: "Export", group: "pflow", kind: "text",
	    placeholder: "sender 10.1.1.1 receiver 10.1.1.2:4739 version 10",
	    on: ["pflow"], keyword: "pflow sender ip receiver ip:port " +
	    "[version 5 | 10]", definition: "Where pf's flows go: from an " +
	    "address of this system to a collector, as NetFlow 5 or IPFIX " +
	    "(10).", values: "sender, an address; receiver, an address and " +
	    "port; version 5 or 10", default: "none" },

	/* bridges: bridge(4), veb(4) and tpmr(4) */
	"bridge.description": { label: "Description", group: "Essentials",
	    kind: "text", keyword: "description text", definition: "A label " +
	    "for the bridge, which show bridge and the page show beside its " +
	    "name.", values: "text", default: "none" },
	"bridge.member": { label: "Members", group: "Essentials", kind: "words",
	    placeholder: "vlan101", keyword: "member interface",
	    definition: "The interfaces the bridge forwards frames between.",
	    values: "interfaces' names", default: "none", risk: "high: a " +
	    "member's traffic is the bridge's; an address on it may stop " +
	    "answering" },
	"bridge.shutdown": { label: "Enabled", group: "Essentials",
	    kind: "down", keyword: "[no] shutdown", definition: "Turned off, " +
	    "the bridge is administratively down and forwards nothing.",
	    default: "on (no shutdown)", risk: "high: the bridge stops " +
	    "forwarding", undo: "shutdown, or no shutdown" },
	"bridge.span": { label: "Span ports", group: "Forwarding",
	    kind: "words", keyword: "span interface",
	    definition: "Interfaces that get a copy of every frame the " +
	    "bridge sees, for monitoring. They are not members.",
	    values: "interfaces' names", default: "none" },
	"bridge.learning": { label: "Learning", group: "Forwarding",
	    kind: "words", keyword: "learning member", definition: "Members " +
	    "whose frames' source addresses the bridge learns, so it sends " +
	    "only to the member an address is on.", values: "members' names",
	    default: "every member, as it is added", needs: "member" },
	"bridge.discover": { label: "Discovery", group: "Forwarding",
	    kind: "words", keyword: "discover member", definition: "Members " +
	    "that get frames for destinations the bridge has not learned.",
	    values: "members' names", default: "every member, as it is added",
	    needs: "member" },
	"bridge.blocknonip": { label: "Block non-IP", group: "Forwarding",
	    kind: "words", keyword: "blocknonip member",
	    definition: "Members that forward only IPv4, IPv6, ARP and RARP.",
	    values: "members' names", default: "none", needs: "member" },
	"bridge.protect": { label: "Protected domains", group: "Forwarding",
	    kind: "lines", placeholder: "vlan101 20", keyword: "protect " +
	    "member domain-ids", definition: "Members in a protected domain " +
	    "do not forward to each other, only to members outside it.",
	    values: "a member, then domain IDs, a line each", default: "none",
	    needs: "member" },
	"bridge.maxaddr": { label: "Address cache", group: "Forwarding",
	    kind: "number", min: 0, max: 4294967295, units: "addresses",
	    keyword: "maxaddr size", definition: "The most addresses the " +
	    "bridge keeps. When full, it learns no more until some time out.",
	    default: "100" },
	"bridge.timeout": { label: "Cache timeout", group: "Forwarding",
	    kind: "number", min: 0, max: 4294967295, units: "seconds",
	    keyword: "timeout seconds", definition: "Seconds a learned " +
	    "address is kept; 0 keeps them until the cache is flushed.",
	    default: "240" },
	"bridge.static": { label: "Static addresses", group: "Forwarding",
	    kind: "lines", placeholder: "00:11:22:33:44:55 vlan101",
	    keyword: "static mac-address member", definition: "Addresses the " +
	    "bridge always sends to one member.", values: "an address, then " +
	    "a member, a line each", default: "none", needs: "member" },
	"bridge.rule": { label: "Rules", group: "Forwarding", kind: "lines",
	    keyword: "rule block | pass in | out | in/out on member [src " +
	    "mac] [dst mac]", definition: "Layer 2 filtering of frames by " +
	    "member and address, the first rule that matches deciding.",
	    values: "rules as bridge(4) gives them, a line each",
	    default: "none", needs: "member" },
	"bridge.stp": { label: "Spanning tree", group: "Spanning tree",
	    kind: "words", keyword: "stp member", definition: "Members that " +
	    "take part in spanning tree, which blocks ports to break loops.",
	    values: "members' names", default: "none", needs: "member" },
	"bridge.priority": { label: "Bridge priority", group: "Spanning tree",
	    kind: "number", min: 0, max: 61440, keyword: "priority value",
	    definition: "Lower becomes the root bridge, which every other " +
	    "bridge's ports point towards.", default: "32768" },
	"bridge.hellotime": { label: "Hello time", group: "Spanning tree",
	    kind: "number", min: 1, max: 2, units: "seconds",
	    keyword: "hellotime seconds", definition: "Seconds between the " +
	    "root bridge's configuration messages.", default: "2" },
	"bridge.fwddelay": { label: "Forward delay", group: "Spanning tree",
	    kind: "number", min: 4, max: 30, units: "seconds",
	    keyword: "fwddelay seconds", definition: "Seconds a port listens " +
	    "and learns before it forwards.", default: "15" },
	"bridge.maxage": { label: "Max age", group: "Spanning tree",
	    kind: "number", min: 6, max: 40, units: "seconds",
	    keyword: "maxage seconds", definition: "Seconds a configuration " +
	    "message is valid; after it, the tree is worked out again.",
	    default: "20" },
	"bridge.ifpriority": { label: "Member priorities", group: "Spanning " +
	    "tree", kind: "lines", placeholder: "em1 128",
	    keyword: "ifpriority member priority", definition: "Each " +
	    "member's spanning tree priority; lower is preferred between two " +
	    "ports to one segment.", values: "a member, then 0 to 240, a " +
	    "line each", default: "128", needs: "stp" },
	"bridge.ifcost": { label: "Member costs", group: "Spanning tree",
	    kind: "lines", placeholder: "em1 20000", keyword: "ifcost member " +
	    "cost", definition: "Each member's path cost; lower is preferred.",
	    values: "a member, then 1 to 200000000, a line each",
	    default: "worked out from the link's speed", needs: "stp" },
	"bridge.vnetid": { label: "VNI", group: "Encapsulation", kind: "number",
	    min: 0, max: 16777215, keyword: "vnetid id", definition: "The " +
	    "virtual network identifier, where the bridge has one.",
	    default: "none" },
	"bridge.parent": { label: "Parent", group: "Encapsulation",
	    kind: "text", keyword: "parent interface", definition: "The " +
	    "interface the bridge sends and receives on, where it has one.",
	    values: "an interface's name", default: "none" },
	"bridge.tunneldomain": { label: "Tunnel routing domain",
	    group: "Encapsulation", kind: "number", min: 0, max: 255,
	    keyword: "tunneldomain rdomain", definition: "The routing domain " +
	    "its encapsulated packets travel in.", default: "0" },
	"bridge.txprio": { label: "Transmit priority", group: "Encapsulation",
	    kind: "text", keyword: "txprio 0-7 | packet | payload",
	    definition: "The priority written in the headers it adds.",
	    values: "0 to 7, packet or payload", default: "the driver's" },
	"bridge.rxprio": { label: "Receive priority", group: "Encapsulation",
	    kind: "text", keyword: "rxprio 0-7 | packet | payload | outer",
	    definition: "Where a received packet's priority comes from.",
	    values: "0 to 7, packet, outer or payload, as the driver takes",
	    default: "packet" },
	"bridge.link": { label: "Link flags", group: "Encapsulation",
	    kind: "words", keyword: "link 0 | 1 | 2", definition: "Link " +
	    "flags, whose meaning each driver gives in its own manual.",
	    values: "0, 1 and 2", default: "none" },

	/* daemons */
	"daemon.enable": { label: "Enabled", keyword: "[no] daemon enable, " +
	    "such as pf enable", definition: "Committing starts the " +
	    "daemon with its rules; committing no enable stops it.",
	    values: "on or off", default: "off", risk: "high: stopping pf " +
	    "or a routing daemon changes what passes and where it goes",
	    undo: "no pf enable stops pf; pf enable starts it" },
	"daemon.rtable": { label: "Routing table", keyword: "rtable number, " +
	    "then the daemon's lines", hint: "each has its own rules",
	    definition: "Which routing table's copy of the daemon is shown. " +
	    "Each routing table runs its own, with its own enable and rules.",
	    values: "0 to 255", default: "0", undo: "none needed: choosing " +
	    "one changes nothing" },

	/* pf's rules */
	"pf.action": { label: "Action", keyword: "pass | block | match",
	    hint: "match only sets options", definition: "pass lets a packet " +
	    "through, block drops it, and match sets options, such as " +
	    "nat-to, without deciding. A packet no rule matches passes.",
	    values: "pass, block or match", default: "none: every rule " +
	    "begins with one", risk: "high: a block on the path a session " +
	    "takes ends it", undo: "Revert, or the rule's text as it was" },
	"pf.ret": { label: "Return", keyword: "block return | return-rst | " +
	    "return-icmp", hint: "return, return-rst or return-icmp; none " +
	    "drops", definition: "What the sender of a blocked packet is " +
	    "told: return sends a TCP reset or an ICMP unreachable, " +
	    "return-rst a TCP reset, return-icmp an ICMP message. Without it " +
	    "the packet is dropped silently.", values: "return, return-rst " +
	    "or return-icmp, with an ICMP code if it takes one",
	    default: "drop, unless set block-policy return", needs: "action " +
	    "block", undo: "clear the field", applies: "block rules" },
	"pf.dir": { label: "Direction", keyword: "in | out", hint: "none: both",
	    definition: "Whether the rule matches packets coming in, going " +
	    "out, or both.", values: "in, out or neither", default: "both",
	    undo: "choose (not set)" },
	"pf.quick": { label: "Quick", keyword: "quick", hint: "the first " +
	    "rule that matches decides", definition: "If the rule matches, " +
	    "pf stops and this rule decides; later rules are not evaluated. " +
	    "Without it, the last rule that matches decides.", values: "on " +
	    "or off", default: "off", risk: "high: a quick rule overrides " +
	    "every rule after it", undo: "clear the box" },
	"pf.log": { label: "Log", keyword: "log", hint: "to pflog0",
	    definition: "Packets the rule matches are logged to pflog0, " +
	    "which pflogd writes to disk; with state, only the packet that " +
	    "makes the state. A busy rule logs a lot.", values: "on or off; " +
	    "log (all) and log (to pflogN) in the text", default: "off",
	    undo: "clear the box" },
	"pf.on": { label: "On", keyword: "on interface", hint: "em0, a " +
	    "group, { em0 em1 } or !em0", definition: "The interfaces the " +
	    "rule applies to.", values: "an interface, a group, a list in " +
	    "braces, or ! before one for all but it", default: "every " +
	    "interface", undo: "clear the field" },
	"pf.af": { label: "Family", keyword: "inet | inet6", hint: "none: both",
	    definition: "The address family the rule matches.",
	    values: "inet, inet6 or neither", default: "both", undo: "choose " +
	    "(none)" },
	"pf.proto": { label: "Protocol", keyword: "proto protocol",
	    hint: "tcp, udp, icmp or { tcp udp }", definition: "The IP " +
	    "protocol the rule matches. Ports need tcp or udp.", values: "a " +
	    "name from /etc/protocols, a number, or a list in braces",
	    default: "every protocol", undo: "clear the field" },
	"pf.from": { label: "From", keyword: "from source",
	    hint: "10.0.0.0/8, <table>, $macro, (em0), any or self",
	    definition: "The source addresses the rule matches.",
	    values: "an address or network, a <table>, a $macro, (interface) " +
	    "for its addresses, any, self, or a list in braces; ! before one " +
	    "excludes it", default: "any", risk: "high: a source wider than " +
	    "meant lets more through", undo: "clear the field" },
	"pf.fromport": { label: "From port", keyword: "port port",
	    hint: "80, 1024:65535, > 1023 or { 80 443 }", definition: "The " +
	    "source ports the rule matches.", values: "a port, a name from " +
	    "/etc/services, a range a:b, an operator such as > 1023, or a " +
	    "list in braces", default: "any port", needs: "proto tcp or udp",
	    undo: "clear the field" },
	"pf.to": { label: "To", keyword: "to destination", hint: "as From",
	    definition: "The destination addresses the rule matches.",
	    values: "as From", default: "any", risk: "high: a destination " +
	    "wider than meant lets more through", undo: "clear the field" },
	"pf.toport": { label: "To port", keyword: "port port", hint: "as " +
	    "From port", definition: "The destination ports the rule matches.",
	    values: "as From port", default: "any port", needs: "proto tcp " +
	    "or udp", undo: "clear the field" },
	"pf.state": { label: "State", keyword: "keep | modulate | synproxy | " +
	    "no state", hint: "pass keeps state unless no state",
	    definition: "keep state tracks a connection, so its later " +
	    "packets pass without the rules; modulate state also randomizes " +
	    "TCP sequence numbers; synproxy state completes the TCP " +
	    "handshake itself first; no state checks every packet against " +
	    "the rules.", values: "keep state, no state, modulate state or " +
	    "synproxy state", default: "keep state, for pass rules",
	    needs: "action pass", undo: "choose (not set)" },
	"pf.natto": { label: "nat-to", keyword: "nat-to address",
	    hint: "(egress)", definition: "The source address of packets " +
	    "going out is rewritten to this one, such as (egress), the " +
	    "egress interface's address.", values: "an address, a <table>, " +
	    "or (interface), with port and pool options", default: "none",
	    needs: "direction out", undo: "clear the field", applies: "pass " +
	    "and match rules" },
	"pf.rdrto": { label: "rdr-to", keyword: "rdr-to address [port port]",
	    hint: "10.0.0.5 port 8080", definition: "Packets coming in are " +
	    "redirected to this address, and port if given.", values: "an " +
	    "address, a <table>, or (interface), with port and pool options",
	    default: "none", needs: "direction in", undo: "clear the field",
	    applies: "pass and match rules" },
	"pf.label": { label: "Label", keyword: "label \"text\"", hint: "for " +
	    "pfctl -s labels", definition: "A name for the rule, so pfctl -s " +
	    "labels counts its packets, bytes and states.", values: "text; " +
	    "$nr is the rule's number", default: "none", undo: "clear the " +
	    "field" },
	"pf.other": { label: "Other options", keyword: "options",
	    hint: "flags S/SA, tag, …", definition: "The rest of the rule's " +
	    "options, as written: flags, tag, tagged, route-to, rtable, " +
	    "queue, max-src-conn and others.", values: "options as " +
	    "pf.conf(5) gives them", default: "none", undo: "clear the field" },
	"pf.macro": { label: "Macro", keyword: "name = value", hint: "in " +
	    "quotes if it has spaces", definition: "A name for a value; " +
	    "$name in the rules stands for it.", values: "a value, in quotes " +
	    "if it has spaces", default: "none", undo: "delete the line in " +
	    "the text" },
	"pf.table": { label: "Table", keyword: "table <name> [persist] " +
	    "[const] { addresses } [file path]", hint: "addresses and networks",
	    definition: "A named set of addresses and networks, quick to " +
	    "look up however large; <name> in the rules stands for it.",
	    values: "addresses and networks; ! before one excludes it",
	    default: "empty", undo: "delete the line in the text" },
	"pf.option": { label: "Option", keyword: "set option value",
	    definition: "A setting for pf as a whole, such as set skip on lo " +
	    "or set block-policy return.", values: "as pf.conf(5) gives for " +
	    "each option", default: "pf's own, for each option",
	    undo: "delete the line in the text" },

	/* bgpd's configuration */
	"bgp.as": { label: "Local AS", keyword: "AS as-number",
	    definition: "The autonomous system this router is in, which " +
	    "every peer sees.", values: "1 to 4294967295, or asdot such as " +
	    "65001.1", default: "none: bgpd does not start without one",
	    risk: "high: every peer expects the old one, and refuses a " +
	    "session with a new one", undo: "the number as it was" },
	"bgp.router-id": { label: "Router ID", keyword: "router-id address",
	    definition: "A 32-bit identifier, written as an IPv4 address, " +
	    "that names this router to its peers.", values: "an IPv4 address",
	    default: "the highest IPv4 address of the system", undo: "clear " +
	    "the field" },
	"bgp.neighbor": { label: "New peer", keyword: "neighbor address { }",
	    definition: "A BGP session with the router at this address; its " +
	    "settings go in its block.", values: "an IPv4 or IPv6 address, a " +
	    "prefix for peers that connect from it, or a $macro",
	    default: "none", undo: "Delete peer" },
	"bgp.network": { label: "Networks", keyword: "network prefix",
	    definition: "A prefix bgpd announces. Filters still decide which " +
	    "peers get it.", values: "a prefix; or inet connected, inet " +
	    "static and the others bgpd.conf(5) gives", default: "none",
	    undo: "Delete" },
	"bgp.remote-as": { label: "Remote AS", keyword: "remote-as as-number",
	    definition: "The AS the peer must be in. The same as the local " +
	    "AS makes it an internal (IBGP) peer.", values: "1 to " +
	    "4294967295, or asdot", default: "its group's, else none: the " +
	    "session is refused", risk: "high: a wrong AS ends the session",
	    undo: "clear the field", applies: "neighbors and groups" },
	"bgp.descr": { label: "Description", keyword: "descr \"text\"",
	    definition: "A name for the peer, which bgpctl shows and takes " +
	    "in place of its address.", values: "text", default: "none",
	    undo: "clear the field", applies: "neighbors and groups" },
	"bgp.local-address": { label: "Local address",
	    keyword: "local-address address", hint: "a line each",
	    definition: "The address this end uses for the session, one for " +
	    "each family.", values: "an IPv4 and an IPv6 address, a line each",
	    default: "none: the system chooses, by the route to the peer",
	    undo: "clear the field", applies: "neighbors and groups" },
	"bgp.multihop": { label: "Multihop", keyword: "multihop hops",
	    hint: "hops", definition: "The peer may be this many hops away. " +
	    "Without it, an external peer must be on a directly connected " +
	    "network.", values: "2 to 255", default: "directly connected, " +
	    "for external peers", undo: "clear the field",
	    applies: "neighbors and groups" },
	"bgp.max-prefix": { label: "Max prefixes", keyword: "max-prefix " +
	    "number [restart minutes]", hint: "900000 restart 15",
	    definition: "If the peer sends more prefixes than this, bgpd " +
	    "closes the session; restart opens it again after that many " +
	    "minutes.", values: "a number, then restart and minutes",
	    default: "no limit", undo: "clear the field",
	    applies: "neighbors and groups" },
	"bgp.announce": { label: "Families", keyword: "announce family " +
	    "subsequent", hint: "IPv4 unicast, a line each",
	    definition: "The address families the session carries.",
	    values: "IPv4 or IPv6, then none, unicast, vpn or flowspec; or " +
	    "EVPN; a line each", default: "the family of the peer's address, " +
	    "unicast", undo: "clear the field", applies: "neighbors and " +
	    "groups" },
	"bgp.passive": { label: "Passive", keyword: "passive",
	    definition: "bgpd waits for the peer to connect, and does not " +
	    "connect itself.", values: "on or off", default: "off",
	    undo: "clear the box", applies: "neighbors and groups" },
	"bgp.down": { label: "Shut down", keyword: "down [reason]",
	    definition: "The session is configured but not started, and its " +
	    "routes are withdrawn.", values: "on or off", default: "off",
	    risk: "high: the peer's routes go", undo: "clear the box",
	    applies: "neighbors and groups" },
	"bgp.filter.action": { label: "Action", keyword: "allow | deny | match",
	    hint: "match only sets", definition: "allow accepts the route, " +
	    "deny drops it, and match sets attributes without deciding.",
	    values: "allow, deny or match", default: "none: every filter " +
	    "begins with one", risk: "high: a deny can drop routes a network " +
	    "needs", undo: "Revert, or the filter's text as it was",
	    applies: "filters, in their order" },
	"bgp.filter.quick": { label: "Quick", keyword: "quick", hint: "the " +
	    "first filter that matches decides", definition: "If the filter " +
	    "matches, bgpd stops and this filter decides. Without it, the " +
	    "last filter that matches decides.", values: "on or off",
	    default: "off", risk: "high: a quick filter overrides every " +
	    "filter after it", undo: "clear the box", applies: "filters, in " +
	    "their order" },
	"bgp.filter.dir": { label: "Direction", keyword: "from | to",
	    hint: "from: received; to: sent", definition: "from filters " +
	    "routes received from peers, to filters routes sent to them.",
	    values: "from or to", default: "none: every filter has one",
	    undo: "choose the other", applies: "filters, in their order" },
	"bgp.filter.peer": { label: "Peer", keyword: "peer", hint: "any, " +
	    "ebgp, ibgp, an address, group \"name\" or AS 64496",
	    definition: "The peers the filter applies to.", values: "any, " +
	    "ebgp, ibgp, an address, group \"name\", or AS and a number",
	    default: "none: every filter names them", undo: "the text as it " +
	    "was", applies: "filters, in their order" },
	"bgp.filter.match": { label: "Matches", keyword: "prefix | " +
	    "prefix-set | as-set | community | …", hint: "prefix 10.0.0.0/8, " +
	    "prefix-set name, community 65001:100; none: every route",
	    definition: "What a route must have for the filter to apply: a " +
	    "prefix, a prefix-set, an AS path, a community and others.",
	    values: "as bgpd.conf(5) gives them", default: "every route",
	    undo: "clear the field", applies: "filters, in their order" },
	"bgp.filter.set": { label: "Sets", keyword: "set { attribute value }",
	    hint: "localpref 200", definition: "Attributes the filter sets " +
	    "on the routes it applies to, such as localpref, med, community " +
	    "or prepend-self.", values: "as bgpd.conf(5) gives them",
	    default: "none", undo: "clear the field", applies: "filters, in " +
	    "their order" },

	/* ospfd's configuration */
	"ospf.router-id": { label: "Router ID", keyword: "router-id address",
	    definition: "The 32-bit identifier, written as an IPv4 address, " +
	    "that names this router to its neighbors. It need not be one of " +
	    "its addresses.", values: "an IPv4 address", default: "the " +
	    "numerically lowest IP address of the router", undo: "clear the " +
	    "field" },
	"ospf.fib-update": { label: "Update the FIB", keyword: "fib-update " +
	    "yes | no", definition: "Whether ospfd installs its routes in " +
	    "the kernel's routing table. With no, it also acts as a stub " +
	    "router, so no traffic is routed through it.", values: "yes or no",
	    default: "yes", risk: "high: with no, this router forwards " +
	    "nothing by OSPF", undo: "choose (not set)" },
	"ospf.redistribute": { label: "Redistribute", keyword: "[no] " +
	    "redistribute static | connected | default | prefix | rtlabel " +
	    "label [set ...]", definition: "Routes from outside OSPF that " +
	    "ospfd announces, such as connected networks or static routes. " +
	    "The first rule that matches a route decides.", values: "one " +
	    "rule per line, as ospfd.conf(5) gives them", default: "none: " +
	    "only OSPF's own routes", undo: "clear the lines" },
	"ospf.interface": { label: "New interface", keyword: "interface name",
	    definition: "Adds an interface to an area. ospfd sends hellos " +
	    "and forms adjacencies on it, unless it is passive, and " +
	    "announces its network.", values: "an interface's name, in an area",
	    default: "none", undo: "Delete" },
	"ospf.metric": { label: "Metric", keyword: "metric cost",
	    definition: "The interface's cost. OSPF prefers the path with " +
	    "the lowest total cost.", values: "1 to 65535", default: "10, " +
	    "unless the area or the top level sets it", undo: "clear the field",
	    applies: "an interface; set in an area or at the top level, it " +
	    "applies to the interfaces after it" },
	"ospf.passive": { label: "Passive", keyword: "passive",
	    definition: "ospfd sends and accepts no OSPF packets on the " +
	    "interface, but still announces its network as a stub.",
	    values: "on or off", default: "off", undo: "clear the box",
	    applies: "an interface" },
	"ospf.hello-interval": { label: "Hello interval",
	    keyword: "hello-interval seconds", definition: "Seconds between " +
	    "hello packets. Neighbors on a network must use the same value.",
	    values: "1 to 65535 seconds", default: "10", undo: "clear the " +
	    "field", applies: "an interface; set in an area or at the top " +
	    "level, it applies to the interfaces after it" },
	"ospf.router-dead-time": { label: "Dead time",
	    keyword: "router-dead-time seconds | minimal",
	    definition: "Seconds without a hello before a neighbor is " +
	    "declared down. Neighbors on a network must use the same value. " +
	    "minimal sets 1 second, with fast hellos.", values: "2 to " +
	    "2147483647 seconds, or minimal", default: "40", undo: "clear " +
	    "the field", applies: "an interface; set in an area or at the " +
	    "top level, it applies to the interfaces after it" },
	"ospf.router-priority": { label: "Priority",
	    keyword: "router-priority priority", definition: "The " +
	    "interface's priority in electing the designated router; with 0 " +
	    "it is never elected.", values: "0 to 255", default: "1",
	    undo: "clear the field", applies: "an interface; set in an area " +
	    "or at the top level, it applies to the interfaces after it" },

	/* ospf6d's configuration */
	"ospf6.router-id": { label: "Router ID", keyword: "router-id address",
	    definition: "The 32-bit identifier, written as an IPv4 address, " +
	    "that names this router to its neighbors. It need not be one of " +
	    "its addresses.", values: "an IPv4 address", default: "the " +
	    "lowest IPv4 address of the router", undo: "clear the field" },
	"ospf6.fib-update": { label: "Update the FIB", keyword: "fib-update " +
	    "yes | no", definition: "Whether ospf6d installs its routes in " +
	    "the kernel's routing table. With no, it also acts as a stub " +
	    "router, so no traffic is routed through it.", values: "yes or no",
	    default: "yes", risk: "high: with no, this router forwards " +
	    "nothing by OSPF", undo: "choose (not set)" },
	"ospf6.redistribute": { label: "Redistribute", keyword: "[no] " +
	    "redistribute static | connected | default | prefix | rtlabel " +
	    "label [set ...]", definition: "Routes from outside OSPF that " +
	    "ospf6d announces, such as connected networks or static routes. " +
	    "The first rule that matches a route decides.", values: "one " +
	    "rule per line, as ospf6d.conf(5) gives them", default: "none: " +
	    "only OSPF's own routes", undo: "clear the lines" },
	"ospf6.interface": { label: "New interface", keyword: "interface name",
	    definition: "Adds an IPv6 interface to an area. ospf6d sends " +
	    "hellos and forms adjacencies on it, unless it is passive, and " +
	    "announces its network.", values: "an interface's name, in an area",
	    default: "none", undo: "Delete" },
	"ospf6.metric": { label: "Metric", keyword: "metric cost",
	    definition: "The interface's cost. OSPF prefers the path with " +
	    "the lowest total cost.", values: "1 to 65535", default: "10, " +
	    "unless the area or the top level sets it", undo: "clear the field",
	    applies: "an interface; set in an area or at the top level, it " +
	    "applies to the interfaces after it" },
	"ospf6.passive": { label: "Passive", keyword: "passive",
	    definition: "ospf6d sends and accepts no OSPF packets on the " +
	    "interface, but still announces its network as a stub.",
	    values: "on or off", default: "off", undo: "clear the box",
	    applies: "an interface" },
	"ospf6.hello-interval": { label: "Hello interval",
	    keyword: "hello-interval seconds", definition: "Seconds between " +
	    "hello packets. Neighbors on a network must use the same value.",
	    values: "1 to 65535 seconds", default: "10", undo: "clear the " +
	    "field", applies: "an interface; set in an area or at the top " +
	    "level, it applies to the interfaces after it" },
	"ospf6.router-dead-time": { label: "Dead time",
	    keyword: "router-dead-time seconds", definition: "Seconds " +
	    "without a hello before a neighbor is declared down. Neighbors " +
	    "on a network must use the same value.", values: "2 to 65535 " +
	    "seconds", default: "40", undo: "clear the field", applies: "an " +
	    "interface; set in an area or at the top level, it applies to " +
	    "the interfaces after it" },
	"ospf6.router-priority": { label: "Priority",
	    keyword: "router-priority priority", definition: "The " +
	    "interface's priority in electing the designated router; with 0 " +
	    "it is never elected.", values: "0 to 255", default: "1",
	    undo: "clear the field", applies: "an interface; set in an area " +
	    "or at the top level, it applies to the interfaces after it" },

	/* eigrpd's configuration */
	"eigrp.router-id": { label: "Router ID", keyword: "router-id address",
	    definition: "The 32-bit identifier, written as an IPv4 address, " +
	    "that names this router to its neighbors.", values: "an IPv4 " +
	    "address", default: "the numerically lowest IP address of the " +
	    "router", undo: "clear the field" },
	"eigrp.fib-update": { label: "Update the FIB", keyword: "fib-update " +
	    "yes | no", definition: "Whether eigrpd installs its routes in " +
	    "the kernel's routing table.", values: "yes or no", default: "yes",
	    risk: "high: with no, this router forwards nothing by EIGRP",
	    undo: "choose (not set)" },
	"eigrp.interface": { label: "New interface", keyword: "interface name",
	    definition: "Adds an interface to an address family and " +
	    "autonomous system. eigrpd forms adjacencies on it, unless it is " +
	    "passive, and announces its networks.", values: "an interface's " +
	    "name, in an address family and AS", default: "none",
	    undo: "Delete" },
	"eigrp.bandwidth": { label: "Bandwidth", keyword: "bandwidth kbit/s",
	    definition: "The bandwidth used in the composite metric, in " +
	    "kilobits per second. It does not change the link's speed.",
	    values: "1 to 10000000 kbit/s", default: "100000", undo: "clear " +
	    "the field", applies: "an interface; set at the top level, in an " +
	    "address family or in an AS, it applies to the interfaces after " +
	    "it" },
	"eigrp.delay": { label: "Delay", keyword: "delay tens-of-microseconds",
	    definition: "The delay used in the composite metric, in tens of " +
	    "microseconds.", values: "1 to 16777215", default: "10",
	    undo: "clear the field", applies: "an interface; set at the top " +
	    "level, in an address family or in an AS, it applies to the " +
	    "interfaces after it" },
	"eigrp.hello-interval": { label: "Hello interval",
	    keyword: "hello-interval seconds", definition: "Seconds between " +
	    "hello packets.", values: "1 to 65535 seconds", default: "5",
	    undo: "clear the field", applies: "an interface; set at the top " +
	    "level, in an address family or in an AS, it applies to the " +
	    "interfaces after it" },
	"eigrp.holdtime": { label: "Hold time", keyword: "holdtime seconds",
	    definition: "Seconds a neighbor waits without a hello from this " +
	    "router before it declares this router down.", values: "1 to " +
	    "65535 seconds", default: "15", undo: "clear the field",
	    applies: "an interface; set at the top level, in an address " +
	    "family or in an AS, it applies to the interfaces after it" },
	"eigrp.passive": { label: "Passive", keyword: "passive",
	    definition: "eigrpd sends and accepts no EIGRP packets on the " +
	    "interface, but still announces its networks.", values: "on or off",
	    default: "off", undo: "clear the box", applies: "an interface" },

	/* ripd's configuration */
	"rip.fib-update": { label: "Update the FIB", keyword: "fib-update " +
	    "yes | no", definition: "Whether ripd installs its routes in the " +
	    "kernel's routing table.", values: "yes or no", default: "yes",
	    risk: "high: with no, this router forwards nothing by RIP",
	    undo: "choose (not set)" },
	"rip.split-horizon": { label: "Split horizon",
	    keyword: "split-horizon simple | poisoned | none",
	    definition: "How routes go back out the interface they were " +
	    "learned on: simple does not send them, and poisoned sends them " +
	    "with an infinite metric. Both prevent routing loops when a " +
	    "router goes down.", values: "simple, poisoned or none",
	    default: "poisoned", undo: "choose (not set)" },
	"rip.triggered-updates": { label: "Triggered updates",
	    keyword: "triggered-updates yes | no", definition: "ripd sends " +
	    "an update as soon as a route changes, rather than waiting for " +
	    "the next regular update.", values: "yes or no", default: "no",
	    undo: "choose (not set)" },
	"rip.redistribute": { label: "Redistribute", keyword: "[no] " +
	    "redistribute static | connected | default | prefix | rtlabel " +
	    "label", definition: "Routes from outside RIP that ripd " +
	    "announces, such as connected networks or static routes. The " +
	    "first rule that matches a route decides.", values: "one rule " +
	    "per line, as ripd.conf(5) gives them", default: "none: only " +
	    "RIP's own routes", undo: "clear the lines" },
	"rip.interface": { label: "New interface", keyword: "interface name",
	    definition: "Adds an interface. ripd sends and receives RIP on " +
	    "it, unless it is passive.", values: "an interface's name",
	    default: "none", undo: "Delete" },
	"rip.cost": { label: "Cost", keyword: "cost number",
	    definition: "The cost of the interface's network, added to the " +
	    "routes learned through it. 16 means unreachable.", values: "1 " +
	    "to 16", default: "1", undo: "clear the field", applies: "an " +
	    "interface; set at the top level, it applies to the interfaces " +
	    "after it" },
	"rip.passive": { label: "Passive", keyword: "passive",
	    definition: "ripd sends and accepts no RIP packets on the " +
	    "interface.", values: "on or off", default: "off", undo: "clear " +
	    "the box", applies: "an interface" },

	/* ldpd's configuration */
	"ldp.router-id": { label: "Router ID", keyword: "router-id address",
	    definition: "The router ID, written as an IPv4 address. With the " +
	    "label space it forms the LSR-ID that neighbors know this router " +
	    "by.", values: "an IPv4 address", default: "the numerically " +
	    "lowest IP address of the router", undo: "clear the field" },
	"ldp.fib-update": { label: "Update the FIB", keyword: "fib-update " +
	    "yes | no", definition: "Whether ldpd installs its labels in the " +
	    "kernel's label forwarding table.", values: "yes or no",
	    default: "yes", risk: "high: with no, this router's labels are " +
	    "not installed", undo: "choose (not set)" },
	"ldp.interface": { label: "New interface", keyword: "interface name",
	    definition: "Adds an interface to an address family. ldpd " +
	    "discovers neighbors on it with link hellos.", values: "an " +
	    "interface's name, in an address family", default: "none",
	    undo: "Delete" },
	"ldp.link-hello-holdtime": { label: "Hello hold time",
	    keyword: "link-hello-holdtime seconds", definition: "Seconds " +
	    "ldpd waits between two hellos from a neighbor before it marks " +
	    "the neighbor down.", values: "3 to 65535 seconds", default: "15",
	    undo: "clear the field", applies: "an interface; set in its " +
	    "address family or at the top level, it applies to the " +
	    "interfaces after it" },
	"ldp.link-hello-interval": { label: "Hello interval",
	    keyword: "link-hello-interval seconds", definition: "Seconds " +
	    "between the link hellos ldpd sends on the interface.",
	    values: "1 to 65535 seconds", default: "5", undo: "clear the field",
	    applies: "an interface; set in its address family or at the top " +
	    "level, it applies to the interfaces after it" },

	/* dvmrpd's configuration */
	"dvmrp.fib-update": { label: "Update the MFC", keyword: "fib-update " +
	    "yes | no", definition: "Whether dvmrpd installs its state in " +
	    "the kernel's multicast forwarding cache.", values: "yes or no",
	    default: "yes", risk: "high: with no, this router forwards no " +
	    "multicast", undo: "choose (not set)" },
	"dvmrp.interface": { label: "New interface", keyword: "interface name",
	    definition: "Adds an interface. dvmrpd runs IGMP and DVMRP on " +
	    "it, unless it is passive.", values: "an interface's name",
	    default: "none", undo: "Delete" },
	"dvmrp.metric": { label: "Metric", keyword: "metric cost",
	    definition: "The interface's cost in DVMRP's route calculation.",
	    values: "1 to 31", default: "1", undo: "clear the field",
	    applies: "an interface; set in a group or at the top level, it " +
	    "applies to the interfaces after it" },
	"dvmrp.passive": { label: "Passive", keyword: "passive",
	    definition: "dvmrpd sends and accepts no IGMP or DVMRP packets " +
	    "on the interface.", values: "on or off", default: "off",
	    undo: "clear the box", applies: "an interface" },
	"dvmrp.igmp-version": { label: "IGMP version",
	    keyword: "igmp-version number", definition: "The newest IGMP " +
	    "version dvmrpd uses on the interface.", values: "1 or 2",
	    default: "2", undo: "clear the field", applies: "an interface; " +
	    "set in a group or at the top level, it applies to the " +
	    "interfaces after it" },
	"dvmrp.query-interval": { label: "Query interval",
	    keyword: "query-interval seconds", definition: "Seconds between " +
	    "the IGMP queries that look for group members.", values: "1 to " +
	    "65535 seconds", default: "125", undo: "clear the field",
	    applies: "an interface; set in a group or at the top level, it " +
	    "applies to the interfaces after it" },

	/* ntpd's configuration */
	"ntp.server": { label: "Server", keyword: "server address [trusted] " +
	    "[weight weight]", definition: "An NTP server to synchronize to. " +
	    "If its name has several addresses, ntpd uses the first that " +
	    "answers.", values: "a host name or an IP address", default: "none",
	    undo: "Delete" },
	"ntp.servers": { label: "Servers", keyword: "servers address " +
	    "[trusted] [weight weight]", definition: "A name whose every " +
	    "address is an NTP server to synchronize to, such as a pool.",
	    values: "a host name or an IP address", default: "none",
	    undo: "Delete" },
	"ntp.sensor": { label: "Sensor", keyword: "sensor device [correction " +
	    "microseconds] [refid ID] [stratum stratum] [trusted] [weight " +
	    "weight]", definition: "A timedelta sensor used as a time " +
	    "source, such as a GPS receiver. * uses every sensor found; one " +
	    "that does not exist is ignored.", values: "a sensor's name, " +
	    "such as nmea0, or *", default: "none", undo: "Delete" },
	"ntp.constraint": { label: "Constraint", keyword: "constraint from " +
	    "url [address ...]", definition: "An HTTPS server whose Date " +
	    "ntpd checks NTP's time against. Replies outside a range near " +
	    "the constraints are discarded.", values: "a URL, host name or " +
	    "IP address", default: "none", undo: "Delete" },
	"ntp.constraints": { label: "Constraints", keyword: "constraints " +
	    "from url", definition: "An HTTPS server name whose every " +
	    "address is a constraint; ntpd uses their median.", values: "a " +
	    "URL, host name or IP address", default: "none", undo: "Delete" },
	"ntp.listen": { label: "Listen on", keyword: "listen on address " +
	    "[rtable table-id]", definition: "An address ntpd answers NTP " +
	    "queries on. * listens on every local address.", values: "an IP " +
	    "address, a host name, or *", default: "none: ntpd answers no one",
	    undo: "Delete" },
	"ntp.query": { label: "Query from", keyword: "query from sourceaddr",
	    definition: "The local address ntpd sends its queries from, for " +
	    "the servers listed after it.", values: "a local IP address",
	    default: "the address the route gives", undo: "Delete" },
	"ntp.trusted": { label: "Trusted", keyword: "trusted",
	    definition: "Time from this source skips the constraint check. " +
	    "Useful at boot, where no constraint can be reached.",
	    values: "on or off", default: "off", risk: "high: a forged reply " +
	    "from this source is believed", undo: "clear the box",
	    applies: "server, servers and sensor lines" },
	"ntp.weight": { label: "Weight", keyword: "weight weight-value",
	    definition: "This source's influence on the offset, relative to " +
	    "the others: 5 counts five times as much as 1.", values: "1 to 10",
	    default: "1", undo: "clear the field", applies: "server, servers " +
	    "and sensor lines" },
	"ntp.correction": { label: "Correction", keyword: "correction " +
	    "microseconds", definition: "Microseconds added to the sensor's " +
	    "offset, to make up for a known lag.", values: "-127000000 to " +
	    "127000000 microseconds", default: "0", undo: "clear the field",
	    applies: "sensor lines" },
	"ntp.refid": { label: "Reference ID", keyword: "refid ID-string",
	    definition: "The reference ID ntpd gives its clients for this " +
	    "sensor, such as GPS.", values: "1 to 4 characters", default: "a " +
	    "generic ID", undo: "clear the field", applies: "sensor lines" },
	"ntp.stratum": { label: "Stratum", keyword: "stratum stratum-value",
	    definition: "The stratum ntpd gives this sensor's time.",
	    values: "1 to 15", default: "1", undo: "clear the field",
	    applies: "sensor lines" },
	"ntp.addresses": { label: "Addresses", keyword: "constraint from url " +
	    "address ...", definition: "Addresses to try for the URL, in " +
	    "turn. The path and the certificate's name still come from the " +
	    "URL.", values: "IP addresses, one a line", default: "the URL's " +
	    "own", undo: "clear the lines", applies: "constraint from lines" },
	"ntp.rtable": { label: "Routing table", keyword: "rtable table-id",
	    definition: "The routing table ntpd listens in.", values: "0 to " +
	    "255", default: "the table ntpd runs in", undo: "clear the field",
	    applies: "listen on lines" },

	/* sasyncd's configuration */
	"sasync.interface": { label: "CARP interface", keyword: "interface " +
	    "interface", definition: "The carp(4) interface whose master or " +
	    "backup state sasyncd follows.", values: "a carp interface's name",
	    default: "none", undo: "clear the field" },
	"sasync.group": { label: "Demotion group", keyword: "group group",
	    definition: "The interface group whose demotion counter sasyncd " +
	    "raises until its first synchronization, so carp does not " +
	    "preempt before then.", values: "an interface group's name",
	    default: "carp", undo: "clear the field" },
	"sasync.mode": { label: "Forced mode", keyword: "mode master | slave " +
	    "| skipslave", definition: "master or slave forces sasyncd's " +
	    "role, for debugging. skipslave does not synchronize SAs or " +
	    "flows whose source or destination is a peer.", values: "master, " +
	    "slave or skipslave", default: "follow the carp interface's state",
	    undo: "choose (not set)" },
	"sasync.peer": { label: "Peer", keyword: "peer address",
	    definition: "Another sasyncd host to synchronize with.",
	    values: "a host name or an IP address", default: "none",
	    undo: "Delete" },
	"sasync.listen": { label: "Listen on", keyword: "listen on address " +
	    "[inet | inet6] [port port]", definition: "The local address, " +
	    "host name or interface sasyncd listens on for its peers.",
	    values: "an address, a host name or an interface's name",
	    default: "every local address", undo: "Delete" },
	"sasync.family": { label: "Address family", keyword: "inet | inet6",
	    definition: "For an interface, the address family to listen with.",
	    values: "inet or inet6", default: "both", undo: "choose (not set)",
	    applies: "listen on lines" },
	"sasync.port": { label: "Port", keyword: "port port",
	    definition: "The TCP port sasyncd listens on. A port out of " +
	    "range is taken as 500.", values: "1 to 65535", default: "500",
	    undo: "clear the field", applies: "listen on lines" },
	"sasync.sharedkey": { label: "Shared key", keyword: "sharedkey key",
	    definition: "The AES key that encrypts what the peers send each " +
	    "other. Every peer needs the same key; sasyncd needs one to start.",
	    values: "16, 24 or 32 bytes: text, or 0x and hexadecimal digits",
	    default: "none", secret: true, undo: "clear the field" },
	"sasync.flushmode": { label: "Flush mode", keyword: "flushmode sync " +
	    "| startup | never", definition: "When the master passes SADB " +
	    "flushes to its slaves: sync passes each one; startup also " +
	    "flushes each slave as it connects; never passes none.",
	    values: "sync, startup or never", default: "startup",
	    undo: "choose (not set)" },
	"sasync.control": { label: "Controls", keyword: "control isakmpd | " +
	    "iked | all | none", definition: "The IKE daemon sasyncd makes " +
	    "active or passive as its role changes; none only synchronizes " +
	    "SAs.", values: "isakmpd, iked, all or none", default: "isakmpd",
	    undo: "choose (not set)" },

	/* rad's configuration */
	"rad.interface": { label: "Interface", keyword: "interface name [{ " +
	    "... }]", definition: "An interface or interface group rad sends " +
	    "router advertisements on. Settings inside it override the " +
	    "global ones.", values: "an interface's or group's name",
	    default: "none: rad needs at least one", undo: "Delete" },
	"rad.prefix": { label: "Prefix", keyword: "prefix prefix [{ ... }]",
	    definition: "A prefix to advertise on the interface.",
	    values: "an IPv6 prefix; /64 if no length is given",
	    default: "the interface's own prefixes, unless no auto prefix",
	    undo: "Delete" },
	"rad.autoprefix": { label: "Auto prefix", keyword: "auto prefix [{ " +
	    "... }]", definition: "Options for the prefixes rad finds on the " +
	    "interface's own addresses.", values: "a block of prefix options",
	    default: "on, with default options", undo: "Delete" },
	"rad.noautoprefix": { label: "No auto prefix", keyword: "no auto " +
	    "prefix", definition: "Advertise only the prefixes listed, and " +
	    "none from the interface's addresses.", values: "present or absent",
	    default: "absent", undo: "Delete" },
	"rad.autonomous": { label: "SLAAC", keyword: "autonomous " +
	    "address-configuration yes | no", definition: "Whether hosts may " +
	    "make their own addresses from this prefix.", values: "yes or no",
	    default: "yes", undo: "choose (not set)" },
	"rad.onlink": { label: "On link", keyword: "on-link yes | no",
	    definition: "Whether the prefix is on this link.", values: "yes " +
	    "or no", default: "yes", undo: "choose (not set)" },
	"rad.pltime": { label: "Preferred lifetime", keyword: "preferred " +
	    "lifetime seconds", definition: "How long addresses made from " +
	    "the prefix stay preferred. A shorter lifetime of the " +
	    "interface's own address wins.", values: "seconds", default: "2700",
	    undo: "clear the field" },
	"rad.vltime": { label: "Valid lifetime", keyword: "valid lifetime " +
	    "seconds", definition: "How long addresses made from the prefix " +
	    "stay valid. A shorter lifetime of the interface's own address " +
	    "wins.", values: "seconds", default: "3600", undo: "clear the " +
	    "field" },
	"rad.dns": { label: "DNS", keyword: "dns { ... }", definition: "Name " +
	    "servers and search domains to advertise. It needs a nameserver " +
	    "or a search line.", values: "a block", default: "none",
	    undo: "Delete" },
	"rad.nameserver": { label: "Name servers", keyword: "nameserver " +
	    "address | { address ... }", definition: "IPv6 name servers " +
	    "hosts may use.", values: "IPv6 addresses, one a line",
	    default: "none", undo: "clear the lines" },
	"rad.search": { label: "Search domains", keyword: "search domain | { " +
	    "domain ... }", definition: "Domains hosts add to names they " +
	    "look up.", values: "domain names, one a line", default: "none",
	    undo: "clear the lines" },
	"rad.lifetime": { label: "Lifetime", keyword: "lifetime seconds",
	    definition: "How long hosts may use the DNS or NAT64 option " +
	    "after an advertisement. For NAT64, 0 says to stop using the " +
	    "prefix.", values: "seconds; at most 65528 for NAT64",
	    default: "3600", undo: "clear the field" },
	"rad.nat64": { label: "NAT64 prefix", keyword: "nat64 prefix prefix " +
	    "[{ lifetime seconds }]", definition: "A prefix whose IPv6 " +
	    "addresses stand for IPv4 ones, through a NAT64 translator.",
	    values: "an IPv6 prefix of length 32, 40, 48, 56, 64 or 96; 96 " +
	    "if no length is given", default: "none", undo: "Delete" },
	"rad.defrouter": { label: "Default router", keyword: "default router " +
	    "yes | no", definition: "Whether hosts may use this router as " +
	    "their default route.", values: "yes or no", default: "yes",
	    undo: "choose (not set)", applies: "in the global settings, or " +
	    "in an interface, where it overrides them" },
	"rad.managed": { label: "Managed (DHCPv6)", keyword: "managed " +
	    "address configuration yes | no", definition: "Tells hosts to " +
	    "get addresses from DHCPv6.", values: "yes or no", default: "no",
	    undo: "choose (not set)", applies: "in the global settings, or " +
	    "in an interface, where it overrides them" },
	"rad.otherconf": { label: "Other (DHCPv6)", keyword: "other " +
	    "configuration yes | no", definition: "Tells hosts to get other " +
	    "settings, such as NTP or DNS servers, from DHCPv6.",
	    values: "yes or no", default: "no", undo: "choose (not set)",
	    applies: "in the global settings, or in an interface, where it " +
	    "overrides them" },
	"rad.rtlifetime": { label: "Router lifetime", keyword: "router " +
	    "lifetime seconds", definition: "How long hosts may use this " +
	    "router as a default router after an advertisement.",
	    values: "seconds", default: "3600", undo: "clear the field",
	    applies: "in the global settings, or in an interface, where it " +
	    "overrides them" },
	"rad.rtpref": { label: "Router preference", keyword: "router " +
	    "preference high | medium | low", definition: "Whether hosts " +
	    "should prefer this router over other default routers.",
	    values: "high, medium or low", default: "medium", undo: "choose " +
	    "(not set)", applies: "in the global settings, or in an " +
	    "interface, where it overrides them" },
	"rad.hoplimit": { label: "Hop limit", keyword: "hop limit hops",
	    definition: "The hop limit hosts put on the packets they send.",
	    values: "a number of hops; 0 leaves it to the hosts", default: "0",
	    undo: "clear the field", applies: "in the global settings, or in " +
	    "an interface, where it overrides them" },
	"rad.mtu": { label: "MTU", keyword: "mtu bytes", definition: "The " +
	    "link MTU to advertise, where it is not well known.",
	    values: "bytes; 0 advertises none", default: "0", undo: "clear " +
	    "the field", applies: "in the global settings, or in an " +
	    "interface, where it overrides them" },
	"rad.lladdr": { label: "Source link-layer address", keyword: "source " +
	    "link-layer address yes | no", definition: "Whether " +
	    "advertisements carry the sending interface's link-layer address.",
	    values: "yes or no", default: "yes", undo: "choose (not set)",
	    applies: "in the global settings, or in an interface, where it " +
	    "overrides them" },
	"rad.reachable": { label: "Reachable time", keyword: "reachable time " +
	    "number", definition: "Milliseconds a host takes a neighbor to " +
	    "be reachable. OpenBSD hosts ignore it.", values: "milliseconds; " +
	    "0 leaves it to the hosts", default: "0", undo: "clear the field",
	    applies: "in the global settings, or in an interface, where it " +
	    "overrides them" },
	"rad.retrans": { label: "Retransmit timer", keyword: "retrans timer " +
	    "number", definition: "Milliseconds between neighbor " +
	    "solicitations. OpenBSD hosts ignore it.",
	    values: "milliseconds; 0 leaves it to the hosts", default: "0",
	    undo: "clear the field", applies: "in the global settings, or in " +
	    "an interface, where it overrides them" },

	/* relayd's configuration */
	"relay.relay": { label: "Relay", keyword: "relay name { ... }",
	    definition: "A relay: relayd accepts each connection itself and " +
	    "opens another to a host it forwards to, so a protocol can " +
	    "filter or change what passes, and TLS can end here.",
	    values: "a name", default: "none", undo: "Delete" },
	"relay.listen": { label: "Listen on", keyword: "listen on address " +
	    "[tcp | udp] port port [tls] [interface name] [pflog]",
	    definition: "The address clients connect to. An interface or a " +
	    "host name gives each of its local addresses.", values: "an " +
	    "address, a host name or an interface's name", default: "none: a " +
	    "relay or redirection needs one", undo: "Delete" },
	"relay.transport": { label: "IP protocol", keyword: "tcp | udp",
	    definition: "For a redirection, the IP protocol it redirects.",
	    values: "tcp or udp", default: "tcp", undo: "choose (not set)",
	    applies: "listen on lines" },
	"relay.port": { label: "Port", keyword: "port port", definition: "On " +
	    "a listen on line, the port clients connect to; a redirection " +
	    "takes a range, min:max. On a forward line, the port of the hosts.",
	    values: "a port number or a service's name", default: "on a " +
	    "forward line, the listen on line's port", undo: "clear the field",
	    applies: "listen on, forward to and route to lines" },
	"relay.tls": { label: "TLS", keyword: "tls", definition: "The relay " +
	    "accepts TLS connections, with the keypair its protocol names.",
	    values: "on or off", default: "off", undo: "clear the check box",
	    applies: "listen on lines" },
	"relay.interface": { label: "Interface", keyword: "interface name",
	    definition: "On a redirection's listen on line, the one " +
	    "interface its rule applies to. On a route to line, the " +
	    "interface toward the hosts, which it needs.", values: "an " +
	    "interface's name", default: "any interface", undo: "clear the " +
	    "field", applies: "redirections' listen on and route to lines" },
	"relay.pflog": { label: "Log to pflog", keyword: "pflog",
	    definition: "Logs the packets the redirection's rule matches to " +
	    "pflog(4).", values: "on or off", default: "off", undo: "clear " +
	    "the check box", applies: "listen on lines" },
	"relay.forward": { label: "Forward to", keyword: "forward to target " +
	    "[options]", definition: "Where connections go: a table of " +
	    "hosts, or for a relay one address, destination or nat lookup. " +
	    "Each line may name a table; the first is the main one, the next " +
	    "its backup.", values: "a table's name in angle brackets, such " +
	    "as <web>, or for a relay an address", default: "none: one is " +
	    "needed", undo: "Delete" },
	"relay.mode": { label: "Mode", keyword: "mode mode [key]",
	    definition: "How a host of the table is chosen for each " +
	    "connection. hash and loadbalance are for relays, least-states " +
	    "for redirections.", values: "roundrobin, random, source-hash, " +
	    "hash, loadbalance or least-states, then a key for the hashes",
	    default: "roundrobin", undo: "clear the field",
	    applies: "forward to and route to lines" },
	"relay.check": { label: "Check", keyword: "check method ...",
	    definition: "How relayd tests each host of the table. A " +
	    "redirection needs one. A script runs as _relayd for each host.",
	    values: "icmp; tcp; tls; http or https path [host name] code N " +
	    "or digest D; send data expect pattern [tls]; binary send hex " +
	    "expect hex [tls]; script path", default: "none", undo: "clear " +
	    "the field", applies: "forward to and route to lines" },
	"relay.timeout": { label: "Timeout", keyword: "timeout milliseconds",
	    definition: "How long a check of a host may take. On a forward " +
	    "line, it overrides the global one. It must not be more than the " +
	    "interval.", values: "milliseconds", default: "200",
	    undo: "clear the field", applies: "the global settings and " +
	    "forward to lines" },
	"relay.interval": { label: "Interval", keyword: "interval seconds",
	    definition: "How often each host is checked. On a forward line, " +
	    "it overrides the global one, and must be a multiple of it.",
	    values: "seconds", default: "10", undo: "clear the field",
	    applies: "the global settings and forward to lines" },
	"relay.demote": { label: "Demote group", keyword: "demote group",
	    definition: "The interface group whose carp demotion counter " +
	    "rises while every host of the table is down.", values: "an " +
	    "interface group's name", default: "none", undo: "clear the field",
	    applies: "forward to and route to lines" },
	"relay.retry": { label: "Retries", keyword: "retry number",
	    definition: "How many more times a failed check, or a relay's " +
	    "failed connection, is tried before the host is down.",
	    values: "a number", default: "0", undo: "clear the field",
	    applies: "forward to and route to lines, and a table's hosts" },
	"relay.inet": { label: "To IPv4", keyword: "inet", definition: "A " +
	    "relay forwards a connection made to an IPv6 address to the IPv4 " +
	    "address in its last 4 bytes.", values: "on or off", default: "off",
	    undo: "clear the check box", applies: "relays' forward lines" },
	"relay.inet6": { label: "To IPv6 prefix", keyword: "inet6 prefix",
	    definition: "A relay forwards a connection made to an IPv4 " +
	    "address to this IPv6 prefix with the IPv4 address as its last 4 " +
	    "bytes.", values: "an IPv6 address", default: "none",
	    undo: "clear the field", applies: "relays' forward lines" },
	"relay.proxy": { label: "PROXY protocol", keyword: "proxy-protocol " +
	    "v1 | v2", definition: "A relay sends a PROXY protocol header " +
	    "with the client's address and port before the data.",
	    values: "v1 or v2", default: "none", undo: "choose (not set)",
	    applies: "relays' forward lines" },
	"relay.forwardtls": { label: "Forward with TLS to",
	    keyword: "forward with tls to target [options]", definition: "As " +
	    "forward to, but the relay connects to the hosts with TLS; its " +
	    "protocol's ca file checks their certificates.", values: "a " +
	    "table's name in angle brackets, such as <web>, or for a relay " +
	    "an address", default: "none", undo: "Delete" },
	"relay.transparent": { label: "Transparent forward to",
	    keyword: "transparent forward to target [options]",
	    definition: "As a relay's forward to, but the connection to the " +
	    "host keeps the client's address as its source.", values: "a " +
	    "table's name in angle brackets, such as <web>, or for a relay " +
	    "an address", default: "none", undo: "Delete" },
	"relay.transparenttls": { label: "Transparent forward with TLS to",
	    keyword: "transparent forward with tls to target [options]",
	    definition: "Transparent forward to, with TLS to the hosts.",
	    values: "a table's name in angle brackets, such as <web>, or for " +
	    "a relay an address", default: "none", undo: "Delete" },
	"relay.useproto": { label: "Protocol", keyword: "protocol name",
	    definition: "The protocol whose settings and rules the relay uses.",
	    values: "a protocol's name", default: "plain TCP", undo: "Delete" },
	"relay.session": { label: "Session timeout", keyword: "session " +
	    "timeout seconds", definition: "How long an idle session lasts.",
	    values: "seconds, up to 2147483647", default: "600",
	    undo: "Delete" },
	"relay.redirect": { label: "Redirection", keyword: "redirect name { " +
	    "... }", definition: "A redirection: pf rewrites the destination " +
	    "of each connection to a host of the table, with an rdr-to rule.",
	    values: "a name", default: "none", undo: "Delete" },
	"relay.routeto": { label: "Route to", keyword: "route to <table> " +
	    "[options] [interface name]", definition: "As forward to, but pf " +
	    "routes the packets to the host without changing their " +
	    "destination, for direct server return.", values: "a table's " +
	    "name in angle brackets", default: "none", undo: "Delete" },
	"relay.disable": { label: "Disabled", keyword: "disable",
	    definition: "The table, redirection or router starts disabled; " +
	    "relayctl enables it.", values: "present or absent",
	    default: "absent", undo: "Delete" },
	"relay.sticky": { label: "Sticky address", keyword: "sticky-address",
	    definition: "Connections from one source go to the same host.",
	    values: "present or absent", default: "absent", undo: "Delete" },
	"relay.pftag": { label: "pf tag", keyword: "pftag name",
	    definition: "The redirection's rule tags the packets it passes, " +
	    "for pf rules to match.", values: "a tag name", default: "none",
	    undo: "Delete" },
	"relay.matchpftag": { label: "Match pf tag", keyword: "match pftag " +
	    "name", definition: "As pftag, but the rule is match in rather " +
	    "than pass in quick, so pf's later rules decide.", values: "a " +
	    "tag name", default: "none", undo: "Delete" },
	"relay.table": { label: "Table", keyword: "table <name> [disable] { " +
	    "host ... }", definition: "A set of hosts that redirections, " +
	    "relays and routers forward to. A redirection's table becomes a " +
	    "pf table.", values: "a name, written in angle brackets",
	    default: "none", undo: "Delete" },
	"relay.hosts": { label: "Hosts", keyword: "{ host [retry N] [parent " +
	    "N] [priority N] [ip ttl N], ... }", definition: "The table's " +
	    "hosts, each with its options. parent takes the state of the " +
	    "host with that number; priority is a router's route priority.",
	    values: "one host a line: an address or a host name, then its " +
	    "options", default: "none: a table needs one", undo: "clear the " +
	    "lines" },
	"relay.proto": { label: "TCP protocol", keyword: "protocol name { " +
	    "... }", definition: "Settings and rules a relay can use: TCP " +
	    "and TLS options, and rules that pass, block or change " +
	    "connections.", values: "a name", default: "none", undo: "Delete" },
	"relay.tlsopts": { label: "TLS options", keyword: "tls option | { " +
	    "option, ... }", definition: "The TLS settings: ciphers, " +
	    "keypair, ca file for checking hosts, ca key and certificate for " +
	    "inspection, protocols and session tickets.", values: "the " +
	    "options as relayd.conf writes them", default: "relayd's defaults",
	    undo: "Delete" },
	"relay.tcpopts": { label: "TCP options", keyword: "tcp option | { " +
	    "option, ... }", definition: "The TCP settings: nodelay, sack, " +
	    "splice, backlog, socket buffer and ip ttl or minttl.",
	    values: "the options as relayd.conf writes them",
	    default: "splice, backlog 10", undo: "Delete" },
	"relay.httpopts": { label: "HTTP options", keyword: "http option | { " +
	    "option, ... }", definition: "The HTTP settings: headerlen and " +
	    "websockets.", values: "the options as relayd.conf writes them",
	    default: "headerlen 8192, no websockets", undo: "Delete" },
	"relay.returnerror": { label: "Return error", keyword: "return error " +
	    "[style string]", definition: "A blocked connection gets an " +
	    "error page rather than being closed.", values: "nothing, or " +
	    "style and a CSS string", default: "closed", undo: "Delete" },
	"relay.pass": { label: "Pass", keyword: "pass [request | response] " +
	    "[quick] [from addr] [to addr] [options]", definition: "A rule " +
	    "that lets the matching connections, requests or responses " +
	    "through, and may change them.", values: "the rule as " +
	    "relayd.conf writes it", default: "pass", undo: "Delete" },
	"relay.block": { label: "Block", keyword: "block [request | " +
	    "response] [quick] [from addr] [to addr] [options]",
	    definition: "A rule that stops the matching connections, " +
	    "requests or responses.", values: "the rule as relayd.conf " +
	    "writes it", default: "none", undo: "Delete" },
	"relay.match": { label: "Match", keyword: "match [request | " +
	    "response] [quick] [from addr] [to addr] [options]",
	    definition: "A rule that changes or tags what it matches and " +
	    "leaves the decision to the other rules.", values: "the rule as " +
	    "relayd.conf writes it", default: "none", undo: "Delete" },
	"relay.httpproto": { label: "HTTP protocol", keyword: "http protocol " +
	    "name { ... }", definition: "A protocol for HTTP, or HTTPS " +
	    "through TLS: its rules can match headers, cookies, paths, " +
	    "queries and URLs.", values: "a name", default: "none",
	    undo: "Delete" },
	"relay.tcpproto": { label: "TCP protocol", keyword: "tcp protocol " +
	    "name { ... }", definition: "A protocol for any TCP service, the " +
	    "same as protocol alone.", values: "a name", default: "none",
	    undo: "Delete" },
	"relay.dnsproto": { label: "DNS protocol", keyword: "dns protocol " +
	    "name { ... }", definition: "A protocol for DNS over UDP: relayd " +
	    "replaces each query's ID with a random one.", values: "a name",
	    default: "none", undo: "Delete" },
	"relay.router": { label: "Router", keyword: "router name { ... }",
	    definition: "Routes relayd adds through the gateways of a table " +
	    "that pass their checks, and takes away when they fail.",
	    values: "a name", default: "none", undo: "Delete" },
	"relay.route": { label: "Route", keyword: "route address/prefix",
	    definition: "A destination the router's gateways reach.",
	    values: "an address with a prefix length", default: "none: a " +
	    "router needs one", undo: "Delete" },
	"relay.rtable": { label: "Routing table", keyword: "rtable id",
	    definition: "The routing table the router's routes go in.",
	    values: "a routing table's number", default: "0", undo: "Delete" },
	"relay.rtlabel": { label: "Route label", keyword: "rtlabel label",
	    definition: "A label the router's routes carry.", values: "a label",
	    default: "none", undo: "Delete" },
	"relay.prefork": { label: "Relay processes", keyword: "prefork number",
	    definition: "How many processes handle the relays' connections; " +
	    "each handles every relay.", values: "a number, 1 or more",
	    default: "3", undo: "clear the field" },
	"relay.loglevel": { label: "Log level", keyword: "log level brief | " +
	    "verbose", definition: "verbose logs what relayd -v would.",
	    values: "brief or verbose", default: "brief", undo: "choose (not " +
	    "set)" },
	"relay.logstate": { label: "Log host state changes", keyword: "log " +
	    "state changes", definition: "Logs each change of a host's " +
	    "state: up, down or unknown.", values: "on or off", default: "off",
	    undo: "clear the check box" },
	"relay.logchecks": { label: "Log every host check", keyword: "log " +
	    "host checks", definition: "Logs every check of every host, its " +
	    "state changed or not.", values: "on or off", default: "off",
	    undo: "clear the check box" },
	"relay.logconn": { label: "Log connections", keyword: "log connection",
	    definition: "Logs every connection through the relays.",
	    values: "on or off", default: "off", undo: "clear the check box" },
	"relay.logerrors": { label: "Log connection errors", keyword: "log " +
	    "connection errors", definition: "Logs only the relays' " +
	    "connections that fail.", values: "on or off", default: "off",
	    undo: "clear the check box" },
	"relay.agentx": { label: "AgentX", keyword: "agentx [context name] " +
	    "[path path]", definition: "Gives relayd's numbers to an AgentX " +
	    "daemon such as snmpd.", values: "on or off", default: "off",
	    undo: "clear the check box" },
	"relay.socket": { label: "Control socket", keyword: "socket path",
	    definition: "Where relayctl reaches relayd. nsh's shows use the " +
	    "default.", values: "a path", default: "/var/run/relayd.sock",
	    undo: "clear the field" }
};

var regOpen = {};	/* ids of the fields whose definitions are open */

/* a module's entries in order, each with its key, for the inspector */
function regList(module) {
	return Object.keys(REGISTRY).filter(function (id) {
		return id.indexOf(module + ".") === 0;
	}).map(function (id) {
		return Object.assign({ key: id.slice(module.length + 1) },
		    REGISTRY[id]);
	});
}

var IFDEFS = regList("if");
var BRDEFS = regList("bridge");

/* id's entry; a missing entry is a bug in the page, so throw */
function reg(id) {
	if (!REGISTRY[id])
		throw new Error("no registry entry for " + id);
	return REGISTRY[id];
}

/* an entry's values, default and undo, or what its kind implies */
function regValues(r) {
	if (r.values)
		return r.values;
	if (r.kind === "number")
		return r.min + " to " + r.max + (r.units ? " " + r.units : "");
	if (r.kind === "choice")
		return r.choices.join(", ");
	return "on or off";
}

function regDefault(r) {
	if (r.default)
		return r.default;
	return r.kind === "noflag" ? "on" : "off";
}

function regUndo(r, key) {
	if (r.undo)
		return r.undo;
	if (r.kind === "noflag")
		return key + ", or no " + key;
	if (r.kind === "flag")
		return "no " + key + ", or " + key;
	if (r.kind === "words" || r.kind === "lines")
		return "no " + key + (r.kind === "words" ? " <word>" :
		    " <line>");
	return "no " + key;
}

/* where an entry applies: its drivers, or else its module's scope */
function regApplies(r, m) {
	if (r.applies)
		return r.applies;
	if (r.on)
		return r.on.join(", ") + " interfaces";
	if (r.wireless)
		return "802.11 interfaces";
	if (r.physical)
		return "physical interfaces";
	return m.scope;
}

/* a link to a manual page, such as pf.conf.5, for REGISTRY_OS */
function regManual(name) {
	var a = el("a", name.replace(/\.(\d)$/, "($1)") + ", " + REGISTRY_OS);

	if (name === "nsh.8")
		return el("span", "nsh(8)");
	a.href = "https://man.openbsd.org/" + REGISTRY_OS.replace(" ", "-") +
	    "/" + name;
	a.target = "_blank";
	a.rel = "noreferrer";
	return a;
}

/*
 * Draw a field: its label, its control, and a hint or else its keyword,
 * with a ? button that shows the registry's entry. A definition stays
 * open when the field is redrawn.
 */
function regField(into, id, c, hint, label) {
	var r = reg(id), m = REGISTRY_MODULES[id.split(".")[0]];
	var row = el("div", null, "field"), info = el("div", null, "info");
	var what = el("button", "?", "what"), def = el("div", null, "def");
	var dl = el("dl"), name = label || r.label;
	var rows = [["Values", regValues(r)], ["Default", regDefault(r)],
	    ["Applies to", regApplies(r, m)], ["Needs", r.needs],
	    ["Risk", r.risk], ["Secret", r.secret ? "yes; anyone who " +
	    "can read the configuration can see it" : ""],
	    ["Undo", regUndo(r, id.split(".").pop())],
	    ["Keyword", r.keyword], ["Manual", regManual(r.man || m.man)],
	    ["Checked by", m.check]];

	row.dataset.reg = id;
	row.appendChild(el("label", name));
	row.appendChild(c);
	info.appendChild(hint || r.hint ? el("span", hint || r.hint) :
	    el("code", r.keyword));
	what.type = "button";
	what.title = "What " + name + " is";
	what.setAttribute("aria-label", "What " + name + " is");
	info.appendChild(what);
	row.appendChild(info);
	def.appendChild(el("p", r.definition));
	rows.forEach(function (x) {
		var dd = el("dd");

		if (!x[1])
			return;
		dl.appendChild(el("dt", x[0]));
		if (typeof x[1] === "string")
			dd.textContent = x[1];
		else
			dd.appendChild(x[1]);
		dl.appendChild(dd);
	});
	def.appendChild(dl);
	row.appendChild(def);
	def.hidden = !regOpen[id];
	what.setAttribute("aria-expanded", String(!def.hidden));
	what.addEventListener("click", function () {
		regOpen[id] = def.hidden;
		def.hidden = !regOpen[id];
		what.setAttribute("aria-expanded", String(!def.hidden));
	});
	into.appendChild(row);
	return row;
}
