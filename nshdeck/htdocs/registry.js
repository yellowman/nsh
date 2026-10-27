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
	    check: "relayd -n, at Validate and at commit" },
	snmp: { scope: "snmpd's configuration", man: "snmpd.conf.5",
	    check: "snmpd -n, at Validate and at commit" },
	ldap: { scope: "ldapd's configuration", man: "ldapd.conf.5",
	    check: "ldapd -n, at Validate and at commit" },
	nppp: { scope: "npppd's configuration", man: "npppd.conf.5",
	    check: "npppd -n, at Validate and at commit" },
	smtp: { scope: "smtpd's configuration", man: "smtpd.conf.5",
	    check: "smtpd -n, at Validate and at commit" },
	ifstate: { scope: "ifstated's configuration", man: "ifstated.conf.5",
	    check: "ifstated -n, at Validate and at commit" },
	ipsec: { scope: "isakmpd's configuration", man: "ipsec.conf.5",
	    check: "ipsecctl -n, at Validate and at commit" },
	ike: { scope: "iked's configuration", man: "iked.conf.5",
	    check: "iked -n, at Validate and at commit" },
	dhcp: { scope: "dhcpd's configuration", man: "dhcpd.conf.5",
	    check: "dhcpd -n, at Validate and at commit" },
	sshd: { scope: "sshd's configuration", man: "sshd_config.5",
	    check: "sshd -t, at Validate and at commit" },
	route: { scope: "static routes", man: "nsh.8",
	    check: "nsh, as each line is staged" }
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
	"bgp.holdtime": { label: "Hold time", keyword: "holdtime seconds",
	    definition: "How long bgpd waits to hear from the peer before it " +
	    "ends the session.", values: "seconds", default: "the global " +
	    "holdtime", undo: "clear the field", applies: "neighbors and " +
	    "groups" },
	"bgp.holdtime-min": { label: "Least hold time", keyword: "holdtime " +
	    "min seconds", definition: "The shortest hold time bgpd accepts " +
	    "from the peer.", values: "seconds", default: "the global " +
	    "holdtime min", undo: "clear the field", applies: "neighbors and " +
	    "groups" },
	"bgp.staletime": { label: "Stale time", keyword: "staletime seconds",
	    definition: "How long, at most, bgpd keeps the peer's routes " +
	    "after a graceful restart.", values: "seconds", default: "the " +
	    "global staletime", undo: "clear the field", applies: "neighbors " +
	    "and groups" },
	"bgp.md5-password": { label: "TCP MD5 password", keyword: "tcp " +
	    "md5sig password secret", definition: "Signs the session's TCP " +
	    "segments with a shared secret, as RFC 2385 describes. After a " +
	    "change, the session must be reset to use the new secret.",
	    values: "text", default: "none", secret: true, undo: "clear the " +
	    "field", applies: "neighbors and groups" },
	"bgp.md5-key": { label: "TCP MD5 key", keyword: "tcp md5sig key secret",
	    definition: "As the TCP MD5 password, with the secret given in " +
	    "hexadecimal.", values: "hexadecimal digits", default: "none",
	    secret: true, undo: "clear the field", applies: "neighbors and " +
	    "groups" },
	"bgp.ipsec": { label: "IPsec", keyword: "ipsec (ah|esp) (in|out) spi " +
	    "spi-number authspec [encspec], or ipsec (ah|esp) ike",
	    definition: "Protects the session with IPsec, keyed by hand or " +
	    "by isakmpd. Keyed by hand, there must be one line for each " +
	    "direction.", values: "as the keyword shows, a line each",
	    default: "none", secret: true, undo: "clear the field",
	    applies: "neighbors and groups" },
	"bgp.ttl-security": { label: "TTL security", keyword: "ttl-security " +
	    "(yes|no)", definition: "Sends with a TTL of 255 and accepts " +
	    "only packets that have not been routed further than multihop " +
	    "allows.", values: "yes or no", default: "no", undo: "clear the " +
	    "field", applies: "neighbors and groups" },
	"bgp.set": { label: "Attributes set", keyword: "set attribute ...",
	    definition: "Sets attributes, such as localpref, on the routes " +
	    "received from the peer. bgpd makes filter rules of them.",
	    values: "what ATTRIBUTE SET in bgpd.conf(5) lists, a line each",
	    default: "none", undo: "clear the field", applies: "neighbors " +
	    "and groups" },
	"bgp.local-as": { label: "Local AS", keyword: "local-as as-number " +
	    "[as-number]", definition: "The AS number sent to the peer in " +
	    "place of the global one, for moving to another AS. bgpd then " +
	    "does not check AS paths for loops.", values: "an AS number, and " +
	    "a 2-byte one", default: "the global AS", risk: "high: with no " +
	    "loop check, filters must stop the peer sending your own routes " +
	    "back", undo: "clear the field", applies: "neighbors and groups" },
	"bgp.enforce-local-as": { label: "Check for loops",
	    keyword: "enforce local-as (yes|no)", definition: "No turns off " +
	    "the check that refuses AS paths that hold the local AS.",
	    values: "yes or no", default: "yes", risk: "high: with no loop " +
	    "check, filters must stop the peer sending your own routes back",
	    undo: "clear the field", applies: "neighbors and groups" },
	"bgp.enforce-neighbor-as": { label: "Check the peer's AS",
	    keyword: "enforce neighbor-as (yes|no)", definition: "Yes " +
	    "refuses AS paths whose first AS is not the peer's.",
	    values: "yes or no", default: "yes, or no for IBGP peers",
	    undo: "clear the field", applies: "neighbors and groups" },
	"bgp.as-override": { label: "AS override", keyword: "as-override " +
	    "(yes|no)", definition: "Replaces the peer's AS in the AS paths " +
	    "it sends with the local AS, before the filters run.",
	    values: "yes or no", default: "no", undo: "clear the field",
	    applies: "neighbors and groups" },
	"bgp.transparent-as": { label: "Transparent AS",
	    keyword: "transparent-as (yes|no)", definition: "Yes leaves the " +
	    "local AS off the AS paths sent to EBGP peers, and passes MED " +
	    "and the well-known communities on unchanged.", values: "yes or no",
	    default: "the global transparent-as", undo: "clear the field",
	    applies: "neighbors and groups" },
	"bgp.reject-as-set": { label: "Reject AS sets", keyword: "reject " +
	    "as-set (yes|no)", definition: "Yes treats routes whose AS path " +
	    "holds an AS_SET as withdrawn.", values: "yes or no",
	    default: "the global reject as-set", undo: "clear the field",
	    applies: "neighbors and groups" },
	"bgp.export": { label: "Export", keyword: "export (none|default-route)",
	    definition: "None sends the peer no updates; default-route sends " +
	    "it only the default route.", values: "none or default-route",
	    default: "every route the filters allow", undo: "clear the field",
	    applies: "neighbors and groups" },
	"bgp.rde-evaluate": { label: "Evaluate", keyword: "rde evaluate " +
	    "(default|all)", definition: "All sends the next best route when " +
	    "the output filters refuse the best one.", values: "default or all",
	    default: "the global rde evaluate", undo: "clear the field",
	    applies: "neighbors and groups" },
	"bgp.role": { label: "Role", keyword: "role role", definition: "The " +
	    "local role for an EBGP session, which ASPA checks and RFC " +
	    "9234's open policy need.", values: "none, provider, customer, " +
	    "rs, rs-client or peer", default: "none", undo: "clear the field",
	    applies: "neighbors and groups" },
	"bgp.route-reflector": { label: "Route reflector",
	    keyword: "route-reflector [address]", definition: "Acts as an " +
	    "RFC 4456 route reflector for the peer, with the address as " +
	    "cluster ID if given.", values: "nothing, or an address",
	    default: "off", undo: "delete the line", applies: "neighbors and " +
	    "groups" },
	"bgp.rib": { label: "RIB", keyword: "rib name", definition: "The RIB " +
	    "the peer's routes go into.", values: "a RIB's name",
	    default: "Loc-RIB", undo: "clear the field", applies: "neighbors " +
	    "and groups" },
	"bgp.port": { label: "Port", keyword: "port port", definition: "The " +
	    "port bgpd connects to.", values: "a port number", default: "179",
	    undo: "clear the field", applies: "neighbors and groups" },
	"bgp.depend-on": { label: "Depends on", keyword: "depend on interface",
	    definition: "Keeps the session idle while the interface has no " +
	    "link; for carp, while it is backup.", values: "an interface",
	    default: "none", undo: "clear the field", applies: "neighbors " +
	    "and groups" },
	"bgp.demote": { label: "Demote", keyword: "demote group",
	    definition: "Raises the carp demotion counter of the interface " +
	    "group while the session is not established.", values: "an " +
	    "interface group, usually carp", default: "none", undo: "clear " +
	    "the field", applies: "neighbors and groups" },
	"bgp.log": { label: "Logging", keyword: "log (no|updates)",
	    definition: "No turns off the peer's own logging; updates logs " +
	    "the updates sent and received.", values: "no or updates",
	    default: "the peer's own logging on", undo: "clear the field",
	    applies: "neighbors and groups" },
	"bgp.dump": { label: "Dump", keyword: "dump (all|updates) (in|out) " +
	    "file [interval]", definition: "Writes the session's BGP " +
	    "messages to a file.", values: "as the keyword shows",
	    default: "none", undo: "clear the field", applies: "neighbors " +
	    "and groups" },
	"bgp.other": { label: "Setting", keyword: "any neighbor setting",
	    definition: "A setting in a group of its own, as written.",
	    values: "what NEIGHBORS AND GROUPS in bgpd.conf(5) lists",
	    default: "none", undo: "delete the line", applies: "neighbors " +
	    "and groups" },
	"bgp.advanced-new": { label: "New setting", keyword: "a setting " +
	    "and its value", definition: "Adds a line of the chosen " +
	    "setting to the peer's block.", values: "the setting's value",
	    default: "none", undo: "delete the line",
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
	    undo: "clear the field" },

	/* snmpd's configuration */
	"snmp.listen": { label: "Listen on", keyword: "listen on [tcp | udp] " +
	    "address [port port] [flags]", definition: "An address snmpd " +
	    "takes requests or traps on, over UDP. Without any, snmpd " +
	    "listens on any address.", values: "an address, or any for every " +
	    "local address", default: "listen on any", undo: "Delete" },
	"snmp.port": { label: "Port", keyword: "port port", definition: "The " +
	    "port of the listen on line.", values: "a port number or a " +
	    "service's name", default: "161, or 162 when notify is its only " +
	    "permission", undo: "clear the field", applies: "listen on lines" },
	"snmp.read": { label: "Read", keyword: "read", definition: "Takes " +
	    "get, getnext and bulkget requests. If a listen on line has none " +
	    "of read, write and notify, it takes read and write, or notify " +
	    "on port 162.", values: "on or off", default: "see the definition",
	    undo: "clear the check box", applies: "listen on lines" },
	"snmp.write": { label: "Write", keyword: "write", definition: "Takes " +
	    "set requests, which change what the agent lets them change. If " +
	    "a listen on line has none of read, write and notify, it takes " +
	    "read and write, or notify on port 162.", values: "on or off",
	    default: "see the definition", risk: "high: whoever passes the " +
	    "security checks can change values", undo: "clear the check box",
	    applies: "listen on lines" },
	"snmp.notify": { label: "Notify", keyword: "notify",
	    definition: "Takes traps, which trap handle lines act on. If a " +
	    "listen on line has none of read, write and notify, it takes " +
	    "read and write, or notify on port 162.", values: "on or off",
	    default: "see the definition", undo: "clear the check box",
	    applies: "listen on lines" },
	"snmp.snmpv1": { label: "SNMPv1", keyword: "snmpv1",
	    definition: "Takes SNMPv1, whose only security is the community. " +
	    "If a listen on line has none of snmpv1, snmpv2c and snmpv3, it " +
	    "takes snmpv3.", values: "on or off", default: "off",
	    undo: "clear the check box", applies: "listen on lines" },
	"snmp.snmpv2c": { label: "SNMPv2c", keyword: "snmpv2c",
	    definition: "Takes SNMPv2c, whose only security is the " +
	    "community. If a listen on line has none of snmpv1, snmpv2c and " +
	    "snmpv3, it takes snmpv3.", values: "on or off", default: "off",
	    undo: "clear the check box", applies: "listen on lines" },
	"snmp.snmpv3": { label: "SNMPv3", keyword: "snmpv3",
	    definition: "Takes SNMPv3, with its users and security level. If " +
	    "a listen on line has none of snmpv1, snmpv2c and snmpv3, it " +
	    "takes snmpv3.", values: "on or off", default: "on, if none of " +
	    "the three is set", undo: "clear the check box",
	    applies: "listen on lines" },
	"snmp.listenudp": { label: "Listen on UDP", keyword: "listen on udp " +
	    "address [port port] [flags]", definition: "As listen on, said " +
	    "explicitly.", values: "an address, or any", default: "none",
	    undo: "Delete" },
	"snmp.listentcp": { label: "Listen on TCP", keyword: "listen on tcp " +
	    "address [port port] [flags]", definition: "As listen on, over " +
	    "TCP.", values: "an address, or any", default: "none",
	    undo: "Delete" },
	"snmp.rocommunity": { label: "Read-only community",
	    keyword: "read-only community string", definition: "The " +
	    "community that lets SNMPv1 and SNMPv2c requests read. It is a " +
	    "password sent in the clear.", values: "a string; not public, " +
	    "which everyone tries", default: "none", secret: true,
	    undo: "clear the field" },
	"snmp.rwcommunity": { label: "Read-write community",
	    keyword: "read-write community string", definition: "The " +
	    "community that lets SNMPv1 and SNMPv2c requests read and write. " +
	    "It is a password sent in the clear.", values: "a string",
	    default: "none", risk: "high: anyone who sees it on the network " +
	    "can change values", secret: true, undo: "clear the field" },
	"snmp.seclevel": { label: "Security level", keyword: "seclevel none " +
	    "| auth | enc", definition: "The least SNMPv3 security snmpd " +
	    "accepts: none, messages signed or not; auth, signed; enc, " +
	    "signed and encrypted. On a trap receiver line, the level the " +
	    "traps are sent with.", values: "none, auth or enc", default: "enc",
	    undo: "choose (not set)", applies: "the global settings and trap " +
	    "receiver lines" },
	"snmp.user": { label: "User", keyword: "user name [auth hmac] " +
	    "[authkey key] [enc cipher] [enckey key]", definition: "An " +
	    "SNMPv3 user. On a trap receiver line, the user the traps are " +
	    "sent as.", values: "a name", default: "none", undo: "Delete",
	    applies: "the users and trap receiver lines" },
	"snmp.auth": { label: "Authentication", keyword: "auth hmac",
	    definition: "The HMAC that signs the user's messages.",
	    values: "hmac-md5, hmac-sha1, hmac-sha224, hmac-sha256, " +
	    "hmac-sha384 or hmac-sha512", default: "hmac-sha1",
	    undo: "choose (not set)", applies: "users" },
	"snmp.authkey": { label: "Authentication key", keyword: "authkey key",
	    definition: "The user's key for signing. Without it, the user's " +
	    "messages are not signed.", values: "a string", default: "none",
	    secret: true, undo: "clear the field", applies: "users" },
	"snmp.enc": { label: "Encryption", keyword: "enc cipher",
	    definition: "The cipher of the user's messages. It needs an " +
	    "authentication key too.", values: "des or aes", default: "aes",
	    undo: "choose (not set)", applies: "users" },
	"snmp.enckey": { label: "Encryption key", keyword: "enckey key",
	    definition: "The user's key for encryption. Without it, the " +
	    "user's messages are not encrypted.", values: "a string",
	    default: "none", secret: true, undo: "clear the field",
	    applies: "users" },
	"snmp.trapcommunity": { label: "Trap community", keyword: "trap " +
	    "community string", definition: "The community of the SNMPv2c " +
	    "traps snmpd sends, unless a receiver gives its own.",
	    values: "a string", default: "none", secret: true, undo: "clear " +
	    "the field" },
	"snmp.trapreceiver": { label: "Trap receiver", keyword: "trap " +
	    "receiver address [oid oid] [snmpv2c [community string] | " +
	    "[snmpv3] user name [seclevel level]] [source-address address]",
	    definition: "A host snmpd sends its traps to.", values: "an " +
	    "address or a host name", default: "none", undo: "Delete" },
	"snmp.oid": { label: "OID", keyword: "oid oid", definition: "The OID " +
	    "of the traps sent to the receiver.", values: "an OID",
	    default: "snmpd's own", undo: "clear the field", applies: "trap " +
	    "receiver lines" },
	"snmp.version": { label: "Version", keyword: "snmpv2c | snmpv3",
	    definition: "The SNMP version of the traps sent to the receiver.",
	    values: "snmpv2c or snmpv3", default: "snmpv3 if a user is given",
	    undo: "choose (not set)", applies: "trap receiver lines" },
	"snmp.community": { label: "Community", keyword: "community string",
	    definition: "The community of the SNMPv2c traps sent to the " +
	    "receiver.", values: "a string", default: "the trap community",
	    secret: true, undo: "clear the field", applies: "trap receiver " +
	    "lines" },
	"snmp.srcaddr": { label: "Source address", keyword: "source-address " +
	    "address", definition: "The address the traps to the receiver " +
	    "are sent from.", values: "an IPv4 or IPv6 address",
	    default: "chosen by the routing table", undo: "clear the field",
	    applies: "trap receiver lines" },
	"snmp.traphandle": { label: "Trap handler", keyword: "trap handle " +
	    "oid \"command\"", definition: "A command snmpd runs for each " +
	    "trap it takes whose OID begins with this one, or with 1.3 for " +
	    "default. The command reads the sender and the trap's values on " +
	    "its input. It needs a listen on line with notify.", values: "an " +
	    "OID or default", default: "none", risk: "high: it runs a " +
	    "command each time a trap arrives", undo: "Delete" },
	"snmp.command": { label: "Command", keyword: "\"command\"",
	    definition: "The command line a trap handler runs.", values: "a " +
	    "command and its arguments", default: "none", undo: "Delete",
	    applies: "trap handle lines" },
	"snmp.syscontact": { label: "Contact", keyword: "system contact string",
	    definition: "Who to contact about this system.", values: "a name " +
	    "or an email address", default: "root@ this host's name",
	    undo: "clear the field" },
	"snmp.sysdescr": { label: "Description", keyword: "system " +
	    "description string", definition: "A description of this system.",
	    values: "text", default: "what uname -a prints", undo: "clear " +
	    "the field" },
	"snmp.syslocation": { label: "Location", keyword: "system location " +
	    "string", definition: "Where this system is.", values: "text",
	    default: "empty", undo: "clear the field" },
	"snmp.sysname": { label: "Name", keyword: "system name string",
	    definition: "This system's name.", values: "a host name",
	    default: "this host's name", undo: "clear the field" },
	"snmp.sysoid": { label: "System OID", keyword: "system oid oid",
	    definition: "The OID that identifies this kind of system.",
	    values: "an OID", default: "1.3.6.1.4.1.30155.23.1",
	    undo: "clear the field" },
	"snmp.sysservices": { label: "Services", keyword: "system services " +
	    "number", definition: "The sum that says which layers this " +
	    "system serves, as sysServices in the SNMP MIB defines it.",
	    values: "a decimal number", default: "snmpd's own", undo: "clear " +
	    "the field" },
	"snmp.engineid": { label: "Engine ID", keyword: "engineid [pen " +
	    "enterprise] format", definition: "This agent's SNMPv3 engine " +
	    "ID, which the users' keys are derived with.", values: "ipv4, " +
	    "ipv6, mac, text, octets, hosthash, agentid or a number, then " +
	    "its value", default: "hosthash of this host's name",
	    undo: "clear the field" },
	"snmp.filterroutes": { label: "Filter routes",
	    keyword: "filter-routes yes | no", definition: "yes asks the " +
	    "kernel to filter route updates on the routing socket: less CPU " +
	    "during large updates, and no routing table in the MIB.",
	    values: "yes or no", default: "no", undo: "choose (not set)" },
	"snmp.object": { label: "Object", keyword: "oid oid name name " +
	    "[read-only | read-write] [integer | string] value",
	    definition: "An OID of this configuration's own, with its value.",
	    values: "an OID", default: "none", undo: "Delete" },
	"snmp.name": { label: "Name", keyword: "name name", definition: "The " +
	    "object's name.", values: "a name", default: "none",
	    undo: "clear the field", applies: "oid lines" },
	"snmp.access": { label: "Access", keyword: "read-only | read-write",
	    definition: "read-write lets a set request change the object's " +
	    "value.", values: "read-only or read-write", default: "read-only",
	    undo: "choose (not set)", applies: "oid lines" },
	"snmp.integer": { label: "Integer value", keyword: "integer number",
	    definition: "The object's value, if it is a number.", values: "a " +
	    "number", default: "none", undo: "clear the field",
	    applies: "oid lines" },
	"snmp.string": { label: "String value", keyword: "string string",
	    definition: "The object's value, if it is text.", values: "text",
	    default: "none", undo: "clear the field", applies: "oid lines" },
	"snmp.blocklist": { label: "Blocked subtree", keyword: "blocklist oid",
	    definition: "A subtree of OIDs snmpd hides.", values: "an OID",
	    default: "none", undo: "Delete" },
	"snmp.mibdir": { label: "MIB directory", keyword: "mib directory path",
	    definition: "A directory snmpd searches for MIB files.",
	    values: "a path", default: "/usr/share/snmp/mibs", undo: "Delete" },
	"snmp.agentx": { label: "AgentX socket", keyword: "agentx [path " +
	    "path] [owner owner] [group group] [mode mode]", definition: "A " +
	    "socket where other daemons, such as relayd, give snmpd their " +
	    "values.", values: "present or absent", default: "absent",
	    undo: "Delete" },
	"snmp.path": { label: "Path", keyword: "path path", definition: "The " +
	    "AgentX socket's path.", values: "a path",
	    default: "/var/agentx/master", undo: "clear the field",
	    applies: "agentx lines" },
	"snmp.owner": { label: "Owner", keyword: "owner owner",
	    definition: "The AgentX socket's owner.", values: "a user's name " +
	    "or number", default: "root", undo: "clear the field",
	    applies: "agentx lines" },
	"snmp.group": { label: "Group", keyword: "group group",
	    definition: "The AgentX socket's group.", values: "a group's " +
	    "name or number", default: "_agentx", undo: "clear the field",
	    applies: "agentx lines" },
	"snmp.mode": { label: "Mode", keyword: "mode mode", definition: "The " +
	    "AgentX socket's permissions.", values: "an octal mode",
	    default: "660", undo: "clear the field", applies: "agentx lines" },

	/* ldapd's configuration */
	"ldap.listen": { label: "Listen on", keyword: "listen on interface " +
	    "[port port] [legacy] [tls | ldaps | secure] [certificate name]",
	    definition: "An interface, address, host name or Unix socket " +
	    "path ldapd listens on. Only TLS, LDAPS, Unix socket and secure " +
	    "connections take passwords.", values: "an interface's name, an " +
	    "address, a host name or an absolute path", default: "none",
	    undo: "Delete" },
	"ldap.port": { label: "Port", keyword: "port port", definition: "The " +
	    "listener's port.", values: "a port number or a service's name",
	    default: "389, or 636 for ldaps", undo: "clear the field",
	    applies: "listen on lines" },
	"ldap.legacy": { label: "Legacy TLS", keyword: "legacy",
	    definition: "Allows TLS 1.0 and 1.1 and their ciphers, which are " +
	    "insecure.", values: "on or off", default: "off", undo: "clear " +
	    "the check box", applies: "listen on lines" },
	"ldap.tls": { label: "Security", keyword: "tls | ldaps | secure",
	    definition: "tls takes STARTTLS; ldaps takes TLS from the start; " +
	    "secure treats a plain connection as secure, for example under " +
	    "IPsec.", values: "tls, ldaps or secure", default: "plain",
	    undo: "choose (not set)", applies: "listen on lines" },
	"ldap.certificate": { label: "Certificate", keyword: "certificate name",
	    definition: "The certificate for TLS: a name in /etc/ldap/certs, " +
	    "or a path without .crt and .key.", values: "a name or an " +
	    "absolute path", default: "the interface's name, in " +
	    "/etc/ldap/certs", undo: "clear the field", applies: "listen on " +
	    "lines" },
	"ldap.namespace": { label: "Namespace", keyword: "namespace suffix { " +
	    "... }", definition: "A subtree of the directory ldapd keeps, in " +
	    "a database of its own. Requests go to the namespace whose " +
	    "suffix matches most.", values: "a DN suffix, such as " +
	    "dc=example,dc=com", default: "none", undo: "Delete" },
	"ldap.rootdn": { label: "Root DN", keyword: "rootdn dn",
	    definition: "The root user, which may read and write everything: " +
	    "in every namespace globally, or in one namespace, whose suffix " +
	    "it must end with.", values: "a DN", default: "none",
	    undo: "clear the field", applies: "the global settings and " +
	    "namespaces" },
	"ldap.rootpw": { label: "Root password", keyword: "rootpw password",
	    definition: "The root user's password, as text or hashed, as " +
	    "ldapd(8) describes.", values: "a password or a hash",
	    default: "none", secret: true, undo: "clear the field",
	    applies: "the global settings and namespaces" },
	"ldap.index": { label: "Index", keyword: "index attribute",
	    definition: "An attribute ldapd keeps an index of. An index " +
	    "added to a namespace with entries needs ldapctl's index.",
	    values: "an attribute's name", default: "none", undo: "Delete",
	    applies: "namespaces" },
	"ldap.cachesize": { label: "Cache size", keyword: "cache-size size",
	    definition: "How many pages of entries are cached.",
	    values: "pages", default: "1024", undo: "Delete",
	    applies: "namespaces" },
	"ldap.indexcachesize": { label: "Index cache size",
	    keyword: "index-cache-size size", definition: "How many pages of " +
	    "the index database are cached.", values: "pages", default: "512",
	    undo: "Delete", applies: "namespaces" },
	"ldap.fsync": { label: "fsync", keyword: "fsync on | off",
	    definition: "off does not force each commit to disk: faster " +
	    "writes, and data can be lost.", values: "on or off", default: "on",
	    undo: "Delete", applies: "namespaces" },
	"ldap.relax": { label: "Relax schema", keyword: "relax schema",
	    definition: "Entries are not checked against the schema, and " +
	    "every attribute may have several values.", values: "present or " +
	    "absent", default: "absent", undo: "Delete",
	    applies: "namespaces" },
	"ldap.strict": { label: "Strict schema", keyword: "strict schema",
	    definition: "Entries are checked against the schema.",
	    values: "present or absent", default: "checked", undo: "Delete",
	    applies: "namespaces" },
	"ldap.compression": { label: "Compression", keyword: "use " +
	    "compression [level level]", definition: "Entries are stored " +
	    "compressed.", values: "present or absent", default: "absent",
	    undo: "Delete", applies: "namespaces" },
	"ldap.level": { label: "Level", keyword: "level level",
	    definition: "How hard entries are compressed.", values: "0 to 9",
	    default: "6", undo: "clear the field", applies: "use compression " +
	    "lines" },
	"ldap.referral": { label: "Referral", keyword: "referral URL",
	    definition: "Another LDAP server to send requests to: globally, " +
	    "those no namespace matches; in a namespace, those that match it.",
	    values: "an ldap:// or ldaps:// URL", default: "none",
	    undo: "Delete", applies: "the global settings and namespaces" },
	"ldap.allow": { label: "Allow", keyword: "allow [access] [to target] " +
	    "[attribute name] [by who]", definition: "A rule that allows " +
	    "what it matches. The last rule that matches decides, and a " +
	    "request no rule matches is allowed; the root DN may do anything.",
	    values: "A rule: [read | write | bind | their list] access, then " +
	    "to any, to root, to DN, to subtree DN or to children of DN, " +
	    "then attribute name, then by any, by self or by DN",
	    default: "allowed", undo: "Delete", applies: "the global " +
	    "settings and namespaces" },
	"ldap.deny": { label: "Deny", keyword: "deny [access] [to target] " +
	    "[attribute name] [by who]", definition: "A rule that denies " +
	    "what it matches. The last rule that matches decides.",
	    values: "A rule: [read | write | bind | their list] access, then " +
	    "to any, to root, to DN, to subtree DN or to children of DN, " +
	    "then attribute name, then by any, by self or by DN",
	    default: "none", undo: "Delete", applies: "the global settings " +
	    "and namespaces" },
	"ldap.schema": { label: "Schema", keyword: "schema filename",
	    definition: "A file of attribute types and object classes to add.",
	    values: "a path", default: "ldapd's core schemas", undo: "Delete" },

	/* npppd's configuration */
	"nppp.tunnel": { label: "Tunnel", keyword: "tunnel name protocol " +
	    "protocol [{ ... }]", definition: "A tunnel npppd takes PPP " +
	    "sessions over, with its PPP settings.", values: "a name",
	    default: "none", undo: "Delete" },
	"nppp.protocol": { label: "Protocol", keyword: "protocol l2tp | pptp " +
	    "| pppoe", definition: "The tunnel's protocol: L2TP, PPTP or PPP " +
	    "over Ethernet.", values: "l2tp, pptp or pppoe", default: "none: " +
	    "a tunnel needs one", undo: "choose (not set)",
	    applies: "tunnels" },
	"nppp.listen": { label: "Listen on", keyword: "listen on address " +
	    "[port port]", definition: "An address an L2TP or PPTP tunnel " +
	    "listens on; PPTP takes only IPv4.", values: "an IPv4 or IPv6 " +
	    "address", default: "0.0.0.0", undo: "Delete", applies: "tunnels" },
	"nppp.port": { label: "Port", keyword: "port port", definition: "The " +
	    "port of the address.", values: "a port number", default: "1701 " +
	    "for L2TP, 1723 for PPTP, 3799 for DAE", undo: "clear the field",
	    applies: "listen on lines and radius dae listen on" },
	"nppp.listenif": { label: "Listen on interface", keyword: "listen on " +
	    "interface name", definition: "The Ethernet interface a PPPoE " +
	    "tunnel listens on.", values: "an interface's name",
	    default: "none", undo: "Delete", applies: "tunnels" },
	"nppp.mru": { label: "MRU", keyword: "mru number", definition: "The " +
	    "largest packet npppd asks the peer to send it.", values: "bytes",
	    default: "1360 for L2TP, 1400 for PPTP, 1492 for PPPoE",
	    undo: "Delete", applies: "tunnels" },
	"nppp.lcpkeepalive": { label: "LCP keepalive",
	    keyword: "lcp-keepalive yes | no", definition: "Whether npppd " +
	    "sends LCP echo requests, and closes a link that does not answer.",
	    values: "yes or no", default: "no for L2TP, yes for PPTP and PPPoE",
	    undo: "Delete", applies: "tunnels" },
	"nppp.authmethod": { label: "Authentication methods",
	    keyword: "authentication-method method ...", definition: "The " +
	    "ways npppd lets a user prove who they are. PAP sends the " +
	    "password in the clear.", values: "pap, chap and mschapv2, " +
	    "separated by spaces", default: "mschapv2 for PPTP, pap chap " +
	    "mschapv2 for the others", undo: "Delete", applies: "tunnels" },
	"nppp.chapname": { label: "CHAP name", keyword: "chap-name name",
	    definition: "The name npppd gives in CHAP.", values: "a name",
	    default: "none", undo: "Delete", applies: "tunnels" },
	"nppp.mppe": { label: "MPPE", keyword: "mppe yes | no | required",
	    definition: "Microsoft Point-to-Point Encryption: yes uses it if " +
	    "the peer agrees, required ends the session if not, no refuses it.",
	    values: "yes, no or required", default: "required for PPTP, yes " +
	    "for L2TP and PPPoE", undo: "Delete", applies: "tunnels" },
	"nppp.idletimeout": { label: "Idle timeout", keyword: "idle-timeout " +
	    "seconds", definition: "A link that sends and receives no data " +
	    "this long is closed. It must be 0 for pppx(4).",
	    values: "seconds; 0 for none", default: "0", undo: "Delete",
	    applies: "tunnels" },
	"nppp.tcpmss": { label: "Adjust TCP MSS", keyword: "tcp-mss-adjust " +
	    "yes | no", definition: "yes lowers the MSS in TCP SYN packets " +
	    "to fit the link's MTU.", values: "yes or no", default: "no",
	    undo: "Delete", applies: "tunnels" },
	"nppp.ingress": { label: "Ingress filter", keyword: "ingress-filter " +
	    "yes | no", definition: "yes drops packets whose source is not " +
	    "the address npppd gave the link.", values: "yes or no",
	    default: "no", undo: "Delete", applies: "tunnels" },
	"nppp.pipex": { label: "pipex", keyword: "pipex yes | no",
	    definition: "Whether the kernel's pipex(4) carries the sessions' " +
	    "packets; the sysctl net.pipex.enable must be on too.",
	    values: "yes or no", default: "yes", undo: "Delete",
	    applies: "tunnels" },
	"nppp.l2tpipsec": { label: "Require IPsec",
	    keyword: "l2tp-require-ipsec yes | no", definition: "yes refuses " +
	    "L2TP connections that are not in IPsec.", values: "yes or no",
	    default: "no", undo: "Delete", applies: "tunnels" },
	"nppp.pppoeservice": { label: "PPPoE service name",
	    keyword: "pppoe-service-name name", definition: "The service " +
	    "name a PPPoE tunnel offers.", values: "a name", default: "empty",
	    undo: "Delete", applies: "tunnels" },
	"nppp.pppoeac": { label: "PPPoE AC name", keyword: "pppoe-ac-name name",
	    definition: "The access concentrator name a PPPoE tunnel gives.",
	    values: "a name", default: "made from the interface's MAC address",
	    undo: "Delete", applies: "tunnels" },
	"nppp.other": { label: "Other", keyword: "option value",
	    definition: "A tunnel setting this form has no field for, as " +
	    "written: LCP, IPCP and CCP timers and counts, the L2TP, PPTP " +
	    "and PPPoE settings, MPPE keys and packet dumps. npppd.conf(5) " +
	    "lists them.", values: "the setting as npppd.conf writes it",
	    default: "none", undo: "Delete", applies: "tunnels" },
	"nppp.ipcp": { label: "IPCP", keyword: "ipcp name { ... }",
	    definition: "Addresses and name servers a session is given. " +
	    "There may be up to 8.", values: "a name", default: "none",
	    undo: "Delete" },
	"nppp.pool": { label: "Pool", keyword: "pool-address range | prefix " +
	    "[for dynamic | static]", definition: "Addresses sessions are " +
	    "given.", values: "a range such as 10.0.0.2-10.0.0.254, or a " +
	    "prefix such as 10.0.0.0/24", default: "none", undo: "Delete",
	    applies: "IPCP settings" },
	"nppp.pooltype": { label: "Allocation", keyword: "for dynamic | static",
	    definition: "dynamic gives the addresses to any session; static " +
	    "keeps them for addresses set for a user.", values: "dynamic or " +
	    "static", default: "dynamic", undo: "choose (not set)",
	    applies: "pool-address lines" },
	"nppp.dns": { label: "DNS servers", keyword: "dns-servers primary " +
	    "[secondary] | resolver", definition: "The name servers a " +
	    "session is given. Without this line, the RADIUS server's are " +
	    "given; 0.0.0.0 gives none.", values: "one or two IPv4 " +
	    "addresses, or resolver", default: "the RADIUS server's",
	    undo: "Delete", applies: "IPCP settings" },
	"nppp.nbns": { label: "NetBIOS name servers", keyword: "nbns-servers " +
	    "primary [secondary]", definition: "The NetBIOS name servers a " +
	    "session is given.", values: "one or two IPv4 addresses",
	    default: "the RADIUS server's", undo: "Delete", applies: "IPCP " +
	    "settings" },
	"nppp.userselected": { label: "User's own address",
	    keyword: "allow-user-selected-address yes | no",
	    definition: "Whether a session may be given the address its user " +
	    "asks for.", values: "yes or no", default: "yes", undo: "Delete",
	    applies: "IPCP settings" },
	"nppp.ipcpmax": { label: "Sessions", keyword: "max-session number",
	    definition: "The most sessions this IPCP setting serves.",
	    values: "a number; 0 for no limit", default: "0", undo: "Delete",
	    applies: "IPCP settings" },
	"nppp.interface": { label: "Interface", keyword: "interface name " +
	    "address address ipcp ipcp", definition: "A pppac(4) or pppx(4) " +
	    "interface the sessions use. There may be up to 8.", values: "an " +
	    "interface's name", default: "none", undo: "Delete" },
	"nppp.address": { label: "Address", keyword: "address address",
	    definition: "The interface's address, which the peers see as the " +
	    "tunnel's.", values: "an IPv4 address", default: "none",
	    undo: "clear the field", applies: "interface lines" },
	"nppp.useipcp": { label: "IPCP", keyword: "ipcp name",
	    definition: "The IPCP setting the interface's sessions use.",
	    values: "an IPCP setting's name", default: "none", undo: "clear " +
	    "the field", applies: "interface lines" },
	"nppp.authentication": { label: "Authentication",
	    keyword: "authentication name type local | radius { ... }",
	    definition: "Where users are checked: a file of users, or RADIUS " +
	    "servers.", values: "a name", default: "none", undo: "Delete" },
	"nppp.type": { label: "Type", keyword: "type local | radius",
	    definition: "local checks users-file; radius asks the " +
	    "authentication servers.", values: "local or radius",
	    default: "none: it needs one", undo: "choose (not set)",
	    applies: "authentication settings" },
	"nppp.suffix": { label: "Username suffix", keyword: "username-suffix " +
	    "string", definition: "Users whose names end with this use this " +
	    "setting.", values: "a string", default: "any user", undo: "Delete",
	    applies: "authentication settings" },
	"nppp.stripnt": { label: "Strip NT domain",
	    keyword: "strip-nt-domain yes | no", definition: "yes takes an " +
	    "NT domain, such as \\\\DOMAIN\\, off the user's name before it " +
	    "is checked.", values: "yes or no", default: "yes", undo: "Delete",
	    applies: "authentication settings" },
	"nppp.stripat": { label: "Strip realm", keyword: "strip-atmark-realm " +
	    "yes | no", definition: "yes takes the part from @ off the " +
	    "user's name before it is checked.", values: "yes or no",
	    default: "no", undo: "Delete", applies: "authentication settings" },
	"nppp.usersfile": { label: "Users file", keyword: "users-file path",
	    definition: "The npppd-users(5) file of a local setting. It must " +
	    "be under /etc/npppd/.", values: "a path", default: "none",
	    undo: "Delete", applies: "authentication settings" },
	"nppp.usermax": { label: "Sessions a user",
	    keyword: "user-max-session number", definition: "The most " +
	    "sessions one user may have through this setting.", values: "a " +
	    "number", default: "the global limit", undo: "Delete",
	    applies: "authentication settings" },
	"nppp.authserver": { label: "Authentication servers",
	    keyword: "authentication-server { ... }", definition: "The " +
	    "RADIUS servers that check users.", values: "a block",
	    default: "none", undo: "Delete", applies: "authentication " +
	    "settings" },
	"nppp.radaddress": { label: "Server", keyword: "address address " +
	    "[port port] secret secret", definition: "A RADIUS server. There " +
	    "may be up to 16.", values: "an address", default: "none",
	    undo: "Delete", applies: "RADIUS servers of authentication " +
	    "settings" },
	"nppp.secret": { label: "Secret", keyword: "secret secret",
	    definition: "The secret shared with the RADIUS server or DAE " +
	    "client.", values: "up to 126 characters", default: "none",
	    secret: true, undo: "clear the field", applies: "RADIUS servers " +
	    "and DAE clients" },
	"nppp.radtimeout": { label: "Timeout", keyword: "timeout seconds",
	    definition: "How long npppd waits for the server's answer.",
	    values: "seconds", default: "9", undo: "Delete",
	    applies: "RADIUS servers of authentication settings" },
	"nppp.radtries": { label: "Tries", keyword: "max-tries number",
	    definition: "How many times a request is sent again.",
	    values: "a number", default: "3", undo: "Delete",
	    applies: "RADIUS servers of authentication settings" },
	"nppp.radfailovers": { label: "Failovers", keyword: "max-failovers " +
	    "number", definition: "How many times npppd moves to another " +
	    "server.", values: "a number", default: "1", undo: "Delete",
	    applies: "RADIUS servers of authentication settings" },
	"nppp.acctserver": { label: "Accounting servers",
	    keyword: "accounting-server { ... }", definition: "The RADIUS " +
	    "servers that npppd tells of each session.", values: "a block",
	    default: "none", undo: "Delete", applies: "authentication " +
	    "settings" },
	"nppp.bind": { label: "Bind", keyword: "bind tunnel from tunnel " +
	    "authenticated by authentication to interface",
	    definition: "Which tunnel's users are checked where, and which " +
	    "interface their sessions use.", values: "a tunnel's name",
	    default: "none", undo: "Delete" },
	"nppp.auth": { label: "Authenticated by", keyword: "authenticated by " +
	    "name", definition: "The authentication setting the tunnel's " +
	    "users are checked by.", values: "an authentication setting's name",
	    default: "none", undo: "clear the field", applies: "bind lines" },
	"nppp.to": { label: "To", keyword: "to interface", definition: "The " +
	    "interface the sessions use.", values: "an interface's name",
	    default: "none", undo: "clear the field", applies: "bind lines" },
	"nppp.nasid": { label: "NAS identifier", keyword: "radius nas-id " +
	    "identifier", definition: "The NAS-Identifier npppd gives RADIUS " +
	    "servers.", values: "a string", default: "none", undo: "clear " +
	    "the field" },
	"nppp.daelisten": { label: "DAE listener", keyword: "radius dae " +
	    "listen on address [port port]", definition: "An address npppd " +
	    "takes RADIUS dynamic authorization requests on, such as to end " +
	    "a session.", values: "an address", default: "none",
	    undo: "Delete" },
	"nppp.daeclient": { label: "DAE client", keyword: "radius dae client " +
	    "address secret secret", definition: "A host allowed to send " +
	    "dynamic authorization requests.", values: "an address",
	    default: "none", risk: "high: it can end sessions",
	    undo: "Delete" },
	"nppp.maxsession": { label: "Sessions", keyword: "set max-session " +
	    "number", definition: "The most sessions npppd serves.",
	    values: "a number; 0 for no limit", default: "0", undo: "clear " +
	    "the field" },
	"nppp.usermaxsession": { label: "Sessions a user", keyword: "set " +
	    "user-max-session number", definition: "The most sessions one " +
	    "user may have.", values: "a number; 0 for no limit", default: "0",
	    undo: "clear the field" },

	/* smtpd's configuration */
	"smtp.listen": { label: "Listen on", keyword: "listen on interface " +
	    "[family] [options]", definition: "An interface, group, address " +
	    "or name smtpd takes mail on.", values: "an interface's or " +
	    "group's name, an address or a domain name", default: "the Unix " +
	    "socket only", undo: "Delete" },
	"smtp.family": { label: "Family", keyword: "inet4 | inet6",
	    definition: "Listens with one address family only.",
	    values: "inet4 or inet6", default: "both", undo: "choose (not set)",
	    applies: "listen on lines" },
	"smtp.port": { label: "Port", keyword: "port port", definition: "The " +
	    "port the listener takes mail on.", values: "a port number or a " +
	    "service's name, such as submission", default: "25; 465 for smtps",
	    undo: "clear the field", applies: "listen on lines" },
	"smtp.tlsmode": { label: "TLS", keyword: "tls | tls-require | smtps",
	    definition: "tls offers STARTTLS; tls-require refuses mail until " +
	    "the client starts TLS; smtps takes TLS from the start.",
	    values: "tls, tls-require or smtps", default: "no TLS",
	    undo: "choose (not set)", applies: "listen on lines" },
	"smtp.verify": { label: "Verify clients", keyword: "verify",
	    definition: "With tls-require or smtps, a client must show a " +
	    "valid certificate.", values: "on or off", default: "off",
	    undo: "clear the check box", applies: "listen on lines" },
	"smtp.pki": { label: "PKI", keyword: "pki name cert | key | dhe ...",
	    definition: "A certificate and key smtpd proves its name with. A " +
	    "listener or relay names one; a listener may name several, for " +
	    "SNI.", values: "a name", default: "none", undo: "Delete",
	    applies: "pki lines and listen on lines" },
	"smtp.ca": { label: "CA", keyword: "ca name cert file",
	    definition: "A CA certificate that client or server certificates " +
	    "are checked against.", values: "a name", default: "the system's",
	    undo: "Delete", applies: "ca lines and listen on lines" },
	"smtp.authmode": { label: "Authentication", keyword: "auth | " +
	    "auth-optional [<table>]", definition: "auth: clients must log " +
	    "in before they send mail; auth-optional: they may. Without a " +
	    "table, they log in with their system accounts.", values: "auth " +
	    "or auth-optional", default: "none", undo: "choose (not set)",
	    applies: "listen on lines" },
	"smtp.hostname": { label: "Host name", keyword: "hostname name",
	    definition: "The name in the listener's greeting.", values: "a " +
	    "host name", default: "the server's name", undo: "clear the field",
	    applies: "listen on lines" },
	"smtp.hostnames": { label: "Host names", keyword: "hostnames <table>",
	    definition: "A table of the name to greet with on each address.",
	    values: "a table, in angle brackets", default: "none",
	    undo: "clear the field", applies: "listen on lines" },
	"smtp.tag": { label: "Tag", keyword: "tag tag", definition: "Tags " +
	    "the listener's sessions, for match tag.", values: "a tag",
	    default: "none", undo: "clear the field", applies: "listen on " +
	    "lines, and listen on socket for some" },
	"smtp.filter": { label: "Filter", keyword: "filter name ...",
	    definition: "A filter: built in, with a phase, conditions and a " +
	    "decision; a filter process; or a chain of filters. A listener " +
	    "names the one its sessions go through.", values: "a name",
	    default: "none", undo: "Delete", applies: "filter lines, and " +
	    "listeners" },
	"smtp.senders": { label: "Senders", keyword: "senders <table> " +
	    "[masquerade]", definition: "A table of the addresses each " +
	    "logged-in user may send as; masquerade rewrites From to match.",
	    values: "a table, in angle brackets, then masquerade or not",
	    default: "any address", undo: "clear the field",
	    applies: "listen on lines" },
	"smtp.masksrc": { label: "Mask source", keyword: "mask-src",
	    definition: "Received headers leave out where the mail came from.",
	    values: "on or off", default: "off", undo: "clear the check box",
	    applies: "listen on lines, and listen on socket for some" },
	"smtp.receivedauth": { label: "Received auth", keyword: "received-auth",
	    definition: "Received headers say whether the session logged in, " +
	    "and as whom.", values: "on or off", default: "off",
	    undo: "clear the check box", applies: "listen on lines" },
	"smtp.nodsn": { label: "No DSN", keyword: "no-dsn",
	    definition: "Turns off delivery status notifications.",
	    values: "on or off", default: "off", undo: "clear the check box",
	    applies: "listen on lines, and listen on socket for some" },
	"smtp.proxyv2": { label: "PROXY protocol", keyword: "proxy-v2",
	    definition: "Takes the client's address from a PROXY protocol v2 " +
	    "header.", values: "on or off", default: "off", undo: "clear the " +
	    "check box", applies: "listen on lines" },
	"smtp.ciphers": { label: "Ciphers", keyword: "ciphers ciphers",
	    definition: "The ciphers the listener's TLS allows.",
	    values: "as tls_config_set_ciphers(3) takes them",
	    default: "libtls's", undo: "clear the field", applies: "listen " +
	    "on lines" },
	"smtp.protocols": { label: "TLS protocols", keyword: "protocols " +
	    "protocols", definition: "The TLS versions the listener allows.",
	    values: "as tls_config_parse_protocols(3) takes them",
	    default: "libtls's", undo: "clear the field", applies: "listen " +
	    "on lines" },
	"smtp.socket": { label: "Listen on socket", keyword: "listen on " +
	    "socket [options]", definition: "Options for the local Unix " +
	    "socket /var/run/smtpd.sock, which smtpd listens on anyway.",
	    values: "present or absent", default: "absent", undo: "Delete" },
	"smtp.match": { label: "Rule", keyword: "match options action name | " +
	    "reject", definition: "Mail that matches is given to the action, " +
	    "or rejected. The first rule that matches decides. from any with " +
	    "for any accepts mail from anyone for any domain.", values: "[!] " +
	    "from ..., [!] for ..., and other options, then action name or " +
	    "reject", default: "none", risk: "high: a rule that relays from " +
	    "any for any is an open relay", undo: "Delete" },
	"smtp.action": { label: "Action", keyword: "action name method " +
	    "[options]", definition: "How mail a rule gives it is delivered.",
	    values: "a name", default: "none", undo: "Delete" },
	"smtp.method": { label: "Method", keyword: "method [options]",
	    definition: "mbox, maildir [path] [junk], lmtp destination, mda " +
	    "command, relay, forward-only or expand-only, then their " +
	    "options. mda runs a command for each message.", values: "the " +
	    "method and options as smtpd.conf writes them", default: "none",
	    undo: "clear the field", applies: "action lines" },
	"smtp.mdawrapper": { label: "MDA wrapper", keyword: "mda wrapper " +
	    "name command", definition: "A command that local deliveries " +
	    "naming the wrapper run in place of their own.", values: "a name",
	    default: "none", risk: "high: it runs a command for each delivery",
	    undo: "Delete" },
	"smtp.command": { label: "Command", keyword: "\"command\"",
	    definition: "The command line, which may hold format specifiers.",
	    values: "a command and its arguments", default: "none",
	    undo: "clear the field", applies: "mda wrapper and proc lines" },
	"smtp.table": { label: "Table", keyword: "table name [type:]path | { " +
	    "value, ... }", definition: "A list or mapping that other lines " +
	    "name in angle brackets.", values: "a name", default: "none",
	    undo: "Delete" },
	"smtp.source": { label: "File", keyword: "[type:]path",
	    definition: "Where the table is kept: a text file, or db: and a " +
	    "file made with makemap(8).", values: "an absolute path, with " +
	    "file: or db: before it", default: "none", undo: "clear the field",
	    applies: "table lines" },
	"smtp.values": { label: "Values", keyword: "{ value, ... }",
	    definition: "The table's values, or its key = value pairs, in " +
	    "the line itself.", values: "one value, or key = value, a line",
	    default: "none", undo: "clear the lines", applies: "table lines" },
	"smtp.cert": { label: "Certificate", keyword: "cert file",
	    definition: "The certificate file, which may hold its chain.",
	    values: "a path", default: "none", undo: "clear the field",
	    applies: "pki and ca lines" },
	"smtp.key": { label: "Key", keyword: "key file", definition: "The " +
	    "certificate's private key file.", values: "a path",
	    default: "none", undo: "clear the field", applies: "pki lines" },
	"smtp.dhe": { label: "DHE", keyword: "dhe none | legacy | auto",
	    definition: "The DHE parameters, for DHE cipher suites.",
	    values: "none, legacy or auto", default: "none", undo: "clear " +
	    "the field", applies: "pki lines" },
	"smtp.def": { label: "Filter", keyword: "phase ... | proc name | " +
	    "proc-exec command | chain { ... }", definition: "What the " +
	    "filter is. proc-exec runs a command.", values: "as smtpd.conf " +
	    "writes it", default: "none", undo: "clear the field",
	    applies: "filter lines" },
	"smtp.proc": { label: "Process", keyword: "proc name command [options]",
	    definition: "A filter process smtpd runs, which filters share.",
	    values: "a name", default: "none", risk: "high: it runs a command",
	    undo: "Delete" },
	"smtp.maxsize": { label: "Largest message", keyword: "smtp " +
	    "max-message-size size", definition: "Larger messages are refused.",
	    values: "bytes, or with K, M or G", default: "35M", undo: "clear " +
	    "the field" },
	"smtp.smtpciphers": { label: "Ciphers", keyword: "smtp ciphers control",
	    definition: "The ciphers for TLS, as SSL_CTX_set_cipher_list(3) " +
	    "takes them.", values: "a control string",
	    default: "HIGH:!aNULL:!MD5", undo: "clear the field" },
	"smtp.subaddr": { label: "Sub-address delimiter", keyword: "smtp " +
	    "sub-addr-delim character", definition: "In a local address, " +
	    "this character and what follows it are ignored.", values: "one " +
	    "character", default: "+", undo: "clear the field" },
	"smtp.queuecompression": { label: "Compress the queue",
	    keyword: "queue compression", definition: "Queue files are " +
	    "stored compressed.", values: "on or off", default: "off",
	    undo: "clear the check box" },
	"smtp.queueencryption": { label: "Queue key", keyword: "queue " +
	    "encryption key", definition: "Queue files are encrypted with " +
	    "this key; stdin or - reads it from smtpd's input.", values: "a " +
	    "key", default: "not encrypted", secret: true, undo: "clear the " +
	    "field" },
	"smtp.queuettl": { label: "Queue lifetime", keyword: "queue ttl delay",
	    definition: "How long a message that cannot yet be delivered " +
	    "stays in the queue.", values: "a number then s, m, h or d",
	    default: "4d", undo: "clear the field" },
	"smtp.bounce": { label: "Warnings", keyword: "bounce warn-interval " +
	    "delay [, delay ...]", definition: "When the sender is warned " +
	    "that a message is still in the queue.", values: "up to four " +
	    "delays, a number then s, m, h or d", default: "4h",
	    undo: "clear the field" },
	"smtp.maxdeferred": { label: "Deferred messages", keyword: "mta " +
	    "max-deferred number", definition: "How many messages are held " +
	    "for a host that failed for now, to send when it answers.",
	    values: "a number", default: "100", undo: "clear the field" },
	"smtp.srskey": { label: "SRS key", keyword: "srs key [backup] secret",
	    definition: "The key of the Sender Rewriting Scheme.",
	    values: "a secret", default: "none", secret: true, undo: "clear " +
	    "the field" },
	"smtp.srsttl": { label: "SRS lifetime", keyword: "srs ttl delay",
	    definition: "After this, a bounce to an SRS address is dropped.",
	    values: "a number then s, m, h or d", default: "4d",
	    undo: "clear the field" },
	"smtp.admd": { label: "ADMD", keyword: "admd authservid",
	    definition: "The domain this server belongs to, which filters " +
	    "write in Authentication-Results headers.", values: "a name",
	    default: "the server's name", undo: "clear the field" },
	"smtp.smtplimit": { label: "SMTP limits", keyword: "smtp limit " +
	    "max-mails | max-rcpt count", definition: "max-mails is the most " +
	    "messages a session; max-rcpt the most recipients a message.",
	    values: "the limit's name and a count", default: "100 and 1000",
	    undo: "Delete" },
	"smtp.mtalimit": { label: "MTA limits", keyword: "mta limit [for " +
	    "domain name] limit value", definition: "Limits on delivering to " +
	    "other servers, for every domain or one.", values: "as " +
	    "smtpd.conf writes them", default: "smtpd's", undo: "Delete" },
	"smtp.mdalimit": { label: "MDA limits", keyword: "mda limit limit " +
	    "value", definition: "Limits on local deliveries.", values: "as " +
	    "smtpd.conf writes them", default: "smtpd's", undo: "Delete" },
	"smtp.schedlimit": { label: "Scheduler limits", keyword: "scheduler " +
	    "limit limit value", definition: "Limits on the queue's scheduler.",
	    values: "as smtpd.conf writes them", default: "smtpd's",
	    undo: "Delete" },

	/* ifstated's configuration */
	"ifstate.macro": { label: "Condition", keyword: "name = \"test\"",
	    definition: "A named condition, which if lines write as $name. A " +
	    "test is an interface's link state, such as em0.link.up, or a " +
	    "command and every N, which ifstated runs each N seconds; tests " +
	    "join with &&, || and !.", values: "a name of letters, digits " +
	    "and _", default: "none", undo: "Delete" },
	"ifstate.value": { label: "Test", keyword: "\"test\"",
	    definition: "The condition's test, as ifstated.conf writes it.",
	    values: "if.link.up, .down or .unknown; \"command\" every " +
	    "seconds; joined with &&, || and !", default: "none",
	    risk: "high: a test with every runs its command each time",
	    undo: "clear the field", applies: "conditions" },
	"ifstate.state": { label: "State", keyword: "state name { ... }",
	    definition: "A state: its init block runs when ifstated enters " +
	    "it, and its other lines each time a test it names changes.",
	    values: "a name", default: "none", undo: "Delete" },
	"ifstate.init": { label: "Init", keyword: "init { ... } | init action",
	    definition: "What ifstated does each time it enters the state.",
	    values: "actions", default: "nothing", undo: "Delete",
	    applies: "states" },
	"ifstate.if": { label: "If", keyword: "if test { ... } | if test " +
	    "action", definition: "Actions done when the test is true.",
	    values: "a test: $name, if.link.up and the like, or \"command\" " +
	    "every seconds, joined with &&, || and !", default: "none",
	    undo: "Delete", applies: "states, init blocks and if blocks" },
	"ifstate.run": { label: "Run", keyword: "run \"command\"",
	    definition: "A shell command ifstated runs, as root.",
	    values: "a command line", default: "none", risk: "high: it runs " +
	    "as root each time its block is done", undo: "Delete",
	    applies: "states, init blocks and if blocks" },
	"ifstate.setstate": { label: "Set state", keyword: "set-state name",
	    definition: "Moves to another state, whose init block then runs.",
	    values: "a state's name", default: "none", undo: "Delete",
	    applies: "states, init blocks and if blocks" },
	"ifstate.initstate": { label: "Initial state", keyword: "init-state " +
	    "name", definition: "The state ifstated starts in.", values: "a " +
	    "state's name", default: "the first state", undo: "clear the " +
	    "field" },

	/* isakmpd's configuration */
	"ipsec.ike": { label: "IKE policy", keyword: "ike [mode] [encap] " +
	    "[tmode] [proto p] from src to dst [local a] [peer b] [main ...] " +
	    "[quick ...] [srcid id] [dstid id] [psk key] [tag t]",
	    definition: "Traffic isakmpd protects with IKEv1: it negotiates " +
	    "SAs with the peer and sets up the flows.", values: "the " +
	    "policy's options", default: "none", undo: "Delete" },
	"ipsec.mode": { label: "Mode", keyword: "passive | dynamic | active",
	    definition: "active starts the negotiation; passive waits for " +
	    "the peer; dynamic starts it, checks that the peer is alive, and " +
	    "uses the host's name as the local identity, for hosts whose " +
	    "address changes.", values: "passive, dynamic or active",
	    default: "active", undo: "choose (not set)", applies: "ike lines" },
	"ipsec.satype": { label: "Protocol", keyword: "esp | ah | ipcomp | " +
	    "ipip", definition: "How the traffic is protected: esp encrypts " +
	    "and authenticates, ah only authenticates.", values: "esp, ah, " +
	    "ipcomp or ipip", default: "esp", undo: "choose (not set)",
	    applies: "ike and flow lines" },
	"ipsec.tmode": { label: "Encapsulation", keyword: "tunnel | transport",
	    definition: "tunnel carries whole packets between networks; " +
	    "transport protects traffic between the two hosts themselves.",
	    values: "tunnel or transport", default: "tunnel", undo: "choose " +
	    "(not set)", applies: "ike, flow and key lines" },
	"ipsec.interface": { label: "Interface", keyword: "interface sec",
	    definition: "A sec(4) interface the policy's traffic goes " +
	    "through, in place of from and to.", values: "a sec interface's " +
	    "name", default: "none", undo: "clear the field", applies: "ike " +
	    "lines" },
	"ipsec.proto": { label: "IP protocol", keyword: "proto protocol",
	    definition: "Protects only this IP protocol.", values: "a " +
	    "protocol's name or number, such as tcp", default: "all",
	    undo: "clear the field", applies: "ike and flow lines" },
	"ipsec.from": { label: "From", keyword: "from src [port p] [(srcnat)]",
	    definition: "The traffic's source.", values: "an address, a " +
	    "network, any, or a list in braces, then port if any",
	    default: "none: it needs one", undo: "clear the field",
	    applies: "ike, flow and key lines" },
	"ipsec.to": { label: "To", keyword: "to dst [port p]",
	    definition: "The traffic's destination.", values: "an address, a " +
	    "network, any, or a list in braces, then port if any",
	    default: "none: it needs one", undo: "clear the field",
	    applies: "ike, flow and key lines" },
	"ipsec.local": { label: "Local", keyword: "local address",
	    definition: "The address of this end of the IKE exchange.",
	    values: "an address or a host name", default: "chosen by the " +
	    "routing table", undo: "clear the field", applies: "ike and flow " +
	    "lines" },
	"ipsec.peer": { label: "Peer", keyword: "peer address",
	    definition: "The other end of the IKE exchange.", values: "an " +
	    "address, a host name or any", default: "the destination, for " +
	    "one host", undo: "clear the field", applies: "ike and flow " +
	    "lines" },
	"ipsec.main": { label: "Phase 1", keyword: "main [auth a] [enc e] " +
	    "[group g] [lifetime t]", definition: "Main mode, and the " +
	    "transforms that protect the IKE exchange.", values: "auth, enc, " +
	    "group and lifetime with their values", default: "hmac-sha1, " +
	    "aes, modp3072, 3600", undo: "clear the field", applies: "ike " +
	    "lines" },
	"ipsec.aggressive": { label: "Phase 1, aggressive",
	    keyword: "aggressive [auth a] [enc e] [group g] [lifetime t]",
	    definition: "Aggressive mode, in place of main. With a " +
	    "pre-shared key it lets an eavesdropper try to guess the key.",
	    values: "as for main", default: "main mode", risk: "high: with a " +
	    "pre-shared key, the key can be guessed offline", undo: "clear " +
	    "the field", applies: "ike lines" },
	"ipsec.quick": { label: "Phase 2", keyword: "quick [auth a] [enc e] " +
	    "[group g] [lifetime t]", definition: "The transforms of the SAs " +
	    "that carry the traffic. A group other than none turns on " +
	    "perfect forward secrecy.", values: "auth, enc, group and " +
	    "lifetime with their values", default: "hmac-sha2-256, aes, 1200",
	    undo: "clear the field", applies: "ike lines" },
	"ipsec.srcid": { label: "Local ID", keyword: "srcid id",
	    definition: "The identity this end gives: a host name, or an " +
	    "email address.", values: "a host name or an email address",
	    default: "this end's address", undo: "clear the field",
	    applies: "ike and flow lines" },
	"ipsec.dstid": { label: "Peer ID", keyword: "dstid id",
	    definition: "The identity the peer must give.", values: "a host " +
	    "name or an email address", default: "the peer's address",
	    undo: "clear the field", applies: "ike and flow lines" },
	"ipsec.rsa": { label: "RSA", keyword: "rsa", definition: "The ends " +
	    "authenticate with their keys and certificates, which isakmpd(8) " +
	    "describes. It is what happens without psk.", values: "on or off",
	    default: "on", undo: "clear the check box", applies: "ike lines" },
	"ipsec.psk": { label: "Pre-shared key", keyword: "psk key",
	    definition: "A key both ends know, in place of certificates.",
	    values: "a string", default: "none", secret: true, undo: "clear " +
	    "the field", applies: "ike lines" },
	"ipsec.tag": { label: "pf tag", keyword: "tag tag", definition: "pf " +
	    "tags the packets of the policy's SAs; $id and $domain stand for " +
	    "the peer's identity.", values: "a tag, quoted if it holds $",
	    default: "none", undo: "clear the field", applies: "ike lines" },
	"ipsec.flow": { label: "Flow", keyword: "flow [satype] [in | out] " +
	    "from src to dst [peer p] [type t]", definition: "A flow set up " +
	    "without IKE, for SAs with keys set by hand or another daemon.",
	    values: "the flow's options", default: "none", undo: "Delete" },
	"ipsec.dir": { label: "Direction", keyword: "in | out",
	    definition: "The flow's direction.", values: "in or out",
	    default: "both", undo: "choose (not set)", applies: "flow lines" },
	"ipsec.type": { label: "Type", keyword: "type use | acquire | " +
	    "require | deny | bypass | dontacq", definition: "What the " +
	    "kernel does with the flow's packets when there is no SA: " +
	    "require drops them; use and acquire send them in the clear; " +
	    "deny drops; bypass skips IPsec.", values: "use, acquire, " +
	    "require, deny, bypass or dontacq", default: "require",
	    undo: "choose (not set)", applies: "flow lines" },
	"ipsec.esp": { label: "ESP by hand", keyword: "esp [tmode] from src " +
	    "to dst spi in:out ... authkey k enckey k", definition: "An ESP " +
	    "SA whose keys are written here rather than negotiated.",
	    values: "the SA's options", default: "none", undo: "Delete" },
	"ipsec.spi": { label: "SPI", keyword: "spi in[:out]",
	    definition: "The SA's security parameter index, each way.",
	    values: "hexadecimal numbers", default: "none", undo: "clear the " +
	    "field", applies: "lines with keys set by hand" },
	"ipsec.udpencap": { label: "UDP encapsulation", keyword: "udpencap",
	    definition: "The SA's packets go in UDP, through NAT.",
	    values: "on or off", default: "off", undo: "clear the check box",
	    applies: "lines with keys set by hand" },
	"ipsec.auth": { label: "Authentication", keyword: "auth algorithm",
	    definition: "The SA's authentication algorithm.",
	    values: "hmac-sha1, hmac-sha2-256 and others ipsec.conf(5) lists",
	    default: "hmac-sha2-256", undo: "clear the field",
	    applies: "lines with keys set by hand" },
	"ipsec.enc": { label: "Encryption", keyword: "enc algorithm",
	    definition: "The SA's cipher.", values: "aes, aes-256-gcm and " +
	    "others ipsec.conf(5) lists", default: "aes", undo: "clear the " +
	    "field", applies: "lines with keys set by hand" },
	"ipsec.comp": { label: "Compression", keyword: "comp algorithm",
	    definition: "An IPcomp SA's compression.", values: "deflate",
	    default: "deflate", undo: "clear the field", applies: "lines " +
	    "with keys set by hand" },
	"ipsec.authkey": { label: "Authentication key", keyword: "authkey " +
	    "key | file path", definition: "The authentication keys, each way.",
	    values: "hexadecimal keys, or file and a path", default: "none",
	    secret: true, undo: "clear the field", applies: "lines with keys " +
	    "set by hand" },
	"ipsec.enckey": { label: "Encryption key", keyword: "enckey key | " +
	    "file path", definition: "The encryption keys, each way.",
	    values: "hexadecimal keys, or file and a path", default: "none",
	    secret: true, undo: "clear the field", applies: "lines with keys " +
	    "set by hand" },
	"ipsec.bundle": { label: "Bundle", keyword: "bundle name",
	    definition: "Groups SAs that apply together.", values: "a name",
	    default: "none", undo: "clear the field", applies: "lines with " +
	    "keys set by hand" },
	"ipsec.ah": { label: "AH by hand", keyword: "ah [tmode] from src to " +
	    "dst spi in:out ... authkey k", definition: "An AH SA whose keys " +
	    "are written here.", values: "the SA's options", default: "none",
	    undo: "Delete" },
	"ipsec.ipcomp": { label: "IPcomp by hand", keyword: "ipcomp [tmode] " +
	    "from src to dst spi in:out", definition: "An IPcomp SA written " +
	    "here.", values: "the SA's options", default: "none",
	    undo: "Delete" },
	"ipsec.ipip": { label: "IP-in-IP by hand", keyword: "ipip [tmode] " +
	    "from src to dst spi in:out", definition: "An IP-in-IP SA " +
	    "written here.", values: "the SA's options", default: "none",
	    undo: "Delete" },
	"ipsec.tcpmd5": { label: "TCP MD5", keyword: "tcpmd5 from src to dst " +
	    "spi in:out authkey k", definition: "TCP MD5 signatures between " +
	    "two hosts, as BGP uses them.", values: "the SA's options",
	    default: "none", undo: "Delete" },
	"ipsec.macro": { label: "Macro", keyword: "name = value",
	    definition: "A name other lines write as $name.", values: "a " +
	    "name of letters, digits and _", default: "none", undo: "Delete" },
	"ipsec.value": { label: "Value", keyword: "value", definition: "What " +
	    "$name stands for.", values: "text, quoted if it has spaces",
	    default: "none", undo: "clear the field", applies: "macros" },

	/* iked's configuration */
	"ike.ikev2": { label: "Policy", keyword: "ikev2 [name] [options]",
	    definition: "Traffic iked protects with IKEv2.", values: "a " +
	    "name, quoted, or none", default: "none", undo: "Delete" },
	"ike.match": { label: "Match", keyword: "quick | skip | default",
	    definition: "quick: a peer that matches stops the search; skip: " +
	    "the policy is only for starting; default: the policy for peers " +
	    "no other matches.", values: "quick, skip or default",
	    default: "none", undo: "choose (not set)", applies: "policies" },
	"ike.mode": { label: "Mode", keyword: "passive | active",
	    definition: "active starts the exchange; passive waits for the " +
	    "peer.", values: "passive or active", default: "passive",
	    undo: "choose (not set)", applies: "policies" },
	"ike.ipcomp": { label: "IPcomp", keyword: "ipcomp", definition: "The " +
	    "traffic is compressed.", values: "on or off", default: "off",
	    undo: "clear the check box", applies: "policies" },
	"ike.tmode": { label: "Encapsulation", keyword: "tunnel | transport",
	    definition: "tunnel carries whole packets between networks; " +
	    "transport protects traffic between the two hosts.",
	    values: "tunnel or transport", default: "tunnel", undo: "choose " +
	    "(not set)", applies: "policies" },
	"ike.natt": { label: "Force NAT-T", keyword: "natt",
	    definition: "Uses UDP encapsulation even when there is no NAT.",
	    values: "on or off", default: "off", undo: "clear the check box",
	    applies: "policies" },
	"ike.satype": { label: "Protocol", keyword: "esp | ah",
	    definition: "esp encrypts and authenticates; ah only " +
	    "authenticates.", values: "esp or ah", default: "esp",
	    undo: "choose (not set)", applies: "policies" },
	"ike.af": { label: "Family", keyword: "inet | inet6",
	    definition: "The address family of the peers.", values: "inet or " +
	    "inet6", default: "either", undo: "choose (not set)",
	    applies: "policies" },
	"ike.rdomain": { label: "Routing domain", keyword: "rdomain number",
	    definition: "The routing domain the decrypted traffic goes in.",
	    values: "a routing domain's number", default: "iked's own",
	    undo: "clear the field", applies: "policies" },
	"ike.proto": { label: "IP protocol", keyword: "proto protocol | { " +
	    "protocol, ... }", definition: "Protects only these IP protocols.",
	    values: "names or numbers", default: "all", undo: "clear the field",
	    applies: "policies" },
	"ike.from": { label: "From", keyword: "from src [port p]",
	    definition: "The traffic's source. Several from ... to pairs may " +
	    "be given, separated by commas.", values: "an address, a " +
	    "network, any or dynamic, then port if any", default: "any",
	    undo: "clear the field", applies: "policies" },
	"ike.to": { label: "To", keyword: "to dst [port p]",
	    definition: "The traffic's destination.", values: "an address, a " +
	    "network, any or dynamic, then port if any", default: "any",
	    undo: "clear the field", applies: "policies" },
	"ike.local": { label: "Local", keyword: "local address",
	    definition: "The address of this end.", values: "an address, a " +
	    "host name or any", default: "any", undo: "clear the field",
	    applies: "policies" },
	"ike.peer": { label: "Peer", keyword: "peer address",
	    definition: "The other end.", values: "an address, a network, a " +
	    "host name or any", default: "any", undo: "clear the field",
	    applies: "policies" },
	"ike.ikesa": { label: "IKE SA", keyword: "ikesa [auth a] [enc e] " +
	    "[prf p] [group g]", definition: "The transforms that protect " +
	    "the IKE exchange. Several ikesa may be given.", values: "auth, " +
	    "enc, prf and group with their values", default: "iked's list",
	    undo: "clear the field", applies: "policies" },
	"ike.childsa": { label: "Child SA", keyword: "childsa [auth a] [enc " +
	    "e] [group g] [esn | noesn]", definition: "The transforms of the " +
	    "SAs that carry the traffic. A group turns on perfect forward " +
	    "secrecy.", values: "auth, enc, group and esn with their values",
	    default: "iked's list", undo: "clear the field",
	    applies: "policies" },
	"ike.srcid": { label: "Local ID", keyword: "srcid id",
	    definition: "The identity this end gives.", values: "a host " +
	    "name, an email address, an address or a certificate's subject",
	    default: "the host's name", undo: "clear the field",
	    applies: "policies" },
	"ike.dstid": { label: "Peer ID", keyword: "dstid id",
	    definition: "The identity the peer must give.", values: "as for " +
	    "the local ID", default: "any", undo: "clear the field",
	    applies: "policies" },
	"ike.ikelifetime": { label: "IKE SA lifetime", keyword: "ikelifetime " +
	    "time", definition: "How long the IKE SA lasts before it is " +
	    "renewed.", values: "seconds, or with m or h; 0 for none",
	    default: "0: not renewed", undo: "clear the field",
	    applies: "policies" },
	"ike.lifetime": { label: "Child SA lifetime", keyword: "lifetime " +
	    "time [bytes bytes]", definition: "How long, or how many bytes, " +
	    "a child SA lasts before it is renewed.", values: "a time, then " +
	    "bytes and a size if any", default: "3h, 4G", undo: "clear the " +
	    "field", applies: "policies" },
	"ike.psk": { label: "Pre-shared key", keyword: "psk key | file path",
	    definition: "A key both ends know, in place of certificates.",
	    values: "a string, 0x and hexadecimal, or file and a path",
	    default: "none", secret: true, undo: "clear the field",
	    applies: "policies" },
	"ike.eap": { label: "EAP", keyword: "eap mschap-v2 | radius",
	    definition: "Remote users log in with EAP: against the users " +
	    "here, or a RADIUS server.", values: "mschap-v2 or radius",
	    default: "none", undo: "clear the field", applies: "policies" },
	"ike.auth": { label: "Authentication", keyword: "rsa | ecdsa256 | " +
	    "ecdsa384 | ecdsa521 | rfc7427", definition: "The kind of key " +
	    "the ends prove themselves with.", values: "rsa, ecdsa256, " +
	    "ecdsa384, ecdsa521 or rfc7427", default: "any kind of signature",
	    undo: "choose (not set)", applies: "policies" },
	"ike.config": { label: "Configuration", keyword: "config option " +
	    "value ...", definition: "What iked gives the peer: an address " +
	    "from a pool, a name server, and others iked.conf(5) lists. " +
	    "Several may be given.", values: "option and value pairs, each " +
	    "after config", default: "none", undo: "clear the field",
	    applies: "policies" },
	"ike.request": { label: "Request", keyword: "request option value",
	    definition: "What iked asks the peer to give it, such as an " +
	    "address.", values: "option and value pairs", default: "none",
	    undo: "clear the field", applies: "policies" },
	"ike.iface": { label: "Interface", keyword: "iface interface",
	    definition: "An interface the peer's assigned address goes on.",
	    values: "an interface's name", default: "none", undo: "clear the " +
	    "field", applies: "policies" },
	"ike.tag": { label: "pf tag", keyword: "tag tag", definition: "pf " +
	    "tags the packets of the policy's SAs.", values: "a tag",
	    default: "none", undo: "clear the field", applies: "policies" },
	"ike.tap": { label: "enc interface", keyword: "tap interface",
	    definition: "The enc(4) interface the policy's traffic shows on.",
	    values: "an enc interface's name", default: "enc0", undo: "clear " +
	    "the field", applies: "policies" },
	"ike.user": { label: "User", keyword: "user name password",
	    definition: "A remote user who logs in with EAP MSCHAPv2.",
	    values: "a name", default: "none", undo: "Delete" },
	"ike.password": { label: "Password", keyword: "password",
	    definition: "The user's password.", values: "a string",
	    default: "none", secret: true, undo: "clear the field",
	    applies: "users" },
	"ike.radserver": { label: "RADIUS server", keyword: "radius server " +
	    "address [port p] secret s", definition: "A RADIUS server EAP " +
	    "logins are checked against.", values: "an address",
	    default: "none", undo: "Delete" },
	"ike.port": { label: "Port", keyword: "port port", definition: "The " +
	    "RADIUS server's port, or the DAE listener's.", values: "a port " +
	    "number", default: "1812, 1813 for accounting, 3799 for DAE",
	    undo: "clear the field", applies: "RADIUS servers and the DAE " +
	    "listener" },
	"ike.secret": { label: "Secret", keyword: "secret secret",
	    definition: "The secret shared with the RADIUS server or DAE " +
	    "client.", values: "a string", default: "none", secret: true,
	    undo: "clear the field", applies: "RADIUS servers and DAE " +
	    "clients" },
	"ike.radacct": { label: "RADIUS accounting server", keyword: "radius " +
	    "accounting server address [port p] secret s", definition: "A " +
	    "RADIUS server told of each session.", values: "an address",
	    default: "none", undo: "Delete" },
	"ike.radconfig": { label: "RADIUS attribute", keyword: "radius " +
	    "config [af] option attribute", definition: "A RADIUS attribute " +
	    "whose value iked gives the peer as a configuration option.",
	    values: "as iked.conf writes it", default: "none", undo: "Delete" },
	"ike.daelisten": { label: "DAE listener", keyword: "radius dae " +
	    "listen on address [port p]", definition: "An address iked takes " +
	    "RADIUS dynamic authorization requests on, such as to end a " +
	    "session.", values: "an address", default: "none", undo: "Delete" },
	"ike.daeclient": { label: "DAE client", keyword: "radius dae client " +
	    "address secret s", definition: "A host allowed to send dynamic " +
	    "authorization requests.", values: "an address", default: "none",
	    risk: "high: it can end sessions", undo: "Delete" },
	"ike.setmode": { label: "Mode", keyword: "set active | passive",
	    definition: "Whether iked starts exchanges for active policies, " +
	    "or only answers.", values: "active or passive", default: "active",
	    undo: "choose (not set)" },
	"ike.setcouple": { label: "Flows", keyword: "set couple | decouple",
	    definition: "couple loads the policies' flows into the kernel; " +
	    "decouple leaves them out, as ikectl decouple does.",
	    values: "couple or decouple", default: "couple", undo: "choose " +
	    "(not set)" },
	"ike.setfrag": { label: "Fragmentation", keyword: "set fragmentation " +
	    "| nofragmentation", definition: "IKEv2 message fragmentation, " +
	    "for paths that drop IP fragments.", values: "fragmentation or " +
	    "nofragmentation", default: "nofragmentation", undo: "choose " +
	    "(not set)" },
	"ike.setmobike": { label: "MOBIKE", keyword: "set mobike | nomobike",
	    definition: "Lets a peer whose address changes keep its SAs.",
	    values: "mobike or nomobike", default: "mobike", undo: "choose " +
	    "(not set)" },
	"ike.setvendorid": { label: "Vendor ID", keyword: "set vendorid | " +
	    "novendorid", definition: "Whether iked sends its vendor ID.",
	    values: "vendorid or novendorid", default: "vendorid",
	    undo: "choose (not set)" },
	"ike.setsingle": { label: "One IKE SA a peer", keyword: "set " +
	    "enforcesingleikesa | noenforcesingleikesa",
	    definition: "Whether a peer may have only one IKE SA, an older " +
	    "one being closed.", values: "enforcesingleikesa or " +
	    "noenforcesingleikesa", default: "noenforcesingleikesa",
	    undo: "choose (not set)" },
	"ike.setsticky": { label: "Sticky addresses", keyword: "set " +
	    "stickyaddress | nostickyaddress", definition: "Whether a peer " +
	    "that comes back gets the address it had.",
	    values: "stickyaddress or nostickyaddress",
	    default: "nostickyaddress", undo: "choose (not set)" },
	"ike.setocsp": { label: "OCSP", keyword: "set ocsp url [tolerate t " +
	    "[maxage t]]", definition: "Where iked checks whether " +
	    "certificates are revoked.", values: "a URL, then its times if any",
	    default: "none", undo: "clear the field" },
	"ike.setpartial": { label: "Partial chains", keyword: "set " +
	    "cert_partial_chain", definition: "Accepts a partial certificate " +
	    "chain if one of its certificates is a CA in /etc/iked/ca/.",
	    values: "on or off", default: "off", undo: "clear the check box" },
	"ike.setdpd": { label: "Liveness checks", keyword: "set " +
	    "dpd_check_interval seconds", definition: "How often iked checks " +
	    "that each peer is still there.", values: "seconds", default: "60",
	    undo: "clear the field" },
	"ike.macro": { label: "Macro", keyword: "name = value",
	    definition: "A name other lines write as $name.", values: "a " +
	    "name of letters, digits and _", default: "none", undo: "Delete" },
	"ike.value": { label: "Value", keyword: "value", definition: "What " +
	    "$name stands for.", values: "text, quoted if it has spaces",
	    default: "none", undo: "clear the field", applies: "macros" },

	/* dhcpd's configuration */
	"dhcp.subnet": { label: "Subnet", keyword: "subnet network netmask " +
	    "mask { ... }", definition: "A network dhcpd serves. Each " +
	    "network dhcpd listens on needs one, with addresses to give or " +
	    "not.", values: "a network address", default: "none",
	    undo: "Delete" },
	"dhcp.netmask": { label: "Netmask", keyword: "netmask mask",
	    definition: "The subnet's mask.", values: "a dotted mask, such " +
	    "as 255.255.255.0", default: "none: it needs one", undo: "clear " +
	    "the field", applies: "subnets" },
	"dhcp.host": { label: "Host", keyword: "host name { ... }",
	    definition: "A client known by its hardware address, which may " +
	    "have a fixed address and settings of its own.", values: "a name",
	    default: "none", undo: "Delete" },
	"dhcp.hardware": { label: "Hardware address", keyword: "hardware " +
	    "ethernet address", definition: "The client's Ethernet address.",
	    values: "six hexadecimal octets, separated by colons",
	    default: "none", undo: "Delete", applies: "hosts" },
	"dhcp.fixedaddr": { label: "Fixed address", keyword: "fixed-address " +
	    "address [, address ...]", definition: "The address the client " +
	    "is always given; with several, the one on the network it boots " +
	    "on.", values: "addresses or host names, separated by commas",
	    default: "one from a range", undo: "Delete", applies: "hosts" },
	"dhcp.range": { label: "Range", keyword: "range [dynamic-bootp] low " +
	    "[high]", definition: "Addresses dhcpd gives clients, from low " +
	    "to high.", values: "two addresses in the subnet, or one",
	    default: "none: no addresses are given", undo: "Delete",
	    applies: "subnets" },
	"dhcp.routers": { label: "Routers", keyword: "option routers address " +
	    "[, address ...]", definition: "The default routers clients are " +
	    "given, in order of preference.", values: "addresses, separated " +
	    "by commas", default: "none", undo: "Delete", applies: "the " +
	    "global settings, subnets, shared networks, groups and hosts" },
	"dhcp.dns": { label: "Name servers", keyword: "option " +
	    "domain-name-servers address [, address ...]", definition: "The " +
	    "name servers clients are given, in order of preference.",
	    values: "addresses or host names, separated by commas",
	    default: "none", undo: "clear the field", applies: "the global " +
	    "settings, subnets, shared networks, groups and hosts" },
	"dhcp.domain": { label: "Domain name", keyword: "option domain-name " +
	    "\"name\"", definition: "The domain name clients are given.",
	    values: "a domain name", default: "none", undo: "clear the field",
	    applies: "the global settings, subnets, shared networks, groups " +
	    "and hosts" },
	"dhcp.ntp": { label: "NTP servers", keyword: "option ntp-servers " +
	    "address [, address ...]", definition: "The NTP servers clients " +
	    "are given.", values: "addresses, separated by commas",
	    default: "none", undo: "Delete", applies: "the global settings, " +
	    "subnets, shared networks, groups and hosts" },
	"dhcp.lease": { label: "Lease time", keyword: "default-lease-time " +
	    "seconds", definition: "How long a lease lasts when the client " +
	    "asks for no time.", values: "seconds", default: "43200",
	    undo: "clear the field", applies: "the global settings, subnets, " +
	    "shared networks, groups and hosts" },
	"dhcp.maxlease": { label: "Longest lease", keyword: "max-lease-time " +
	    "seconds", definition: "The longest lease a client may ask for.",
	    values: "seconds", default: "86400", undo: "clear the field",
	    applies: "the global settings, subnets, shared networks, groups " +
	    "and hosts" },
	"dhcp.filename": { label: "Boot file", keyword: "filename \"file\"",
	    definition: "The file a client boots from.", values: "a file name",
	    default: "none", undo: "Delete", applies: "the global settings, " +
	    "subnets, shared networks, groups and hosts" },
	"dhcp.nextserver": { label: "Boot server", keyword: "next-server " +
	    "server", definition: "The server the boot file is loaded from.",
	    values: "an address or a host name", default: "this server",
	    undo: "Delete", applies: "the global settings, subnets, shared " +
	    "networks, groups and hosts" },
	"dhcp.option": { label: "Option", keyword: "option name value",
	    definition: "A DHCP option this form has no field for, which " +
	    "dhcp-options(5) lists.", values: "the option's name",
	    default: "none", undo: "Delete", applies: "the global settings, " +
	    "subnets, shared networks, groups and hosts" },
	"dhcp.value": { label: "Value", keyword: "value", definition: "The " +
	    "option's value, as dhcpd.conf writes it.", values: "as " +
	    "dhcp-options(5) says for the option", default: "none",
	    undo: "clear the field", applies: "options" },
	"dhcp.other": { label: "Other", keyword: "statement", definition: "A " +
	    "statement this form has no field for, as written, such as " +
	    "allow, deny or server-name.", values: "the statement as " +
	    "dhcpd.conf writes it", default: "none", undo: "Delete",
	    applies: "the global settings, subnets, shared networks, groups " +
	    "and hosts" },
	"dhcp.sharednet": { label: "Shared network",
	    keyword: "shared-network name { ... }", definition: "Subnets on " +
	    "one physical network.", values: "a name", default: "none",
	    undo: "Delete" },
	"dhcp.group": { label: "Group", keyword: "group { ... }",
	    definition: "Hosts or subnets that share settings.", values: "a " +
	    "block", default: "none", undo: "Delete" },
	"dhcp.authoritative": { label: "Authoritative",
	    keyword: "authoritative", definition: "dhcpd answers a client " +
	    "asking for an address that does not belong on its network with " +
	    "a refusal, so the client starts again. It is what dhcpd does " +
	    "unless a scope says not authoritative.", values: "present or " +
	    "absent", default: "authoritative", undo: "clear the check box" },

	/* sshd's configuration */
	"sshd.port": { label: "Port", keyword: "Port port", definition: "A " +
	    "port sshd listens on, at each address it listens on without a " +
	    "port of its own.", values: "a port number, a line each",
	    default: "22", undo: "clear the field", applies: "the global " +
	    "settings" },
	"sshd.listenaddress": { label: "Listen address",
	    keyword: "ListenAddress address[:port] [rdomain domain]",
	    definition: "A local address sshd listens on, with a port and " +
	    "routing domain if given.", values: "an address or host name, a " +
	    "line each", default: "every local address in the default " +
	    "routing domain", undo: "clear the field", applies: "the global " +
	    "settings" },
	"sshd.addressfamily": { label: "Address family",
	    keyword: "AddressFamily family", definition: "The address " +
	    "families sshd uses.", values: "any, inet or inet6", default: "any",
	    undo: "choose (not set)", applies: "the global settings" },
	"sshd.hostkey": { label: "Host keys", keyword: "HostKey file",
	    definition: "A file holding a private host key.", values: "a " +
	    "path, a line each", default: "/etc/ssh/ssh_host_ecdsa_key, " +
	    "ssh_host_ed25519_key, ssh_host_mldsa44_ed25519_key and " +
	    "ssh_host_rsa_key", undo: "clear the field", applies: "the " +
	    "global settings" },
	"sshd.hostcertificate": { label: "Host certificates",
	    keyword: "HostCertificate file", definition: "A file holding a " +
	    "host certificate, which must match one of the host keys.",
	    values: "a path, a line each", default: "none", undo: "clear the " +
	    "field", applies: "the global settings" },
	"sshd.permitrootlogin": { label: "Root login",
	    keyword: "PermitRootLogin yes | prohibit-password | " +
	    "forced-commands-only | no", definition: "Whether root may log " +
	    "in, and how: prohibit-password allows keys only, and " +
	    "forced-commands-only allows keys with a forced command only.",
	    values: "yes, prohibit-password, forced-commands-only or no",
	    default: "prohibit-password", risk: "high: yes lets root log in " +
	    "with a password", undo: "choose (not set)", applies: "the " +
	    "global settings and Match sections" },
	"sshd.passwordauthentication": { label: "Passwords",
	    keyword: "PasswordAuthentication yes | no", definition: "Whether " +
	    "a password may be used to log in.", values: "yes or no",
	    default: "yes", undo: "choose (not set)", applies: "the global " +
	    "settings and Match sections" },
	"sshd.kbdinteractiveauthentication": { label: "Keyboard-interactive",
	    keyword: "KbdInteractiveAuthentication yes | no",
	    definition: "Whether keyboard-interactive login is allowed, with " +
	    "the styles of login.conf(5).", values: "yes or no", default: "yes",
	    undo: "choose (not set)", applies: "the global settings and " +
	    "Match sections" },
	"sshd.pubkeyauthentication": { label: "Public keys",
	    keyword: "PubkeyAuthentication yes | no", definition: "Whether a " +
	    "public key may be used to log in.", values: "yes or no",
	    default: "yes", undo: "choose (not set)", applies: "the global " +
	    "settings and Match sections" },
	"sshd.permitemptypasswords": { label: "Empty passwords",
	    keyword: "PermitEmptyPasswords yes | no", definition: "Whether " +
	    "an account with an empty password may log in, when passwords " +
	    "are allowed.", values: "yes or no", default: "no", risk: "high: " +
	    "yes lets an account with no password log in", undo: "choose " +
	    "(not set)", applies: "the global settings and Match sections" },
	"sshd.authenticationmethods": { label: "Methods required",
	    keyword: "AuthenticationMethods list ...", definition: "The " +
	    "methods a user must complete to log in: lists of methods " +
	    "separated by commas, any one list being enough.",
	    values: "lists such as publickey,password, separated by spaces, " +
	    "or any", default: "any: one method is enough", undo: "clear the " +
	    "field", applies: "the global settings and Match sections" },
	"sshd.maxauthtries": { label: "Login attempts",
	    keyword: "MaxAuthTries number", definition: "How many attempts " +
	    "to log in one connection may make.", values: "a number",
	    default: "6", undo: "clear the field", applies: "the global " +
	    "settings and Match sections" },
	"sshd.logingracetime": { label: "Time to log in",
	    keyword: "LoginGraceTime time", definition: "How long a " +
	    "connection may take to log in before sshd ends it; 0 for no " +
	    "limit.", values: "seconds, or a time such as 2m", default: "120 " +
	    "seconds", undo: "clear the field", applies: "the global " +
	    "settings" },
	"sshd.authorizedkeysfile": { label: "Authorized keys files",
	    keyword: "AuthorizedKeysFile file ...", definition: "The files " +
	    "holding a user's public keys, under the home directory unless a " +
	    "path is absolute; none for no file.", values: "paths separated " +
	    "by spaces, or none", default: ".ssh/authorized_keys " +
	    ".ssh/authorized_keys2", undo: "clear the field", applies: "the " +
	    "global settings and Match sections" },
	"sshd.trustedusercakeys": { label: "User CA keys",
	    keyword: "TrustedUserCAKeys file", definition: "A file of the " +
	    "keys of certificate authorities trusted to sign user " +
	    "certificates.", values: "a path, or none", default: "none",
	    undo: "clear the field", applies: "the global settings and Match " +
	    "sections" },
	"sshd.allowusers": { label: "Allowed users", keyword: "AllowUsers " +
	    "pattern ...", definition: "If set, only users that match one of " +
	    "these patterns may log in. Each line adds to the list.",
	    values: "user name patterns, or USER@HOST, separated by spaces",
	    default: "every user may log in", risk: "high: a user who is not " +
	    "listed can no longer log in over ssh", undo: "clear the field",
	    applies: "the global settings and Match sections" },
	"sshd.allowgroups": { label: "Allowed groups", keyword: "AllowGroups " +
	    "pattern ...", definition: "If set, only users in a group that " +
	    "matches one of these patterns may log in. Each line adds to the " +
	    "list.", values: "group name patterns, separated by spaces",
	    default: "users of every group may log in", risk: "high: a user " +
	    "in no listed group can no longer log in over ssh", undo: "clear " +
	    "the field", applies: "the global settings and Match sections" },
	"sshd.denyusers": { label: "Denied users", keyword: "DenyUsers " +
	    "pattern ...", definition: "Users that match one of these " +
	    "patterns may not log in. Each line adds to the list.",
	    values: "user name patterns, or USER@HOST, separated by spaces",
	    default: "none", undo: "clear the field", applies: "the global " +
	    "settings and Match sections" },
	"sshd.denygroups": { label: "Denied groups", keyword: "DenyGroups " +
	    "pattern ...", definition: "Users in a group that matches one of " +
	    "these patterns may not log in. Each line adds to the list.",
	    values: "group name patterns, separated by spaces", default: "none",
	    undo: "clear the field", applies: "the global settings and Match " +
	    "sections" },
	"sshd.allowtcpforwarding": { label: "TCP forwarding",
	    keyword: "AllowTcpForwarding yes | all | no | local | remote",
	    definition: "Whether TCP ports may be forwarded: yes or all for " +
	    "both ways, or local or remote only.", values: "yes, all, no, " +
	    "local or remote", default: "yes", undo: "choose (not set)",
	    applies: "the global settings and Match sections" },
	"sshd.allowagentforwarding": { label: "Agent forwarding",
	    keyword: "AllowAgentForwarding yes | no", definition: "Whether " +
	    "ssh-agent(1) may be forwarded.", values: "yes or no",
	    default: "yes", undo: "choose (not set)", applies: "the global " +
	    "settings and Match sections" },
	"sshd.allowstreamlocalforwarding": { label: "Socket forwarding",
	    keyword: "AllowStreamLocalForwarding yes | all | no | local | " +
	    "remote", definition: "Whether Unix-domain sockets may be " +
	    "forwarded: yes or all for both ways, or local or remote only.",
	    values: "yes, all, no, local or remote", default: "yes",
	    undo: "choose (not set)", applies: "the global settings and " +
	    "Match sections" },
	"sshd.x11forwarding": { label: "X11 forwarding",
	    keyword: "X11Forwarding yes | no", definition: "Whether X11 may " +
	    "be forwarded.", values: "yes or no", default: "no",
	    undo: "choose (not set)", applies: "the global settings and " +
	    "Match sections" },
	"sshd.permittunnel": { label: "Tunnels", keyword: "PermitTunnel yes " +
	    "| point-to-point | ethernet | no", definition: "Whether tun(4) " +
	    "devices may be forwarded: point-to-point at layer 3, ethernet " +
	    "at layer 2, yes for both.", values: "yes, point-to-point, " +
	    "ethernet or no", default: "no", undo: "choose (not set)",
	    applies: "the global settings and Match sections" },
	"sshd.gatewayports": { label: "Gateway ports",
	    keyword: "GatewayPorts no | yes | clientspecified",
	    definition: "Where a port a client forwards from this side " +
	    "listens: no on the loopback address only, yes on every address, " +
	    "clientspecified where the client says.", values: "no, yes or " +
	    "clientspecified", default: "no", undo: "choose (not set)",
	    applies: "the global settings and Match sections" },
	"sshd.disableforwarding": { label: "No forwarding",
	    keyword: "DisableForwarding yes | no", definition: "Turns off " +
	    "every kind of forwarding, whatever the other settings say.",
	    values: "yes or no", default: "no", undo: "choose (not set)",
	    applies: "the global settings and Match sections" },
	"sshd.permitopen": { label: "Forwarding destinations",
	    keyword: "PermitOpen host:port ...", definition: "Where TCP " +
	    "forwarding may connect to.", values: "host:port entries " +
	    "separated by spaces, or any or none", default: "any",
	    undo: "clear the field", applies: "the global settings and Match " +
	    "sections" },
	"sshd.permitlisten": { label: "Forwarding listeners",
	    keyword: "PermitListen [host:]port ...", definition: "Where a " +
	    "remote forwarding may listen.", values: "port or host:port " +
	    "entries separated by spaces, or any or none", default: "any",
	    undo: "clear the field", applies: "the global settings and Match " +
	    "sections" },
	"sshd.maxstartups": { label: "Connections logging in",
	    keyword: "MaxStartups number | start:rate:full",
	    definition: "How many connections may be logging in at once. " +
	    "With start:rate:full, sshd refuses rate percent of new ones at " +
	    "start, more as the count nears full, and all at full.",
	    values: "a number, or start:rate:full", default: "10:30:100",
	    undo: "clear the field", applies: "the global settings" },
	"sshd.maxsessions": { label: "Sessions a connection",
	    keyword: "MaxSessions number", definition: "How many shell, " +
	    "login or subsystem sessions one connection may open.",
	    values: "a number", default: "10", undo: "clear the field",
	    applies: "the global settings and Match sections" },
	"sshd.clientaliveinterval": { label: "Client alive interval",
	    keyword: "ClientAliveInterval time", definition: "How long the " +
	    "client may be silent before sshd asks it to answer; 0 for never.",
	    values: "seconds, or a time such as 5m", default: "0",
	    undo: "clear the field", applies: "the global settings and Match " +
	    "sections" },
	"sshd.clientalivecountmax": { label: "Client alive count",
	    keyword: "ClientAliveCountMax number", definition: "How many of " +
	    "those requests may go unanswered before sshd ends the connection.",
	    values: "a number", default: "3", undo: "clear the field",
	    applies: "the global settings and Match sections" },
	"sshd.ciphers": { label: "Ciphers", keyword: "Ciphers list",
	    definition: "The ciphers sshd allows.", values: "names separated " +
	    "by commas; +, - or ^ first adds them to, takes them from or " +
	    "puts them first in sshd's own list", default: "sshd's own list, " +
	    "in sshd_config(5)", undo: "clear the field", applies: "the " +
	    "global settings" },
	"sshd.macs": { label: "MACs", keyword: "MACs list", definition: "The " +
	    "message authentication codes sshd allows.", values: "names " +
	    "separated by commas; +, - or ^ first adds them to, takes them " +
	    "from or puts them first in sshd's own list", default: "sshd's " +
	    "own list, in sshd_config(5)", undo: "clear the field",
	    applies: "the global settings" },
	"sshd.kexalgorithms": { label: "Key exchange",
	    keyword: "KexAlgorithms list", definition: "The key exchange " +
	    "methods sshd offers.", values: "names separated by commas; +, - " +
	    "or ^ first adds them to, takes them from or puts them first in " +
	    "sshd's own list", default: "sshd's own list, in sshd_config(5)",
	    undo: "clear the field", applies: "the global settings" },
	"sshd.hostkeyalgorithms": { label: "Host key algorithms",
	    keyword: "HostKeyAlgorithms list", definition: "The host key " +
	    "signature methods sshd offers.", values: "names separated by " +
	    "commas", default: "sshd's own list, in sshd_config(5)",
	    undo: "clear the field", applies: "the global settings" },
	"sshd.pubkeyacceptedalgorithms": { label: "Public key algorithms",
	    keyword: "PubkeyAcceptedAlgorithms list", definition: "The " +
	    "signature methods sshd accepts for public keys.",
	    values: "names separated by commas; +, - or ^ first adds them " +
	    "to, takes them from or puts them first in sshd's own list",
	    default: "sshd's own list, in sshd_config(5)", undo: "clear the " +
	    "field", applies: "the global settings and Match sections" },
	"sshd.subsystem": { label: "Subsystem", keyword: "Subsystem name " +
	    "command", definition: "A subsystem a client may ask for, such " +
	    "as sftp, and the command that serves it.", values: "a name and " +
	    "a command, such as sftp /usr/libexec/sftp-server", default: "none",
	    undo: "Delete", applies: "the global settings" },
	"sshd.keyword": { label: "Keyword", keyword: "Keyword value",
	    definition: "A line whose keyword no tab shows, as written.",
	    values: "a keyword from sshd_config(5)", default: "none",
	    undo: "Delete" },
	"sshd.value": { label: "Value", keyword: "Keyword value",
	    definition: "What follows the line's keyword, as written.",
	    values: "what sshd_config(5) says for the keyword", default: "none",
	    undo: "Delete" },
	"sshd.match": { label: "Match", keyword: "Match criteria",
	    definition: "A section whose lines apply, in place of the global " +
	    "settings, to connections that meet all its criteria, such as " +
	    "User sftp or Address 192.0.2.0/24. It runs to the next Match " +
	    "line.", values: "criteria with their patterns, or All",
	    default: "none", undo: "Delete" },

	/* Network's static routes */
	"route.rtable": { label: "Routing table", kind: "number", min: 0,
	    max: 255, keyword: "rtable table-id", definition: "The routing " +
	    "table the route is in. Table 0 is the default, and its routes " +
	    "are at the top level; another table's are under its rtable line.",
	    default: "0", undo: "Delete" },
	"route.destination": { label: "Destination", keyword: "route " +
	    "destination[/prefixlen | /netmask] gateway [flags]",
	    definition: "The network or host the route is for. Without a " +
	    "prefix length or netmask, it is one host.", values: "an IPv4 " +
	    "address with /prefixlen or /netmask, or an IPv6 address with " +
	    "/prefixlen", default: "none", undo: "Delete" },
	"route.gateway": { label: "Gateway", keyword: "route " +
	    "destination[/prefixlen | /netmask] gateway [flags]",
	    definition: "The address packets for the destination are sent " +
	    "to. A route is not added without one.", values: "an address of " +
	    "the destination's family", default: "none", undo: "Delete" },
	"route.flags": { label: "Flags", keyword: "route " +
	    "destination[/prefixlen | /netmask] gateway [flags]",
	    definition: "blackhole discards packets for the route, and " +
	    "reject rejects them with an ICMP unreachable; iface makes the " +
	    "destination directly reachable; nompath allows no other gateway " +
	    "for it; mtu sets its MTU.", values: "blackhole, cloning, iface, " +
	    "llinfo, nompath, nostatic, proto1, proto2 or reject, separated " +
	    "by spaces, and mtu 64 to 65536", default: "none", undo: "clear " +
	    "the field" }
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
