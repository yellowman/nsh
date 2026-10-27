/*
 * services.js: the Security and Services daemons whose configurations
 * share bgpd.conf's grammar, as editors.js shows them: each daemon's
 * statement kinds, which stmtconf.js reads and edits, and its tabs. A
 * tab holds settings that appear once, or lists statements of some
 * kinds, one row each, or both; or shows what a show prints. A block's
 * kind names the kinds of the statements in it. A kind's warn, given a
 * statement read, says what makes it risky, if anything. Each field's
 * help is the registry entry svReg() names. Nothing here uses the page,
 * so the kit runs it in node.
 */
"use strict";

/* a weight or trusted, as ntpd.conf's sources share them */
var SV_NTP_SOURCE = [{ key: "trusted", flag: true }, { key: "weight" }];

/* a value of yes or no */
var SV_YESNO = ["yes", "no"];

/* rad.conf's settings, global or an interface's */
var SV_RAD_RA = ["defrouter", "managed", "otherconf", "rtlifetime",
    "rtpref", "hoplimit", "mtu", "lladdr", "reachable", "retrans"];

/* the options of relayd.conf's forward and route lines, in their order */
var SV_RELAY_FWD = [{ key: "port" }, { key: "mode", upto: true, raw: true },
    { key: "check", upto: true, raw: true }, { key: "timeout" },
    { key: "interval" }, { key: "demote" }, { key: "retry" },
    { key: "inet", flag: true }, { key: "inet6", raw: true },
    { key: "proxy", kw: ["proxy-protocol"], choices: ["v1", "v2"] },
    { key: "interface" }];

/* a relayd.conf line that forwards, from its words */
function svRelayFwd(id, kw) {
	return { id: id, kw: kw, args: [{ key: "to", raw: true }],
	    opts: SV_RELAY_FWD, fixed: true };
}

/* a relayd.conf line whose words after its own are one value */
function svRelayRest(id, kw) {
	return { id: id, kw: kw, args: [{ key: id, rest: true, raw: true }] };
}

/* the options of an snmpd.conf listen on line, in their order */
var SV_SNMP_LISTEN = [{ key: "port" }, { key: "read", flag: true },
    { key: "write", flag: true }, { key: "notify", flag: true },
    { key: "snmpv1", flag: true }, { key: "snmpv2c", flag: true },
    { key: "snmpv3", flag: true }];

/* an snmpd.conf listen on line, from its words */
function svSnmpListen(id, kw) {
	return { id: id, kw: kw, args: [{ key: "address" }],
	    opts: SV_SNMP_LISTEN, fixed: true, warn: function (s) {
		return s.v.write ? "accepts writes" : "";
	} };
}

/* an snmpd.conf community, which appears once */
function svSnmpCommunity(id, kw, warn) {
	return { id: id, kw: kw, args: [{ key: "community", secret: true }],
	    warn: warn };
}

/* an address only this host reaches, or a Unix socket's path */
var SV_LOCAL = /^(lo[0-9]*|127\.0\.0\.1|::1|localhost|\/.*)$/;

/*
 * a statement no other kind of its block matches, shown as written: a
 * kind with no words of its own matches any statement, the least well
 */
var SV_OTHER = { id: "other", kw: [], args: [{ key: "line", rest: true,
    raw: true }] };

/* an npppd.conf setting of yes or no */
function svYesNo(id, kw) {
	return { id: id, kw: [kw], args: [{ key: "value",
	    choices: SV_YESNO }] };
}

/* an npppd.conf setting of one value */
function svOne(id, kw, key) {
	return { id: id, kw: [kw], args: [{ key: key }] };
}

/* the statements of an npppd.conf RADIUS server */
var SV_NPPP_RADIUS = ["radaddress", "radtimeout", "radtries",
    "radfailovers"];

/* the statements a namespace or the top of ldapd.conf share */
var SV_LDAP_ACI = ["allow", "deny"];

/* the statements in a relayd.conf protocol */
var SV_RELAY_RULES = ["tlsopts", "tcpopts", "httpopts", "returnerror",
    "pass", "block", "match"];

var SV_DAEMONS = {
	ntp: { prog: "ntpd", blocks: [],
	    kinds: [
		{ id: "server", kw: ["server"], args: [{ key: "address" }],
		    opts: SV_NTP_SOURCE },
		{ id: "servers", kw: ["servers"], args: [{ key: "address" }],
		    opts: SV_NTP_SOURCE },
		{ id: "sensor", kw: ["sensor"], args: [{ key: "device" }],
		    opts: [{ key: "correction" }, { key: "refid" },
		    { key: "stratum" }].concat(SV_NTP_SOURCE) },
		{ id: "constraint", kw: ["constraint", "from"],
		    args: [{ key: "url" }], list: { key: "addresses" } },
		{ id: "constraints", kw: ["constraints", "from"],
		    args: [{ key: "url" }] },
		{ id: "listen", kw: ["listen", "on"],
		    args: [{ key: "address" }], opts: [{ key: "rtable" }] },
		{ id: "query", kw: ["query", "from"],
		    args: [{ key: "address" }] }
	    ],
	    tabs: [
		{ id: "sources", label: "Sources", kinds: ["server", "servers",
		    "sensor"], cols: ["weight", "trusted"] },
		{ id: "constraints", label: "Constraints",
		    kinds: ["constraint", "constraints"], cols: ["addresses"] },
		{ id: "listen", label: "Listening", kinds: ["listen", "query"],
		    cols: ["rtable"] }
	    ] },
	sasync: { prog: "sasyncd", blocks: [],
	    kinds: [
		{ id: "interface", kw: ["interface"],
		    args: [{ key: "interface" }] },
		{ id: "group", kw: ["group"], args: [{ key: "group" }] },
		{ id: "mode", kw: ["mode"], args: [{ key: "mode",
		    choices: ["master", "slave", "skipslave"] }] },
		{ id: "peer", kw: ["peer"], args: [{ key: "address" }] },
		{ id: "listen", kw: ["listen", "on"],
		    args: [{ key: "address" }], fixed: true,
		    opts: [{ key: "family", words: ["inet", "inet6"] },
		    { key: "port" }] },
		{ id: "sharedkey", kw: ["sharedkey"], args: [{ key: "key",
		    secret: true }] },
		{ id: "flushmode", kw: ["flushmode"], args: [{ key: "flushmode",
		    choices: ["sync", "startup", "never"] }] },
		{ id: "control", kw: ["control"], args: [{ key: "control",
		    choices: ["isakmpd", "iked", "all", "none"] }] }
	    ],
	    tabs: [
		{ id: "carp", label: "CARP", single: ["interface", "group",
		    "mode"] },
		{ id: "peers", label: "Peers", kinds: ["peer", "listen"],
		    cols: ["family", "port"] },
		{ id: "sync", label: "Synchronization", single: ["sharedkey",
		    "flushmode", "control"] }
	    ] },
	rad: { prog: "rad", blocks: ["interface", "prefix", "auto", "nat64",
	    "dns"],
	    kinds: [
		{ id: "interface", kw: ["interface"], args: [{ key: "name" }],
		    block: "maybe", inner: ["prefix", "autoprefix",
		    "noautoprefix", "dns"].concat(SV_RAD_RA) },
		{ id: "prefix", kw: ["prefix"], args: [{ key: "prefix",
		    raw: true }], block: "maybe", inner: ["autonomous",
		    "onlink", "pltime", "vltime"] },
		{ id: "autoprefix", kw: ["auto", "prefix"], block: "maybe",
		    inner: ["autonomous", "onlink", "pltime", "vltime"] },
		{ id: "noautoprefix", kw: ["no", "auto", "prefix"] },
		{ id: "autonomous", kw: ["autonomous", "address-configuration"],
		    args: [{ key: "value", choices: SV_YESNO }] },
		{ id: "onlink", kw: ["on-link"], args: [{ key: "value",
		    choices: SV_YESNO }] },
		{ id: "pltime", kw: ["preferred", "lifetime"],
		    args: [{ key: "seconds" }] },
		{ id: "vltime", kw: ["valid", "lifetime"],
		    args: [{ key: "seconds" }] },
		{ id: "dns", kw: ["dns"], block: true, inner: ["lifetime",
		    "nameserver", "search"] },
		{ id: "nameserver", kw: ["nameserver"],
		    args: [{ key: "addresses", group: true }] },
		{ id: "search", kw: ["search"], args: [{ key: "domains",
		    group: true }] },
		{ id: "lifetime", kw: ["lifetime"],
		    args: [{ key: "seconds" }] },
		{ id: "nat64", kw: ["nat64", "prefix"], args: [{ key: "prefix",
		    raw: true }], block: "maybe", inner: ["lifetime"] },
		{ id: "defrouter", kw: ["default", "router"],
		    args: [{ key: "value", choices: SV_YESNO }] },
		{ id: "managed", kw: ["managed", "address", "configuration"],
		    args: [{ key: "value", choices: SV_YESNO }] },
		{ id: "otherconf", kw: ["other", "configuration"],
		    args: [{ key: "value", choices: SV_YESNO }] },
		{ id: "rtlifetime", kw: ["router", "lifetime"],
		    args: [{ key: "seconds" }] },
		{ id: "rtpref", kw: ["router", "preference"],
		    args: [{ key: "value", choices: ["high", "medium",
		    "low"] }] },
		{ id: "hoplimit", kw: ["hop", "limit"],
		    args: [{ key: "hops" }] },
		{ id: "mtu", kw: ["mtu"], args: [{ key: "bytes" }] },
		{ id: "lladdr", kw: ["source", "link-layer", "address"],
		    args: [{ key: "value", choices: SV_YESNO }] },
		{ id: "reachable", kw: ["reachable", "time"],
		    args: [{ key: "ms" }] },
		{ id: "retrans", kw: ["retrans", "timer"],
		    args: [{ key: "ms" }] }
	    ],
	    tabs: [
		{ id: "interfaces", label: "Interfaces", kinds: ["interface"] },
		{ id: "global", label: "Global", single: SV_RAD_RA },
		{ id: "dns", label: "DNS", kinds: ["dns"] },
		{ id: "nat64", label: "NAT64", kinds: ["nat64"] }
	    ] },
	relay: { prog: "relayd", blocks: ["relay", "redirect", "protocol",
	    "http", "tcp", "dns", "router"],
	    kinds: [
		{ id: "relay", kw: ["relay"], args: [{ key: "name" }],
		    block: true, inner: ["listen", "forward", "forwardtls",
		    "transparent", "transparenttls", "useproto", "session"],
		    innerCols: ["port", "check"] },
		{ id: "redirect", kw: ["redirect"], args: [{ key: "name" }],
		    block: true, inner: ["listen", "forward", "routeto",
		    "disable", "sticky", "pftag", "matchpftag", "session"],
		    innerCols: ["port", "check"] },
		{ id: "listen", kw: ["listen", "on"],
		    args: [{ key: "address" }], fixed: true,
		    opts: [{ key: "transport", words: ["tcp", "udp"] },
		    { key: "port" }, { key: "tls", flag: true },
		    { key: "interface" }, { key: "pflog", flag: true }] },
		svRelayFwd("forward", ["forward", "to"]),
		svRelayFwd("forwardtls", ["forward", "with", "tls", "to"]),
		svRelayFwd("transparent", ["transparent", "forward", "to"]),
		svRelayFwd("transparenttls", ["transparent", "forward", "with",
		    "tls", "to"]),
		svRelayFwd("routeto", ["route", "to"]),
		{ id: "useproto", kw: ["protocol"],
		    args: [{ key: "protocol" }] },
		{ id: "session", kw: ["session", "timeout"],
		    args: [{ key: "seconds" }] },
		{ id: "disable", kw: ["disable"] },
		{ id: "sticky", kw: ["sticky-address"] },
		{ id: "pftag", kw: ["pftag"], args: [{ key: "tag" }] },
		{ id: "matchpftag", kw: ["match", "pftag"],
		    args: [{ key: "tag" }] },
		{ id: "table", kw: ["table"], args: [{ key: "name",
		    angle: true }], opts: [{ key: "disable", flag: true },
		    { key: "hosts", brace: true, group: true, raw: true,
		    joins: ["retry", "parent", "priority", "ip", "ttl"] }] },
		{ id: "proto", kw: ["protocol"], args: [{ key: "name" }],
		    block: "maybe", inner: SV_RELAY_RULES },
		{ id: "httpproto", kw: ["http", "protocol"],
		    args: [{ key: "name" }], block: "maybe",
		    inner: SV_RELAY_RULES },
		{ id: "tcpproto", kw: ["tcp", "protocol"],
		    args: [{ key: "name" }], block: "maybe",
		    inner: SV_RELAY_RULES },
		{ id: "dnsproto", kw: ["dns", "protocol"],
		    args: [{ key: "name" }], block: "maybe",
		    inner: SV_RELAY_RULES },
		svRelayRest("tlsopts", ["tls"]),
		svRelayRest("tcpopts", ["tcp"]),
		svRelayRest("httpopts", ["http"]),
		svRelayRest("returnerror", ["return", "error"]),
		svRelayRest("pass", ["pass"]),
		svRelayRest("block", ["block"]),
		svRelayRest("match", ["match"]),
		{ id: "router", kw: ["router"], args: [{ key: "name" }],
		    block: true, inner: ["route", "forward", "rtable",
		    "rtlabel", "disable"], innerCols: ["port", "check"] },
		{ id: "route", kw: ["route"], args: [{ key: "prefix",
		    raw: true }] },
		{ id: "rtable", kw: ["rtable"], args: [{ key: "id" }] },
		{ id: "rtlabel", kw: ["rtlabel"], args: [{ key: "label" }] },
		{ id: "interval", kw: ["interval"],
		    args: [{ key: "seconds" }] },
		{ id: "timeout", kw: ["timeout"], args: [{ key: "ms" }] },
		{ id: "prefork", kw: ["prefork"],
		    args: [{ key: "processes" }] },
		{ id: "loglevel", kw: ["log", "level"], args: [{ key: "level",
		    choices: ["brief", "verbose"] }] },
		{ id: "logstate", kw: ["log", "state", "changes"] },
		{ id: "logchecks", kw: ["log", "host", "checks"] },
		{ id: "logconn", kw: ["log", "connection"] },
		{ id: "logerrors", kw: ["log", "connection", "errors"] },
		{ id: "agentx", kw: ["agentx"] },
		{ id: "socket", kw: ["socket"], args: [{ key: "path" }] }
	    ],
	    tabs: [
		{ id: "relays", label: "Relays", kinds: ["relay"] },
		{ id: "redirects", label: "Redirections", kinds: ["redirect"] },
		{ id: "tables", label: "Tables", kinds: ["table"],
		    cols: ["hosts"] },
		{ id: "protocols", label: "Protocols", kinds: ["proto",
		    "httpproto", "tcpproto", "dnsproto"] },
		{ id: "routers", label: "Routers", kinds: ["router"] },
		{ id: "global", label: "Global", single: ["interval", "timeout",
		    "prefork", "loglevel", "logstate", "logchecks", "logconn",
		    "logerrors", "agentx", "socket"] },
		{ id: "hosts", label: "Hosts", show: "relay hosts" }
	    ] },
	snmp: { prog: "snmpd", blocks: [],
	    kinds: [
		svSnmpListen("listen", ["listen", "on"]),
		svSnmpListen("listenudp", ["listen", "on", "udp"]),
		svSnmpListen("listentcp", ["listen", "on", "tcp"]),
		svSnmpCommunity("rocommunity", ["read-only", "community"],
		    function (s) {
			return s.v.community === "public" ? "well known" : "";
		}),
		svSnmpCommunity("rwcommunity", ["read-write", "community"],
		    function () {
			return "anyone who knows it can write";
		}),
		svSnmpCommunity("trapcommunity", ["trap", "community"]),
		{ id: "seclevel", kw: ["seclevel"], args: [{ key: "level",
		    choices: ["none", "auth", "enc"] }], warn: function (s) {
			return s.v.level === "none" ? "accepts unsigned " +
			    "messages" : "";
		} },
		{ id: "user", kw: ["user"], args: [{ key: "name" }],
		    opts: [{ key: "auth", choices: ["hmac-md5", "hmac-sha1",
		    "hmac-sha224", "hmac-sha256", "hmac-sha384",
		    "hmac-sha512"] }, { key: "authkey", secret: true },
		    { key: "enc", choices: ["des", "aes"] },
		    { key: "enckey", secret: true }], warn: function (s) {
			return s.v.authkey ? "" : "no authentication";
		} },
		{ id: "trapreceiver", kw: ["trap", "receiver"],
		    args: [{ key: "address" }], fixed: true,
		    opts: [{ key: "oid" }, { key: "version", words: ["snmpv2c",
		    "snmpv3"] }, { key: "community", secret: true },
		    { key: "user" }, { key: "seclevel" },
		    { key: "srcaddr", kw: ["source-address"] }] },
		{ id: "traphandle", kw: ["trap", "handle"],
		    args: [{ key: "oid" }, { key: "command" }],
		    warn: function () {
			return "runs a command";
		} },
		{ id: "syscontact", kw: ["system", "contact"],
		    args: [{ key: "contact" }] },
		{ id: "sysdescr", kw: ["system", "description"],
		    args: [{ key: "description" }] },
		{ id: "syslocation", kw: ["system", "location"],
		    args: [{ key: "location" }] },
		{ id: "sysname", kw: ["system", "name"],
		    args: [{ key: "name" }] },
		{ id: "sysoid", kw: ["system", "oid"], args: [{ key: "oid" }] },
		{ id: "sysservices", kw: ["system", "services"],
		    args: [{ key: "services" }] },
		{ id: "engineid", kw: ["engineid"], args: [{ key: "format",
		    rest: true, raw: true }] },
		{ id: "filterroutes", kw: ["filter-routes"],
		    args: [{ key: "value", choices: ["yes", "no"] }] },
		{ id: "object", kw: ["oid"], args: [{ key: "oid" }],
		    fixed: true, opts: [{ key: "name" }, { key: "access",
		    words: ["read-only", "read-write"] }, { key: "integer" },
		    { key: "string" }] },
		{ id: "blocklist", kw: ["blocklist"], args: [{ key: "oid" }] },
		{ id: "mibdir", kw: ["mib", "directory"],
		    args: [{ key: "path" }] },
		{ id: "agentx", kw: ["agentx"], opts: [{ key: "path" },
		    { key: "owner" }, { key: "group" }, { key: "mode" }] }
	    ],
	    tabs: [
		{ id: "listeners", label: "Listeners", kinds: ["listen",
		    "listenudp", "listentcp"], cols: ["port", "read", "write",
		    "notify"] },
		{ id: "access", label: "Access", single: ["rocommunity",
		    "rwcommunity", "seclevel"], kinds: ["user"],
		    cols: ["auth", "enc"] },
		{ id: "traps", label: "Traps", single: ["trapcommunity"],
		    kinds: ["trapreceiver", "traphandle"], cols: ["version",
		    "community"] },
		{ id: "system", label: "System", single: ["syscontact",
		    "sysdescr", "syslocation", "sysname", "sysoid",
		    "sysservices", "engineid", "filterroutes"] },
		{ id: "advanced", label: "Advanced", kinds: ["object",
		    "blocklist", "mibdir", "agentx"] }
	    ] },
	ldap: { prog: "ldapd", blocks: ["namespace"],
	    kinds: [
		{ id: "listen", kw: ["listen", "on"],
		    args: [{ key: "address" }], fixed: true,
		    opts: [{ key: "port" }, { key: "legacy",
		    flag: true }, { key: "tls", words: ["tls", "ldaps",
		    "secure"] }, { key: "certificate" }], warn: function (s) {
			return s.v.tls || SV_LOCAL.test(s.v.address) ? "" :
			    "not encrypted";
		} },
		{ id: "namespace", kw: ["namespace"], args: [{ key: "suffix" }],
		    block: true, inner: ["rootdn", "rootpw", "index",
		    "cachesize", "indexcachesize", "fsync", "relax", "strict",
		    "compression", "referral"].concat(SV_LDAP_ACI) },
		{ id: "rootdn", kw: ["rootdn"], args: [{ key: "dn" }] },
		{ id: "rootpw", kw: ["rootpw"], args: [{ key: "password",
		    secret: true }] },
		{ id: "referral", kw: ["referral"], args: [{ key: "url" }] },
		{ id: "index", kw: ["index"], args: [{ key: "attribute" }] },
		{ id: "cachesize", kw: ["cache-size"],
		    args: [{ key: "bytes" }] },
		{ id: "indexcachesize", kw: ["index-cache-size"],
		    args: [{ key: "bytes" }] },
		{ id: "fsync", kw: ["fsync"], args: [{ key: "value",
		    choices: ["on", "off"] }] },
		{ id: "relax", kw: ["relax", "schema"] },
		{ id: "strict", kw: ["strict", "schema"] },
		{ id: "compression", kw: ["use", "compression"],
		    opts: [{ key: "level" }] },
		{ id: "allow", kw: ["allow"], args: [{ key: "allow", rest: true,
		    raw: true }] },
		{ id: "deny", kw: ["deny"], args: [{ key: "deny", rest: true,
		    raw: true }] },
		{ id: "schema", kw: ["schema"], args: [{ key: "path" }] }
	    ],
	    tabs: [
		{ id: "listeners", label: "Listeners", kinds: ["listen"],
		    cols: ["port", "tls"] },
		{ id: "namespaces", label: "Namespaces", kinds: ["namespace"] },
		{ id: "access", label: "Access", single: ["rootdn", "rootpw"],
		    kinds: SV_LDAP_ACI },
		{ id: "schemas", label: "Schemas", kinds: ["schema",
		    "referral"] },
		{ id: "stats", label: "Statistics", show: "ldap stats" }
	    ] },
	nppp: { prog: "npppd", blocks: ["tunnel", "ipcp", "authentication",
	    "authentication-server", "accounting-server"],
	    kinds: [
		{ id: "tunnel", kw: ["tunnel"], args: [{ key: "name" }],
		    opts: [{ key: "protocol", choices: ["l2tp", "pptp",
		    "pppoe"] }], block: "maybe", inner: ["listen", "listenif",
		    "mru", "lcpkeepalive", "authmethod", "chapname", "mppe",
		    "idletimeout", "tcpmss", "ingress", "pipex", "l2tpipsec",
		    "pppoeservice", "pppoeac", "other"],
		    innerCols: ["port"] },
		{ id: "listen", kw: ["listen", "on"],
		    args: [{ key: "address" }], opts: [{ key: "port" }] },
		{ id: "listenif", kw: ["listen", "on", "interface"],
		    args: [{ key: "interface" }] },
		svOne("mru", "mru", "bytes"),
		svYesNo("lcpkeepalive", "lcp-keepalive"),
		{ id: "authmethod", kw: ["authentication-method"],
		    args: [{ key: "methods", rest: true, raw: true }],
		    warn: function (s) {
			return /(^| )pap( |$)/.test(s.v.methods) ? "PAP " +
			    "sends passwords in the clear" : "";
		} },
		svOne("chapname", "chap-name", "name"),
		{ id: "mppe", kw: ["mppe"], args: [{ key: "value",
		    choices: ["yes", "no", "required"] }] },
		svOne("idletimeout", "idle-timeout", "seconds"),
		svYesNo("tcpmss", "tcp-mss-adjust"),
		svYesNo("ingress", "ingress-filter"),
		svYesNo("pipex", "pipex"),
		svYesNo("l2tpipsec", "l2tp-require-ipsec"),
		svOne("pppoeservice", "pppoe-service-name", "name"),
		svOne("pppoeac", "pppoe-ac-name", "name"),
		SV_OTHER,
		{ id: "ipcp", kw: ["ipcp"], args: [{ key: "name" }],
		    block: true, inner: ["pool", "dns", "nbns", "userselected",
		    "ipcpmax"] },
		{ id: "pool", kw: ["pool-address"], args: [{ key: "range",
		    raw: true }], opts: [{ key: "pooltype", kw: ["for"],
		    choices: ["dynamic", "static"] }] },
		{ id: "dns", kw: ["dns-servers"], args: [{ key: "servers",
		    rest: true, raw: true }] },
		{ id: "nbns", kw: ["nbns-servers"], args: [{ key: "servers",
		    rest: true, raw: true }] },
		svYesNo("userselected", "allow-user-selected-address"),
		svOne("ipcpmax", "max-session", "sessions"),
		{ id: "interface", kw: ["interface"], args: [{ key: "name" }],
		    fixed: true, opts: [{ key: "address" }, { key: "useipcp",
		    kw: ["ipcp"] }] },
		{ id: "authentication", kw: ["authentication"],
		    args: [{ key: "name" }], opts: [{ key: "type",
		    choices: ["local", "radius"] }], block: true,
		    inner: ["suffix", "stripnt", "stripat", "usersfile",
		    "usermax", "authserver", "acctserver"] },
		svOne("suffix", "username-suffix", "suffix"),
		svYesNo("stripnt", "strip-nt-domain"),
		svYesNo("stripat", "strip-atmark-realm"),
		svOne("usersfile", "users-file", "path"),
		svOne("usermax", "user-max-session", "sessions"),
		{ id: "authserver", kw: ["authentication-server"], block: true,
		    inner: SV_NPPP_RADIUS },
		{ id: "acctserver", kw: ["accounting-server"], block: true,
		    inner: SV_NPPP_RADIUS },
		{ id: "radaddress", kw: ["address"], args: [{ key: "address" }],
		    fixed: true, opts: [{ key: "port" }, { key: "secret",
		    secret: true }] },
		svOne("radtimeout", "timeout", "seconds"),
		svOne("radtries", "max-tries", "tries"),
		svOne("radfailovers", "max-failovers", "failovers"),
		{ id: "bind", kw: ["bind", "tunnel", "from"],
		    args: [{ key: "tunnel" }], fixed: true,
		    opts: [{ key: "auth", kw: ["authenticated", "by"] },
		    { key: "to" }] },
		{ id: "nasid", kw: ["radius", "nas-id"],
		    args: [{ key: "id" }] },
		{ id: "daelisten", kw: ["radius", "dae", "listen", "on"],
		    args: [{ key: "address" }], opts: [{ key: "port" }] },
		{ id: "daeclient", kw: ["radius", "dae", "client"],
		    args: [{ key: "address" }], opts: [{ key: "secret",
		    secret: true }] },
		{ id: "maxsession", kw: ["set", "max-session"],
		    args: [{ key: "sessions" }] },
		{ id: "usermaxsession", kw: ["set", "user-max-session"],
		    args: [{ key: "sessions" }] }
	    ],
	    tabs: [
		{ id: "tunnels", label: "Tunnels", kinds: ["tunnel"],
		    cols: ["protocol"] },
		{ id: "addresses", label: "Addresses", kinds: ["ipcp",
		    "interface"], cols: ["address", "useipcp"] },
		{ id: "auth", label: "Authentication", kinds: ["authentication",
		    "bind"], cols: ["type", "auth", "to"] },
		{ id: "radius", label: "RADIUS", single: ["nasid"],
		    kinds: ["daelisten", "daeclient"], cols: ["port",
		    "secret"] },
		{ id: "global", label: "Global", single: ["maxsession",
		    "usermaxsession"] }
	    ] }
};

/* daemon d's kinds of the given ids, in their order */
function svKinds(d, ids) {
	return ids.map(function (id) {
		return d.kinds.find(function (k) {
			return k.id === id;
		});
	});
}

/* the ids of the kinds of tab t: its settings, then its list */
function svTab(t) {
	return (t.single || []).concat(t.kinds || []);
}

/* daemon d's kinds at the top level: those of its tabs */
function svTop(d) {
	return svKinds(d, [].concat.apply([], d.tabs.map(svTab)));
}

/*
 * The statements of the given kinds in block p, or at the top level,
 * each read as the kind that matches it best among all those there
 */
function svList(doc, d, p, kinds) {
	return stList(p ? p.children || [] : doc.nodes, p ? kinds :
	    svTop(d)).filter(function (s) {
		return kinds.indexOf(s.kind) !== -1;
	});
}

/*
 * The registry entry of field key of kind k of daemon name: a kind's
 * first argument is the statement itself; any other field is the
 * daemon's, so kinds that share an option share its entry
 */
function svReg(name, k, key) {
	if (!key || (k.args || []).length && k.args[0].key === key)
		return name + "." + k.id;
	return name + "." + key;
}

/*
 * each registry entry daemon name's editor draws, for the kinds of its
 * tabs and the kinds in their blocks
 */
function svFields(name) {
	var d = SV_DAEMONS[name], out = [], seen = [];
	var add = function (id) {
		if (out.indexOf(id) === -1)
			out.push(id);
	};
	var walk = function (kinds) {
		kinds.forEach(function (k) {
			if (seen.indexOf(k) !== -1)
				return;
			seen.push(k);
			add(svReg(name, k));
			(k.args || []).concat(k.opts || [], k.list ?
			    [k.list] : []).forEach(function (f) {
				add(svReg(name, k, f.key));
			});
			walk(svKinds(d, k.inner || []));
		});
	};

	d.tabs.forEach(function (t) {
		walk(svKinds(d, svTab(t)));
	});
	return out;
}
