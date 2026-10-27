/*
 * services.js: the Security and Services daemons whose configurations
 * share bgpd.conf's grammar, as editors.js shows them: each daemon's
 * statement kinds, which stmtconf.js reads and edits, and its tabs. A
 * tab lists statements of some kinds, one row each; or holds settings
 * that appear once; or shows what a show prints. A block's kind names
 * the kinds of the statements in it. Each field's help is the registry
 * entry svReg() names. Nothing here uses the page, so the kit runs it in
 * node.
 */
"use strict";

/* a weight or trusted, as ntpd.conf's sources share them */
var SV_NTP_SOURCE = [{ key: "trusted", flag: true }, { key: "weight" }];

/* a value of yes or no */
var SV_YESNO = ["yes", "no"];

/* rad.conf's settings, global or an interface's */
var SV_RAD_RA = ["defrouter", "managed", "otherconf", "rtlifetime",
    "rtpref", "hoplimit", "mtu", "lladdr", "reachable", "retrans"];

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
		walk(svKinds(d, t.kinds || t.single || []));
	});
	return out;
}
