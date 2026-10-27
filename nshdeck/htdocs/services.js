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

/* each registry entry daemon name's editor draws */
function svFields(name) {
	var d = SV_DAEMONS[name], out = [];
	var add = function (id) {
		if (out.indexOf(id) === -1)
			out.push(id);
	};

	d.tabs.forEach(function (t) {
		svKinds(d, t.kinds || t.single || []).forEach(function (k) {
			add(svReg(name, k));
			(k.args || []).concat(k.opts || [], k.list ?
			    [k.list] : []).forEach(function (f) {
				add(svReg(name, k, f.key));
			});
		});
	});
	return out;
}
