/*
 * relations.js: typed relations between interfaces. Some come from the
 * configuration: interface and bridge settings, and daemon rules that
 * name an interface. Others come from show interface. Each relation
 * records its sources. Nothing is inferred from names: vlan10 has no
 * parent unless its settings or show interface give one.
 */
"use strict";

/* each relation's wording, as seen from its first end and from its second */
var RELATIONS = {
	"parent-link": ["runs on", "carries"],
	"carp-underlay": ["advertises through", "carries CARP for"],
	"trunk-member": ["is a port of", "has the port"],
	"bridge-member": ["is a member of", "has the member"],
	"tunnel-underlay": ["tunnels from", "carries the tunnel of"],
	"routing-domain-member": ["is in", ""],
	"service-ref": ["names", "is named by"]
};

/* routing daemons whose rules list the interfaces they run on */
var ROUTERS = ["ospf", "ospf6", "rip", "eigrp", "ldp", "dvmrp"];

/* the interface and bridge blocks in a configuration's text */
function relBlocks(text) {
	var out = [], b = null;

	text.split("\n").forEach(function (l) {
		var m = /^(interface|bridge) (\S+)$/.exec(l);

		if (m !== null)
			out.push(b = { name: m[2], bridge: m[1] === "bridge",
			    lines: [] });
		else if (b !== null && /^\s/.test(l))
			b.lines.push(l.trim());
		else
			b = null;
	});
	return out;
}

/* add an edge, or add a source to an existing one */
function relAdd(edges, type, from, to, said, what) {
	var key = [type, from, to, what || ""].join(" "), e = edges.find(
	    function (x) {
		return x.key === key;
	});

	if (!e)
		edges.push({ key: key, type: type, from: from, to: to,
		    what: what || "", said: [said] });
	else if (e.said.indexOf(said) === -1)
		e.said.push(said);
}

/* the interface that has address addr, or addr if none does */
function relOwner(addr) {
	var a = addrs.find(function (x) {
		return x.address === addr;
	});

	return a ? a.interface : addr;
}

/* the edges given by v, the settings of interface or bridge name */
function relSettings(edges, name, bridge, v) {
	var say = function (type, from, to) {
		relAdd(edges, type, from, to, "configured");
	};

	if (v.parent)
		say("parent-link", name, v.parent);
	if (v.carpdev)
		say("carp-underlay", name, v.carpdev);
	(v.trunkport || []).forEach(function (p) {
		say("trunk-member", p, name);
	});
	if (bridge)
		(v.member || []).forEach(function (p) {
			say("bridge-member", p, name);
		});
	if (v.rdomain && v.rdomain !== "0")
		say("routing-domain-member", name, "rdomain " + v.rdomain);
	if (v.tunnel)
		say("tunnel-underlay", name, relOwner(v.tunnel.split(/\s+/)[0]));
}

/* the edges show interface gives */
function relRunning(edges) {
	ifs.forEach(function (r) {
		var say = function (type, from, to) {
			relAdd(edges, type, from, to, "running");
		};

		if (r.parent)
			say("parent-link", r.name, r.parent);
		if (r["carp-device"])
			say("carp-underlay", r.name, r["carp-device"]);
		if (r["trunk-parent"])
			say("trunk-member", r.name, r["trunk-parent"]);
		if (r.rdomain)
			say("routing-domain-member", r.name, "rdomain " + r.rdomain);
		if (r["tunnel-source"])
			say("tunnel-underlay", r.name, relOwner(r["tunnel-source"]));
	});
}

/*
 * The edges daemon rules give: pf rules on an interface, and the
 * interfaces a routing daemon runs on. Only names known() accepts count.
 */
function relRules(edges, text, known) {
	var conf = daemonConf(text);

	Object.keys(conf).forEach(function (k) {
		var name = k.split(" ")[0], rt = Number(k.split(" ")[1]);
		var by = name + (rt ? " in rtable " + rt : "");
		var rules = conf[k].rules;

		if (rules === null)
			return;
		if (name === "pf")
			pfParse(rules.join("\n") + "\n").stmts.forEach(function (s) {
				if (s.kind !== "rule" || !s.rule.on)
					return;
				s.rule.on.split(/[\s{},!]+/).forEach(function (w) {
					if (known(w))
						relAdd(edges, "service-ref", by, w,
						    "configured", s.raw.trim());
				});
			});
		else if (ROUTERS.indexOf(name) !== -1)
			rules.forEach(function (l) {
				var m = /^\s*interface\s+([^\s{]+)/.exec(l);

				if (m !== null && known(m[1]))
					relAdd(edges, "service-ref", by, m[1],
					    "configured", "interface " + m[1]);
			});
	});
}

/*
 * Every edge from text, a configuration, and from show interface. If over
 * is given, its settings replace the lines of that interface or bridge,
 * as an edit would.
 */
function relEdges(text, over) {
	var edges = [], blocks = relBlocks(text), done = false;

	blocks.forEach(function (b) {
		var mine = over && over.name === b.name &&
		    over.bridge === b.bridge;

		relSettings(edges, b.name, b.bridge, mine ? over.v :
		    settings(b.lines, b.bridge ? BRDEFS : IFDEFS));
		done = done || mine;
	});
	if (over && !done)
		relSettings(edges, over.name, over.bridge, over.v);
	relRunning(edges);
	relRules(edges, text, function (name) {
		return relRuns(name) || blocks.some(function (b) {
			return b.name === name;
		});
	});
	return edges;
}

/* true if show interface lists name */
function relRuns(name) {
	return ifs.some(function (r) {
		return r.name === name;
	});
}

/* the edges at name */
function relOf(edges, name) {
	return edges.filter(function (e) {
		return e.from === name || e.to === name;
	});
}

/*
 * Compare the edges after an edit, now, with those before it, was: a
 * configured edge only in now is added by the edit, and one only in was
 * is removed by it.
 */
function relEdited(was, now) {
	var conf = function (list, key) {
		return list.some(function (e) {
			return e.key === key && e.said.indexOf("configured") !== -1;
		});
	};
	var out = now.map(function (e) {
		return Object.assign({}, e, { said: e.said.map(function (s) {
			return s === "configured" && !conf(was, e.key) ?
			    "added by the edit" : s;
		}) });
	});

	was.forEach(function (e) {
		var o;

		if (!conf(was, e.key) || conf(now, e.key))
			return;
		o = out.find(function (x) {
			return x.key === e.key;
		});
		if (o)
			o.said.push("removed by the edit");
		else
			out.push(Object.assign({}, e, { said:
			    ["removed by the edit"] }));
	});
	return out;
}

/*
 * Draw a row for each edge of name's in list: the relation, the other end
 * and the sources. go(other) runs when the other interface is chosen.
 * all holds every edge, and gives a routing domain's other members.
 */
function relRows(into, name, list, all, go) {
	list.forEach(function (e) {
		var out = e.from === name, other = out ? e.to : e.from;
		var row = el("div", null, "rel"), says = el("span", null, "says");

		says.appendChild(document.createTextNode(RELATIONS[e.type][out ?
		    0 : 1] + " "));
		if (e.type === "routing-domain-member" ||
		    e.type === "service-ref")
			says.appendChild(el("span", other, "mono"));
		else
			relLink(says, other, go);
		if (e.type === "routing-domain-member")
			all.filter(function (x) {
				return x.type === e.type && x.to === e.to &&
				    x.from !== name;
			}).map(function (x) {
				return x.from;
			}).filter(function (n, i, a) {
				return a.indexOf(n) === i;
			}).forEach(function (n, i) {
				says.appendChild(document.createTextNode(i ?
				    ", " : ", with "));
				relLink(says, n, go);
			});
		row.appendChild(says);
		if (e.what)
			row.appendChild(el("code", e.what));
		row.appendChild(el("span", e.said.join(", "), "said"));
		into.appendChild(row);
	});
	if (!list.length)
		into.appendChild(el("p", "Nothing", "nothing"));
}

/*
 * Draw the interface at an edge's other end as a link, noting if it is
 * not running; or an address that no interface has.
 */
function relLink(into, name, go) {
	var b;

	if (!relRuns(name) && /^[0-9a-f.:]+$/i.test(name) &&
	    /[.:]/.test(name)) {
		into.appendChild(el("span", name, "mono"));
		into.appendChild(el("span", " (no interface has it)", "dim"));
		return;
	}
	b = el("button", name, "goto");
	b.type = "button";
	b.addEventListener("click", function () {
		go(name);
	});
	into.appendChild(b);
	if (!relRuns(name))
		into.appendChild(el("span", " (not running)", "dim"));
}
