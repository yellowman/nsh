/*
 * routeconf.js: reads and edits the configurations of ospfd, ospf6d,
 * eigrpd, ripd, ldpd and dvmrpd for the page, and parses the interface
 * and neighbor tables their ctl programs print. The configurations share
 * bgpd.conf's grammar, so bgpdconf.js parses them; this file knows
 * where each daemon lists its interfaces and which settings the page
 * edits. Nothing here uses the page, so the kit runs it in node.
 */
"use strict";

/*
 * Each routing daemon: its program and ctl program; the blocks its
 * configuration nests; the block paths that hold its interfaces, where
 * an empty path is the top level; the global and interface settings the
 * page edits, each with its control; the interface settings its table
 * shows; the columns of its ctl program's interface and neighbor tables;
 * and the show that lists its routes or labels.
 */
var RT_DAEMONS = {
	ospf: { prog: "ospfd", ctl: "ospfctl", blocks: ["area", "interface"],
	    under: [["area"]],
	    global: [["router-id", "text"], ["fib-update", ["", "yes", "no"]],
	    ["redistribute", "lines"]],
	    iface: [["metric", "text"], ["passive", "check"],
	    ["hello-interval", "text"], ["router-dead-time", "text"],
	    ["router-priority", "text"]],
	    cols: ["metric", "passive"],
	    ifaces: ["Interface", "Address", "State", "HelloTimer",
	    "Linkstate", "Uptime", "nc", "ac"],
	    nbrs: ["ID", "Pri", "State", "DeadTime", "Address", "Iface",
	    "Uptime"], routes: "rib" },
	ospf6: { prog: "ospf6d", ctl: "ospf6ctl", blocks: ["area",
	    "interface"], under: [["area"]],
	    global: [["router-id", "text"], ["fib-update", ["", "yes", "no"]],
	    ["redistribute", "lines"]],
	    iface: [["metric", "text"], ["passive", "check"],
	    ["hello-interval", "text"], ["router-dead-time", "text"],
	    ["router-priority", "text"]],
	    cols: ["metric", "passive"],
	    ifaces: ["Interface", "Address", "State", "HelloTimer",
	    "Linkstate", "Uptime"],
	    nbrs: ["ID", "Pri", "State", "DeadTime", "Iface", "Uptime"],
	    routes: "rib" },
	eigrp: { prog: "eigrpd", ctl: "eigrpctl", blocks: ["address-family",
	    "autonomous-system", "interface"],
	    under: [["address-family", "autonomous-system"]],
	    global: [["router-id", "text"], ["fib-update", ["", "yes", "no"]]],
	    iface: [["bandwidth", "text"], ["delay", "text"],
	    ["hello-interval", "text"], ["holdtime", "text"],
	    ["passive", "check"]],
	    cols: ["bandwidth", "delay", "passive"],
	    ifaces: ["AF", "AS", "Interface", "Address", "Linkstate", "Uptime",
	    "nc"],
	    nbrs: ["AF", "AS", "Address", "Iface", "Holdtime", "Uptime"],
	    routes: "topology" },
	rip: { prog: "ripd", ctl: "ripctl", blocks: ["interface"],
	    under: [[]],
	    global: [["fib-update", ["", "yes", "no"]], ["split-horizon",
	    ["", "simple", "poisoned", "none"]], ["triggered-updates",
	    ["", "yes", "no"]], ["redistribute", "lines"]],
	    iface: [["cost", "text"], ["passive", "check"]],
	    cols: ["cost", "passive"],
	    ifaces: ["Interface", "Address", "State", "Linkstate", "Uptime"],
	    nbrs: ["ID", "State", "Address", "Iface", "Uptime"],
	    routes: "rib" },
	ldp: { prog: "ldpd", ctl: "ldpctl", blocks: ["address-family",
	    "interface", "targeted-neighbor", "neighbor", "l2vpn",
	    "pseudowire"], under: [["address-family"]],
	    global: [["router-id", "text"], ["fib-update", ["", "yes", "no"]]],
	    iface: [["link-hello-holdtime", "text"],
	    ["link-hello-interval", "text"]],
	    cols: ["link-hello-interval"],
	    ifaces: ["AF", "Interface", "State", "Linkstate", "Uptime",
	    "Hello Timers", "ac"],
	    nbrs: ["AF", "ID", "State", "Remote Address", "Uptime"],
	    routes: "lib" },
	dvmrp: { prog: "dvmrpd", ctl: "dvmrpctl", blocks: ["interface",
	    "group"], under: [[], ["group"]],
	    global: [["fib-update", ["", "yes", "no"]]],
	    iface: [["metric", "text"], ["passive", "check"],
	    ["igmp-version", "text"], ["query-interval", "text"]],
	    cols: ["metric", "passive"],
	    ifaces: ["Interface", "Address", "State", "ProbeTimer", "Linkstate",
	    "Uptime", "Groups"],
	    nbrs: ["ID", "State", "DeadTime", "Address", "Interface", "Uptime"],
	    routes: "rib" }
};

/* values the ctl programs print in one column that have a space in them */
var RT_WORDS = ["no carrier", "half duplex", "full duplex", "no network"];

/* a block's short name: area 0.0.0.0, ipv4, AS 1 or group */
function rtPlaceName(n) {
	var w = n.words.slice(0, n.words.indexOf("{"));

	if (w[0] === "address-family")
		return w.slice(1).join(" ");
	if (w[0] === "autonomous-system")
		return "AS " + w.slice(1).join(" ");
	return w.join(" ");
}

/*
 * the places that can hold interfaces: each a chain of blocks from the
 * top, empty for the top level, and its name
 */
function rtPlaces(doc, d) {
	var out = [];
	var walk = function (nodes, path, chain) {
		if (path.length === 0) {
			out.push({ chain: chain, name: chain.map(rtPlaceName).
			    join(", ") });
			return;
		}
		nodes.forEach(function (n) {
			if (n.children && n.words[0] === path[0])
				walk(n.children, path.slice(1),
				    chain.concat([n]));
		});
	};

	d.under.forEach(function (p) {
		walk(doc.nodes, p, []);
	});
	return out;
}

/* the statements a place holds directly */
function rtHeld(doc, chain) {
	return chain.length ? chain[chain.length - 1].children : doc.nodes;
}

/*
 * the interfaces, in order, each with its node, name, place and the
 * settings it sets itself; others lists its other statements
 */
function rtInterfaces(doc, d) {
	var out = [];

	rtPlaces(doc, d).forEach(function (p) {
		rtHeld(doc, p.chain).forEach(function (n) {
			var s = { node: n, name: n.words[1] || "", place: p,
			    other: [] };

			if (n.words[0] !== "interface")
				return;
			(n.children || []).forEach(function (c) {
				var k = d.iface.find(function (f) {
					return f[0] === c.words[0];
				});

				if (!k || c.children)
					s.other.push(c);
				else
					s[k[0]] = k[1] === "check" ? true :
					    bgpRest(c);
			});
			out.push(s);
		});
	});
	return out;
}

/*
 * the value of setting k that interface f takes from the blocks around
 * it, with where it is set, or null: the last statement of k before f,
 * at the top level or in a block that holds f, as the daemons read
 * them. A flag such as passive is only ever the interface's own.
 */
function rtInherited(doc, d, f, k) {
	var names = ["the top level"].concat(f.place.chain.map(rtPlaceName));
	var best = null;

	if (d.iface.some(function (s) {
		return s[0] === k && s[1] === "check";
	}))
		return null;
	[doc.nodes].concat(f.place.chain.map(function (n) {
		return n.children;
	})).forEach(function (list, i) {
		list.forEach(function (c) {
			if (c.words[0] === k && !c.children &&
			    c.start < f.node.start && (!best ||
			    c.start > best.n.start))
				best = { n: c, from: names[i] };
		});
	});
	return best ? { value: bgpRest(best.n), from: best.from } : null;
}

/* the global settings: each the text after its keyword, lines joined */
function rtGlobal(doc, d) {
	var s = {};

	d.global.forEach(function (f) {
		s[f[0]] = doc.nodes.filter(function (n) {
			return n.words[0] === f[0] && !n.children;
		}).map(function (n) {
			return bgpRest(n);
		}).join("\n");
	});
	return s;
}

/* top-level statements that are not global settings, places or macros */
function rtOther(doc, d) {
	return doc.nodes.filter(function (n) {
		return !n.children && n.kind !== "macro" && n.words[0] !==
		    "interface" && !d.global.some(function (f) {
			return f[0] === n.words[0];
		});
	});
}

/*
 * Set global setting k to value: in place of its statements, or before
 * the first block or interface, after any macros; none if value is empty
 */
function rtSetGlobal(doc, k, value) {
	var first = doc.nodes.find(function (n) {
		return n.children || n.words[0] === "interface";
	});

	if (doc.nodes.length === 0)
		return value === "" ? doc : bgpSplice(doc, 0, 0,
		    String(value).split("\n").filter(function (v) {
			return v.trim() !== "";
		}).map(function (v) {
			return k + " " + v.trim() + "\n";
		}));
	return bgpSet(doc, { children: doc.nodes, start: -1, close: first ?
	    bgpLead(doc, first) : doc.lines.length }, k, value);
}

/*
 * Set interface n's setting k to value. An interface written on one
 * line becomes a block to hold it.
 */
function rtSetIface(doc, n, k, value) {
	var ind;

	if (n.children)
		return bgpSet(doc, n, k, value);
	if (value === "" || value === false)
		return doc;
	ind = /^\s*/.exec(doc.lines[n.start])[0];
	doc = bgpSplice(doc, n.start, n.end, [ind + n.code + " {" +
	    (n.comments.length ? " " + n.comments.join(" ") : "") + "\n",
	    ind + "}\n"]);
	return bgpSet(doc, bgpAll(doc.nodes).find(function (x) {
		return x.start === n.start;
	}), k, value);
}

/*
 * Add interface name to the place chain ends at: before the block's
 * closing brace, or at the top level after the last interface
 */
function rtAddIface(doc, chain, name) {
	var n = chain[chain.length - 1], at, ind, last;

	if (!n) {
		last = doc.nodes.filter(function (x) {
			return x.words[0] === "interface";
		}).pop();
		at = last ? last.end : doc.lines.length;
		return bgpSplice(doc, at, at, ["interface " + name + "\n"]);
	}
	if (n.close === n.start) {
		/* a one-line block, split over lines */
		ind = /^\s*/.exec(doc.lines[n.start])[0];
		return bgpSplice(doc, n.start, n.start + 1, [ind +
		    n.words.slice(0, -2).join(" ") + " {\n", ind +
		    "\tinterface " + name + "\n", ind + "}\n"]);
	}
	return bgpSplice(doc, n.close, n.close, [bgpIndent(doc, n) +
	    "interface " + name + "\n"]);
}

/*
 * Parse a table a ctl program printed, whose header starts with cols[0]
 * and cols[1]: one object per row, keyed by column. A value in RT_WORDS
 * counts as one word, and any extra words go to the last column.
 */
function rtTable(text, cols) {
	var lines = text.split("\n"), out = [];
	var at = lines.findIndex(function (l) {
		var w = l.trim().split(/\s+/);

		return w[0] === cols[0] && w[1] === cols[1].split(" ")[0];
	});

	if (at === -1)
		return out;
	lines.slice(at + 1).forEach(function (l) {
		var t = l, w, r = {};

		if (l.trim() === "")
			return;
		RT_WORDS.forEach(function (m) {
			t = t.split(m).join(m.replace(/ /g, "\u001f"));
		});
		w = t.trim().split(/\s+/).map(function (x) {
			return x.replace(/\u001f/g, " ");
		});
		cols.forEach(function (c, j) {
			r[c] = j < cols.length - 1 ? w[j] || "" :
			    w.slice(j).join(" ");
		});
		out.push(r);
	});
	return out;
}
