/*
 * network.js: Network's sections past the interfaces. Switching lists
 * the bridges, the aggregates and the VLANs; HA & tunnels lists CARP,
 * pfsync and the tunnels. Each row is an interface, with what the
 * configuration sets for it, or else what show interface reports, and
 * opens the interface's inspector. Routing tables & routes lists the
 * routing tables and the static routes; a route opens a form in the
 * inspector's place, which stages nsh's route lines. The configuration
 * is the candidate's in configure, else what runs, as the inspector's
 * is.
 */
"use strict";

var netTopic = "ports";	/* the section shown */
var netConf = null;	/* the configuration's text, once read */
var netRoute = null;	/* the route in the form, as read and as edited */

/*
 * A column's value comes from a function of the interface's settings, v,
 * its facts from show interface, r, and its name. This one is the
 * configured value of key, else r's field, if any.
 */
function netEither(key, field) {
	return function (v, r) {
		return v[key] !== "" ? v[key] : r[field] !== undefined ?
		    String(r[field]) : "";
	};
}

function netList(key) {
	return function (v) {
		return v[key].join(" ");
	};
}

function netAddresses(v, r, name) {
	return addresses(name).join(" ");
}

/* name's CARP vhids, as show interface reports them, field f of each */
function netVhids(f) {
	return function (v, r, name) {
		return vhids.filter(function (x) {
			return x.interface === name;
		}).map(function (x) {
			return String(x[f]);
		}).join(" ");
	};
}

/* each section's tables: a title, the drivers it lists, and columns */
var NET_SECTIONS = {
	switching: [
		{ title: "Bridges", drivers: ["bridge", "veb", "tpmr"],
		    cols: [["Members", netList("member")],
		    ["Spanning tree", netList("stp")]] },
		{ title: "Aggregates", drivers: ["trunk", "aggr"],
		    cols: [["Protocol", netEither("trunkproto", "")],
		    ["Ports", function (v, r, name) {
			return v.trunkport.length ? v.trunkport.join(" ") :
			    ifs.filter(function (p) {
				return p["trunk-parent"] === name;
			}).map(function (p) {
				return p.name;
			}).join(" ");
		}]] },
		{ title: "VLANs", drivers: ["vlan", "svlan"],
		    cols: [["Parent", netEither("parent", "parent")],
		    ["VLAN ID", netEither("vnetid", "vnetid")],
		    ["Addresses", netAddresses]] }
	],
	ha: [
		{ title: "CARP", drivers: ["carp"],
		    cols: [["Device", netEither("carpdev", "carp-device")],
		    ["Virtual host ID", function (v, r, name) {
			return v.vhid !== "" ? v.vhid :
			    netVhids("vhid")(v, r, name);
		}],
		    ["State", netVhids("state")],
		    ["Addresses", netAddresses]] },
		{ title: "pfsync", drivers: ["pfsync"],
		    cols: [["Sync device", netEither("syncdev", "")],
		    ["Sync peer", netEither("syncpeer", "")]] },
		{ title: "Tunnels", drivers: ["gre", "egre", "mgre", "nvgre",
		    "eoip", "gif", "etherip", "vxlan", "wg", "mpe", "mpw",
		    "mpip", "pppoe", "ppp", "tun", "tap", "sec"],
		    cols: [["Tunnel", function (v, r) {
			return v.tunnel !== "" ? v.tunnel :
			    r["tunnel-source"] ? r["tunnel-source"] + " " +
			    (r["tunnel-destination"] || "") : "";
		}], ["Parent", netEither("parent", "parent")],
		    ["Addresses", netAddresses]] }
	]
};

/* the configuration read again, and the section drawn */
function netLoad() {
	return ask("GET", "config", { what: cur && cur.mode !== 0 ?
	    "candidate" : "running" }).then(function (j) {
		netConf = said(j);
		netDraw();
	});
}

/*
 * the interfaces with one of drivers: those show interface lists, in
 * its order, then those only the configuration names
 */
function netNames(drivers) {
	var names = ifs.map(function (r) {
		return r.name;
	}).concat(relBlocks(netConf).map(function (b) {
		return b.name;
	}));

	return names.filter(function (n, i) {
		return names.indexOf(n) === i && drivers.indexOf(driver(n)) !==
		    -1;
	});
}

/* name's settings, as the configuration's block for it has them */
function netSettings(name) {
	var b = relBlocks(netConf).find(function (x) {
		return x.name === name;
	}), defs = isBridge(name) ? BRDEFS : IFDEFS;

	return settings(b ? b.lines : [], defs);
}

/* section s's table, a row an interface, each opening its inspector */
function netTable(box, s) {
	var names = netNames(s.drivers), t = el("table", null, "grid pick");
	var head = el("tr");

	box.appendChild(el("h3", s.title));
	if (!names.length) {
		box.appendChild(el("p", "None", "nothing"));
		return;
	}
	["", "Interface"].concat(s.cols.map(function (c) {
		return c[0];
	})).forEach(function (h) {
		head.appendChild(el("th", h));
	});
	t.appendChild(head);
	names.forEach(function (name) {
		var r = ifs.find(function (x) {
			return x.name === name;
		}), v = netSettings(name), led = el("td");
		var tr = el("tr", null, name === selected ? "sel" : "");

		led.appendChild(el("i", null, "led " + (r ? state(r) : "")));
		tr.appendChild(led);
		tr.appendChild(el("td", name, "mono"));
		s.cols.forEach(function (c) {
			tr.appendChild(el("td", c[1](v, r || {}, name),
			    "mono"));
		});
		tr.addEventListener("click", function () {
			selected = name;
			netDraw();
			iftable();
			inspect(name);
		});
		t.appendChild(tr);
	});
	box.appendChild(t);
}

/* the section chosen: the interfaces' table, or the others' tables */
function netDraw() {
	var box = $("net-other");

	$("if-table").hidden = netTopic !== "ports";
	box.hidden = netTopic === "ports";
	if (netTopic === "ports")
		return;
	box.textContent = "";
	if (netConf === null) {
		box.appendChild(el("p", "Reading the configuration", "dim"));
		return;
	}
	if (netTopic === "routes") {
		netRoutesDraw(box);
		return;
	}
	NET_SECTIONS[netTopic].forEach(function (s) {
		netTable(box, s);
	});
}

/*
 * text's static routes: each its routing table, destination, gateway
 * and flags, from the route lines at the top level, which are table
 * 0's, and those in each rtable block
 */
function netRoutes(text) {
	var out = [], rt = null;

	text.split("\n").forEach(function (l) {
		var m = /^rtable (\d+)/.exec(l), r;

		if (m !== null)
			rt = Number(m[1]);
		else if (!/^\s/.test(l))
			rt = null;
		r = /^( ?)route (\S+) (\S+)(.*)$/.exec(l);
		if (r !== null && (r[1] === "") === (rt === null))
			out.push({ rt: rt === null ? 0 : rt, dest: r[2],
			    gate: r[3], flags: r[4].trim() });
	});
	return out;
}

/* text's routing tables: 0, and each rtable line's, with its name */
function netRtables(text) {
	return [{ rt: 0, name: "" }].concat(text.split("\n").map(function (l) {
		var m = /^rtable (\d+)\s*(.*)$/.exec(l);

		return m && { rt: Number(m[1]), name: m[2] };
	}).filter(Boolean));
}

/*
 * a table with head's columns and a row of cells for each of rows; if
 * pick is given, row i is selected if sel(i), and a click picks it
 */
function netGrid(head, rows, sel, pick) {
	var t = el("table", null, "grid" + (pick ? " pick" : ""));
	var tr = el("tr");

	head.forEach(function (h) {
		tr.appendChild(el("th", h));
	});
	t.appendChild(tr);
	rows.forEach(function (r, i) {
		var row = el("tr", null, pick && sel(i) ? "sel" : "");

		r.forEach(function (c, j) {
			row.appendChild(el("td", String(c), j ? "mono" : ""));
		});
		if (pick)
			row.addEventListener("click", function () {
				pick(i);
			});
		t.appendChild(row);
	});
	return t;
}

/*
 * the routing tables, with how many interfaces each has, as show
 * interface reports their routing domains, and how many static routes;
 * then the static routes, each opening its form; and a route added
 */
function netRoutesDraw(box) {
	var routes = netRoutes(netConf);

	box.appendChild(el("h3", "Routing tables"));
	box.appendChild(netGrid(["Table", "Name", "Interfaces",
	    "Static routes"], netRtables(netConf).map(function (t) {
		return [t.rt, t.name, ifs.filter(function (r) {
			return (r.rdomain || 0) === t.rt;
		}).length, routes.filter(function (r) {
			return r.rt === t.rt;
		}).length];
	})));
	box.appendChild(el("h3", "Static routes"));
	if (!routes.length)
		box.appendChild(el("p", "None", "nothing"));
	else
		box.appendChild(netGrid(["Table", "Destination", "Gateway",
		    "Flags"], routes.map(function (r) {
			return [r.rt, r.dest, r.gate, r.flags];
		}), function (i) {
			return netRoute !== null &&
			    JSON.stringify(netRoute.was) ===
			    JSON.stringify(routes[i]);
		}, function (i) {
			netRouteOpen(routes[i]);
		}));
	box.appendChild(edButton("New route", function () {
		netRouteOpen(null);
	}));
}

/* route r in the form, or a new one if r is null */
function netRouteOpen(r) {
	selected = "";
	insp = null;
	iftable();
	netRoute = { was: r, now: Object.assign({ rt: 0, dest: "",
	    gate: "", flags: "" }, r), results: [] };
	netDraw();
	netRouteForm();
}

/* nsh's line for route r, or to remove it */
function netRouteLine(r, no) {
	return (no ? "no " : "") + "route " + r.dest + " " + r.gate +
	    (r.flags && !no ? " " + r.flags : "");
}

/*
 * the lines that make the route in the form what it now is, each in its
 * routing table's context: table 0's at the top level, another's under
 * its rtable line
 */
function netRouteLines() {
	var was = netRoute.was, now = netRoute.now, out = [], last = 0;
	var put = function (rt, line) {
		if (rt !== 0 && rt === last)
			out.splice(out.length - 1, 0, line);
		else
			out = out.concat(rt === 0 ? [line] : ["rtable " + rt,
			    line, "exit"]);
		last = rt;
	};

	if (was && JSON.stringify(was) === JSON.stringify(now))
		return [];
	if (was)
		put(was.rt, netRouteLine(was, true));
	if (now.dest !== "" && now.gate !== "")
		put(now.rt, netRouteLine(now));
	return out;
}

/* an input for the route's key, kept in the form as it is typed */
function netInput(stanza, key, number) {
	var c = el("input", null, "mono"), r = netRoute.now;

	if (number) {
		c.type = "number";
		c.min = 0;
		c.max = 255;
	}
	c.value = r[key];
	c.dataset.key = "route" + key;
	c.addEventListener("input", function () {
		r[key] = number ? Number(c.value) : c.value.trim();
		stanza.textContent = netRouteLines().join("\n");
	});
	return c;
}

/* the route's form, in the inspector's place */
function netRouteForm() {
	var box = $("inspector"), grid = el("div", null, "sfields");
	var stanza = el("pre", null, "term stanza"), bar = el("div", null,
	    "bar");

	box.textContent = "";
	box.appendChild(el("h2", netRoute.was ? "Route" : "New route",
	    "iname"));
	regField(grid, "route.rtable", netInput(stanza, "rt", true));
	regField(grid, "route.destination", netInput(stanza, "dest"));
	regField(grid, "route.gateway", netInput(stanza, "gate"));
	regField(grid, "route.flags", netInput(stanza, "flags"));
	box.appendChild(grid);
	box.appendChild(el("h3", "nsh's lines"));
	stanza.textContent = netRouteLines().join("\n");
	box.appendChild(stanza);
	netRoute.results.forEach(function (x) {
		box.appendChild(el("div", (x.ok ? "✓ " : "✗ ") + x.line +
		    (x.out ? " — " + x.out.trim() : ""), "result " + (x.ok ?
		    "ok" : "bad")));
	});
	if (netRoute.was)
		bar.appendChild(edButton("Delete", function () {
			netRoute.now = Object.assign({}, netRoute.was, {
			    dest: "" });
			netRouteStage();
		}));
	bar.appendChild(edButton("Stage", netRouteStage, "primary"));
	box.appendChild(bar);
}

/*
 * the route's lines into the candidate, entering configure private if
 * not in configure; then the routes again, and the route as it now is
 */
function netRouteStage() {
	var lines = netRouteLines(), results = [], p = Promise.resolve();
	var now = netRoute.now;

	if (!lines.length)
		return p;
	if (!cur || cur.mode === 0)
		p = configure("configure", { mode: "private" },
		    "configure private");
	lines.forEach(function (l) {
		p = p.then(function () {
			return configure("line", { line: l },
			    $("prompt").textContent + " " + l);
		}).then(function (j) {
			if (!/^(rtable \d+|exit)$/.test(l))
				results.push({ line: l, ok: j.ok,
				    out: said(j) });
		});
	});
	return p.then(netLoad).then(function () {
		var r = netRoutes(netConf).find(function (x) {
			return x.rt === now.rt && x.dest === now.dest &&
			    x.gate === now.gate;
		}) || null;

		/* a route deleted leaves an empty form */
		netRoute = { was: r, now: Object.assign({ rt: 0, dest: "",
		    gate: "", flags: "" }, r || (now.dest === "" ? {} : now)),
		    results: results };
		netDraw();
		netRouteForm();
	});
}

$("net-topics").addEventListener("change", function (e) {
	netTopic = e.target.value;
	netConf = null;
	netDraw();
	if (netTopic !== "ports")
		netLoad();
});
