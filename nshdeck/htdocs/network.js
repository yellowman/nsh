/*
 * network.js: Network's sections past the interfaces. Switching lists
 * the bridges, the aggregates and the VLANs; HA & tunnels lists CARP,
 * pfsync and the tunnels. Each row is an interface, with what the
 * configuration sets for it, or else what show interface reports, and
 * opens the interface's inspector. The configuration is the
 * candidate's in configure, else what runs, as the inspector's is.
 */
"use strict";

var netTopic = "ports";	/* the section shown */
var netConf = null;	/* the configuration's text, once read */

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
	NET_SECTIONS[netTopic].forEach(function (s) {
		netTable(box, s);
	});
}

$("net-topics").addEventListener("change", function (e) {
	netTopic = e.target.value;
	netConf = null;
	netDraw();
	if (netTopic !== "ports")
		netLoad();
});
