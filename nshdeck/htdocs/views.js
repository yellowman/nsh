/*
 * views.js: what a show answers, drawn for a person to read. A kind
 * with a view of its own is drawn by it: the system's versions, who is
 * logged in, the host's name. Any other kind is a sheet of its records,
 * each value read by what its field holds (sessions.c's fields): a time
 * as how long ago, a size as KB to TB, a span in days and hours, and
 * each field's name in words
 */
"use strict";

/* a field's name in words, where its parts alone would not say it */
var LABELS = {
	"link-address": "MAC address",
	"hardware-address": "MAC address",
	"rdomain": "Routing domain",
	"rtable": "Routing table",
	"nsh-version": "nsh version",
	"line": "Terminal",
	"expire": "Expires",
	"vnetid": "VNET ID"
};

/* parts of a field's name said in capitals */
var CAPS = ["apn", "carp", "cpu", "dhcp", "icc", "id", "ip", "ipsec",
    "mac", "mtu", "pin", "rssi", "sa", "sim", "ssid", "ttl", "vhid"];

/* a kind's name in words */
var TITLES = {
	"address": "Addresses",
	"arp-entry": "ARP table",
	"bridge": "Bridges",
	"bridge-address": "Learned addresses",
	"bridge-member": "Bridge members",
	"carp-vhid": "CARP",
	"daemon": "Daemons",
	"dhcp-lease": "DHCP leases",
	"dhcp-name-server": "Name servers from DHCP",
	"dhcp-route": "Routes from DHCP",
	"interface": "Interfaces",
	"ip-address": "Addresses",
	"ipsec-flow": "IPsec flows",
	"ndp-entry": "Neighbor cache",
	"route": "Routes",
	"slaac-address-proposal": "Address proposals",
	"slaac-interface": "SLAAC",
	"slaac-name-server": "Name servers from router advertisements",
	"slaac-name-server-proposal": "Name server proposals",
	"slaac-prefix": "Prefixes",
	"slaac-router-advertisement": "Router advertisements",
	"slaac-router-proposal": "Default router proposals",
	"vlan": "VLANs",
	"wg-peer": "WireGuard peers"
};

/* numbers that are a size in bytes, a span, a rate, or yes or no */
var BYTES = ["memory", "input-bytes", "output-bytes"];
var SECONDS = ["lease-time", "lifetime", "preferred-lifetime",
    "router-lifetime", "valid-lifetime"];
var MSECS = ["reachable-time", "retransmit-time"];
var RATES = ["line-rate"];
var YESNO = ["autonomous", "managed", "on-link", "other", "proxy",
    "router", "running", "temporary"];

/* a field's name in words: "input-bytes" is "Input bytes" */
function fieldLabel(name) {
	var w;

	if (LABELS[name] !== undefined)
		return LABELS[name];
	w = name.split("-").map(function (p) {
		return CAPS.indexOf(p) !== -1 ? p.toUpperCase() : p;
	}).join(" ");
	return w.charAt(0).toUpperCase() + w.slice(1);
}

function kindTitle(kind) {
	return TITLES[kind] !== undefined ? TITLES[kind] : fieldLabel(kind);
}

/* n of unit, as words: "1 day", "3 hours" */
function countWords(n, unit) {
	return n + " " + unit + (n === 1 ? "" : "s");
}

/*
 * a span of s seconds, as a person says it: "45 seconds", "19 minutes",
 * "6 hours 4 minutes", "1 day 2 hours"
 */
function spanWords(s) {
	var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600);
	var m = Math.floor(s % 3600 / 60);

	if (d > 0)
		return countWords(d, "day") + (h ? " " + countWords(h,
		    "hour") : "");
	if (h > 0)
		return countWords(h, "hour") + (m ? " " + countWords(m,
		    "minute") : "");
	if (m > 0)
		return countWords(m, "minute");
	return countWords(Math.floor(s), "second");
}

/* time t, in seconds since 1970, as how long ago it was or how soon */
function agoWords(t) {
	var d = Date.now() / 1000 - t;

	if (Math.abs(d) < 60)
		return d >= 0 ? "just now" : "in under a minute";
	return d >= 0 ? spanWords(d) + " ago" : "in " + spanWords(-d);
}

/*
 * time t as this browser's date and time, "Sat 14 Nov, 05:38", and its
 * year if it is not this one
 */
function dateWords(t) {
	var d = new Date(t * 1000);

	return d.toLocaleString(undefined, { weekday: "short",
	    day: "numeric", month: "short", year: d.getFullYear() ===
	    new Date().getFullYear() ? undefined : "numeric",
	    hour: "2-digit", minute: "2-digit" });
}

/* n bytes, as KB to TB, as nsh says them: 1024 to a KB */
function sizeWords(n) {
	var units = ["bytes", "KB", "MB", "GB", "TB"], i = 0;

	while (n >= 1024 && i < units.length - 1) {
		n /= 1024;
		i++;
	}
	return (i === 0 || n >= 100 ? Math.round(n) : n.toFixed(1)) + " " +
	    units[i];
}

/* a time, as how long ago, with its date and time when pointed at */
function agoCell(t) {
	var e = el("span", Number(t) === 0 ? "never" : agoWords(Number(t)),
	    "ago");

	if (Number(t) !== 0)
		e.title = dateWords(Number(t));
	return e;
}

/*
 * field f of record r as an element, read by what it holds, is; or null
 * if r has none
 */
function fieldValue(r, f, is) {
	var v = r[f], e;

	if (v === undefined || v === null || v === "")
		return null;
	if (is === "time")
		return agoCell(v);
	if (Array.isArray(v)) {
		e = el("span", null, "chips");
		v.forEach(function (n) {
			e.appendChild(el("span", n, "chip"));
		});
		return e;
	}
	if (is === "address")
		return el("span", v, "mono");
	if (typeof v === "number") {
		if (BYTES.indexOf(f) !== -1)
			return el("span", sizeWords(v));
		if (SECONDS.indexOf(f) !== -1)
			return el("span", spanWords(v));
		if (MSECS.indexOf(f) !== -1)
			return el("span", v < 1000 ? v + " ms" :
			    spanWords(v / 1000));
		if (RATES.indexOf(f) !== -1)
			return el("span", bps(v));
		if (YESNO.indexOf(f) !== -1)
			return el("span", v ? "yes" : "no", v ? "yes" : "no");
		return el("span", v.toLocaleString(), "mono");
	}
	return el("span", String(v).replace(/\s+$/, ""), "words");
}

/* a sheet: a card with its title, and a count if there is one */
function sheetOf(title, count) {
	var s = el("section", null, "sheet"), h = el("header");

	h.appendChild(el("h3", title));
	if (count !== undefined && count !== null)
		h.appendChild(el("span", String(count), "count"));
	s.appendChild(h);
	return s;
}

/*
 * records of kind, as a sheet: one as a list of its fields, more as a
 * table; fields says what each field holds, in order, where it is known
 */
function drawKind(kind, recs, fields, into) {
	var s = sheetOf(kindTitle(kind), recs.length > 1 ? recs.length :
	    null), names = [], dl, t, tr;

	if (fields)
		names = Object.keys(fields);
	recs.forEach(function (r) {
		Object.keys(r).forEach(function (f) {
			if (f !== "kind" && names.indexOf(f) === -1)
				names.push(f);
		});
	});
	/* a field none of them has is left out */
	names = names.filter(function (f) {
		return recs.some(function (r) {
			return fieldValue(r, f, fields && fields[f]) !== null;
		});
	});
	if (recs.length === 1) {
		dl = el("dl", null, "fields");
		names.forEach(function (f) {
			var dd = el("dd");

			dd.appendChild(fieldValue(recs[0], f, fields &&
			    fields[f]));
			dl.appendChild(el("dt", fieldLabel(f)));
			dl.appendChild(dd);
		});
		s.appendChild(dl);
	} else {
		t = el("table", null, "grid");
		tr = el("tr");
		names.forEach(function (f) {
			tr.appendChild(el("th", fieldLabel(f)));
		});
		t.appendChild(tr);
		recs.forEach(function (r) {
			var row = el("tr");

			names.forEach(function (f) {
				var v = fieldValue(r, f, fields && fields[f]);
				var td = el("td");

				if (v !== null)
					td.appendChild(v);
				if (typeof r[f] === "number" && fields &&
				    fields[f] === "number")
					td.className = "num";
				row.appendChild(td);
			});
			t.appendChild(row);
		});
		s.appendChild(el("div", null, "scroll")).appendChild(t);
	}
	into.appendChild(s);
}

/* a tile of a sheet: its label, its value, and a line under it */
function tileOf(label, value, under) {
	var d = el("div", null, "tile");

	d.appendChild(el("span", label, "label"));
	d.appendChild(el("span", value, "value"));
	if (under)
		d.appendChild(el("span", under, "under"));
	return d;
}

/* the system: what it is, how long it has been up, what it runs on */
function drawVersion(recs, into) {
	var r = recs[0], s, h, tiles, dl, boot = Number(r["boot-time"]);
	var kernel = String(r.kernel || "").trim().split("\n");
	var build = r.compiled + " by " + r["compiled-by"] + "@" +
	    r["compile-host"];

	s = sheetOf([r.system, r.release].join(" ") + " · " + r.machine);
	s.classList.add("system");
	h = s.querySelector("header");
	h.appendChild(el("span", "nsh " + r["nsh-version"], "chip"));
	tiles = el("div", null, "tiles");
	if (boot)
		tiles.appendChild(tileOf("Up", spanWords(Date.now() / 1000 -
		    boot), "since " + dateWords(boot)));
	if (r.memory !== undefined)
		tiles.appendChild(tileOf("Memory", sizeWords(r.memory)));
	if (r.cpu)
		tiles.appendChild(tileOf("CPU", r.cpu)).classList.add("long");
	s.appendChild(tiles);
	dl = el("dl", null, "fields");
	dl.appendChild(el("dt", "Kernel"));
	dl.appendChild(el("dd", kernel[0], "mono"));
	if (kernel.length > 1) {
		dl.appendChild(el("dt", ""));
		dl.appendChild(el("dd", kernel.slice(1).join(" ").trim(),
		    "mono dim"));
	}
	dl.appendChild(el("dt", "nsh"));
	dl.appendChild(el("dd", "Built " + build));
	s.appendChild(dl);
	into.appendChild(s);
}

/* a person's initial on a disc of a colour their name chooses */
function avatarOf(name) {
	var d = el("span", (name || "?").charAt(0).toUpperCase(), "avatar");
	var h = 0, i;

	for (i = 0; i < name.length; i++)
		h = (h * 31 + name.charCodeAt(i)) % 360;
	d.style.setProperty("--hue", h);
	return d;
}

/* who is logged in, the newest login first */
function drawLogins(recs, into) {
	var s = sheetOf("Logged in", recs.length), ul = el("ul", null,
	    "people");

	recs.slice().sort(function (a, b) {
		return Number(b.time) - Number(a.time);
	}).forEach(function (r) {
		var li = el("li"), who = el("div", null, "who");
		var when = el("div", null, "when");

		li.appendChild(avatarOf(r.user || ""));
		who.appendChild(el("b", r.user));
		who.appendChild(el("span", "on " + r.line + (r.host ?
		    " from " + r.host : ""), "meta"));
		li.appendChild(who);
		when.appendChild(agoCell(r.time));
		when.appendChild(el("span", dateWords(Number(r.time)),
		    "meta"));
		li.appendChild(when);
		ul.appendChild(li);
	});
	s.appendChild(ul);
	if (!recs.length)
		s.appendChild(el("p", "Nobody is logged in.", "dim"));
	into.appendChild(s);
}

/* the host's name, large, and its domain lighter */
function drawHostname(recs, into) {
	var s = sheetOf("Host name"), p = el("p", null, "big");
	var n = String(recs[0].name || ""), dot = n.indexOf(".");

	p.appendChild(el("span", dot === -1 ? n : n.slice(0, dot)));
	if (dot !== -1)
		p.appendChild(el("span", n.slice(dot), "dim"));
	s.appendChild(p);
	into.appendChild(s);
}

/* whether field f of record r, a list of names, has name */
function named(r, f, name) {
	return Array.isArray(r[f]) && r[f].indexOf(name) !== -1;
}

/* a mask's length in bits: 24 for 255.255.255.0, 64 for ffff:ffff:ffff:ffff:: */
function maskBits(mask) {
	var bytes = [], halves, groups, i, b, n = 0;

	if (mask.indexOf(".") !== -1)
		bytes = mask.split(".").map(Number);
	else {
		halves = mask.split("::");
		groups = halves[0] ? halves[0].split(":") : [];
		if (halves.length > 1) {
			i = halves[1] ? halves[1].split(":") : [];
			groups = groups.concat(new Array(8 - groups.length -
			    i.length).fill("0"), i);
		}
		groups.forEach(function (g) {
			var v = parseInt(g || "0", 16);

			bytes.push(v >> 8, v & 255);
		});
	}
	for (i = 0; i < bytes.length && bytes[i] === 255; i++)
		n += 8;
	for (b = 128; i < bytes.length && bytes[i] & b; b >>= 1)
		n++;
	return n;
}

/* an address and its mask as a prefix, "10.0.0.0/24", or "default" */
function prefixOf(address, mask) {
	var n;

	if (!mask)
		return address;
	n = maskBits(mask);
	if (n === 0 && /^[0.:]*$/.test(address))
		return "default";
	return address + "/" + n;
}

/* chips, one for each word that is not empty */
function chipsOf(words) {
	var e = el("span", null, "chips");

	words.filter(Boolean).forEach(function (w) {
		e.appendChild(el("span", w, "chip"));
	});
	return e;
}

/* a state as a light and its word: on, warn, or off */
function stateOf(word, light) {
	var e = el("span", null, "state");

	e.appendChild(el("i", null, "led " + light));
	e.appendChild(document.createTextNode(word));
	return e;
}

/*
 * when a neighbor entry expires: in how long, or, with no time, that
 * it is static (STATIC among its flags) or permanent, as arp(8) and
 * ndp(8) say
 */
function expiresOf(r) {
	var e = Number(r.expire || 0), now = Date.now() / 1000, x;

	if (!e)
		return el("span", named(r, "flags", "STATIC") ? "Static" :
		    "Permanent", "dim");
	if (e <= now)
		return el("span", "Expired", "dim");
	x = el("span", "in " + spanWords(Math.ceil(e - now)));
	x.title = dateWords(e);
	return x;
}

/* whether a cell's content shows nothing */
function blank(v) {
	return v === null || v === undefined || v === "" ||
	    (v instanceof Node && v.textContent === "");
}

/*
 * a table of recs: a column for each of cols, its heading and what a
 * record shows there, text or an element, and its cells' class. A
 * column empty in every row but the first column is left out
 */
function tableOf(cols, recs) {
	var t = el("table", null, "grid"), tr = el("tr"), d = el("div",
	    null, "scroll"), rows, keep;

	rows = recs.map(function (r) {
		return cols.map(function (c) {
			return c[1](r);
		});
	});
	keep = cols.map(function (c, i) {
		return i === 0 || rows.some(function (row) {
			return !blank(row[i]);
		});
	});
	cols.forEach(function (c, i) {
		if (keep[i])
			tr.appendChild(el("th", c[0], c[2] === "num" ? "num" :
			    ""));
	});
	t.appendChild(tr);
	rows.forEach(function (cells) {
		var row = el("tr");

		cells.forEach(function (v, i) {
			var td;

			if (!keep[i])
				return;
			td = el("td", null, cols[i][2] || "");
			if (v instanceof Node)
				td.appendChild(v);
			else if (!blank(v))
				td.textContent = v;
			row.appendChild(td);
		});
		t.appendChild(row);
	});
	d.appendChild(t);
	return d;
}

/* a sheet of recs as tableOf() draws them */
function drawTable(title, cols, recs, into) {
	var s = sheetOf(title, recs.length);

	s.appendChild(tableOf(cols, recs));
	into.appendChild(s);
}

/* a neighbor's MAC address, or that it has none yet */
function macOf(r) {
	return r["link-address"] ? r["link-address"] : el("span",
	    "incomplete", "dim");
}

/* the ARP table, as arp(8) reads it */
function drawArp(recs, into) {
	drawTable("ARP table", [
	    ["Address", function (r) { return r.address; }, "mono"],
	    ["MAC address", macOf, "mono"],
	    ["Interface", function (r) { return r.interface; }],
	    ["Expires", expiresOf],
	    ["", function (r) {
		return chipsOf([r.proxy ? "proxy" : "",
		    named(r, "flags", "PROTO2") ? "published" : ""]);
	    }]], recs, into);
}

/* how a neighbor is, as a light: reachable, stale, being checked, gone */
var NDSTATES = { reachable: "on", stale: "", delay: "warn",
    probe: "warn", incomplete: "bad", nostate: "" };

/* the neighbor cache, as ndp(8) reads it */
function drawNdp(recs, into) {
	drawTable("Neighbor cache", [
	    ["Address", function (r) { return r.address; }, "mono"],
	    ["MAC address", macOf, "mono"],
	    ["Interface", function (r) { return r.interface; }],
	    ["State", function (r) {
		return r.state === undefined ? null :
		    stateOf(String(r.state), NDSTATES[r.state] || "");
	    }],
	    ["Expires", expiresOf],
	    ["", function (r) {
		return chipsOf([r.router ? "router" : ""]);
	    }]], recs, into);
}

/* a route's flags that say something of it, in words */
var ROUTEWORDS = { GATEWAY: "", HOST: "host", REJECT: "reject",
    DYNAMIC: "redirect", MODIFIED: "modified", CLONING: "cloning",
    LLINFO: "neighbor", STATIC: "static", PROTO1: "", PROTO2: "",
    UP: "", DONE: "", MASK_PRESENT: "" };

/* a routing table, as route(8) reads it */
function drawRoutes(recs, into) {
	drawTable("Routes", [
	    ["Destination", function (r) {
		/* a host route is its address, as route(8) prints it */
		return named(r, "flags", "HOST") ? r.destination :
		    prefixOf(r.destination, r.netmask);
	    }, "mono"],
	    ["Gateway", function (r) {
		if (r["gateway-name"])
			return el("span", "on " + r["gateway-name"], "dim");
		return r.gateway || "";
	    }, "mono"],
	    ["Interface", function (r) { return r.interface; }],
	    ["", function (r) {
		var w = (r.flags || []).map(function (f) {
			return ROUTEWORDS[f] === undefined ? f.toLowerCase() :
			    ROUTEWORDS[f];
		});

		if (Array.isArray(r.flags) && !named(r, "flags", "UP"))
			w.unshift("down");
		return chipsOf(w);
	    }],
	    ["Priority", function (r) { return r.priority; }, "num"],
	    ["Used", function (r) {
		return r.use === undefined ? "" : r.use.toLocaleString();
	    }, "num"],
	    ["MTU", function (r) { return r.mtu || ""; }, "num"]],
	    recs, into);
}

/* the addresses, as show ip reads them: what configured each */
function drawAddresses(recs, into) {
	drawTable("Addresses", [
	    ["Address", function (r) {
		return prefixOf(r.address, r.netmask);
	    }, "mono"],
	    ["Interface", function (r) { return r.interface; }],
	    ["Configured by", function (r) {
		return r["configured-by"] ? chipsOf([r["configured-by"]]) :
		    null;
	    }],
	    ["Routing domain", function (r) { return r.rdomain || ""; },
	    "num"],
	    ["", function (r) { return chipsOf(r.flags || []); }]],
	    recs.slice().sort(function (a, b) {
		return String(a.interface).localeCompare(b.interface);
	    }), into);
}

/* an interface's state from its flags and link: up, no carrier, down */
function upOf(r) {
	if (!named(r, "flags", "UP"))
		return stateOf("down", "");
	if (r.link && /no carrier|down/.test(r.link))
		return stateOf("no carrier", "warn");
	return stateOf("up", "on");
}

/* the VLANs: each one's tag, its parent and whether it is up */
function drawVlans(recs, into) {
	drawTable("VLANs", [
	    ["VLAN", function (r) { return r.name; }, "mono"],
	    ["Tag", function (r) { return r.vnetid; }, "num"],
	    ["Parent", function (r) { return r.parent || ""; }, "mono"],
	    ["State", upOf],
	    ["Routing domain", function (r) { return r.rdomain || ""; },
	    "num"],
	    ["Description", function (r) { return r.description || ""; }]],
	    recs, into);
}

/*
 * the interfaces: each one's state, link, addresses, MTU and how much
 * it has carried; the addresses are the answer's address records
 */
function drawInterfaces(recs, into, all) {
	var addrs = (all.address || []);

	drawTable("Interfaces", [
	    ["Interface", function (r) { return r.name; }, "mono"],
	    ["State", upOf],
	    ["Link", function (r) { return r.link || ""; }],
	    ["Addresses", function (r) {
		return addrs.filter(function (a) {
			return a.interface === r.name;
		}).map(function (a) {
			return prefixOf(a.address, a.netmask);
		}).join(" ");
	    }, "mono"],
	    ["MTU", function (r) { return r.mtu; }, "num"],
	    ["In", function (r) {
		return r["input-bytes"] === undefined ? "" :
		    sizeWords(r["input-bytes"]);
	    }, "num"],
	    ["Out", function (r) {
		return r["output-bytes"] === undefined ? "" :
		    sizeWords(r["output-bytes"]);
	    }, "num"],
	    ["Errors", function (r) {
		var n = (r["input-errors"] || 0) + (r["output-errors"] || 0);

		return n ? n.toLocaleString() : "";
	    }, "num"],
	    ["Description", function (r) { return r.description || ""; }]],
	    recs, into);
}

/*
 * the bridges: each a sheet of its members, with their spanning-tree
 * state, and the addresses it has learned. A bridge's records come
 * before its own, and name it as their interface
 */
function drawBridges(recs, into, all) {
	recs.forEach(function (b) {
		var s = sheetOf(b.name), mine = function (r) {
			return r.interface === b.name;
		};
		var members = (all["bridge-member"] || []).filter(mine);
		var learned = (all["bridge-address"] || []).filter(mine);

		if (b.description)
			s.querySelector("header").appendChild(el("span",
			    b.description, "count"));
		s.appendChild(el("h4", "Members · " + members.length));
		s.appendChild(tableOf([
		    ["Member", function (r) { return r.name; }, "mono"],
		    ["Spanning tree", function (r) {
			return r["stp-state"] || "";
		    }],
		    ["", function (r) {
			return chipsOf((r.flags || []).map(function (f) {
				return f.toLowerCase();
			}));
		    }]], members));
		s.appendChild(el("h4", "Learned addresses · " +
		    learned.length));
		if (learned.length)
			s.appendChild(tableOf([
			    ["Address", function (r) { return r.address; },
			    "mono"],
			    ["On", function (r) { return r.member; }, "mono"],
			    ["Age", function (r) {
				return r.age === undefined ? "" :
				    spanWords(r.age);
			    }],
			    ["", function (r) {
				return chipsOf((r.flags || []).map(
				    function (f) {
					return f.toLowerCase();
				}));
			    }]], learned));
		into.appendChild(s);
	});
}

/*
 * dhcpleased's leases: each one's address, its server, how long it lasts
 * and when it expires, and the name servers and routes it gave its
 * interface
 */
function drawLeases(recs, into, all) {
	recs.forEach(function (r) {
		var s = sheetOf(r.interface + " · DHCP lease");
		var dl = el("dl", null, "fields"), now = Date.now() / 1000;
		var mine = function (x) {
			return x.interface === r.interface;
		};
		var ns = (all["dhcp-name-server"] || []).filter(mine);
		var routes = (all["dhcp-route"] || []).filter(mine);
		var row = function (label, v) {
			var dd = el("dd");

			if (blank(v))
				return;
			dd.append(v);
			dl.appendChild(el("dt", label));
			dl.appendChild(dd);
		};
		var end = Number(r.requested || 0) + Number(r["lease-time"] ||
		    0);

		if (r.state)
			s.querySelector("header").appendChild(stateOf(r.state,
			    /^bound$/i.test(r.state) ? "on" : "warn"));
		row("Address", r.address ? el("span", prefixOf(r.address,
		    r.netmask), "mono") : null);
		row("Server", r.server ? el("span", r.server, "mono") : null);
		row("Lease", r["lease-time"] === undefined ? null :
		    spanWords(r["lease-time"]) + (!r.requested ? "" : end > now ?
		    ", expires in " + spanWords(Math.ceil(end - now)) :
		    ", expired"));
		row("Name servers", ns.length ? el("span", ns.map(function (x) {
			return x.address;
		}).join(", "), "mono") : null);
		routes.forEach(function (x) {
			row("Route", el("span", prefixOf(x.destination,
			    x.netmask) + " via " + x.gateway, "mono"));
		});
		s.appendChild(dl);
		into.appendChild(s);
	});
}

/* IP protocols, by number, as IPsec flows name them */
var PROTOCOLS = { 0: "any", 1: "icmp", 6: "tcp", 17: "udp", 58: "icmp6" };

/* an IPsec flow's end: its prefix, and its port if it has one */
function flowEnd(r, which) {
	var p = prefixOf(r[which], r[which + "-mask"]);

	return r[which + "-port"] ? p + " port " + r[which + "-port"] : p;
}

/* the IPsec flows, as ipsecctl -sf reads them */
function drawFlows(recs, into) {
	drawTable("IPsec flows", [
	    ["From", function (r) { return flowEnd(r, "source"); }, "mono"],
	    ["To", function (r) { return flowEnd(r, "destination"); },
	    "mono"],
	    ["Protocol", function (r) {
		return PROTOCOLS[r.protocol] !== undefined ?
		    PROTOCOLS[r.protocol] : r.protocol;
	    }],
	    ["Peer", function (r) { return r.peer || ""; }, "mono"],
	    ["", function (r) {
		return chipsOf([r.direction, r["sa-type"], r.type]);
	    }]], recs, into);
}

/*
 * the kinds drawn by a view of their own; one is given the answer's
 * records of every kind too, for those that belong to its own
 */
var DRAWS = {
	version: drawVersion,
	login: drawLogins,
	hostname: drawHostname,
	"arp-entry": drawArp,
	"ndp-entry": drawNdp,
	route: drawRoutes,
	"ip-address": drawAddresses,
	vlan: drawVlans,
	interface: drawInterfaces,
	bridge: drawBridges,
	"dhcp-lease": drawLeases,
	"ipsec-flow": drawFlows
};

/* kinds a view above draws with the kind each names */
var DRAWN_WITH = { address: "interface", "bridge-member": "bridge",
    "bridge-address": "bridge", "dhcp-name-server": "dhcp-lease",
    "dhcp-route": "dhcp-lease" };

/*
 * A show's answer j, drawn into out: what nshd printed as text, each
 * kind of record by its view, or, for any other, as a sheet
 */
function showDrawn(j, out) {
	var kinds = {}, order = [];

	out.textContent = "";
	(j.records || []).forEach(function (r) {
		if (r.kind === "message") {
			out.appendChild(el("pre", r.text, "term"));
			return;
		}
		if (!kinds[r.kind]) {
			kinds[r.kind] = [];
			order.push(r.kind);
		}
		kinds[r.kind].push(r);
	});
	order.forEach(function (k) {
		if (kinds[DRAWN_WITH[k]] !== undefined)
			return;
		if (DRAWS[k] !== undefined)
			DRAWS[k](kinds[k], out, kinds);
		else
			drawKind(k, kinds[k], (j.fields || {})[k], out);
	});
	if (!order.length && !(j.records || []).length && said(j) === "")
		out.appendChild(el("p", "Nothing to show.", "dim"));
}
