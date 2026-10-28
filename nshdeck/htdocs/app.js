/*
 * nshdeck's page: nshd's answers, as nshdeck gives them, in seven
 * workspaces, the last a terminal (term.js). Requests are forms, sent
 * with X-Nshdeck: 1, which a page of another site cannot send; answers
 * are JSON. Every string nshd sends is put in the page as text, never
 * as HTML.
 */
"use strict";

var stream = null;		/* the event stream, while one is open */
var LOGLINES = 2000;		/* log lines kept on the page, at most */
var ifs = [];			/* show interface's interfaces, the last */
var addrs = [];			/* and their addresses */
var vhids = [];			/* and their CARP vhids */
var selected = "";		/* the interface Network shows chosen */
var reask = null;		/* interfaces asked again, once they settle */
var deadline = 0;		/* when a confirmed commit goes back, or 0 */
var ticker = null;
var comp = null;		/* the input its choices are for */
var cur = null;			/* the user's context, as nshd last gave it */
var LOOK = 5000;		/* how often the Overview looks at traffic, ms */
var looker = null;
var jacks = {};			/* each port's button, by its name */
var packets = {};		/* each port's packets, at the last look */
var chosen = -1;		/* the saved configuration History shows */
var pending = null;		/* the operation that waits to be confirmed */
var pendingOut = null;		/* where what it prints goes */
var errs = [];			/* what nshd refused, the newest first */

/* what each configure mode is */
var MODES = {
	private: "Your own candidate. Other sessions' commits show " +
	    "through it.",
	shared: "One candidate for all shared sessions. Commit commits " +
	    "every session's changes.",
	exclusive: "The shared candidate, locked to you. Exit discards what " +
	    "was not committed.",
	terminal: "No candidate: each line changes the running system at " +
	    "once. Commit saves it."
};

/* what each view shows, and what it says when it has nothing */
var VIEWS = {
	diff: ["What Commit would change: + added, − removed.",
	    "No changes: the candidate is what runs."],
	candidate: ["The whole candidate.", "The candidate is empty."],
	running: ["What runs now.", "Nothing runs."],
	startup: ["What was saved last. The system boots with it.",
	    "No configuration is saved."]
};

/* the operations nshd runs, each a line to start from, and what it does */
var OPS = [
	["flush arp", "Empties the ARP cache."],
	["flush ndp", "Empties the NDP cache."],
	["flush routes", "Clears the routing table."],
	["flush pf ", "Clears pf's rules, states, tables or counters; ? " +
	    "lists which."],
	["flush bridge-dyn ", "Removes the addresses a bridge learned; name " +
	    "the bridge."],
	["bgp reload", "A daemon's action, such as bgp reload."],
	["interface ", "An interface's bssid, setpuk or chgpin, after its " +
	    "name."],
	["diff-config", "Compares the saved configuration with what runs."],
	["crontab", "Lists root's scheduled jobs."],
	["reboot", "Restarts the system; halt stops it, and powerdown turns " +
	    "it off."]
];

/* drivers of interfaces that are not ports of the box */
var PSEUDO = ["lo", "enc", "pflog", "pfsync", "pflow", "carp", "vlan",
    "svlan", "trunk", "aggr", "bridge", "veb", "tpmr", "vport", "vether",
    "pair", "vxlan", "gre", "egre", "mgre", "nvgre", "eoip", "gif",
    "etherip", "wg", "tun", "tap", "mpe", "mpw", "mpip", "pppoe", "ppp",
    "sec", "bpe", "mobileip"];

/* the logical interfaces, by what they are, and what each is on */
var GROUPS = [
	{ name: "VLANs", drivers: ["vlan", "svlan"], rel: function (r) {
		return (r.parent ? "on " + r.parent : "no parent") +
		    (r.vnetid !== undefined ? " · vnetid " + r.vnetid :
		    "");
	} },
	{ name: "Redundancy", drivers: ["carp", "pfsync"], rel: function (r) {
		return r["carp-device"] ? "on " + r["carp-device"] : "";
	} },
	{ name: "Aggregates", drivers: ["trunk", "aggr"], rel: function (r) {
		var m = ifs.filter(function (p) {
			return p["trunk-parent"] === r.name;
		}).map(function (p) {
			return p.name;
		});

		return m.length ? "ports " + m.join(", ") : "no ports";
	} },
	{ name: "Bridges", drivers: ["bridge", "veb", "tpmr"],
	    rel: function () {
		return "";
	} },
	{ name: "Tunnels", drivers: ["gre", "egre", "mgre", "nvgre", "eoip",
	    "gif", "etherip", "vxlan", "wg", "mpe", "mpw", "mpip", "pppoe",
	    "ppp", "tun", "tap", "sec"], rel: function (r) {
		if (r["tunnel-destination"])
			return (r["tunnel-source"] || "") + " → " +
			    r["tunnel-destination"];
		return r.parent ? "on " + r.parent : "";
	} },
	{ name: "Other", drivers: null, rel: function () {
		return "";
	} }
];

function $(id) {
	return document.getElementById(id);
}

/* an element of tag, with text and class, if any */
function el(tag, text, cls) {
	var e = document.createElement(tag);

	if (text !== undefined && text !== null)
		e.textContent = text;
	if (cls)
		e.className = cls;
	return e;
}

/* a request's answer, as JSON; a 401 shows the login again */
function ask(method, name, fields) {
	var body = new URLSearchParams(fields || {});
	var url = "api/" + name;
	var opts = { method: method, credentials: "same-origin",
	    headers: { "X-Nshdeck": "1" } };

	if (method === "GET") {
		if (body.toString() !== "")
			url += "?" + body.toString();
	} else
		opts.body = body;
	return fetch(url, opts).then(function (r) {
		if (r.status === 401 && name !== "login")
			loggedOut();
		return r.json().then(function (j) {
			j.httpStatus = r.status;
			return j;
		});
	});
}

/* what an answer says, as text: what nshd printed, or why it failed */
function said(j) {
	if (j.error !== undefined)
		return "% " + j.error + "\n";
	return j.output || "";
}

/* records of kind */
function of(j, kind) {
	return (j.records || []).filter(function (r) {
		return r.kind === kind;
	});
}

/* where the user is in configure, as nsh's prompt says it */
function where(ctx) {
	var modes = ["", "private", "shared", "exclusive", "terminal"];
	var s;

	if (!ctx || ctx.mode === 0)
		return "";
	s = "configure " + (modes[ctx.mode] || ctx.mode);
	if (ctx.interface)
		s += ", " + (ctx.bridge ? "bridge " : "interface ") +
		    ctx.interface;
	if (ctx.rtable)
		s += ", rtable " + ctx.rtable;
	return s;
}

function context(j) {
	var w, f = $("configure-form");

	if (j.context === undefined)
		return;
	cur = j.context;
	w = where(j.context);
	$("where").textContent = w || "not in configure";
	$("where").classList.toggle("on", w !== "");
	$("prompt").textContent = w ? "nsh(" + w + ")>" : "nsh>";
	changes(j.context.mode !== 0);
	/* the Changes topic, as the session is now */
	if (cur.mode !== 0)
		f.mode.value = ["", "private", "shared", "exclusive",
		    "terminal"][cur.mode];
	$("enter").disabled = cur.mode !== 0;
	$("exit").disabled = cur.mode === 0;
	$("discard").disabled = cur.mode === 0 || cur.mode === 4;
	$("line-form").line.placeholder = cur.mode === 0 ?
	    "Enter configure first" : "";
	$("mode-help").textContent = MODES[f.mode.value];
	loadable();
	if (!$("ws-system").hidden && !$("topic-changes").hidden)
		view();
}

/* System's topic, shown */
function topic(name) {
	$("topics").querySelector("[value=" + name + "]").checked = true;
	["changes", "history", "jobs", "live", "errors"].forEach(function (t) {
		$("topic-" + t).hidden = t !== name;
	});
	if (name === "changes")
		view();
	else if (name === "history")
		saved();
	else if (name === "jobs")
		daemons("system");
}

/* the configuration the View chooses, or why there is none */
function view() {
	var what = $("config-form").what.value;

	$("view-help").textContent = VIEWS[what][0];
	ask("GET", "config", { what: what }).then(function (j) {
		var mode = (j.context || cur || { mode: 0 }).mode;
		var none = !j.ok && mode === 0 && (what === "diff" ||
		    what === "candidate");

		if ($("config-form").what.value !== what)
			return;
		if (what === "diff" && !none)
			diffInto($("config-out"), said(j));
		else
			$("config-out").textContent = none ? "" : said(j);
		$("config-empty").textContent = none ? "There is no candidate " +
		    "until you Enter configure." : VIEWS[what][1];
	});
}

/* a diff's text into pre, a line each, colored by what it does */
function diffInto(pre, text) {
	pre.textContent = "";
	pre.classList.add("diff");
	if (text === "")
		return;
	text.replace(/\n$/, "").split("\n").forEach(function (l) {
		var c = /^(---|\+\+\+) /.test(l) ? "hdr" : l[0] === "+" ? "add" :
		    l[0] === "-" ? "del" : l[0] === "%" ? "msg" : "";

		pre.appendChild(el("span", l || " ", c));
	});
}

/* what saved configuration n changed, under its row, or not again */
function changed(tr, n) {
	var b = tr.querySelector(".twisty"), next = tr.nextSibling, pre;

	if (next !== null && next.classList.contains("changes")) {
		next.remove();
		b.setAttribute("aria-expanded", "false");
		return;
	}
	next = el("tr", null, "changes");
	next.appendChild(el("td"));
	next.firstChild.colSpan = 6;
	pre = next.firstChild.appendChild(el("pre", null, "term"));
	tr.after(next);
	b.setAttribute("aria-expanded", "true");
	ask("GET", "config", { what: "changes", n: n }).then(function (j) {
		diffInto(pre, said(j) || "% No changes from the configuration " +
		    "saved before it\n");
	});
}

/* the saved configurations, as rows: N, generation, when, who, why */
function saved() {
	ask("GET", "config", { what: "rollback" }).then(function (j) {
		var t = $("saved-table"), head = el("tr"), n = 0;

		t.textContent = "";
		["", "", "Generation", "Saved", "By", "Comment"].forEach(
		    function (h) {
			head.appendChild(el("th", h));
		});
		said(j).split("\n").forEach(function (l) {
			var m = /^ *(\d+)  (.*)$/.exec(l), tr, f, g, b;

			if (m === null)
				return;
			f = m[2].split(/ {2,}/);
			g = /^generation (\d+)$/.exec(f[0]);
			if (g !== null)
				f.shift();
			tr = el("tr", null, Number(m[1]) === chosen ?
			    "sel" : "");
			tr.dataset.n = m[1];
			b = el("button", null, "twisty");
			b.type = "button";
			b.setAttribute("aria-expanded", "false");
			b.setAttribute("aria-label", "What " + m[1] + " changed");
			b.addEventListener("click", function (e) {
				e.stopPropagation();
				changed(tr, Number(m[1]));
			});
			tr.appendChild(el("td")).appendChild(b);
			tr.appendChild(el("td", m[1], "num"));
			tr.appendChild(el("td", g !== null ? g[1] : "", "num"));
			tr.appendChild(el("td", f[0], "mono"));
			tr.appendChild(el("td", f[1] || ""));
			tr.appendChild(el("td", f.slice(2).join("  "),
			    "descr"));
			tr.addEventListener("click", function () {
				choose(Number(m[1]), f);
			});
			if (n++ === 0)
				t.appendChild(head);
			t.appendChild(tr);
		});
		$("saved-count").textContent = n ? n + " kept" : "";
		if (j.error !== undefined)
			$("saved-out").textContent = said(j);
	});
}

/* saved configuration n, shown */
function choose(n, f) {
	chosen = n;
	$("saved-table").querySelectorAll("tr").forEach(function (tr) {
		tr.classList.toggle("sel", tr.dataset.n === String(n));
	});
	$("saved-name").textContent = "Saved " + n + " · " + f[0] +
	    (f[1] ? " · " + f[1] : "");
	loadable();
	ask("GET", "config", { what: "rollback", n: n }).then(function (j) {
		if (chosen === n)
			$("saved-out").textContent = said(j);
	});
}

/* whether the configuration chosen can be loaded, and why not */
function loadable() {
	var help = $("load-help"), mode = cur ? cur.mode : 0;

	$("load").disabled = chosen < 1 || mode === 0 || mode === 4;
	if (chosen === 0)
		help.textContent = "This is what was saved last.";
	else if (mode === 0 || mode === 4)
		help.textContent = "To load one, enter configure " +
		    "under Changes.";
	else
		help.textContent = "Load makes it the candidate. Review it " +
		    "under Changes.";
}

/* the operations, as rows that start the line */
function ops() {
	var t = $("op-kinds");

	OPS.forEach(function (o) {
		var tr = el("tr");

		tr.appendChild(el("td", o[0], "mono"));
		tr.appendChild(el("td", o[1], "descr"));
		tr.addEventListener("click", function () {
			$("op-form").line.value = o[0];
			$("op-form").line.focus();
		});
		t.appendChild(tr);
	});
}

/* an operation, run once it is confirmed, what it prints into out */
function operate(line, rtable, out) {
	pending = { line: line, rtable: rtable };
	pendingOut = out;
	$("op-line").textContent = line + (rtable !== "0" ?
	    "\nin routing table " + rtable : "");
	$("op-dialog").showModal();
}

/*
 * how many top-level statements a diff changes: each one added or
 * removed, and each one with a line added or removed under it, where a
 * statement removed and one added just after it with the same first
 * word count once, as one statement changed
 */
function objects(diff) {
	var seen = Object.create(null), n = 0, head = "", last = "";

	diff.split("\n").forEach(function (l) {
		var m = /^([-+ ])(\S.*)$/.exec(l), key;

		if (/^(---|\+\+\+) /.test(l) ||
		    (m === null && !/^[-+] /.test(l)))
			return;
		if (m !== null && m[1] === " ") {
			head = m[2];
			return;
		}
		key = m !== null ? m[2] : head;
		if (m !== null && m[1] === "+" && last !== "" &&
		    last.split(" ")[0] === key.split(" ")[0])
			key = last;
		if (m !== null)
			head = key;
		last = m !== null && m[1] === "-" ? key : "";
		if (!seen[key])
			n++;
		seen[key] = true;
	});
	return n;
}

/* how the candidate differs from what runs, in the strip */
function changes(inConfigure) {
	var tag = $("changes");

	if (!inConfigure) {
		tag.hidden = true;
		$("led-cfg").className = "led";
		return;
	}
	ask("GET", "config", { what: "diff" }).then(function (j) {
		var n = objects(said(j));

		tag.textContent = n === 0 ? "no changes" : n === 1 ?
		    "1 object changed" : n + " objects changed";
		tag.classList.toggle("on", n > 0);
		tag.hidden = false;
		$("led-cfg").className = n > 0 ? "led warn" : "led on";
	});
}

/* a short label for one of system's warnings, the warning its title */
function healthTag(text) {
	var t = el("span", /^The boot failed/.test(text) ? "boot failed" :
	    /did not finish$/.test(text) ? "commit unfinished" :
	    /not saved$|not the saved/.test(text) ? "not saved" :
	    /not rolled back/.test(text) ? "not rolled back" : "warning",
	    "tag warn");

	t.title = text;
	return t;
}

/*
 * what runs, on the strip: its generation, when it was last saved and
 * by whom, and system's warnings, all from the list of what is kept
 */
function runState() {
	ask("GET", "config", { what: "rollback" }).then(function (j) {
		var h = $("health"), f = null;

		h.textContent = "";
		$("run").hidden = j.error !== undefined;
		if (j.error !== undefined)
			return;
		said(j).split("\n").forEach(function (l) {
			var m;

			if ((m = /^% (.*)$/.exec(l)) !== null)
				h.appendChild(healthTag(m[1]));
			else if ((m = /^ *0  (.*)$/.exec(l)) !== null)
				f = m[1].split(/ {2,}/);
		});
		$("gen").hidden = f === null || !/^generation \d+$/.test(f[0]);
		if (!$("gen").hidden)
			$("gen").textContent = f.shift();
		$("last-save").textContent = f === null ? "never saved" :
		    "saved " + f[0].slice(0, 16) + (f[1] ? " by " + f[1] : "");
	});
}

/* the workspace name, shown */
function workspace(name) {
	document.querySelectorAll("#rail button[data-ws]").forEach(
	    function (b) {
		b.classList.toggle("on", b.dataset.ws === name);
	});
	document.querySelectorAll("main > section").forEach(function (s) {
		s.hidden = s.id !== "ws-" + name;
	});
	if (name === "overview" || name === "network")
		interfaces();
	/* the Overview looks again every so often, for its ports' traffic */
	clearInterval(looker);
	looker = name !== "overview" ? null : setInterval(function () {
		if (!document.hidden)
			interfaces();
	}, LOOK);
	if (name === "terminal")
		terminalShown();
	if (name === "routing" || name === "security" || name === "services")
		daemons(name);
	if (name === "system")
		topic($("topics").querySelector(":checked").value);
}

function driver(name) {
	return name.replace(/[0-9]+$/, "");
}

/* is r one of the box's ports */
function physical(r) {
	return PSEUDO.indexOf(driver(r.name)) === -1;
}

function flag(r, f) {
	return Array.isArray(r.flags) && r.flags.indexOf(f) !== -1;
}

/* off: down; warn: up, with no link; on: up, and running */
function state(r) {
	if (!flag(r, "UP"))
		return "off";
	if (!flag(r, "RUNNING") || r.link === "down" ||
	    r.link === "no carrier")
		return "warn";
	return "on";
}

/* a line rate, as a port's label says it */
function rate(r) {
	var b = Number(r["line-rate"] || 0);

	if (b >= 1e9)
		return (b / 1e9) + "G";
	if (b >= 1e6)
		return (b / 1e6) + "M";
	return "";
}

function addresses(name) {
	return addrs.filter(function (a) {
		return a.interface === name;
	}).map(function (a) {
		return a.address;
	});
}

/* show interface, for the Overview and Network */
function interfaces() {
	return ask("GET", "show", { words: "interface" }).then(function (j) {
		ifs = of(j, "interface");
		addrs = of(j, "address");
		vhids = of(j, "carp-vhid");
		faceplate();
		readout();
		logical();
		iftable();
		netDraw();
		if (!$("ws-network").hidden && selected !== "" &&
		    (!insp || insp.name !== selected))
			inspect(selected);
	});
}

/* a port: an RJ45 cage, with its link and activity lights in it */
function port(name) {
	var p = el("button"), jack = el("span", null, "jack");

	p.type = "button";
	jack.appendChild(el("i", null, "led link"));
	jack.appendChild(el("i", null, "led act"));
	p.appendChild(jack);
	p.appendChild(el("span", name, "label"));
	p.appendChild(el("span", null, "rate"));
	p.setAttribute("aria-expanded", "false");
	p.addEventListener("click", function () {
		tray(name);
	});
	return p;
}

/*
 * Open or close a port's tray under the ports. It lists the interfaces on
 * the port and what the port belongs to, from the running configuration
 * and show interface. Choosing the open port again closes it.
 */
function tray(name) {
	var box = $("tray");

	Object.keys(jacks).forEach(function (n) {
		jacks[n].setAttribute("aria-expanded", String(n === name &&
		    box.dataset.port !== name));
	});
	if (box.dataset.port === name) {
		box.dataset.port = "";
		box.hidden = true;
		return Promise.resolve();
	}
	box.dataset.port = name;
	return ask("GET", "config", { what: "running" }).then(function (j) {
		var all = relEdges(said(j)), head = el("div", null, "bar");
		var go = function (n) {
			selected = n;
			workspace("network");
		};
		var on = relOf(all, name).filter(function (e) {
			return e.to === name && (e.type === "parent-link" ||
			    e.type === "carp-underlay");
		});

		if (box.dataset.port !== name)
			return;
		box.textContent = "";
		head.appendChild(el("h3", name));
		head.appendChild(el("span", null, "fill"));
		head.appendChild(el("button", "Inspect")).addEventListener(
		    "click", function () {
			go(name);
		});
		box.appendChild(head);
		box.appendChild(el("h4", "On this port"));
		relRows(box, name, on, all, go);
		box.appendChild(el("h4", "Linked to"));
		relRows(box, name, relOf(all, name).filter(function (e) {
			return on.indexOf(e) === -1;
		}), all, go);
		box.hidden = false;
	});
}

/*
 * the ports, as a box's face shows them, in the kernel's order, a block
 * for each driver; made again only when they are not the same ports, so
 * that a look changes their lights and nothing else. A port's link light
 * is its state; its activity light is on if it counted packets, in or
 * out, since the last look
 */
function faceplate() {
	var ports = $("ports"), blocks = {}, list = ifs.filter(physical);
	var names = list.map(function (r) {
		return r.name;
	}).join(" ");

	if (ports.dataset.names !== names) {
		ports.textContent = "";
		ports.dataset.names = names;
		jacks = {};
		list.forEach(function (r) {
			var d = driver(r.name);

			if (!blocks[d]) {
				blocks[d] = el("div", null, "block");
				blocks[d].appendChild(el("div", null, "row"));
				blocks[d].appendChild(el("span", d, "silk"));
				ports.appendChild(blocks[d]);
			}
			jacks[r.name] = blocks[d].firstChild.appendChild(
			    port(r.name));
		});
	}
	list.forEach(function (r) {
		var p = jacks[r.name], n = Number(r["input-packets"] || 0) +
		    Number(r["output-packets"] || 0);

		p.className = "port " + state(r);
		p.title = r.name + (r.description ? " — " +
		    r.description : "") + "\n" + (r.link || "") +
		    (addresses(r.name).length ? "\n" +
		    addresses(r.name).join("\n") : "");
		p.querySelector(".act").classList.toggle("on",
		    packets[r.name] !== undefined && packets[r.name] !== n);
		p.querySelector(".rate").textContent = rate(r);
		packets[r.name] = n;
	});
}

/* the readout on the box's face: its ports, interfaces and addresses */
function readout() {
	var ports = ifs.filter(physical);
	var v4 = addrs.filter(function (a) {
		return a.address && a.address.indexOf(":") === -1;
	}).length;

	$("r-ports").textContent = ports.filter(function (r) {
		return state(r) === "on";
	}).length + " of " + ports.length + " up";
	$("r-ifs").textContent = ifs.length + ", " + (ifs.length -
	    ports.length) + " logical";
	$("r-addrs").textContent = v4 + " IPv4, " + (addrs.length - v4) +
	    " IPv6";
}

/*
 * the logical interfaces, grouped, each with what it is on; drawn again
 * only when that changed, as the Overview looks often
 */
function logical() {
	var into = $("logical"), seen = {}, groups = [], drawn;

	GROUPS.forEach(function (g) {
		var list = ifs.filter(function (r) {
			var d = driver(r.name);

			if (seen[r.name] || (g.drivers === null ?
			    PSEUDO.indexOf(d) === -1 :
			    g.drivers.indexOf(d) === -1))
				return false;
			seen[r.name] = true;
			return true;
		});

		if (list.length)
			groups.push([g.name, list.map(function (r) {
				return [r.name, state(r), g.rel(r),
				    addresses(r.name)[0] || ""];
			})]);
	});
	drawn = JSON.stringify(groups);
	if (into.dataset.drawn === drawn)
		return;
	into.dataset.drawn = drawn;
	into.textContent = "";
	groups.forEach(function (g) {
		var box = el("div", null, "group"), head = el("h3", g[0]);

		head.appendChild(el("span", String(g[1].length), "count"));
		box.appendChild(head);
		g[1].forEach(function (x) {
			var row = el("button", null, "lif");

			row.type = "button";
			row.appendChild(el("i", null, "led " + x[1]));
			row.appendChild(el("b", x[0]));
			row.appendChild(el("span", x[2], "rel"));
			row.appendChild(el("span", x[3], "addr"));
			row.addEventListener("click", function () {
				selected = x[0];
				workspace("network");
			});
			box.appendChild(row);
		});
		into.appendChild(box);
	});
}

/* the interfaces, a row each, in Network */
function iftable() {
	var t = $("if-table"), head = el("tr");

	t.textContent = "";
	["", "Interface", "Description", "Link", "Addresses", "MTU",
	    "rdomain", "Type"].forEach(function (h) {
		head.appendChild(el("th", h));
	});
	t.appendChild(head);
	ifs.forEach(function (r) {
		var tr = el("tr", null, r.name === selected ? "sel" : "");
		var led = el("td"), type = el("td", r.type || "", "type");

		led.appendChild(el("i", null, "led " + state(r)));
		tr.appendChild(led);
		tr.appendChild(el("td", r.name, "mono"));
		tr.appendChild(el("td", r.description || "", "descr"));
		tr.appendChild(el("td", r.link || ""));
		tr.appendChild(el("td", addresses(r.name).join(" "), "mono"));
		tr.appendChild(el("td", r.mtu !== undefined ? r.mtu : "",
		    "num"));
		tr.appendChild(el("td", r.rdomain !== undefined ? r.rdomain :
		    "", "num"));
		/* short: the whole of it in its title */
		type.title = r.type || "";
		tr.appendChild(type);
		tr.addEventListener("click", function () {
			selected = r.name;
			iftable();
			inspect(r.name);
		});
		t.appendChild(tr);
	});
	$("net-count").textContent = ifs.length + " interfaces";
}

/* records, a table for each kind, a column for each field any has */
function tables(records, into) {
	var kinds = {}, order = [];

	into.textContent = "";
	records.forEach(function (r) {
		if (r.kind === "message") {
			into.appendChild(el("pre", r.text, "term"));
			return;
		}
		if (!kinds[r.kind]) {
			kinds[r.kind] = [];
			order.push(r.kind);
		}
		kinds[r.kind].push(r);
	});
	order.forEach(function (k) {
		var cols = [], table = el("table", null, "grid"),
		    tr = el("tr");

		kinds[k].forEach(function (r) {
			Object.keys(r).forEach(function (c) {
				if (c !== "kind" && cols.indexOf(c) === -1)
					cols.push(c);
			});
		});
		into.appendChild(el("h3", k + " · " + kinds[k].length));
		cols.forEach(function (c) {
			tr.appendChild(el("th", c));
		});
		table.appendChild(tr);
		kinds[k].forEach(function (r) {
			var row = el("tr");

			cols.forEach(function (c) {
				var v = r[c];

				row.appendChild(el("td", v === undefined ? "" :
				    Array.isArray(v) ? v.join(" ") : String(v)));
			});
			table.appendChild(row);
		});
		into.appendChild(table);
	});
}

function show(words, out) {
	return ask("GET", "show", { words: words }).then(function (j) {
		tables(j.records || [], out);
		if (said(j) !== "")
			out.appendChild(el("pre", said(j), "term"));
	});
}

/* a workspace's shows: its presets, and a line of nsh's show */
function shows(div) {
	var bar = el("div", null, "bar"), form = el("form", null, "cliline");
	var input = el("input", null, "cli"), out = el("div", null, "out");

	bar.appendChild(el("h2", "Show"));
	div.dataset.presets.split("|").forEach(function (w) {
		var b = el("button", w, "preset");

		b.type = "button";
		b.addEventListener("click", function () {
			input.value = w;
			show(w, out);
		});
		bar.appendChild(b);
	});
	form.appendChild(el("span", "show>"));
	input.dataset.prefix = "show ";
	input.setAttribute("aria-label", "Show what");
	input.autocomplete = "off";
	input.spellcheck = false;
	input.placeholder = "Tab completes, ? lists";
	form.appendChild(input);
	form.addEventListener("submit", function (e) {
		e.preventDefault();
		closeChoices();
		show(input.value, out);
	});
	div.appendChild(bar);
	div.appendChild(form);
	div.appendChild(out);
}

/*
 * Tab: the input's line completed by nshdeck, in the user's mode; ? or
 * a Tab nshdeck cannot complete: its choices, under the input
 */
function complete(input, help) {
	var line = (input.dataset.prefix || "") + input.value;

	return ask("GET", "complete", { line: line, help: help ? 1 : 0 }).then(
	    function (j) {
		var ins = of(j, "insert"), choices = of(j, "choice");

		if (ins.length) {
			input.value += ins[0].text;
			closeChoices();
		} else if (choices.length)
			openChoices(input, choices);
		else {
			closeChoices();
			input.classList.add("nope");
			setTimeout(function () {
				input.classList.remove("nope");
			}, 300);
		}
	});
}

function openChoices(input, choices) {
	var box = $("choices"), r = input.getBoundingClientRect();

	box.textContent = "";
	choices.forEach(function (c) {
		var hint = /^[<\[]/.test(c.word);
		var row = el("div", null, "choice" + (hint ? " hint" : ""));

		row.setAttribute("role", "option");
		row.appendChild(el("span", c.word, "w"));
		row.appendChild(el("span", c.help || "", "h"));
		if (!hint)
			row.addEventListener("mousedown", function (e) {
				e.preventDefault();
				pick(input, c.word);
			});
		box.appendChild(row);
	});
	box.style.left = Math.round(r.left + window.scrollX) + "px";
	box.style.top = Math.round(r.bottom + window.scrollY + 2) + "px";
	box.style.minWidth = Math.round(r.width) + "px";
	box.hidden = false;
	comp = input;
}

function closeChoices() {
	$("choices").hidden = true;
	comp = null;
}

/* a choice, in place of the word the input ends with */
function pick(input, word) {
	var v = input.value;

	input.value = v.slice(0, v.lastIndexOf(" ") + 1) + word + " ";
	closeChoices();
	input.focus();
}

/* the choice the arrows move to, by d */
function move(d) {
	var rows = Array.prototype.slice.call(
	    document.querySelectorAll("#choices .choice:not(.hint)"));
	var i = rows.findIndex(function (r) {
		return r.classList.contains("sel");
	});

	if (rows.length === 0)
		return;
	if (i !== -1)
		rows[i].classList.remove("sel");
	i = (i + d + rows.length) % rows.length;
	rows[i].classList.add("sel");
	rows[i].scrollIntoView({ block: "nearest" });
}

function keys(e) {
	var t = e.target, sel;

	if (!t.classList || !t.classList.contains("cli"))
		return;
	if (e.key === "Tab" && !e.shiftKey) {
		e.preventDefault();
		complete(t, false);
	} else if (e.key === "?") {
		e.preventDefault();
		complete(t, true);
	} else if (comp === t && (e.key === "ArrowDown" ||
	    e.key === "ArrowUp")) {
		e.preventDefault();
		move(e.key === "ArrowDown" ? 1 : -1);
	} else if (comp === t && e.key === "Enter" &&
	    (sel = document.querySelector("#choices .sel")) !== null) {
		e.preventDefault();
		pick(t, sel.querySelector(".w").textContent);
	} else if (e.key === "Escape")
		closeChoices();
}

/* to the transcript: what was asked, and what nshd said */
function transcript(asked, j) {
	var t = $("transcript");

	t.textContent += asked + "\n" + said(j);
	t.scrollTop = t.scrollHeight;
	context(j);
	refused(asked, j);
}

/*
 * request asked, answered j, kept for the Errors topic if nshd refused
 * it, with when and in which workspace; the same request succeeding
 * takes its error away, and a commit or rollback that succeeds takes
 * them all, as the candidate they were about is gone
 */
function refused(asked, j) {
	var on = document.querySelector("#rail button.on");

	errs = errs.filter(function (e) {
		return e.what !== asked;
	});
	if (j.ok && /^(commit|rollback)\b/.test(asked) &&
	    asked !== "commit check")
		errs = [];
	else if (!j.ok)
		errs.unshift({ when: new Date().toTimeString().slice(0, 8),
		    ws: on ? on.dataset.ws : "", where: on ? on.title : "",
		    what: asked, said: said(j).trim() });
	errs = errs.slice(0, 100);
	errors();
}

/* the errors, in the strip and the Errors topic */
function errors() {
	var t = $("errors-table"), head = el("tr");

	$("errors").hidden = !errs.length;
	$("errors").textContent = errs.length === 1 ? "1 error" :
	    errs.length ? errs.length + " errors" : "";
	$("errors-count").textContent = errs.length ? String(errs.length) :
	    "";
	t.textContent = "";
	if (!errs.length)
		return;
	["When", "Where", "Request", "What nshd said"].forEach(function (h) {
		head.appendChild(el("th", h));
	});
	t.appendChild(head);
	errs.forEach(function (e) {
		var tr = el("tr");

		tr.appendChild(el("td", e.when, "mono"));
		tr.appendChild(el("td", e.where));
		tr.appendChild(el("td", e.what, "mono"));
		tr.appendChild(el("td", e.said, "descr"));
		tr.addEventListener("click", function () {
			if (e.ws)
				workspace(e.ws);
		});
		t.appendChild(tr);
	});
}

function configure(name, fields, asked) {
	return ask("POST", name, fields).then(function (j) {
		transcript(asked, j);
		return j;
	});
}

/* a confirmed commit's deadline, counted down in the strip */
function confirmBy(minutes) {
	var tag = $("deadline");

	clearInterval(ticker);
	deadline = minutes ? Date.now() + minutes * 60000 : 0;
	tag.hidden = !deadline;
	$("led-cnf").className = deadline ? "led warn blink" : "led";
	if (!deadline)
		return;
	ticker = setInterval(function () {
		var s = Math.max(0, Math.round((deadline - Date.now()) / 1000));

		tag.textContent = "confirm within " + Math.floor(s / 60) + ":" +
		    String(s % 60).padStart(2, "0");
		if (s === 0)
			confirmBy(0);
	}, 1000);
}

/* the event stream, following the logs checked */
function follow() {
	var logs = [];

	document.querySelectorAll("#events-form input:checked").forEach(
	    function (c) {
		logs.push(c.value);
	});
	if (stream)
		stream.close();
	stream = new EventSource("api/events" + (logs.length ?
	    "?logs=" + logs.join(",") : ""));
	stream.onopen = function () {
		$("live").className = $("led-sys").className = "led on";
	};
	stream.onerror = function () {
		$("live").className = $("led-sys").className = "led warn";
	};
	stream.addEventListener("notice", function (e) {
		noticed(JSON.parse(e.data));
	});
	stream.addEventListener("refused", function (e) {
		noticed({ kind: "refused", text: JSON.parse(e.data).text });
	});
	/* this page fell behind, and some events went: what it shows, again */
	stream.addEventListener("dropped", function () {
		$("log").textContent += "[some lines were dropped]\n";
		noticed({ kind: "dropped", text: "some events were dropped" });
		interfaces();
	});
	stream.addEventListener("log", function (e) {
		var d = JSON.parse(e.data), log = $("log");
		var lines = (log.textContent + d.text).split("\n");

		if (lines.length > LOGLINES)
			lines = lines.slice(lines.length - LOGLINES);
		log.textContent = lines.join("\n");
		log.scrollTop = log.scrollHeight;
	});
}

function noticed(d) {
	var li = el("li"), list = $("notices");
	var when = new Date().toTimeString().slice(0, 8);
	var text = when + " " + d.kind;
	var whose = ["commit", "confirmed", "applied", "lock", "unlock"];

	if (whose.indexOf(d.kind) !== -1)
		text += " by uid " + d.uid;
	if (d.kind === "confirmed")
		text += ", " + d.n + " minutes";
	if (d.text)
		text += ": " + d.text.trim();
	li.textContent = text;
	list.insertBefore(li, list.firstChild);
	while (list.children.length > 200)
		list.removeChild(list.lastChild);
	if (d.kind === "confirmed")
		confirmBy(d.n);
	else if (d.kind === "commit" || d.kind === "back")
		confirmBy(0);
	if ((d.kind === "commit" || d.kind === "back") &&
	    !$("topic-history").hidden)
		saved();
	if (["commit", "confirmed", "applied", "back"].indexOf(d.kind) !== -1)
		runState();
	if (whose.indexOf(d.kind) !== -1 && d.kind !== "lock" &&
	    d.kind !== "unlock") {
		$("r-last").textContent = d.kind + " " + when + ", uid " +
		    d.uid;
	}
	/* interfaces or routes changed: asked again once they settle */
	if ((d.kind === "links" || d.kind === "routes") && !document.hidden &&
	    (!$("ws-overview").hidden || !$("ws-network").hidden)) {
		clearTimeout(reask);
		reask = setTimeout(interfaces, 1000);
	}
}

/* the host's name and version, on the strip and the plate */
function host() {
	ask("GET", "show", { words: "hostname" }).then(function (j) {
		var h = of(j, "hostname");

		if (h.length) {
			$("hostname").textContent = h[0].name;
			$("plate-host").textContent = h[0].name;
		}
	});
	ask("GET", "show", { words: "version" }).then(function (j) {
		var m = of(j, "message");

		$("plate-ver").textContent = j.ok && m.length ?
		    m[0].text.split("\n")[0] : "";
	});
}

function loggedIn(j) {
	$("who").textContent = j.user + " · " + j.perms.join(" ");
	$("login").hidden = true;
	$("deck").hidden = false;
	follow();
	host();
	runState();
	workspace("overview");
}

/*
 * Show the login form. Once someone has logged in, reload the page
 * instead, so that nothing the last user saw remains.
 */
function loggedOut() {
	if (!$("deck").hidden)
		location.reload();
	else
		$("login").hidden = false;
}

/* a form's submit, as fn of its fields, without leaving the page */
function on(id, fn) {
	$(id).addEventListener("submit", function (e) {
		e.preventDefault();
		closeChoices();
		fn(e.target);
	});
}

document.addEventListener("DOMContentLoaded", function () {
	on("login", function (f) {
		ask("POST", "login", { user: f.user.value,
		    password: f.password.value }).then(function (j) {
			f.password.value = "";
			if (j.httpStatus !== 200) {
				$("login-error").textContent = j.error;
				return;
			}
			$("login-error").textContent = "";
			loggedIn(j);
		});
	});
	$("logout").addEventListener("click", function () {
		ask("POST", "logout").then(loggedOut);
	});
	document.querySelectorAll("#rail button[data-ws]").forEach(
	    function (b) {
		b.addEventListener("click", function () {
			workspace(b.dataset.ws);
		});
	});
	document.querySelectorAll(".shows").forEach(shows);
	document.querySelectorAll(".daemons").forEach(daemonsBox);
	ops();
	$("topics").addEventListener("change", function (e) {
		topic(e.target.value);
	});
	document.addEventListener("keydown", keys);
	document.addEventListener("input", function (e) {
		if (e.target === comp)
			closeChoices();
	});
	document.addEventListener("mousedown", function (e) {
		if (!$("choices").contains(e.target))
			closeChoices();
	});
	$("compare").addEventListener("click", function () {
		$("config-form").what.value = "diff";
		$("topics").querySelector("[value=changes]").checked = true;
		workspace("system");
	});
	$("validate").addEventListener("click", function () {
		$("topics").querySelector("[value=changes]").checked = true;
		workspace("system");
		configure("commit", { check: "1" }, "commit check");
	});
	$("commit").addEventListener("click", function () {
		$("commit-dialog").showModal();
	});
	$("commit-cancel").addEventListener("click", function () {
		$("commit-dialog").close();
	});
	on("commit-form", function (f) {
		var fields = {}, asked = "commit";

		if (f.confirmed.checked) {
			fields.minutes = f.minutes.value;
			asked += " confirmed " + f.minutes.value;
		}
		if (f.comment.value !== "") {
			fields.comment = f.comment.value;
			asked += " comment " + f.comment.value;
		}
		$("commit-dialog").close();
		configure("commit", fields, asked);
	});
	/* a configuration chosen is shown */
	$("config-form").addEventListener("change", view);
	$("configure-form").addEventListener("change", function (e) {
		$("mode-help").textContent = MODES[e.target.value];
	});
	$("mode-help").textContent = MODES.private;
	on("configure-form", function (f) {
		configure("configure", { mode: f.mode.value },
		    "configure " + f.mode.value);
	});
	$("errors").addEventListener("click", function () {
		workspace("system");
		topic("errors");
	});
	$("errors-clear").addEventListener("click", function () {
		errs = [];
		errors();
	});
	$("discard").addEventListener("click", function () {
		configure("rollback", { n: "0" }, "rollback");
	});
	$("exit").addEventListener("click", function () {
		configure("exit", {}, "exit");
	});
	on("line-form", function (f) {
		var line = f.line.value;

		configure("line", { line: line }, $("prompt").textContent +
		    " " + line).then(function (j) {
			if (j.ok)
				f.line.value = "";
		});
	});
	$("load").addEventListener("click", function () {
		var n = chosen;

		topic("changes");
		configure("rollback", { n: n }, "rollback " + n);
	});
	/* an operation runs once it is confirmed */
	on("op-form", function (f) {
		operate(f.line.value, f.rtable.value, $("op-out"));
	});
	$("op-cancel").addEventListener("click", function () {
		$("op-dialog").close();
	});
	on("op-confirm", function () {
		$("op-dialog").close();
		ask("POST", "op", pending).then(function (j) {
			var out = pendingOut;

			out.textContent = "";
			(j.records || []).forEach(function (r) {
				out.textContent += r.text !== undefined ?
				    r.text : JSON.stringify(r) + "\n";
			});
			out.textContent += said(j);
		});
	});
	on("events-form", follow);

	/* logged in already, if the cookie still says so */
	ask("GET", "whoami").then(function (j) {
		if (j.httpStatus === 200)
			loggedIn(j);
		else
			loggedOut();
	});
});
