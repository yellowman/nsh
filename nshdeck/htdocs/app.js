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
var ifs = [];			/* interfaces from the last show interface */
var addrs = [];			/* and their addresses */
var vhids = [];			/* and their CARP vhids */
var selected = "";		/* interface selected in Network */
var reask = null;		/* interfaces asked again, once they settle */
var deadline = 0;		/* unconfirmed commit's rollback time, or 0 */
var ticker = null;
var comp = null;		/* input whose choices are shown, or null */
var cur = null;			/* the user's context, as nshd last gave it */
var hostname = "nsh";		/* the host's name, for the prompt */
var LOOK = 5000;		/* how often the Overview looks at traffic, ms */
var looker = null;
var jacks = {};			/* each port's button, by its name */
var packets = {};		/* each port's packets, at the last look */
var chosen = -1;		/* the saved configuration History shows */
var pending = null;		/* the operation that waits to be confirmed */
var pendingOut = null;		/* where its output goes */
var errs = [];			/* what nshd refused, the newest first */
/*
 * The routing table the page is focused on, as nsh's rtable N, or null
 * for every table: the page then shows that table's (inTable()). This
 * tab keeps it for its next page, until the user logs out
 */
var table = null;

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

/* operations nshd runs: the start of a line, and a description */
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

/* nsh's prompt for the context, as cprompt() and iprompt() make it */
function nshprompt(ctx) {
	var modes = ["", "config-private", "config", "config-exclusive",
	    "config-terminal"];
	var conf = ctx && ctx.mode !== 0, m;

	if (conf && ctx.interface)
		return hostname + "(" + (ctx.bridge ? "bridge-" :
		    "interface-") + ctx.interface + ")# ";
	m = conf ? modes[ctx.mode] || "config" : "";
	if (ctx && ctx.rtable)
		m += (m ? "-" : "") + "rtable " + ctx.rtable;
	return hostname + (m ? "(" + m + ")" : "") + (conf ? "# " : "> ");
}

function context(j) {
	var f = $("configure-form");

	if (j.context === undefined)
		return;
	cur = j.context;
	$("prompt").textContent = nshprompt(cur);
	changes(j.context.mode !== 0);
	/* the Changes topic, as the session is now */
	if (cur.mode !== 0)
		f.mode.value = ["", "private", "shared", "exclusive",
		    "terminal"][cur.mode];
	$("enter").disabled = cur.mode !== 0;
	$("exit").disabled = cur.mode === 0;
	$("discard").disabled = cur.mode === 0 || cur.mode === 4;
	$("mode-help").textContent = MODES[f.mode.value];
	loadable();
	if (!$("ws-system").hidden && !$("topic-changes").hidden)
		view();
}

/* System's topic, shown */
function topic(name) {
	$("topics").querySelector("[value=" + name + "]").checked = true;
	["changes", "history", "logs", "jobs", "live",
	    "errors"].forEach(function (t) {
		$("topic-" + t).hidden = t !== name;
	});
	if (name === "changes")
		view();
	else if (name === "history")
		saved();
	else if (name === "logs")
		toEnd($("log"));
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

/* what saved configuration n changed, shown under its row or hidden */
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

/* the operations, as rows a click puts in the operation line */
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

/* an operation to confirm, which then runs and prints into out */
function operate(line, rtable, out) {
	pending = { line: line, rtable: rtable };
	pendingOut = out;
	$("op-line").textContent = line + (rtable !== "0" ?
	    "\nin routing table " + rtable : "");
	$("op-dialog").showModal();
}

/*
 * how many top-level statements a diff changes: each one added or
 * removed, or with a line added or removed under it; a statement removed
 * and one added just after it with the same first word count as one
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

/* how the candidate differs from the running configuration, in the strip */
function changes(inConfigure) {
	var tag = $("changes");

	if (!inConfigure) {
		tag.hidden = true;
		$("led-cfg").className = "led";
		return;
	}
	ask("GET", "config", { what: "diff" }).then(function (j) {
		var n = objects(said(j));

		tag.textContent = n === 1 ? "1 object changed" : n +
		    " objects changed";
		tag.classList.add("on");
		tag.hidden = n === 0;
		$("led-cfg").className = n > 0 ? "led warn" : "led on";
	});
}

/* a short label for one of system's warnings, with the warning as its title */
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
 * the running configuration, on the strip: its generation, when it was
 * last saved and by whom, and system's warnings, all from the list of
 * saved configurations
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
	/* the Overview and Network look again every so often, for traffic */
	clearInterval(looker);
	looker = name !== "overview" && name !== "network" ? null :
	    setInterval(function () {
		if (!document.hidden)
			interfaces();
	}, LOOK);
	pfWatch(name === "security");
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

/* is interface r in the table the page is focused on, if it is */
function inTable(r) {
	return table === null || Number(r.rdomain || 0) === table;
}

/*
 * The tables the user may focus on: 0, each the interfaces are in and
 * each the configuration names, with its name
 */
function tableChoices() {
	var pick = $("table-pick"), names = {};

	names[0] = "";
	ifs.forEach(function (r) {
		names[Number(r.rdomain || 0)] = "";
	});
	if (netConf !== null)
		netRtables(netConf).forEach(function (t) {
			names[t.rt] = t.name;
		});
	if (table !== null && names[table] === undefined)
		names[table] = "";
	pick.textContent = "";
	pick.appendChild(el("option", "all")).value = "";
	Object.keys(names).map(Number).sort(function (a, b) {
		return a - b;
	}).forEach(function (n) {
		pick.appendChild(el("option", n + (names[n] ? " " + names[n] :
		    ""))).value = String(n);
	});
	pick.value = table === null ? "" : String(table);
	$("table-what").textContent = table === null ? "" : "rtable " +
	    table + (names[table] ? " · " + names[table] : "");
}

/*
 * Focus the page on routing table n, or on every table if n is null: a
 * bar above the page and a frame around it say so, and what the page
 * shows is drawn again
 */
function focusTable(n) {
	table = n;
	try {
		if (n === null)
			sessionStorage.removeItem("nshdeck.table");
		else
			sessionStorage.setItem("nshdeck.table", String(n));
	} catch (e) {
		/* kept for this page only */
	}
	$("deck").classList.toggle("focused", n !== null);
	$("tablebar").hidden = n === null;
	tableChoices();
	/* an operation runs in the table */
	$("op-form").rtable.value = n === null ? "0" : String(n);
	$("op-form").rtable.disabled = n !== null;
	/* a line typed with the page focused on no table is the top level's */
	if (n === null && cur && cur.mode !== 0 && !cur.interface &&
	    (cur.rtable || 0) !== 0)
		configure("line", { line: "rtable 0" },
		    $("prompt").textContent + "rtable 0");
	/* what the inspector shows of another table goes */
	if ((selected !== "" && !netInTable(selected)) ||
	    (netRoute !== null && n !== null && netRoute.now.rt !== n)) {
		selected = "";
		insp = null;
		netRoute = null;
		iasked++;
		$("inspector").textContent = "";
		$("inspector").appendChild(el("p", "Choose an interface.",
		    "dim"));
	}
	faceplate();
	readout();
	logical();
	iftable();
	netDraw();
	/* a workspace of daemons on screen shows the table's */
	document.querySelectorAll(".daemons").forEach(function (d) {
		if (d.offsetParent !== null)
			daemons(d.dataset.ws);
	});
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
		sampled(ifs, Date.now());
		tableChoices();
		faceplate();
		trayRates();
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
	p.appendChild(el("span", null, "util")).appendChild(el("i"));
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
		box.appendChild(el("div")).id = "tray-rates";
		trayRates();
		box.appendChild(el("h4", "On this port"));
		relRows(box, name, on, all, go);
		box.appendChild(el("h4", "Linked to"));
		relRows(box, name, relOf(all, name).filter(function (e) {
			return on.indexOf(e) === -1;
		}), all, go);
		box.hidden = false;
	});
}

/* the open tray's counters, as of the last look */
function trayRates() {
	var box = $("tray-rates");

	if (box === null)
		return;
	box.textContent = "";
	box.appendChild(rateLines($("tray").dataset.port));
}

/*
 * the ports, as a box's face shows them, in the kernel's order, a block
 * for each driver. They are made again only when the ports change, so
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
	chassisFit();
	list.forEach(function (r) {
		var p = jacks[r.name], n = Number(r["input-packets"] || 0) +
		    Number(r["output-packets"] || 0), u = utilisation(r);

		/* a port in another table is there, and not chosen */
		p.className = "port " + state(r) + (inTable(r) ? "" : " out");
		p.disabled = !inTable(r);
		p.title = r.name + (r.description ? " — " +
		    r.description : "") + "\n" + (r.link || "") +
		    (addresses(r.name).length ? "\n" +
		    addresses(r.name).join("\n") : "") + (u < 0 ? "" :
		    "\n" + Math.round(u * 100) + "% of its line rate");
		/* how full the line is, as a bar under the port */
		p.querySelector(".util i").style.width = (u < 0 ? 0 :
		    Math.round(u * 100)) + "%";
		p.querySelector(".act").classList.toggle("on",
		    packets[r.name] !== undefined && packets[r.name] !== n);
		p.querySelector(".rate").textContent = rate(r);
		packets[r.name] = n;
	});
}

/*
 * The page is the one thing that scrolls. An inspector stays in view as
 * it scrolls while the inspector fits in the page's view, and scrolls
 * with the page when it is taller (style.css)
 */
function stickWhileFits(box) {
	var main = document.querySelector("main"), fit = function () {
		box.classList.toggle("tall", box.offsetHeight > main.clientHeight);
	};

	new ResizeObserver(fit).observe(box);
	new ResizeObserver(fit).observe(main);
}

/*
 * change, which makes the page longer above box's end: if that end was
 * in view, the page scrolls to keep it there, as a log or the transcript
 * once scrolled itself; if the page was scrolled away, it stays
 */
function followEnd(box, change) {
	var main = document.querySelector("main");
	var m = main.getBoundingClientRect(), r = box.getBoundingClientRect();
	var was = r.height && r.bottom >= m.top && r.bottom <= m.bottom + 1;

	change();
	if (was)
		toEnd(box);
}

/* the page scrolled down until box's end is in view, if it is below */
function toEnd(box) {
	var main = document.querySelector("main");
	var below = box.getBoundingClientRect().bottom -
	    main.getBoundingClientRect().bottom;

	if (below > 0)
		main.scrollTop += below;
}

/*
 * The box is taller if its ports do not fit in one row beside its plate
 * and readout: they go under those, the box's width (style.css). Asked
 * again when the ports, the window or the page's size change
 */
function chassisFit() {
	var box = $("ports").parentNode, rows = {};

	if ($("ws-overview").hidden)
		return;
	box.classList.remove("tall");
	Object.keys(jacks).forEach(function (n) {
		rows[jacks[n].offsetTop] = true;
	});
	box.classList.toggle("tall", Object.keys(rows).length > 1);
}

/*
 * the readout on the box's face: its ports, interfaces and addresses, in
 * the table the page is focused on
 */
function readout() {
	var mine = ifs.filter(inTable), ports = mine.filter(physical);
	var names = mine.map(function (r) {
		return r.name;
	}), as = addrs.filter(function (a) {
		return names.indexOf(a.interface) !== -1;
	}), v4 = as.filter(function (a) {
		return a.address && a.address.indexOf(":") === -1;
	}).length;

	$("r-ports").textContent = ports.filter(function (r) {
		return state(r) === "on";
	}).length + " of " + ports.length + " up";
	$("r-ifs").textContent = mine.length + ", " + (mine.length -
	    ports.length) + " logical";
	$("r-addrs").textContent = v4 + " IPv4, " + (as.length - v4) +
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

			if (seen[r.name] || !inTable(r) || (g.drivers === null ?
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
	["", "Interface", "Description", "Link", "Addresses", "In bit/s",
	    "Out bit/s", "5 min", "Errors"].forEach(function (h) {
		head.appendChild(el("th", h));
	});
	["MTU", "rdomain", "Type"].forEach(function (h) {
		head.appendChild(el("th", h, "spare"));
	});
	t.appendChild(head);
	ifs.filter(inTable).forEach(function (r) {
		var tr = el("tr", null, r.name === selected ? "sel" : "");
		var led = el("td"), type = el("td", r.type || "", "type spare");

		led.appendChild(el("i", null, "led " + state(r)));
		tr.appendChild(led);
		tr.appendChild(el("td", r.name, "mono"));
		tr.appendChild(el("td", r.description || "", "descr"));
		tr.appendChild(el("td", r.link || ""));
		tr.appendChild(el("td", addresses(r.name).join(" "), "mono"));
		rateCells(tr, r.name);
		tr.appendChild(el("td", r.mtu !== undefined ? r.mtu : "",
		    "num spare"));
		tr.appendChild(el("td", r.rdomain !== undefined ? r.rdomain :
		    "", "num spare"));
		/* the type may be cut short: its title shows it all */
		type.title = r.type || "";
		tr.appendChild(type);
		tr.addEventListener("click", function () {
			selected = r.name;
			iftable();
			inspect(r.name);
		});
		t.appendChild(tr);
	});
	$("net-count").textContent = ifs.filter(inTable).length +
	    " interfaces";
	netFit();
}

/* a show's words, as at nsh's prompt, in the table the page is focused on */
function show(words, out) {
	return ask("GET", "show", { words: words, rtable: table === null ? 0 :
	    table }).then(function (j) {
		showDrawn(j, out);
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
			show(input.value, out);
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

	/* the line typed in stays in view under what it said */
	followEnd($("line-form"), function () {
		t.textContent += asked + "\n" + said(j);
	});
	context(j);
	refused(asked, j);
}

/*
 * request asked, answered j, kept for the Errors topic if nshd refused
 * it, with when and in which workspace. The same request succeeding
 * takes its error away, and a commit or rollback that succeeds (not
 * commit check) takes them all, as the candidate they were about is gone
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

/*
 * In configure, a line typed goes into the routing table the page is
 * focused on, as after rtable N at nsh's configure prompt: the table is
 * entered first, unless the session is in it or in an interface. Table
 * 0's lines are the top level's
 */
function intoTable() {
	var rt = table === null ? 0 : table;

	if (table === null || !cur || cur.mode === 0 || cur.interface ||
	    (cur.rtable || 0) === rt)
		return Promise.resolve();
	return configure("line", { line: "rtable " + rt },
	    $("prompt").textContent + "rtable " + rt);
}

/*
 * The session in configure, in the mode chosen in System's Changes, if it
 * is not in configure already: as the user logs in, and before a change.
 * Only a refusal shows in the transcript
 */
function entering() {
	var mode = $("configure-form").mode.value, asked = "configure " + mode;

	if (cur && cur.mode !== 0)
		return Promise.resolve();
	return ask("POST", "configure", { mode: mode }).then(function (j) {
		if (j.ok) {
			context(j);
			refused(asked, j);
		} else
			transcript(asked, j);
		return j;
	});
}

/* what each permission allows, as nsh(8) says */
var GRANTS = [
	["view", "View", "Every show, the configuration included"],
	["operate", "Operate", "Operations, such as flush, reboot and a " +
	    "daemon's actions, and ping and traceroute"],
	["configure", "Configure", "A candidate of your own, commit and " +
	    "rollback"],
	["admin", "Admin", "The shared candidate, and changes to what runs " +
	    "as root or decides who may log in"],
	["exec", "Exec", "Programs nsh runs as you, such as ssh and an " +
	    "editor"]
];

/* the user and what their permissions allow, at the Overview's foot */
function access(user, perms) {
	var s = sheetOf("Your access"), h = s.querySelector("header");
	var dl = el("dl", null, "fields grants");

	h.insertBefore(avatarOf(user), h.firstChild);
	h.querySelector("h3").textContent = user;
	h.appendChild(el("span", "what your login class allows", "count"));
	GRANTS.forEach(function (g) {
		var on = perms.indexOf(g[0]) !== -1;

		dl.appendChild(el("dt", g[1], on ? "on" : "off"));
		dl.appendChild(el("dd", on ? g[2] : "Not allowed", on ? "" :
		    "dim"));
	});
	s.appendChild(dl);
	$("access").textContent = "";
	$("access").appendChild(s);
}

/* an unconfirmed commit's deadline, counted down in the strip */
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

/*
 * the event stream, following the logs checked, each from its past
 * again: what the log showed goes
 */
function follow() {
	var logs = [];

	document.querySelectorAll("#events-form input:checked").forEach(
	    function (c) {
		logs.push(c.value);
	});
	if (stream)
		stream.close();
	$("log").textContent = "";
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
	/* this page fell behind and lost events: interfaces asked again */
	stream.addEventListener("dropped", function () {
		followEnd($("log"), function () {
			$("log").textContent += "[some lines were dropped]\n";
		});
		noticed({ kind: "dropped", text: "some events were dropped" });
		interfaces();
	});
	stream.addEventListener("log", function (e) {
		var d = JSON.parse(e.data), log = $("log");
		var lines = (log.textContent + d.text).split("\n");
		var first = log.textContent === "";

		if (lines.length > LOGLINES)
			lines = lines.slice(lines.length - LOGLINES);
		followEnd(log, function () {
			log.textContent = lines.join("\n");
		});
		/* a log's past, as it begins: its newest line in view */
		if (first)
			toEnd(log);
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
			hostname = h[0].name;
			$("prompt").textContent = nshprompt(cur);
		}
	});
	ask("GET", "show", { words: "version" }).then(function (j) {
		var m = of(j, "message");

		$("plate-ver").textContent = j.ok && m.length ?
		    m[0].text.split("\n")[0] : "";
	});
}

function loggedIn(j) {
	var f = $("configure-form"), admin = j.perms.indexOf("admin") !== -1;
	var n;

	$("who").textContent = j.user;
	access(j.user, j.perms);
	/*
	 * into configure: the shared candidate, which needs admin, else a
	 * candidate of the user's own
	 */
	f.mode.value = admin ? "shared" : "private";
	f.querySelectorAll("[value=shared], [value=exclusive]").forEach(
	    function (i) {
		i.disabled = !admin;
	});
	$("mode-help").textContent = MODES[f.mode.value];
	if (admin || j.perms.indexOf("configure") !== -1)
		entering();
	$("login").hidden = true;
	$("deck").hidden = false;
	/* the table this tab was focused on, before the page was reloaded */
	try {
		n = sessionStorage.getItem("nshdeck.table");
	} catch (e) {
		n = null;
	}
	if (n !== null && /^\d+$/.test(n) && Number(n) <= 255)
		focusTable(Number(n));
	follow();
	host();
	runState();
	/* the light crosses the box as it is first shown (style.css) */
	$("ports").parentNode.classList.add("lit");
	workspace("overview");
}

/*
 * Show the login form. Once someone has logged in, reload the page
 * instead, so that nothing the last user saw remains.
 */
function loggedOut() {
	/* the next user's page is focused on no table */
	try {
		sessionStorage.removeItem("nshdeck.table");
	} catch (e) {
		/* nothing was kept */
	}
	if (!$("deck").hidden)
		location.reload();
	else {
		$("login").hidden = false;
		loginPrompt();
	}
}

/*
 * The login form's cursor, put where input's caret is, in cells; and a
 * password's stars, as many as it has characters (style.css)
 */
function loginCursor(input) {
	var field = input.parentNode, echo = field.querySelector(".echo");

	if (echo !== null)
		echo.textContent = "*".repeat(input.value.length);
	field.style.setProperty("--at", input.selectionDirection ===
	    "backward" ? input.selectionStart : input.selectionEnd);
	field.style.setProperty("--scrolled", echo !== null ? 0 :
	    input.scrollLeft);
}

/*
 * How far above the middle of its line the login form's font draws a
 * star, in ems: the stars are put down by that (style.css). A canvas
 * says where the star's ink is, and where the font's line is
 */
function starDrop(echo) {
	var cs = getComputedStyle(echo), m;
	var ctx = document.createElement("canvas").getContext("2d");

	ctx.font = cs.fontWeight + " 100px " + cs.fontFamily;
	m = ctx.measureText("*");
	if (m.fontBoundingBoxAscent === undefined)
		return;
	echo.style.setProperty("--drop", (m.actualBoundingBoxAscent -
	    m.actualBoundingBoxDescent - m.fontBoundingBoxAscent +
	    m.fontBoundingBoxDescent) / 200 + "em");
}

/* at most this many lines of logins tried are kept above the prompt */
var LOGINLINES = 240;

/*
 * A login tried, kept above a new prompt as a terminal keeps it: its
 * name, its Password: line, and why it was refused; or, if why is
 * null, an empty name, which only asks again
 */
function loginFailed(user, why) {
	var past = $("login-past"), line = function (ask, text) {
		var p = past.appendChild(el("div"));

		if (ask !== null)
			p.appendChild(el("span", ask, "ask"));
		p.appendChild(document.createTextNode(text));
	};

	line("login:", " " + user);
	if (why !== null) {
		line("Password:", "");
		line(null, why.replace(/^% /, ""));
	}
	while (past.children.length > LOGINLINES)
		past.removeChild(past.firstChild);
	loginPrompt();
}

/* a new login: prompt, at the bottom, with the cursor in it */
function loginPrompt() {
	var f = $("login"), tty = f.querySelector(".tty");

	f.user.value = "";
	f.password.value = "";
	f.classList.remove("asked");
	f.user.focus();
	loginCursor(f.user);
	loginCursor(f.password);
	tty.scrollTop = tty.scrollHeight;
}

/* the login form's field in use, focused again if it lost the focus */
function loginRefocus() {
	var f = $("login");

	if (document.activeElement !== f.user &&
	    document.activeElement !== f.password)
		(f.classList.contains("asked") ? f.password : f.user).focus();
}

/* a form's submit, handled by fn, without leaving the page */
function on(id, fn) {
	$(id).addEventListener("submit", function (e) {
		e.preventDefault();
		closeChoices();
		fn(e.target);
	});
}

/*
 * The page's size, a step of ZOOMS, which the person chooses with A- and
 * A+ and this browser keeps. 1 is the size the window gives (style.css)
 */
var ZOOMS = [.85, 1, 1.15, 1.3, 1.5, 1.75];

function zoomTo(i) {
	i = Math.max(0, Math.min(ZOOMS.length - 1, i));
	document.documentElement.style.setProperty("--zoom", ZOOMS[i]);
	$("smaller").disabled = i === 0;
	$("larger").disabled = i === ZOOMS.length - 1;
	try {
		localStorage.setItem("nshdeck.zoom", String(ZOOMS[i]));
	} catch (e) {
		/* the size is kept for this page only */
	}
	termSized();
	chassisFit();
	netFit();
	return i;
}

document.addEventListener("DOMContentLoaded", function () {
	var z = 1;

	try {
		z = ZOOMS.indexOf(Number(localStorage.getItem("nshdeck.zoom")));
	} catch (e) {
		z = -1;
	}
	z = zoomTo(z === -1 ? 1 : z);
	$("smaller").addEventListener("click", function () {
		z = zoomTo(z - 1);
	});
	$("larger").addEventListener("click", function () {
		z = zoomTo(z + 1);
	});
	/* as login(1) does, Enter after the name asks for the password */
	$("login").user.addEventListener("keydown", function (e) {
		if (e.key === "Enter" && e.target.value === "")
			return;
		if (e.key === "Enter") {
			e.preventDefault();
			$("login").classList.add("asked");
			$("login").password.focus();
		}
	});
	starDrop($("login").querySelector(".echo"));
	[$("login").user, $("login").password].forEach(function (i) {
		["input", "focus", "keyup", "mouseup", "scroll"].forEach(
		    function (ev) {
			i.addEventListener(ev, function () {
				loginCursor(i);
			});
		});
	});
	/* the caret moved, by a key held or the mouse */
	document.addEventListener("selectionchange", function () {
		var i = document.activeElement;

		if (i !== null && i.form === $("login"))
			loginCursor(i);
	});
	/*
	 * a click in the terminal, or a key typed while nothing has the
	 * focus, puts the cursor back where it was
	 */
	$("login").querySelector(".tty").addEventListener("mouseup",
	    loginRefocus);
	document.addEventListener("keydown", function () {
		if (!$("login").hidden)
			loginRefocus();
	}, true);
	on("login", function (f) {
		var user = f.user.value;

		/* as login(1) does, an empty name asks again */
		if (user === "") {
			loginFailed("", null);
			return;
		}
		ask("POST", "login", { user: user,
		    password: f.password.value }).then(function (j) {
			f.password.value = "";
			loginCursor(f.password);
			if (j.httpStatus !== 200) {
				loginFailed(user, j.error || "Login incorrect");
				return;
			}
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
	$("table-pick").addEventListener("change", function (e) {
		focusTable(e.target.value === "" ? null :
		    Number(e.target.value));
	});
	$("leave").addEventListener("click", function () {
		focusTable(null);
	});
	document.querySelectorAll(".daemons").forEach(daemonsBox);
	document.querySelectorAll("#inspector, .dinsp").forEach(stickWhileFits);
	ops();
	$("topics").addEventListener("change", function (e) {
		topic(e.target.value);
	});
	document.addEventListener("keydown", keys);
	window.addEventListener("resize", chassisFit);
	window.addEventListener("resize", netFit);
	/* once: showing the Overview again does not send the light again */
	$("ports").parentNode.addEventListener("animationend", function (e) {
		if (e.animationName === "glint")
			e.currentTarget.classList.remove("lit");
	});
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
	$("mode-help").textContent = MODES.shared;
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

		entering().then(intoTable).then(function () {
			return configure("line", { line: line },
			    $("prompt").textContent + line);
		}).then(function (j) {
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
