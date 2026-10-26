/*
 * editors.js: editors for pf's and bgpd's rules, under the daemons'
 * table. pf's rules are listed as statements in order, and bgpd's as
 * peers, networks and filters. Both are read from the rules' text with
 * pfconf.js and bgpdconf.js, and each change is written back into that
 * text, which the inspector's Rules box shows and Stage stages. The text
 * is the only source: anything typed in it is read again here.
 */
"use strict";

var ed = null;		/* the daemon the editor shows, and its selection */
var edLater = null;	/* a redraw for when typing in the text stops */

/* the views of pf's statements */
var PF_SHOW = [["all", "All"], ["filter", "Filtering"],
    ["translate", "NAT & redirects"], ["tables", "Tables & macros"],
    ["options", "Options"], ["anchors", "Anchors"]];

/* the rule fields the form shows: key, label, control and hint */
var PF_FIELDS = [
	["action", "Action", ["pass", "block", "match"], "match only sets " +
	    "options"],
	["ret", "Return", "text", "return, return-rst or return-icmp; " +
	    "none drops"],
	["dir", "Direction", ["", "in", "out"], "none: both"],
	["quick", "Quick", "check", "the first rule that matches decides"],
	["log", "Log", "check", "to pflog0"],
	["on", "On", "text", "em0, a group, { em0 em1 } or !em0"],
	["af", "Family", ["", "inet", "inet6"], "none: both"],
	["proto", "Protocol", "text", "tcp, udp, icmp or { tcp udp }"],
	["from", "From", "text", "10.0.0.0/8, <table>, $macro, (em0), any " +
	    "or self"],
	["fromport", "From port", "text", "80, 1024:65535, > 1023 or " +
	    "{ 80 443 }"],
	["to", "To", "text", "as From"],
	["toport", "To port", "text", "as From port"],
	["state", "State", ["", "keep state", "no state", "modulate state",
	    "synproxy state"], "pass keeps state unless no state"],
	["natto", "nat-to", "text", "(egress)"],
	["rdrto", "rdr-to", "text", "10.0.0.5 port 8080"],
	["label", "Label", "text", "for pfctl -s labels"],
	["other", "Other options", "text", "flags S/SA, tag, …"]
];

/* the neighbor settings the form shows: key, label, control and hint */
var BGP_FIELDS = [
	["remote-as", "Remote AS", "text", ""],
	["descr", "Description", "text", ""],
	["local-address", "Local address", "lines", "a line each"],
	["multihop", "Multihop", "text", "hops"],
	["max-prefix", "Max prefixes", "text", "900000 restart 15"],
	["announce", "Families", "lines", "IPv4 unicast, a line each"],
	["passive", "Passive", "check", ""],
	["down", "Shut down", "check", ""]
];

/* the inspector's Rules text box, or null if it is not drawn */
function rulesArea() {
	return document.querySelector(".daemons[data-ws=" + dinsp.ws +
	    "] .dinsp textarea.rules");
}

/* set the rules to text, in the inspector's text box and its line count */
function rulesNow(text) {
	var area = rulesArea();

	dinsp.now.rules = text;
	if (area) {
		area.value = text;
		area.classList.toggle("edited", text !== dinsp.was.rules);
	}
	drefresh();
}

/* redraw the editor of the inspected daemon from its rules */
function structured() {
	var box;

	document.querySelectorAll(".structured").forEach(function (b) {
		b.textContent = "";
	});
	if (!dinsp || (dinsp.def.name !== "pf" && dinsp.def.name !== "bgp")) {
		ed = null;
		return;
	}
	box = document.querySelector(".daemons[data-ws=" + dinsp.ws +
	    "] .structured");
	if (!ed || ed.daemon !== dinsp.def.name || ed.rt !== dinsp.rt)
		ed = { daemon: dinsp.def.name, rt: dinsp.rt, sel: -1,
		    show: "all", tab: "peers", peer: "", summary: null };
	if (ed.daemon === "pf")
		pfEditor(box);
	else
		bgpEditor(box);
}

/* redraw the editor once the text has not changed for a moment */
function structuredLater() {
	clearTimeout(edLater);
	edLater = setTimeout(structured, 400);
}

/*
 * Redraw the editor after the current event, so that focus has already
 * moved, and give focus back to the control with the same key.
 */
function edRedraw() {
	setTimeout(function () {
		var a = document.activeElement, key = a && a.dataset ?
		    a.dataset.key : undefined, e;

		structured();
		if (key !== undefined && (e = document.querySelector(
		    ".structured [data-key='" + key + "']")) !== null)
			e.focus();
	}, 0);
}

/* a segmented control with one choice selected, like the page's others */
function edSegs(name, list, chosen, change) {
	var seg = el("div", null, "seg");

	seg.setAttribute("role", "radiogroup");
	list.forEach(function (c) {
		var lab = el("label"), input = el("input");

		input.type = "radio";
		input.name = name;
		input.value = c[0];
		input.checked = c[0] === chosen;
		input.addEventListener("change", function () {
			change(c[0]);
		});
		lab.appendChild(input);
		lab.appendChild(el("span", c[1]));
		seg.appendChild(lab);
	});
	return seg;
}

/* a field's control: a select, a check box, a text area or a text input */
function edControl(key, kind, value, change) {
	var c, o;

	if (Array.isArray(kind)) {
		c = el("select");
		kind.concat(kind.indexOf(value) === -1 ? [value] : []).forEach(
		    function (v) {
			o = el("option", v === "" ? "(none)" : v);
			o.value = v;
			c.appendChild(o);
		});
		c.value = value;
	} else if (kind === "check") {
		c = el("input");
		c.type = "checkbox";
		c.checked = !!value;
	} else if (kind === "lines") {
		c = el("textarea", null, "lines mono");
		c.rows = 2;
		c.value = value;
	} else {
		c = el("input", null, "mono");
		c.value = value;
	}
	c.dataset.key = key;
	c.addEventListener("change", function () {
		change(kind === "check" ? c.checked : c.value);
	});
	return c;
}

/* a form field: label, control and an optional hint */
function edField(into, label, c, hint) {
	var row = el("div", null, "field"), info = el("div", null, "info");

	row.appendChild(el("label", label));
	row.appendChild(c);
	if (hint) {
		info.appendChild(el("span", hint));
		row.appendChild(info);
	}
	into.appendChild(row);
	return row;
}

/* a link to an OpenBSD manual page, such as pf.conf(5), in a new tab */
function edManual(name) {
	var a = el("a", name);

	a.href = "https://man.openbsd.org/" + name.replace(/\((\d)\)$/, ".$1");
	a.target = "_blank";
	a.rel = "noreferrer";
	return a;
}

/* a button that calls fn */
function edButton(text, fn, cls) {
	var b = el("button", text, cls);

	b.type = "button";
	b.addEventListener("click", fn);
	return b;
}

/* true if pf's view show includes statement s */
function pfShown(s, show) {
	var tr = s.kind === "rule" && s.rule.opts.some(function (o) {
		return PF_TRANSLATE.indexOf(o.word) !== -1;
	});

	if (show === "filter")
		return s.kind === "rule" && !tr;
	if (show === "translate")
		return tr;
	if (show === "tables")
		return s.kind === "macro" || s.kind === "table";
	if (show === "options")
		return s.kind === "option";
	if (show === "anchors")
		return s.kind === "anchor";
	return s.kind !== "blank";
}

/* write ed.doc back into the rules and redraw the editor */
function pfDone() {
	rulesNow(pfText(ed.doc));
	edRedraw();
}

/* draw pf's editor: a row per statement, and a form for the selected one */
function pfEditor(box) {
	var doc = pfParse(dinsp.now.rules), bar = el("div", null, "bar");
	var t = el("table", null, "grid pick srules"), head = el("tr"), n = 0;
	var last = -1, help;

	ed.doc = doc;
	bar.appendChild(el("h2", "pf's rules"));
	bar.appendChild(edSegs("pfshow", PF_SHOW, ed.show, function (v) {
		ed.show = v;
		structured();
	}));
	bar.appendChild(el("span", null, "fill"));
	doc.stmts.forEach(function (s, i) {
		if (s.kind === "rule" || s.kind === "anchor")
			last = i;
	});
	bar.appendChild(edButton("Add rule", function () {
		pfInsert(ed.doc, ed.sel >= 0 ? ed.sel : last, "pass");
		ed.sel = ed.sel >= 0 ? ed.sel + 1 : last >= 0 ? last + 1 :
		    ed.doc.stmts.length - 1;
		if (ed.show !== "all" && ed.show !== "filter")
			ed.show = "all";
		pfDone();
	}));
	if (ed.show === "tables")
		bar.appendChild(edButton("Add table", function () {
			var at = -1;

			ed.doc.stmts.forEach(function (s, i) {
				if (s.kind === "macro" || s.kind === "table")
					at = i;
			});
			pfInsert(ed.doc, at, "table <new> { }");
			ed.sel = at + 1;
			pfDone();
		}));
	box.appendChild(bar);
	help = el("p", "The last rule that matches decides, unless one is " +
	    "quick. ", "help");
	help.appendChild(edManual("pf.conf(5)"));
	box.appendChild(help);
	["#", "Action", "Dir", "On", "AF", "Proto", "From", "To",
	    "Options"].forEach(function (h) {
		head.appendChild(el("th", h));
	});
	t.appendChild(head);
	doc.stmts.forEach(function (s, i) {
		var tr;

		if (s.kind === "rule")
			n++;
		if (!pfShown(s, ed.show))
			return;
		tr = pfRow(s, s.kind === "rule" ? n : "");
		tr.classList.toggle("sel", i === ed.sel);
		tr.addEventListener("click", function () {
			ed.sel = ed.sel === i ? -1 : i;
			structured();
		});
		t.appendChild(tr);
		if (s.kind === "anchor" && s.body)
			s.body.stmts.forEach(function (b) {
				if (b.kind !== "blank" && b.kind !== "comment")
					t.appendChild(pfRow(b, "", "inner"));
			});
		if (i === ed.sel)
			t.appendChild(pfForm(s, i));
	});
	box.appendChild(t);
}

/* a statement's row: a rule's parts, or the statement's kind and text */
function pfRow(s, n, cls) {
	var tr = el("tr", null, cls || ""), r = s.rule, td;
	var act = el("td");

	if (s.kind === "rule") {
		tr.appendChild(el("td", String(n), "num"));
		act.appendChild(el("span", r.action, "act act-" + r.action));
		if (r.quick)
			act.appendChild(el("span", " quick", "dim"));
		tr.appendChild(act);
		[r.dir, r.on, r.af, r.proto, [r.from, r.fromport ? "port " +
		    r.fromport : ""].filter(Boolean).join(" "), [r.to,
		    r.toport ? "port " + r.toport : ""].filter(Boolean).join(" "),
		    [r.state, r.natto ? "nat-to " + r.natto : "", r.rdrto ?
		    "rdr-to " + r.rdrto : "", r.log, r.label ? "label " +
		    r.label : "", r.other].filter(Boolean).join(" · ")].forEach(
		    function (v) {
			tr.appendChild(el("td", v || "", "mono"));
		});
		return tr;
	}
	tr.appendChild(el("td"));
	if (s.kind === "comment") {
		td = tr.appendChild(el("td", s.comments.join(" "), "cmt"));
		td.colSpan = 9;
		return tr;
	}
	tr.appendChild(el("td", { macro: "macro", table: "table",
	    option: "set", anchor: "anchor" }[s.kind] || "native", "kind"));
	td = tr.appendChild(el("td", s.kind === "macro" ? s.name + " = " +
	    s.value : s.kind === "table" ? [s.name].concat(s.flags,
	    s.files.map(function (f) {
		return "file " + f;
	}), s.addrs !== null ? ["{ " + s.addrs + " }"] : []).join(" ") :
	    s.kind === "option" ? s.name + " " + s.value :
	    s.kind === "anchor" ? s.raw.trim().split("\n")[0] : s.raw.trim(),
	    "mono"));
	td.colSpan = 8;
	return tr;
}

/* the form for statement i: its fields, its text and buttons to move it */
function pfForm(s, i) {
	var tr = el("tr", null, "sform"), td = el("td"), grid = el("div",
	    null, "sfields"), pre = el("pre", s.raw.replace(/\n$/, ""),
	    "term stanza"), bar = el("div", null, "bar");
	var set = function (key) {
		return function (v) {
			if (s.kind === "rule")
				pfRuleSet(s.rule, key, v);
			else
				s[key] = v.trim();
			pfWrite(s);
			pfDone();
		};
	};

	td.colSpan = 10;
	if (s.kind === "rule")
		PF_FIELDS.forEach(function (f) {
			var v = s.rule[f[0]];

			if (f[0] === "ret" && s.rule.action !== "block")
				return;
			edField(grid, f[1], edControl(f[0], f[2], f[2] === "check" ?
			    !!v : v || "", set(f[0])), f[3]);
		});
	else if (s.kind === "macro")
		edField(grid, s.name, edControl("value", "text", s.value,
		    set("value")), "in quotes if it has spaces");
	else if (s.kind === "table")
		edField(grid, s.name, edControl("addrs", "text", s.addrs || "",
		    set("addrs")), "addresses and networks" + (s.files.length ?
		    ", and its files'" : ""));
	else if (s.kind === "option")
		edField(grid, "set " + s.name, edControl("value", "text", s.value,
		    set("value")), "");
	else
		grid.appendChild(el("p", "Edit this statement as text.",
		    "help"));
	td.appendChild(grid);
	td.appendChild(el("h3", "As written"));
	td.appendChild(pre);
	if (s.kind === "rule" || s.kind === "anchor") {
		bar.appendChild(edButton("Move up", function () {
			if (pfMove(ed.doc, i, -1)) {
				ed.sel = ed.doc.stmts.indexOf(s);
				pfDone();
			}
		}));
		bar.appendChild(edButton("Move down", function () {
			if (pfMove(ed.doc, i, 1)) {
				ed.sel = ed.doc.stmts.indexOf(s);
				pfDone();
			}
		}));
	}
	bar.appendChild(edButton("Delete", function () {
		pfRemove(ed.doc, i);
		ed.sel = -1;
		pfDone();
	}));
	td.appendChild(bar);
	tr.appendChild(td);
	return tr;
}

/* write doc back into the rules and redraw the editor */
function bgpDone(doc) {
	rulesNow(bgpText(doc));
	edRedraw();
}

/* read show bgp summary into ed and redraw the editor */
function bgpState() {
	var e = ed;

	ed.summary = { rows: [], error: "" };
	return ask("GET", "show", { words: "bgp summary" }).then(function (j) {
		var text = of(j, "message").map(function (m) {
			return m.text;
		}).join("") + (j.output || "");

		if (ed !== e)
			return;
		ed.summary = { rows: bgpSummary(text), error: j.ok ? "" :
		    said(j).trim() || "bgpd does not answer" };
		structured();
	});
}

/* draw bgpd's editor: AS and router ID, then peers, networks or filters */
function bgpEditor(box) {
	var doc = bgpParse(dinsp.now.rules), bar = el("div", null, "bar");
	var as = doc.nodes.find(function (n) {
		return n.kind === "as";
	});
	var rid = doc.nodes.find(function (n) {
		return n.kind === "routerid";
	});
	var top = function (kind, word) {
		return function (v) {
			var n = kind === "as" ? as : rid, d;

			v = v.trim();
			if (n)
				d = bgpSplice(doc, n.start, n.end, v === "" ? [] :
				    [bgpLineOf(doc, n, word + " " + v)]);
			else
				d = v === "" ? doc : bgpSplice(doc, 0, 0,
				    [word + " " + v + "\n"]);
			bgpDone(d);
		};
	};

	ed.doc = doc;
	bar.appendChild(el("h2", "bgpd"));
	bar.appendChild(el("label", "Local AS", "dim"));
	bar.appendChild(edControl("as", "text", as ? bgpRest(as) : "",
	    top("as", "AS"))).classList.add("narrow");
	bar.appendChild(el("label", "Router ID", "dim"));
	bar.appendChild(edControl("rid", "text", rid ? bgpRest(rid) : "",
	    top("routerid", "router-id")));
	bar.appendChild(edSegs("bgptab", [["peers", "Peers"], ["networks",
	    "Networks"], ["filters", "Filters"]], ed.tab, function (v) {
		ed.tab = v;
		ed.sel = -1;
		structured();
	}));
	bar.appendChild(el("span", null, "fill"));
	box.appendChild(bar);
	if (ed.tab === "networks")
		bgpNetworks(box, doc);
	else if (ed.tab === "filters")
		bgpFilters(box, doc);
	else
		bgpPeersTab(box, doc, as ? bgpRest(as) : "");
}

/* find a peer's row in show bgp summary by description or address */
function bgpSeen(p, macros) {
	var a = /^\$/.test(p.address) ? macros[p.address.slice(1)] :
	    p.address;

	if (!ed.summary)
		return null;
	return ed.summary.rows.find(function (r) {
		return r.name === bgpUnquote(p.descr) || r.name === a;
	}) || null;
}

/* the peers, one row each, and the selected peer's form */
function bgpPeersTab(box, doc, localAS) {
	var peers = bgpPeers(doc), macros = bgpMacros(doc);
	var t = el("table", null, "grid pick"), head = el("tr");
	var bar = el("div", null, "bar"), addr = el("input", null, "mono");

	if (ed.summary === null)
		bgpState();
	bar.appendChild(el("span", ed.summary === null ? "Asking bgpd" :
	    ed.summary.error ? "State: " + ed.summary.error :
	    "State from bgpctl", "dim"));
	bar.appendChild(el("span", null, "fill"));
	bar.appendChild(edButton("Ask again", bgpState));
	addr.placeholder = "Address";
	addr.setAttribute("aria-label", "The new peer's address");
	addr.dataset.key = "newpeer";
	bar.appendChild(addr);
	bar.appendChild(edButton("Add peer", function () {
		var a = addr.value.trim();

		/* one word, with no quote, brace, comment or escape */
		if (!/^[^\s{}"#\\]+$/.test(a)) {
			addr.focus();
			return;
		}
		ed.peer = a;
		bgpDone(bgpAdd(doc, "neighbor " + a + " {\n}\n",
		    ["neighbor", "group"]));
	}));
	box.appendChild(bar);
	["", "Peer", "Description", "Remote AS", "Group", "State", "Up/Down",
	    "Prefixes"].forEach(function (h) {
		head.appendChild(el("th", h));
	});
	t.appendChild(head);
	peers.forEach(function (p) {
		var s = bgpSeen(p, macros), tr = el("tr", null,
		    p.address === ed.peer ? "sel" : ""), led = el("td");

		led.appendChild(el("i", null, "led " + (!s ? "" :
		    s.state === "Established" ? "on" : p.down ? "" : "warn")));
		tr.appendChild(led);
		tr.appendChild(el("td", p.address, "mono"));
		tr.appendChild(el("td", bgpUnquote(p.descr), "descr"));
		tr.appendChild(el("td", p["remote-as"] ||
		    p["group-remote-as"], "num"));
		tr.appendChild(el("td", p.group));
		tr.appendChild(el("td", p.down ? "down, as configured" :
		    s ? s.state : ""));
		tr.appendChild(el("td", s ? s.updown : "", "mono"));
		tr.appendChild(el("td", s && s.prefixes !== null ?
		    String(s.prefixes) : "", "num"));
		tr.addEventListener("click", function () {
			ed.peer = ed.peer === p.address ? "" : p.address;
			structured();
		});
		t.appendChild(tr);
	});
	box.appendChild(t);
	peers.forEach(function (p) {
		if (p.address === ed.peer)
			bgpPeerForm(box, doc, p, localAS, macros);
	});
}

/*
 * a peer's form: its session, inbound and outbound filters, and other
 * settings
 */
function bgpPeerForm(box, doc, p, localAS, macros) {
	var panel = el("div", null, "speer"), grid = el("div", null, "sfields");
	var flows = el("div", null, "flows"), fs = doc.nodes.filter(
	    function (n) {
		return n.kind === "filter" && bgpFilter(n) !== null;
	}), bar = el("div", null, "bar");

	panel.appendChild(el("h3", "Session with " + p.address));
	BGP_FIELDS.forEach(function (f) {
		var c = edControl(f[0], f[2], f[2] === "check" ? !!p[f[0]] :
		    f[0] === "descr" ? bgpUnquote(p[f[0]]) : p[f[0]],
		    function (v) {
			bgpDone(bgpSet(doc, p.node, f[0], v));
		});

		if (p["group-" + f[0]] && f[2] !== "check")
			c.placeholder = p["group-" + f[0]] + ", from group " +
			    p.group;
		edField(grid, f[1], c, f[3]);
	});
	panel.appendChild(grid);
	[["from", "Inbound"], ["to", "Outbound"]].forEach(function (w) {
		var col = el("div", null, "flow"), list = el("ol");

		col.appendChild(el("h3", w[1]));
		fs.forEach(function (n) {
			var f = bgpFilter(n), a = bgpApplies(f, p, localAS, macros);
			var li;

			if (f.dir !== w[0] || a === "no")
				return;
			li = list.appendChild(el("li", n.code, "mono"));
			if (a === "maybe")
				li.appendChild(el("span", " (maybe)", "dim"));
		});
		col.appendChild(list.children.length ? list :
		    el("p", "None", "empty"));
		flows.appendChild(col);
	});
	panel.appendChild(flows);
	if (p.other.length) {
		panel.appendChild(el("h3", "Other settings"));
		panel.appendChild(el("pre", p.other.map(function (o) {
			return o.code.replace(/\b(password|key)\s+\S+/g,
			    "$1 ••••••");
		}).join("\n"), "term"));
	}
	bar.appendChild(edButton("Delete peer", function () {
		ed.peer = "";
		bgpDone(bgpRemove(doc, p.node));
	}));
	panel.appendChild(bar);
	box.appendChild(panel);
}

/* the networks bgpd announces, one per line */
function bgpNetworks(box, doc) {
	var t = el("table", null, "grid"), bar = el("div", null, "bar");

	bar.appendChild(el("span", null, "fill"));
	bar.appendChild(edButton("Add network", function () {
		bgpDone(bgpAdd(doc, "network 192.0.2.0/24\n", ["network"]));
	}));
	box.appendChild(bar);
	doc.nodes.filter(function (n) {
		return n.kind === "network";
	}).forEach(function (n, i) {
		var tr = el("tr"), td = el("td");

		td.appendChild(el("span", "network ", "dim mono"));
		td.appendChild(edControl("net" + i, "text", bgpRest(n),
		    function (v) {
			bgpDone(v.trim() === "" ? bgpRemove(doc, n) :
			    bgpSplice(doc, n.start, n.end, [bgpLineOf(doc, n,
			    "network " + v.trim())]));
		}));
		tr.appendChild(td);
		td = el("td");
		td.appendChild(edButton("Delete", function () {
			bgpDone(bgpRemove(doc, n));
		}));
		tr.appendChild(td);
		t.appendChild(tr);
	});
	box.appendChild(t);
}

/* the filters in order, one row each, and a form for the selected one */
function bgpFilters(box, doc) {
	var fs = doc.nodes.filter(function (n) {
		return n.kind === "filter";
	});
	var t = el("table", null, "grid pick srules"), head = el("tr");
	var bar = el("div", null, "bar");

	bar.appendChild(el("p", "The last filter that matches decides, " +
	    "unless one is quick. ", "help")).appendChild(
	    edManual("bgpd.conf(5)"));
	bar.appendChild(el("span", null, "fill"));
	bar.appendChild(edButton("Add filter", function () {
		var after = ed.sel >= 0 && fs[ed.sel] ? fs[ed.sel].end :
		    fs.length ? fs[fs.length - 1].end : doc.lines.length;

		ed.sel = ed.sel >= 0 ? ed.sel + 1 : fs.length;
		bgpDone(bgpSplice(doc, after, after, ["allow from any\n"]));
	}));
	box.appendChild(bar);
	["#", "Action", "Dir", "Peer", "Matches", "Sets"].forEach(function (h) {
		head.appendChild(el("th", h));
	});
	t.appendChild(head);
	fs.forEach(function (n, i) {
		var f = bgpFilter(n), tr = el("tr", null, i === ed.sel ?
		    "sel" : ""), act = el("td"), td;

		tr.appendChild(el("td", String(i + 1), "num"));
		if (f === null) {
			tr.appendChild(el("td", "native", "kind"));
			td = tr.appendChild(el("td", n.code, "mono"));
			td.colSpan = 4;
		} else {
			act.appendChild(el("span", f.action, "act act-" +
			    (f.action === "allow" ? "pass" : f.action ===
			    "deny" ? "block" : "match")));
			if (f.quick)
				act.appendChild(el("span", " quick", "dim"));
			tr.appendChild(act);
			[f.dir, f.peer, f.match, f.set].forEach(function (v) {
				tr.appendChild(el("td", v, "mono"));
			});
		}
		tr.addEventListener("click", function () {
			ed.sel = ed.sel === i ? -1 : i;
			structured();
		});
		t.appendChild(tr);
		if (i === ed.sel)
			t.appendChild(bgpFilterForm(doc, n, f, i));
	});
	box.appendChild(t);
}

/* a filter's form: its fields, its text and buttons to move it */
function bgpFilterForm(doc, n, f, i) {
	var tr = el("tr", null, "sform"), td = el("td"), grid = el("div", null,
	    "sfields"), bar = el("div", null, "bar");
	var set = function (key) {
		return function (v) {
			f[key] = typeof v === "string" ? v.trim() : v;
			bgpDone(bgpSplice(doc, n.start, n.end, [bgpLineOf(doc, n,
			    bgpFilterText(f))]));
		};
	};

	td.colSpan = 6;
	if (f !== null) {
		edField(grid, "Action", edControl("faction", ["allow", "deny",
		    "match"], f.action, set("action")), "match only sets");
		edField(grid, "Quick", edControl("fquick", "check", f.quick,
		    set("quick")), "the first filter that matches decides");
		edField(grid, "Direction", edControl("fdir", ["from", "to"],
		    f.dir, set("dir")), "from: received; to: sent");
		edField(grid, "Peer", edControl("fpeer", "text", f.peer,
		    set("peer")), "any, ebgp, ibgp, an address, group " +
		    "\"name\" or AS 64496");
		edField(grid, "Matches", edControl("fmatch", "text", f.match,
		    set("match")), "prefix 10.0.0.0/8, prefix-set name, " +
		    "community 65001:100; none: every route");
		edField(grid, "Sets", edControl("fset", "text", f.set,
		    set("set")), "localpref 200");
	} else
		grid.appendChild(el("p", "Edit this statement as text.",
		    "help"));
	td.appendChild(grid);
	td.appendChild(el("h3", "As written"));
	td.appendChild(el("pre", doc.lines.slice(n.start, n.end).join("").
	    replace(/\n$/, ""), "term stanza"));
	[["Move up", -1], ["Move down", 1]].forEach(function (m) {
		bar.appendChild(edButton(m[0], function () {
			var d = bgpMove(doc, n, m[1]);

			if (d !== doc) {
				ed.sel = i + m[1];
				bgpDone(d);
			}
		}));
	});
	bar.appendChild(edButton("Delete", function () {
		ed.sel = -1;
		bgpDone(bgpRemove(doc, n));
	}));
	td.appendChild(bar);
	tr.appendChild(td);
	return tr;
}
