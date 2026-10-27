/*
 * editors.js: editors for the rules of pf, bgpd, the other routing
 * daemons and the Security and Services daemons, under the daemons'
 * table. pf's rules are listed as statements in order, bgpd's as peers,
 * networks and filters, a routing daemon's as its interfaces and global
 * settings, beside its live neighbors and routes, and another daemon's
 * as the statements of each of its tabs. Each is read from the rules'
 * text with pfconf.js, bgpdconf.js, routeconf.js or stmtconf.js, and
 * each change is written back into that text, which the inspector's
 * Rules box shows and Stage stages. The text is the only source:
 * anything typed in it is read again here.
 */
"use strict";

var ed = null;		/* the daemon the editor shows, and its selection */
var edLater = null;	/* a redraw for when typing in the text stops */

/* the views of pf's statements */
var PF_SHOW = [["all", "All"], ["filter", "Filtering"],
    ["translate", "NAT & redirects"], ["tables", "Tables & macros"],
    ["options", "Options"], ["anchors", "Anchors"]];

/* the rule fields the form shows: key and control (labels in registry.js) */
var PF_FIELDS = [
	["action", ["pass", "block", "match"]],
	["ret", "text"],
	["dir", ["", "in", "out"]],
	["quick", "check"],
	["log", "check"],
	["on", "text"],
	["af", ["", "inet", "inet6"]],
	["proto", "text"],
	["from", "text"],
	["fromport", "text"],
	["to", "text"],
	["toport", "text"],
	["state", ["", "keep state", "no state", "modulate state",
	    "synproxy state"]],
	["natto", "text"],
	["rdrto", "text"],
	["label", "text"],
	["other", "text"]
];

/* the neighbor settings the form shows: key and control */
var BGP_FIELDS = [
	["remote-as", "text"],
	["descr", "text"],
	["local-address", "lines"],
	["multihop", "text"],
	["max-prefix", "text"],
	["announce", "lines"],
	["passive", "check"],
	["down", "check"]
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
	if (!dinsp || (dinsp.def.name !== "pf" && dinsp.def.name !== "bgp" &&
	    !RT_DAEMONS[dinsp.def.name] && !SV_DAEMONS[dinsp.def.name])) {
		ed = null;
		return;
	}
	box = document.querySelector(".daemons[data-ws=" + dinsp.ws +
	    "] .structured");
	if (!ed || ed.daemon !== dinsp.def.name || ed.rt !== dinsp.rt)
		ed = { daemon: dinsp.def.name, rt: dinsp.rt, sel: -1,
		    show: "all", tab: dinsp.def.name === "bgp" ? "peers" :
		    RT_DAEMONS[dinsp.def.name] ? "interfaces" :
		    SV_DAEMONS[dinsp.def.name] ?
		    SV_DAEMONS[dinsp.def.name].tabs[0].id : "", peer: "",
		    summary: null, live: null, add: "" };
	if (ed.daemon === "pf")
		pfEditor(box);
	else if (ed.daemon === "bgp")
		bgpEditor(box);
	else if (RT_DAEMONS[ed.daemon])
		rtEditor(box);
	else
		svEditor(box);
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

/*
 * a field's control: a select, a check box, a text area, a text input or
 * one for a secret
 */
function edControl(key, kind, value, change) {
	var c, o;

	if (Array.isArray(kind)) {
		c = el("select");
		kind.concat(kind.indexOf(value) === -1 ? [value] : []).forEach(
		    function (v) {
			o = el("option", v === "" ? "(not set)" : v);
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
	} else if (kind === "secret") {
		/* shown as dots: the Rules box still holds it */
		c = el("input", null, "mono");
		c.type = "password";
		c.autocomplete = "off";
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
			regField(grid, "pf." + f[0], edControl(f[0], f[1],
			    f[1] === "check" ? !!v : v || "", set(f[0])));
		});
	else if (s.kind === "macro")
		regField(grid, "pf.macro", edControl("value", "text", s.value,
		    set("value")), null, s.name);
	else if (s.kind === "table")
		regField(grid, "pf.table", edControl("addrs", "text",
		    s.addrs || "", set("addrs")), s.files.length ?
		    "addresses and networks, and its files'" : null, s.name);
	else if (s.kind === "option")
		regField(grid, "pf.option", edControl("value", "text", s.value,
		    set("value")), null, "set " + s.name);
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
	var grid = el("div", null, "sfields");
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
	bar.appendChild(edSegs("bgptab", [["peers", "Peers"], ["networks",
	    "Networks"], ["filters", "Filters"]], ed.tab, function (v) {
		ed.tab = v;
		ed.sel = -1;
		structured();
	}));
	bar.appendChild(el("span", null, "fill"));
	box.appendChild(bar);
	regField(grid, "bgp.as", edControl("as", "text", as ? bgpRest(as) :
	    "", top("as", "AS")));
	regField(grid, "bgp.router-id", edControl("rid", "text", rid ?
	    bgpRest(rid) : "", top("routerid", "router-id")));
	box.appendChild(grid);
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
	var grid = el("div", null, "sfields"), line = el("div", null,
	    "addline");

	if (ed.summary === null)
		bgpState();
	bar.appendChild(el("span", ed.summary === null ? "Asking bgpd" :
	    ed.summary.error ? "State: " + ed.summary.error :
	    "State from bgpctl", "dim"));
	bar.appendChild(el("span", null, "fill"));
	bar.appendChild(edButton("Ask again", bgpState));
	box.appendChild(bar);
	addr.placeholder = "Address";
	addr.setAttribute("aria-label", "The new peer's address");
	addr.dataset.key = "newpeer";
	line.appendChild(addr);
	line.appendChild(edButton("Add peer", function () {
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
	regField(grid, "bgp.neighbor", line);
	box.appendChild(grid);
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
		var c = edControl(f[0], f[1], f[1] === "check" ? !!p[f[0]] :
		    f[0] === "descr" ? bgpUnquote(p[f[0]]) : p[f[0]],
		    function (v) {
			bgpDone(bgpSet(doc, p.node, f[0], v));
		});

		if (p["group-" + f[0]] && f[1] !== "check")
			c.placeholder = p["group-" + f[0]] + ", from group " +
			    p.group;
		regField(grid, "bgp." + f[0], c);
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
	var grid = el("div", null, "sfields"), rows = el("div", null, "rows");

	doc.nodes.filter(function (n) {
		return n.kind === "network";
	}).forEach(function (n, i) {
		var line = el("div", null, "addline");

		line.appendChild(edControl("net" + i, "text", bgpRest(n),
		    function (v) {
			bgpDone(v.trim() === "" ? bgpRemove(doc, n) :
			    bgpSplice(doc, n.start, n.end, [bgpLineOf(doc, n,
			    "network " + v.trim())]));
		}));
		line.appendChild(edButton("Delete", function () {
			bgpDone(bgpRemove(doc, n));
		}));
		rows.appendChild(line);
	});
	rows.appendChild(edButton("Add network", function () {
		bgpDone(bgpAdd(doc, "network 192.0.2.0/24\n", ["network"]));
	}));
	regField(grid, "bgp.network", rows);
	box.appendChild(grid);
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
		regField(grid, "bgp.filter.action", edControl("faction",
		    ["allow", "deny", "match"], f.action, set("action")));
		regField(grid, "bgp.filter.quick", edControl("fquick", "check",
		    f.quick, set("quick")));
		regField(grid, "bgp.filter.dir", edControl("fdir", ["from",
		    "to"], f.dir, set("dir")));
		regField(grid, "bgp.filter.peer", edControl("fpeer", "text",
		    f.peer, set("peer")));
		regField(grid, "bgp.filter.match", edControl("fmatch", "text",
		    f.match, set("match")));
		regField(grid, "bgp.filter.set", edControl("fset", "text",
		    f.set, set("set")));
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

/* a ctl program's show, as text, and whether it answered */
function rtShow(words) {
	return ask("GET", "show", { words: words }).then(function (j) {
		return { ok: j.ok, error: said(j).trim(), text: of(j,
		    "message").map(function (m) {
			return m.text;
		}).join("") + (j.output || "") };
	});
}

/* read the daemon's interface, neighbor and route shows, and redraw */
function rtState() {
	var e = ed, d = RT_DAEMONS[e.daemon];

	ed.live = { asking: true };
	return Promise.all([rtShow(e.daemon + " interfaces"),
	    rtShow(e.daemon + " neighbor"), rtShow(e.daemon + " " +
	    d.routes)]).then(function (a) {
		var bad = a.find(function (x) {
			return !x.ok;
		});

		if (ed !== e)
			return;
		ed.live = { ifaces: rtTable(a[0].text, d.ifaces),
		    nbrs: rtTable(a[1].text, d.nbrs), routes: a[2].text,
		    error: !bad ? "" : bad.error || d.prog +
		    " does not answer" };
		structured();
	});
}

/*
 * draw a routing daemon's editor: its interfaces, live neighbors, live
 * routes or labels, or global settings
 */
function rtEditor(box) {
	var d = RT_DAEMONS[ed.daemon], doc = bgpParse(dinsp.now.rules,
	    d.blocks), bar = el("div", null, "bar"), live = ed.live;

	ed.doc = doc;
	bar.appendChild(el("h2", d.prog));
	bar.appendChild(edSegs("rttab", [["interfaces", "Interfaces"],
	    ["neighbors", "Neighbors"], ["routes", d.routes === "lib" ?
	    "Labels" : "Routes"], ["global", "Global"]], ed.tab, function (v) {
		ed.tab = v;
		ed.sel = -1;
		structured();
	}));
	bar.appendChild(el("span", null, "fill"));
	if (dinsp.rt !== 0)
		bar.appendChild(el("span", "Live state is shown for rtable 0 " +
		    "only", "dim"));
	else {
		if (live === null)
			rtState();
		bar.appendChild(el("span", !live || live.asking ? "Asking " +
		    d.prog : live.error ? "State: " + live.error :
		    "State from " + d.ctl, "dim"));
		bar.appendChild(edButton("Ask again", rtState));
	}
	box.appendChild(bar);
	if (ed.tab === "neighbors")
		rtLiveTable(box, d.nbrs, live && live.nbrs, "No neighbors");
	else if (ed.tab === "routes")
		box.appendChild(el("pre", live && live.routes || "", "term"));
	else if (ed.tab === "global")
		rtGlobalTab(box, doc, d);
	else
		rtInterfacesTab(box, doc, d);
}

/* a table of rows a ctl program printed, with its columns */
function rtLiveTable(box, cols, rows, none) {
	var t = el("table", null, "grid"), head = el("tr");

	cols.forEach(function (c) {
		head.appendChild(el("th", c));
	});
	t.appendChild(head);
	(rows || []).forEach(function (r) {
		var tr = el("tr");

		cols.forEach(function (c) {
			tr.appendChild(el("td", r[c], "mono"));
		});
		t.appendChild(tr);
	});
	box.appendChild(t);
	if (rows && !rows.length)
		box.appendChild(el("p", none, "nothing"));
}

/* the row of the interface table for name, if the daemon listed it */
function rtLiveIface(name) {
	var live = ed.live;

	return live && live.ifaces ? live.ifaces.find(function (r) {
		return r.Interface === name;
	}) || null : null;
}

/*
 * the interfaces, one row each with their place, chosen settings, live
 * state and neighbor count; the selected one's form; and a field to add
 * one
 */
function rtInterfacesTab(box, doc, d) {
	var list = rtInterfaces(doc, d), places = rtPlaces(doc, d);
	var t = el("table", null, "grid pick"), head = el("tr");
	var grid = el("div", null, "sfields"), line = el("div", null,
	    "addline"), name = el("input", null, "mono"), where;
	var prefix = ed.daemon + ".";

	["", "Interface", "In"].concat(d.cols.map(function (k) {
		return reg(prefix + k).label;
	}), ["State", "Neighbors"]).forEach(function (h) {
		head.appendChild(el("th", h));
	});
	t.appendChild(head);
	list.forEach(function (f) {
		var key = f.place.name + " " + f.name, tr = el("tr", null,
		    key === ed.sel ? "sel" : ""), led = el("td");
		var bare = f.name.split(":")[0], r = rtLiveIface(bare);
		var state = r ? r.State || r.Linkstate : "";
		var nbrs = ed.live && ed.live.nbrs ? ed.live.nbrs.filter(
		    function (x) {
			return (x.Iface || x.Interface) === bare;
		}).length : "";

		led.appendChild(el("i", null, "led " + (!r ? "" :
		    /^(DOWN|down|no carrier)$/.test(state) ? "warn" : "on")));
		tr.appendChild(led);
		tr.appendChild(el("td", f.name, "mono"));
		tr.appendChild(el("td", f.place.name));
		d.cols.forEach(function (k) {
			var v = f[k], i = rtInherited(doc, d, f, k);

			tr.appendChild(el("td", v === true ? "yes" : v !==
			    undefined ? v : i ? i.value : "", v === undefined &&
			    i ? "dim" : "mono"));
		});
		tr.appendChild(el("td", state));
		tr.appendChild(el("td", String(nbrs), "num"));
		tr.addEventListener("click", function () {
			ed.sel = ed.sel === key ? -1 : key;
			structured();
		});
		t.appendChild(tr);
		if (key === ed.sel)
			t.appendChild(rtIfaceForm(doc, d, f));
	});
	box.appendChild(t);
	if (!list.length)
		box.appendChild(el("p", "No interfaces", "nothing"));
	if (places.length) {
		where = edControl("rtplace", places.map(function (p, i) {
			return String(i);
		}), "0", function () {});
		Array.prototype.forEach.call(where.options, function (o) {
			o.textContent = places[o.value].name || "top level";
		});
		if (places.length > 1)
			line.appendChild(where);
		name.placeholder = "Interface";
		name.dataset.key = "newiface";
		name.setAttribute("aria-label", "The new interface's name");
		line.appendChild(name);
		line.appendChild(edButton("Add interface", function () {
			var n = name.value.trim(), p = places[where.value];

			/* one word, with no quote, brace, comment or escape */
			if (!/^[^\s{}"#\\]+$/.test(n)) {
				name.focus();
				return;
			}
			ed.sel = p.name + " " + n;
			bgpDone(rtAddIface(doc, p.chain, n));
		}));
	} else
		line.appendChild(el("span", "Add " + {
		    area: "an area", "address-family": d.under[0].length > 1 ?
		    "an address family and AS" : "an address family"
		    }[d.under[0][0]] + " in the text first.", "dim"));
	regField(grid, prefix + "interface", line);
	box.appendChild(grid);
}

/* an interface's form: its settings, its other statements, Delete */
function rtIfaceForm(doc, d, f) {
	var tr = el("tr", null, "sform"), td = el("td"), grid = el("div", null,
	    "sfields"), bar = el("div", null, "bar");

	td.colSpan = 5 + d.cols.length;
	td.appendChild(el("h3", f.name + (f.place.name ? " in " +
	    f.place.name : "")));
	d.iface.forEach(function (k) {
		var v = f[k[0]], i = rtInherited(doc, d, f, k[0]);
		var c = edControl("rt" + k[0], k[1], k[1] === "check" ? !!v :
		    v || "", function (x) {
			bgpDone(rtSetIface(doc, f.node, k[0], k[1] === "check" ?
			    x : x.trim()));
		});

		if (i)
			c.placeholder = i.value + ", from " + i.from;
		regField(grid, ed.daemon + "." + k[0], c);
	});
	td.appendChild(grid);
	if (f.other.length) {
		td.appendChild(el("h3", "Other settings"));
		td.appendChild(el("pre", f.other.map(function (o) {
			return o.code;
		}).join("\n"), "term"));
	}
	bar.appendChild(edButton("Delete", function () {
		ed.sel = -1;
		bgpDone(bgpRemove(doc, f.node));
	}));
	td.appendChild(bar);
	tr.appendChild(td);
	return tr;
}

/* the global settings as fields, and the other top-level statements */
function rtGlobalTab(box, doc, d) {
	var grid = el("div", null, "sfields"), g = rtGlobal(doc, d);
	var other = rtOther(doc, d);

	d.global.forEach(function (k) {
		regField(grid, ed.daemon + "." + k[0], edControl("rt" + k[0],
		    k[1], g[k[0]], function (v) {
			bgpDone(rtSetGlobal(doc, k[0], v.trim()));
		}));
	});
	box.appendChild(grid);
	if (other.length) {
		box.appendChild(el("h3", "Other settings"));
		box.appendChild(el("pre", other.map(function (o) {
			return o.code;
		}).join("\n"), "term"));
	}
}

/* draw a Security or Services daemon's editor: the tab chosen */
function svEditor(box) {
	var d = SV_DAEMONS[ed.daemon], doc = bgpParse(dinsp.now.rules,
	    d.blocks), bar = el("div", null, "bar");
	var t = d.tabs.find(function (x) {
		return x.id === ed.tab;
	}) || d.tabs[0];

	ed.doc = doc;
	bar.appendChild(el("h2", d.prog));
	bar.appendChild(edSegs("svtab", d.tabs.map(function (x) {
		return [x.id, x.label];
	}), t.id, function (v) {
		ed.tab = v;
		ed.sel = -1;
		ed.add = "";
		structured();
	}));
	bar.appendChild(el("span", null, "fill"));
	box.appendChild(bar);
	if (t.show)
		svShowTab(box, t);
	if (t.single)
		svSingleTab(box, doc, d, t);
	if (t.kinds)
		svListTab(box, doc, d, t.kinds, t.cols || [], null, "");
}

/* field f's control, of the kind its spec gives, with value v */
function svControl(f, v, change) {
	return edControl("sv" + f.key, f.flag ? "check" : f.choices ||
	    f.words ? [""].concat(f.choices || f.words) : f.lines || f.group ?
	    "lines" : f.secret ? "secret" : "text", f.flag ?
	    !!v : Array.isArray(v) ? v.join("\n") : v === undefined ? "" : v,
	    change);
}

/*
 * The statements of the given kinds in block p, or at the top level, a
 * row each: its kind, its first value and the fields in cols; under the
 * one selected, its form; and a line to add one. path keeps a nested
 * table's selection apart from its block's.
 */
function svListTab(box, doc, d, ids, cols, p, path) {
	var kinds = svKinds(d, ids), name = ed.daemon;
	var list = svList(doc, d, p, kinds);
	var t = el("table", null, "grid pick"), head = el("tr");
	var grid = el("div", null, "sfields"), line = el("div", null,
	    "addline"), val = el("input", null, "mono"), pick;
	var k = kinds.find(function (x) {
		return path + x.id === ed.add;
	}) || kinds[0];

	["Statement", "Value"].concat(cols.map(function (c) {
		return reg(name + "." + c).label;
	})).forEach(function (h) {
		head.appendChild(el("th", h));
	});
	t.appendChild(head);
	list.forEach(function (s, i) {
		var key = path + i, tr = el("tr", null, key === ed.sel ? "sel" :
		    ""), first = (s.kind.args || [])[0];

		tr.appendChild(svWarned(el("td", s.kind.kw.join(" ")), s));
		tr.appendChild(el("td", first ? svCell(first, s.v[first.key]) :
		    "", "mono"));
		cols.forEach(function (c) {
			tr.appendChild(el("td", svCell(stField(s.kind, c),
			    s.v[c]), "mono"));
		});
		tr.addEventListener("click", function (e) {
			e.stopPropagation();
			ed.sel = ed.sel === key ? -1 : key;
			structured();
		});
		t.appendChild(tr);
		if (key === ed.sel || String(ed.sel).indexOf(key + "/") === 0)
			t.appendChild(svForm(doc, d, s, cols.length + 2, key));
	});
	box.appendChild(t);
	if (!list.length)
		box.appendChild(el("p", "None", "nothing"));
	if (kinds.length > 1) {
		pick = edControl("svkind", kinds.map(function (x) {
			return x.id;
		}), k.id, function (v) {
			ed.add = path + v;
			structured();
		});
		Array.prototype.forEach.call(pick.options, function (o) {
			o.textContent = svKinds(d, [o.value])[0].kw.join(" ");
		});
		line.appendChild(pick);
	}
	val.dataset.key = "svnew";
	val.placeholder = k.args && k.args.length ? reg(svReg(name, k)).label :
	    "";
	val.setAttribute("aria-label", "The new statement's value");
	if (k.args && k.args.length)
		line.appendChild(val);
	line.appendChild(edButton("Add", function () {
		var v = val.value.trim();

		if (k.args && k.args.length && (v === "" || /\n/.test(v))) {
			val.focus();
			return;
		}
		ed.sel = path + svAfter(doc, d, p, kinds, k);
		bgpDone(stAdd(doc, p, k, v === "" ? [] : [v], kinds));
	}));
	regField(grid, svReg(name, k), line, null, "New " +
	    reg(svReg(name, k)).label.toLowerCase());
	box.appendChild(grid);
}

/* field f's value v in a table's cell: a secret's is hidden */
function svCell(f, v) {
	return f.secret && v ? "hidden" : v === true ? "yes" :
	    Array.isArray(v) ? v.join(", ") : v || "";
}

/* e, with what makes statement s risky, if its kind says anything */
function svWarned(e, s) {
	var w = s && s.kind.warn ? s.kind.warn(s) : "";

	if (w)
		e.appendChild(el("span", w, "tag warn"));
	return e;
}

/* where the next statement of kind k goes among those of kinds in p */
function svAfter(doc, d, p, kinds, k) {
	var list = svList(doc, d, p, kinds), i;

	for (i = list.length - 1; i >= 0; i--)
		if (list[i].kind === k)
			return i + 1;
	return list.length;
}

/*
 * statement s's form, in a row of width columns: a field for each of its
 * values, its other words as written, the statements of its block, and
 * Delete
 */
function svForm(doc, d, s, width, key) {
	var tr = el("tr", null, "sform"), td = el("td"), grid = el("div", null,
	    "sfields"), bar = el("div", null, "bar"), k = s.kind;

	td.colSpan = width;
	td.addEventListener("click", function (e) {
		e.stopPropagation();
	});
	(k.args || []).concat(k.opts || [], k.list ? [k.list] :
	    []).forEach(function (f) {
		regField(grid, svReg(ed.daemon, k, f.key), svControl(f ===
		    k.list ? Object.assign({ lines: true }, f) : f, s.v[f.key],
		    function (v) {
			bgpDone(stSet(doc, s, f.key, typeof v === "string" ?
			    v.trim() : v));
		}));
	});
	td.appendChild(grid);
	if (s.other.length) {
		td.appendChild(el("h3", "Other words"));
		td.appendChild(el("pre", s.other.join(" "), "term"));
	}
	if (k.inner) {
		td.appendChild(el("h3", "In it"));
		svListTab(td, doc, d, k.inner, k.innerCols || [], s.node,
		    key + "/");
	}
	bar.appendChild(edButton("Delete", function () {
		ed.sel = -1;
		bgpDone(bgpRemove(doc, s.node));
	}));
	td.appendChild(bar);
	tr.appendChild(td);
	return tr;
}

/*
 * settings that appear once: a field each, its first value or presence;
 * one added goes after the others, or before the first statement
 */
function svSingleTab(box, doc, d, t) {
	var grid = el("div", null, "sfields"), kinds = svKinds(d, t.single);

	kinds.forEach(function (k) {
		var s = svList(doc, d, null, [k])[0], a = (k.args || [])[0];

		svWarned(regField(grid, svReg(ed.daemon, k), svControl(a ||
		    { key: k.id, flag: true }, a ? s && s.v[a.key] : !!s,
		    function (v) {
			if (a)
				bgpDone(stSingle(doc, null, k, v, svTop(d),
				    kinds));
			else if (v && !s)
				bgpDone(stAdd(doc, null, k, [], kinds, true));
			else if (!v && s)
				bgpDone(bgpRemove(doc, s.node));
		})).querySelector(".info"), s);
	});
	box.appendChild(grid);
}

/* what a show prints, asked for when the tab is drawn, and again on Ask */
function svShowTab(box, t) {
	var bar = el("div", null, "bar"), live = ed.live;
	var ask = function () {
		var e = ed;

		ed.live = { tab: t.id, asking: true };
		return rtShow(t.show).then(function (r) {
			if (ed !== e)
				return;
			ed.live = { tab: t.id, text: r.text, error: r.ok ? "" :
			    r.error || "no answer" };
			structured();
		});
	};

	if (dinsp.rt !== 0) {
		box.appendChild(el("p", "Shown for rtable 0 only", "nothing"));
		return;
	}
	if (!live || live.tab !== t.id) {
		ask();
		live = null;
	}
	bar.appendChild(el("span", !live || live.asking ? "Asking" :
	    live.error ? "State: " + live.error : "show " + t.show, "dim"));
	bar.appendChild(el("span", null, "fill"));
	bar.appendChild(edButton("Ask again", ask));
	box.appendChild(bar);
	box.appendChild(el("pre", live && live.text || "", "term"));
}
