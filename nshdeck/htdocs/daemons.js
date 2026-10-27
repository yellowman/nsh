/*
 * daemons.js: the daemons nsh starts, each in its workspace, a row for
 * each routing table it is in: whether the configuration enables it,
 * its rules, and whether it runs. The one chosen is inspected: its rules
 * as text, staged into the candidate as its edit in nsh sets them, and
 * whether it is enabled, as nsh's line; and its actions, each a live
 * operation
 */
"use strict";

/*
 * Each daemon: its workspace, what it is, whether it runs in other
 * routing tables, whether it has rules and an enable, and the actions
 * that act on it as it runs, as nsh's tables have them; and for one
 * with no rules, the command nsh starts it with and what each of its
 * arguments does
 */
var DAEMONS = [
	{ name: "pf", ws: "security", label: "PF firewall", rules: 1,
	    enable: 1, ops: ["reload"] },
	{ name: "ipsec", ws: "security", label: "IKEv1 and IPsec (isakmpd)",
	    rt: 1, rules: 1, enable: 1, ops: ["reload", "show"] },
	{ name: "ike", ws: "security", label: "IKEv2 (iked)", rt: 1,
	    rules: 1, enable: 1, ops: ["active", "passive", "couple",
	    "decouple", "reload", "reset", "show"] },
	{ name: "sasync", ws: "security", label: "IPsec state " +
	    "synchronization (sasyncd)", rt: 1, rules: 1, enable: 1, ops: [] },
	{ name: "sshd", ws: "security", label: "SSH server (sshd)", rt: 1,
	    rules: 1, enable: 1, ops: [] },
	{ name: "bgp", ws: "routing", label: "BGP (bgpd)", rules: 1,
	    enable: 1, ops: ["reload", "fib", "neighbor", "network"] },
	{ name: "ospf", ws: "routing", label: "OSPFv2 (ospfd)", rt: 1,
	    rules: 1, enable: 1, ops: ["reload", "fib", "log", "show"] },
	{ name: "ospf6", ws: "routing", label: "OSPFv3 (ospf6d)", rt: 1,
	    rules: 1, enable: 1, ops: ["reload", "fib", "log"] },
	{ name: "eigrp", ws: "routing", label: "EIGRP (eigrpd)", rt: 1,
	    rules: 1, enable: 1, ops: ["reload", "fib", "log", "show"] },
	{ name: "rip", ws: "routing", label: "RIP (ripd)", rt: 1, rules: 1,
	    enable: 1, ops: ["reload", "fib", "show"] },
	{ name: "ldp", ws: "routing", label: "MPLS LDP (ldpd)", rules: 1,
	    enable: 1, ops: ["reload", "fib", "clear", "show"] },
	{ name: "dvmrp", ws: "routing", label: "DVMRP (dvmrpd)", rt: 1,
	    rules: 1, enable: 1, ops: ["log", "show"] },
	{ name: "dhcp", ws: "services", label: "DHCP server (dhcpd)", rt: 1,
	    rules: 1, enable: 1, ops: ["restart"] },
	{ name: "rad", ws: "services", label: "IPv6 router advertisements " +
	    "(rad)", rules: 1, enable: 1, ops: [] },
	{ name: "resolv", ws: "services", label: "DNS resolution (resolvd)",
	    enable: 1, ops: [], runs: "/sbin/resolvd", args: [] },
	{ name: "ntp", ws: "services", label: "Time (ntpd)", rules: 1,
	    enable: 1, ops: [] },
	{ name: "snmp", ws: "services", label: "SNMP agent (snmpd)", rt: 1,
	    rules: 1, enable: 1, ops: [] },
	{ name: "relay", ws: "services", label: "Load balancing (relayd)",
	    rt: 1, rules: 1, enable: 1, ops: ["reload", "host", "table",
	    "redirect", "monitor", "poll", "show"] },
	{ name: "nppp", ws: "services", label: "PPP concentrator (npppd)",
	    rt: 1, rules: 1, enable: 1, ops: ["clear", "session", "monitor"] },
	{ name: "ftp-proxy", ws: "services", label: "FTP proxy", rt: 1,
	    enable: 1, ops: [], runs: "/usr/sbin/ftp-proxy -D 2", args: [
	    ["-D 2", "Logs only messages of syslog level 2 (critical) or " +
	    "more severe. The default is 5."]], note: "It listens on " +
	    "127.0.0.1, port 8021, where a pf divert-to rule must send FTP." },
	{ name: "tftp-proxy", ws: "services", label: "TFTP proxy", rt: 1,
	    enable: 1, ops: [], runs: "/usr/sbin/tftp-proxy -v -l 127.0.0.1",
	    args: [["-v", "Logs each connection and request."],
	    ["-l 127.0.0.1", "Listens on the loopback address only."]],
	    note: "It listens on port 6969, where a pf divert-to rule must " +
	    "send TFTP." },
	{ name: "tftp", ws: "services", label: "TFTP server (tftpd)", rt: 1,
	    enable: 1, ops: [], runs: "/usr/sbin/tftpd -l 127.0.0.1 /tftpboot",
	    args: [["-l 127.0.0.1", "Listens on the loopback address only, " +
	    "so other hosts reach it only through pf."], ["/tftpboot",
	    "The directory it serves, which it makes its root."]] },
	{ name: "inet", ws: "services", label: "Internet super-server " +
	    "(inetd)", rt: 1, rules: 1, enable: 1, ops: [] },
	{ name: "smtp", ws: "services", label: "Mail transfer (smtpd)", rt: 1,
	    rules: 1, enable: 1, ops: ["log", "pause", "remove", "resume",
	    "schedule-all"] },
	{ name: "ldap", ws: "services", label: "LDAP directory (ldapd)",
	    rt: 1, rules: 1, enable: 1, ops: ["log", "compact", "index"] },
	{ name: "ifstate", ws: "services", label: "Link-state automation " +
	    "(ifstated)", rt: 1, rules: 1, enable: 1, ops: [] },
	{ name: "crontab", ws: "system", label: "Root's scheduled jobs, " +
	    "also called scheduler", rules: 1, ops: [] },
	{ name: "motd", ws: "system", label: "Message of the day", rules: 1,
	    ops: [] }
];

var dconf = {};		/* each daemon's rules and state, by "name rtable" */
var dfacts = [];	/* show daemons' records, the last */
var dchosen = {};	/* each workspace's daemon chosen: its name and rtable */
var dinsp = null;	/* the daemon inspected, its settings, and edits */

/*
 * a workspace's daemons: a table, the pf or bgpd editor under it
 * (editors.js), and an inspector beside them
 */
function daemonsBox(div) {
	var bar = el("div", null, "bar"), split = el("div", null, "netsplit");
	var main = el("div", null, "dmain");
	var aside = el("aside", null, "panel dinsp");

	bar.appendChild(el("h2", "Daemons"));
	bar.appendChild(el("span", null, "dim count"));
	main.appendChild(el("table", null, "grid pick"));
	main.appendChild(el("div", null, "structured"));
	split.appendChild(main);
	aside.setAttribute("aria-label", "The daemon's settings");
	aside.appendChild(el("p", "Choose a daemon.", "dim"));
	split.appendChild(aside);
	div.appendChild(bar);
	div.appendChild(split);
}

/* is there a candidate: configure, but not configure terminal */
function candidate() {
	return cur && cur.mode !== 0 && cur.mode !== 4;
}

function daemonDef(name) {
	return DAEMONS.find(function (d) {
		return d.name === name;
	});
}

/*
 * each daemon's rules and whether it is enabled, by "name rtable", as
 * text, a configuration, has them: at the top for rtable 0, and in an
 * rtable's block, a space in, for the rest; a rules block's lines a
 * space further in, to its "!"
 */
function daemonConf(text) {
	var out = {}, rt = 0, rules = null;

	text.split("\n").forEach(function (l) {
		var pad = rt ? " " : "", m, k;

		if (rules !== null) {
			if (l.indexOf(pad + " ") === 0)
				rules.push(l.slice(pad.length + 1));
			else
				rules = null;
			return;
		}
		if ((m = /^rtable (\d+)/.exec(l)) !== null) {
			rt = Number(m[1]);
			return;
		}
		if (l === "!")
			rt = 0;
		m = /^(\S+) (rules|enable|disable)$/.exec(l.slice(pad.length));
		if (l.indexOf(pad) !== 0 || m === null || !daemonDef(m[1]))
			return;
		k = m[1] + " " + rt;
		out[k] = out[k] || { rules: null, enabled: false };
		if (m[2] === "rules")
			rules = out[k].rules = [];
		else
			out[k].enabled = m[2] === "enable";
	});
	return out;
}

/* name's records in rtable rt, of show daemons */
function observed(name, rt) {
	return dfacts.find(function (r) {
		return r.daemon === name && r.rtable === rt;
	});
}

/* what show daemons says of name in rt, and its light */
function running(name, rt) {
	var r = observed(name, rt);

	if (!r || r.running === undefined)
		return ["", ""];
	if (name === "pf")
		return [r.running ? "enabled" : "disabled", r.running ? "on" : ""];
	if (!r.running)
		return ["not running", ""];
	return ["running, " + r.processes + (r.processes === 1 ?
	    " process" : " processes"), "on"];
}

/* the configuration, and show daemons: ws's daemons, drawn */
function daemons(ws) {
	return Promise.all([ask("GET", "config", { what: candidate() ?
	    "candidate" : "running" }), ask("GET", "show",
	    { words: "daemons" })]).then(function (a) {
		var c = dchosen[ws];

		dconf = daemonConf(said(a[0]));
		dfacts = of(a[1], "daemon");
		dtable(ws);
		if (c)
			return dinspect(ws, c.name, c.rt);
	});
}

/* ws's daemons, a row for each rtable each is in, configured or running */
function dtable(ws) {
	var box = document.querySelector(".daemons[data-ws=" + ws + "]");
	var t = box.querySelector("table"), head = el("tr"), n = 0;
	var c = dchosen[ws];

	t.textContent = "";
	["", "Daemon", "What", "Rtable", "Configured", "Rules",
	    "Observed"].forEach(function (h) {
		head.appendChild(el("th", h));
	});
	t.appendChild(head);
	DAEMONS.filter(function (d) {
		return d.ws === ws;
	}).forEach(function (d) {
		var rts = [0];

		Object.keys(dconf).concat(dfacts.map(function (r) {
			return r.daemon + " " + r.rtable;
		})).forEach(function (k) {
			var w = k.split(" "), rt = Number(w[1]);

			if (w[0] === d.name && rts.indexOf(rt) === -1)
				rts.push(rt);
		});
		rts.sort(function (a, b) {
			return a - b;
		}).forEach(function (rt) {
			var cf = dconf[d.name + " " + rt] || {};
			var ob = running(d.name, rt), tr = el("tr", null, c &&
			    c.name === d.name && c.rt === rt ? "sel" : "");
			var led = el("td");

			led.appendChild(el("i", null, "led " + (ob[1] ||
			    (cf.enabled ? "warn" : ""))));
			tr.appendChild(led);
			tr.appendChild(el("td", d.name, "mono"));
			tr.appendChild(el("td", d.label, "descr"));
			tr.appendChild(el("td", String(rt), "num"));
			tr.appendChild(el("td", cf.enabled ? "enabled" : ""));
			tr.appendChild(cf.rules ? el("td", cf.rules.length +
			    (cf.rules.length === 1 ? " line" : " lines")) :
			    el("td", d.runs ? d.runs.split(" ").slice(1).join(
			    " ") : "", "mono dim"));
			tr.appendChild(el("td", ob[0]));
			tr.addEventListener("click", function () {
				dchosen[ws] = { name: d.name, rt: rt };
				dtable(ws);
				dinspect(ws, d.name, rt);
			});
			t.appendChild(tr);
			n++;
		});
	});
	box.querySelector(".count").textContent = candidate() ?
	    "candidate" : "running";
}

/*
 * name's rules and state in rt, inspected: the candidate's rules, asked
 * of nshd, in configure; else what runs has
 */
function dinspect(ws, name, rt) {
	var d = daemonDef(name), cf = dconf[name + " " + rt] || {};
	var p = Promise.resolve({ ok: true, output: cf.rules && cf.rules.length ?
	    cf.rules.join("\n") + "\n" : "" });

	if (d.rules && candidate())
		p = ask("GET", "rules", { daemon: name, rtable: rt });
	return p.then(function (j) {
		var was = { enabled: !!cf.enabled, rules: j.ok ? said(j) : "" };

		dinsp = { ws: ws, def: d, rt: rt, was: was,
		    now: { enabled: was.enabled, rules: was.rules },
		    from: candidate() ? "candidate" : "running",
		    results: j.ok ? [] : [{ line: name + " rules", ok: false,
		    out: said(j) }], open: dinsp && dinsp.def === d ?
		    dinsp.open : {} };
		dinspector();
	});
}

/* text's lines, its last newline or not */
function textLines(t) {
	return t === "" ? [] : t.replace(/\n$/, "").split("\n");
}

/* lines of text, as a count of those added and taken away */
function linesChanged(was, now) {
	var a = textLines(was), b = textLines(now), add = 0, del = 0;
	var left = {};

	a.forEach(function (l) {
		left[l] = (left[l] || 0) + 1;
	});
	b.forEach(function (l) {
		if (left[l])
			left[l]--;
		else
			add++;
	});
	Object.keys(left).forEach(function (l) {
		del += left[l];
	});
	return [add, del];
}

/* a group of the inspector's, open if it was, or if open */
function dgroup(box, name, open) {
	var det = el("details", null, "igroup"), sum = el("summary");

	det.open = dinsp.open[name] !== undefined ? dinsp.open[name] : open;
	det.addEventListener("toggle", function () {
		dinsp.open[name] = det.open;
	});
	sum.appendChild(el("span", name));
	sum.appendChild(el("span", null, "dim count"));
	det.appendChild(sum);
	box.appendChild(det);
	return det;
}

/* the inspector of the daemon chosen, drawn again */
function dinspector() {
	var d = dinsp.def, box = document.querySelector(".daemons[data-ws=" +
	    dinsp.ws + "] .dinsp");
	var head = el("div", null, "ihead"), ob = running(d.name, dinsp.rt);
	var det, row, input, area, out, form, line, bar = el("div", null, "bar");
	var revert = el("button", "Revert"), check = el("button", "Validate");
	var stage = el("button", "Stage", "primary");

	box.textContent = "";
	head.appendChild(el("i", null, "led " + ob[1]));
	head.appendChild(el("h2", d.name, "iname"));
	head.appendChild(el("span", [d.label, d.rt ? "rtable " + dinsp.rt :
	    "", ob[0]].filter(Boolean).join(" · "), "dim"));
	box.appendChild(head);
	box.appendChild(el("p", dinsp.from, "dim from"));

	det = dgroup(box, "Essentials", true);
	if (d.enable) {
		input = el("input");
		input.type = "checkbox";
		input.checked = dinsp.now.enabled;
		row = regField(det, "daemon.enable", input, d.name + " enable");
		row.classList.toggle("edited", dinsp.now.enabled !==
		    dinsp.was.enabled);
		input.addEventListener("change", function () {
			dinsp.now.enabled = input.checked;
			dinspector();
		});
	}
	if (d.rt) {
		input = el("input", null, "mono");
		input.type = "number";
		input.min = 0;
		input.max = 255;
		input.value = dinsp.rt;
		regField(det, "daemon.rtable", input);
		input.addEventListener("change", function () {
			var rt = Number(input.value);

			if (rt >= 0 && rt <= 255 && Math.floor(rt) === rt) {
				dchosen[dinsp.ws] = { name: d.name, rt: rt };
				dtable(dinsp.ws);
				dinspect(dinsp.ws, d.name, rt);
			}
		});
	}

	if (d.rules) {
		det = dgroup(box, "Rules", true);
		dinsp.count = det.querySelector(".count");
		area = el("textarea", null, "rules");
		area.value = dinsp.now.rules;
		area.spellcheck = false;
		area.setAttribute("aria-label", d.name + "'s rules");
		area.classList.toggle("edited", dinsp.now.rules !==
		    dinsp.was.rules);
		det.appendChild(area);
		det.appendChild(el("p", "Stage puts them in the candidate; " +
		    "Validate tests them.", "help"));
		area.addEventListener("input", function () {
			dinsp.now.rules = area.value;
			area.classList.toggle("edited", area.value !==
			    dinsp.was.rules);
			drefresh();
			structuredLater();
		});
	} else if (d.runs) {
		det = dgroup(box, "Command", true);
		det.appendChild(el("pre", d.runs, "cmd"));
		row = el("dl", null, "args");
		d.args.forEach(function (a) {
			row.appendChild(el("dt", a[0], "mono"));
			row.appendChild(el("dd", a[1]));
		});
		if (d.args.length)
			det.appendChild(row);
		det.appendChild(el("p", "No rules. nsh starts it with this " +
		    "command, which cannot be changed." + (d.note ? " " +
		    d.note : ""), "help"));
	}

	if (d.ops.length) {
		det = dgroup(box, "Live operations", false);
		row = el("div", null, "bar");
		row.appendChild(el("span", "Live operation", "tag warn"));
		d.ops.forEach(function (o) {
			var b = el("button", o, "preset");

			b.type = "button";
			b.addEventListener("click", function () {
				line.value = d.name + " " + o + " ";
				line.focus();
			});
			row.appendChild(b);
		});
		det.appendChild(row);
		det.appendChild(el("p", "On the running " + d.name + ", not " +
		    "the candidate. Needs operate.", "help"));
		form = el("form", null, "cliline");
		form.appendChild(el("span", "op>"));
		line = el("input", null, "cli");
		line.setAttribute("aria-label", "Operation");
		line.autocomplete = "off";
		line.spellcheck = false;
		line.placeholder = "Tab completes, ? lists";
		form.appendChild(line);
		form.appendChild(el("button", "Run…"));
		det.appendChild(form);
		out = det.appendChild(el("pre", null, "term"));
		form.addEventListener("submit", function (e) {
			e.preventDefault();
			closeChoices();
			operate(line.value.trim(), String(dinsp.rt), out);
		});
	}

	dinsp.results.forEach(function (x) {
		box.appendChild(el("div", (x.ok ? "✓ " : "✗ ") + x.line +
		    (x.out ? " — " + x.out.trim() : ""), "result " +
		    (x.ok ? "ok" : "bad")));
	});
	revert.type = check.type = stage.type = "button";
	revert.addEventListener("click", function () {
		dinsp.now = { enabled: dinsp.was.enabled, rules: dinsp.was.rules };
		dinsp.results = [];
		dinspector();
	});
	check.title = "commit check: tests the candidate, and commits nothing";
	check.disabled = !candidate();
	check.addEventListener("click", function () {
		configure("commit", { check: "1" }, "commit check").then(
		    function (j) {
			dinsp.results = [{ line: "commit check", ok: j.ok,
			    out: said(j) }];
			dinspector();
		});
	});
	stage.addEventListener("click", dstage);
	bar.appendChild(revert);
	bar.appendChild(check);
	bar.appendChild(stage);
	box.appendChild(bar);
	dinsp.revert = revert;
	dinsp.stage = stage;
	drefresh();
	structured();
}

/* what follows from the edits: the count of lines, and the buttons */
function drefresh() {
	var c = linesChanged(dinsp.was.rules, dinsp.now.rules);
	var edited = dinsp.now.enabled !== dinsp.was.enabled ||
	    dinsp.now.rules !== dinsp.was.rules;

	if (dinsp.def.rules)
		dinsp.count.textContent = c[0] + c[1] ? "+" + c[0] + " −" +
		    c[1] + " lines" : "";
	dinsp.revert.disabled = dinsp.stage.disabled = !edited;
}

/*
 * the edits, into the candidate, entering configure private if not in
 * configure: whether it is enabled, as nsh's line, in its rtable's mode;
 * its rules, as its edit in nsh sets them; then it again, with how each
 * went
 */
function dstage() {
	var d = dinsp.def, rt = dinsp.rt, ws = dinsp.ws, results = [];
	var lines = [], text = dinsp.now.rules, p = Promise.resolve();

	if (dinsp.now.enabled !== dinsp.was.enabled)
		lines.push(d.name + (dinsp.now.enabled ? " enable" :
		    " disable"));
	if (!cur || cur.mode === 0)
		p = configure("configure", { mode: "private" },
		    "configure private");
	/* an rtable's block, which its rules need too */
	if (rt !== 0)
		lines = ["rtable " + rt].concat(lines, ["exit"]);
	lines.forEach(function (l) {
		p = p.then(function () {
			return configure("line", { line: l },
			    $("prompt").textContent + " " + l);
		}).then(function (j) {
			if (!/^(rtable \d+|exit)$/.test(l))
				results.push({ line: l, ok: j.ok, out: said(j) });
		});
	});
	if (text !== dinsp.was.rules)
		p = p.then(function () {
			return ask("POST", "setrules", { daemon: d.name,
			    rtable: rt, text: text });
		}).then(function (j) {
			var n = textLines(text).length, what = d.name + " rules, " + n + (n === 1 ?
			    " line" : " lines") + (rt ? ", rtable " + rt : "");

			transcript("! " + what, j);
			results.push({ line: what, ok: j.ok, out: said(j) });
		});
	return p.then(function () {
		changes(cur && cur.mode !== 0);
		return daemons(ws);
	}).then(function () {
		dinsp.results = results;
		dinspector();
	});
}
