/*
 * inspector.js: an interface's settings, in Network: each as the
 * configuration nshd has it, the candidate's in configure, else what
 * runs; and what was changed, as nsh's lines, staged into the candidate,
 * entering configure private first if not in configure
 */
"use strict";

var insp = null;	/* the interface inspected, its settings, and edits */

function isBridge(name) {
	return ["bridge", "veb", "tpmr"].indexOf(driver(name)) !== -1;
}

/* a setting's value, when the configuration says nothing of it */
function unset(d) {
	if (d.kind === "flag")
		return false;
	if (d.kind === "noflag" || d.kind === "down")
		return true;
	if (d.kind === "words" || d.kind === "lines")
		return [];
	return "";
}

/* the lines of name's block in text, a configuration, each trimmed */
function block(text, head) {
	var out = [], inside = false;

	text.split("\n").forEach(function (l) {
		if (l === head)
			inside = true;
		else if (inside && /^\s/.test(l))
			out.push(l.trim());
		else
			inside = false;
	});
	return out;
}

/* the settings, as lines of a block say them */
function settings(lines, defs) {
	var v = {};

	defs.forEach(function (d) {
		v[d.key] = unset(d);
	});
	lines.forEach(function (l) {
		var no = l.indexOf("no ") === 0;
		var w = (no ? l.slice(3) : l).split(/\s+/);
		var d = defs.find(function (x) {
			return x.key === w[0];
		});

		if (!d)
			return;
		if (d.kind === "flag" || d.kind === "noflag")
			v[d.key] = !no;
		else if (d.kind === "down")
			v[d.key] = no;
		else if (no)
			v[d.key] = unset(d);
		else if (d.kind === "words")
			v[d.key] = v[d.key].concat(w.slice(1));
		else if (d.kind === "lines")
			v[d.key] = v[d.key].concat([w.slice(1).join(" ")]);
		else
			v[d.key] = w.slice(1).join(" ");
	});
	return v;
}

/* nsh's lines that make was now; a routing domain's first, as it clears */
function edits(defs, was, now) {
	var out = [];

	defs.forEach(function (d) {
		var a = was[d.key], b = now[d.key], k = d.key, lines = [];

		if (d.kind === "flag" || d.kind === "noflag") {
			if (a !== b)
				lines.push((b ? "" : "no ") + k);
		} else if (d.kind === "down") {
			if (a !== b)
				lines.push(b ? "no shutdown" : "shutdown");
		} else if (d.kind === "words" || d.kind === "lines") {
			a.forEach(function (x) {
				if (b.indexOf(x) === -1)
					lines.push("no " + k + " " + x);
			});
			b.forEach(function (x) {
				if (a.indexOf(x) === -1)
					lines.push(k + " " + x);
			});
		} else if (a !== b)
			lines.push(b === "" ? "no " + k : k + " " + b);
		if (k === "rdomain")
			out = lines.concat(out);
		else
			out = out.concat(lines);
	});
	return out;
}

function same(a, b) {
	return JSON.stringify(a) === JSON.stringify(b);
}

/* is d one for r, the interface: unless every setting is asked for */
function applies(d, r) {
	if (insp.every || !same(insp.was[d.key], unset(d)))
		return true;
	if (d.physical && PSEUDO.indexOf(driver(r.name)) !== -1)
		return false;
	if (d.wireless && r.type !== "IEEE 802.11")
		return false;
	return !d.on || d.on.indexOf(driver(r.name)) !== -1;
}

/* name's settings, as the configuration has them, inspected */
function inspect(name) {
	var inConfigure = cur && cur.mode !== 0;
	var bridge = isBridge(name);

	return ask("GET", "config", { what: inConfigure ? "candidate" :
	    "running" }).then(function (j) {
		var defs = bridge ? BRDEFS : IFDEFS;
		var lines = block(said(j), (bridge ? "bridge " : "interface ") +
		    name);
		var was = settings(lines, defs);

		insp = { name: name, bridge: bridge, defs: defs, was: was,
		    now: JSON.parse(JSON.stringify(was)),
		    every: insp && insp.every, from: inConfigure ?
		    "candidate" : "running", results: [] };
		inspector();
	});
}

/*
 * a setting's control, which keeps insp.now as it changes: a value's
 * control changes what follows from it, and a list's draws the
 * inspector again
 */
function control(d) {
	var v = insp.now[d.key], box, input, add;

	if (d.kind === "flag" || d.kind === "noflag" || d.kind === "down") {
		input = el("input");
		input.type = "checkbox";
		input.checked = v;
		input.addEventListener("change", function () {
			insp.now[d.key] = input.checked;
			refresh();
		});
		return input;
	}
	if (d.kind === "choice") {
		input = el("select");
		[""].concat(d.choices).forEach(function (c) {
			var o = el("option", c === "" ? "(not set)" : c);

			o.value = c;
			input.appendChild(o);
		});
		input.value = v;
		input.addEventListener("change", function () {
			insp.now[d.key] = input.value;
			refresh();
		});
		return input;
	}
	if (d.kind === "words" || d.kind === "lines") {
		box = el("div", null, d.kind === "words" ? "chips" : "rows");
		v.forEach(function (x, i) {
			var c = el("span", null, "chip"), rm = el("button", "×");

			c.appendChild(el("span", x, "mono"));
			rm.type = "button";
			rm.title = "Take away";
			rm.setAttribute("aria-label", "Take away " + x);
			rm.addEventListener("click", function () {
				insp.now[d.key] = v.slice(0, i).concat(v.slice(i + 1));
				inspector();
			});
			c.appendChild(rm);
			box.appendChild(c);
		});
		input = el("input", null, "mono add");
		input.placeholder = d.placeholder || "add";
		input.setAttribute("aria-label", "Add to " + d.label);
		add = function (again) {
			var t = input.value.trim(), more;

			if (t === "")
				return;
			/* emptied, as drawing again takes it away, which is a change */
			input.value = "";
			more = d.kind === "words" ? t.split(/\s+/) : [t];
			insp.now[d.key] = v.concat(more.filter(function (x) {
				return v.indexOf(x) === -1;
			}));
			inspector(again ? d.key : null);
		};
		input.addEventListener("keydown", function (e) {
			if (e.key === "Enter") {
				e.preventDefault();
				add(true);
			}
		});
		input.addEventListener("change", function () {
			add(false);
		});
		box.appendChild(input);
		return box;
	}
	input = el("input", null, "mono");
	if (d.kind === "number") {
		input.type = "number";
		input.min = d.min;
		input.max = d.max;
	}
	input.value = v;
	input.placeholder = d.placeholder || "not set";
	input.addEventListener("input", function () {
		insp.now[d.key] = input.value.trim();
		refresh();
	});
	return input;
}

/* what follows from the settings as they are now: marks, counts, lines */
function refresh() {
	var lines = edits(insp.defs, insp.was, insp.now);

	insp.defs.forEach(function (d) {
		if (insp.rows[d.key])
			insp.rows[d.key].classList.toggle("edited",
			    !same(insp.now[d.key], insp.was[d.key]));
	});
	Object.keys(insp.counts).forEach(function (g) {
		var set = insp.groups[g].filter(function (d) {
			return !same(insp.now[d.key], unset(d));
		});

		/* what is set shows, folded or not */
		insp.counts[g].textContent = set.length ? set.length +
		    " set: " + set.map(function (d) {
			return d.key;
		}).join(", ") : "";
	});
	insp.stanza.textContent = lines.length ? [(insp.bridge ? "bridge " :
	    "interface ") + insp.name].concat(lines.map(function (l) {
		return " " + l;
	}), ["exit"]).join("\n") : "no changes";
	insp.revert.disabled = insp.stage.disabled = lines.length === 0;
	insp.lines = lines;
}

/* the inspector drawn again; focus kept on key's control, if given */
function inspector(key) {
	var box = $("inspector"), r = ifs.find(function (x) {
		return x.name === insp.name;
	}) || { name: insp.name };
	var head = el("div", null, "ihead"), groups = {}, order = [];
	var every = el("label", null, "dim"), check = el("input");
	var stanza = el("pre", null, "term stanza"), bar = el("div", null, "bar");
	var revert = el("button", "Revert"), stage = el("button", "Stage",
	    "primary"), focus = null;

	insp.rows = {};
	insp.counts = {};
	insp.groups = groups;
	insp.stanza = stanza;
	insp.revert = revert;
	insp.stage = stage;

	box.textContent = "";
	head.appendChild(el("i", null, "led " + (r.flags ? state(r) : "")));
	head.appendChild(el("h2", insp.name, "iname"));
	head.appendChild(el("span", [r.type, r.link, rate(r)].filter(
	    Boolean).join(" · "), "dim"));
	box.appendChild(head);
	check.type = "checkbox";
	check.checked = insp.every;
	check.addEventListener("change", function () {
		insp.every = check.checked;
		inspector();
	});
	every.appendChild(check);
	every.appendChild(document.createTextNode(" every setting"));
	box.appendChild(el("p", insp.from, "dim from"));
	box.appendChild(every);

	insp.defs.forEach(function (d) {
		if (!applies(d, r))
			return;
		if (!groups[d.group]) {
			groups[d.group] = [];
			order.push(d.group);
		}
		groups[d.group].push(d);
	});
	order.forEach(function (g) {
		var det = el("details", null, "igroup"), sum = el("summary");
		var edited = groups[g].some(function (d) {
			return !same(insp.now[d.key], insp.was[d.key]);
		});

		det.open = g === "Essentials" || edited || (insp.open &&
		    insp.open[g]);
		det.addEventListener("toggle", function () {
			insp.open = insp.open || {};
			insp.open[g] = det.open;
		});
		sum.appendChild(el("span", g));
		insp.counts[g] = sum.appendChild(el("span", null, "dim count"));
		det.appendChild(sum);
		groups[g].forEach(function (d) {
			var c = control(d);

			insp.rows[d.key] = regField(det, (insp.bridge ?
			    "bridge." : "if.") + d.key, c);
			if (d.key === key)
				focus = c.querySelector ? c.querySelector(
				    "input.add") : null;
		});
		box.appendChild(det);
	});

	box.appendChild(el("h3", "nsh's lines"));
	box.appendChild(stanza);
	insp.results.forEach(function (x) {
		box.appendChild(el("div", (x.ok ? "✓ " : "✗ ") +
		    x.line + (x.out ? " — " + x.out.trim() : ""),
		    "result " + (x.ok ? "ok" : "bad")));
	});
	revert.type = stage.type = "button";
	revert.addEventListener("click", function () {
		insp.now = JSON.parse(JSON.stringify(insp.was));
		insp.results = [];
		inspector();
	});
	stage.addEventListener("click", function () {
		staged(insp.lines);
	});
	bar.appendChild(revert);
	bar.appendChild(stage);
	box.appendChild(bar);
	refresh();
	if (focus)
		focus.focus();
}

/*
 * lines into the candidate, one at a time, in the interface's mode,
 * entering configure private if not in configure; then the settings again
 */
function staged(lines) {
	var head = (insp.bridge ? "bridge " : "interface ") + insp.name;
	var all = [head].concat(lines, ["exit"]), results = [];
	var p = Promise.resolve();

	if (!cur || cur.mode === 0)
		p = configure("configure", { mode: "private" },
		    "configure private");
	all.forEach(function (l) {
		p = p.then(function () {
			return configure("line", { line: l },
			    $("prompt").textContent + " " + l);
		}).then(function (j) {
			if (l !== head && l !== "exit")
				results.push({ line: l, ok: j.ok,
				    out: said(j) });
		});
	});
	return p.then(function () {
		return inspect(insp.name);
	}).then(function () {
		insp.results = results;
		inspector();
	});
}
