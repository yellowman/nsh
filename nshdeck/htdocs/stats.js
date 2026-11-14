/*
 * stats.js: what the counters nshd sends say of now. An interface's
 * rates are the difference between two looks at show interface, kept
 * for a few minutes and drawn as a small graph; its errors are marked
 * when they rose. pf's states and rates, from show statistics pf, are
 * on a readout in Security, as the Overview's. All of it is kept in
 * this page alone, and is gone with it
 */
"use strict";

var KEPT = 60;		/* an interface's rates kept: five minutes of looks */
var seen = {};		/* each interface's last counters, and its rates */
var pfseen = null;	/* pf's last counters, and when */
var pflooker = null;

var SVG = "http://www.w3.org/2000/svg";

/* an interface's counters that only ever rise */
var COUNTERS = ["input-bytes", "output-bytes", "input-packets",
    "output-packets", "input-errors", "output-errors", "input-drops",
    "collisions"];

function svg(tag, attrs) {
	var e = document.createElementNS(SVG, tag);

	Object.keys(attrs).forEach(function (k) {
		e.setAttribute(k, attrs[k]);
	});
	return e;
}

/* n, in at most four digits, and its unit's letter */
function scaled(n) {
	var units = ["", "k", "M", "G", "T"], i = 0;

	while (n >= 1000 && i < units.length - 1) {
		n /= 1000;
		i++;
	}
	return [n >= 100 || i === 0 ? String(Math.round(n)) : n.toFixed(1),
	    units[i]];
}

/* a rate in bits a second, as text */
function bps(n) {
	var s = scaled(n);

	return s[0] + " " + s[1] + "bit/s";
}

/*
 * The interfaces' counters at a look, list, taken at now, in
 * milliseconds: each one's rates since the look before, added to what
 * is kept of it. An interface whose counter fell was made again, and
 * has no rate for this look
 */
function sampled(list, now) {
	var next = {};

	list.forEach(function (r) {
		var p = seen[r.name], c = {}, s, dt, fell = false;

		COUNTERS.forEach(function (k) {
			c[k] = Number(r[k] || 0);
			if (p && c[k] < p.c[k])
				fell = true;
		});
		s = { c: c, t: now, hist: p && !fell ? p.hist : [],
		    rose: false, rate: null };
		if (p && !fell && now > p.t) {
			dt = (now - p.t) / 1000;
			s.rate = {
			    ibps: (c["input-bytes"] - p.c["input-bytes"]) * 8 /
				dt,
			    obps: (c["output-bytes"] - p.c["output-bytes"]) *
				8 / dt,
			    ipps: (c["input-packets"] -
				p.c["input-packets"]) / dt,
			    opps: (c["output-packets"] -
				p.c["output-packets"]) / dt
			};
			s.rose = c["input-errors"] > p.c["input-errors"] ||
			    c["output-errors"] > p.c["output-errors"] ||
			    c["input-drops"] > p.c["input-drops"];
			s.hist = s.hist.concat([s.rate]).slice(-KEPT);
		}
		next[r.name] = s;
	});
	seen = next;
}

/* name's rates kept, as a graph: in and out, to the larger's scale */
function spark(name) {
	var s = seen[name], w = 72, h = 20, g, max = 1;
	var line = function (key, cls) {
		var pts = s.hist.map(function (x, i) {
			return (w - (s.hist.length - 1 - i) * w / (KEPT - 1))
			    .toFixed(1) + "," + (h - 1 - x[key] / max *
			    (h - 2)).toFixed(1);
		});

		g.appendChild(svg("polyline", { points: pts.join(" "),
		    "class": cls }));
	};

	g = svg("svg", { viewBox: "0 0 " + w + " " + h, "class": "spark",
	    role: "img" });
	if (!s || s.hist.length < 2)
		return g;
	s.hist.forEach(function (x) {
		max = Math.max(max, x.ibps, x.obps);
	});
	g.appendChild(svg("title", {})).textContent = name + ": the last " +
	    Math.round(s.hist.length * LOOK / 60000) + " minutes, at most " +
	    bps(max);
	line("ibps", "in");
	line("obps", "out");
	return g;
}

/* the cells of name's row that say its traffic and its errors */
function rateCells(tr, name) {
	var s = seen[name], graph = el("td", null, "graph"), bad;
	var errors = s ? s.c["input-errors"] + s.c["output-errors"] : 0;
	var drops = s ? s.c["input-drops"] : 0;

	tr.appendChild(el("td", s && s.rate ? scaled(s.rate.ibps).join("") :
	    "", "num"));
	tr.appendChild(el("td", s && s.rate ? scaled(s.rate.obps).join("") :
	    "", "num"));
	graph.appendChild(spark(name));
	tr.appendChild(graph);
	bad = tr.appendChild(el("td", errors + drops ? String(errors +
	    drops) : "", "num" + (s && s.rose ? " rose" : "")));
	if (s)
		bad.title = s.c["input-errors"] + " input errors, " +
		    s.c["output-errors"] + " output errors, " + drops +
		    " input drops, " + s.c.collisions + " collisions" +
		    (s.rose ? "; rising" : "");
}

/* name's counters, in words, for its port's tray */
function rateLines(name) {
	var s = seen[name], dl = el("dl", null, "counters");
	var row = function (k, v) {
		dl.appendChild(el("dt", k));
		dl.appendChild(el("dd", v));
	};

	if (!s)
		return dl;
	if (s.rate) {
		row("In", bps(s.rate.ibps) + ", " +
		    Math.round(s.rate.ipps) + " packets/s");
		row("Out", bps(s.rate.obps) + ", " +
		    Math.round(s.rate.opps) + " packets/s");
	}
	row("Errors", s.c["input-errors"] + " in, " + s.c["output-errors"] +
	    " out" + (s.rose ? ", rising" : ""));
	row("Drops", s.c["input-drops"] + " in");
	row("Collisions", String(s.c.collisions));
	return dl;
}

/* how full r's line is, 0 to 1, by the busier direction, or -1 */
function utilisation(r) {
	var s = seen[r.name], line = Number(r["line-rate"] || 0);

	if (!s || !s.rate || line === 0)
		return -1;
	return Math.min(1, Math.max(s.rate.ibps, s.rate.obps) / line);
}

/*
 * pf's panel, the readout's kind, from show statistics pf: its states
 * now, and its rates since the look before, which the first look lacks
 */
function pfDraw(r, now) {
	var panel = $("pf-meter"), p = pfseen, dt, c = {};
	var f = function (k) {
		return Number(r["status." + k] || 0);
	};
	var per = function (k, unit) {
		var s;

		if (!p || dt <= 0 || c[k] < p.c[k])
			return "\u2013";
		s = scaled((c[k] - p.c[k]) / dt);
		return s[0] + " " + s[1] + unit;
	};
	var row = function (k, v) {
		panel.appendChild(el("dt", k));
		panel.appendChild(el("dd", v));
	};

	/* packets and bytes: IPv4's and IPv6's, in then out */
	c.searches = f("fcounters[0]");
	c.inserts = f("fcounters[1]");
	c.removals = f("fcounters[2]");
	c.passed = f("pcounters[0][0][0]") + f("pcounters[0][1][0]") +
	    f("pcounters[1][0][0]") + f("pcounters[1][1][0]");
	c.blocked = f("pcounters[0][0][1]") + f("pcounters[0][1][1]") +
	    f("pcounters[1][0][1]") + f("pcounters[1][1][1]");
	c.inbits = (f("bcounters[0][0]") + f("bcounters[1][0]")) * 8;
	c.outbits = (f("bcounters[0][1]") + f("bcounters[1][1]")) * 8;
	dt = p ? (now - p.t) / 1000 : 0;
	panel.textContent = "";
	row("pf", f("running") ? "enabled" : "disabled");
	row("States", String(f("states")));
	row("Searches", per("searches", "/s"));
	row("Inserts", per("inserts", "/s"));
	row("Removals", per("removals", "/s"));
	row("Passed", per("passed", "packets/s"));
	row("Blocked", per("blocked", "packets/s"));
	row("In", per("inbits", "bit/s"));
	row("Out", per("outbits", "bit/s"));
	panel.hidden = false;
	pfseen = { c: c, t: now };
}

/* pf's panel, looked at now; hidden if nshd does not say */
function pfLook() {
	return ask("GET", "show", { words: "statistics pf" }).then(
	    function (j) {
		var r = of(j, "pf_stats");

		if (r.length)
			pfDraw(r[0], Date.now());
		else
			$("pf-meter").hidden = true;
	});
}

/* pf's panel looks while Security is shown (app.js's workspace()) */
function pfShown(shown) {
	clearInterval(pflooker);
	pflooker = null;
	if (!shown)
		return;
	pfseen = null;
	pfLook();
	pflooker = setInterval(function () {
		if (!document.hidden)
			pfLook();
	}, LOOK);
}
