/*
 * stats.js: what the counters nshd sends say of now. An interface's
 * rates are the difference between two looks at show interface, kept
 * for a few minutes and drawn as a small graph, and in the tray as a
 * larger one; its errors are marked when they rose. pf's states and
 * rates, from show kernel pf, are on a readout in Security, as the
 * Overview's. All of it is kept in this page alone, and is gone with it
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

/* each rate kept: the counter it is of, and what one counted is worth */
var RATE_OF = {
	ibps: ["input-bytes", 8], obps: ["output-bytes", 8],
	ipps: ["input-packets", 1], opps: ["output-packets", 1],
	ierrs: ["input-errors", 1], oerrs: ["output-errors", 1],
	idrops: ["input-drops", 1], colls: ["collisions", 1]
};

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
 * milliseconds: each one's rates since the look before, a second, with
 * when, added to what is kept of it. An interface whose counter fell
 * was made again, and has no rate for this look
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
			s.rate = { t: now };
			Object.keys(RATE_OF).forEach(function (k) {
				var n = RATE_OF[k][0];

				s.rate[k] = (c[n] - p.c[n]) * RATE_OF[k][1] / dt;
			});
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

/*
 * The tray's graph: an interface's rates kept, of the choice of GRAPHS
 * chosen, over the last five minutes, the newest look at its right.
 * Pointed at, or chosen and moved with the arrow keys, it says each of
 * its rates at a look. Its plot and its tip are made once, so that a
 * look draws the lines again and leaves the graph chosen as it was
 */
var GRAPHS = [
	{ name: "Throughput", unit: "bit/s", lines: [["In", "ibps"],
	    ["Out", "obps"]] },
	{ name: "Packets", unit: "packets/s", lines: [["In", "ipps"],
	    ["Out", "opps"]] },
	{ name: "Errors", unit: "errors/s", lines: [["In", "ierrs"],
	    ["Out", "oerrs"]] },
	{ name: "Drops", unit: "drops/s", lines: [["In", "idrops"]] },
	{ name: "Collisions", unit: "collisions/s", lines: [["Collisions",
	    "colls"]] }
];
var SPAN = KEPT * LOOK;	/* the time the graph spans, ms */
var graphOf = 0;	/* the choice of GRAPHS shown */
var graphX = null;	/* where the graph is pointed at, or null */
var graphAt = null;	/* what it drew last: its looks, where, and more */
var graphSize = null;	/* its plot's size, watched */

/*
 * n, a rate of graph g, as text: a few figures, with no ".0", and with
 * unit, its unit
 */
function graphFigure(n, g, unit) {
	var s = n > 0 && n < 10 ? [String(Number(n.toPrecision(2))), ""] :
	    scaled(n);

	s[0] = s[0].replace(/\.0$/, "");

	if (!unit)
		return s[0] + s[1];
	return g.unit === "bit/s" ? s[0] + " " + s[1] + g.unit : s[0] + s[1] +
	    " " + g.unit;
}

/* a scale for rates up to max: a round top, and the step of its rules */
function graphScale(max) {
	var e, f, step;

	if (!(max > 0))
		return { top: 1, step: 1 };
	e = Math.pow(10, Math.floor(Math.log10(max / 4)));
	f = max / 4 / e;
	step = (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * e;
	return { top: Math.ceil(max / step - 1e-9) * step, step: step };
}

/*
 * A path through pts, [x, y] by rising x: straight between two, and
 * through more a curve that rises or falls only where they do, so that
 * it never shows a rate no look counted (d3's monotone curve, Steffen's
 * slopes)
 */
function graphPath(pts) {
	var n = pts.length, t = [], d, i, h0, h1, s0, s1;
	var at = function (p) {
		return p[0].toFixed(1) + "," + p[1].toFixed(1);
	};
	var sign = function (x) {
		return x < 0 ? -1 : 1;
	};

	if (n < 3)
		return n ? "M" + pts.map(at).join("L") : "";
	for (i = 1; i < n - 1; i++) {
		h0 = pts[i][0] - pts[i - 1][0];
		h1 = pts[i + 1][0] - pts[i][0];
		s0 = (pts[i][1] - pts[i - 1][1]) / h0;
		s1 = (pts[i + 1][1] - pts[i][1]) / h1;
		t[i] = (sign(s0) + sign(s1)) * Math.min(Math.abs(s0),
		    Math.abs(s1), .5 * Math.abs((s0 * h1 + s1 * h0) /
		    (h0 + h1))) || 0;
	}
	t[0] = (3 * (pts[1][1] - pts[0][1]) / (pts[1][0] - pts[0][0]) - t[1]) /
	    2;
	t[n - 1] = (3 * (pts[n - 1][1] - pts[n - 2][1]) / (pts[n - 1][0] -
	    pts[n - 2][0]) - t[n - 2]) / 2;
	d = "M" + at(pts[0]);
	for (i = 1; i < n; i++) {
		h0 = (pts[i][0] - pts[i - 1][0]) / 3;
		d += "C" + at([pts[i - 1][0] + h0, pts[i - 1][1] + h0 *
		    t[i - 1]]) + " " + at([pts[i][0] - h0, pts[i][1] - h0 *
		    t[i]]) + " " + at(pts[i]);
	}
	return d;
}

/* a time of day, as hours, minutes and seconds */
function graphClock(t) {
	var d = new Date(t);

	return [d.getHours(), d.getMinutes(), d.getSeconds()].map(
	    function (n) {
		return String(n).padStart(2, "0");
	}).join(":");
}

/*
 * The tray's graph for interface name, made in into: the choice of what
 * it shows, the keys of its lines with their newest rates, and its plot
 */
function graphMake(into, name) {
	var box = el("div", null, "graph"), bar = el("div", null, "graph-bar");
	var seg = el("div", null, "seg"), plot = el("div", null, "plot");
	var chart = svg("svg", { role: "img", tabindex: "0" });

	seg.setAttribute("role", "radiogroup");
	seg.setAttribute("aria-label", "What the graph shows");
	GRAPHS.forEach(function (g, i) {
		var l = el("label"), r = el("input");

		r.type = "radio";
		r.name = "graph";
		r.value = String(i);
		r.checked = i === graphOf;
		l.appendChild(r);
		l.appendChild(el("span", g.name));
		seg.appendChild(l);
	});
	seg.addEventListener("change", function (e) {
		graphOf = Number(e.target.value);
		graphDraw();
	});
	bar.appendChild(seg);
	bar.appendChild(el("span", null, "keys"));
	plot.dataset.name = name;
	plot.id = "graph-plot";
	plot.appendChild(chart);
	plot.appendChild(el("div", null, "tip")).hidden = true;
	plot.addEventListener("pointermove", function (e) {
		graphX = e.clientX - plot.getBoundingClientRect().left;
		graphPoint();
	});
	plot.addEventListener("pointerleave", function () {
		graphX = null;
		graphPoint();
	});
	chart.addEventListener("focus", function () {
		if (graphX === null && graphAt !== null &&
		    graphAt.looks.length)
			graphX = graphAt.looks[graphAt.looks.length - 1].x;
		graphPoint();
	});
	chart.addEventListener("blur", function () {
		graphX = null;
		graphPoint();
	});
	chart.addEventListener("keydown", function (e) {
		var i = graphNearest(), last;

		if (i === -1 || ["ArrowLeft", "ArrowRight", "Home",
		    "End"].indexOf(e.key) === -1)
			return;
		last = graphAt.looks.length - 1;
		i = e.key === "Home" ? 0 : e.key === "End" ? last :
		    Math.max(0, Math.min(last, i + (e.key === "ArrowLeft" ?
		    -1 : 1)));
		graphX = graphAt.looks[i].x;
		graphPoint();
		e.preventDefault();
	});
	box.appendChild(bar);
	box.appendChild(plot);
	into.appendChild(box);
	if (graphSize !== null)
		graphSize.disconnect();
	graphSize = new ResizeObserver(function () {
		graphDraw();
	});
	graphSize.observe(plot);
	graphX = null;
	graphAt = null;
}

/* the look graphX is nearest, of those drawn, or -1 */
function graphNearest() {
	var best = -1;

	if (graphX === null || graphAt === null)
		return -1;
	graphAt.looks.forEach(function (p, i) {
		if (best === -1 || Math.abs(p.x - graphX) <
		    Math.abs(graphAt.looks[best].x - graphX))
			best = i;
	});
	return best;
}

/*
 * The tray's graph drawn again, from its interface's rates kept: a rule
 * for each step of its scale, the minutes, and a line for each of its
 * rates, over a wash of its color, ending in a dot at the newest look
 */
function graphDraw() {
	var plot = $("graph-plot"), g = GRAPHS[graphOf], s, keys, chart;
	var rem, w, h, l, r, top, foot, sc, max = 0, looks = [], first, end;
	var x, y, v, k, defs, clip, lines, label;

	if (plot === null)
		return;
	s = seen[plot.dataset.name];
	keys = plot.parentNode.querySelector(".keys");
	chart = plot.querySelector("svg");
	rem = parseFloat(getComputedStyle(document.documentElement).fontSize);
	w = plot.clientWidth;
	h = plot.clientHeight;
	/* a tray not yet shown has no size: it is drawn once it is shown */
	if (!w || !h)
		return;
	l = 3.6923 * rem;
	r = .9231 * rem;
	top = .6154 * rem;
	foot = h - 1.6923 * rem;
	if (s && s.hist.length) {
		end = s.hist[s.hist.length - 1].t;
		first = s.hist.findIndex(function (e) {
			return e.t >= end - SPAN;
		});
		looks = s.hist.slice(Math.max(0, first - 1));
	}
	looks.forEach(function (e) {
		g.lines.forEach(function (ln) {
			max = Math.max(max, e[ln[1]]);
		});
	});
	sc = graphScale(max);
	x = function (t) {
		return l + (t - end + SPAN) / SPAN * (w - l - r);
	};
	y = function (n) {
		return top + (1 - n / sc.top) * (foot - top);
	};
	chart.textContent = "";
	chart.setAttribute("viewBox", "0 0 " + w + " " + h);
	defs = chart.appendChild(svg("defs", {}));
	["in", "out"].forEach(function (c) {
		var wash = defs.appendChild(svg("linearGradient", {
		    id: "graph-" + c, x1: 0, y1: 0, x2: 0, y2: 1 }));

		wash.appendChild(svg("stop", { offset: 0, "class": c,
		    "stop-opacity": .16 }));
		wash.appendChild(svg("stop", { offset: 1, "class": c,
		    "stop-opacity": 0 }));
	});
	clip = defs.appendChild(svg("clipPath", { id: "graph-clip" }));
	clip.appendChild(svg("rect", { x: l, y: top - 2, width: w - l - r,
	    height: foot - top + 4 }));

	/* the scale's rules, and their rates */
	for (k = 0; k * sc.step <= sc.top * (1 + 1e-9) && looks.length; k++) {
		v = Math.round(y(k * sc.step)) + .5;
		chart.appendChild(svg("line", { x1: l, x2: w - r, y1: v, y2: v,
		    "class": "rule" }));
		chart.appendChild(svg("text", { x: l - .4615 * rem, y: v +
		    .3077 * rem, "class": "tick", "text-anchor": "end" }))
		    .textContent = graphFigure(k * sc.step, g, false);
	}
	/* a minute's rule, each minute back from the newest look */
	for (k = 1; k * 60000 < SPAN && looks.length; k++) {
		v = Math.round(x(end - k * 60000)) + .5;
		chart.appendChild(svg("line", { x1: v, x2: v, y1: top, y2: foot,
		    "class": "rule minute" }));
	}
	chart.appendChild(svg("text", { x: l, y: h - .3846 * rem,
	    "class": "tick" })).textContent = Math.round(SPAN / 60000) +
	    " min ago";
	chart.appendChild(svg("text", { x: w - r, y: h - .3846 * rem,
	    "class": "tick", "text-anchor": "end" })).textContent = "now";
	if (!looks.length) {
		chart.appendChild(svg("line", { x1: l, x2: w - r, y1: foot + .5,
		    y2: foot + .5, "class": "rule" }));
		chart.appendChild(svg("text", { x: (l + w - r) / 2, y: (top +
		    foot) / 2, "class": "empty", "text-anchor": "middle" }))
		    .textContent = s ? "Rates come with the next look." :
		    plot.dataset.name + " has no counters.";
	}

	/* each rate's wash, and then its line, the first rate's last */
	lines = g.lines.map(function (ln, i) {
		return { label: ln[0], key: ln[1], c: i ? "out" : "in",
		    pts: looks.map(function (e) {
			return [x(e.t), y(e[ln[1]])];
		}) };
	}).reverse();
	k = chart.appendChild(svg("g", { "clip-path": "url(#graph-clip)" }));
	lines.forEach(function (ln) {
		if (ln.pts.length > 1)
			k.appendChild(svg("path", { d: graphPath(ln.pts) + "L" +
			    ln.pts[ln.pts.length - 1][0].toFixed(1) + "," +
			    foot + "L" + ln.pts[0][0].toFixed(1) + "," + foot +
			    "Z", fill: "url(#graph-" + ln.c + ")" }));
	});
	lines.forEach(function (ln) {
		k.appendChild(svg("path", { d: graphPath(ln.pts),
		    "class": "line " + ln.c }));
	});
	lines.forEach(function (ln) {
		var p = ln.pts[ln.pts.length - 1];

		if (p)
			chart.appendChild(svg("circle", { cx: p[0], cy: p[1],
			    r: 4, "class": "dot " + ln.c }));
	});
	lines.reverse();

	/* where it is pointed at: a hairline, and a dot on each line */
	k = chart.appendChild(svg("g", { "class": "cross",
	    visibility: "hidden" }));
	k.appendChild(svg("line", { y1: top, y2: foot }));
	lines.forEach(function (ln) {
		k.appendChild(svg("circle", { r: 4, "class": "dot " + ln.c }));
	});

	/* the keys, each with its newest rate */
	keys.textContent = "";
	lines.forEach(function (ln) {
		var key = keys.appendChild(el("span"));
		var e = looks[looks.length - 1];

		key.appendChild(el("i", null, ln.c));
		key.appendChild(document.createTextNode(ln.label));
		key.appendChild(el("b", e ? graphFigure(e[ln.key], g, true) :
		    "–"));
	});
	label = plot.dataset.name + ", " + g.name.toLowerCase() +
	    " over the last " + Math.round(SPAN / 60000) + " minutes";
	chart.setAttribute("aria-label", looks.length ? label + ": " +
	    lines.map(function (ln) {
		return ln.label + " " + graphFigure(looks[looks.length - 1][
		    ln.key], g, true) + " now, at most " + graphFigure(Math.max.
		    apply(null, looks.map(function (e) {
			return e[ln.key];
		})), g, true);
	}).join("; ") : label + ": none yet");
	/* the looks drawn: the one before the five minutes is not */
	graphAt = { g: g, lines: lines, looks: looks.map(function (e) {
		return { t: e.t, x: x(e.t), e: e };
	}).filter(function (p) {
		return p.x >= l;
	}), y: y, top: top };
	graphPoint();
}

/*
 * The look the graph is pointed at, if it is: a hairline at it, a dot
 * where each line crosses it, and in a tip, when it was and its rates
 */
function graphPoint() {
	var plot = $("graph-plot"), i = graphNearest(), cross, tip, p, row;

	if (plot === null)
		return;
	cross = plot.querySelector(".cross");
	tip = plot.querySelector(".tip");
	if (cross === null)
		return;
	if (i === -1) {
		cross.setAttribute("visibility", "hidden");
		tip.hidden = true;
		return;
	}
	p = graphAt.looks[i];
	cross.firstChild.setAttribute("x1", Math.round(p.x) + .5);
	cross.firstChild.setAttribute("x2", Math.round(p.x) + .5);
	graphAt.lines.forEach(function (ln, j) {
		var dot = cross.childNodes[j + 1];

		dot.setAttribute("cx", p.x);
		dot.setAttribute("cy", graphAt.y(p.e[ln.key]));
	});
	cross.setAttribute("visibility", "visible");
	tip.textContent = "";
	tip.appendChild(el("div", graphClock(p.t), "when"));
	graphAt.lines.forEach(function (ln) {
		row = tip.appendChild(el("div"));
		row.appendChild(el("i", null, ln.c));
		row.appendChild(el("b", graphFigure(p.e[ln.key], graphAt.g,
		    true)));
		row.appendChild(document.createTextNode(ln.label));
	});
	tip.hidden = false;
	tip.style.top = graphAt.top + "px";
	tip.style.left = (p.x + 12 + tip.offsetWidth > plot.clientWidth ?
	    p.x - 12 - tip.offsetWidth : p.x + 12) + "px";
}

/* how full r's line is, 0 to 1, by the busier direction, or -1 */
function utilisation(r) {
	var s = seen[r.name], line = Number(r["line-rate"] || 0);

	if (!s || !s.rate || line === 0)
		return -1;
	return Math.min(1, Math.max(s.rate.ibps, s.rate.obps) / line);
}

/*
 * pf's panel, the readout's kind, from show kernel pf: its states
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
	return ask("GET", "show", { words: "kernel pf" }).then(
	    function (j) {
		var r = of(j, "pf_stats");

		if (r.length)
			pfDraw(r[0], Date.now());
		else
			$("pf-meter").hidden = true;
	});
}

/* pf's panel looks while Security is shown (app.js's workspace()) */
function pfWatch(shown) {
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
