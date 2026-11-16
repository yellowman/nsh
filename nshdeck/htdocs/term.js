/*
 * term.js: terminals, each nsh on a pty, which nshdeck runs for the user
 * logged in (nshdeck(8)'s reserve, open, terminal, type and close), each
 * in a tab of its own. A reservation asks for its channel, and an open
 * of the channel starts its nsh;
 * xterm.js draws it; what nsh writes comes on the channel's event
 * stream, in base64; and what is typed goes, as its bytes, in frames,
 * one at a time, each with its sequence, and the same frame again until
 * nshdeck takes it. A tab keeps all of that its own, and runs on while
 * another is shown
 */
"use strict";

var TFRAME = 750;	/* a frame's bytes, at most */
var tabs = [];		/* the terminals' tabs, in their order */
var tab = null;		/* the tab shown */
var tabsMade = 0;	/* tabs made, which numbers each one's ids */

/* the header: the shown tab's state, and its buttons, which act on it */
function tshow() {
	var t = tab;

	$("term-state").textContent = t === null ? "no terminal" : t.text;
	$("term-led").className = "led " + (t === null ? "off" : t.led);
	$("term-connect").disabled = t === null || t.stream !== null ||
	    t.opening;
	$("term-end").disabled = t === null || t.stream === null;
}

/* tab t's state, in words, and its light */
function tstate(t, text, led) {
	t.text = text;
	t.led = led;
	t.dot.className = "led " + led;
	if (t === tab)
		tshow();
}

/*
 * Tab t's next frame: TFRAME of the bytes typed at most, a character's
 * bytes split between two frames if they come so, and the size, if it
 * changed; one frame at a time, the one after the last one taken
 */
function tsend(t) {
	var b = new Uint8Array(TFRAME), n = 0, k, s = "", i;

	if (t.frame !== null || !t.runs ||
	    (t.typed.length === 0 && t.size === null))
		return;
	while (t.typed.length > 0 && n < TFRAME) {
		k = Math.min(t.typed[0].length, TFRAME - n);
		b.set(t.typed[0].subarray(0, k), n);
		n += k;
		t.typed[0] = t.typed[0].subarray(k);
		if (t.typed[0].length === 0)
			t.typed.shift();
	}
	for (i = 0; i < n; i++)
		s += String.fromCharCode(b[i]);
	t.frame = { channel: t.channel, seq: t.seq + 1, data: btoa(s) };
	if (t.size !== null) {
		t.frame.rows = t.size.rows;
		t.frame.cols = t.size.cols;
		t.size = null;
	}
	tpost(t, t.frame);
}

/*
 * Tab t's frame f, sent; and sent again as it was if nsh has no room for
 * it yet, or if its answer was lost, which nshdeck answers without
 * taking it twice
 */
function tpost(t, f) {
	ask("POST", "type", f).then(function (j) {
		if (t.frame !== f)
			return;
		if (j.ok) {
			t.seq = f.seq;
			t.frame = null;
			tsend(t);
		} else if (j.httpStatus === 503)
			setTimeout(function () {
				if (t.frame === f)
					tpost(t, f);
			}, 250);
		else
			tend(t, j.error || "typed into a terminal gone");
	}, function () {
		setTimeout(function () {
			if (t.frame === f)
				tpost(t, f);
		}, 1000);
	});
}

/* bytes typed in tab t, from xterm.js, to be sent */
function tbytes(t, b) {
	t.typed.push(b);
	tsend(t);
}

/*
 * Request name with fields, asked again as it was, as many as tries
 * times, if its answer was lost: an open asked again is answered as it
 * was and starts nothing, and a reservation whose answer was lost ends
 * unopened
 */
function tretry(name, fields, tries) {
	return ask("POST", name, fields).catch(function (e) {
		if (tries <= 1)
			throw e;
		return tretry(name, fields, tries - 1);
	});
}

/*
 * A new tab, shown, and an nsh opened in it: its terminal, which
 * xterm.js draws in its panel, and its nsh's channel, stream and what is
 * typed into it, which it shares with no other tab
 */
function tnew() {
	var t = { n: ++tabsMade, stream: null, channel: 0, runs: false,
	    opening: false, closed: false, table: null, typed: [],
	    size: null, seq: 0, frame: null, text: "", led: "off" };

	t.tab = document.createElement("span");
	t.tab.className = "ttab";
	t.pick = document.createElement("button");
	t.pick.type = "button";
	t.pick.id = "ttab-" + t.n;
	t.pick.setAttribute("role", "tab");
	t.pick.setAttribute("aria-controls", "tpanel-" + t.n);
	t.dot = document.createElement("span");
	t.name = document.createElement("span");
	t.name.textContent = "nsh";
	t.pick.append(t.dot, t.name);
	t.shut = document.createElement("button");
	t.shut.type = "button";
	t.shut.className = "tclose";
	t.shut.textContent = "×";
	t.shut.setAttribute("aria-label", "Close nsh");
	t.tab.append(t.pick, t.shut);
	$("term-tabs").append(t.tab);
	t.panel = document.createElement("div");
	t.panel.id = "tpanel-" + t.n;
	t.panel.className = "tpanel";
	t.panel.setAttribute("role", "tabpanel");
	t.panel.setAttribute("aria-labelledby", t.pick.id);
	$("term").append(t.panel);
	t.term = new Terminal({ cursorBlink: true, fontSize: termPx(),
	    fontFamily: getComputedStyle(document.body)
	    .getPropertyValue("--mono").trim(), scrollback: 5000,
	    theme: { background: "#0b0d10", foreground: "#d7dce2",
	    cursor: "#4ea1ff", cursorAccent: "#0b0d10",
	    selectionBackground: "#2b4a6f" } });
	t.fit = new FitAddon.FitAddon();
	t.term.loadAddon(t.fit);
	t.term.open(t.panel);
	/* text as UTF-8, a NUL too; and bytes as they are */
	t.term.onData(function (d) {
		tbytes(t, new TextEncoder().encode(d));
	});
	t.term.onBinary(function (d) {
		tbytes(t, Uint8Array.from(d, function (c) {
			return c.charCodeAt(0);
		}));
	});
	t.term.onResize(function (s) {
		t.size = { rows: s.rows, cols: s.cols };
		tsend(t);
	});
	t.pick.addEventListener("click", function () {
		tselect(t);
	});
	t.shut.addEventListener("click", function () {
		tclose(t);
	});
	tabs.push(t);
	tselect(t);
	tconnect(t);
}

/*
 * Tab t shown, the others hidden, or none if t is null: only the tab
 * shown is sized to its box, as it is shown
 */
function tselect(t) {
	tab = t;
	tabs.forEach(function (u) {
		u.panel.hidden = u !== t;
		u.pick.setAttribute("aria-selected", String(u === t));
		u.pick.tabIndex = u === t ? 0 : -1;
	});
	$("term-none").hidden = t !== null;
	if (t !== null && !$("ws-terminal").hidden) {
		tfit(t);
		t.term.focus();
	}
	tshow();
}

/*
 * Tab t, shown, sized to its box, its text the page's size: a hidden tab
 * is sized only once it is shown, and sends no size before
 */
function tfit(t) {
	t.term.options.fontSize = termPx();
	t.fit.fit();
}

/*
 * An nsh in tab t, if none runs or is opening there: a channel reserved,
 * and then opened. Once the channel is reserved, closing the tab closes
 * it, as a refusal does; a tab closed before that closes it when it
 * comes
 */
function tconnect(t) {
	var fields;

	if (t.stream !== null || t.opening)
		return;
	t.channel = 0;
	t.typed = [];
	t.size = null;
	t.seq = 0;
	t.frame = null;
	/* nsh begins in the table the page is focused on, as nsh -T does */
	t.table = table;
	fields = { rows: t.term.rows, cols: t.term.cols };
	if (t.table !== null)
		fields.rtable = t.table;
	t.opening = true;
	tstate(t, "starting nsh", "warn");
	tretry("reserve", {}, 3).then(function (j) {
		if (j.ok && !t.closed) {
			t.channel = fields.channel = j.channel;
			return tretry("open", fields, 3);
		}
		if (j.ok)
			tclosing(j.channel);
		return j;
	}).then(function (j) {
		t.opening = false;
		if (t.closed)
			return;
		if (j.ok)
			tfollow(t, j.channel);
		else {
			if (t.channel !== 0)
				tclosing(t.channel);
			t.channel = 0;
			tstate(t, j.error, "off");
		}
	}, function () {
		t.opening = false;
		if (t.closed)
			return;
		if (t.channel !== 0)
			tclosing(t.channel);
		t.channel = 0;
		tstate(t, "nshdeck did not answer", "off");
	});
}

/* the stream of tab t's terminal, on channel c: what its nsh writes */
function tfollow(t, c) {
	var s = new EventSource("api/terminal?channel=" + c);

	t.stream = s;
	t.channel = c;
	tstate(t, "starting nsh", "warn");
	s.addEventListener("ready", function (e) {
		var r = JSON.parse(e.data);

		if (t.stream !== s)
			return;
		t.runs = true;
		t.name.textContent = r.label;
		t.shut.setAttribute("aria-label", "Close " + r.label);
		tstate(t, r.label + (t.table === null ? "" :
		    ", opened in table " + t.table), "on");
		tsend(t);
		if (t === tab)
			t.term.focus();
	});
	s.addEventListener("out", function (e) {
		var a = atob(e.data), b = new Uint8Array(a.length), i;

		if (t.stream !== s)
			return;
		for (i = 0; i < a.length; i++)
			b[i] = a.charCodeAt(i);
		t.term.write(b);
	});
	s.addEventListener("end", function (e) {
		if (t.stream === s)
			tgone(t, JSON.parse(e.data).text);
	});
	/* EventSource would ask again, which follows no terminal now */
	s.onerror = function () {
		if (t.stream === s)
			tend(t, "disconnected");
	};
}

/*
 * Tab t's stream ended, and its nsh with it, as why says; the tab keeps
 * what its nsh wrote
 */
function tgone(t, why) {
	if (t.stream === null)
		return;
	t.stream.close();
	t.stream = null;
	t.channel = 0;
	t.runs = false;
	t.typed = [];
	t.frame = null;
	why = why.trim();
	t.term.write("\r\n\x1b[2m[" + why + "]\x1b[0m\r\n");
	tstate(t, why, "off");
}

/*
 * channel c closed; if nshdeck does not answer, its terminal ends all
 * the same once no stream follows it
 */
function tclosing(c) {
	ask("POST", "close", { channel: c }).catch(function () {
		return null;
	});
}

/*
 * tab t's nsh, ended by the page, as why says: its channel closed, as
 * its stream is, so that nshdeck need not notice the stream's end
 */
function tend(t, why) {
	if (t.channel !== 0)
		tclosing(t.channel);
	tgone(t, why);
}

/* tab t closed, its nsh ended: what comes for it later is dropped */
function tclose(t) {
	var i = tabs.indexOf(t);

	t.closed = true;
	tend(t, "closed");
	t.term.dispose();
	t.tab.remove();
	t.panel.remove();
	tabs.splice(i, 1);
	if (tab === t)
		tselect(tabs.length > 0 ? tabs[Math.min(i, tabs.length - 1)] :
		    null);
}

/* the page's text size in pixels, which the terminals' follows */
function termPx() {
	return Math.round(parseFloat(getComputedStyle(document.documentElement)
	    .fontSize));
}

/* the page's size changed (app.js): the tab shown follows */
function termSized() {
	if (tab !== null && !$("ws-terminal").hidden)
		tfit(tab);
}

/*
 * the Terminal workspace, shown: its tab, sized to its box; or, with
 * none, a tab with an nsh opened in it. A tab whose nsh ended stays so
 * until Connect
 */
function terminalShown() {
	if (tab === null)
		tnew();
	else {
		tfit(tab);
		tab.term.focus();
	}
}

document.addEventListener("DOMContentLoaded", function () {
	$("term-new").addEventListener("click", tnew);
	$("term-connect").addEventListener("click", function () {
		if (tab !== null)
			tconnect(tab);
	});
	$("term-end").addEventListener("click", function () {
		if (tab !== null)
			tend(tab, "disconnected");
	});
	/* the arrow keys move between the tabs */
	$("term-tabs").addEventListener("keydown", function (e) {
		var i = tabs.indexOf(tab);

		if (i === -1 || (e.key !== "ArrowLeft" &&
		    e.key !== "ArrowRight"))
			return;
		i = (i + (e.key === "ArrowLeft" ? tabs.length - 1 : 1)) %
		    tabs.length;
		tselect(tabs[i]);
		tabs[i].pick.focus();
		e.preventDefault();
	});
	/* a wider window can mean larger text too (style.css) */
	window.addEventListener("resize", termSized);
});
