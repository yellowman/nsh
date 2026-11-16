/*
 * term.js: a terminal, nsh on a pty, which nshdeck runs for the user
 * logged in (nshdeck(8)'s open, terminal and type). An open asks for
 * it, and is answered with its channel; xterm.js draws it; what nsh
 * writes comes on the channel's event stream, in base64; and what is
 * typed goes, as its bytes, in frames, one at a time, each with its
 * sequence, and the same frame again until nshdeck takes it
 */
"use strict";

var term = null;	/* xterm.js's terminal, once it is drawn */
var termfit = null;	/* its fit addon, which sizes it to its box */
var tstream = null;	/* the terminal's stream, while it is open */
var tchannel = 0;	/* its channel, once nshdeck says it runs */
var topening = false;	/* an open asked, not yet answered */
var ttable = null;	/* the table the terminal's nsh began in, if the page */
			/* was focused on one as it opened */
var TFRAME = 750;	/* a frame's bytes, at most */
var typed = [];		/* bytes typed, not yet in a frame, as Uint8Arrays */
var tsize = null;	/* a size not yet in a frame */
var tseq = 0;		/* the last frame nshdeck took */
var tframe = null;	/* the frame sent, not yet taken */

/* the terminal's state, in words, its light, and its buttons */
function tstate(text, led) {
	$("term-state").textContent = text;
	$("term-led").className = "led " + led;
	$("term-connect").disabled = tstream !== null || topening;
	$("term-end").disabled = tstream === null;
}

/*
 * The next frame: TFRAME of the bytes typed at most, a character's
 * bytes split between two frames if they come so, and the size, if it
 * changed; one frame at a time, the one after the last one taken
 */
function tsend() {
	var b = new Uint8Array(TFRAME), n = 0, k, s = "", i;

	if (tframe !== null || tchannel === 0 ||
	    (typed.length === 0 && tsize === null))
		return;
	while (typed.length > 0 && n < TFRAME) {
		k = Math.min(typed[0].length, TFRAME - n);
		b.set(typed[0].subarray(0, k), n);
		n += k;
		typed[0] = typed[0].subarray(k);
		if (typed[0].length === 0)
			typed.shift();
	}
	for (i = 0; i < n; i++)
		s += String.fromCharCode(b[i]);
	tframe = { channel: tchannel, seq: tseq + 1, data: btoa(s) };
	if (tsize !== null) {
		tframe.rows = tsize.rows;
		tframe.cols = tsize.cols;
		tsize = null;
	}
	tpost(tframe);
}

/*
 * frame f, sent; and sent again as it was if nsh has no room for it yet,
 * or if its answer was lost, which nshdeck answers without taking it
 * twice
 */
function tpost(f) {
	ask("POST", "type", f).then(function (j) {
		if (tframe !== f)
			return;
		if (j.ok) {
			tseq = f.seq;
			tframe = null;
			tsend();
		} else if (j.httpStatus === 503)
			setTimeout(function () {
				if (tframe === f)
					tpost(f);
			}, 250);
		else
			tgone(j.error || "typed into a terminal gone");
	}, function () {
		setTimeout(function () {
			if (tframe === f)
				tpost(f);
		}, 1000);
	});
}

/* bytes typed, from xterm.js, to be sent */
function tbytes(b) {
	typed.push(b);
	tsend();
}

/* a name for an open, which the page gives it again if it asks again */
function topenid() {
	var b = new Uint32Array(2);

	crypto.getRandomValues(b);
	return b[0].toString(36) + b[1].toString(36);
}

/*
 * An open of fields, asked again, with the same name, as many as tries
 * times, if its answer was lost: nshdeck answers that with the same
 * channel, so a lost answer opens no second nsh
 */
function topen(fields, tries) {
	return ask("POST", "open", fields).catch(function (e) {
		if (tries <= 1)
			throw e;
		return topen(fields, tries - 1);
	});
}

/* the terminal, drawn the first time, and an nsh opened for it */
function tconnect() {
	var fields;

	if (tstream !== null || topening)
		return;
	if (term === null) {
		term = new Terminal({ cursorBlink: true, fontSize: termPx(),
		    fontFamily: getComputedStyle(document.body)
		    .getPropertyValue("--mono").trim(), scrollback: 5000,
		    theme: { background: "#0b0d10", foreground: "#d7dce2",
		    cursor: "#4ea1ff", cursorAccent: "#0b0d10",
		    selectionBackground: "#2b4a6f" } });
		termfit = new FitAddon.FitAddon();
		term.loadAddon(termfit);
		term.open($("term"));
		/* text as UTF-8, a NUL too; and bytes as they are */
		term.onData(function (d) {
			tbytes(new TextEncoder().encode(d));
		});
		term.onBinary(function (d) {
			tbytes(Uint8Array.from(d, function (c) {
				return c.charCodeAt(0);
			}));
		});
		term.onResize(function (s) {
			tsize = { rows: s.rows, cols: s.cols };
			tsend();
		});
	}
	termfit.fit();
	tchannel = 0;
	typed = [];
	tsize = null;
	tseq = 0;
	tframe = null;
	/* nsh begins in the table the page is focused on, as nsh -T does */
	ttable = table;
	fields = { request: topenid(), rows: term.rows, cols: term.cols };
	if (ttable !== null)
		fields.rtable = ttable;
	topening = true;
	tstate("starting nsh", "warn");
	topen(fields, 3).then(function (j) {
		topening = false;
		if (j.ok && !j.ended)
			tfollow(j.channel);
		else
			tstate(j.ended ? "nsh ended" : j.error, "off");
	}, function () {
		topening = false;
		tstate("nshdeck did not answer", "off");
	});
}

/* the stream of the terminal on channel c: what its nsh writes */
function tfollow(c) {
	tstream = new EventSource("api/terminal?channel=" + c);
	tstate("starting nsh", "warn");
	tstream.addEventListener("ready", function (e) {
		var r = JSON.parse(e.data);

		tchannel = r.channel;
		tstate(r.label + (ttable === null ? "" : ", rtable " + ttable),
		    "on");
		tsend();
		term.focus();
	});
	tstream.addEventListener("out", function (e) {
		var s = atob(e.data), b = new Uint8Array(s.length), i;

		for (i = 0; i < s.length; i++)
			b[i] = s.charCodeAt(i);
		term.write(b);
	});
	tstream.addEventListener("end", function (e) {
		tgone(JSON.parse(e.data).text);
	});
	/* EventSource would ask again, which would start another nsh */
	tstream.onerror = function () {
		tgone("disconnected");
	};
}

/* the terminal's stream ended, and its nsh with it, as why says */
function tgone(why) {
	if (tstream === null)
		return;
	tstream.close();
	tstream = null;
	tchannel = 0;
	typed = [];
	tframe = null;
	why = why.trim();
	term.write("\r\n\x1b[2m[" + why + "]\x1b[0m\r\n");
	tstate(why, "off");
}

/* the page's text size in pixels, which the terminal's follows */
function termPx() {
	return Math.round(parseFloat(getComputedStyle(document.documentElement)
	    .fontSize));
}

/* the page's size changed (app.js): the terminal's text follows */
function termSized() {
	if (term === null)
		return;
	term.options.fontSize = termPx();
	if (!$("ws-terminal").hidden)
		termfit.fit();
}

/* the Terminal workspace, shown: its terminal, connected if it is not */
function terminalShown() {
	if (tstream === null)
		tconnect();
	else {
		termfit.fit();
		term.focus();
	}
}

document.addEventListener("DOMContentLoaded", function () {
	$("term-connect").addEventListener("click", tconnect);
	$("term-end").addEventListener("click", function () {
		tgone("disconnected");
	});
	/* a wider window can mean larger text too (style.css) */
	window.addEventListener("resize", termSized);
});
