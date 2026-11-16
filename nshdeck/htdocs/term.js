/*
 * term.js: a terminal, nsh on a pty, which nshdeck runs for the user
 * logged in (nshdeck(8)'s open, terminal and type). An open asks for
 * it, and is answered with its channel; xterm.js draws it; what nsh
 * writes comes on the channel's event stream, in base64; and what is
 * typed goes in type requests, one at a time, in order, and again a
 * little later if nsh has not yet taken what came before
 */
"use strict";

var term = null;	/* xterm.js's terminal, once it is drawn */
var termfit = null;	/* its fit addon, which sizes it to its box */
var tstream = null;	/* the terminal's stream, while it is open */
var tchannel = 0;	/* its channel, once nshdeck says it runs */
var topening = false;	/* an open asked, not yet answered */
var typing = "";	/* typed, not yet sent */
var ttable = null;	/* the table the terminal's nsh began in, if the page */
			/* was focused on one as it opened */
var sending = false;	/* a type request not yet answered */

/* the terminal's state, in words, its light, and its buttons */
function tstate(text, led) {
	$("term-state").textContent = text;
	$("term-led").className = "led " + led;
	$("term-connect").disabled = tstream !== null || topening;
	$("term-end").disabled = tstream === null;
}

/* what was typed, sent 300 characters at most, to fit 1023 bytes of UTF-8 */
function tsend() {
	var n = Math.min(typing.length, 300), keys;

	if (sending || tchannel === 0 || n === 0)
		return;
	/* not half of a character that takes two UTF-16 units */
	if (n < typing.length && /[\uD800-\uDBFF]/.test(typing[n - 1]))
		n--;
	keys = typing.slice(0, n);
	typing = typing.slice(n);
	sending = true;
	ask("POST", "type", { channel: tchannel, keys: keys }).then(
	    function (j) {
		sending = false;
		if (j.httpStatus === 503 && tchannel !== 0) {
			typing = keys + typing;
			setTimeout(tsend, 250);
		} else
			tsend();
	}, function () {
		sending = false;
	});
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
		term.onData(function (d) {
			/* a NUL cannot be sent */
			typing += d.replace(/\0/g, "");
			tsend();
		});
		term.onResize(function (s) {
			if (tchannel !== 0)
				ask("POST", "type", { channel: tchannel,
				    keys: "", rows: s.rows, cols: s.cols });
		});
	}
	termfit.fit();
	tchannel = 0;
	typing = "";
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
	typing = "";
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
